use std::net::SocketAddr;
use std::str::FromStr;
use crate::error::{CryptoError, Result};
use crate::p2p::{PeerAddr, PeerId};
use data_encoding::BASE32_NOPAD;
use crc::{Crc, CRC_32_ISO_HDLC};
use serde::{Deserialize, Serialize};

const CRC_ISO: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ticket {
    pub version: u8,
    pub node_id: [u8; 32],
    pub relay_url: Option<String>,
    pub direct_addrs: Vec<SocketAddr>,
    pub pqc_fp_algo: u8,
    pub pqc_sign_fp: [u8; 32],
    pub pqc_enc_fp: [u8; 32],
}

impl Ticket {
    /// Build a ticket from a transport-agnostic [`PeerAddr`]. Backends
    /// (currently iroh) are responsible for converting their native
    /// address type to [`PeerAddr`] before calling this.
    pub fn new(addr: PeerAddr, pqc_sign_fp: Option<[u8; 32]>, pqc_enc_fp: Option<[u8; 32]>) -> Self {
        let mut algo = 0u8;
        let mut sign_fp = [0u8; 32];
        let mut enc_fp = [0u8; 32];

        if let Some(fp) = pqc_sign_fp {
            algo |= 1;
            sign_fp = fp;
        }
        if let Some(fp) = pqc_enc_fp {
            algo |= 2;
            enc_fp = fp;
        }

        Self {
            version: 1,
            node_id: addr.peer_id.to_bytes(),
            relay_url: addr.relay_url,
            direct_addrs: addr.direct_addrs,
            pqc_fp_algo: algo,
            pqc_sign_fp: sign_fp,
            pqc_enc_fp: enc_fp,
        }
    }

    /// Extract the transport-agnostic address. Infallible — the ticket
    /// already stores the address in its canonical wire form. Backends
    /// convert this to their native address type at use time.
    pub fn peer_addr(&self) -> PeerAddr {
        PeerAddr {
            peer_id: PeerId::new(self.node_id),
            relay_url: self.relay_url.clone(),
            direct_addrs: self.direct_addrs.clone(),
        }
    }

}

impl FromStr for Ticket {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self> {
        if !s.starts_with("nkct1") {
            return Err(CryptoError::Parameter("Invalid ticket prefix".to_string()));
        }

        let data = BASE32_NOPAD.decode(s[5..].as_bytes())
            .map_err(|e| CryptoError::Parameter(format!("Invalid ticket encoding: {}", e)))?;

        if data.len() < 1 + 32 + 2 + 2 + 1 + 32 + 32 + 4 {
            return Err(CryptoError::Parameter("Ticket too short".to_string()));
        }

        let (body, checksum_bytes) = data.split_at(data.len() - 4);
        let expected_checksum = u32::from_le_bytes(checksum_bytes.try_into().unwrap());
        if CRC_ISO.checksum(body) != expected_checksum {
            return Err(CryptoError::Parameter("Ticket checksum mismatch".to_string()));
        }

        // Bounds-checked cursor over the (attacker-controlled) ticket body.
        // The fixed-length guard above only covers the mandatory fields; the
        // variable-length relay URL and direct-address list must each be
        // validated against the remaining buffer before slicing, or a crafted
        // ticket (with a valid CRC, which the attacker can compute) would panic
        // with a slice-out-of-range — a DoS reachable from CLI args and the FFI
        // `peer_from_ticket` entry point. Mirrors the `take()` pattern in
        // prekey.rs / one_shot.rs.
        let mut offset = 0usize;
        let take = |offset: &mut usize, n: usize| -> Result<&[u8]> {
            let end = offset
                .checked_add(n)
                .ok_or_else(|| CryptoError::Parameter("ticket length overflow".to_string()))?;
            if end > body.len() {
                return Err(CryptoError::Parameter("ticket truncated".to_string()));
            }
            let s = &body[*offset..end];
            *offset = end;
            Ok(s)
        };

        let version = take(&mut offset, 1)?[0];
        if version != 1 {
            return Err(CryptoError::Parameter(format!("Unsupported ticket version: {}", version)));
        }

        let node_id: [u8; 32] = take(&mut offset, 32)?.try_into().unwrap();

        let relay_url_len = u16::from_le_bytes(take(&mut offset, 2)?.try_into().unwrap()) as usize;
        let relay_url = if relay_url_len > 0 {
            let s = std::str::from_utf8(take(&mut offset, relay_url_len)?)
                .map_err(|_| CryptoError::Parameter("Invalid UTF-8 in relay URL".to_string()))?;
            Some(s.to_string())
        } else {
            None
        };

        let direct_addrs_count =
            u16::from_le_bytes(take(&mut offset, 2)?.try_into().unwrap()) as usize;
        // Cap the pre-allocation: a bogus count can claim up to 65535 while the
        // body is short, so size modestly and let the Vec grow as `take`
        // actually yields verified entries.
        let mut direct_addrs = Vec::with_capacity(direct_addrs_count.min(16));
        for _ in 0..direct_addrs_count {
            let family = take(&mut offset, 1)?[0];
            match family {
                4 => {
                    let ip: [u8; 4] = take(&mut offset, 4)?.try_into().unwrap();
                    let port = u16::from_le_bytes(take(&mut offset, 2)?.try_into().unwrap());
                    direct_addrs.push(SocketAddr::new(std::net::IpAddr::V4(ip.into()), port));
                }
                6 => {
                    let ip: [u8; 16] = take(&mut offset, 16)?.try_into().unwrap();
                    let port = u16::from_le_bytes(take(&mut offset, 2)?.try_into().unwrap());
                    direct_addrs.push(SocketAddr::new(std::net::IpAddr::V6(ip.into()), port));
                }
                other => {
                    return Err(CryptoError::Parameter(format!("Invalid IP family: {}", other)))
                }
            }
        }

        let pqc_fp_algo = take(&mut offset, 1)?[0];
        let pqc_sign_fp: [u8; 32] = take(&mut offset, 32)?.try_into().unwrap();
        let pqc_enc_fp: [u8; 32] = take(&mut offset, 32)?.try_into().unwrap();

        Ok(Self {
            version,
            node_id,
            relay_url,
            direct_addrs,
            pqc_fp_algo,
            pqc_sign_fp,
            pqc_enc_fp,
        })
    }
}

impl std::fmt::Display for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut payload = Vec::new();
        payload.push(self.version);
        payload.extend_from_slice(&self.node_id);
        
        let relay = self.relay_url.as_deref().unwrap_or("");
        payload.extend_from_slice(&(relay.len() as u16).to_le_bytes());
        payload.extend_from_slice(relay.as_bytes());

        payload.extend_from_slice(&(self.direct_addrs.len() as u16).to_le_bytes());
        for addr in &self.direct_addrs {
            match addr {
                SocketAddr::V4(a) => {
                    payload.push(4);
                    payload.extend_from_slice(&a.ip().octets());
                    payload.extend_from_slice(&a.port().to_le_bytes());
                }
                SocketAddr::V6(a) => {
                    payload.push(6);
                    payload.extend_from_slice(&a.ip().octets());
                    payload.extend_from_slice(&a.port().to_le_bytes());
                }
            }
        }

        payload.push(self.pqc_fp_algo);
        payload.extend_from_slice(&self.pqc_sign_fp);
        payload.extend_from_slice(&self.pqc_enc_fp);

        let checksum = CRC_ISO.checksum(&payload);
        payload.extend_from_slice(&checksum.to_le_bytes());

        write!(f, "nkct1{}", BASE32_NOPAD.encode(&payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // Wrap an arbitrary ticket body in a valid CRC + base32 envelope, exactly
    // as a (possibly malicious) producer would. The CRC is computed over the
    // attacker-chosen body, so it is never a barrier to a crafted ticket.
    fn encode_ticket(body: &[u8]) -> String {
        let checksum = CRC_ISO.checksum(body);
        let mut payload = body.to_vec();
        payload.extend_from_slice(&checksum.to_le_bytes());
        format!("nkct1{}", BASE32_NOPAD.encode(&payload))
    }

    #[test]
    fn roundtrip_with_relay_and_addrs() {
        let t = Ticket {
            version: 1,
            node_id: [7u8; 32],
            relay_url: Some("https://relay.example".to_string()),
            direct_addrs: vec![
                "192.0.2.1:443".parse().unwrap(),
                "[2001:db8::1]:8080".parse().unwrap(),
            ],
            pqc_fp_algo: 3,
            pqc_sign_fp: [1u8; 32],
            pqc_enc_fp: [2u8; 32],
        };
        let parsed = Ticket::from_str(&t.to_string()).expect("roundtrip parse");
        assert_eq!(parsed.node_id, t.node_id);
        assert_eq!(parsed.relay_url, t.relay_url);
        assert_eq!(parsed.direct_addrs, t.direct_addrs);
        assert_eq!(parsed.pqc_fp_algo, t.pqc_fp_algo);
        assert_eq!(parsed.pqc_sign_fp, t.pqc_sign_fp);
        assert_eq!(parsed.pqc_enc_fp, t.pqc_enc_fp);
    }

    // The fixed-length min guard requires body >= 102 bytes; these craft a body
    // that passes it but declares a variable-length field running past the end,
    // which previously sliced out of range and panicked (DoS).

    #[test]
    fn oversize_relay_url_len_is_rejected_not_panic() {
        let mut body = vec![0u8; 102];
        body[0] = 1; // version
        body[33..35].copy_from_slice(&u16::MAX.to_le_bytes()); // relay_url_len
        assert!(Ticket::from_str(&encode_ticket(&body)).is_err());
    }

    #[test]
    fn oversize_direct_addrs_count_is_rejected_not_panic() {
        let mut body = vec![4u8; 102]; // fill with IPv4 family bytes
        body[0] = 1; // version
        body[33..35].copy_from_slice(&0u16.to_le_bytes()); // relay_url_len = 0
        body[35..37].copy_from_slice(&u16::MAX.to_le_bytes()); // direct_addrs_count
        assert!(Ticket::from_str(&encode_ticket(&body)).is_err());
    }

    #[test]
    fn truncated_relay_url_is_rejected_not_panic() {
        let mut body = vec![0u8; 102];
        body[0] = 1;
        // Declare an 80-byte relay URL, but only 67 bytes remain after the
        // length field.
        body[33..35].copy_from_slice(&80u16.to_le_bytes());
        assert!(Ticket::from_str(&encode_ticket(&body)).is_err());
    }
}
