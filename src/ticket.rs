use iroh::{NodeId, NodeAddr, RelayUrl};
use std::net::SocketAddr;
use std::str::FromStr;
use crate::error::{CryptoError, Result};
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
    pub fn new(node_addr: NodeAddr, pqc_sign_fp: Option<[u8; 32]>, pqc_enc_fp: Option<[u8; 32]>) -> Self {
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
            node_id: *node_addr.node_id.as_bytes(),
            relay_url: node_addr.relay_url.map(|u| u.to_string()),
            direct_addrs: node_addr.direct_addresses.into_iter().collect(),
            pqc_fp_algo: algo,
            pqc_sign_fp: sign_fp,
            pqc_enc_fp: enc_fp,
        }
    }

    pub fn node_addr(&self) -> Result<NodeAddr> {
        let node_id = NodeId::from_bytes(&self.node_id).map_err(|e| CryptoError::Parameter(format!("Invalid NodeId: {}", e)))?;
        let relay_url = self.relay_url.as_ref()
            .map(|s| RelayUrl::from_str(s).map_err(|e| CryptoError::Parameter(format!("Invalid RelayUrl: {}", e))))
            .transpose()?;
        
        Ok(NodeAddr {
            node_id,
            relay_url,
            direct_addresses: self.direct_addrs.iter().cloned().collect(),
        })
    }

    pub fn to_string(&self) -> String {
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

        format!("nkct1{}", BASE32_NOPAD.encode(&payload))
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

        let mut offset = 0;
        let version = body[offset]; offset += 1;
        if version != 1 {
            return Err(CryptoError::Parameter(format!("Unsupported ticket version: {}", version)));
        }

        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&body[offset..offset+32]); offset += 32;

        let relay_url_len = u16::from_le_bytes(body[offset..offset+2].try_into().unwrap()) as usize; offset += 2;
        let relay_url = if relay_url_len > 0 {
            let s = std::str::from_utf8(&body[offset..offset+relay_url_len])
                .map_err(|_| CryptoError::Parameter("Invalid UTF-8 in relay URL".to_string()))?;
            offset += relay_url_len;
            Some(s.to_string())
        } else {
            None
        };

        let direct_addrs_count = u16::from_le_bytes(body[offset..offset+2].try_into().unwrap()) as usize; offset += 2;
        let mut direct_addrs = Vec::with_capacity(direct_addrs_count);
        for _ in 0..direct_addrs_count {
            let family = body[offset]; offset += 1;
            if family == 4 {
                let mut ip_bytes = [0u8; 4];
                ip_bytes.copy_from_slice(&body[offset..offset+4]); offset += 4;
                let port = u16::from_le_bytes(body[offset..offset+2].try_into().unwrap()); offset += 2;
                direct_addrs.push(SocketAddr::new(std::net::IpAddr::V4(ip_bytes.into()), port));
            } else if family == 6 {
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&body[offset..offset+16]); offset += 16;
                let port = u16::from_le_bytes(body[offset..offset+2].try_into().unwrap()); offset += 2;
                direct_addrs.push(SocketAddr::new(std::net::IpAddr::V6(ip_bytes.into()), port));
            } else {
                return Err(CryptoError::Parameter(format!("Invalid IP family: {}", family)));
            }
        }

        let pqc_fp_algo = body[offset]; offset += 1;
        let mut pqc_sign_fp = [0u8; 32];
        pqc_sign_fp.copy_from_slice(&body[offset..offset+32]); offset += 32;
        let mut pqc_enc_fp = [0u8; 32];
        pqc_enc_fp.copy_from_slice(&body[offset..offset+32]);

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
        write!(f, "{}", self.to_string())
    }
}
