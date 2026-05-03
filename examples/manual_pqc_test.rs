use nk_crypto_tool::backend;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = "ML-DSA-65";
    let (sk, pk, _) = backend::pqc_keygen_dsa(algo)?;
    println!("Keygen ok. pk len: {}, sk len: {}", pk.len(), sk.len());
    
    let msg = b"Handshake transcript test message";
    let sig = backend::pqc_sign(algo, &sk, msg, None)?;
    println!("Sign ok. sig len: {}", sig.len());
    
    let ok = backend::pqc_verify(algo, &pk, msg, &sig)?;
    println!("Verify result: {}", ok);
    
    if ok {
        println!("TEST PASSED");
    } else {
        println!("TEST FAILED");
    }
    Ok(())
}
