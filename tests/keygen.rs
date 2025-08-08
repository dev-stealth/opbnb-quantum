use opbnb_quantum::crypto::*;
use sha2::{Digest, Sha256};

fn fp4(bytes: &[u8]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

#[test]
fn generate_keys_ok_and_fingerprints() {
    // Kyber
    let kyber = kyber1024_keypair();
    assert!(!kyber.public_key.is_empty());
    assert!(!kyber.secret_key.is_empty());
    assert_ne!(kyber.public_key, kyber.secret_key);
    let kfp = fp4(&kyber.public_key);
    println!(
        "Kyber Public fp: {:02x}{:02x}{:02x}{:02x}",
        kfp[0], kfp[1], kfp[2], kfp[3]
    );

    // NTRU
    let ntru = ntru_keypair();
    assert!(!ntru.public_key.is_empty());
    assert!(!ntru.secret_key.is_empty());
    assert_ne!(ntru.public_key, ntru.secret_key);
    let nfp = fp4(&ntru.public_key);
    println!(
        "NTRU Public  fp: {:02x}{:02x}{:02x}{:02x}",
        nfp[0], nfp[1], nfp[2], nfp[3]
    );

    // Dilithium (ML-DSA-5)
    let dil = dilithium5_keypair();
    assert!(!dil.public_key.is_empty());
    assert!(!dil.secret_key.is_empty());
    assert_ne!(dil.public_key, dil.secret_key);
    let dfp = fp4(&dil.public_key);
    println!(
        "Dilithium Public fp: {:02x}{:02x}{:02x}{:02x}",
        dfp[0], dfp[1], dfp[2], dfp[3]
    );
}
