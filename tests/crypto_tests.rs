use opbnb_quantum::crypto::kem::*;
use opbnb_quantum::crypto::sig::*;
use opbnb_quantum::crypto::{CryptoConfig, KemAlgorithm};

#[test]
fn test_kyber1024_kem_roundtrip() {
    let keypair = generate_kyber_keys();
    let encapsulated = kyber_encapsulate(&keypair.public_key);
    let shared_secret = kyber_decapsulate(&encapsulated.ciphertext, &keypair.secret_key);
    assert_eq!(shared_secret, encapsulated.shared_secret);
    assert!(!shared_secret.is_empty());
}

#[test]
fn test_ntru_kem_roundtrip() {
    let keypair = generate_ntru_keys();
    let encapsulated = ntru_encapsulate(&keypair.public_key);
    let shared_secret = ntru_decapsulate(&encapsulated.ciphertext, &keypair.secret_key);
    assert_eq!(shared_secret, encapsulated.shared_secret);
    assert!(!shared_secret.is_empty());
}

#[test]
fn test_dilithium5_signature_valid() {
    let keypair = generate_dilithium_keys();
    let message = b"Quantum-secure wallet test message";
    let signature = sign_message(&keypair.secret_key, message);
    assert!(verify_message(
        &signature.bytes,
        &keypair.public_key,
        message
    ));
}

#[test]
fn test_dilithium5_signature_invalid_message() {
    let keypair = generate_dilithium_keys();
    let message = b"Original message";
    let wrong_message = b"Tampered message";
    let signature = sign_message(&keypair.secret_key, message);
    assert!(!verify_message(
        &signature.bytes,
        &keypair.public_key,
        wrong_message
    ));
}

#[test]
fn property_test_shared_secret_randomness() {
    let keypair = generate_kyber_keys();
    let encapsulated1 = kyber_encapsulate(&keypair.public_key);
    let encapsulated2 = kyber_encapsulate(&keypair.public_key);
    assert_ne!(encapsulated1.shared_secret, encapsulated2.shared_secret);
}

#[test]
fn property_test_signature_determinism() {
    let keypair = generate_dilithium_keys();
    let message = b"Deterministic signature test";
    let sig1 = sign_message(&keypair.secret_key, message);
    let sig2 = sign_message(&keypair.secret_key, message);
    assert_eq!(sig1.bytes, sig2.bytes);
}

#[test]
fn test_switch_toggle_roundtrip() {
    let mut cfg = CryptoConfig::default();
    let original = cfg.kem.clone();
    cfg.switch_kem();
    assert_ne!(cfg.kem, original);
    cfg.switch_kem();
    assert_eq!(cfg.kem, original);
    assert!(matches!(
        cfg.kem,
        KemAlgorithm::Kyber1024 | KemAlgorithm::NtruHps4096_821
    ));
}
