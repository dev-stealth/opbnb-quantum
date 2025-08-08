use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

/// Public/secret keypair for Dilithium5 (ML-DSA-5)
pub struct SigKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// Detached signature bytes
pub struct Signature {
    pub bytes: Vec<u8>,
}

/// Generate a fresh Dilithium5 keypair.
pub fn generate_dilithium_keys() -> SigKeyPair {
    let (pk, sk) = dilithium5::keypair();
    SigKeyPair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    }
}

/// Sign a message with a Dilithium5 secret key.
pub fn sign_message(sk: &[u8], message: &[u8]) -> Signature {
    let secret_key =
        dilithium5::SecretKey::from_bytes(sk).expect("Invalid Dilithium secret key bytes");
    let sig = dilithium5::detached_sign(message, &secret_key);
    Signature {
        bytes: sig.as_bytes().to_vec(),
    }
}

/// Verify a detached signature against a message and public key.
pub fn verify_message(sig: &[u8], pk: &[u8], message: &[u8]) -> bool {
    let signature = DetachedSignature::from_bytes(sig).expect("Invalid Dilithium signature bytes");
    let public_key =
        dilithium5::PublicKey::from_bytes(pk).expect("Invalid Dilithium public key bytes");
    dilithium5::verify_detached_signature(&signature, message, &public_key).is_ok()
}
