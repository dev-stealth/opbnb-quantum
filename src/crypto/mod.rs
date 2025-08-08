//! Crypto module
//!
//! Samler KEM- og signatur-implementasjoner og eksporterer et konsistent API.
//! Referanse: 03_pq-crypto_stack.md

pub mod kem;
pub mod sig;
pub mod switch;

pub use kem::{
    generate_kyber_keys as kyber1024_keypair, generate_ntru_keys as ntru_keypair,
    kyber_decapsulate, kyber_encapsulate, ntru_decapsulate, ntru_encapsulate, KemCipher,
    KemKeyPair,
};

pub use sig::{
    generate_dilithium_keys as dilithium5_keypair, sign_message as dilithium5_sign,
    verify_message as dilithium5_verify, SigKeyPair, Signature,
};

pub use switch::{CryptoConfig, KemAlgorithm};
