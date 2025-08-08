//! Fail-safe PQC Switching
//!
//! Automatisk bytte mellom KEM-algoritmer ved deprecations eller integritetsfeil.
//! Ref: 03_pq-crypto_stack.md §4.2

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KemAlgorithm {
    /// ML-KEM-1024 (Kyber1024)
    Kyber1024,
    /// NTRU-HPS 4096-821 (pqcrypto_ntru::ntruhps4096821)
    NtruHps4096_821,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SigAlgorithm {
    /// ML-DSA-5 (Dilithium5)
    Dilithium5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub kem: KemAlgorithm,
    pub sig: SigAlgorithm,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            kem: KemAlgorithm::Kyber1024,
            sig: SigAlgorithm::Dilithium5,
        }
    }
}

impl CryptoConfig {
    pub fn switch_kem(&mut self) {
        self.kem = match self.kem {
            KemAlgorithm::Kyber1024 => KemAlgorithm::NtruHps4096_821,
            KemAlgorithm::NtruHps4096_821 => KemAlgorithm::Kyber1024,
        };
    }
}
