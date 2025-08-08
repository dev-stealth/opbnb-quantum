//! opbnb-quantum
//!
//! Quantum-secure wallet core library.
//! This crate provides:
//! - Post-quantum cryptography primitives (Kyber, NTRU-HRSS, Dilithium5)
//! - Fail-safe PQC switching
//! - Zero-knowledge proof integration (Halo2, STARK)
//!
//! Reference: 03_pq-crypto_stack.md

pub mod crypto;
