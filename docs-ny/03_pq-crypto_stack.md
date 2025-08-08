`03_pq-crypto_stack.md`

# 03 – Post-Quantum Crypto Stack

*Quantum-Secure Wallet Pro — Build-step ➋*

---

## Innholdsfortegnelse

1. Algoritme-oversikt
2. Nivå-og parameter-valg
3. Nøkkel­håndtering & rotasjon
4. Fail-safe «crypto-break» prosedyre
5. Secure-wipe spesifikasjon
6. Randomness & entropi­kilder
7. Enclave-API (FROST + PQC)
8. Testmatrise & formell bevisføring
9. Vedlegg A – CLI-kommandoer

---

## 1 · Algoritme-oversikt

| Primitive  | Valgt standard                 | Rolle                  | Migrasjons­sti                |
| ---------- | ------------------------------ | ---------------------- | ----------------------------- |
| KEM        | **Kyber-1024** (NIST finalist) | ECDH-erstatter         | Kyber-1536 > Classic McEliece |
| Signatur   | **Dilithium-III**              | Auth, firmware, tx-sig | Dilithium-V → Falcon-1024     |
| Threshold  | **FROST-Dilithium**            | 2-of-n wallet keys     | FROST-Falcon                  |
| Symmetrisk | **AES-256-GCM** (HW-AES)       | Channel & datastore    | **XChaCha20-Poly1305**        |
| Hash       | **SHA3-512**, **BLAKE3**       | Commitment, PRNG       | Poseidon (ZK-friendly)        |

*Alle biblioteker er pinned i `Cargo.lock` med reproducible hashes.*

---

## 2 · Nivå- og parameter-valg

| Sikkerhets­mål | Bits  | Parameter                  | Kommentar                               |
| -------------- | ----- | -------------------------- | --------------------------------------- |
| Conf. / Int.   | ≥ 256 | Kyber-1024, Dilithium-III  | 256-bit post-kvant motstand (ref: NIST) |
| Long-term keys | ≥ 256 | FROST-Dilithium (t=2, n=5) | 2-of-5 signatarer kreves                |
| ZK circuits    | ≥ 128 | Poseidon-BN254             | Sikker nok m/ STARK-agg. reserve        |

---

## 3 · Nøkkel­håndtering & rotasjon

1. **Usage-based**: Hver signatur eller KEM-dekryptering øker «key-age». Ved `age > 10 000` roteres.
2. **Time-based**: T+180 dager tvungen rotasjon (cron-job i enclave).
3. **Protocol**:

   1. Generér ny key-pair i enclave (sealed).
   2. FROST «re-share» til del-takere (`frost-cli reshare …`).
   3. On-chain oppdater transaksjon med ny public key (gas-budsjett ≤ 80 k).
4. **Versioning**: Public key-tags: `v{alg}-{param}-{ts}` eks.: `kyber1024-20250805`.

---

## 4 · Fail-safe «crypto-break» prosedyre

| Fase | Utfall                    | Handling                                                      |
| ---- | ------------------------- | ------------------------------------------------------------- |
| 0    | Mistenkt sårbarhet        | Flag i CI (`crypto-alert`) → manuell verifisering             |
| 1    | Confirmed CVE, PoC < 24 t | Automatisk «soft-fork» til migrasjons­algoritme pr. tabell §1 |
| 2    | Key-recovery sannsynlig   | All signering stanses, full key-rotation (Step 3)             |
| 3    | On-chain fork             | Pause kontrakter, «escape hatch» til cold storage             |

---

## 5 · Secure-wipe spesifikasjon

*Gjelder både RAM, swap, enclave SRAM, SSD/LUKS.*

1. **RAM**: `memzero_explicit()` -variant i Rust (`zeroize::Zeroizing`).
2. **Enclave**: `EGETKEY`-tempered DRAM flush + `clflushopt` loop.
3. **SSD**: `blkdiscard --secure` → `nvme format --ses=1`.
4. **TPM-sealed counters** verifierer at wipe-nonce = 0 før ny key kan importeres.

---

## 6 · Randomness & entropi­kilder

| Kilde                | Bit/s      | Health-check                   |
| -------------------- | ---------- | ------------------------------ |
| RDRAND / RDSEED      | \~2 Mb/s   | NIST-SP800-90B                 |
| `getrandom()` Linux  | \~1 Mb/s   | Catena self-test               |
| Audio-bias (mic-off) | \~100 Kb/s | Min-entropy ≥ 0.7              |
| **HKDF-SHA3** DRBG   | N/A        | Continuous-test, reseed 30 min |

All RNG-failover går via `ring::rand`.

---

## 7 · Enclave-API (FROST + PQC)

pub trait PqKms {
    /// Kyber decaps → shared key
    fn decapsulate(&self, ct: &[u8]) -> Result<[u8; 32]>;
    /// Dilithium sign
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>;
    /// FROST round-1 commitment
    fn frost_commit(&self, nonce: &[u8; 32]) -> Result<FrostCommitment>;
}

*All bridging via gRPC-TLS (Enclave ↔ CLI) with attestation token.*

---

## 8 · Testmatrise & formell bevisføring

| Testtype | Coverage-mål     | Verktøy                  |
| -------- | ---------------- | ------------------------ |
| Unit     | ≥ 85 % lines     | `cargo tarpaulin`        |
| Property | 1000 runs / func | `proptest`, `quickcheck` |
| PQC-KAT  | 100 % vectors    | NIST KAT-suite           |
| Fuzz     | Continuous       | `cargo fuzz`, `libAFL`   |
| Formal   | Re-write rules   | `kani`, `hacl-spec`      |

---

## 9 · Vedlegg A – CLI-kommandoer

| Formål            | Kommando                                        |
| ----------------- | ----------------------------------------------- |
| Generér Kyber key | `qswallet-cli key gen --alg kyber1024`          |
| Re-share FROST    | `frost-cli reshare -n 5 -t 2`                   |
| Audit entropy     | `rngtest --blockcount=9000 /dev/random`         |
| Wipe & rotate     | `qswallet-cli key wipe && qswallet-cli key gen` |

---

> **Oppdatert:** 5 aug 2025 — innført nøkkel­rotasjon, fail-safe PQC-fallback, secure-wipe-rutine og full RNG-health.
