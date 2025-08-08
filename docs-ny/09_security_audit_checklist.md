09\_security\_audit\_checklist.md

# 09 – Security Audit Checklist

*Quantum-Secure Wallet Pro — Gate ➒ «Pre-Audit»*

---

## Innholdsfortegnelse

1. Terminologi & milepæler
2. Audit-faser & «go/no-go»-porter
3. Automatiserte skannere (CVE, SCA, SBOM)
4. Manuell kodegjennomgang
5. Timing- & sidekanals-sjekk 🆕
6. Firmware & chain-of-trust-verifikasjon 🆕
7. Avhengighets-locking & reproducible builds 🆕
8. Bug-bounty-program (utvidet scope) 🆕
9. Akseptkriterier (scorekort)
10. Leveranser & rapportering
11. Vedlegg A – Audit-tidslinje
12. Vedlegg B – Kontaktmatrise

---

## 1 · Terminologi & milepæler

| Begrep              | Definisjon                                                           |
| ------------------- | -------------------------------------------------------------------- |
| **SLSA 4**          | Full bygg-proveniens; artefakter signert & attestert (ref: 08 §2).   |
| **PCR-policy**      | TPM PCR 0, 2, 7 må matche bundet hash-liste (ref: 02 §5).            |
| **FROST-Dilithium** | 2-of-n post-kvant signaturskjema brukt i wallet-nøkler (ref: 03 §1). |

---

## 2 · Audit-faser & «go/no-go»-porter

| Fase                         | Beskrivelse                        | Exit-kriterium                    |
| ---------------------------- | ---------------------------------- | --------------------------------- |
| **α – Static Analyse**       | SAST, linters, type-system alerts  | 0 «high»-severity funn            |
| **β – Dependency Scan**      | CVE, license, SBOM diff            | Intet CVSS ≥ 7 uten mitigasjon    |
| **γ – Manual Review**        | Krypto-implementasjon, ZK-circuits | Alle kritiske issues løst/patchet |
| **δ – Sidechannel & Timing** | Se §5                              | Varians ≤ 5 μs per krypto-op      |
| **ε – Supply-Chain**         | SLSA, firmware, lockfiles          | Fulcio-signatur & Rekor-innslag   |
| **ζ – Report Sign-off**      | Auditor signerer PDF + SPDX        | CTO & Sec-lead godkjenner         |

---

## 3 · Automatiserte skannere

| Verktøy           | Kommando                                             | «Pass» terskel         |
| ----------------- | ---------------------------------------------------- | ---------------------- |
| **grype**         | `grype sbom.json`                                    | Ingen «critical» CVE   |
| **trivy**         | `trivy fs --scanners vuln,secret .`                  | 0 hard-coded secrets   |
| **cargo-audit**   | `cargo audit --deny warnings`                        | 0 unpatched RUSTSEC    |
| **syft + cosign** | `syft dir:/ -o cyclonedx-json` → `cosign attest ...` | SBOM publisert i Rekor |

---

## 4 · Manuell kodegjennomgang

1. **Crypto-primitives** (Kyber-1024, Dilithium-III):
   – Diff mot reference KAT; ingen «unsafe» blokker.
2. **ZK-circuits (Halo2 + STARK)**:
   – Sjekk constraints ≤ gas-budsjett (ref: 05 §2.3).
3. **Solidity-kontrakter**:
   – Re-entrancy, overflow, access-kontroll.
4. **Rust CLI**:
   – `#![forbid(unsafe_code)]` håndhevet, memory-sikkerhet.

---

## 5 · Timing- & Sidekanals-sjekk 🆕

| Punkt                  | Test                                | Pass-kriterium                         |
| ---------------------- | ----------------------------------- | -------------------------------------- |
| **Cache timing**       | `valgrind --tool=cachegrind` + diff | ≤ 5 % varians                          |
| **Blinded arithmetic** | Review Dilithium, Kyber impl.       | Alle big-int ops konstant-tid          |
| **EM & Power**         | Lab oscilloskop > 1 GHz             | Ingen korrelasjons-lekkasje (p > 0.05) |
| **Network burst**      | Dummy-trafikk på                    | Faktisk TX rate ±10 % av baseline      |

---

## 6 · Firmware & Chain-of-Trust Verifikasjon 🆕

1. **LVFS-manifest signatur**:
   `fwupdmgr get-history --json` → sig = valid.
2. **sbctl verify** (§5 i 02):
   – GRUB, shim, kernel image hash-match.
3. **PCR-log** sammenlignes mot golden JSON.
4. **Rekor-innslag** for hver firmware-SBOM.

---

## 7 · Avhengighets-locking & Reproducible Builds 🆕

| Artefakt | Lock-fil              | Kontroll                         |
| -------- | --------------------- | -------------------------------- |
| Rust     | `Cargo.lock`          | `--locked` flag i CI             |
| Nix      | `flake.lock`          | SHA-256 pinned                   |
| Node-JS  | `pnpm-lock.yaml` (UI) | `pnpm install --frozen-lockfile` |
| Docker   | Immutable digest      | `FROM ghcr.io/...@sha256:<hash>` |

CI sjekker diff; endring = «no-go» før manuell review.

---

## 8 · Bug-Bounty-Program (utvidet scope) 🆕

| Scope-område               | Max Payout  | Notat                           |
| -------------------------- | ----------- | ------------------------------- |
| Remote RCE, key-exfil      | 50 000 USDT | Enklave breakout inkl. SGX, SNP |
| Timing/sidechannel         | 20 000 USDT | EM, cache, power                |
| Supply-chain compromise    | 20 000 USDT | Malicious dep/firmware          |
| ZK-soundness break         | 25 000 USDT | Fake proof passes verifier      |
| Anonymitet-deanonymisering | 15 000 USDT | Mixnet or dummy-bypass          |

Rapporter via `https://hackerone.com/qs-wallet` — PGP-kryptert.

---

## 9 · Akseptkriterier (scorekort)

| Kategori           | Maks    | Min Pass | Vekt |
| ------------------ | ------- | -------- | ---- |
| CVE Score          | 30      | 27       | 0.30 |
| Side-kanal         | 20      | 18       | 0.20 |
| Supply-chain       | 20      | 18       | 0.20 |
| ZK-Proof soundness | 15      | 14       | 0.15 |
| Smart-contract gas | 15      | 14       | 0.15 |
| **Total**          | **100** | **91**   |      |

---

## 10 · Leveranser & rapportering

* **PDF-rapport** (gpg-signert)
* **Issue-tracker CSV** med severity & patch-status
* **Attestasjoner**: SLSA-provenance, SBOM-hash
* **Final scorekort** – §9 signert av auditor og CTO

---

## 11 · Vedlegg A – Audit-tidslinje

| Dag | Aktivitet                   |
| --- | --------------------------- |
| -14 | Kick-off call, scope freeze |
| -7  | Static-analyse & CVE-scan   |
| -5  | Manual review start         |
| -2  | Side-kanal lab-test         |
| 0   | Findings draft → Dev        |
| +2  | Patch-retest                |
| +5  | Final report                |

---

## 12 · Vedlegg B – Kontaktmatrise

| Rolle        | Navn (alias) | Key-ID     |
| ------------ | ------------ | ---------- |
| Lead Auditor | «owlsec»     | 0xA1B2C3D4 |
| CTO          | «lynx»       | 0xE5F6A7B8 |
| Sec-Lead     | «orca»       | 0xC0FFEE02 |

---

> **Oppdatert:** 5 aug 2025 — innført sidekanal-sjekk §5, firmware chain-of-trust §6, lockfile-policy §7, samt utvidet bug-bounty-scope.
