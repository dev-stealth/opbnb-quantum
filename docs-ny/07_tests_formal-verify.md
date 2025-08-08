---

title: "07\_tests\_formal-verify"
version: "v3.0"
status: "authoritative"
last\_updated: "2025-08-05"
audience: "QA / Formal-methods / Security-audit"
scope:

* Enhet-, property-, fuzz-, invariant- og E2E-tester
* Dekningskrav & CI-gates
* Formell verifikasjon (Coq 8.20, Isabelle 2025, Kani, SMT)
* Statisk analyse & differential fuzz
  pinned\_tools:
  rust\_test\_framework: "proptest 2.0"
  solidity\_test\_framework: "Foundry 1.10 (fuzz/invariant)"
  coverage: "cargo-tarpaulin 0.27"
  coq: "8.20.1 (17 Jan 2025)"
  isabelle: "Isabelle2025 (Mar 2025)"
  kani: "kani-verifier 0.33 (Rust 1.79 LTS)"
  echidna: "3.2.0 (Jun 2025)"

---

## 0  Formål

1. Sikre funksjonell korrekthet av PQ-crypto, ZK-cirkuits, kontrakter og klient.
2. Underbygge sikkerhets- og anonymitetsgarantier.
3. Overholde gas-, ytelses- og OPSEC-SLOer.
4. Maskinbevise sentrale egenskaper (uforgjengelig signatur, nullifier-unikhet, batch-invariant).

---

## 1  Mappestruktur

tests/
├─ rust/
│  ├─ pq/
│  │  ├─ vectors_dilithium.rs
│  │  ├─ vectors_kyber.rs
│  │  └─ property_pq.rs
│  ├─ circuits/
│  │  ├─ sanity.rs
│  │  ├─ gpu_cpu_equiv.rs
│  │  └─ bench.rs
│  ├─ client/
│  │  ├─ opsec_block.rs
│  │  └─ e2e_flow.rs
│  └─ aggregator/
│     └─ stark_correct.rs
├─ solidity/
│  ├─ ShieldedPool.t.sol
│  ├─ DecoyBatcher.t.sol
│  ├─ ThresholdPaymaster.t.sol
│  └─ Integration.t.sol
└─ formal/
   ├─ coq/
   │  ├─ SigSchemeNF.v
   │  └─ HKDF_PRF.v
   ├─ isabelle/
   │  └─ StarkBatch.thy
   ├─ kani/
   │  └─ hkdf_harness.rs
   └─ smt/
      └─ pool_invariant.smt2

## 2  Rust-tester

| Modul           | Rammeverk                           | Dekning & mål                              |
| --------------- | ----------------------------------- | ------------------------------------------ |
| **pq/**         | proptest 2.0 – 2 000 cases per prop | Sign ⊕ verify = true, KEM enc/dec symmetri |
| **circuits/**   | custom Halo2 harness                | 0 constraints unsatisfied                  |
| **aggregator/** | proptest + Winterfell               | Batch ≥ 1 000 bevis, verify = true         |
| **client/**     | tokio integration                   | OPSEC-gates blokkerer ved brudd            |

Krav: `cargo tarpaulin --branches --fail-under 85`.

### 2.1  Eksempel – Dilithium property-test

#[proptest]
fn sign_verify_holds(msg in proptest::collection::vec(any::<u8>(), 1..1024)) {
    let (pk, sk) = pq::dilithium::keygen();
    let sig = pq::dilithium::sign(&msg, &sk);
    prop_assert!(pq::dilithium::verify(&msg, &sig, &pk));
}

## 3  Solidity-tester (Foundry)

| Type                   | Antall | Fokus                                |
| ---------------------- | -----: | ------------------------------------ |
| Unit                   |     42 | Edge-cases                           |
| Fuzz                   |     18 | Input-perm.                          |
| Invariant              |      6 | Nullifier-unikhet, saldo-likevekt    |
| Differential (Echidna) |      4 | ERC-20 re-entrancy, Paymaster-refund |

Dekning: `forge coverage` ≥ 90 %.

---

## 4  Fuzz & differential-verktøy

* **Echidna 3.2** – Solidity differential fuzz
* **Medusa 0.8** – Storage-kollisjon
* **Hypothesis-Rust** – ZK-gadget range (valgfritt)

---

## 5  Formell verifikasjon

| Lag       | Verktøy                 | Egenskap                       |
| --------- | ----------------------- | ------------------------------ |
| PQ-KI     | **Kani**                | HKDF-PRF, FROST-unforgeability |
| Halo2     | Coq 8.20 + gnark-export | Circuit ≡ spec                 |
| STARK AIR | Isabelle2025            | Soundness & completeness       |
| Solidity  | SMTChecker, Scribble    | State safety                   |
| System    | TLA⁺ 2                  | Liveness (batch flush)         |

### 5.1  Coq-stub

Theorem Dilithium_FROST_unforgeable :
  forall (adv : Adversary), 
    Pr[Game_FROST adv] <= 2 ^ -128.

### 5.2  Isabelle-teorem

theory StarkBatch
imports Main
begin
theorem sound_batch:
  assumes "Winterfell.verify Π"
  shows   "⋀tx. tx ∈ Π ⟹ valid_tx tx"
end

### 5.3  Kani-harness

#[kani::proof]
fn hkdf_prf() {
    let ikm = kani::any_slice_of::<u8>();
    let salt = kani::any_slice_of::<u8>();
    let okm1 = pq::hkdf::extract_expand(ikm, salt);
    let okm2 = pq::hkdf::extract_expand(ikm, salt);
    assert_eq!(okm1, okm2);
}

## 6  CI-pipeline

1. `cargo test --workspace`
2. `tarpaulin --fail-under 85`
3. `forge test -vvv --invariant`
4. Echidna nightly fuzz
5. `make coq isa kani`
6. Static analyse: Slither, `cargo audit`, `cargo deny`
7. Artifact-upload: Criterion HTML, coverage, proof-logs

---

## 7  Deknings- & tids-SLO

| Lag           | Dekning                   | Maks tid (CI) |
| ------------- | ------------------------- | ------------- |
| Rust          | ≥ 85 % line / 80 % branch | 15 min        |
| Solidity      | ≥ 90 % runtime instr.     | 8 min         |
| ZK circuits   | ≥ 95 % constraints        | 6 min         |
| Formal proofs | må passere                | 25 min        |

---

## 8  “✅ Done when” sjekkliste

* [ ] `cargo test` & `forge test` grønt
* [ ] Tarpaulin ≥ 85 %, rapport lastet opp
* [ ] Minst tre invariants per kontrakt, ingen falsk-positiv
* [ ] Kani, Coq & Isabelle passer
* [ ] Criterion benchmark-HTML vedlagt
* [ ] 24 h Echidna-fuzz → 0 high severity
* [ ] Statisk analyse → 0 kritiske / høye CVE

---

## 9  Neste steg

Koble test- og proof-artefakter til SLSA provenance og release-workflow (se 08\_ci\_cd\_deploy.md).
