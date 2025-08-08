title: "04_zk-circuits_halo2_stark"
version: "v3.0"
status: "authoritative"
last\_updated: "2025-08-05"
audience: "ZK / Cryptography / GPU-infra"
scope:
  - Per-tx Halo2 zk-SNARK (transparent, no trusted setup)
  - GPU-akselerert prover (ICICLE-Halo2 v2)
  - Batch-aggregasjon til zk-STARK (Winterfell v0.13 + StarkPack)
  - Solidity verifier-binding + on-chain recursion
pinned\_versions:
  halo2\_proofs: "0.3.1"
  halo2\_gadgets: "0.3.1"
  icicle\_halo2: "v2.0.0"
  winterfell: "0.13.1"
  starkpack: "0.2.0"
gpu\_targets:
  nvidia: "CUDA 12.5 (driver ≥ 555)"
  amd:    "ROCm 6.0"
  intel:  "oneAPI 2025.1 (beta ICICLE branch)"

---

## 0  Mål

| KPI                         | SLO (CPU)   | SLO (GPU) |
| --------------------------- | ----------- | --------- |
| Halo2-proving (1 tx)        | ≤ 420 ms    | ≤ 35 ms   |
| STARK-batch (1 000 tx)      | ≤ 22 s      | ≤ 1.8 s   |
| Halo2-verifisering on-chain | ≤ 230 k gas | –         |
| Aggregert STARK-verify      | ≤ 7 ms CPU  | –         |

---

## 1  Mappe- og modul-tre

circuits/
├─ Cargo.toml            # workspace
├─ halo2/                # per-tx circuits
│  ├─ Cargo.toml
│  ├─ build.rs
│  └─ src/
│     ├─ sig_proof.rs
│     ├─ note_commit.rs
│     ├─ nullifier.rs
│     ├─ range_fuzzy.rs
│     ├─ merkle_membership.rs
│     ├─ batching_constraints.rs
│     └─ poseidon.rs
├─ stark-agg/            # batch-aggregator
│  ├─ Cargo.toml
│  └─ src/
│     ├─ halo2_adapter.rs
│     ├─ trace.rs
│     ├─ fri.rs
│     ├─ commitments.rs
│     └─ gpu_backend.rs
├─ benches/
│  └─ batch_bench.rs
└─ params/
   ├─ kzg-free.txt
   └─ cache/.gitkeep

---

## 2  `circuits/Cargo.toml` (utdrag)

[workspace]
members = ["halo2", "stark-agg"]

[patch.crates-io]
halo2_proofs = { package = "icicle-halo2",
                 git = "https://github.com/ingonyama-zk/icicle-halo2",
                 tag = "v2.0.0" }

---

## 3  Halo2 – design & implementasjon

| Chip                   | Rows | Cols |  Gates  | Forklaring                                    |
| ---------------------- | :--: | :--: | :-----: | --------------------------------------------- |
| SigProofChip           | 22 k |  16  | ≈ 200 k | ZK-bevis for ML-DSA-signatur uten PK-lekkasje |
| NoteCommitChip         | 12 k |  12  | ≈ 140 k | Poseidon-hash av stealth-PK‖note\_r           |
| NullifierChip          |  6 k |   8  |  ≈ 60 k | Hindre dobbel-bruk                            |
| RangeFuzzyChip         |  4 k |   6  |  ≈ 48 k | Beløps-obfuskering                            |
| MerkleMembershipChip   |  3 k |   8  |  ≈ 40 k | Merkle-sti (dyp 32)                           |
| BatchingConstraintChip |  2 k |   4  |  ≈ 20 k | Multi-tx inflation-sjekk                      |

### 3.1  `build.rs`

fn main() {
    if std::env::var("CARGO_FEATURE_GPU").is_ok() ||
       std::env::var("ICICLE").is_ok() {
        println!("cargo:rustc-cfg=feature=\"gpu\"");
    }
}

Bygg GPU-variant:
`cargo build --release --features gpu`

---

## 4  zk-STARK batch-aggregator

### 4.1  Arkitektur

1. **halo2\_adapter** serialiserer bevis → feltelementer.
2. **Trace builder** fyller Winterfell AIR.
3. **FRI + StarkPack** pakker 1 000 Halo2-bevis i én STARK.
4. **VerifierStark.sol** kaller Bedrock FRI-precompile.

### 4.2  `stark-agg/Cargo.toml` (utdrag)

[package]
name = "stark-agg"
edition = "2021"

[dependencies]
winterfell = { version = "0.13.1",
               default-features = false,
               features = ["concurrent"] }
starkpack  = "0.2"
blake3     = "1.5"
halo2_proofs = { workspace = true }
rayon      = "1"
cuda-sys   = { version = "0.3", optional = true }

[features]
default = ["cuda"]
cuda    = ["cuda-sys"]


## 5  GPU-backend

| Flag         | Feature                 | Krav          |
| ------------ | ----------------------- | ------------- |
| `gpu_nvidia` | `--features gpu,cuda`   | CUDA ≥ 12.5   |
| `gpu_amd`    | `--features gpu,rocm`   | ROCm 6.0      |
| `gpu_intel`  | `--features gpu,oneapi` | oneAPI 2025.1 |

---

## 6  Benchmarks

`tools/zk/bench.sh`:

#!/usr/bin/env bash
set -euo pipefail
export RUSTFLAGS="-C target-cpu=native"
cargo bench -p halo2 --features gpu --bench all
cargo bench -p stark-agg --bench batch_bench

HTML-rapporter i `target/criterion/reports/`.

---

## 7  Solidity-verifier binding

Genereres med:

forge run --ffi scripts/codegen/halo2_sol_gen.rs \
  --sig proofs/halo2_vk.json \
  --out contracts/src/libraries/VerifierHalo2.sol

Gass­mål: 230 k gas.

---

## 8  Test-matrise

| Test              | Fil                                       | Dekning             |
| ----------------- | ----------------------------------------- | ------------------- |
| Circuit KAT       | `halo2/tests/kat.rs`                      | 100 %               |
| Constraint-sanity | `halo2/tests/sanity.rs`                   | ≥ 95 %              |
| GPU vs CPU likhet | `halo2/tests/gpu_cpu.rs`                  | SHA-256-hash        |
| STARK korrekthet  | `stark-agg/tests/proof.rs`                | 128-bit             |
| Solidity-verifier | `contracts/test/Verifier.t.sol`           | 3 cases             |
| E2E 10 000 tx     | `test-harness/scenarios/heavy_decoy.toml` | Latens & anonymitet |

---

## 9  Formelle bevis-hooks

* Halo2-gadgets → `r1cs.json` for Coq.
* Winterfell AIR → Isabelle-teorem.

---

## 10  “✅ Done when”

* Halo2 tester (GPU) grønt på x86\_64 & ARM
* GPU-prove ≤ 35 ms @ RTX 5090
* STARK batch 1 000 tx < 2 s
* Solidity-verify gas ≤ 230 k
* Bench-HTML lastet opp i CI
* Forge test integrasjon grønt
* Formelle bevis passert

---

## 11  Neste steg

Gå til **05\_smart\_contracts.md** for ABI-generering, Foundry property-tests og gas-optimering.
