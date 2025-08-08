title: "opBNB Quantum-Secure ZK Privacy Wallet – 01_project-overview"
version: "v3.0"
status: "authoritative"
last_updated: "2025-08-05"
owners:
  - handle: "@core-arch"
  - handle: "@zk-lead"
  - handle: "@infra-sec"
targets:
  - runtime: "opBNB (EVM L2)"
  - client_os: "Ubuntu 22.04 LTS (server/desktop)"
  - enclaves: ["Intel SGX", "AMD SEV-SNP", "Arm CCA"]
  - cpu: "x86_64/AVX2, aarch64/NEON"
principles:
  - non_custodial: true
  - post_quantum: true
  - on_chain_unlinkability: "mandatory"
  - reproducible_builds: "mandatory"
  - zero_trust: "client/enclave-only keys"
dependencies_defined_in: ["02_ubuntu-22.04_setup.md", "03_pq-crypto_stack.md", "04_zk-circuits_halo2_stark.md"]
artifact_policy:
  encrypted_artifacts: false
  key_material_persistence: "none (RAM-only/enclave-only)"
  build_pin: "nix flake + lockfiles; Docker digests pinned"
security_gates:
  - "No network anonymity → block"
  - "Attestation fail → block"
  - "Anonymity set < 128 real participants → block"
  - "System clock skew > 2s → block"
  - "Kernel/root integrity fail → block"
---

# 1. Oversikt

Dette dokumentet er **kilden til sannhet** for prosjektstruktur, arbeidsrekkefølge og milepæler.  
All praktisk installasjon, versjonspinning og kommandolinjer ligger i `02_ubuntu-22.04_setup.md` (vert), `03_pq-crypto_stack.md` (PQ-KI) og `04_zk-circuits_halo2_stark.md` (ZK).  
Denne fila gir deg **tre-visning**, **ansvarsdeling**, **build-/test-orkestrering**, og **release-kriterier**.

---

# 2. Mappestruktur (autoritativ)

> **Merk:** Alle filer finnes som stubs med `// TODO` eller minimal boilerplate når repo initialiseres.  
> Fil-/mappenavn er stabile; interne implementasjonsdetaljer kan endres per modul.

```text
opbnb-qs-privacy-wallet/
├─ .editorconfig
├─ .gitattributes
├─ .gitignore
├─ LICENSE
├─ README.md
├─ SECURITY.md
├─ CODEOWNERS
├─ CONTRIBUTING.md
├─ Makefile
├─ flake.nix
├─ flake.lock
├─ docker/
│  ├─ dev.Dockerfile
│  ├─ ci.Dockerfile
│  └─ runtime.Dockerfile
├─ nix/
│  ├─ overlays.nix
│  ├─ packages.nix
│  └─ shells.nix
├─ configs/
│  ├─ chains/
│  │  ├─ opbnb-mainnet.json
│  │  └─ opbnb-testnet.json
│  ├─ opsec/
│  │  ├─ thresholds.yaml            # anonymitetssett, jitter, dummy-kvoter
│  │  └─ policy.rego                # OPA/Conftest policy for OPSEC-gates
│  ├─ tor/
│  │  ├─ torrc
│  │  └─ bridges.txt
│  ├─ mixnet/
│  │  ├─ sphinx.toml
│  │  └─ nodes.list
│  ├─ wg/
│  │  ├─ client.conf.tpl            # Noise IKpsk2 (WireGuard-style)
│  │  └─ peers.list
│  └─ attestation/
│     ├─ sgx/spid.conf.tpl
│     ├─ sev-snp/policy.json
│     └─ arm-cca/policy.json
├─ scripts/
│  ├─ devnet/anvil-up.sh
│  ├─ devnet/anvil-down.sh
│  ├─ ops/attest-verify.sh
│  ├─ ops/rekor-verify.sh
│  ├─ ops/sbom-generate.sh
│  ├─ ops/slsa-provenance.sh
│  └─ rel/pack-release.sh
├─ docs/
│  ├─ 01_project-overview.md        # (denne fila)
│  ├─ 02_ubuntu-22.04_setup.md
│  ├─ 03_pq-crypto_stack.md
│  ├─ 04_zk-circuits_halo2_stark.md
│  ├─ 05_smart_contracts.md
│  ├─ 06_cli_client.md
│  ├─ 07_tests_formal-verify.md
│  ├─ 08_ci_cd_deploy.md
│  ├─ 09_security_audit_checklist.md
│  └─ 10_user_ops_docs.md
├─ contracts/                       # Solidity (Foundry)
│  ├─ foundry.toml
│  ├─ lib/                          # vendored via forge remappings
│  ├─ src/
│  │  ├─ ShieldedPool.sol
│  │  ├─ DecoyBatcher.sol
│  │  ├─ ThresholdPaymaster.sol
│  │  ├─ libraries/
│  │  │  ├─ Notes.sol
│  │  │  ├─ Poseidon.sol
│  │  │  ├─ Merkle.sol
│  │  │  └─ VerifierHalo2.sol      # verifier binding (sol)
│  │  └─ interfaces/
│  │     ├─ IShieldedPool.sol
│  │     ├─ IDecoyBatcher.sol
│  │     └─ IThresholdPaymaster.sol
│  └─ test/
│     ├─ ShieldedPool.t.sol
│     ├─ DecoyBatcher.t.sol
│     ├─ ThresholdPaymaster.t.sol
│     └─ Integration.t.sol
├─ circuits/                        # Rust (Halo2) + zk-STARK aggregator
│  ├─ Cargo.toml
│  ├─ Cargo.lock
│  ├─ halo2/
│  │  ├─ Cargo.toml
│  │  ├─ src/
│  │  │  ├─ sig_proof.rs            # ZK bevis for PQ-signatur (ML-DSA) uten PK on-chain
│  │  │  ├─ note_commit.rs
│  │  │  ├─ nullifier.rs
│  │  │  ├─ range_fuzzy.rs
│  │  │  ├─ merkle_membership.rs
│  │  │  ├─ batching_constraints.rs
│  │  │  └─ poseidon.rs
│  │  └─ benches/
│  │     └─ halo2_benches.rs
│  ├─ stark-agg/
│  │  ├─ Cargo.toml
│  │  ├─ src/
│  │  │  ├─ trace.rs
│  │  │  ├─ fri.rs
│  │  │  ├─ commitments.rs
│  │  │  ├─ halo2_adapter.rs        # aggregator for halo2 bevis → STARK batch
│  │  │  └─ gpu_backend.rs
│  │  └─ benches/
│  │     └─ stark_benches.rs
│  └─ params/
│     ├─ kZG-free.txt               # dokumentasjon (transparent setup)
│     └─ cache/.gitkeep             # lokal cache (ikke versjonertes artefakter)
├─ client/                          # Rust + C (enclave shims)
│  ├─ Cargo.toml
│  ├─ Cargo.lock
│  ├─ cli/                          # binær: qsw (Quantum Secure Wallet)
│  │  ├─ src/
│  │  │  ├─ main.rs
│  │  │  ├─ ops/
│  │  │  │  ├─ deposit.rs
│  │  │  │  ├─ transfer.rs
│  │  │  │  ├─ withdraw.rs
│  │  │  │  ├─ sync.rs
│  │  │  │  └─ health.rs
│  │  │  ├─ net/
│  │  │  │  ├─ tor.rs
│  │  │  │  ├─ mixnet.rs
│  │  │  │  ├─ wg_noise.rs
│  │  │  │  └─ fallback_i2p.rs
│  │  │  ├─ enclave/
│  │  │  │  ├─ keystore.rs          # RAM-only handle
│  │  │  │  ├─ attest.rs
│  │  │  │  └─ ipc.rs
│  │  │  ├─ zk/
│  │  │  │  ├─ prove.rs             # Halo2 call-out
│  │  │  │  └─ aggregate.rs         # STARK batch trigger
│  │  │  ├─ opsec/
│  │  │  │  ├─ checks.rs            # gates (policy.rego + local telemetry)
│  │  │  │  └─ jitter.rs
│  │  │  ├─ airgap/
│  │  │  │  ├─ qr_encode.rs
│  │  │  │  └─ ultrasonic.rs
│  │  │  └─ ui.rs                   # TUI (ratatui) m/logikk for nekting
│  │  └─ build.rs
│  ├─ enclave/                      # SGX/SEV/CCA shims
│  │  ├─ sgx/
│  │  │  ├─ Enclave.edl
│  │  │  ├─ src/lib.rs
│  │  │  └─ build.rs
│  │  ├─ sev-snp/
│  │  │  └─ src/lib.rs
│  │  └─ arm-cca/
│  │     └─ src/lib.rs
│  └─ tests/
│     ├─ opsec_block.rs
│     ├─ enclave_attest.rs
│     └─ e2e_flow.rs
├─ pq/                               # Post-Quantum KI (bindings + threshold)
│  ├─ Cargo.toml
│  ├─ src/
│  │  ├─ kyber.rs
│  │  ├─ dilithium.rs
│  │  ├─ threshold_dsa.rs
│  │  ├─ hkdf.rs
│  │  └─ stealth_addr.rs            # Kyber-DH engangsadresser
│  └─ benches/
│     └─ pq_benches.rs
├─ interfaces/                       # Cross-boundary proto/ABI/IDL
│  ├─ abi/
│  │  ├─ ShieldedPool.json
│  │  ├─ DecoyBatcher.json
│  │  └─ ThresholdPaymaster.json
│  ├─ grpc/
│  │  └─ aggregator.proto
│  └─ ipc/
│     └─ enclave.ipc
├─ aggregator/                       # Off-chain batcher + L2 submitter
│  ├─ Cargo.toml
│  ├─ src/
│  │  ├─ watcher.rs
│  │  ├─ decoy_scheduler.rs
│  │  ├─ stark_batcher.rs
│  │  ├─ l2_submit.rs
│  │  └─ paymaster_mesh.rs
│  └─ tests/
│     └─ batch_policy.rs
├─ test-harness/
│  ├─ docker-compose.yml             # opBNB RPC, anvil mirror, mock mixnet
│  ├─ fixtures/
│  │  └─ notes.json
│  └─ scenarios/
│     ├─ deposit_withdraw.toml
│     └─ heavy_decoy.toml
├─ ci/
│  ├─ workflows/
│  │  ├─ build.yml
│  │  ├─ test.yml
│  │  ├─ lint.yml
│  │  ├─ prov-slsa.yml
│  │  └─ release.yml
│  └─ policies/
│     └─ attestation.rego
└─ tools/
   ├─ zk/
   │  └─ bench.sh
   ├─ codegen/
   │  └─ abi_export.rs
   └─ diagnostics/
      └─ net_trace.rs

# 3. Arkitektur på høyt nivå

**On-chain (Solidity):**

* `ShieldedPool`: notekring, commitments/nullifiers, inn/ut-flyt (ingen PK on-chain).
* `DecoyBatcher`: Poisson-jitter, dummy-noter, batch-regler (≥16 ekte / ≥80 dummy).
* `ThresholdPaymaster`: gas via Dilithium-threshold; anti-fingerprint.

**Off-chain:**

* **CLI/TUI** (`client/cli`): transaksjonsorchestrering, OPSEC-gates, air-gap utskrift (QR/ultralyd).
* **Enclave shims** (`client/enclave`): RAM-only nøkkelhåndtering og attestasjon.
* **ZK** (`circuits/halo2`, `circuits/stark-agg`): per-tx Halo2 + daglig STARK-aggregasjon.
* **Aggregator** (`aggregator`): følger mempool, fyller dummy-kvoter, samler bevis og sender batch.

**PQ-KI** (`/pq`):

* Kyber-basert DH for stealth-adresser, Dilithium for signatur/threshold-DSA.
* Hybrid-rotasjon og HKDF for nøkkelavledning; rotasjon hver 90. dag (enforced i CLI).

**Lag-0 anonymitet:**

* Mixnet + Tor/I2P/HORNET fallback; 6 hopp; WireGuard-lignende Noise-kryptering mellom klient⇄mirrors.

---

# 4. Arbeidsrekkefølge (fra ren maskin → mainnet)

1. **Base image og toolchain**
   `02_ubuntu-22.04_setup.md` → installer kernel-støtte, Docker/Nix, Rust/Node/Go/Python, GPU-drivere (valgfritt).
   ✅ *Done when*: `nix develop` og `make doctor` passerer.

2. **PQ-stack**
   `03_pq-crypto_stack.md` → bygg liboqs/bindings, kjør `cargo bench -p pq`.
   ✅ *Done when*: Kyber/Dilithium vektor-tester og threshold-simulasjon består.

3. **Halo2-circuits**
   `04_zk-circuits_halo2_stark.md` → implementer `sig_proof.rs`, `note_commit.rs`, `nullifier.rs`, `range_fuzzy.rs`.
   ✅ *Done when*: `tools/zk/bench.sh` < T\_gitt og `circuits/halo2` tester består.

4. **STARK-aggregator**
   Implementer `halo2_adapter.rs` og `stark_batcher.rs`; konfigurer GPU-backend.
   ✅ *Done when*: batch-bevis (< X sek/1000 tx) og verifikator-test passerer.

5. **Kontrakter**
   `05_smart_contracts.md` → skriv kontrakter, Foundry-tester, deploy-skript for testnet.
   ✅ *Done when*: `forge test -vvv` grønt og `forge script` gjør tørrkjøring OK.

6. **CLI + Enclave**
   `06_cli_client.md` → implementer OPSEC-gates, attestasjonsflyt, air-gap I/O.
   ✅ *Done when*: `client/tests/*` + end-to-end scenarioer i `test-harness` er grønne.

7. **CI/CD og artefakter**
   `08_ci_cd_deploy.md` → GitHub Actions (build/test/lint/bench/SBOM/SLSA), release bundles.
   ✅ *Done when*: signed, reproducible artefakter med provenance.

8. **Sikkerhet + Audit**
   `09_security_audit_checklist.md` → threat-model, formell verifikasjon (Coq/Isabelle stubs), ekstern audit-booking.
   ✅ *Done when*: pre-audit sjekker og bug-bounty program aktivt.

9. **Sluttbruker og drift**
   `10_user_ops_docs.md` → brukerflow, recovery, feilsøking.
   ✅ *Done when*: intern brukertest og opBNB testnet-pilot.

---

# 5. Bygg, kjør og test (top-level)

> **Første gangs oppsett**: Følg `02_ubuntu-22.04_setup.md`. Nedenfor er *orkestrering*.

## 5.1 Kommandoer (Makefile, høyeste nivå)

# Sikkerhets-sjekk og miljø
doctor:               ## Verifiser toolchain, GPU, kernel og policy
bootstrap:            ## Hent submodules, installer hooks, pre-commit
fmt:                  ## Formatér Rust/Solidity/Go/TOML/MD
lint:                 ## clippy + solhint + shellcheck + yamllint
sbom:                 ## Generer SBOM (syft)
prove:                ## Kjør Halo2 prover-benchmarks
aggregate:            ## STARK batch for siste runde
test:                 ## Alle tester (Rust + Foundry)
e2e:                  ## Test-harness scenarier (docker-compose)
release:              ## Bygg signerte artefakter + SLSA provenance

## 5.2 Lokalt dev-nett

make bootstrap
docker compose -f test-harness/docker-compose.yml up -d
./scripts/devnet/anvil-up.sh


## 5.3 Kjør hele rødløypa
# 1) PQ-stack
cargo test -p pq

# 2) Halo2 circuits
cargo test -p circuits-halo2
tools/zk/bench.sh

# 3) STARK aggregator
cargo test -p circuits-stark-agg
cargo bench -p circuits-stark-agg

# 4) Kontrakter
cd contracts && forge test -vvv

# 5) E2E
make e2e

# 6. Kvalitetsporter (mandatory)

* **Reproduserbarhet:** `nix build .#cli` må gi identisk hash på CI og lokalt.
* **Attestasjon:** `scripts/ops/attest-verify.sh` verifiserer SGX/SEV/CCA quotes.
* **OPSEC gates:** `client/cli` nekter hvis noen av: Tor/mixnet nede, lav anonymitet, attestasjonsfeil, klokkeavvik > 2s, root-modifikasjon.
* **Anonymitetssett:** Batcher blokkeres < 128 ekte deltakere; dummy≥80; jitter 0–120 min.
* **Kryptokonfig:** Kyber1024 + Dilithium-5; rotasjon <= 90 dager (automatisert sjekk i `client/cli`).
* **Statisk analyse:** `cargo audit`, `cargo deny`, `slither` for kontrakter.
* **Formell basis:** Lemma-stubs oppdatert og koblet til CI (se `07_tests_formal-verify.md`).

---

# 7. Trusselmodell (sammendrag)

| Angriper                   | Kapabilitet                       | Mottiltak                                              |
| -------------------------- | --------------------------------- | ------------------------------------------------------ |
| Global passiv/aktiv        | Full nettverksobservasjon, timing | Mixnet+Tor 6 hopp, dummy-trafikk, Poisson-jitter       |
| Kvantedatamaskin           | Lattice-målrettet                 | PQ-algoritmer (Kyber/Dilithium), ZK uten trusted setup |
| Node-operator              | Censur, gas-fingerprinting        | Threshold Paymaster, shadow-batches                    |
| Klient-kompromiss          | Disk/persistens                   | RAM-only/enclave-only, attestasjonsporter              |
| Statistisk deanonymisering | Store datasett                    | Fuzzy commits, batching, dummy-policies                |

---

# 8. Kodestandard og policy

* **Språk:** Rust (2021 edition), Solidity (>=0.8.20), litt C for enclave shims.
* **Stil:** `rustfmt`, `clippy -D warnings`, `solhint`, `pre-commit`.
* **Commits:** Conventional Commits; signerte commits (`git commit -S`); release-tag med provenance.
* **Secrets:** Aldri i repo. `.env` er forbudt; runtime via enclosures/attestation.
* **Issue labels:** `area/*`, `sec/*`, `zk/*`, `pq/*`, `good-first-issue`.

---

# 9. Artefakter og release

* **CLI binær:** `qsw` for linux-x86\_64 og linux-aarch64 (musl hvor mulig).
* **Kontrakt-pakker:** `interfaces/abi/*.json` + `deployments/*.json` (testnet/mainnet).
* **ZK:** ingen forhåndsgenererte nøkler; kun *cache* lokalt i `circuits/params/cache/` (gitignored).
* **Provenance:** SBOM + SLSA vouches lastes opp som release-assets.

---

# 10. Sjekklister (Done-when)

## 10.1 Base & PQ

* [ ] `make doctor` grønt på ren 22.04 vert.
* [ ] `cargo test -p pq` og benches innenfor SLO.

## 10.2 ZK

* [ ] Halo2 enhetstester grønt; constraints dekkes ≥95%.
* [ ] STARK batch ≤ mål-latens ved 1000 tx.

## 10.3 On-chain

* [ ] `forge test` grønt inkl. properties/fuzz.
* [ ] Gas-profilering innenfor budsjett.

## 10.4 Klient/OPSEC

* [ ] Attestasjon verifiseres mot valgt TEE.
* [ ] OPSEC-gates demonstrert (nekting ved feil).

## 10.5 E2E & Release

* [ ] `make e2e` alle scenarioer passert.
* [ ] Reproduserbare binærer + signerte releases.

---

# 11. Vedlikehold og eierskap

* **Arkitekturansvarlig:** `@core-arch` – endrer mappe/fil-kontrakter.
* **ZK-ansvarlig:** `@zk-lead` – endrer circuits/aggregator.
* **Infra-ansvarlig:** `@infra-sec` – endrer docker/nix/CI, OPSEC-policy.
* **Endringsprosess:** PR + to godkjenninger (arkitektur + domenefag). Breaking changes krever minor/major bump.

---

# 12. Hurtigstart (for nye bidragsytere)

git clone git@github.com:org/opbnb-qs-privacy-wallet.git
cd opbnb-qs-privacy-wallet
make bootstrap
nix develop -c bash
make doctor


Les deretter:

1. `02_ubuntu-22.04_setup.md` → installer vert.
2. `03_pq-crypto_stack.md` → PQ-stack.
3. `04_zk-circuits_halo2_stark.md` → ZK-circuits.

---

# 13. Ordliste

* **Stealth-adresse:** Engangs-adresse avledet via Kyber-DH.
* **Nullifier:** Bevisbar markør for én-gangs forbruk av note.
* **Fuzzy commit:** Beløps-obfuskering i commitment som motvirker linking.
* **Batch-aggregasjon:** Samling av mange Halo2-bevis i én STARK-bevis.

---

# 14. Referanser (interne)

* `05_smart_contracts.md` – ABI, interfaces, invariants.
* `06_cli_client.md` – OPSEC-gates, nettverksanonymitet.
* `07_tests_formal-verify.md` – testmatrise og formelle bevis.
* `08_ci_cd_deploy.md` – CI/CD, attestasjons-policy og deploy.
* `09_security_audit_checklist.md` – audit-forberedelser.
* `10_user_ops_docs.md` – bruker- og driftsmanual.


::contentReference[oaicite:0]{index=0}

