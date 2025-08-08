title: "opBNB Quantum-Secure ZK Privacy Wallet – 01_project-overview"
version: "v3.0"
status: "authoritative"
last\_updated: "2025-08-05"
owners:

* handle: "@core-arch"
* handle: "@zk-lead"
* handle: "@infra-sec"
  targets:
* runtime: "opBNB (EVM L2)"
* client\_os: "Ubuntu 22.04 LTS"
* enclaves: \["Intel SGX", "AMD SEV-SNP", "Arm CCA"]
* cpu: "x86\_64/AVX2 eller aarch64/NEON"
  principles:
* non\_custodial: true
* post\_quantum: true
* on\_chain\_unlinkability: mandatory
* reproducible\_builds: mandatory
* zero\_trust: "client/enclave-only keys"
  dependencies\_defined\_in: \["02\_ubuntu-22.04\_setup.md", "03\_pq-crypto\_stack.md", "04\_zk-circuits\_halo2\_stark.md"]
  artifact\_policy:
  encrypted\_artifacts: false
  key\_material\_persistence: "none (RAM-only/enclave-only)"
  build\_pin: "nix flake + lockfiles; Docker digests pinned"
  security\_gates:
* "No network anonymity → block"
* "Attestation fail → block"
* "Anonymity set < 128 real participants → block"
* "System clock skew > 2 s → block"
* "Kernel/root integrity fail → block"

---

# 1  Oversikt

Dokumentet er **kilden til sannhet** for prosjekt­struktur, arbeids­rekkefølge og milepæler. Installasjon og versjonspinning ligger i `02_ubuntu-22.04_setup.md`, PQ-KI i `03_pq-crypto_stack.md`, ZK-stack i `04_zk-circuits_halo2_stark.md`.

---

# 2  Mappestruktur

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
│  ├─ chains/opbnb-mainnet.json
│  ├─ chains/opbnb-testnet.json
│  ├─ opsec/thresholds.yaml
│  ├─ opsec/policy.rego
│  ├─ tor/torrc
│  ├─ tor/bridges.txt
│  ├─ mixnet/sphinx.toml
│  ├─ mixnet/nodes.list
│  ├─ wg/client.conf.tpl
│  ├─ wg/peers.list
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
├─ docs/01_project-overview.md     ← denne fila
│   … (02–10 .md følger)
├─ contracts/
│  ├─ foundry.toml
│  ├─ src/ShieldedPool.sol
│  ├─ src/DecoyBatcher.sol
│  ├─ src/ThresholdPaymaster.sol
│  ├─ src/libraries/…
│  ├─ src/interfaces/…
│  └─ test/…
├─ circuits/
│  ├─ halo2/…
│  ├─ stark-agg/…
│  └─ params/
├─ client/
│  ├─ cli/src/…
│  ├─ enclave/sgx/…
│  └─ tests/…
├─ pq/…   (Kyber + Dilithium bindings)
├─ interfaces/abi & grpc
├─ aggregator/…
├─ test-harness/docker-compose.yml
└─ ci/workflows/*.yml

---

# 3  Arkitektur på høyt nivå

* **On-chain:** `ShieldedPool.sol`, `DecoyBatcher.sol`, `ThresholdPaymaster.sol`.
* **Off-chain:** Rust-CLI med enclave-shims; Halo2-bevis per transaksjon; daglig STARK-batch.
* **PQ-KI:** Kyber-DH stealth-adresser; Dilithium-5 threshold-signering.
* **Lag-0 anonymitet:** Mixnet + Tor/I2P, 6 hopp, dummy-trafikk kontinuerlig.

---

# 4  Arbeidsrekkefølge

1. **Base-image & toolchain** – `02_ubuntu-22.04_setup.md`
2. **PQ-stack** – `03_pq-crypto_stack.md`
git clone git@github.com:org/opbnb-qs-privacy-wallet.git
cd opbnb-qs-privacy-wallet
make bootstrap
nix develop -c bash
make doctor
3. **Halo2-circuits** – `04_zk-circuits_halo2_stark.md`
4. **STARK-aggregator**
5. **Solidity-kontrakter** – `05_smart_contracts.md`
6. **CLI + Enclave** – `06_cli_client.md`
7. **Test & Formell bevis** – `07_tests_formal-verify.md`
8. **CI/CD & release** – `08_ci_cd_deploy.md`
9. **Audit-forberedelser** – `09_security_audit_checklist.md`
10. **Bruker-/drifts­dokumentasjon** – `10_user_ops_docs.md`

---

# 5  Make-mål (utdrag)

* `make doctor` → verifiser miljø & OPSEC
* `make fmt`  → formatter hele repo
* `make test` → Rust + Foundry tester
* `make prove` → Halo2-benchmarks
* `make aggregate` → STARK batch
* `make e2e`  → full docker-scenario
* `make release` → signerte artefakter + SLSA provenance

---

# 6  Kvalitetsporter

* Reproduserbar Nix-build
* SGX/SEV/CCA-attestasjon OK
* Anonymitetssett ≥ 128
* Nøkkelrotasjon ≤ 90 d
* Dekningskrav: Rust ≥ 85 %, Solidity ≥ 90 %

---

# 7  Trusselmodell (kort)

| Angriper             | Kapabilitet             | Mottiltak                           |
| -------------------- | ----------------------- | ----------------------------------- |
| Global passiv/aktiv  | Full nett­overvåkning   | Mixnet + Tor; dummy-trafikk         |
| Kvantedatamaskin     | Lattice-angrep          | Kyber1024 & Dilithium-5             |
| Node-operator        | Censur, gas-fingerprint | Threshold Paymaster, shadow-batches |
| Klient-kompromiss    | Disk/­persistens        | RAM-only keys; attestation-gates    |
| Statistisk deanonym. | Store datasett          | Fuzzy-commit, batching              |

---

# 8  Kodestandard

* Rust 2021, `rustfmt`, `clippy -D warnings`.
* Solidity 0.8.31, `via-IR`, optimizer 1 000 000 runs.
* Konvensjonelle commits med signatur.

---

# 9  Artefakter & release

* `qsw`-binær (x86\_64 & aarch64)
* Kontrakt-ABIs + deployments JSON
* Ingen trusted-setup-nøkler i repo; lokal cache git-ignored.
* SBOM + SLSA provenance lastes opp som release-assets.

---

# 10  Sjekklister (utdrag)

### Base & PQ

* [ ] `make doctor` grønt
* [ ] Kyber/Dilithium vektortester pass

### ZK

* [ ] Halo2-constraints ≥ 95 % dekket
* [ ] STARK batch < 2 s per 1 000 tx

### On-chain

* [ ] `forge test` grønt, gas ≤ mål

### Klient/OPSEC

* [ ] Attestasjon validert
* [ ] OPSEC-gates demonstrert

### Release

* [ ] Reproduserbare binærer + cosign-signatur

---

# 11  Vedlikehold & eierskap

* Arkitektur: **@core-arch**
* ZK-stack: **@zk-lead**
* Infra/CI: **@infra-sec**
* PR-regler: minst to godkjenninger, én må være domenefaglig ansvarlig.

---

# 12  Hurtigstart for nye bidragsytere

git clone git@github.com:org/opbnb-qs-privacy-wallet.git
cd opbnb-qs-privacy-wallet
make bootstrap
nix develop -c bash
make doctor

Les deretter `02_ubuntu-22.04_setup.md` → `03_pq-crypto_stack.md` → `04_zk-circuits_halo2_stark.md`.

---

# 13  Ordliste

* **Stealth-adresse:** engangs-adresse fra Kyber-DH.
* **Nullifier:** bevisbar markør for én-gangs forbruk av note.
* **Fuzzy commit:** beløps-obfuskering.
* **Batch-aggregasjon:** samling av Halo2-bevis i én STARK-bevis.

---

# 14  Referanser

Se dokumentene 02–10 for detaljer om miljø, kryptografi, ZK, kontrakter, klient, CI/CD, audit og bruker­drift.
