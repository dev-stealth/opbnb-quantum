title: "08_ci_cd_deploy"
version: "v3.0"
status: "authoritative"
last\_updated: "2025-08-05"
audience: "Dev-Ops / Release-Engineering"
scope:
  - GitHub Actions-pipelines (build → test → audit → release)
  - Reproduserbare Nix-/Docker-bygger (SLSA Level 3 provenance)
  - Artefakt-signering m/**cosign 2.5** & OIDC-keyless
  - SBOM & CVE-skanning (Syft + Grype)
  - TEE-attestasjon-verifisering (SGX/SEV/CCA)
ci\_platform: "github.com/org/opbnb-qs-privacy-wallet"
min\_runners:
  - ubuntu-22.04-x64 (GitHub-hosted)
  - ubuntu-22.04-arm64 (self-hosted, AWS Graviton 3)
  - gpu-nvidia (self-hosted, RTX 5090, CUDA 12.5)

---

## 0 Mål

| Leveranse                                | Kvalitet                       | Krav                  |
| ---------------------------------------- | ------------------------------ | --------------------- |
| *Binaries* (`qsw-x86_64`, `qsw-aarch64`) | byte-identisk hash lokalt & CI | Nix flake-lock        |
| *Contracts* (flattened + ABI)            | verified on testnet            | Slither 0 kritiske    |
| *Proof-artefakter* (Halo2, STARK)        | bundlet                        | size < 24 MB          |
| *SLSA provenance*                        | Level 3 attested               | slsa-github-generator |
| *Signaturer*                             | **cosign 2.5** keyless         | OIDC-token            |

---

## 1 Workflow-oversikt

| Workflow-fil      | Trigger      | Hovedjobber                                          |
| ----------------- | ------------ | ---------------------------------------------------- |
| **build.yml**     | PR & push    | Nix restore → build-matrix → upload artefakter       |
| **test.yml**      | PR & push    | Rust, Foundry, Tarpaulin, Coverage-gate              |
| **lint.yml**      | PR           | Clippy, Rustfmt, Solhint, Shellcheck, OPA / Conftest |
| **prov-slsa.yml** | push `main`  | SLSA L3 provenance (slsa-framework)                  |
| **release.yml**   | Git tag `v*` | Build → SBOM → cosign sign → GitHub Release          |

---

## 2 Bygg-workflow `.github/workflows/build.yml`

name: build
on:
  pull_request:
  push:
    branches: [main]
concurrency: build-${{ github.sha }}
jobs:
  nix-build:
    strategy:
      matrix:
        os: [ubuntu-22.04]
        arch: [x64, arm64]
    runs-on: ${{ matrix.os }}-${{ matrix.arch }}
    steps:
      - uses: actions/checkout@v4
      - uses: DeterminateSystems/nix-installer-action@v3.5.2
      - uses: nix-community/cache-nix-action@v1
      - name: Build (flake)
        run: nix build .#cli --print-out-paths
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: qsw-${{ matrix.arch }}
          path: result/

*(Self-hosted GPU-runner bygger med `ICICLE=1 nix build`.)*

---

## 3 Test-workflow `test.yml`

env:
  CARGO_TERM_COLOR: always
jobs:
  rust-tests:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: DeterminateSystems/nix-installer-action@v3.5.2
      - run: nix develop -c cargo test --workspace
  coverage:
    needs: rust-tests
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: taiki-e/install-action@cargo-tarpaulin
      - run: cargo tarpaulin --workspace --line --branch --fail-under 85

Foundry-tester kjøres i egen jobb med `foundry-install@v2`.

---

## 4 Lint-workflow

* **Clippy** (`-D warnings`) & **rustfmt**
* **Solhint** & **Slither** static-analyse
* **Shellcheck** & **yamllint**
* **Conftest** som kjører OPSEC-policy `configs/opsec/policy.rego` mot bygg-artefakter.

---

## 5 SLSA Level 3 provenance `prov-slsa.yml`

permissions:
  id-token: write
  contents: read
jobs:
  provenance:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: slsa-framework/slsa-github-generator@v2.1.0
        with:
          base64-subjects: |
            cli:x86_64
            cli:aarch64
      - name: Upload provenance
        uses: actions/upload-artifact@v4
        with:
          name: slsa-provenance.intoto.jsonl
          path: provenance.jsonl

## 6 Release-workflow `release.yml`

name: release
on:
  workflow_dispatch:
  push:
    tags: ['v*.*.*']
jobs:
  build-and-sign:
    runs-on: ubuntu-22.04
    environment: release
    steps:
      - uses: actions/checkout@v4
      - uses: DeterminateSystems/nix-installer-action@v3.5.2
      - run: nix build .#cli --out-link result
      - name: Generate SBOM
        run: |
          syft packages file:result/qsw-x86_64 --output spdx-json > qsw.spdx.json
      - name: Cosign (keyless OIDC)
        env:
          COSIGN_EXPERIMENTAL: "true"
        run: |
          cosign attest --predicate qsw.spdx.json --type spdx --yes \
            ghcr.io/org/qsw:${{ github.ref_name }}
      - name: GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          files: |
            result/qsw-x86_64
            result/qsw-aarch64
            qsw.spdx.json
            slsa-provenance.intoto.jsonl


## 7 TEE-attestasjon-jobb

jobs:
  attest-verify:
    runs-on: ubuntu-22.04
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Verify SGX quote
        uses: docker://ghcr.io/attest/v1-sgx-qe
        with:
          quote: ${{ secrets.SGX_QUOTE }}
      - name: DCAP library
        run: |
          ./scripts/ops/attest-verify.sh ${{ secrets.SGX_QUOTE }}

## 8 Artefakt-matrise

| Artefakt                       | Path i release | Signert? | SBOM? |
| ------------------------------ | -------------- | -------- | ----- |
| `qsw-x86_64`                   | `/bin/`        | Cosign   | SPDX  |
| `qsw-aarch64`                  | `/bin/`        | Cosign   | SPDX  |
| `contracts.zip`                | `/contracts/`  | Cosign   | n/a   |
| `proofs.tar.zst`               | `/proofs/`     | Cosign   | n/a   |
| `coverage.lcov`                | `/reports/`    | n/a      | n/a   |
| `bench.html`                   | `/reports/`    | n/a      | n/a   |
| `slsa-provenance.intoto.jsonl` | `/`            | n/a      | n/a   |

---

## 9 Miljø & secrets

| Secret / Var          | Bruk            | Origin       |
| --------------------- | --------------- | ------------ |
| `COSIGN_EXPERIMENTAL` | enable keyless  | repo         |
| `OPBNB_RPC_URL`       | deploy script   | env/prod     |
| `SGX_QUOTE`           | attestation job | secure store |
| `GH_TOKEN`            | release upload  | GitHub       |

Bruk **GitHub Environments** med “required reviewers” for prod-deploy.

---

## 10 Deknings- og blokkeringsregler

* Build-feil → PR rødt
* Coverage < 85 % → blokker merge
* Gas-snapshot over mål → “changes-requested” etikett settes
* Slither kritisk funn → blokker release
* Provenance mangler → release-jobb avbrytes

---

## 11 SLSA-flyt (skisse)

flowchart TD
    subgraph CI
      checkout --> nixBuild
      nixBuild --> test
      test --> slsaGen
      slsaGen --> artefacts
    end
    artefacts --> ghRelease
    ghRelease --> users

## 12 “✅ Done when”-sjekkliste

* [ ] Alle workflows grønne på PR & main
* [ ] GPU-runner bygger < 20 min
* [ ] SLSA-JSON verifisert av `slsa-verifier`
* [ ] SBOM + cosign-attest tilgjengelig
* [ ] Release-assets har checksum-manifest
* [ ] Attestation-verify pass for minst én TEE
* [ ] Environments / secrets policy-reviewet (two-man-rule)

---

## 13 Neste steg

Når CI/CD-røret er stabilt, oppdater **09\_security\_audit\_checklist.md** med lenker til:

1. Slither HTML-rapport
2. Tarpaulin & coverage-badge
3. SLSA provenance viewer
4. SBOM CycloneDX for auditører

---
