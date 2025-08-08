# 02 – Ubuntu 22.04 Deterministic Build & Supply-Chain-Hardened Environment  
*Quantum-Secure Wallet Pro — Build-step ➊*  

---

## Innholdsfortegnelse
1. [Vertskrav](#1-vertskrav)  
2. [Pre-flight-sjekk ⚠️](#2-pre-flight-sjekk)  
3. [Installér verifisert Ubuntu 22.04-ISO](#3-installer-verifisert-ubuntu2204-iso)  
4. [Immutable OS-baseline (Nix + APT pinning)](#4-immutable-os-baseline)  
5. [TPM-forankret Secure Boot](#5-tpm-forankret-secure-boot)  
6. [Firmware-verifikasjon & auto-oppdatering](#6-firmware-verifikasjon--auto-oppdatering)  
7. [Reproduserbar toolchain (SBOM)](#7-reproduserbar-toolchain-sbom)  
8. [Hermetisk bygg-container (Nix & Docker rootless)](#8-hermetisk-bygg-container)  
9. [Intel/AMD SGX + RISC-V Keystone-enclaves](#9-enclave-støtte)  
10. [Supply-chain-skanning + SLSA 4-proveniens](#10-supply-chain-skanning--slsa-4)  
11. [Daglig oppdaterings- & rotasjonsrutine](#11-daglig-rutine)  
12. [Vedlegg A – Kommando-referanse](#vedlegg-a--kommando-referanse)  

---

## 1 · Vertskrav
⚙️ Hardware: 4 CPU-kjerner, 16 GB RAM, 200 GB SSD, TPM 2.0
🔐 BIOS: Secure Boot & IOMMU slått på
🌐 Nettverk: Kun kablet (ingen Wi-Fi) under første init


---

## 2 · Pre-flight-sjekk ⚠️
1. **Bekreft BIOS-hash:**  
   ```bash
   sha256sum /sys/firmware/efi/efivars/SecureBoot-$(ls /sys/firmware/efi/efivars | grep SecureBoot) | cut -d' ' -f1

Sammenlign mot signert hash-liste fra produsent.

2. TPM-eierskap:

sudo tpm2_pcrread --pcr-list sha256:0,2,7
tpm2_getcap -c properties-fixed | grep -E 'TPM2_PT_FAMILY_INDICATOR|TPM2_PT_MANUFACTURER'

3. Firmware-status:

fwupdmgr get-devices

3 · Installér verifisert Ubuntu 22.04-ISO

# 1. Last ned ISO + signatur
curl -O https://releases.ubuntu.com/22.04/ubuntu-22.04.4-desktop-amd64.iso
curl -O https://releases.ubuntu.com/22.04/SHA256SUMS.gpg
curl -O https://releases.ubuntu.com/22.04/SHA256SUMS

# 2. Verifiser signatur
gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys 0xF6ECB3762474EDA9
gpg --verify SHA256SUMS.gpg SHA256SUMS

# 3. Sjekk ISO-hash
sha256sum -c <(grep ubuntu-22.04.4.*amd64.iso SHA256SUMS)

# 4. Skriv ISO hermetisk:
sudo dd if=ubuntu-22.04.4-desktop-amd64.iso of=/dev/sdX bs=4M status=progress oflag=sync

→ Installer med «Minimal installation», slå av tredjeparts-­repoer.


| Komponent     | Tiltak                                                                                           |                                                                        |
| ------------- | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| **APT**       | `Unattended-Upgrades "origin=Ubuntu,archive=jammy-security";`<br>`APT::Default-Release "jammy";` |                                                                        |
| **Pinning**   | `/etc/apt/preferences.d/00-pinning`: pin alt unntatt `jammy{,-security,-updates}` til `-1000`.   |                                                                        |
| **Nix**       | \`\`\`bash\ncurl -L [https://nixos.org/nix/install](https://nixos.org/nix/install)               | sh -s -- --daemon --yes\n\`\`\`<br>Aktiver `flakes` & `repl-optimise`. |
| **OverlayFS** | Rotfs monteres `ro`, `/etc`, `/var` som overlay `rw` (systemd-unit).                             |                                                                        |

5 · TPM-forankret Secure Boot

sudo sbctl status           # Installer sbctl fra sigstore PPA
sudo sbctl generate-keys
sudo sbctl enroll-keys -m   # krever BIOS-passord
sudo sbctl verify

PCR-policy: lås kjede opp til shim, grub, kernel‐image (PCR 0,2,7). Logger auto-pushes til Sigstore Fulcio (ref: 08 §2.3).

6 · Firmware-verifikasjon & auto-oppdatering

1. Aktiver LVFS-testing-repo kun for signert maskinvare.

sudo fwupdmgr refresh --force
sudo fwupdmgr get-updates --verbose
sudo fwupdmgr update --no-reboot

2. Lagre firmware SBOM:

fwupdmgr get-updates --json > /var/log/firmware-sbom.json


7 · Reproduserbar toolchain (SBOM)


| Verktøy   | Versjon           | Byggmetode                                                                           |
| --------- | ----------------- | ------------------------------------------------------------------------------------ |
| `rustup`  | 1.77.0            | `nix develop -c rustup install stable --profile minimal --component clippy,rust-src` |
| `cargo`   | 1.77.0            | Som over (locked via `rust-toolchain.toml`)                                          |
| `foundry` | 0.2.0             | Nix flake input, reproducible SHA-hash                                               |
| `zk`      | halo2 + zkevm-0.7 | Provided via crate lock-file; reproducible `cargo --locked` build                    |
| `cosign`  | 2.2.1             | Static musl build validated via sigstore/cosign                                      |

SBOM genereres av Syft v1.13 (syft dir:/ --scope all-layers -o cyclonedx-json).

8 · Hermetisk bygg-container

nix develop -c \
docker run --rm -it \
  --pull=always \
  --read-only \
  --tmpfs /run \
  --tmpfs /tmp \
  --security-opt=no-new-privileges \
  --cap-drop=ALL \
  --user 1000:1000 \
  ghcr.io/qswallet/build-env:22.04-slsa4@sha256:<IMMUTABLE>

Alle CI-jobber kjører samme image (ref: 08 §1).

9 · Enclave-støtte
| Arkitektur      | Driver                          | Attestasjon                         |
| --------------- | ------------------------------- | ----------------------------------- |
| Intel SGX       | `isgx` DKMS, locked tag `v2.17` | `aesmd` + DCAP v1.16                |
| AMD SEV-SNP     | `sevctl`, kernel ≥ 5.19         | OCA cert-chain bundle               |
| RISC-V Keystone | `keystone-driver` tag `v1.4`    | Local attestation + remote `ra-tls` |

Remote-attestation CLI

qswallet-cli enclave attest --format cosign

10 · Supply-chain-skanning + SLSA 4
1. Chainguard Witness i GitHub Actions:

- uses: chainguard-dev/witness@v0.4
  with:
    attestation: provenance
    predicateType: slsaProvenance/v1

2. Sigstore Fulcio + Rekor for alt semver-utgitt binært artefakt.

3. Grype CVE-skanning blokker merge ved CVSS ≥ 7.

11 · Daglig rutine
# 00:30 UTC ± 5 min (cron)
systemctl start os-update-immutable.service

# 00:45 UTC
nix run github:mozilla/supply-chain@v0.9 -- scan /nix/store

# 01:00 UTC
fwupdmgr update --no-reboot && reboot

Etter reboot kjøres tpm2_pcrread → PCR-logg pushes signert til Sigstore Rekor.

Vedlegg A – Kommando-referanse <a name="vedlegg-a--kommando-referanse"></a>
| Formål                     | Kommando                                        | Resultat                        |
| -------------------------- | ----------------------------------------------- | ------------------------------- |
| Verify kernel immutability | `sbctl verify --fix`                            | Fail CI hvis hash mismatch      |
| Build wallet CLI           | `nix develop -c cargo build --release --locked` | `./target/release/qswallet-cli` |
| Run full test-suite        | `nix develop -c cargo tarpaulin --out Xml`      | Coverage ≥ 85 %                 |
| Publish provenance         | `cosign attest --type slsaprovenance ...`       | Rekor log-entry                 |

Merk 📌 Alle skript er kjedet i ci/scripts/pre-build.sh og post-build.sh; endre dem kun via pull request som passerer req-review:sec-leads (ref: 08 §1.4).

Oppdatert: 5 aug 2025 — inkluderer TPM-policy, immutability-checksums, SLSA 4-steget og utvidet firmware-SBOM.
