06\_cli\_client.md

# 06 – CLI-klient (Rust + Enklave + Mixnet)

*Quantum-Secure Wallet Pro — Build-step ➏*

---

## Innholdsfortegnelse

1. Funksjonsoversikt
2. Bygg & Distribusjon
3. Enklave-integrasjon
4. Remote Attestasjon & Autonomi­ske Oppdateringer
5. Tor-tvang & Nettverks­hygiene
6. Anti-timing & Dummy-trafikk
7. Kommando­referanse
8. Test­matrise
9. Sikkerhets­notater

---

## 1 · Funksjonsoversikt

| Modul                | Hovedansvar                                      | Kritiske forbedringer (2025-08-05)               |
| -------------------- | ------------------------------------------------ | ------------------------------------------------ |
| `qswallet-cli` binær | Signering, on-chain interaksjon, nøkkel­rotasjon | Uniform delay, ratelimit, side­kanals-mitigasjon |
| Enklave gRPC-bridge  | FROST-Dilithium operasjoner                      | Selv-sjekk + remote attestasjon                  |
| Mixnet-proxy         | Tor-sirkulasjon, dummy-trafikk                   | Auto-reconnect, circuit-sanity test              |

---

## 2 · Bygg & Distribusjon

*Alle bygg utføres hermetisk i Nix-basert Docker-image `ghcr.io/qswallet/cli:22.04-slsa4`.*

# ⚙️ 1. Klon repo
git clone https://github.com/QS-wallet/pro.git && cd pro

# ⚙️ 2. Bygg binær (reprodu­cerbar)
nix develop -c cargo build --release --locked

# ⚙️ 3. Generér og signér SBOM + provenance
syft ./target/release/qswallet-cli -o spdx-json > sbom.json
cosign attest --predicate sbom.json --type cyclonedx ./target/release/qswallet-cli

## 3 · Enklave-integrasjon

1. **Initial paring**
   `$ qswallet-cli enclave pair --device /dev/sgx/enclave0`
   *Bekrefter ECDSA-p256 device-sertifikat lokalt.*

2. **FROST-Dilithium signaturflyt**

   * CLI → enklave: `SignRequest(msg_hash)`
   * Enklave verifiserer PCR-policy (0,2,7) → returnerer `SigShare`
   * CLI koordinerer threshold & sender on-chain TX.

3. **Selv-sjekk ved oppstart**

   * PCR-lesing + målehash mot bundet liste (`/etc/qswallet/pcr-allow.txt`).
   * Firmware → cosign-verifisering av manifest.
   * Feil ⇒ blokkér alle kryptografiske operasjoner.

---

## 4 · Remote Attestasjon & Autonome Oppdateringer

| Fase            | Kommando                                                       | Beskrivelse                                                     |
| --------------- | -------------------------------------------------------------- | --------------------------------------------------------------- |
| 1 · Attest      | `qswallet-cli enclave attest --format cosign`                  | Sender DCAP-rapport til Sigstore Fulcio; mottar SCT-bundne JWT. |
| 2 · Verifiser   | `cosign verify-attestation --type slsaprovenance qswallet-cli` | Bekrefter kjede → Rekor-log skriv.                              |
| 3 · Auto-update | `qswallet-cli enclave upgrade --channel stable`                | Henter signert WASM-image via mixnet; verifiserer key‐rollover. |

*Oppdatering skjer «A/B» — gammel instans holdes aktiv til ny er attestert.*

---

## 5 · Tor-tvang & Nettverks­hygiene

* **Tor-daemon set-cap drop=ALL, no-new-privs, transparent-proxy**.
* Hardkodet SOCKS 5 på `127.0.0.1:9050`; CLI nekter annen utgående trafikk (iptables DROP).
* Automatisk ny circuit hver 10. minutt eller etter 30 TX.
  `$ qswallet-cli network rotate-circuit`
* Reconnect-policy: eksponentiell back-off (1 – 60 s), maks 10 forsøk → failsafe «offline-mode».

---

## 6 · Anti-timing & Dummy-trafikk

1. **Uniform delay:** hver TX pakkes med tilfeldig ventetid 250–750 ms.
2. **Batching:** meldinger flushes i 1 s time-slice for å skjule burst-mønster.
3. **Dummy-generator:**
   `$ qswallet-cli network start-dummy --rate 30m`
   Genererer cover-TX (nullifier-proofs) hver \~30 min (jitter ±5 m).
4. **Ratelimit lokal UI:** maks 5 sign-forsøk / minutt.

---

## 7 · Kommando­referanse

| Formål                  | Kommando                                         |
| ----------------------- | ------------------------------------------------ |
| Generér ny FROST-del    | `qswallet-cli key share --threshold 2 --total 5` |
| Attestasjon + print SCT | `qswallet-cli enclave attest -o json`            |
| Sjekk Tor-status        | `qswallet-cli network status`                    |
| Dummy-trafikk toggle    | `qswallet-cli network start-dummy / stop-dummy`  |
| Secure wipe             | `qswallet-cli key wipe --secure`                 |

---

## 8 · Test­matrise

| Testtype    | Mål                         | Verktøy                     |
| ----------- | --------------------------- | --------------------------- |
| Unit-tests  | ≥ 85 %                      | `cargo test --all --locked` |
| Integration | Mixnet, enclave, chain stub | `nixos-tests`               |
| Fuzz        | gRPC API                    | `cargo fuzz run fuzz_api`   |
| Side-kanal  | Timing ≤ 5 µs var           | `klee-symbolic` script      |

---

## 9 · Sikkerhets­notater

* **Ingen seed/privkey** må noen gang vises i stdout eller logg (ref: 09 §2).
* CLI nekter å kjøre hvis:

  1. Tor ikke er i *Guard* status, eller
  2. Enklave PCR-verifikasjon feiler, eller
  3. Firmware-manifest ikke signert av `wallet.dev` Fulcio-root.
* Dummy-trafikk kan ikke deaktiveres i «release» build uten *force-flag* i utviklerkanal.

*Oppdatert: 5 aug 2025 — fjernet fallback-nettverk, lagt inn remote-attestasjon, anti-timing-funksjoner, og robust auto-oppdatering av enklave-image.*
