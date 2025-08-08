10\_user\_ops\_docs.md

# 10 – Bruker- og driftsmanual

*Quantum-Secure Wallet Pro – Steg ➓*

---

## Innholdsfortegnelse

1. Kom i gang
2. Grunnleggende operasjoner
3. Sikkerhetsrutiner
4. Anonymitetsrutiner
5. Backup & katastrofe-gjenoppretting
6. Varsling & hendelseshåndtering
7. Feilsøking
8. Vanlige spørsmål
9. Vedlegg A – Kommando-sammendrag
10. Vedlegg B – Varslings-API

---

## 1 · Kom i gang

* **Systemkrav**: Ubuntu 22.04 (immutable profil, ref: 02 §4), TPM 2.0, kablet nett.
* **Installasjon**

  1. Last ned signert binær `qswallet-cli` fra <mixnet-URL>.
  2. Verifisér signatur: `cosign verify-blob --key fulcio.pub qswallet-cli`.
  3. Kjør første oppstart: `./qswallet-cli init`.
* **Paring med enklave**: `qswallet-cli enclave pair`.

---

## 2 · Grunnleggende operasjoner

| Operasjon      | Kommando                                     | Notat                               |
| -------------- | -------------------------------------------- | ----------------------------------- |
| Send betaling  | `qswallet-cli tx send --to <addr> --amt 1.2` | Ventetid 250–750 ms før signatur.   |
| Motta          | Del anonym mottaks-QR fra `receive --qr`.    | Ingen on-chain adresse-link.        |
| Sjekk saldo    | `qswallet-cli balance`                       | Query går via mixnet.               |
| Nøkkelrotasjon | `qswallet-cli key rotate`                    | Tvinges også automatisk hver 180 d. |

---

## 3 · Sikkerhetsrutiner

1. **Nøkkel-hygiene**

   * Private keys forlater aldri enklaven.
   * Ingen eksport av seed støttes (refuses CLI).
2. **Rotasjon**

   * CLI minner deg når «key-age» > 10 000 signaturer.
   * Alltid bekreft remote attestasjon før ny nøkkel tas i bruk.
3. **Secure-wipe**

   * `key wipe` sletter nøkkelpar lokalt + kvitterer mot TPM-teller.
4. **Firmwareoppdatering**

   * Kjør `enclave upgrade --channel stable` ukentlig.
   * Oppdatering skjer A/B; gammel versjon beholdes til ny er attestert.
5. **Ikke-godkjente miljø**

   * CLI nekter å kjøre dersom Tor er offline, PCR-policy mis-matcher, eller firmware-manifest mangler Fulcio-signatur (ref: 06 §9).

---

## 4 · Anonymitetsrutiner

1. **Dummy-trafikk** – alltid PÅ

   * Starter automatisk: 1 cover-TX / 30 min ± 5 min.
   * Status: `network status` → «Dummy-rate: OK».
2. **Mixnet-kontroll**

   * Automatisk ny Tor-circuit hver 10. min eller 30 TX.
   * Manuell: `network rotate-circuit`.
3. **Timing-beskyttelse**

   * Uniform delay på alle TX; ikke forsøk å «speed-booste» CLI.
4. **Frakoblet modus**

   * Dersom mixnet down > 10 forsøk → CLI går i «offline-mode».
   * Signering er da deaktivert for å hindre deanonymisering.

---

## 5 · Backup & katastrofe-gjenoppretting

| Scenario              | Fremgangsmåte                                      | Kommentar                       |
| --------------------- | -------------------------------------------------- | ------------------------------- |
| Enklave-tap           | Gjenopprett via FROST-participant ≥ t              | Krever minst 2 av 5 del-nøkler. |
| Maskinvarefeil        | Installer ny vert → `enclave recover --pcr <file>` | PCR-logg fra siste backup USB.  |
| Ketil (tjeneste) down | Bruk on-chain «emergency exit» kontrakt            | Gas ≤ 80 k.                     |

---

## 6 · Varsling & hendelseshåndtering

1. **Automatiske varsler**

   * 0-day feed fra NVD pushes til CLI (`--watch cve`).
   * Varsling om identitetslekkasje («anon-risk») sendes fra sentinel-noder.
2. **Webhook-integrasjon**

   * `qswallet-cli alert add-webhook https://hooks.example.com`
   * Hendelsestyper: `cve`, `mixnet_down`, `pcr_mismatch`.
3. **Incident Journal**

   * Alle kritiske hendelser logges til `/var/log/qswallet/*.json` (lokal, kryptert).

---

## 7 · Feilsøking

| Symptom                     | Sjekk                  | Løsning                                   |
| --------------------------- | ---------------------- | ----------------------------------------- |
| «Tor not in Guard state»    | `systemctl status tor` | Restart Tor; sjekk brannmur.              |
| `PCR mismatch`              | `sbctl verify`         | Firmware-rollback, kjør oppdatering.      |
| «Enclave signature refused» | `enclave attest`       | Oppgrader enklave-image til siste stable. |
| Lave dummy-rater            | `network start-dummy`  | Overstyr, så rapportér til support.       |

---

## 8 · Vanlige spørsmål

**Q:** Kan jeg deaktivere dummy-trafikken for å spare data?
**A:** Nei; deaktivert dummy reduserer anonymitet dramatisk og er ikke støttet i produksjons-build (ref: 01 §3.3).

**Q:** Hvordan verifiserer jeg at builden min er identisk med CI?
**A:** Kjør `nix develop -c cargo build --release --locked` → `sha256sum` på binær skal matche public digest i GitHub Release.

---

## 9 · Vedlegg A – Kommando-sammendrag

* `init` – første-gangs konfigurasjon
* `enclave pair | attest | upgrade`
* `tx send | history`
* `key rotate | wipe`
* `network status | start-dummy | rotate-circuit`
* `alert add-webhook | list`

---

## 10 · Vedlegg B – Varslings-API

POST /v1/alert
{
  "event": "cve",
  "cve_id": "CVE-2025-1234",
  "severity": "critical",
  "timestamp": "2025-08-06T12:34:56Z"
}

Signer webhook-payload med Dilithium-III public key `alert.qswallet.pub`.

---

Oppdatert: 5 aug 2025 — nye seksjoner for dummy-trafikk, nøkkel-hygiene, og 0-day-varsler.
