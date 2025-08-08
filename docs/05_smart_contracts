title: "05_smart_contracts"
version: "v3.0"
status: "authoritative"
last\_updated: "2025-08-05"
audience: "Solidity / Protocol / Security-audit teams"
scope:
  - On-chain contracts for **opBNB Bedrock** (EVM-L2)
  - Solidity ≥ 0.8.30 (Prague EVM)
  - ERC-4337 Account Abstraction + Paymaster mesh
  - Halo2 & zk-STARK verifier bindings
  - Anti-sensur / dummy-batch enforcement
pinned\_versions:
  solidity: 0.8.31
  openzeppelin: 5.0.1
  forge\_std: 1.10.0
  ds-test: 0.5.3
  bnb-chain/opbnb: v1.4.0-bedrock

---

## 0  Mål

| Modul                  | Ansvar                                   | Gas-mål | Sikkerhets-invariant         |
| ---------------------- | ---------------------------------------- | ------: | ---------------------------- |
| **ShieldedPool**       | Commit/Nullify notes, Halo2-verif.       | ≤ 160 k | PK aldri on-chain            |
| **DecoyBatcher**       | Poisson-jitter, dummy-noter, batch-flush |  ≤ 80 k | Batch ≥ 16 ekte / ≥ 80 dummy |
| **ThresholdPaymaster** | ERC-4337 gas via Dilithium-threshold     |  ≤ 75 k | t = 3/n ≥ 5, replay-proof    |
| **VerifierHalo2**      | Halo2-verif. for Pool                    | ≤ 230 k | Felt-param samsvar           |
| **VerifierStark**      | STARK-batch verif.                       | ≤ 110 k | Batch-size-bevis ≥ 128       |

---

## 1  Mappestruktur

contracts/
├─ foundry.toml
├─ script/
│  ├─ Deploy.s.sol
│  ├─ Upgrade.s.sol
│  └─ Utils.sol
├─ src/
│  ├─ ShieldedPool.sol
│  ├─ DecoyBatcher.sol
│  ├─ ThresholdPaymaster.sol
│  ├─ libraries/
│  │  ├─ Notes.sol
│  │  ├─ Poseidon.sol
│  │  ├─ Merkle.sol
│  │  └─ VerifierHalo2.sol   # autogen
│  └─ interfaces/
│     ├─ IShieldedPool.sol
│     ├─ IDecoyBatcher.sol
│     ├─ IThresholdPaymaster.sol
│     └─ IEntryPoint.sol
└─ test/
   ├─ ShieldedPool.t.sol
   ├─ DecoyBatcher.t.sol
   ├─ ThresholdPaymaster.t.sol
   └─ Integration.t.sol

## 2  Kontrakt-design

### 2.1  ShieldedPool

* **State:**
  `root`, `nullifierHash`, `noteCommitments`, `verifier`
* **Funksjoner:**
  `deposit(bytes32 commitment)` → event + Merkle-oppdatering
  `withdraw(Proof, bytes32 nullifier, address to, uint256 value)`
  `_verifyZkProof()` via `VerifierHalo2`
* **Invariants:**

  * Nullifier kan sette *én* gang
  * Merkle-path matcher `root`
  * Beløp følger fuzzy-range (bevist i circuit)

### 2.2  DecoyBatcher

Ring-buffer-queue, dummy-budsjett, `flush()` når ready(): `(real ≥ 16 && dummy ≥ 80)` eller 2 t timeout.
Shadow gas-masks: ekstra `address(0xdead)` no-ops.

### 2.3  ThresholdPaymaster

ERC-4337 `IPaymaster`; off-chain quorum signatur sendes i `paymasterAndData`.
Ingen private nøkler on-chain; kun gruppe-PK.

---

## 3  Solidity-kompilator

foundry.toml:

solc_version   = "0.8.31"
evm_version    = "paris"
optimizer      = true
optimizer_runs = 1_000_000
via_ir         = true

---

## 4  Kode-stubber (forkortet eksempel)

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.31;

import {IVerifierHalo2} from "./interfaces/IVerifierHalo2.sol";
import {Merkle} from "./libraries/Merkle.sol";

contract ShieldedPool {
    IVerifierHalo2 public immutable verifier;
    bytes32 public root;
    mapping(bytes32 => bool) public nullifierHash;

    event NoteCommit(bytes32 indexed commitment, uint32 index, uint256 timestamp);
    event Withdraw(address indexed to, uint256 amount);

    constructor(bytes32 _root, address _verifier) {
        root = _root;
        verifier = IVerifierHalo2(_verifier);
    }

    function deposit(bytes32 commitment) external payable {
        // TODO: enforce note size; update merkle tree
        emit NoteCommit(commitment, 0, block.timestamp);
    }

    function withdraw(
        bytes calldata proof,
        bytes32 nullifier,
        address payable to,
        uint256 value
    ) external {
        require(!nullifierHash[nullifier], "spent");
        require(
            verifier.verify(proof, abi.encodePacked(nullifier, to, value, root)),
            "invalid proof"
        );
        nullifierHash[nullifier] = true;
        (bool ok, ) = to.call{value: value}("");
        require(ok, "transfer fail");
        emit Withdraw(to, value);
    }
}

*(DecoyBatcher og ThresholdPaymaster følger samme struktur.)*

---

## 5  Autogenererte verifiers

* **Halo2**: genereres fra vk-JSON (`halo2_sol_gen.rs`).
* **STARK**: wrapper rundt Bedrock FRI-precompile `0x000…0521`.

---

## 6  Foundry-tester

forge test -vvv
forge coverage --report lcov

Dekningskrav: ShieldedPool ≥ 95 %, øvrige ≥ 90 %.

---

## 7  Gas-mål

`forge snapshot --json | jq '.[] | {name, gas}'`

| Funksjon                  |                            Mål |
| ------------------------- | -----------------------------: |
| `deposit`                 |                        ≤ 160 k |
| `withdraw` inkl. verify   |                        ≤ 230 k |
| `flush`                   | ≤ 190 k total (≤ 2 k per note) |
| `validatePaymasterUserOp` |                         ≤ 75 k |

---

## 8  Sikkerhets­notater

* Reentrancy: Pull-payments.
* Fee-angrep: Paymaster sjekker `maxGasPrice`, tidsstempel.
* Front-running: optional commit-reveal delay.
* Ingen proxier – immutable kontrakter; batch-param via timelock-governance.

---

## 9  Deployment-script

forge script script/Deploy.s.sol:Deploy \
  --rpc-url $OPBNB_RPC --broadcast --verify

---

## 10  “✅ Done when”

* `forge test` grønt, dekning ≥ 90 %
* Gas-snapshot innen mål
* Verifier-contracts < 24 KB bytecode
* Slither & Mythril: 0 kritiske
* Deploy-script verifisert på opBNB-testnet

---

## 11  Neste steg

Integrer CLI-kall og kjør `make e2e` i docker-testnet; book pre-audit gas-review.
