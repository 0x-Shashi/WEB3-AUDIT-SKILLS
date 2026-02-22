---
id: FUEL-SCAN
title: Fuel Network Security Scanner
category: chain-scanner
trigger: "Audit Fuel|Sway|FuelVM"
last_updated: 2025-01-31
---

# Fuel Network Security Scanner

Security scanner for Fuel Network smart contracts written in Sway. Fuel uses a UTXO-based model with the FuelVM, fundamentally different from EVM account-based chains.

---

## Language & Runtime

| Attribute | Value |
|-----------|-------|
| Chain | Fuel (modular execution layer) |
| Language | Sway (Rust-inspired, purpose-built for FuelVM) |
| VM | FuelVM (register-based, not stack-based like EVM) |
| Transaction Model | UTXO-based (like Bitcoin, unlike Ethereum's account model) |
| Token Model | Native multi-asset (assets are first-class, not contract-based) |
| Program Types | Contract, Script, Predicate, Library |
| Toolchain | `forc` (Fuel Orchestrator), `fuel-core` |
| Testing | `fuels-rs` (Rust SDK) |

---

## FuelVM vs EVM: Key Differences

| Feature | EVM (Ethereum) | FuelVM (Fuel) |
|---------|----------------|---------------|
| Transaction model | Account-based | UTXO-based |
| Assets | ERC20 contracts | Native multi-asset |
| Parallelism | Sequential | Parallel (UTXO enables it) |
| State access | Any contract can read global state | State access declared upfront |
| Reentrancy | Possible (external calls) | Different model (no direct reentrancy) |
| Stack | Stack-based (256-bit words) | Register-based (64-bit words) |
| Programs | Smart contracts only | Contracts, Scripts, Predicates |

---

## Detection Capabilities

| Category | Detection | Severity |
|----------|-----------|----------|
| **UTXO** | Same UTXO consumed in multiple paths | Critical |
| **UTXO** | Coin output not created for change | High |
| **Predicates** | Predicate logic bypass via crafted input | Critical |
| **Predicates** | Predicate gas limit exceeded (always fails) | High |
| **Assets** | Wrong `AssetId` used in transfer or balance check | Critical |
| **Assets** | Missing `AssetId` validation on received funds | High |
| **Access Control** | Missing `msg_sender()` validation on privileged functions | Critical |
| **Access Control** | Identity type confusion (`Address` vs `ContractId`) | High |
| **Storage** | Storage key collision in manual key assignment | High |
| **Storage** | Storage slot manipulation via `asm` blocks | Medium |
| **Math** | Integer overflow (Sway u64 wraps in some contexts) | High |
| **Math** | Division by zero (panic) | Medium |
| **Scripts** | Incorrect script-to-contract call sequencing | Medium |
| **Scripts** | Script return value not validated by caller | Medium |

---

## Program Types and Security Implications

### Contract

Persistent state, deployed on-chain, callable by transactions and scripts:

```sway
contract;

storage {
    owner: Identity = Identity::Address(Address::zero()),
    balance: u64 = 0,
}

abi MyContract {
    #[storage(read, write)]
    fn deposit();
    
    #[storage(read, write)]
    fn withdraw(amount: u64);
}

impl MyContract for Contract {
    #[storage(read, write)]
    fn deposit() {
        // msg_amount() = forwarded base asset amount
        // msg_asset_id() = forwarded asset ID
        storage.balance.write(storage.balance.read() + msg_amount());
    }
    
    #[storage(read, write)]
    fn withdraw(amount: u64) {
        // MUST validate caller
        require(
            msg_sender().unwrap() == storage.owner.read(),
            "unauthorized"
        );
        storage.balance.write(storage.balance.read() - amount);
        transfer(msg_sender().unwrap(), AssetId::base(), amount);
    }
}
```

### Predicate

Stateless UTXO spending conditions — returns `true` or `false`:

```sway
predicate;

// Predicate that allows spending only if multiple conditions met
fn main(expected_recipient: Address, min_amount: u64) -> bool {
    // Predicates have NO state and NO side effects
    // They validate whether a UTXO can be spent
    let tx_outputs = tx_outputs_count();
    
    // Check: output sends to expected recipient
    // Check: amount >= min_amount
    // Returns true only if conditions are met
    true // or false
}
```

**Predicate Security:** Predicates are pure functions evaluated at validation time. If the predicate returns `true`, the UTXO can be spent. Any logic error = funds at risk.

### Script

Transaction-level orchestration (not deployed, executed once):

```sway
script;

use my_contract_abi::MyContract;

fn main(contract_id: ContractId, amount: u64) {
    let contract = abi(MyContract, contract_id.into());
    contract.deposit {  // Call parameters
        gas: 10_000,
        coins: amount,
        asset_id: AssetId::base(),
    }();
}
```

---

## Native Multi-Asset Model

Unlike EVM where tokens are contract-based (ERC20), Fuel has native multi-asset support:

```sway
// Every contract can mint its own sub-assets
let sub_id = SubId::zero();
let asset_id = AssetId::new(ContractId::this(), sub_id);

// Mint native assets
mint(sub_id, amount);

// Transfer native assets  
transfer(recipient, asset_id, amount);

// Check forwarded asset
let received_asset = msg_asset_id();
require(received_asset == expected_asset, "wrong asset");
```

**Critical Check:** Always validate `msg_asset_id()` matches the expected asset. Failing to do so allows an attacker to send a worthless asset and receive legitimate assets in return.

---

## Resources
- [Fuel Patterns](resources/fuel-patterns.md)

## Workflows
- [Fuel Audit](workflows/fuel-audit.md)

## Overview
Fuel is a modular execution layer with:
- Sway language (Rust-inspired)
- UTXO-based model (not account-based)
- FuelVM (not EVM)
- Native multi-asset support
- Predicates (stateless UTXO conditions)
- Parallel transaction processing via strict state access declarations
