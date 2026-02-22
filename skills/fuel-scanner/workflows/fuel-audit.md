---
id: FUEL-WF-AUDIT
title: Fuel / Sway Contract Audit Workflow
parent: fuel-scanner
type: workflow
last_updated: 2025-01-31
---

# Fuel / Sway Audit Workflow

Systematic audit workflow for Fuel Network programs written in Sway. Covers contracts, scripts, predicates, and libraries.

---

## Prerequisites

| Requirement | Details |
|-------------|----------|
| Compiler | `forc build` (Fuel Orchestrator) |
| Toolchain | `fuelup` for toolchain management |
| Testing | `forc test` (unit tests) + `fuels-rs` (integration tests in Rust) |
| Config | `Forc.toml` for dependencies and project config |
| Network | `fuel-core` for local node |

---

## Step 1: Program Structure Mapping

Identify all program types in the project:

| Program Type | File Header | State | Security Focus |
|-------------|-------------|-------|----------------|
| `contract;` | `contract;` | Persistent storage | Primary audit target |
| `script;` | `script;` | None | Transaction orchestration |
| `predicate;` | `predicate;` | None | UTXO spending conditions |
| `library;` | `library;` | None | Shared logic |

For each contract:
- List all ABI functions with their attributes (`#[storage(read)]`, `#[storage(read, write)]`, `#[payable]`)
- Map storage variables and their types
- Identify `configurable` constants
- List all events (logged types)

---

## Step 2: Access Control

For every ABI function, verify authorization:

```sway
// Access control pattern in Sway
abi MyContract {
    #[storage(read, write)]
    fn privileged_action();
}

impl MyContract for Contract {
    #[storage(read, write)]
    fn privileged_action() {
        // msg_sender() returns Result<Identity>
        let caller = msg_sender().unwrap();
        require(caller == storage.owner.read(), "unauthorized");
        // ... perform action
    }
}
```

| Function Attribute | Implication | Check |
|-------------------|-------------|-------|
| `#[storage(read)]` | Reads state only | Lower risk, but may leak sensitive info |
| `#[storage(read, write)]` | Modifies state | **Must have access control** |
| `#[payable]` | Accepts asset forwarding | **Must validate asset ID and amount** |
| No attributes | Pure function | Generally safe |

- [ ] Every `#[storage(read, write)]` function has caller validation
- [ ] Every `#[payable]` function validates `msg_asset_id()` and `msg_amount()`
- [ ] `msg_sender()` `Result` is properly handled (not just `.unwrap()`)
- [ ] `Identity::Address` vs `Identity::ContractId` distinguished where needed

---

## Step 3: Asset Handling

Fuel's native multi-asset model requires careful asset validation:

```sway
// AssetId = SHA-256(ContractId, SubId)
// Base asset (ETH on Fuel) = AssetId::base()
// Sub-assets minted by contracts have unique IDs

// AUDIT: For every function that receives or sends assets:
// 1. Is the received asset ID validated?
// 2. Is the sent asset ID correct?
// 3. Is the amount correctly calculated?
```

- [ ] `msg_asset_id()` checked against expected asset on ALL payable functions
- [ ] Multi-asset operations validate each asset independently
- [ ] Asset minting (`mint()`) has proper access control and supply tracking
- [ ] Asset burning (`burn()`) properly reduces supply
- [ ] Transfer recipients verified (no sending to zero address)

---

## Step 4: Predicate Review

Predicates are **critical** — a bug can permanently lock or leak funds:

- [ ] All conditions use `configurable` for constants (not function parameters)
- [ ] Predicate gas consumption estimated and within limits
- [ ] All edge cases handled (empty inputs, boundary values)
- [ ] No external calls (predicates cannot call contracts)
- [ ] Return value `false` by default (fail-safe)
- [ ] Complex predicates have exhaustive test coverage

---

## Step 5: Storage Analysis

Sway storage layout:

```sway
storage {
    // Auto-generated storage slots based on variable name
    owner: Identity = Identity::Address(Address::zero()),
    balance: u64 = 0,
    
    // StorageMap for key-value pairs
    balances: StorageMap<Identity, u64> = StorageMap {},
    
    // StorageVec for dynamic arrays
    participants: StorageVec<Identity> = StorageVec {},
}
```

- [ ] No manual storage slot assignments that could collide with auto-generated slots
- [ ] `StorageVec` access uses bounds checking
- [ ] `StorageMap` read handles missing keys (`.try_read()`)
- [ ] Storage layout won't break on upgrade (if upgradeable)
- [ ] No `asm` blocks that manipulate storage directly (unless justified)

---

## Step 6: Math Review

| Type | Size | Overflow |
|------|------|----------|
| `u8` | 8-bit | Wraps in release |
| `u16` | 16-bit | Wraps in release |
| `u32` | 32-bit | Wraps in release |
| `u64` | 64-bit | Wraps in release |
| `u256` | 256-bit | Wraps in release |

- [ ] Critical arithmetic uses checked operations (`checked_add`, `checked_mul`)
- [ ] Division operations check for zero denominator
- [ ] Price/rate calculations have sufficient precision
- [ ] Accumulator variables use large enough types

---

## Step 7: UTXO Model Analysis

Understand how the contract interacts with Fuel's UTXO model:

- [ ] Contract handles multiple inputs in a single transaction correctly
- [ ] Change outputs created when partial UTXO spending occurs
- [ ] No assumption about input ordering
- [ ] Contract state consistent across multi-call transactions (scripts calling multiple functions)

---

## Step 8: Script Review

Scripts orchestrate multi-step transactions:

- [ ] Script validates return values from contract calls
- [ ] Script handles contract call failures gracefully
- [ ] Script doesn't pass conflicting parameters to sequential calls
- [ ] Call parameters (gas, coins, asset_id) correctly set for each call

---

## Step 9: Cross-Contract Safety

```sway
// Cross-contract call pattern
let other = abi(OtherContract, contract_id.into());
let result = other.some_function {
    gas: 10_000,
    coins: 0,
    asset_id: AssetId::base(),
}();
```

- [ ] Called contract addresses validated (not user-supplied without checks)
- [ ] Gas forwarding doesn't starve the calling contract
- [ ] Return values from external calls validated
- [ ] No trust assumptions about external contract behavior

---

## Step 10: Report

### Severity Guide for Fuel/Sway

| Severity | Criteria | Example |
|----------|----------|---------|
| **Critical** | Fund theft or permanent lock | Predicate bypass allowing unauthorized UTXO spend |
| **High** | Fund loss under conditions | Asset confusion accepting wrong token as payment |
| **Medium** | Incorrect behavior | Integer overflow in non-critical calculation |
| **Low** | Best practice violation | Missing events for state changes |

Always include:
- Fuel-specific context (UTXO model, program type affected)
- `fuels-rs` test case demonstrating the vulnerability
- Fix with Sway code example
