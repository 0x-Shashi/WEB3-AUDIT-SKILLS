---
id: CW-WF-AUDIT
title: CosmWasm Contract Audit Workflow
parent: cosmos-scanner
type: workflow
last_updated: 2025-01-31
---

# CosmWasm Contract Audit Workflow

Systematic audit workflow for CosmWasm smart contracts written in Rust. Covers standard contracts, IBC-enabled contracts, and multi-contract systems.

---

## Prerequisites

| Requirement | Details |
|-------------|----------|
| Compiler | `cargo build --target wasm32-unknown-unknown --release` |
| Optimizer | `cosmwasm/rust-optimizer` Docker image for reproducible builds |
| Framework | `cosmwasm-std` >= 1.0 |
| Testing | `cw-multi-test` for integration tests |
| Schema | `cosmwasm-schema` for JSON schema generation |

---

## Step 1: Contract Structure Mapping

Map all entry points and understand the contract's interface:

```rust
// Typical CosmWasm contract structure:
// src/
// ├── contract.rs    → Entry points (instantiate, execute, query, migrate, reply)
// ├── msg.rs         → Message definitions (InstantiateMsg, ExecuteMsg, QueryMsg)
// ├── state.rs       → Storage definitions (Item, Map, SnapshotMap)
// ├── error.rs       → Error types (ContractError)
// ├── helpers.rs     → Utility functions
// └── lib.rs         → Module declarations
```

Document for each entry point:
- **`instantiate`**: What config is set? Who becomes admin? What state is initialized?
- **`execute`**: List every `ExecuteMsg` variant. Which modify critical state? Which move funds?
- **`query`**: List every `QueryMsg` variant. Any that iterate unbounded?
- **`migrate`**: Does it exist? Who can call it? What does it change?
- **`reply`**: What SubMessages trigger it? Reply-on-success vs reply-on-error vs reply-always?
- **`sudo`**: Does the contract implement `sudo`? (Privileged chain-level calls)

---

## Step 2: Authorization

For every `ExecuteMsg` variant, verify authorization:

| Pattern | Code | Safe? |
|---------|------|-------|
| Admin check | `if info.sender != config.admin { return Err(...) }` | YES |
| Owner check | `if info.sender != token.owner { return Err(...) }` | YES |
| No check | Function doesn't read `info.sender` | DANGEROUS |
| Allowlist | `if !ALLOWLIST.has(deps.storage, &info.sender)` | YES (verify list management) |

### Common Authorization Bugs

```rust
// BUG 1: Admin check uses == instead of != 
// (typo that allows anyone EXCEPT admin)
if info.sender == config.admin {
    return Err(ContractError::Unauthorized {});
}

// BUG 2: Admin address not validated during instantiation
pub fn instantiate(deps: DepsMut, _env: Env, info: MessageInfo, msg: InstantiateMsg)
    -> Result<Response, ContractError> {
    let config = Config {
        admin: msg.admin, // Not validated! Could be invalid address
    };
    // SAFE: Validate the address
    let admin = deps.api.addr_validate(&msg.admin)?;
}

// BUG 3: Funds sent but not checked
pub fn execute_buy(deps: DepsMut, info: MessageInfo) -> Result<Response, ContractError> {
    // Assumes correct denom and amount were sent, but doesn't check
    // SAFE: Check funds explicitly
    let payment = info.funds.iter()
        .find(|c| c.denom == "uatom")
        .ok_or(ContractError::NoFunds {})?;
    if payment.amount < required_amount {
        return Err(ContractError::InsufficientFunds {});
    }
}
```

- [ ] Every `ExecuteMsg` handler validates `info.sender`
- [ ] Admin addresses validated with `deps.api.addr_validate()`
- [ ] `info.funds` checked when payment is expected
- [ ] No funds accepted when payment is NOT expected

---

## Step 3: State Management

Review all storage types and access patterns:

| Type | cw-storage-plus | Risk |
|------|-----------------|------|
| `Item<T>` | Single value | Low (bounded) |
| `Map<K, V>` | Key-value mapping | Medium (unbounded growth) |
| `SnapshotMap<K, V>` | Map with history | High (grows with every change) |
| `IndexedMap<K, V>` | Map with secondary indices | Medium (index sync issues) |
| `Deque<T>` | Double-ended queue | Medium (unbounded growth) |

### Storage Safety Checklist

- [ ] All `Map` iterations use `.range()` with pagination (`.take(limit)`)
- [ ] No unbounded `collect()` on iterators in query handlers
- [ ] `SnapshotMap` usage justified (needed for historical queries?)
- [ ] Storage keys don't collide across different state variables
- [ ] State updates are atomic within a single message execution

---

## Step 4: Cross-Contract Communication

CosmWasm uses **SubMessages** for cross-contract calls:

```rust
// Fire-and-forget (no reply)
let msg = WasmMsg::Execute {
    contract_addr: other_contract.to_string(),
    msg: to_binary(&other_msg)?,
    funds: vec![],
};
Ok(Response::new().add_message(msg))

// With reply handling
let submsg = SubMsg::reply_on_success(
    WasmMsg::Execute { /* ... */ },
    REPLY_ID,
);
Ok(Response::new().add_submessage(submsg))
```

### SubMessage Security

| Reply Mode | When Called | Risk |
|-----------|-------------|------|
| `reply_on_success` | Only if sub-call succeeds | State may be inconsistent if sub-call fails silently |
| `reply_on_error` | Only if sub-call fails | State already partially committed |
| `reply_always` | Always | Must handle both success and error paths |
| No reply | Fire-and-forget | Cannot know if sub-call succeeded |

- [ ] Reply handlers check `msg.id` to distinguish between different SubMessages
- [ ] Reply handlers handle both success and error cases
- [ ] State updates before SubMessage are rolled back on failure (or handled in reply)
- [ ] No reentrancy via SubMessage reply chain

---

## Step 5: IBC Integration

If the contract implements IBC entry points:

```rust
// IBC entry points
#[entry_point]
pub fn ibc_channel_open(/* ... */) -> Result<IbcChannelOpenResponse, ContractError> { }
#[entry_point]
pub fn ibc_channel_connect(/* ... */) -> Result<IbcBasicResponse, ContractError> { }
#[entry_point]
pub fn ibc_packet_receive(/* ... */) -> Result<IbcReceiveResponse, ContractError> { }
#[entry_point]
pub fn ibc_packet_ack(/* ... */) -> Result<IbcBasicResponse, ContractError> { }
#[entry_point]
pub fn ibc_packet_timeout(/* ... */) -> Result<IbcBasicResponse, ContractError> { }
```

### IBC Security Checklist

- [ ] `ibc_channel_open` validates counterparty port and channel version
- [ ] `ibc_packet_receive` validates packet source (port, channel)
- [ ] Packet data deserialization handles invalid/malicious data gracefully
- [ ] Timeout handling properly reverts any state changes from the send side
- [ ] Acknowledgement errors don't leave state inconsistent
- [ ] Channel ordering (ordered vs unordered) is appropriate for the use case
- [ ] No assumption about packet delivery order (for unordered channels)

---

## Step 6: Math Review

CosmWasm uses custom integer types:

| Type | Range | Overflow Behavior |
|------|-------|-------------------|
| `Uint128` | 0 to 2^128-1 | Panics on overflow (safe in CosmWasm) |
| `Uint256` | 0 to 2^256-1 | Panics on overflow |
| `Uint64` | 0 to 2^64-1 | Panics on overflow |
| `Decimal` | Fixed-point 18 decimals | Panics on overflow |
| `Decimal256` | Fixed-point 18 decimals, 256-bit | Panics on overflow |

**Key:** CosmWasm integer types panic on overflow (unlike raw Rust integers in release mode which wrap). However, the **panic itself** causes the transaction to fail, which can be weaponized for DoS.

- [ ] Accumulator variables use `Uint256` if they could exceed `Uint128` range
- [ ] Division operations check for zero denominator
- [ ] `Decimal` precision sufficient for rate calculations
- [ ] Fee/reward calculations don't lose precision due to integer division order

---

## Step 7: Migration

```rust
#[entry_point]
pub fn migrate(deps: DepsMut, _env: Env, msg: MigrateMsg) -> Result<Response, ContractError> {
    // CRITICAL: Check contract version
    let version = cw2::get_contract_version(deps.storage)?;
    if version.contract != CONTRACT_NAME {
        return Err(ContractError::WrongContract {});
    }
    if version.version >= CONTRACT_VERSION.to_string() {
        return Err(ContractError::AlreadyMigrated {});
    }
    // Perform migration...
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new())
}
```

- [ ] `migrate` entry point exists (if upgradeability is intended)
- [ ] Migration checks contract name and version (use `cw2`)
- [ ] Only contract admin can trigger migration (enforced by CosmWasm runtime)
- [ ] State schema changes handled (old state → new state)
- [ ] Admin can be changed or removed (assess centralization risk)

---

## Step 8: Query Safety

- [ ] No unbounded iteration in any query handler
- [ ] All list queries paginated with reasonable default limits
- [ ] Queries don't perform expensive computation (could be used for gas griefing on chains that charge query gas)
- [ ] Sensitive data not exposed via queries (if applicable)

---

## Step 9: Admin Powers

Assess centralization risk:

| Admin Power | Risk Level | Mitigation |
|-------------|------------|------------|
| Can migrate (upgrade) contract | HIGH | Multisig, timelock, governance |
| Can change config parameters | MEDIUM | Bounds checking, timelock |
| Can pause/unpause | MEDIUM | Necessary but should be multisig |
| Can withdraw funds | CRITICAL | Should require timelock + multisig |
| Can mint tokens | CRITICAL | Supply cap, governance |
| Admin is immutable EOA | HIGH | Should be changeable to multisig |

- [ ] Admin can be transferred (not hardcoded)
- [ ] Critical admin actions have timelock or require governance
- [ ] Admin cannot rug-pull user funds directly
- [ ] Emergency pause mechanism exists but is properly restricted

---

## Step 10: Report

### Severity Guide for CosmWasm

| Severity | Criteria | Example |
|----------|----------|---------|
| **Critical** | Direct fund theft, unlimited minting | Missing `info.sender` check on withdraw |
| **High** | Fund loss under conditions, protocol DoS | Unbounded iteration in execute handler |
| **Medium** | Incorrect behavior, limited impact | Precision loss in fee calculation |
| **Low** | Best practice violation, informational | Missing `cw2` version tracking |
| **Gas Optimization** | Unnecessary gas consumption | Redundant storage reads |

### Report Structure

1. Protocol overview and scope
2. Findings table (severity, title, status)
3. Detailed findings with:
   - Description and affected code
   - Impact assessment (Cosmos-specific: gas, IBC, governance implications)
   - PoC or test case (using `cw-multi-test`)
   - Recommended fix with code
4. Centralization risks
5. Gas optimization suggestions
