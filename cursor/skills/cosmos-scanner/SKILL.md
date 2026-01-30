---
name: Cosmos Scanner
description: CosmWasm smart contract vulnerability scanner with 50+ security patterns
version: 1.0.0
author: Web3 Security Plugin
tags: [cosmwasm, cosmos, rust, security, audit, scanner, vulnerability]
---

# Cosmos Scanner Skill

Comprehensive security scanner for CosmWasm smart contracts in the Cosmos ecosystem. Covers Rust-based CosmWasm contracts, IBC messaging, and Cosmos SDK integrations.

## Capabilities

- **CosmWasm Analysis**: Contract lifecycle, messages, queries, storage
- **IBC Security**: Cross-chain messaging, channel validation, packet handling
- **Cosmos SDK Integration**: Bank, staking, distribution module interactions
- **CW Standards**: CW20, CW721, CW1, CW3 compliance and security
- **Storage Patterns**: State management, migrations, item/map security

## Vulnerability Categories

### Category 1: Message Validation (MV)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| MV-01 | Missing Sender Validation | Critical | Access Control |
| MV-02 | Unvalidated Message Fields | High | Input Validation |
| MV-03 | Reply Data Injection | High | Message Handling |
| MV-04 | Missing Denom Validation | High | Token Handling |
| MV-05 | Info Funds Mismatch | High | Payment Handling |

### Category 2: Storage Security (ST)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| ST-01 | Storage Key Collision | Critical | Storage |
| ST-02 | Uninitialized State Access | High | Storage |
| ST-03 | Migration State Corruption | Critical | Upgrades |
| ST-04 | Missing State Bounds | Medium | Validation |
| ST-05 | Deque/Map Iteration DoS | Medium | Storage |

### Category 3: Access Control (AC)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| AC-01 | Missing Admin Check | Critical | Authorization |
| AC-02 | Improper Role Verification | Critical | Authorization |
| AC-03 | Unprotected Execute Entry | Critical | Authorization |
| AC-04 | Sudo Privilege Escalation | Critical | Authorization |
| AC-05 | Reply Callback Manipulation | High | Authorization |

### Category 4: Arithmetic (AR)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| AR-01 | Integer Overflow | High | Math |
| AR-02 | Integer Underflow | High | Math |
| AR-03 | Decimal Precision Loss | Medium | Math |
| AR-04 | Division by Zero | High | Math |
| AR-05 | Uint128/Uint256 Cast Issues | High | Math |

### Category 5: IBC Security (IBC)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| IBC-01 | Missing Channel Validation | Critical | IBC |
| IBC-02 | Packet Data Manipulation | Critical | IBC |
| IBC-03 | Timeout Handling Flaws | High | IBC |
| IBC-04 | Acknowledgement Injection | High | IBC |
| IBC-05 | Channel Ordering Issues | Medium | IBC |

### Category 6: Reentrancy & Ordering (RE)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| RE-01 | Submessage Reentrancy | High | Reentrancy |
| RE-02 | Reply Ordering Issues | Medium | Logic |
| RE-03 | State Update After SubMsg | High | Reentrancy |
| RE-04 | Cross-Contract Reentrancy | High | Reentrancy |

### Category 7: Token Handling (TK)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| TK-01 | Missing Denom Whitelist | High | Token |
| TK-02 | CW20 Allowance Race | Medium | Token |
| TK-03 | Native Token Confusion | High | Token |
| TK-04 | Missing Zero Check | Medium | Token |
| TK-05 | LP Token Inflation | Critical | Token |

### Category 8: Query Security (QY)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| QY-01 | Unbounded Query Response | Medium | DoS |
| QY-02 | Cross-Contract Query Trust | High | Trust |
| QY-03 | Stale Query Data | Medium | Logic |
| QY-04 | Query Reentrancy | Low | Edge Case |

---

## CosmWasm Contract Structure

### Standard Entry Points

```rust
use cosmwasm_std::{
    entry_point, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    // Initialize contract state
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Transfer { recipient, amount } => {
            execute_transfer(deps, env, info, recipient, amount)
        }
        // ... other handlers
    }
}

#[entry_point]
pub fn query(
    deps: Deps,
    env: Env,
    msg: QueryMsg,
) -> StdResult<Binary> {
    match msg {
        QueryMsg::Balance { address } => query_balance(deps, address),
        // ... other handlers
    }
}

#[entry_point]
pub fn migrate(
    deps: DepsMut,
    env: Env,
    msg: MigrateMsg,
) -> Result<Response, ContractError> {
    // Handle contract migration
}
```

### Secure Patterns

**Access Control:**
```rust
//  Admin check
fn only_admin(deps: Deps, info: &MessageInfo) -> Result<(), ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized {});
    }
    Ok(())
}

//  Validated address
fn validate_recipient(deps: Deps, recipient: &str) -> Result<Addr, ContractError> {
    deps.api.addr_validate(recipient)
        .map_err(|_| ContractError::InvalidAddress {})
}
```

**Safe Funds Handling:**
```rust
//  Verify expected payment
fn verify_payment(
    info: &MessageInfo,
    expected_denom: &str,
    expected_amount: Uint128,
) -> Result<(), ContractError> {
    let received = info
        .funds
        .iter()
        .find(|c| c.denom == expected_denom)
        .map(|c| c.amount)
        .unwrap_or_default();
    
    if received != expected_amount {
        return Err(ContractError::InvalidPayment {
            expected: expected_amount,
            received,
        });
    }
    Ok(())
}
```

---

## Protocol-Specific Checklists

### DeFi Protocols

```markdown
## AMM/DEX Checklist
- [ ] LP token math verified (no inflation)
- [ ] Slippage protection implemented
- [ ] Price manipulation resistant
- [ ] Pool ratio validation
- [ ] Fee calculations precise

## Lending Protocol Checklist
- [ ] Collateral calculations verified
- [ ] Liquidation threshold correct
- [ ] Interest accrual precise
- [ ] Oracle integration secure
- [ ] Bad debt handling implemented

## Staking Protocol Checklist
- [ ] Unbonding period enforced
- [ ] Reward calculations correct
- [ ] Slashing handled properly
- [ ] Delegation tracking accurate
```

### CW Standards

```markdown
## CW20 Token Checklist
- [ ] Transfer validates recipient
- [ ] Allowance race condition mitigated
- [ ] Minting access controlled
- [ ] Burn properly reduces supply
- [ ] Zero amount handling

## CW721 NFT Checklist
- [ ] Ownership correctly tracked
- [ ] Transfer validations complete
- [ ] Approval properly scoped
- [ ] Metadata immutable or controlled
```

---

## Analysis Commands

```bash
# Build
cargo build

# Test
cargo test

# Check (faster than build)
cargo check

# Clippy lints
cargo clippy

# Schema generation
cargo schema

# Optimize for deployment
cargo run-script optimize
```

### Grep Patterns

```bash
# Find entry points
grep -rn "#\[entry_point\]" src/

# Find execute handlers
grep -rn "ExecuteMsg::" src/

# Find storage definitions
grep -rn "Item::\|Map::\|Deque::" src/

# Find sender usage
grep -rn "info.sender\|info.funds" src/

# Find SubMessages
grep -rn "SubMsg::\|WasmMsg::" src/

# Find reply handlers
grep -rn "reply\|Reply" src/

# Find IBC handlers
grep -rn "ibc_\|IbcMsg::" src/

# Find arithmetic
grep -rn "checked_add\|checked_sub\|checked_mul\|checked_div" src/
grep -rn "[+\-*/]" src/ | grep -v "//"

# Find unwrap usage
grep -rn "\.unwrap()" src/
```

---

## Resources

- [cosmwasm-patterns.md](resources/cosmwasm-patterns.md) - Detailed vulnerability patterns
- [ibc-security.md](resources/ibc-security.md) - IBC messaging security
- [storage-security.md](resources/storage-security.md) - State management security

## Workflows

- [cosmwasm-audit.md](workflows/cosmwasm-audit.md) - Complete CosmWasm audit process

---

## Integration with Cyfrin Solodit

```markdown
## Search Queries for Cosmos Findings

- "cosmwasm" - All CosmWasm findings
- "cosmos" - Cosmos ecosystem issues
- "ibc" - IBC messaging bugs
- "cw20" - CW20 token issues
- "cw721" - CW721 NFT issues
```

