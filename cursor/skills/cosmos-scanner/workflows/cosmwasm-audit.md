# CosmWasm Audit Workflow

Systematic workflow for auditing CosmWasm smart contracts.

---

## Phase 1: Setup (30 minutes)

### 1.1 Environment Setup

```bash
git clone [repo]
cd [repo]

# Build
cargo build

# Run tests
cargo test

# Check for warnings
cargo clippy

# Generate schema (if available)
cargo schema
```

### 1.2 Scope Mapping

```markdown
## Audit Scope

**Contract Name:** [name]
**CosmWasm Version:** [version]
**Commit:** [hash]

### Entry Points
| Entry Point | Purpose | Priority |
|-------------|---------|----------|
| instantiate | Contract init | High |
| execute | State changes | Critical |
| query | Read state | Medium |
| migrate | Upgrades | Critical |
| sudo | Gov actions | High |
| ibc_* | IBC handlers | Critical |

### Execute Handlers
| Handler | Access | Priority |
|---------|--------|----------|
| Transfer | Public | High |
| Withdraw | Owner | Critical |
| UpdateConfig | Admin | Critical |

### Storage Items
| Item | Type | Purpose |
|------|------|---------|
| CONFIG | Item | Configuration |
| BALANCES | Map | User balances |
| STATE | Item | Global state |
```

---

## Phase 2: Message Analysis (2-3 hours)

### 2.1 Per-Handler Template

```markdown
## Handler: execute_[name]

### Purpose
[What this handler does]

### Access Control
- Who can call: [Anyone / Owner / Admin]
- Verification: [Line/method]

### Input Validation
| Field | Type | Validated? | How? |
|-------|------|------------|------|
| recipient | String | ✅ | addr_validate |
| amount | Uint128 | ❌ | ISSUE |

### Funds Handling
- Expected: [denom, amount] or none
- Validated: [Yes/No]

### State Changes
| Storage | Before | After |
|---------|--------|-------|
| BALANCES[sender] | x | x - amount |
| BALANCES[recipient] | y | y + amount |

### SubMessages
| Target | Purpose | Reply? |
|--------|---------|--------|
| Bank::Send | Transfer | No |

### Events/Attributes
- [List emitted attributes]

### Issues Found
- [None or list]
```

---

## Phase 3: Access Control Audit (2 hours)

### 3.1 Permission Matrix

```markdown
| Handler | Auth Type | Verified? | Location |
|---------|-----------|-----------|----------|
| transfer | Sender owns balance | ✅ | L45 |
| withdraw | Only owner | ✅ | L78 |
| update_config | Only admin | ❌ ISSUE | L112 |
| mint | Only minter role | ✅ | L156 |
```

### 3.2 Access Control Patterns

```rust
// Verify these patterns are correctly implemented:

// Owner check
fn only_owner(deps: Deps, info: &MessageInfo) -> Result<(), ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.owner {
        return Err(ContractError::Unauthorized {});
    }
    Ok(())
}

// Admin check
fn only_admin(deps: Deps, info: &MessageInfo) -> Result<(), ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if !config.admins.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    Ok(())
}
```

---

## Phase 4: Storage Security (1-2 hours)

### 4.1 Storage Inventory

```markdown
## Storage Items

| Name | Type | Key Format | Value |
|------|------|------------|-------|
| CONFIG | Item | "config" | Config |
| BALANCES | Map | (&Addr) | Uint128 |
| ORDERS | Map | (u64) | Order |
| USER_ORDERS | Map | (&Addr, u64) | () |
```

### 4.2 Storage Security Checks

```markdown
## Storage Audit

### Key Collision Check
- [ ] All Items have unique prefixes
- [ ] All Maps have unique prefixes
- [ ] No prefix is substring of another

### Initialization
| Storage | Initialized In | Required? |
|---------|----------------|-----------|
| CONFIG | instantiate | ✅ Yes |
| BALANCES | on first deposit | Optional |

### Migration Safety
- [ ] Old state version readable
- [ ] Migration updates all necessary fields
- [ ] No orphaned data
```

---

## Phase 5: Arithmetic Review (1-2 hours)

### 5.1 Operation Inventory

```markdown
| Location | Operation | Type | Checked? |
|----------|-----------|------|----------|
| L45 | a + b | Uint128 | ✅ checked_add |
| L78 | a - b | Uint128 | ❌ ISSUE |
| L112 | a * b / c | Uint128 | ⚠️ precision |
```

### 5.2 Safe Patterns

```rust
// ✅ All arithmetic should use checked operations
amount.checked_add(other)?;
amount.checked_sub(other)?;
amount.checked_mul(other)?;
amount.checked_div(other)?;

// ✅ For precision-sensitive calculations
use cosmwasm_std::{Uint256, Decimal};

let result = Uint256::from(a)
    .checked_mul(Uint256::from(b))?
    .checked_div(Uint256::from(c))?;
```

---

## Phase 6: Funds Handling (1-2 hours)

### 6.1 Funds Flow Analysis

```markdown
## Funds Flow

### Incoming Funds
| Handler | Expected Denom | Validated? |
|---------|----------------|------------|
| deposit | uatom | ✅ |
| buy | config.denom | ✅ |

### Outgoing Funds
| Handler | Method | Amount Source |
|---------|--------|---------------|
| withdraw | BankMsg::Send | state balance |
| claim | BankMsg::Send | calculated reward |

### Fund Invariants
- [ ] Sum of balances = contract balance
- [ ] No funds stuck in contract
- [ ] No funds sent without deduction
```

### 6.2 Funds Validation Pattern

```rust
// ✅ Proper funds validation
fn validate_funds(
    info: &MessageInfo,
    expected_denom: &str,
    expected_amount: Uint128,
) -> Result<(), ContractError> {
    // Check exactly one coin
    if info.funds.len() != 1 {
        return Err(ContractError::InvalidFunds {});
    }
    
    let coin = &info.funds[0];
    
    // Check denom
    if coin.denom != expected_denom {
        return Err(ContractError::InvalidDenom {});
    }
    
    // Check amount
    if coin.amount != expected_amount {
        return Err(ContractError::InvalidAmount {});
    }
    
    Ok(())
}
```

---

## Phase 7: SubMessage & Reply (1-2 hours)

### 7.1 SubMessage Analysis

```markdown
## SubMessages

| Handler | SubMsg Target | Reply Mode | Reply ID |
|---------|---------------|------------|----------|
| execute_swap | DEX contract | OnSuccess | 1 |
| execute_stake | Staking module | Always | 2 |

### Reply Handler Analysis

| Reply ID | Purpose | State Changes |
|----------|---------|---------------|
| 1 | Handle swap result | Update balances |
| 2 | Handle stake result | Update stake info |
```

### 7.2 Reply Security

```rust
// ✅ Proper reply handling
#[entry_point]
pub fn reply(
    deps: DepsMut,
    _env: Env,
    msg: Reply,
) -> Result<Response, ContractError> {
    match msg.id {
        SWAP_REPLY_ID => handle_swap_reply(deps, msg),
        STAKE_REPLY_ID => handle_stake_reply(deps, msg),
        _ => Err(ContractError::UnknownReplyId { id: msg.id }),
    }
}

fn handle_swap_reply(
    deps: DepsMut,
    msg: Reply,
) -> Result<Response, ContractError> {
    // ✅ Check result
    let result = msg.result.into_result()
        .map_err(|e| ContractError::SubMsgFailed { reason: e })?;
    
    // ✅ Parse response data if needed
    let data = result.data
        .ok_or(ContractError::NoResponseData {})?;
    
    // ✅ Validate and process
    // ...
    
    Ok(Response::new())
}
```

---

## Phase 8: IBC Analysis (if applicable) (2-3 hours)

See [ibc-security.md](resources/ibc-security.md) for detailed IBC audit process.

### Quick IBC Checklist

- [ ] Channel validation in ibc_channel_open
- [ ] Packet data validation in ibc_packet_receive
- [ ] Timeout handler refunds properly
- [ ] Ack handler handles success/error
- [ ] Pending operations tracked
- [ ] No funds lost in any path

---

## Phase 9: Query Security (1 hour)

### 9.1 Query Audit

```markdown
| Query | Pagination? | Max Limit | Sensitive? |
|-------|-------------|-----------|------------|
| all_users | ✅ | 30 | No |
| user_balance | N/A | N/A | No |
| config | N/A | N/A | ⚠️ Admin addr |
```

### 9.2 Query Patterns

```rust
// ✅ Paginated query
pub fn query_all_items(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<Binary> {
    const MAX_LIMIT: u32 = 30;
    const DEFAULT_LIMIT: u32 = 10;
    
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let start = start_after.map(|s| Bound::exclusive(s));
    
    let items: Vec<_> = ITEMS
        .range(deps.storage, start, None, Order::Ascending)
        .take(limit as usize)
        .collect::<StdResult<Vec<_>>>()?;
    
    to_json_binary(&ItemsResponse { items })
}
```

---

## Phase 10: Testing (2-4 hours)

### 10.1 Attack Tests

```rust
#[test]
fn test_unauthorized_withdraw() {
    let mut deps = mock_dependencies();
    let info = mock_info("attacker", &[]);
    
    // Setup...
    
    let msg = ExecuteMsg::Withdraw { amount: Uint128::new(100) };
    let res = execute(deps.as_mut(), mock_env(), info, msg);
    
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), ContractError::Unauthorized {});
}

#[test]
fn test_invalid_denom() {
    let mut deps = mock_dependencies();
    let info = mock_info("user", &[coin(100, "wrong_denom")]);
    
    let msg = ExecuteMsg::Deposit {};
    let res = execute(deps.as_mut(), mock_env(), info, msg);
    
    assert!(res.is_err());
}
```

### 10.2 Edge Cases

```rust
#[test]
fn test_zero_amount() { /* ... */ }

#[test]
fn test_max_amount() { /* ... */ }

#[test]
fn test_empty_funds() { /* ... */ }

#[test]
fn test_multiple_coins() { /* ... */ }
```

---

## Quick Grep Audit

```bash
# Entry points
grep -rn "#\[entry_point\]" src/

# Execute handlers
grep -rn "ExecuteMsg::" src/

# Storage definitions
grep -rn "Item::\|Map::" src/

# Sender checks
grep -rn "info.sender" src/

# Funds handling
grep -rn "info.funds" src/

# Address validation
grep -rn "addr_validate" src/

# SubMessages
grep -rn "SubMsg::" src/

# Reply handling
grep -rn "Reply\|reply" src/

# Arithmetic
grep -rn "checked_add\|checked_sub" src/

# Unwrap usage (potential panic)
grep -rn "\.unwrap()" src/

# Error handling
grep -rn "ContractError\|StdError" src/
```

---

## Audit Completion Checklist

### Messages
- [ ] All execute handlers reviewed
- [ ] Input validation complete
- [ ] Access control verified
- [ ] Funds handling secure

### Storage
- [ ] No key collisions
- [ ] All storage initialized properly
- [ ] Migration handles old state

### Arithmetic
- [ ] All operations use checked math
- [ ] Precision handled correctly
- [ ] No division by zero

### SubMessages
- [ ] Reply handlers complete
- [ ] All reply IDs handled
- [ ] Error paths handled

### IBC (if applicable)
- [ ] Channel validation
- [ ] Packet validation
- [ ] Timeout/ack handling

### Queries
- [ ] Pagination implemented
- [ ] Limits enforced
- [ ] No sensitive data exposed

### Testing
- [ ] Unit tests pass
- [ ] Attack tests written
- [ ] Edge cases covered

