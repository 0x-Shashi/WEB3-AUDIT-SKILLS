---
id: COSMWASM-PATTERNS
title: CosmWasm Vulnerability Patterns
category: cosmos-scanner
difficulty: advanced
triggers:
  - cosmwasm vulnerability patterns
  - cosmwasm security
  - cosmos smart contract bugs
  - cw20 vulnerability
related_skills:
  - cosmos-scanner/resources/ibc-security.md
  - cosmos-scanner/workflows/cosmwasm-audit.md
tags:
  - cosmwasm
  - cosmos
  - rust
  - patterns
last_updated: 2026-02-24
---

# CosmWasm Vulnerability Patterns

> CosmWasm contracts run in a sandboxed Wasm VM on Cosmos SDK chains. Unlike Solidity, CosmWasm uses an actor model with message-passing (no synchronous external calls), Rust's type safety, and explicit storage management. These patterns cover the unique vulnerabilities in this architecture.

---

## 1. Unbounded State Iteration (CRITICAL)

**Impact**: A contract that iterates over its entire state map in a single call will hit the gas limit as state grows, rendering the function permanently unusable (DoS).

### Vulnerable Code
```rust
pub fn execute_distribute_rewards(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
) -> Result<Response, ContractError> {
    // BUG: Iterates over ALL stakers — gas DoS when stakers > ~1000
    let stakers: Vec<(Addr, Uint128)> = STAKERS
        .range(deps.storage, None, None, Order::Ascending)
        .map(|item| {
            let (addr, stake) = item?;
            Ok((addr, stake))
        })
        .collect::<StdResult<Vec<_>>>()?;

    for (addr, stake) in stakers {
        let reward = calculate_reward(stake)?;
        REWARDS.update(deps.storage, &addr, |r| -> StdResult<_> {
            Ok(r.unwrap_or_default() + reward)
        })?;
    }

    Ok(Response::new())
}
```

### Secure Code
```rust
pub fn execute_distribute_rewards(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    start_after: Option<String>,
    limit: Option<u32>,
) -> Result<Response, ContractError> {
    let limit = limit.unwrap_or(50).min(100); // FIX: Bounded pagination

    let start = start_after
        .map(|s| Bound::exclusive(deps.api.addr_validate(&s)?))
        .transpose()?;

    let stakers: Vec<(Addr, Uint128)> = STAKERS
        .range(deps.storage, start, None, Order::Ascending)
        .take(limit as usize)  // FIX: Only process `limit` entries
        .map(|item| {
            let (addr, stake) = item?;
            Ok((addr, stake))
        })
        .collect::<StdResult<Vec<_>>>()?;

    for (addr, stake) in stakers {
        let reward = calculate_reward(stake)?;
        REWARDS.update(deps.storage, &addr, |r| -> StdResult<_> {
            Ok(r.unwrap_or_default() + reward)
        })?;
    }

    Ok(Response::new().add_attribute("processed", limit.to_string()))
}
```

**Detection**: Search for `.range(storage, None, None, ...)` without `.take()`. Any unbounded iteration is a red flag.

---

## 2. Missing Authorization on Execute Handlers (CRITICAL)

**Impact**: Any address can call privileged functions (withdraw, update config, mint tokens).

### Vulnerable Code
```rust
pub fn execute_withdraw(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> Result<Response, ContractError> {
    // BUG: No check on info.sender — anyone can withdraw
    let config = CONFIG.load(deps.storage)?;

    let msg = BankMsg::Send {
        to_address: info.sender.to_string(), // Attacker receives funds
        amount: vec![Coin { denom: config.denom.clone(), amount }],
    };

    Ok(Response::new().add_message(msg))
}
```

### Secure Code
```rust
pub fn execute_withdraw(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    // FIX: Verify sender is authorized
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized {});
    }

    // Also verify contract has sufficient balance
    let balance = deps.querier.query_balance(&env.contract.address, &config.denom)?;
    if balance.amount < amount {
        return Err(ContractError::InsufficientFunds {});
    }

    let msg = BankMsg::Send {
        to_address: config.treasury.to_string(), // FIX: Send to treasury, not sender
        amount: vec![Coin { denom: config.denom, amount }],
    };

    Ok(Response::new().add_message(msg))
}
```

---

## 3. Arithmetic Overflow in Token Math (CRITICAL)

**Impact**: Uint128/Uint256 overflow panics or wraps, causing incorrect token accounting.

### Vulnerable Code
```rust
pub fn calculate_shares(
    deposit: Uint128,
    total_supply: Uint128,
    total_assets: Uint128,
) -> Uint128 {
    // BUG: If total_assets == 0 on first deposit, division by zero panics
    // BUG: deposit * total_supply can overflow Uint128 for large values
    deposit * total_supply / total_assets
}
```

### Secure Code
```rust
pub fn calculate_shares(
    deposit: Uint128,
    total_supply: Uint128,
    total_assets: Uint128,
) -> StdResult<Uint128> {
    if total_assets.is_zero() {
        // First depositor: 1:1 share ratio
        return Ok(deposit);
    }

    // FIX: Use Uint256 intermediate to prevent overflow
    let deposit_256 = Uint256::from(deposit);
    let supply_256 = Uint256::from(total_supply);
    let assets_256 = Uint256::from(total_assets);

    let shares_256 = deposit_256
        .checked_mul(supply_256)?
        .checked_div(assets_256)?;

    // Safely downcast back to Uint128
    Uint128::try_from(shares_256)
        .map_err(|_| StdError::generic_err("shares overflow Uint128"))
}
```

---

## 4. SubMessage Reply Mishandling (HIGH)

**Impact**: Malicious or failed sub-messages can corrupt state if the reply handler doesn't properly handle errors or validate the reply data.

### Vulnerable Code
```rust
pub fn execute_swap(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    offer: Coin,
) -> Result<Response, ContractError> {
    // Track expected swap in state BEFORE sub-message executes
    PENDING_SWAP.save(deps.storage, &PendingSwap {
        user: info.sender.clone(),
        amount: offer.amount,
    })?;

    let swap_msg = WasmMsg::Execute {
        contract_addr: dex_contract.to_string(),
        msg: to_json_binary(&DexMsg::Swap { offer })?,
        funds: vec![offer.clone()],
    };

    // BUG: Using ReplyOn::Always but only handling success in reply
    Ok(Response::new().add_submessage(SubMsg::reply_always(swap_msg, SWAP_REPLY_ID)))
}

#[entry_point]
pub fn reply(deps: DepsMut, _env: Env, msg: Reply) -> Result<Response, ContractError> {
    match msg.id {
        SWAP_REPLY_ID => {
            // BUG: Assumes success — doesn't check msg.result
            let pending = PENDING_SWAP.load(deps.storage)?;
            // Credits user even if swap failed!
            BALANCES.update(deps.storage, &pending.user, |b| -> StdResult<_> {
                Ok(b.unwrap_or_default() + pending.amount)
            })?;
            PENDING_SWAP.remove(deps.storage);
            Ok(Response::new())
        }
        _ => Err(ContractError::UnknownReplyId { id: msg.id }),
    }
}
```

### Secure Code
```rust
#[entry_point]
pub fn reply(deps: DepsMut, _env: Env, msg: Reply) -> Result<Response, ContractError> {
    match msg.id {
        SWAP_REPLY_ID => {
            let pending = PENDING_SWAP.load(deps.storage)?;
            PENDING_SWAP.remove(deps.storage);

            // FIX: Check reply result explicitly
            match msg.result {
                SubMsgResult::Ok(response) => {
                    // Parse return data to get actual swap output
                    let output = parse_swap_response(response)?;
                    BALANCES.update(deps.storage, &pending.user, |b| -> StdResult<_> {
                        Ok(b.unwrap_or_default() + output.received)
                    })?;
                    Ok(Response::new().add_attribute("swap", "success"))
                }
                SubMsgResult::Err(err) => {
                    // FIX: Refund user on failure
                    let refund = BankMsg::Send {
                        to_address: pending.user.to_string(),
                        amount: vec![Coin {
                            denom: pending.denom,
                            amount: pending.amount,
                        }],
                    };
                    Ok(Response::new()
                        .add_message(refund)
                        .add_attribute("swap", "failed"))
                }
            }
        }
        _ => Err(ContractError::UnknownReplyId { id: msg.id }),
    }
}
```

---

## 5. Storage Key Collision (HIGH)

**Impact**: Overlapping key prefixes in `cw-storage-plus` cause different data types to read/write each other's storage slots.

### Vulnerable Code
```rust
use cw_storage_plus::{Item, Map};

// BUG: "config" and "config_v2" share prefix "config"
// Map keys starting with "config" will collide with Item "config_v2"
pub const CONFIG: Item<Config> = Item::new("config");
pub const CONFIG_V2: Item<ConfigV2> = Item::new("config_v2"); // Starts with "config"!

// BUG: Map and Item with overlapping namespaces
pub const USERS: Map<&Addr, UserData> = Map::new("user");
pub const USER_COUNT: Item<u64> = Item::new("user_count"); // Key prefix overlaps!
```

### Secure Code
```rust
use cw_storage_plus::{Item, Map};

// FIX: Use short, unique, non-overlapping prefixes
pub const CONFIG: Item<Config> = Item::new("cfg");
pub const CONFIG_V2: Item<ConfigV2> = Item::new("cf2");

pub const USERS: Map<&Addr, UserData> = Map::new("usr");
pub const USER_COUNT: Item<u64> = Item::new("ucnt");

// Best practice: Use single-character or numeric prefixes
pub const BALANCES: Map<&Addr, Uint128> = Map::new("b");
pub const TOTAL_SUPPLY: Item<Uint128> = Item::new("s");
pub const ADMIN: Item<Addr> = Item::new("a");
```

**Detection**: List all storage constants and check if any key is a prefix of another.

---

## 6. Unprotected Migrate Entry Point (HIGH)

**Impact**: Without proper access control, anyone who can trigger a migration (if the contract allows it) can change the contract's code hash, replacing the entire contract logic.

### Vulnerable Code
```rust
#[entry_point]
pub fn migrate(deps: DepsMut, _env: Env, msg: MigrateMsg) -> Result<Response, ContractError> {
    // BUG: No version check, no admin check
    // The migrate entrypoint itself is admin-gated by the chain,
    // BUT the logic inside should still validate state transitions
    CONFIG.update(deps.storage, |mut config| -> StdResult<_> {
        config.some_field = msg.new_value; // No validation
        Ok(config)
    })?;
    Ok(Response::new())
}
```

### Secure Code
```rust
#[entry_point]
pub fn migrate(deps: DepsMut, _env: Env, msg: MigrateMsg) -> Result<Response, ContractError> {
    // FIX: Validate contract version (prevent downgrade)
    let ver = cw2::get_contract_version(deps.storage)?;
    if ver.contract != CONTRACT_NAME {
        return Err(ContractError::InvalidContract {});
    }

    let current: Version = ver.version.parse()?;
    let new: Version = CONTRACT_VERSION.parse()?;
    if current >= new {
        return Err(ContractError::InvalidVersion {
            current: ver.version,
            new: CONTRACT_VERSION.to_string(),
        });
    }

    // Perform state migration
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new().add_attribute("migrate", "success"))
}
```

---

## 7. Reentrancy via Message Ordering (HIGH)

**Impact**: CosmWasm prevents synchronous reentrancy (no external calls mid-execution), but messages execute in order after the current handler completes. If state is updated after adding messages, the message sees stale state.

### Vulnerable Pattern
```rust
pub fn execute_withdraw(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let balance = BALANCES.load(deps.storage, &info.sender)?;
    if balance < amount {
        return Err(ContractError::InsufficientFunds {});
    }

    // Send funds THEN update state? In CosmWasm this is safe for single messages
    // BUT: If you add multiple sub-messages, order matters
    let send = BankMsg::Send {
        to_address: info.sender.to_string(),
        amount: vec![Coin { denom: "uatom".into(), amount }],
    };

    // FIX: Always update state BEFORE adding messages (CEI pattern still best practice)
    BALANCES.save(deps.storage, &info.sender, &(balance - amount))?;

    Ok(Response::new().add_message(send))
}
```

**Key insight**: CosmWasm's actor model prevents direct reentrancy, but sub-message replies CAN re-enter. Always apply CEI (Checks-Effects-Interactions) pattern.

---

## 8. Funds Sent but Not Verified (MEDIUM)

**Impact**: Execute handler accepts `info.funds` but doesn't validate the amount or denom, leading to under/overpayment.

### Vulnerable Code
```rust
pub fn execute_buy(
    deps: DepsMut,
    info: MessageInfo,
    token_id: String,
) -> Result<Response, ContractError> {
    let listing = LISTINGS.load(deps.storage, &token_id)?;

    // BUG: Doesn't check that user sent the correct amount
    // User can send 1 uatom and buy a 1000 uatom item
    // info.funds is whatever the user sent — could be empty!

    LISTINGS.remove(deps.storage, &token_id);
    // Transfer NFT to buyer...
    Ok(Response::new())
}
```

### Secure Code
```rust
pub fn execute_buy(
    deps: DepsMut,
    info: MessageInfo,
    token_id: String,
) -> Result<Response, ContractError> {
    let listing = LISTINGS.load(deps.storage, &token_id)?;

    // FIX: Validate exact payment
    let payment = info
        .funds
        .iter()
        .find(|c| c.denom == listing.price_denom)
        .ok_or(ContractError::NoPayment {})?;

    if payment.amount < listing.price {
        return Err(ContractError::InsufficientPayment {});
    }

    // Refund excess
    let mut msgs = vec![];
    if payment.amount > listing.price {
        let refund = payment.amount - listing.price;
        msgs.push(BankMsg::Send {
            to_address: info.sender.to_string(),
            amount: vec![Coin { denom: listing.price_denom.clone(), amount: refund }],
        });
    }

    LISTINGS.remove(deps.storage, &token_id);
    Ok(Response::new().add_messages(msgs))
}
```

---

## 9. Query Amplification / Expensive Queries (MEDIUM)

**Impact**: View functions that trigger expensive computation or large state reads can DoS full nodes.

### Detection
```rust
// Look for queries that iterate unbounded state
#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        // BUG: Returns ALL stakers — DoS if thousands exist
        QueryMsg::AllStakers {} => {
            let stakers: Vec<_> = STAKERS
                .range(deps.storage, None, None, Order::Ascending)
                .collect::<StdResult<Vec<_>>>()?;
            to_json_binary(&stakers)
        }
    }
}

// FIX: Always paginate queries
QueryMsg::Stakers { start_after, limit } => {
    let limit = limit.unwrap_or(30).min(100);
    let start = start_after.map(Bound::exclusive);
    let stakers: Vec<_> = STAKERS
        .range(deps.storage, start, None, Order::Ascending)
        .take(limit as usize)
        .collect::<StdResult<Vec<_>>>()?;
    to_json_binary(&stakers)
}
```

---

## CosmWasm Audit Checklist

### Critical Checks
- [ ] All execute handlers check `info.sender` authorization
- [ ] All state iterations are bounded (`.take(limit)`)
- [ ] Arithmetic uses `checked_*` methods or `Uint256` intermediates
- [ ] `info.funds` validated for amount and denom in payment handlers

### High Checks
- [ ] SubMessage replies handle both success and error cases
- [ ] Storage key prefixes are unique and non-overlapping
- [ ] Migrate entry validates contract version (no downgrade)
- [ ] State updated before messages added (CEI pattern)

### Medium Checks
- [ ] Queries are paginated with reasonable limits
- [ ] Admin functions have timelock or multisig
- [ ] Events/attributes emitted for all state changes
- [ ] CW2 contract info stored and validated

---

## Related Files

- [IBC Security Guide](ibc-security.md) — Inter-Blockchain Communication attack surface
- [CosmWasm Audit Workflow](../workflows/cosmwasm-audit.md) — Step-by-step audit process
