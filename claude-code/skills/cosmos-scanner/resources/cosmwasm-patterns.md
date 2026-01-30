# CosmWasm Vulnerability Patterns

Detailed vulnerability patterns for CosmWasm smart contracts.

---

## MV-01: Missing Sender Validation

### Description
Execute function doesn't verify the caller's identity or permissions.

### Vulnerable Code
```rust
pub fn execute_withdraw(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,  // Not validated!
    vault_id: u64,
    amount: Uint128,
) -> Result<Response, ContractError> {
    //  Anyone can withdraw from any vault!
    let mut vault = VAULTS.load(deps.storage, vault_id)?;
    vault.balance = vault.balance.checked_sub(amount)?;
    VAULTS.save(deps.storage, vault_id, &vault)?;
    
    Ok(Response::new()
        .add_message(BankMsg::Send {
            to_address: info.sender.to_string(),
            amount: vec![coin(amount.u128(), "uatom")],
        }))
}
```

### Secure Code
```rust
pub fn execute_withdraw(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    vault_id: u64,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let vault = VAULTS.load(deps.storage, vault_id)?;
    
    //  Verify caller owns the vault
    if info.sender != vault.owner {
        return Err(ContractError::Unauthorized {});
    }
    
    // ... proceed with withdrawal
}
```

---

## MV-04: Missing Denom Validation

### Description
Accepting any token denomination without validation.

### Vulnerable Code
```rust
pub fn execute_deposit(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    //  Accepts any denom!
    let amount = info.funds[0].amount;
    
    let mut state = STATE.load(deps.storage)?;
    state.total_deposits = state.total_deposits.checked_add(amount)?;
    STATE.save(deps.storage, &state)?;
    
    Ok(Response::new())
}
```

### Secure Code
```rust
pub fn execute_deposit(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    
    //  Find specific denom
    let deposit = info
        .funds
        .iter()
        .find(|c| c.denom == config.deposit_denom)
        .ok_or(ContractError::InvalidDenom {})?;
    
    //  Ensure only one coin sent
    if info.funds.len() != 1 {
        return Err(ContractError::MultipleCoins {});
    }
    
    // ... proceed with deposit
}
```

---

## MV-05: Info Funds Mismatch

### Description
Payment amount doesn't match expected/declared amount.

### Vulnerable Code
```rust
pub fn execute_buy(
    deps: DepsMut,
    info: MessageInfo,
    item_id: u64,
    declared_amount: Uint128,  // User claims payment amount
) -> Result<Response, ContractError> {
    let item = ITEMS.load(deps.storage, item_id)?;
    
    //  Trusts declared_amount, not actual funds!
    if declared_amount < item.price {
        return Err(ContractError::InsufficientPayment {});
    }
    
    // Transfers based on declared, not received
}
```

### Secure Code
```rust
pub fn execute_buy(
    deps: DepsMut,
    info: MessageInfo,
    item_id: u64,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let item = ITEMS.load(deps.storage, item_id)?;
    
    //  Check actual funds received
    let payment = info
        .funds
        .iter()
        .find(|c| c.denom == config.payment_denom)
        .map(|c| c.amount)
        .unwrap_or_default();
    
    if payment < item.price {
        return Err(ContractError::InsufficientPayment {
            required: item.price,
            received: payment,
        });
    }
    
    // ... proceed with purchase
}
```

---

## ST-01: Storage Key Collision

### Description
Different storage items using overlapping keys.

### Vulnerable Code
```rust
//  Same prefix for different data types
const CONFIG: Item<Config> = Item::new("config");
const CONFIG_V2: Item<ConfigV2> = Item::new("config");  // Collision!

//  Map keys can collide
const USER_DATA: Map<&str, UserData> = Map::new("user");
const USER_STATS: Map<&str, UserStats> = Map::new("user");  // Collision!
```

### Secure Code
```rust
//  Unique prefixes for each storage item
const CONFIG: Item<Config> = Item::new("config_v1");
const CONFIG_V2: Item<ConfigV2> = Item::new("config_v2");

//  Unique namespaces
const USER_DATA: Map<&Addr, UserData> = Map::new("user_data");
const USER_STATS: Map<&Addr, UserStats> = Map::new("user_stats");

//  Use typed keys for complex maps
const POSITION: Map<(&Addr, u64), Position> = Map::new("position");
```

---

## ST-03: Migration State Corruption

### Description
Contract migration corrupts or loses existing state.

### Vulnerable Code
```rust
#[entry_point]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: MigrateMsg,
) -> Result<Response, ContractError> {
    //  Overwrites existing state without migration
    let new_config = Config::default();
    CONFIG.save(deps.storage, &new_config)?;
    
    Ok(Response::new())
}
```

### Secure Code
```rust
// Define old and new state versions
#[cw_serde]
pub struct ConfigV1 {
    pub admin: Addr,
    pub fee: Uint128,
}

#[cw_serde]
pub struct ConfigV2 {
    pub admin: Addr,
    pub fee: Uint128,
    pub fee_recipient: Addr,  // New field
}

const CONFIG_V1: Item<ConfigV1> = Item::new("config");
const CONFIG_V2: Item<ConfigV2> = Item::new("config_v2");

#[entry_point]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, ContractError> {
    //  Load old state
    let old_config = CONFIG_V1.load(deps.storage)?;
    
    //  Migrate to new state
    let new_config = ConfigV2 {
        admin: old_config.admin,
        fee: old_config.fee,
        fee_recipient: deps.api.addr_validate(&msg.fee_recipient)?,
    };
    
    //  Save new state
    CONFIG_V2.save(deps.storage, &new_config)?;
    
    //  Optionally remove old state
    CONFIG_V1.remove(deps.storage);
    
    Ok(Response::new())
}
```

---

## RE-01: Submessage Reentrancy

### Description
State changes after submessage can be exploited through reply.

### Vulnerable Code
```rust
pub fn execute_withdraw(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let balance = BALANCES.load(deps.storage, &info.sender)?;
    
    //  External call BEFORE state update
    let msg = SubMsg::reply_on_success(
        BankMsg::Send {
            to_address: info.sender.to_string(),
            amount: vec![coin(amount.u128(), "uatom")],
        },
        REPLY_ID,
    );
    
    // State update happens later in reply - vulnerable!
    
    Ok(Response::new().add_submessage(msg))
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
    let mut balance = BALANCES.load(deps.storage, &info.sender)?;
    
    //  State update BEFORE external call
    if balance < amount {
        return Err(ContractError::InsufficientBalance {});
    }
    balance = balance.checked_sub(amount)?;
    BALANCES.save(deps.storage, &info.sender, &balance)?;
    
    // External call AFTER state update
    let msg = BankMsg::Send {
        to_address: info.sender.to_string(),
        amount: vec![coin(amount.u128(), "uatom")],
    };
    
    Ok(Response::new().add_message(msg))
}
```

---

## AC-04: Sudo Privilege Escalation

### Description
Sudo entry point not properly secured or misused.

### Vulnerable Code
```rust
#[entry_point]
pub fn sudo(
    deps: DepsMut,
    _env: Env,
    msg: SudoMsg,
) -> Result<Response, ContractError> {
    //  Sudo allows arbitrary state changes
    match msg {
        SudoMsg::UpdateAdmin { new_admin } => {
            let new_admin = deps.api.addr_validate(&new_admin)?;
            CONFIG.update(deps.storage, |mut config| -> StdResult<_> {
                config.admin = new_admin;
                Ok(config)
            })?;
            Ok(Response::new())
        }
    }
}
```

### Considerations
```rust
// Sudo is called by governance/chain, not users
// But still needs careful design:

#[entry_point]
pub fn sudo(
    deps: DepsMut,
    _env: Env,
    msg: SudoMsg,
) -> Result<Response, ContractError> {
    match msg {
        SudoMsg::UpdateConfig { updates } => {
            //  Validate all updates
            validate_config_updates(&updates)?;
            
            //  Log the change
            let mut config = CONFIG.load(deps.storage)?;
            apply_updates(&mut config, updates);
            CONFIG.save(deps.storage, &config)?;
            
            Ok(Response::new()
                .add_attribute("action", "sudo_update_config")
                .add_attribute("updates", format!("{:?}", updates)))
        }
    }
}
```

---

## AR-01: Integer Overflow

### Description
Arithmetic operations without overflow protection.

### Vulnerable Code
```rust
pub fn add_rewards(
    deps: DepsMut,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let mut state = STATE.load(deps.storage)?;
    
    //  Uint128 operations can overflow (though Rust panics)
    state.total_rewards = state.total_rewards + amount;
    
    STATE.save(deps.storage, &state)?;
    Ok(Response::new())
}
```

### Secure Code
```rust
pub fn add_rewards(
    deps: DepsMut,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let mut state = STATE.load(deps.storage)?;
    
    //  Use checked arithmetic
    state.total_rewards = state.total_rewards
        .checked_add(amount)
        .map_err(|_| ContractError::Overflow {})?;
    
    STATE.save(deps.storage, &state)?;
    Ok(Response::new())
}
```

---

## AR-03: Decimal Precision Loss

### Description
Division before multiplication causing precision loss.

### Vulnerable Code
```rust
pub fn calculate_share(
    user_deposit: Uint128,
    total_deposits: Uint128,
    rewards: Uint128,
) -> Uint128 {
    //  Division first loses precision
    let share_ratio = user_deposit / total_deposits;  // Rounds to 0 if user < total
    share_ratio * rewards
}
```

### Secure Code
```rust
use cosmwasm_std::Uint256;

pub fn calculate_share(
    user_deposit: Uint128,
    total_deposits: Uint128,
    rewards: Uint128,
) -> Result<Uint128, ContractError> {
    if total_deposits.is_zero() {
        return Err(ContractError::DivisionByZero {});
    }
    
    //  Use larger type, multiply first
    let user_256 = Uint256::from(user_deposit);
    let total_256 = Uint256::from(total_deposits);
    let rewards_256 = Uint256::from(rewards);
    
    let share = user_256
        .checked_mul(rewards_256)?
        .checked_div(total_256)?;
    
    // Safe to convert back if we know bounds
    Ok(Uint128::try_from(share)?)
}
```

---

## QY-01: Unbounded Query Response

### Description
Query returns unbounded list, causing DoS.

### Vulnerable Code
```rust
pub fn query_all_users(deps: Deps) -> StdResult<Binary> {
    //  Returns ALL users - can be huge
    let users: Vec<_> = USERS
        .range(deps.storage, None, None, Order::Ascending)
        .collect::<StdResult<Vec<_>>>()?;
    
    to_json_binary(&UsersResponse { users })
}
```

### Secure Code
```rust
pub fn query_users_paginated(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<Binary> {
    //  Enforce maximum limit
    const MAX_LIMIT: u32 = 30;
    const DEFAULT_LIMIT: u32 = 10;
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    
    let start = start_after.map(|s| Bound::exclusive(s));
    
    let users: Vec<_> = USERS
        .range(deps.storage, start, None, Order::Ascending)
        .take(limit as usize)
        .collect::<StdResult<Vec<_>>>()?;
    
    to_json_binary(&UsersResponse { users })
}
```

---

## TK-01: Missing Denom Whitelist

### Description
Contract accepts any token without validation.

### Vulnerable Code
```rust
pub fn execute_stake(
    deps: DepsMut,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    //  Accepts any token as stake
    for coin in info.funds.iter() {
        // Updates stake with any token
        update_stake(deps.storage, &info.sender, coin)?;
    }
    Ok(Response::new())
}
```

### Secure Code
```rust
pub fn execute_stake(
    deps: DepsMut,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    
    //  Only accept whitelisted tokens
    for coin in info.funds.iter() {
        if !config.allowed_denoms.contains(&coin.denom) {
            return Err(ContractError::InvalidDenom {
                denom: coin.denom.clone(),
            });
        }
        update_stake(deps.storage, &info.sender, coin)?;
    }
    Ok(Response::new())
}
```

