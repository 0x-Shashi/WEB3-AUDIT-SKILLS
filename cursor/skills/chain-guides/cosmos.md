---
id: CHAIN-COSMOS
title: Cosmos/CosmWasm Security Guide
category: chain-guides
chain: cosmos
difficulty: advanced
tags: [cosmos, cosmwasm, ibc, rust, tendermint]
last_updated: 2026-01-31
---

# Cosmos/CosmWasm Security Guide

## Overview

Cosmos chains use a fundamentally different architecture than EVM chains. Smart contracts are written in Rust using CosmWasm, and inter-chain communication uses IBC (Inter-Blockchain Communication).

## Key Differences from EVM

| Aspect | Ethereum | Cosmos |
|--------|----------|--------|
| Language | Solidity | Rust (CosmWasm) |
| VM | EVM | Wasm |
| Consensus | PoS | Tendermint BFT |
| Finality | Probabilistic | Instant (single block) |
| Cross-Chain | Bridges | IBC (native) |
| Upgrades | Proxy pattern | Native migrations |

## Critical Vulnerability Categories

### 1. Entry Point Validation

CosmWasm contracts have multiple entry points that need validation.

```rust
// VULNERABLE - No sender validation
#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::AdminWithdraw { amount } => {
            // Anyone can call this!
            let bank_msg = BankMsg::Send {
                to_address: info.sender.to_string(),
                amount: vec![amount],
            };
            Ok(Response::new().add_message(bank_msg))
        }
    }
}
```

```rust
// SECURE - Proper authorization
#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::AdminWithdraw { amount } => {
            // Load admin from storage
            let admin = ADMIN.load(deps.storage)?;
            
            // Verify sender is admin
            if info.sender != admin {
                return Err(ContractError::Unauthorized {});
            }
            
            let bank_msg = BankMsg::Send {
                to_address: admin.to_string(),
                amount: vec![amount],
            };
            Ok(Response::new().add_message(bank_msg))
        }
    }
}
```

### 2. Integer Overflow (Rust Specifics)

Rust handles overflow differently in debug vs release mode.

```rust
// VULNERABLE - Unchecked arithmetic in release mode
pub fn add_balance(current: u128, amount: u128) -> u128 {
    current + amount  // Wraps in release mode!
}

// SECURE - Use checked arithmetic
pub fn add_balance(current: u128, amount: u128) -> Result<u128, ContractError> {
    current
        .checked_add(amount)
        .ok_or(ContractError::Overflow {})
}

// Or use Uint128 which has safe operations
use cosmwasm_std::Uint128;

pub fn add_balance(current: Uint128, amount: Uint128) -> Result<Uint128, ContractError> {
    current.checked_add(amount).map_err(|_| ContractError::Overflow {})
}
```

### 3. Reentrancy in CosmWasm

CosmWasm uses a message-passing model, making reentrancy different but still possible.

```rust
// VULNERABLE - State modified after external message
#[entry_point]
pub fn execute(...) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Withdraw { amount } => {
            let balance = BALANCES.load(deps.storage, &info.sender)?;
            
            // Send tokens (external call)
            let send_msg = BankMsg::Send {
                to_address: info.sender.to_string(),
                amount: vec![Coin { denom: "uatom".to_string(), amount }],
            };
            
            // If the recipient is a contract, it executes before this state update
            // Reentrancy via reply or submessages
            BALANCES.save(deps.storage, &info.sender, &(balance - amount))?;
            
            Ok(Response::new().add_message(send_msg))
        }
    }
}
```

```rust
// SECURE - Update state before external call (CEI pattern)
#[entry_point]
pub fn execute(...) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Withdraw { amount } => {
            let balance = BALANCES.load(deps.storage, &info.sender)?;
            
            // Update state FIRST
            let new_balance = balance.checked_sub(amount)
                .map_err(|_| ContractError::InsufficientFunds {})?;
            BALANCES.save(deps.storage, &info.sender, &new_balance)?;
            
            // THEN send tokens
            let send_msg = BankMsg::Send {
                to_address: info.sender.to_string(),
                amount: vec![Coin { denom: "uatom".to_string(), amount }],
            };
            
            Ok(Response::new().add_message(send_msg))
        }
    }
}
```

### 4. IBC Security

Inter-Blockchain Communication introduces cross-chain vulnerabilities.

```rust
// IBC SECURITY CONSIDERATIONS

// 1. Packet acknowledgment handling
#[entry_point]
pub fn ibc_packet_ack(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketAckMsg,
) -> Result<IbcBasicResponse, ContractError> {
    // CRITICAL: Handle failed packets
    let ack: StdAck = from_binary(&msg.acknowledgement.data)?;
    
    match ack {
        StdAck::Success(_) => {
            // Packet delivered successfully
        }
        StdAck::Error(err) => {
            // MUST handle failure - refund tokens, revert state
            let original_packet: MyPacket = from_binary(&msg.original_packet.data)?;
            refund_tokens(deps, original_packet)?;
        }
    }
    
    Ok(IbcBasicResponse::new())
}

// 2. Packet timeout handling
#[entry_point]
pub fn ibc_packet_timeout(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketTimeoutMsg,
) -> Result<IbcBasicResponse, ContractError> {
    // CRITICAL: Timeout means packet never delivered
    // MUST refund/revert
    let original_packet: MyPacket = from_binary(&msg.packet.data)?;
    refund_tokens(deps, original_packet)?;
    
    Ok(IbcBasicResponse::new())
}
```

```rust
// VULNERABLE - Missing channel validation
#[entry_point]
pub fn ibc_packet_receive(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, ContractError> {
    // Anyone on any chain could send this packet!
    let packet: MyPacket = from_binary(&msg.packet.data)?;
    process_packet(deps, packet)?;
    Ok(IbcReceiveResponse::new())
}

// SECURE - Validate channel
#[entry_point]
pub fn ibc_packet_receive(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, ContractError> {
    // Verify this is from an expected channel
    let channel = msg.packet.dest.channel_id;
    let expected_channel = TRUSTED_CHANNEL.load(deps.storage)?;
    
    if channel != expected_channel {
        return Err(ContractError::UnauthorizedChannel {});
    }
    
    let packet: MyPacket = from_binary(&msg.packet.data)?;
    process_packet(deps, packet)?;
    Ok(IbcReceiveResponse::new())
}
```

### 5. Reply Handler Vulnerabilities

Submessage replies need careful handling.

```rust
// Reply IDs for submessages
const TRANSFER_REPLY_ID: u64 = 1;
const SWAP_REPLY_ID: u64 = 2;

// VULNERABLE - Ignores reply errors
#[entry_point]
pub fn reply(deps: DepsMut, env: Env, msg: Reply) -> Result<Response, ContractError> {
    match msg.id {
        TRANSFER_REPLY_ID => {
            // What if the transfer failed?
            // If we don't check, state may be inconsistent
            Ok(Response::new())
        }
        _ => Ok(Response::new())
    }
}

// SECURE - Handle all reply cases
#[entry_point]
pub fn reply(deps: DepsMut, env: Env, msg: Reply) -> Result<Response, ContractError> {
    match msg.id {
        TRANSFER_REPLY_ID => {
            match msg.result {
                SubMsgResult::Ok(_) => {
                    // Transfer succeeded
                    complete_transfer(deps)?;
                }
                SubMsgResult::Err(err) => {
                    // Transfer failed - revert our state
                    revert_transfer(deps)?;
                    return Err(ContractError::TransferFailed { reason: err });
                }
            }
            Ok(Response::new())
        }
        _ => Err(ContractError::UnknownReplyId { id: msg.id })
    }
}
```

### 6. Storage Key Collisions

```rust
// VULNERABLE - Simple string keys can collide
const BALANCE_KEY: &str = "balance";
const USER_KEY: &str = "user";

// If user address contains "balance", could collide

// SECURE - Use namespaced keys with cw-storage-plus
use cw_storage_plus::{Item, Map};

const BALANCE: Map<&Addr, Uint128> = Map::new("balance");
const USER_INFO: Map<&Addr, UserInfo> = Map::new("user_info");
const ADMIN: Item<Addr> = Item::new("admin");

// cw-storage-plus handles namespacing safely
```

### 7. Instantiate2 and Address Prediction

```rust
// CosmWasm supports predictable addresses via instantiate2

// SECURE - Validate predicted address matches
#[entry_point]
pub fn execute(...) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::CreateChild { salt } => {
            // Predict the address
            let creator = env.contract.address.clone();
            let code_id = CHILD_CODE_ID.load(deps.storage)?;
            let checksum = deps.querier.query_wasm_code_info(code_id)?.checksum;
            
            let predicted = instantiate2_address(
                &checksum,
                &deps.api.addr_canonicalize(creator.as_str())?,
                &salt,
            )?;
            
            // Store before creating
            CHILDREN.save(deps.storage, &predicted, &ChildInfo::default())?;
            
            let instantiate_msg = WasmMsg::Instantiate2 {
                admin: Some(creator.to_string()),
                code_id,
                label: "child".to_string(),
                msg: to_binary(&ChildInstantiateMsg {})?,
                funds: vec![],
                salt,
            };
            
            Ok(Response::new().add_message(instantiate_msg))
        }
    }
}
```

## Audit Checklist

```
[ ] All entry points validate sender authorization
[ ] Arithmetic uses checked operations or Uint128/Uint256
[ ] State updates before external messages (CEI)
[ ] IBC packet ack/timeout handlers refund properly
[ ] IBC channels are validated
[ ] Reply handlers check SubMsgResult
[ ] Storage uses namespaced keys (cw-storage-plus)
[ ] No panic! in production code
[ ] Error messages don't leak sensitive info
[ ] Migration handler validates state
[ ] Instantiate validates all config
```

## Common Patterns

### Safe Token Transfer
```rust
pub fn safe_transfer(
    deps: DepsMut,
    recipient: &Addr,
    amount: Uint128,
) -> Result<Response, ContractError> {
    // Update internal state first
    let balance = BALANCES.load(deps.storage, recipient)?;
    BALANCES.save(deps.storage, recipient, &balance.checked_add(amount)?)?;
    
    // Then create transfer message
    let msg = BankMsg::Send {
        to_address: recipient.to_string(),
        amount: vec![Coin {
            denom: "uatom".to_string(),
            amount,
        }],
    };
    
    Ok(Response::new().add_message(msg))
}
```

### Access Control
```rust
use cw_ownable::{cw_ownable_execute, cw_ownable_query};

// Using cw-ownable crate for standard access control
#[cw_ownable_execute]
#[entry_point]
pub fn execute(...) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::AdminAction {} => {
            // cw-ownable provides assert_owner
            cw_ownable::assert_owner(deps.storage, &info.sender)?;
            // ... admin logic
        }
    }
}
```

## Testing

```rust
#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    
    #[test]
    fn test_unauthorized_admin_action() {
        let mut deps = mock_dependencies();
        let info = mock_info("attacker", &[]);
        
        let res = execute(
            deps.as_mut(),
            mock_env(),
            info,
            ExecuteMsg::AdminWithdraw { amount: Uint128::new(1000) },
        );
        
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), ContractError::Unauthorized {});
    }
}
```
