# IBC Security Guide

Security considerations for Inter-Blockchain Communication (IBC) in CosmWasm contracts.

---

## IBC Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       CHAIN A                               │
│  ┌─────────────────┐         ┌─────────────────────────┐   │
│  │  IBC Contract   │ ──────► │     IBC Module          │   │
│  │  (Application)  │ ◄────── │     (Relayer)           │   │
│  └─────────────────┘         └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                          │  ▲
                          ▼  │ (Light Client Verification)
┌─────────────────────────────────────────────────────────────┐
│                       CHAIN B                               │
│  ┌─────────────────┐         ┌─────────────────────────┐   │
│  │  IBC Contract   │ ◄────── │     IBC Module          │   │
│  │  (Application)  │ ──────► │     (Relayer)           │   │
│  └─────────────────┘         └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## IBC Entry Points

### Required Entry Points

```rust
use cosmwasm_std::{
    entry_point, IbcBasicResponse, IbcChannelCloseMsg, IbcChannelConnectMsg,
    IbcChannelOpenMsg, IbcPacketAckMsg, IbcPacketReceiveMsg, IbcPacketTimeoutMsg,
    IbcReceiveResponse,
};

/// Called when a channel is being opened
#[entry_point]
pub fn ibc_channel_open(
    deps: DepsMut,
    _env: Env,
    msg: IbcChannelOpenMsg,
) -> Result<IbcChannelOpenResponse, ContractError> {
    // Validate channel parameters
    validate_channel(msg.channel())?;
    Ok(None) // Or Some(Ibc3ChannelOpenResponse { ... })
}

/// Called when channel handshake completes
#[entry_point]
pub fn ibc_channel_connect(
    deps: DepsMut,
    _env: Env,
    msg: IbcChannelConnectMsg,
) -> Result<IbcBasicResponse, ContractError> {
    // Store channel info
    let channel = msg.channel();
    CHANNELS.save(deps.storage, &channel.endpoint.channel_id, &channel.clone())?;
    Ok(IbcBasicResponse::new())
}

/// Called when receiving a packet
#[entry_point]
pub fn ibc_packet_receive(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, ContractError> {
    // Process incoming packet
    let packet = msg.packet;
    let data: PacketData = from_json(&packet.data)?;
    
    // Handle packet...
    
    Ok(IbcReceiveResponse::new()
        .set_ack(to_json_binary(&Ack::Success {})?))
}

/// Called when our packet is acknowledged
#[entry_point]
pub fn ibc_packet_ack(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketAckMsg,
) -> Result<IbcBasicResponse, ContractError> {
    // Handle acknowledgement
    let ack: Ack = from_json(&msg.acknowledgement.data)?;
    // Process based on success/failure
    Ok(IbcBasicResponse::new())
}

/// Called when our packet times out
#[entry_point]
pub fn ibc_packet_timeout(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketTimeoutMsg,
) -> Result<IbcBasicResponse, ContractError> {
    // Handle timeout - refund, rollback, etc.
    let packet = msg.packet;
    let data: PacketData = from_json(&packet.data)?;
    
    // Rollback the operation
    Ok(IbcBasicResponse::new())
}

/// Called when channel is closed
#[entry_point]
pub fn ibc_channel_close(
    deps: DepsMut,
    _env: Env,
    msg: IbcChannelCloseMsg,
) -> Result<IbcBasicResponse, ContractError> {
    // Handle channel close
    let channel = msg.channel();
    CHANNELS.remove(deps.storage, &channel.endpoint.channel_id);
    Ok(IbcBasicResponse::new())
}
```

---

## IBC-01: Missing Channel Validation

### Description
Accepting packets from any channel without validation.

### Vulnerable Code
```rust
#[entry_point]
pub fn ibc_channel_open(
    _deps: DepsMut,
    _env: Env,
    _msg: IbcChannelOpenMsg,
) -> Result<IbcChannelOpenResponse, ContractError> {
    // ❌ Accepts ANY channel!
    Ok(None)
}

#[entry_point]
pub fn ibc_packet_receive(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, ContractError> {
    // ❌ Processes packet from any channel
    let data: PacketData = from_json(&msg.packet.data)?;
    process_transfer(deps, data)?;
    Ok(IbcReceiveResponse::new().set_ack(ack_success()))
}
```

### Secure Code
```rust
const IBC_VERSION: &str = "myprotocol-1";
const ORDERING: IbcOrder = IbcOrder::Unordered;

fn validate_channel(channel: &IbcChannel) -> Result<(), ContractError> {
    // ✅ Verify version
    if channel.version != IBC_VERSION {
        return Err(ContractError::InvalidIbcVersion {
            expected: IBC_VERSION.to_string(),
            actual: channel.version.clone(),
        });
    }
    
    // ✅ Verify ordering
    if channel.order != ORDERING {
        return Err(ContractError::InvalidChannelOrder {});
    }
    
    Ok(())
}

#[entry_point]
pub fn ibc_channel_open(
    deps: DepsMut,
    _env: Env,
    msg: IbcChannelOpenMsg,
) -> Result<IbcChannelOpenResponse, ContractError> {
    validate_channel(msg.channel())?;
    Ok(None)
}

#[entry_point]
pub fn ibc_packet_receive(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, ContractError> {
    let packet = &msg.packet;
    
    // ✅ Verify channel is known/expected
    if !ALLOWED_CHANNELS.has(deps.storage, &packet.dest.channel_id) {
        return Err(ContractError::UnknownChannel {});
    }
    
    let data: PacketData = from_json(&packet.data)?;
    process_transfer(deps, data)?;
    Ok(IbcReceiveResponse::new().set_ack(ack_success()))
}
```

---

## IBC-02: Packet Data Manipulation

### Description
Trusting packet data without validation.

### Vulnerable Code
```rust
#[derive(Serialize, Deserialize)]
struct TransferPacket {
    sender: String,
    recipient: String,
    amount: Uint128,
}

#[entry_point]
pub fn ibc_packet_receive(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, ContractError> {
    let data: TransferPacket = from_json(&msg.packet.data)?;
    
    // ❌ Trusts sender/recipient from packet without validation
    let recipient = deps.api.addr_validate(&data.recipient)?;
    mint_tokens(deps, recipient, data.amount)?;
    
    Ok(IbcReceiveResponse::new().set_ack(ack_success()))
}
```

### Secure Code
```rust
#[entry_point]
pub fn ibc_packet_receive(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, ContractError> {
    let packet = &msg.packet;
    let data: TransferPacket = from_json(&packet.data)?;
    
    // ✅ Validate amount
    if data.amount.is_zero() {
        return Ok(IbcReceiveResponse::new().set_ack(ack_error("zero amount")));
    }
    
    // ✅ Validate recipient address format
    let recipient = match deps.api.addr_validate(&data.recipient) {
        Ok(addr) => addr,
        Err(_) => return Ok(IbcReceiveResponse::new().set_ack(ack_error("invalid recipient"))),
    };
    
    // ✅ Check against whitelist/limits if needed
    let config = CONFIG.load(deps.storage)?;
    if data.amount > config.max_transfer {
        return Ok(IbcReceiveResponse::new().set_ack(ack_error("exceeds limit")));
    }
    
    // ✅ Log the source for auditing
    let response = IbcReceiveResponse::new()
        .set_ack(ack_success())
        .add_attribute("source_channel", &packet.src.channel_id)
        .add_attribute("source_port", &packet.src.port_id);
    
    mint_tokens(deps, recipient, data.amount)?;
    
    Ok(response)
}
```

---

## IBC-03: Timeout Handling Flaws

### Description
Improper handling of packet timeout, leading to lost funds.

### Vulnerable Code
```rust
// When sending a packet
pub fn execute_transfer(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    channel_id: String,
    recipient: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    // Deduct balance
    let mut balance = BALANCES.load(deps.storage, &info.sender)?;
    balance = balance.checked_sub(amount)?;
    BALANCES.save(deps.storage, &info.sender, &balance)?;
    
    // Send packet
    let packet = TransferPacket { /* ... */ };
    let msg = IbcMsg::SendPacket {
        channel_id,
        data: to_json_binary(&packet)?,
        timeout: IbcTimeout::with_timestamp(env.block.time.plus_seconds(300)),
    };
    
    Ok(Response::new().add_message(msg))
}

// ❌ Missing timeout handler - funds lost on timeout!
```

### Secure Code
```rust
// Store pending transfers
const PENDING_TRANSFERS: Map<u64, PendingTransfer> = Map::new("pending");

pub fn execute_transfer(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    channel_id: String,
    recipient: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    // Deduct balance
    let mut balance = BALANCES.load(deps.storage, &info.sender)?;
    balance = balance.checked_sub(amount)?;
    BALANCES.save(deps.storage, &info.sender, &balance)?;
    
    // ✅ Store pending transfer for potential refund
    let sequence = get_next_sequence(deps.storage)?;
    PENDING_TRANSFERS.save(deps.storage, sequence, &PendingTransfer {
        sender: info.sender.clone(),
        amount,
    })?;
    
    let packet = TransferPacket {
        sequence,
        recipient,
        amount,
    };
    
    let msg = IbcMsg::SendPacket {
        channel_id,
        data: to_json_binary(&packet)?,
        timeout: IbcTimeout::with_timestamp(env.block.time.plus_seconds(300)),
    };
    
    Ok(Response::new().add_message(msg))
}

#[entry_point]
pub fn ibc_packet_timeout(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketTimeoutMsg,
) -> Result<IbcBasicResponse, ContractError> {
    let packet = msg.packet;
    let data: TransferPacket = from_json(&packet.data)?;
    
    // ✅ Load pending transfer
    let pending = PENDING_TRANSFERS.load(deps.storage, data.sequence)?;
    
    // ✅ Refund the sender
    let mut balance = BALANCES.load(deps.storage, &pending.sender)?;
    balance = balance.checked_add(pending.amount)?;
    BALANCES.save(deps.storage, &pending.sender, &balance)?;
    
    // ✅ Remove pending transfer
    PENDING_TRANSFERS.remove(deps.storage, data.sequence);
    
    Ok(IbcBasicResponse::new()
        .add_attribute("action", "timeout_refund")
        .add_attribute("refunded", pending.amount))
}

#[entry_point]
pub fn ibc_packet_ack(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketAckMsg,
) -> Result<IbcBasicResponse, ContractError> {
    let packet = msg.original_packet;
    let data: TransferPacket = from_json(&packet.data)?;
    let ack: Ack = from_json(&msg.acknowledgement.data)?;
    
    match ack {
        Ack::Success {} => {
            // ✅ Transfer succeeded, remove pending
            PENDING_TRANSFERS.remove(deps.storage, data.sequence);
            Ok(IbcBasicResponse::new().add_attribute("result", "success"))
        }
        Ack::Error(err) => {
            // ✅ Transfer failed, refund
            let pending = PENDING_TRANSFERS.load(deps.storage, data.sequence)?;
            let mut balance = BALANCES.load(deps.storage, &pending.sender)?;
            balance = balance.checked_add(pending.amount)?;
            BALANCES.save(deps.storage, &pending.sender, &balance)?;
            PENDING_TRANSFERS.remove(deps.storage, data.sequence);
            
            Ok(IbcBasicResponse::new()
                .add_attribute("result", "error")
                .add_attribute("error", err))
        }
    }
}
```

---

## IBC-05: Channel Ordering Issues

### Description
Using wrong channel ordering for the protocol.

### Considerations

```rust
// ORDERED channels:
// - Packets processed in sequence order
// - If one packet fails, channel closes
// - Good for: state machines requiring order

// UNORDERED channels:
// - Packets processed in any order
// - Individual packet failure doesn't affect channel
// - Good for: independent transfers

fn validate_channel(channel: &IbcChannel) -> Result<(), ContractError> {
    // For independent transfers, use UNORDERED
    if channel.order != IbcOrder::Unordered {
        return Err(ContractError::WrongOrder {});
    }
    
    // For ordered protocols (e.g., streaming), use ORDERED
    // But handle the implications of channel closure
    
    Ok(())
}
```

---

## Acknowledgement Patterns

### Standard Acknowledgement

```rust
use cosmwasm_std::StdAck;

// Success acknowledgement
fn ack_success() -> Binary {
    StdAck::success(b"ok").to_binary()
}

// Error acknowledgement (does NOT close channel)
fn ack_error(err: &str) -> Binary {
    StdAck::error(err).to_binary()
}
```

### Custom Acknowledgement

```rust
#[cw_serde]
pub enum Ack {
    Success { 
        amount_received: Uint128 
    },
    Error { 
        code: u32, 
        message: String 
    },
}

fn create_ack(result: Result<Uint128, ContractError>) -> Binary {
    match result {
        Ok(amount) => to_json_binary(&Ack::Success { amount_received: amount }).unwrap(),
        Err(e) => to_json_binary(&Ack::Error { 
            code: e.code(), 
            message: e.to_string() 
        }).unwrap(),
    }
}
```

---

## IBC Audit Checklist

### Channel Security
- [ ] Channel version validated
- [ ] Channel ordering appropriate for protocol
- [ ] Counterparty port/channel validated (if needed)
- [ ] Channel state stored and checked

### Packet Security
- [ ] Packet data fully validated
- [ ] Amount bounds checked
- [ ] Addresses validated on this chain
- [ ] Rate limiting considered

### Timeout/Ack Handling
- [ ] Timeout handler refunds correctly
- [ ] Ack handler processes success/error
- [ ] Pending operations tracked
- [ ] No state corruption on failure

### Error Handling
- [ ] Errors return proper acks (not panic)
- [ ] Channel doesn't close unexpectedly
- [ ] Funds never lost in any path
