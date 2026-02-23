---
id: COSMOS-IBC-SECURITY
title: IBC Security Guide
category: cosmos-scanner
difficulty: advanced
triggers:
  - IBC security
  - IBC vulnerabilities
  - inter-blockchain communication
  - cross-chain cosmos
  - packet validation
related_skills:
  - cosmos-scanner/resources/cosmwasm-patterns.md
  - cosmos-scanner/workflows/cosmwasm-audit.md
tags:
  - cosmos
  - ibc
  - cross-chain
  - security
last_updated: 2026-01-31
---

# IBC Security Guide

> IBC (Inter-Blockchain Communication) is the defining protocol of the Cosmos ecosystem. It enables trustless cross-chain asset transfers, contract calls, and data queries. IBC vulnerabilities are uniquely dangerous because they can compromise assets across multiple chains simultaneously.

---

## IBC Architecture Overview

```
Chain A                                   Chain B
┌──────────────┐                         ┌──────────────┐
│ Application  │                         │ Application  │
│ (Contract)   │                         │ (Contract)   │
├──────────────┤                         ├──────────────┤
│ IBC Module   │                         │ IBC Module   │
│ • Port       │      Relayer           │ • Port       │
│ • Channel    │ ◄─────────────────────► │ • Channel    │
│ • Connection │                         │ • Connection │
├──────────────┤                         ├──────────────┤
│ Light Client │ ← Verifies B's state   │ Light Client │
│ (of Chain B) │                         │ (of Chain A) │
└──────────────┘                         └──────────────┘
```

### Key Concepts
| Concept | Description | Security Relevance |
|---------|-------------|-------------------|
| **Client** | Light client verifying counterparty chain state | Compromised client = forged proofs |
| **Connection** | Authenticated link between two chains | One connection per chain pair |
| **Channel** | Application-level communication path | Each contract binds to a port/channel |
| **Packet** | Data unit sent between chains | Must be validated by receiver |
| **Relayer** | Off-chain process that relays packets | Untrusted — cannot forge proofs but can delay/reorder |
| **Acknowledgement** | Receiver's response to a packet | Must handle success AND failure |
| **Timeout** | Packet expiration mechanism | Must trigger refund/revert |

---

## IBC Packet Lifecycle

```
Sender Chain                     Relayer                    Receiver Chain
     │                              │                           │
     │ 1. SendPacket()              │                           │
     │──────────────────────────────►                           │
     │                              │ 2. Relay packet + proof   │
     │                              │──────────────────────────►│
     │                              │                           │ 3. OnRecvPacket()
     │                              │                           │    → Process + return ACK
     │                              │ 4. Relay acknowledgement  │
     │                              │◄──────────────────────────│
     │ 5. OnAcknowledgementPacket() │                           │
     │◄──────────────────────────────                           │
     │                              │                           │
     │    --- OR if timeout ---     │                           │
     │ 5b. OnTimeoutPacket()        │                           │
     │◄──────────────────────────────                           │
```

---

## Vulnerability 1: Unvalidated Packet Source (CRITICAL)

**Impact**: Processing packets from unknown or malicious channels allows arbitrary cross-chain message injection.

### Vulnerable Code (CosmWasm IBC)
```rust
#[entry_point]
pub fn ibc_packet_receive(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, ContractError> {
    let packet = msg.packet;

    // BUG: No validation of packet source — any channel accepted
    let transfer: TransferData = from_json(&packet.data)?;

    // Mints tokens based on unvalidated cross-chain message
    BALANCES.update(deps.storage, &transfer.receiver, |b| -> StdResult<_> {
        Ok(b.unwrap_or_default() + transfer.amount)
    })?;

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
    let packet = msg.packet;

    // FIX: Validate the packet comes from a known, trusted channel
    let channel_info = CHANNEL_INFO.load(deps.storage, &packet.dest.channel_id)?;
    if channel_info.counterparty_port != packet.src.port_id
        || channel_info.counterparty_channel != packet.src.channel_id
    {
        return Err(ContractError::UnauthorizedChannel {});
    }

    let transfer: TransferData = from_json(&packet.data)?;

    // Validate receiver address
    let receiver = deps.api.addr_validate(&transfer.receiver)?;

    // Validate amount is non-zero
    if transfer.amount.is_zero() {
        return Err(ContractError::ZeroAmount {});
    }

    BALANCES.update(deps.storage, &receiver, |b| -> StdResult<_> {
        Ok(b.unwrap_or_default() + transfer.amount)
    })?;

    Ok(IbcReceiveResponse::new().set_ack(ack_success()))
}
```

---

## Vulnerability 2: Timeout Mishandling (CRITICAL)

**Impact**: When a packet times out, the sender's state must be reverted. Failure to refund locks user funds permanently.

### Vulnerable Code
```rust
#[entry_point]
pub fn ibc_packet_timeout(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketTimeoutMsg,
) -> Result<IbcBasicResponse, ContractError> {
    // BUG: Timeout handler is empty — escrowed funds never refunded
    Ok(IbcBasicResponse::new())
}
```

### Secure Code
```rust
#[entry_point]
pub fn ibc_packet_timeout(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketTimeoutMsg,
) -> Result<IbcBasicResponse, ContractError> {
    let packet = msg.packet;
    let transfer: TransferData = from_json(&packet.data)?;

    // FIX: Refund escrowed tokens to sender
    let sender = deps.api.addr_validate(&transfer.sender)?;

    BALANCES.update(deps.storage, &sender, |b| -> StdResult<_> {
        Ok(b.unwrap_or_default() + transfer.amount)
    })?;

    // Also un-escrow if escrow was used
    ESCROW.update(deps.storage, &packet.src.channel_id, |e| -> StdResult<_> {
        let escrow = e.unwrap_or_default();
        Ok(escrow.checked_sub(transfer.amount)?)
    })?;

    Ok(IbcBasicResponse::new()
        .add_attribute("action", "timeout_refund")
        .add_attribute("sender", transfer.sender)
        .add_attribute("amount", transfer.amount))
}
```

---

## Vulnerability 3: Acknowledgement Error Handling (HIGH)

**Impact**: When the receiver returns an error acknowledgement, the sender must handle it (typically by refunding). Ignoring error acks causes silent fund loss.

### Vulnerable Code
```rust
#[entry_point]
pub fn ibc_packet_ack(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketAckMsg,
) -> Result<IbcBasicResponse, ContractError> {
    // BUG: Only handles success — error ack ignored, funds lost
    let ack: AckResult = from_json(&msg.acknowledgement.data)?;
    match ack {
        AckResult::Success(_) => {
            // Great, transfer confirmed
            Ok(IbcBasicResponse::new())
        }
        // Missing: AckResult::Error case — funds escrowed but never received!
    }
}
```

### Secure Code
```rust
#[entry_point]
pub fn ibc_packet_ack(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketAckMsg,
) -> Result<IbcBasicResponse, ContractError> {
    let ack: AckResult = from_json(&msg.acknowledgement.data)?;
    let packet = msg.original_packet;
    let transfer: TransferData = from_json(&packet.data)?;

    match ack {
        AckResult::Success(_) => {
            Ok(IbcBasicResponse::new().add_attribute("ibc_ack", "success"))
        }
        AckResult::Error(err) => {
            // FIX: Refund sender on error acknowledgement
            let sender = deps.api.addr_validate(&transfer.sender)?;
            BALANCES.update(deps.storage, &sender, |b| -> StdResult<_> {
                Ok(b.unwrap_or_default() + transfer.amount)
            })?;
            Ok(IbcBasicResponse::new()
                .add_attribute("ibc_ack", "error")
                .add_attribute("refunded", transfer.amount))
        }
    }
}
```

---

## Vulnerability 4: Channel Ordering Mismatch (HIGH)

**Impact**: Using ORDERED channels when UNORDERED is needed (or vice versa) can cause permanent channel closure or out-of-order processing.

### Key Differences
| Aspect | ORDERED | UNORDERED |
|--------|---------|-----------|
| Packet delivery | Strictly sequential | Any order |
| Timeout behavior | Entire channel closes | Only that packet times out |
| Use case | Sequenced operations | Independent transfers |
| Risk | One timeout = permanent DoS | Packets may arrive out of order |

```rust
// FIX: Choose ordering based on protocol needs
#[entry_point]
pub fn ibc_channel_open(
    _deps: DepsMut,
    _env: Env,
    msg: IbcChannelOpenMsg,
) -> Result<IbcChannelOpenResponse, ContractError> {
    let channel = msg.channel();

    // For token transfers: UNORDERED (timeouts don't close channel)
    if channel.order != IbcOrder::Unordered {
        return Err(ContractError::InvalidChannelOrdering {});
    }

    // Validate version
    if channel.version != ICS20_VERSION {
        return Err(ContractError::InvalidVersion {});
    }

    Ok(None)
}
```

---

## Vulnerability 5: Light Client Exploitation (CRITICAL)

**Impact**: A compromised or buggy light client can be used to generate forged inclusion proofs, allowing an attacker to fabricate cross-chain messages (e.g., fake token transfers).

### Attack Vectors
| Vector | Description | Mitigation |
|--------|-------------|------------|
| Validator set fraud | Compromised validators sign fraudulent state | Multi-light-client verification |
| Header manipulation | Forged block headers accepted | Strict misbehavior detection |
| Connection hijack | Attacker creates new connection with malicious client | Whitelist trusted connections |
| Expired client | Using state from expired light client | Client expiry enforcement |

```rust
// Defense: Validate connection/client in channel open
#[entry_point]
pub fn ibc_channel_open(
    deps: DepsMut,
    _env: Env,
    msg: IbcChannelOpenMsg,
) -> Result<IbcChannelOpenResponse, ContractError> {
    let channel = msg.channel();

    // Verify the connection uses a trusted light client
    // This is typically handled at the SDK level, but contracts
    // should validate counterparty chain identity
    if let Some(counterparty) = &channel.counterparty_endpoint.port_id {
        if counterparty != EXPECTED_COUNTERPARTY_PORT {
            return Err(ContractError::UnauthorizedCounterparty {});
        }
    }

    Ok(None)
}
```

---

## Vulnerability 6: Relayer Exploitation (MEDIUM)

**Impact**: While relayers cannot forge proofs, they control WHEN and IF packets are relayed, enabling griefing and MEV.

### Attack Vectors
| Attack | Description | Impact |
|--------|-------------|--------|
| Selective relay | Relayer only relays profitable packets | User packets stuck |
| Timeout forcing | Delay relay until packet times out | User must wait for timeout refund |
| Ordering manipulation | In ORDERED channels, delay one packet to block all | Channel-wide DoS |
| Front-running | Relayer sees packet content and front-runs on dest chain | MEV extraction |

### Mitigation
```rust
// Set reasonable timeouts to limit relayer griefing window
let packet_timeout = IbcTimeout::with_timestamp(
    env.block.time.plus_seconds(600), // 10 minute timeout
);
// Short timeout = less griefing window, but more timeout risk
// Long timeout = more griefing window, but fewer false timeouts
```

---

## IBC Audit Checklist

### Critical Checks
- [ ] `ibc_packet_receive` validates source port and channel against whitelist
- [ ] `ibc_packet_timeout` refunds all escrowed assets to sender
- [ ] `ibc_packet_ack` handles both success AND error acknowledgements
- [ ] Packet data fully validated (amounts, addresses, format)

### High Checks
- [ ] Channel ordering matches protocol requirements
- [ ] Channel version validated in `ibc_channel_open`
- [ ] Counterparty port/channel validated
- [ ] Escrow accounting is symmetric (send = escrow, timeout/error = un-escrow)

### Medium Checks
- [ ] Timeout duration is reasonable (not too short, not too long)
- [ ] IBC middleware chain correctly ordered and validated
- [ ] Relayer incentives considered (will packets actually get relayed?)
- [ ] Channel close handlers clean up state properly

---

## Real-World IBC Incidents

| Incident | Impact | Root Cause | Year |
|----------|--------|-----------|------|
| BNB Bridge IBC exploit (PoC) | Theoretical | Client verification bypass in Cosmos SDK | 2022 |
| Juno validator set attack | Governance crisis | Social engineering + validator collusion | 2022 |
| Osmosis LP vulnerability | $5M at risk (whitehat) | Math error in LP withdrawal + IBC interaction | 2022 |

---

## Related Files

- [CosmWasm Patterns](cosmwasm-patterns.md) — CosmWasm-specific vulnerability patterns
- [CosmWasm Audit Workflow](../workflows/cosmwasm-audit.md) — Step-by-step audit process
