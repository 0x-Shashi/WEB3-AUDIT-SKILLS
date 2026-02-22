# Cosmos Security Guide

## Chain Overview

- **Type:** Sovereign L1 (Tendermint/CometBFT)
- **Languages:** Go (Cosmos SDK modules), Rust (CosmWasm contracts)
- **Account Model:** Account-based with module accounts
- **Finality:** ~6 seconds (instant finality with 2/3+ validator agreement)
- **Interoperability:** IBC (Inter-Blockchain Communication)

## Key Security Considerations

### 1. Cosmos SDK Module Security
```go
// Cosmos apps are built from modules:
// - bank: token transfers
// - staking: validator delegation
// - gov: governance proposals
// - authz: authorization grants
// Custom modules interact via Keeper pattern
```

**Module audit risks:**
- Keeper methods may lack proper authorization
- Module account permissions not correctly set
- BeginBlocker/EndBlocker logic can be exploited
- State migration during upgrades can introduce bugs

### 2. IBC (Inter-Blockchain Communication)
```
IBC is the cross-chain messaging protocol:
Channel → Port → Connection → Client → Counterparty Chain
```

**Critical IBC risks:**
- Light client verification bugs
- Packet timeout handling
- Channel ordering (ORDERED vs UNORDERED)
- IBC middleware vulnerabilities
- Relayer trust (relayers cannot forge, but can censor/delay)

```go
// [VULNERABLE] Not validating IBC packet source
func (k Keeper) OnRecvPacket(ctx sdk.Context, packet channeltypes.Packet) error {
    // MISSING: validate packet.SourcePort and packet.SourceChannel
    var data MyPacketData
    json.Unmarshal(packet.GetData(), &data)
    // Process without verifying source chain!
}
```

### 3. CosmWasm Contract Security
```rust
// CosmWasm contracts (Rust) have unique patterns:
// - Instantiate / Execute / Query entry points
// - No reentrancy by default (single-threaded execution)
// - State stored in key-value storage (cw-storage-plus)
// - Cross-contract calls via SubMessages
```

**CosmWasm risks:**
- Reply handler bugs (SubMessage callbacks)
- Storage key collisions
- Integer overflow (Uint128/Uint256 types)
- Gas limit manipulation
- Admin/migration key control

```rust
// [VULNERABLE] Unbounded iteration
pub fn execute_distribute(deps: DepsMut, env: Env) -> Result<Response, ContractError> {
    let holders: Vec<_> = HOLDERS.range(deps.storage, None, None, Order::Ascending)
        .collect::<StdResult<Vec<_>>>()?;  // Could be millions!
    // Will run out of gas
}
```

### 4. Governance Attacks
- Cosmos chains have on-chain governance
- Parameter changes can be proposed
- Software upgrades via governance
- **Audit check:** Can malicious governance proposals break the protocol?

### 5. Staking and Slashing
- Validators can be slashed for double-signing or downtime
- Delegators share slashing risk
- Unbonding period (typically 21 days)
- **Audit check:** Protocol interactions with staking module

### 6. AuthZ (Authorization Grants)
```go
// AuthZ allows granting permissions to other accounts
// Risk: overly broad grants
// Example: granting GenericAuthorization for all MsgSend
// allows the grantee to send ANY tokens from the granter
```

## Cosmos-Specific Audit Checklist

### SDK Modules
- [ ] Keeper methods have proper authorization
- [ ] Module account permissions correctly configured
- [ ] BeginBlocker/EndBlocker logic is safe
- [ ] State migration in upgrades validated
- [ ] Panic recovery in message handlers
- [ ] AnteHandler chain correctly ordered

### IBC
- [ ] IBC packet source validated (port + channel)
- [ ] Packet timeout handling is correct
- [ ] Channel ordering appropriate for use case
- [ ] IBC middleware properly chained
- [ ] Light client type validated

### CosmWasm
- [ ] No unbounded iterations
- [ ] SubMessage reply handlers correct
- [ ] Storage key prefixes unique
- [ ] Admin/migration controls appropriate
- [ ] Integer arithmetic checked (cosmwasm types)
- [ ] Query responses bounded in size

## Common Vulnerabilities in Cosmos

| Vulnerability | Description |
|--------------|-------------|
| IBC relay spoofing | Not validating packet source port/channel |
| Unbounded iteration | Gas DoS via large state iteration |
| Governance exploit | Malicious parameter change proposals |
| AuthZ abuse | Overly broad authorization grants |
| Module keeper bypass | Direct storage access without authorization |
| CosmWasm reply bugs | SubMessage callback handling errors |
