---
id: CAIRO-MESSAGING
title: L1-L2 Messaging Security
parent: cairo-scanner
type: resource
last_updated: 2025-01-31
---

# L1-L2 Messaging Security

Security guide for Starknet's L1 (Ethereum) ↔ L2 (Starknet) messaging system. Cross-layer messaging is one of the highest-risk areas in Starknet contracts — message replay, missing validation, and finality assumptions have led to critical vulnerabilities in bridge protocols.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│ Ethereum L1                                         │
│                                                     │
│  ┌──────────────┐    sendMessageToL2()              │
│  │ L1 Contract  │ ──────────────────────┐           │
│  │ (Bridge)     │                       │           │
│  │              │ <─── consumeMessageFromL2()       │
│  └──────────────┘                       │           │
│                                         ▼           │
│  ┌──────────────────────────────────────────────┐   │
│  │ Starknet Core Contract (Ethereum)            │   │
│  │ - Stores message hashes                      │   │
│  │ - Verifies STARK proofs                      │   │
│  │ - Manages L1→L2 message queue               │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
                          │
                 STARK Proof │ Messages
                          │
┌─────────────────────────────────────────────────────┐
│ Starknet L2                                         │
│                                                     │
│  ┌──────────────┐    l1_handler                     │
│  │ L2 Contract  │ <─── receives L1→L2 messages      │
│  │ (Bridge)     │                                   │
│  │              │ ───> send_message_to_l1_syscall    │
│  └──────────────┘                                   │
└─────────────────────────────────────────────────────┘
```

---

## L1 → Starknet (L1→L2 Messages)

### How It Works

1. L1 contract calls `StarknetCore.sendMessageToL2(to_address, selector, payload)`
2. Message is added to L1→L2 message queue in the Starknet Core contract
3. Starknet sequencer picks up the message and delivers it to the target L2 contract
4. L2 contract receives the message via its `#[l1_handler]` function

### Security Checks for L1→L2

| Check | Why | How |
|-------|-----|-----|
| **Validate L1 sender** | Prevent unauthorized sources | First parameter of `l1_handler` is the L1 sender address — verify it matches expected L1 contract |
| **Prevent message replay** | Same message should not be processed twice | Track message nonces or hashes in storage |
| **Validate payload format** | Malformed payloads can cause undefined behavior | Deserialize and validate all payload fields |
| **Rate limiting** | Prevent message flooding | Optional: limit message processing frequency |

### L1→L2 Handler Pattern

```cairo
#[l1_handler]
fn handle_deposit(
    ref self: ContractState,
    from_address: felt252,  // L1 sender address (automatically provided)
    user: ContractAddress,
    amount: u256,
    nonce: felt252
) {
    // CHECK 1: Validate L1 sender
    assert(
        from_address == self.l1_bridge_address.read().into(), 
        'Unauthorized L1 sender'
    );
    
    // CHECK 2: Replay protection
    let message_hash = pedersen::pedersen(
        pedersen::pedersen(user.into(), amount.low.into()),
        nonce
    );
    assert(!self.processed_messages.read(message_hash), 'Message already processed');
    self.processed_messages.write(message_hash, true);
    
    // CHECK 3: Validate payload
    assert(amount > 0, 'Zero amount');
    assert(user.is_non_zero(), 'Zero address');
    
    // EFFECT: Credit user
    let current_balance = self.balances.read(user);
    self.balances.write(user, current_balance + amount);
    
    // EVENT: Log for indexing
    self.emit(L1DepositReceived { user, amount, nonce, l1_sender: from_address });
}
```

---

## Starknet → L1 (L2→L1 Messages)

### How It Works

1. L2 contract calls `send_message_to_l1_syscall(to_address, payload)`
2. Message is included in the L2 block
3. Starknet prover generates STARK proof for the block (including the message)
4. Proof is verified on L1 by the Starknet Core contract
5. L1 contract calls `StarknetCore.consumeMessageFromL2(from_address, payload)` to consume the message

### Security Checks for L2→L1

| Check | Why | How |
|-------|-----|-----|
| **Wait for proof finalization** | Message is not valid until STARK proof is verified on L1 | Use `consumeMessageFromL2` which checks proof status |
| **Validate L2 sender** | Ensure message originated from the correct L2 contract | Pass `from_address` (L2 contract) to `consumeMessageFromL2` |
| **Single consumption** | Message must be consumed exactly once | `consumeMessageFromL2` decrements message count (handles this) |
| **Payload integrity** | Payload must match what was sent from L2 | Hash comparison of payload with on-chain record |

### L2→L1 Sending Pattern

```cairo
#[external(v0)]
fn initiate_withdrawal(ref self: ContractState, l1_recipient: felt252, amount: u256) {
    let caller = get_caller_address();
    
    // CHECK: Sufficient balance
    let balance = self.balances.read(caller);
    assert(balance >= amount, 'Insufficient balance');
    
    // EFFECT: Debit user balance BEFORE sending message
    self.balances.write(caller, balance - amount);
    
    // INTERACT: Send L2→L1 message
    let mut payload = ArrayTrait::new();
    payload.append(l1_recipient);
    payload.append(amount.low.into());
    payload.append(amount.high.into());
    
    send_message_to_l1_syscall(
        self.l1_bridge_address.read().into(),
        payload.span()
    ).unwrap();
    
    self.emit(WithdrawalInitiated { user: caller, l1_recipient, amount });
}
```

### L1 Consumption Pattern (Solidity)

```solidity
function completeWithdrawal(
    uint256 l2ContractAddress,
    address recipient,
    uint256 amount
) external {
    // Consumes the message — reverts if message doesn't exist or already consumed
    uint256[] memory payload = new uint256[](3);
    payload[0] = uint256(uint160(recipient));
    payload[1] = amount & type(uint128).max;     // low 128 bits
    payload[2] = amount >> 128;                   // high 128 bits
    
    starknetCore.consumeMessageFromL2(l2ContractAddress, payload);
    
    // Transfer tokens to recipient
    IERC20(token).transfer(recipient, amount);
}
```

---

## Common Messaging Vulnerabilities

### 1. Missing L1 Sender Validation (CRITICAL)

```cairo
// VULNERABLE: Accepts messages from ANY L1 address
#[l1_handler]
fn handle_deposit(ref self: ContractState, from_address: felt252, user: ContractAddress, amount: u256) {
    // from_address not checked — attacker deploys L1 contract to send arbitrary messages
    self.balances.write(user, self.balances.read(user) + amount);
}
```

### 2. Message Replay (CRITICAL)

```cairo
// VULNERABLE: No nonce — same deposit can be processed multiple times
#[l1_handler]
fn handle_deposit(ref self: ContractState, from_address: felt252, user: ContractAddress, amount: u256) {
    assert(from_address == self.l1_bridge.read().into(), 'Bad sender');
    // Missing: Replay protection
    self.balances.write(user, self.balances.read(user) + amount);
}
```

### 3. L1 Finality Assumption (HIGH)

On L1, a message may exist in a pending block that gets reorged. Consuming a message based on insufficient confirmations could lead to double-spending.

**Mitigation:** The Starknet Core contract handles proof verification internally. Always use `consumeMessageFromL2()` — never attempt to verify messages manually.

### 4. Amount Encoding Mismatch (HIGH)

Starknet and Ethereum use different integer representations. A `u256` on Starknet is two `felt252` values (low, high), while on Ethereum it's a single `uint256`.

```
Starknet u256:  { low: felt252, high: felt252 }
Ethereum uint256: single 256-bit value

Encoding: payload[0] = low, payload[1] = high
Decoding: amount = (high << 128) | low
```

**Mitigation:** Always test encoding/decoding with edge cases including $0$, $2^{128} - 1$, and $2^{256} - 1$.

---

## Security Checklist

- [ ] All `l1_handler` functions validate `from_address` against expected L1 contract
- [ ] Message replay protection implemented (nonce or hash tracking)
- [ ] L2→L1 messages debit user state BEFORE sending message (CEI pattern)
- [ ] `u256` encoding between L1 and L2 handles low/high split correctly
- [ ] L1 consumption uses `consumeMessageFromL2()` (not manual verification)
- [ ] Proof finalization waited before L1 consumption
- [ ] Events emitted for all message sends and receives
- [ ] Error handling for failed message consumption
- [ ] Payload validation (non-zero amounts, valid addresses)
