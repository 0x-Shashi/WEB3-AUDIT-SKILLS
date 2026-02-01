---
id: CHAIN-STARKNET
title: StarkNet Security Guide
category: chain-guides
chain: starknet
language: cairo
difficulty: advanced
tags: [starknet, cairo, zk-rollup, stark, account-abstraction]
last_updated: 2026-01-31
---

# StarkNet Security Guide

## Overview

StarkNet is a ZK-Rollup using STARK proofs and the Cairo programming language. Its unique architecture (native AA, storage proofs, different EVM model) creates distinct security considerations.

```
┌─────────────────────────────────────────────────────────────────┐
│                    STARKNET ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  L2 (STARKNET)                        L1 (ETHEREUM)             │
│  ┌─────────────────────────────┐    ┌──────────────────┐       │
│  │  Sequencer                  │    │                  │       │
│  │  ┌─────────┐  ┌─────────┐  │    │  Core Contract   │       │
│  │  │ Account │  │Contract │  │    │  ┌────────────┐  │       │
│  │  │  (AA)   │  │ (Cairo) │  │────│  │ State Root │  │       │
│  │  └─────────┘  └─────────┘  │    │  │ STARK Proof│  │       │
│  │                            │    │  └────────────┘  │       │
│  └─────────────────────────────┘    └──────────────────┘       │
│                                                                 │
│  KEY DIFFERENCES FROM EVM:                                      │
│  • Native account abstraction (all accounts are contracts)      │
│  • Cairo language (not Solidity)                                │
│  • Storage proofs (access historical state)                     │
│  • Different transaction model                                  │
│  • Felt252 field elements (not uint256)                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Cairo Language Fundamentals

### Basic Types

```cairo
// Cairo 1.0+ (current version)

// Field elements (0 to P-1, where P is prime)
fn example_felt() {
    let x: felt252 = 100;
    let y: felt252 = 200;
    
    // Arithmetic wraps around P (not 2^256)
    // P ≈ 2^251 + 17 * 2^192 + 1
    let z = x + y;  // Safe if < P
}

// Unsigned integers (bounded, overflow-checked)
fn example_uint() {
    let a: u256 = 1000_u256;
    let b: u128 = 500_u128;
    
    // Overflow panics by default (good!)
    let c = a + b.into();  // Must convert types
}

// Arrays (different from Solidity)
fn example_array() {
    let mut arr = ArrayTrait::new();
    arr.append(1);
    arr.append(2);
    
    // Arrays are consumed on read!
    let first = *arr.at(0);  // Snapshot, doesn't consume
    let popped = arr.pop_front();  // Consumes
}
```

### Storage Model

```cairo
// Storage in Cairo contracts

#[storage]
struct Storage {
    // Simple storage
    balance: felt252,
    
    // Mappings
    balances: LegacyMap<ContractAddress, u256>,
    
    // Nested mappings
    allowances: LegacyMap<(ContractAddress, ContractAddress), u256>,
}

// SECURITY: Storage layout is NOT the same as Solidity
// Storage addresses computed differently
// Collisions possible if not careful with mapping keys
```

---

## Attack Vector 1: Account Abstraction Vulnerabilities

### Native AA Model

```cairo
// ALL accounts on StarkNet are contracts
// No EOAs!

#[starknet::interface]
trait IAccount<TContractState> {
    fn __validate__(ref self: TContractState, calls: Array<Call>) -> felt252;
    fn __execute__(ref self: TContractState, calls: Array<Call>) -> Array<Span<felt252>>;
    fn __validate_declare__(self: @TContractState, class_hash: felt252) -> felt252;
}

// ATTACK VECTORS:
// 1. Signature validation bugs
// 2. Nonce management issues
// 3. Gas estimation attacks
// 4. Multicall atomicity issues
```

### Signature Validation

```cairo
// VULNERABLE: Weak signature validation
#[external(v0)]
fn __validate__(ref self: ContractState, calls: Array<Call>) -> felt252 {
    let tx_info = get_tx_info().unbox();
    let signature = tx_info.signature;
    
    // WRONG: Only checking signature length
    assert(signature.len() == 2, 'Invalid sig length');
    
    // MISSING: Actual signature verification!
    
    starknet::VALIDATED  // Returns valid anyway!
}

// SECURE: Proper ECDSA validation
#[external(v0)]
fn __validate__(ref self: ContractState, calls: Array<Call>) -> felt252 {
    let tx_info = get_tx_info().unbox();
    let tx_hash = tx_info.transaction_hash;
    let signature = tx_info.signature;
    
    // Verify ECDSA signature
    let is_valid = check_ecdsa_signature(
        tx_hash,
        self.public_key.read(),
        *signature.at(0),  // r
        *signature.at(1)   // s
    );
    
    assert(is_valid, 'Invalid signature');
    starknet::VALIDATED
}
```

### Multicall Atomicity

```cairo
// StarkNet __execute__ handles multiple calls atomically

#[external(v0)]
fn __execute__(
    ref self: ContractState,
    calls: Array<Call>
) -> Array<Span<felt252>> {
    // VULNERABILITY: Not checking call success
    let mut results = ArrayTrait::new();
    
    let mut i = 0;
    loop {
        if i >= calls.len() { break; }
        
        let call = calls.at(i);
        let result = starknet::call_contract_syscall(
            *call.to,
            *call.selector,
            call.calldata.span()
        );
        
        // MISSING: Check for failure!
        // If one call fails, others might have succeeded
        // Partial execution = inconsistent state
        
        results.append(result.unwrap_syscall());
        i += 1;
    };
    
    results
}
```

---

## Attack Vector 2: felt252 Arithmetic

### Field Element Overflow

```cairo
// felt252 is NOT uint256!
// Range: 0 to P-1 (P ≈ 2^251)

fn vulnerable_math(a: felt252, b: felt252) -> felt252 {
    // VULNERABILITY: No overflow check for felt252
    // If a + b >= P, wraps around!
    
    let result = a + b;  // Could wrap
    result
}

// ATTACK EXAMPLE:
// P ≈ 3618502788666131213697322783095070105623107215331596699973092056135872020481
// If a = P - 1, b = 2
// a + b = (P - 1 + 2) mod P = 1
// Attacker turns huge value into 1!

// SECURE: Use bounded integers
fn safe_math(a: u256, b: u256) -> u256 {
    // u256 panics on overflow
    a + b  // Safe
}

// Or explicit checks for felt252
fn checked_felt_add(a: felt252, b: felt252) -> felt252 {
    let a_u256: u256 = a.into();
    let b_u256: u256 = b.into();
    let sum = a_u256 + b_u256;
    
    // Check didn't wrap
    assert(sum >= a_u256, 'Overflow');
    
    sum.try_into().unwrap()
}
```

### Division Precision

```cairo
// felt252 division is field division (multiplicative inverse)
// NOT integer division!

fn field_division() {
    let a: felt252 = 10;
    let b: felt252 = 3;
    
    // This is NOT 10/3 = 3
    // This is 10 * (3^-1 mod P)
    // Result is some huge felt252!
    let result = a / b;
    
    // To get integer division:
    let a_u256: u256 = a.into();
    let b_u256: u256 = b.into();
    let int_div = a_u256 / b_u256;  // = 3
}
```

---

## Attack Vector 3: Storage Collisions

### Storage Address Calculation

```cairo
// StarkNet storage addresses calculated via hash

// For simple variables:
// storage_address = pedersen(variable_name)

// For mappings:
// storage_address = pedersen(pedersen(mapping_name), key)

// VULNERABILITY: Custom storage can collide
#[storage]
struct Storage {
    // These could theoretically collide with computed addresses
    my_var: felt252,
    my_map: LegacyMap<felt252, felt252>,
}

// If attacker controls 'key' in my_map
// Could they find 'key' such that:
// pedersen(pedersen('my_map'), key) == pedersen('my_var')?
// In practice: computationally infeasible but worth noting
```

### Proxy Storage

```cairo
// StarkNet proxy pattern storage

#[storage]
struct Storage {
    // Use specific storage slots for upgradeability
    implementation: ClassHash,
    admin: ContractAddress,
}

// VULNERABILITY: If implementation uses same storage slots
// Could corrupt proxy admin/implementation

// DEFENSE: Use unique storage addresses
const IMPLEMENTATION_SLOT: felt252 = selector!("implementation_hash");
const ADMIN_SLOT: felt252 = selector!("admin_address");
```

---

## Attack Vector 4: L1↔L2 Messaging

### Message Structure

```cairo
// L1 → L2 Message
struct L1ToL2Message {
    from_address: EthAddress,    // L1 sender
    to_address: ContractAddress, // L2 recipient
    selector: felt252,           // Function to call
    payload: Array<felt252>,     // Arguments
    nonce: felt252,              // Prevents replay
}

// L2 → L1 Message
fn send_message_to_l1(to_address: EthAddress, payload: Array<felt252>) {
    send_message_to_l1_syscall(to_address, payload.span()).unwrap_syscall();
}
```

### Message Validation Vulnerabilities

```cairo
// VULNERABLE: No sender validation
#[l1_handler]
fn handle_deposit(ref self: ContractState, from_address: felt252, amount: u256) {
    // WRONG: Anyone on L1 could have sent this!
    // from_address is just a parameter, not verified
    
    self.balances.write(from_address, amount);
}

// SECURE: Validate L1 sender
#[l1_handler]
fn handle_deposit(
    ref self: ContractState,
    from_address: felt252,
    user: ContractAddress,
    amount: u256
) {
    // Verify message came from authorized L1 contract
    assert(
        from_address == self.l1_bridge.read().into(),
        'Unauthorized L1 sender'
    );
    
    self.balances.write(user, amount);
}
```

### Replay Attacks

```cairo
// L1→L2 messages include nonce (automatic)
// L2→L1 messages do NOT have automatic replay protection!

// VULNERABLE L1 consumer:
contract L1Receiver {
    function consumeMessage(uint256[] calldata payload) external {
        // WRONG: No replay protection
        // Same message can be consumed multiple times
        
        processPayload(payload);
    }
}

// SECURE: Track consumed messages
contract L1ReceiverSecure {
    mapping(bytes32 => bool) public consumedMessages;
    
    function consumeMessage(uint256[] calldata payload) external {
        bytes32 msgHash = keccak256(abi.encode(
            l2SenderAddress,
            address(this),
            payload
        ));
        
        require(!consumedMessages[msgHash], "Already consumed");
        consumedMessages[msgHash] = true;
        
        starknetCore.consumeMessageFromL2(l2SenderAddress, payload);
        processPayload(payload);
    }
}
```

---

## Attack Vector 5: Class Declaration Attacks

### Class Hash System

```cairo
// StarkNet separates code (class) from instances (contracts)
// declare_class() → class_hash
// deploy(class_hash) → contract_address

// VULNERABILITY: Class replacement
// If you control class declaration, you control ALL instances

#[external(v0)]
fn upgrade(ref self: ContractState, new_class: ClassHash) {
    // WRONG: No access control
    // Anyone can upgrade!
    
    replace_class_syscall(new_class).unwrap_syscall();
}

// SECURE:
#[external(v0)]
fn upgrade(ref self: ContractState, new_class: ClassHash) {
    self.only_admin();
    
    // Verify new class is legitimate
    assert(self.approved_classes.read(new_class), 'Unapproved class');
    
    replace_class_syscall(new_class).unwrap_syscall();
    
    emit Upgraded { new_class };
}
```

---

## Audit Checklist

### Cairo Contract Security

```markdown
## Cairo Security Review

### Arithmetic Safety
□ Using bounded integers (u256, u128) for amounts?
□ felt252 overflow considered?
□ Division uses integer types not felt252?
□ No precision loss in calculations?

### Account Abstraction (if account contract)
□ __validate__ actually validates signature?
□ Nonce management correct?
□ __execute__ handles failures atomically?
□ No validation/execution mismatch?

### Access Control
□ Sensitive functions protected?
□ Admin/owner properly set in constructor?
□ Upgrade mechanism secure?
□ Class replacement restricted?

### Storage
□ No storage collisions with proxy?
□ Mapping keys properly bounded?
□ Storage reads/writes in correct order?

### L1↔L2 Messaging
□ L1 handler validates from_address?
□ L2→L1 messages have replay protection on L1?
□ Message payload correctly encoded?
□ Failure cases handled?
```

### StarkNet-Specific Patterns

```markdown
## StarkNet-Specific Checks

### Syscall Safety
□ All syscalls have proper error handling?
□ call_contract_syscall checked for failure?
□ Storage syscalls in correct order?

### Event Emission
□ Important state changes emit events?
□ Event data correctly indexed?
□ No sensitive data in events?

### Gas Considerations
□ Computation steps bounded?
□ No unbounded loops?
□ Storage access minimized?
```

---

## Code Examples

### Secure Token Implementation

```cairo
#[starknet::contract]
mod SecureToken {
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    
    #[storage]
    struct Storage {
        name: felt252,
        symbol: felt252,
        total_supply: u256,
        balances: LegacyMap<ContractAddress, u256>,
        allowances: LegacyMap<(ContractAddress, ContractAddress), u256>,
    }
    
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Transfer: Transfer,
        Approval: Approval,
    }
    
    #[derive(Drop, starknet::Event)]
    struct Transfer {
        from: ContractAddress,
        to: ContractAddress,
        value: u256,
    }
    
    #[external(v0)]
    fn transfer(
        ref self: ContractState,
        recipient: ContractAddress,
        amount: u256
    ) -> bool {
        let sender = get_caller_address();
        
        // Safe: u256 checks for underflow
        let sender_balance = self.balances.read(sender);
        assert(sender_balance >= amount, 'Insufficient balance');
        
        // Update balances
        self.balances.write(sender, sender_balance - amount);
        self.balances.write(
            recipient,
            self.balances.read(recipient) + amount
        );
        
        self.emit(Transfer { from: sender, to: recipient, value: amount });
        
        true
    }
}
```

---

## Related Resources

- [StarkNet Documentation](https://docs.starknet.io/)
- [Cairo Book](https://book.cairo-lang.org/)
- [StarkNet Security](https://github.com/starknet-io/starknet-security)
- [StarkNet Contracts](https://github.com/OpenZeppelin/cairo-contracts)
