# Starknet Security Guide

## Chain Overview

- **Type:** Validity Rollup (zkRollup) L2
- **Language:** Cairo
- **VM:** Cairo VM (STARK-based)
- **Proving:** zk-STARK proofs
- **Finality:** ~minutes (proof generation) + L1 verification
- **Gas Token:** ETH (STRK for some fees)
- **Chain ID:** SN_MAIN

## Key Security Considerations

### 1. Cairo Language (Not EVM!)
```cairo
// Cairo is fundamentally different from Solidity:
// - Based on field elements (felts) - not uint256
// - No native integer overflow protection
// - Immutable by default
// - No inheritance (uses components/traits)
// - Storage is explicit via @storage_var

// Felt arithmetic:
// felts are elements of a prime field P = 2^251 + 17*2^192 + 1
// Operations wrap around this prime
// Division is modular inverse (a/b = a * b^(-1) mod P)
```

### 2. Felt Arithmetic (Critical!)
```cairo
// [VULNERABLE] Felt comparison is NOT integer comparison
// felts are in range [0, P-1] where P is the prime
// "Negative" numbers are actually large positive felts

// Example: -1 in felt = P - 1 = very large number
// Comparing felt < 100 doesn't work as expected for "negative" felts

// [SAFE] Use uint256 or explicit range checks
fn safe_transfer(amount: u256) {
    assert(amount <= MAX_AMOUNT, 'Amount too large');
}
```

### 3. Storage Model
```cairo
// Starknet uses a different storage model:
// - Storage addresses are felts (pedersen hash of variable name)
// - No storage slots like EVM
// - Maps use pedersen hash of (base_address, key)
// - Storage is sparse (unwritten = 0)

// Storage collision risk:
// - Custom storage address calculation can collide
// - Map keys that hash to same storage address
```

### 4. Contract Upgradability
```cairo
// Starknet contracts are upgradeable by default:
// - Contract = class hash + storage
// - replace_class_syscall changes the class (logic)
// - Storage is preserved during upgrade
// 
// [AUDIT] Who can call replace_class_syscall?
// This is equivalent to proxy upgrade in Solidity
// Must check access control on upgrade function
```

### 5. L1 <-> L2 Messaging
```
L1 → Starknet: send_message_to_l2 (via StarknetCore on Ethereum)
Starknet → L1: send_message_to_l1_syscall (consumed by L1 contract)
```

**Critical risks:**
- L1→L2 messages are asynchronous (not instant)
- L2→L1 messages require proof finalization
- Message nonce/hash must be checked to prevent replay
- Sequencer can delay/censor messages

### 6. Account Abstraction (Native)
```cairo
// All Starknet accounts are smart contracts
// Account contracts implement:
// - __validate__: signature/auth validation
// - __execute__: transaction execution
//
// Implications:
// - No EOAs exist on Starknet
// - Custom signature schemes possible
// - Account contract bugs affect ALL user actions
// - tx_info.account_contract_address is the "sender"
```

### 7. Syscalls
Key Starknet syscalls:
- `call_contract_syscall`: Cross-contract calls
- `deploy_syscall`: Deploy new contracts
- `emit_event_syscall`: Emit events
- `get_block_info_syscall`: Block context
- `get_execution_info_syscall`: Transaction context
- `send_message_to_l1_syscall`: L2→L1 messaging
- `replace_class_syscall`: Upgrade contract logic
- `library_call_syscall`: Like delegatecall

### 8. Reentrancy
- Cairo does NOT have a native reentrancy guard
- Cross-contract calls via `call_contract_syscall` can re-enter
- Component-based architecture can hide reentrancy paths
- **Audit check:** Apply same reentrancy analysis as Solidity

## Starknet-Specific Audit Checklist

- [ ] Felt arithmetic: no accidental wrapping in comparisons
- [ ] Use u256/u128 types instead of raw felts where appropriate
- [ ] Access control on `replace_class_syscall` (upgrade)
- [ ] Storage address collisions checked
- [ ] L1<>L2 message replay protection
- [ ] Account abstraction: custom validation logic reviewed
- [ ] Reentrancy protection on state-changing functions
- [ ] Event emissions for important state changes
- [ ] Cryptographic operations use felt-compatible math
- [ ] Sequencer trust assumptions documented
- [ ] Library call (delegatecall equivalent) targets validated
- [ ] Component interactions don't create hidden vulnerabilities

## Common Vulnerabilities on Starknet

| Vulnerability | Description |
|--------------|-------------|
| Felt arithmetic bugs | Wrapping/comparison errors with field elements |
| Upgrade access control | Unprotected replace_class_syscall |
| L1<>L2 message replay | Missing nonce/hash validation |
| Storage collision | Custom storage calculations overlap |
| Reentrancy | No native guard, cross-contract calls re-enter |
| Account validation bypass | Custom __validate__ logic flawed |
