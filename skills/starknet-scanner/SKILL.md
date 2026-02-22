---
id: STARKNET-SCAN
title: Starknet Specialized Scanner
category: chain-scanner
trigger: "Audit Starknet|Starknet contract"
last_updated: 2025-01-31
---

# Starknet Specialized Scanner

Specialized security scanner for Starknet Cairo contracts. Extends the general [Cairo Scanner](../cairo-scanner/SKILL.md) with Starknet-specific patterns: account abstraction, contract upgrades via `replace_class`, component architecture, and the L1-L2 messaging bridge.

---

## Why a Separate Starknet Scanner?

While the Cairo Scanner covers language-level patterns (felt arithmetic, Sierra safety), Starknet-specific features create unique attack surfaces:

| Feature | Security Impact |
|---------|----------------|
| Account Abstraction | Custom validation logic = custom attack surface |
| `replace_class_syscall` | Contract upgrade mechanism — must be protected |
| Components (like Solidity libraries) | Storage collision between components |
| L1-L2 Messaging | Cross-chain replay, message validation |
| Sequencer | Centralized sequencer = MEV, censorship risks |
| Fee market | STRK token fees, gas estimation |

---

## Detection Capabilities

| Category | Detection | Severity |
|----------|-----------|----------|
| **Account** | `__validate__` missing signature check | Critical |
| **Account** | `__execute__` allows arbitrary call without validation | Critical |
| **Account** | Signature replay across chains (no chain_id in hash) | High |
| **Upgrade** | `replace_class_syscall` callable by unauthorized party | Critical |
| **Upgrade** | No upgrade delay/timelock | High |
| **Upgrade** | Storage layout incompatibility after upgrade | High |
| **Components** | Storage collision between components | High |
| **Components** | Component events shadowing contract events | Medium |
| **L1-L2** | Message replay (consumed message not tracked) | Critical |
| **L1-L2** | Missing sender validation on L1 handler | Critical |
| **L1-L2** | Message not consumed (stuck funds) | High |
| **Felt** | Felt arithmetic wrapping (p = 2^251 + 17*2^192 + 1) | High |
| **Storage** | Storage address collision (Pedersen hash) | Medium |
| **Access** | Missing caller validation on external function | Critical |
| **Access** | Ownable component not initialized | High |

---

## Starknet Account Abstraction

Every account on Starknet is a smart contract. This means custom validation logic:

```cairo
#[starknet::contract(account)]
mod MyAccount {
    // REQUIRED: Validates transaction signature
    // If this returns successfully, the tx is considered valid
    #[external(v0)]
    fn __validate__(
        ref self: ContractState,
        calls: Array<Call>
    ) -> felt252 {
        // CRITICAL: Must verify the transaction signature
        // If this blindly returns VALIDATED, anyone can submit txs as this account
        let tx_hash = get_tx_info().unbox().transaction_hash;
        let signature = get_tx_info().unbox().signature;
        
        // Verify signature against stored public key
        assert(check_ecdsa_signature(tx_hash, self.public_key.read(), *signature.at(0), *signature.at(1)), 'invalid sig');
        
        starknet::VALIDATED
    }
    
    // REQUIRED: Executes the validated transaction
    #[external(v0)]
    fn __execute__(
        ref self: ContractState,
        calls: Array<Call>
    ) -> Array<Span<felt252>> {
        // Execute each call
        // Typically a loop over calls with call_contract_syscall
    }
}
```

### Account Security Checklist

- [ ] `__validate__` verifies transaction hash signature
- [ ] `__validate__` uses stored public key (not hardcoded)
- [ ] Signature cannot be replayed (nonce handled by protocol)
- [ ] `chain_id` included in signature verification (cross-chain replay)
- [ ] Key rotation mechanism exists and is secure
- [ ] Multicall execution handles failures correctly (atomicity)

---

## Contract Upgrade via `replace_class_syscall`

Starknet contracts can upgrade their logic using `replace_class_syscall`:

```cairo
use starknet::replace_class_syscall;
use starknet::ClassHash;

#[external(v0)]
fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
    // CRITICAL: WHO can call this?
    self.ownable.assert_only_owner();
    
    // Replace the contract's class (logic) with new implementation
    replace_class_syscall(new_class_hash).unwrap();
    
    // Emit upgrade event
    self.emit(Upgraded { new_class_hash });
}
```

### Upgrade Security

| Risk | Description |
|------|-------------|
| Unauthorized upgrade | Anyone calling `replace_class_syscall` can change contract logic |
| No timelock | Instant upgrade = no time for users to exit |
| Storage incompatibility | New class may interpret storage differently |
| Proxy pattern | If using proxy, verify `replace_class` on implementation, not just proxy |

- [ ] `replace_class_syscall` protected by access control (owner, governance)
- [ ] Upgrade delay (timelock) implemented for critical contracts
- [ ] Storage layout documented and verified compatible across versions
- [ ] Upgrade event emitted

---

## Component Architecture

Starknet components are reusable modules (similar to Solidity libraries with storage):

```cairo
// Using OpenZeppelin components
#[starknet::contract]
mod MyContract {
    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::token::erc20::ERC20Component;
    
    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: ERC20Component, storage: erc20, event: ERC20Event);
    
    #[storage]
    struct Storage {
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        erc20: ERC20Component::Storage,
        // Custom storage
        my_value: felt252,
    }
}
```

### Component Security

| Risk | Description |
|------|-------------|
| Storage collision | Two components writing to same storage address |
| Uninitialized component | Ownable without `initializer()` = no owner set |
| Event shadowing | Component events with same name as contract events |
| Version mismatch | Component version incompatible with contract |

- [ ] All components initialized in constructor
- [ ] `#[substorage(v0)]` used correctly (automatic storage isolation)
- [ ] No manual storage access that could collide with component storage
- [ ] Component versions compatible with each other

---

## L1-L2 Messaging

Starknet communicates with Ethereum L1 via asynchronous messaging:

| Direction | Mechanism | Latency |
|-----------|-----------|----------|
| L1 → L2 | `send_message_to_l2()` on Starknet Core contract | ~minutes (L2 block time) |
| L2 → L1 | `send_message_to_l1_syscall()` in Cairo | ~hours (proof verification) |

### L1-L2 Security Checklist

- [ ] L2 handler validates L1 sender (`from_address` in L1Handler)
- [ ] L1 handler validates L2 sender (message origin)
- [ ] Messages consumed exactly once (replay protection)
- [ ] Message format matches between L1 and L2 contracts
- [ ] Stuck message handling (cancellation mechanism exists)
- [ ] Fee handling on L1→L2 messages correct

---

## Resources
- [Starknet Patterns](resources/starknet-patterns.md)

## Workflows
- [Starknet Audit](workflows/starknet-audit.md)

## See Also
- [Cairo Scanner](../cairo-scanner/SKILL.md) for Cairo language patterns
- [Chain Guide: Starknet](../chain-guides/starknet.md) for chain context
