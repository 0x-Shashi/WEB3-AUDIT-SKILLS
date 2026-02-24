---
id: STARKNET-PATTERNS
title: Starknet-Specific Vulnerability Patterns
category: starknet-scanner
difficulty: advanced
triggers:
  - starknet vulnerability patterns
  - cairo starknet security
  - felt comparison
  - replace_class
  - l1 handler
related_skills:
  - starknet-scanner/workflows/starknet-audit.md
  - cairo-scanner/resources/cairo-patterns.md
  - cairo-scanner/resources/starknet-security.md
tags:
  - starknet
  - cairo
  - patterns
  - security
last_updated: 2026-02-24
---

# Starknet-Specific Vulnerability Patterns

> These patterns cover Starknet infrastructure and architecture vulnerabilities — L1-L2 messaging, account abstraction, class upgrades, and component storage. For Cairo language-level patterns (felt arithmetic, Dict handling, assertion bugs), see [cairo-scanner/resources/cairo-patterns.md](../../cairo-scanner/resources/cairo-patterns.md).

---

## 1. Unprotected replace_class (CRITICAL)

**Impact**: `replace_class_syscall` swaps the contract's class hash, replacing ALL logic. Without access control, anyone can replace the contract with arbitrary code and drain all assets.

### Vulnerable Code
```cairo
#[starknet::contract]
mod vulnerable_vault {
    use starknet::replace_class_syscall;
    use starknet::ClassHash;

    #[storage]
    struct Storage {
        balance: u256,
    }

    // BUG: No access control — anyone can replace the contract logic
    #[external(v0)]
    fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
        replace_class_syscall(new_class_hash).unwrap();
    }
}
```

### Secure Code
```cairo
#[starknet::contract]
mod secure_vault {
    use starknet::{replace_class_syscall, ClassHash, get_caller_address, ContractAddress};
    use openzeppelin::access::ownable::OwnableComponent;

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;

    #[storage]
    struct Storage {
        balance: u256,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[external(v0)]
    fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
        // FIX: Only owner can upgrade
        self.ownable.assert_only_owner();

        // FIX: Prevent setting class hash to zero (bricking)
        assert(!new_class_hash.is_zero(), 'Class hash zero');

        replace_class_syscall(new_class_hash).unwrap();
        self.emit(Upgraded { new_class_hash });
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Upgraded: Upgraded,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    struct Upgraded {
        new_class_hash: ClassHash,
    }
}
```

**Real-World Impact**: Unprotected `replace_class` is the Starknet equivalent of an unprotected `selfdestruct` + arbitrary delegatecall. Any contract with this pattern can be completely taken over.

---

## 2. Account __validate__ Bypass (CRITICAL)

**Impact**: Starknet account abstraction requires every account contract to implement `__validate__` which checks transaction signatures. If validation logic is weak, attackers can replay or forge transactions.

### Vulnerable Code
```cairo
#[starknet::contract(account)]
mod vulnerable_account {
    #[external(v0)]
    fn __validate__(self: @ContractState, calls: Array<Call>) -> felt252 {
        // BUG: Always returns VALID — no actual signature check
        starknet::VALIDATED
    }

    #[external(v0)]
    fn __validate_deploy__(
        self: @ContractState,
        class_hash: felt252,
        salt: felt252,
    ) -> felt252 {
        // BUG: No signature verification on deploy
        starknet::VALIDATED
    }

    #[external(v0)]
    fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
        // All calls execute without validation
        execute_calls(calls)
    }
}
```

### Secure Code
```cairo
#[starknet::contract(account)]
mod secure_account {
    use starknet::{get_tx_info, get_caller_address, VALIDATED};

    #[storage]
    struct Storage {
        public_key: felt252,
    }

    #[external(v0)]
    fn __validate__(self: @ContractState, calls: Array<Call>) -> felt252 {
        // FIX: Verify ECDSA signature against stored public key
        let tx_info = get_tx_info().unbox();
        let tx_hash = tx_info.transaction_hash;
        let signature = tx_info.signature;
        assert(signature.len() == 2_u32, 'Invalid sig length');

        let is_valid = check_ecdsa_signature(
            tx_hash, self.public_key.read(), *signature.at(0), *signature.at(1),
        );
        assert(is_valid, 'Invalid signature');
        VALIDATED
    }

    #[external(v0)]
    fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
        // FIX: Only callable from __validate__ → __execute__ flow (protocol enforced)
        // Verify caller is zero (protocol invocation, not external call)
        let caller = get_caller_address();
        assert(caller.is_zero(), 'Only protocol can call');
        execute_calls(calls)
    }
}
```

---

## 3. L1 Handler Spoofing (CRITICAL)

**Impact**: `#[l1_handler]` functions process messages from L1 (Ethereum). If the handler doesn't validate `from_address`, any Ethereum address can send messages to manipulate L2 state.

### Vulnerable Code
```cairo
#[l1_handler]
fn deposit_from_l1(
    ref self: ContractState,
    from_address: felt252,  // L1 sender address
    user: ContractAddress,
    amount: u256,
) {
    // BUG: No validation that from_address is the legitimate L1 bridge contract
    // Anyone on L1 can call StarknetCore.sendMessageToL2() with arbitrary data
    self.balances.write(user, self.balances.read(user) + amount);
}
```

### Secure Code
```cairo
#[storage]
struct Storage {
    l1_bridge_address: felt252,  // Store the trusted L1 contract address
    balances: LegacyMap::<ContractAddress, u256>,
}

#[l1_handler]
fn deposit_from_l1(
    ref self: ContractState,
    from_address: felt252,
    user: ContractAddress,
    amount: u256,
) {
    // FIX: Validate the L1 sender is the trusted bridge contract
    assert(from_address == self.l1_bridge_address.read(), 'Invalid L1 sender');

    // FIX: Additional validation
    assert(amount > 0, 'Zero amount');

    self.balances.write(user, self.balances.read(user) + amount);
    self.emit(DepositReceived { from_l1: from_address, user, amount });
}
```

**Detection**: Search for `#[l1_handler]` functions and verify every one checks `from_address` against a stored trusted L1 address.

---

## 4. Storage Key Collision (HIGH)

**Impact**: Starknet uses Pedersen hash of variable names for storage slot computation. With components (formerly "modules in Cairo 0"), multiple components can accidentally write to the same storage slot.

### Vulnerable Code
```cairo
// Component A stores 'balance'
#[starknet::component]
mod ComponentA {
    #[storage]
    struct Storage {
        balance: u256,  // sn_keccak("balance") → slot X
    }
}

// Component B ALSO stores 'balance'
#[starknet::component]
mod ComponentB {
    #[storage]
    struct Storage {
        balance: u256,  // sn_keccak("balance") → SAME slot X!
    }
}

// When both components are used in a contract, they silently overwrite each other
#[starknet::contract]
mod vulnerable_contract {
    component!(path: ComponentA, storage: comp_a, event: EventA);
    component!(path: ComponentB, storage: comp_b, event: EventB);
    // comp_a.balance and comp_b.balance → SAME storage slot
}
```

### Mitigation
```cairo
// FIX: In Cairo 2.6.3+, use #[substorage(v0)] which prefixes component storage
// with the component's contract state member name, preventing collisions
#[storage]
struct Storage {
    #[substorage(v0)]
    comp_a: ComponentA::Storage,  // Prefixed: sn_keccak("comp_a") + offset
    #[substorage(v0)]
    comp_b: ComponentB::Storage,  // Prefixed: sn_keccak("comp_b") + offset
}

// Pre-2.6.3: Manually prefix storage variable names
// ComponentA::user_balance, ComponentB::reward_balance
```

**Detection**: List all storage variable names across all components used by a contract. Flag any duplicates.

---

## 5. Felt252 Comparison Bugs (HIGH)

**Impact**: `felt252` is a field element in $[0, P)$ where $P = 2^{251} + 17 \cdot 2^{192} + 1$. "Negative" values are actually large values near $P$. Comparisons using `<` or `>` on felt252 can produce unexpected results.

### Vulnerable Code
```cairo
// BUG: felt252 comparison treats -1 as P-1 (a huge number)
fn is_positive(amount: felt252) -> bool {
    amount > 0  // -1.into() → P-1 → returns true!
}

// BUG: Balance check using felt252 allows wrap-around
fn withdraw(ref self: ContractState, amount: felt252) {
    let balance = self.balances.read(get_caller_address());
    assert(balance >= amount, 'Insufficient');  // Unreliable with felt252
    self.balances.write(
        get_caller_address(),
        balance - amount  // Can underflow to near-P value
    );
}
```

### Secure Code
```cairo
// FIX: Use u256 or u128 for token amounts — proper integer semantics
fn withdraw(ref self: ContractState, amount: u256) {
    let balance: u256 = self.balances.read(get_caller_address());
    assert(balance >= amount, 'Insufficient');
    // u256 subtraction panics on underflow — safe
    self.balances.write(get_caller_address(), balance - amount);
}

// FIX: If felt252 is required, use explicit range checks
fn validate_amount(amount: felt252) {
    // Constrain to a safe range
    let amount_u128: u128 = amount.try_into().expect('Amount out of range');
}
```

---

## 6. Reentrancy via call_contract_syscall (HIGH)

**Impact**: `call_contract_syscall` invokes external contracts. Unlike Solidity, Starknet doesn't have a built-in reentrancy guard in the protocol. External calls can re-enter the calling contract.

### Vulnerable Code
```cairo
#[external(v0)]
fn withdraw(ref self: ContractState, amount: u256) {
    let balance = self.balances.read(get_caller_address());
    assert(balance >= amount, 'Insufficient');

    // BUG: External call BEFORE state update
    let token = IERC20Dispatcher { contract_address: self.token.read() };
    token.transfer(get_caller_address(), amount);

    // State update happens after external call — reentrancy window
    self.balances.write(get_caller_address(), balance - amount);
}
```

### Secure Code
```cairo
#[storage]
struct Storage {
    balances: LegacyMap::<ContractAddress, u256>,
    reentrancy_guard: bool,
}

#[external(v0)]
fn withdraw(ref self: ContractState, amount: u256) {
    // FIX: Reentrancy guard
    assert(!self.reentrancy_guard.read(), 'Reentrant call');
    self.reentrancy_guard.write(true);

    let caller = get_caller_address();
    let balance = self.balances.read(caller);
    assert(balance >= amount, 'Insufficient');

    // FIX: Update state BEFORE external call (CEI pattern)
    self.balances.write(caller, balance - amount);

    let token = IERC20Dispatcher { contract_address: self.token.read() };
    token.transfer(caller, amount);

    self.reentrancy_guard.write(false);
    self.emit(Withdrawal { user: caller, amount });
}
```

---

## 7. Library Call to Untrusted Class (MEDIUM)

**Impact**: `library_call_syscall` executes code from another class hash in the context of the current contract (like Solidity's `delegatecall`). If the class hash is user-supplied or stored insecurely, an attacker can execute arbitrary logic.

### Detection
```cairo
// Audit: Is the class_hash trusted?
use starknet::library_call_syscall;

fn execute_logic(class_hash: ClassHash, selector: felt252, calldata: Span<felt252>) {
    // DANGER: If class_hash comes from user input or unprotected storage
    library_call_syscall(class_hash, selector, calldata).unwrap();
}
```

### Checklist
- [ ] Class hash is hardcoded or stored in admin-only-writable storage
- [ ] No user-supplied class hash reaches `library_call_syscall`
- [ ] If upgradeable via class hash change, protected by access control

---

## 8. Component Storage Conflicts (MEDIUM)

**Impact**: When composing multiple OpenZeppelin components (Ownable, Pausable, ReentrancyGuard, etc.), hasty integration can cause event name collisions, conflicting initializers, or missing hook calls.

### Checklist
- [ ] No duplicate event names across components
- [ ] All component initializers called in constructor
- [ ] Component hooks (before_update, after_update) properly chained
- [ ] Storage member names in `#[substorage(v0)]` are unique

---

## 9. Missing Events on State Changes (MEDIUM)

**Impact**: Starknet indexers (Apibara, Checkpoint) and block explorers rely on events. Missing events make protocol activity invisible to off-chain systems.

### Checklist
- [ ] Every `#[external(v0)]` that modifies storage emits at least one event
- [ ] Events indexed with `#[key]` attribute on fields used for filtering
- [ ] Event structs include all relevant state change data
- [ ] Events emitted AFTER state is finalized (reflect actual new state)

---

## Real-World Starknet Incidents

| Incident | Vulnerability | Impact |
|---|---|---|
| Multiple early DeFi contracts | Unprotected `replace_class` | Full contract takeover possible |
| L1-L2 bridge implementations | Missing `from_address` validation | Unauthorized L2 minting |
| Cairo 0 → Cairo 2 migrations | Storage slot layout changes | Corrupted state after upgrade |
| Component composition bugs | Storage key collisions | Silent data overwrite |

---

## Starknet Audit Checklist

### Critical Checks
- [ ] `replace_class_syscall` protected by owner/multisig
- [ ] Account `__validate__` performs real signature verification
- [ ] All `#[l1_handler]` functions validate `from_address`
- [ ] No unbounded loops in external functions (sequencer gas limits)

### High Checks
- [ ] Felt arithmetic uses u128/u256 for token amounts
- [ ] No reentrancy via `call_contract_syscall` (CEI or guard)  
- [ ] Component storage keys verified unique
- [ ] Class hashes for `library_call` are admin-controlled

### Medium Checks
- [ ] Events emitted for all state changes, indexed appropriately
- [ ] Component initializers chained correctly
- [ ] Storage migration handled for upgrades

---

## Related Files

- [Starknet Audit Workflow](../workflows/starknet-audit.md) — Full 10-step Starknet audit process
- [Cairo Patterns](../../cairo-scanner/resources/cairo-patterns.md) — Cairo language vulnerability patterns
- [Starknet Security](../../cairo-scanner/resources/starknet-security.md) — Starknet framework security
