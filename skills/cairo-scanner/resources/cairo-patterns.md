---
id: CAIRO-PATTERNS
title: Cairo Vulnerability Patterns
parent: cairo-scanner
type: resource
last_updated: 2025-01-31
---

# Cairo Vulnerability Patterns

Comprehensive vulnerability patterns for Cairo smart contracts (Cairo 2.x / Sierra) on Starknet, with code examples and mitigations.

---

## Critical

### 1. Felt Overflow / Underflow

Field elements (felt252) operate in modular arithmetic over $P = 2^{251} + 17 \cdot 2^{192} + 1$. Subtraction of a larger value from a smaller wraps to a massive positive number.

**Vulnerable Pattern:**

```cairo
#[external(v0)]
fn transfer(ref self: ContractState, to: ContractAddress, amount: felt252) {
    let sender_balance = self.balances.read(get_caller_address());
    // VULNERABLE: If amount > sender_balance, result wraps to P - difference
    let new_balance = sender_balance - amount;
    self.balances.write(get_caller_address(), new_balance);
    self.balances.write(to, self.balances.read(to) + amount);
}
```

**Attack:** If `sender_balance = 100` and `amount = 200`, then `new_balance = P - 100` (an astronomically large number). The sender now has a near-infinite balance.

**Fixed Pattern:**

```cairo
#[external(v0)]
fn transfer(ref self: ContractState, to: ContractAddress, amount: u256) {
    let sender_balance: u256 = self.balances.read(get_caller_address());
    assert(sender_balance >= amount, 'Insufficient balance');
    self.balances.write(get_caller_address(), sender_balance - amount);
    self.balances.write(to, self.balances.read(to) + amount);
}
```

**Mitigation:** Use `u256` or `u128` for all financial amounts. Reserve `felt252` for hashes, addresses, and non-arithmetic identifiers.

---

### 2. Unprotected Contract Upgrade

The `replace_class_syscall` changes the contract's implementation class hash immediately. Without access control, anyone can upgrade the contract.

**Vulnerable Pattern:**

```cairo
#[external(v0)]
fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
    // VULNERABLE: No access control — anyone can call
    replace_class_syscall(new_class_hash).unwrap();
}
```

**Fixed Pattern:**

```cairo
#[external(v0)]
fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
    // Only owner can upgrade
    let caller = get_caller_address();
    assert(caller == self.owner.read(), 'Only owner can upgrade');
    assert(new_class_hash.is_non_zero(), 'Invalid class hash');
    replace_class_syscall(new_class_hash).unwrap();
    self.emit(Upgraded { new_class_hash });
}
```

---

### 3. Missing Reentrancy Guard

Cairo has no built-in reentrancy protection. `call_contract_syscall` can trigger re-entry.

**Vulnerable Pattern:**

```cairo
#[external(v0)]
fn withdraw(ref self: ContractState, amount: u256) {
    let balance = self.balances.read(get_caller_address());
    assert(balance >= amount, 'Insufficient');
    
    // VULNERABLE: External call before state update
    let token = IERC20Dispatcher { contract_address: self.token.read() };
    token.transfer(get_caller_address(), amount);
    
    self.balances.write(get_caller_address(), balance - amount);
}
```

**Fixed Pattern:**

```cairo
#[external(v0)]
fn withdraw(ref self: ContractState, amount: u256) {
    // Reentrancy guard
    assert(!self.locked.read(), 'Reentrant call');
    self.locked.write(true);
    
    let balance = self.balances.read(get_caller_address());
    assert(balance >= amount, 'Insufficient');
    
    // Effects before interactions
    self.balances.write(get_caller_address(), balance - amount);
    
    // Interaction
    let token = IERC20Dispatcher { contract_address: self.token.read() };
    token.transfer(get_caller_address(), amount);
    
    self.locked.write(false);
}
```

---

## High

### 4. Storage Address Collision

Starknet storage uses Pedersen hash: `storage_address = pedersen(variable_base, key)`. If two different state variables produce the same hash, they share storage.

**Risk Scenario:**

```cairo
#[storage]
struct Storage {
    balances: Map<ContractAddress, u256>,     // base = sn_keccak("balances")
    allowances: Map<ContractAddress, u256>,   // base = sn_keccak("allowances")
    // If custom storage addressing is used, collision is possible
}
```

**Mitigation:** Always use the standard `#[storage]` macro (which handles addressing correctly). Never compute storage addresses manually unless you've verified uniqueness.

### 5. L1-L2 Message Replay

L1→L2 messages consumed via `l1_handler` can be replayed if the contract doesn't track consumed messages.

**Vulnerable Pattern:**

```cairo
#[l1_handler]
fn deposit_from_l1(ref self: ContractState, from_address: felt252, user: ContractAddress, amount: u256) {
    // VULNERABLE: No replay protection — same message can be consumed again
    self.balances.write(user, self.balances.read(user) + amount);
}
```

**Fixed Pattern:**

```cairo
#[l1_handler]
fn deposit_from_l1(ref self: ContractState, from_address: felt252, user: ContractAddress, amount: u256, nonce: felt252) {
    // Verify L1 sender (Starknet core provides this as first arg)
    assert(from_address == self.l1_bridge_address.read().into(), 'Invalid L1 sender');
    
    // Replay protection
    assert(!self.consumed_messages.read(nonce), 'Message already consumed');
    self.consumed_messages.write(nonce, true);
    
    self.balances.write(user, self.balances.read(user) + amount);
    self.emit(L1DepositReceived { user, amount, nonce });
}
```

### 6. Account Validation Bypass

Custom account contracts must implement `__validate__` correctly. If validation is too permissive, anyone can execute transactions on behalf of the account.

**Vulnerable Pattern:**

```cairo
#[external(v0)]
fn __validate__(self: @ContractState, calls: Array<Call>) -> felt252 {
    // VULNERABLE: Always returns VALID — no signature check
    starknet::VALIDATED
}
```

**Fixed Pattern:**

```cairo
#[external(v0)]
fn __validate__(self: @ContractState, calls: Array<Call>) -> felt252 {
    let tx_info = get_tx_info().unbox();
    let tx_hash = tx_info.transaction_hash;
    let signature = tx_info.signature;
    
    // Verify signature against account's public key
    assert(self._is_valid_signature(tx_hash, signature), 'Invalid signature');
    starknet::VALIDATED
}
```

---

## Medium

### 7. Unbounded Storage Growth

Maps and arrays without size limits can grow indefinitely, making iteration expensive or impossible.

**Pattern:** Add length tracking and enforce limits for any dynamic collection.

### 8. Missing Event Emission

State changes without events make off-chain indexing impossible and reduce auditability.

**Pattern:** Emit events for all significant state changes (`transfer`, `approval`, `upgrade`, `ownership_transfer`).

### 9. Felt-to-Integer Comparison Gotchas

Comparing felt252 values with `<` or `>` can produce unexpected results when values conceptually represent "negative" numbers (values near $P$).

**Pattern:** Convert to `u256` before any ordering comparison.

---

## Cairo-Specific Notes

| Property | Detail |
|----------|--------|
| Field prime $P$ | $2^{251} + 17 \cdot 2^{192} + 1$ |
| Felt range | $[0, P-1]$ |
| Division semantics | Modular inverse: $a / b = a \cdot b^{-1} \pmod{P}$ |
| Integer types | `u8`, `u16`, `u32`, `u64`, `u128`, `u256` — all have overflow protection |
| No native reentrancy guard | Must implement manually (no `nonReentrant` modifier) |
| Account model | All accounts are contracts (native account abstraction) |

## Audit Checklist

- [ ] All financial amounts use `u256` or `u128` (not `felt252`)
- [ ] `replace_class_syscall` protected by access control
- [ ] `l1_handler` functions validate L1 sender and prevent replay
- [ ] External calls follow checks-effects-interactions pattern
- [ ] Custom `__validate__` verifies signatures correctly
- [ ] Storage variables use standard addressing (no manual collision risk)
- [ ] Events emitted for all state changes
- [ ] Felt comparisons don't assume integer semantics
