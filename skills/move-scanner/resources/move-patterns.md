---
id: MOVE-PATTERNS
title: Move Vulnerability Patterns
parent: move-scanner
type: resource
last_updated: 2025-01-31
---

# Move Vulnerability Patterns

Detailed vulnerability patterns for Move smart contracts on Aptos and Sui, with vulnerable code examples, attack scenarios, and mitigations.

---

## Critical

### 1. Capability Leak

A capability object (AdminCap, MintCap, TreasuryCap) stored in a publicly accessible location allows unauthorized users to perform privileged operations.

**Vulnerable Pattern (Aptos):**

```move
// VULNERABLE: AdminCap stored under a known address with 'store' — anyone with access can use it
struct AdminCap has key, store, copy, drop {}

public entry fun init(admin: &signer) {
    move_to(admin, AdminCap {});
}

// Anyone who can get a reference to AdminCap can call this
public fun mint(cap: &AdminCap, amount: u64): Coin<MyToken> {
    // Mints tokens...
}
```

**Why It's Dangerous:** The `copy` ability allows duplication, and `store` allows nesting inside other resources that could be extracted. Combined with `drop`, the cap can be silently discarded after copying.

**Fixed Pattern:**

```move
// SAFE: AdminCap without copy/drop — linear, non-duplicable, must be stored or destroyed
struct AdminCap has key {
    id: UID, // Sui
}

// Only the holder of the original cap can use it
public fun mint(_cap: &AdminCap, amount: u64): Coin<MyToken> {
    // Mints tokens...
}
```

---

### 2. Missing Signer Validation

```move
// VULNERABLE: No signer check — anyone can call
public entry fun withdraw(pool: &mut Pool, amount: u64) {
    let coins = coin::extract(&mut pool.balance, amount);
    transfer::public_transfer(coins, tx_context::sender(ctx));
}

// SAFE: Requires signer + validates against stored authority
public entry fun withdraw(admin: &signer, pool: &mut Pool, amount: u64) {
    assert!(signer::address_of(admin) == pool.authority, E_NOT_AUTHORIZED);
    let coins = coin::extract(&mut pool.balance, amount);
    coin::deposit(signer::address_of(admin), coins);
}
```

---

### 3. Resource Duplication via `copy`

```move
// DANGEROUS: Coin-like struct with copy = infinite money
struct Token has key, store, copy {
    amount: u64
}

// Attacker can duplicate:
let original = get_token();
let duplicated = copy original; // Now has 2x the tokens
```

**Rule:** Never give `copy` ability to value-holding types.

---

## High

### 4. Unprotected Module Upgrade

**Aptos:**
```move
// Check upgrade policy at framework level
// Upgrade policies: compatible (default), immutable
// If 'compatible', whoever holds the upgrade authority can change module logic
// Risk: If authority is an EOA, one compromised key = protocol takeover
```

**Sui:**
```move
// VULNERABLE: UpgradeCap not burned or properly secured
fun init(otw: MY_MODULE, ctx: &mut TxContext) {
    // UpgradeCap created but not handled — if it's stored publicly, anyone can upgrade
    let upgrade_cap = package::claim(otw, ctx);
    transfer::public_transfer(upgrade_cap, tx_context::sender(ctx));
    // Better: transfer::transfer (not public) or burn if immutable
}
```

---

### 5. Friend Function Abuse

```move
// RISKY: Too many friend modules can access internal functions
friend my_package::module_a;
friend my_package::module_b;
friend my_package::module_c; // Does module_c really need access?

public(friend) fun internal_mint(amount: u64): Coin<MyToken> {
    // Only friend modules can call — but are all friends trusted?
}
```

**Audit Rule:** Every `public(friend)` function should have a documented reason for each friend module.

---

### 6. Integer Overflow

Move integers (`u8`, `u64`, `u128`, `u256`) abort on overflow/underflow — unlike Solidity 0.7 and below, or Solana Rust in release mode. However, the **abort** itself can be weaponized:

```move
// DoS via overflow abort
public fun deposit(pool: &mut Pool, amount: u64) {
    pool.total = pool.total + amount; // Aborts if total + amount > u64::MAX
    // Attacker deposits enough to make pool.total near u64::MAX
    // Next legitimate user's deposit aborts = denial of service
}
```

**Mitigation:** Use `u128` or `u256` for accumulator variables, or explicitly handle near-max values.

---

## Medium

### 7. Missing Abort Codes

```move
// BAD: Generic abort — impossible to debug or monitor
assert!(condition, 0);

// GOOD: Descriptive error code with documentation
const E_INSUFFICIENT_BALANCE: u64 = 1001;
const E_NOT_AUTHORIZED: u64 = 1002;
assert!(balance >= amount, E_INSUFFICIENT_BALANCE);
```

### 8. Dynamic Field Overflow (Sui)

```move
// VULNERABLE: Unbounded dynamic fields
public fun add_entry(obj: &mut MyObject, key: String, value: u64) {
    dynamic_field::add(obj, key, value); // No count limit
}

// SAFE: Enforce bounds
const MAX_ENTRIES: u64 = 10000;
assert!(obj.entry_count < MAX_ENTRIES, E_TOO_MANY_ENTRIES);
dynamic_field::add(obj, key, value);
obj.entry_count = obj.entry_count + 1;
```

---

## Move Type System Security Reference

| Ability | Allows | Security Rule |
|---------|--------|---------------|
| `key` | Global storage (Aptos) / Object (Sui) | Required for top-level storage |
| `store` | Can be nested inside other structs | Be careful — stored values may be extractable |
| `copy` | Can be duplicated | NEVER on value-holding types (coins, tokens, shares) |
| `drop` | Can be silently discarded | CAREFUL on capabilities — dropping = losing access |

## Audit Checklist

- [ ] No value-holding type has `copy` ability
- [ ] Capabilities (AdminCap, MintCap) have minimal abilities (key only, or key + store)
- [ ] All entry functions validate signer/caller
- [ ] Upgrade authority properly secured (or set to immutable)
- [ ] Friend declarations are minimal and justified
- [ ] Integer arithmetic uses appropriately sized types
- [ ] Abort codes are unique and documented
- [ ] Events emitted for all state changes
