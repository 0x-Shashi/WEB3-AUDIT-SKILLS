# Sui Security Guide

## Chain Overview

- **Type:** L1 (Move variant)
- **Language:** Sui Move (different from Aptos Move)
- **Account Model:** Object-centric (not account-centric)
- **Consensus:** Narwhal/Bullshark (DAG-based)
- **Finality:** ~400ms (for owned objects), ~2s (shared objects)
- **Gas Token:** SUI

## Key Security Considerations

### 1. Object Model (Key Difference from Aptos!)
```move
// Sui uses OBJECTS instead of resources stored under accounts
// Object types:
// - Owned: belongs to one address (parallel, fast)
// - Shared: accessible by any transaction (sequenced, slower)
// - Immutable: frozen, read-only forever
// - Wrapped: contained within another object

// [CRITICAL] Owned vs Shared affects consensus path!
// Owned object transactions can be processed in parallel
// Shared object transactions must go through consensus
```

### 2. Object Ownership and Transfer
```move
// [VULNERABLE] Transferring without proper checks
public fun transfer_nft(nft: NFT, recipient: address) {
    transfer::public_transfer(nft, recipient);
    // Any caller with the object can transfer!
}

// [SAFE] With access control
public fun transfer_nft(nft: NFT, ctx: &TxContext) {
    assert!(object::owner(&nft) == tx_context::sender(ctx), ENotOwner);
    // Only owner can initiate transfer
}
```

### 3. Sui Move vs Core Move Differences
```
Key differences from Aptos Move:
1. Object-centric vs account-centric storage
2. No global storage operations (move_to, move_from, borrow_global)
3. TxContext instead of signer for authentication
4. Dynamic fields (attach fields to objects at runtime)
5. One-Time Witness (OTW) pattern for singleton creation
6. Custom transfer policies via transfer::public_transfer
```

### 4. Dynamic Fields
```move
// Dynamic fields can attach data to objects at runtime
// Risks:
// - No compile-time type checking for dynamic field keys
// - Can create unbounded storage (gas DoS)
// - Key collisions if namespace not managed

// [VULNERABLE] Unbounded dynamic field addition
public fun add_metadata(obj: &mut UID, key: String, value: String) {
    dynamic_field::add(obj, key, value); // No limit on how many!
}
```

### 5. One-Time Witness (OTW) Pattern
```move
// OTW is created exactly once during module publish
// Used to prove module initialization happened correctly

// [VULNERABLE] Not using OTW for unique initialization
public fun init(ctx: &mut TxContext) {
    // Can be called multiple times if not using OTW!
}

// [SAFE] Using OTW
public fun init(witness: MY_MODULE, ctx: &mut TxContext) {
    // MY_MODULE witness can only be created during publish
    // Guarantees single initialization
}
```

### 6. Clock and Randomness
```move
// Sui provides shared Clock object for timestamps
// Clock is a shared object - adds consensus overhead
// Randomness: Sui has on-chain randomness (drand-based)

// [VULNERABLE] Using Clock for randomness
public fun pseudo_random(clock: &Clock): u64 {
    clock::timestamp_ms(clock) % 100 // Predictable!
}
```

### 7. Package Upgrades
- Sui packages can be upgraded with compatibility checks
- Upgrade capability is an owned object
- Upgrade policy: compatible, additive-only, or immutable
- **Audit check:** Who holds the UpgradeCap? Is it properly restricted?

## Sui-Specific Audit Checklist

- [ ] Object ownership model correct (owned vs shared vs immutable)
- [ ] Shared objects only where necessary (performance impact)
- [ ] TxContext sender validated for access control
- [ ] Dynamic fields bounded (no unlimited growth)
- [ ] One-Time Witness used for singleton resources
- [ ] UpgradeCap properly secured (or burned for immutability)
- [ ] Object wrapping/unwrapping logic correct
- [ ] Transfer policies appropriate (public_transfer vs internal)
- [ ] Clock usage doesn't introduce timing vulnerabilities
- [ ] Event emissions for audit trail
- [ ] Object ID generation deterministic and collision-free
- [ ] Reentrancy: consider shared object contention

## Common Vulnerabilities in Sui

| Vulnerability | Description |
|--------------|-------------|
| Object ownership bypass | Shared object accessed without authorization |
| Missing TxContext.sender check | Privileged action without authentication |
| Dynamic field overflow | Unbounded dynamic fields = gas DoS |
| UpgradeCap leak | Upgrade capability not properly secured |
| OTW not used | Module initialization can be replayed |
| Shared object contention | Performance DoS via shared object spam |
