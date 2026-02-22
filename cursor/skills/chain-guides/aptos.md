# Aptos Security Guide

## Chain Overview

- **Type:** L1 (Move-based)
- **Language:** Move
- **Account Model:** Resource-oriented (resources stored under accounts)
- **Consensus:** AptosBFT (DiemBFT variant)
- **Finality:** ~1 second
- **Gas Token:** APT

## Key Security Considerations

### 1. Move Language and Resource Model
```move
// Move uses RESOURCES instead of storage mappings
// Resources cannot be copied or dropped (unless ability granted)
// Resources are stored under accounts (not in contract storage)

// Key abilities:
// - copy: value can be duplicated
// - drop: value can be discarded
// - store: value can be stored in global storage
// - key: value can be used as a global storage key

// [SAFE BY DESIGN] Resources prevent double-spending
// You physically cannot copy a Coin resource
struct Coin has store {
    value: u64,
}
```

### 2. Module Upgrade Risks
```move
// Move modules can be upgraded (by default)
// Upgrade policy levels:
// - Compatible: only adds new functions/resources
// - Immutable: cannot be upgraded
// - Arbitrary (careful!): any changes allowed

// [VULNERABLE] Module with arbitrary upgrade policy
// Module owner can change logic after deployment
// Equivalent to Solidity unaudited proxy upgrade
```

**Audit check:** What is the upgrade policy? Is it appropriate?

### 3. Ability Constraints
```move
// [VULNERABLE] Overly permissive abilities
struct ImportantToken has key, store, copy, drop {
    // copy + drop means tokens can be duplicated and destroyed freely!
    value: u64,
}

// [SAFE] Restrictive abilities
struct ImportantToken has key, store {
    // Cannot be copied or dropped - must be explicitly handled
    value: u64,
}
```

### 4. Access Control (Signer-based)
```move
// Move uses &signer for access control
// signer represents the account that signed the transaction

// [VULNERABLE] Public function without signer check
public fun admin_withdraw(vault: &mut Vault, amount: u64) {
    // No signer parameter - anyone can call!
    vault.balance = vault.balance - amount;
}

// [SAFE] Requires signer
public fun admin_withdraw(admin: &signer, vault: &mut Vault, amount: u64) {
    assert!(signer::address_of(admin) == vault.admin, ERROR_UNAUTHORIZED);
    vault.balance = vault.balance - amount;
}
```

### 5. Integer Overflow
- Move aborts on integer overflow/underflow by default
- This is SAFER than Solidity but can cause DoS
- **Audit check:** Can overflow abort be used to DoS critical functions?

### 6. Global Storage Operations
```move
// move_to: store resource under account
// move_from: remove resource from account
// borrow_global: read resource
// borrow_global_mut: write resource

// [VULNERABLE] No existence check
public fun get_balance(account: address): u64 {
    let coin = borrow_global<Coin>(account); // ABORTS if not exists!
    coin.value
}

// [SAFE] Check existence first
public fun get_balance(account: address): u64 {
    if (!exists<Coin>(account)) return 0;
    borrow_global<Coin>(account).value
}
```

### 7. Aptos Framework Modules
Key framework modules to understand:
- `aptos_coin`: APT token management
- `coin`: generic coin standard (like ERC-20)
- `aptos_account`: account creation and management
- `object`: Aptos object model
- `fungible_asset`: new token standard (replacing coin)

## Aptos-Specific Audit Checklist

- [ ] Module upgrade policy verified (immutable for critical modules)
- [ ] Resource abilities are minimally permissive
- [ ] All privileged functions require `&signer`
- [ ] Signer address validated against expected admin/owner
- [ ] `exists<>` checks before `borrow_global`/`move_from`
- [ ] Integer overflow aborts won't cause critical DoS
- [ ] Event emissions for important state changes
- [ ] Coin vs FungibleAsset standard usage
- [ ] Object model: ownership and transfer logic correct
- [ ] No phantom type parameter abuse

## Common Vulnerabilities in Aptos/Move

| Vulnerability | Description |
|--------------|-------------|
| Missing signer check | Public function without authentication |
| Overly permissive abilities | copy + drop on valuable resources |
| Module upgrade abuse | Arbitrary upgrade policy on critical module |
| Resource existence | Abort on missing resource = DoS |
| Type confusion | Generic types instantiated incorrectly |
| Object ownership | Transfer logic allows unauthorized moves |
