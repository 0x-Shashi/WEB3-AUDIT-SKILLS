---
id: APTOS-PATTERNS
title: Aptos Vulnerability Patterns
category: aptos-scanner
difficulty: advanced
triggers:
  - aptos vulnerability patterns
  - aptos security issues
  - move aptos bugs
  - capability leak
related_skills:
  - aptos-scanner/workflows/aptos-audit.md
  - move-scanner/resources/move-patterns.md
  - move-scanner/resources/aptos-security.md
tags:
  - aptos
  - move
  - patterns
  - security
last_updated: 2026-01-31
---

# Aptos Vulnerability Patterns

> Aptos uses Move language with its own framework modules, global storage model, and capability-based access control. These patterns cover Aptos-specific vulnerabilities beyond the generic Move patterns in [move-scanner](../../move-scanner/).

---

## 1. Capability Leak (CRITICAL)

**Impact**: `SignerCapability`, `MintCapability`, `BurnCapability`, or custom capability objects stored in publicly accessible resources allow unauthorized users to perform privileged operations.

### Vulnerable Code
```move
module exploit::vulnerable_vault {
    use aptos_framework::account;
    use aptos_framework::coin;

    struct VaultConfig has key {
        // BUG: SignerCapability stored in a struct with `key` ability
        // but no access restriction — anyone who owns a VaultConfig can use it
        signer_cap: account::SignerCapability,
        admin: address,
    }

    // BUG: Public function returns the capability
    public fun get_signer_cap(config: &VaultConfig): &account::SignerCapability {
        &config.signer_cap
    }

    // BUG: No signer check — anyone can call
    public entry fun withdraw(vault_addr: address, amount: u64) acquires VaultConfig {
        let config = borrow_global<VaultConfig>(vault_addr);
        let vault_signer = account::create_signer_with_capability(&config.signer_cap);
        // Attacker creates a signer for the vault and drains it
        coin::transfer<AptosCoin>(&vault_signer, @attacker, amount);
    }
}
```

### Secure Code
```move
module secure::vault {
    use aptos_framework::account;
    use aptos_framework::coin;

    struct VaultConfig has key {
        signer_cap: account::SignerCapability,
        admin: address,
    }

    // FIX: Never expose capability publicly
    // FIX: Require admin signer for privileged operations
    public entry fun withdraw(
        admin: &signer,
        vault_addr: address,
        amount: u64,
        recipient: address,
    ) acquires VaultConfig {
        let config = borrow_global<VaultConfig>(vault_addr);

        // FIX: Verify caller is admin
        assert!(signer::address_of(admin) == config.admin, E_NOT_ADMIN);

        let vault_signer = account::create_signer_with_capability(&config.signer_cap);
        coin::transfer<AptosCoin>(&vault_signer, recipient, amount);
    }
}
```

---

## 2. Missing Signer Validation (CRITICAL)

**Impact**: Public entry functions that modify global state without checking the signer allow anyone to alter protocol state.

### Vulnerable Code
```move
module exploit::staking {
    struct StakePool has key {
        total_staked: u64,
        reward_rate: u64,
    }

    // BUG: Public entry function without signer parameter
    // Anyone can change the reward rate
    public entry fun set_reward_rate(pool_addr: address, new_rate: u64) acquires StakePool {
        let pool = borrow_global_mut<StakePool>(pool_addr);
        pool.reward_rate = new_rate;
    }
}
```

### Secure Code
```move
module secure::staking {
    struct StakePool has key {
        total_staked: u64,
        reward_rate: u64,
        admin: address,
    }

    // FIX: Require admin signer
    public entry fun set_reward_rate(
        admin: &signer,
        pool_addr: address,
        new_rate: u64,
    ) acquires StakePool {
        let pool = borrow_global_mut<StakePool>(pool_addr);
        assert!(signer::address_of(admin) == pool.admin, E_NOT_ADMIN);
        assert!(new_rate <= MAX_REWARD_RATE, E_RATE_TOO_HIGH);
        pool.reward_rate = new_rate;
    }
}
```

**Detection**: Search for `public entry fun` without `&signer` as first parameter, or with `&signer` but no `assert!` checking the address.

---

## 3. Fake Coin Registration (CRITICAL)

**Impact**: Aptos coin module uses phantom types (`CoinType`) for type safety. If a protocol accepts any `CoinType` without validating the coin's metadata or address, an attacker can register a fake coin with the same name.

### Vulnerable Code
```move
module exploit::dex {
    // BUG: Accepts any CoinType — attacker deploys FakeUSDC at their own address
    public entry fun swap<CoinIn, CoinOut>(
        user: &signer,
        amount_in: u64,
    ) acquires Pool {
        let coin_in = coin::withdraw<CoinIn>(user, amount_in);
        // No validation that CoinIn is the REAL USDC, not a fake one
        let pool = borrow_global_mut<Pool<CoinIn, CoinOut>>(@dex);
        // ...
    }
}
```

### Secure Code
```move
module secure::dex {
    // FIX: Verify coin type originates from expected address
    public entry fun swap<CoinIn, CoinOut>(
        user: &signer,
        amount_in: u64,
    ) acquires Pool, CoinRegistry {
        // FIX: Check coin is registered in our whitelist
        let registry = borrow_global<CoinRegistry>(@dex);
        assert!(
            type_info::account_address(&type_info::type_of<CoinIn>()) == registry.expected_coin_address,
            E_INVALID_COIN
        );

        let coin_in = coin::withdraw<CoinIn>(user, amount_in);
        // Safe: CoinIn verified to be from expected source
    }
}
```

---

## 4. Unprotected Module Upgrade (HIGH)

**Impact**: Aptos modules can be upgraded unless the upgrade policy is set to `immutable`. If `compatible` or `arbitrary` policy is used, the deployer can replace contract logic.

### Detection
```move
// Check the upgrade policy in Move.toml or initialization
// Policies:
// - compatible: Can upgrade with compatible changes (most common, risky)
// - immutable: Cannot upgrade (safest for users)
// - arbitrary: Can replace with any code (most dangerous)

// In code, check for:
use aptos_framework::code;

// Safe: Make module permanently immutable after deployment
public entry fun freeze_module(admin: &signer) {
    code::publish_package_txn(
        admin,
        metadata,
        code_vec,
        // policy: IMMUTABLE
    );
}
```

### Checklist
- [ ] Upgrade policy documented and appropriate for protocol risk level
- [ ] If upgradeable: timelock or multisig protects upgrade authority
- [ ] `compatible` policy verified: new code doesn't change struct layouts
- [ ] Users informed if contract is upgradeable

---

## 5. Resource Extraction via move_from (HIGH)

**Impact**: `move_from<T>(addr)` extracts a resource from global storage. If a function exposes this without proper authorization, an attacker can steal resources from any address.

### Vulnerable Code
```move
// BUG: Anyone can extract resource from any address
public fun claim_reward(addr: address): Reward acquires Reward {
    move_from<Reward>(addr) // No signer check!
}
```

### Secure Code
```move
// FIX: Only the resource owner can extract their own resource
public fun claim_reward(owner: &signer): Reward acquires Reward {
    move_from<Reward>(signer::address_of(owner))
}
```

---

## 6. Unbounded Table/SmartTable Growth (HIGH)

**Impact**: Aptos `Table` and `SmartTable` types can grow unboundedly. Operations that iterate or scan tables scale with size, eventually exceeding the gas limit.

### Detection
```move
// Look for Table operations without size bounds
use aptos_std::table::{Table, Self};

struct Registry has key {
    users: Table<address, UserData>, // Can grow indefinitely
}

// BUG: No limit on entries — gas DoS when Table is large
public entry fun register(user: &signer) acquires Registry {
    let registry = borrow_global_mut<Registry>(@protocol);
    table::add(&mut registry.users, signer::address_of(user), UserData { ... });
    // No max users check → unbounded growth
}
```

### Mitigation
```move
// FIX: Enforce maximum entries
const MAX_USERS: u64 = 10_000;

public entry fun register(user: &signer) acquires Registry {
    let registry = borrow_global_mut<Registry>(@protocol);
    assert!(registry.user_count < MAX_USERS, E_MAX_USERS);
    table::add(&mut registry.users, signer::address_of(user), UserData { ... });
    registry.user_count = registry.user_count + 1;
}
```

---

## 7. Integer Overflow (MEDIUM)

**Impact**: Move arithmetic aborts on overflow by default (unlike Rust release mode). This prevents silent corruption but enables DoS if large values cause panics.

### Detection
```move
// Move aborts on overflow — this is SAFE from corruption
// BUT: It means an attacker can trigger an abort by providing large values
let result = a + b; // Aborts if overflow — DoS vector

// Use checked math when you need to handle gracefully:
if (a > MAX_U64 - b) {
    // Handle overflow gracefully instead of aborting
    return E_OVERFLOW
};
let result = a + b;
```

---

## 8. Event Ordering & Missing Events (MEDIUM)

**Impact**: Off-chain indexers rely on event ordering. Missing or misordered events cause incorrect protocol state in frontends, dashboards, and bots.

### Checklist
- [ ] Every state-changing function emits an event
- [ ] Events emitted AFTER state change (reflect final state)
- [ ] Event structs include all relevant fields (who, what, amount, timestamp)
- [ ] Event handles created in module initialization

---

## 9. Friend Module Abuse (MEDIUM)

**Impact**: `friend` declarations allow other modules to call `public(friend)` functions. If a friend module is compromised or has bugs, it inherits the vulnerable module's privileges.

### Detection
```move
module protocol::vault {
    // Audit: Who are the friends? Are they all trusted?
    friend protocol::router;
    friend protocol::governance;
    friend protocol::rewards;  // Is this necessary?

    // This function is callable by all friend modules
    public(friend) fun internal_transfer(from: address, to: address, amount: u64) {
        // If any friend module has a bug, this can be called unexpectedly
    }
}
```

### Checklist
- [ ] Friend list is minimal (only modules that NEED access)
- [ ] All friend modules are in the same package (audited together)
- [ ] `public(friend)` functions still validate inputs
- [ ] No circular friend dependencies

---

## Aptos Audit Checklist

### Critical Checks
- [ ] All capabilities (SignerCap, MintCap, etc.) stored securely, never exposed publicly
- [ ] All `public entry fun` functions validate signer authorization
- [ ] CoinType parameters validated against expected coin addresses
- [ ] No `move_from` without signer ownership check

### High Checks
- [ ] Module upgrade policy documented and appropriate
- [ ] Table/SmartTable growth bounded with max limits
- [ ] Resource access patterns prevent unauthorized extraction
- [ ] `acquires` annotation present on all functions accessing global storage

### Medium Checks
- [ ] Integer operations handle overflow gracefully (not just abort)
- [ ] All state changes emit events
- [ ] Friend module list is minimal and justified
- [ ] View functions don't trigger expensive computation

---

## Related Files

- [Aptos Audit Workflow](../workflows/aptos-audit.md) — Step-by-step Aptos audit process
- [Move Patterns](../../move-scanner/resources/move-patterns.md) — Generic Move vulnerability patterns
- [Aptos Security](../../move-scanner/resources/aptos-security.md) — Aptos framework module security
- [ ] Module upgrade policy set appropriately (immutable if possible)
- [ ] Coin operations use aptos_framework::coin correctly
- [ ] Table/SmartTable growth bounded
- [ ] Resource initialization checked before access
