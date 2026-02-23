---
id: SUI-OBJECT-SECURITY
title: Sui Object Security Model
category: sui-scanner
difficulty: advanced
triggers:
  - sui object security
  - sui ownership model
  - shared object security
  - sui dynamic fields
related_skills:
  - sui-scanner/resources/sui-patterns.md
  - sui-scanner/SKILL.md
tags:
  - sui
  - object-model
  - ownership
  - security
last_updated: 2026-01-31
---

# Sui Object Security

> Sui's object model is the foundation of its security architecture. Every piece of state is an object with an owner, and ownership determines who can access, modify, or transfer it. Understanding this model is essential for auditing any Sui protocol.

---

## Object Ownership Types

### 1. Owned Objects
**Definition**: Objects with a single owner (address). Only the owner can use them as transaction inputs.

```move
struct UserProfile has key, store {
    id: UID,
    name: vector<u8>,
    score: u64,
}

// Create an owned object — only `recipient` can use it
public entry fun create_profile(
    name: vector<u8>,
    ctx: &mut TxContext,
) {
    let profile = UserProfile {
        id: object::new(ctx),
        name,
        score: 0,
    };
    // transfer::transfer sends to a specific owner
    transfer::transfer(profile, tx_context::sender(ctx));
}
```

| Property | Detail |
|---|---|
| Consensus | Not required (fast parallel execution) |
| Access | Only owner can pass as `&T`, `&mut T`, or `T` in transactions |
| Security Benefit | Strongest isolation — no other user can touch it |
| Risk | Ownership transfer to wrong address is irreversible |
| Use For | User wallets, personal NFTs, individual positions |

---

### 2. Shared Objects
**Definition**: Objects accessible by any transaction. Require consensus ordering.

```move
struct LiquidityPool has key {
    id: UID,
    reserve_a: Balance<CoinA>,
    reserve_b: Balance<CoinB>,
    admin: address,
}

// Share makes the object globally accessible
public entry fun create_pool(ctx: &mut TxContext) {
    let pool = LiquidityPool {
        id: object::new(ctx),
        reserve_a: balance::zero(),
        reserve_b: balance::zero(),
        admin: tx_context::sender(ctx),
    };
    // CRITICAL: Once shared, the pool is accessible by ANY transaction
    transfer::share_object(pool);
}

// MUST validate caller for privileged operations on shared objects
public entry fun update_admin(
    pool: &mut LiquidityPool,
    new_admin: address,
    ctx: &mut TxContext,
) {
    assert!(tx_context::sender(ctx) == pool.admin, E_NOT_ADMIN);
    pool.admin = new_admin;
}
```

| Property | Detail |
|---|---|
| Consensus | Required (ordered by validators) |
| Access | Any user can reference in transactions |
| Security Risk | **Must validate caller explicitly** — no automatic access control |
| Performance Risk | Contention bottleneck if many transactions touch same object |
| Use For | Global state (pools, registries, oracles) |

### Shared Object Security Rules
1. **Always check `tx_context::sender`** for admin/privileged operations
2. **Minimize shared objects** — prefer owned objects where possible
3. **Expect concurrent access** — design for parallel modification
4. **Never store user-specific data** in a shared object if an owned object works

---

### 3. Immutable Objects
**Definition**: Objects frozen with `transfer::freeze_object`. Cannot be modified or deleted ever again.

```move
struct Config has key, store {
    id: UID,
    max_supply: u64,
    decimals: u8,
}

public entry fun publish_config(ctx: &mut TxContext) {
    let config = Config {
        id: object::new(ctx),
        max_supply: 1_000_000_000,
        decimals: 9,
    };
    // After freeze: config is permanently read-only, accessible by anyone
    transfer::freeze_object(config);
}

// Can only be passed as &Config (immutable reference) — never &mut Config
public fun get_max_supply(config: &Config): u64 {
    config.max_supply
}
```

| Property | Detail |
|---|---|
| Consensus | Not required (read-only, parallel safe) |
| Access | Anyone can read via `&T` |
| Modification | Impossible — frozen permanently |
| Use For | Published packages, coin metadata, protocol constants |

---

### 4. Wrapped Objects
**Definition**: Objects stored inside another object. They lose their independent identity and are only accessible through the parent.

```move
struct Vault has key {
    id: UID,
    // The Coin is "wrapped" inside Vault
    locked_funds: Coin<SUI>,
    unlock_time: u64,
    owner: address,
}

// Wrapping: Coin<SUI> goes inside Vault
public entry fun lock_funds(
    coin: Coin<SUI>,
    unlock_time: u64,
    ctx: &mut TxContext,
) {
    let vault = Vault {
        id: object::new(ctx),
        locked_funds: coin,  // Wrapped — coin no longer independently accessible
        unlock_time,
        owner: tx_context::sender(ctx),
    };
    transfer::transfer(vault, tx_context::sender(ctx));
}

// Unwrapping: Coin<SUI> extracted from Vault
public entry fun unlock(
    vault: Vault,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(tx_context::sender(ctx) == vault.owner, E_NOT_OWNER);
    assert!(clock::timestamp_ms(clock) >= vault.unlock_time, E_TOO_EARLY);

    let Vault { id, locked_funds, unlock_time: _, owner } = vault;
    object::delete(id);
    transfer::public_transfer(locked_funds, owner);  // Unwrapped
}
```

| Property | Detail |
|---|---|
| Access | Only through parent object's module |
| Identity | Loses independent ID while wrapped |
| Risk | Wrapping bugs can make objects permanently inaccessible |
| Risk | Unwrapping without authorization leaks the wrapped object |

---

## Dynamic Fields vs Normal Fields

### Normal Fields
- Fixed at struct definition time
- All stored in one object (gas-efficient for small state)
- Type-checked at compile time

### Dynamic Fields
- Added/removed at runtime
- Each field is a separate object on-chain
- Two types: `dynamic_field` (stores value) and `dynamic_object_field` (stores object with its own ID)

```move
use sui::dynamic_field as df;
use sui::dynamic_object_field as dof;

// Adding a dynamic field
df::add(&mut parent.id, b"config_key", ConfigValue { ... });

// Adding a dynamic object field (object retains its ID)
dof::add(&mut parent.id, b"child_key", ChildObject { id: object::new(ctx), ... });

// Reading
let config: &ConfigValue = df::borrow(&parent.id, b"config_key");

// Removing
let config: ConfigValue = df::remove(&mut parent.id, b"config_key");
```

### Dynamic Field Security Risks

| Risk | Description | Mitigation |
|---|---|---|
| Unbounded growth | No compile-time limit on entries | Enforce max count in code |
| Key collision | Different fields using same key | Use typed keys (structs, not raw strings) |
| Orphaned fields | Parent deleted without removing dynamic fields | Clean up all dynamic fields before `object::delete` |
| Gas DoS | Large number of fields makes operations expensive | Paginate, limit, charge fees |

---

## Object Ability Matrix

| Ability | Meaning | Security Implication |
|---|---|---|
| `key` | Can be stored as a top-level object (has `id: UID`) | Required for all Sui objects |
| `store` | Can be stored inside another object or transferred with `public_transfer` | Types with `store` can be freely transferred — may bypass custom transfer logic |
| `copy` | Can be duplicated | Dangerous for value types (tokens) — minting from thin air |
| `drop` | Can be silently discarded | Resource leaks if used incorrectly — safe for markers/witnesses |

### Common Patterns
```move
// Token/Coin: key + store (NO copy — prevents duplication)
struct MyCoin has key, store { id: UID, value: u64 }

// Capability: key only (NO store — prevents unauthorized transfer)
struct AdminCap has key { id: UID }

// Witness: drop only (consumed during init, cannot be stored)
struct TOKEN has drop {}

// Read-only config: key + store (then frozen)
struct Config has key, store { id: UID, params: Params }
```

---

## Security Audit Matrix

| Check | Owned | Shared | Immutable | Wrapped |
|---|---|---|---|---|
| Owner validated? | Auto (by Sui) | **Manual required** | N/A | Via parent |
| Transfer restricted? | Check abilities | N/A (not transferable) | N/A | Only via unwrap |
| Concurrent access safe? | N/A (single owner) | **Must verify** | Safe (read-only) | Via parent |
| Deletion safe? | Check unwrap logic | Rarely deleted | Cannot delete | Must unwrap children first |
| Dynamic fields bounded? | Check | **Critical** | N/A | Check |

---

## Related Files

- [Sui Patterns](sui-patterns.md) — Vulnerability patterns with code examples
- [Sui Scanner Overview](../SKILL.md) — Architecture overview
- [Sui Audit Workflow](../workflows/sui-audit.md) — Step-by-step process
