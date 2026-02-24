---
id: SUI-PATTERNS
title: Sui Vulnerability Patterns
category: sui-scanner
difficulty: advanced
triggers:
  - sui vulnerability patterns
  - sui move security bugs
  - object ownership bypass
  - upgrade cap leak
related_skills:
  - sui-scanner/SKILL.md
  - sui-scanner/resources/object-security.md
  - sui-scanner/workflows/sui-audit.md
  - move-scanner/resources/sui-security.md
tags:
  - sui
  - move
  - patterns
  - security
last_updated: 2026-02-24
---

# Sui Vulnerability Patterns

> Sui's object-centric model creates a unique security surface. These patterns cover Sui-specific vulnerabilities involving object ownership, capabilities, transfer policies, and the shared object consensus model. For generic Move language issues (integer overflow, missing `acquires`, etc.), see [move-scanner](../../move-scanner/).

---

## 1. Shared Object Access Without Authorization (CRITICAL)

**Impact**: Shared objects can be referenced by any transaction. If a function accepts a shared object but doesn't validate the caller, anyone can modify protocol state.

### Vulnerable Code
```move
module exploit::vulnerable_pool {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    struct LiquidityPool has key {
        id: UID,
        reserve_a: u64,
        reserve_b: u64,
        fee_rate: u64,
        admin: address,
    }

    // BUG: Accepts shared pool but doesn't check caller
    public entry fun set_fee_rate(
        pool: &mut LiquidityPool,
        new_rate: u64,
        _ctx: &mut TxContext,
    ) {
        // Anyone can change the fee rate!
        pool.fee_rate = new_rate;
    }
}
```

### Secure Code
```move
module secure::pool {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};

    struct LiquidityPool has key {
        id: UID,
        reserve_a: u64,
        reserve_b: u64,
        fee_rate: u64,
        admin: address,
    }

    // FIX: Validate caller is admin
    public entry fun set_fee_rate(
        pool: &mut LiquidityPool,
        new_rate: u64,
        ctx: &mut TxContext,
    ) {
        assert!(tx_context::sender(ctx) == pool.admin, E_NOT_ADMIN);
        assert!(new_rate <= MAX_FEE_RATE, E_RATE_TOO_HIGH);
        pool.fee_rate = new_rate;
    }
}
```

**Detection**: Find all `public entry fun` that take `&mut SharedObject` without a `tx_context::sender` check.

---

## 2. UpgradeCap Leak (CRITICAL)

**Impact**: `UpgradeCap` controls module upgrades. If it's transferred to the wrong address, publicly shared, or not properly secured, an attacker can replace all contract logic.

### Vulnerable Code
```move
module exploit::my_protocol {
    use sui::package;
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct MY_PROTOCOL has drop {}

    fun init(otw: MY_PROTOCOL, ctx: &mut TxContext) {
        let publisher = package::claim(otw, ctx);
        transfer::public_transfer(publisher, tx_context::sender(ctx));

        // BUG: UpgradeCap not handled — Sui creates it automatically
        // If not captured and secured, it may be accessible to the deployer
        // without proper multisig/governance protection
    }
}
```

### Secure Code
```move
module secure::my_protocol {
    use sui::package;
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    struct MY_PROTOCOL has drop {}

    fun init(otw: MY_PROTOCOL, ctx: &mut TxContext) {
        let publisher = package::claim(otw, ctx);
        transfer::public_transfer(publisher, tx_context::sender(ctx));

        // FIX Option 1: Transfer UpgradeCap to a multisig/DAO address
        // (UpgradeCap is returned from publish transaction)

        // FIX Option 2: Make package immutable (no future upgrades)
        // package::make_immutable(upgrade_cap);

        // FIX Option 3: Set policy to restrict upgrade scope
        // package::only_additive_upgrades(&mut upgrade_cap);
        // package::only_dep_upgrades(&mut upgrade_cap);
    }
}
```

### Upgrade Policy Levels
| Policy | Risk | Description |
|---|---|---|
| `compatible` | High | Can change function implementations, add functions |
| `additive` | Medium | Can only add new modules/functions, not modify existing |
| `dep_only` | Low | Can only change dependencies |
| `immutable` | None | Package frozen forever (safest) |

---

## 3. Missing One-Time Witness (CRITICAL)

**Impact**: The One-Time Witness (OTW) pattern ensures `init()` runs exactly once at publish time. If a module creates important objects (treasury caps, admin caps) without OTW, they can potentially be recreated.

### Vulnerable Code
```move
module exploit::token {
    use sui::coin;
    use sui::tx_context::TxContext;

    struct TOKEN has drop {}  // Not a valid OTW — lowercase module name, or wrong type name

    // BUG: init without OTW parameter — can this be called again?
    fun init(ctx: &mut TxContext) {
        // If someone can call this function somehow, they create a new TreasuryCap
        let (treasury_cap, metadata) = coin::create_currency<TOKEN>(
            TOKEN {},  // BUG: This should ONLY be created once
            9,
            b"TOKEN",
            b"",
            b"",
            option::none(),
            ctx,
        );
    }
}
```

### Secure Code
```move
module secure::token {
    use sui::coin;
    use sui::tx_context::TxContext;
    use sui::transfer;

    // FIX: OTW struct name must match MODULE name (uppercase)
    // Must have ONLY `drop` ability
    struct TOKEN has drop {}

    // FIX: OTW as first parameter — Sui runtime guarantees single execution
    fun init(otw: TOKEN, ctx: &mut TxContext) {
        let (treasury_cap, metadata) = coin::create_currency<TOKEN>(
            otw,  // Consumed here — can never be created again
            9,
            b"TOKEN",
            b"",
            b"",
            option::none(),
            ctx,
        );
        // Transfer to deployer (or freeze, or share with governance)
        transfer::public_transfer(treasury_cap, tx_context::sender(ctx));
        transfer::public_freeze_object(metadata);
    }
}
```

**OTW Rules** (enforced by Sui runtime):
1. Struct name matches module name (uppercase)
2. Has only `drop` ability
3. Has no fields (or a single `bool` field)
4. Created only in `init()` function
5. Consumed in `init()` — cannot be stored

---

## 4. Dynamic Field Overflow (HIGH)

**Impact**: Dynamic fields (`dynamic_field`, `dynamic_object_field`) allow adding arbitrary key-value pairs to objects. Without bounds, an attacker can force unbounded growth, increasing gas costs for legitimate operations.

### Vulnerable Code
```move
module exploit::registry {
    use sui::dynamic_field;
    use sui::object::{Self, UID};

    struct Registry has key {
        id: UID,
        // No entry count — unbounded growth
    }

    // BUG: No limit on entries
    public entry fun register(
        registry: &mut Registry,
        name: vector<u8>,
        data: vector<u8>,
        _ctx: &mut TxContext,
    ) {
        // Attacker can call this millions of times with different names
        dynamic_field::add(&mut registry.id, name, data);
    }
}
```

### Secure Code
```move
module secure::registry {
    use sui::dynamic_field;
    use sui::object::{Self, UID};

    const MAX_ENTRIES: u64 = 10_000;

    struct Registry has key {
        id: UID,
        entry_count: u64,
    }

    // FIX: Bounded growth + fee
    public entry fun register(
        registry: &mut Registry,
        name: vector<u8>,
        data: vector<u8>,
        fee: Coin<SUI>,
        _ctx: &mut TxContext,
    ) {
        assert!(registry.entry_count < MAX_ENTRIES, E_REGISTRY_FULL);
        assert!(coin::value(&fee) >= REGISTRATION_FEE, E_LOW_FEE);

        // Register with validated bounds
        dynamic_field::add(&mut registry.id, name, data);
        registry.entry_count = registry.entry_count + 1;

        // Take fee
        transfer::public_transfer(fee, @protocol_treasury);
    }
}
```

---

## 5. Transfer Policy Bypass (HIGH)

**Impact**: Sui distinguishes `transfer::transfer` (module-internal) from `transfer::public_transfer` (requires `store` ability). Using the wrong one can bypass transfer restrictions like NFT royalties.

### Vulnerable Code
```move
module exploit::nft_marketplace {
    // BUG: Uses public_transfer for an NFT that should enforce royalties
    public entry fun buy_nft<T: key + store>(
        nft: T,
        buyer: address,
    ) {
        // public_transfer works because T has `store`
        // BUT: This bypasses any TransferPolicy enforcement
        transfer::public_transfer(nft, buyer);
    }
}
```

### Secure Code
```move
module secure::nft_marketplace {
    use sui::transfer_policy::{Self, TransferPolicy, TransferRequest};

    // FIX: Use Sui's TransferPolicy framework for custom transfer rules
    public fun buy_nft<T: key + store>(
        nft: T,
        policy: &TransferPolicy<T>,
        payment: Coin<SUI>,
        ctx: &mut TxContext,
    ): TransferRequest<T> {
        // Creates a transfer request that must satisfy all policy rules
        let request = transfer_policy::new_request(
            object::id(&nft),
            coin::value(&payment),
            object::id(policy),
        );

        // Transfer the NFT
        transfer::public_transfer(nft, tx_context::sender(ctx));

        // Return request — caller must resolve all policy rules before completing
        request
    }
}
```

---

## 6. Shared Object Contention DoS (HIGH)

**Impact**: Shared objects require consensus ordering. If a critical protocol object is shared, an attacker can spam transactions referencing it, creating a bottleneck that degrades performance for all users.

### Detection
```move
// Audit: Which objects are shared? Could they be owned instead?
public entry fun init(ctx: &mut TxContext) {
    let pool = LiquidityPool { id: object::new(ctx), ... };

    // Shared: Every swap transaction competes for ordering
    transfer::share_object(pool);  // ← Contention risk
}

// Better: Split into per-user owned objects where possible
// Use shared objects ONLY for truly global state
```

### Mitigation Strategies
- Split shared state into per-user owned objects (e.g., each user has their own `Position` object)
- Use shared objects only for global invariants (total supply, oracle prices)
- Batch operations that touch the same shared object
- Consider `Immutable` objects for read-only shared data

---

## 7. Object Wrapping/Unwrapping Bugs (MEDIUM)

**Impact**: Wrapped objects (stored inside another object) lose their individual identity. If wrapping/unwrapping logic has bugs, objects can become permanently inaccessible.

### Vulnerable Code
```move
module exploit::escrow {
    struct Escrow<T: key + store> has key {
        id: UID,
        item: T,        // Wrapped — T is inside Escrow
        seller: address,
    }

    // BUG: Anyone can unwrap and take the item
    public entry fun claim<T: key + store>(
        escrow: Escrow<T>,
        ctx: &mut TxContext,
    ) {
        let Escrow { id, item, seller: _ } = escrow;
        object::delete(id);
        // Item goes to caller, regardless of who should receive it
        transfer::public_transfer(item, tx_context::sender(ctx));
    }
}
```

### Secure Code
```move
module secure::escrow {
    struct Escrow<T: key + store> has key {
        id: UID,
        item: T,
        seller: address,
        buyer: address,
        price: u64,
    }

    // FIX: Only designated buyer can claim, must pay
    public entry fun claim<T: key + store>(
        escrow: Escrow<T>,
        payment: Coin<SUI>,
        ctx: &mut TxContext,
    ) {
        let sender = tx_context::sender(ctx);
        assert!(sender == escrow.buyer, E_NOT_BUYER);
        assert!(coin::value(&payment) >= escrow.price, E_LOW_PAYMENT);

        let Escrow { id, item, seller, buyer: _, price: _ } = escrow;
        object::delete(id);

        // Item to buyer, payment to seller
        transfer::public_transfer(item, sender);
        transfer::public_transfer(payment, seller);
    }
}
```

---

## 8. Clock Manipulation (MEDIUM)

**Impact**: Sui provides a shared `Clock` object for on-chain time. While validators set the time, protocols that use narrow time windows for critical operations may be vulnerable to timing manipulation or stale reads.

### Checklist
- [ ] Time-sensitive operations use reasonable windows (not seconds-precise)
- [ ] Clock object obtained from transaction context, not from user input
- [ ] No critical financial operations depend on sub-minute time precision
- [ ] Deadline checks use `>=` rather than `==` for expiration

---

## 9. Missing Coin Value Check (MEDIUM)

**Impact**: When functions accept `Coin<T>` parameters, failing to verify the coin's value allows zero-value or insufficient-value transactions.

### Vulnerable Code
```move
public entry fun stake(
    pool: &mut StakePool,
    coin: Coin<SUI>,
    ctx: &mut TxContext,
) {
    // BUG: No minimum stake check
    // User can stake 0 SUI and still get rewards shares
    let amount = coin::value(&coin);
    pool.shares = pool.shares + amount; // 0 + 0 = still gets position
    coin::put(&mut pool.balance, coin);
}
```

### Secure Code
```move
public entry fun stake(
    pool: &mut StakePool,
    coin: Coin<SUI>,
    ctx: &mut TxContext,
) {
    let amount = coin::value(&coin);
    assert!(amount >= MIN_STAKE, E_BELOW_MINIMUM);

    pool.shares = pool.shares + amount;
    coin::put(&mut pool.balance, coin);
}
```

---

## Sui Audit Checklist

### Critical Checks
- [ ] All shared object access validates `tx_context::sender` for privileged operations
- [ ] `UpgradeCap` secured (multisig, governance, or made immutable)
- [ ] One-Time Witness pattern used correctly for module initialization
- [ ] `Publisher` object secured and transfer restricted

### High Checks
- [ ] Dynamic fields have bounded growth (max limit + fee)
- [ ] Transfer policies enforced for types requiring custom transfer rules
- [ ] Shared object count minimized (prefer owned objects)
- [ ] Coin values validated (no zero-value attacks)
- [ ] Object ID generation is collision-free

### Medium Checks
- [ ] Wrapping/unwrapping logic handles all edge cases
- [ ] Clock usage doesn't depend on precise timing
- [ ] `public_transfer` vs `transfer` usage correct for type abilities
- [ ] All `key` objects handled (no orphaned objects consuming gas)

---

## Related Files

- [Sui Scanner Overview](../SKILL.md) — Architecture, Sui vs Aptos comparison
- [Object Security](object-security.md) — Deep dive on ownership model
- [Sui Audit Workflow](../workflows/sui-audit.md) — Step-by-step audit process
- [Move Patterns](../../move-scanner/resources/move-patterns.md) — Generic Move patterns
- [Sui Security](../../move-scanner/resources/sui-security.md) — Sui framework module security
