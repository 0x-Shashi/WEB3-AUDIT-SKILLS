---
id: MOVE-SUI-SEC
title: Sui Security Considerations
parent: move-scanner
type: resource
last_updated: 2025-01-31
---

# Sui Security Considerations

Sui-specific security concerns, patterns, and audit guidance. Sui uses Move with an **object model** (fundamentally different from Aptos's global storage model), enabling parallel execution for owned objects.

---

## Object Model (Different from Aptos!)

Sui replaces Aptos's global storage with an object-centric model:

| Object Type | Ownership | Consensus | Parallel Execution | Use Case |
|-------------|-----------|-----------|-------------------|----------|
| **Owned** | Single address or object | Not needed | YES (fast) | User wallets, personal NFTs |
| **Shared** | Accessible by anyone | Required | NO (slower) | DEX pools, lending markets |
| **Immutable** | Nobody (frozen) | Not needed | YES (read-only) | Constants, published packages |
| **Wrapped** | Contained inside another object | Follows parent | Follows parent | Nested data structures |

### Security Implications of Object Types

| Risk | Object Type | Description |
|------|-------------|-------------|
| **Contention DoS** | Shared | Multiple transactions competing for same shared object can cause delays |
| **Unauthorized access** | Shared | Any transaction can reference a shared object — access control is in code |
| **Object loss** | Owned | If transferred to wrong address, object may be unrecoverable |
| **Extraction** | Wrapped | Wrapped objects can only be accessed through parent — verify unwrapping rules |

---

## Sui-Specific Vulnerabilities

### 1. Shared Object Contention (DoS)

Shared objects require consensus (Narwhal/Bullshark), which is slower than owned-object transactions. If a protocol uses shared objects for high-frequency operations, it creates a bottleneck.

```move
// RISKY: Global shared counter — every user transaction touches this
struct GlobalState has key {
    id: UID,
    total_deposits: u64,
    total_users: u64,
}

// BETTER: Per-user owned objects + periodic aggregation
struct UserDeposit has key {
    id: UID,
    owner: address,
    amount: u64,
}
```

**Design Rule:** Minimize shared object access. Use owned objects for user-specific state and shared objects only for truly global state (pools, order books).

### 2. Missing `tx_context::sender()` Validation

```move
// VULNERABLE: No access control — anyone can call
public entry fun admin_withdraw(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
    let coins = balance::split(&mut pool.balance, amount);
    transfer::public_transfer(coin::from_balance(coins, ctx), tx_context::sender(ctx));
    // Anyone calling this gets the tokens!
}

// SAFE: Admin check
public entry fun admin_withdraw(admin_cap: &AdminCap, pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
    // AdminCap is an owned object — only the holder can pass it
    let coins = balance::split(&mut pool.balance, amount);
    transfer::public_transfer(coin::from_balance(coins, ctx), tx_context::sender(ctx));
}
```

### 3. UpgradeCap Not Secured

```move
// The UpgradeCap controls who can upgrade the package
fun init(otw: MY_MODULE, ctx: &mut TxContext) {
    let upgrade_cap = package::claim(otw, ctx);
    
    // RISKY: public_transfer allows the cap to be further transferred
    transfer::public_transfer(upgrade_cap, tx_context::sender(ctx));
    
    // BETTER for immutable package: burn the cap
    package::burn_publisher(publisher);
    
    // OR: restrict transfer with transfer::transfer (non-public, wrapped in module)
    transfer::transfer(upgrade_cap, @admin_address);
}
```

### 4. One-Time Witness Misuse

Sui's one-time witness (OTW) pattern ensures an init function runs exactly once:

```move
// OTW must be:
// - Named after the module (in UPPER_CASE)
// - Has only `drop` ability
// - No fields
struct MY_MODULE has drop {}

fun init(otw: MY_MODULE, ctx: &mut TxContext) {
    // This function is called exactly once when the package is published
    // OTW is consumed (dropped) — cannot be created again
    
    assert!(sui::types::is_one_time_witness(&otw), E_NOT_OTW);
    
    // Initialize singleton resources here
    let treasury_cap = coin::create_currency(otw, 8, b"MTK", b"My Token", b"", option::none(), ctx);
}
```

**Audit Check:** Verify that `init` with OTW is used for all singleton initialization. If not, anyone could potentially call a public init function multiple times.

### 5. Dynamic Field Overflow

```move
// VULNERABLE: Unbounded dynamic fields
public fun register(obj: &mut Registry, name: String, data: Data) {
    dynamic_field::add(&mut obj.id, name, data);
    // No limit on how many fields can be added
    // Could become expensive to manage or iterate
}

// SAFE: Bounded
public fun register(obj: &mut Registry, name: String, data: Data) {
    assert!(obj.count < MAX_ENTRIES, E_OVERFLOW);
    dynamic_field::add(&mut obj.id, name, data);
    obj.count = obj.count + 1;
}
```

### 6. Object Wrapping/Unwrapping Logic Errors

```move
// Wrapping hides an object inside another — removing it from global state
// It can only be accessed through the parent

struct Vault has key {
    id: UID,
    // Wrapped coin — not directly accessible
    locked_coins: Coin<SUI>,
}

// VULNERABILITY: Anyone can unwrap
public fun extract(vault: Vault): Coin<SUI> {
    let Vault { id, locked_coins } = vault;
    object::delete(id);
    locked_coins // Anyone calling this gets the coins
}

// SAFE: Owner check
public entry fun extract(vault: Vault, ctx: &mut TxContext) {
    assert!(/* verify ownership */, E_NOT_OWNER);
    let Vault { id, locked_coins } = vault;
    object::delete(id);
    transfer::public_transfer(locked_coins, tx_context::sender(ctx));
}
```

---

## Sui Coin & Token Security

| Operation | Module | Security Note |
|-----------|--------|---------------|
| Create currency | `coin::create_currency` | Requires OTW — singleton guarantee |
| Mint | `coin::mint` | Requires `&mut TreasuryCap` — verify who holds it |
| Burn | `coin::burn` | Requires `&mut TreasuryCap` |
| Transfer | `transfer::public_transfer` | For types with `store` ability |
| Transfer (restricted) | `transfer::transfer` | Only within defining module — more controlled |

### TreasuryCap Security

```move
// TreasuryCap controls minting — MUST be secured
fun init(otw: MY_TOKEN, ctx: &mut TxContext) {
    let (treasury_cap, metadata) = coin::create_currency(otw, 8, ...);
    
    // Option 1: Transfer to admin (controlled)
    transfer::transfer(treasury_cap, @admin);
    
    // Option 2: Share for governance-controlled minting
    transfer::share_object(treasury_cap); // CAREFUL: needs access control in mint function
    
    // Option 3: Freeze (no more minting ever)
    transfer::freeze_object(treasury_cap);
}
```

---

## Sui Audit Checklist

- [ ] Object ownership model correct for each data structure
- [ ] Shared objects used only where truly necessary (not for user-specific data)
- [ ] `tx_context::sender()` checked for access control in shared object operations
- [ ] UpgradeCap properly secured (or burned for immutable packages)
- [ ] One-Time Witness used for singleton initialization
- [ ] Dynamic fields have growth bounds
- [ ] Object wrapping/unwrapping has proper authorization
- [ ] TreasuryCap properly secured (not publicly shared without access control)
- [ ] `transfer::public_transfer` vs `transfer::transfer` used appropriately
- [ ] Events emitted for all significant state changes
- [ ] Shared object contention analyzed for DoS risk
