# Sui Move Vulnerability Patterns

Comprehensive database of Sui-specific vulnerability patterns with detection strategies.

---

## Object Model Patterns

### Pattern OO-01: Improper Shared Object Access

**Risk Level:** Critical

**Description:** Shared objects in Sui are globally accessible. Without proper access control, any transaction can modify them.

**Detection Pattern:**
```
1. Find transfer::share_object() calls
2. Check public functions that take &mut SharedObject
3. Verify access control (capability, sender check)
4. Flag if anyone can mutate
```

**Vulnerable:**
```move
module example::pool {
    use sui::transfer;
    use sui::object::{Self, UID};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::tx_context::TxContext;

    struct Pool has key {
        id: UID,
        balance: Balance<SUI>
    }

    public entry fun create_pool(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            balance: balance::zero()
        };
        transfer::share_object(pool);  // Shared!
    }

    // VULNERABLE: No access control
    public entry fun drain(pool: &mut Pool, ctx: &mut TxContext) {
        let amount = balance::value(&pool.balance);
        let coin = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coin, tx_context::sender(ctx));
    }
}
```

**Secure:**
```move
module example::pool {
    use sui::transfer;
    use sui::object::{Self, UID, ID};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::tx_context::{Self, TxContext};

    struct Pool has key {
        id: UID,
        balance: Balance<SUI>
    }

    struct AdminCap has key, store {
        id: UID,
        pool_id: ID
    }

    public entry fun create_pool(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            balance: balance::zero()
        };
        let cap = AdminCap {
            id: object::new(ctx),
            pool_id: object::id(&pool)
        };
        transfer::share_object(pool);
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    // SECURE: Requires AdminCap linked to this pool
    public entry fun drain(
        pool: &mut Pool,
        cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        assert!(cap.pool_id == object::id(pool), 0);
        let amount = balance::value(&pool.balance);
        let coin = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coin, tx_context::sender(ctx));
    }
}
```

---

### Pattern OO-02: Object Ownership Confusion

**Risk Level:** High

**Description:** Mixing up owned and shared object semantics can lead to access control bypasses or deadlocks.

**Detection Pattern:**
```
1. Find objects used both as owned and shared
2. Check if ownership is verified before operations
3. Flag mixed usage patterns
```

**Vulnerable:**
```move
// VULNERABLE: Treating shared object like owned
public entry fun process(
    obj: &mut SharedObject,
    ctx: &mut TxContext
) {
    // Assuming only owner can call - WRONG
    // Anyone can pass a shared object reference
    obj.data = new_data();
}
```

**Secure:**
```move
// SECURE: Explicit ownership verification
public entry fun process(
    obj: &mut SharedObject,
    owner_cap: &OwnerCap,
    ctx: &mut TxContext
) {
    assert!(owner_cap.obj_id == object::id(obj), ENotOwner);
    obj.data = new_data();
}
```

---

### Pattern OO-04: Wrapped Object Extraction

**Risk Level:** Critical

**Description:** Objects wrapped inside other objects can be extracted if not properly protected.

**Detection Pattern:**
```
1. Find Option<Object> or vector<Object> in structs
2. Check extraction functions
3. Verify authorization before extraction
```

**Vulnerable:**
```move
struct Wrapper has key {
    id: UID,
    inner: Option<ValuedNFT>
}

// VULNERABLE: Anyone can extract wrapped object
public entry fun unwrap(
    wrapper: &mut Wrapper,
    ctx: &mut TxContext
) {
    let nft = option::extract(&mut wrapper.inner);
    transfer::public_transfer(nft, tx_context::sender(ctx));
}
```

**Secure:**
```move
struct Wrapper has key {
    id: UID,
    inner: Option<ValuedNFT>,
    owner: address
}

// SECURE: Only owner can extract
public entry fun unwrap(
    wrapper: &mut Wrapper,
    ctx: &mut TxContext
) {
    assert!(wrapper.owner == tx_context::sender(ctx), ENotOwner);
    let nft = option::extract(&mut wrapper.inner);
    transfer::public_transfer(nft, tx_context::sender(ctx));
}
```

---

## Capability Patterns

### Pattern CP-01: Missing Capability Verification

**Risk Level:** Critical

**Description:** Capabilities must be verified to belong to the resource being accessed.

**Detection Pattern:**
```
1. Find all *Cap structs
2. Check if they contain resource ID
3. Verify ID comparison in functions
4. Flag missing verification
```

**Vulnerable:**
```move
struct Pool has key { id: UID, balance: Balance<SUI> }
struct AdminCap has key { id: UID }  // No pool reference!

public entry fun admin_action(
    pool: &mut Pool,
    _cap: &AdminCap,  // Accepts ANY AdminCap
    ctx: &mut TxContext
) {
    // Attacker with any AdminCap can access any pool
}
```

**Secure:**
```move
struct Pool has key { id: UID, balance: Balance<SUI> }
struct AdminCap has key { 
    id: UID,
    pool_id: ID  // Links to specific pool
}

public entry fun admin_action(
    pool: &mut Pool,
    cap: &AdminCap,
    ctx: &mut TxContext
) {
    assert!(cap.pool_id == object::id(pool), EWrongCap);
    // Now cap is verified for this specific pool
}
```

---

### Pattern CP-02: Capability Leakage

**Risk Level:** Critical

**Description:** Capabilities with `store` ability can be transferred, potentially to malicious actors.

**Detection Pattern:**
```
1. Find capability structs with store ability
2. Check if transfer should be restricted
3. Flag if store not needed
```

**Vulnerable:**
```move
// VULNERABLE: store allows unrestricted transfer
struct AdminCap has key, store {
    id: UID,
    pool_id: ID
}

// Attacker can buy/trade for AdminCap
```

**Secure:**
```move
// SECURE: No store, only controlled transfer
struct AdminCap has key {
    id: UID,
    pool_id: ID
}

// Must use module's transfer function
public entry fun transfer_admin(
    cap: AdminCap,
    new_admin: address,
    multisig_approval: &MultisigApproval,
    ctx: &mut TxContext
) {
    verify_multisig(multisig_approval);
    transfer::transfer(cap, new_admin);
}
```

---

### Pattern CP-03: Hot Potato Bypass

**Risk Level:** High

**Description:** Hot potato pattern uses objects without drop/store to force consumption. If bypassed, operations can be abandoned mid-way.

**Detection Pattern:**
```
1. Find structs with only key ability (no drop, no store)
2. Verify creation and consumption are paired
3. Check all code paths consume the hot potato
```

**Vulnerable:**
```move
// Hot potato for flash loan
struct FlashLoan { amount: u64, pool_id: ID }

public fun borrow(pool: &mut Pool, amount: u64): (Coin<SUI>, FlashLoan) {
    let coin = coin::take(&mut pool.balance, amount, ctx);
    let receipt = FlashLoan { amount, pool_id: object::id(pool) };
    (coin, receipt)
}

// VULNERABLE: No enforcement that repay is called
// Attacker can just not call repay (Move will error, but...)
```

**Secure:**
```move
// Hot potato with no drop/store
struct FlashLoan { amount: u64, pool_id: ID }
// Note: No `drop` ability means MUST be consumed

public fun borrow(pool: &mut Pool, amount: u64, ctx: &mut TxContext): (Coin<SUI>, FlashLoan) {
    // ... same
}

// This MUST be called or transaction fails
public fun repay(pool: &mut Pool, coin: Coin<SUI>, loan: FlashLoan) {
    let FlashLoan { amount, pool_id } = loan;  // Consumes hot potato
    assert!(coin::value(&coin) >= amount, EInsufficientRepayment);
    balance::join(&mut pool.balance, coin::into_balance(coin));
}
```

---

## Dynamic Field Patterns

### Pattern DF-01: Dynamic Field Type Confusion

**Risk Level:** Critical

**Description:** Using raw keys for dynamic fields allows type confusion attacks.

**Detection Pattern:**
```
1. Find dynamic_field::add/borrow with string/vector keys
2. Check if custom key types used
3. Flag raw key usage
```

**Vulnerable:**
```move
// VULNERABLE: String key allows collision
public fun add_config(parent: &mut UID, config: Config) {
    dynamic_field::add(parent, b"config", config);
}

public fun add_malicious(parent: &mut UID, data: MaliciousData) {
    // Attacker can add with same key, different type!
    dynamic_field::add(parent, b"config", data);
}
```

**Secure:**
```move
// SECURE: Type-safe key
struct ConfigKey has copy, drop, store {}

public fun add_config(parent: &mut UID, config: Config) {
    dynamic_field::add(parent, ConfigKey {}, config);
}

// Cannot add MaliciousData with ConfigKey - type mismatch
```

---

### Pattern DF-02: Missing Existence Check

**Risk Level:** High

**Description:** Accessing dynamic fields that don't exist causes runtime errors.

**Detection Pattern:**
```
1. Find dynamic_field::borrow/borrow_mut calls
2. Check if exists() called first
3. Flag unguarded access
```

**Vulnerable:**
```move
// VULNERABLE: Crashes if field doesn't exist
public fun get_config(parent: &UID): &Config {
    dynamic_field::borrow<ConfigKey, Config>(parent, ConfigKey {})
}
```

**Secure:**
```move
// SECURE: Check existence first
public fun get_config(parent: &UID): Option<&Config> {
    if (dynamic_field::exists_<ConfigKey>(parent, ConfigKey {})) {
        option::some(dynamic_field::borrow<ConfigKey, Config>(parent, ConfigKey {}))
    } else {
        option::none()
    }
}
```

---

### Pattern DF-05: Unauthorized Dynamic Field Access

**Risk Level:** Critical

**Description:** If UID is exposed, anyone can add/modify dynamic fields.

**Detection Pattern:**
```
1. Find functions returning &mut UID
2. Check if UID exposed to public
3. Flag exposed UIDs
```

**Vulnerable:**
```move
struct MyObject has key {
    id: UID,
    data: u64
}

// VULNERABLE: Exposes UID for modification
public fun get_uid(obj: &mut MyObject): &mut UID {
    &mut obj.id
}

// Attacker can add arbitrary dynamic fields!
```

**Secure:**
```move
// SECURE: Never expose UID directly
// Only expose controlled field operations
public fun set_config(obj: &mut MyObject, config: Config, cap: &AdminCap) {
    verify_cap(cap, obj);
    dynamic_field::add(&mut obj.id, ConfigKey {}, config);
}
```

---

## Coin and Balance Patterns

### Pattern CB-01: Coin Duplication via Reference

**Risk Level:** Critical

**Description:** Passing Coin by reference allows reuse in multiple operations.

**Detection Pattern:**
```
1. Find functions taking &Coin<T>
2. Check if value is "spent" based on reference
3. Flag reference-based value consumption
```

**Vulnerable:**
```move
// VULNERABLE: Coin passed by reference
public entry fun deposit(
    pool: &mut Pool,
    coin: &Coin<SUI>,
    ctx: &mut TxContext
) {
    // Coin still owned by caller, but pool "sees" value
    pool.total_deposited = pool.total_deposited + coin::value(coin);
    // Caller can reuse same coin for multiple deposits!
}
```

**Secure:**
```move
// SECURE: Take ownership
public entry fun deposit(
    pool: &mut Pool,
    coin: Coin<SUI>,
    ctx: &mut TxContext
) {
    let value = coin::value(&coin);
    pool.total_deposited = pool.total_deposited + value;
    balance::join(&mut pool.balance, coin::into_balance(coin));
    // Coin consumed, cannot reuse
}
```

---

### Pattern CB-03: Missing Coin Type Check

**Risk Level:** High

**Description:** Generic functions may accept wrong coin types.

**Detection Pattern:**
```
1. Find generic Coin<T> parameters
2. Check if T constrained
3. Verify expected coin type
```

**Vulnerable:**
```move
// VULNERABLE: Accepts any coin type
public entry fun swap<CoinIn, CoinOut>(
    pool: &mut Pool,
    coin_in: Coin<CoinIn>,
    ctx: &mut TxContext
): Coin<CoinOut> {
    // What if CoinIn is a worthless token?
    // No validation of accepted coin types
}
```

**Secure:**
```move
// SECURE: Whitelist approach with type registry
public entry fun swap<CoinIn, CoinOut>(
    pool: &mut Pool,
    coin_in: Coin<CoinIn>,
    ctx: &mut TxContext
): Coin<CoinOut> {
    assert!(is_supported_coin<CoinIn>(pool), EUnsupportedCoin);
    assert!(is_supported_coin<CoinOut>(pool), EUnsupportedCoin);
    // ... swap logic
}
```

---

## Clock and Time Patterns

### Pattern CT-01: Clock Manipulation

**Risk Level:** Medium

**Description:** Sui's Clock is provided by validators but can have slight variations.

**Detection Pattern:**
```
1. Find clock::timestamp_ms usage
2. Check time-sensitive operations
3. Verify tolerance for slight variations
```

**Secure Pattern:**
```move
// Use reasonable time windows, not exact timestamps
public fun is_expired(deadline: u64, clock: &Clock): bool {
    clock::timestamp_ms(clock) > deadline + GRACE_PERIOD
}
```

---

## Events and Indexing Patterns

### Pattern EI-01: Missing Events for Critical Actions

**Risk Level:** Medium

**Description:** Important state changes should emit events for off-chain tracking.

**Detection Pattern:**
```
1. Find state-changing functions
2. Check for event::emit calls
3. Flag critical actions without events
```

**Secure Pattern:**
```move
struct WithdrawEvent has copy, drop {
    pool_id: ID,
    amount: u64,
    recipient: address,
    timestamp: u64
}

public entry fun withdraw(
    pool: &mut Pool,
    amount: u64,
    clock: &Clock,
    ctx: &mut TxContext
) {
    // ... withdraw logic
    
    event::emit(WithdrawEvent {
        pool_id: object::id(pool),
        amount,
        recipient: tx_context::sender(ctx),
        timestamp: clock::timestamp_ms(clock)
    });
}
```

---

## Upgrade Patterns

### Pattern UP-01: Missing Upgrade Guard

**Risk Level:** High

**Description:** Package upgrades can introduce vulnerabilities if not properly controlled.

**Detection Pattern:**
```
1. Check if UpgradeCap protected
2. Verify upgrade policy
3. Check for timelock on upgrades
```

**Secure Pattern:**
```move
// Store UpgradeCap in controlled object
struct UpgradeGuard has key {
    id: UID,
    cap: UpgradeCap,
    timelock_end: u64
}

public entry fun upgrade(
    guard: &mut UpgradeGuard,
    policy: &UpgradePolicy,
    clock: &Clock,
    // ... upgrade params
) {
    assert!(clock::timestamp_ms(clock) >= guard.timelock_end, ETimelocked);
    // Perform upgrade with guard.cap
}
```

---

## Sui-Specific Gotchas

### 1. Epoch Boundaries
```move
// Staking rewards only available after epoch change
// Don't assume immediate availability
```

### 2. Gas Coin Handling
```move
// SUI used for gas is handled specially
// Be careful with exact balance checks
```

### 3. Object Deletion
```move
// Deleting objects with dynamic fields
// Must remove all dynamic fields first!
public fun destroy(obj: MyObject) {
    let MyObject { id, .. } = obj;
    // Remove all dynamic fields before this
    object::delete(id);
}
```

### 4. Shared Object Consensus
```move
// Shared object transactions require consensus
// Higher latency than owned object txs
// Consider owned objects when possible
```

---

## Testing Patterns

### Test Utilities
```move
#[test_only]
use sui::test_scenario::{Self, Scenario};

#[test]
fun test_access_control() {
    let admin = @0xAD;
    let attacker = @0xBAD;
    
    let scenario = test_scenario::begin(admin);
    // ... setup
    
    test_scenario::next_tx(&mut scenario, attacker);
    // Try unauthorized access - should fail
    
    test_scenario::end(scenario);
}
```

---

## Quick Detection Commands

```bash
# Find all shared objects
grep -r "share_object\|public_share_object" --include="*.move"

# Find capability structs
grep -r "struct.*Cap.*has.*key" --include="*.move"

# Find dynamic field usage
grep -r "dynamic_field::\|dynamic_object_field::" --include="*.move"

# Find public entry points
grep -r "public entry fun" --include="*.move"

# Find coin operations
grep -r "coin::take\|coin::put\|balance::join" --include="*.move"

# Find objects with store (potentially transferable)
grep -r "has key, store\|has store, key" --include="*.move"
```
