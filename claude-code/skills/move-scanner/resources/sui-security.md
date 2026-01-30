# Sui Security Guide

Security considerations specific to Sui blockchain and Move development.

---

## Sui Object Model

### Object Types

```move
use sui::object::{Self, UID, ID};
use sui::transfer;
use sui::tx_context::{Self, TxContext};

// Owned Object - belongs to one address
struct OwnedNFT has key, store {
    id: UID,
    name: vector<u8>,
}

// Shared Object - accessible by anyone (consensus required)
struct SharedPool has key {
    id: UID,
    balance: Balance<SUI>,
}

// Immutable Object - read-only, no owner
struct ImmutableConfig has key {
    id: UID,
    max_supply: u64,
}
```

### Object Ownership

```move
// Create and transfer to sender
public entry fun create_nft(ctx: &mut TxContext) {
    let nft = OwnedNFT {
        id: object::new(ctx),
        name: b"My NFT",
    };
    transfer::transfer(nft, tx_context::sender(ctx));
}

// For objects with 'store' ability
public entry fun create_transferable(ctx: &mut TxContext) {
    let obj = Transferable {
        id: object::new(ctx),
        // ...
    };
    transfer::public_transfer(obj, tx_context::sender(ctx));
}

// Create shared object
public entry fun create_pool(ctx: &mut TxContext) {
    let pool = SharedPool {
        id: object::new(ctx),
        balance: balance::zero(),
    };
    transfer::share_object(pool);  // Becomes shared, no owner
}

// Freeze object (make immutable)
public entry fun freeze_config(config: ImmutableConfig) {
    transfer::freeze_object(config);  // Becomes immutable
}
```

---

## Sui Framework Security

### Balance and Coin

```move
use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};

// Balance is internal representation (no UID)
struct Vault has key {
    id: UID,
    funds: Balance<SUI>,
}

// Coin is transferable object wrapping Balance
public entry fun deposit(vault: &mut Vault, coin: Coin<SUI>) {
    let balance = coin::into_balance(coin);
    balance::join(&mut vault.funds, balance);
}

public entry fun withdraw(
    vault: &mut Vault,
    amount: u64,
    ctx: &mut TxContext
) {
    let balance = balance::split(&mut vault.funds, amount);
    let coin = coin::from_balance(balance, ctx);
    transfer::public_transfer(coin, tx_context::sender(ctx));
}
```

### Transfer Policy

```move
use sui::transfer_policy::{Self, TransferPolicy, TransferPolicyCap};

// For controlled transfers (NFT marketplaces, royalties)
struct NFT has key, store { id: UID }

// Create transfer policy
public fun create_policy(
    publisher: &Publisher,
    ctx: &mut TxContext
): (TransferPolicy<NFT>, TransferPolicyCap<NFT>) {
    transfer_policy::new<NFT>(publisher, ctx)
}

// Add royalty rule
public fun add_royalty(
    policy: &mut TransferPolicy<NFT>,
    cap: &TransferPolicyCap<NFT>,
    royalty_bps: u16
) {
    // Add royalty enforcement
}
```

---

## Object References

### Reference Types

```move
// Immutable reference - read only
public fun get_balance(vault: &Vault): u64 {
    balance::value(&vault.funds)
}

// Mutable reference - can modify
public fun add_balance(vault: &mut Vault, amount: Balance<SUI>) {
    balance::join(&mut vault.funds, amount);
}

// By value - consumes the object
public entry fun destroy_vault(vault: Vault) {
    let Vault { id, funds } = vault;
    object::delete(id);
    // funds must be handled (transferred or destroyed)
}
```

### Object as Entry Parameter

```move
// Owned object - only owner can pass
public entry fun use_owned(nft: OwnedNFT, ctx: &mut TxContext) {
    // Only NFT owner can call
    // NFT is consumed, must be returned or transferred
    transfer::transfer(nft, tx_context::sender(ctx));
}

// Shared object - anyone can pass reference
public entry fun use_shared(pool: &mut SharedPool) {
    // Anyone can call, but requires consensus
    // pool is borrowed, not consumed
}

// Object reference - owner passes
public entry fun read_owned(nft: &OwnedNFT): u64 {
    // Read-only access
    vector::length(&nft.name)
}
```

---

## Dynamic Fields

```move
use sui::dynamic_field as df;
use sui::dynamic_object_field as dof;

// Dynamic field - stores any value under a key
struct Parent has key {
    id: UID,
}

// Add dynamic field
public fun add_data<K: copy + drop + store, V: store>(
    parent: &mut Parent,
    key: K,
    value: V
) {
    assert!(!df::exists_(&parent.id, key), E_ALREADY_EXISTS);
    df::add(&mut parent.id, key, value);
}

// Borrow dynamic field
public fun get_data<K: copy + drop + store, V: store>(
    parent: &Parent,
    key: K
): &V {
    df::borrow(&parent.id, key)
}

// Dynamic object field - stores objects (has UID)
public fun add_child(
    parent: &mut Parent,
    child: Child
) {
    dof::add(&mut parent.id, b"child", child);
}
```

### Dynamic Field Security

```move
// ⚠️ Key collision risk with generic keys
struct TypedKey has copy, drop, store {
    key_type: u8,
    key_value: address,
}

// ✅ Use type-safe keys
public fun add_user_data(parent: &mut Parent, user: address, data: UserData) {
    let key = TypedKey { key_type: 1, key_value: user };
    assert!(!df::exists_(&parent.id, key), E_EXISTS);
    df::add(&mut parent.id, key, data);
}
```

---

## Capability Pattern

### Witness Pattern

```move
// One-time witness for type authority
struct MYTOKEN has drop {}

fun init(witness: MYTOKEN, ctx: &mut TxContext) {
    // witness proves this is module initialization
    let (treasury_cap, metadata) = coin::create_currency(
        witness,  // consumed, can't be recreated
        9,
        b"MYTOKEN",
        b"My Token",
        b"Description",
        option::none(),
        ctx
    );
    // ...
}
```

### Admin Capability

```move
struct AdminCap has key, store {
    id: UID,
}

fun init(ctx: &mut TxContext) {
    // Create admin cap on module init
    let cap = AdminCap { id: object::new(ctx) };
    transfer::transfer(cap, tx_context::sender(ctx));
}

// Only AdminCap holder can call
public entry fun admin_action(
    _cap: &AdminCap,  // Proves ownership
    // ... other params
) {
    // Privileged action
}
```

### Publisher

```move
use sui::package::{Self, Publisher};

struct MYMODULE has drop {}

fun init(witness: MYMODULE, ctx: &mut TxContext) {
    let publisher = package::claim(witness, ctx);
    transfer::public_transfer(publisher, tx_context::sender(ctx));
}

// Publisher proves module authority
public fun verify_publisher<T>(publisher: &Publisher) {
    assert!(package::from_package<T>(publisher), E_NOT_PUBLISHER);
}
```

---

## Clock and Time

```move
use sui::clock::{Self, Clock};

// ⚠️ Clock is a shared object, updated by validators
// Don't use for high-precision or critical timing

public entry fun check_deadline(
    clock: &Clock,
    deadline_ms: u64
) {
    let now = clock::timestamp_ms(clock);
    assert!(now <= deadline_ms, E_EXPIRED);
}

// Clock must be passed as argument (shared object)
// Object ID: 0x6
```

---

## Package Upgrades

### Upgrade Capability

```move
use sui::package::{Self, UpgradeCap, UpgradeTicket, UpgradeReceipt};

// UpgradeCap created on publish
// Control who can upgrade by transferring cap

struct AdminCap has key, store { id: UID }

public entry fun authorize_upgrade(
    admin: &AdminCap,
    cap: &UpgradeCap,
    policy: u8,
    digest: vector<u8>,
): UpgradeTicket {
    // Verify admin
    package::authorize_upgrade(cap, policy, digest)
}

public entry fun commit_upgrade(
    cap: &mut UpgradeCap,
    receipt: UpgradeReceipt,
) {
    package::commit_upgrade(cap, receipt);
}
```

### Upgrade Policies

```move
// Upgrade policies
const COMPATIBLE: u8 = 0;  // All changes allowed
const ADDITIVE: u8 = 128;  // Only additions
const DEP_ONLY: u8 = 192;  // Only dependency upgrades
const IMMUTABLE: u8 = 255; // No upgrades

public entry fun make_immutable(cap: UpgradeCap) {
    package::make_immutable(cap);  // Consumes cap, no more upgrades
}
```

---

## Testing

```move
#[test_only]
module my_package::tests {
    use sui::test_scenario::{Self as ts, Scenario};
    use sui::test_utils;
    use my_package::my_module::{Self, Pool, AdminCap};
    
    #[test]
    fun test_create_pool() {
        let admin = @0xAD;
        let mut scenario = ts::begin(admin);
        
        // Create pool
        ts::next_tx(&mut scenario, admin);
        {
            my_module::create_pool(ts::ctx(&mut scenario));
        };
        
        // Verify pool created
        ts::next_tx(&mut scenario, admin);
        {
            let pool = ts::take_shared<Pool>(&scenario);
            assert!(my_module::get_balance(&pool) == 0, 0);
            ts::return_shared(pool);
        };
        
        ts::end(scenario);
    }
    
    #[test]
    #[expected_failure(abort_code = my_module::E_NOT_ADMIN)]
    fun test_unauthorized_fails() {
        let admin = @0xAD;
        let user = @0xBB;
        let mut scenario = ts::begin(admin);
        
        // Init with admin
        ts::next_tx(&mut scenario, admin);
        {
            my_module::init_for_testing(ts::ctx(&mut scenario));
        };
        
        // User tries admin action
        ts::next_tx(&mut scenario, user);
        {
            my_module::admin_only(ts::ctx(&mut scenario));  // Should fail
        };
        
        ts::end(scenario);
    }
}
```

---

## Audit Checklist

### Sui-Specific Checks

- [ ] Object types appropriate (owned vs shared vs immutable)
- [ ] Shared objects used only when necessary (contention)
- [ ] Objects properly consumed or transferred
- [ ] Dynamic fields have unique keys
- [ ] Transfer policies enforced for regulated assets
- [ ] Publisher authority verified for sensitive operations
- [ ] Clock usage accounts for validator control
- [ ] UpgradeCap properly secured or made immutable
- [ ] Entry functions validate object ownership context
- [ ] Balance and Coin operations atomic

