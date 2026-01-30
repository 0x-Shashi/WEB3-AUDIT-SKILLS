# Aptos Security Guide

Security considerations specific to Aptos blockchain and Move development.

---

## Aptos Architecture

### Account Model

```move
// Aptos uses an account-based model
// Resources are stored under account addresses

// Check if resource exists
let exists = exists<MyResource>(addr);

// Borrow resource (must exist)
let resource = borrow_global<MyResource>(addr);

// Borrow mutable (must exist)
let resource_mut = borrow_global_mut<MyResource>(addr);

// Move to account (must have signer)
move_to(signer, MyResource { ... });

// Move from account (destructive)
let resource = move_from<MyResource>(addr);
```

### Signer vs Address

```move
// Signer = authenticated account, can modify storage
public entry fun create_resource(account: &signer) {
    let addr = signer::address_of(account);
    move_to(account, MyResource { owner: addr });
}

// Address = just an identifier, read-only access
public fun get_balance(addr: address): u64 acquires Balance {
    borrow_global<Balance>(addr).value
}
```

---

## Aptos Framework Security

### Coin Module

```move
use aptos_framework::coin;

// CRITICAL: Always check registration before deposit
public fun safe_deposit<CoinType>(
    account_addr: address,
    coins: Coin<CoinType>
) {
    assert!(
        coin::is_account_registered<CoinType>(account_addr),
        E_NOT_REGISTERED
    );
    coin::deposit(account_addr, coins);
}

// Register for coin type
public entry fun register<CoinType>(account: &signer) {
    coin::register<CoinType>(account);
}

// Mint (requires MintCapability)
public fun mint<CoinType>(
    cap: &MintCapability<CoinType>,
    amount: u64
): Coin<CoinType> {
    coin::mint(amount, cap)
}

// Burn (requires BurnCapability)
public fun burn<CoinType>(
    cap: &BurnCapability<CoinType>,
    coins: Coin<CoinType>
) {
    coin::burn(coins, cap);
}
```

### Account Module

```move
use aptos_framework::account;

// Create account if doesn't exist
public entry fun ensure_account_exists(
    creator: &signer,
    new_addr: address
) {
    if (!account::exists_at(new_addr)) {
        account::create_account(new_addr);
    };
}

// Get sequence number (for replay protection)
public fun get_sequence_number(addr: address): u64 {
    account::get_sequence_number(addr)
}

// SignerCapability - allows creating signer from resource account
struct ModuleData has key {
    signer_cap: SignerCapability,
}

public fun get_module_signer(data: &ModuleData): signer {
    account::create_signer_with_capability(&data.signer_cap)
}
```

### Timestamp Module

```move
use aptos_framework::timestamp;

//  WARNING: Timestamp is set by validators
// Don't use for high-precision timing

public fun check_deadline(deadline: u64) {
    let now = timestamp::now_seconds();
    assert!(now <= deadline, E_DEADLINE_PASSED);
}

// For microseconds
public fun now_microseconds(): u64 {
    timestamp::now_microseconds()
}
```

---

## Resource Account Pattern

```move
// Resource accounts are accounts controlled by modules
// Used for: pools, vaults, protocol treasuries

use aptos_framework::account::{Self, SignerCapability};

struct ModuleState has key {
    signer_cap: SignerCapability,
    resource_address: address,
}

// Initialize module with resource account
fun init_module(admin: &signer) {
    let (resource_signer, signer_cap) = account::create_resource_account(
        admin,
        b"unique_seed"
    );
    
    let resource_address = signer::address_of(&resource_signer);
    
    move_to(admin, ModuleState {
        signer_cap,
        resource_address,
    });
}

// Use resource account signer
public fun module_action() acquires ModuleState {
    let state = borrow_global<ModuleState>(@module_addr);
    let resource_signer = account::create_signer_with_capability(&state.signer_cap);
    
    // Now can perform actions as resource account
    coin::transfer<AptosCoin>(&resource_signer, recipient, amount);
}
```

---

## Table and Smart Table

### Table (Basic)

```move
use aptos_std::table::{Self, Table};

struct Registry has key {
    data: Table<address, UserInfo>,
}

// Add entry
public fun add_user(registry: &mut Registry, addr: address, info: UserInfo) {
    assert!(!table::contains(&registry.data, addr), E_ALREADY_EXISTS);
    table::add(&mut registry.data, addr, info);
}

// Get entry
public fun get_user(registry: &Registry, addr: address): &UserInfo {
    table::borrow(&registry.data, addr)
}

// Remove entry
public fun remove_user(registry: &mut Registry, addr: address): UserInfo {
    table::remove(&mut registry.data, addr)
}
```

### Smart Table (Better for Iteration)

```move
use aptos_std::smart_table::{Self, SmartTable};

struct Pool has key {
    positions: SmartTable<address, Position>,
}

// Smart tables support iteration and are gas-efficient
public fun for_each_position(pool: &Pool, f: |&Position|) {
    smart_table::for_each_ref(&pool.positions, |_addr, position| {
        f(position);
    });
}
```

---

## Events

```move
use aptos_framework::event::{Self, EventHandle};

struct ModuleEvents has key {
    transfer_events: EventHandle<TransferEvent>,
}

struct TransferEvent has drop, store {
    from: address,
    to: address,
    amount: u64,
}

// Emit event
public fun emit_transfer(
    events: &mut ModuleEvents,
    from: address,
    to: address,
    amount: u64
) {
    event::emit_event(&mut events.transfer_events, TransferEvent {
        from,
        to,
        amount,
    });
}
```

---

## Access Control Patterns

### Simple Owner

```move
struct Config has key {
    owner: address,
    // ... other fields
}

public fun only_owner(config: &Config, caller: &signer) {
    assert!(
        signer::address_of(caller) == config.owner,
        E_NOT_OWNER
    );
}
```

### Capability Pattern

```move
struct AdminCap has key, store {}

// Only module can create AdminCap
fun init_module(admin: &signer) {
    move_to(admin, AdminCap {});
}

// Functions requiring admin
public entry fun admin_action(
    admin: &signer,
    // ... params
) acquires AdminCap {
    // Verify caller has AdminCap
    assert!(exists<AdminCap>(signer::address_of(admin)), E_NOT_ADMIN);
    // ... action
}
```

### Role-Based Access Control

```move
use aptos_std::simple_map::{Self, SimpleMap};

struct AccessControl has key {
    roles: SimpleMap<address, u64>,  // address -> role bitmap
}

const ROLE_ADMIN: u64 = 1;
const ROLE_OPERATOR: u64 = 2;
const ROLE_MINTER: u64 = 4;

public fun has_role(acl: &AccessControl, addr: address, role: u64): bool {
    if (!simple_map::contains_key(&acl.roles, &addr)) {
        return false
    };
    let user_roles = *simple_map::borrow(&acl.roles, &addr);
    (user_roles & role) == role
}

public fun require_role(acl: &AccessControl, caller: &signer, role: u64) {
    let addr = signer::address_of(caller);
    assert!(has_role(acl, addr, role), E_MISSING_ROLE);
}
```

---

## Upgrade Security

### Package Upgrade Policies

```toml
# Move.toml
[package]
name = "my_package"
version = "1.0.0"
upgrade_policy = "compatible"  # Options: compatible, immutable

# compatible - Allows upgrades that don't break storage layout
# immutable - No upgrades allowed
```

### Safe Upgrade Practices

```move
// 1. Never remove or reorder struct fields
struct State has key {
    field1: u64,     // v1: slot 0
    field2: address, // v1: slot 1
    // v2: Add new fields at end only
    field3: u64,     // v2: slot 2 (safe addition)
}

// 2. Use versioning for migrations
struct StateV2 has key {
    version: u64,
    // ... fields
}

public fun migrate_v1_to_v2(admin: &signer) acquires StateV1 {
    let old = move_from<StateV1>(signer::address_of(admin));
    let new = StateV2 {
        version: 2,
        // ... convert fields
    };
    move_to(admin, new);
}
```

---

## Testing

### Unit Tests

```move
#[test_only]
module my_addr::my_module_tests {
    use my_addr::my_module;
    use std::signer;
    use aptos_framework::account;
    
    #[test(admin = @0x123)]
    public fun test_init(admin: &signer) {
        account::create_account_for_test(signer::address_of(admin));
        my_module::init(admin);
        // ... assertions
    }
    
    #[test(admin = @0x123, user = @0x456)]
    #[expected_failure(abort_code = my_module::E_NOT_OWNER)]
    public fun test_unauthorized_fails(admin: &signer, user: &signer) {
        // Test that unauthorized action fails
        my_module::admin_only_action(user);  // Should abort
    }
}
```

### Move Prover (Formal Verification)

```move
spec module {
    // Invariant: total supply equals sum of all balances
    invariant forall addr: address:
        exists<Balance>(addr) ==> 
            global<TotalSupply>(@module).value >= global<Balance>(addr).value;
}

spec fun deposit {
    // Precondition
    requires amount > 0;
    requires exists<Balance>(addr);
    
    // Postcondition
    ensures global<Balance>(addr).value == old(global<Balance>(addr).value) + amount;
    
    // Abort conditions
    aborts_if !exists<Balance>(addr);
    aborts_if global<Balance>(addr).value + amount > MAX_U64;
}
```

---

## Audit Checklist

### Aptos-Specific Checks

- [ ] Coin registration checked before deposits
- [ ] Signer vs address used appropriately
- [ ] Resource existence checked before borrow_global
- [ ] SignerCapability stored securely
- [ ] Events emitted for all state changes
- [ ] Table keys designed to prevent collision
- [ ] Upgrade policy appropriate for use case
- [ ] Resource accounts properly secured
- [ ] Timestamp usage accounts for manipulation tolerance

