# Move Vulnerability Patterns

Detailed vulnerability patterns for Move smart contracts on Aptos and Sui.

---

## RS-01: Resource Duplication

### Description
Creating multiple copies of a resource that should be unique, leading to token inflation or state corruption.

### Vulnerable Code
```move
struct Coin has copy, key, store {  // ❌ 'copy' on valuable resource!
    value: u64
}

public fun duplicate_coins(coin: &Coin): Coin {
    *coin  // Returns a copy - infinite money!
}
```

### Secure Code
```move
struct Coin has key, store {  // ✅ No 'copy' ability
    value: u64
}

// Coins can only be moved, not copied
public fun transfer(coin: Coin, recipient: address) {
    // coin is moved, original owner loses access
}
```

### Detection
- Check for `copy` ability on value-bearing structs
- Review any struct representing assets/tokens

---

## RS-02: Resource Destruction

### Description
Accidentally destroying valuable resources by not properly handling them.

### Vulnerable Code
```move
struct Coin has key, store, drop {  // ❌ 'drop' allows silent destruction
    value: u64
}

public fun process(coin: Coin) {
    // Function ends without using coin
    // coin is silently dropped - value lost!
}
```

### Secure Code
```move
struct Coin has key, store {  // ✅ No 'drop' - must be handled
    value: u64
}

public fun process(coin: Coin): Coin {
    // Must return or move coin
    coin
}

// Or explicitly destroy with zero check
public fun destroy_zero(coin: Coin) {
    let Coin { value } = coin;
    assert!(value == 0, E_NON_ZERO);
}
```

---

## AC-01: Missing Signer Check

### Description
Entry function doesn't verify the signer has authority to perform the action.

### Vulnerable Code (Aptos)
```move
public entry fun withdraw(
    user: &signer,
    vault_addr: address,
    amount: u64
) acquires Vault {
    // ❌ Anyone can withdraw from any vault!
    let vault = borrow_global_mut<Vault>(vault_addr);
    let coins = coin::extract(&mut vault.balance, amount);
    coin::deposit(signer::address_of(user), coins);
}
```

### Secure Code (Aptos)
```move
public entry fun withdraw(
    user: &signer,
    amount: u64
) acquires Vault {
    // ✅ Withdraw only from signer's own vault
    let user_addr = signer::address_of(user);
    let vault = borrow_global_mut<Vault>(user_addr);
    let coins = coin::extract(&mut vault.balance, amount);
    coin::deposit(user_addr, coins);
}
```

### Vulnerable Code (Sui)
```move
public entry fun withdraw(
    vault: &mut Vault,
    amount: u64,
    ctx: &mut TxContext
) {
    // ❌ Anyone with Vault reference can withdraw!
    let coins = balance::split(&mut vault.balance, amount);
    transfer::public_transfer(coin::from_balance(coins, ctx), tx_context::sender(ctx));
}
```

### Secure Code (Sui)
```move
public entry fun withdraw(
    vault: &mut Vault,
    amount: u64,
    ctx: &mut TxContext
) {
    // ✅ Verify caller is vault owner
    assert!(vault.owner == tx_context::sender(ctx), E_NOT_OWNER);
    
    let coins = balance::split(&mut vault.balance, amount);
    transfer::public_transfer(coin::from_balance(coins, ctx), tx_context::sender(ctx));
}
```

---

## AC-02: Missing Capability Check

### Description
Privileged function doesn't verify caller holds the required capability.

### Vulnerable Code
```move
struct AdminCap has key, store { id: UID }

public entry fun admin_function(/* no cap check */) {
    // ❌ Anyone can call this!
    // ... privileged operations
}
```

### Secure Code
```move
struct AdminCap has key, store { id: UID }

public entry fun admin_function(
    _cap: &AdminCap,  // ✅ Requires capability
    // ... other params
) {
    // Only holders of AdminCap can call
    // ... privileged operations
}
```

---

## AC-03: Unprotected Entry Function

### Description
Entry function performs sensitive operations without proper authorization.

### Vulnerable Code
```move
// ❌ Public entry with no access control
public entry fun set_price(oracle: &mut Oracle, price: u64) {
    oracle.price = price;  // Anyone can manipulate price!
}
```

### Secure Code
```move
public entry fun set_price(
    cap: &OracleAdminCap,  // ✅ Requires capability
    oracle: &mut Oracle,
    price: u64
) {
    assert!(cap.oracle_id == object::id(oracle), E_WRONG_ORACLE);
    oracle.price = price;
}
```

---

## AR-01: Integer Overflow

### Description
Arithmetic operations exceeding type bounds without proper checks.

### Vulnerable Code
```move
public fun add_balance(vault: &mut Vault, amount: u64) {
    vault.balance = vault.balance + amount;  // Can overflow!
}
```

### Secure Code
```move
public fun add_balance(vault: &mut Vault, amount: u64) {
    // Move VMs typically abort on overflow, but be explicit
    let new_balance = vault.balance + amount;
    assert!(new_balance >= vault.balance, E_OVERFLOW);  // Explicit check
    vault.balance = new_balance;
}

// Or use math libraries
use aptos_std::math64;

public fun add_balance_safe(vault: &mut Vault, amount: u64) {
    vault.balance = math64::add(vault.balance, amount);
}
```

---

## AP-01: Coin Registration Missing

### Description
Attempting coin operations on unregistered accounts.

### Vulnerable Code
```move
public entry fun airdrop<CoinType>(
    admin: &signer,
    recipient: address,
    amount: u64
) acquires Treasury {
    let treasury = borrow_global_mut<Treasury>(signer::address_of(admin));
    let coins = coin::extract(&mut treasury.balance, amount);
    // ❌ Will fail if recipient not registered for CoinType
    coin::deposit(recipient, coins);
}
```

### Secure Code
```move
public entry fun airdrop<CoinType>(
    admin: &signer,
    recipient: address,
    amount: u64
) acquires Treasury {
    // ✅ Check registration first
    if (!coin::is_account_registered<CoinType>(recipient)) {
        // Either abort or handle gracefully
        abort E_NOT_REGISTERED
    };
    
    let treasury = borrow_global_mut<Treasury>(signer::address_of(admin));
    let coins = coin::extract(&mut treasury.balance, amount);
    coin::deposit(recipient, coins);
}
```

---

## AP-04: Table Key Collision

### Description
Using predictable or colliding keys in Aptos Table structures.

### Vulnerable Code
```move
use aptos_std::table::{Self, Table};

struct Registry has key {
    users: Table<u64, UserData>,  // ❌ Sequential IDs can collide
}

public fun register(registry: &mut Registry, user_id: u64, data: UserData) {
    table::add(&mut registry.users, user_id, data);
}
```

### Secure Code
```move
struct Registry has key {
    users: Table<address, UserData>,  // ✅ Address is unique
}

public fun register(registry: &mut Registry, user: &signer, data: UserData) {
    let addr = signer::address_of(user);
    assert!(!table::contains(&registry.users, addr), E_ALREADY_REGISTERED);
    table::add(&mut registry.users, addr, data);
}
```

---

## SU-01: Shared Object Contention

### Description
Overuse of shared objects causing transaction failures due to contention.

### Vulnerable Code
```move
// ❌ Global counter as shared object - every transaction conflicts
struct GlobalCounter has key {
    id: UID,
    count: u64,
}

public entry fun increment(counter: &mut GlobalCounter) {
    counter.count = counter.count + 1;
}
```

### Secure Code
```move
// ✅ Use owned objects where possible
struct UserCounter has key {
    id: UID,
    count: u64,
}

public entry fun increment(counter: &mut UserCounter) {
    counter.count = counter.count + 1;
}

// Or batch operations to reduce contention
public entry fun batch_increment(counter: &mut GlobalCounter, amount: u64) {
    counter.count = counter.count + amount;
}
```

---

## SU-02: Object Ownership Issues

### Description
Improper handling of object ownership in Sui, leading to unauthorized access.

### Vulnerable Code
```move
public entry fun process(obj: MyObject) {
    // ❌ obj is consumed but not transferred - destroyed!
}
```

### Secure Code
```move
public entry fun process(obj: MyObject, ctx: &mut TxContext) {
    // ✅ Transfer back or to recipient
    transfer::transfer(obj, tx_context::sender(ctx));
}

// Or use reference if not consuming
public entry fun process_ref(obj: &MyObject) {
    // Read-only access, ownership unchanged
}
```

---

## SU-04: Dynamic Field Collision

### Description
Colliding keys in Sui dynamic fields causing overwrites.

### Vulnerable Code
```move
use sui::dynamic_field as df;

public fun add_data(parent: &mut UID, key: u64, data: Data) {
    // ❌ Numeric keys can easily collide
    df::add(parent, key, data);
}
```

### Secure Code
```move
// ✅ Use unique type-based keys
struct DataKey has copy, drop, store { user: address }

public fun add_data(parent: &mut UID, user: address, data: Data) {
    let key = DataKey { user };
    assert!(!df::exists_(parent, key), E_ALREADY_EXISTS);
    df::add(parent, key, data);
}
```

---

## LG-02: Missing Abort Condition

### Description
Critical invariants not enforced with abort conditions.

### Vulnerable Code
```move
public fun withdraw(vault: &mut Vault, amount: u64): Coin {
    // ❌ No balance check - could underflow
    vault.balance = vault.balance - amount;
    Coin { value: amount }
}
```

### Secure Code
```move
public fun withdraw(vault: &mut Vault, amount: u64): Coin {
    // ✅ Check invariant
    assert!(vault.balance >= amount, E_INSUFFICIENT_BALANCE);
    vault.balance = vault.balance - amount;
    Coin { value: amount }
}
```

---

## UP-01: Unprotected Upgrade (Aptos)

### Description
Module upgrade without proper authorization.

### Aptos Upgrade Considerations
```move
// Aptos uses package upgrade policies
// Set in Move.toml:
// [package]
// upgrade_policy = "compatible"  // or "immutable"

// For upgradeable packages, control upgrade capability
struct UpgradeCap has key, store {
    package_address: address,
}

public entry fun upgrade_module(
    cap: &UpgradeCap,
    // ... upgrade params
) {
    // Only cap holder can upgrade
}
```

### Sui Package Publishing
```move
// Sui packages are immutable by default
// Use Upgrade Caps for upgradeable packages

struct UpgradeCap has key {
    id: UID,
    package: ID,
    version: u64,
}

public entry fun authorize_upgrade(
    cap: &UpgradeCap,
    policy: u8,
    digest: vector<u8>
): UpgradeTicket {
    // Verify cap permissions
    // Return upgrade ticket
}
```

---

## Generic Type Security

### Vulnerable Code
```move
// ❌ No constraint on T - could be malicious type
public fun process<T>(item: T) {
    // What if T has unexpected behavior?
}
```

### Secure Code
```move
// ✅ Constrain generics appropriately
public fun process<T: store + drop>(item: T) {
    // T must have store and drop abilities
}

// ✅ Verify coin types
public fun swap<CoinA, CoinB>(
    pool: &mut Pool<CoinA, CoinB>,
    coin_in: Coin<CoinA>
): Coin<CoinB> {
    // Type parameters ensure correct coins used
}
```
