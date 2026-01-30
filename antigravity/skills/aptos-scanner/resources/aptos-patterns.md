# Aptos Move Vulnerability Patterns

Comprehensive database of Aptos-specific vulnerability patterns with detection strategies.

---

## Signer Patterns

### Pattern SV-01: Missing Signer Verification

**Risk Level:** Critical

**Description:** Functions taking &signer must verify the signer is authorized for the operation.

**Detection Pattern:**
```
1. Find functions with &signer parameter
2. Check if signer::address_of compared to expected
3. Flag if no authorization check
```

**Vulnerable:**
```move
module example::vault {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    struct Vault has key {
        coins: Coin<AptosCoin>,
    }

    // VULNERABLE: Anyone can call pretending to be admin
    public entry fun admin_withdraw(
        admin: &signer,
        amount: u64
    ) acquires Vault {
        let vault = borrow_global_mut<Vault>(@vault_address);
        let withdrawn = coin::extract(&mut vault.coins, amount);
        coin::deposit(signer::address_of(admin), withdrawn);
    }
}
```

**Secure:**
```move
module example::vault {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    struct Vault has key {
        coins: Coin<AptosCoin>,
        admin: address,
    }

    // SECURE: Verify signer is admin
    public entry fun admin_withdraw(
        admin: &signer,
        amount: u64
    ) acquires Vault {
        let vault = borrow_global_mut<Vault>(@vault_address);
        assert!(signer::address_of(admin) == vault.admin, 1); // ENOT_ADMIN
        
        let withdrawn = coin::extract(&mut vault.coins, amount);
        coin::deposit(signer::address_of(admin), withdrawn);
    }
}
```

---

### Pattern SV-02: SignerCapability Leak

**Risk Level:** Critical

**Description:** SignerCapability allows creating signers for resource accounts. If leaked, attackers gain full control.

**Detection Pattern:**
```
1. Find SignerCapability in structs
2. Check if any public function returns or exposes it
3. Verify create_signer_with_capability is internal only
```

**Vulnerable:**
```move
struct ResourceAccountConfig has key {
    signer_cap: SignerCapability,
}

// VULNERABLE: Exposes the capability
public fun get_resource_signer_cap(): SignerCapability acquires ResourceAccountConfig {
    let config = borrow_global<ResourceAccountConfig>(@resource);
    config.signer_cap  // Returns capability!
}
```

**Secure:**
```move
struct ResourceAccountConfig has key {
    signer_cap: SignerCapability,
    admin: address,
}

// SECURE: Capability never leaves module
// Only returns signer for internal use
fun get_resource_signer(): signer acquires ResourceAccountConfig {
    let config = borrow_global<ResourceAccountConfig>(@resource);
    account::create_signer_with_capability(&config.signer_cap)
}

// Admin-only function that uses resource signer internally
public entry fun perform_action(admin: &signer) acquires ResourceAccountConfig {
    let config = borrow_global<ResourceAccountConfig>(@resource);
    assert!(signer::address_of(admin) == config.admin, ENOT_ADMIN);
    
    let resource_signer = get_resource_signer();
    // Use resource_signer internally
}
```

---

### Pattern SV-03: Resource Account Creation Race

**Risk Level:** High

**Description:** If resource account address is predictable, attacker can front-run creation.

**Detection Pattern:**
```
1. Find account::create_resource_account calls
2. Check if seed is predictable/constant
3. Verify no sensitive state at predictable address
```

**Vulnerable:**
```move
// VULNERABLE: Predictable seed
public entry fun initialize(admin: &signer) {
    let (resource_signer, cap) = account::create_resource_account(
        admin,
        b"vault"  // Same seed always = same address
    );
    // Attacker can compute address and front-run
}
```

**Secure:**
```move
// SECURE: Unique seed or verified creation
public entry fun initialize(admin: &signer, unique_seed: vector<u8>) {
    // Verify this hasn't been initialized
    assert!(!exists<Initialized>(signer::address_of(admin)), EALREADY_INIT);
    
    let (resource_signer, cap) = account::create_resource_account(
        admin,
        unique_seed  // Unique per deployment
    );
    
    move_to(admin, Initialized { done: true });
}
```

---

## Global Storage Patterns

### Pattern GS-01: Missing Exists Check

**Risk Level:** High

**Description:** borrow_global aborts if resource doesn't exist. Must check with exists<T> first.

**Detection Pattern:**
```
1. Find borrow_global/borrow_global_mut calls
2. Check if exists<T> verified before
3. Flag direct access without check
```

**Vulnerable:**
```move
// VULNERABLE: Aborts if user not registered
public fun get_balance(user: address): u64 acquires UserAccount {
    let account = borrow_global<UserAccount>(user);
    account.balance
}
```

**Secure:**
```move
// SECURE: Handle non-existence gracefully
public fun get_balance(user: address): u64 acquires UserAccount {
    if (!exists<UserAccount>(user)) {
        return 0
    };
    let account = borrow_global<UserAccount>(user);
    account.balance
}
```

---

### Pattern GS-02: Double Initialization

**Risk Level:** High

**Description:** move_to aborts if resource already exists. Can cause denial of service or be exploited if not checked.

**Detection Pattern:**
```
1. Find move_to calls
2. Check if exists<T> verified false before
3. Flag if can be called multiple times
```

**Vulnerable:**
```move
// VULNERABLE: Second call fails
public entry fun initialize(admin: &signer) {
    move_to(admin, Config { value: 0 });
}

// Also VULNERABLE: Overwrite check missing
public entry fun initialize_v2(admin: &signer, value: u64) {
    if (exists<Config>(signer::address_of(admin))) {
        let config = borrow_global_mut<Config>(signer::address_of(admin));
        config.value = value;  // Should this be allowed?
    } else {
        move_to(admin, Config { value });
    }
}
```

**Secure:**
```move
// SECURE: Explicit initialization check
public entry fun initialize(admin: &signer) {
    let admin_addr = signer::address_of(admin);
    assert!(!exists<Config>(admin_addr), EALREADY_INITIALIZED);
    move_to(admin, Config { value: 0 });
}
```

---

### Pattern GS-03: Unauthorized Global Access

**Risk Level:** Critical

**Description:** Accessing global storage at wrong address can lead to unauthorized access.

**Detection Pattern:**
```
1. Find borrow_global with computed/parameter address
2. Verify address is authorized for caller
3. Check if user can manipulate address
```

**Vulnerable:**
```move
// VULNERABLE: User controls which account to modify
public entry fun update_any_user(
    caller: &signer,
    target_user: address,  // Attacker controlled!
    new_value: u64
) acquires UserData {
    let data = borrow_global_mut<UserData>(target_user);
    data.value = new_value;  // Can modify anyone's data!
}
```

**Secure:**
```move
// SECURE: Only modify caller's own data
public entry fun update_my_data(
    caller: &signer,
    new_value: u64
) acquires UserData {
    let caller_addr = signer::address_of(caller);
    let data = borrow_global_mut<UserData>(caller_addr);
    data.value = new_value;
}

// Or with proper authorization
public entry fun update_user_data(
    admin: &signer,
    target_user: address,
    new_value: u64
) acquires AdminConfig, UserData {
    let config = borrow_global<AdminConfig>(@admin_addr);
    assert!(signer::address_of(admin) == config.admin, ENOT_ADMIN);
    
    let data = borrow_global_mut<UserData>(target_user);
    data.value = new_value;
}
```

---

## Coin Patterns

### Pattern CF-01: Coin Capability Exposure

**Risk Level:** Critical

**Description:** MintCapability, BurnCapability, FreezeCapability must never be exposed.

**Detection Pattern:**
```
1. Find *Capability in structs
2. Check for public functions returning capability
3. Verify capability reference not leaked
```

**Vulnerable:**
```move
struct Capabilities<phantom CoinType> has key {
    mint_cap: MintCapability<CoinType>,
    burn_cap: BurnCapability<CoinType>,
}

// VULNERABLE: Returns capability reference
public fun get_mint_cap<CoinType>(): &MintCapability<CoinType> acquires Capabilities {
    &borrow_global<Capabilities<CoinType>>(@module_addr).mint_cap
}

// With the reference, attacker can mint unlimited tokens
public fun mint_with_ref<CoinType>(
    cap: &MintCapability<CoinType>,
    amount: u64
): Coin<CoinType> {
    coin::mint(amount, cap)
}
```

**Secure:**
```move
struct Capabilities<phantom CoinType> has key {
    mint_cap: MintCapability<CoinType>,
    burn_cap: BurnCapability<CoinType>,
    admin: address,
}

// SECURE: Only admin can mint, cap never exposed
public entry fun admin_mint<CoinType>(
    admin: &signer,
    to: address,
    amount: u64
) acquires Capabilities {
    let caps = borrow_global<Capabilities<CoinType>>(@module_addr);
    assert!(signer::address_of(admin) == caps.admin, ENOT_ADMIN);
    
    let coins = coin::mint(amount, &caps.mint_cap);
    coin::deposit(to, coins);
}
```

---

### Pattern CF-02: Missing Coin Registration

**Risk Level:** Medium

**Description:** Before depositing coins, account must be registered for that coin type.

**Detection Pattern:**
```
1. Find coin::deposit calls
2. Check if coin::is_account_registered verified
3. Or if coin::register called first
```

**Vulnerable:**
```move
// VULNERABLE: May fail if user not registered
public entry fun send_reward<CoinType>(
    sender: &signer,
    recipient: address,
    amount: u64
) acquires Vault {
    let vault = borrow_global_mut<Vault>(@vault);
    let coins = coin::extract(&mut vault.coins, amount);
    coin::deposit(recipient, coins);  // Fails if not registered!
}
```

**Secure:**
```move
// SECURE: Handle registration
public entry fun send_reward<CoinType>(
    sender: &signer,
    recipient: address,
    amount: u64
) acquires Vault {
    // Option 1: Require pre-registration
    assert!(coin::is_account_registered<CoinType>(recipient), ENOT_REGISTERED);
    
    // Option 2: Use managed_fungible_asset for auto-deposit
    
    let vault = borrow_global_mut<Vault>(@vault);
    let coins = coin::extract(&mut vault.coins, amount);
    coin::deposit(recipient, coins);
}
```

---

### Pattern CF-05: Flash Loan Without Repayment Check

**Risk Level:** High

**Description:** Flash loans must verify repayment in same transaction.

**Detection Pattern:**
```
1. Find loan/borrow functions
2. Check for hot potato pattern or callback
3. Verify repayment enforced
```

**Vulnerable:**
```move
// VULNERABLE: No repayment enforcement
public fun flash_loan<CoinType>(
    amount: u64
): Coin<CoinType> acquires Pool {
    let pool = borrow_global_mut<Pool<CoinType>>(@pool);
    coin::extract(&mut pool.coins, amount)
    // Caller keeps the coins, no repayment required!
}
```

**Secure:**
```move
// SECURE: Hot potato pattern
struct FlashLoanReceipt<phantom CoinType> {
    amount: u64,
    // No drop ability - must be consumed!
}

public fun flash_loan<CoinType>(
    amount: u64
): (Coin<CoinType>, FlashLoanReceipt<CoinType>) acquires Pool {
    let pool = borrow_global_mut<Pool<CoinType>>(@pool);
    let coins = coin::extract(&mut pool.coins, amount);
    let receipt = FlashLoanReceipt<CoinType> { amount };
    (coins, receipt)
}

// MUST be called to consume receipt
public fun repay<CoinType>(
    coins: Coin<CoinType>,
    receipt: FlashLoanReceipt<CoinType>
) acquires Pool {
    let FlashLoanReceipt { amount } = receipt;
    assert!(coin::value(&coins) >= amount, EINSUFFICIENT_REPAYMENT);
    
    let pool = borrow_global_mut<Pool<CoinType>>(@pool);
    coin::merge(&mut pool.coins, coins);
}
```

---

## Table Patterns

### Pattern TV-01: Missing Table Key Check

**Risk Level:** High

**Description:** table::borrow aborts if key doesn't exist.

**Detection Pattern:**
```
1. Find table::borrow calls
2. Check if table::contains verified first
3. Flag unguarded access
```

**Vulnerable:**
```move
// VULNERABLE: Aborts if user not in table
public fun get_user_info(
    users: &Table<address, UserInfo>,
    user: address
): &UserInfo {
    table::borrow(users, user)
}
```

**Secure:**
```move
// SECURE: Check existence
public fun get_user_info(
    users: &Table<address, UserInfo>,
    user: address
): Option<UserInfo> {
    if (!table::contains(users, user)) {
        return option::none()
    };
    option::some(*table::borrow(users, user))
}

// Or return default
public fun get_user_balance(
    balances: &Table<address, u64>,
    user: address
): u64 {
    if (!table::contains(balances, user)) {
        return 0
    };
    *table::borrow(balances, user)
}
```

---

## Event Patterns

### Pattern EV-01: Missing Critical Events

**Risk Level:** Medium

**Description:** Important state changes should emit events for tracking.

**Detection Pattern:**
```
1. Find state-changing functions
2. Check for event::emit_event calls
3. Flag critical operations without events
```

**Secure Pattern:**
```move
struct WithdrawEvent has drop, store {
    user: address,
    amount: u64,
    timestamp: u64,
}

struct EventStore has key {
    withdraw_events: EventHandle<WithdrawEvent>,
}

public entry fun withdraw(
    user: &signer,
    amount: u64
) acquires Vault, EventStore {
    let user_addr = signer::address_of(user);
    
    // Withdraw logic...
    
    // Emit event
    let events = borrow_global_mut<EventStore>(@vault);
    event::emit_event(&mut events.withdraw_events, WithdrawEvent {
        user: user_addr,
        amount,
        timestamp: timestamp::now_seconds(),
    });
}
```

---

## Upgrade Patterns

### Pattern MU-01: Unrestricted Module Upgrade

**Risk Level:** Critical

**Description:** Without upgrade policy, modules can be upgraded arbitrarily.

**Detection Commands:**
```bash
# Check Move.toml
grep "upgrade_policy" Move.toml

# Should see:
# [package]
# upgrade_policy = "compatible"  # or "immutable"
```

**Secure Pattern:**
```toml
# Move.toml
[package]
name = "my_module"
version = "1.0.0"
upgrade_policy = "compatible"  # Prevents breaking changes

# For fully locked modules:
# upgrade_policy = "immutable"
```

---

## Aptos Framework Gotchas

### 1. Timestamp Dependency
```move
// Timestamp from validators, slight variations possible
let now = timestamp::now_seconds();
// Use >= instead of == for time checks
```

### 2. Coin vs Fungible Asset
```move
// New projects should use fungible_asset
// Legacy coin interface being deprecated
use aptos_framework::fungible_asset;
use aptos_framework::primary_fungible_store;
```

### 3. Object Model (New)
```move
// Aptos is adding object model similar to Sui
use aptos_framework::object;
// Check which model project uses
```

### 4. Gas Limits
```move
// Avoid unbounded loops
// Max gas per transaction limits computation
while (i < vector::length(&large_vec)) {  // Could hit gas limit
    // ...
}
```

---

## Quick Detection Commands

```bash
# Find signers
grep -r "&signer" sources/ --include="*.move"

# Find global storage
grep -r "borrow_global\|move_to\|exists<" sources/

# Find capabilities
grep -r "Capability\|SignerCapability" sources/

# Find coin operations
grep -r "coin::mint\|coin::burn\|coin::deposit" sources/

# Find tables
grep -r "Table<\|table::" sources/

# Find public entry points
grep -r "public entry fun" sources/
```
