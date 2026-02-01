---
id: CHAIN-APTOS
title: Aptos Security Guide
category: chain-guides
chain: aptos
language: move
difficulty: advanced
tags: [aptos, move, resources, modules, timestamps]
last_updated: 2026-01-31
---

# Aptos Security Guide

## Overview

Aptos uses the Move language with a resource-oriented model. Unlike Sui's object model, Aptos uses global storage with resources stored under accounts.

```
┌─────────────────────────────────────────────────────────────────┐
│                      APTOS ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STORAGE MODEL                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                                                         │   │
│  │  Account 0x1          Account 0x2          Account 0x3  │   │
│  │  ┌──────────┐        ┌──────────┐        ┌──────────┐  │   │
│  │  │Resources │        │Resources │        │Resources │  │   │
│  │  │ - Coin   │        │ - Coin   │        │ - NFT    │  │   │
│  │  │ - Config │        │ - Token  │        │ - Store  │  │   │
│  │  └──────────┘        └──────────┘        └──────────┘  │   │
│  │                                                         │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  KEY DIFFERENCES FROM SUI:                                      │
│  • Account-based storage (not object-based)                     │
│  • Resources stored under addresses                             │
│  • Global storage access                                        │
│  • Different transaction model                                  │
│  • Explicit resource management                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Move on Aptos Fundamentals

### Resource Model

```move
// Aptos uses resources stored under accounts

module example::vault {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;
    
    // Resource stored under user's account
    struct Vault has key {
        coins: Coin<AptosCoin>,
    }
    
    // Create vault under signer's account
    public entry fun create_vault(account: &signer) {
        let vault = Vault {
            coins: coin::zero<AptosCoin>(),
        };
        // Store under account address
        move_to(account, vault);
    }
    
    // Deposit into user's vault
    public entry fun deposit(
        account: &signer,
        amount: u64
    ) acquires Vault {
        let addr = signer::address_of(account);
        let vault = borrow_global_mut<Vault>(addr);
        
        let coins = coin::withdraw<AptosCoin>(account, amount);
        coin::merge(&mut vault.coins, coins);
    }
}
```

### Abilities System

```move
// Aptos Move abilities control resource behavior

// key: Can be stored in global storage
// store: Can be stored inside other resources
// copy: Can be copied
// drop: Can be discarded

struct CanCopy has copy, drop { value: u64 }
struct NoCopy has drop { value: u64 }  // Can't duplicate
struct Resource has key, store { value: u64 }  // Storable

// SECURITY: Resources without 'drop' must be explicitly handled
// Can't accidentally lose valuable resources
```

---

## Attack Vector 1: Resource Safety Violations

### Missing Acquires Annotation

```move
// VULNERABILITY: Forgetting 'acquires' can cause runtime errors

module vulnerable::storage {
    struct Data has key { value: u64 }
    
    // WRONG: Missing 'acquires Data'
    public fun read_data(addr: address): u64 {
        // This will compile but fail at runtime!
        let data = borrow_global<Data>(addr);
        data.value
    }
    
    // CORRECT:
    public fun read_data(addr: address): u64 acquires Data {
        let data = borrow_global<Data>(addr);
        data.value
    }
}
```

### Resource Existence Checks

```move
// VULNERABILITY: Not checking if resource exists

module vulnerable::vault {
    struct Vault has key { balance: u64 }
    
    // WRONG: Assumes vault exists
    public fun withdraw(account: &signer, amount: u64) acquires Vault {
        let addr = signer::address_of(account);
        // ABORT if vault doesn't exist!
        let vault = borrow_global_mut<Vault>(addr);
        vault.balance = vault.balance - amount;
    }
    
    // CORRECT: Check existence first
    public fun withdraw_safe(account: &signer, amount: u64) acquires Vault {
        let addr = signer::address_of(account);
        assert!(exists<Vault>(addr), ERR_NO_VAULT);
        
        let vault = borrow_global_mut<Vault>(addr);
        assert!(vault.balance >= amount, ERR_INSUFFICIENT);
        vault.balance = vault.balance - amount;
    }
}
```

### Double Move/Borrow

```move
// VULNERABILITY: Multiple mutable borrows

module vulnerable::double_borrow {
    struct Pool has key { a: u64, b: u64 }
    
    // WRONG: Can't have two mutable borrows
    public fun swap(pool_addr: address) acquires Pool {
        let pool1 = borrow_global_mut<Pool>(pool_addr);
        let pool2 = borrow_global_mut<Pool>(pool_addr);  // ERROR!
        
        let temp = pool1.a;
        pool1.a = pool2.b;
        pool2.b = temp;
    }
    
    // CORRECT: Single borrow, multiple field access
    public fun swap_safe(pool_addr: address) acquires Pool {
        let pool = borrow_global_mut<Pool>(pool_addr);
        let temp = pool.a;
        pool.a = pool.b;
        pool.b = temp;
    }
}
```

---

## Attack Vector 2: Signer Authorization Issues

### Signer Validation

```move
// The 'signer' type proves account authorization

module vulnerable::auth {
    // VULNERABLE: No signer verification
    public fun transfer(
        from: address,  // Just an address, no proof!
        to: address,
        amount: u64
    ) acquires Balance {
        // WRONG: Anyone can call with any 'from' address
        let balance = borrow_global_mut<Balance>(from);
        balance.value = balance.value - amount;
        
        let to_balance = borrow_global_mut<Balance>(to);
        to_balance.value = to_balance.value + amount;
    }
    
    // SECURE: Require signer
    public fun transfer_safe(
        from: &signer,  // Proves authorization!
        to: address,
        amount: u64
    ) acquires Balance {
        let from_addr = signer::address_of(from);
        let balance = borrow_global_mut<Balance>(from_addr);
        balance.value = balance.value - amount;
        
        let to_balance = borrow_global_mut<Balance>(to);
        to_balance.value = to_balance.value + amount;
    }
}
```

### Capability Extraction

```move
// VULNERABILITY: Storing signer reference for later use

module vulnerable::escrow {
    struct Escrow has key {
        owner: address,
        // WRONG: Can't store signer, but storing address
        // allows anyone who knows address to claim
    }
    
    public fun create(account: &signer) {
        let escrow = Escrow {
            owner: signer::address_of(account),
        };
        move_to(account, escrow);
    }
    
    // VULNERABLE: Only checks address match
    public fun claim(account: &signer, escrow_addr: address) acquires Escrow {
        let escrow = borrow_global<Escrow>(escrow_addr);
        // This is actually fine because we have signer
        // But if claim took 'claimer: address' it would be vulnerable
    }
}
```

---

## Attack Vector 3: Coin/Token Vulnerabilities

### Coin Registration

```move
// Aptos requires coin registration before receiving

module vulnerable::airdrop {
    use aptos_framework::coin;
    
    // VULNERABLE: Assumes recipient is registered
    public fun airdrop<CoinType>(
        sender: &signer,
        recipient: address,
        amount: u64
    ) {
        let coins = coin::withdraw<CoinType>(sender, amount);
        // ABORT if recipient not registered for CoinType!
        coin::deposit(recipient, coins);
    }
    
    // SECURE: Check or register
    public fun airdrop_safe<CoinType>(
        sender: &signer,
        recipient: address,
        amount: u64
    ) {
        // Check if registered
        if (!coin::is_account_registered<CoinType>(recipient)) {
            // Either abort or handle differently
            abort ERR_NOT_REGISTERED
        };
        
        let coins = coin::withdraw<CoinType>(sender, amount);
        coin::deposit(recipient, coins);
    }
}
```

### Fake Coin Types

```move
// VULNERABILITY: Not verifying coin type authenticity

module vulnerable::exchange {
    // WRONG: Accepts any CoinType
    public fun swap<CoinIn, CoinOut>(
        account: &signer,
        amount_in: u64
    ): Coin<CoinOut> {
        let coins_in = coin::withdraw<CoinIn>(account, amount_in);
        // Attacker can use FakeCoin as CoinIn!
        
        // Calculate output (vulnerable to fake coin)
        let amount_out = calculate_output(amount_in);
        coin::mint<CoinOut>(amount_out)  // Assuming we can mint
    }
    
    // SECURE: Verify coin types against whitelist
    struct Config has key {
        allowed_coins: vector<TypeInfo>,
    }
    
    public fun swap_safe<CoinIn, CoinOut>(
        account: &signer,
        amount_in: u64
    ): Coin<CoinOut> acquires Config {
        // Verify CoinIn is allowed
        let config = borrow_global<Config>(@exchange);
        let coin_type = type_info::type_of<CoinIn>();
        assert!(
            vector::contains(&config.allowed_coins, &coin_type),
            ERR_INVALID_COIN
        );
        
        // Proceed with swap...
    }
}
```

---

## Attack Vector 4: Timestamp Manipulation

### Block Timestamp Usage

```move
// Aptos timestamp comes from validators

module vulnerable::timelock {
    use aptos_framework::timestamp;
    
    struct TimeLock has key {
        unlock_time: u64,
        value: u64,
    }
    
    public fun withdraw(account: &signer) acquires TimeLock {
        let addr = signer::address_of(account);
        let lock = borrow_global_mut<TimeLock>(addr);
        
        // CONSIDERATION: Timestamp is in microseconds!
        let now = timestamp::now_microseconds();
        assert!(now >= lock.unlock_time, ERR_LOCKED);
        
        // Withdraw...
    }
}

// ATTACK VECTOR:
// - Validators can slightly manipulate timestamp
// - Bounded by consensus rules
// - Don't use for high-precision timing
```

### Timestamp Precision

```move
// VULNERABILITY: Wrong timestamp units

module vulnerable::auction {
    use aptos_framework::timestamp;
    
    // WRONG: Mixing seconds and microseconds
    public fun end_auction(end_time: u64) {
        // timestamp::now_microseconds() returns MICROSECONDS
        // If end_time is in seconds, comparison is wrong!
        let now = timestamp::now_microseconds();
        assert!(now >= end_time, ERR_NOT_ENDED);
        
        // If end_time = 1700000000 (seconds since epoch)
        // now = 1700000000000000 (microseconds)
        // Comparison always passes!
    }
    
    // CORRECT: Consistent units
    public fun end_auction_safe(end_time_us: u64) {
        let now_us = timestamp::now_microseconds();
        assert!(now_us >= end_time_us, ERR_NOT_ENDED);
    }
}
```

---

## Attack Vector 5: View Function Issues

### Stale Data in View Functions

```move
// View functions read current state but can be stale

#[view]
public fun get_balance(addr: address): u64 acquires Balance {
    let balance = borrow_global<Balance>(addr);
    balance.value
    // WARNING: By the time caller acts on this, value might change
}

// ATTACK:
// 1. Attacker calls get_balance() → returns 1000
// 2. Victim checks balance via view function
// 3. Attacker withdraws in same block
// 4. Victim acts on stale data
```

### View Function Reentrancy Info Leak

```move
// View functions can expose internal state

#[view]
public fun get_internal_price(): u64 acquires Pool {
    let pool = borrow_global<Pool>(@pool_address);
    pool.internal_price
    // If internal_price differs from oracle...
    // Attacker knows arbitrage opportunity
}
```

---

## Audit Checklist

### Resource Security

```markdown
## Resource Security Review

### Storage Operations
□ All functions have correct 'acquires' annotations?
□ Resource existence checked before access?
□ No double mutable borrows?
□ Resources properly cleaned up?

### Resource Abilities
□ Valuable resources lack 'drop'?
□ 'copy' not on sensitive resources?
□ 'key' only where global storage needed?
□ 'store' permissions appropriate?

### Global Storage
□ Access patterns secure?
□ No unauthorized resource creation?
□ Resource addresses validated?
```

### Authorization

```markdown
## Authorization Review

### Signer Usage
□ All privileged functions require signer?
□ Signer address verified?
□ No address-only authorization for sensitive ops?
□ Capability pattern used correctly?

### Access Control
□ Admin functions protected?
□ Role-based access implemented correctly?
□ Upgrade authority secured?
```

### Coin/Token

```markdown
## Token Security Review

### Coin Operations
□ Recipient registration checked?
□ Coin type verification?
□ No mint authority leaks?
□ Burn permissions correct?

### Type Safety
□ Generic coin types validated?
□ No type confusion attacks?
□ Whitelist for accepted coins?
```

---

## Code Examples

### Secure Vault Implementation

```move
module secure::vault {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::timestamp;
    
    const ERR_NOT_INITIALIZED: u64 = 1;
    const ERR_ALREADY_INITIALIZED: u64 = 2;
    const ERR_INSUFFICIENT_BALANCE: u64 = 3;
    const ERR_LOCKED: u64 = 4;
    
    struct Vault has key {
        coins: Coin<AptosCoin>,
        lock_until: u64,  // Microseconds
    }
    
    public entry fun initialize(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<Vault>(addr), ERR_ALREADY_INITIALIZED);
        
        move_to(account, Vault {
            coins: coin::zero<AptosCoin>(),
            lock_until: 0,
        });
    }
    
    public entry fun deposit(
        account: &signer,
        amount: u64
    ) acquires Vault {
        let addr = signer::address_of(account);
        assert!(exists<Vault>(addr), ERR_NOT_INITIALIZED);
        
        let vault = borrow_global_mut<Vault>(addr);
        let coins = coin::withdraw<AptosCoin>(account, amount);
        coin::merge(&mut vault.coins, coins);
    }
    
    public entry fun withdraw(
        account: &signer,
        amount: u64
    ) acquires Vault {
        let addr = signer::address_of(account);
        assert!(exists<Vault>(addr), ERR_NOT_INITIALIZED);
        
        let vault = borrow_global_mut<Vault>(addr);
        
        // Check timelock
        let now = timestamp::now_microseconds();
        assert!(now >= vault.lock_until, ERR_LOCKED);
        
        // Check balance
        assert!(coin::value(&vault.coins) >= amount, ERR_INSUFFICIENT_BALANCE);
        
        let withdrawn = coin::extract(&mut vault.coins, amount);
        coin::deposit(addr, withdrawn);
    }
    
    public entry fun set_lock(
        account: &signer,
        lock_duration_seconds: u64
    ) acquires Vault {
        let addr = signer::address_of(account);
        assert!(exists<Vault>(addr), ERR_NOT_INITIALIZED);
        
        let vault = borrow_global_mut<Vault>(addr);
        let now = timestamp::now_microseconds();
        // Convert seconds to microseconds
        vault.lock_until = now + (lock_duration_seconds * 1_000_000);
    }
    
    #[view]
    public fun get_balance(addr: address): u64 acquires Vault {
        if (!exists<Vault>(addr)) {
            return 0
        };
        let vault = borrow_global<Vault>(addr);
        coin::value(&vault.coins)
    }
}
```

---

## Related Resources

- [Aptos Documentation](https://aptos.dev/)
- [Move Language Book](https://move-language.github.io/move/)
- [Aptos Security Guide](https://aptos.dev/guides/security)
- [Aptos Framework](https://github.com/aptos-labs/aptos-core/tree/main/aptos-move/framework)
