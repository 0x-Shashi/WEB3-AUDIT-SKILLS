---
id: CHAIN-SUI
title: Sui Security Guide
category: chain-guides
chain: sui
language: move
difficulty: advanced
tags: [sui, move, objects, ptb, shared-objects]
last_updated: 2026-01-31
---

# Sui Security Guide

## Overview

Sui uses the Move language with an object-centric model. Objects can be owned, shared, or immutable, creating unique security considerations around object ownership and parallel execution.

```
┌─────────────────────────────────────────────────────────────────┐
│                       SUI ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  OBJECT MODEL                                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                                                         │   │
│  │  ┌─────────┐   ┌─────────┐   ┌─────────────┐           │   │
│  │  │ Owned   │   │ Shared  │   │ Immutable   │           │   │
│  │  │ Object  │   │ Object  │   │   Object    │           │   │
│  │  └────┬────┘   └────┬────┘   └──────┬──────┘           │   │
│  │       │             │               │                   │   │
│  │  Single owner   Consensus      Read-only               │   │
│  │  Fast path      required       Never changes           │   │
│  │                                                         │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  KEY FEATURES:                                                  │
│  • Object-centric (not account-centric)                         │
│  • Parallel transaction execution                               │
│  • Programmable Transaction Blocks (PTBs)                       │
│  • No global storage                                            │
│  • Move language with Sui extensions                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Move on Sui Fundamentals

### Object Types

```move
// Sui objects must have 'key' ability and UID field

module example::my_module {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    
    // Basic owned object
    struct MyObject has key, store {
        id: UID,
        value: u64,
    }
    
    // Create owned object (goes to sender)
    public fun create(ctx: &mut TxContext) {
        let obj = MyObject {
            id: object::new(ctx),
            value: 100,
        };
        transfer::transfer(obj, tx_context::sender(ctx));
    }
    
    // Create shared object (anyone can access)
    public fun create_shared(ctx: &mut TxContext) {
        let obj = MyObject {
            id: object::new(ctx),
            value: 100,
        };
        transfer::share_object(obj);  // Now shared!
    }
    
    // Create immutable object (frozen forever)
    public fun create_immutable(ctx: &mut TxContext) {
        let obj = MyObject {
            id: object::new(ctx),
            value: 100,
        };
        transfer::freeze_object(obj);  // Now immutable!
    }
}
```

### Capabilities Pattern

```move
// Sui uses capabilities for access control

module example::admin {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;
    use sui::transfer;
    
    // Admin capability (only holder can perform admin actions)
    struct AdminCap has key, store {
        id: UID,
    }
    
    // Protected resource
    struct Treasury has key {
        id: UID,
        balance: u64,
    }
    
    // Only AdminCap holder can withdraw
    public fun withdraw(
        _admin: &AdminCap,  // Proves ownership
        treasury: &mut Treasury,
        amount: u64
    ): u64 {
        assert!(treasury.balance >= amount, EInsufficientBalance);
        treasury.balance = treasury.balance - amount;
        amount
    }
}
```

---

## Attack Vector 1: Object Ownership Confusion

### Owned vs Shared Object Attacks

```move
// VULNERABILITY: Treating owned object as if it were shared

module vulnerable::pool {
    struct Pool has key {
        id: UID,
        balance: u64,
    }
    
    // WRONG: Pool should be shared, but created as owned
    public fun create_pool(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            balance: 1000,
        };
        // Goes to creator only!
        transfer::transfer(pool, tx_context::sender(ctx));
        
        // Other users can't interact with this pool!
    }
    
    // CORRECT: Share the pool
    public fun create_shared_pool(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            balance: 1000,
        };
        transfer::share_object(pool);  // Anyone can access
    }
}
```

### Object Wrapping Attacks

```move
// Objects can be wrapped inside other objects

module vulnerable::wrapper {
    struct Wrapper<T: store> has key {
        id: UID,
        inner: T,  // Wrapped object
    }
    
    // VULNERABILITY: Wrapping shared object
    public fun wrap_object<T: key + store>(
        obj: T,
        ctx: &mut TxContext
    ) {
        // If 'obj' was shared, it's now effectively owned!
        // Original shared object becomes inaccessible
        let wrapper = Wrapper {
            id: object::new(ctx),
            inner: obj,  // DANGEROUS if obj was shared
        };
        transfer::transfer(wrapper, tx_context::sender(ctx));
    }
}

// ATTACK:
// 1. Protocol creates shared Pool object
// 2. Attacker wraps the Pool
// 3. Pool is now owned by attacker's Wrapper
// 4. No one else can access the Pool!

// DEFENSE: Don't allow wrapping of critical shared objects
// Use dynamic fields instead of wrapping
```

---

## Attack Vector 2: Shared Object Exploits

### Race Conditions

```move
// Shared objects require consensus = ordering attacks possible

module vulnerable::auction {
    struct Auction has key {
        id: UID,
        highest_bid: u64,
        highest_bidder: address,
        ended: bool,
    }
    
    public fun bid(
        auction: &mut Auction,
        amount: u64,
        ctx: &mut TxContext
    ) {
        assert!(!auction.ended, EAuctionEnded);
        assert!(amount > auction.highest_bid, EBidTooLow);
        
        // VULNERABILITY: No refund of previous bidder
        // Race condition: bid and end_auction simultaneously
        
        auction.highest_bid = amount;
        auction.highest_bidder = tx_context::sender(ctx);
    }
    
    public fun end_auction(auction: &mut Auction) {
        // If this executes before legitimate bid...
        auction.ended = true;
    }
}
```

### Shared Object DoS

```move
// Shared object access can be blocked

module vulnerable::queue {
    struct SharedQueue has key {
        id: UID,
        items: vector<u64>,
    }
    
    // VULNERABILITY: Unbounded operation on shared object
    public fun process_all(queue: &mut SharedQueue) {
        while (!vector::is_empty(&queue.items)) {
            let item = vector::pop_back(&mut queue.items);
            // Process item (could be expensive)
            process_item(item);
        }
    }
    
    // ATTACK: 
    // 1. Add thousands of items to queue
    // 2. Call process_all
    // 3. Transaction takes forever / runs out of gas
    // 4. No one else can use the queue during this time
}
```

---

## Attack Vector 3: PTB (Programmable Transaction Block) Exploits

### PTB Structure

```typescript
// PTB allows multiple operations in one transaction

const tx = new TransactionBlock();

// Multiple operations atomically
const coin1 = tx.splitCoins(tx.gas, [100]);
const coin2 = tx.splitCoins(tx.gas, [200]);
tx.mergeCoins(coin1, [coin2]);
tx.transferObjects([coin1], recipient);

// ATTACK SURFACE: 
// - Complex interaction between operations
// - Flash loan-like patterns
// - Ordering dependencies
```

### Flash Loan via PTB

```move
// PTB enables flash loans without explicit support

// In single PTB:
// 1. Borrow from pool (get coins)
// 2. Use coins for arbitrage
// 3. Return coins to pool
// All atomic!

module vulnerable::pool {
    // VULNERABLE: No flash loan protection
    public fun borrow(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        // Returns coins without immediate repayment check
        // PTB user can use coins and repay later in same tx
        coin::take(&mut pool.balance, amount, ctx)
    }
    
    public fun repay(pool: &mut Pool, payment: Coin<SUI>) {
        coin::put(&mut pool.balance, payment);
    }
}

// ATTACK:
// PTB: borrow(1000) -> manipulate_price() -> repay(1000) + profit
```

### Capability Leaking via PTB

```move
// PTB can pass capabilities between calls

// VULNERABLE: Returning capability from function
public fun get_admin_cap(admin: &AdminCap): &AdminCap {
    admin  // Returns reference to cap
    // In PTB, this reference can be used in subsequent calls
}

// ATTACK PTB:
// 1. Call get_admin_cap with legitimate cap
// 2. Use returned reference for unauthorized actions
// 3. All in same PTB

// DEFENSE: Don't return capability references
// Or use hot potato pattern
```

---

## Attack Vector 4: Type Confusion

### Generic Type Exploits

```move
// Move generics can be exploited

module vulnerable::vault {
    struct Vault<phantom T> has key {
        id: UID,
        balance: u64,
    }
    
    // VULNERABLE: No type verification
    public fun withdraw<T>(
        vault: &mut Vault<T>,
        amount: u64
    ): u64 {
        // Withdraws 'amount' regardless of T
        vault.balance = vault.balance - amount;
        amount
    }
}

// ATTACK:
// 1. Deposit 100 with type Vault<RealToken>
// 2. Create Vault<FakeToken> (different type, same ID impossible)
// Actually... Sui's object model prevents this specific attack
// But type confusion can still occur in other ways
```

### Witness Pattern Bypasses

```move
// Witness pattern for one-time initialization

module example::token {
    // One-Time Witness (OTW)
    struct TOKEN has drop {}
    
    fun init(witness: TOKEN, ctx: &mut TxContext) {
        // Can only be called once (witness is one-time)
        create_currency(witness, ...);
    }
}

// VULNERABILITY: Not using OTW correctly
module vulnerable::token {
    struct TOKEN has drop {}  // Missing 'copy' is good
    
    // WRONG: Public function that creates witness
    public fun create_witness(): TOKEN {
        TOKEN {}  // Anyone can create!
    }
    
    // CORRECT: Only in init (module initialization)
}
```

---

## Attack Vector 5: Clock and Randomness

### Clock Manipulation

```move
// Sui provides shared Clock object

module vulnerable::time_lock {
    use sui::clock::{Self, Clock};
    
    struct TimeLock has key {
        id: UID,
        unlock_time: u64,
        value: u64,
    }
    
    public fun withdraw(
        lock: &mut TimeLock,
        clock: &Clock
    ): u64 {
        // Check time
        let current_time = clock::timestamp_ms(clock);
        assert!(current_time >= lock.unlock_time, ETooEarly);
        
        // VULNERABILITY: Clock is shared object
        // Ordering: attacker's tx might execute before clock update
        // But Clock is updated by validators, so relatively safe
        
        let value = lock.value;
        lock.value = 0;
        value
    }
}
```

### Randomness Issues

```move
// Sui 1.x+ has on-chain randomness, but...

module vulnerable::lottery {
    // WRONG: Using predictable values
    public fun pick_winner(
        lottery: &mut Lottery,
        ctx: &TxContext
    ): address {
        // tx_context values are predictable!
        let seed = tx_context::epoch(ctx);  // Predictable
        let winner_index = seed % vector::length(&lottery.participants);
        *vector::borrow(&lottery.participants, winner_index)
    }
}

// SECURE: Use Sui's random module (Sui 1.x+)
module secure::lottery {
    use sui::random::{Self, Random};
    
    public fun pick_winner(
        lottery: &mut Lottery,
        random: &Random,
        ctx: &mut TxContext
    ): address {
        let generator = random::new_generator(random, ctx);
        let winner_index = random::generate_u64(&mut generator) 
            % vector::length(&lottery.participants);
        *vector::borrow(&lottery.participants, winner_index)
    }
}
```

---

## Audit Checklist

### Object Model Security

```markdown
## Object Security Review

### Ownership
□ Correct ownership type (owned/shared/immutable)?
□ Shared objects used for multi-user access?
□ Can critical shared objects be wrapped?
□ Object transfer restrictions appropriate?

### Capabilities
□ Capabilities properly protected?
□ No capability leaking in returns?
□ Hot potato pattern where needed?
□ One-Time Witness used correctly?

### Dynamic Fields
□ Dynamic field keys controlled?
□ No field name collisions?
□ Removal handled correctly?
```

### PTB Safety

```markdown
## PTB Security Review

### Flash Patterns
□ Flash loan resistance where needed?
□ Repayment enforced same transaction?
□ No profitable atomic arbitrage?

### Atomicity
□ Multi-step operations safe if partial?
□ State consistent after any step?
□ Capability usage bounded to transaction?
```

### Move-Specific

```markdown
## Move Security Review

### Types
□ Generics properly constrained?
□ Phantom types used correctly?
□ Type confusion prevented?

### Arithmetic
□ Overflow/underflow checked?
□ Division by zero handled?
□ Precision loss acceptable?

### Vectors/Collections
□ Bounded iteration?
□ Empty collection handling?
□ Index bounds checking?
```

---

## Code Examples

### Secure Shared Pool

```move
module secure::pool {
    use sui::object::{Self, UID};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::tx_context::TxContext;
    use sui::transfer;
    
    struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
        total_shares: u64,
    }
    
    struct PoolShare has key, store {
        id: UID,
        shares: u64,
    }
    
    // Create shared pool
    public fun create_pool(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            balance: balance::zero(),
            total_shares: 0,
        };
        transfer::share_object(pool);
    }
    
    // Deposit with share accounting
    public fun deposit(
        pool: &mut Pool,
        coin: Coin<SUI>,
        ctx: &mut TxContext
    ): PoolShare {
        let amount = coin::value(&coin);
        let shares = if (pool.total_shares == 0) {
            amount  // First deposit: 1:1
        } else {
            // shares = amount * total_shares / total_balance
            (amount * pool.total_shares) / balance::value(&pool.balance)
        };
        
        assert!(shares > 0, EZeroShares);
        
        coin::put(&mut pool.balance, coin);
        pool.total_shares = pool.total_shares + shares;
        
        PoolShare {
            id: object::new(ctx),
            shares,
        }
    }
    
    // Withdraw with share burning
    public fun withdraw(
        pool: &mut Pool,
        share: PoolShare,
        ctx: &mut TxContext
    ): Coin<SUI> {
        let PoolShare { id, shares } = share;
        object::delete(id);
        
        // amount = shares * total_balance / total_shares
        let amount = (shares * balance::value(&pool.balance)) / pool.total_shares;
        
        pool.total_shares = pool.total_shares - shares;
        
        coin::take(&mut pool.balance, amount, ctx)
    }
}
```

---

## Related Resources

- [Sui Documentation](https://docs.sui.io/)
- [Move Book](https://move-book.com/)
- [Sui Security Best Practices](https://docs.sui.io/guides/developer/security)
- [Sui Move Examples](https://github.com/MystenLabs/sui/tree/main/examples)
