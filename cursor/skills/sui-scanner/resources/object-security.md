# Sui Object Security Deep Dive

## Object Model Overview

Sui's object-centric model is fundamentally different from account-based blockchains. Every piece of data is an object with a unique ID, version, and owner.

---

## Object Types

### 1. Owned Objects
```move
// Single address ownership
// Only owner can use in transactions
// Parallel execution possible
struct OwnedNFT has key {
    id: UID,
    data: vector<u8>
}

// Created and transferred to owner
transfer::transfer(nft, recipient);
```

**Security Considerations:**
- Only owner can pass as transaction argument
- No consensus required (fast)
- Can become "locked" if owner loses access

### 2. Shared Objects
```move
// Globally accessible
// Anyone can use in transactions
// Requires consensus (slower)
struct SharedPool has key {
    id: UID,
    balance: Balance<SUI>
}

// Made shared
transfer::share_object(pool);
```

**Security Considerations:**
- MUST have access control
- Anyone can include in transaction
- Serialization through consensus
- Cannot become owned again

### 3. Immutable Objects
```move
// Cannot be modified
// Freely accessible
// No consensus needed
struct Config has key {
    id: UID,
    max_supply: u64
}

// Made immutable
transfer::freeze_object(config);
```

**Security Considerations:**
- Truly immutable (safe)
- Good for configuration
- Cannot be updated (plan ahead)

### 4. Wrapped Objects
```move
// Object inside another object
struct Vault has key {
    id: UID,
    wrapped_coin: Coin<SUI>,  // Wrapped!
    nested: Option<NFT>       // Also wrapped
}
```

**Security Considerations:**
- Wrapped objects not directly accessible
- Must unwrap to use
- Parent object controls access
- Can hide value from balance checks

---

## Object Abilities

### Key Ability
```move
// Required for objects
// Means it can be stored on-chain with address
struct MyObject has key { id: UID }
```

### Store Ability
```move
// Can be stored inside other objects
// Can be transferred with public_transfer
struct Transferable has key, store { id: UID }
```

**Security Warning:**
```move
// With store: Anyone with ownership can transfer
transfer::public_transfer(obj, anyone);

// Without store: Only module can transfer
transfer::transfer(obj, controlled_recipient);
```

### Copy Ability
```move
// Usually NOT for objects
// Would allow duplication!
struct Copiable has copy { value: u64 }  // DANGER if key
```

### Drop Ability
```move
// Can be discarded without explicit destruction
// Usually NOT for objects
struct Droppable has drop { temp: u64 }
```

---

## Object Ownership Patterns

### Pattern 1: Direct Ownership
```move
// Simple: Object owned by address
struct SimpleNFT has key {
    id: UID,
    name: String
}

public entry fun mint(ctx: &mut TxContext) {
    let nft = SimpleNFT {
        id: object::new(ctx),
        name: string::utf8(b"My NFT")
    };
    transfer::transfer(nft, tx_context::sender(ctx));
}
```

### Pattern 2: Capability-Based Ownership
```move
// Object is shared, caps control access
struct SharedVault has key {
    id: UID,
    balance: Balance<SUI>
}

struct VaultCap has key {
    id: UID,
    vault_id: ID,
    permissions: u8  // Bitmask
}

const PERMISSION_WITHDRAW: u8 = 1;
const PERMISSION_DEPOSIT: u8 = 2;
const PERMISSION_ADMIN: u8 = 4;

public entry fun withdraw(
    vault: &mut SharedVault,
    cap: &VaultCap,
    amount: u64,
    ctx: &mut TxContext
) {
    assert!(cap.vault_id == object::id(vault), EWrongVault);
    assert!(cap.permissions & PERMISSION_WITHDRAW != 0, ENoPermission);
    
    let coin = coin::take(&mut vault.balance, amount, ctx);
    transfer::public_transfer(coin, tx_context::sender(ctx));
}
```

### Pattern 3: Parent-Child Ownership
```move
// Objects form hierarchy
struct Parent has key {
    id: UID
}

struct Child has key, store {
    id: UID,
    parent_id: ID
}

// Child added as dynamic object field
public fun add_child(parent: &mut Parent, child: Child) {
    dynamic_object_field::add(&mut parent.id, ChildKey {}, child);
}

// Access control through parent
public fun use_child(parent: &Parent): &Child {
    dynamic_object_field::borrow(&parent.id, ChildKey {})
}
```

---

## Version and Mutation

### Object Versioning
```move
// Sui automatically tracks version
// Each mutation increments version
// Critical for preventing double-spends
```

### Mutable References
```move
// &mut Object: Can modify
// &Object: Read-only
// Object: Take ownership

public entry fun modify(obj: &mut MyObject) {
    obj.value = obj.value + 1;
    // Version auto-incremented
}
```

---

## Common Vulnerabilities

### 1. Shared Object Without Access Control
```move
// VULNERABLE
public entry fun steal(pool: &mut SharedPool, ctx: &mut TxContext) {
    let all = balance::value(&pool.balance);
    let coin = coin::take(&mut pool.balance, all, ctx);
    transfer::public_transfer(coin, tx_context::sender(ctx));
}
```

### 2. Object ID Confusion
```move
// VULNERABLE: Trusting external ID
public entry fun process(
    obj: &mut MyObject,
    claimed_id: ID  // Attacker provides
) {
    assert!(claimed_id == object::id(obj), EWrongId);
    // Wait, this always passes! We're checking obj's own ID
    // Attacker can pass any obj and matching ID
}

// SECURE: Verify against known source
public entry fun process(
    obj: &mut MyObject,
    registry: &Registry
) {
    assert!(table::contains(&registry.known_objects, object::id(obj)), EUnknown);
}
```

### 3. Wrapped Object Extraction
```move
// VULNERABLE: No owner check
public entry fun extract(
    wrapper: &mut Wrapper,
    ctx: &mut TxContext
) {
    let valuable = option::extract(&mut wrapper.inner);
    transfer::public_transfer(valuable, tx_context::sender(ctx));
}

// SECURE: Owner verification
public entry fun extract(
    wrapper: &mut Wrapper,
    ctx: &mut TxContext
) {
    assert!(wrapper.owner == tx_context::sender(ctx), ENotOwner);
    let valuable = option::extract(&mut wrapper.inner);
    transfer::public_transfer(valuable, tx_context::sender(ctx));
}
```

### 4. Missing Object in Registry
```move
// VULNERABLE: Object created but not registered
public entry fun create(registry: &mut Registry, ctx: &mut TxContext) {
    let obj = MyObject { id: object::new(ctx) };
    // Forgot to register!
    transfer::transfer(obj, tx_context::sender(ctx));
}

// SECURE: Always register
public entry fun create(registry: &mut Registry, ctx: &mut TxContext) {
    let obj = MyObject { id: object::new(ctx) };
    table::add(&mut registry.objects, object::id(&obj), true);
    transfer::transfer(obj, tx_context::sender(ctx));
}
```

---

## Object Security Checklist

### Creation
- [ ] Object ID generated with `object::new(ctx)`
- [ ] Initial owner set correctly
- [ ] Registered in any necessary tables/vectors
- [ ] Correct abilities (key, store) assigned
- [ ] Events emitted for tracking

### Access
- [ ] Owned objects: Verify caller is owner (automatic)
- [ ] Shared objects: Explicit access control
- [ ] Capabilities verified against object ID
- [ ] Version checks if needed

### Modification
- [ ] Authorized caller verified
- [ ] State transitions valid
- [ ] Invariants maintained
- [ ] Events emitted

### Deletion
- [ ] Dynamic fields removed first
- [ ] Proper authorization
- [ ] Registry cleaned up
- [ ] Final events emitted

### Transfer
- [ ] Authorization checked
- [ ] Use `transfer` for controlled, `public_transfer` only if needed
- [ ] Recipient validated if necessary
- [ ] Transfer restrictions enforced

---

## Testing Object Security

```move
#[test]
fun test_shared_object_access_control() {
    use sui::test_scenario;
    
    let admin = @0xADMIN;
    let attacker = @0xBAD;
    
    let scenario = test_scenario::begin(admin);
    
    // Setup: Create shared pool with admin cap
    test_scenario::next_tx(&mut scenario, admin);
    {
        let pool = create_pool(test_scenario::ctx(&mut scenario));
        transfer::share_object(pool);
        
        let cap = AdminCap { 
            id: object::new(test_scenario::ctx(&mut scenario)),
            pool_id: /* ... */ 
        };
        transfer::transfer(cap, admin);
    };
    
    // Attack: Try to drain without cap
    test_scenario::next_tx(&mut scenario, attacker);
    {
        let pool = test_scenario::take_shared<Pool>(&scenario);
        
        // This should fail - attacker has no cap
        // withdraw(&mut pool, 1000, test_scenario::ctx(&mut scenario));
        
        test_scenario::return_shared(pool);
    };
    
    test_scenario::end(scenario);
}
```
