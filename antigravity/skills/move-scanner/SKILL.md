---
name: Move Scanner
description: Aptos/Sui Move smart contract vulnerability scanner with 50+ security patterns
version: 1.0.0
author: Web3 Security Plugin
tags: [move, aptos, sui, security, audit, scanner, vulnerability]
---

# Move Scanner Skill

Comprehensive security scanner for Move-based smart contracts on Aptos and Sui blockchains. Covers Move language security patterns, resource safety, ability constraints, and blockchain-specific considerations.

## Capabilities

- **Move Language Analysis**: Resource model, abilities, generics security
- **Aptos-Specific Patterns**: Aptos framework, coin, account security
- **Sui-Specific Patterns**: Object model, shared objects, Sui framework
- **Cross-Platform Analysis**: Common Move patterns across both chains
- **Module Security**: Visibility, friend declarations, entry functions

## Vulnerability Categories

### Category 1: Resource Safety (RS)

| ID | Pattern | Severity | Platform |
|----|---------|----------|----------|
| RS-01 | Resource Duplication | Critical | Both |
| RS-02 | Resource Destruction | Critical | Both |
| RS-03 | Missing Resource Check | High | Both |
| RS-04 | Improper Resource Transfer | High | Both |
| RS-05 | Resource Leak | Medium | Both |

### Category 2: Ability Violations (AB)

| ID | Pattern | Severity | Platform |
|----|---------|----------|----------|
| AB-01 | Improper Copy Ability | High | Both |
| AB-02 | Improper Drop Ability | High | Both |
| AB-03 | Improper Store Ability | Medium | Both |
| AB-04 | Missing Key Ability | High | Both |
| AB-05 | Ability Constraint Bypass | Critical | Both |

### Category 3: Access Control (AC)

| ID | Pattern | Severity | Platform |
|----|---------|----------|----------|
| AC-01 | Missing Signer Check | Critical | Both |
| AC-02 | Missing Capability Check | Critical | Both |
| AC-03 | Unprotected Entry Function | Critical | Both |
| AC-04 | Friend Module Abuse | High | Both |
| AC-05 | Public Function Exposure | High | Both |

### Category 4: Arithmetic (AR)

| ID | Pattern | Severity | Platform |
|----|---------|----------|----------|
| AR-01 | Integer Overflow | High | Both |
| AR-02 | Integer Underflow | High | Both |
| AR-03 | Division by Zero | High | Both |
| AR-04 | Precision Loss | Medium | Both |
| AR-05 | Unchecked Cast | High | Both |

### Category 5: Aptos-Specific (AP)

| ID | Pattern | Severity | Platform |
|----|---------|----------|----------|
| AP-01 | Coin Registration Missing | High | Aptos |
| AP-02 | Missing Account Creation | High | Aptos |
| AP-03 | Event Handle Misuse | Medium | Aptos |
| AP-04 | Table Key Collision | High | Aptos |
| AP-05 | Timestamp Manipulation | Medium | Aptos |

### Category 6: Sui-Specific (SU)

| ID | Pattern | Severity | Platform |
|----|---------|----------|----------|
| SU-01 | Shared Object Contention | Medium | Sui |
| SU-02 | Object Ownership Issues | Critical | Sui |
| SU-03 | Transfer Policy Bypass | High | Sui |
| SU-04 | Dynamic Field Collision | High | Sui |
| SU-05 | Clock Manipulation | Medium | Sui |

### Category 7: Logic Errors (LG)

| ID | Pattern | Severity | Platform |
|----|---------|----------|----------|
| LG-01 | Incorrect Condition | Varies | Both |
| LG-02 | Missing Abort Condition | High | Both |
| LG-03 | Loop Bound Issues | Medium | Both |
| LG-04 | Off-by-One Errors | Medium | Both |
| LG-05 | Missing Return | High | Both |

### Category 8: Upgradeability (UP)

| ID | Pattern | Severity | Platform |
|----|---------|----------|----------|
| UP-01 | Unprotected Upgrade | Critical | Aptos |
| UP-02 | Storage Layout Breaking | Critical | Both |
| UP-03 | Module Replacement Issues | High | Both |

---

## Move Language Quick Reference

### Abilities

```move
// The four abilities in Move
struct Coin has key, store { value: u64 }  // Can be stored globally, in other structs
struct NFT has key { id: u64 }              // Global storage only
struct Ticket has store, drop { }           // Storable, can be discarded
struct Resource has key { }                 // Must be explicitly handled

// copy - Can be copied (implicitly)
// drop - Can be discarded (implicitly)  
// store - Can be stored in global storage
// key - Can be a top-level resource in global storage
```

### Resource Safety Rules

```move
// Resources WITHOUT drop must be explicitly consumed
struct ImportantData has key {
    value: u64
}

//  CORRECT - Resource explicitly moved
public fun transfer(data: ImportantData, recipient: address) {
    move_to(recipient, data);  // Moved to storage
}

//  ERROR - Resource would be dropped
public fun bad_function(data: ImportantData) {
    // Function ends without using data - COMPILE ERROR
}
```

---

## Aptos Quick Reference

### Module Structure

```move
module my_addr::my_module {
    use std::signer;
    use aptos_framework::coin;
    use aptos_framework::account;
    
    /// Resource stored under user accounts
    struct UserData has key {
        balance: u64,
    }
    
    /// Initialize module (called once)
    fun init_module(admin: &signer) {
        // Module initialization
    }
    
    /// Entry function - callable from transactions
    public entry fun deposit(user: &signer, amount: u64) acquires UserData {
        let addr = signer::address_of(user);
        // ... logic
    }
    
    /// Public function - callable from other modules
    public fun get_balance(addr: address): u64 acquires UserData {
        borrow_global<UserData>(addr).balance
    }
}
```

### Aptos Common Patterns

```move
// Coin operations
public entry fun transfer_coins<CoinType>(
    from: &signer,
    to: address,
    amount: u64
) {
    // Verify recipient can receive
    if (!coin::is_account_registered<CoinType>(to)) {
        // Handle unregistered account
    };
    coin::transfer<CoinType>(from, to, amount);
}

// Resource existence check
public fun ensure_user_data(user: &signer) {
    let addr = signer::address_of(user);
    if (!exists<UserData>(addr)) {
        move_to(user, UserData { balance: 0 });
    };
}
```

---

## Sui Quick Reference

### Module Structure

```move
module my_package::my_module {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    
    /// Owned object
    struct Sword has key, store {
        id: UID,
        strength: u64,
    }
    
    /// Shared object
    struct GameState has key {
        id: UID,
        total_swords: u64,
    }
    
    /// Create owned object
    public fun create_sword(ctx: &mut TxContext): Sword {
        Sword {
            id: object::new(ctx),
            strength: 10,
        }
    }
    
    /// Entry function with owned object
    public entry fun transfer_sword(sword: Sword, recipient: address) {
        transfer::public_transfer(sword, recipient);
    }
    
    /// Entry function with shared object
    public entry fun use_shared(state: &mut GameState) {
        state.total_swords = state.total_swords + 1;
    }
}
```

### Sui Object Types

```move
// Owned objects - single owner, no contention
transfer::transfer(obj, recipient);          // Transfer to address
transfer::public_transfer(obj, recipient);   // If has 'store' ability

// Shared objects - accessible by all, potential contention
transfer::share_object(obj);

// Immutable objects - read-only, no contention
transfer::freeze_object(obj);
```

---

## Protocol-Specific Checklists

### DeFi on Move

```markdown
## AMM/DEX Checklist
- [ ] Coin type parameters validated
- [ ] LP token math verified (no inflation attacks)
- [ ] Slippage protection implemented
- [ ] Proper capability checks for admin functions
- [ ] Resource cleanup on pool close

## Lending Protocol Checklist
- [ ] Collateral calculations verified
- [ ] Liquidation logic correct
- [ ] Interest accrual precise
- [ ] Oracle integration secure
- [ ] Bad debt handling implemented

## NFT Marketplace Checklist
- [ ] Ownership verified before transfer
- [ ] Payment and NFT swap atomic
- [ ] Royalty calculations correct
- [ ] Listing/delisting logic sound
```

---

## Analysis Commands

### Aptos

```bash
# Build
aptos move compile

# Test
aptos move test

# Publish (devnet)
aptos move publish --profile devnet

# Prove (formal verification)
aptos move prove
```

### Sui

```bash
# Build
sui move build

# Test
sui move test

# Publish
sui client publish --gas-budget 100000000
```

---

## Grep Patterns

```bash
# Find entry functions
grep -rn "public entry fun\|entry fun" sources/

# Find public functions
grep -rn "public fun" sources/

# Find friend declarations
grep -rn "friend " sources/

# Find resource definitions
grep -rn "struct.*has key\|struct.*has store" sources/

# Find global storage operations
grep -rn "move_to\|move_from\|borrow_global\|exists<" sources/

# Find signer usage
grep -rn "signer::address_of\|&signer" sources/

# Find abort conditions
grep -rn "assert!\|abort " sources/

# Find arithmetic
grep -rn "[+\-*/]" sources/ | grep -v "//"
```

---

## Resources

- [move-patterns.md](resources/move-patterns.md) - Detailed vulnerability patterns
- [aptos-security.md](resources/aptos-security.md) - Aptos-specific security guide
- [sui-security.md](resources/sui-security.md) - Sui-specific security guide

## Workflows

- [move-audit.md](workflows/move-audit.md) - Complete Move contract audit process

---

## Integration with Cyfrin Solodit

```markdown
## Search Queries for Move Findings

- "move" - All Move-related findings
- "aptos" - Aptos-specific issues
- "sui" - Sui-specific issues
- "resource" - Resource handling bugs
- "ability" - Ability constraint issues
```

