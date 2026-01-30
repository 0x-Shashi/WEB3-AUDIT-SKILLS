---
name: sui-scanner
description: "Comprehensive Sui Move vulnerability scanner for Move modules and smart contracts. Covers object ownership, dynamic fields, capability patterns, and Sui-specific attack vectors. Use this skill when auditing Sui programs."
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Sui Vulnerability Scanner

## Purpose

This skill provides systematic vulnerability scanning for Sui Move smart contracts. It includes:
- 50+ Sui-specific vulnerability patterns
- Object ownership security analysis
- Dynamic field vulnerabilities
- Capability pattern security
- Sui Move-specific attack vectors

---

## When to Use This Skill

**Use when:**
- Auditing Sui Move modules
- Reviewing object ownership patterns
- Analyzing capability-based access control
- Checking dynamic field security
- Scanning for Sui-specific attack vectors

**Trigger phrases:**
- "Audit this Sui contract"
- "Check this Move module for Sui"
- "Review Sui security"
- "Scan for Sui vulnerabilities"

---

## When NOT to Use

Do NOT use this skill for:
- Aptos Move (use aptos-scanner - different stdlib)
- EVM chains (use solidity-scanner)
- Solana (use solana-scanner)
- Generic Move without Sui context

---

## Sui Security Fundamentals

### Key Concepts

```

                    SUI SECURITY MODEL                    

 OBJECTS                                                  
  Everything is an object with unique ID                
  Owned (single address) vs Shared (global access)      
  Object ownership = access control                     

 CAPABILITIES                                             
  Hot Potato pattern for forced consumption             
  Witness pattern for type-level authorization          
  AdminCap pattern for privilege management             

 DYNAMIC FIELDS                                           
  Attach arbitrary data to objects                      
  Can bypass static analysis                            
  Critical security consideration                       

```

---

## Vulnerability Categories

### Category 1: Object Ownership Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| OO-01 | Improper shared object access | Critical | Missing access control on shared objects |
| OO-02 | Object ownership confusion | High | Owned vs shared object misuse |
| OO-03 | Missing object versioning | High | Version not checked on updates |
| OO-04 | Wrapped object extraction | Critical | Unauthorized object unwrapping |
| OO-05 | Object ID manipulation | Critical | Trusting external object IDs |

#### OO-01: Improper Shared Object Access

**Vulnerable Code:**
```move
// VULNERABLE: Shared object with no access control
public entry fun withdraw(
    pool: &mut Pool,
    amount: u64,
    ctx: &mut TxContext
) {
    // Anyone can withdraw from shared pool!
    let coin = coin::take(&mut pool.balance, amount, ctx);
    transfer::public_transfer(coin, tx_context::sender(ctx));
}
```

**Secure Code:**
```move
// SECURE: Proper access control with capability
public entry fun withdraw(
    pool: &mut Pool,
    cap: &WithdrawCap,
    amount: u64,
    ctx: &mut TxContext
) {
    assert!(cap.pool_id == object::id(pool), EInvalidCap);
    let coin = coin::take(&mut pool.balance, amount, ctx);
    transfer::public_transfer(coin, tx_context::sender(ctx));
}
```

---

### Category 2: Capability Pattern Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| CP-01 | Missing capability verification | Critical | Cap not validated against resource |
| CP-02 | Capability leakage | Critical | Cap can be transferred when shouldn't |
| CP-03 | Hot potato bypass | High | Forced consumption pattern broken |
| CP-04 | Witness misuse | High | Witness pattern incorrectly implemented |
| CP-05 | AdminCap centralization | Medium | Single point of failure |

#### CP-01: Missing Capability Verification

**Vulnerable Code:**
```move
// VULNERABLE: Cap not linked to specific pool
public entry fun admin_withdraw(
    pool: &mut Pool,
    _cap: &AdminCap,  // Not verified!
    amount: u64,
    ctx: &mut TxContext
) {
    // Any AdminCap works for any pool
    let coin = coin::take(&mut pool.balance, amount, ctx);
    transfer::public_transfer(coin, tx_context::sender(ctx));
}
```

**Secure Code:**
```move
// SECURE: Cap verified against specific pool
public entry fun admin_withdraw(
    pool: &mut Pool,
    cap: &AdminCap,
    amount: u64,
    ctx: &mut TxContext
) {
    assert!(cap.pool_id == object::id(pool), EWrongCap);
    let coin = coin::take(&mut pool.balance, amount, ctx);
    transfer::public_transfer(coin, tx_context::sender(ctx));
}
```

---

### Category 3: Dynamic Field Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| DF-01 | Dynamic field type confusion | Critical | Wrong type extracted |
| DF-02 | Missing existence check | High | Field may not exist |
| DF-03 | Key collision | Medium | Same key different meaning |
| DF-04 | Orphaned dynamic fields | Medium | Fields not cleaned up |
| DF-05 | Unauthorized field access | Critical | Anyone can read/modify |

#### DF-01: Dynamic Field Type Confusion

**Vulnerable Code:**
```move
// VULNERABLE: Assuming type without verification
public fun get_config(parent: &UID): &Config {
    // What if someone added a different type with this key?
    dynamic_field::borrow<vector<u8>, Config>(parent, b"config")
}
```

**Secure Code:**
```move
// SECURE: Type-safe key pattern
struct ConfigKey has copy, drop, store {}

public fun get_config(parent: &UID): &Config {
    dynamic_field::borrow<ConfigKey, Config>(parent, ConfigKey {})
}
```

---

### Category 4: Coin and Balance Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| CB-01 | Coin duplication | Critical | Same coin used twice |
| CB-02 | Balance underflow | Critical | Withdraw more than available |
| CB-03 | Missing coin type check | High | Wrong coin type accepted |
| CB-04 | Dust attack | Medium | Small amounts DoS |
| CB-05 | Flash loan abuse | High | Unchecked loan repayment |

#### CB-01: Coin Duplication

**Vulnerable Code:**
```move
// VULNERABLE: Coin reference allows reuse
public entry fun deposit(
    pool: &mut Pool,
    coin: &Coin<SUI>,  // Reference, not ownership!
    ctx: &mut TxContext
) {
    // Caller keeps the coin and pool "sees" the value
    pool.balance = pool.balance + coin::value(coin);
}
```

**Secure Code:**
```move
// SECURE: Take ownership of coin
public entry fun deposit(
    pool: &mut Pool,
    coin: Coin<SUI>,  // Ownership transfer
    ctx: &mut TxContext
) {
    let value = coin::value(&coin);
    balance::join(&mut pool.balance, coin::into_balance(coin));
}
```

---

### Category 5: Transfer and Freeze Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| TF-01 | Improper transfer method | High | Wrong transfer function used |
| TF-02 | Freeze bypass | Critical | Frozen object can still be used |
| TF-03 | Transfer during tx | Medium | Object transferred mid-function |
| TF-04 | Missing transfer restriction | High | Soulbound object transferable |

#### TF-01: Improper Transfer Method

**Vulnerable Code:**
```move
// VULNERABLE: Using public_transfer on owned object with store
public entry fun claim_nft(
    nft: NFT,  // Has store ability
    ctx: &mut TxContext
) {
    // This allows anyone to re-transfer!
    transfer::public_transfer(nft, tx_context::sender(ctx));
}
```

**Secure Code:**
```move
// SECURE: Use transfer for controlled ownership
public entry fun claim_nft(
    nft: NFT,  // Remove store ability if possible
    ctx: &mut TxContext
) {
    transfer::transfer(nft, tx_context::sender(ctx));
}
```

---

## Detection Workflow

### Step 1: Object Analysis
```
1. List all struct definitions
2. Classify: Owned vs Shared vs Wrapped
3. Check store/copy/drop abilities
4. Identify capability objects (AdminCap, etc.)
```

### Step 2: Access Control Review
```
1. Find all public/entry functions
2. Map capability requirements
3. Verify cap-to-resource binding
4. Check for missing validations
```

### Step 3: Dynamic Field Audit
```
1. Find dynamic_field/dynamic_object_field usage
2. Verify type-safe key patterns
3. Check existence before access
4. Ensure proper cleanup
```

### Step 4: Coin Flow Analysis
```
1. Trace all Coin<T> parameters
2. Verify ownership transfer (not reference)
3. Check balance operations
4. Validate coin type constraints
```

---

## Sui-Specific Checklists

### Object Security Checklist
- [ ] Shared objects have proper access control
- [ ] Object IDs not trusted from external input
- [ ] Version checks on mutable operations
- [ ] Wrapped objects properly protected
- [ ] Object abilities (store/copy/drop) appropriate

### Capability Checklist
- [ ] All capabilities linked to specific resources
- [ ] Hot potato pattern enforced where needed
- [ ] AdminCap has backup/multisig
- [ ] Witness pattern correctly implemented
- [ ] Capability transfer restrictions enforced

### Dynamic Field Checklist
- [ ] Type-safe key patterns used
- [ ] Existence checked before access
- [ ] No key collisions possible
- [ ] Orphaned fields cleaned up
- [ ] Access control on field operations

---

## Real-World Exploits

| Protocol | Vulnerability | Loss | Root Cause |
|----------|--------------|------|------------|
| Cetus DEX | Object ownership | $223M | Shared object access control |
| Turbos Finance | Capability bypass | $12M | Missing cap verification |
| FlowX Finance | Dynamic field | $2.5M | Type confusion in fields |

---

## Quick Reference Commands

```bash
# Find shared objects
grep -r "transfer::share_object" .

# Find dynamic field usage
grep -r "dynamic_field::" .

# Find capability patterns
grep -r "Cap\|Capability" . --include="*.move"

# Find public entry points
grep -r "public entry fun" .
```

---

## Integration with Other Skills

- Use `move-scanner` for generic Move patterns
- Use `token-analyzer` for Coin implementations
- Use `access-control-patterns` for capability design
- Use `methodology/llm-audit-workflow` for systematic review
