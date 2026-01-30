# Sui Move Audit Workflow

## Phase 1: Project Understanding (30 min)

### 1.1 Gather Documentation
```bash
# Check for docs
ls docs/ README.md DESIGN.md

# Check Move.toml for dependencies
cat Move.toml
```

### 1.2 Identify Modules
```bash
# List all Move files
find sources/ -name "*.move" | head -20

# Count total modules
find sources/ -name "*.move" | wc -l
```

### 1.3 Architecture Overview
Questions to answer:
- What is the main purpose?
- What objects are shared vs owned?
- What capabilities exist?
- What external dependencies?

---

## Phase 2: Object Analysis (1-2 hours)

### 2.1 Catalog All Structs
```bash
# Find all structs
grep -r "struct.*has.*key" sources/ --include="*.move"

# Categorize by abilities
grep -r "has key, store" sources/  # Transferable
grep -r "has key {" sources/       # Non-transferable
```

### 2.2 Ownership Classification
For each struct with `key`:
```
[ ] Is it shared? (share_object called)
[ ] Is it owned? (transfer to address)
[ ] Is it immutable? (freeze_object)
[ ] Is it wrapped? (inside another object)
```

### 2.3 Object Relationships
```
Draw diagram:
- Parent-child relationships
- Capability-to-resource links
- Dynamic field attachments
```

---

## Phase 3: Access Control Audit (2-3 hours)

### 3.1 Map Entry Points
```bash
# All public entry functions
grep -r "public entry fun" sources/ --include="*.move"
```

### 3.2 For Each Entry Point

| Function | Objects | Required Auth | Verified? |
|----------|---------|---------------|-----------|
| `withdraw` | Pool (shared) | AdminCap | ✓/✗ |
| `deposit` | Pool (shared) | None | N/A |
| ... | ... | ... | ... |

### 3.3 Capability Verification
```move
// Check pattern for each cap usage:
public entry fun sensitive_action(
    resource: &mut Resource,
    cap: &SomeCap,  // Is this verified?
    ctx: &mut TxContext
) {
    // LOOK FOR THIS:
    assert!(cap.resource_id == object::id(resource), EWrongCap);
}
```

### 3.4 Shared Object Audit
For each shared object:
```
[ ] All mutating functions have access control
[ ] Read functions are safe
[ ] No way to drain/corrupt without auth
```

---

## Phase 4: Coin and Balance Security (1-2 hours)

### 4.1 Find All Coin Operations
```bash
grep -r "Coin<\|Balance<" sources/ --include="*.move"
grep -r "coin::take\|coin::put\|coin::split" sources/
grep -r "balance::join\|balance::split" sources/
```

### 4.2 Coin Flow Tracing
For each function handling coins:
```
[ ] Coins passed by value (not reference)
[ ] Balance operations correct
[ ] No dust attack vectors
[ ] Flash loan properly enforced
```

### 4.3 Balance Invariant Checks
```move
// Verify total balance conserved
// Before operation: total_in
// After operation: total_in == total_out + fees
```

---

## Phase 5: Dynamic Field Audit (1 hour)

### 5.1 Find Dynamic Field Usage
```bash
grep -r "dynamic_field::\|dynamic_object_field::" sources/
```

### 5.2 Key Type Analysis
```
[ ] Using type-safe keys (not strings/vectors)
[ ] No key collision possible
[ ] Existence checked before access
```

### 5.3 UID Exposure
```
[ ] UID never returned as mutable reference
[ ] Dynamic field access controlled
```

---

## Phase 6: Edge Cases (1-2 hours)

### 6.1 Numeric Bounds
```move
// Check for:
// - Overflow in arithmetic
// - Division by zero
// - Underflow in subtraction
```

### 6.2 Empty/Zero States
```
[ ] Zero amount operations handled
[ ] Empty collections handled
[ ] First user edge cases
[ ] Last user edge cases
```

### 6.3 Reentrancy (Limited in Sui)
```
// Sui is mostly safe due to object ownership
// But check for:
// - Programmable transactions
// - Shared object ordering
```

---

## Phase 7: Upgrade Analysis (30 min)

### 7.1 UpgradeCap Location
```bash
# Find upgrade cap handling
grep -r "UpgradeCap\|upgrade" sources/
```

### 7.2 Upgrade Safety
```
[ ] UpgradeCap protected (multisig, timelock)
[ ] Upgrade policy appropriate
[ ] Storage compatibility maintained
```

---

## Phase 8: Testing Review (1 hour)

### 8.1 Test Coverage
```bash
# Find all tests
grep -r "#\[test\]" sources/ tests/
```

### 8.2 Critical Path Testing
```
[ ] Access control tests (negative cases)
[ ] Balance invariant tests
[ ] Edge case tests
[ ] Failure mode tests
```

---

## Finding Templates

### Critical Finding
```markdown
## [C-01] Shared Object Missing Access Control

**Severity:** Critical

**Location:** sources/pool.move:L45

**Description:**
The `withdraw` function allows anyone to drain the shared pool.

**Vulnerable Code:**
```move
public entry fun withdraw(
    pool: &mut Pool,
    amount: u64,
    ctx: &mut TxContext
) {
    // No access control!
    let coin = coin::take(&mut pool.balance, amount, ctx);
    transfer::public_transfer(coin, tx_context::sender(ctx));
}
```

**Impact:**
Complete loss of all funds in the pool.

**Recommendation:**
Add capability verification:
```move
public entry fun withdraw(
    pool: &mut Pool,
    cap: &WithdrawCap,
    amount: u64,
    ctx: &mut TxContext
) {
    assert!(cap.pool_id == object::id(pool), EInvalidCap);
    // ...
}
```
```

### High Finding
```markdown
## [H-01] Capability Not Verified Against Resource

**Severity:** High
...
```

---

## Quick Commands Reference

```bash
# Object analysis
grep -r "struct.*has.*key" sources/
grep -r "share_object\|transfer::transfer" sources/

# Access control
grep -r "public entry fun\|public fun" sources/
grep -r "assert!" sources/

# Coin operations
grep -r "Coin<\|Balance<\|coin::\|balance::" sources/

# Dynamic fields
grep -r "dynamic_field\|dynamic_object_field" sources/

# Testing
sui move test
sui move test --coverage
```

---

## Deliverables Checklist

- [ ] Object inventory with ownership classification
- [ ] Access control matrix
- [ ] Coin flow diagram
- [ ] Finding report (Critical/High/Medium/Low/Info)
- [ ] Recommendations for each finding
- [ ] Test coverage assessment
