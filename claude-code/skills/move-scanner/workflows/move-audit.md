# Move Contract Audit Workflow

Systematic workflow for auditing Move smart contracts on Aptos and Sui.

---

## Phase 1: Setup (30 minutes)

### 1.1 Environment Setup

**Aptos:**
```bash
git clone [repo]
cd [repo]
aptos move compile
aptos move test
```

**Sui:**
```bash
git clone [repo]
cd [repo]
sui move build
sui move test
```

### 1.2 Scope Mapping

```markdown
## Audit Scope

**Platform:** Aptos / Sui
**Move Version:** [version]
**Commit:** [hash]

### Modules
| Module | Purpose | Priority |
|--------|---------|----------|
| pool | AMM logic | Critical |
| token | Token impl | High |
| admin | Admin funcs | Critical |

### Entry Functions
| Function | Module | Access |
|----------|--------|--------|
| swap | pool | Public |
| add_liquidity | pool | Public |
| set_fee | admin | Admin |

### Resources/Objects
| Type | Location | Purpose |
|------|----------|---------|
| Pool | pool | Pool state |
| LPToken | token | LP shares |
| AdminCap | admin | Admin auth |
```

---

## Phase 2: Module Structure Analysis (1-2 hours)

### 2.1 Per-Module Template

```markdown
## Module: [name]

### Dependencies
| Use | Purpose |
|-----|---------|
| std::signer | Signer operations |
| aptos_framework::coin | Coin operations |

### Structs
| Struct | Abilities | Purpose |
|--------|-----------|---------|
| Pool | key, store | Pool state |
| Config | key | Configuration |

### Constants
| Name | Value | Purpose |
|------|-------|---------|
| E_NOT_OWNER | 1 | Error code |
| FEE_BPS | 30 | Fee basis points |

### Functions
| Function | Visibility | Entry? | Acquires |
|----------|------------|--------|----------|
| init_module | private | no | - |
| swap | public | yes | Pool |
| get_balance | public | no | Pool |

### Friend Declarations
| Friend Module | Purpose |
|---------------|---------|
| admin | Admin access |
```

---

## Phase 3: Ability Analysis (1 hour)

### 3.1 Ability Audit

```markdown
## Ability Analysis

### Value-Bearing Structs
| Struct | copy | drop | store | key | Correct? |
|--------|------|------|-------|-----|----------|
| Coin | ❌ | ❌ | ✅ | ✅ | ✅ |
| LPToken | ❌ | ❌ | ✅ | ✅ | ✅ |
| NFT | ❌ | ❌ | ✅ | ✅ | ✅ |

### Capability Structs
| Struct | copy | drop | store | key | Correct? |
|--------|------|------|-------|-----|----------|
| AdminCap | ❌ | ❌ | ✅ | ✅ | ✅ |
| MintCap | ❌ | ❌ | ✅ | ✅ | ✅ |

### Issues Found
- [ ] None / [Issue]
```

### 3.2 Ability Red Flags

```move
// ❌ RED FLAG: copy on value-bearing struct
struct Coin has copy, key, store { value: u64 }

// ❌ RED FLAG: drop on valuable resource
struct NFT has drop, key { id: u64 }

// ✅ CORRECT: No copy/drop on valuable structs
struct SafeCoin has key, store { value: u64 }
```

---

## Phase 4: Access Control Audit (2-3 hours)

### 4.1 Entry Function Analysis

```markdown
## Entry Function: [name]

### Parameters
| Param | Type | Purpose |
|-------|------|---------|
| user | &signer | Caller auth |
| amount | u64 | Transfer amt |

### Access Control
- [ ] Signer verified
- [ ] Capability checked
- [ ] Ownership verified

### Authorization Flow
1. [Step 1]
2. [Step 2]
```

### 4.2 Access Control Matrix

```markdown
| Function | Auth Type | Verified? | Notes |
|----------|-----------|-----------|-------|
| swap | Public | N/A | Anyone |
| add_liquidity | Public | N/A | Anyone |
| set_fee | AdminCap | ✅ | |
| upgrade | UpgradeCap | ✅ | |
| mint | MintCap | ❌ ISSUE | Missing |
```

---

## Phase 5: Resource/Object Safety (2-3 hours)

### 5.1 Resource Lifecycle (Aptos)

```markdown
## Resource: [Name]

### Creation
- Function: `create()`
- Who: Admin only
- Validation: ✅

### Storage
- Location: Under owner address
- borrow_global: ✅ exists check
- borrow_global_mut: ✅ auth check

### Destruction
- Function: `destroy()`
- Cleanup: ✅ All values handled
- Orphans: ❌ None
```

### 5.2 Object Lifecycle (Sui)

```markdown
## Object: [Name]

### Creation
- Function: `create()`
- Type: Owned / Shared / Immutable
- Transfer: ✅ Transferred to sender

### Consumption
- Functions that consume: `destroy()`, `merge()`
- All paths return/transfer: ✅

### Dynamic Fields
- Keys unique: ✅
- Collision possible: ❌
```

---

## Phase 6: Arithmetic Review (1-2 hours)

### 6.1 Operation Inventory

```markdown
## Arithmetic Operations

| Location | Operation | Type | Overflow Safe? |
|----------|-----------|------|----------------|
| pool:45 | a + b | u64 | ✅ Move aborts |
| pool:78 | a * b / c | u128 | ⚠️ Check order |
| fee:23 | a - b | u64 | ❌ No check |
```

### 6.2 Precision Analysis

```markdown
## Precision Issues

### LP Token Calculation
Location: pool.move:156
```move
let lp_amount = (deposit * total_lp) / total_reserves;
```
Issue: Division before multiplication can lose precision
Fix: Use u128 intermediates
```

---

## Phase 7: Platform-Specific Audit

### 7.1 Aptos Checks

```markdown
## Aptos-Specific

### Coin Operations
- [ ] Registration checked before deposit
- [ ] MintCapability secured
- [ ] BurnCapability secured

### Account Operations
- [ ] exists_at checked before borrow
- [ ] SignerCapability stored securely
- [ ] Resource account properly initialized

### Tables
- [ ] Key collision prevented
- [ ] Iteration handled (SmartTable if needed)

### Events
- [ ] All state changes emit events
- [ ] EventHandle properly managed
```

### 7.2 Sui Checks

```markdown
## Sui-Specific

### Object Model
- [ ] Object type appropriate (owned/shared/immutable)
- [ ] Shared objects minimized (contention)
- [ ] Objects not silently consumed

### Transfer Operations
- [ ] transfer vs public_transfer correct
- [ ] TransferPolicy enforced (if applicable)
- [ ] Publisher authority verified

### Dynamic Fields
- [ ] Keys are unique (typed keys)
- [ ] Collision protection in place
- [ ] Cleanup on parent destruction

### Time
- [ ] Clock usage tolerates manipulation
- [ ] No high-precision timing reliance
```

---

## Phase 8: Logic Review (3-4 hours)

### 8.1 Function-by-Function

```markdown
## Function: swap

### Purpose
Exchange token A for token B

### Input Validation
| Input | Type | Validated? | How? |
|-------|------|------------|------|
| amount_in | u64 | ✅ | > 0 check |
| min_out | u64 | ✅ | Used in slippage |

### State Changes
| State | Before | After |
|-------|--------|-------|
| reserve_a | x | x + amount_in |
| reserve_b | y | y - amount_out |

### Invariants
- [ ] k = reserve_a * reserve_b constant (AMM)
- [ ] amount_out >= min_out (slippage)

### Return Value
- Type: Coin<B>
- Correct: ✅
```

---

## Phase 9: Testing (2-4 hours)

### 9.1 Attack Tests

**Aptos:**
```move
#[test(admin = @0x1, attacker = @0x2)]
#[expected_failure(abort_code = E_NOT_ADMIN)]
fun test_unauthorized_admin_action(
    admin: &signer,
    attacker: &signer
) {
    init_module(admin);
    admin_action(attacker);  // Should fail
}
```

**Sui:**
```move
#[test]
#[expected_failure(abort_code = E_NOT_OWNER)]
fun test_unauthorized_fails() {
    let mut scenario = test_scenario::begin(@0x1);
    // Setup...
    test_scenario::end(scenario);
}
```

### 9.2 Edge Cases

```move
#[test]
fun test_zero_amount() { /* Should fail or handle */ }

#[test]
fun test_max_amount() { /* Check overflow */ }

#[test]
fun test_empty_pool() { /* First deposit edge case */ }
```

---

## Quick Grep Audit

```bash
# Entry functions
grep -rn "public entry fun\|entry fun" sources/

# Public functions
grep -rn "public fun" sources/

# Friend declarations
grep -rn "friend " sources/

# Struct definitions with abilities
grep -rn "struct.*has" sources/

# Signer usage
grep -rn "&signer\|signer::" sources/

# Global storage (Aptos)
grep -rn "move_to\|move_from\|borrow_global\|exists<" sources/

# Assertions
grep -rn "assert!\|abort " sources/

# Arithmetic
grep -rn "[+\-*/]" sources/ | grep -v "//"

# Object operations (Sui)
grep -rn "transfer::\|object::new\|share_object" sources/
```

---

## Audit Completion Checklist

### Abilities
- [ ] No `copy` on value-bearing structs
- [ ] No `drop` on valuable resources
- [ ] Appropriate abilities for each struct

### Access Control
- [ ] All entry functions have appropriate access control
- [ ] Capabilities properly secured
- [ ] Signer checks present where needed
- [ ] Friend declarations minimal and necessary

### Resource/Object Safety
- [ ] All resources properly consumed or stored
- [ ] No resource leaks
- [ ] Object ownership correctly handled
- [ ] Dynamic fields have unique keys

### Arithmetic
- [ ] Overflow/underflow considered
- [ ] Division precision handled
- [ ] Checked operations where needed

### Platform-Specific
- [ ] Aptos: Coin registration, Tables, Events
- [ ] Sui: Object model, Transfer policy, Clock

### Logic
- [ ] All paths return/abort correctly
- [ ] Invariants maintained
- [ ] Edge cases handled

### Testing
- [ ] Unit tests pass
- [ ] Attack tests written
- [ ] Edge cases covered

