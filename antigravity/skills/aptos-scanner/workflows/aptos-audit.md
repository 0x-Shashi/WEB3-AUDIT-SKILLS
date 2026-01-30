# Aptos Move Audit Workflow

## Phase 1: Project Setup (30 min)

### 1.1 Understand Project Structure
```bash
# Check Move.toml
cat Move.toml

# List source files
find sources/ -name "*.move"

# Check dependencies
grep -A 10 "[dependencies]" Move.toml
```

### 1.2 Compile and Test
```bash
# Compile
aptos move compile

# Run tests
aptos move test

# Check test coverage
aptos move test --coverage
```

---

## Phase 2: Entry Point Analysis (1 hour)

### 2.1 Map All Entry Points
```bash
# Find all public entry functions
grep -rn "public entry fun" sources/
```

### 2.2 Create Entry Point Matrix

| Function | Module | Signers | Auth Check | acquires |
|----------|--------|---------|------------|----------|
| `initialize` | main | admin | N/A | None |
| `deposit` | vault | user | None | Vault |
| `withdraw` | vault | user | Balance | Vault |
| `admin_withdraw` | vault | admin | Admin | Vault, Config |

### 2.3 For Each Entry Point
- [ ] Who can call it?
- [ ] What resources does it modify?
- [ ] What authorization is required?
- [ ] What can go wrong?

---

## Phase 3: Signer Audit (1-2 hours)

### 3.1 Find All Signer Usage
```bash
grep -rn "&signer" sources/ --include="*.move"
```

### 3.2 Signer Verification Checklist
For each function with &signer:

```move
public entry fun some_function(
    signer: &signer,  // <- Is this verified?
    ...
) {
    // LOOK FOR:
    // 1. Direct address check
    assert!(signer::address_of(signer) == EXPECTED_ADDR, ENOT_AUTHORIZED);
    
    // 2. Role-based check
    assert!(is_admin(signer::address_of(signer)), ENOT_ADMIN);
    
    // 3. Ownership check
    assert!(signer::address_of(signer) == resource.owner, ENOT_OWNER);
}
```

### 3.3 SignerCapability Audit
```bash
# Find SignerCapability usage
grep -rn "SignerCapability" sources/
grep -rn "create_signer_with_capability" sources/
```

Verify:
- [ ] SignerCapability stored securely
- [ ] Never exposed via public function
- [ ] Only used internally

---

## Phase 4: Resource Audit (1-2 hours)

### 4.1 Find All Resources
```bash
grep -rn "struct.*has.*key" sources/
```

### 4.2 For Each Resource
- [ ] Where is it stored? (which address)
- [ ] Who can create it?
- [ ] Who can modify it?
- [ ] Who can destroy it?

### 4.3 Global Storage Access Patterns
```bash
# Find all global storage access
grep -rn "borrow_global\|borrow_global_mut" sources/
grep -rn "move_to\|move_from" sources/
```

For each access:
- [ ] exists<T> checked before borrow_global
- [ ] Address is correct (not user-controlled inappropriately)
- [ ] Authorization verified before mutation

---

## Phase 5: Coin Audit (1-2 hours)

### 5.1 Find Coin Types
```bash
grep -rn "struct.*CoinType\|Coin<\|coin::" sources/
```

### 5.2 Capability Security
```bash
grep -rn "MintCapability\|BurnCapability\|FreezeCapability" sources/
```

Verify:
- [ ] Capabilities stored in key resource
- [ ] Never exposed via public function
- [ ] Proper authorization for mint/burn

### 5.3 Coin Flow Tracing
For each function handling coins:
```move
// Trace: where do coins come from? where do they go?
coin::extract(...)  // Source
coin::deposit(...)  // Destination
coin::merge(...)    // Aggregation
```

---

## Phase 6: Math & Logic (1 hour)

### 6.1 Arithmetic Operations
```bash
grep -rn "+ \| - \| \* \| / " sources/ --include="*.move"
```

Check:
- [ ] Overflow protection (use checked math)
- [ ] Division by zero
- [ ] Underflow on subtraction

### 6.2 Comparison Logic
```bash
grep -rn "assert!\|if \|while " sources/
```

Check:
- [ ] Off-by-one errors
- [ ] Boundary conditions
- [ ] Edge cases (0, max, first, last)

---

## Phase 7: Access Control Summary (30 min)

### 7.1 Build Access Control Matrix

| Resource/Action | Admin | Owner | User | Anyone |
|-----------------|-------|-------|------|--------|
| Initialize |  | | | |
| Deposit | | |  | |
| Withdraw | |  | | |
| Emergency Withdraw |  | | | |
| Upgrade |  | | | |

### 7.2 Verify Each Permission
- [ ] Can admin role be compromised?
- [ ] Is there admin key rotation?
- [ ] Are there backdoors?

---

## Phase 8: Testing Review (1 hour)

### 8.1 Test Coverage
```bash
aptos move test --coverage
```

### 8.2 Test Quality Check
- [ ] Positive cases (happy path)
- [ ] Negative cases (unauthorized access)
- [ ] Edge cases (zero, max values)
- [ ] Failure modes

---

## Finding Templates

### Critical
```markdown
## [C-01] Missing Signer Verification in Admin Function

**Severity:** Critical

**Location:** sources/vault.move:L45

**Description:**
The `admin_withdraw` function takes an admin signer but never verifies the signer's address.

**Vulnerable Code:**
```move
public entry fun admin_withdraw(
    admin: &signer,
    amount: u64
) acquires Vault {
    // No check that admin is actually authorized!
    let vault = borrow_global_mut<Vault>(@vault);
    let coins = coin::extract(&mut vault.coins, amount);
    coin::deposit(signer::address_of(admin), coins);
}
```

**Impact:**
Any account can drain all funds from the vault.

**Recommendation:**
```move
public entry fun admin_withdraw(
    admin: &signer,
    amount: u64
) acquires Vault, Config {
    let config = borrow_global<Config>(@vault);
    assert!(signer::address_of(admin) == config.admin, ENOT_ADMIN);
    // ... rest
}
```
```

---

## Quick Reference

```bash
# Compile
aptos move compile

# Test
aptos move test

# Coverage
aptos move test --coverage

# Find signers
grep -rn "&signer" sources/

# Find resources
grep -rn "has.*key" sources/

# Find global access
grep -rn "borrow_global\|move_to" sources/

# Find capabilities
grep -rn "Capability" sources/
```

---

## Deliverables

- [ ] Entry point inventory
- [ ] Signer verification matrix
- [ ] Resource access analysis
- [ ] Coin flow diagram
- [ ] Finding report
- [ ] Recommendations
