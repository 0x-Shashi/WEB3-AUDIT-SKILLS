# Aztec Contract Audit Workflow

## Phase 1: Setup (30 min)

### 1.1 Project Overview
```bash
# Check project structure
ls -la src/

# Find all Noir files
find . -name "*.nr"

# Check Nargo.toml
cat Nargo.toml
```

### 1.2 Build & Test
```bash
# Build
nargo build

# Test
nargo test

# Check for errors
nargo check
```

---

## Phase 2: Contract Structure Analysis (1 hour)

### 2.1 Map All Functions
```bash
# Public functions
grep -rn "#\[aztec(public)\]" src/

# Private functions
grep -rn "#\[aztec(private)\]" src/

# Internal functions
grep -rn "#\[aztec(internal)\]" src/
```

### 2.2 Create Function Matrix

| Function | Type | Caller Check | Notes Used | Nullifiers |
|----------|------|--------------|------------|------------|
| `transfer` | Private | Yes | Spends + Creates | Yes |
| `balance_of` | Private | Read only | Reads | No |
| `mint_public` | Public | Admin only | N/A | N/A |

---

## Phase 3: Note Analysis (1-2 hours)

### 3.1 Identify Note Types
```bash
grep -rn "struct.*Note" src/
```

For each note type:
- Fields (value, owner, randomness, etc.)
- compute_nullifier implementation
- get_header implementation
- serialize/deserialize

### 3.2 Note Security Checklist

For each note type:
- [ ] Has randomness field
- [ ] Randomness set from context
- [ ] Nullifier includes secret key
- [ ] Nullifier includes randomness
- [ ] Note can be reconstructed by owner

### 3.3 Trace Note Lifecycle

```
Creation → Encryption → Storage → Discovery → Spending
   ↓           ↓           ↓          ↓           ↓
new()    encrypt_log   insert()  get_notes  push_nullifier
```

---

## Phase 4: Nullifier Audit (1-2 hours)

### 4.1 Find Nullifier Code
```bash
grep -rn "compute_nullifier\|push_nullifier" src/
```

### 4.2 Nullifier Checklist

For each spending function:
- [ ] Nullifier computed correctly
- [ ] Nullifier pushed to context
- [ ] Owner's secret included
- [ ] Note randomness included
- [ ] No collision possible

### 4.3 Double-Spend Test Cases

```noir
#[test]
fn test_no_double_spend() {
    // Create note
    // Spend note (should succeed)
    // Try to spend same note again (should fail)
}
```

---

## Phase 5: Access Control (1-2 hours)

### 5.1 Find Authorization Checks
```bash
grep -rn "context.msg_sender\|assert.*owner" src/
```

### 5.2 Access Control Matrix

| Function | Who Can Call | How Verified |
|----------|--------------|--------------|
| `transfer` | Note owner | assert(note.owner == msg_sender) |
| `transfer_from` | Owner or authorized | authwit check |
| `admin_mint` | Admin | assert(sender == admin) |

### 5.3 Authwit Review

If authwit used:
- [ ] Authwit properly computed
- [ ] Authwit verified before action
- [ ] Authwit consumed after use (no replay)
- [ ] Authwit expiry if applicable

---

## Phase 6: Privacy Analysis (1-2 hours)

### 6.1 Public/Private Boundary
```bash
# Find public function calls from private
grep -rn "call_public_function" src/
```

### 6.2 Privacy Leak Checklist

For each public call from private:
- [ ] Arguments don't leak sensitive data
- [ ] Amount disclosure acceptable?
- [ ] Timing doesn't reveal info
- [ ] Return values handled privately

### 6.3 Note Linkability

Check for patterns that could link notes:
- [ ] Unique amounts (e.g., 1337) traceable
- [ ] Consistent timing patterns
- [ ] Same addresses always transacting

---

## Phase 7: Constraint Verification (1 hour)

### 7.1 Find All Assertions
```bash
grep -rn "assert(" src/
```

### 7.2 Constraint Completeness

| Operation | Required Constraints | Implemented |
|-----------|---------------------|-------------|
| Transfer | balance >= amount | ✓/✗ |
| Mint | caller == admin | ✓/✗ |
| Burn | caller == owner | ✓/✗ |

### 7.3 Arithmetic Safety
- [ ] No overflow in additions
- [ ] No underflow in subtractions
- [ ] Field arithmetic handled correctly

---

## Phase 8: State Synchronization (30 min)

### 8.1 Find State Updates
```bash
# Private state
grep -rn "storage\." src/

# Public state  
grep -rn "\.read()\|\.write(" src/
```

### 8.2 Synchronization Checklist
- [ ] Private burns update public total_supply
- [ ] Private mints update public total_supply
- [ ] Invariants maintained across public/private

---

## Finding Templates

### Critical - Nullifier Issue
```markdown
## [C-01] Missing Nullifier in Spend Function

**Severity:** Critical

**Location:** src/main.nr:L45

**Description:**
The `transfer` function spends notes without emitting nullifiers, allowing double-spending.

**Vulnerable Code:**
```noir
#[aztec(private)]
fn transfer(note: ValueNote, recipient: AztecAddress) {
    // note.compute_nullifier not called!
    // context.push_nullifier not called!
    
    let new_note = ValueNote::new(note.value, recipient);
    storage.notes.insert(new_note);
}
```

**Impact:**
Users can spend the same note unlimited times, creating tokens from nothing.

**Recommendation:**
```noir
#[aztec(private)]
fn transfer(note: ValueNote, recipient: AztecAddress) {
    let nullifier = note.compute_nullifier(&mut context);
    context.push_nullifier(nullifier);
    
    let new_note = ValueNote::new(note.value, recipient);
    storage.notes.insert(new_note);
}
```
```

---

## Quick Reference Commands

```bash
# Build
nargo build

# Test
nargo test

# Format
nargo fmt

# Find public functions
grep -rn "#\[aztec(public)\]" src/

# Find private functions
grep -rn "#\[aztec(private)\]" src/

# Find nullifiers
grep -rn "nullifier" src/

# Find note operations
grep -rn "insert\|get_notes" src/

# Find assertions
grep -rn "assert(" src/
```

---

## Deliverables

- [ ] Note type inventory with security analysis
- [ ] Nullifier implementation review
- [ ] Access control matrix
- [ ] Privacy boundary analysis
- [ ] Finding report with severity ratings
- [ ] Recommendations for each finding
