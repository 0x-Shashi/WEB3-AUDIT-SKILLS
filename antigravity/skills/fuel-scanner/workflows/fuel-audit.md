# FuelVM Audit Workflow

## Phase 1: Setup (30 min)

### 1.1 Project Structure
```bash
# Check Forc.toml
cat Forc.toml

# List Sway files
find . -name "*.sw"

# Identify project type
grep -r "contract;\|predicate;\|script;\|library;" src/
```

### 1.2 Build & Test
```bash
# Build
forc build

# Test
forc test

# Format check
forc fmt --check
```

---

## Phase 2: Contract Type Analysis (30 min)

### 2.1 Identify Components

| Component | File | Type | Purpose |
|-----------|------|------|---------|
| main.sw | contract | Core logic | Main protocol |
| auth.sw | predicate | Auth | UTXO spending |
| setup.sw | script | Script | One-time setup |

### 2.2 Dependency Map
```bash
# Check dependencies
grep -r "use\|mod" src/
```

---

## Phase 3: Function Analysis (1-2 hours)

### 3.1 Map All Functions
```bash
# Find all functions
grep -rn "fn " src/ | grep -v "//"

# Find payable
grep -rn "#\[payable\]" src/

# Find storage
grep -rn "#\[storage" src/
```

### 3.2 Function Matrix

| Function | Visibility | Payable | Storage | Auth Check |
|----------|------------|---------|---------|------------|
| `deposit` | Public | Yes | Write | None |
| `withdraw` | Public | No | Read/Write | msg_sender |
| `set_admin` | Public | No | Write | Admin only |

---

## Phase 4: Access Control (1-2 hours)

### 4.1 Find Authorization
```bash
grep -rn "msg_sender()" src/
grep -rn "require\|assert" src/
```

### 4.2 Access Control Matrix

| Function | Who Can Call | Verification |
|----------|--------------|--------------|
| `deposit` | Anyone | N/A |
| `withdraw` | Balance owner | msg_sender == owner |
| `admin_action` | Admin | msg_sender == admin |

### 4.3 Authorization Checklist
- [ ] All privileged functions check msg_sender
- [ ] Admin transfer is two-step (optional)
- [ ] No default admin (initialized properly)

---

## Phase 5: Asset Flow Analysis (1-2 hours)

### 5.1 Find Asset Operations
```bash
grep -rn "msg_amount\|msg_asset_id" src/
grep -rn "transfer\|mint\|burn" src/
```

### 5.2 Asset Flow Diagram
```
User deposits → msg_amount() verified
              → asset_id verified
              → balance updated
              
User withdraws → balance checked
              → balance updated
              → transfer() called
```

### 5.3 Asset Checklist
- [ ] msg_amount() verified on all payable
- [ ] msg_asset_id() verified (correct asset)
- [ ] Change returned if overpaid
- [ ] Mint restricted to authorized
- [ ] Burn only by owner/authorized

---

## Phase 6: Predicate Audit (1-2 hours)

### 6.1 Find Predicates
```bash
grep -rn "predicate;" src/
```

### 6.2 Predicate Security

For each predicate:
- [ ] Cannot return true unconditionally
- [ ] Proper signature verification
- [ ] Replay attack prevented
- [ ] No sensitive data exposed
- [ ] Correct identity verified

### 6.3 Common Predicate Patterns

```sway
// Good: Signature with tx_id
fn main(signer: Address) -> bool {
    let sig = tx_witness_data(0);
    let msg = tx_id();  // Unique per tx
    ec_recover_address(sig, msg) == signer
}
```

---

## Phase 7: Storage Analysis (1 hour)

### 7.1 Map Storage
```bash
grep -rn "storage {" src/ -A 20
```

### 7.2 Storage Checklist
- [ ] All reads use try_read() for uninitialized safety
- [ ] No storage slot collisions
- [ ] Bounded collection growth
- [ ] Proper initialization

### 7.3 Initialization Check
- [ ] Constructor or initializer exists
- [ ] Cannot be re-initialized
- [ ] All storage initialized before use

---

## Phase 8: Reentrancy Check (30 min)

### 8.1 Find External Calls
```bash
grep -rn "transfer\|call" src/
```

### 8.2 For Each External Call
```
Function: withdraw()
External Call: transfer() at line 45
State Update: balance update at line 48
Order: VULNERABLE - external before state

Fix: Move line 48 before line 45
```

### 8.3 CEI Pattern Verification
- [ ] Checks (require/assert) first
- [ ] Effects (state changes) second
- [ ] Interactions (external calls) last

---

## Phase 9: Script Audit (if applicable) (30 min)

### 9.1 Script Security
- [ ] Validates all inputs
- [ ] Doesn't leak sensitive data
- [ ] Handles failures gracefully
- [ ] Proper logging

---

## Finding Templates

### Critical
```markdown
## [C-01] Anyone Can Withdraw Any User's Funds

**Severity:** Critical

**Location:** src/main.sw:L45

**Description:**
The `withdraw` function does not verify that the caller owns the balance being withdrawn.

**Vulnerable Code:**
```sway
#[storage(read, write)]
fn withdraw(user: Identity, amount: u64) {
    let balance = storage.balances.get(user).read();
    require(balance >= amount, "Insufficient");
    
    storage.balances.insert(user, balance - amount);
    transfer(user, BASE_ASSET_ID, amount);
}
```

**Impact:**
Any user can drain any other user's balance.

**Recommendation:**
```sway
#[storage(read, write)]
fn withdraw(amount: u64) {
    let caller = msg_sender().unwrap();
    let balance = storage.balances.get(caller).try_read().unwrap_or(0);
    require(balance >= amount, "Insufficient");
    
    storage.balances.insert(caller, balance - amount);
    transfer(caller, BASE_ASSET_ID, amount);
}
```
```

---

## Quick Reference Commands

```bash
# Build
forc build

# Test
forc test

# Format
forc fmt

# Find functions
grep -rn "fn " src/

# Find payable
grep -rn "#\[payable\]" src/

# Find storage
grep -rn "#\[storage" src/

# Find msg_sender
grep -rn "msg_sender()" src/

# Find asset ops
grep -rn "msg_amount\|msg_asset_id" src/

# Find transfers
grep -rn "transfer\|mint\|burn" src/
```

---

## Deliverables

- [ ] Component inventory (contracts, predicates, scripts)
- [ ] Function access matrix
- [ ] Asset flow diagram
- [ ] Predicate security analysis
- [ ] Storage layout documentation
- [ ] Finding report with severity ratings
- [ ] Recommendations for each finding
