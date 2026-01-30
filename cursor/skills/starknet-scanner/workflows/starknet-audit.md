# Starknet Audit Workflow

## Phase 1: Setup (30 min)

### 1.1 Project Overview
```bash
# Check Scarb.toml
cat Scarb.toml

# List Cairo files
find src/ -name "*.cairo"

# Check dependencies
grep -A 20 "[dependencies]" Scarb.toml
```

### 1.2 Build & Test
```bash
# Build
scarb build

# Test
scarb test

# Format check
scarb fmt --check
```

---

## Phase 2: Entry Point Analysis (1 hour)

### 2.1 Map All Entry Points
```bash
# External functions
grep -rn "#\[external(v0)\]" src/

# L1 handlers
grep -rn "#\[l1_handler\]" src/

# Constructors
grep -rn "#\[constructor\]" src/
```

### 2.2 Entry Point Matrix

| Function | Access | Caller Check | State Modified |
|----------|--------|--------------|----------------|
| `transfer` | External | Caller is owner | balances |
| `handle_deposit` | L1 Handler | L1 sender | balances |
| `admin_action` | External | Admin only | config |

---

## Phase 3: Account Abstraction (if applicable) (1-2 hours)

### 3.1 Find Account Functions
```bash
grep -rn "__validate__\|__execute__\|__validate_declare__\|__validate_deploy__" src/
```

### 3.2 __validate__ Security Checklist
- [ ] Nonce verified against tx_info
- [ ] Chain ID verified
- [ ] Signature verified correctly
- [ ] No bypass paths
- [ ] Gas estimation bounded

### 3.3 __execute__ Security Checklist
- [ ] Nonce incremented
- [ ] Only callable after validation
- [ ] Multicall handles reentrancy

---

## Phase 4: L1L2 Messaging (1-2 hours)

### 4.1 Find Message Handlers
```bash
# L1 handlers
grep -rn "#\[l1_handler\]" src/

# L2L1 messages
grep -rn "send_message_to_l1" src/
```

### 4.2 L1 Handler Checklist (for each handler)
- [ ] from_address verified against trusted L1 contract
- [ ] Message format validated
- [ ] Idempotent processing
- [ ] Proper error handling

### 4.3 L2L1 Checklist
- [ ] State changes reversible if L1 fails
- [ ] Timeout/cancellation mechanism
- [ ] Proper event emission

---

## Phase 5: Storage Analysis (1 hour)

### 5.1 Map Storage
```bash
grep -rn "#\[storage\]" src/ -A 30
```

### 5.2 Storage Checklist
- [ ] All values properly initialized
- [ ] No slot collisions possible
- [ ] Upgrade-safe layout
- [ ] No sensitive data exposed

### 5.3 Map Access
For each storage variable:
```
Variable: admin
- Read by: get_admin, require_admin
- Written by: constructor, transfer_ownership
- Access control: Only admin can write
```

---

## Phase 6: Access Control (1-2 hours)

### 6.1 Find Caller Checks
```bash
grep -rn "get_caller_address" src/
```

### 6.2 For Each External Function

| Function | Who Can Call | How Verified |
|----------|--------------|--------------|
| `transfer` | Anyone with balance | Balance check |
| `admin_withdraw` | Admin only | Caller == admin |
| `pause` | Admin only | Caller == admin |

### 6.3 Access Control Checklist
- [ ] All privileged functions have access control
- [ ] Admin address not hardcoded
- [ ] Multi-sig for critical operations (if needed)
- [ ] Ownership transfer is two-step (if applicable)

---

## Phase 7: Type Safety (1 hour)

### 7.1 Find Unsafe Patterns
```bash
# Unwrap calls
grep -rn "\.unwrap()" src/

# felt252 arithmetic
grep -rn "felt252" src/ | grep "+\|-\|*\|/"
```

### 7.2 Type Safety Checklist
- [ ] u256 used for amounts (not felt252)
- [ ] Options handled with match, not unwrap
- [ ] Results propagated correctly
- [ ] Array bounds checked

---

## Phase 8: Upgrade Analysis (30 min)

### 8.1 Find Upgrade Mechanism
```bash
grep -rn "replace_class_syscall\|upgrade" src/
```

### 8.2 Upgrade Checklist
- [ ] Upgrade requires admin authorization
- [ ] Timelock before execution (optional)
- [ ] Storage layout preserved
- [ ] Events emitted for transparency

---

## Finding Templates

### Critical
```markdown
## [C-01] L1 Handler Missing Sender Verification

**Severity:** Critical

**Location:** src/bridge.cairo:L45

**Description:**
The `handle_deposit` L1 handler does not verify the L1 sender, allowing any L1 contract to mint tokens.

**Vulnerable Code:**
```cairo
#[l1_handler]
fn handle_deposit(
    ref self: ContractState,
    from_address: felt252,  // Not verified!
    user: ContractAddress,
    amount: u256
) {
    self.mint(user, amount);
}
```

**Impact:**
Attacker can deploy L1 contract to mint unlimited tokens.

**Recommendation:**
```cairo
#[l1_handler]
fn handle_deposit(
    ref self: ContractState,
    from_address: felt252,
    user: ContractAddress,
    amount: u256
) {
    assert(from_address == self.l1_bridge.read().into(), 'Invalid sender');
    self.mint(user, amount);
}
```
```

---

## Quick Reference Commands

```bash
# Build
scarb build

# Test
scarb test

# Format
scarb fmt

# Find externals
grep -rn "#\[external" src/

# Find L1 handlers
grep -rn "#\[l1_handler\]" src/

# Find storage
grep -rn "#\[storage\]" src/

# Find caller checks
grep -rn "get_caller_address" src/

# Find asserts
grep -rn "assert(" src/
```

---

## Deliverables

- [ ] Entry point inventory
- [ ] Account abstraction analysis (if applicable)
- [ ] L1L2 message flow diagram
- [ ] Storage layout documentation
- [ ] Access control matrix
- [ ] Finding report with severity ratings
- [ ] Recommendations for each finding
