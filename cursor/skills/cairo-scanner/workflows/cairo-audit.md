# Cairo Contract Audit Workflow

Systematic workflow for auditing StarkNet Cairo smart contracts.

---

## Phase 1: Setup (30 minutes)

### 1.1 Environment

```bash
# Clone and build
git clone [repo]
cd [repo]
scarb build

# Run tests
scarb test

# Check Cairo version
grep "cairo-version" Scarb.toml
```

### 1.2 Scope Mapping

```markdown
## Audit Scope

**Cairo Version:** 2.x
**Commit:** [hash]
**Dependencies:** OpenZeppelin Cairo [version]

### Contracts
| Contract | Purpose | Priority |
|----------|---------|----------|
| Bridge.cairo | L1-L2 bridge | Critical |
| Token.cairo | ERC20 implementation | High |
| Vault.cairo | Asset storage | Critical |

### Interfaces
| Interface | Implementations |
|-----------|-----------------|
| IBridge | Bridge |
| IERC20 | Token |

### Key Actors
| Actor | Permissions |
|-------|-------------|
| Owner | Upgrade, pause |
| User | Deposit, withdraw |
| Relayer | Complete L1 messages |
```

---

## Phase 2: Contract Structure Analysis (1-2 hours)

### 2.1 Per-Contract Template

```markdown
## Contract: [Name]

### Storage Layout
| Field | Type | Purpose |
|-------|------|---------|
| owner | ContractAddress | Admin |
| balances | Map<Addr, u256> | User balances |
| total_supply | u256 | Total tokens |

### External Functions
| Function | Access | State Change |
|----------|--------|--------------|
| transfer | Anyone | Write |
| mint | Owner | Write |
| balance_of | Anyone | Read |

### L1 Handlers
| Handler | Purpose | L1 Origin |
|---------|---------|-----------|
| handle_deposit | Process L1 deposits | L1Bridge |

### Events
| Event | When Emitted |
|-------|--------------|
| Transfer | On transfer/mint/burn |
| Deposit | On L1 message processed |

### Components Used
| Component | Purpose |
|-----------|---------|
| OwnableComponent | Access control |
| ERC20Component | Token logic |
```

---

## Phase 3: Access Control Audit (2-3 hours)

### 3.1 Function Permission Matrix

```markdown
## Permission Matrix

| Function | Signer Check | Owner Check | Other Check |
|----------|--------------|-------------|-------------|
| transfer | ✅ caller | ❌ | ❌ |
| mint | ✅ caller | ✅ | ❌ |
| upgrade | ✅ caller | ✅ | ❌ |
| handle_deposit | N/A (L1) | ❌ | ✅ L1 origin |

### Issues Found
- [ ] None / [Issue description]
```

### 3.2 Access Control Patterns

```cairo
// Check each pattern is correctly implemented

// 1. Owner check
fn only_owner(self: @ContractState) {
    let caller = get_caller_address();
    let owner = self.owner.read();
    assert(!caller.is_zero(), 'Invalid caller');
    assert(caller == owner, 'Not owner');
}

// 2. L1 origin check
#[l1_handler]
fn handle_message(ref self: ContractState, from_address: felt252, ...) {
    assert(from_address == self.l1_contract.read(), 'Invalid L1 sender');
}

// 3. Role check (if using roles)
fn only_role(self: @ContractState, role: felt252) {
    let caller = get_caller_address();
    assert(self.has_role(role, caller), 'Missing role');
}
```

---

## Phase 4: Storage Security (1-2 hours)

### 4.1 Storage Analysis

```markdown
## Storage Security

### Initialization Check
| Field | Initialized In | Zero Check |
|-------|----------------|------------|
| owner | constructor | ✅ |
| l1_contract | initialize | ✅ |
| token | initialize | ❌ ISSUE |

### Upgrade Safety
| Field | Same Position | Type Change |
|-------|---------------|-------------|
| owner | ✅ v1 slot 0 | ❌ |
| balances | ✅ v1 slot 1 | ❌ |
| new_field | ✅ appended | N/A |
```

### 4.2 Grep for Storage Issues

```bash
# Find storage reads without prior writes
grep -rn ".read()" src/ | grep -v "constructor\|initialize"

# Find storage variables
grep -rn "#\[storage\]" -A 20 src/

# Find writes
grep -rn ".write(" src/
```

---

## Phase 5: Arithmetic Review (1-2 hours)

### 5.1 Operation Inventory

```markdown
## Arithmetic Operations

| Location | Operation | Type | Checked? |
|----------|-----------|------|----------|
| token:45 | a + b | u256 | ✅ |
| vault:78 | a - b | u256 | ❌ ISSUE |
| fees:23 | a * b / c | u128 | ✅ |
```

### 5.2 Cairo Arithmetic Patterns

```cairo
// VERIFY: Overflow-safe patterns used

// ✅ Checked add
use core::integer::u256_checked_add;
let result = u256_checked_add(a, b).expect('Overflow');

// ✅ Checked sub
let result = u256_checked_sub(a, b).expect('Underflow');

// ✅ Safe division (check divisor)
assert(divisor > 0, 'Division by zero');
let result = a / divisor;

// ❌ Unsafe
let result = a + b;  // May overflow in some contexts
```

---

## Phase 6: L1-L2 Messaging (if applicable) (2-3 hours)

### 6.1 L1 Handler Analysis

```markdown
## L1 Handler: handle_deposit

### Validation Checklist
- [ ] from_address verified against expected L1 contract
- [ ] All payload parameters validated
- [ ] Zero address checks for recipients
- [ ] Amount validation (> 0, within bounds)
- [ ] State properly updated
- [ ] Event emitted

### Code Review
```cairo
#[l1_handler]
fn handle_deposit(...) {
    // Each line reviewed for security
}
```

### Issues
- [None or findings]
```

### 6.2 L2 → L1 Message Analysis

```markdown
## L2 → L1 Message: withdraw

### Validation Checklist
- [ ] Caller authorized
- [ ] Amount validated
- [ ] Tokens burned BEFORE message sent
- [ ] Payload format matches L1 expectation
- [ ] Nonce included for replay protection
- [ ] Event emitted

### Payload Format
| Index | Field | Type | Notes |
|-------|-------|------|-------|
| 0 | recipient | felt252 | L1 address |
| 1 | amount_low | felt252 | u256 low bits |
| 2 | amount_high | felt252 | u256 high bits |
| 3 | nonce | felt252 | Replay protection |
```

---

## Phase 7: Logic Review (3-4 hours)

### 7.1 Function-by-Function Analysis

```markdown
## Function: [name]

### Purpose
[What this function does]

### Input Validation
| Parameter | Type | Validated? | How? |
|-----------|------|------------|------|
| amount | u256 | ✅ | > 0 check |
| recipient | Addr | ✅ | !is_zero() |

### State Changes
| Variable | Before | After |
|----------|--------|-------|
| balance | x | x - amount |
| total | y | y - amount |

### External Calls
| Target | Method | Purpose |
|--------|--------|---------|
| token | transfer | Move tokens |

### Return Value
- Type: bool
- Conditions: true on success

### Invariants Affected
- Total supply = sum of all balances

### Issues
- [None or findings]
```

---

## Phase 8: Cairo-Specific Checks (1-2 hours)

### 8.1 Felt252 Issues

```markdown
## Felt252 Analysis

### Conversions Found
| Location | From | To | Safe? |
|----------|------|-----|-------|
| line 45 | u256 | felt252 | ❌ |
| line 78 | felt252 | u128 | ✅ handled |
```

### 8.2 Option/Result Handling

```bash
# Find unwrap usage
grep -rn ".unwrap()" src/

# Find unhandled Options
grep -rn "Option::" src/ | grep -v "Some\|None\|match\|if let"
```

### 8.3 Component Integration

```markdown
## Component Security

| Component | Initialized? | Events Emitted? |
|-----------|--------------|-----------------|
| Ownable | ✅ constructor | ✅ |
| ERC20 | ✅ constructor | ✅ |
```

---

## Phase 9: Upgrade Security (if upgradeable) (1 hour)

### 9.1 Upgrade Analysis

```markdown
## Upgrade Security

### Access Control
- [ ] Only owner can upgrade
- [ ] Upgrade function protected

### Storage Layout
- [ ] No field reordering
- [ ] No field removal
- [ ] New fields appended only
- [ ] Types unchanged

### Events
- [ ] Upgrade event emitted

### Code
```cairo
fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
    self.only_owner();
    assert(!new_class_hash.is_zero(), 'Invalid class');
    self.emit(Upgraded { new_class_hash });
    starknet::replace_class_syscall(new_class_hash);
}
```
```

---

## Phase 10: Testing (2-4 hours)

### 10.1 Attack Tests

```cairo
#[cfg(test)]
mod attack_tests {
    #[test]
    #[should_panic(expected: ('Not owner',))]
    fn test_unauthorized_upgrade() {
        let mut state = setup();
        let attacker = contract_address_const::<'attacker'>();
        set_caller_address(attacker);
        
        // Should fail
        state.upgrade(class_hash);
    }
    
    #[test]
    #[should_panic(expected: ('Invalid L1 sender',))]
    fn test_invalid_l1_origin() {
        // Test L1 handler with wrong origin
    }
}
```

### 10.2 Edge Cases

```cairo
#[test]
fn test_zero_amount_transfer() { /* ... */ }

#[test]
fn test_max_amount_operations() { /* ... */ }

#[test]
fn test_self_transfer() { /* ... */ }
```

---

## Quick Grep Audit

```bash
# Access control
grep -rn "get_caller_address\|only_owner\|assert(" src/

# Storage
grep -rn ".read()\|.write(" src/

# External calls
grep -rn "Dispatcher\|call_contract" src/

# L1 messaging
grep -rn "#\[l1_handler\]\|send_message_to_l1" src/

# Arithmetic
grep -rn "[+\-*/]=\|checked_add\|checked_sub" src/

# Upgrades
grep -rn "replace_class_syscall\|ClassHash" src/

# Dangerous patterns
grep -rn ".unwrap()\|panic\|assert(" src/
```

---

## Audit Completion Checklist

### Access Control
- [ ] All external functions have appropriate access control
- [ ] Owner functions protected
- [ ] L1 handlers verify origin
- [ ] Zero address checks present

### Storage
- [ ] All storage initialized properly
- [ ] No storage collisions
- [ ] Upgrade-safe layout

### Arithmetic
- [ ] Overflow protection where needed
- [ ] Underflow protection where needed
- [ ] Division by zero prevented
- [ ] Precision loss acceptable

### L1-L2 Messaging
- [ ] L1 origin verified
- [ ] Payload format matches L1 exactly
- [ ] Replay protection implemented
- [ ] Events emitted for tracking

### Logic
- [ ] All paths return correctly
- [ ] Edge cases handled
- [ ] Invariants maintained

### Cairo-Specific
- [ ] Felt252 conversions safe
- [ ] Options/Results handled
- [ ] Components properly integrated
- [ ] Traits correctly implemented

### Testing
- [ ] Unit tests pass
- [ ] Attack tests written
- [ ] Edge cases tested
