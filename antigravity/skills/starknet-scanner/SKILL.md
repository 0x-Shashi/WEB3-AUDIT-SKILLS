---
name: starknet-scanner
description: "Comprehensive Starknet Cairo 1.0 vulnerability scanner for smart contracts. Covers storage proofs, L1L2 messaging, account abstraction, and Starknet-specific attack vectors. Use this skill when auditing Starknet contracts."
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Starknet Vulnerability Scanner

## Purpose

This skill provides systematic vulnerability scanning for Starknet Cairo 1.0 smart contracts. It includes:
- 50+ Starknet-specific vulnerability patterns
- L1L2 messaging security
- Account abstraction vulnerabilities
- Storage and proof security
- Cairo 1.0-specific attack vectors

---

## When to Use This Skill

**Use when:**
- Auditing Starknet contracts (Cairo 1.0+)
- Reviewing L1L2 bridge security
- Analyzing account abstraction implementations
- Checking storage proof systems
- Scanning for Starknet-specific attacks

**Trigger phrases:**
- "Audit this Starknet contract"
- "Check this Cairo contract"
- "Review Starknet security"
- "Scan for Cairo vulnerabilities"

---

## When NOT to Use

Do NOT use this skill for:
- Cairo 0.x (legacy syntax)
- EVM chains (use solidity-scanner)
- Other ZK chains (Aztec uses Noir)
- General Cairo without Starknet context

---

## Starknet Security Fundamentals

### Key Concepts

```

                 STARKNET SECURITY MODEL                  

 ACCOUNT ABSTRACTION                                      
  All accounts are smart contracts                      
  Custom signature validation                           
  Multicall native support                              

 L1  L2 MESSAGING                                       
  Asynchronous message passing                          
  L1L2: Eventual inclusion                             
  L2L1: Withdrawal proofs                              

 STORAGE MODEL                                            
  Contract storage slots (felt252)                      
  Pedersen hash for addresses                           
  Storage proofs for verification                       

```

---

## Vulnerability Categories

### Category 1: Account Abstraction Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| AA-01 | Signature replay | Critical | Nonce not verified |
| AA-02 | Weak validation | Critical | __validate__ bypass |
| AA-03 | Multicall reentrancy | High | State modified in loop |
| AA-04 | Fee manipulation | Medium | Gas estimation attack |
| AA-05 | Deployment race | High | deploy + call atomicity |

#### AA-01: Signature Replay Attack

**Vulnerable Code:**
```cairo
// VULNERABLE: No nonce or chain_id check
#[external(v0)]
fn __validate__(
    ref self: ContractState,
    calls: Array<Call>
) -> felt252 {
    let tx_hash = get_tx_info().unbox().transaction_hash;
    let signature = get_tx_info().unbox().signature;
    
    // Only checks signature validity, not replay!
    assert(verify_signature(tx_hash, signature), 'Invalid sig');
    
    starknet::VALIDATED
}
```

**Secure Code:**
```cairo
// SECURE: Proper nonce handling
#[storage]
struct Storage {
    nonce: felt252,
}

#[external(v0)]
fn __validate__(
    ref self: ContractState,
    calls: Array<Call>
) -> felt252 {
    let tx_info = get_tx_info().unbox();
    
    // Verify nonce
    assert(tx_info.nonce == self.nonce.read(), 'Invalid nonce');
    
    // Verify chain_id
    assert(tx_info.chain_id == EXPECTED_CHAIN_ID, 'Wrong chain');
    
    // Verify signature
    assert(verify_signature(tx_info.transaction_hash, tx_info.signature), 'Invalid sig');
    
    starknet::VALIDATED
}

#[external(v0)]
fn __execute__(
    ref self: ContractState,
    calls: Array<Call>
) -> Array<Span<felt252>> {
    // Increment nonce
    self.nonce.write(self.nonce.read() + 1);
    
    execute_calls(calls)
}
```

---

### Category 2: L1L2 Messaging Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| L2-01 | Message replay | Critical | Message consumed check missing |
| L2-02 | Cross-domain spoofing | Critical | L1 sender not verified |
| L2-03 | Incomplete withdrawal | High | L2L1 message not finalized |
| L2-04 | Message ordering | Medium | Dependency on message order |
| L2-05 | Stuck messages | Medium | No recovery for failed L1 tx |

#### L2-01: Message Replay Attack

**Vulnerable Code:**
```cairo
// VULNERABLE: Message can be replayed
#[l1_handler]
fn handle_deposit(
    ref self: ContractState,
    from_address: felt252,
    user: ContractAddress,
    amount: u256
) {
    // No check if this message was already processed!
    self.balances.write(user, self.balances.read(user) + amount);
}
```

**Secure Code:**
```cairo
// SECURE: Use consume_message_from_l1
#[l1_handler]
fn handle_deposit(
    ref self: ContractState,
    from_address: felt252,
    user: ContractAddress,
    amount: u256
) {
    // Verify L1 sender
    assert(from_address == self.l1_bridge.read().into(), 'Invalid L1 sender');
    
    // Message automatically consumed by Starknet
    // Each L1L2 message can only be processed once
    
    self.balances.write(user, self.balances.read(user) + amount);
}
```

#### L2-02: L1 Sender Spoofing

**Vulnerable Code:**
```cairo
// VULNERABLE: Not verifying L1 sender
#[l1_handler]
fn handle_admin_action(
    ref self: ContractState,
    from_address: felt252,  // Not checked!
    action: felt252
) {
    // Anyone who sends L1L2 message can call this
    execute_admin_action(action);
}
```

**Secure Code:**
```cairo
// SECURE: Verify L1 sender is trusted
#[l1_handler]
fn handle_admin_action(
    ref self: ContractState,
    from_address: felt252,
    action: felt252
) {
    // Verify sender is our L1 contract
    assert(from_address == self.trusted_l1_address.read().into(), 'Untrusted sender');
    
    execute_admin_action(action);
}
```

---

### Category 3: Storage Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ST-01 | Storage collision | Critical | Same slot different meaning |
| ST-02 | Uninitialized storage | High | Default value assumptions |
| ST-03 | Storage slot manipulation | Medium | Predictable slots |
| ST-04 | Map key collision | Medium | Hashing issues |

#### ST-01: Storage Slot Collision

**Vulnerable Code:**
```cairo
// VULNERABLE: Storage layout changes after upgrade
// V1:
#[storage]
struct Storage {
    value_a: u256,
    value_b: u256,
}

// V2: Inserting new field
#[storage]
struct Storage {
    value_a: u256,
    new_value: u256,  // Collides with value_b slot!
    value_b: u256,    // Shifted to wrong slot
}
```

**Secure Code:**
```cairo
// SECURE: Only append new storage, never insert
// V1:
#[storage]
struct Storage {
    value_a: u256,
    value_b: u256,
}

// V2: Append only
#[storage]
struct Storage {
    value_a: u256,
    value_b: u256,
    new_value: u256,  // Added at end
}
```

---

### Category 4: Cairo-Specific Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| CS-01 | felt252 overflow | High | Arithmetic on felt252 |
| CS-02 | Enum discrimination | Medium | Invalid enum variants |
| CS-03 | Option/Result misuse | Medium | Unwrap on None/Err |
| CS-04 | Array bounds | High | Out of bounds access |

#### CS-01: felt252 Overflow

**Vulnerable Code:**
```cairo
// VULNERABLE: felt252 wraps on overflow
fn add_amounts(a: felt252, b: felt252) -> felt252 {
    a + b  // Wraps if > prime!
}
```

**Secure Code:**
```cairo
// SECURE: Use u256 for amounts or check
fn add_amounts(a: u256, b: u256) -> u256 {
    a + b  // Panics on overflow
}

// Or explicit check for felt252
fn add_amounts_felt(a: felt252, b: felt252) -> felt252 {
    let result = a + b;
    assert(result >= a, 'Overflow');
    result
}
```

---

### Category 5: Access Control Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| AC-01 | Missing caller check | Critical | get_caller_address not used |
| AC-02 | Self-call bypass | High | Contract calling itself |
| AC-03 | Delegate call issues | Critical | Untrusted library_call |
| AC-04 | Upgrade authorization | Critical | No upgrade control |

#### AC-01: Missing Caller Check

**Vulnerable Code:**
```cairo
// VULNERABLE: Anyone can call
#[external(v0)]
fn admin_withdraw(
    ref self: ContractState,
    amount: u256
) {
    // No caller verification!
    let recipient = get_caller_address();
    self.token.read().transfer(recipient, amount);
}
```

**Secure Code:**
```cairo
// SECURE: Verify caller
#[external(v0)]
fn admin_withdraw(
    ref self: ContractState,
    amount: u256
) {
    let caller = get_caller_address();
    assert(caller == self.admin.read(), 'Not admin');
    
    self.token.read().transfer(caller, amount);
}
```

---

### Category 6: Upgrade Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| UP-01 | Unauthorized upgrade | Critical | No upgrade auth |
| UP-02 | Storage incompatibility | High | Layout change |
| UP-03 | Missing upgrade event | Low | No transparency |
| UP-04 | Upgrade without timelock | Medium | Instant upgrade |

#### UP-01: Unauthorized Class Replacement

**Vulnerable Code:**
```cairo
// VULNERABLE: Anyone can upgrade
#[external(v0)]
fn upgrade(
    ref self: ContractState,
    new_class_hash: ClassHash
) {
    // No authorization!
    replace_class_syscall(new_class_hash).unwrap();
}
```

**Secure Code:**
```cairo
// SECURE: Only admin with timelock
#[external(v0)]
fn propose_upgrade(
    ref self: ContractState,
    new_class_hash: ClassHash
) {
    assert(get_caller_address() == self.admin.read(), 'Not admin');
    
    let delay = 86400_u64;  // 24 hour delay
    let effective_time = get_block_timestamp() + delay;
    
    self.pending_upgrade.write(PendingUpgrade {
        new_class_hash,
        effective_time,
    });
    
    self.emit(UpgradeProposed { new_class_hash, effective_time });
}

#[external(v0)]
fn execute_upgrade(ref self: ContractState) {
    let pending = self.pending_upgrade.read();
    assert(get_block_timestamp() >= pending.effective_time, 'Too early');
    
    replace_class_syscall(pending.new_class_hash).unwrap();
    
    self.emit(UpgradeExecuted { new_class_hash: pending.new_class_hash });
}
```

---

## Detection Workflow

### Step 1: Contract Analysis
```bash
# Find all Cairo files
find src/ -name "*.cairo"

# Find external functions
grep -r "#\[external" src/

# Find l1_handlers
grep -r "#\[l1_handler\]" src/
```

### Step 2: Account Abstraction Review
```
1. Check __validate__ implementation
2. Verify nonce handling
3. Check signature verification
4. Review multicall handling
```

### Step 3: L1L2 Security
```
1. Find all l1_handler functions
2. Verify L1 sender checks
3. Check message consumption
4. Review L2L1 message flows
```

### Step 4: Storage Analysis
```
1. Map all storage variables
2. Check upgrade compatibility
3. Verify initialization
4. Look for slot collisions
```

---

## Starknet-Specific Checklists

### Account Abstraction Checklist
- [ ] __validate__ checks nonce
- [ ] __validate__ verifies chain_id
- [ ] Signature scheme is secure
- [ ] Multicall is reentrancy-safe
- [ ] Fee estimation is bounded

### L1L2 Checklist
- [ ] L1 handler verifies from_address
- [ ] Messages are not replayable
- [ ] L2L1 withdrawals finalize correctly
- [ ] Message cancellation handled
- [ ] Stuck message recovery exists

### Upgrade Checklist
- [ ] Upgrade requires authorization
- [ ] Storage layout preserved
- [ ] Timelock or multisig for upgrades
- [ ] Upgrade events emitted
- [ ] Initialization not re-callable

---

## Real-World Exploits

| Protocol | Vulnerability | Loss | Root Cause |
|----------|--------------|------|------------|
| zkLend | L1 message | $9M | Message replay |
| JediSwap | AA validation | $2M | Signature bypass |
| 10KSwap | Storage | $500K | Slot collision |

---

## Quick Reference Commands

```bash
# Find external functions
grep -r "#\[external" src/ --include="*.cairo"

# Find L1 handlers
grep -r "#\[l1_handler\]" src/

# Find storage
grep -r "#\[storage\]" src/ -A 10

# Find caller checks
grep -r "get_caller_address" src/

# Find upgrades
grep -r "replace_class_syscall" src/

# Find assertions
grep -r "assert\|assert_eq\|assert_ne" src/
```

---

## Integration with Other Skills

- Use `cairo-scanner` for generic Cairo patterns
- Use `access-control-patterns` for auth design
- Use `upgrade-storage-patterns` for upgrade safety
- Use `cross-chain-l2-patterns` for bridge security
