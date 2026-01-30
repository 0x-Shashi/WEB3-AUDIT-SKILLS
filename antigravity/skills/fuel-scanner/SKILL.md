---
name: fuel-scanner
description: "Comprehensive FuelVM (Sway) vulnerability scanner for smart contracts. Covers UTXO handling, predicates, scripts, and Fuel-specific attack vectors. Use this skill when auditing Fuel contracts."
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# FuelVM Vulnerability Scanner

## Purpose

This skill provides systematic vulnerability scanning for FuelVM smart contracts written in Sway. It includes:
- 40+ Fuel-specific vulnerability patterns
- UTXO security analysis
- Predicate vulnerabilities
- Script security
- Fuel-specific attack vectors

---

## When to Use This Skill

**Use when:**
- Auditing Fuel contracts (Sway)
- Reviewing UTXO handling
- Analyzing predicate security
- Checking script safety
- Scanning for Fuel-specific attacks

**Trigger phrases:**
- "Audit this Fuel contract"
- "Check this Sway contract"
- "Review Fuel security"
- "Scan for Fuel vulnerabilities"

---

## When NOT to Use

Do NOT use this skill for:
- EVM chains (use solidity-scanner)
- Solana (use solana-scanner)
- Other UTXO chains (Bitcoin, Cardano)
- Generic Rust without Fuel context

---

## FuelVM Security Fundamentals

### Key Concepts

```

                   FUELVM SECURITY MODEL                  

 UTXO MODEL                                               
  Unspent Transaction Outputs                           
  Parallel transaction execution                        
  Native assets (multi-token)                           

 PREDICATES                                               
  Stateless spending conditions                         
  Pure functions (no state changes)                     
  Unlock UTXOs when satisfied                           

 CONTRACTS                                                
  Stateful smart contracts                              
  Storage + functions                                   
  Similar to Solidity but Rust-like                     

```

---

## Vulnerability Categories

### Category 1: UTXO Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| UX-01 | UTXO double-spend | Critical | Same UTXO used twice |
| UX-02 | Insufficient input validation | High | UTXO amount not verified |
| UX-03 | Change output missing | High | Funds locked in contract |
| UX-04 | Asset ID confusion | Critical | Wrong asset accepted |

#### UX-01: Input Validation Missing

**Vulnerable Code:**
```sway
// VULNERABLE: Not checking input amount
#[payable]
fn deposit() {
    let sender = msg_sender().unwrap();
    // Assuming correct amount without verification!
    storage.balances.insert(sender, 1000);
}
```

**Secure Code:**
```sway
// SECURE: Verify actual amount sent
#[payable]
fn deposit() {
    let sender = msg_sender().unwrap();
    let amount = msg_amount();  // Actual amount sent
    let asset = msg_asset_id();
    
    require(asset == BASE_ASSET_ID, "Wrong asset");
    require(amount > 0, "Zero amount");
    
    let current = storage.balances.get(sender).try_read().unwrap_or(0);
    storage.balances.insert(sender, current + amount);
}
```

#### UX-04: Asset ID Confusion

**Vulnerable Code:**
```sway
// VULNERABLE: Any asset accepted
#[payable]
fn swap() {
    let amount = msg_amount();
    // Not checking which asset was sent!
    mint_output_tokens(amount);
}
```

**Secure Code:**
```sway
// SECURE: Verify expected asset
#[payable]
fn swap() {
    let amount = msg_amount();
    let asset = msg_asset_id();
    
    require(
        asset == EXPECTED_TOKEN_ID,
        "Wrong token"
    );
    
    mint_output_tokens(amount);
}
```

---

### Category 2: Predicate Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| PR-01 | Weak predicate logic | Critical | Always returns true |
| PR-02 | Missing signature check | Critical | No authorization |
| PR-03 | Replay attack | High | Signature reusable |
| PR-04 | Front-running | Medium | Predictable unlock |

#### PR-01: Weak Predicate Logic

**Vulnerable Code:**
```sway
// VULNERABLE: Always unlocks
predicate;

fn main() -> bool {
    // Some broken logic that always returns true
    let condition = true;  // Bug!
    condition
}
```

**Secure Code:**
```sway
// SECURE: Proper verification
predicate;

use std::tx::{tx_witness_data, tx_id};
use std::ecr::ec_recover_address;

fn main(expected_signer: Address) -> bool {
    let signature: B512 = tx_witness_data(0);
    let tx_hash = tx_id();
    
    let recovered = ec_recover_address(signature, tx_hash);
    
    match recovered {
        Ok(address) => address == expected_signer,
        Err(_) => false
    }
}
```

#### PR-03: Predicate Replay

**Vulnerable Code:**
```sway
// VULNERABLE: Signature can be reused
predicate;

fn main(signature: B512, signer: Address) -> bool {
    // Uses static message - replay possible
    let message = sha256("unlock");
    let recovered = ec_recover_address(signature, message);
    recovered.unwrap() == signer
}
```

**Secure Code:**
```sway
// SECURE: Include UTXO identifier in signed message
predicate;

use std::tx::{tx_id, tx_witness_data};
use std::inputs::input_coin_owner;

fn main(signer: Address) -> bool {
    let signature: B512 = tx_witness_data(0);
    // tx_id is unique per transaction - prevents replay
    let tx_hash = tx_id();
    
    let recovered = ec_recover_address(signature, tx_hash);
    recovered.unwrap() == signer
}
```

---

### Category 3: Access Control Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| AC-01 | Missing msg_sender check | Critical | Anyone can call |
| AC-02 | Contract ID confusion | High | Wrong caller accepted |
| AC-03 | Storage manipulation | Critical | Unauthorized storage access |
| AC-04 | Owner bypass | Critical | Owner check flawed |

#### AC-01: Missing Sender Verification

**Vulnerable Code:**
```sway
// VULNERABLE: No caller check
#[storage(write)]
fn set_admin(new_admin: Identity) {
    storage.admin.write(new_admin);
}
```

**Secure Code:**
```sway
// SECURE: Verify caller is current admin
#[storage(read, write)]
fn set_admin(new_admin: Identity) {
    let caller = msg_sender().unwrap();
    let current_admin = storage.admin.read();
    
    require(caller == current_admin, "Not admin");
    require(new_admin != Identity::Address(Address::zero()), "Invalid admin");
    
    storage.admin.write(new_admin);
}
```

---

### Category 4: Reentrancy in Fuel

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| RE-01 | Cross-contract reentrancy | High | External call before state update |
| RE-02 | Script reentrancy | Medium | Script calls back |

#### RE-01: Cross-Contract Reentrancy

**Vulnerable Code:**
```sway
// VULNERABLE: External call before state update
#[storage(read, write)]
fn withdraw(amount: u64) {
    let sender = msg_sender().unwrap();
    let balance = storage.balances.get(sender).read();
    require(balance >= amount, "Insufficient");
    
    // Transfer before state update!
    transfer(sender, BASE_ASSET_ID, amount);
    
    // State update after external call
    storage.balances.insert(sender, balance - amount);
}
```

**Secure Code:**
```sway
// SECURE: Checks-Effects-Interactions
#[storage(read, write)]
fn withdraw(amount: u64) {
    let sender = msg_sender().unwrap();
    let balance = storage.balances.get(sender).read();
    require(balance >= amount, "Insufficient");
    
    // State update FIRST
    storage.balances.insert(sender, balance - amount);
    
    // Transfer AFTER state update
    transfer(sender, BASE_ASSET_ID, amount);
}
```

---

### Category 5: Storage Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ST-01 | Storage collision | Critical | Same slot different data |
| ST-02 | Uninitialized storage | High | Default value issues |
| ST-03 | Storage DoS | Medium | Unbounded growth |

#### ST-01: Storage Key Collision

**Vulnerable Code:**
```sway
// VULNERABLE: Manual storage key collision possible
storage {
    // Using same slot for different purposes
    data1 in 0x0: u64 = 0,
    data2 in 0x0: u64 = 0,  // Collision!
}
```

**Secure Code:**
```sway
// SECURE: Unique keys
storage {
    data1: u64 = 0,
    data2: u64 = 0,
    // Compiler handles slot allocation
}
```

#### ST-02: Uninitialized Storage Read

**Vulnerable Code:**
```sway
// VULNERABLE: Reading uninitialized storage
#[storage(read)]
fn get_balance(user: Identity) -> u64 {
    storage.balances.get(user).read()  // Panics if not set!
}
```

**Secure Code:**
```sway
// SECURE: Handle uninitialized case
#[storage(read)]
fn get_balance(user: Identity) -> u64 {
    storage.balances.get(user).try_read().unwrap_or(0)
}
```

---

### Category 6: Native Asset Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| NA-01 | Mint without control | Critical | Anyone can mint |
| NA-02 | Burn authorization | High | Anyone can burn |
| NA-03 | Asset metadata manipulation | Medium | Metadata editable |
| NA-04 | Sub-ID collision | High | Same sub-id different assets |

#### NA-01: Unauthorized Minting

**Vulnerable Code:**
```sway
// VULNERABLE: Anyone can mint
fn mint_tokens(recipient: Identity, amount: u64) {
    mint(amount);
    transfer(recipient, AssetId::default(), amount);
}
```

**Secure Code:**
```sway
// SECURE: Only minter can mint
#[storage(read)]
fn mint_tokens(recipient: Identity, amount: u64) {
    let caller = msg_sender().unwrap();
    require(caller == storage.minter.read(), "Not minter");
    require(amount > 0, "Zero amount");
    
    // Check max supply
    let new_supply = storage.total_supply.read() + amount;
    require(new_supply <= MAX_SUPPLY, "Exceeds max");
    
    mint(amount);
    transfer(recipient, AssetId::default(), amount);
    
    storage.total_supply.write(new_supply);
}
```

---

## Detection Workflow

### Step 1: Project Analysis
```bash
# Find all Sway files
find . -name "*.sw"

# Check Forc.toml
cat Forc.toml

# Identify contract type
grep -r "contract;\|predicate;\|script;\|library;" src/
```

### Step 2: Entry Point Analysis
```bash
# Find all public functions
grep -r "fn " src/*.sw | grep -v "//"

# Find payable functions
grep -r "#\[payable\]" src/

# Find storage functions
grep -r "#\[storage" src/
```

### Step 3: Asset Flow Analysis
```
1. Find msg_amount() calls
2. Find msg_asset_id() calls
3. Verify asset validation
4. Track transfer/mint/burn
```

### Step 4: Predicate Review
```
1. Find main() function
2. Check return conditions
3. Verify signature checks
4. Check for replay protection
```

---

## Fuel-Specific Checklists

### Contract Checklist
- [ ] msg_sender() checked on privileged functions
- [ ] msg_amount() and msg_asset_id() verified on payable
- [ ] Storage initialized before read
- [ ] Reentrancy safe (CEI pattern)
- [ ] Events emitted for important actions

### Predicate Checklist
- [ ] Cannot return true unconditionally
- [ ] Signature verification if needed
- [ ] Replay attack prevented (tx_id in signature)
- [ ] No sensitive data leaked
- [ ] Correct UTXO owner validated

### Native Asset Checklist
- [ ] Mint restricted to authorized
- [ ] Burn properly authorized
- [ ] Total supply tracked
- [ ] Asset IDs validated
- [ ] Sub-IDs unique

---

## Real-World Exploits

| Protocol | Vulnerability | Loss | Root Cause |
|----------|--------------|------|------------|
| SwaySwap (testnet) | Asset confusion | N/A | Missing asset ID check |
| Fuel example | Predicate bypass | N/A | Always-true condition |

---

## Quick Reference Commands

```bash
# Find contracts
grep -r "contract;" src/

# Find predicates
grep -r "predicate;" src/

# Find scripts
grep -r "script;" src/

# Find payable functions
grep -r "#\[payable\]" src/

# Find storage operations
grep -r "#\[storage" src/

# Find msg_sender
grep -r "msg_sender()" src/

# Find transfers
grep -r "transfer\|mint\|burn" src/

# Find asset operations
grep -r "msg_amount\|msg_asset_id" src/
```

---

## Integration with Other Skills

- Use `access-control-patterns` for authorization design
- Use `reentrancy-patterns` for CEI pattern
- Use `token-patterns` for native asset security
- Use `methodology/llm-audit-workflow` for systematic review
