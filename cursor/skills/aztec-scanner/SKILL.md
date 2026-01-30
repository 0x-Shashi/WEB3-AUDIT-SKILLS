---
name: aztec-scanner
description: "Comprehensive Aztec Network (Noir) vulnerability scanner for private smart contracts. Covers private state management, nullifiers, note lifecycle, and ZK-specific attack vectors. Use this skill when auditing Aztec contracts."
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Aztec Vulnerability Scanner

## Purpose

This skill provides systematic vulnerability scanning for Aztec private smart contracts written in Noir. It includes:
- 40+ Aztec-specific vulnerability patterns
- Private state security
- Nullifier management
- Note encryption and lifecycle
- ZK-specific attack vectors

---

## When to Use This Skill

**Use when:**
- Auditing Aztec contracts (Noir)
- Reviewing private state implementations
- Analyzing nullifier security
- Checking note encryption
- Scanning for ZK-specific attacks

**Trigger phrases:**
- "Audit this Aztec contract"
- "Check this Noir contract"
- "Review Aztec security"
- "Scan for privacy vulnerabilities"

---

## When NOT to Use

Do NOT use this skill for:
- Public EVM contracts (use solidity-scanner)
- Starknet Cairo (use starknet-scanner)
- Other ZK systems (ZKSync, Polygon zkEVM)
- Generic Noir without Aztec context

---

## Aztec Security Fundamentals

### Key Concepts

```
┌─────────────────────────────────────────────────────────┐
│                 AZTEC SECURITY MODEL                     │
├─────────────────────────────────────────────────────────┤
│ PRIVATE STATE                                            │
│ • State stored as encrypted notes                       │
│ • Notes are consumed (nullified) and created            │
│ • UTXO-like model with privacy                          │
├─────────────────────────────────────────────────────────┤
│ NULLIFIERS                                               │
│ • Prevent double-spending of notes                      │
│ • Must be deterministically derived                     │
│ • Revealed on-chain (privacy-preserving)                │
├─────────────────────────────────────────────────────────┤
│ NOTE LIFECYCLE                                           │
│ • Creation: Encrypted, added to tree                    │
│ • Reading: Decrypted by owner                           │
│ • Spending: Nullifier revealed, note consumed           │
└─────────────────────────────────────────────────────────┘
```

---

## Vulnerability Categories

### Category 1: Nullifier Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| NL-01 | Weak nullifier | Critical | Predictable nullifier |
| NL-02 | Missing nullifier | Critical | Note can be double-spent |
| NL-03 | Nullifier collision | Critical | Different notes same nullifier |
| NL-04 | Nullifier leak | High | Reveals note information |

#### NL-01: Weak/Predictable Nullifier

**Vulnerable Code:**
```noir
// VULNERABLE: Nullifier doesn't include secret
fn compute_nullifier(note: ValueNote) -> Field {
    // Only uses public data - anyone can compute!
    hash([note.value, note.owner])
}
```

**Secure Code:**
```noir
// SECURE: Nullifier includes owner's secret
fn compute_nullifier(note: ValueNote, secret: Field) -> Field {
    // Includes secret - only owner can compute
    pedersen_hash([
        note.value,
        note.owner,
        secret,
        note.randomness
    ])
}
```

#### NL-02: Missing Nullifier Check

**Vulnerable Code:**
```noir
// VULNERABLE: Can spend same note twice
#[aztec(private)]
fn transfer(note: ValueNote, recipient: AztecAddress) {
    // No nullifier emitted!
    let new_note = ValueNote::new(note.value, recipient);
    storage.notes.insert(new_note);
}
```

**Secure Code:**
```noir
// SECURE: Nullifier prevents double-spend
#[aztec(private)]
fn transfer(note: ValueNote, recipient: AztecAddress) {
    // Emit nullifier to consume the note
    let nullifier = note.compute_nullifier(&mut context);
    context.push_nullifier(nullifier);
    
    let new_note = ValueNote::new(note.value, recipient);
    storage.notes.insert(new_note);
}
```

---

### Category 2: Private State Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| PS-01 | State leak to public | Critical | Private data exposed |
| PS-02 | Unencrypted sensitive | Critical | Data stored plaintext |
| PS-03 | Timing leak | Medium | Operation timing reveals info |
| PS-04 | Note linking | Medium | Notes can be correlated |

#### PS-01: Private State Leaking to Public

**Vulnerable Code:**
```noir
// VULNERABLE: Private value exposed in public function
#[aztec(public)]
fn reveal_balance(user: AztecAddress) -> Field {
    // This is PUBLIC! Everyone sees the balance
    storage.balances.at(user).read()
}
```

**Secure Code:**
```noir
// SECURE: Balance stays private
#[aztec(private)]
fn check_balance_sufficient(
    user: AztecAddress,
    minimum: Field
) -> bool {
    let balance = storage.balances.at(user).get_value();
    balance >= minimum  // Only returns boolean, not amount
}
```

#### PS-02: Weak Note Encryption

**Vulnerable Code:**
```noir
// VULNERABLE: Note randomness is predictable
fn create_note(value: Field, owner: AztecAddress) -> ValueNote {
    ValueNote {
        value,
        owner,
        randomness: 0  // PREDICTABLE!
    }
}
```

**Secure Code:**
```noir
// SECURE: Proper randomness
fn create_note(value: Field, owner: AztecAddress, context: &mut Context) -> ValueNote {
    ValueNote {
        value,
        owner,
        randomness: context.request_randomness()
    }
}
```

---

### Category 3: Access Control Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| AC-01 | Missing sender check | Critical | Anyone can call |
| AC-02 | Public function misuse | High | Private should be public |
| AC-03 | Authwit bypass | Critical | Authentication bypass |
| AC-04 | Private function exposure | High | Private callable externally |

#### AC-01: Missing Sender Verification

**Vulnerable Code:**
```noir
// VULNERABLE: No sender check
#[aztec(private)]
fn spend_note(note: ValueNote) {
    // Anyone can spend anyone's notes!
    let nullifier = note.compute_nullifier(&mut context);
    context.push_nullifier(nullifier);
}
```

**Secure Code:**
```noir
// SECURE: Verify sender owns the note
#[aztec(private)]
fn spend_note(note: ValueNote) {
    let sender = context.msg_sender();
    assert(note.owner == sender, "Not owner");
    
    let nullifier = note.compute_nullifier(&mut context);
    context.push_nullifier(nullifier);
}
```

#### AC-03: Authentication Witness Bypass

**Vulnerable Code:**
```noir
// VULNERABLE: Authwit not properly checked
#[aztec(private)]
fn transfer_from(from: AztecAddress, to: AztecAddress, amount: Field) {
    // Should check if sender is authorized by 'from'
    // but check is missing!
    internal_transfer(from, to, amount);
}
```

**Secure Code:**
```noir
// SECURE: Proper authwit check
#[aztec(private)]
fn transfer_from(from: AztecAddress, to: AztecAddress, amount: Field) {
    let sender = context.msg_sender();
    
    if (sender != from) {
        // Check authentication witness
        let action = compute_authwit_action(from, to, amount);
        assert(context.is_valid_authwit(from, action), "Not authorized");
    }
    
    internal_transfer(from, to, amount);
}
```

---

### Category 4: Note Lifecycle Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| LC-01 | Orphaned notes | Medium | Notes created but inaccessible |
| LC-02 | Missing note commitment | High | Note not added to tree |
| LC-03 | Note replay | Critical | Same note created twice |
| LC-04 | Invalid note hash | High | Note can't be proven |

#### LC-01: Orphaned Notes

**Vulnerable Code:**
```noir
// VULNERABLE: Note created but owner can't find it
#[aztec(private)]
fn transfer(amount: Field, recipient: AztecAddress) {
    let note = ValueNote::new(amount, recipient);
    storage.notes.insert(note);
    // Missing: emit encrypted log for recipient!
}
```

**Secure Code:**
```noir
// SECURE: Recipient is notified
#[aztec(private)]
fn transfer(amount: Field, recipient: AztecAddress) {
    let note = ValueNote::new(amount, recipient);
    storage.notes.insert(note);
    
    // Emit encrypted log so recipient can discover the note
    emit_encrypted_log(
        &mut context,
        recipient,
        note.serialize()
    );
}
```

---

### Category 5: Constraint Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| CT-01 | Missing constraint | Critical | Logic not enforced |
| CT-02 | Over-constrained | Low | Valid operations fail |
| CT-03 | Constraint bypass | Critical | Constraint can be avoided |
| CT-04 | Underflow/Overflow | High | Arithmetic issues in constraints |

#### CT-01: Missing Constraint

**Vulnerable Code:**
```noir
// VULNERABLE: Balance can go negative
#[aztec(private)]
fn transfer(amount: Field, recipient: AztecAddress) {
    let sender = context.msg_sender();
    let sender_balance = get_balance(sender);
    let recipient_balance = get_balance(recipient);
    
    // Missing: assert(sender_balance >= amount)
    
    set_balance(sender, sender_balance - amount);
    set_balance(recipient, recipient_balance + amount);
}
```

**Secure Code:**
```noir
// SECURE: Balance check enforced
#[aztec(private)]
fn transfer(amount: Field, recipient: AztecAddress) {
    let sender = context.msg_sender();
    let sender_balance = get_balance(sender);
    let recipient_balance = get_balance(recipient);
    
    assert(sender_balance >= amount, "Insufficient balance");
    
    set_balance(sender, sender_balance - amount);
    set_balance(recipient, recipient_balance + amount);
}
```

---

### Category 6: Public/Private Boundary

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| PB-01 | Privacy leak at boundary | High | Private data crosses to public |
| PB-02 | Inconsistent state | High | Public/private state mismatch |
| PB-03 | Front-running | Medium | Public part front-runnable |
| PB-04 | Missing finalization | High | Private state not finalized |

#### PB-01: Privacy Leak at Boundary

**Vulnerable Code:**
```noir
// VULNERABLE: Exact amount revealed
#[aztec(private)]
fn private_to_public_transfer(amount: Field, recipient: AztecAddress) {
    // Burn private tokens
    burn_private(amount);
    
    // Mint public tokens - amount is now PUBLIC
    context.call_public_function(
        self_address,
        "mint_public",
        [recipient, amount]  // amount exposed!
    );
}
```

**Secure Code:**
```noir
// SECURE: Consider if amount disclosure is acceptable
// If not, use commitment schemes or fixed denominations
#[aztec(private)]
fn private_to_public_transfer(amount: Field, recipient: AztecAddress) {
    // User explicitly accepts privacy loss for this amount
    assert(user_accepts_disclosure, "User must accept disclosure");
    
    burn_private(amount);
    context.call_public_function(
        self_address,
        "mint_public",
        [recipient, amount]
    );
}

// Alternative: Fixed denomination transfers
fn fixed_transfer() {
    // Only transfer fixed amounts (e.g., 1, 10, 100)
    // Less information leaked
}
```

---

## Detection Workflow

### Step 1: Contract Analysis
```bash
# Find all Noir files
find src/ -name "*.nr"

# Find public functions
grep -r "#\[aztec(public)\]" src/

# Find private functions
grep -r "#\[aztec(private)\]" src/
```

### Step 2: Nullifier Review
```
1. Find all note types
2. Check compute_nullifier implementation
3. Verify nullifiers pushed in spending functions
4. Check for nullifier uniqueness
```

### Step 3: Note Lifecycle Analysis
```
1. Trace note creation (insert)
2. Verify encrypted logs emitted
3. Check note spending (nullifier push)
4. Verify no orphaned notes
```

### Step 4: Privacy Boundary Check
```
1. Find public functions
2. Check what data flows from private
3. Verify acceptable disclosure
4. Check for timing leaks
```

---

## Aztec-Specific Checklists

### Nullifier Checklist
- [ ] Nullifiers include owner's secret
- [ ] Nullifiers include note randomness
- [ ] Nullifiers pushed when notes spent
- [ ] No nullifier collisions possible
- [ ] Nullifier doesn't reveal note contents

### Note Security Checklist
- [ ] Notes use proper randomness
- [ ] Encrypted logs emitted for recipients
- [ ] Note hash computed correctly
- [ ] Owner can discover their notes
- [ ] Notes can't be replayed

### Access Control Checklist
- [ ] msg_sender checked where needed
- [ ] Authwit properly implemented
- [ ] Note ownership verified before spending
- [ ] Public functions appropriately restricted

### Privacy Checklist
- [ ] Private data doesn't leak to public
- [ ] No timing attacks possible
- [ ] Notes aren't linkable
- [ ] Amount privacy preserved where needed

---

## Real-World Considerations

### Privacy vs Functionality Trade-offs
```
More Privacy → More Constraints → Higher Proving Cost
Less Privacy → Simpler → Cheaper but Weaker

Balance based on use case:
- DeFi: May need some disclosure for liquidations
- Payments: Maximum privacy preferred
- Identity: Selective disclosure
```

### Aztec Testnet Gotchas
- Testnet behavior may differ from mainnet
- Prover changes can affect constraint limits
- API evolving - check latest docs

---

## Quick Reference Commands

```bash
# Find public functions
grep -r "#\[aztec(public)\]" src/

# Find private functions
grep -r "#\[aztec(private)\]" src/

# Find nullifier computation
grep -r "compute_nullifier" src/

# Find note insertions
grep -r "\.insert(" src/

# Find assertions
grep -r "assert(" src/

# Find encrypted logs
grep -r "emit_encrypted_log" src/

# Find context usage
grep -r "context\." src/
```

---

## Integration with Other Skills

- Use `signature-crypto-patterns` for nullifier design
- Use `access-control-patterns` for authwit design
- Use `methodology/llm-audit-workflow` for systematic review
