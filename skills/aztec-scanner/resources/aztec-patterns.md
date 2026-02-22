---
id: AZTEC-PATTERNS
title: Aztec / Noir Vulnerability Patterns
parent: aztec-scanner
type: resource
last_updated: 2025-01-31
---

# Aztec / Noir Vulnerability Patterns

Detailed vulnerability patterns for Aztec Network contracts written in Noir, organized by severity. These patterns are unique to Aztec's privacy-preserving architecture.

---

## Critical

### 1. Privacy Leak via Public State

The most fundamental Aztec vulnerability — private data written to public storage:

```noir
// VULNERABLE: Private function writes to public storage
// This exposes the transfer amount to the sequencer and public observers
#[aztec(private)]
fn private_transfer(to: AztecAddress, amount: Field) {
    // ... nullify sender's notes ...
    // ... create recipient's notes ...
    
    // BUG: Writing amount to public storage leaks it!
    storage.total_transferred.write(amount);
}

// SAFE: Keep all private data in notes
#[aztec(private)]
fn private_transfer(to: AztecAddress, amount: Field) {
    // Nullify sender's notes
    // Create recipient's notes
    // Only emit nullifiers and note hashes (both opaque)
    // No public state touched
}
```

**Key Rule:** Private functions should NEVER write values derived from private inputs to public state. Even writing a hash can leak information if the preimage space is small.

---

### 2. Nullifier Collision

Two different notes producing the same nullifier = one note becomes unspendable:

```noir
// VULNERABLE: Nullifier depends only on note content, not position
fn compute_nullifier(note: &MyNote) -> Field {
    // If two notes have identical content, they produce the same nullifier
    // First spend succeeds, second is rejected (duplicate nullifier)
    pedersen_hash([note.amount, note.owner])
}

// SAFE: Include unique note nonce/randomness in nullifier
fn compute_nullifier(note: &MyNote, context: &PrivateContext) -> Field {
    pedersen_hash([
        note.amount,
        note.owner,
        note.randomness,     // Unique per note
        context.note_index,  // Position in tree
    ])
}
```

**Nullifier Requirements:**
- Must be unique per note (even for identical note content)
- Must be deterministic (same note always produces same nullifier)
- Must be unlinkable to the note hash (privacy)
- Must be computable only by the note owner (authorization)

---

### 3. Double Spend — Missing Nullifier Emission

```noir
// VULNERABLE: Note consumed but nullifier not emitted
#[aztec(private)]
fn spend(note: MyNote) {
    let value = note.amount;
    // Use the value...
    // BUG: Never nullified the note!
    // Attacker can spend the same note again
}

// SAFE: Always nullify consumed notes
#[aztec(private)] 
fn spend(note_hash: Field) {
    let note = storage.notes.get_note(note_hash);
    let nullifier = note.compute_nullifier(&mut context);
    context.push_new_nullifier(nullifier);
    // Now the note is consumed and can't be re-spent
}
```

---

## High

### 4. Public/Private State Desynchronization

```noir
// PROBLEM: Private function queries public state, but gets STALE data
// Private executes client-side BEFORE public functions run

#[aztec(private)]
fn private_buy(amount: Field) {
    // This reads public price at time of client execution
    // But price might change before the public function runs!
    let price = storage.public_price.read(); // STALE!
    // ...
}

// SAFER: Enqueue the public check, let it verify at execution time
#[aztec(private)]
fn private_buy(amount: Field, max_price: Field) {
    // Do private operations first
    // ...
    
    // Enqueue public function to verify price at execution time
    context.call_public_function(
        storage.address(),
        "verify_and_execute_buy",
        [amount, max_price]
    );
}

#[aztec(public)]
fn verify_and_execute_buy(amount: Field, max_price: Field) {
    let current_price = storage.price.read(); // Fresh read
    assert(current_price <= max_price); // Slippage protection
    // Execute buy at current price
}
```

---

### 5. Oracle Manipulation

Private functions use oracles to fetch off-chain data during client-side execution:

```noir
// VULNERABLE: Trusting oracle data without constraint
#[aztec(private)]
fn process() {
    // Oracle runs on user's machine — user controls the output!
    let oracle_data = oracle::get_price();
    // If oracle_data is used in constraints, the user can set it
    // to any value that satisfies the circuit
}

// SAFER: Oracle data must be validated against public state or commitments
#[aztec(private)]
fn process(committed_price_hash: Field) {
    let oracle_data = oracle::get_price();
    // Verify oracle data matches a committed value
    assert(pedersen_hash([oracle_data]) == committed_price_hash);
}
```

**Key:** The user runs the client-side prover, so they control oracle outputs. Any oracle data must be constrained against verifiable commitments.

---

### 6. Access Control in Private Functions

```noir
// VULNERABLE: No sender authentication
#[aztec(private)]
fn admin_action() {
    // Who's calling? In private context, msg_sender is hidden
    // Need to prove identity via note ownership or other mechanism
    // BUG: No auth check
    do_privileged_thing();
}

// SAFE: Verify caller owns an admin note
#[aztec(private)]
fn admin_action(admin_note_hash: Field) {
    // Only the holder of the admin note can call this
    let admin_note = storage.admin_notes.get_note(admin_note_hash);
    assert(admin_note.owner == context.msg_sender());
    // Optionally nullify admin note to prevent replay
    do_privileged_thing();
}
```

---

## Medium

### 7. Note Discovery Failure

If a note is encrypted with the wrong key, the recipient can never find or spend it:

```noir
// VULNERABLE: Note encrypted for wrong recipient
#[aztec(private)]
fn transfer(to: AztecAddress, amount: Field) {
    let note = MyNote::new(amount, to);
    // BUG: encrypted_log sent with wrong encryption key
    // Recipient's PXE (client) will never discover this note
    // Funds are effectively burned — locked forever
    storage.notes.insert(&mut context, note);
}
```

### 8. Circuit Constraint Issues

**Under-constrained:** Missing constraints allow invalid proofs to be accepted:

```noir
// VULNERABLE: Constraint doesn't fully validate
fn verify_transfer(sender_balance: Field, amount: Field, new_balance: Field) {
    // Should assert: new_balance = sender_balance - amount
    // BUG: Only checks non-negative, doesn't verify arithmetic
    assert(new_balance as u64 >= 0); // Always true for Field!
}

// SAFE: Full constraint
fn verify_transfer(sender_balance: Field, amount: Field, new_balance: Field) {
    assert(sender_balance >= amount); // Sufficient balance
    assert(new_balance == sender_balance - amount); // Correct arithmetic
}
```

**Over-constrained:** Overly strict constraints reject valid transactions:
- User experience issue rather than security issue
- But can cause DoS if legitimate users can't transact

---

## Aztec Audit Checklist

- [ ] Private functions never write private data to public state
- [ ] Nullifiers are unique (include randomness/nonce, not just note content)
- [ ] Every consumed note emits a nullifier
- [ ] Nullifier computable only by note owner
- [ ] Public/private state interaction accounts for execution order
- [ ] Oracle data validated against commitments (not trusted blindly)
- [ ] Private function access control via note ownership (not just address checks)
- [ ] Notes encrypted for correct recipient with correct key
- [ ] Circuit constraints are complete (not under or over constrained)
- [ ] Privacy analysis: no information leakage through observable side channels
