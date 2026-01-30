# Aztec Noir Vulnerability Patterns

Comprehensive database of Aztec-specific vulnerability patterns for private smart contracts.

---

## Nullifier Patterns

### Pattern NL-01: Weak Nullifier Derivation

**Risk Level:** Critical

**Description:** Nullifiers must be unpredictable to prevent front-running and ensure only the note owner can spend.

**Detection Pattern:**
```
1. Find compute_nullifier functions
2. Check if owner's secret included
3. Check if note randomness included
4. Flag predictable derivations
```

**Vulnerable:**
```noir
impl ValueNote {
    // VULNERABLE: No secret, anyone can compute
    fn compute_nullifier(self) -> Field {
        pedersen_hash([self.value, self.owner])
    }
}
```

**Secure:**
```noir
impl ValueNote {
    // SECURE: Includes owner's nullifier secret key
    fn compute_nullifier(self, context: &mut PrivateContext) -> Field {
        let nullifier_key = context.get_nullifier_secret_key(self.owner);
        pedersen_hash([
            self.value,
            self.owner.to_field(),
            self.randomness,
            nullifier_key
        ])
    }
}
```

---

### Pattern NL-02: Missing Nullifier Emission

**Risk Level:** Critical

**Description:** If nullifier isn't pushed to context, note can be spent multiple times.

**Detection Pattern:**
```
1. Find note spending logic
2. Check if context.push_nullifier called
3. Flag spending without nullifier
```

**Vulnerable:**
```noir
#[aztec(private)]
fn spend_tokens(note: ValueNote, amount: Field) {
    // Verify ownership
    assert(note.owner == context.msg_sender());
    
    // Missing: context.push_nullifier(...)
    
    // Create change note
    if note.value > amount {
        let change = ValueNote::new(note.value - amount, note.owner);
        storage.notes.insert(change);
    }
    // Original note NOT nullified - can spend again!
}
```

**Secure:**
```noir
#[aztec(private)]
fn spend_tokens(note: ValueNote, amount: Field) {
    assert(note.owner == context.msg_sender());
    
    // Emit nullifier to prevent double-spend
    let nullifier = note.compute_nullifier(&mut context);
    context.push_nullifier(nullifier);
    
    if note.value > amount {
        let change = ValueNote::new(note.value - amount, note.owner);
        storage.notes.insert(change);
    }
}
```

---

### Pattern NL-03: Nullifier Collision

**Risk Level:** Critical

**Description:** Different notes producing same nullifier allows one note to invalidate another.

**Detection Pattern:**
```
1. Check nullifier includes unique note identifier
2. Verify randomness is unique per note
3. Flag shared randomness
```

**Vulnerable:**
```noir
// VULNERABLE: Two notes with same owner+value have same nullifier
fn compute_nullifier(self, secret: Field) -> Field {
    pedersen_hash([self.value, self.owner, secret])
    // Missing randomness - collision possible!
}
```

**Secure:**
```noir
// SECURE: Randomness ensures uniqueness
fn compute_nullifier(self, secret: Field) -> Field {
    pedersen_hash([
        self.value,
        self.owner,
        self.randomness,  // Unique per note
        secret
    ])
}
```

---

## Privacy Patterns

### Pattern PS-01: Private State Exposure

**Risk Level:** Critical

**Description:** Private data passed to public functions becomes visible on-chain.

**Detection Pattern:**
```
1. Find call_public_function calls
2. Check arguments for sensitive data
3. Flag private values in public calls
```

**Vulnerable:**
```noir
#[aztec(private)]
fn claim_reward(secret_amount: Field) {
    // secret_amount becomes public!
    context.call_public_function(
        self_address,
        "mint_public",
        [context.msg_sender().to_field(), secret_amount]
    );
}
```

**Secure:**
```noir
#[aztec(private)]
fn claim_reward(commitment: Field) {
    // Only reveal commitment, not actual amount
    context.call_public_function(
        self_address,
        "process_commitment",
        [commitment]
    );
    
    // Amount stays private, verified via ZK proof
}
```

---

### Pattern PS-02: Note Linking Attack

**Risk Level:** Medium

**Description:** Patterns in note creation/spending can link transactions to same user.

**Detection Pattern:**
```
1. Check if note values are fixed denominations
2. Look for timing patterns
3. Check for amount correlation
```

**Mitigation:**
```noir
// Use fixed denominations to prevent amount correlation
const DENOMINATIONS: [Field; 4] = [1, 10, 100, 1000];

fn create_notes(amount: Field, owner: AztecAddress) {
    // Break amount into standard denominations
    // Harder to trace than exact amounts
}
```

---

### Pattern PS-03: Encrypted Log Missing

**Risk Level:** High

**Description:** Without encrypted log, recipient can't discover their notes.

**Detection Pattern:**
```
1. Find note insertions (storage.notes.insert)
2. Check if emit_encrypted_log follows
3. Flag missing notifications
```

**Vulnerable:**
```noir
#[aztec(private)]
fn transfer(amount: Field, recipient: AztecAddress) {
    // Spend sender's note
    let sender_note = storage.notes.get(context.msg_sender());
    context.push_nullifier(sender_note.compute_nullifier(&mut context));
    
    // Create recipient's note
    let new_note = ValueNote::new(amount, recipient);
    storage.notes.insert(new_note);
    
    // Missing: emit_encrypted_log
    // Recipient won't know they received tokens!
}
```

**Secure:**
```noir
#[aztec(private)]
fn transfer(amount: Field, recipient: AztecAddress) {
    let sender_note = storage.notes.get(context.msg_sender());
    context.push_nullifier(sender_note.compute_nullifier(&mut context));
    
    let new_note = ValueNote::new(amount, recipient);
    storage.notes.insert(new_note);
    
    // Notify recipient
    emit_encrypted_log(
        &mut context,
        recipient,
        new_note.serialize()
    );
}
```

---

## Access Control Patterns

### Pattern AC-01: Missing Owner Check

**Risk Level:** Critical

**Description:** Anyone can spend notes without verifying ownership.

**Detection Pattern:**
```
1. Find functions that spend notes
2. Check if note.owner verified against msg_sender
3. Flag missing ownership checks
```

**Vulnerable:**
```noir
#[aztec(private)]
fn burn(note: ValueNote) {
    // Anyone can burn anyone's notes!
    context.push_nullifier(note.compute_nullifier(&mut context));
}
```

**Secure:**
```noir
#[aztec(private)]
fn burn(note: ValueNote) {
    let sender = context.msg_sender();
    assert(note.owner == sender, "Not the owner");
    
    context.push_nullifier(note.compute_nullifier(&mut context));
}
```

---

### Pattern AC-03: Authentication Witness Issues

**Risk Level:** Critical

**Description:** Authwit allows delegated actions. Improper implementation allows bypass.

**Detection Pattern:**
```
1. Find functions with "from" parameter different from sender
2. Check if authwit validated
3. Flag missing validation
```

**Vulnerable:**
```noir
#[aztec(private)]
fn transfer_from(
    from: AztecAddress,
    to: AztecAddress,
    amount: Field
) {
    // No check that sender is authorized!
    spend_from(from, amount);
    mint_to(to, amount);
}
```

**Secure:**
```noir
#[aztec(private)]
fn transfer_from(
    from: AztecAddress,
    to: AztecAddress,
    amount: Field
) {
    let sender = context.msg_sender();
    
    if sender != from {
        // Verify sender is authorized by 'from'
        let action = compute_transfer_authwit(from, to, amount);
        assert(
            context.verify_authwit(from, action),
            "Not authorized"
        );
        // Consume the authwit to prevent replay
        context.consume_authwit(from, action);
    }
    
    spend_from(from, amount);
    mint_to(to, amount);
}
```

---

## Constraint Patterns

### Pattern CT-01: Missing Balance Check

**Risk Level:** Critical

**Description:** Without balance constraints, users can spend more than they own.

**Detection Pattern:**
```
1. Find spending operations
2. Check if balance >= amount asserted
3. Flag missing checks
```

**Vulnerable:**
```noir
#[aztec(private)]
fn transfer(amount: Field, recipient: AztecAddress) {
    let sender = context.msg_sender();
    
    // Just create new note without checking balance!
    let new_note = ValueNote::new(amount, recipient);
    storage.notes.insert(new_note);
}
```

**Secure:**
```noir
#[aztec(private)]
fn transfer(amount: Field, recipient: AztecAddress) {
    let sender = context.msg_sender();
    
    // Get and spend sender's note (implicitly checks balance)
    let notes = storage.notes.get_notes(sender, amount);
    let total = spend_notes(notes);
    assert(total >= amount, "Insufficient balance");
    
    // Create recipient note
    let new_note = ValueNote::new(amount, recipient);
    storage.notes.insert(new_note);
    
    // Create change if needed
    if total > amount {
        let change = ValueNote::new(total - amount, sender);
        storage.notes.insert(change);
    }
}
```

---

### Pattern CT-04: Field Arithmetic Issues

**Risk Level:** High

**Description:** Field arithmetic wraps around. Unchecked operations can overflow.

**Detection Pattern:**
```
1. Find arithmetic operations
2. Check if overflow possible
3. Flag unchecked operations
```

**Vulnerable:**
```noir
fn add_balances(a: Field, b: Field) -> Field {
    a + b  // Can overflow in field arithmetic
}
```

**Secure:**
```noir
fn add_balances(a: Field, b: Field) -> Field {
    let result = a + b;
    // Ensure no overflow (simplified check)
    assert(result >= a, "Overflow");
    result
}

// Or use u128 for bounded arithmetic
fn add_balances_safe(a: u128, b: u128) -> u128 {
    a + b  // Checked by default
}
```

---

## Note Type Patterns

### Pattern NT-01: Note Without Randomness

**Risk Level:** High

**Description:** Notes need randomness for privacy and nullifier uniqueness.

**Detection Pattern:**
```
1. Find note struct definitions
2. Check for randomness field
3. Verify randomness is set properly
```

**Vulnerable:**
```noir
struct ValueNote {
    value: Field,
    owner: AztecAddress,
    // Missing randomness!
}

impl ValueNote {
    fn new(value: Field, owner: AztecAddress) -> Self {
        ValueNote { value, owner }
    }
}
```

**Secure:**
```noir
struct ValueNote {
    value: Field,
    owner: AztecAddress,
    randomness: Field,  // Required for privacy
}

impl ValueNote {
    fn new(
        value: Field,
        owner: AztecAddress,
        context: &mut PrivateContext
    ) -> Self {
        ValueNote {
            value,
            owner,
            randomness: context.request_randomness()
        }
    }
}
```

---

## Public/Private Boundary Patterns

### Pattern PB-02: State Inconsistency

**Risk Level:** High

**Description:** Public and private state can become inconsistent if not properly synchronized.

**Detection Pattern:**
```
1. Find contracts with both public and private state
2. Check if invariants maintained across both
3. Flag potential inconsistencies
```

**Vulnerable:**
```noir
// Private function burns tokens
#[aztec(private)]
fn burn_private(amount: Field) {
    spend_private_tokens(amount);
    // Missing: update total_supply in public!
}

// Total supply becomes incorrect
```

**Secure:**
```noir
#[aztec(private)]
fn burn_private(amount: Field) {
    spend_private_tokens(amount);
    
    // Queue public state update
    context.call_public_function(
        self_address,
        "decrease_total_supply",
        [amount]
    );
}

#[aztec(public)]
internal fn decrease_total_supply(amount: Field) {
    let current = storage.total_supply.read();
    storage.total_supply.write(current - amount);
}
```

---

## Quick Detection Commands

```bash
# Find all Noir files
find . -name "*.nr"

# Find public functions
grep -r "#\[aztec(public)\]" src/

# Find private functions
grep -r "#\[aztec(private)\]" src/

# Find nullifier computation
grep -r "compute_nullifier\|push_nullifier" src/

# Find note operations
grep -r "\.insert(\|\.get_notes(" src/

# Find assertions
grep -r "assert(" src/

# Find encrypted logs
grep -r "emit_encrypted" src/

# Find public calls from private
grep -r "call_public_function" src/
```
