---
id: AZTEC-WF-AUDIT
title: Aztec / Noir Contract Audit Workflow
parent: aztec-scanner
type: workflow
last_updated: 2025-01-31
---

# Aztec / Noir Contract Audit Workflow

Audit workflow for Aztec Network contracts written in Noir. Uniquely requires both traditional smart contract auditing AND zero-knowledge circuit analysis.

---

## Prerequisites

| Requirement | Details |
|-------------|----------|
| Language | Noir (latest stable version) |
| Toolchain | `nargo` (Noir compiler) |
| Framework | `aztec-nr` (Aztec Noir library) |
| Testing | `nargo test` + Aztec sandbox for integration tests |
| Concepts Required | ZK circuits, UTXO model, note encryption, nullifiers |

---

## Step 1: Contract Structure Mapping

Map all functions by visibility and execution domain:

| Decorator | Execution | State Access | Privacy |
|-----------|-----------|--------------|----------|
| `#[aztec(private)]` | Client-side | Notes (UTXO) | Inputs/outputs hidden |
| `#[aztec(public)]` | Sequencer | Storage slots | Fully visible |
| `#[aztec(public, internal)]` | Sequencer (internal only) | Storage slots | Visible |
| `#[aztec(private, internal)]` | Client (internal only) | Notes | Hidden |

Document for each function:
- Which notes does it create/nullify?
- Does it call public functions (enqueue)?
- What oracle calls does it make?
- What constraints does it enforce?

---

## Step 2: Privacy Analysis

This is the **most critical step** for Aztec audits. Systematically check for information leaks:

### Direct Leaks
- [ ] Private function NEVER writes private inputs to public state
- [ ] Private function NEVER emits private data in public logs/events
- [ ] Private function parameters not derivable from public observations

### Indirect Leaks
- [ ] Transaction timing doesn't reveal private information
- [ ] Gas consumption doesn't vary based on private inputs (constant-time operations)
- [ ] Number of nullifiers/note hashes doesn't reveal transaction type
- [ ] Public function call ordering doesn't reveal private intent

### Metadata Leaks
- [ ] Transaction origin (who submitted to mempool) doesn't deanonymize
- [ ] Contract address interaction pattern doesn't reveal user identity
- [ ] Note sizes are uniform (don't reveal amount by size)

---

## Step 3: Note Management

Audit the complete note lifecycle:

```
Create → Encrypt → Store (note hash tree) → Discover (PXE) → Nullify (spend)
```

### Note Creation
- [ ] Note content correctly set (owner, amount, randomness)
- [ ] Note hash computed correctly (all fields included)
- [ ] Note encrypted for correct recipient's public key
- [ ] Encrypted log emitted for note discovery

### Note Spending
- [ ] Note retrieved and verified (exists in tree)
- [ ] Nullifier computed and emitted
- [ ] Note cannot be spent twice (nullifier prevents replay)
- [ ] Only the owner can compute the nullifier (authorization)

### Note Types
- [ ] Custom note types include sufficient randomness
- [ ] Note serialization/deserialization is correct
- [ ] No field truncation in note hashing

---

## Step 4: Nullifier Safety

Nullifiers are the mechanism that prevents double-spending in Aztec's UTXO model:

| Property | Requirement | Consequence of Failure |
|----------|-------------|------------------------|
| Unique | Different notes → different nullifiers | Note permanently locked |
| Deterministic | Same note always → same nullifier | Inconsistent state |
| Unlinkable | Can't link nullifier to note hash | Privacy leak |
| Owner-only | Only owner can compute | Unauthorized spending |

- [ ] Nullifier computation includes note randomness/nonce
- [ ] Nullifier computation includes owner's secret key
- [ ] Nullifier is a cryptographically strong hash (Pedersen/Poseidon)
- [ ] No nullifier collision possible between different note types

---

## Step 5: Circuit Constraint Review

Noir compiles to arithmetic circuits. Every assertion becomes a constraint:

### Under-Constrained Circuits

```noir
// EXAMPLE: Missing constraint allows forgery
fn transfer(sender_bal: Field, amount: Field, receiver_bal: Field) {
    // Constraints:
    assert(sender_bal >= amount);  // Sender has enough
    // MISSING: assert(new_sender_bal == sender_bal - amount)
    // MISSING: assert(new_receiver_bal == receiver_bal + amount)
    // Without these, prover can set arbitrary new balances!
}
```

- [ ] Every intermediate value is constrained
- [ ] Input/output relationships fully specified
- [ ] No "free" witness variables that can take arbitrary values
- [ ] Range constraints on values that should be bounded (e.g., amounts must fit u64)

### Over-Constrained Circuits
- [ ] Constraints don't reject valid transactions
- [ ] Edge cases (zero amounts, self-transfers) handled

---

## Step 6: Oracle Review

Oracles provide off-chain data to private functions during client-side execution:

```noir
// Oracle call (runs on user's machine)
#[oracle(get_notes)]
fn oracle_get_notes(storage_slot: Field) -> [NoteData; MAX_NOTES] {}
```

**Critical:** Oracles run on the user's machine. The user controls oracle output.

- [ ] Oracle data validated against on-chain commitments
- [ ] Oracle data cannot be set to arbitrary values without detection
- [ ] Custom oracles (non-standard) documented and justified
- [ ] Oracle failure handled gracefully (doesn't break circuit)

---

## Step 7: Access Control

Private function access control works differently than public:

| Method | Public Functions | Private Functions |
|--------|-----------------|-------------------|
| Caller check | `context.msg_sender()` | Note ownership proof |
| Admin role | Storage variable | Admin note held by admin |
| Allowlist | Storage mapping | Note with allowlist membership |

- [ ] Public functions check `context.msg_sender()` for privileged operations
- [ ] Private functions verify note ownership for authorization
- [ ] Cross-function calls (private → public) maintain authorization context
- [ ] Internal functions properly restricted (can't be called externally)

---

## Step 8: Public/Private State Consistency

The execution order (private first, then public) creates consistency challenges:

- [ ] Private function's enqueued public calls handle state changes correctly
- [ ] Public function validates data from private context (don't blindly trust)
- [ ] State invariants maintained across private+public execution boundary
- [ ] Concurrent transactions don't create inconsistent state

---

## Step 9: Encryption & Key Management

- [ ] Notes encrypted with recipient's public encryption key (not signing key)
- [ ] Encryption scheme correctly implemented (no key reuse issues)
- [ ] Key derivation follows Aztec key hierarchy
- [ ] Viewing keys (if applicable) properly scoped
- [ ] Encryption doesn't leak plaintext length

---

## Step 10: Report

### Severity Guide for Aztec

| Severity | Criteria | Example |
|----------|----------|---------|
| **Critical** | Privacy leak, fund theft, double-spend | Private amount written to public state |
| **High** | Privacy degradation, fund lock | Nullifier collision locking notes |
| **Medium** | Incorrect behavior, limited privacy impact | Stale public state read in private function |
| **Low** | Best practice, informational | Non-uniform note sizes |

### Aztec-Specific Report Notes

- Always specify whether the issue is in **private** or **public** context
- For privacy findings, describe the **information leaked** and **to whom**
- For circuit findings, describe the **under/over-constraint** precisely
- Include a proof-of-concept showing the privacy leak or constraint violation
- Describe the privacy impact in terms of the threat model (sequencer, observer, MEV)
