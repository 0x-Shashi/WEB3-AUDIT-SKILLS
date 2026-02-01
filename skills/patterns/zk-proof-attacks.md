---
id: ATTACK-ZK-PROOF
title: ZK Proof System Attacks
category: attack-patterns
difficulty: expert
tags: [zk, zero-knowledge, snark, stark, verifier, prover]
last_updated: 2026-01-31
---

# ZK Proof System Attacks

## Overview

Zero-knowledge proofs enable privacy and scalability but introduce complex attack surfaces in circuit design, proof generation, and verification.

```
┌─────────────────────────────────────────────────────────────────┐
│                     ZK PROOF SYSTEM                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PROVER                PROOF               VERIFIER             │
│  ┌──────────┐        ┌──────┐           ┌──────────┐           │
│  │ Private  │───────►│  π   │──────────►│ Verify   │           │
│  │ Witness  │        │      │           │ On-chain │           │
│  └──────────┘        └──────┘           └──────────┘           │
│       │                  │                   │                  │
│       ▼                  ▼                   ▼                  │
│  ┌────────────────────────────────────────────────────┐        │
│  │              ATTACK SURFACES                       │        │
│  │  • Under-constrained circuits                      │        │
│  │  • Trusted setup compromise                        │        │
│  │  • Proof malleability                              │        │
│  │  • Verifier bugs                                   │        │
│  │  • Soundness errors                                │        │
│  │  • Data availability attacks                       │        │
│  └────────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

---

## ZK System Types

| System | Trusted Setup | Proof Size | Verify Time | Use Case |
|--------|---------------|------------|-------------|----------|
| **Groth16** | Yes (per circuit) | ~200 bytes | Fast | zkSync, Zcash |
| **PLONK** | Yes (universal) | ~400 bytes | Medium | Aztec, Polygon zkEVM |
| **STARKs** | No | Large (~100KB) | Medium | StarkNet, zkPorter |
| **Halo2** | No | Medium | Medium | Scroll, Taiko |

---

## Attack Vector 1: Under-Constrained Circuits

### The Problem

```
Circuits must FULLY constrain all valid witnesses.
Under-constrained = multiple witnesses satisfy the circuit for same public inputs

EXAMPLE (Broken):
┌─────────────────────────────────────────────────────────────────┐
│  Circuit intent: Prove knowledge of x where hash(x) = H         │
│                                                                 │
│  WRONG implementation:                                          │
│  ┌─────────────────┐                                           │
│  │ signal input x  │ ← Any value works!                        │
│  │ signal output H │ ← No constraint tying x to H!             │
│  │                 │                                           │
│  │ H <== hash(x)   │ ← Missing: constraint H == hash(x)        │
│  └─────────────────┘                                           │
│                                                                 │
│  Attacker can prove knowledge of ANY x, regardless of real H!   │
└─────────────────────────────────────────────────────────────────┘
```

### Circom Example

```circom
// VULNERABLE: Under-constrained circuit

pragma circom 2.0.0;

template VulnerableTransfer() {
    signal input sender_balance;
    signal input amount;
    signal input recipient_balance;
    
    signal output new_sender_balance;
    signal output new_recipient_balance;
    
    // VULNERABILITY: No constraint that sender has enough balance!
    new_sender_balance <-- sender_balance - amount;  // <-- is assignment only!
    new_recipient_balance <-- recipient_balance + amount;
    
    // Missing: new_sender_balance === sender_balance - amount
    // Missing: new_sender_balance >= 0
}

// SECURE: Fully constrained
template SecureTransfer() {
    signal input sender_balance;
    signal input amount;
    signal input recipient_balance;
    
    signal output new_sender_balance;
    signal output new_recipient_balance;
    
    // Constrain balance update
    new_sender_balance <== sender_balance - amount;
    new_recipient_balance <== recipient_balance + amount;
    
    // Constrain non-negative (using helper component)
    component gte = GreaterEqThan(64);
    gte.in[0] <== sender_balance;
    gte.in[1] <== amount;
    gte.out === 1;  // Enforce sender_balance >= amount
}
```

### Real-World Examples

```markdown
## Tornado Cash (2022)
- Under-constrained merkle tree verification
- Attacker could prove membership without being in tree
- Root cause: Missing constraint on merkle path validation

## ZK Bridge (2023)  
- Missing constraint on message sender
- Could prove message from any sender
- $5M+ at risk

## DETECTION PATTERNS:
1. Look for `<--` without corresponding `===`
2. Check range constraints on all arithmetic
3. Verify merkle proof constraints complete
4. Ensure nullifier uniqueness enforced
```

---

## Attack Vector 2: Trusted Setup Attacks

### Toxic Waste Problem

```
Groth16/PLONK require trusted setup generating parameters

SETUP:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Generate random τ (toxic waste)                                │
│         │                                                       │
│         ▼                                                       │
│  Compute: [τ^0, τ^1, τ^2, ... τ^n]G                            │
│         │                                                       │
│         ▼                                                       │
│  MUST destroy τ!                                                │
│                                                                 │
│  IF τ is known:                                                 │
│  - Attacker can forge proofs                                    │
│  - Entire system is broken                                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Multi-Party Ceremony Attacks

```markdown
## MPC Ceremony Security

The ceremony is secure if AT LEAST ONE participant is honest.

ATTACK VECTORS:
1. **Compromise all participants**
   - All participants collude
   - All participants' machines compromised
   
2. **Contribution manipulation**
   - Insert backdoor during contribution
   - Skip randomness injection
   
3. **Verification skip**
   - Accept invalid contributions
   - Don't verify transcript continuity

DEFENSES:
- Large number of participants (1000+)
- Diverse geographic/organizational distribution
- Publish all transcripts for verification
- Allow anyone to verify ceremony
```

### Verification Code

```solidity
// Verify trusted setup transcript

contract SetupVerifier {
    // Verify contribution is properly derived
    function verifyContribution(
        bytes calldata prevTranscript,
        bytes calldata newTranscript,
        bytes calldata proof
    ) external pure returns (bool) {
        // 1. Verify prev transcript hash
        require(
            keccak256(prevTranscript) == expectedPrevHash,
            "Invalid previous transcript"
        );
        
        // 2. Verify new transcript extends prev correctly
        // (Pairing checks that new = prev * random)
        require(
            verifyPairing(prevTranscript, newTranscript, proof),
            "Invalid contribution"
        );
        
        // 3. Verify no tau knowledge proof
        require(
            verifyNoTauKnowledge(proof),
            "Tau knowledge detected"
        );
        
        return true;
    }
}
```

---

## Attack Vector 3: Proof Malleability

### The Problem

```
Some proof systems allow modifying valid proofs into different valid proofs

ATTACK:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Original: Proof π proves statement S                           │
│                                                                 │
│  Malleable: Proof π' also proves S (π' ≠ π)                     │
│                                                                 │
│  ISSUE: If proof is used as unique identifier...                │
│  - Replay with π' after π already used                          │
│  - DoS by submitting π' before π                                │
│  - Privacy break (link π and π' as same statement)              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Real Exploitation

```solidity
// Vulnerable: Uses proof as nullifier
contract VulnerableZKApp {
    mapping(bytes32 => bool) public usedProofs;
    
    function processProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external {
        bytes32 proofHash = keccak256(proof);
        require(!usedProofs[proofHash], "Proof already used");
        
        require(verifier.verify(proof, publicInputs), "Invalid proof");
        
        usedProofs[proofHash] = true;
        
        // VULNERABILITY: Attacker can create malleable proof π'
        // Different hash, same public inputs, still valid!
        _processTransaction(publicInputs);
    }
}

// Secure: Uses public inputs as nullifier
contract SecureZKApp {
    mapping(bytes32 => bool) public usedNullifiers;
    
    function processProof(
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 nullifier  // Explicitly in public inputs
    ) external {
        require(!usedNullifiers[nullifier], "Already processed");
        
        // Verify nullifier is committed in public inputs
        require(
            bytes32(publicInputs[0:32]) == nullifier,
            "Nullifier mismatch"
        );
        
        require(verifier.verify(proof, publicInputs), "Invalid proof");
        
        usedNullifiers[nullifier] = true;
        _processTransaction(publicInputs);
    }
}
```

---

## Attack Vector 4: Verifier Bugs

### Solidity Verifier Issues

```solidity
// Common verifier vulnerabilities

contract VulnerableVerifier {
    // VULNERABILITY 1: Missing scalar field check
    function verify(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata inputs
    ) external view returns (bool) {
        // MISSING: Check inputs < scalar field order
        // Attacker can use inputs >= q to forge proofs
        
        // Should have:
        // for (uint i = 0; i < inputs.length; i++) {
        //     require(inputs[i] < SCALAR_FIELD_ORDER);
        // }
    }
    
    // VULNERABILITY 2: Missing point validation
    function verifyPoint(
        uint256 x,
        uint256 y
    ) internal pure returns (bool) {
        // MISSING: Check point is on curve
        // Attacker can use invalid points
        
        // Should verify: y^2 = x^3 + ax + b (mod p)
    }
    
    // VULNERABILITY 3: Incorrect pairing check
    function pairing(
        G1Point[] memory p1,
        G2Point[] memory p2
    ) internal view returns (bool) {
        // WRONG: Checking wrong number of pairings
        // Groth16 requires exactly 4 pairings
    }
}
```

### Verifier Audit Checklist

```markdown
## Verifier Security Checklist

### Input Validation
□ All scalar inputs < field order?
□ All points validated on curve?
□ Point at infinity handled correctly?
□ Correct number of public inputs?

### Cryptographic Operations
□ Pairing equation correct?
□ Miller loop implementation correct?
□ Final exponentiation correct?
□ No modular arithmetic overflow?

### Gas & DoS
□ Gas consumption bounded?
□ No unbounded loops on inputs?
□ Precompile failures handled?
□ Stack depth sufficient?

### Integration
□ Verifier matches circuit exactly?
□ Verification key matches trusted setup?
□ Public inputs parsed correctly?
□ Proof format matches expected?
```

---

## Attack Vector 5: Soundness Errors

### Algebraic Attacks

```markdown
## Soundness = Cannot prove false statements

Common soundness breaks:

1. **Field overflow**
   - Arithmetic wraps around field order
   - Can prove 0 = 1 in certain cases
   
2. **Insufficient rounds**
   - Interactive protocols need enough rounds
   - Fiat-Shamir transform must cover all
   
3. **Weak randomness**
   - Verifier challenges predictable
   - Prover can game responses

4. **Incomplete constraints**
   - Circuit doesn't capture all requirements
   - Edge cases not constrained
```

### Example: Field Overflow

```circom
// VULNERABLE: Integer overflow in field
template Vulnerable() {
    signal input a;
    signal input b;
    signal output c;
    
    // Circom operates in prime field
    // If a + b >= p, wraps around!
    c <== a + b;
    
    // Attacker can find a, b where:
    // a + b ≡ target (mod p)
    // Even if a + b > p
}

// SECURE: Range-checked inputs
template Secure() {
    signal input a;
    signal input b;
    signal output c;
    
    // Constrain inputs to safe range
    component rangeA = Num2Bits(64);  // Max 64 bits
    rangeA.in <== a;
    
    component rangeB = Num2Bits(64);
    rangeB.in <== b;
    
    // Now a + b cannot overflow
    c <== a + b;
}
```

---

## Attack Vector 6: Data Availability Attacks

### ZK Rollup DA Issues

```
ZK rollups post proofs on-chain but may hide transaction data

ATTACK:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Valid State Transition Proof                                   │
│         │                                                       │
│         ▼                                                       │
│  ┌────────────────┐                                            │
│  │ Proof verifies │ ← Correct state transition                  │
│  └────────────────┘                                            │
│         │                                                       │
│         ▼                                                       │
│  ┌────────────────┐                                            │
│  │ But data not   │ ← Users can't reconstruct state!           │
│  │ available      │                                            │
│  └────────────────┘                                            │
│         │                                                       │
│         ▼                                                       │
│  Users cannot prove their balances                              │
│  Operator can censor/freeze funds                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Defense Patterns

```solidity
// Force data availability

contract ZKRollupWithDA {
    // Option 1: Post data on-chain
    function submitBatch(
        bytes calldata proof,
        bytes calldata transactions  // All tx data on-chain
    ) external {
        require(verifier.verify(proof, transactions), "Invalid proof");
        
        // Data is now permanently available on-chain
        emit BatchSubmitted(batchId, transactions);
    }
    
    // Option 2: Data availability committee
    function submitBatchWithDAC(
        bytes calldata proof,
        bytes32 dataHash,
        bytes[] calldata dacSignatures
    ) external {
        // Verify DAC attested to data availability
        require(
            verifyDACSignatures(dataHash, dacSignatures),
            "Insufficient DAC attestations"
        );
        
        require(verifier.verify(proof, dataHash), "Invalid proof");
    }
    
    // Option 3: Blob data (EIP-4844)
    function submitBatchWithBlob(
        bytes calldata proof,
        bytes32 blobHash
    ) external {
        // Blob data available for limited time
        // Sufficient for fraud proof window
        require(verifier.verify(proof, blobHash), "Invalid proof");
    }
}
```

---

## Audit Checklist

### Circuit Audit

```markdown
## Circuit Security Review

### Constraint Completeness
□ Every `<--` has corresponding `===`?
□ All arithmetic operations constrained?
□ Range constraints on all inputs?
□ No unconstrained intermediate signals?

### Cryptographic Soundness
□ Hash function constraints complete?
□ Signature verification constraints complete?
□ Merkle proof verification complete?
□ Nullifier computation constrained?

### Edge Cases
□ Zero inputs handled correctly?
□ Maximum value inputs safe?
□ Empty arrays/lists handled?
□ Duplicate inputs rejected?

### Information Leakage
□ Private inputs not leaked via constraints?
□ Timing attacks not possible?
□ Error messages don't leak private data?
```

### Integration Audit

```markdown
## ZK System Integration Review

### Verifier Contract
□ Verifier matches circuit?
□ Verification key correct?
□ Input validation complete?
□ Precompiles used correctly?

### Data Flow
□ Public inputs derived correctly?
□ Private inputs stay private?
□ Proof generation deterministic?
□ Proof not replayable?

### System Security
□ Trusted setup verified?
□ Ceremony transcript available?
□ Data availability ensured?
□ Upgrade mechanism safe?
```

---

## Related Resources

- [ZK Bug Tracker](https://github.com/0xPARC/zk-bug-tracker)
- [Circom Documentation](https://docs.circom.io/)
- [zkSNARKs Explained](https://vitalik.eth.limo/general/2021/01/26/snarks.html)
- [STARK vs SNARK](https://consensys.net/blog/blockchain-explained/zero-knowledge-proofs-starks-vs-snarks/)
