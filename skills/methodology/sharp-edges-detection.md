---
id: METH-SHARP-EDGES-DETECTION
title: Sharp Edges Detection
category: methodology
severity: critical
chains: [ethereum, solana, cosmos, aptos, all]
languages: [solidity, rust, move, typescript]
tags:
  - sharp-edges
  - dangerous-apis
  - footguns
  - variant-analysis
  - language-specific
  - attack-surface
  - pattern-extraction
  - semgrep
last_updated: 2026-02-27
description: >-
  Use when systematically hunting for dangerous API usage, language-specific
  footguns, and error-prone defaults across a codebase — applies the
  Source-Transform-Sink framework to extract variant patterns from known
  vulnerabilities. Different from individual vulnerability patterns — this
  is a meta-methodology for DISCOVERING which dangerous constructs exist
  in any given codebase regardless of language or chain.
---

# Sharp Edges Detection

## Overview

Sharp edges are language features, API defaults, or common coding patterns
that silently produce vulnerabilities. They are not bugs in the traditional
sense — the code compiles, passes basic tests, and appears correct. The
danger is that correctness DEPENDS on the developer knowing the edge.

**Core principle**: Every language and framework has footguns. Systematically
catalog them, scan for them, and flag every instance. One missed sharp edge
can be a Critical vulnerability.

### Why Sharp Edges Are Different from Bugs

| Property | Normal Bug | Sharp Edge |
|----------|-----------|------------|
| Visible in review | Often obvious | Looks correct |
| Compiler/linter catches it | Usually | Never |
| Developer intended the code | No | Yes |
| Requires domain knowledge | Sometimes | Always |
| Example | Off-by-one | `tx.origin` for auth |

## Sharp Edges Catalog

### Solidity-Specific Sharp Edges

#### Authentication Footguns

| Sharp Edge | Why It's Dangerous | Safe Alternative |
|-----------|-------------------|------------------|
| `tx.origin` for auth | Phishing via malicious contract forwards `tx.origin` | `msg.sender` + explicit caller checks |
| Missing `onlyOwner` on critical functions | Unrestricted access to privileged ops | Role-based access control (OpenZeppelin) |
| `ecrecover` returning `address(0)` | Invalid signature silently returns zero address | Check `recovered != address(0)` before use |
| Signature malleability (s-value) | Same message can produce two valid signatures | Enforce `s <= secp256k1n/2` |

#### State Mutation Footguns

| Sharp Edge | Why It's Dangerous | Safe Alternative |
|-----------|-------------------|------------------|
| External calls before state updates | Classic reentrancy — state is stale during callback | Checks-Effects-Interactions pattern |
| `delegatecall` to untrusted target | Callee executes in caller's storage context | Whitelist targets; verify implementation |
| `selfdestruct` in implementation | Bricks proxy contracts permanently | Remove `selfdestruct`; use circuit-breakers |
| Uninitialized proxy storage | Implementation slot collision overwrites state | Use ERC-1967 storage slots |
| Missing reentrancy guard on `withdraw` | Recursive calls drain funds | `nonReentrant` modifier + CEI |

#### Arithmetic & Precision Footguns

| Sharp Edge | Why It's Dangerous | Safe Alternative |
|-----------|-------------------|------------------|
| Unchecked math in assembly | Overflow/underflow bypasses Solidity 0.8 protections | Explicit bounds checks in assembly blocks |
| Division before multiplication | Precision loss amplifies with each division | `(a * b) / c` not `(a / c) * b` |
| `block.timestamp` for randomness | Miners can manipulate within ~15 second window | Chainlink VRF or commit-reveal |
| Casting `int256` to `uint256` | Negative values wrap to enormous positive values | Check `value >= 0` before cast |
| `abi.encodePacked` with dynamic types | Hash collisions when adjacent dynamic args merge | Use `abi.encode` for hashing |

#### EVM Execution Footguns

| Sharp Edge | Why It's Dangerous | Safe Alternative |
|-----------|-------------------|------------------|
| Unchecked low-level `.call()` return | Failed call silently continues execution | `require(success, "call failed")` |
| `gasleft()` for randomness/branching | Gas is manipulable by miners and users | Never branch on gas remaining |
| `SSTORE` to same slot costs less | Optimizer removes "redundant" stores that aren't | Test with optimizer on AND off |
| Frontrunning on `approve` | Race condition between old and new allowance | `increaseAllowance`/`decreaseAllowance` |

### Rust (Solana) Sharp Edges

#### Account Validation Footguns

| Sharp Edge | Why It's Dangerous | Safe Alternative |
|-----------|-------------------|------------------|
| Missing owner check | Any program can create accounts with matching seeds | `constraint = account.owner == expected_program` |
| Missing signer check | Unsigned instructions accepted | Add `Signer<'info>` constraint |
| Unchecked account deserialization | Attacker passes account of wrong type | Use typed `Account<'info, T>` wrappers |
| PDA without bump verification | Attacker can grind alternative PDAs | Store and verify bump seed |
| Missing `is_initialized` check | Double-initialization overwrites legitimate data | Check flag before writing; use Anchor `init` |

#### Arithmetic Footguns

| Sharp Edge | Why It's Dangerous | Safe Alternative |
|-----------|-------------------|------------------|
| `as` casts (e.g., `u64 as u32`) | Silent truncation — no panic, no error | Use `try_into().unwrap()` or checked casts |
| Integer overflow in release mode | Rust wraps in release by default | Use `checked_add`, `checked_mul`, etc. |
| Floating-point in on-chain code | Non-deterministic across validators | Use fixed-point with explicit precision constants |
| `unwrap()` on user-controlled input | Program panics, blocking all users | Return `ProgramError` or use `?` operator |

#### CPI (Cross-Program Invocation) Footguns

| Sharp Edge | Why It's Dangerous | Safe Alternative |
|-----------|-------------------|------------------|
| CPI to unverified program ID | Attacker substitutes malicious program | Hardcode expected program ID; verify at runtime |
| Missing PDA signer seeds in CPI | CPI call fails or uses wrong authority | Pass all seeds including bump |
| Returning data from untrusted CPI | Return data can be spoofed | Verify CPI callee before trusting return |
| `invoke_signed` with wrong seeds | Silent failure — different PDA derived | Log and verify derived PDA matches expected |

### Move (Aptos/Sui) Sharp Edges

| Sharp Edge | Why It's Dangerous | Safe Alternative |
|-----------|-------------------|------------------|
| Missing `acquires` annotation | Compile error, but easy to forget in refactors | Run `aptos move prove` after every change |
| Phantom type parameter abuse | Type erasure allows substituting malicious types | Use `has store` ability constraints |
| `borrow_global_mut` without guards | Global state races in concurrent transactions | Design around object model where possible |
| Missing coin type verification | Accept any coin type as payment | Check `CoinType == expected` before transfer |

### Cross-Language Sharp Edges

| Sharp Edge | Languages | Why It's Dangerous |
|-----------|-----------|-------------------|
| Hash collision in mappings | Solidity, Rust, Move | `keccak256(abi.encodePacked(a,b))` collisions |
| Timestamp dependence | All | Block producer controls timestamp |
| Reentrancy (cross-contract) | Solidity, Rust via CPI | Callback between state read and write |
| Uninitialized storage | Solidity (proxy), Rust | First writer sets critical parameters |
| Integer precision loss | All | Division truncation accumulates |

## Source-Transform-Sink Framework

The S-T-S framework extracts variant patterns from a single known vulnerability
into a reusable detection pattern.

### Framework Concept

```
SOURCE    →    TRANSFORM    →    SINK
(where dangerous      (how data flows     (where the
 data enters)          through code)        damage occurs)
```

### Extraction Process

Given a known vulnerability:

1. **Identify the SINK** — What operation caused the damage?
   - Unauthorized transfer, storage overwrite, privilege escalation
2. **Trace to SOURCE** — Where did the dangerous input originate?
   - User calldata, oracle response, CPI return data, storage read
3. **Map the TRANSFORM** — What processing occurred between source and sink?
   - Casting, arithmetic, deserialization, encoding

### Pattern Templates

#### Template 1: Missing Validation (Auth Bypass)

```
SOURCE: msg.sender / ctx.accounts.authority
TRANSFORM: None (direct use without check)
SINK: State mutation / fund transfer

Detection: Find state-changing functions where caller identity
           is used but never validated against stored authority.
```

#### Template 2: Unsafe Type Conversion

```
SOURCE: External numeric input (uint256, u64, i128)
TRANSFORM: Type cast (as, uint128(), int256())
SINK: Arithmetic operation or comparison

Detection: Find all type narrowing casts. Check if overflow/underflow
           is handled. Check if sign change is validated.
```

#### Template 3: Oracle Data Trust

```
SOURCE: Oracle price feed (Chainlink, Pyth, Switchboard)
TRANSFORM: Price calculation (multiply, divide, normalize)
SINK: Collateral valuation, liquidation threshold

Detection: Find all oracle reads. Verify staleness check, confidence
           interval check, zero-price check, and decimal normalization.
```

#### Template 4: Cross-Program Trust

```
SOURCE: CPI return data / external call return
TRANSFORM: Deserialization, field extraction
SINK: Authorization decision or value calculation

Detection: Find all CPI calls or external calls. Verify program ID
           is validated before trusting the return data.
```

#### Template 5: Encoded Data Collision

```
SOURCE: Multiple user-controlled string/bytes inputs
TRANSFORM: abi.encodePacked concatenation
SINK: keccak256 hash used as mapping key or signature

Detection: Find all abi.encodePacked calls with 2+ dynamic args.
           Check if the hash is used for uniqueness guarantees.
```

## Variant Analysis Workflow

### Step 1: Catalog Known Instance

```
FINDING: [describe the vulnerability found]
SHARP EDGE: [which dangerous API/pattern was misused]
ROOT CAUSE: [why the dangerous pattern was used]
```

### Step 2: Extract Pattern Template

```
S-T-S Pattern:
  SOURCE: [input type and origin]
  TRANSFORM: [data processing steps]
  SINK: [dangerous operation reached]

Regex/Semgrep signature: [detection pattern]
```

### Step 3: Scan for Variants

Run the extracted pattern across:
- [ ] Same contract (other functions)
- [ ] Same project (other contracts)
- [ ] Dependencies (inherited/imported code)
- [ ] Related protocols (forks, similar architecture)

### Step 4: Classify Hits

For each match found by scanning:

| Classification | Action |
|---------------|--------|
| True positive — exploitable | File as separate finding |
| True positive — mitigated elsewhere | Note in report as defense-in-depth |
| False positive — different context | Document why this instance is safe |
| New variant — different transform | Add new S-T-S template to catalog |

## Semgrep Integration

### Writing Custom Rules

```yaml
rules:
  - id: solidity-tx-origin-auth
    patterns:
      - pattern: require(tx.origin == $ADDR, ...)
    message: "tx.origin used for authentication — phishable"
    severity: ERROR
    languages: [solidity]

  - id: solidity-unsafe-encodePacked
    patterns:
      - pattern: keccak256(abi.encodePacked($...ARGS))
      - metavariable-regex:
          metavariable: $...ARGS
          regex: ".*,.*"  # at least 2 arguments
    message: "abi.encodePacked with multiple args — hash collision risk"
    severity: WARNING
    languages: [solidity]

  - id: rust-unchecked-as-cast
    patterns:
      - pattern: $X as $TYPE
      - metavariable-regex:
          metavariable: $TYPE
          regex: "(u8|u16|u32|i8|i16|i32)"
    message: "Narrowing cast may silently truncate"
    severity: WARNING
    languages: [rust]
```

### Running Scans

```bash
# Scan Solidity project
semgrep --config sharp-edges-solidity.yaml contracts/

# Scan Rust project
semgrep --config sharp-edges-rust.yaml programs/

# Scan with all rules
semgrep --config sharp-edges/ .
```

## Systematic Checklist

### Pre-Audit Sharp Edge Sweep

**Phase 1: Language Identification**
- [ ] Identify all languages in scope
- [ ] Load language-specific sharp edges catalog
- [ ] Note compiler/runtime version (affects which edges apply)

**Phase 2: Automated Scan**
- [ ] Run semgrep with language-specific rules
- [ ] Run slither (Solidity) or clippy (Rust) with security lints
- [ ] Collect all hits — do NOT filter yet

**Phase 3: Manual Triage**
- [ ] For each automated hit, classify: TP / FP / needs investigation
- [ ] For each TP, extract S-T-S template
- [ ] Run variant analysis with extracted templates

**Phase 4: Documentation**
- [ ] Map each sharp edge to a finding or "verified safe" note
- [ ] Record new patterns discovered during analysis
- [ ] Update project-specific sharp edges catalog

### Per-Function Sharp Edge Checklist

For each function in scope:

- [ ] **Auth**: Who can call this? Is the check correct? (tx.origin? msg.sender?)
- [ ] **Inputs**: Are all external inputs validated? Type ranges? Lengths?
- [ ] **Arithmetic**: Any division? Any casting? Any unchecked blocks?
- [ ] **External calls**: Any `.call()`, `delegatecall`, CPI, or cross-contract?
- [ ] **State ordering**: Are state changes before or after external calls?
- [ ] **Return values**: Are all return values checked?
- [ ] **Encoding**: Any `abi.encodePacked` with dynamic types?
- [ ] **Timestamps**: Any `block.timestamp` used for logic beyond logging?

## Integration with Other Skills

| Skill | How Sharp Edges Detection Feeds Into It |
|-------|----------------------------------------|
| [Variant Analysis](../variant-analysis/) | S-T-S templates become variant search patterns |
| [Static Analysis](../static-analysis/) | Semgrep rules from sharp edges catalog |
| [Codebase Recon](methodology/codebase-recon-methodology.md) | Sharp edges inform what to look for in recon |
| [Exploit Forensics](../exploit-forensics/) | Post-exploit: which sharp edge was the root cause? |
| [Fix Patterns](../fix-patterns/) | Each sharp edge has a paired safe alternative |

## Example: Full Sharp Edge Analysis

### Scenario: Lending Protocol on Solana

```
1. Language scan → Rust + Anchor
2. Load: Rust sharp edges + Solana account validation edges
3. Automated scan finds:
   - 3 × `as u64` casts (potential truncation)
   - 1 × missing owner check on interest rate account
   - 2 × unwrap() on deserialize()
4. Manual triage:
   - Cast #1: u128 → u64, could overflow → FINDING (High)
   - Cast #2: u32 → u64, safe widening → FP
   - Cast #3: i64 → u64, negative wraps → FINDING (Critical)
   - Owner check: exploitable by substituting malicious account → FINDING (Critical)
   - unwrap #1: on user input → FINDING (Medium, DoS)
   - unwrap #2: on known-good constant → FP
5. Extract S-T-S templates from findings #1, #3, #4
6. Variant scan finds 2 more instances of pattern #3
7. Total: 5 findings from systematic sharp edge sweep
```
