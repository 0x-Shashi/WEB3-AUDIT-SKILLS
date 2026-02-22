---
id: STATIC-WF-ANALYSIS
title: Static Analysis Workflow
parent: static-analysis
type: workflow
last_updated: 2025-01-31
---

# Static Analysis Workflow

Step-by-step process for integrating static analysis into a smart contract audit. Run this workflow AFTER compilation and BEFORE manual code review.

---

## Prerequisites

- [ ] Solidity project compiles successfully (`forge build` or `npx hardhat compile`)
- [ ] Slither installed (`pip install slither-analyzer`)
- [ ] Correct `solc` version selected (`solc-select use 0.8.XX`)
- [ ] Project dependencies resolved (submodules cloned, npm installed)
- [ ] Aderyn installed (optional: `cargo install aderyn`)

---

## Step 1: Environment Verification

```bash
# Verify compilation
forge build  # Foundry
# or
npx hardhat compile  # Hardhat

# Verify Slither installation
slither --version  # Should be >= 0.10.0

# Verify solc version matches project pragma
solc --version
solc-select use 0.8.20  # Match project's pragma

# Quick project overview with Slither
slither . --print human-summary --filter-paths "node_modules|lib|test"
```

Expected output from `human-summary`:
```
Compilation warnings/errors on ...
INFO:Slither:
Total number of contracts in source: 12
Source lines of code (SLOC) in source: 1,847
Number of assembly lines: 23
Number of optimization issues: 8
Number of informational issues: 15
Number of low issues: 6
Number of medium issues: 3
Number of high issues: 1
ERCs: ERC20, ERC4626
```

---

## Step 2: Full Slither Scan

```bash
# Run all detectors, output JSON for tracking
slither . \
  --json slither-full.json \
  --filter-paths "node_modules|lib|test|script|mock" \
  2>&1 | tee slither-output.txt
```

Capture the summary output. Note total findings by severity.

| Severity | Count | Triaged |
|----------|------|---------|
| High | [N] | [ ] |
| Medium | [N] | [ ] |
| Low | [N] | [ ] |
| Informational | [N] | [ ] |

---

## Step 3: Triage High-Severity Findings

For each High finding:

```
1. Read detector description (what pattern was matched?)
2. Navigate to flagged code location
3. Understand the full execution context:
   - Is the function externally callable?
   - Are there modifiers protecting it?
   - Is the external call to a trusted target?
4. Determine verdict: TRUE POSITIVE or FALSE POSITIVE
5. If TP: Classify severity (may differ from Slither's) and write finding
6. If FP: Document why (will be useful if questioned)
```

### High-Priority Detectors to Review First

| Detector | What to Check |
|----------|---------------|
| `reentrancy-eth` | Is there really a state change after an ETH transfer? Is there a reentrancy guard? |
| `arbitrary-send-eth` | Who controls the recipient? Is the function access-controlled? |
| `controlled-delegatecall` | Can user actually control the target address? |
| `suicidal` | Is `selfdestruct` access-controlled? (Also: deprecated after Dencun) |
| `unprotected-upgrade` | Can anyone call `upgradeTo()`? |
| `uninitialized-state` | Is the variable actually used before assignment? |

---

## Step 4: Triage Medium-Severity Findings

Same triage process. Pay special attention to:

| Detector | Context Check |
|----------|---------------|
| `reentrancy-no-eth` | Cross-function reentrancy is often real. Check if state corruption is exploitable. |
| `unchecked-transfer` | Is the token known-good (WETH, OZ ERC20) or arbitrary? Arbitrary = likely TP. |
| `tx-origin` | Is it used for auth or just logging? Auth = TP. |
| `incorrect-equality` | Is `==` comparing to a manipulable value (balance, supply)? |
| `divide-before-multiply` | Does the lost precision actually matter in context? Small amounts = Low, large = Medium. |

---

## Step 5: Targeted Detector Runs

After initial triage, run focused scans on high-risk areas:

```bash
# REENTRANCY DEEP DIVE
# Run all reentrancy variants
slither . --detect reentrancy-eth,reentrancy-no-eth,reentrancy-benign,reentrancy-events \
  --filter-paths "node_modules|lib|test"

# ACCESS CONTROL AUDIT
slither . --detect arbitrary-send-eth,arbitrary-send-erc20,controlled-delegatecall,suicidal,unprotected-upgrade \
  --filter-paths "node_modules|lib|test"

# ERC COMPLIANCE
slither . --print erc-conformance
slither . --detect erc20-interface,erc721-interface

# PRECISION / MATH
slither . --detect divide-before-multiply,incorrect-equality \
  --filter-paths "node_modules|lib|test"

# DANGEROUS PATTERNS
slither . --detect encode-packed-collision,unchecked-lowlevel,unchecked-send,unchecked-transfer \
  --filter-paths "node_modules|lib|test"
```

---

## Step 6: Aderyn Complementary Scan (Optional)

```bash
# Run Aderyn for complementary detection
aderyn . --src src/ --output aderyn-report.md
```

Aderyn catches some patterns Slither misses:
- Centralization risk indicators
- Solmate `SafeTransferLib` contract existence check
- Push0 opcode incompatibility
- More modern Solidity anti-patterns

---

## Step 7: Printer Analysis for Architecture

Use Slither's printers to support architecture understanding:

```bash
# Contract-level overview
slither . --print contract-summary --filter-paths "node_modules|lib|test"

# Function-level overview (modifiers, visibility, state mutability)
slither . --print function-summary --filter-paths "node_modules|lib|test"

# Storage layout (CRITICAL for upgradeable contracts)
slither . --print variable-order --filter-paths "node_modules|lib|test"

# Call graph for architecture mapping
slither . --print call-graph --filter-paths "node_modules|lib|test"
# Convert to image: dot -Tpng call-graph.dot -o callgraph.png

# Inheritance hierarchy
slither . --print inheritance-graph --filter-paths "node_modules|lib|test"
```

---

## Step 8: Document Results

### Findings Summary Table

| # | Tool | Detector | Contract | Function | Lines | Verdict | Severity | Notes |
|---|------|----------|----------|----------|-------|---------|----------|-------|
| 1 | Slither | reentrancy-eth | Vault | `withdraw()` | 45-52 | TP | HIGH | No CEI, no guard |
| 2 | Slither | arbitrary-send-eth | Treasury | `sweep()` | 78 | FP | - | onlyOwner |
| 3 | Slither | unchecked-transfer | Pool | `swap()` | 112 | TP | MED | Arbitrary token |
| 4 | Aderyn | centralization-risk | Config | `setFee()` | 34 | TP | MED | No timelock |
| 5 | Slither | tx-origin | Auth | `verify()` | 23 | TP | MED | Auth = phishable |

### Coverage Gap Analysis

| What Static Analysis Caught | What It Missed (Need Manual Review) |
|----------------------------|--------------------------------------|
| Reentrancy in withdraw | Flash loan oracle manipulation |
| Unchecked transfer returns | Economic model flaws |
| tx.origin auth | Cross-contract state inconsistency |
| Missing zero-address check | Governance attack vectors |

---

## Step 9: Cross-Reference with Manual Review

| Action | Purpose |
|--------|--------|
| Start manual review at Slither TP locations | Highest confidence areas |
| Review FP locations for design concerns | May indicate risky patterns even if not exploitable |
| Focus manual on business logic | Static analysis cannot detect economic exploits |
| Focus manual on cross-contract flows | Slither analyzes mostly single-contract |
| Re-run Slither after fixes | Verify fixes, catch regressions |

---

## Common Pitfalls

| Pitfall | Correction |
|---------|------------|
| Ignoring Low/Info findings | Low findings indicate design issues; Info reveals code quality |
| Trusting FP labels without verification | Always verify — context may make FP into TP |
| Only running default detectors | Targeted runs catch edge cases |
| Not re-running after code changes | Fixes can introduce new issues |
| Relying solely on static analysis | Static tools miss: flash loan attacks, oracle manipulation, governance exploits, economic invariant violations, MEV |
| Overwhelming report with FPs | Filter aggressively; only true issues in final report |
