---
id: quick-scan-workflow
title: Quick Scan Workflow
category: workflow
parent_skill: solidity-scanner/SKILL.md
triggers:
  - quick scan
  - rapid review
  - triage
  - time-boxed review
  - preliminary assessment
tags:
  - quick-scan
  - triage
  - workflow
  - rapid
last_updated: 2026-02-24
---

# Quick Scan Workflow (15–20 minutes)

## Purpose

Rapid vulnerability identification for time-constrained reviews: contest triage, preliminary assessments, or deciding whether a codebase warrants a full audit. This is NOT a substitute for a comprehensive audit — it catches the top 10–20% of issues with the highest severity.

## When to Use

| Scenario | Time | Goal |
|---|---|---|
| Contest first hour | 15–20 min | Find quick wins before deep dive |
| Client pre-assessment | 20 min | Decide if full audit is needed |
| PR/diff review | 10–15 min | Check a specific code change |
| Bug bounty triage | 15 min | Rapid scan of a new target |
| Post-incident response | 10 min | Quick check for related vulnerabilities |

## Confidence Scoring

A quick scan can only provide limited assurance. Report your confidence level:

| Confidence | Meaning | Criteria |
|---|---|---|
| **Low** (30–50%) | Major gaps remain | Only automated tools + access control checked |
| **Medium** (50–70%) | Core paths reviewed | Money flows traced, oracle checked, CEI verified |
| **High** (70–85%) | Thorough quick pass | All 6 steps completed, no complex logic skipped |

A quick scan can NEVER provide > 85% confidence. Complex protocol logic, cross-contract interactions, and multi-step attack chains require a comprehensive audit.

---

## Steps

### Step 1: Setup & Reconnaissance (2 min)

```bash
# Identify compiler version
grep -r "pragma solidity" src/ --include="*.sol" | head -20

# Count contracts and SLOC
find src/ -name "*.sol" | wc -l                    # contract count
find src/ -name "*.sol" -exec cat {} \; | wc -l    # total lines
cloc src/ --include-lang=Solidity                   # if cloc installed

# List external dependencies
cat package.json | grep -A 20 '"dependencies"'     # npm
grep -r "import" src/ --include="*.sol" | grep "@" | sort -u  # imports
```

**Record immediately**:

```markdown
Quick Scan Notes:
- Solidity version: ___
- Compiler optimizations: ___
- Contract count: ___
- Total SLOC: ___
- External deps: ___
- Protocol type: [ ] AMM  [ ] Lending  [ ] Vault  [ ] Bridge  [ ] Governance  [ ] Other
- Proxy pattern: [ ] None  [ ] Transparent  [ ] UUPS  [ ] Beacon  [ ] Diamond
```

---

### Step 2: Automated Scan (3 min)

```bash
# Slither — fast mode, critical detectors only
slither . --filter-paths "test|mock|script" 2>&1 | tee slither-quick.txt

# Aderyn — very fast Rust-based scanner
aderyn . --output aderyn-quick.md
```

**Triage in 60 seconds** — scan output for these detector names only:

| Detector | If Found | Action |
|---|---|---|
| `reentrancy-eth` | Possible reentrancy with ETH | Verify CEI pattern manually |
| `reentrancy-no-eth` | Possible reentrancy (state) | Check if state updated after external call |
| `suicidal` | Unprotected selfdestruct | Critical — verify immediately |
| `arbitrary-send-eth` | Unguarded ETH send | Check access control on function |
| `controlled-delegatecall` | User-controlled delegatecall | Critical — verify target validation |
| `uninitialized-state` | State variable never initialized | Check if default value is safe |
| `unchecked-transfer` | ERC20 return value ignored | Check if using SafeERC20 |
| `weak-prng` | Predictable randomness | Check if used for security-critical logic |
| `tx-origin` | tx.origin for auth | Verify it's not the sole auth check |

Skip everything else. Low-severity and informational findings are noise in a quick scan.

---

### Step 3: Access Control Pass (3 min)

```bash
# List all external/public functions
slither . --print function-summary 2>/dev/null | grep -E "external|public" | grep -v "view|pure"

# Check for missing access control
grep -rn "function.*external\|function.*public" src/ --include="*.sol" | \
  grep -v "view\|pure\|override\|constructor\|receive\|fallback"
```

**Quick check each state-changing external function**:

```markdown
For each function, answer:
1. Who should call this?  → everyone / admin / keeper
2. Is there a modifier?  → onlyOwner / onlyRole / none ← FLAG IF NONE
3. Can it move funds?    → yes / no ← HIGH PRIORITY IF YES + NO MODIFIER
```

**Specific patterns to catch**:

```bash
# Unprotected initialize
grep -rn "function initialize" src/ --include="*.sol"
# Verify: has `initializer` modifier? Can be called twice?

# Unprotected upgrade
grep -rn "upgradeTo\|upgradeToAndCall" src/ --include="*.sol"
# Verify: has `onlyOwner` or equivalent?

# Unprotected selfdestruct (pre-Cancun)
grep -rn "selfdestruct\|SELFDESTRUCT" src/ --include="*.sol"

# Unprotected pause/unpause
grep -rn "function pause\|function unpause\|function setPause" src/ --include="*.sol"
```

---

### Step 4: Money Flow Pass (5 min)

**This is the highest-value step.** Trace every path that moves tokens or ETH.

```bash
# Find all token transfers
grep -rn "\.transfer\|\.transferFrom\|\.safeTransfer\|\.safeTransferFrom" src/ --include="*.sol"

# Find all ETH sends
grep -rn "\.call{value\|\.send(\|\.transfer(" src/ --include="*.sol"

# Find all mint/burn operations
grep -rn "\_mint\|\_burn" src/ --include="*.sol"

# Find all approve/allowance operations
grep -rn "\.approve\|\.safeApprove\|\.safeIncreaseAllowance" src/ --include="*.sol"
```

**For each transfer found, verify**:

| Check | What to Look For | Severity if Missing |
|---|---|---|
| CEI pattern | State updated BEFORE external call? | Critical (reentrancy) |
| Return value | Using safeTransfer or checking bool return? | High (silent failure) |
| Amount validation | Is amount > 0? Is amount ≤ balance? | Medium |
| Recipient validation | Can recipient be address(0)? | Low |
| Fee-on-transfer | Is actual received amount checked? | Medium–High |

**Share/exchange rate check** (if vault or pool):

```bash
# Find division operations in share calculations
grep -rn "totalSupply\|totalAssets\|convertToShares\|convertToAssets" src/ --include="*.sol"
```

Quick questions:
- What happens when `totalSupply == 0`? (first depositor)
- Is rounding direction correct? (should favor protocol)
- Can anyone donate to inflate the exchange rate?

---

### Step 5: High-Impact Checks (5 min)

Run through these five critical areas. Spend ~1 minute on each.

#### 5a: Oracle Usage

```bash
grep -rn "latestRoundData\|latestAnswer\|getPrice\|slot0\|getReserves\|observe" src/ --include="*.sol"
```

| Pattern | Risk | Quick Verdict |
|---|---|---|
| `latestAnswer()` | No staleness check possible | Flag immediately |
| `latestRoundData()` without staleness check | Stale price risk | Check for `updatedAt` comparison |
| `slot0()` or `getReserves()` | Spot price = flash loan manipulable | Flag immediately |
| `observe()` with time window | TWAP — generally safer | Check window length (≥ 30 min) |

#### 5b: Flash Loan Vectors

```bash
# Check if protocol reads external balances
grep -rn "balanceOf(address(this))\|getReserves\|slot0" src/ --include="*.sol"
```

Any function that reads an external balance and acts on it in the same transaction is a potential flash loan target.

#### 5c: Signature / Replay Protection

```bash
grep -rn "ecrecover\|ECDSA\|EIP712\|permit\|nonce" src/ --include="*.sol"
```

If signatures are used: Is there a nonce? Is there a deadline? Is there chain ID in the domain separator?

#### 5d: Proxy / Storage

```bash
grep -rn "delegatecall\|Proxy\|Upgradeable\|ERC1967" src/ --include="*.sol"
```

If upgradeable: storage gaps present? `_disableInitializers()` in constructor? Implementation can't be initialized directly?

#### 5e: Timestamp / Block Dependence

```bash
grep -rn "block.timestamp\|block.number" src/ --include="*.sol"
```

Is `block.timestamp` used for randomness (bad) or deadlines (acceptable)?

---

### Step 6: Report Quick Findings

**Output format** — concise, actionable:

```markdown
# Quick Scan Report
Date: YYYY-MM-DD
Auditor: [name]
Scope: [contracts/commit]
Time spent: [X] minutes
Confidence: [Low / Medium / High]

## Summary
- Contracts scanned: X
- SLOC: X
- Critical findings: X
- High findings: X
- Medium findings: X
- Recommendation: [ ] Safe to proceed  [ ] Needs full audit  [ ] Do NOT deploy

## Findings

### [QS-01] [Critical/High/Medium] Title
**File**: Contract.sol:Line
**Description**: One sentence.
**Impact**: What can go wrong.
**Fix**: Specific change needed.

### [QS-02] ...

## Areas NOT Covered (Limitations)
- [ ] Complex business logic verification
- [ ] Multi-step attack chain analysis
- [ ] Full token compatibility testing
- [ ] Invariant testing
- [ ] Cross-contract interaction analysis
- [ ] Gas optimization review
```

---

## Exit Criteria

A quick scan is complete when ALL of these are true:

```markdown
- [ ] Automated tools run and critical findings triaged
- [ ] All state-changing external functions checked for access control
- [ ] All token/ETH transfer paths traced for CEI compliance
- [ ] Oracle usage verified (if any)
- [ ] Flash loan attack surfaces identified (if any)
- [ ] Confidence level assigned
- [ ] Quick scan report generated
```

## Escalation Decision

After completing the quick scan, decide the next step:

| Finding | Action |
|---|---|
| Critical or High found | Escalate immediately. Recommend full audit before deployment. |
| Multiple Mediums | Recommend full audit. Quick scan likely missed deeper issues. |
| Only Lows / Clean | Protocol may be safe, but note quick scan limitations. |
| Complex protocol logic | Recommend comprehensive audit regardless of quick scan results. |
| Fork with minimal changes | Quick scan may be sufficient if original was audited. Verify diff only. |
