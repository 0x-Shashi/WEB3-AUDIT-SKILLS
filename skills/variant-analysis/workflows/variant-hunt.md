---
id: variant-hunt-workflow
title: Variant Hunt Workflow
category: workflow
parent_skill: variant-analysis/SKILL.md
triggers:
  - found vulnerability
  - same bug elsewhere
  - variant search
  - root cause hunt
tags:
  - variant-analysis
  - workflow
  - search
  - methodology
last_updated: 2026-02-24
---

# Variant Hunt Workflow

## Trigger

Run this workflow **every time** you discover a vulnerability during an audit. A single finding should trigger a full variant sweep. Do not report a finding until you have completed this workflow.

## Overview

```
┌──────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐
│ DOCUMENT │──►│ ABSTRACT  │──►│  BUILD    │──►│  SEARCH   │──►│ VALIDATE  │
│ the bug  │   │ root cause│   │  queries  │   │  codebase │   │ each hit  │
└──────────┘   └───────────┘   └───────────┘   └───────────┘   └─────┬─────┘
                                                                     │
┌──────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌────▼──────┐
│ REPORT   │◄──│ AGGREGATE │◄──│ CROSS-REF │◄──│  EXPAND   │◄──│ CLASSIFY  │
│ all      │   │ severity  │   │ historical│   │  related  │   │ confirmed │
└──────────┘   └───────────┘   └───────────┘   └───────────┘   └───────────┘
```

---

## Step 1: Document the Found Bug

Capture the finding in precise detail before abstracting.

**Template (fill every field):**

```markdown
## Initial Finding Record

- **Contract**: TokenVault.sol
- **Function**: `withdraw(uint256 amount)`
- **Line**: 142–158
- **Pattern**: State change after external call (CEI violation)
- **Root Cause**: `balances[msg.sender] -= amount` occurs after `token.safeTransfer(msg.sender, amount)`
- **Impact**: Attacker can re-enter `withdraw()` and drain vault
- **Severity (initial)**: High
- **Vulnerable Code**:
```

```solidity
// VULNERABLE — state update after external call
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    token.safeTransfer(msg.sender, amount); // ← external call
    balances[msg.sender] -= amount;         // ← state change AFTER call
    totalDeposited -= amount;
}
```

**Why document first?** You need the exact code structure to build accurate search queries. Skipping this step leads to vague grep patterns that miss variants or produce excessive false positives.

---

## Step 2: Abstract the Pattern

Move from the specific bug to a generalized pattern using the **Abstraction Ladder**:

| Level | Description | Example |
|---|---|---|
| **L0 — Instance** | Exact code location | `withdraw()` line 155 does `balances -= amount` after `safeTransfer` |
| **L1 — Function** | Specific function pattern | `safeTransfer` followed by storage write in same function |
| **L2 — Category** | Vulnerability category | External call before state update (reentrancy / CEI violation) |
| **L3 — Root Cause** | Fundamental flaw | State mutation after untrusted external interaction |

**Target: L2** for primary search, **L3** for expansion search.

### Abstraction Questions

Ask these for every finding:

1. **What is the minimum code structure that is vulnerable?**
   → External call (`call`, `transfer`, `send`, `safeTransfer`, `safeTransferFrom`) followed by a storage write (`mapping[key] = value`, `variable = value`)

2. **What keywords/opcodes identify this pattern?**
   → `safeTransfer`, `transfer`, `.call{`, `send(`, followed by `=` assignment to state variable

3. **Does the vulnerability depend on specific context?**
   → No — any function with an external call before a state update is potentially vulnerable, regardless of token type or function purpose

4. **What are the related but distinct patterns?**
   → Read-only reentrancy (view function reads stale state), cross-function reentrancy (enters different function), cross-contract reentrancy (re-enters via callback to a different contract)

---

## Step 3: Build Search Queries

Construct queries at multiple levels of specificity, from tight to broad.

### 3A. Tight Regex — High confidence, may miss variants

```bash
# Find exact CEI violation pattern: safeTransfer/transfer followed by state writes
grep -rn -A8 "\.safeTransfer\|\.transfer\b\|\.call{" --include="*.sol" \
  | grep -B2 "\[.*\] \(=\|-=\|+=\)"
```

### 3B. Medium Regex — Broader, some false positives

```bash
# Find ALL external calls in the codebase
grep -rn "\.call{value\|\.call(\|\.safeTransfer\|\.safeTransferFrom\|\.transfer(\|\.send(" \
  --include="*.sol"

# Then for each match, manually check if state updates follow
```

### 3C. Broad Regex — Pattern family sweep

```bash
# Find ALL state-changing operations (to cross-reference with external calls)
grep -rn "\[.*\] =\|\[.*\] -=\|\[.*\] +=" --include="*.sol"

# Find all functions with both external calls and state changes
# (requires manual cross-reference of the two grep outputs)
```

### 3D. Slither Custom Detector (Automated)

```python
# custom_detector.py — Find functions that write state after external calls
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.cfg.node import NodeType
from slither.slithir.operations import HighLevelCall, LowLevelCall

class StateAfterExternalCall(AbstractDetector):
    ARGUMENT = "state-after-call"
    HELP = "State variable written after external call"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://example.com"

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                external_call_seen = False
                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, (HighLevelCall, LowLevelCall)):
                            external_call_seen = True
                    if external_call_seen and node.state_variables_written:
                        info = [
                            f"State written after external call in ",
                            function, "\n\t",
                            node, "\n"
                        ]
                        results.append(self.generate_result(info))
        return results
```

Run: `slither . --detect state-after-call`

### 3E. Semgrep Rule

```yaml
rules:
  - id: reentrancy-state-after-call
    patterns:
      - pattern: |
          $IFACE.safeTransfer(...);
          ...
          $MAP[$KEY] = $VALUE;
      - pattern: |
          $IFACE.transfer(...);
          ...
          $MAP[$KEY] = $VALUE;
      - pattern: |
          $ADDR.call{...}(...);
          ...
          $MAP[$KEY] = $VALUE;
    message: "State modification after external call — potential reentrancy"
    severity: ERROR
    languages: [solidity]
```

Run: `semgrep --config reentrancy.yaml .`

### Query Selection Strategy

| Query Approach | Speed | False Positives | False Negatives | Best For |
|---|---|---|---|---|
| Tight grep | Fast | Very Low | High (misses variants) | Quick validation |
| Medium grep | Fast | Medium | Medium | First sweep |
| Broad grep | Fast | High | Low | Comprehensive coverage |
| Slither detector | Moderate | Low | Low | Production audit |
| Semgrep rule | Moderate | Low | Medium | Repeatable checks |

**Recommended order**: Medium grep → Broad grep → Slither/Semgrep for confirmation.

---

## Step 4: Execute Codebase Search

### Scope: EVERYTHING

```
Search targets (must cover ALL):
├── src/                    ← All production contracts
├── contracts/              ← Alternative layout
├── lib/                    ← Dependencies and forks
├── interfaces/             ← Check implementations match
├── test/                   ← Tests reveal intended behavior
├── script/                 ← Deployment scripts may have issues
└── node_modules/openzeppelin/  ← If using modified OZ contracts
```

### Search Execution Checklist

- [ ] Searched all production contracts (not just the one with the bug)
- [ ] Searched inherited base contracts
- [ ] Searched libraries used by the vulnerable contract
- [ ] Searched proxy implementations (all versions if upgradeable)
- [ ] Checked interfaces match implementations
- [ ] Searched test files for clues about intended behavior
- [ ] Searched deployment scripts for initialization patterns
- [ ] Cross-checked any forked/vendored dependencies

### Organizing Results

Create a tracking table as you search:

```markdown
| # | File | Function | Line | Pattern Match | Status |
|---|------|----------|------|---------------|--------|
| 1 | TokenVault.sol | withdraw() | 155 | safeTransfer before balance update | CONFIRMED |
| 2 | TokenVault.sol | claim() | 203 | safeTransfer before reward update | INVESTIGATING |
| 3 | LPPool.sol | removeLiquidity() | 89 | transfer before share burn | INVESTIGATING |
| 4 | Staking.sol | unstake() | 112 | safeTransfer before stake update | INVESTIGATING |
| 5 | RewardDistributor.sol | distribute() | 67 | safeTransfer in loop | FALSE POSITIVE (nonReentrant) |
```

---

## Step 5: Validate Each Match

Every potential match must pass a 6-point validation:

### 5A. Pattern Confirmation

```
Q: Is the vulnerable code structure actually present?
   (not just similar-looking code that is safe)

Example FALSE POSITIVE:
   token.safeTransfer(msg.sender, amount);
   emit Withdrawal(msg.sender, amount);  // ← this is NOT a state change
   // (balance was already updated before safeTransfer)
```

### 5B. Reachability Analysis

```
Q: Can an attacker reach this code path?
   - Is the function public/external?
   - What are the preconditions (require statements)?
   - Can the attacker satisfy modifier checks?
   - Is it behind a timelock or admin gate?

Example UNREACHABLE:
   function emergencyWithdraw() external onlyOwner {
       token.safeTransfer(owner, balance);
       balance = 0;  // CEI violation — but only owner can call
   }
   // → Still a design concern, but not exploitable by attacker
   //   Downgrade from High to Low/Informational
```

### 5C. Exploitability Check

```
Q: Can an attacker extract value?
   - Does the victim contract hold funds?
   - Is the callback attacker-controlled?
   - Can the reentrancy actually modify state in the attacker's favor?
   - Is there a reentrancy guard (nonReentrant modifier)?

Solidity-specific checks:
   - token.transfer() on standard ERC20 → NO callback (safe)
   - token.safeTransfer() with ERC777 → YES callback via tokensReceived()
   - address.call{value: x}("") → YES callback via receive()/fallback()
   - IERC721.safeTransferFrom → YES callback via onERC721Received()
```

### 5D. Existing Mitigations

```
Q: Is this already protected?
   Common mitigations:
   - ReentrancyGuard / nonReentrant modifier
   - Check-Effects-Interactions pattern correctly applied
   - Pull payment pattern (no direct transfer)
   - Token whitelist (no ERC777/callback tokens allowed)
   - Reentrancy lock via transient storage (EIP-1153)
```

### 5E. Impact Assessment

```
Q: What is the worst-case impact?

   For each confirmed variant, assess:
   - Maximum financial loss (in USD terms if possible)
   - Who is affected (users, protocol, LPs)
   - Is it repeatable or one-time?
   - Does it cascade to other parts of the system?
```

### 5F. Severity Classification

| Criteria | High | Medium | Low | Informational |
|---|---|---|---|---|
| Funds at risk | Direct loss | Indirect/limited | Theoretical | Best practice |
| Attacker requirement | Any user | Privileged role | Lucky timing | N/A |
| Likelihood | Highly likely | Possible | Edge case | N/A |
| Mitigation complexity | None present | Partial | Nearly mitigated | Style concern |

---

## Step 6: Classify Confirmed Variants

Group confirmed findings by their relationship:

### Category A: Identical Variants
Same root cause, same code pattern, different locations.
→ Report as **single finding with multiple instances**

```markdown
## [H-01] CEI Violation Allows Reentrancy in Multiple Functions

**Root Cause**: State updates occur after external token transfers

**Affected Locations**:
1. `TokenVault.withdraw()` — L155
2. `TokenVault.claim()` — L203
3. `LPPool.removeLiquidity()` — L89

**Single Recommendation**: Apply Check-Effects-Interactions pattern in all three functions, or add nonReentrant modifier.
```

### Category B: Related Variants
Same root cause family, different manifestation.
→ Report as **separate findings, cross-referenced**

```markdown
## [H-01] Reentrancy via CEI Violation in withdraw()
See also: [H-02] Read-only reentrancy in getPrice()

## [H-02] Read-Only Reentrancy in Price Oracle
See also: [H-01] Reentrancy via CEI violation
```

### Category C: Pattern-Adjacent Findings
Found during variant search but actually a different vulnerability class.
→ Report as **independent finding** (but credit variant analysis)

---

## Step 7: Expand to Related Patterns

After completing the primary variant search, widen the net:

### Expansion Matrix

| Original Finding | Related Pattern to Check | Search Query |
|---|---|---|
| CEI violation (reentrancy) | Read-only reentrancy | `grep -rn "view\|pure" *.sol` — check if view functions read state that external calls can modify |
| CEI violation (reentrancy) | Cross-function reentrancy | Map all functions sharing same state variables |
| Unchecked `transfer` return | Unchecked `approve` return | `grep -rn "\.approve(" *.sol \| grep -v "require\|if\|assert\|SafeERC20"` |
| Missing access control | Unprotected `initialize()` | `grep -rn "function initialize\|function init" *.sol` |
| Missing access control | Unprotected selfdestruct | `grep -rn "selfdestruct\|SELFDESTRUCT" *.sol` |
| Oracle manipulation | TWAP vs spot price | Check if protocol uses `slot0()` (spot) vs `observe()` (TWAP) |
| Rounding down on deposit | Rounding down on withdrawal | `grep -rn "/ \|div(" *.sol` — check all division operations |
| First depositor attack | Inflation attack | Check if `totalSupply == 0` case is handled |

### Cross-Contract Dependency Map

```
Build this for every protocol:

Contract A ──uses──► Oracle
Contract B ──uses──► Oracle
Contract C ──reads──► Contract A.totalDeposited

If Oracle is manipulable:
  → Contract A vulnerable
  → Contract B vulnerable  (variant!)
  → Contract C vulnerable  (second-order variant!)
```

---

## Step 8: Cross-Reference Historical Data

Before finalizing, check if the root cause pattern has known historical instances:

### 8A. Solodit Database Query

Search pattern: `"reentrancy" OR "CEI violation" OR "check-effects-interactions"`
→ Review top 10 results for attack patterns you may have missed

### 8B. DeFiHackLabs Reproduction

Check `SunWeb3Sec/DeFiHackLabs` for real-world exploits with the same root cause:
- Euler Finance (March 2023) — reentrancy in `donateToReserves()`
- Cream Finance (October 2021) — reentrancy via ERC777 token
- Fei Protocol (April 2022) — read-only reentrancy in Balancer pool

### 8C. Code4rena / Sherlock Reports

Search past audit reports for the same protocol type:
- "Compound fork" + "reentrancy" → multiple findings across forks
- "ERC4626 vault" + "first deposit" → 28+ similar findings
- "AMM" + "price manipulation" → oracle-related variant catalog

### 8D. Known Compiler / Framework Bugs

Check if the Solidity version or framework introduces the pattern:
- Solidity <0.8.0 → arithmetic overflow/underflow
- Solidity <0.8.15 → ABI encoder bug with nested arrays
- OpenZeppelin <4.7.3 → governance voting vulnerability
- OpenZeppelin <4.9.3 → ERC2771Context vulnerability

---

## Step 9: Aggregate Severity

When multiple variants of the same root cause exist, the aggregate severity may differ from individual severity:

### Severity Aggregation Rules

| Individual Severity | Instance Count | Aggregate Assessment |
|---|---|---|
| High × 1 | 1 | High |
| High × 3 | 3 | Critical (systemic pattern) |
| Medium × 1 | 1 | Medium |
| Medium × 5+ | 5+ | High (widespread pattern indicates systemic issue) |
| Low × 10+ | 10+ | Medium (pervasive, may indicate architectural flaw) |

### Aggregate Impact Calculation

```
Total Impact = Σ(individual instance impact) + systemic risk premium

Example:
  Instance 1 (withdraw):   $500K max loss
  Instance 2 (claim):      $200K max loss
  Instance 3 (unstake):    $300K max loss
  ──────────────────────────────────────
  Sum:                      $1M max loss
  Systemic premium:         Same root cause in 3/4 state-changing functions
                           → indicates architectural misunderstanding of CEI
                           → future functions likely to repeat the pattern
```

---

## Step 10: Report All Variants

### Single-Root-Cause Report Template

```markdown
## [SEVERITY-##] Root Cause Title

### Summary
[One-sentence description of the root cause pattern]

### Root Cause
[Technical description of why this pattern is vulnerable]

### Instances Found

| # | Contract | Function | Line | Impact | Notes |
|---|----------|----------|------|--------|-------|
| 1 | TokenVault.sol | withdraw() | 155 | High — direct fund drain | Original finding |
| 2 | TokenVault.sol | claim() | 203 | High — reward theft | Variant |
| 3 | LPPool.sol | removeLiquidity() | 89 | Medium — LP token loss | Variant |

### Proof of Concept

[Single PoC that demonstrates the most impactful instance, with notes on how to adapt for other instances]

### Recommendation

[Single architectural fix that addresses ALL instances. Prefer systemic fixes over per-function patches.]

**Preferred**: Add `ReentrancyGuard` and apply `nonReentrant` to all state-changing external functions.

**Alternative**: Refactor all affected functions to follow Check-Effects-Interactions pattern.

### Variant Analysis Notes
- **Search method**: grep + Slither custom detector
- **Total matches scanned**: 12
- **Confirmed vulnerable**: 3
- **False positives**: 5 (protected by nonReentrant)
- **Not applicable**: 4 (no attacker-controlled callback)
- **Related patterns checked**: Read-only reentrancy (none found), cross-function reentrancy (none found)
```

---

## Quick-Reference Grep Patterns by Vulnerability Class

| Vulnerability | Primary Grep | Refinement |
|---|---|---|
| Reentrancy (CEI) | `grep -rn "\.call{\|\.safeTransfer\|\.transfer(" *.sol` | Cross-ref with state writes after match |
| Unchecked return | `grep -rn "\.call(\|\.send(\|\.transfer(" *.sol \| grep -v "require\|if ("` | Verify no success check |
| Access control | `grep -rn "function.*external\|function.*public" *.sol \| grep -v "onlyOwner\|onlyRole\|require"` | Check if function modifies state |
| Oracle manipulation | `grep -rn "slot0\|getReserves\|latestAnswer\|latestRoundData" *.sol` | Check for staleness/manipulation protection |
| Rounding errors | `grep -rn "/ \|\.div(" *.sol` | Check for round-down favoring attacker |
| First depositor | `grep -rn "totalSupply\|totalAssets\|totalShares" *.sol` | Check zero-supply edge case |
| Frontrunning | `grep -rn "deadline\|block.timestamp\|tx.origin" *.sol` | Check for timing assumptions |
| Storage collision | `grep -rn "delegatecall\|DELEGATECALL" *.sol` | Check storage layout compatibility |
| Signature replay | `grep -rn "ecrecover\|ECDSA\|EIP712" *.sol` | Check nonce/deadline/chainId included |
| Flash loan risk | `grep -rn "flashLoan\|flashMint\|balanceOf\|totalSupply" *.sol` | Check if balance used as decision input |

---

## Checklist: Variant Hunt Completion

Before closing the variant analysis, verify:

- [ ] All production contracts searched (not just related ones)
- [ ] Inherited / parent contracts checked
- [ ] Libraries and utility contracts checked
- [ ] Proxy implementation contracts checked (all versions)
- [ ] Related pattern families expanded (Section 7 matrix)
- [ ] Historical database cross-referenced
- [ ] Every match validated with 6-point check
- [ ] Severity aggregated across instances
- [ ] Single root-cause report written with all instances
- [ ] Recommendation addresses root cause, not symptoms
