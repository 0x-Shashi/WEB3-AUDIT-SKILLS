---
id: METH-FINDING-QUALITY-STANDARDS
title: Finding Quality Standards
category: methodology
severity: high
chains: [ethereum, solana, cosmos, aptos, all]
languages: [solidity, rust, move, typescript]
tags:
  - finding-quality
  - severity-scoring
  - documentation-standards
  - quality-metrics
  - review-criteria
  - audit-report
  - coverage-tracking
last_updated: 2026-02-27
description: >-
  Use when writing audit findings, reviewing finding quality, or scoring
  audit deliverables — provides quantitative quality metrics for individual
  findings (clarity, PoC quality, severity accuracy, fix quality, coverage).
  Different from audit-report-templates (which covers report FORMAT) — this
  focuses on SCORING, quality thresholds, and good vs bad finding examples.
---

# Finding Quality Standards

## Overview

An audit finding is not "done" when a bug is identified. A finding is done
when it meets documentation standards that allow the protocol team to
understand, reproduce, prioritize, and fix the issue without asking
follow-up questions.

**Core principle**: A finding you can't explain to a senior developer in
90 seconds isn't documented well enough. Quality is measured, not assumed.

### Quality Dimensions

```
FINDING QUALITY = f(Clarity, PoC, Severity, Fix, Coverage)

Clarity:   Can someone unfamiliar reproduce this from the description alone?
PoC:       Does the proof demonstrate the EXACT impact claimed?
Severity:  Is the severity classification defensible with evidence?
Fix:       Is the recommendation specific, implementable, and safe?
Coverage:  Does the finding cover the full scope of the issue?
```

## Quality Scoring Rubric

### Dimension 1: Clarity (0-10)

| Score | Criteria |
|-------|---------|
| 9-10 | Title immediately communicates the issue. Root cause in first sentence. Impact quantified. Location specific to function:line. Any developer can understand without additional context. |
| 7-8 | Title is descriptive. Root cause clear within first paragraph. Impact described but not quantified. Location identifies the contract and function. |
| 5-6 | Title is generic. Root cause buried in description. Impact is vague ("could lead to loss"). Location only identifies the contract. |
| 3-4 | Title is misleading or overly broad. Root cause unclear. Reader must infer the actual issue. Location is approximate. |
| 1-2 | Finding is a wall of text with no clear structure. Root cause indistinguishable from consequences. Location missing or wrong. |

**Good example (Clarity: 9/10)**:
```markdown
## [H-01] Vault.withdraw() Missing Balance Check Allows Any User to Drain Protocol Funds

**Root Cause**: `withdraw()` at Vault.sol:L142 does not verify 
`balances[msg.sender] >= amount` before transferring funds.

**Impact**: Any user can withdraw the entire vault balance (currently 
$12.4M TVL) by calling `withdraw(vault.balance)` once.

**Location**: Vault.sol:L142, `withdraw(uint256 amount)` function.
```

**Bad example (Clarity: 3/10)**:
```markdown
## Missing Validation

The vault contract has some issues with validation that could potentially 
allow unauthorized operations. The withdraw function doesn't seem to properly
check things before executing. This could be problematic if exploited by
a malicious actor who sends a transaction to the contract.
```

### Dimension 2: PoC Quality (0-10)

| Score | Criteria |
|-------|---------|
| 9-10 | Runnable Foundry/Hardhat test. Sets up realistic state. Exploit steps match description. Assertions verify claimed impact. Logs show before/after balance changes. |
| 7-8 | Runnable test with clear exploit steps. Assertions present but don't fully verify impact. Setup uses simplified state. |
| 5-6 | Pseudocode showing exploit flow. Steps are logical but not executable. No assertions. |
| 3-4 | Vague description of attack. "Attacker could potentially..." without concrete steps. |
| 1-2 | No PoC. Finding is theoretical with no evidence. |
| N/A | PoC not required for this severity (Low/Info). |

**Good example (PoC: 9/10)**:
```solidity
function test_VULN_unauthorized_withdrawal() public {
    // Setup: Alice deposits 10 ETH
    vm.deal(alice, 10 ether);
    vm.prank(alice);
    vault.deposit{value: 10 ether}();
    assertEq(address(vault).balance, 10 ether);
    
    // Attack: Bob (no deposits) withdraws all funds
    uint256 bobBefore = address(bob).balance;
    vm.prank(bob);
    vault.withdraw(10 ether);
    
    // Impact verified: Bob stole 10 ETH
    assertEq(address(bob).balance, bobBefore + 10 ether);
    assertEq(address(vault).balance, 0);
    // Output: [PASS] Bob gained 10 ETH, vault drained
}
```

**Bad example (PoC: 2/10)**:
```
If an attacker calls withdraw() they might be able to take funds 
that don't belong to them because of the missing check.
```

### Dimension 3: Severity Accuracy (0-10)

| Score | Criteria |
|-------|---------|
| 9-10 | Severity matches impact × likelihood matrix exactly. Impact quantified in $ or user count. Likelihood justified with attack cost analysis. No reasonable auditor would dispute. |
| 7-8 | Severity is defensible but could go one notch either way. Impact described but not precisely quantified. Likelihood reasonable but not analyzed in depth. |
| 5-6 | Severity is approximately correct but argument is weak. No impact quantification. Likelihood assumed without justification. |
| 3-4 | Severity is inflated or deflated by one level. Finding uses wrong framework (e.g., marking DoS as Critical without fund-loss). |
| 1-2 | Severity is clearly wrong. Critical for an informational issue, or Low for a fund-drain. |

**Severity classification guide**:

```
CRITICAL (Score 9-10): Loss of funds without user action
  - Exact $ amount at risk (TVL, pool balance)
  - Attack requires only knowledge + gas
  - No time constraints or race conditions
  - Example: "Any user drains $12.4M vault with single tx"

HIGH (Score 7-8): Loss of funds with some constraints
  - Funds at risk but attack has conditions
  - Requires specific timing, front-running, or oracle state
  - Affects many users but not total drain
  - Example: "Liquidation manipulation steals collateral during 
    price volatility"

MEDIUM (Score 4-6): Conditional impact or limited loss
  - Requires specific conditions that may not always hold
  - Loss is bounded (e.g., < 1% of TVL)
  - DoS that is temporary and recoverable
  - Example: "Fee rounding at 0.01% precision over 1000 txs"

LOW (Score 1-3): Minimal impact or best practice
  - No direct fund loss
  - Informational improvements
  - Gas optimization
  - Code quality
  - Example: "Event missing indexed parameter for off-chain tracking"
```

### Dimension 4: Fix Quality (0-10)

| Score | Criteria |
|-------|---------|
| 9-10 | Fix is specific code (not "add validation"). Fix addresses root cause, not symptom. Fix doesn't introduce new vulnerabilities. Fix is tested (green phase from TDD). |
| 7-8 | Fix is specific and addresses root cause. Minor edge cases not covered. Test not provided but approach is clear. |
| 5-6 | Fix is directionally correct but vague ("add an access control check"). May address symptom instead of root cause. |
| 3-4 | Fix is generic ("validate inputs"). Could apply to any vulnerability. |
| 1-2 | No fix recommendation. Or fix introduces new vulnerability. |

**Good example (Fix: 9/10)**:
```solidity
// FIX: Add balance check before withdrawal
function withdraw(uint256 amount) external {
+   require(balances[msg.sender] >= amount, "Insufficient balance");
    balances[msg.sender] -= amount;
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "Transfer failed");
}

// Regression test confirming fix:
function test_REGRESSION_withdrawal_blocked() public {
    vm.prank(bob); // Bob has 0 balance
    vm.expectRevert("Insufficient balance");
    vault.withdraw(1 ether);
}
```

**Bad example (Fix: 2/10)**:
```
Recommendation: Add proper validation to the withdraw function.
```

### Dimension 5: Coverage (0-10)

| Score | Criteria |
|-------|---------|
| 9-10 | Finding covers ALL instances of the pattern. Variant analysis done. Related functions checked. No "I only found it in withdraw() but deposit() has the same issue" during review. |
| 7-8 | Primary instance fully documented. Mentions existence of variants but doesn't detail all of them. |
| 5-6 | Primary instance documented. No variant analysis. Reader discovers similar issues in adjacent code. |
| 3-4 | Incomplete analysis. Finding describes one path but misses worse paths. |
| 1-2 | Superficial. Obvious related issues not mentioned. |

## Composite Quality Score

```
Finding Quality = (Clarity × 0.25) + (PoC × 0.25) + (Severity × 0.20)
                + (Fix × 0.15) + (Coverage × 0.15)

Minimum thresholds:
  Critical finding:  >= 8.0 composite
  High finding:      >= 7.5 composite
  Medium finding:    >= 7.0 composite
  Low/Info finding:  >= 6.0 composite
```

## Quality Gate Checklist

Before submitting any finding:

```yaml
pre_submission_gate:
  clarity:
    - "Title communicates issue in < 15 words?"
    - "Root cause in first sentence?"
    - "Impact quantified ($ or user count)?"
    - "Location has contract:function:line?"
  
  poc:
    - "Runnable test provided (Critical/High)?"
    - "Test assertions verify claimed impact?"
    - "Setup uses realistic protocol state?"
    - "Steps match the described attack path?"
  
  severity:
    - "Impact × likelihood matrix applied?"
    - "Severity defensible to another auditor?"
    - "Not inflated for higher payout?"
    - "Not deflated to avoid controversy?"
  
  fix:
    - "Addresses root cause, not symptom?"
    - "Specific code change, not 'add validation'?"
    - "Fix doesn't break other functionality?"
    - "Regression test provided?"
  
  coverage:
    - "All instances of this pattern found?"
    - "Variant functions checked?"
    - "Related attack paths explored?"
```

## Coverage Tracking Matrix

Track finding coverage across audit scope:

```
╔═══════════════╦══════════════╦════════════╦══════════╗
║ Contract      ║ Findings     ║ LOC Ratio  ║ Status   ║
╠═══════════════╬══════════════╬════════════╬══════════╣
║ Vault.sol     ║ 3 (H,M,L)   ║ 450 LOC    ║ Complete ║
║ Oracle.sol    ║ 1 (M)        ║ 180 LOC    ║ Complete ║
║ Governor.sol  ║ 2 (H,M)      ║ 320 LOC    ║ Complete ║
║ Token.sol     ║ 0            ║ 120 LOC    ║ Complete ║
║ Timelock.sol  ║ 1 (L)        ║ 95 LOC     ║ Complete ║
╚═══════════════╩══════════════╩════════════╩══════════╝

Expected finding density: 1-3 findings per 100 LOC of complex logic
If density is 0 for complex contract → verify audit depth
If density is >5 per 100 LOC → verify deduplication
```

## Good vs Bad Finding Examples

### Example 1: Access Control

**Good finding (Quality: 9.2/10)**:
```markdown
## [C-01] Missing Access Control on Vault.withdraw() Allows Complete Fund Drain

**Severity**: Critical
**Location**: Vault.sol:L142, `withdraw(uint256 amount)`
**Impact**: Any address can withdraw all vault funds ($12.4M at current TVL)

### Root Cause
The `withdraw()` function does not check `balances[msg.sender] >= amount`.
An attacker with zero deposits can call `withdraw(address(vault).balance)` 
to drain all protocol funds in a single transaction.

### Proof of Concept
[Runnable Foundry test showing Bob draining Alice's deposits]

### Recommendation
Add balance verification:
```solidity
require(balances[msg.sender] >= amount, "Insufficient balance");
```

### Variant Analysis
- `emergencyWithdraw()` at L189: Same issue — no balance check
- `withdrawToken()` at L215: Protected by `onlyOwner` — different scope
```

**Bad finding (Quality: 3.1/10)**:
```markdown
## Withdrawal Issue

There might be a problem with withdrawals in the vault. Users could 
potentially withdraw more than they should. The contract should add 
better checks. Consider reviewing the withdraw logic for edge cases 
and potential exploits. This impacts the security of user funds.
```

### Example 2: Oracle Manipulation

**Good finding (Quality: 8.8/10)**:
```markdown
## [H-02] Spot Price Oracle in Lending.liquidate() Enables Flash Loan Manipulation

**Severity**: High
**Location**: Lending.sol:L298, `liquidate()` → calls Oracle.getPrice()
**Impact**: Attacker profits ~$50K per liquidation via flash loan price 
manipulation. Requires $2M flash loan (0.09% fee = $1.8K cost).

### Root Cause  
`liquidate()` reads spot price from Uniswap pool.getReserves() at L298.
A flash loan can manipulate reserves within the same block, artificially
making healthy positions appear undercollateralized.

### Attack Path
1. Flash borrow 1M USDC
2. Dump into WETH/USDC pool → crash WETH price 40%
3. Call liquidate() on healthy WETH positions (now "undercollateralized")
4. Buy discounted WETH collateral at liquidation price
5. Repay flash loan
6. Profit: ~$50K per large position

### Recommendation
Replace spot price with Uniswap V3 TWAP (30-minute window):
```solidity
uint256 price = oracle.consult(WETH, 1800); // 30-min TWAP
```
```

## Finding Quality Anti-Patterns

| Anti-Pattern | Example | Fix |
|-------------|---------|-----|
| Severity inflation | "Critical: Missing event" | Events are Info/Low |
| Impact hand-waving | "This could lead to loss" | Quantify: "$X at risk" |
| Fix by suggestion | "Consider adding checks" | Show exact code change |
| One-liner findings | "Missing access control on X" | Full finding template |
| Theoretical attacks | "If attacker had admin..." | Is the attack realistic? |
| Duplicated findings | Same root cause, 5 entries | Deduplicate to one + variants |
| Copy-paste PoC | PoC from different audit | Write fresh PoC for this code |

## Cross-References

- [audit-report-templates.md](audit-report-templates.md) — Report FORMAT (not scoring)
- [verification-discipline.md](verification-discipline.md) — Evidence requirements
- [tdd-security-testing.md](tdd-security-testing.md) — PoC test cycle
- [poc-writing-guide.md](poc-writing-guide.md) — PoC structure templates
- [systematic-root-cause.md](systematic-root-cause.md) — Root cause methodology

## Sources

- QMD (Quality Metrics for Documentation): Finding quality scoring framework
- Code4rena: Judge scoring criteria for severity and quality
- Sherlock: Finding quality standards and deduplication rules
- Superpowers: code-reviewer agent (adapted for security finding review)
