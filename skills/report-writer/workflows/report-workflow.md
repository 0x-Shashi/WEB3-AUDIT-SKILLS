---
id: RPT-WF-REPORT
title: Report Generation Workflow
parent: report-writer
type: workflow
last_updated: 2025-01-31
---

# Report Generation Workflow

Step-by-step process for transforming raw audit findings into a polished, professional audit report.

---

## Step 1: Collect Findings

Gather all identified issues from the audit process:

| Source | Type | Examples |
|--------|------|----------|
| Manual review notes | Logic bugs, access control issues | Missing reentrancy guard |
| Static analysis output | Tool-flagged issues (Slither, Aderyn) | Unchecked return value |
| Test results | Failed invariant tests, edge cases | Overflow at max supply |
| Architecture review | Design-level concerns | Centralization, upgradeability |

For each raw finding, capture:
- [ ] Contract and function location
- [ ] Description of the issue
- [ ] How it was discovered
- [ ] Initial severity estimate
- [ ] Whether a PoC exists

---

## Step 2: Classify Severity

Apply the Likelihood × Impact matrix to each finding:

### Likelihood Questions

1. **Who can trigger it?** Anyone (High) / Specific role (Medium) / Unusual conditions (Low)
2. **What's the cost?** Free (High) / Moderate gas/capital (Medium) / Expensive (Low)
3. **Is it detectable?** Hard to detect (High) / Noticeable (Medium) / Obvious (Low)
4. **How reliable is the exploit?** Always works (High) / Sometimes (Medium) / Rarely (Low)

### Impact Questions

1. **What's lost?** User funds (High) / Protocol fees (Medium) / Convenience (Low)
2. **How many affected?** All users (High) / Some users (Medium) / Edge cases (Low)
3. **Is it reversible?** No (High) / With admin action (Medium) / Self-resolving (Low)
4. **What's the scope?** Entire protocol (High) / Single contract (Medium) / Single function (Low)

### Deduplication

Before finalizing:
- [ ] Check for duplicate findings (same root cause)
- [ ] Merge findings that share a root cause — report the root cause, list all instances
- [ ] Separate findings that have different root causes even if symptoms are similar

---

## Step 3: Write Descriptions

For each finding, write a clear description following these rules:

| Rule | Good Example | Bad Example |
|------|-------------|-------------|
| Be specific | "The `withdraw()` function at L189 does not check `balances[msg.sender]`" | "There's a vulnerability" |
| State root cause | "Because state is updated after the external call" | "There's a reentrancy issue" |
| Explain context | "In the context of a lending pool where users deposit ETH" | [No context given] |
| Use present tense | "The function allows..." | "The function would allow..." |
| Avoid jargon without explanation | "CEI pattern violation (state update after external call)" | "CEI violation" |

---

## Step 4: Create PoCs

For Critical and High findings, write proof-of-concept tests:

### PoC Requirements

| Requirement | Details |
|-------------|----------|
| Compilable | Must compile with `forge build` |
| Runnable | Must pass with `forge test --match-test test_exploit_name` |
| Self-contained | Should not require external setup |
| Commented | Each step explains the attack |
| Asserted | `assert` statements prove the impact |

### PoC Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract ExploitTest is Test {
    Vault vault;
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");
    
    function setUp() public {
        vault = new Vault();
        // Setup: give victim some funds, vault some state
        deal(victim, 100 ether);
    }
    
    function test_exploit_description() public {
        // 1. Victim deposits legitimate funds
        vm.prank(victim);
        vault.deposit{value: 100 ether}();
        
        // 2. Attacker exploits vulnerability
        vm.prank(attacker);
        vault.withdraw(100 ether);  // No balance check!
        
        // 3. Verify impact
        assertEq(attacker.balance, 100 ether, "Attacker stole funds");
        assertEq(address(vault).balance, 0, "Vault drained");
    }
}
```

---

## Step 5: Write Recommendations

For each finding, provide a specific, implementable fix:

| Quality | Bad Recommendation | Good Recommendation |
|---------|-------------------|---------------------|
| Specificity | "Add a check" | "Add `require(balances[msg.sender] >= amount)` before the transfer" |
| Code | [No code] | Diff showing exact changes |
| Completeness | "Use a reentrancy guard" | "Apply `nonReentrant` modifier AND follow CEI pattern" |
| Trade-offs | [Not mentioned] | "This adds ~5000 gas per call but prevents reentrancy" |

### Fix Format

```diff
function withdraw(uint256 amount) external {
+   require(balances[msg.sender] >= amount, "Insufficient balance");
+   balances[msg.sender] -= amount;
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
-   balances[msg.sender] -= amount;
}
```

---

## Step 6: Executive Summary

Write the executive summary LAST (after all findings are documented):

### Structure

1. **What is the protocol?** (1 sentence)
2. **What was audited?** (scope: # contracts, # SLOC, commit)
3. **What was found?** (finding counts by severity)
4. **Overall assessment** (1-2 sentences: "Generally well-written with [X] critical issue")
5. **Key recommendation** ("We recommend addressing [C-01] before deployment")

### Example

> **VaultProtocol** is a yield-aggregating vault that deposits user funds
> into multiple DeFi strategies to maximize returns.
>
> The audit reviewed 3 contracts (520 SLOC) at commit `abc123`. We
> identified 1 Critical, 2 High, 3 Medium, and 4 Low severity findings.
>
> The codebase demonstrates competent Solidity development with proper
> use of OpenZeppelin contracts. However, the critical reentrancy
> vulnerability in the withdrawal flow (C-01) must be resolved before
> mainnet deployment.

---

## Step 7: Internal Review

Before delivering:

- [ ] Every finding has severity justification (Likelihood × Impact)
- [ ] Every Critical/High finding has a working PoC
- [ ] Every finding has a specific recommendation with code
- [ ] No duplicate findings (same root cause reported separately)
- [ ] Finding IDs are sequential (no gaps: C-01, H-01, H-02, M-01...)
- [ ] Locations (contract, function, line) are correct
- [ ] Executive summary accurately reflects findings
- [ ] Scope table matches actual files reviewed
- [ ] Commit hash is correct
- [ ] Grammar and formatting are professional

---

## Step 8: Format and Deliver

Apply the [Report Template](resources/report-template.md) and export:

| Format | Use Case |
|--------|----------|
| Markdown | GitHub, developer reference, version control |
| PDF | Client delivery, formal record |
| HTML | Web publication |

### Post-Delivery

- [ ] Schedule fix review (typically 1-2 weeks after delivery)
- [ ] For fix review: verify each finding's fix commit, update status
- [ ] Publish v1.1 with fix statuses (Fixed / Acknowledged / Disputed)
