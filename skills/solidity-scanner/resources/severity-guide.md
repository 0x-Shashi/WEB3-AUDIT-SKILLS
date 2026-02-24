---
id: solidity-severity-guide
title: Solidity Severity Classification Guide
category: resource
parent_skill: solidity-scanner/SKILL.md
description: >
  Structured severity classification system for Solidity audit findings.
  Includes decision tree, platform-specific criteria (Code4rena, Sherlock,
  CodeHawks), worked examples, and edge case handling.
tags:
  - solidity
  - severity
  - classification
  - audit
last_updated: 2026-02-24
---

# Severity Classification Guide

## Overview

Severity classification determines how urgently a finding must be addressed. Accurate classification builds credibility with clients and contest judges. This guide provides a structured decision process that removes subjectivity.

## Severity Levels

### Critical

**Definition**: Immediate, unconditional loss of significant funds or complete protocol compromise.

**Criteria** (ALL must be true):
- Exploitable with high probability (no unlikely preconditions)
- Affects all or most users / the protocol itself
- No existing mitigation reduces the impact
- Attacker profit is significant relative to protocol TVL

**Examples**:

| Finding | Why Critical |
|---|---|
| Reentrancy allowing full vault drain | Direct fund theft, any user can exploit, unbounded loss |
| Unprotected `upgradeTo()` allows malicious implementation | Complete protocol compromise via arbitrary code execution |
| Uninitialized proxy implementation — attacker takes ownership | Full control of protocol, can drain all funds |
| `selfdestruct` callable by anyone | Permanent protocol destruction, all funds lost |
| Unbounded token minting without access control | Infinite dilution, any holder's value reduced to zero |

---

### High

**Definition**: Significant fund loss or protocol disruption under specific but realistic conditions.

**Criteria** (at least 2 of 3):
- Exploitable under specific conditions (but conditions are realistic)
- Significant financial impact (>$10K or >1% of TVL)
- Affects a meaningful subset of users

**Examples**:

| Finding | Why High |
|---|---|
| Oracle manipulation via flash loan leading to incorrect liquidations | Realistic attack, significant fund loss, affects borrowers |
| Cross-function reentrancy allowing partial fund drain | Requires specific token (ERC777) but is exploitable when present |
| Signature replay allowing double withdrawal | Requires user to submit tx, but then attacker can replay unlimited |
| First depositor inflation attack in ERC4626 vault | Requires being first depositor (realistic in new vaults) |
| Missing slippage protection on protocol-initiated swaps | MEV bots will sandwich, protocol loses value on every swap |

---

### Medium

**Definition**: Limited fund loss, non-critical functionality impairment, or issues requiring unlikely conditions.

**Criteria** (at least 1):
- Bounded financial impact (loss is limited by design)
- Requires unlikely preconditions (admin malice, specific timing)
- Affects limited set of users or limited scope
- Protocol functionality impaired but not destroyed

**Examples**:

| Finding | Why Medium |
|---|---|
| Centralization risk — admin can set fee to 100% | Requires admin malice, often accepted risk, but impact is high if triggered |
| Rounding error in share calculation — up to 1 wei per tx | Bounded loss, but repeatable across thousands of transactions |
| Missing deadline on swap — validator can hold tx | Requires malicious validator, impact depends on price movement |
| DoS via unbounded loop — gas limit blocks function | Protocol impaired, but no direct fund loss, can be worked around |
| Fee-on-transfer token breaks accounting | Requires specific token type to be used, limited to that token |

---

### Low

**Definition**: Best practice violations, minor inefficiencies, or theoretical issues with no practical exploit path.

**Criteria** (at least 1):
- No direct fund loss under any realistic scenario
- Gas optimization opportunity
- Code quality improvement
- Informational observation

**Examples**:

| Finding | Why Low |
|---|---|
| Floating pragma (`^0.8.0` instead of `0.8.24`) | No direct exploit, but untested compiler versions could introduce bugs |
| Missing zero-address check on constructor parameter | Deployment would fail visibly, no hidden exploit |
| Missing event on state change | No security impact, but makes off-chain monitoring harder |
| Unused state variable consuming storage slot | Gas waste, no security impact |
| `block.timestamp` used for non-critical display | Miner can manipulate by ~15 seconds, but no financial impact |

---

## Decision Tree

```
START: Evaluate the finding
│
├─ Can an attacker steal/lock/destroy significant funds directly?
│   ├─ YES, unconditionally → CRITICAL
│   └─ YES, but requires specific conditions →
│       ├─ Conditions are realistic (flash loan, common token type, etc.) → HIGH
│       └─ Conditions are unlikely (admin malice, specific deployment state) → MEDIUM
│
├─ Can an attacker impair protocol functionality?
│   ├─ Core functionality permanently broken → HIGH
│   ├─ Core functionality temporarily impaired → MEDIUM
│   └─ Non-critical functionality affected → LOW
│
├─ Is there a financial loss?
│   ├─ Unbounded loss → HIGH (or CRITICAL if unconditional)
│   ├─ Bounded/limited loss → MEDIUM
│   └─ Dust amounts only → LOW
│
└─ None of the above → LOW / INFORMATIONAL
```

## Platform-Specific Criteria

Different audit platforms use slightly different severity scales. Calibrate your classification accordingly.

### Code4rena (C4)

| Severity | C4 Definition | Payout Impact |
|---|---|---|
| **High** | Assets can be stolen/lost/compromised directly, or a critical protocol functionality is compromised | 70% of pool |
| **Medium** | Assets not at direct risk, but protocol function could be impacted, or leak value through some sequence of events | 20% of pool |
| **QA** | Low-impact, non-critical, informational | Quality Assurance report pool |
| **Gas** | Gas optimization | Gas report pool |

**C4-specific notes**:
- Centralization risks are typically Medium (unless unconditional rug vector)
- Findings requiring admin malice are usually QA unless the admin role is an EOA
- Duplicates are grouped — unique root cause matters more than instance count

### Sherlock

| Severity | Sherlock Definition |
|---|---|
| **High** | Definite loss of funds without requiring any particular states |
| **Medium** | Causes a loss of funds but requires certain external conditions or specific states, OR contract/protocol breaks |
| **Low** | Not accepted (Sherlock does not accept Low findings) |

**Sherlock-specific notes**:
- Sherlock requires a clear "loss" — DoS alone is Medium only if it locks funds
- "External condition" includes the need for a specific token type (fee-on-transfer)
- Admin-controlled risks are generally not valid findings unless the admin is clearly malicious path

### CodeHawks (Cyfrin)

| Severity | Impact: High | Impact: Medium | Impact: Low |
|---|---|---|---|
| **Likelihood: High** | Critical | High | Medium |
| **Likelihood: Medium** | High | Medium | Low |
| **Likelihood: Low** | Medium | Low | Low |

**CodeHawks-specific notes**:
- Uses an impact × likelihood matrix
- "Likelihood" means "how likely is it that this actually gets exploited"
- Gas optimizations are accepted as separate category

## Severity Adjustment Factors

These factors can move a finding up or down one level:

### Upgrade Factors (may increase severity)

| Factor | Effect | Example |
|---|---|---|
| Multiple instances | Medium → High | Same bug in 5 functions = systemic issue |
| Composability | +1 level | Flash loan makes oracle manipulation trivially exploitable |
| Historical precedent | Validates severity | "Same pattern caused $60M loss in The DAO" |
| Protocol TVL | Context matters | Rounding error of 0.01% on $1B TVL = $100K |

### Downgrade Factors (may reduce severity)

| Factor | Effect | Example |
|---|---|---|
| Existing mitigation | -1 level | Timelock prevents instant admin rug |
| Required attacker cost | Reduces likelihood | Attack requires $50M capital with $1K profit |
| Admin/trusted role required | -1 level | Only multisig can trigger |
| Theoretical only | Medium → Low | No practical exploit path demonstrated |

## Worked Examples

### Example 1: Oracle Missing Staleness Check

```solidity
(, int256 price, , , ) = priceFeed.latestRoundData();
return uint256(price);
```

**Analysis**:
- **Impact**: If Chainlink feed goes stale, protocol uses outdated price → incorrect liquidations/borrowing → fund loss
- **Likelihood**: Chainlink feeds have real-world downtime events (e.g., during network congestion)
- **Conditions**: Need Chainlink feed to actually go stale — realistic but not guaranteed
- **Scope**: All users relying on this price feed

**Classification**: **Medium** (High impact × Medium likelihood = High by matrix, but Chainlink staleness is a well-known pattern and many auditors would call this Medium because feeds rarely go stale for extended periods. Context-dependent.)

### Example 2: Unrestricted Mint Function

```solidity
function mint(address to, uint256 amount) external {
    _mint(to, amount);
}
```

**Analysis**:
- **Impact**: Anyone can mint unlimited tokens → total dilution → all holders lose value
- **Likelihood**: Easily exploitable, no preconditions
- **Conditions**: None — callable by anyone immediately
- **Scope**: All token holders

**Classification**: **Critical** (unconditional, unbounded, immediate)

### Example 3: Unbounded Loop in Distribution

```solidity
for (uint i = 0; i < users.length; i++) {
    payable(users[i]).transfer(rewards[i]);
}
```

**Analysis**:
- **Impact**: Function reverts once array is too large → rewards permanently stuck
- **Likelihood**: High as protocol grows
- **Conditions**: Array must grow beyond gas limit (~1500 transfers at 21K gas each)
- **Scope**: All users waiting for distribution

**Classification**: **Medium** (funds at risk via permanent lock, but requires protocol growth; DoS + potential fund lock)

## Edge Cases

### "Admin Can Rug" — When Is It a Finding?

| Admin Setup | Severity | Reasoning |
|---|---|---|
| Admin = EOA, no timelock | Medium | One key compromise = total loss |
| Admin = 2/3 multisig, no timelock | Low | Requires collusion/compromise of majority |
| Admin = 5/9 multisig + 48h timelock | Informational | Standard security practice |
| Admin = governance with token voting | Medium | Flash loan governance attack possible |

### Dust Amounts — When Do They Matter?

```
If amount_per_tx < 1 wei of ETH → Informational
If amount_per_tx < $0.01 → Low (unless repeatable thousands of times)
If amount_per_tx × realistic_tx_count > $1000 → Medium
If amount_per_tx × realistic_tx_count > protocol_TVL × 1% → High
```

## Further Reading

- [Vulnerability Patterns](vulnerability-patterns.md) — Code examples for each pattern
- [False Positives](false-positives.md) — When NOT to report
