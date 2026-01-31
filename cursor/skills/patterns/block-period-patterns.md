---
id: PAT-BLOCK-PERIOD
title: Block Period Security Patterns
category: timing
severity: medium
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - block
  - timestamp
  - number

finding_count: 3
last_updated: 2026-01-31
---
# Block Period Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 2 | 1 | 0 |

**Common Sources**: Quantstamp, Sherlock, Code4rena

---

## Detection Checklist

- [ ] Check for block period vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-02] `BLOCK_PERIOD` is incorrect

**Source**: Code4rena
**Protocol**: zkSync
**Impact**: MEDIUM

**Details**:

[Config.sol#L47](https://github.com/code-423n4/2022-10-zksync/blob/456078b53a6d09636b84522ac8f3e8049e4e3af5/ethereum/contracts/zksync/Config.sol#L47)<br>

The `BLOCK_PERIOD` is set to 13 seconds in `Config.sol`.

```sol
uint256 constant BLOCK_PERIOD = 13 seconds;
```

Since moving to Proof-of-Stake (PoS) after the Merge, block times on ethereum are fixed at 12 seconds per block (slots).
<https://ethereum.org/en/developers/docs/consensus-mechanisms/pos/#:~:text=Whereas%20under%20proof%2Dof%2Dwork,block%20proposer%20in%20every%20slot>.

### Impact

This results in incorrect calculation of `PRIORITY_EXPIRATION` which is used to determine when a transaction in the Priority Queue should be considered expired.

```sol
uint256 constant PRIORITY_EXPIRATION_PERIOD = 3 days;
/// @dev Expiration delta for priority request to be satisfied (in ETH blocks)
uint256 constant PRIORITY_EXPIRATION = PRIORITY_EXPIRATION_PERIOD/BLOCK_PERIOD;
```

The time difference can be calulated

```python
>>> 3*24*60*60 / 13    # 3 days / 13 sec block period
19938.46153846154
>>> 3*24*60*60 / 12    # 3 days / 12 sec block period
21600.0
>>> 21600 - 19938      # difference in blocks
1662
>>> 1662 * 12 / (60 * 60) # difference in hours
5.54
```

By using block time of 13 seconds, a transaction in the Priority Queue incorrectly expires 5.5 hours earlier than is expected.

5.5 hours is a significant amount of time difference so I believe this issue to be Medium severity.

### Recommended Mitigation Steps

Change

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-zksync)

---

### Example 2: M-2: `optionTokens` can be expired even though the epoch is not over

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/63 

## Found by 
BenRai, qandisa
## Summary

When deploying an `optionToken` the parameter `expiry` is rounded down to the nearest day at 0000 UTC but since the end of an epoch is calculated by the `epochDuration` and the exact time the epoch has stared and the `optionToken` was created this can lead to an epoch still being active but the corresponding `optionToken` to be already expired. 

## Vulnerability Detail

When starting a new epoch, the variable `epochStart` is set to the current time (`block.timestamp`) and the end of the epoch is calculated by adding the `epochDuration` to the `epochStart` variable. 

The `optionToken` of the new epoch is deployed with the parameter `expire` calculated based on the current time stamp, the `timeUntilEligible` and the `eligibleDuration`. (`uint48(block.timestamp) + timeUntilEligible + eligibleDuration`). The final expiration date of the optionToken is rounded down to the nearest day at 0000 UTC before the token is deployed.

Since the `epochDuration` can be as close as 1 second to the sum of `timeUntilEligible + eligibleDuration` this can lead to an epoch still being active but its `optionToken` to be already expired.

Example:

epochDuration = 7 days
timeUntilEligible = 0
eligibleDuration = 7 days + 12 hours


New epoch is launched on the 01.01.2024 at 11:45 am.

=>
epochStart = block.timestamp  = 01.01.2024 at 11:45 am
epochEnd = epochStart + epochDuration =

*[Content truncated...]*

---

### Example 3: Mismatched `msg_value` Validation and Refund Logic in `op::create_master` Causes Underfunded Transactions

**Source**: Quantstamp
**Protocol**: XDAO
**Impact**: LOW

**Details**:

**Update**
The team fixed the issue as recommended. Addressed in: `3be95dd540da57f9f2a1e20dd8f514e6158e9029`.

**File(s) affected:**`contracts/factory.fc`

**Description:** In the `factory`s `op::create_master`, the initial check requires `msg_value > service_fee + BASE_FEE * (6 + mint_messages_count)`, but the refund calculation deducts `service_fee + BASE_FEE * (8 + mint_messages_count)`. This discrepancy allows transactions that pass validation to fail later or refund less than expected, leading to user confusion and potential loss of funds.

**Exploit Scenario:**

1.   A user provides `msg_value` that meets the `(6 + mint_messages_count)` requirement but falls short of `(8 + mint_messages_count)`.
2.   Deployment proceeds past the initial check but later attempts to refund, leading to a revert or incorrect refund amount.
3.   The deployment unexpectedly fails or the user loses more TON than anticipated.

**Recommendation:** Align the validation threshold with the actual outgoing costs by updating the check to account for all `BASE_FEE` deductions (including minting flow and message sends). For example, require `msg_value > service_fee + BASE_FEE * (8 + mint_messages_count)`.

**Reference**: [View Original Finding](https://certificate.quantstamp.com/full/xdao/2670863d-2e1c-42e6-a15c-5572dd4fef85/index.html)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

