---
id: PAT-APPROVE-MAX
title: Approve Max Security Patterns
category: token
severity: medium
difficulty: beginner
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - approval
  - allowance
  - permit

finding_count: 3
last_updated: 2026-01-31
---
# Approve Max Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 2 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for approve max vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-02] Pool.sol & Synth.sol: Failing Max Value Allowance

**Source**: Code4rena
**Protocol**: Spartan Protocol
**Impact**: HIGH

**Details**:

## Handle

hickuphh3


## Vulnerability details

### Impact

In the `_approve` function, if the allowance passed in is `type(uint256).max`, nothing happens (ie. allowance will still remain at previous value). Contract integrations (DEXes for example) tend to hardcode this value to set maximum allowance initially, but this will result in zero allowance given instead.

This also makes the comment `// No need to re-approve if already max` misleading, because the max allowance attainable is `type(uint256).max - 1`, and re-approval does happen in this case.

This affects the `approveAndCall` implementation since it uses `type(uint256).max` as the allowance amount, but the resulting allowance set is zero.

### Recommended Mitigation Steps

Keep it simple, remove the condition.

```jsx
function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "!owner");
        require(spender != address(0), "!spender");
        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }
```

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-spartan)

---

### Example 2: M-3: `universalApproveMax` will not work for some tokens that don't support approve `type(uint256).max` amount.

**Source**: Sherlock
**Protocol**: DODO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-dodo-judging/issues/41 

## Found by 
Tomo, jayphbee

## Summary
`universalApproveMax` will not work for some tokens that don't support approve `type(uint256).max` amount.

## Vulnerability Detail
There are tokens that doesn't support approve spender `type(uint256).max` amount. So the `universalApproveMax` will not work for some tokens like `UNI` or `COMP` who will revert when approve `type(uint256).max` amount.

## Impact
Tokens that don't support approve `type(uint256).max` amount could not be swapped by calling `externalSwap` function.

## Code Snippet
https://github.com/sherlock-audit/2022-11-dodo/blob/main/contracts/SmartRoute/DODORouteProxy.sol#L181-L183
```solidity
            if (approveTarget != address(0)) {
                IERC20(fromToken).universalApproveMax(approveTarget, fromTokenAmount);
            }
```
https://github.com/sherlock-audit/2022-11-dodo/blob/main/contracts/SmartRoute/lib/UniversalERC20.sol#L36-L48
```solidity
function universalApproveMax(
        IERC20 token,
        address to,
        uint256 amount
    ) internal {
        uint256 allowance = token.allowance(address(this), to);
        if (allowance < amount) {
            if (allowance > 0) {
                token.safeApprove(to, 0);
            }
            token.safeApprove(to, type(uint256).max);
        }
    }
```

## Tool used

Manual Review

## Recommendation
I would suggest approve only the necessay amount of token to the `approveTa

*[Content truncated...]*

---

### Example 3: [M-09] broken logic in `configureGmxState()` of PirexGmx contract because it doesn't properly call `safeApprove()` for stakedGmx address

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexGmx.sol#L269-L293>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexGmx.sol#L346-L355>

### Impact

Function `configureGmxState()` of `PirexGmx` is for configuring GMX contract state but logic is using `safeApprove()` improperly, it won't reset approval amount for old `stakedGmx` address This would cause 4 problem:

1.  Different behavior in `setContract()` and `configureGmxState()` for handling `stakeGmx` address changes. in `setContract()` the logic reset approval for old address to zero but in `configureGmxState()` the logic don't reset old address GMX spending approval.
2.  The call to this function would revert if `stakeGmx` address didn't changed but other addresses has been changed so `owner` can't use this to configure contract.
3.  Contract won't reset approval for old `stakedGmx` address which is a threat because contract in that address can steal all the GMX balance any time in the future if that old address had been compromised.
4.  Contract won't reset approval for old `stakedGmx` address, if `owner` use `configureGmxState()` to change the `stakeGmx` value then it won't be possible to set `stakedGmx` value to previous ones by using either `configureGmxState()` or `setContract()` and contract would be in broken state.

### Proof of Concept

This is `configureGmxState()` code in `PirexGmx`:

      

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

