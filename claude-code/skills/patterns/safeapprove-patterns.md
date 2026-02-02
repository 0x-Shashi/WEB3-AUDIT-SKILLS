---
id: PAT-SAFEAPPROVE
title: Safeapprove Security Patterns
category: token
severity: medium
difficulty: intermediate
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
# SafeApprove Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 3 | 0 | 0 |

**Common Sources**: Spearbit, Code4rena

---

## Detection Checklist

- [ ] Check for safeapprove vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: safeApprove indepositToken could revert for non-standard token like USDT

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: MEDIUM

**Details**:

## Security Analysis

## Severity
**Medium Risk**

## Context
AeraVaultV1.sol#L893

## Description
Some non-standard tokens like USDT will revert when a contract or a user tries to approve an allowance when the spender allowance has already been set to a non-zero value. In the current code, we have not seen any real problem with this fact because the amount retrieved via `depositToken()` is approved and sent to the Balancer pool via `joinPool()` and `managePoolBalance()`. Balancer transfers the same amount, lowering the approval to 0 again. 

However, if the approval is not lowered to exactly 0 (due to a rounding error or another unforeseen situation), then the next approval in `depositToken()` will fail (assuming a token like USDT is used), blocking all further deposits.

**Note:** Set to medium risk because the probability of this happening is low, but the impact would be high. We also should note that OpenZeppelin has officially deprecated the `safeApprove` function, suggesting to use instead `safeIncreaseAllowance` and `safeDecreaseAllowance`.

## Recommendation
Adopt a safer approach to cover edge cases such as the abovementioned USDT token and implement the following solution:

```solidity
function depositToken(IERC20 token, uint256 amount) internal {
    token.safeTransferFrom(owner(), address(this), amount);
    // - token.safeApprove(address(bVault), amount);
    uint256 allowance = token.allowance(address(this), address(bVault));
    if (allowance > 0) {
        tok

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 2: Seaport auctions not compatible with USDT

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Security Analysis Report

## Severity
**Medium Risk**

## Context
`CollateralToken.sol#L173`

## Description
As per the ERC20 specification, the `approve()` function is expected to return a boolean:

```solidity
function approve(address _spender, uint256 _value) public returns (bool success)
```

However, USDT deviates from this standard, and its `approve()` method does not have a return value. Hence, if USDT is used as a payment token, the following line reverts in `validateOrder()` as it expects return data but doesn't receive it:

```solidity
paymentToken.approve(address(transferProxy), s.LIEN_TOKEN.getOwed(stack));
```

## Recommendation
Use Solmate's `safeApprove()` function to accommodate USDT's `approve()`:

```solidity
paymentToken.safeApprove(address(transferProxy), s.LIEN_TOKEN.getOwed(stack));
```

## Additional Information
- **Astaria:** Fixed in PR339.
- **Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review-July.pdf)

---

### Example 3: [M-23] Function `withdraw()` and `redeem()` in ERC4626RouterBase would revert always because they have unnecessary allowance setting

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

<https://github.com/AstariaXYZ/astaria-gpl/blob/4b49fe993d9b807fe68b3421ee7f2fe91267c9ef/src/ERC4626RouterBase.sol#L48><br>
<https://github.com/AstariaXYZ/astaria-gpl/blob/4b49fe993d9b807fe68b3421ee7f2fe91267c9ef/src/ERC4626RouterBase.sol#L62>

Functions withdraw() and redeem()  in ERC4626RouterBase  are used to withdraw user funds from vaults and they call `vault.withdraw()` and `vault.redeem()` and logics in vault transfer user shares and user required to give spending allowance for vault and there is no need for ERC4626RouterBase to set approval for vault and because those approved tokens won't be used and code uses `safeApprove()` so next calls to `withdraw()` and `redeem()` would revert because code would tries to change allowance amount while it's not zero. those functions would revert always and AstariaRouter uses them and user won't be able to use those function and any other protocol integrating with Astaria calling those function would have broken logic. also if UI interact with protocol with router functions then UI would have broken parts too. and functions in router support users to set slippage allowance and without them users have to interact with vault directly and they may lose funds because of the slippage.

### Proof of Concept

This is `withdraw()` and `redeem()` code in ERC4626RouterBase:

      function withdraw(
        IERC4626 vault,
        address to,
        uint256 amount,
        uint256 maxSharesOut
      ) public payable virtual override return

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

