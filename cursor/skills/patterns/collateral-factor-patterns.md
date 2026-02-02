---
id: PAT-COLLATERAL-FACTOR
title: Collateral Factor Security Patterns
category: defi
severity: high
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - collateral
  - lending
  - liquidation

finding_count: 3
last_updated: 2026-01-31
---
# Collateral Factor Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 1 | 0 | 0 |

**Common Sources**: Sherlock, ZachObront, Code4rena

---

## Detection Checklist

- [ ] Check for collateral factor vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-06] Collateralization ratio can be broken by users redeeming deposits for ETH

**Source**: ZachObront
**Protocol**: Dyad
**Impact**: HIGH

**Details**:

A key property of the DYAD system is that the collateralization ratio (300%) is maintained. This means that for every 1 DYAD in circulation, there is 3x as much ETH (priced in USD) in the vault.

This invariant is enforced in the withdraw() function, which stops users from minting more DYAD when such a mint would break the invariant:

```solidity
function withdraw(uint from, address to, uint amount) external
isNftOwnerOrHasPermission(from, Permission.WITHDRAW)
isUnlocked(from)
{
_subDeposit(from, amount);

uint collatVault    = address(this).balance * _getEthPrice()/1e8;
uint newCollatRatio = collatVault.divWadDown(dyad.totalSupply() + amount);
if (newCollatRatio < MIN_COLLATERIZATION_RATIO) { revert CrTooLow(); }
...
}
```

However, the same check is not enforced when redeeming ETH out of the contract. Since a key goal is keeping the ratio of circulating DYAD and ETH bounded by this ratio, it is crucial that we enforce this check on both DYAD minting and ETH redeeming.

**Proof of Concept**

Here is a test showing that we can get the collateralization ratio as low as 1:1 by withdrawing all non-minted deposits:

```solidity
function test_CollateralizationRatioBrokenOnRedeemDeposit() public {
// We deposit 5000 in totalDeposit and mint 1000 of them. Ratio is $5000 of ETH / 1000 supply.
uint id1 = dNft.mint{value: 5 ether}(address(this));
dNft.withdraw(id1, address(this), 1000e18);
console.log(_calculateCollateralizationRatio()); // returns 5e18 - success

// We can now withdra

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/ZachObront/2023-02-12-Dyad.md)

---

### Example 2: H-8: Cross available value is not accounting the position fees

**Source**: Sherlock
**Protocol**: Elfi
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-05-elfi-protocol-judging/issues/42 

The protocol has acknowledged this issue.

## Found by 
mstpr-brainbot
## Summary
Cross available value is the maximum margin that an account can open a position. This value currently subtracts if the account has any losses but not assumes the fees which can be negative as well. This makes the account have a greater maximum margin than it should be.
## Vulnerability Detail
Cross available value is calculated in AccountProcess::getCrossAvailableValue() function as follows:
```solidity
            (totalNetValue + cache.totalIMUsd + accountProps.orderHoldInUsd).toInt256() -
            totalUsedValue.toInt256() +
            (cache.totalPnl >= 0 ? int256(0) : cache.totalPnl) -
            (cache.totalIMUsdFromBalance + totalBorrowingValue).toInt256();
```

As we can observe in above code snippet if there is a negative PnL it is subtracted from the positions available cross value. The reason for this is that if the account has a negative PnL that means when the position is realized accounts net value will drop hence, it is critical to account anything that can/will drop the accounts net value such as sum PnL of the positions account has. However, this calculation missing a key factor that also can drop the accounts net value which is the fees; closeFee, borrowingFee and fundingFee. When the position is settled these fees will added on top of the PnL so it can be assumed that it will affect the us

*[Content truncated...]*

---

### Example 3: [M-04] Undercollateralized loans possible

**Source**: Code4rena
**Protocol**: Duality Focus
**Impact**: MEDIUM

**Details**:

_Submitted by cmichel_

[Comptroller.sol#L1491](https://github.com/code-423n4/2022-04-dualityfocus/blob/f21ef7708c9335ee1996142e2581cb8714a525c9/contracts/compound_rari_fork/Comptroller.sol#L1491)<br>

The `_setPoolCollateralFactors` function does not check that the collateral factor is < 100%.<br>
It's possible that it's set to 200% and then borrows more than the collateral is worth, stealing from the pool.

### Recommended Mitigation Steps

Disable the possibility of ever having a collateral factor > 100% by checking:

```diff
for (uint256 i = 0; i < pools.length; i++) {
+   require(collateralFactorsMantissa[i] <= 1e18, "CF > 100%");
    poolCollateralFactors[pools[i]] = collateralFactorsMantissa[i];
}
```

**[0xdramaone (Duality Focus) confirmed, but disagreed with Medium severity and commented](https://github.com/code-423n4/2022-04-dualityfocus-findings/issues/12#issuecomment-1094732426):**
 > We agree, we should have a max setting for collateral factor of pools to provide confidence to users. That said, this would only be abusable by admins, and so we consider low risk (since controlled by multisig).

**[Jack the Pug (judge) commented](https://github.com/code-423n4/2022-04-dualityfocus-findings/issues/12#issuecomment-1097569137):**
 > Good catch!
> 
> Unbounded `collateralFactor` configuration made it possible for malicious/compromised privileged roles to rug the users, which I consider a real and very practical threat that should be addressed from the smart contract lev

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-dualityfocus)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

