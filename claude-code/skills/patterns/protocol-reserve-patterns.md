# Protocol Reserve Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 2 | 0 | 0 |

**Common Sources**: Pashov Audit Group, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Check for protocol reserve vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Wrong reserve factor computation on P2P rates

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Audit Report

## Severity
**High Risk**

## Context
`MarketsManagerForAave.sol#L413-L418`

## Description
The reserve factor is taken on the entire P2P supply and borrow rates instead of just on the spread of the pool rates. It’s currently overcharging suppliers and borrowers and making it possible to earn a worse rate on Morpho than the pool rates.

```solidity
supplyP2PSPY[_marketAddress] =
(meanSPY * (MAX_BASIS_POINTS - reserveFactor[_marketAddress])) /
MAX_BASIS_POINTS;

borrowP2PSPY[_marketAddress] =
(meanSPY * (MAX_BASIS_POINTS + reserveFactor[_marketAddress])) /
MAX_BASIS_POINTS;
```

## Recommendation
Fix the computation. The real reserve factor should apply only on the spread so you’re right that this formula is wrong and needs to be updated: 
`a + (1/2 ± f)(b-a)` where f is the reserve factor.

## Spearbit
Acknowledged, fixed in PR #565.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 2: M-9: Protocol Reserve Within A LToken Vault Can Be Lent Out

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/122-M 
## Found by 
xiaoming90

## Summary

Protocol reserve, which serves as a liquidity backstop or to compensate the protocol, within a LToken vault can be lent out to the borrowers.

## Vulnerability Detail

The purpose of the protocol reserve within a LToken vault is to compensate the protocol or serve as a liquidity backstop. However, based on the current setup, it is possible for the protocol reserve within a Ltoken vault to be lent out.

The following functions within the `LToken` contract show that the protocol reserve is intentionally preserved by removing the protocol reserve from the calculation of total assets within a LToken vault. As such, whenever the Liquidity Providers (LPs) attempt to redeem their LP token, the protocol reserves will stay intact and will not be withdrawn by the LPs.

https://github.com/sherlock-audit/2022-08-sentiment/blob/main/protocol/src/tokens/LToken.sol#L191

```solidity
function totalAssets() public view override returns (uint) {
    return asset.balanceOf(address(this)) + getBorrows() - getReserves();
}
```

https://github.com/sherlock-audit/2022-08-sentiment/blob/main/protocol/src/tokens/LToken.sol#L195

```solidity
function getBorrows() public view returns (uint) {
    return borrows + borrows.mulWadUp(getRateFactor());
}
```

https://github.com/sherlock-audit/2022-08-sentiment/blob/main/protocol/src/tokens/LToken.sol#L176

```solidity
function getReserve

*[Content truncated...]*

---

### Example 3: [M-01] Minting of `fToken` and `xToken` allowed during stability mode

**Source**: Pashov Audit Group
**Protocol**: RWf(x)_2025-08-20
**Impact**: MEDIUM

**Details**:

_Resolved_

## Severity

**Impact:** Medium  

**Likelihood:** Medium  

## Description

The `Market.mint()` function mints both fToken and xToken [based on the current collateral ratio](https://github.com/RegnumAurumAcquisitionCorp/fx-contracts/blob/main/contracts/f(x)/math/FxLowVolatilityMath.sol#L293-L307).  
In the original Aladdin implementation, this function could be called only once. However, RegnumFx [removed this restriction](https://github.com/RegnumAurumAcquisitionCorp/fx-contracts/compare/bbb461cba879349c24c02d87872e93ec0a1a1975...f6e865df2dd46d67a49391d94e54b26e6a8af43c#diff-2c8d19ba3d13b72d110c2a9536e5e9915118ad919b38848357200e91afb683faL252), allowing it to be called multiple times.

When the system enters stability mode, the collateral ratio has fallen below the defined safe threshold. This indicates that additional base tokens need to be deposited to restore the ratio.

Allowing `mint()` during stability mode worsens the problem: each new mint increases the number of fTokens in circulation, which in turn raises the amount of base tokens required to bring the system back to a healthy state. As a result, recovery becomes more difficult, and the system may remain undercollateralized for longer.

The severity chosen for this issue is medium, because only whitelisted managers can use the function, and they are trusted entities that are not interested in making stablecoin depeg.

## Recommendations

Restrict `mint()` from being called when the system is in stabili

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/RWf(x)-security-review_2025-08-20.md)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
