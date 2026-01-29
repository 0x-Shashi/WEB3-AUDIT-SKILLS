# Hardcoded Setting Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 4 | 0 | 0 |

**Common Sources**: Sherlock, Spearbit, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for hardcoded setting vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: M-2: [Medium-1] Hardcoded `monsterMultiplier` in case of `stakedTimeBonus` disregards the updates done to  `monsterMultiplier` through `setMonsterMultiplier()`

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/56 

## Found by 
curiousapple, hansfriese

## Summary
[Medium-1] Hardcoded monsterMultiplier in case of ``stakedTimeBonus`` disregards the updates done to  ``monsterMultiplier`` through ``setMonsterMultiplier()``

## Vulnerability Detail
FrankenDAO allows users to stake two types of NFTs, `Frankenpunks` and `Frankenmonsters` , one of which is considered more valuable, ie: `Frankenpunks`, 

This is achieved by reducing votes applicable for `Frankenmonsters` by `monsterMultiplier`.

```solidity
function getTokenVotingPower(uint _tokenId) public override view returns (uint) {
      if (ownerOf(_tokenId) == address(0)) revert NonExistentToken();

      // If tokenId < 10000, it's a FrankenPunk, so 100/100 = a multiplier of 1
      uint multiplier = _tokenId < 10_000 ? PERCENT : monsterMultiplier;
      
      // evilBonus will return 0 for all FrankenMonsters, as they are not eligible for the evil bonus
      return ((baseVotes * multiplier) / PERCENT) + stakedTimeBonus[_tokenId] + evilBonus(_tokenId);
    }
```

This `monsterMultiplier` is initially set as 50 and could be changed by governance proposal.

```solidity
function setMonsterMultiplier(uint _monsterMultiplier) external onlyExecutor {
    emit MonsterMultiplierChanged(monsterMultiplier = _monsterMultiplier); 
  }
```

However, one piece of code inside the FrakenDAO staking contract doesn't consider this and has a monster multiplier hardcoded.



*[Content truncated...]*

---

### Example 2: [M-01] Operator might be unable to withdraw rewards due to gas limit

**Source**: Pashov Audit Group
**Protocol**: Smoothly
**Impact**: MEDIUM

**Details**:

**Severity**

**Impact:**
High, as operator's yield will be frozen

**Likelihood:**
Low, as it requires operator to be a special multi-sig wallet or contract

**Description**

The `PoolGovernance:withdrawRewards` method allows operators to withdraw their yield, which happens with this external call:

```solidity
(bool sent, ) = msg.sender.call{value: rewards, gas: 2300}("");
```

The 2300 gas limit might not be enough for smart contract wallets that have a `receive` or `fallback` function that takes more than 2300 gas units, which is too low (you can't do much more than emit an event). If that is the case, the operator won't be able to claim his rewards and they will be stuck in the contract forever.

**Recommendations**

Remove the gas limit from the external call. It can also be removed from the same logic in `SmoothlyPool` as well.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-08-01-Smoothly.md)

---

### Example 3: An incorrect decimal supplied to initializeSwap for a token cannot be corrected

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Security Assessment Report

## Severity
**Medium Risk**

## Context
`SwapAdminFacet.sol#L109-L119`

## Description
Once a swap is initialized by the owner or an admin (indexed by the `key` parameter), the decimal precisions per token, and therefore `tokenPrecisionMultipliers`, cannot be changed. If the supplied decimals include a wrong value, it would cause incorrect calculations when a swap is being made. Currently, there is no update mechanism for `tokenPrecisionMultipliers`, nor a mechanism for removing `swapStorages[_key]`.

## Recommendation
Add a restricted endpoint for updating the `tokenPrecisionMultipliers` for a token in an internal swap pool in case a mistake has been made when providing the decimals.

## Connext
We will remove the swap if we made a mistake when initializing the swap pool, because we have to update token balances and `adminFees` in the swap object when updating `tokenPrecisionMultipliers`. Solved in PR 2354.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 4: TWAP intervals should be flexible as per market conditions

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: MEDIUM

**Details**:

## Security Report

## Severity
**Medium Risk**

## Context
`SwapManagerUniV3.sol#L140-L149`

## Description
The protocol is using the same `TWAP_INTERVAL` for both `weth-morpho` and `weth-reward` token pools while their liquidity and activity might be different. It should use separate appropriate values for both pools.

## Recommendation
The `TWAP_INTERVAL` value should be changeable (and not constant) by the admin/owner since it is dependent upon market conditions and activity (for example, a 1-hour TWAP might lag considerably in sudden movements).

## Responses
- **Morpho:** Valid issue, will fix.
- **Spearbit:** Recommendation has been followed in the PR #557.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 5: H-1: Wrong calculation of `tickCumulatives` due to hardcoded pool fees

**Source**: Sherlock
**Protocol**: RealWagmi
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-real-wagmi-judging/issues/48 

## Found by 
Bauchibred, OxZ00mer, ast3ros, bitsurfer, crimson-rat-reach, duc, josephdara, mahdiRostami, n1punp, n33k, shogoki, stopthecap
## Summary
Wrong calculation of `tickCumulatives` due to hardcoded pool fees

## Vulnerability Detail
Real Wagmi is using a hardcoded `500` fee to calculate the `amountOut` to check for slippage and revert if it was to high, or got less funds back than expected. 

```@solidity
 IUniswapV3Pool(underlyingTrustedPools[500].poolAddress)
```

There are several problems with the hardcoding of the `500` as the fee.

- Not all tokens have `500` fee pools
- The swapping takes place in pools that don't have a `500` fee
- The `500` pool fee is not the optimal to fetch the `tickCumulatives` due to low volume

Specially as they are deploying in so many secondary chains like Kava, this will be a big problem pretty much in every transaction over there.

If any of those scenarios is given, `tickCumulatives`  will be incorrectly calculated and it will set an incorrect slippage return.

## Impact
Incorrect slippage calculation will increase the risk of `rebalanceAll()` rebalance getting rekt.

## Code Snippet
https://github.com/sherlock-audit/2023-06-real-wagmi/blob/main/concentrator/contracts/Multipool.sol#L816-L838
https://github.com/sherlock-audit/2023-06-real-wagmi/blob/main/concentrator/contracts/Multipool.sol#L823
## Tool used

Manual Review

## Recommendation
Consider al

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
