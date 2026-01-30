# Mapping Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 2 | 0 | 0 |

**Common Sources**: Sherlock, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for mapping vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: M-22: Memorializing an NFT position on the same bucket of a previously memorialized NFT locks redemption

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/13 

## Found by 
MalfurionWhitehat

## Summary

Memorializing a position as an NFT on the same bucket of an existing memorialized position will not allow any of the owners to directly redeem it back later.

## Vulnerability Detail

This issue happens because, after a position is memorialized on the `PositionManager`, this contract will centralize LP positions from different users, but these will be mapped to the same address from the point of view of Ajna pools (different users will be mapped as the same `lender` from the point of view of a `Pool`). 

If more than one user has memorialized a position to the same bucket index, when attempting to `PositionManager.redeemPositions`, the call to [`pool.transferLPs`](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/PositionManager.sol#L311) will revert with [`NoAllowance`](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/libraries/external/LenderActions.sol#L538), as `LenderActions` does not allow a transfer with value lower than the total `lenderLpBalance`.

Because of that, any of the users' that share a bucket `redeemPositions` calls will fail.

## Impact

Although users that share a bucket with memorialized positions are not able to direct redeem their positions, they can eventually get their LPs back with a specific set of actions.

By first calling `PositionManager.moveLiquidity` to a bucket _without any other LP

*[Content truncated...]*

---

### Example 2: H-7: WAuraPools will irreversibly break if reward tokens are added to pool after deposit

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/127 

## Found by 
0x52, Ch\_301
## Summary

WAuraPools will irreversibly break if reward tokens are added to pool after deposit due to an OOB error on accExtPerShare.

## Vulnerability Detail

[WAuraPools.sol#L166-L189](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L166-L189)

        uint extraRewardsCount = IAuraRewarder(crvRewarder)
            .extraRewardsLength(); <- @audit-issue rewardTokenCount pulled fresh
        tokens = new address[](extraRewardsCount + 1);
        rewards = new uint256[](extraRewardsCount + 1);

        tokens[0] = IAuraRewarder(crvRewarder).rewardToken();
        rewards[0] = _getPendingReward(
            stCrvPerShare,
            crvRewarder,
            amount,
            lpDecimals
        );

        for (uint i = 0; i < extraRewardsCount; i++) {
            address rewarder = IAuraRewarder(crvRewarder).extraRewards(i);

            @audit-issue attempts to pull from array which will be too small if tokens are added
            uint256 stRewardPerShare = accExtPerShare[tokenId][i];
            tokens[i + 1] = IAuraRewarder(rewarder).rewardToken();
            rewards[i + 1] = _getPendingReward(
                stRewardPerShare,
                rewarder,
                amount,
                lpDecimals
            );
        }

accExtPerShare stores the current rewardPerToken when the position is fir

*[Content truncated...]*

---

### Example 3: [M-02] The stake fees are not tracked on chain

**Source**: Pashov Audit Group
**Protocol**: Smoothly
**Impact**: MEDIUM

**Details**:

**Severity**

**Impact:**
High, as it can result in wrong accounting of ETH held by `SmoothlyPool`

**Likelihood:**
Low, as it requires off-chain code to be wrong

**Description**

Every validator who joins the `SmoothlyPool` should register by paying a `STAKE_FEE` (with the size of 0.065 ETH) to the contract. The pool does not track how much of a stake fee balance a validator has, which is problematic for the following reasons:

1. The pool has no guarantee that it holds at least `numValidators * STAKE_FEE` ETH in its balance - the ETH might have been mistakenly distributed as rewards or claimed as fees from operators
2. It is possible for a validator to deposit more than `STAKE_FEE` if he calls `SmoothlyPool::addStake` multiple times
3. The slashing/punishment mechanism can't be enforced on chain

**Recommendations**

Add a mapping to track validators' stake fee balances in `SmoothlyPool`.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-08-01-Smoothly.md)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

