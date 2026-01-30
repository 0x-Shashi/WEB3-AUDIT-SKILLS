# Update State After Admin Action Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 2 | 0 | 0 |

**Common Sources**: Spearbit, Code4rena

---

## Detection Checklist

- [ ] Check for update state after admin action vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: updateWeightsGradually allows change rates to start in the past with a very high maximumRatio

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
AeraVaultV1.sol#L599-L639

## Description
The current `updateWeightsGradually` is using `startTime` instead of the minimal start time that should be `Math.max(block.timestamp, startTime)`. Because internally Balancer will use `startTime = Math.max(currentTime, startTime);` as the `startTime`, this allows for:

- Having a `startTime` in the past.
- Having a `targetWeights[i]` higher than allowed.

We also suggest adding another check to prevent `startTime > endTime`. Although Balancer replicates the same check, it is still needed in the Aera implementation to prevent transactions from reverting because of an underflow error on 

```solidity
uint256 duration = endTime - startTime;
```

## Recommendation
Update the code to correctly initialize the `startTime` value and add a check to prevent having `endTime` in the past (`startTime > endTime`). A possible solution looks as follows:

```solidity
function updateWeightsGradually( ... ) ... {
    startTime = Math.max(block.timestamp, startTime);
    if (startTime > endTime) {
        revert Aera__WeightChangeEndBeforeStart();
    }
    if (
        Math.max(block.timestamp, startTime) +
        MINIMUM_WEIGHT_CHANGE_DURATION > endTime
    ) {
        revert Aera__WeightChangeDurationIsBelowMin(
            endTime - startTime, // no longer reverts
            MINIMUM_WEIGHT_CHANGE_DURATION
        );
    }
    ...
}
```

## Gauntlet
Recommendation implemented in PR #146

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 2: Manager can cause an immediate weight change

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: HIGH

**Details**:

## High Risk Security Issue in ManagedPool.sol

## Severity
**High Risk**

## Context
- `ManagedPool.sol#L254-L272`
- `ManagedPool.sol#L620-L654`
- `ManagedPool.sol#L680-L698`

## Description
Balancers `ManagedPool` uses 32-bit values for `startTime` and `endTime` but does not verify if those values exist within that range. When `endTime` is set to \(2^{32}\), it becomes larger than `startTime`, so the `_require(startTime <= endTime, ...)` statement will not revert. When `endTime` is converted to 32 bits, it will get a value of 0, causing the check in `_calculateWeightChangeProgress()` with `if (currentTime >= endTime)` to be true, thus leading to an immediate weight change.

This allows the Manager to trigger an immediate weight change via the `updateWeightsGradually()` function and open arbitrage opportunities.

**Note:** 
- `startTime` is also subject to this overflow problem.
- The same issue occurs in the latest version of `ManagedPool`.
- This issue has been reported to Balancer by the Spearbit team.

Also see the following issues:
- Managed Pools are still undergoing development and may contain bugs and/or change significantly
- Important fields of Balancer can be overwritten by `endTime`

## Code Example
```solidity
contract ManagedPool is BaseWeightedPool, ReentrancyGuard {
    function updateWeightsGradually(uint256 startTime, uint256 endTime, ... ) {
        ...
        uint256 currentTime = block.timestamp;
        startTime = Math.max(currentTime, startTime);
  

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 3: [H-01] Wrong reward token calculation in MasterChef contract

**Source**: Code4rena
**Protocol**: Concur Finance
**Impact**: HIGH

**Details**:

_Submitted by throttle, also found by cccz, cmichel, and leastwood_

[MasterChef.sol#L86](https://github.com/code-423n4/2022-02-concur/blob/main/contracts/MasterChef.sol#L86)<br>

When adding new token pool for staking in MasterChef contract

```javascript
function add(address _token, uint _allocationPoints, uint16 _depositFee, uint _startBlock)
```

All other, already added, pools should be updated but currently they are not.<br>
Instead, only totalPoints is updated. Therefore, old (and not updated) pools will lose it's share during the next update.<br>
Therefore, user rewards are not computed correctly (will be always smaller).

### Proof of Concept

Scenario 1:

1.  Owner adds new pool (first pool) for staking with points = 100 (totalPoints=100)<br>
    and 1 block later Alice stakes 10 tokens in the first pool.
2.  1 week passes
3.  Alice withdraws her 10 tokens and claims X amount of reward tokens.<br>
    and 1 block later Bob stakes 10 tokens in the first pool.
4.  1 week passes
5.  Owner adds new pool (second pool) for staking with points = 100 (totalPoints=200)<br>
    and 1 block later Bob withdraws his 10 tokens and claims X/2 amount of reward tokens.<br>
    But he should get X amount

Scenario 2:

1.  Owner adds new pool (first pool) for staking with points = 100 (totalPoints=100).
2.  1 block later Alice, Bob and Charlie stake 10 tokens there (at the same time).
3.  1 week passes
4.  Owner adds new pool (second pool) for staking with points = 400 (totalPoints=50

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-concur)

---

### Example 4: Initial cycle time is wrong when queuing several config updates

**Source**: Spearbit
**Protocol**: Maple Finance
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
`withdrawal-manager::WithdrawalManager.sol#L123`

## Description
The initial cycle time will be wrong if there's already an upcoming config change that changes the cycle duration.

### Example
```plaintext
currentCycleId: 100
config[0] = currentConfig = {initialCycleId: 1, cycleDuration = 1 days}
config[1] = {initialCycleId: 101, cycleDuration = 7 days}
```
Now, scheduling will create a config with `initialCycleId: 103` and `initialCycleTime = now + 3 * 1 days`, but the cycle durations for cycles (100, 101, 102) are `1 days + 7 days + 7 days`.

## Recommendation
Optimistically "apply" (just for the computation, not actually activate it) any pending configs for a cycle ID and then sum up the cycle durations for the cycles `[currentCycleId, currentCycleId + 1, currentCycleId + 2]`. Add the result to `getWindowStart(currentCycleId_)`.

## Maple
Fixed in #50.

## Spearbit
Fixed.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/MapleV2.pdf)

---

### Example 5: ERC721SeaDrop 'sadmin would need to set feeBps manually after/before creation of each drop by the owner

**Source**: Spearbit
**Protocol**: SeaDrop
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- `ERC721SeaDrop.sol#L180`
- `ERC721SeaDrop.sol#L256`

## Description
When an owner of an `ERC721SeaDrop` token creates either a public or a token gated drop by calling `updatePublicDrop` or `updateTokenGatedDrop`, the `PublicDrop.feeBps` / `TokenGatedDropStage.feeBps` is initially set to 0. So the admin would need to set the `feeBps` parameter at some point (before or after). Forgetting to set this parameter results in not receiving the protocol fees.

## Recommendation
There are multiple ways to mitigate this:

1. The admin monitors the activities on-chain and if it sees a newly created drop, calls either `updatePublicDropFee` or `updateTokenGatedDropFee` (depending on the type of the drop) to set the `feeBps`.
   
2. Enforcing that both `updatePublicDrop` and `updatePublicDropFee` (or `updateTokenGatedDrop` and `updateTokenGatedDropFee`) be called by the owner and the admin before a drop can start. The enforcement can be either on the `ERC721SeaDrop` side or on the `SeaDrop` side. Also, there could be a flag set by the admin to waive the protocol fee.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Seadrop-Spearbit-Security-Review.pdf)

---

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

