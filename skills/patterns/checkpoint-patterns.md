# CheckPoint Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 0 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena

---

## Detection Checklist

- [ ] Check for checkpoint vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-03] Multiple vote checkpoints per block will lead to incorrect vote accounting

**Source**: Code4rena
**Protocol**: Nouns Builder
**Impact**: HIGH

**Details**:

_Submitted by berndartmueller, also found by 0x52, 0xSky, bin2chen, cccz, Chom, davidbrai, elprofesor, izhuer, m9800, PwnPatrol, and rvierdiiev_

Voting power for each NFT owner is persisted within timestamp-dependent checkpoints. Every voting power increase or decrease is recorded. However, the implementation of `ERC721Votes` creates separate checkpoints with the same timestamp for each interaction, even when the interactions happen in the same block/timestamp.

### Impact

Checkpoints with the same `timestamp` will cause issues within the `ERC721Votes.getPastVotes(..)` function and will return incorrect votes for a given `_timestamp`.

### Proof of Concept

[lib/token/ERC721Votes.sol#L252-L253](https://github.com/code-423n4/2022-09-nouns-builder/blob/7e9fddbbacdd7d7812e912a369cfd862ee67dc03/src/lib/token/ERC721Votes.sol#L252-L253)

```solidity
/// @dev Records a checkpoint
/// @param _account The account address
/// @param _id The checkpoint id
/// @param _prevTotalVotes The account's previous voting weight
/// @param _newTotalVotes The account's new voting weight
function _writeCheckpoint(
    address _account,
    uint256 _id,
    uint256 _prevTotalVotes,
    uint256 _newTotalVotes
) private {
    // Get the pointer to store the checkpoint
    Checkpoint storage checkpoint = checkpoints[_account][_id];

    // Record the updated voting weight and current time
    checkpoint.votes = uint192(_newTotalVotes);
    checkpoint.timestamp = uint64(block.timestamp);

    emit Dele

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-nouns-builder)

---

### Example 2: [H-04] ERC20ConvictionScore._writeCheckpoint` does not write to storage on same block

**Source**: Code4rena
**Protocol**: FairSide
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

In `ERC20ConvictionScore._writeCheckpoint`, when the checkpoint is overwritten (`checkpoint.fromBlock == blockNumber`), the new value is set to the `memory checkpoint` structure and never written to storage.

```solidity
// @audit this is MEMORY, setting new convictionScore doesn't write to storage
Checkpoint memory checkpoint = checkpoints[user][nCheckpoints - 1];

if (nCheckpoints > 0 && checkpoint.fromBlock == blockNumber) {
    checkpoint.convictionScore = newCS;
}
```

Users that have their conviction score updated several times in the same block will only have their first score persisted.

###### POC
*   User updates their conviction with `updateConvictionScore(user)`
*   **In the same block**, the user now redeems an NFT conviction using `acquireConviction(id)`. This calls `_increaseConvictionScore(user, amount)` which calls `_writeCheckpoint(..., prevConvictionScore + amount)`. The updated checkpoint is **not** written to storage, and the user lost their conviction NFT. (The conviction/governance totals might still be updated though, leading to a discrepancy.)

#### Impact
Users that have their conviction score updated several times in the same block will only have their first score persisted.

This also applies to the total conviction scores `TOTAL_CONVICTION_SCORE` and `TOTAL_GOVERNANCE_SCORE` (see `_updateConvictionTotals`) which is a big issue as these are updated a lot of times each block.

It can also be used for inflating a user's convic

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-fairside)

---

### Example 3: H-1: Bypass the blacklist restriction because the blacklist check is not done when minting or burning

**Source**: Sherlock
**Protocol**: Dinari
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-dinari-judging/issues/64 

## Found by 
ctf\_sec, dirk\_y, p-tsanev, toshii
## Summary

Bypass the blacklist restriction because the blacklist check is not done when minting or burning

## Vulnerability Detail

In the whitepaper:

> the protocol emphasis that they implement a blacklist feature for enforcing OFAC, AML and other account security requirements
A blacklisted will not able to send or receive tokens

the protocol want to use the whitelist feature to be compliant to not let the blacklisted address send or receive dSahres

For this reason, before token transfer, the protocol check if address from or address to is blacklisted and the blacklisted address can still create buy order or sell order

```solidity
   function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // Restrictions ignored for minting and burning
        // If transferRestrictor is not set, no restrictions are applied

        // @audit
        // why don't you not apply mint and burn in blacklist?
        if (from == address(0) || to == address(0) || address(transferRestrictor) == address(0)) {
            return;
        }

        // Check transfer restrictions
        transferRestrictor.requireNotRestricted(from, to);
    }
```

this is calling

```solidity
function requireNotRestricted(address from, address to) external view virtual {
	// Check if either account is restricted
	if (blacklist[from] || blackl

*[Content truncated...]*

---

### Example 4: H-1: Flashloan `TEL` tokens to stake and exit in the same block can fake a huge amount of stake with minimal material cost

**Source**: Sherlock
**Protocol**: Telcoin
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-telcoin-judging/issues/83 

## Found by 
WATCHPUG

## Summary

`Checkpoints#getAtBlock()` can be faked with falshloan as it may return the value of the first checkpoint in the same block.

## Vulnerability Detail

`Checkpoints#getAtBlock()` will return the value on check point #0 when there are two check points in the same block (#0 and #1).

Therefore, one can take a falshloan of TEL tokens to stake and exit in the same block, which will create two checkpoints.

## Impact

Malicious user can fake their stake to gain a high percentage rewards with falshloan and avoid slashing.

## Code Snippet

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/StakingModule.sol#L147-L149

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/StakingModule.sol#L403-L406

## Tool used

Manual Review

## Recommendation

Consider requiring the `exit` to be at least 1 block later than the blocknumber of the original stake.

## Discussion

**amshirif**

https://github.com/telcoin/telcoin-staking/pull/9

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
