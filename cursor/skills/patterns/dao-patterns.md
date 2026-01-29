# DAO Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 2 | 0 | 0 |

**Common Sources**: Sherlock

---

## Detection Checklist

- [ ] Check for dao vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-2: `Staking.unstake()` doesn't decrease the original voting power that was used in `Staking.stake()`.

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/70 

## Found by 
Haruxe, 0x52, hansfriese

## Summary
`Staking.unstake()` doesn't decrease the original voting power that was used in `Staking.stake()`.

## Vulnerability Detail
When users stake/unstake the underlying NFTs, it calculates the token voting power using [getTokenVotingPower()](https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L507-L515) and increases/decreases their voting power accordingly.

```solidity
    function getTokenVotingPower(uint _tokenId) public override view returns (uint) {
      if (ownerOf(_tokenId) == address(0)) revert NonExistentToken();

      // If tokenId < 10000, it's a FrankenPunk, so 100/100 = a multiplier of 1
      uint multiplier = _tokenId < 10_000 ? PERCENT : monsterMultiplier;
      
      // evilBonus will return 0 for all FrankenMonsters, as they are not eligible for the evil bonus
      return ((baseVotes * multiplier) / PERCENT) + stakedTimeBonus[_tokenId] + evilBonus(_tokenId);
    }
```

But `getTokenVotingPower()` uses some parameters like `monsterMultiplier` and `baseVotes` and the output would be changed for the same `tokenId` after the admin changed these settings.

Currently, `_stake()` and `_unstake()` calculates the token voting power independently and the below scenario would be possible.

- At the first time, `baseVotes = 20, monsterMultiplier = 50`.
- A user staked a `FrankenMonsters` and his voting power = 10 [

*[Content truncated...]*

---

### Example 2: H-1: The total community voting power is updated incorrectly when a user delegates.

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/91 

## Found by 
Trumpero, curiousapple, hansfriese

## Summary
When a user delegates their voting power from staked tokens, the total community voting power should be updated. But the update logic is not correct, the the total community voting power could be wrong values.

## Vulnerability Detail

```solidity
    tokenVotingPower[currentDelegate] -= amount;
    tokenVotingPower[_delegatee] += amount; 

    // If a user is delegating back to themselves, they regain their community voting power, so adjust totals up
    if (_delegator == _delegatee) {
      _updateTotalCommunityVotingPower(_delegator, true);

    // If a user delegates away their votes, they forfeit their community voting power, so adjust totals down
    } else if (currentDelegate == _delegator) {
      _updateTotalCommunityVotingPower(_delegator, false);
    }
```
When the total community voting power is increased in the first if statement, `_delegator`'s token voting power might be positive already and community voting power might be added to total community voting power before.

Also, `currentDelegate`'s token voting power might be still positive after delegation so we shouldn't remove the communitiy voting power this time.

## Impact
The total community voting power can be incorrect.

## Code Snippet
https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L293-L313

## Tool used
Manual Review

## Recommendati

*[Content truncated...]*

---

### Example 3: M-6: Delegate can keep can keep delegatee trapped indefinitely

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/23 

## Found by 
rvierdiiev, 0x52

## Summary

Users are allowed to delegate their votes to other users. Since staking does not implement checkpoints, users are not allowed to delegate or unstake during an active proposal if their delegate has already voted. A malicious delegate can abuse this by creating proposals so that there is always an active proposal and their delegatees are always locked to them.

## Vulnerability Detail

    modifier lockedWhileVotesCast() {
      uint[] memory activeProposals = governance.getActiveProposals();
      for (uint i = 0; i < activeProposals.length; i++) {
        if (governance.getReceipt(activeProposals[i], getDelegate(msg.sender)).hasVoted) revert TokenLocked();
        (, address proposer,) = governance.getProposalData(activeProposals[i]);
        if (proposer == getDelegate(msg.sender)) revert TokenLocked();
      }
      _;
    }

The above modifier is applied when unstaking or delegating. This reverts if the delegate of msg.sender either has voted or currently has an open proposal. The result is that under those conditions, the delgatee cannot unstake or delegate. A malicious delegate can abuse these conditions to keep their delegatees forever delegated to them. They would keep opening proposals so that delegatees could never unstake or delegate. A single users can only have a one proposal opened at the same time so they would use a secondary account to al

*[Content truncated...]*

---

### Example 4: M-5: castVote can be called by anyone even those without votes

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/25 

## Found by 
Trumpero, 0x52, hansfriese

## Summary

Governance#castVote can be called by anyone, even users that don't have any votes. Since the voting refund is per address, an adversary could use a large number of addresses to vote with zero votes to drain the vault.

## Vulnerability Detail

    function _castVote(address _voter, uint256 _proposalId, uint8 _support) internal returns (uint) {
        // Only Active proposals can be voted on
        if (state(_proposalId) != ProposalState.Active) revert InvalidStatus();
        
        // Only valid values for _support are 0 (against), 1 (for), and 2 (abstain)
        if (_support > 2) revert InvalidInput();

        Proposal storage proposal = proposals[_proposalId];

        // If the voter has already voted, revert        
        Receipt storage receipt = proposal.receipts[_voter];
        if (receipt.hasVoted) revert AlreadyVoted();

        // Calculate the number of votes a user is able to cast
        // This takes into account delegation and community voting power
        uint24 votes = (staking.getVotes(_voter)).toUint24();

        // Update the proposal's total voting records based on the votes
        if (_support == 0) {
            proposal.againstVotes = proposal.againstVotes + votes;
        } else if (_support == 1) {
            proposal.forVotes = proposal.forVotes + votes;
        } else if (_support == 2) {
            pr

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
