# Vote Security Patterns

## Overview

**Frequency**: 22 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 14 | 8 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Cyfrin, Spearbit, Shieldify

---

## Detection Checklist

- [ ] Check for vote vulnerabilities in all external functions
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

### Example 2: Oracle.removeMember could, in the same epoch, allow members to vote multiple times and other members to not vote at all

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: HIGH

**Details**:

## Oracle Vulnerability Report

**Severity:** High Risk  
**Context:** Oracle.1.sol#L213-L222  

## Description

The current implementation of `removeMember` is introducing an exploit that allows an oracle member to vote multiple times in the same epoch, while preventing another oracle that has never voted from casting a vote during the same epoch.

Due to the implementation of `OracleMembers.deleteItem`, the last item of the array is swapped with the item that is being deleted, and then the last element is popped.

### Example Scenario

1. At T0, add member `m0` to the list of members: `members[0] = m0`.
2. At T1, add member `m1` to the list of members: `members[1] = m1`.
3. At T3, `m0` calls `reportBeacon(...)`. This action triggers a call to `ReportsPositions.register(uint256(0));` which registers that the member at index 0 has voted.
4. At T4, the oracle admin calls `removeMember(m0)`. This operation swaps `m0`’s address from the last position of the array with the position of the member being deleted. After this, it pops the last position of the array. The state changes from:
   - `members[0] = m0; members[1] = m1`
   - to `members[0] = m1;`.

At this point, the oracle member `m1` will not be able to vote during this epoch because when he/she calls `reportBeacon(...)`, the function will check:

```solidity
if (ReportsPositions.get(uint256(memberIndex))) {
    revert AlreadyReported(_epochId, msg.sender);
}
```

This is because `int256 memberIndex = OracleMembers.indexOf(

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 3: Attacker can destroy user voting power by setting `ERC721Power::totalPower` and all existing NFTs `currentPower` to 0

**Source**: Cyfrin
**Protocol**: Dexe
**Impact**: HIGH

**Details**:

**Description:** Attacker can destroy user voting power by setting `ERC721Power::totalPower` & all existing nfts' `currentPower` to 0 via a permission-less attack contract by exploiting a discrepancy ("<" vs "<=") in `ERC721Power` [L144](https://github.com/dexe-network/DeXe-Protocol/tree/f2fe12eeac0c4c63ac39670912640dc91d94bda5/contracts/gov/ERC721/ERC721Power.sol#L144) & [L172](https://github.com/dexe-network/DeXe-Protocol/tree/f2fe12eeac0c4c63ac39670912640dc91d94bda5/contracts/gov/ERC721/ERC721Power.sol#L172):

```solidity
function recalculateNftPower(uint256 tokenId) public override returns (uint256 newPower) {
    // @audit execution allowed to continue when
    // block.timestamp == powerCalcStartTimestamp
    if (block.timestamp < powerCalcStartTimestamp) {
        return 0;
    }
    // @audit getNftPower() returns 0 when
    // block.timestamp == powerCalcStartTimestamp
    newPower = getNftPower(tokenId);

    NftInfo storage nftInfo = nftInfos[tokenId];

    // @audit as this is the first update since power
    // calculation has just started, totalPower will be
    // subtracted by nft's max power
    totalPower -= nftInfo.lastUpdate != 0 ? nftInfo.currentPower : getMaxPowerForNft(tokenId);
    // @audit totalPower += 0 (newPower = 0 in above line)
    totalPower += newPower;

    nftInfo.lastUpdate = uint64(block.timestamp);
    // @audit will set nft's current power to 0
    nftInfo.currentPower = newPower;
}

function getNftPower(uint256 tokenId) public view ove

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-10-cyfrin-dexe.md)

---

### Example 4: Attacker can combine flashloan with delegated voting to decide a proposal and withdraw their tokens while the proposal is still in Locked state

**Source**: Cyfrin
**Protocol**: Dexe
**Impact**: HIGH

**Details**:

**Description:** Attacker can combine a flashloan with delegated voting to bypass the existing flashloan mitigations, allowing the attacker to decide a proposal & withdraw their tokens while the proposal is still in the Locked state. The entire attack can be performed in 1 transaction via an attack contract.

**Impact:** Attacker can bypass existing flashloan mitigations to decide the outcome of proposals by combining flashloan with delegated voting.

**Proof of Concept:** Add the attack contract to `mock/utils/FlashDelegationVoteAttack.sol`:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "../../interfaces/gov/IGovPool.sol";

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract FlashDelegationVoteAttack {
    //
    // how the attack contract works:
    //
    // 1) use flashloan to acquire large amount of voting tokens
    //    (caller transfer tokens to contract before calling to simplify PoC)
    // 2) deposit voting tokens into GovPool
    // 3) delegate voting power to slave contract
    // 4) slave contract votes with delegated power
    // 5) proposal immediately reaches quorum and moves into Locked state
    // 6) undelegate voting power from slave contract
    //    since undelegation works while Proposal is in locked state
    // 7) withdraw voting tokens from GovPool while proposal still in Locked state
    // 8) all in 1 txn
    //

    function attack(address govPoolAddress, address tokenAddress, uint256 proposalId) ext

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-10-cyfrin-dexe.md)

---

### Example 5: [H-01] PartyGovernance: Can vote multiple times by transferring NFT in same block as proposal

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: HIGH

**Details**:

_Submitted by Lambda, also found by Trust_

`PartyGovernanceNFT` uses the voting power at the time of proposal when calling `accept`. The problem with that is that a user can vote, transfer the NFT (and the voting power) to a different wallet, and then vote from this second wallet again during the same block that the proposal was created.
This can also be repeated multiple times to get an arbitrarily high voting power and pass every proposal unanimously.

The consequences of this are very severe. Any user (no matter how small his voting power is) can propose and pass arbitrary proposals animously and therefore steal all assets (including the precious tokens) out of the party.

### Proof Of Concept

This diff shows how a user with a voting power of 50/100 gets a voting power of 100/100 by transferring the NFT to a second wallet that he owns and voting from that one:

```diff
--- a/sol-tests/party/PartyGovernanceUnit.t.sol
+++ b/sol-tests/party/PartyGovernanceUnit.t.sol
@@ -762,6 +762,7 @@ contract PartyGovernanceUnitTest is Test, TestUtils {
         TestablePartyGovernance gov =
             _createGovernance(100e18, preciousTokens, preciousTokenIds);
         address undelegatedVoter = _randomAddress();
+        address recipient = _randomAddress();
         // undelegatedVoter has 50/100 intrinsic VP (delegated to no one/self)
         gov.rawAdjustVotingPower(undelegatedVoter, 50e18, address(0));
 
@@ -772,38 +773,13 @@ contract PartyGovernanceUnitTest is Test, TestUtils {

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 6: H-1: "Votes" balance can be increased indefinitely in multiple contracts

**Source**: Sherlock
**Protocol**: Tokensoft
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-tokensoft-judging/issues/41 

## Found by 
0xDanielH, 0xDjango, 0xbranded, 0xlx, AkshaySrivastav, BenRai, Czar102, Musaka, VAD37, Yuki, caventa, dany.armstrong90, jah, jkoppel, kutugu, magellanXtrachev, ni8mare, p-tsanev, p12473, pengun, r0bert, stopthecap, twicek, y1cunhui
## Summary
The "voting power" can be easily manipulated in the following contracts:
- `ContinuousVestingMerkle`
- `PriceTierVestingMerkle`
- `PriceTierVestingSale_2_0`
- `TrancheVestingMerkle`
- `CrosschainMerkleDistributor`
- `CrosschainContinuousVestingMerkle`
- `CrosschainTrancheVestingMerkle`
- All the contracts inheriting from the contracts listed above

This is caused by the public `initializeDistributionRecord()` function that can be recalled multiple times without any kind of access control:
```solidity
  function initializeDistributionRecord(
    uint32 _domain, // the domain of the beneficiary
    address _beneficiary, // the address that will receive tokens
    uint256 _amount, // the total claimable by this beneficiary
    bytes32[] calldata merkleProof
  ) external validMerkleProof(_getLeaf(_beneficiary, _amount, _domain), merkleProof) {
    _initializeDistributionRecord(_beneficiary, _amount);
  }
```

## Vulnerability Detail
The `AdvancedDistributor` abstract contract which inherits from the `ERC20Votes`, `ERC20Permit` and `ERC20` contracts, distributes tokens to beneficiaries with voting-while-vesting and administrative controls. Basically, 

*[Content truncated...]*

---

### Example 7: [H-03] Users Can Use `Flashloan` to Increase Voting Power of Expired Positions and Execute Proposal for Their Benefits

**Source**: Shieldify
**Protocol**: Guanciale Stake
**Impact**: HIGH

**Details**:

## Severity

High Risk

## Description

If we assume the Medium-01 from the report is fixed in the `increaseAndStake()` function which allows users to add the amount to their stake without updating the lock duration then the below scenario might be executable:

- Assume Alice's `lockUntil` reached the current `block.timestamp`.

- Alice got a huge flashloan of GUAN token (can get another token as flashloan and then swap it to GUAN) and called the `increaseAndStake()` function with the flashloan amount.

- If we assume the Medium-01 issue is fixed then the transaction will be executed without reverting since Alice increased the stake amount only.

- The `veGUAN` core logic allows the stakes to have voting power depending on their stake amount even if the lock duration expired, this is clearly shown in the function below:

```solidity
function _calculateVotingPower(
  UD60x18 votingPowerCurveAFactorX18,
  UD60x18 remainingLockDurationX18,
  UD60x18 positionStakeX18
)
  internal
  pure
  returns (uint256 scalingFactor, uint256 votingPower)
{
  // calculate the lock multiplier as explained in the function's natspec
  UD60x18 scalingFactorX18 = votingPowerCurveAFactorX18.mul(remainingLockDurationX18).add(UNIT); // @audit 1e18 get added even if the calc = 0

  // return the scaling factor and voting power
  scalingFactor = scalingFactorX18.intoUint256();
  votingPower = positionStakeX18.mul(scalingFactorX18).intoUint256();
}
```

- This way Alice can have huge voting power due to h

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/Guanciale-Stake-Security-Review.md)

---

### Example 8: Attacker can at anytime dramatically lower `ERC721Power::totalPower` close to 0

**Source**: Cyfrin
**Protocol**: Dexe
**Impact**: HIGH

**Details**:

**Description:** Attacker can at anytime dramatically lower `ERC721Power::totalPower` close to 0 using a permission-less attack contract by taking advantage of being able to call `ERC721Power::recalculateNftPower()` & `getNftPower()` for non-existent nfts:

```solidity
function getNftPower(uint256 tokenId) public view override returns (uint256) {
    if (block.timestamp <= powerCalcStartTimestamp) {
        return 0;
    }

    // @audit 0 for non-existent tokenId
    uint256 collateral = nftInfos[tokenId].currentCollateral;

    // Calculate the minimum possible power based on the collateral of the nft
    // @audit returns default maxPower for non-existent tokenId
    uint256 maxNftPower = getMaxPowerForNft(tokenId);
    uint256 minNftPower = maxNftPower.ratio(collateral, getRequiredCollateralForNft(tokenId));
    minNftPower = maxNftPower.min(minNftPower);

    // Get last update and current power. Or set them to default if it is first iteration
    // @audit both 0 for non-existent tokenId
    uint64 lastUpdate = nftInfos[tokenId].lastUpdate;
    uint256 currentPower = nftInfos[tokenId].currentPower;

    if (lastUpdate == 0) {
        lastUpdate = powerCalcStartTimestamp;
        // @audit currentPower set to maxNftPower which
        // is just the default maxPower even for non-existent tokenId!
        currentPower = maxNftPower;
    }

    // Calculate reduction amount
    uint256 powerReductionPercent = reductionPercent * (block.timestamp - lastUpdate);
    uint256 p

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-10-cyfrin-dexe.md)

---

### Example 9: [H-02] Single host can unfairly skip veto period for proposal that does not have full host support

**Source**: Code4rena
**Protocol**: Party Protocol
**Impact**: HIGH

**Details**:

After a proposal passes the vote threshold, there is a delay before it can be executed so that hosts get a chance to `veto` it if they wish. If all hosts voting in favour of the proposal, then this veto period is skipped.

However, a single host can ensure the veto period is skipped even if no other hosts `accept` the proposal. The veto period is in place to prevent harmful/exploitative proposals from being executed, even if they are passed; therefore, a malicious/compromised host being able to skip the veto period can be seriously harmful to the protocol and its users. The [Tornado Cash governance hack](https://medium.com/coinmonks/tornado-cash-governance-hack-ec77ebb3aa68) from May 2023 is a relevant example, during which the attacker was able to steal around `$`1 million worth of assets.

This attack has a very low cost and a very high potential impact. If a malicious proposal is crafted in the same way used by the Tornado Cash attacker using hidden `CREATE2` and `SELFDESTRUCT` operations, then it is entirely feasible that it would meet the voting threshold, as many voters may not be savvy enough to spot the red flags.

### Proof of Concept

`PartyGovernance#abdicateHost` is a function that allows a host to renounce their host privileges, and transfer them to another address.

```solidity
File: contracts\party\PartyGovernance.sol

457:     /// @notice Transfer party host status to another.
458:     /// @param newPartyHost The address of the new host.
459:     function abdi

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-10-party)

---

### Example 10: Decrementing the quorum in Oracle in some scenarios can open up a frontrunning/backrunning opportunity for some oracle members

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- Oracle.1.sol#L338-L370
- Oracle.1.sol#L260
- Oracle.1.sol#L156 @ 030b52feb5af2dd2ad23da0d512c5b0e55eb8259

## Description
Assume there are 2 groups of oracle members A and B where they have voted for report variants \(V_a\) and \(V_b\) respectively. Let's also assume the count for these variants \(C_a\) and \(C_b\) are equal and are the highest variant vote counts among all possible variants. If the Oracle admin changes the quorum to a number less than or equal to \(C_a + 1 = C_b + 1\), any oracle member can backrun this transaction by the admin to decide which report variant \(V_a\) or \(V_b\) gets pushed to the River. This is because when a lower quorum is submitted by the admin and there exist two variants that have the highest number of votes, in the `_getQuorumReport` function the returned `isQuorum` parameter would be false since `repeat == 0` is false:

```solidity
return (maxval >= _quorum && repeat == 0, variants[maxind]);
```

Note that this issue also exists in the commit hash 030b52feb5af2dd2ad23da0d512c5b0e55eb8259 and can be triggered by the admin either by calling `setQuorum` or `addMember` when the abovementioned conditions are met. Also, note that the free oracle member agent can frontrun the admin transaction to decide the quorum earlier in the scenario above. Thus this way `_getQuorumReport` would actually return that it is a quorum.

## Recommendation
This issue is similar to "The reportBeacon is prone to front-runnin

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 11: [M-09] `activateProposal()` need time delay

**Source**: Code4rena
**Protocol**: Olympus DAO
**Impact**: MEDIUM

**Details**:

_Submitted by &#95;&#95;141345&#95;&#95;, also found by 0x1f8b, Trust, V&#95;B, and zzzitron_

<https://github.com/code-423n4/2022-08-olympus/blob/b5e139d732eb4c07102f149fb9426d356af617aa/src/policies/Governance.sol#L205-L262><br>

There is no time lock or delay when activating a proposal, the previous one could be replaced immediately. In `vote()` call, a user might want to vote for the previous proposal, but if the `vote()` call and the `activateProposal()` is very close or even in the same block, it is quite possible that the user actually voted for another proposal without much knowledge of. A worse case is some malicious user watching the mempool, and front run a big vote favor/against the `activeProposal`, effectively influence the voting result.

These situations are not what the governance intends to deliver, and might also affect the results of 2 proposals.

### Proof of Concept

`activateProposal()` can take effect right away, replacing the `activeProposal`. And `vote()` does not specify which `proposalId` to vote for, but the `activeProposal` could be different from last second.

src/policies/Governance.sol

```solidity
    function activateProposal(uint256 proposalId_) external {
        ProposalMetadata memory proposal = getProposalMetadata[proposalId_];

        if (msg.sender != proposal.submitter) {
            revert NotAuthorizedToActivateProposal();
        }

        if (block.timestamp > proposal.submissionTimestamp + ACTIVATION_DEADLINE) {
            re

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-olympus)

---

### Example 12: H-1: `QVSimpleStrategy` never updates `allocator.voiceCredits`.

**Source**: Sherlock
**Protocol**: Allo V2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-09-Gitcoin-judging/issues/150 

## Found by 
0x00ffDa, 0x3b, 0xMAKEOUTHILL, 0xarno, 0xbepresent, 0xkaden, Arz, BenRai, GimelSec, HChang26, HHK, Kodyvim, Kow, Kral01, Martians, Nyx, WATCHPUG, ZdravkoHr., al88nsk, alexxander, ashirleyshe, ast3ros, bronze\_pickaxe, carrotsmuggler, chaduke, coffiasd, cu5t0mPe0, dany.armstrong90, detectiveking, dipp, fibonacci, jah, jkoppel, jovi, lemonmon, lil.eth, nobody2018, osmanozdemir1, pengun, pontifex, qbs, rvierdiiev, sandNallani, seeques, simon135, tnquanghuy0512, toshii, wangxx2026
Every allocator in `QVSimpleStrategy` has a maximum credit limit. An allocator should not be able to bypass the limit. However, `QVSimpleStrategy` fails to record the allocated votes. An allocator can vote as many as possible.

## Vulnerability Detail

`QVSimpleStrategy._allocate` calls `_hasVoiceCreditsLeft` to check that the recipient has voice credits left to allocate.
https://github.com/sherlock-audit/2023-09-Gitcoin/blob/main/allo-v2/contracts/strategies/qv-simple/QVSimpleStrategy.sol#L121
```solidity
    function _allocate(bytes memory _data, address _sender) internal virtual override {
        …

        // check that the recipient has voice credits left to allocate
        if (!_hasVoiceCreditsLeft(voiceCreditsToAllocate, allocator.voiceCredits)) revert INVALID();

        _qv_allocate(allocator, recipient, recipientId, voiceCreditsToAllocate, _sender);
    }
```

`QVSimpleStrategy._hasVoiceCreditsLeft` c

*[Content truncated...]*

---

### Example 13: [H-05] ArbitraryCallsProposal.sol and ListOnOpenseaProposal.sol safeguards can be bypassed by cancelling in-progress proposal allowing the majority to steal NFT

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: HIGH

**Details**:

_Submitted by 0x52_

Note: PartyDAO acknowledges that "canceling an InProgress proposal (mid-step) can leave the governance party in a vulnerable or undesirable state because there is no cleanup logic run during a cancel" in the "Known Issues / Topics" section of the contest readme. I still believe that this vulnerability needs to be mitigated as it can directly lead to loss of user funds.

### Impact

Majority vote can abuse cancel functionality to steal an NFT owned by the party.

### Proof of Concept

ArbitraryCallsProposal.sol implements the following safeguards for arbitrary proposals that are not unanimous:

1.  Prevents the ownership of any NFT changing during the call. It does this by checking the the ownership of all NFTs before and after the call.

2.  Prevents calls that would change the approval status of any NFT. This is done by disallowing the "approve" and "setApprovalForAll" function selectors.

Additionally ListOnOpenseaProposal.sol implements the following safeguards:

1.  NFTs are first listed for auction on Zora so that if they are listed for a very low price then the auction will keep them from being purchased at such a low price.

2.  At the end of the auction the approval is revoked when `\_cleanUpListing` is called.

These safeguards are ultimately ineffective though. The majority could use the following steps to steal the NFT:

1.  Create ListOnOpenseaProposal with high sell price and short cancel delay

2.  Vote to approve proposal with majority vote

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 14: [H-04] Old delegatee not deleted when delegating to new tokenId

**Source**: Code4rena
**Protocol**: Golom
**Impact**: HIGH

**Details**:

[VoteEscrowDelegation.sol#L80](https://github.com/code-423n4/2022-07-golom/blob/8f198624b97addbbe9602a451c908ea51bd3357c/contracts/vote-escrow/VoteEscrowDelegation.sol#L80)<br>

In `delegate`, when a user delegates to a new tokenId, the tokenId is not removed from the current delegatee. Therefore, one user can easily multiply his voting power, which makes the toking useless for voting / governance decisions.

### Proof Of Concept

Bob owns the token with ID 1 with a current balance of 1000. He also owns tokens 2, 3, 4, 5. Therefore, he calls `delegate(1, 2)`, `delegate(1, 3)`, `delegate(1, 4)`, `delegate(1, 5)`. Now, if there is a governance decision and `getVotes` is called, Bobs balance of 1000 is included in token 2, 3, 4, and 5. Therefore, he quadrupled the voting power of token 1.

### Recommended Mitigation Steps

Remove the entry in `delegatedTokenIds` of the old delegatee or simply call `removeDelegation` first.

**[zeroexdead (Golom) confirmed](https://github.com/code-423n4/2022-07-golom-findings/issues/169)**

**[zeroexdead (Golom) commented](https://github.com/code-423n4/2022-07-golom-findings/issues/169#issuecomment-1238345165):**
 > Fixed. 
> 
> Ref: https://github.com/golom-protocol/contracts/commit/c74d95b4105eeb878d2781982178db5ca08a1a9b



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-golom)

---

### Example 15: [H-07] Attacker can DOS private party by donating ETH then calling buy

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: HIGH

**Details**:

_Submitted by 0x52_

Party is DOS'd and may potentially lose access to NFT.

### Proof of Concept

[Crowdfund.sol#L280-L298](https://github.com/PartyDAO/party-contracts-c4/blob/3896577b8f0fa16cba129dc2867aba786b730c1b/contracts/crowdfund/Crowdfund.sol#L280-L298)

    party = party_ = partyFactory
        .createParty(
            address(this),
            Party.PartyOptions({
                name: name,
                symbol: symbol,
                governance: PartyGovernance.GovernanceOpts({
                    hosts: governanceOpts.hosts,
                    voteDuration: governanceOpts.voteDuration,
                    executionDelay: governanceOpts.executionDelay,
                    passThresholdBps: governanceOpts.passThresholdBps,
                    totalVotingPower: _getFinalPrice().safeCastUint256ToUint96(),
                    feeBps: governanceOpts.feeBps,
                    feeRecipient: governanceOpts.feeRecipient
                })
            }),
            preciousTokens,
            preciousTokenIds
        );

[BuyCrowdfundBase.sol#L166-L173](https://github.com/PartyDAO/party-contracts-c4/blob/3896577b8f0fa16cba129dc2867aba786b730c1b/contracts/crowdfund/BuyCrowdfundBase.sol#L166-L173)

    function _getFinalPrice()
        internal
        override
        view
        returns (uint256)
    {
        return settledPrice;
    }

When BuyCrowdFund.sol successfully completes a buy, totalVotingPower is set to `\_getFinalPrice` which in the case of BuyCrowd

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 16: H-4: Staking#_unstake removes votes from wrong person if msg.sender != owner

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/30 

## Found by 
0x52, cccz

## Summary

Staking#_unstake allows any msg.sender to unstake tokens for any owner that has approved them. The issue is that even when msg.sender != owner the votes are removed from msg.sender instead of owner. The result is that the owner keeps their votes and msg.sender loses theirs. This could be abused to hijack or damage voting.

## Vulnerability Detail

    address owner = ownerOf(_tokenId);
    if (msg.sender != owner && !isApprovedForAll[owner][msg.sender] && msg.sender != getApproved[_tokenId]) revert NotAuthorized();

Staking#_unstake allows any msg.sender to unstake tokens for any owner that has approved them.

    uint lostVotingPower;
    for (uint i = 0; i < numTokens; i++) {
        lostVotingPower += _unstakeToken(_tokenIds[i], _to);
    }

    votesFromOwnedTokens[msg.sender] -= lostVotingPower;
    // Since the delegate currently has the voting power, it must be removed from their balance
    // If the user doesn't delegate, delegates(msg.sender) will return self
    tokenVotingPower[getDelegate(msg.sender)] -= lostVotingPower;
    totalTokenVotingPower -= lostVotingPower;

After looping through _unstakeToken all accumulated votes are removed from msg.sender. The problem with this is that msg.sender is allowed to unstake tokens for users other than themselves and in these cases they will lose votes rather than the user who owns the token.

Example:
User 

*[Content truncated...]*

---

### Example 17: [M-03] Burning an NFT can be used to block voting

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: MEDIUM

**Details**:

A new validation in the `accept()` function has been introduced in order to mitigate a potential attack to the party governance.

By burning an NFT, a party member can reduce the total voting power of the party just before creating a proposal and voting for it. Since the snapshot used to vote is previous to this action, this means the user can still use their burned voting power while voting in a proposal with a reduced total voting power. This is stated in the comment attached to the new validation:

<https://github.com/code-423n4/2023-05-party/blob/main/contracts/party/PartyGovernance.sol#L589-L598>

```solidity
589:         // Prevent voting in the same block as the last burn timestamp.
590:         // This is to prevent an exploit where a member can burn their card to
591:         // reduce the total voting power of the party, then propose and vote in
592:         // the same block since `getVotingPowerAt()` uses `values.proposedTime - 1`.
593:         // This would allow them to use the voting power snapshot just before
594:         // their card was burned to vote, potentially passing a proposal that
595:         // would have otherwise not passed.
596:         if (lastBurnTimestamp == block.timestamp) {
597:             revert CannotRageQuitAndAcceptError();
598:         }
```
This change can be abused by a bad actor in order to DoS the voting of a proposal. The call to `accept()` can be front-runned with a call to `burn()`, which would trigger the revert in the origin

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-party)

---

### Example 18: [M-07] `totalVotingPower` needs to be snapshotted for each proposal because it can change and thereby affect consensus when accepting / vetoing proposals

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-04-party/blob/440aafacb0f15d037594cebc85fd471729bcb6d9/contracts/party/PartyGovernance.sol#L598-L605>

<https://github.com/code-423n4/2023-04-party/blob/440aafacb0f15d037594cebc85fd471729bcb6d9/contracts/proposals/VetoProposal.sol#L46-L51>

This issue does not manifest itself in a limited segment of the code.

Instead it spans multiple contracts and derives its impact from the interaction of these contracts.

In the PoC section I will do my best in explaining how this results in an issue.

I discussed this with the sponsor and they explained to me that this issue is due to a PR that has unintentionally not been merged.

![Discord message](https://user-images.githubusercontent.com/118979828/231990051-b9f731f1-1678-43e3-81e4-7ec0164bdc10.png)

So they have already written the code that is necessary to fix this issue. It's just not been merged with this branch. So since the sponsor knows about this already and it's just the PR that has gone missing it's not necessary for me to provide the full Solidity code to fix this issue.

In short, this issue is due to the fact that the `totalVotingPower` is not snapshotted when a proposal is created.

The votes that are used to vote for a proposal (or veto it) are based on a specific snapshot (1 block prior to the proposal being created).

When the `totalVotingPower` changes this leads to unintended consequences.

When `totalVotingPower` decreases, votes become more valuable than they should be.

And whe

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-party)

---

### Example 19: M-1: User Can Vote Even When They Have 0 Locked Mento (Edge Case)

**Source**: Sherlock
**Protocol**: Mento
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-mento-judging/issues/14 

## Found by 
ComposableSecurity, HHK, Kose, ParthMandale, sakshamguruji, slylandro, y4y
## Summary

There exists an edge case where the user will be withdrawing his entire locked MENTO amount and even then will be able to vote , this is depicted by a PoC to make things clearer.

## Vulnerability Detail

The flow to receiving voting power can be understood in simple terms as follows ->

Users locks his MENTO and chooses a delegate-> received veMENTO which gives them(delegatee) voting power (there's cliff and slope at play too)

The veMENTO is not a standard ERC20 , it is depicted through "lines" , voting power declines ( ie. slope period) with time
and with time you can withdraw more of your MENTO.

The edge case where the user will be withdrawing his entire locked MENTO amount and even then will be able
to vote is as follows ->

1.) User has locked his MENTO balance in the Locking.sol

2.) The owner of the contract "stops" the contract for some emergency reason.

3.) In this stopped state the user calls withdraw() which calls getAvailableForWithdraw() here https://github.com/sherlock-audit/2024-02-mento/blob/main/mento-core/contracts/governance/locking/Locking.sol#L97

4.) Since the contract is stopped , the `getAvailableForWithdraw` will return the entire locked amount of the user as withdrawable 

```solidity
function getAvailableForWithdraw(address account) public view returns (uint96) {
    uint96

*[Content truncated...]*

---

### Example 20: M-7: castVote can be called by anyone even those without votes

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/25 

## Found by 
hansfriese, 0x52, Trumpero

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

### Example 21: M-8: Adversary can abuse delegating to lower quorum

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/24 

## Found by 
0x52

## Summary

When a user delegates to another user they surrender their community voting power. The quorum threshold for a vote is determined when it is created. Users can artificially lower quorum by delegating to other users then creating a proposal. After it's created they can self delegate and regain all their community voting power to reach quorum easier. 

## Vulnerability Detail

    // If a user is delegating back to themselves, they regain their community voting power, so adjust totals up
    if (_delegator == _delegatee) {
      _updateTotalCommunityVotingPower(_delegator, true);

    // If a user delegates away their votes, they forfeit their community voting power, so adjust totals down
    } else if (currentDelegate == _delegator) {
      _updateTotalCommunityVotingPower(_delegator, false);
    }

When a user delegates to user other than themselves, they forfeit their community votes and lowers the total number of votes. When they self delegate again they will recover all their community voting power.

        newProposal.id = newProposalId.toUint96();
        newProposal.proposer = msg.sender;
        newProposal.targets = _targets;
        newProposal.values = _values;
        newProposal.signatures = _signatures;
        newProposal.calldatas = _calldatas;

        //@audit quorum votes locked at creation

        newProposal.quorumVotes = quorumVotes().toUint24(

*[Content truncated...]*

---

### Example 22: M-5: castVote can be called by anyone even those without votes

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

- Total findings analyzed: 22
- Examples shown: 22
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
