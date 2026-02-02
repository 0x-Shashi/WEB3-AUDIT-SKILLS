---
id: PAT-CHAIN-REORGANIZATION-ATTACK
title: Chain Reorganization Attack Security Patterns
category: consensus
severity: medium
difficulty: advanced
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - reorg
  - reorganization
  - finality

finding_count: 18
last_updated: 2026-01-31
---
# Chain Reorganization Attack Security Patterns

## Overview

**Frequency**: 18 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 13 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, ConsenSys, Spearbit, Cyfrin

---

## Detection Checklist

- [ ] Check for chain reorganization attack vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Block Reorg Can Allow For Double Spending

**Source**: AuditOne
**Protocol**: Aurorafastbridge
**Impact**: HIGH

**Details**:

**Description**: 

Block reorg, also known as blockchain reorganization, is a situation where a competing chain replaces the main blockchain. This can happen when multiple miners find valid blocks at the same time, and the network has to decide which block to include in the blockchain. In some cases, the network may choose to include a block that is not in the main blockchain, resulting in a reorganization of the chain.

**Recommendations:**

To mitigate the risk of block reorgs, the Fast Bridge project may need to implement additional measures, such as waiting for multiple confirmations before proceeding with token transfers or implementing a fallback mechanism in case of a block reorg.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/AuditOne/2023-05-09-Aurorafastbridge.md)

---

### Example 2: [M-09] Create methods are suspicious of the reorg attack

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

The createVaultBooster() function deploys a new VaultBooster contract using the `create`, where the address derivation depends only on the VaultBoosterFactory nonce.

Re-orgs can happen in all EVM chains and as confirmed the contracts will be deployed on most EVM compatible L2s including Arbitrum, etc. It is also planned to be deployed on ZKSync in future. In ethereum, where this is deployed, Re-orgs has already been happened. For more info, [check here](https://decrypt.co/101390/ethereum-beacon-chain-blockchain-reorg).

This issue will increase as some of the chains like Arbitrum and Polygon are suspicious of the reorg attacks.

Polygon re-org reference: [click here](https://protos.com/polygon-hit-by-157-block-reorg-despite-hard-fork-to-reduce-reorgs/). This one happened this year in February, 2023.

Polygon blocks forked: [check here](https://polygonscan.com/blocks_forked)

The issue would happen when users rely on the address derivation in advance or try to deploy the position clone with the same address on different EVM chains, any funds sent to the `new` contract could potentially be withdrawn by anyone else. All in all, it could lead to the theft of user funds.

```Solidity
File: src/VaultBoosterFactory.sol

    function createVaultBooster(PrizePool _prizePool, address _vault, address _owner) external returns (VaultBooster) {
>>        VaultBooster booster = new VaultBooster(_prizePool, _vault, _owner);

        emit CreatedVaultBooster(booster, _prizePool, _vault, _own

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-pooltogether)

---

### Example 3: [M-01] Identifying publications using its ID makes the protocol vulnerable to blockchain re-orgs

**Source**: Code4rena
**Protocol**: Lens Protocol
**Impact**: MEDIUM

**Details**:

In the protocol, publications are uniquely identified through the publisher's profile ID and the publication's ID. For example, when a user calls `act()`, the publication being acted on is determined by `publicationActedProfileId` and `publicationActedId`:

[ActionLib.sol#L23-L26](https://github.com/code-423n4/2023-07-lens/blob/main/contracts/libraries/ActionLib.sol#L23-L26)

```solidity
        Types.Publication storage _actedOnPublication = StorageLib.getPublication(
            publicationActionParams.publicationActedProfileId,
            publicationActionParams.publicationActedId
        );
```

However, as publication IDs are not based on the publication's data, this could cause users to act on the wrong publication in the event a blockchain re-org occurs.

For example:

*   Assume the following transactions occur in separate blocks:
    *   Block 1: Alice calls `post()` to create a post; its publication ID is 20.
    *   Block 2: Bob is interested in the post, he calls `act()` with `publicationActedId = 20` to act on the post.
    *   Block 3: Alice calls `comment()` separately, which creates another publication; its publication ID is 21.
*   A blockchain re-org occurs; block 1 is dropped in place of block 3:
    *   Alice's comment now has the publication ID 20 instead of 21.
*   Bob's call to `act()` in block 2 is applied on top of the re-orged blockchain:
    *   This causes him to act on the comment instead of the post he intended to, as it now has the publication 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-lens)

---

### Example 4: [M-04] Many `create` methods are suspicious of the reorg attack

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: MEDIUM

**Details**:

### Proof of Concept

There are many instances of this; but to understand things better, take the example of the `createTalosV3Strategy` method.

The `createTalosV3Strategy` function deploys a new `TalosStrategyStaked` contract using the `create` method, where the address derivation depends only on the arguments passed.

At the same time, some of the chains like Arbitrum and Polygon are suspicious of the reorg attack.

```solidity
File: TalosStrategyStaked.sol

  function createTalosV3Strategy(
        IUniswapV3Pool pool,
        ITalosOptimizer optimizer,
        BoostAggregator boostAggregator,
        address strategyManager,
        FlywheelCoreInstant flywheel,
        address owner
    ) public returns (TalosBaseStrategy) {
        return new TalosStrategyStaked( // @audit-issue Reorg Attack
                pool,
                optimizer,
                boostAggregator,
                strategyManager,
                flywheel,
                owner
            );
    }

```

[Link to Code](https://github.com/code-423n4/2023-05-maia/blob/main/src/talos/TalosStrategyStaked.sol#L28)

Even more, the reorg can be a couple of minutes long. So, it is quite enough to create the `TalosStrategyStaked` and transfer funds to that address using the `deposit` method; especially when someone uses a script and not doing it by hand.

Optimistic rollups (Optimism/Arbitrum) are also suspect to reorgs. If someone finds a fraud, the blocks will be reverted, even though the user receives

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 5: TRST-M-3 Attacker could abuse victim's vote to pass their own proposal

**Source**: Trust Security
**Protocol**: Mozaic Archimedes
**Impact**: MEDIUM

**Details**:

**Description:**
Proposals are created using `submitProposal()`:
```solidity
        function submitProposal(uint8 _actionType, bytes memory _payload)  public onlyCouncil {
             uint256 proposalId = proposalCount;
                 proposals[proposalId] = Proposal(msg.sender,_actionType, 
                    _payload, 0, false);
                proposalCount += 1;
         emit ProposalSubmitted(proposalId, msg.sender);
        }
```
After submission, council members approve them by calling `confirmTransaction()`:

```solidity
        function confirmTransaction(uint256 _proposalId) public onlyCouncil 
            notConfirmed(_proposalId) {
             confirmations[_proposalId][msg.sender] = true;
             proposals[_proposalId].confirmation += 1;
        emit Confirmation(_proposalId, msg.sender);
        }
```
Notably, the **_proposalId** passed to `confirmTransaction()` is simply the **proposalCount** at time 
of submission. This design allows the following scenario to occur:
1. User A submits proposal P1
2. User B is interested in the proposal and confirms it
3. Attacker submits proposal P2
4. A blockchain re-org occurs. Submission of P1 is dropped in place of P2.
5. User B's confirmation is applied on top of the re-orged blockchain. Attacker gets their 
vote.
We've seen very large re-orgs in top blockchains such as Polygon, so this threat remains a 
possibility to be aware of.

**Recommended Mitigation:**
Calculate **proposalId** as a hash of the proposal p

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-23-Mozaic Archimedes.md)

---

### Example 6: in3-server - should enforce safe settings for minBlockHeight Won't Fix

**Source**: ConsenSys
**Protocol**: Slock.it Incubed3
**Impact**: MEDIUM

**Details**:

#### Resolution



The default block is changed to 10 and `minBlockHeight` is added to the registry
(as part of the properties) in [8c72633e](https://git.slock.it/in3/ts/in3-server/commit/8c72633e53651bb4dc2b0d6627ce6c238dd3e2e8), but allow the user to define a `minBlockHeight` lower than this number. The client is responsible to review the settings depending on how secure they want their nodes to be.


Client response:



> 
> We have discussed this, but decided to keep it flexible. This means:
> 
> 
> 1. We have put the minBlockHeight into the registry (as part of the properties). Because these properties indicate the limit and capabilities of the node and give the client a chance to filter out nodes if they dont match the requirements. So each client is able to filter out node who are not willing to take the risk and sign for example latest-6. Of course these nodes will most likely only store a low deposit ( you can not have a signature of a young block and a high deposit), but if you need a high security the nodes with a deposit will propably wait at least 10 or more blocks. In order to protect the owner of a node of using insecure settings, we will use our wizard to check the deposit and minBlockHeights and warn or educate the user. The reason why this flexibility is important, is because there use cases where dapps will not accept the let user wait 10 blocks before confirming a transaction. If the dapp developer needs a signature of a younger block, he will need to liv

*[Content truncated...]*

**Reference**: [View Original Finding](https://consensys.net/diligence/audits/2019/09/slock.it-incubed3/)

---

### Example 7: Polygon chain reorgs will change mystery box tiers which can be gamed by validators

**Source**: Cyfrin
**Protocol**: Mode Earnm
**Impact**: HIGH

**Details**:

**Description:** [`REQUEST_CONFIRMATIONS = 3`](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L26) is too small for polygon, as [chain re-orgs frequently have block-depth greater than 3](https://polygonscan.com/blocks_forked?p=1).

**Impact:** Chain re-orgs re-order blocks and transactions changing randomness results. Someone who originally won a rare box could have that result changed into a common box and vice versa due to changing randomness result during the re-org.

This can also be [exploited by validators](https://docs.chain.link/vrf/v2/security/#choose-a-safe-block-confirmation-time-which-will-vary-between-blockchains) who can intentionally rewrite the chain's history to force a randomness request into a different block, changing the randomness result. This allows validators to get a fresh random value which may be to their advantage if they are minting mystery boxes by moving the txn around to get a better randomness result to mint a rarer box.

**Recommended Mitigation:** `REQUEST_CONFIRMATIONS = 30` appears very safe for polygon as it is very rare for chain re-orgs to have block-depth greater than this. If this happens occasionally it isn't a big deal, but if it happens all the time ("3" ensures this) that is not good and potentially exploitable by validators.

**Mode:**
Fixed in commit [85b2012](https://github.com/Earnft/smart-contracts/commit/85b20121604b5d162bb14c2c96731b8345ca1cb3).

**Cyfrin:** 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-20-cyfrin-mode-earnm.md)

---

### Example 8: [C-01] Polygon chain reorgs will often change game results

**Source**: Pashov Audit Group
**Protocol**: Nft Loots
**Impact**: HIGH

**Details**:

**Impact:**
High, as an already winning user will lose its reward

**Likelihood:**
High, as reorgs with > 3 depth happen often on Polygon

**Description**

The `REQUEST_CONFIRMATION` constant in `VRFv2Consumer` is set to 3. This value is used to tell the Chainlink VRF service how much blocks do you want to wait at a minimum before receiving randomness. The reason this value was added is because of chain reorganizations - when this event happens, blocks and transactions get reorganized and they change. This is a serious problem in this application as it is expected to be launched on Polygon (mentioned in `README.md`), but as we can see [here](https://polygonscan.com/blocks_forked) there are more than 5 block reorganizations a day with depth that is more than 3 blocks. In [this article](https://protos.com/polygon-hit-by-157-block-reorg-despite-hard-fork-to-reduce-reorgs/) we can even see a recent event where there was a 156 block depth chain reorg on Polygon. This means that it is possible that often the winner of a lootbox game to be changed since when your transaction for requesting randomness from VRF is moved to a different block then the randomness will change as well.

**Recommendations**

Use a larger `REQUEST_CONFIRMATIONS` value - I would suggest around 60 to be safe. For the past 7 days the deepest chain reorganization had a depth of < 30 blocks. While 60 might not fit your use case for the game, I think anything below 25-30 is potentially dangerous to the project's u

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-06-01-NFT Loots.md)

---

### Example 9: [H-02] Miners Can Re-Roll the VRF Output to Game the Protocol

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: HIGH

**Details**:

_Submitted by leastwood_.

#### Impact

Miners are able to rewrite a chain's history if they dislike the VRF output used by the protocol. Consider the following example:

*   A miner or well-funded user is participating in the PoolTogether protocol.
*   A VRF request is made and fulfilled in the same block.
*   The protocol participant does not benefit from the VRF output and therefore wants to increase their chances of winning by including the output in another block, producing an entirely new VRF output. This is done by re-orging the chain, i.e. following a new canonical chain where the VRF output has not been included in a block.
*   This attack can be continued as long as the attacker controls 51% of the network. The miner itself could control a much smaller proportion of the network and still be able to mine a few blocks in succession, although this is of low probability but entirely possible.
*   A well-funded user could also pay miners to re-org the chain on their behalf in the form of MEV to achieve the same benefit.

The PoolTogether team is aware of this issue but is yet to mitigate this attack vector fully.

#### Proof of Concept

- <https://docs.chain.link/docs/vrf-security-considerations/#choose-a-safe-block-confirmation-time-which-will-vary-between-blockchains>
- <https://github.com/pooltogether/pooltogether-rng-contracts/blob/master/contracts/RNGChainlink.sol>
- <https://github.com/pooltogether/v4-core/blob/master/contracts/DrawBeacon.sol#L311-L324>
- <https://

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-10-pooltogether)

---

### Example 10: Malicious clients can use forks or reorgs to convict honest nodes Won't Fix

**Source**: ConsenSys
**Protocol**: Slock.it Incubed3
**Impact**: HIGH

**Details**:

#### Resolution



Default value for past signed blocks is changed to 10 blocks. Slockit plans to use their off-chain channels to notify clients for planned forks. They also looking into using fork oracles in the future releases to detect planned hardforks to mitigate risks.


#### Description


In case of reorgs it is possible to have more than 6 blocks in a node that gets replaced by a new longer chain. Also for forks, such as upcoming [Istanbul fork](https://blog.infura.io/were-ready-for-the-istanbul-fork-e39afc2b1412), its common to have some nodes taking some time to update and they will be in the wrong chain for the time being. In both cases, in3-nodes are prone to sign blocks that are considered invalid in the main chain.
Malicious nodes can catch these instances and convict the honest users in the main chain to get 50% of their deposits.


#### Recommendation


No perfect solution comes to mind at this time. One possible mitigation method for forks could be to disable the network on the time of the fork but this is most certainly going to be a threat to the system itself.

**Reference**: [View Original Finding](https://consensys.net/diligence/audits/2019/09/slock.it-incubed3/)

---

### Example 11: [M-01] QuestFactory is suspicious of the reorg attack

**Source**: Code4rena
**Protocol**: RabbitHole
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/rabbitholegg/quest-protocol/blob/8c4c1f71221570b14a0479c216583342bd652d8d/contracts/QuestFactory.sol#L75
https://github.com/rabbitholegg/quest-protocol/blob/8c4c1f71221570b14a0479c216583342bd652d8d/contracts/QuestFactory.sol#L108


## Vulnerability details

## Description

The `createQuest` function deploys a quest contract using the `create`, where the address derivation depends only on the `QuestFactory` nonce. 

At the same time, some of the chains (Polygon, Optimism, Arbitrum) to which the `QuestFactory` will be deployed are suspicious of the reorg attack.

- https://polygonscan.com/blocks_forked

![](https://i.imgur.com/N8tDUVX.png)

Here you may be convinced that the Polygon has in practice subject to reorgs. Even more, the reorg on the picture is 1.5 minutes long. So, it is quite enough to create the quest and transfer funds to that address, especially when someone uses a script, and not doing it by hand.

Optimistic rollups (Optimism/Arbitrum) are also suspect to reorgs since if someone finds a fraud the blocks will be reverted, even though the user receives a confirmation and already created a quest.

## Attack scenario

Imagine that Alice deploys a quest, and then sends funds to it. Bob sees that the network block reorg happens and calls `createQuest`. Thus, it creates `quest` with an address to which Alice sends funds. Then Alices' transactions are executed and Alice transfers funds to Bob's controlled quest. 

## Impact

If use

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-rabbithole)

---

### Example 12: [M-14] Re-org attack in factory

**Source**: Code4rena
**Protocol**: Frankencoin
**Impact**: MEDIUM

**Details**:

The `createClone` function deploys a clone contract using the create, where the address derivation depends only on the `PositionFactory` nonce.

Re-orgs can happen in all EVM chains. In ethereum, where currently Frankencoin is deployed, it is not "super common" but it still happens, being the last one less than a year ago:

<https://decrypt.co/101390/ethereum-beacon-chain-blockchain-reorg>

The issue increases the changes of happening because frankencoin is thinking about deploying also in L2's/ rollups, proof:

<https://discord.com/channels/810916927919620096/1095308824354758696/1096693817450692658>

where re-orgs have been much more active:

<https://protos.com/polygon-hit-by-157-block-reorg-despite-hard-fork-to-reduce-reorgs/>

being the last one, less than a year ago.

The issue would happen when users rely on the address derivation in advance or try to deploy the position clone with the same address on different EVM chains, any funds sent to the new clone could potentially be withdrawn by anyone else. All in all, it could lead to the theft of user funds.

As you can see in a previous report, the issue should be marked and judged as a medium:

<https://code4rena.com/reports/2023-01-rabbithole/#m-01-questfactory-is-suspicious-of-the-reorg-attack>

### Proof of Concept

Imagine that Alice deploys a position clone, and then sends funds to it. Bob sees that the network block reorg happens and calls `clonePosition`. Thus, it creates a position clone with an address to which Al

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-frankencoin)

---

### Example 13: M-2: useLoan doesn't allow liqudator to specifiy maximum price

**Source**: Sherlock
**Protocol**: Kairos Loan
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-02-kairos-judging/issues/25 

## Found by 
0x52

## Summary

useLoan doesn't allow the liquidator to specify a max price they are will to pay for the collateral they are liquidating. On the surface this doesn't seem like an issue because the price is always decreasing due to the dutch auction. However this can be problematic if the chain the contracts are deployed suffers a reorg attack. This can place the transaction earlier than anticipated and therefore charge the user more than they meant to pay. On Ethereum this is unlikely but this is meant to be deployed on any compatible EVM chain many of which are frequently reorganized.

## Vulnerability Detail

See summary.

## Impact

Liquidator can be charged more than intended

## Code Snippet

https://github.com/sherlock-audit/2023-02-kairos/blob/main/kairos-contracts/src/AuctionFacet.sol#L59-L73

## Tool used

Manual Review

## Recommendation

Allow liquidator to specify a max acceptable price to pay



## Discussion

**npasquie**

fixed here https://github.com/kairos-loan/kairos-contracts/pull/50

---

### Example 14: Block depth used does not offer guarantees against reorgs under edge cases

**Source**: Spearbit
**Protocol**: Redacted Dinero Infrastructure
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

**Context:** cdk-dinero-keeper/src/functions/update-validator-stats/index.ts#L226

**Description:** 
The Ethereum chain finalizes roughly every 2 epochs (64 slots); at this point, the network offers extreme guarantees for the finalized blocks. The current value of `CONFIRMATION_BLOCKS=30` would be historically safe but offers no guarantees in edge/attack cases against reorgs and non-finality incidents.

**Recommendation:** 
There is a notion of finalized blocks that could be used instead. The data would be older but would represent the finalized state of the network. Note that in the case of a non-finality incident on the network, the value will be stuck in the past unless the network is healthy again. This may even be an advantage as you will not perform actions on data that might change or spend funds that should not have been.

**Redacted:** Fixed in PR 56.

**Spearbit:** 
The recommendation was followed and a fix was applied in PR 56 at commit `3772bdd8`.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Redacted-Dinero-Infrastructure-Security-Review.pdf)

---

### Example 15: [M-01] No check for sequencer uptime can lead to dutch auctions failing or executing at bad prices

**Source**: Code4rena
**Protocol**: Ethereum Credit Guild
**Impact**: MEDIUM

**Details**:

The `AuctionHouse` contract implements a Dutch auction mechanism to recover debt from collateral. However, there is no check for sequencer uptime, which could lead to auctions failing or executing at unfavorable prices.

The current deployment parameters allow auctions to succeed without a loss to the protocol for a duration of 10m 50s. If there's no bid on the auction after this period, the protocol has no other option but to take a loss or forgive the loan. This could have serious consequences in the event of a network outage, as any loss results in the slashing of all users with weight on the term.

Network outages and large reorgs happen with relative frequency. For instance, Arbitrum suffered an hour-long outage just two weeks ago ([source](https://github.com/ArbitrumFoundation/docs/blob/50ee88b406e6e5f3866b32d147d05a6adb0ab50e/postmortems/15\_Dec\_2023.md)).

### Proof of Concept

Consider the following scenario:

1. A loan is called and an auction is initiated.
2. The network experiences an outage, causing the sequencer to go offline.
3. The auction fails to receive any bids within the 10m 50s window due to the outage.
4. The protocol is forced to take a loss (if there's still a bid after the `midPoint` and before the auction ends) or forgive the loan, both leading to the complete slashing of all users with weight on the term.

### Recommended Mitigation Steps

To mitigate this issue, consider integrating an external uptime feed such as [Chainlink's L2 Sequencer Feeds]

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-12-ethereumcreditguild)

---

### Example 16: Risk of double-spend attacks due to use of single-node Clique consensus without nality API

**Source**: TrailOfBits
**Protocol**: Scroll, l2geth
**Impact**: MEDIUM

**Details**:

## Diculty: Medium

## Type: Denial of Service

## Description
l2geth uses the proof-of-authority Clique consensus protocol, defined by EIP-255. This consensus type is not designed for single-node networks, and an attacker-controlled sequencer node may produce multiple conflicting forks of the chain to facilitate double-spend attacks.

The severity of this finding is compounded by the fact that there is no API for an end user to determine whether their transaction has been finalized by L1, forcing L2 users to use ineffective block/time delays to determine finality.

Clique consensus was originally designed as a replacement for proof-of-work consensus for Ethereum testnets. It uses the same fork choice rule as Ethereums proof-of-work consensus; the fork with the highest difficulty should be considered the canonical fork.

Clique consensus does not use proof-of-work and cannot update block difficulty using the traditional calculation; instead, block difficulty may be one of two values:
- 1 if the block was mined by the designated signer for the block height
- 2 if the block was mined by a non-designated signer for the block height

This means that in a network with only one authorized signer, all of the blocks and forks produced by the sequencer will have the same difficulty value, making it impossible for syncing nodes to determine which fork is canonical at the given block height.

In a normal proof-of-work network, one of the proposed blocks will have a higher diffic

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/2023-08-scrollL2geth-initial-securityreview.pdf)

---

### Example 17: [M-08] An attacker can front-run `deployVault` to deploy at the same address

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

Vaults are created from the factory via `CREATE1`. An attacker can front-run `deployVault` to deploy at the same address, but with different config. If the deployed chain reorg, a different vault might also be deployed at the same address.

### Proof of Concept

<https://github.com/GenerationSoftware/pt-v5-vault/blob/b1deb5d494c25f885c34c83f014c8a855c5e2749/src/VaultFactory.sol#L67-L78>

1.  Bob setup a bot to monitor the `mempool` when PT deploys a new vault.
2.  Bob's bot saw a deployment by PT at `0x1234` and fires a tx to deposit immediately.
3.  Alice front-runs PT's deployment by deploying a malicious vault at `0x1234`.
4.  Bob's transaction ended up deposited into Alice's malicious vault.

### Recommended Mitigation Steps

Use `CREATE2` and the vault config as salt.

### Assessed type

MEV

**[asselstine (PoolTogether) disputed and commented](https://github.com/code-423n4/2023-07-pooltogether-findings/issues/416#issuecomment-1644728305):**
 > The Vault address is a derivative of the (sender address, nonce).  I don't see how this scenario is possible?

**[Picodes (judge) commented](https://github.com/code-423n4/2023-07-pooltogether-findings/issues/416#issuecomment-1666992892):**
 > @asselstine - exactly. Here, it only depends on the nonce of the factory; so in case of reorg, someone could "override" a vault deployment and all following transactions would still be executed.

**[PoolTogether mitigated](https://github.com/code-423n4/2023-08-pooltogether-mitigation#individu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-pooltogether)

---

### Example 18: M-4: Loss of bond amounts on re-org attacks

**Source**: Sherlock
**Protocol**: Optimism Fault Proofs
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-optimism-2024-judging/issues/201 

The protocol has acknowledged this issue.

## Found by 
MiloTruck, Trust
## Summary

The `move()` function lacks proper identification of the target of the move, leading to successful re-org attacks which can take the honest participant's funds.

## Vulnerability Detail

Participants in the game can call `attack()`, `defend()` or `move()`, each accepting a `parentIndex` which corresponds to the claim being challenged, and a `_claim` commitment. 

When participants claim, they have a particular claim in mind which they wish to challenge, and then pass on that claim's index. However, between the moment they sent the TX and the moment that TX is executed, a block reorg can take place. When it occurs, the challenge corresponding to that ID may change to another challenge, which may be valid or invalid in a different way. Regardless, the participant's commitment to that `move()` will be wrong, and they stand to lose their bond amount.

Chain reorgs are very prevalent in Ethereum mainnet, where the contract is deployed. You can check [this](https://etherscan.io/blocks_forked) index of reorged blocks on etherscan. It is **incorrect** to assume the attacker will wait until it achieved finality, because there's no warnings or documentation available for them to identify this as a threat. Therefore, it remains a very valid concern with reasonable hypotheticals.

Note that in high depths, the bond amoun

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 18
- Examples shown: 18
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

