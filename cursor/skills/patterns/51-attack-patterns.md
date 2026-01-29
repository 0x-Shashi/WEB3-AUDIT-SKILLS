# 51% Attack Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 1 | 1 | 0 |

**Common Sources**: Code4rena, MixBytes

---

## Detection Checklist

- [ ] Check for 51% attack vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] The 51% majority can hijack the party's precious tokens through an arbitrary call proposal if the `AddPartyCardsAuthority` contract is added as an authority in the party.

**Source**: Code4rena
**Protocol**: Party Protocol
**Impact**: HIGH

**Details**:

### Pre-requisite knowledge & an overview of the features in question

1. **The [**`AddPartyCardsAuthority`**](https://github.com/code-423n4/2023-10-party/blob/main/contracts/authorities/AddPartyCardsAuthority.sol) contract:** The `AddPartyCardsAuthority` contract is a contract designed to be integrated into a Party and it has only one purpose - to mint new party governance NFT tokens for party members.
    - The party has to add this contract as an authority before it can start minting new party governance NFT tokens for users.
    - The `AddPartyCardsAuthority` contract is deployed on the mainnet on address `0xC534bb3640A66fAF5EAE8699FeCE511e1c331cAD`

2. **The 51% Majority attack:** The PartyDAO team has put a lot of safeguards on a type of proposal called `ArbitraryCallsProposal` to prevent the 51% majority of the party to steal the precious NFT tokens of the party through this type of proposal. For a precious NFT token to be transferred out of the party to any other entity through this proposal, the proposal needs to be unanimously voted (100% of party members have voted on that proposal).

### Overview of the vulnerability

There is no check on the [`ArbitraryCallsProposal`](https://github.com/code-423n4/2023-10-party/blob/main/contracts/proposals/ArbitraryCallsProposal.sol) contract that prevents the calling of the [`AddPartyCardsAuthority`](https://github.com/code-423n4/2023-10-party/blob/main/contracts/authorities/AddPartyCardsAuthority.sol) contract. This allows the

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-10-party)

---

### Example 2: [H-06]  A majority attack can steal precious NFT from the party by crafting and chaining two proposals

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: HIGH

**Details**:

_Submitted by Trust, also found by ladboy233 and Lambda_

<https://github.com/PartyDAO/party-contracts-c4/blob/3896577b8f0fa16cba129dc2867aba786b730c1b/contracts/proposals/ProposalExecutionEngine.sol#L116>

<https://github.com/PartyDAO/party-contracts-c4/blob/3896577b8f0fa16cba129dc2867aba786b730c1b/contracts/proposals/FractionalizeProposal.sol#L54-L62>

### Description

The PartyGovernance system has many defenses in place to protect against a majority holder stealing the NFT. Majority cannot exfiltrate the ETH gained from selling precious NFT via any proposal, and it's impossible to sell NFT for any asset except ETH. If the party were to be compensated via an ERC20 token, majority could pass an ArbitraryCallsProposal to transfer these tokens to an attacker wallet. Unfortunately, FractionalizeProposal is vulnerable to this attack. Attackers could pass two proposals and wait for them to be ready for execution. Firstly, a FractionalizeProposal to fractionalize the NFT and mint totalVotingPower amount of ERC20 tokens of the created vault. Secondly, an ArbitraryCallsProposal to transfer the entire ERC20 token supply to an attacker address. At this point, attacker can call `vault.redeem()` to burn the outstanding token supply and receive the NFT back.

### Impact

A 51% majority could steal the precious NFT from the party and leave it empty.

### Proof of Concept

The only non-trivial component of this attack is that the created vault, whose tokens we wish to transfer out, has an

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 3: [M-11] Loss of Veto Power can Lead to 51% Attack

**Source**: Code4rena
**Protocol**: Nouns Builder
**Impact**: MEDIUM

**Details**:

_Submitted by TomJ, also found by 0xSky, ayeslick, Chom, pedr02b2, PwnPatrol, yixxas, and zkhorse_

[Governor.sol#L76](https://github.com/code-423n4/2022-09-nouns-builder/blob/7e9fddbbacdd7d7812e912a369cfd862ee67dc03/src/governance/governor/Governor.sol#L76)<br>
[Governor.sol#L596-L602](https://github.com/code-423n4/2022-09-nouns-builder/blob/7e9fddbbacdd7d7812e912a369cfd862ee67dc03/src/governance/governor/Governor.sol#L596-L602)<br>

The veto power is important functionality for current Nouns DAO logic in order to protect their treasury from malicious proposals.
However there is lack of zero address check and lack of 2 step address changing process for vetoer address.<br>
This might lead to DAO owner losing their veto power unintentionally and open to 51% attack which can drain their entire treasury.

<https://dialectic.ch/editorial/nouns-governance-attack><br>
<https://dialectic.ch/editorial/nouns-governance-attack-2>

### Proof of Concept

Lack of 0-address check for vetoer address at initialize() of Governor.sol<br>
Also I recommend to make changing address process of vetoer at updateVetoer() into 2-step process to avoid accidently setting
vetoer to arbitrary address and end up lossing veto power unintentionally.

    Governor.sol:
    57:    function initialize(
             ...
    76:        settings.vetoer = _vetoer;

<!---->

    596:    function updateVetoer(address _newVetoer) external onlyOwner {
    597:        if (_newVetoer == address(0)) revert ADDRESS_ZERO();

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-nouns-builder)

---

### Example 4: Remove unnecessary ETH handling logic for maker asset

**Source**: MixBytes
**Protocol**: Barter DAO
**Impact**: LOW

**Details**:

##### Description
In the [`callExecutor()`](https://github.com/BarterLab/argon/blob/f653d58132124854db42d2bd93d0c6b91da2c398/contracts/InchFusionBarterResolver.sol#L93-L123) function, there's logic that checks if the maker asset is ETH and skips token transfer:

```solidity
if (makerAsset.get() != address(0) && 
    makerAsset.get() != address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE)
   ) {
    IERC20(makerAsset.get()).safeTransfer(address(executor), makingAmount);
}
```

This logic appears to be leftover code from UniswapX solver implementation and is not needed in the context of 1inch Fusion orders.
<br/>
##### Recommendation
We recommend removing unnecessary logic.

---

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/Barter%20DAO/InchFusionBarterResolver/README.md#3-remove-unnecessary-eth-handling-logic-for-maker-asset)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
