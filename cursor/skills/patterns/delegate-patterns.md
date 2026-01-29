# Delegate Security Patterns

## Overview

**Frequency**: 8 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 6 | 0 | 0 |

**Common Sources**: Code4rena, Cyfrin, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Check for delegate vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Attacker can combine flashloan with delegated voting to decide a proposal and withdraw their tokens while the proposal is still in Locked state

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

### Example 2: Attacker can at anytime dramatically lower `ERC721Power::totalPower` close to 0

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

### Example 3: [M-06] OperateProxy.callFunction() should check if the callee is a contract

**Source**: Code4rena
**Protocol**: Rolla
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-03-rolla/blob/efe4a3c1af8d77c5dfb5ba110c3507e67a061bdd/quant-protocol/contracts/utils/OperateProxy.sol#L10-L19


## Vulnerability details

https://github.com/code-423n4/2022-03-rolla/blob/efe4a3c1af8d77c5dfb5ba110c3507e67a061bdd/quant-protocol/contracts/Controller.sol#L550-L558

```solidity
    /// @notice Allows a sender/signer to make external calls to any other contract.
    /// @dev A separate OperateProxy contract is used to make the external calls so
    /// that the Controller, which holds funds and has special privileges in the Quant
    /// Protocol, is never the `msg.sender` in any of those external calls.
    /// @param _callee The address of the contract to be called.
    /// @param _data The calldata to be sent to the contract.
    function _call(address _callee, bytes memory _data) internal {
        IOperateProxy(operateProxy).callFunction(_callee, _data);
    }
```

https://github.com/code-423n4/2022-03-rolla/blob/efe4a3c1af8d77c5dfb5ba110c3507e67a061bdd/quant-protocol/contracts/utils/OperateProxy.sol#L10-L19

```solidity
    function callFunction(address callee, bytes memory data) external override {
        require(
            callee != address(0),
            "OperateProxy: cannot make function calls to the zero address"
        );

        (bool success, bytes memory returnData) = address(callee).call(data);
        require(success, "OperateProxy: low-level call failed");
        emit FunctionCallExecut

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-rolla)

---

### Example 4: Presence of delegate not enforced

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Security Issue Report

**Severity:** Medium Risk  
**Context:** 
- BridgeFacet.sol#L395-L414 
- BridgeFacet.sol#L563-L567 
- BridgeFacet.sol#L337-L369  

**Description:**  
A delegate address on the destination chain can be used to fix stuck transactions by changing the slippage limits and by re-executing transactions. However, the presence of a delegate address isn't checked in `_xcall()`.

**Note:** Set to medium risk because tokens could get lost.

### Relevant Functions:

```solidity
function forceUpdateSlippage(TransferInfo calldata _params, uint256 _slippage) external onlyDelegate(_params) {
    ...
}
```

```solidity
function execute(ExecuteArgs calldata _args) external nonReentrant whenNotPaused returns (bytes32) {
    (bytes32 transferId, DestinationTransferStatus status) = _executeSanityChecks(_args);
    ...
}
```

```solidity
function _executeSanityChecks(ExecuteArgs calldata _args) private view returns (bytes32, DestinationTransferStatus) {
    // If the sender is not an approved relayer, revert
    if (!s.approvedRelayers[msg.sender] && msg.sender != _args.params.delegate) {
        revert BridgeFacet__execute_unapprovedSender();
    }
}
```

**Recommendation:**  
Enforce the presence of a delegate address in `_xcall()`. Or at least document the behavior explicitly.

### Connext:
Yes, it's always going to be necessary to have a delegate if you want to have a strategy for handling destination-side slippage conditions being unfavorable. If you don't have one, y

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 5: [M-01] Delegate call in `Vault#_execute` can alter Vault's ownership

**Source**: Code4rena
**Protocol**: Fractional
**Impact**: MEDIUM

**Details**:

_Submitted by byterocket, also found by 242, &#95;141345&#95;, 0x1f8b, ACai, ayeslick, berndartmueller, BradMoon, cccz, Chom, giovannidisiena, infosec&#95;us&#95;team, Lambda, minhtrng, nine9, oyc&#95;109, PwnedNoMore, reassor, scaraven, slywaters, sseefried, tofunmi, Twpony, and unforgiven_

<https://github.com/code-423n4/2022-07-fractional/blob/main/src/Vault.sol#L62>

<https://github.com/code-423n4/2022-07-fractional/blob/main/src/Vault.sol#L126>

<https://github.com/code-423n4/2022-07-fractional/blob/main/src/Vault.sol#L25>

### Impact

The `Vault#execute` function calls a target contract's function via `delegatecall` if the caller is either the owner of the Vault or the target contract is part of a merkle tree, indicating a permission to call the target contract.

```solidity
// Check that the caller is either a module with permission to call or the owner.
if (!MerkleProof.verify(_proof, merkleRoot, leaf)) {
    if (msg.sender != owner)
        revert NotAuthorized(msg.sender, _target, selector);
}
```

*(See [Vault#execute](https://github.com/code-423n4/2022-07-fractional/blob/main/src/Vault.sol#L62))*

If the checks succeed, the internal `_execute()` function is used to execute the call via `delegatecall`.

`delegatecall`s have to be used with caution because the contract being called is using the caller's contract storage, i.e. the callee contract can alter the caller's contract state (for more info, see [Solidity docs](https://docs.soliditylang.org/en/latest/introduc

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-fractional)

---

### Example 6: [M-21] AdapterBase should always use delegatecall to call the functions in the strategy

**Source**: Code4rena
**Protocol**: Popcorn
**Impact**: MEDIUM

**Details**:

The strategy contract will generally let the Adapter contract use delegatecall to call its functions.

So IAdapter(address(this)).call is used frequently in strategy contracts, because when the Adapter calls the strategy's functions using delegatecall, address(this) is the Adapter:

```solidity
  function harvest() public override {
    address router = abi.decode(IAdapter(address(this)).strategyConfig(), (address));
    address asset = IAdapter(address(this)).asset();
    ...
```

But in AdapterBase.\_verifyAndSetupStrategy, the verifyAdapterSelectorCompatibility/verifyAdapterCompatibility/setUp functions are not called with delegatecall, which causes the context of these functions to be the strategy contract:

```solidity
    function _verifyAndSetupStrategy(bytes4[8] memory requiredSigs) internal {
        strategy.verifyAdapterSelectorCompatibility(requiredSigs);
        strategy.verifyAdapterCompatibility(strategyConfig);
        strategy.setUp(strategyConfig);
    }
```

And since the strategy contract does not implement the interface of the Adapter contract, these functions will fail, making it impossible to create a Vault using that strategy.

```solidity
  function verifyAdapterCompatibility(bytes memory data) public override {
    address router = abi.decode(data, (address));
    address asset = IAdapter(address(this)).asset();
```

More dangerously, if functions such as setup are executed successfully because they do not call the Adapter's functions, they may later

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-popcorn)

---

### Example 7: M-6: Delegate can keep can keep delegatee trapped indefinitely

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

### Example 8: M-8: Adversary can abuse delegating to lower quorum

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

## Statistics

- Total findings analyzed: 8
- Examples shown: 8
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
