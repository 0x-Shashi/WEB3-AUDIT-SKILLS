---
id: PAT-ACCESS-CONTROL
title: Access Control Security Patterns
category: access-control
severity: high
difficulty: advanced
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - authorization
  - permissions
  - roles

finding_count: 48
last_updated: 2026-01-31
---
# Access Control Security Patterns

## Overview

**Frequency**: 48 occurrences (0.09% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 27 | 19 | 2 | 0 |

**Common Sources**: Code4rena, Spearbit, Sherlock, Quantstamp, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for access control vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-09] Attacker can steal 99% of total balance from any reward token in any Staking contract

**Source**: Code4rena
**Protocol**: Popcorn
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/vault/VaultController.sol#L108-L110>

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/vault/VaultController.sol#L483-L503> 

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L296-L315>

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L351-L360> 

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L377-L378>

<https://github.com/code-423n4/2023-01-popcorn/blob/main/src/utils/MultiRewardStaking.sol#L390-L399>

### Impact

Attacker can steal 99% of the balance of a reward token of any Staking contract in the blockchain. An attacker can do this by modifying the reward speed of the target reward token.

So an attacker gets access to `changeRewardSpeed`, he will need to deploy a vault using the target Staking contract as its Staking contract. Since the Staking contract is now attached to the attacker's created vault, he can now successfully `changeRewardSpeed`. Now with `changeRewardSpeed`, attacker can set the `rewardSpeed` to any absurdly large amount that allows them to drain 99% of the balance (dust usually remains due to rounding issues) after some seconds (12 seconds in the PoC.)

### Proof of Concept

This attack is made possible by the following issues:

1.  Any user can deploy a Vault that uses any existing Staking contract - <https://github.com/code-423n4/2023-01-popcorn/blob/mai

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-popcorn)

---

### Example 2: Too generic calls in GenericBridgeFacet allow stealing of tokens

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
- `GenericBridgeFacet.sol#L69-L120`
- `LibSwap.sol#L30-L68`

## Description
With the contract `GenericBridgeFacet`, the functions `swapAndStartBridgeTokensGeneric()` (via `LibSwap.swap()`) and `_startBridge()` allow arbitrary function calls, which enable anyone to call `transferFrom()` and steal tokens from users who have provided a large allowance to the LiFi protocol. This vulnerability has been exploited in the past.

### Additional Risks
- Ability to call the LiFi Diamond itself via functions that dont have `nonReentrant`.
- Potential cancellation of transfers for other users.
- Calling functions protected by checks on `this`, such as `completeBridgeTokensViaStargate`.

```solidity
contract GenericBridgeFacet is ILiFi, ReentrancyGuard {
    function swapAndStartBridgeTokensGeneric(
        ...
        LibSwap.swap(_lifiData.transactionId, _swapData[i]);
        ...
    )
    
    function _startBridge(BridgeData memory _bridgeData) internal {
        ...
        (bool success, bytes memory res) = _bridgeData.callTo.call{ value: value }(_bridgeData.callData);
        ...
    }
}

library LibSwap {
    function swap(bytes32 transactionId, SwapData calldata _swapData) internal {
        ...
        (bool success, bytes memory res) = _swapData.callTo.call{ value: nativeValue }(_swapData.callData);
        ...
    }
}
```

## Recommendation
Whitelist the external call addresses and function signatures for both the dece

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 3: Anyone can take a loan out on behalf of any collateral holder at any terms

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Security Vulnerability Report

## Severity
**High Risk**

## Context
`VaultImplementation.sol#L225`

## Description
In the `_validateCommitment()` function, the initial checks are intended to ensure that the caller who is requesting the lien is someone who should have access to the collateral that it's being taken out against. The caller also inputs a receiver, who will be receiving the lien. 

In this validation, this receiver is checked against the collateral holder, and the validation is approved in the case that `receiver == holder`. However, this does not imply that the collateral holder wants to take this loan.

This opens the door to a malicious lender pushing unwanted loans on holders of collateral by calling `commitToLien` with their `collateralId`, as well as their address set to the receiver. This will pass the `receiver == holder` check and execute the loan.

In the best case, the borrower discovers this and quickly repays the loan, incurring a fee and a small amount of interest. In the worst case, the borrower doesn't know this happens, and their collateral is liquidated.

## Recommendation
Only allow calls from the holder or operator to lead to valid commitments:

```solidity
address holder = CT.ownerOf(collateralId);
address operator = CT.getApproved(collateralId);

if (
    msg.sender != holder &&
    receiver != holder &&
    receiver != operator &&
    !ROUTER().isValidVault(receiver)
) {
    msg.sender != operator &&
    CT.isApprovedForAll(holder, msg.s

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 4: VaultImplementation.buyoutLien can be DoSed by calls to LienToken.buyoutLien

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity: High Risk

### Context
- LienToken.sol#L102
- LienToken.sol#L121
- VaultImplementation.sol#L305

### Description
Anyone can call into `LienToken.buyoutLien` and provide params of the type `LienActionBuyout`:  
`params.incoming` is not used, so for example, vault signatures or strategy validation is skipped. There are a few checks for `params.encumber`.

Let's define the following variables:

| Parameter | Value |
|-----------|-------|
| i         | params.position |
| kj        | params.encumber.stack[j].point.position |
| tj        | params.encumber.stack[j].point.last |
| ej        | params.encumber.stack[j].point.end |
| e0       | itnow+D0 |
| i         | lj params.encumber.stack[j].point.lienId |
| l0       | ih(N0 i,V0 i,S0 i,c0 i, (A0max i,r0 i,D0 i,P0 i,L0 i)) where h is the keccak256 of the encoding |
| rj        | params.encumber.stack[j].lien.details.rate : old rate |
| r0       | params.encumber.lien.details.rate : new rate |
| c         | params.encumber.collateralId |

| Parameter | Value |
|-----------|-------|
| cj        | params.encumber.stack[j].lien.collateralId |
| c0       | params.encumber.lien.collateralId |
| Aj        | params.encumber.stack[j].point.amount |
| A0       | params.encumber.amount |
| Amax     | params.encumber.stack[j].lien.details.maxAmount |
| A0max    | params.encumber.lien.details.maxAmount |
| R         | params.encumber.receiver |
| Nj        | params.encumber.stack[j].lien.token |
| N0      

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 5: [H-02] Protocol fees can be withdrawn multiple times in Erc20Quest

**Source**: Code4rena
**Protocol**: RabbitHole
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/rabbitholegg/quest-protocol/blob/8c4c1f71221570b14a0479c216583342bd652d8d/contracts/Erc20Quest.sol#L102-L104


## Vulnerability details

The `withdrawFee` function present in the `Erc20Quest` contract can be used to withdraw protocol fees after a quest has ended, which are sent to the protocol fee recipient address:

https://github.com/rabbitholegg/quest-protocol/blob/8c4c1f71221570b14a0479c216583342bd652d8d/contracts/Erc20Quest.sol#L102-L104

```solidity
function withdrawFee() public onlyAdminWithdrawAfterEnd {
    IERC20(rewardToken).safeTransfer(protocolFeeRecipient, protocolFee());
}
```

This function doesn't provide any kind of protection and can be called multiple times, which will send more tokens than intended to the protocol fee recipient, stealing funds from the contract.

## Impact

The `withdrawFee` function can be called multiples after a quest has ended, potentially stealing funds from other people. The contract may have funds from unclaimed receipts (i.e. users that have completed the quest, redeemed their receipt but haven't claimed their rewards yet) and remaining tokens from participants who didn't complete the quest, which can be claimed back by the owner of the quest.

Note also that the `onlyAdminWithdrawAfterEnd` modifier, even though it indicates that an "admin" should be allowed to call this function, only validates the quest end time and fails to provide any kind of access control:

https://github.com/rabbitholegg

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-rabbithole)

---

### Example 6: [H-04] Lack of access control on tSQD's `registerTokenOnL2`

**Source**: Pashov Audit Group
**Protocol**: Subsquid
**Impact**: HIGH

**Details**:

## Severity

**Impact**: High, malicious attacker can set L2 custom address to different address to break the bridge token.

**Likelihood**: Medium, attacker can front-ran the `registerTokenOnL2` to break the bridge token.

## Description

tSQD is designed so that it can be bridged from Ethereum (L1) to Arbitrum (L2) via Arbitrums generic-custom gateway.
However, the `registerTokenOnL2` function, which sets the L2 token address via `gateway.registerTokenToL2`, is not currently restricted.

```solidity
  function registerTokenOnL2(
    address l2CustomTokenAddress,
    uint256 maxSubmissionCostForCustomGateway,
    uint256 maxSubmissionCostForRouter,
    uint256 maxGasForCustomGateway,
    uint256 maxGasForRouter,
    uint256 gasPriceBid,
    uint256 valueForGateway,
    uint256 valueForRouter,
    address creditBackAddress
  ) public payable {
    require(!shouldRegisterGateway, "ALREADY_REGISTERED");
    shouldRegisterGateway = true;

    gateway.registerTokenToL2{value: valueForGateway}(
      l2CustomTokenAddress, maxGasForCustomGateway, gasPriceBid, maxSubmissionCostForCustomGateway, creditBackAddress
    );

    router.setGateway{value: valueForRouter}(
      address(gateway), maxGasForRouter, gasPriceBid, maxSubmissionCostForRouter, creditBackAddress
    );

    shouldRegisterGateway = false;
  }
```

An attacker can front-run the `registerTokenOnL2` and put an incorrect address for `l2CustomTokenAddress` to break the bridge token. Once it is called, the L2 token canno

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Subsquid-security-review.md)

---

### Example 7: [H-17] Giant pools can be drained due to weak vault authenticity check

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-11-stakehouse/blob/5f853d055d7aa1bebe9e24fd0e863ef58c004339/contracts/liquid-staking/GiantSavETHVaultPool.sol#L50><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/5f853d055d7aa1bebe9e24fd0e863ef58c004339/contracts/liquid-staking/GiantMevAndFeesPool.sol#L44>

An attacker can withdraw all ETH staked by users in a Giant pool. Both `GiantSavETHVaultPool` and `GiantMevAndFeesPool` are affected.

### Proof of Concept

The `batchDepositETHForStaking` function in the Giant pools check whether a provided vault is authentic by validating its liquid staking manager contract and sends funds to the vault when the check passes ([GiantSavETHVaultPool.sol#L48-L58](https://github.com/code-423n4/2022-11-stakehouse/blob/5f853d055d7aa1bebe9e24fd0e863ef58c004339/contracts/liquid-staking/GiantSavETHVaultPool.sol#L48-L58)):

```solidity
SavETHVault savETHPool = SavETHVault(_savETHVaults[i]);
require(
    liquidStakingDerivativeFactory.isLiquidStakingManager(address(savETHPool.liquidStakingManager())),
    "Invalid liquid staking manager"
);

// Deposit ETH for staking of BLS key
savETHPool.batchDepositETHForStaking{ value: transactionAmount }(
    _blsPublicKeys[i],
    _stakeAmounts[i]
);
```

An attacker can pass an exploit contract as a vault. The exploit contract will implement `liquidStakingManager` that will return a valid staking manager contract address to trick a Giant pool into sending ETH to the exploit contract:

```solidity
// test/foundry

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 8: ROLE-BASED ACCESS CONTROL MISSING

**Source**: Halborn
**Protocol**: MonoX
**Impact**: HIGH

**Details**:

##### Description

In smart contracts, implementing a correct Access Control policy is an essential step to maintain security and decentralization for permissions on a token. All the features of the smart contract , such as mint/burn tokens and pause contracts are given by Access Control. For instance, Ownership is the most common form of Access Control. In other words, the owner of a contract (the account that deployed it by default) can do some administrative tasks on it. Nevertheless, other authorization levels are required to follow the principle of least privilege, also known as least authority. Briefly, any process, user or program only can access to the necessary resources or information. Otherwise, the ownership role is useful in a simple system, but more complex projects require the use of more roles by using Role-based access control.

Code Location
-------------

#### Monoswap.sol

```
function setFeeTo (address _feeTo) onlyOwner external {
    feeTo = _feeTo;
}

function setFees (uint16 _fees) onlyOwner external {
    require(_fees<1e3, "fees too large");
    fees = _fees;
}

function setDevFee (uint16 _devFee) onlyOwner external {
    require(_devFee<1e3, "devFee too large");
    devFee = _devFee;
}

// update status of a pool. onlyOwner.
function updatePoolStatus(address _token, PoolStatus _status) public onlyOwner {
    PoolInfo storage pool = pools[_token];
    pool.status = _status;
}

/**
 @dev update pools price if there were no active trading for the last 

*[Content truncated...]*

**Reference**: [View Original Finding](https://www.halborn.com/audits/monox/monox-smart-contract-security-assessment)

---

### Example 9: Incorrect set up and logic of `referralInfoMap` in `SystemConfig::updateReferrerInfo` function

**Source**: Codehawks
**Protocol**: Tadle
**Impact**: HIGH

**Details**:

## Summary
- The `referralInfo` contains 3 members: `referrer`, `referrerRate` and `authorityRate`.
- Here referrer is the person which has referred the other person.
- The referralInfoMap contains a mapping from an address to `ReferralInfo`, where it is expected to return the 3 members mentioned above for a person who is referred by the `referrer`, but the `referralInfoMap` sets the referrer address to all the 3 members which is incorrect.
- As well as anyone can call the function to update the mapping for any address and set arbitrary value for whole mapping members as well as the address for which the mapping is mapped to `referralInfo`

## Vulnerability Details
- The vulnerability is present in the `updateReferrerInfo` function where it allows the caller to set up any arbitrary values for the `referrer`, `referrerRate` and `authorityRate`, as well as the address for which mapping is mapped from is also set to as `referrer`.
- As a result of which anyone can maliciously set values for anyone, but where it is expected that the referrer should only be able to set value for the person to whom he is referring.
- When a user calls the `updateReferrerInfo` function, it sets the mapping as `referralInfoMap[referrer]`, and sets up all the values as passed.

- The referral bonus is allocated during the call to `createTaker` via `_updateReferralBonus` function, where it uses the values as:
```
referralInfoMap[msg.sender], where msg.sender is the one to whom referrer has referred to


*[Content truncated...]*

---

### Example 10: H-6: Cross-chain message authentication can be bypassed, allowing an attacker to disrupt the state of vaults

**Source**: Sherlock
**Protocol**: Derby
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-derby-judging/issues/309 

## Found by 
Jeiwan

## Summary
A malicious actor may send a cross-chain message to an `XProvider` contract and bypass the `onlySource` authentication check. As a result, they'll be able to call any function in the `XProvider` contract that has the `onlySource` modifier and disrupt the state of `XChainController` and all vaults.
## Vulnerability Detail
The protocol integrates with Connext to handle cross-chain interactions. [XProvider](https://github.com/sherlock-audit/2023-01-derby/blob/main/derby-yield-optimiser/contracts/XProvider.sol#L14) is a contract that manages interactions between vaults deployed on all supported networks and `XChainController`. `XProvider` is deployed on each of the network where a vault is deployed and is used to send and receive cross-chain messages via Connext. `XProvider` is a core contract that handles vault rebalancing, transferring of allocations from Game to `XChainController` and to vaults, transferring of tokens deposited to vaults between vault on different networks. Thus, it's critical that the functions of this contract are only called by authorized actors.

To ensure that cross-chain messages are sent from authorized actors, there's [onlySource](https://github.com/sherlock-audit/2023-01-derby/blob/main/derby-yield-optimiser/contracts/XProvider.sol#L85) modifier that's applied to the [xReceive](https://github.com/sherlock-audit/2023-01-derby/blob/main/derby-yie

*[Content truncated...]*

---

### Example 11: [C-04] Lack of access control in `ResetSystem::resetGame()`

**Source**: Pashov Audit Group
**Protocol**: Primodium_2024-10-02
**Impact**: HIGH

**Details**:

## Severity

**Impact:** High

**Likelihood:** High

## Description

The `resetGame` function in the `ResetSystem` contract does not implement any form of access control, allowing anyone to call it. This creates a severe vulnerability, as any unauthorized user can reset the entire game state, leading to potential loss of progress and disruption of gameplay.

Additionally, in the configuration file `mud.config.ts`, the `openAccess` flag for several subsystems, including `ResetClearLoopSubsystem`, is correctly set to `false`, but this access control has not been applied to the `ResetSystem` contract. The absence of a modifier enforcing access restrictions exacerbates the issue.

Here is the code where access control is missing:

```solidity
function resetGame() public {
    IWorld world = IWorld(_world());
    world.Empires__clearLoop();
    P_GameConfigData memory config = P_GameConfig.get();

    P_GameConfig.setGameOverBlock(block.number + config.nextGameLengthTurns * config.turnLengthBlocks);
    P_GameConfig.setGameStartTimestamp(block.timestamp);
    createPlanets(); // Planet and Empire tables are reset to default values
    LibShieldEater.initialize(); // ShieldEater relocated, charge reset, and destination set
    initPrice(); // Empire.setPointPrice and OverrideCost tables are reset to default values
    Turn.set(block.number + config.turnLengthBlocks, EEmpire.Red, 1);
}
```

This lack of control could lead to a malicious actor resetting the game at any time, which co

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Primodium-security-review_2024-10-02.md)

---

### Example 12: [H-07] Anyone can get the NFT collateral token after an Auction without bidding due to missing check on `msg.sender`

**Source**: Code4rena
**Protocol**: BendDAO
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/libraries/logic/IsolateLogic.sol#L477>

In IsolateLogic.sol, liquidation of an isolate loan can only be placed after the auction period is passed with bidding. The problem is that there is a missing check on `msg.sender` in isolate liquidation flow, which allows anyone to take the collateral NFT token.

```solidity
//src/libraries/logic/IsolateLogic.sol
  function executeIsolateLiquidate(InputTypes.ExecuteIsolateLiquidateParams memory params) internal {
  ...
    if (params.supplyAsCollateral) {
        //@audit due to no check on msg.sender, anyone calls isolateLiquidate will get the collateral nft
 |>     VaultLogic.erc721TransferIsolateSupplyOnLiquidate(nftAssetData, params.msgSender, params.nftTokenIds);
    } else {
      VaultLogic.erc721DecreaseIsolateSupplyOnLiquidate(nftAssetData, params.nftTokenIds);

 |>     VaultLogic.erc721TransferOutLiquidity(nftAssetData, params.msgSender, params.nftTokenIds);
    }
  ...
```

https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/libraries/logic/IsolateLogic.sol#L473

Flows: `IsolateLiquidation::isolateLiquidate -> IsolateLogic.executeIsolateLiquidate()`. Note that `msg.sender` is passed from `isolateLiquidate()` to the end of `executeIsolateLiquidate()` without any checks.

### Proof of Concept

See added unit test `test_Anyone_Can_LiquidateWETH()`. Only `tsLiquidator1` auctioned, but `tsBo

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-07-benddao)

---

### Example 13: [H-01] Anyone can update the address of the Router in the DcntEth contract to any address they would like to set.

**Source**: Code4rena
**Protocol**: Decent
**Impact**: HIGH

**Details**:

By allowing anybody to set the address of the Router contract to any address they want to set it allows malicious users to get access to the mint and burn functions of the DcntEth contract.

### Proof of Concept

The [`DcntEth::setRouter() function`](https://github.com/decentxyz/decent-bridge/blob/7f90fd4489551b69c20d11eeecb17a3f564afb18/src/DcntEth.sol#L20-L22) has not an access control to restrict who can call this function. This allows anybody to set the address of the router contract to any address they'd like to set it.

> DcntEth.sol

```solidity
//@audit-issue => No access control to restrict who can set the address of the router contract
function setRouter(address _router) public {
    router = _router;
}
```

The functions [`DcntEth::mint() function`](https://github.com/decentxyz/decent-bridge/blob/7f90fd4489551b69c20d11eeecb17a3f564afb18/src/DcntEth.sol#L24-L26) & [`DcntEth::burn() function`](https://github.com/decentxyz/decent-bridge/blob/7f90fd4489551b69c20d11eeecb17a3f564afb18/src/DcntEth.sol#L28-L30) can be called only by the router contract.

> DcntEth.sol

```solidity

    //@audit-info => Only the router can call the mint()
    function mint(address _to, uint256 _amount) public onlyRouter {
        _mint(_to, _amount);
    }

    //@audit-info => Only the router can call the burn()
    function burn(address _from, uint256 _amount) public onlyRouter {
        _burn(_from, _amount);
    }
```

A malicious user can set the address of the router contract to an ac

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-decent)

---

### Example 14: [H-01] All tokens can be stolen from `VirtualAccount` due to missing access modifier

**Source**: Code4rena
**Protocol**: Maia DAO
**Impact**: HIGH

**Details**:

All non-native assets (ERC20 tokens, NFTs, etc.) can be stolen by anyone from a `VirtualAccount` using its [`payableCall(...)`](https://github.com/code-423n4/2023-09-maia/blob/f5ba4de628836b2a29f9b5fff59499690008c463/src/VirtualAccount.sol#L84-L112) method, which lacks the necessary access control modifier [`requiresApprovedCaller`](https://github.com/code-423n4/2023-09-maia/blob/f5ba4de628836b2a29f9b5fff59499690008c463/src/VirtualAccount.sol#L159-L167). See also, the [call(...)](https://github.com/code-423n4/2023-09-maia/blob/f5ba4de628836b2a29f9b5fff59499690008c463/src/VirtualAccount.sol#L65-L82) method which utilizes the [`requiresApprovedCaller`](https://github.com/code-423n4/2023-09-maia/blob/f5ba4de628836b2a29f9b5fff59499690008c463/src/VirtualAccount.sol#L159-L167) modifier.

Therefore, an attacker can craft a call to e.g. `ERC20.transfer(...)` on behalf of the contract, like the [withdrawERC20(...)](https://github.com/code-423n4/2023-09-maia/blob/f5ba4de628836b2a29f9b5fff59499690008c463/src/VirtualAccount.sol#L55-L58) method does, while bypassing access control by executing the call via [`payableCall(...)`](https://github.com/code-423n4/2023-09-maia/blob/f5ba4de628836b2a29f9b5fff59499690008c463/src/VirtualAccount.sol#L84-L112).

As a consequence, all non-native assets of the `VirtualAccount` can be stolen by anyone causing a loss for its owner.

### Proof of Concept

Add the code below as a new test file `test/ulysses-omnichain/VirtualAccount.t.sol` and run it using `f

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-09-maia)

---

### Example 15: [H-03] Incorrectly implemented modifiers in `LybraConfigurator.sol` allow any address to call functions that are supposed to be restricted

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: HIGH

**Details**:

The modifiers `onlyRole` (bytes32 role) and `checkRole` (bytes32 role) are not implemented correctly. This would allow anybody to call sensitive functions that should be restricted.

### Proof of Concept

For the POC, I set up a new foundry projects and copied the folders lybra, mocks and OFT in the src folder of the new project. I installed the dependencies and then I created a file `POCs.t.sol` in the test folder. Here is the code that shows a random address can call sensitive functions that should be restricted:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/lybra/configuration/LybraConfigurator.sol";
import "../src/lybra/governance/GovernanceTimelock.sol";
import "../src/lybra/miner/esLBRBoost.sol";

contract POCsTest is Test {
    Configurator public lybraConfigurator;
    GovernanceTimelock public governance;
    esLBRBoost public boost;

    address public dao = makeAddr("dao");
    address public curvePool = makeAddr("curvePool");
    address public randomUser = makeAddr("randomUser");
    address public admin = makeAddr("admin");

    address public eusd = makeAddr("eusd");
    address public pEusd = makeAddr("pEusd");

    address proposerOne = makeAddr("proposerOne");
    address executorOne = makeAddr("executorOne");

    address[] proposers = [proposerOne];
    address[] executors = [executorOne];

    address public rewardsPool = makeAddr("rewardsPool");

    function setUp() public {
   

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 16: The castApproval /castDisapproval doesn't check if role parameter is the approvalRole

**Source**: Spearbit
**Protocol**: Llama
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**Critical Risk**

## Context
`LlamaCore.sol#L642`

## Description
A policyholder should be able to cast their approval for an action if they have the `approvalRole` defined in the strategy. It should not be possible for other roles to cast an action.

The `_castApproval` method verifies if the policyholder has the role passed as an argument but doesn't check if it actually has `approvalRole`, which is eligible to cast an approval. This means any role in the llama contract can participate in the approval with completely different quantities (weights). 

The same problem occurs for the `castDisapproval` function as well.

## Recommendation
The check could be added inside the strategy in the `getApprovalQuantityAt` function: 

```solidity
RelativeStrategy.sol#L174
function getApprovalQuantityAt(address policyholder, uint8 role, uint256 timestamp) external view
returns (uint128) {
    + if (role != approvalRole) return 0;
    uint128 quantity = policy.getPastQuantity(policyholder, role, timestamp);
    return quantity > 0 && forceApprovalRole[role] ? type(uint128).max : quantity;
}
```

If the passed role doesn't equal the `approvalRole`, a quantity of zero could be returned:
```solidity
if (role != approvalRole) return 0;
```

## Resolution
**Llama:** Fixed in commit `38b5a9`.  
**Spearbit:** Resolved.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Llama-Spearbit-Security-Review.pdf)

---

### Example 17: Max approval to any address is possible

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Risk Report

## Severity
**High Risk**

## Context
`HopFacetOptimized.sol#L33-L45`

## Description
The function `HopFacetOptimized.setApprovalForBridges()` can be called by anyone to give maximum approval to any address for any ERC20 token. This vulnerability allows any ERC20 token left in the Diamond to be stolen.

```solidity
function setApprovalForBridges(address[] calldata bridges, address[] calldata tokensToApprove) external {
    ...
    LibAsset.maxApproveERC20(..., type(uint256).max);
    ...
}
```

## Recommendation
Add authorization to the function `setApprovalForBridges()` so only the owner can call it. This can be implemented in the following way:

```solidity
function setApprovalForBridges(address[] calldata bridges, address[] calldata tokensToApprove) external {
    + LibDiamond.enforceIsContractOwner();
    ...
    LibAsset.maxApproveERC20(..., type(uint256).max);
    ...
}
```

## LiFi
Fixed in PR 244.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-retainer1-Spearbit-Security-Review.pdf)

---

### Example 18: H-8: Lack of access control for `mintRebalancer()` and `burnRebalancer()`

**Source**: Sherlock
**Protocol**: USSD - Autonomous Secure Dollar
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-USSD-judging/issues/777 

## Found by 
0x2e, 0xAzez, 0xHati, 0xMojito, 0xPkhatri, 0xRobocop, 0xSmartContract, 0xStalin, 0xeix, 0xyPhilic, 14si2o\_Flint, AlexCzm, Angry\_Mustache\_Man, Aymen0909, Bahurum, Bauchibred, Bauer, BlockChomper, Brenzee, BugBusters, BugHunter101, Delvir0, DevABDee, Dug, Fanz, GimelSec, HonorLt, J4de, JohnnyTime, Juntao, Kodyvim, Kose, Lilyjjo, Madalad, Nyx, PokemonAuditSimulator, RaymondFam, Saeedalipoor01988, SanketKogekar, Schpiel, SensoYard, T1MOH, TheNaubit, Tricko, VAD37, Vagner, WATCHPUG, \_\_141345\_\_, anthony, ast3ros, auditsea, berlin-101, blackhole, blockdev, carrotsmuggler, chainNue, chalex.eth, cjm00n, coincoin, coryli, ctf\_sec, curiousapple, dacian, evilakela, georgits, giovannidisiena, immeas, innertia, jah, juancito, kie, kiki\_dev, lil.eth, m4ttm, mahdikarimi, mrpathfindr, n33k, neumo, ni8mare, nobody2018, pavankv241, pengun, qbs, qckhp, qpzm, ravikiran.web3, saidam017, sam\_gmk, sashik\_eth, shaka, shealtielanz, shogoki, simon135, slightscan, smiling\_heretic, tallo, theOwl, the\_endless\_sea, toshii, tsvetanovv, tvdung94, twcctop, twicek, vagrant, ver0759, warRoom, whiteh4t9527, ww4tson, yy
## Summary

Lack of access control in `USSD.mintRebalancer()` and `USSD.burnRebalancer()` can lead to a denial-of-service attack and malfunction of the rebalancer as it can alter `totalSupply`, which is used in `rebalancer.SellUSSDBuyCollateral` to calculate `ownval`.

## Vulnerability Detail

Ba

*[Content truncated...]*

---

### Example 19: WatcherManager is not set correctly

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Security Analysis Report

## Severity
**Medium Risk**

## Context
`WatcherClient.sol#L36-L39`

## Description
The `setWatcherManager` function missed actually updating the `watcherManager`. Instead, it is just emitting an event indicating that the Watcher Manager is updated when it is not. This could become a problem once new modules are added/revised in the `WatcherManager` contract, and `WatcherClient` wants to use this upgraded `WatcherManager`. `WatcherClient` will be forced to use the outdated `WatcherManager` contract code.

## Recommendation
Revise the `setWatcherManager` function as shown below:

```solidity
function setWatcherManager(address _watcherManager) external onlyOwner {
    require(_watcherManager != address(watcherManager), "already watcher manager");
    watcherManager = WatcherManager(_watcherManager);
    emit WatcherManagerChanged(_watcherManager);
}
```

## Connext
Fixed in PR 2432.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 20: Router recipient can be configured more than once

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
RoutersFacet.sol#L401

## Description
The comments from the `setRouterRecipient` function mentioned that the router should only be able to set the recipient once. Otherwise, no problem is solved. However, based on the current implementation, it is possible for the router to set its recipient more than once.

### File: RoutersFacet.sol
```solidity
394: /**
395:  * @notice Sets the designated recipient for a router
396:  * @dev Router should only be able to set this once otherwise if router key compromised,
397:  * no problem is solved since attacker could just update recipient
398:  * @param router Router address to set recipient
399:  * @param recipient Recipient Address to set to router
400:  */
401: function setRouterRecipient(address router, address recipient) external onlyRouterOwner(router) {
```

Let's assume that during router setup, the `setupRouter` function is being called and the owner is set to Alice's first EOA (0x123), and the recipient is set to Alice's second EOA (0x456). Although the comment mentioned that `setRouterRecipient` should only be set once, this is not true because this function will only revert if the `_prevRecipient == recipient`. As long as the new recipient is not the same as the previous recipient, the function will happily accept the new recipient.

Therefore, if the router's signing key is compromised by Bob (attacker), he could call the `setRouterRecipient` function to change the new recipient to his per

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 21: Improve dexAllowlist

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Security Analysis Report

## Severity: Medium Risk

### Context:
- **Files:** 
  - SwapperV2.sol (#L67-L81)
  - Swapper.sol (#L65-L78)
  - LibAccess.sol (#L13-L15)
  - DexManagerFacet.sol
  - AccessManagerFacet.sol

### Description:
The functions `_executeSwaps()` in both `SwapperV2.sol` and `Swapper.sol` employ a whitelist to ensure that the correct functions in the permitted DEXes are executed. The validation checks for `approveTo`, `callTo`, and `signature` (`callData`) are conducted independently. This independent approach creates a risk, as any signature can be considered valid for any DEX in conjunction with any `approveTo` address. This grants broader access than necessary.

This issue is critical because multiple functions may share the same signature. For instance, the following two functions have identical signatures:

- `gasprice_bit_ether(int128)`
- `transferFrom(address,address,uint256)`

The bytes4 signature for both is `0x23b872dd`. Notably, brute-forcing an innocuous-looking function is straightforward. 

The `transferFrom()` function poses a particular threat as it enables the sweeping of tokens from other users who have granted an allowance to the LiFi Diamond. If a DEX that contains a function with the same signature gets whitelisted, this could be exploited with the existing code.

**Present in both SwapperV2.sol and Swapper.sol:**
```solidity
function _executeSwaps(...) ... {
    ...
    if (
        !(appStorage.dexAllowlist[currentSwapData.approveTo]

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 22: DAO fees potentially unavailable due to overly strict access control

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: MEDIUM

**Details**:

## Audit Report

## Severity: Medium Risk

### Context
OrderBook.sol#L790

### Description
The `collectFees` function is guarded by an inline access control require statement condition which prevents anyone, except a host, from invoking the function. Only the host of the market is authorized to invoke, effectively delivering all collected fees, including the part of the fees belonging to the DAO.

```solidity
function collectFees() external nonReentrant {
    require(msg.sender == _host(), Errors.ACCESS); // @audit only host authorized
    if (_baseFeeBalance > 1) {
        _collectFees(_baseToken, _baseFeeBalance - 1);
        _baseFeeBalance = 1;
    }
    if (_quoteFeeBalance > 1) {
        _collectFees(_quoteToken, _quoteFeeBalance - 1);
        _quoteFeeBalance = 1;
    }
}
```

This access control is too strict and can lead to funds being locked permanently in the worst-case scenario. As the host is a single point of failure, if access to the wallet is lost or is incorrectly transferred, the fees for both the host and the DAO will be locked.

### Recommendation
It is recommended to remove the access control from the `collectFees` function, as collected fees are transferred to fixed addresses being the host and the treasury. In such a setup, anyone should be able to invoke the function and trigger collected fees delivery at any time, and it should not be limited only to the host of the market.

### Clober
Fixed in PR 315.

### Spearbit
Verified. Authorization modified. E

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 23: [M-12] Attacker can grift syndicate staking by staking a small amount

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-stakehouse/blob/a0558ed7b12e1ace1fe5c07970c7fc07eb00eebd/contracts/liquid-staking/LiquidStakingManager.sol#L882><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/23c3cf65975cada7fd2255a141b359a6b31c2f9c/contracts/syndicate/Syndicate.sol#L22>

`LiquidStakingManager._autoStakeWithSyndicate` always stakes a fixed amount of 12 ETH. However, `Syndicate.stake` only allows a total staking amount of 12 ETH and reverts otherwise:

```solidity
if (_sETHAmount + totalStaked > 12 ether) revert InvalidStakeAmount();
```

An attacker can abuse this and front-run calls to `mintDerivatives` (which call `_autoStakeWithSyndicate` internally). Because `Syndicate.stake` can be called by everyone, he can stake the minimum amount (1 gwei) such that the `mintDerivatives` call fails.

### Proof Of Concept

As soon as there is a `mintDerivatives` call in the mempool, an attacker (that owns sETH) calls `Syndicate.stake` with an amount of 1 gwei. `_autoStakeWithSyndicate` will still call `Syndicate.stake` with 12 ether. However, `_sETHAmount + totalStaked > 12 ether` will then be true, meaning that the call will revert.

### Recommended Mitigation Steps

Only allow staking through the LiquidStakingManager, i.e. add access control to `Syndicate.stake`.


**[vince0656 (Stakehouse) confirmed](https://github.com/code-423n4/2022-11-stakehouse-findings/issues/146#issuecomment-1329482113)**


***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 24: H-1: Anyone could call `depositReward` with zero reward to extend the period finish time

**Source**: Sherlock
**Protocol**: Zivoe
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-03-zivoe-judging/issues/11 

## Found by 
0brxce, 0xAnmol, 0xboriskataa, 0xpiken, 0xvj, 14si2o\_Flint, 9oelm, AMOW, Afriaudit, Bauer, CL001, Dliteofficial, Drynooo, FastTiger, Ironsidesec, Krace, Kunhah, Maniacs, Nihavent, Ruhum, SilverChariot, Timenov, Tychai0s, amar, araj, asui, blockchain555, cergyk, coffiasd, dany.armstrong90, dimulski, forgebyola, heedfxn, jasonxiale, joicygiore, krikolkk, lemonmon, marchev, mt030d, novaman33, pashap9990, rbserver, sakshamguruji, sl1, sunill\_eth, t0x1c
## Summary

Anyone could extend the reward finish time, potentially resulting in users receiving fewer rewards than expected within the same time period.

## Vulnerability Detail

The function `depositReward` can be called by anyone, even with zero rewards, allowing it to be exploited to extend the reward finish time at little cost. 
This could result in loss of rewards; for instance, if there are 10 DAI rewards within a 10-day period, a malicious user could extend the finish time on *day 5*, extending the finish time to the 15th day. Participants would only receive 7.5 DAI by the 10th day.

```solidity
    function depositReward(address _rewardsToken, uint256 reward) external updateReward(address(0)) nonReentrant {
        IERC20(_rewardsToken).safeTransferFrom(_msgSender(), address(this), reward);

        // Update vesting accounting for reward (if existing rewards being distributed, increase proportionally).
        if (block.timestamp >=

*[Content truncated...]*

---

### Example 25: [M-24] Node runner who is already known to be malicious cannot be banned before corresponding smart wallet is created

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L356-L377><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L507-L509><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L426-L492>

Currently, the `rotateNodeRunnerOfSmartWallet` function provides the only way to set `bannedNodeRunners` to `true` for a malicious node runner. However, before the node runner calls the `registerBLSPublicKeys` function to create a smart wallet, calling the `rotateNodeRunnerOfSmartWallet` function reverts. This means that for a node runner, who is already known to be malicious such as someone controlling a hacker address, calling the `isNodeRunnerBanned` function always return `false` before the `registerBLSPublicKeys` function is called for the first time, and executing `require(isNodeRunnerBanned(msg.sender) == false, "Node runner is banned from LSD network")` when calling the `registerBLSPublicKeys` function for the first time is not effective. As the monitoring burden can be high, the malicious node runner could interact with the protocol maliciously for a while already after the `registerBLSPublicKeys` function is called until the DAO notices the malicious activities and then calls the `rotateNodeRunnerOfSmartWallet` function. When the DAO does not react promptly, some damages to the protocol could be done 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

## Statistics

- Total findings analyzed: 48
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

