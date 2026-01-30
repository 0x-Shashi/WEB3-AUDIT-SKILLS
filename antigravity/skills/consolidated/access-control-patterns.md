# Access Control Security Patterns (Consolidated)

> **Broken access control is a top vulnerability. Missing auth = instant critical.**

---

## Quick Summary

| Vulnerability | Description | Severity |
|---------------|-------------|----------|
| Missing Access Control | Critical function callable by anyone | Critical |
| tx.origin Authentication | Phishable, not secure for auth | Critical |
| Unprotected Initialize | Proxy initialization front-runnable | Critical |
| Privilege Escalation | Lower role can gain higher privileges | Critical |
| Centralization Risk | Single admin can rug entire protocol | High |
| Missing Zero Check | Admin set to address(0) permanently | High |
| Improper Role Management | Roles not properly validated/revoked | High |

---

## Detection Strategy

### Common Vulnerable Patterns
```solidity
// CRITICAL: No access control on sensitive function
function setPrice(uint _price) external {  // ← Anyone can call!
    price = _price;
}

// CRITICAL: Using tx.origin for auth
function withdraw() external {
    require(tx.origin == owner);  // ← Phishable via malicious contract
}

// CRITICAL: Initialize without protection
function initialize(address _owner) external {
    owner = _owner;  // ← Can be front-run
}
```

### Safe Patterns
```solidity
// SAFE: Proper access control
function setPrice(uint _price) external onlyOwner {
    price = _price;
}

// SAFE: Using msg.sender
function withdraw() external {
    require(msg.sender == owner);
}

// SAFE: Initializer with protection
function initialize(address _owner) external initializer {
    require(_owner != address(0), "Zero address");
    owner = _owner;
}
```

### Role-Based Access Control
```solidity
// OpenZeppelin AccessControl pattern
bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

function criticalFunction() external onlyRole(ADMIN_ROLE) { ... }
function operatorFunction() external onlyRole(OPERATOR_ROLE) { ... }
```

### Audit Checklist
- [ ] Every external/public function has appropriate access control
- [ ] No use of tx.origin for authentication
- [ ] initialize() protected with initializer modifier
- [ ] Admin functions have timelock for critical operations
- [ ] Zero address checks on all address setters
- [ ] Role hierarchy properly enforced
- [ ] Renounce/transfer ownership has safety checks
- [ ] Multi-sig for critical admin functions

---

## Centralization Risk Assessment

| Risk Level | Pattern | Mitigation |
|------------|---------|------------|
| Critical | Single EOA owner | Multi-sig wallet |
| Critical | Instant parameter changes | Timelock |
| High | Owner can pause indefinitely | Emergency DAO vote |
| High | Owner can upgrade arbitrarily | Governance + timelock |
| Medium | Owner can set fees to 100% | Fee caps in code |

---

## Included Pattern Files

- access-control-patterns.md, admin-patterns.md, ownership-patterns.md
- msgsender-patterns.md, delegate-patterns.md
- pause-patterns.md, blacklisted-patterns.md, whitelist-blacklist-match-patterns.md
- update-state-after-admin-action-patterns.md

---

## Full Pattern Details

---
## access-control-patterns.md
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
- Ability to call the LiFi Diamond itself via functions that donâ€™t have `nonReentrant`.
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

tSQD is designed so that it can be bridged from Ethereum (L1) to Arbitrum (L2) via Arbitrumâ€™s generic-custom gateway.
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


---
## admin-patterns.md
# Admin Security Patterns

## Overview

**Frequency**: 36 occurrences (0.07% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 11 | 25 | 0 | 0 |

**Common Sources**: Code4rena, Spearbit, Sherlock, Cyfrin, Codehawks

---

## Detection Checklist

- [ ] Check for admin vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: The Protocol owner can drain users' currency tokens

**Source**: Spearbit
**Protocol**: LOOKSRARE
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context:
- LooksRareProtocol.sol#L138
- LooksRareProtocol.sol#L391-L398
- ITransferSelectorNFT.sol#L14-L17
- TransferSelectorNFT.sol#L41
- TransferSelectorNFT.sol#L89-L98

## Description:
The Protocol owner can drain users' currency tokens that have been approved to the protocol. Makers who want to bid on NFTs would need to approve their currency token to be spent by the protocol. The owner should not be able to access these funds for free.

The owner can drain the funds as follows:

1. Calls `addTransferManagerForAssetType` and assigns the currency token as the `transferManagerForAssetType` and `IERC20.transferFrom.selector` as the `selectorForAssetType` for a new `assetType`.
2. Signs an almost empty `MakerAsk` order and sets its collection as the address of the targeted user and the `assetType` to the newly created `assetType`. The owner also creates the corresponding `TakerBid` by setting the `recipient` field to the amount of currency they would like to transfer.
3. Calls the `executeTakerBid` endpoint with the above data without a `merkleTree` or `affiliate`.

```solidity
// file: test/foundry/Attack.t.sol
pragma solidity 0.8.17;

import {IStrategyManager} from "../../contracts/interfaces/IStrategyManager.sol";
import {IBaseStrategy} from "../../contracts/interfaces/IBaseStrategy.sol";
import {OrderStructs} from "../../contracts/libraries/OrderStructs.sol";
import {ProtocolBase} from "./ProtocolBase.t.sol";
import {MockERC20} from "../mock

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LooksRare-Spearbit-Security-Review.pdf)

---

### Example 2: Malicious manager could cause Vault funds to be inaccessible

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
AeraVaultV1.sol#L794-L822

## Description
The `calculateAndDistributeManagerFees()` function pushes tokens to the manager, and if for unknown reasons this action fails, the entire Vault would be blocked, and funds become inaccessible. This occurs because the following functions depend on the execution of `calculateAndDistributeManagerFees()`: 

- `deposit()`
- `withdraw()`
- `setManager()`
- `claimManagerFees()`
- `initiateFinalization()`
- `finalize()`

Within `calculateAndDistributeManagerFees()`, the function `safeTransfer()` is the riskiest and could fail under the following situations:

- A token with a callback is used, for example, an ERC777 token, and the callback is not implemented correctly.
- A token with a blacklist option is used and the manager is blacklisted. For example, USDC has such blacklist functionality. Because the manager can be an unknown party, a small risk exists that he is malicious and his address could be blacklisted in USDC.

**Note:** Set as high risk because although probability is very small, impact results in Vault funds becoming inaccessible.

```solidity
function calculateAndDistributeManagerFees() internal {
    ...
    for (uint256 i = 0; i < amounts.length; i++) {
        tokens[i].safeTransfer(manager, amounts[i]);
    }
}
```

## Recommendation
Beware of including tokens with callbacks such as ERC777 tokens into the Vault. Additionally, use a pull over push pattern to let the manager retrieve fees. Th

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 3: Manager can cause an immediate weight change

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
Balancerâ€™s `ManagedPool` uses 32-bit values for `startTime` and `endTime` but does not verify if those values exist within that range. When `endTime` is set to \(2^{32}\), it becomes larger than `startTime`, so the `_require(startTime <= endTime, ...)` statement will not revert. When `endTime` is converted to 32 bits, it will get a value of 0, causing the check in `_calculateWeightChangeProgress()` with `if (currentTime >= endTime)` to be true, thus leading to an immediate weight change.

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

### Example 4: A malicious owner or user with a Role.Router role can drain a router 's liquidity

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Report

## Severity: High Risk

### Context
- `RoutersFacet.sol#L263-L267`
- `RoutersFacet.sol#L297`
- `RoutersFacet.sol#L498`
- `BridgeFacet.sol#L622`

### Description
A malicious owner or user with the `Role.Router` role (denominated as A in this example) can drain a router's liquidity for a current router (a router that has already been added to the system and might potentially have significant liquidity in some assets).

Here is how A can do it (this can also be done atomically):
1. Remove the router by calling `removeRouter`.
2. Add the router back by calling `setupRouter` and set the owner and recipient parameters to accounts A has access to/control over.
3. Loop over all tokens that the router has liquidity in and call `removeRouterLiquidityFor` to drain/redirect the funds into accounts A has control over.

This means that all routers would need to put their trust in the owner (of this Connext instance) and any user who has a `Role.Router` with their liquidity. Thus, the current setup is not trustless.

### Recommendation
To remove this trust assumption, a redesign is required for how routers get integrated into this system. It would be best to have the function in a form like:

```solidity
function addRouter(IRouter router)
```

(renamed `setupRouter` to `addRouter`). Here, `IRouter` is an interface that establishes the requirements that the router would need to meet.

A router:
1. Needs to be able to set its own owner or recipient if required. This might 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 5: [H-01] Wrong reward token calculation in MasterChef contract

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

### Example 6: [H-06] Setting new controller can break YVaultLPFarming

**Source**: Code4rena
**Protocol**: JPEG'd
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-04-jpegd/blob/e72861a9ccb707ced9015166fbded5c97c6991b6/contracts/farming/yVaultLPFarming.sol#L170
https://github.com/code-423n4/2022-04-jpegd/blob/e72861a9ccb707ced9015166fbded5c97c6991b6/contracts/vaults/yVault/yVault.sol#L108


## Vulnerability details

## Impact
The accruals in `yVaultLPFarming` will fail if [`currentBalance < previousBalance`](https://github.com/code-423n4/2022-04-jpegd/blob/e72861a9ccb707ced9015166fbded5c97c6991b6/contracts/farming/yVaultLPFarming.sol#L170) in `_computeUpdate`.

```solidity
currentBalance = vault.balanceOfJPEG() + jpeg.balanceOf(address(this));
uint256 newRewards = currentBalance - previousBalance;
```

No funds can be withdrawn anymore as the `withdraw` functions first trigger an `_update`.

The `currentBalance < previousBalance` case can, for example, be triggerd by decreasing the `vault.balanceOfJPEG()` due to calling `yVault.setController`:

```solidity
function setController(address _controller) public onlyOwner {
    // @audit can reduce balanceofJpeg which breaks other masterchef contract
    require(_controller != address(0), "INVALID_CONTROLLER");
    controller = IController(_controller);
}

function balanceOfJPEG() external view returns (uint256) {
    // @audit new controller could return a smaller balance
    return controller.balanceOfJPEG(address(token));
}
```

## Recommended Mitigation Steps
Setting a new controller on a vault must be done very carefully and requires a

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-jpegd)

---

### Example 7: [H-09] Vault#setController() owner of the Vault contracts can drain funds from the Vault

**Source**: Code4rena
**Protocol**: InsureDAO
**Impact**: HIGH

**Details**:

## Handle

WatchPug


## Vulnerability details

https://github.com/code-423n4/2022-01-insure/blob/19d1a7819fe7ce795e6d4814e7ddf8b8e1323df3/contracts/Vault.sol#L485-L496

```solidity
function setController(address _controller) public override onlyOwner {
    require(_controller != address(0), "ERROR_ZERO_ADDRESS");

    if (address(controller) != address(0)) {
        controller.migrate(address(_controller));
        controller = IController(_controller);
    } else {
        controller = IController(_controller);
    }

    emit ControllerSet(_controller);
}
```

The owner of the Vault contract can set an arbitrary address as the `controller`.

https://github.com/code-423n4/2022-01-insure/blob/19d1a7819fe7ce795e6d4814e7ddf8b8e1323df3/contracts/Vault.sol#L342-L352

```solidity
function utilize() external override returns (uint256 _amount) {
    if (keeper != address(0)) {
        require(msg.sender == keeper, "ERROR_NOT_KEEPER");
    }
    _amount = available(); //balance
    if (_amount > 0) {
        IERC20(token).safeTransfer(address(controller), _amount);
        balance -= _amount;
        controller.earn(address(token), _amount);
    }
}
```

A malicious `controller` contract can transfer funds from the Vault to the attacker.

## PoC

A malicious/compromised can:

1. Call `Vault#setController()` and set `controller` to a malicious contract;
    -   L489 the old controller will transfer funds to the new, malicious controller.
2. Call `Vault#utilize()` to deposit all the b

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-insure)

---

### Example 8: [H-05] backdoor in withdrawRedundant

**Source**: Code4rena
**Protocol**: InsureDAO
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `Vault.withdrawRedundant` has wrong logic that allows the admins to steal the underlying vault token.

```solidity
function withdrawRedundant(address _token, address _to)
     external
     override
     onlyOwner
{
     if (
          _token == address(token) &&
          balance < IERC20(token).balanceOf(address(this))
     ) {
          uint256 _redundant = IERC20(token).balanceOf(address(this)) -
               balance;
          IERC20(token).safeTransfer(_to, _redundant);
     } else if (IERC20(_token).balanceOf(address(this)) > 0) {
          // @audit they can rug users. let's say balance == IERC20(token).balanceOf(address(this)) => first if false => transfers out everything
          IERC20(_token).safeTransfer(
               _to,
               IERC20(_token).balanceOf(address(this))
          );
     }
}
```

#### POC
- Vault deposits increase as `Vault.addValue` is called and the `balance` increases by `_amount` as well as the actual `IERC20(token).balanceOf(this)`. Note that `balance == IERC20(token).balanceOf(this)`
- Admins call `vault.withdrawRedundant(vault.token(), attacker)` which goes into the `else if` branch due to the balance inequality condition being `false`. It will transfer out all `vault.token()` amounts to the attacker.

## Impact
There's a backdoor in the `withdrawRedundant` that allows admins to steal all user deposits.

## Recommended Mitigation Steps
I think the devs wanted this logic from th

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-insure)

---

### Example 9: The off-chain mechanism must be ensured to work in a correct order strictly

**Source**: Cyfrin
**Protocol**: Stake Link
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The `PriorityPool` contract relies on the distribution oracle for accounting and the accounting calculation is done off-chain.

According to the communication with the protocol team, the correct workflow for queued deposits can be described as below:
- Whenever there is a new room for deposit in the staking pool, the function `depositQueuedTokens` is called.
- The `PriorityPool` contract is paused by calling `pauseForUpdate()`.
- Accounting calculations happen off-chain using the function `getAccountData()` and `getDepositsSinceLastUpdate()`(`depositsSinceLastUpdate`) variable to compose the latest Merkle tree.
- The distribution oracle calls the function `updateDistribution()` and this will resume the `PriorityPool`.

The only purpose of pausing the queue contract is to prevent unqueue until the accounting status are updated.
Through an analysis we found that the off-chain mechanism MUST follow the order very strictly or else user funds can be stolen.
While we acknowledge that the protocol team will ensure it, we decided to keep this finding as a medium risk because we can not verify the off-chain mechanism.

**Impact:** If the off-chain mechanism occurs in a wrong order by any chance, user funds can be stolen.
Given the likelihood is low, we evaluate the impact to be Medium.

**Proof of Concept:** The below test case shows the attack scenario.
```javascript
  it('Cyfrin: off-chain mechanism in an incorrect order can lead to user funds 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-08-25-cyfrin-stake-link.md)

---

### Example 10: Owner can circumvent allowance() viaenableTradingWithWeights()

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: MEDIUM

**Details**:

## Security Assessment Report

## Severity
**Medium Risk**

## Context
AeraVaultV1.sol#L564-L593

## Description
The vault Owner can set arbitrary weights via `disableTrading()` and then call `enableTradingWithWeights()` to set the spot price and create arbitrage opportunities for himself. This way, `allowance()` in `withdraw()` checks, which limit the amount of funds an owner can withdraw, can be circumvented. Something similar can be done with `enableTradingRiskingArbitrage()` in combination with sufficient time.

Also see the following issues:
- `allowance()` doesnâ€™t limit `withdraw()`
- `enableTradingWithWeights` allows the Treasury to change the poolâ€™s weights even if the swap is not disabled
- Separation of concerns between Owner and Manager

### Functions
```solidity
function disableTrading() ... onlyOwnerOrManager ... {
    setSwapEnabled(false);
}

function enableTradingWithWeights(uint256[] calldata weights) ... onlyOwner ... {
    ...
    pool.updateWeightsGradually(timestamp, timestamp, weights);
    setSwapEnabled(true);
}

function enableTradingRiskingArbitrage() ... onlyOwner ... {
    setSwapEnabled(true);
}
```

## Recommendation
Consider allowing only the manager to execute the `disableTrading()` function, although this also has disadvantages. Additionally, use an oracle to determine the spot price (as is already envisioned for the next versions of the protocol).

## Gauntlet
For safety reasons, we want the treasury to have full control over trading. Given o

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 11: diamondCut() allows re-execution of old updates

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Medium Risk Severity Report

## Context
LibDiamond.sol#L95-L119

## Description
The function `diamondCut()` of `LibDiamond` verifies the signed version of the update parameters. It checks whether the signed version is available and if a sufficient amount of time has passed. However, it doesnâ€™t prevent multiple executions, and the signed version remains valid indefinitely.

This allows old updates to be executed again. Assume the following:

- `facet_x` (or `function_y`) has value: `version_1`.
- Then, replace `facet_x` (or `function_y`) with `version_2`.
- A bug is found in `version_2`, and it is rolled back with: replace `facet_x` (or `function_y`) with `version_1`.
- Then a (malicious) owner could immediately do: replace `facet_x` (or `function_y`) with `version_2` (because it is still valid).

**Note:** The risk is limited because it can only be executed by the contract owner; however, this is probably not how the mechanism should work.

```solidity
library LibDiamond {
    function diamondCut(...) ... {
        ...
        uint256 time = ds.acceptanceTimes[keccak256(abi.encode(_diamondCut, _init, _calldata))];
        require(time != 0 && time < block.timestamp, "LibDiamond: delay not elapsed");
        ...
    }
}
```

## Recommendation
Consider doing the following:

- Add a validity period for updates.
- Remember which updates have been executed and prevent re-execution.
- Add a nonce (for cases where re-execution is wanted).

## Connext
Solved in PR 1576.

## Spearb

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 12: [M-09] DAO or lsdn owner can steal funds from node runner

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L356-L377>

DAO or LSD network owner can swap node runner of the smart contract to their own eoa, allowing them to withdrawETH or claim rewards from node runner.

### Proof of Concept

There are no checks done when swapping the node runner whether there are funds in the smart contract that belongs to the node runner. Therefore, a malicious dao or lsd network owner can simply swap them out just right after the node runner has deposited 4 ether in the smart wallet.

Place poc in LiquidStakingManager.sol

```solidity
    function testDaoCanTakeNodeRunner4ETH() public {
        address nodeRunner = accountOne; vm.deal(nodeRunner, 4 ether);
        address feesAndMevUser = accountTwo; vm.deal(feesAndMevUser, 4 ether);
        address savETHUser = accountThree; vm.deal(savETHUser, 24 ether);
        address attacker = accountFour;


        registerSingleBLSPubKey(nodeRunner, blsPubKeyOne, accountFour);

        vm.startPrank(admin);
        manager.rotateNodeRunnerOfSmartWallet(nodeRunner, attacker, true);

        vm.stopPrank();

        vm.startPrank(attacker);
        emit log_uint(attacker.balance);
        manager.withdrawETHForKnot(attacker,blsPubKeyOne);
        emit log_uint(attacker.balance);
        vm.stopPrank();
    }

```

### Tools Used

forge

### Recommended Mitigation Steps

Send back outstanding ETH and rewards that belongs to node runner if swapping is

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 13: [M-08] DAO admin in LiquidStakingManager.sol can rug the registered node operator by stealing their fund in the smart wallet via arbitrary execution.

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/LiquidStakingManager.sol#L202
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/LiquidStakingManager.sol#L210
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/LiquidStakingManager.sol#L426
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/LiquidStakingManager.sol#L460
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/smart-wallet/OwnableSmartWallet.sol#L63


## Vulnerability details

## Impact

Dao admin in LiquidStakingManager.sol can rug the registered node operator by stealing their fund via arbitrary execution.

## Proof of Concept

After the Liquid Staking Manager.so is deployed via LSDNFactory::deployNewLiquidStakingDerivativeNetwork,

```solidity
/// @notice Deploys a new LSDN and the liquid staking manger required to manage the network
/// @param _dao Address of the entity that will govern the liquid staking network
/// @param _stakehouseTicker Liquid staking derivative network ticker (between 3-5 chars)
function deployNewLiquidStakingDerivativeNetwork(
	address _dao,
	uint256 _optionalCommission,
	bool _deployOptionalHouseGatekeeper,
	string calldata _stakehouseTicker
) 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 14: [M-26] Compromised or malicious DAO can restrict actions of node runners who are not malicious

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LSDNFactory.sol#L73-L102><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L239-L246><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L308-L321><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L356-L377><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L326-L350>

### Impact

When calling the `deployNewLiquidStakingDerivativeNetwork` function, `_dao` is not required to be an address that corresponds to a governance contract. This is also confirmed by the code walkthrough at <https://www.youtube.com/watch?v=7UHDUA9l6Ek&t=650s>, which mentions that `_dao` can correspond to an address of a single user. Especially when the DAO is set to be an EOA address, it is possible that its private key becomes compromised. Moreover, because the `updateDAOAddress` function lacks a two step procedure for transferring the DAO's role, it is possible that the DAO is set to an uncontrolled address, which can be malicious. When the DAO becomes compromised or malicious, the actions of the node runners, who are not malicious, can be restricted at the DAO's will, such as by calling functions like `rotateEOARepresentativeOfNodeRunner` and `rotateNodeRunnerOfSmar

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 15: Renouncing ownership or admin role could affect the normal operation of Connext

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Assessment Report

## Severity: High Risk

### Context
- Affected Contracts: `WatcherClient.sol`, `WatchManager.sol`, `Merkle.sol`, `RootManager.sol`, `ConnextPriceOracle.sol`, `Upgrade-BeaconController.sol`, `ProposedOwnableFacet.sol#L276-L285`

### Description
Consider the following scenarios:

#### Instance 1 - Renouncing Ownership
All the contracts that extend from `ProposedOwnable` or `ProposedOwnableUpgradeable` inherit a method called `renounceOwnership`. The owner of the contract can use this method to give up their ownership, thereby leaving the contract without an owner. If that were to happen, it would not be possible to perform any owner-specific functionality on that contract anymore.

The following is a summary of the affected contracts and their impact if the ownership has been renounced. One of the most significant impacts is that Connext's message system cannot recover after a fraud has been resolved since there is no way to unpause and add the connector back to the system.

#### Instance 2 - Renouncing Admin Role
All the contracts that extend from `ProposedOwnableFacet` inherit a method called `revokeRole`. 

1. Assume that the Owner has renounced its power and the only Admin remaining used `revokeRole` to renounce its Admin role.
2. Now the contract is left with Zero Owner & Admin.
3. All swap operations collect admin fees via the `SwapUtils.sol` contract. In the absence of any Admin & Owner, these fees will get stuck in the contract with no way

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 16: ERC721SeaDrop 's modifier onlyOwnerOrAdministrator would allow either the owner or theadmin to override the other person's config parameters.

**Source**: Spearbit
**Protocol**: SeaDrop
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- ERC721SeaDrop.sol#L106
- ERC721SeaDrop.sol#L212
- ERC721SeaDrop.sol#L289
- ERC721SeaDrop.sol#L345

## Description
The following 4 external functions in `ERC721SeaDrop` have the `onlyOwnerOrAdministrator` modifier which allows either one to override the other person's work:
- `updateAllowedSeaDrop`
- `updateAllowList`
- `updateDropURI`
- `updateSigner`

This means there should be some sort of off-chain trust established between these two entities. Otherwise, there are possible vectors of attack.

Here is an example of how the owner can override `AllowListData.merkleRoot` and the other fields within `AllowListData` to generate proofs for any allowed SeaDrop `smintAllowList` endpoint that would have `MintParams.feeBps` equal to 0:

1. The administrator calls `updateAllowList` to set the Merkle root for an allowed SeaDrop implementation for this contract and emit the other parameters as logs. The SeaDrop endpoint being called by `ERC721SeaDrop.updateAllowList`: `SeaDrop.sol#L827`
   
2. The owner calls `updateAllowList` but this time with new parameters, specifically a new Merkle root that is computed from leaves that have `MintParams.feeBps == 0`.

3. Users/minters use the generated proof corresponding to the latest allow list update and pass their `mintParams.feeBps` as 0, thus avoiding the protocol fee deduction for the `creatorPaymentAddress` (`SeaDrop.sol#L187-L194`).

## Recommendation
Only use this implementation of `IERC721SeaDrop` if 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Seadrop-Spearbit-Security-Review.pdf)

---

### Example 17: The vault manager has unchecked power to create arbitrage using setSwapFees

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: HIGH

**Details**:

## High Risk Vulnerability Report

## Severity
**High Risk**

## Context
- AeraVaultV1.sol: Lines 663-679
- BasePool.sol: Lines 58-59

## Description
A previously known issue was that a malicious vault manager could arbitrage the vault like in the below scenario:

1. Set the swap fees to a high value by calling `setSwapFee` (10% is the maximum).
2. Wait for the market price to move against the spot price.
3. In the same transaction, reduce the swap fees to ~0 (0.0001% is the minimum) and arbitrage the vault.

The proposed fix was to limit the percentage change of the swap fee to a maximum of `MAXIMUM_SWAP_FEE_PERCENT_CHANGE` each time. However, because there is no restriction on how many times the `setSwapFee` function can be called in a block or transaction, a malicious manager can still call it multiple times in the same transaction and eventually set the swap fee to the value they want.

## Recommendation
Enforce a cooldown period of reasonable length between two consecutive `setSwapFee` function calls.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 18: [M-04] Very critical Owner privileges can cause complete destruction of the project in a possible privateKey exploit

**Source**: Code4rena
**Protocol**: Trader Joe
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-traderjoe/blob/main/src/libraries/PendingOwnable.sol#L42


## Vulnerability details

### Vulnerability details
Typically, the contractâ€™s owner is the account that deploys the contract. As a result, the owner is able to perform certain privileged activities.

However, Owner privileges are numerous and there is no timelock structure in the process of using these privileges.
The Owner is assumed to be an EOA, since the documents do not provide information on whether the Owner will be a multisign structure.

In parallel with the private key thefts of the project owners, which have increased recently, this vulnerability has been stated as medium.

Similar vulnerability;
Private keys stolen:

Hackers have stolen cryptocurrency worth around â‚¬552 million from a blockchain project linked to the popular online game Axie Infinity, in one of the largest cryptocurrency heists on record. Security issue : PrivateKey of the project officer was stolen:
https://www.euronews.com/next/2022/03/30/blockchain-network-ronin-hit-by-552-million-crypto-heist


### Proof of Concept

`onlyOwner` powers;
```js
14 results - 2 files

src/LBFactory.sol:
  220:     function setLBPairImplementation(address _LBPairImplementation) external override onlyOwner {
  322:     function setLBPairIgnored() external override onlyOwner {
  355:     function setPreset() external override onlyOwner {
  401:     function removePreset(uint16 _binStep) external override o

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-traderjoe)

---

### Example 19: [M-01] Contract Owner Possesses Too Many Privileges

**Source**: Code4rena
**Protocol**: Blur Exchange
**Impact**: MEDIUM

**Details**:

[ExecutionDelegate.sol#L119](https://github.com/code-423n4/2022-10-blur/blob/2fdaa6e13b544c8c11d1c022a575f16c3a72e3bf/contracts/ExecutionDelegate.sol#L119)<br>

To use the protocol (buy/sell NFTs), users must approve the `ExecutionDelegate` to handle transfers for their `ERC721`, `ERC1155`, or `ERC20` tokens.

The safety mechanisms mentioned by the protocol do not protect users at all if the project's owner decides to rugpull.

From the contest page, Safety Features:

*   The calling contract must be approved on the `ExecutionDelegate`
*   Users have the ability to revoke approval from the `ExecutionDelegate` without having to individually calling every token contract.

### Proof of Concept

```sol
function transferERC20(address token, address from, address to, uint256 amount)
        approvedContract
        external
        returns (bool)
    {
        require(revokedApproval[from] == false, "User has revoked approval");
        return IERC20(token).transferFrom(from, to, amount);
    }
```

The owner can set `approvedContract`  to any address at any time with `approveContract(address _contract)`, and `revokeApproval()` can be frontrun. As a result, all user funds approved to the `ExecutionDelegate` contract can be lost via rugpull.

### Justification

While rug-pulling may not be the project's intention, I find that this is still an inherently dangerous design.

I am unsure about the validity of centralization risk findings on C4, but I argue this is a valid High risk issu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-blur)

---

### Example 20: M-8: Permissioned rebalancing functions leading to loss of assets

**Source**: Sherlock
**Protocol**: Napier
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-01-napier-judging/issues/99 

The protocol has acknowledged this issue.

## Found by 
Arabadzhiev, ZanyBonzy, cawfree, thisvishalsingh, xiaoming90
## Summary

Permissioned rebalancing functions that could only be accessed by admin could lead to a loss of assets.

## Vulnerability Detail

Per the contest's README page, it stated that the admin/owner is "RESTRICTED". Thus, any finding showing that the owner/admin can steal a user's funds, cause loss of funds or harm to the users, or cause the user's fund to be struck is valid in this audit contest.

> Q: Is the admin/owner of the protocol/contracts TRUSTED or RESTRICTED?
>
> RESTRICTED

The following describes a way where the admin can block users from withdrawing their assets from the protocol

1. The admin calls the `setRebalancer` function to set the rebalance to a wallet address owned by them.

https://github.com/sherlock-audit/2024-01-napier/blob/main/napier-v1/src/adapters/BaseLSTAdapter.sol#L245

```solidity
File: BaseLSTAdapter.sol
245:     function setRebalancer(address _rebalancer) external onlyOwner {
246:         rebalancer = _rebalancer;
247:     }
```

2. The admin calls the `setTargetBufferPercentage` the set the `targetBufferPercentage` to the smallest possible value of 1%. This will cause only 1% of the total ETH deposited by all the users to reside on the adaptor contract. This will cause the ETH buffer to deplete quickly and cause all the redemption and withdrawa

*[Content truncated...]*

---

### Example 21: [M-03] Protocol fee rate can be arbitrarily modified by the owner and the new rate will apply to all existing orders

**Source**: Code4rena
**Protocol**: Infinity NFT Marketplace
**Impact**: MEDIUM

**Details**:

_Submitted by WatchPug, also found by berndartmueller, BowTiedWardens, cccz, csanuragjain, defsec, GreyArt, joestakey, m9800, peritoflores, reassor, Ruhum, shenwilly, throttle, and zer0dot_

```solidity
function matchOneToOneOrders(
    OrderTypes.MakerOrder[] calldata makerOrders1,
    OrderTypes.MakerOrder[] calldata makerOrders2
  ) external {
    uint256 startGas = gasleft();
    uint256 numMakerOrders = makerOrders1.length;
    require(msg.sender == MATCH_EXECUTOR, 'OME');
    require(numMakerOrders == makerOrders2.length, 'mismatched lengths');

    // the below 3 variables are copied to memory once to save on gas
    // an SLOAD costs minimum 100 gas where an MLOAD only costs minimum 3 gas
    // since these values won't change during function execution, we can save on gas by copying them to memory once
    // instead of SLOADing once for each loop iteration
    uint16 protocolFeeBps = PROTOCOL_FEE_BPS;
    uint32 wethTransferGasUnits = WETH_TRANSFER_GAS_UNITS;
```

Per [the comment](https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityExchange.sol#L1120-L1121):

> Transfer fees. Fees are always transferred from buyer to the seller and the exchange although seller is the one that actually 'pays' the fees

And the code:

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityExchange.sol#L725-L729>

```solidity
    uint256 protocolFee = (protocolF

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-infinity)

---

### Example 22: Centralization risk

**Source**: Cyfrin
**Protocol**: Swapexchange
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol has an owner with privileged rights to perform admin tasks that can affect users.
Especially, the owner can change the fee settings and reward handler address.

1. Validation is missing for admin fee setter functions.

```solidity
FeeData.sol
31:     function setFeeValue(uint256 feeValue) external onlyOwner {
32:         require(feeValue < _feeDenominator, "Fee percentage must be less than 1");
33:         _feeValue = feeValue;
34:     }

43:
44:     function setFixedFee(uint256 fixedFee) external onlyOwner {//@audit-issue validate min/max
45:         _fixedFee = fixedFee;
46:     }
```

2. Important changes initiated by admin should be logged via events.

```solidity
File: helpers/FeeData.sol

31:     function setFeeValue(uint256 feeValue) external onlyOwner {

36:     function setMaxHops(uint256 maxHops) external onlyOwner {

40:     function setMaxSwaps(uint256 maxSwaps) external onlyOwner {

44:     function setFixedFee(uint256 fixedFee) external onlyOwner {

48:     function setFeeToken(address feeTokenAddress) public onlyOwner {

53:     function setFeeTokens(address[] memory feeTokenAddresses) public onlyOwner {

60:     function clearFeeTokens() public onlyOwner {

```

```solidity
File: helpers/TransferHelper.sol

86:     function setRewardHandler(address rewardAddress) external onlyOwner {

92:     function setRewardsActive(bool _rewardsActive) external onlyOwner {

```

**Impact:** While the protocol owner is rega

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-swapexchange.md)

---

### Example 23: [M-02] Owner can transfer all ERC20 reward token out using function recoverERC20

**Source**: Code4rena
**Protocol**: Paladin
**Impact**: MEDIUM

**Details**:

The function recoverERC20 is very privileged. It means to recover any token that is accidently sent to the contract.

```solidity
function recoverERC20(address token) external onlyOwner returns(bool) {
	if(minAmountRewardToken[token] != 0) revert Errors.CannotRecoverToken();

	uint256 amount = IERC20(token).balanceOf(address(this));
	if(amount == 0) revert Errors.NullValue();
	IERC20(token).safeTransfer(owner(), amount);

	return true;
}
```

However, admin / owner can use this function to transfer all the reserved reward tokens, which result in fund loss of the pledge creator and the loss of reward for users that want to delegate the veToken.

Also, the recovered token is sent to owner directly instead of sending to a recipient address.

The safeguard

```solidity
if(minAmountRewardToken[token] != 0)
```

cannot stop owner transferring funds because if the owner is compromised or misbehaves, he can adjust the whitelist easily.

### Proof of Concept

The admin can set minAmountRewardToken\[token] to 0 first by calling updateRewardToken:

```solidity
function updateRewardToken(address token, uint256 minRewardPerSecond) external onlyOwner {
```

By doing this the admin removes the token from the whitelist, then the token can call recoverERC20 to transfer all the token into the owner wallet.

```solidity
function recoverERC20(address token) external onlyOwner returns(bool) {
```

### Recommended Mitigation Steps

We recommend that the project uses a multisig wallet to safeguard 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-paladin)

---

### Example 24: M-11: FRAX admin can adjust fee rate to harm Napier and its users

**Source**: Sherlock
**Protocol**: Napier
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-01-napier-judging/issues/108 

The protocol has acknowledged this issue.

## Found by 
xiaoming90
## Summary

FRAX admin can adjust fee rates to harm Napier and its users, preventing Napier users from withdrawing.

## Vulnerability Detail

Per the contest page, the admins of the protocols that Napier integrates with are considered "RESTRICTED". This means that any issue related to FRAX's admin action that could negatively affect Napier protocol/users will be considered valid in this audit contest.

> Q: Are the admins of the protocols your contracts integrate with (if any) TRUSTED or RESTRICTED?
> RESTRICTED

Following is one of the ways that FRAX admin can harm Napier and its users.

FRAX admin can set the fee to 100%.

https://etherscan.io/address/0x82bA8da44Cd5261762e629dd5c605b17715727bd#code#L3413

```solidity
File: FraxEtherRedemptionQueue.sol
217:     /// @notice Sets the fee for redeeming
218:     /// @param _newFee New redemption fee given in percentage terms, using 1e6 precision
219:     function setRedemptionFee(uint64 _newFee) external {
220:         _requireSenderIsTimelock();
221:         if (_newFee > FEE_PRECISION) revert ExceedsMaxRedemptionFee(_newFee, FEE_PRECISION);
222: 
223:         emit SetRedemptionFee({ oldRedemptionFee: redemptionQueueState.redemptionFee, newRedemptionFee: _newFee });
224: 
225:         redemptionQueueState.redemptionFee = _newFee;
226:     }
```

When the adaptor attempts to redeem the 

*[Content truncated...]*

---

### Example 25: M-7: Users are unable to collect their yield if tranche is paused

**Source**: Sherlock
**Protocol**: Napier
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-01-napier-judging/issues/97 

The protocol has acknowledged this issue.

## Found by 
xiaoming90
## Summary

Users are unable to collect their yield if Tranche is paused, resulting in a loss of assets for the victims.

## Vulnerability Detail

Per the contest's README page, it stated that the admin/owner is "RESTRICTED". Thus, any finding showing that the owner/admin can steal a user's funds, cause loss of funds or harm to the users, or cause the user's fund to be struck is valid in this audit contest.

> Q: Is the admin/owner of the protocol/contracts TRUSTED or RESTRICTED?
>
> RESTRICTED

The admin of the protocol has the ability to pause the Tranche contract, and no one except for the admin can unpause it. If a malicious admin paused the Tranche contract, the users will not be able to collect their yield earned, leading to a loss of assets for them.

https://github.com/sherlock-audit/2024-01-napier/blob/main/napier-v1/src/Tranche.sol#L605

```solidity
File: Tranche.sol
603:     /// @notice Pause issue, collect and updateUnclaimedYield
604:     /// @dev only callable by management
605:     function pause() external onlyManagement {
606:         _pause();
607:     }
608: 
609:     /// @notice Unpause issue, collect and updateUnclaimedYield
610:     /// @dev only callable by management
611:     function unpause() external onlyManagement {
612:         _unpause();
613:     }
```

The following shows that the `collect` function can

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 36
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## ownership-patterns.md
# Ownership Security Patterns

## Overview

**Frequency**: 13 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 10 | 0 | 0 |

**Common Sources**: Code4rena, Spearbit, Cyfrin, Sherlock

---

## Detection Checklist

- [ ] Check for ownership vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: OrderNFT theft due to controlling future and past tokens of same order index

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context
- `OrderBook.sol#L410`
- `OrderNFT.sol#L285`

## Description
The order queue is implemented as a ring buffer. To retrieve an order (`Orderbook.getOrder`), the index in the queue is computed as `orderIndex % _MAX_ORDER`. The owner of an `OrderNFT` also uses this function.

```solidity
function _getOrder(OrderKey calldata orderKey) internal view returns (Order storage) {
    return _getQueue(orderKey.isBid, orderKey.priceIndex).orders[orderKey.orderIndex & _MAX_ORDER_M];
}
```

`CloberOrderBook(market).getOrder(decodeId(tokenId)).owner`

As a result, the current owner of the NFT of `orderIndex` also owns all NFTs with `orderIndex + k * _MAX_ORDER`.

An attacker can set approvals of future token IDs to themselves. These approvals are not cleared on `OrderNFT.onMint`. When a victim mints this future token ID, the attacker can steal the NFT and cancel the NFT to claim their tokens.

```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../../../contracts/interfaces/CloberMarketSwapCallbackReceiver.sol";
import "../../../../contracts/mocks/MockQuoteToken.sol";
import "../../../../contracts/mocks/MockBaseToken.sol";
import "../../../../contracts/mocks/MockOrderBook.sol";
import "../../../../contracts/markets/VolatileMarket.sol";
import "../../../../contracts/OrderNFT.sol";
import "../utils/MockingFactoryTest.sol";
import "./Constants.sol";

contract ExploitsTest is Test, CloberMarketSw

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 2: Missing owner check on from when transferring tokens

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: HIGH

**Details**:

## Security Report

## Severity: High Risk

### Context
`OrderNFT.sol#L207`

### Description
The `OrderNFT.transferFrom`/`safeTransferFrom` methods use the internal `_transfer` function. While they check approvals on `msg.sender` through `_isApprovedOrOwner(msg.sender, tokenId)`, it is never checked that the specified `from` parameter is actually the owner of the NFT. 

An attacker can decrease other users' NFT balances, making them unable to cancel or claim their NFTs and locking users' funds. The attacker transfers their own NFT passing the victim as `from` by calling `transferFrom(from=victim, to=attackerAccount, tokenId=attackerTokenId)`. This passes the `_isApprovedOrOwner` check but reduces `from`'s balance.

### Recommendation
Add the following check to `_transfer`:

```solidity
require(ownerOf(tokenId) == from, Errors.ACCESS);
```

### Clober
Fixed PR 310.

### Spearbit
Verified. Ownership check added.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 3: [M-01] `isOwner` / `onlyOwner` checks can be bypassed by attacker in ERC721/ERC20 implementations

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[ERC721H.sol#L185](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/abstract/ERC721H.sol#L185)<br>
[ERC721H.sol#L121](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/abstract/ERC721H.sol#L121)<br>

ERC20H and ERC721H are base contracts for NFTs / coins to inherit from. They supply the modifier onlyOwner and function isOwner which are used in the implementations for access control. However, there are several functions which when using these the answer may be corrupted to true by an attacker.

The issue comes from confusion between calls coming from HolographERC721's fallback function, and calls from actually implemented functions.

In the fallback function, the enforcer appends an additional 32 bytes of `msg.sender`:

    assembly {
      calldatacopy(0, 0, calldatasize())
      mstore(calldatasize(), caller())
      let result := call(gas(), sload(_sourceContractSlot), callvalue(), 0, add(calldatasize(), 32), 0, 0)
      returndatacopy(0, 0, returndatasize())
      switch result
      case 0 {
        revert(0, returndatasize())
      }
      default {
        return(0, returndatasize())
      }
    }

Indeed these are the bytes read as msgSender:

    function msgSender() internal pure returns (address sender) {
      assembly {
        sender := calldataload(sub(calldatasize(), 0x20))
      }
    }

and isOwner simply compares these to the stored owner:

    functi

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 4: Renouncing ownership or admin role could affect the normal operation of Connext

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Assessment Report

## Severity: High Risk

### Context
- Affected Contracts: `WatcherClient.sol`, `WatchManager.sol`, `Merkle.sol`, `RootManager.sol`, `ConnextPriceOracle.sol`, `Upgrade-BeaconController.sol`, `ProposedOwnableFacet.sol#L276-L285`

### Description
Consider the following scenarios:

#### Instance 1 - Renouncing Ownership
All the contracts that extend from `ProposedOwnable` or `ProposedOwnableUpgradeable` inherit a method called `renounceOwnership`. The owner of the contract can use this method to give up their ownership, thereby leaving the contract without an owner. If that were to happen, it would not be possible to perform any owner-specific functionality on that contract anymore.

The following is a summary of the affected contracts and their impact if the ownership has been renounced. One of the most significant impacts is that Connext's message system cannot recover after a fraud has been resolved since there is no way to unpause and add the connector back to the system.

#### Instance 2 - Renouncing Admin Role
All the contracts that extend from `ProposedOwnableFacet` inherit a method called `revokeRole`. 

1. Assume that the Owner has renounced its power and the only Admin remaining used `revokeRole` to renounce its Admin role.
2. Now the contract is left with Zero Owner & Admin.
3. All swap operations collect admin fees via the `SwapUtils.sol` contract. In the absence of any Admin & Owner, these fees will get stuck in the contract with no way

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 5: M-1: Transferring Ownership Might Break The Market

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/41 

## Found by 
xiaoming90

## Summary

After the transfer of the market ownership, the market might stop working, and no one could purchase any bond token from the market leading to a loss of sale for the market makers.

## Vulnerability Detail

The `callbackAuthorized` mapping contains a list of whitelisted market owners authorized to use the callback. When the users call the `purchaseBond` function, it will check at Line 390 if the current market owner is still authorized to use a callback. Otherwise, the function will revert.

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseSDA.sol#L379

```solidity
File: BondBaseSDA.sol
379:     function purchaseBond(
380:         uint256 id_,
381:         uint256 amount_,
382:         uint256 minAmountOut_
383:     ) external override returns (uint256 payout) {
384:         if (msg.sender != address(_teller)) revert Auctioneer_NotAuthorized();
385: 
386:         BondMarket storage market = markets[id_];
387:         BondTerms memory term = terms[id_];
388: 
389:         // If market uses a callback, check that owner is still callback authorized
390:         if (market.callbackAddr != address(0) && !callbackAuthorized[market.owner])
391:             revert Auctioneer_NotAuthorized();
```

However, if the market owner transfers the market ownership to someone else. The market will stop working because the new market owner might not be on the

*[Content truncated...]*

---

### Example 6: Centralization risk

**Source**: Cyfrin
**Protocol**: Swapexchange
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol has an owner with privileged rights to perform admin tasks that can affect users.
Especially, the owner can change the fee settings and reward handler address.

1. Validation is missing for admin fee setter functions.

```solidity
FeeData.sol
31:     function setFeeValue(uint256 feeValue) external onlyOwner {
32:         require(feeValue < _feeDenominator, "Fee percentage must be less than 1");
33:         _feeValue = feeValue;
34:     }

43:
44:     function setFixedFee(uint256 fixedFee) external onlyOwner {//@audit-issue validate min/max
45:         _fixedFee = fixedFee;
46:     }
```

2. Important changes initiated by admin should be logged via events.

```solidity
File: helpers/FeeData.sol

31:     function setFeeValue(uint256 feeValue) external onlyOwner {

36:     function setMaxHops(uint256 maxHops) external onlyOwner {

40:     function setMaxSwaps(uint256 maxSwaps) external onlyOwner {

44:     function setFixedFee(uint256 fixedFee) external onlyOwner {

48:     function setFeeToken(address feeTokenAddress) public onlyOwner {

53:     function setFeeTokens(address[] memory feeTokenAddresses) public onlyOwner {

60:     function clearFeeTokens() public onlyOwner {

```

```solidity
File: helpers/TransferHelper.sol

86:     function setRewardHandler(address rewardAddress) external onlyOwner {

92:     function setRewardsActive(bool _rewardsActive) external onlyOwner {

```

**Impact:** While the protocol owner is rega

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-swapexchange.md)

---

### Example 7: setContractOwner() is insufficient to lock down the owner

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

**Context:** MakeLiFiDiamondImmutable.s.sol#L14-L17. LibDiamond.sol#L70-L75, OwnershipFacet.sol#L66-L73

**Description:**  
The function `transferOwnershipToZeroAddress()` is meant to make the Diamond immutable. It sets the contract owner to 0. However, the contract owner can still be changed if there happens to be a `pendingOwner`. In that case, `confirmOwnershipTransfer()` can still change the contract owner.

```solidity
function transferOwnershipToZeroAddress() external {
    // transfer ownership to 0 address
    LibDiamond.setContractOwner(address(0));
}

function setContractOwner(address _newOwner) internal {
    DiamondStorage storage ds = diamondStorage();
    address previousOwner = ds.contractOwner;
    ds.contractOwner = _newOwner;
    emit OwnershipTransferred(previousOwner, _newOwner);
}

function confirmOwnershipTransfer() external {
    Storage storage s = getStorage();
    address _pendingOwner = s.newOwner;
    if (msg.sender != _pendingOwner) revert NotPendingOwner();
    emit OwnershipTransferred(LibDiamond.contractOwner(), _pendingOwner);
    LibDiamond.setContractOwner(_pendingOwner);
    s.newOwner = LibAsset.NULL_ADDRESS;
}
```

**Recommendation:** Possible solutions  
- First call `cancelOwnershipTransfer()` (and ignore reverts)  
- Reset `s.newOwner` of the `OwnershipFacet`  
- Also remove `OwnershipFacet` (but then function `owner()` is no longer accessible)  

**LiFi:** Solved in PR 250.  
**Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-retainer1-Spearbit-Security-Review.pdf)

---

### Example 8: Lack of two-step role transfer

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: MEDIUM

**Details**:

## Security Advisory

## Severity
**Medium Risk**

## Context
- `MarketFactory.sol#L146-L152`
- `MarketFactory.sol#L137-L140`

## Description
The contracts lack two-step role transfer functionality. Both the ownership of the `MarketFactory` and the change of a market's host are implemented as single-step functions. The basic validation checks whether the address is not a zero address for a market, but it does not properly account for scenarios where the address receiving the role is inaccessible.

Given that `handOverHost` can be invoked by anyone who created the market, it is possible to unintentionally or intentionally make a typo. An attacker could exploit this situation to disrupt fees collection, as the host affects `collectFees` in `OrderBook` (which is documented as a separate issue).

While ownership transfer should ideally be less error-proneâ€”being conducted by a DAO with careâ€”implementing a two-step role transfer remains preferable.

## Recommendation
It is recommended to implement a two-step role transfer where:
1. The role recipient is set.
2. The recipient must then claim that role to finalize the transfer.

## Clober
Fixed in PR 322.

## Spearbit
Verified. Two-step role transfers added for the contract's owner and the market's host.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 9: [M-04] It's possible to swap NFT token ids without fee and also attacker can wrap unwrap all the NFT token balance of the Pair contract and steal their air drops for those token ids

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L217-L243> <br><https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L248-L262>

Users can `wrap()` their NFT tokens (which id is whitelisted) and receive `1e18` fractional token or they can pay `1e18` fractional token and unwrap NFT token. there is two issue here:

1.  anyone can swap their NFT token id with another NFT token id without paying any fee(both ids should be whitelisted). it's swap without fee.
2.  attacker can swap his NFT token(with whitelisted id) for all the NFT balance of contract and steal those NFT tokens airdrop all in one transaction.

### Proof of Concept

This is `wrap()` and `unwrap()` code:

        function wrap(uint256[] calldata tokenIds, bytes32[][] calldata proofs)
            public
            returns (uint256 fractionalTokenAmount)
        {
            // *** Checks *** //

            // check that wrapping is not closed
            require(closeTimestamp == 0, "Wrap: closed");

            // check the tokens exist in the merkle root
            _validateTokenIds(tokenIds, proofs);

            // *** Effects *** //

            // mint fractional tokens to sender
            fractionalTokenAmount = tokenIds.length * ONE;
            _mint(msg.sender, fractionalTokenAmount);

            // *** Interactions *** //

            // transfer nfts from sender
            for (uint256 i = 0;

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-caviar)

---

### Example 10: [M-07] OwnableSmartWallet: Multiple approvals can lead to unwanted ownership transfers

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/smart-wallet/OwnableSmartWallet.sol#L94><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/smart-wallet/OwnableSmartWallet.sol#L105-L106>

The `OwnableSmartWallet` contract employs a mechanism for the owner to approve addresses that can then claim ownership (<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/smart-wallet/OwnableSmartWallet.sol#L94>) of the contract.

The source code has a comment included which states that "Approval is revoked, in order to avoid unintended transfer allowance if this wallet ever returns to the previous owner" (<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/smart-wallet/OwnableSmartWallet.sol#L105-L106>).

This means that when ownership is transferred from User A to User B, the approvals that User A has given should be revoked.

The existing code does not however revoke all approvals that User A has given. It only revokes one approval.

This can lead to unwanted transfers of ownership.

### Proof of Concept

1.  User A approves User B and User C to claim ownership
2.  User B claims ownership first
3.  Only User A's approval for User B is revoked, not however User A's approval for User C
4.  User B transfers ownerhsip back to User A
5.  Now User C can claim ownership eve

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 11: [M-01] `wrapETH2LD` permissioning is over-extended

**Source**: Code4rena
**Protocol**: ENS
**Impact**: MEDIUM

**Details**:

Undesired use of ENS wrapper.

### Proof of Concept

[NameWrapper.sol#L219-L223](https://github.com/code-423n4/2022-07-ens/blob/ff6e59b9415d0ead7daf31c2ed06e86d9061ae22/contracts/wrapper/NameWrapper.sol#L219-L223)<br>

Current permissioning for wrapETH2LD allows msg.senders who are not owner to call it if they are EITHER approved for all on the ERC721 registrar or approved on the wrapper. Allowing users who are approved for the ERC721 registrar makes sense. By giving them approval, you are giving them approval to do what they wish with the token. Any other restrictions are moot regardless because they could use approval to transfer themselves the token anyways and bypass them as the new owner. The issue is allowing users who are approved for the wrapper contract to wrap the underlying domain. By giving approval to the contract the user should only be giving approval for the wrapped domains. As it is currently setup, once a user has given approval on the wrapper contract they have essentially given approval for every domain, wrapped or unwrapped, because any unwrapped domain can be wrapped and taken control of. This is an over-extension of approval which should be limited to the tokens managed by the wrapper contract and not extend to unwrapped domains

### Recommended Mitigation Steps

Remove L221.

**[Arachnid (ENS) disagreed with severity and commented](https://github.com/code-423n4/2022-07-ens-findings/issues/51#issuecomment-1196225256):**
 > This was by design, but the wa

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-ens)

---

### Example 12: [M-12] No Transfer Ownership Pattern

**Source**: Code4rena
**Protocol**: Boot Finance
**Impact**: MEDIUM

**Details**:

## Handle

defsec


## Vulnerability details

## Impact

The current ownership transfer process involves the current owner calling Swap.transferOwnership(). This function checks the new owner is not the zero address and proceeds to write the new owner's address into the owner's state variable. If the nominated EOA account is not a valid account, it is entirely possible the owner may accidentally transfer ownership to an uncontrolled account, breaking all functions with the onlyOwner() modifier.

## Proof of Concept

1. Navigate to "https://github.com/code-423n4/2021-11-bootfinance/blob/7c457b2b5ba6b2c887dafdf7428fd577e405d652/customswap/contracts/Swap.sol#L30"
2. The contract has many onlyOwner function.
3. The contract is inherited from the Ownable which includes transferOwnership.

## Tools Used

None

## Recommended Mitigation Steps

Implement zero address check and Consider implementing a two step process where the owner nominates an account and the nominated account needs to call an acceptOwnership() function for the transfer of ownership to fully succeed. This ensures the nominated EOA account is a valid and active account.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-bootfinance)

---

### Example 13: [M-03] onlyOwner Role Can Unintentionally Influence settleAuction()

**Source**: Code4rena
**Protocol**: Kuiper
**Impact**: MEDIUM

**Details**:

## Handle

leastwood


## Vulnerability details

## Impact

The `onlyOwner` role is able to make changes to the protocol with an immediate affect, while other changes made in `Basket.sol` and `Auction.sol` incur a one day timelock. As a result, an `onlyOwner` role may unintentionally frontrun a `settleAuction()` transaction by making changes to `auctionDecrement` and `auctionMultiplier`, potentially causing the auction bonder to over compensate during a rebalance. Additionally, there is no way for an auction bonder to recover their tokens in the event this does happen.

## Proof of Concept

https://github.com/code-423n4/2021-09-defiProtocol/blob/main/contracts/contracts/Factory.sol#L39-L59
https://github.com/code-423n4/2021-09-defiProtocol/blob/main/contracts/contracts/Auction.sol#L89-L99

## Tools Used

Manual code review

## Recommended Mitigation Steps

Consider adding a timelock delay to all functions affecting protocol execution. Alternatively, `bondForRebalance()` can set state variables for any external calls made to `Factory.sol` (i.e. `factory.auctionMultiplier()` and `factory.auctionDecrement()`), ensuring that `settleAuction()` is called according to these expected results.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-defiprotocol)

---

## Statistics

- Total findings analyzed: 13
- Examples shown: 13
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## msgsender-patterns.md
# msgSender Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 2 | 0 | 0 |

**Common Sources**: Codehawks, Spearbit, Pashov Audit Group, Code4rena

---

## Detection Checklist

- [ ] Check for msgsender vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Incorrect set up and logic of `referralInfoMap` in `SystemConfig::updateReferrerInfo` function

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

### Example 2: The castApprovalBySig and castDisapprovalBySig functions can revert

**Source**: Spearbit
**Protocol**: Llama
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context
LlamaCore.sol#L683-L685

## Description
The `castApprovalBySig` and `castDisapprovalBySig` functions are used to cast an approve or disapprove via an off-chain signature. Within the `_preCastAssertions`, a check is performed against the strategy using `msg.sender` instead of `policyholder`. The strategy (e.g., `AbsoluteStrategy`) uses that argument to check if the cast sender is a policyholder.

```solidity
isApproval
? actionInfo.strategy.isApprovalEnabled(actionInfo, msg.sender)
: actionInfo.strategy.isDisapprovalEnabled(actionInfo, msg.sender);
```

While this works for normal cast, using the ones with signatures will fail as the sender can be anyone who calls the method with the signature signed off-chain.

## Recommendation
Consider sending the policyholder instead of `msg.sender`.

## Llama
Fixed in commit `4bb184` and PR `285`.

## Spearbit
Resolved.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Llama-Spearbit-Security-Review.pdf)

---

### Example 3: [M-01] `isOwner` / `onlyOwner` checks can be bypassed by attacker in ERC721/ERC20 implementations

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[ERC721H.sol#L185](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/abstract/ERC721H.sol#L185)<br>
[ERC721H.sol#L121](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/abstract/ERC721H.sol#L121)<br>

ERC20H and ERC721H are base contracts for NFTs / coins to inherit from. They supply the modifier onlyOwner and function isOwner which are used in the implementations for access control. However, there are several functions which when using these the answer may be corrupted to true by an attacker.

The issue comes from confusion between calls coming from HolographERC721's fallback function, and calls from actually implemented functions.

In the fallback function, the enforcer appends an additional 32 bytes of `msg.sender`:

    assembly {
      calldatacopy(0, 0, calldatasize())
      mstore(calldatasize(), caller())
      let result := call(gas(), sload(_sourceContractSlot), callvalue(), 0, add(calldatasize(), 32), 0, 0)
      returndatacopy(0, 0, returndatasize())
      switch result
      case 0 {
        revert(0, returndatasize())
      }
      default {
        return(0, returndatasize())
      }
    }

Indeed these are the bytes read as msgSender:

    function msgSender() internal pure returns (address sender) {
      assembly {
        sender := calldataload(sub(calldatasize(), 0x20))
      }
    }

and isOwner simply compares these to the stored owner:

    functi

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 4: [M-05] The protocol uses `_msgSender()` extensively, but not everywhere

**Source**: Pashov Audit Group
**Protocol**: Florence Finance
**Impact**: MEDIUM

**Details**:

**Impact:**
Low, because protocol will still function normally, but an expectedly desired types of transactions won't work

**Likelihood:**
High, because it is certain that he issue will occur as code is

**Description**

The code is using OpenZeppelin's `Context` contract which is intended to allow meta-transactions. It works by using doing a call to `_msgSender()` instead of querying `msg.sender` directly, because the method allows those special transactions. The problem is that the `onlyDelegate` and `onlyFundApprover` modifiers in `LoanVault` use `msg.sender` directly instead of `_msgSender()`, which breaks this intent and will not allow meta-transactions at all in the methods that have those modifiers, which are one of the important ones in the `LoanVault` contract.

**Recommendations**

Change the code in the `onlyDelegate` and `onlyFundApprover` modifiers to use `_msgSender()` instead of `msg.sender`.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-04-01-Florence Finance.md)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## delegate-patterns.md
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


---
## pause-patterns.md
# Pause Security Patterns

## Overview

**Frequency**: 10 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 10 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Cantina, Cyfrin, Spearbit

---

## Detection Checklist

- [ ] Check for pause vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: The off-chain mechanism must be ensured to work in a correct order strictly

**Source**: Cyfrin
**Protocol**: Stake Link
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The `PriorityPool` contract relies on the distribution oracle for accounting and the accounting calculation is done off-chain.

According to the communication with the protocol team, the correct workflow for queued deposits can be described as below:
- Whenever there is a new room for deposit in the staking pool, the function `depositQueuedTokens` is called.
- The `PriorityPool` contract is paused by calling `pauseForUpdate()`.
- Accounting calculations happen off-chain using the function `getAccountData()` and `getDepositsSinceLastUpdate()`(`depositsSinceLastUpdate`) variable to compose the latest Merkle tree.
- The distribution oracle calls the function `updateDistribution()` and this will resume the `PriorityPool`.

The only purpose of pausing the queue contract is to prevent unqueue until the accounting status are updated.
Through an analysis we found that the off-chain mechanism MUST follow the order very strictly or else user funds can be stolen.
While we acknowledge that the protocol team will ensure it, we decided to keep this finding as a medium risk because we can not verify the off-chain mechanism.

**Impact:** If the off-chain mechanism occurs in a wrong order by any chance, user funds can be stolen.
Given the likelihood is low, we evaluate the impact to be Medium.

**Proof of Concept:** The below test case shows the attack scenario.
```javascript
  it('Cyfrin: off-chain mechanism in an incorrect order can lead to user funds 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-08-25-cyfrin-stake-link.md)

---

### Example 2: A market could be deprecated but still prevent liquidators to liquidate borrowers if isLiquidateBorrowPaused istrue

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context 
- aave-v2/MorphoGovernance.sol#L358-L366 
- compound/MorphoGovernance.sol#L368-L376 

## Description 
Currently, when a market must be deprecated, Morpho checks that borrowing has been paused before applying the new value for the flag.

```solidity
function setIsDeprecated(address _poolToken, bool _isDeprecated)
external
onlyOwner
isMarketCreated(_poolToken)
{
    if (!marketPauseStatus[_poolToken].isBorrowPaused) revert BorrowNotPaused();
    marketPauseStatus[_poolToken].isDeprecated = _isDeprecated;
    emit IsDeprecatedSet(_poolToken, _isDeprecated);
}
```

The same check should be done in `isLiquidateBorrowPaused`, allowing the deprecation of a market only if `isLiquidateBorrowPaused == false`, otherwise liquidators would not be able to liquidate borrowers on a deprecated market.

## Recommendation 
Prevent the deprecation of a market if the `isLiquidateBorrowPaused` flag is set to true. Consider also checking the `isDeprecated` flag in the `setIsLiquidateBorrowPaused` to prevent pausing the liquidation if the market is deprecated. If Morpho implements the specific behavior, it should also be aware of the issue described in "setIsPausedForAllMarkets" bypassing the check done in `setIsBorrowPaused` and allowing resuming borrow on a deprecated market.

## Morpho 
We acknowledge this issue. The reason behind this is the following: given what @MathisGD said, if we want to be consistent, we should prevent pausing the liquidation borrow on

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/MorphoV1-Spearbit-Security-Review.pdf)

---

### Example 3: [M-03] User Could Change The State Of The System While In Pause Mode

**Source**: Code4rena
**Protocol**: Nibbl
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-06-nibbl/blob/8c3dbd6adf350f35c58b31723d42117765644110/contracts/NibblVault.sol#L443


## Vulnerability details

## Proof-of-Concept

Calling `NibblVault.updateTWAP` function will change the state of the system. It will cause the TWAP to be updated and buyout to be rejected in certain condition.

When the system is in `Pause` mode, the system state should be frozen. However, it was possible someone to call the `NibblVault.updateTWAP` function during the `Pause` mode, thus making changes to the system state.

[https://github.com/code-423n4/2022-06-nibbl/blob/8c3dbd6adf350f35c58b31723d42117765644110/contracts/NibblVault.sol#L443](https://github.com/code-423n4/2022-06-nibbl/blob/8c3dbd6adf350f35c58b31723d42117765644110/contracts/NibblVault.sol#L443)

```solidity
/// @notice Updates the TWAV when in buyout
/// @dev TWAV can be updated only in buyout state
function updateTWAV() external override {
    require(status == Status.buyout, "NibblVault: Status!=Buyout");
    uint32 _blockTimestamp = uint32(block.timestamp % 2**32);
    if (_blockTimestamp != lastBlockTimeStamp) {
        _updateTWAV(getCurrentValuation(), _blockTimestamp);   
        _rejectBuyout(); //For the case when TWAV goes up when updated externally
    }
}
```

## Recommended Mitigation Steps

Ensure that the `NibblVault.updateVault` function cannot be called when the system is in `Pause` mode.

Add the `whenNotPaused` modifier to the function.

```solidity
///

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-nibbl)

---

### Example 4: Inconsistent pause enforcement in WrappedBitcornNativeOFTAdapter 

**Source**: Cantina
**Protocol**: Bitcorn
**Impact**: MEDIUM

**Details**:

## Vulnerability Report

## Context
(No context files were provided by the reviewer)

## Description
The `_credit` function in the `WrappedBitcornNativeOFTAdapter.sol` contract lacks the `whenNotPaused` modifier, allowing token credits even when the contract is paused. This enables users to receive tokens through cross-chain transfers during a pause, undermining the effectiveness of the emergency pause mechanism. It also creates an inconsistent state, with some operations blocked while others continue after an emergency pause.

## Recommendation
Add the `whenNotPaused` modifier to the `_credit` function to ensure consistent pause behavior across all token operations:

```solidity
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
internal
virtual
override
+ whenNotPaused
returns (uint256 amountReceivedLD)
{
    (bool success,) = _to.call{value: _amountLD}("");
    if (!success) {
        revert WithdrawalFailed();
    }
    return _amountLD;
}
```

## Status
- Bitcorn: Fixed in 4adafa00
- Cantina Managed: Verified fix.

**Reference**: [View Original Finding](https://cdn.cantina.xyz/reports/cantina_bitcorn_december2024.pdf)

---

### Example 5: [M-02] `pause/unpause` functionalities not implemented in many pausable contracts

**Source**: Code4rena
**Protocol**: Stader Labs
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-06-stader/blob/main/contracts/SocializingPool.sol#L21> <br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/Auction.sol#L14> <br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/StaderOracle.sol#L17><br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/OperatorRewardsCollector.sol#L16>

The following contracts: `SocializingPool`, `StaderOracle`, `OperatorRewardsCollector` and `Auction` are supposed to be pausable (as they all inherit from `PausableUpgradeable`), but they don't implement the external `pause/unpause` functionalities which means it will never be possible to pause them.

### Proof of Concept

All the following contracts `SocializingPool`, `StaderOracle`, `OperatorRewardsCollector` and `Auction` inherit from the openzeppelin `PausableUpgradeable` extension which means that they contain internal functions `_pause` and `_unpause`.

Because those functions are internal, the contract must implement two other public/external `pause` and `unpause` functions to allow the manager to pause and unpause the contracts when necessary. None of the aforementioned contracts implement those functions, which means even if those contracts are supposed to be pausable (and have the `pause/unpause` functionalities), none of them can be paused.

### Recommended Mitigation Steps

Add public/external `pause` and `unpause` functions in the aforementioned contracts to allow them to be pausable, this can be

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-stader)

---

### Example 6: [M-08] Builders must pay more interest when the system is paused.

**Source**: Code4rena
**Protocol**: Rigor Protocol
**Impact**: MEDIUM

**Details**:

_Submitted by hansfriese, also found by 0x52, 0xNazgul, and rbserver_

[Community.sol#L455](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Community.sol#L455)<br>
[Community.sol#L484](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Community.sol#L484)<br>
[Community.sol#L509](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Community.sol#L509)<br>

Builders can't repay when the system is paused so they must pay more interest for the paused period.

### Proof of Concept

Builders can repay to lenders using 3 functions, [repayLender()](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Community.sol#L455), [reduceDebt()](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Community.sol#L484), and [escrow()](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Community.sol#L509).

But they all don't work when the system is paused and builders have no way to avoid it.

Furthermore, the HomeFi admin is the main lender of builders and there is no assurance that the admin would pause the community for a while to get more interest.

### Tools Used

Solidity Visual Developer of VSCode

### Recommended Mitigation Steps

Recommend thinking of an approach to make 3 repay functions work for pa

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-rigor)

---

### Example 7: [M-05] StakingRewards.sol#stake is intended to be pausable but isn't

**Source**: Code4rena
**Protocol**: Y2k Finance
**Impact**: MEDIUM

**Details**:

Staking is unable to be paused as intended.

### Proof of Concept

StakingRewards.sol inherits pausable and implements the whenNotPaused modifier on stake, but doesn't implement any method to actually pause or unpause the contract. Pausable.sol only implements internal functions, which requires external or public functions to be implemented to wrap them. Since nothing like this has been implemented, the entire pausing system is rendered useless and staking cannot be paused as is intended.

### Recommended Mitigation Steps

Create simple external pause and unpause functions that can be called by owner.

**[MiguelBits (Y2K Finance) disputed](https://github.com/code-423n4/2022-09-y2k-finance-findings/issues/38)** 

**[HickupHH3 (judge) commented](https://github.com/code-423n4/2022-09-y2k-finance-findings/issues/38#issuecomment-1280395938):**
 > Great catch!
> 
> While the contract is taken from Synthetix's StakingRewards; note that they use a [different version of Pausable](https://github.com/Synthetixio/synthetix/blob/develop/contracts/Pausable.sol) that comes with a `setPaused()` function. This is notably absent from OZ's implementation; one has to have the pause and unpause function explicitly created.



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-y2k-finance)

---

### Example 8: [M-03] Contract inherits from `Pausable` but does not expose pausing/unpausing functionality

**Source**: Pashov Audit Group
**Protocol**: Parcel Payroll
**Impact**: MEDIUM

**Details**:

**Impact:**
Low, as methods do not have `whenNotPaused` modifier

**Likelihood:**
High, as it is certain that contract can't be paused at all

**Description**

The `Organizer` smart contract inherits from OpenZeppelin's `Pausable` contract, but the `_pause` and `_unpause` methods are not exposed externally to be callable and also no method actually uses the `whenNotPaused` modifier. This shows that `Pausable` was used incorrectly and is possible to give out a false sense of security when actually contract is not pausable at all.

**Recommendations**

Either remove `Pausable` from the contract or add `whenNotPaused` modifier to the methods that you want to be safer and also expose the `_pause` and `_unpause` methods externally with access control.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-02-01-Parcel Payroll.md)

---

### Example 9: M-3: The protocol shouldn't charge interests when paused

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/234 

## Found by 
hansfriese, rvierdiiev



## Summary
The protocol charges interest from users using `virtualPrice` and it increases when the protocol is paused.

As a result, users would be forced to pay more interests and experience an unexpected liquidation.

## Vulnerability Detail
The protocol has 3 kinds of the vault and each one has `pause/unpause` option by `pausers`.

Also, each collateral would be paused using `CollateralBook.pauseCollateralType()`.

But it updates the `virtualPrice` during the paused period and the below scenarios would be possible.

#### Scenario 1
1. A user `Alice` opened a loan using some collaterals.
2. The vault was paused for a while for some unexpected reason.
3. Meanwhile, her loan was changed to a `liquidatable` one but she can't add collaterals(or close the loan) in the paused state.
4. After the protocol is unpaused, she's trying to protect her loan by adding collaterals but `Bob` can liquidate her loan with front running.
5. Even if her loan isn't liquidated, she should pay interests during the paused period and it's not fair for her.

#### Scenario 2
1. A user `Alice` opened a loan with `minOpeningMargin = 101%`.
2. After the protocol was paused for some reason, the admin decided to change `minOpeningMargin = 105%`.
3. `Alice` wants to close her loan before it's applied because it's too high for her but she can't because it's paused.
4. After the new `minOpenin

*[Content truncated...]*

---

### Example 10: M-3: User withdrawals are dependent on admin actions

**Source**: Sherlock
**Protocol**: Opyn Crab Netting
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-opyn-judging/issues/83 

## Found by 
Deivitto, dipp, Jeiwan, thec00n

## Summary
Users can deposit USDC and Crabv2 tokens at any time, but there are limitations around withdrawals. Users could have permanently locked up their funds if specific owner actions are not triggered. 

## Vulnerability Detail
The owner can call `toggleAuctionLive()` and prevent any withdrawals from occurring. User withdrawals are only enabled again when the owner calls `withdrawAuction()` or `depositAuction()`. If the owner loses their key or becomes malicious and never calls these functions, then the users have no way of withdrawing their funds. 

## Impact
Users could get their funds locked up in the `Netting` contract without a way to withdraw them again.

## Code Snippet
https://github.com/sherlock-audit/2022-11-opyn/blob/main/crab-netting/src/CrabNetting.sol#L276-L283

https://github.com/sherlock-audit/2022-11-opyn/blob/main/crab-netting/src/CrabNetting.sol#L321-L327

https://github.com/sherlock-audit/2022-11-opyn/blob/main/crab-netting/src/CrabNetting.sol#L223-L226

## Tool used
Manual Review

## Recommendation
Lock up times are necessary for the system to work but users should always be able to withdraw their funds eventually without any dependecy of the owner.  When users deposit tokens, a meaningful expiry timestamp should be set by the contract. Before the expiry deposits are locked and the funds can be used during auctions. After expiry de

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 10
- Examples shown: 10
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## blacklisted-patterns.md
# Blacklisted Security Patterns

## Overview

**Frequency**: 16 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 11 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Spearbit, Cyfrin, ConsenSys

---

## Detection Checklist

- [ ] Check for blacklisted vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: OrderBook Denial of Service leveraging blacklistable tokens like USDC

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context
- **Audit Commit**: `OrderBook.sol#L649-L666`
- **Dev Commit**: `OrderBook.sol#L687-L706`

## Description
The issue was spotted while analyzing additional impact and fix for 67. Proof of concept checked with the original audit commit: `28062f477f571b38fe4f8455170bd11094a71862` and the newest available commit from the dev branch: `2ed4370b5de9cec5c455f5485358db194f093b01`.

Due to the architectural decision that implements the orders queue as a cyclic buffer, the `OrderBook` starts to overwrite stale orders after reaching `MAX_ORDERS` (~32k) for a given price point. If an order was never claimed, or it is broken and cannot be claimed, it becomes impossible to place a new order in the queue. This issue arises because it is not possible to finalize the stale order and deliver the underlying assets, which is necessary when placing a new order and replacing a stale order.

Effectively, this issue can be used to block the main functionality of the `OrderBook`, so placing new orders for a given price point. Only a single broken order per price-point is enough to trigger this condition. The issue will not be immediately visible as it requires the cyclic buffer to make a full circle and encounter the broken order.

The proof of concept in `SecurityAuditTests.sol` attachment implements a simple scenario where a USDC-like mock token is used:

1. Mallory creates one ASK order at some price point (to sell X base tokens for Y quoteTokens).
2. Mallory 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 2: [H-02] DoS: Blacklisted user may prevent withdrawExcessRewards()

**Source**: Code4rena
**Protocol**: FactoryDAO
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-05-factorydao/blob/db415804c06143d8af6880bc4cda7222e5463c0e/contracts/PermissionlessBasicPoolFactory.sol#L242-L256
https://github.com/code-423n4/2022-05-factorydao/blob/db415804c06143d8af6880bc4cda7222e5463c0e/contracts/PermissionlessBasicPoolFactory.sol#L224-L234


## Vulnerability details

## Impact

If one user becomes blacklisted or otherwise cannot be transferred funds in any of the rewards tokens or the deposit token then they will not be able to call `withdraw()` for that token.

The impact of one user not being able to call `withdraw()` is that the owner will now never be able to call `withdrawExcessRewards()` and therefore lock not only the users rewards and deposit but also and excess rewards attributed to the owner.

Thus, one malicious user may deliberately get them selves blacklisted to prevent the owner from claiming the final rewards. Since the attacker may do this with negligible balance in their `deposit()` this attack is very cheap.

## Proof of Concept

It is possible for `IERC20(pool.rewardTokens[i]).transfer(receipt.owner, transferAmount);` to fail for numerous reasons. Such as if a user has been blacklisted (in certain ERC20 tokens) or if a token is paused or there is an attack and the token is stuck.

This will prevent `withdraw()` from being called.

```solidity
        for (uint i = 0; i < rewards.length; i++) {
            pool.rewardsWeiClaimed[i] += rewards[i];
            pool.rewardFunding[i] -

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-factorydao)

---

### Example 3: H-4: Lender force Loan become default

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/23 

## Found by 
hansfriese, 0x52, wagmi, IllIllI, bin2chen, Zarf, dipp, libratus, simon135, Trumpero, zaskoh, TrungOre, cccz

## Summary
in ```repay()``` directly transfer the debt token to Lender, but did not consider that Lender can not accept the token (in contract blacklist), resulting in repay() always revert, and finally the Loan can only expire, Loan be default

## Vulnerability Detail
The only way for the borrower to get the collateral token back is to repay the amount owed via repay(). Currently in the repay() method transfers the debt token directly to the Lender.
This has a problem:
 if the Lender is blacklisted by the debt token now, the debtToken.transferFrom() method will fail and the repay() method will always fail and finally the Loan will default.
Example:
Assume collateral token = ETH,debt token = USDC, owner = alice
1.alice call request() to loan 2000 usdc , duration = 1 mon
2.bob call clear(): loanID =1
3.bob transfer loan[1].lender = jack by Cooler.approve/transfer  
  Note: jack has been in USDC's blacklist for some reason before
or bob in USDC's blacklist for some reason now, it doesn't need transfer 'lender')
4.Sometime before the expiration date, alice call repay(id=1) , it will always revert, Because usdc.transfer(jack) will revert
5.after 1 mon, loan[1] default, jack call defaulted() get collateral token

```solidity
    function repay (uint256 loanID, uint256 repaid) external

*[Content truncated...]*

---

### Example 4: H-2: Netting and withdraw auction can be frozen permanently

**Source**: Sherlock
**Protocol**: Opyn Crab Netting
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-opyn-judging/issues/219 

## Found by 
joestakey, bin2chen, hyh, libratus, KingNFT, Zarf, yixxas, cccz

## Summary

An attacker can permanently block the auctions by using a blocked address to fail USDC transfers, which are now required for the auction to proceed.

## Vulnerability Detail

Say Bob knows that one of his addresses is blocked by USDC. He has/can obtain CRAB, which he can transfer to this address.

As withdraw queue requires each transfer call to be successful, this will permanently freezes the functionality, i.e. all future auctions will be blocked.

Knowing that, Bob will block the auctions when it's beneficial to him the most.

## Impact

netAtPrice() and withdrawAuction() will be blocked as long as Bob's withdrawal is queued. There is no way for the owner to manually alter this state.

As auction timing can have material impact on the beneficiaries, the inability to perform netting and withdraw auction will lead to losses for them as Bob will choose the moment to execute the attack to benefit himself at the expense of the participants.

Setting the severity to be high as this is permanent freeze of the core functionality fully controllable by the attacker only.

## Code Snippet

netAtPrice() will be reverting at Bob's withdrawal:

https://github.com/sherlock-audit/2022-11-opyn/blob/main/crab-netting/src/CrabNetting.sol#L389-L419

```solidity
        // process withdraws and send usdc
        i = withdrawsIndex

*[Content truncated...]*

---

### Example 5: Atomic fees delivery susceptible to funds lockout

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- OrderBook.sol#L791-L798 
- OrderBook.sol#L804-L805

## Description
The `collectFees` function delivers the `quoteToken` part of fees as well as the `baseToken` part of fees atomically and simultaneously to both the DAO and the host. In case a single address is blacklisted (e.g., via USDC blacklist feature) or a token in a pair is maliciously configured, it is possible for transfers to one of the addresses to revert, blocking fees delivery.

```solidity
function collectFees() external nonReentrant { // @audit delivers both tokens atomically
    require(msg.sender == _host(), Errors.ACCESS);
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

```solidity
function _collectFees(IERC20 token, uint256 amount) internal { // @audit delivers to both wallets
    uint256 daoFeeAmount = (amount * _DAO_FEE) / _FEE_PRECISION;
    uint256 hostFeeAmount = amount - daoFeeAmount;
    _transferToken(token, _daoTreasury(), daoFeeAmount);
    _transferToken(token, _host(), hostFeeAmount);
}
```

There are multiple scenarios where this situation can occur. For instance, a malicious host might block the function for the DAO to prevent collecting at least the guaranteed valuable `quoteToken`, or a hacked DAO could swap the treasury to an invalid address and renoun

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 6: [M-02] Attacker contract can avoid being blocked by BlockList.sol

**Source**: Code4rena
**Protocol**: FIAT DAO
**Impact**: MEDIUM

**Details**:

_Submitted by JohnSmith, also found by ayeslick, reassor, rokinot, and scaraven_

To block an address it must pass the `isContract(address)` check:<br>
<https://github.com/code-423n4/2022-08-fiatdao/blob/main/contracts/features/Blocklist.sol#L25>

    contracts/features/Blocklist.sol
    25:         require(_isContract(addr), "Only contracts");

Which just checks code length at the address provided.

    contracts/features/Blocklist.sol
    37:     function _isContract(address addr) internal view returns (bool) {
    38:         uint256 size;
    39:         assembly {
    40:             size := extcodesize(addr)
    41:         }
    42:         return size > 0;
    43:     }

Attacker can interact with the system and selfdestruct his contract, and with help of CREATE2 recreate it at same address when he needs to interact with the system again.

### Proof of concept

Below is a simple example of salted contract creation, which you can test against `_isContract(address)` function.

```solidity
pragma solidity 0.8.15;

contract BlockList {
    function _isContract(address addr) external view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }
}

contract AttackerContract {
  function destroy() external {
    selfdestruct(payable(0));
  }
}

contract AttackerFactory {
    function deploy() external returns (address) {
        return address(new AttackerContract{salt: bytes32("123")}());
    }


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-fiatdao)

---

### Example 7: H-1: Bypass the blacklist restriction because the blacklist check is not done when minting or burning

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

### Example 8: [M-15]  Blocklisting in payment ERC20 can cause rented NFT to be stuck in Safe

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

When a rental is stopped, [`Stop.stopRent()`](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L265) transfers the rented NFT back from the renter's Safe to the lender's wallet and transfers the ERC20 payments from the payment escrow contract to the respective recipients (depending on the type of rental, those can be the renter, the lender, or both).

To transfer the ERC20 payments, [`PaymentEscrow.settlePayment()`](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L320) is called.

`PaymentEscrow.settlePayment()` will use [`_safeTransfer()`](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L100) (via `_settlePayment()` and `_settlePaymentProRata()` or `_settlePaymentInFull()`) to transfer the ERC20 payments to the recipients:

*   If the rental was a BASE order, the payment is sent to the lender.
*   If the rental was a PAY order and the rental period is over, the payment is sent to the renter.
*   If the rental was a PAY order and the rental period is not over, the payment is split between the lender and the renter.

If either the payment recipient or the payment escrow contract are blocklisted in the payment ERC20, the transfer will fail and `_safeTransfer()` will revert. In this case the rental is not stopped, the rented NFT will still be in the renter's Safe, and the payment w

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 9: Commented-out blacklist check allows restricted transfers

**Source**: Cyfrin
**Protocol**: Yieldfi
**Impact**: MEDIUM

**Details**:

**Description:** In [`PerpetualBond::_update`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/PerpetualBond.sol#L508-L510), the line intended to restrict transfers between non-blacklisted users is currently commented out:

```solidity
function _update(address from, address to, uint256 amount) internal virtual override {
    // Placeholder for Blacklist check
    // require(!IBlackList(administrator).isBlackListed(from) && !IBlackList(administrator).isBlackListed(to), "blacklisted");
```

This effectively disables blacklist enforcement on transfers of `PerpetualBond` tokens.

**Impact:** Blacklisted addresses can freely hold and transfer `PerpetualBond` tokens, bypassing any intended access control or compliance restrictions.

**Recommended Mitigation:** Uncomment the blacklist check in `_update` to enforce transfer restrictions for blacklisted users.

**YieldFi:** Fixed in commit [`a820743`](https://github.com/YieldFiLabs/contracts/commit/a82074332cc1f57eba398100c3a43e8a70a4c8ce)

**Cyfrin:** Verified. Line doing the blacklist check is now uncommented.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-04-24-cyfrin-yieldfi-v2.0.md)

---

### Example 10: M-6: If the recipient is added to the USDC blacklist, then cancel() does not work

**Source**: Sherlock
**Protocol**: NounsDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-nounsdao-judging/issues/37 

## Found by 
Zarf, joestakey, cccz, bin2chen

## Summary
cancel() will send the vested USDC to the recipient, if the recipient is added to the USDC blacklist, then cancel() will not work

## Vulnerability Detail
When cancel() is called, it sends the vested USDC to the recipient and cancels future payments.
Consider a scenario where if the payer intends to call cancel() to cancel the payment stream, a malicious recipient can block the address from receiving USDC by adding it to the USDC blacklist (e.g. by doing something malicious with that address, etc.), which prevents the payer from canceling the payment stream and withdrawing future payments 
```solidity
    function cancel() external onlyPayerOrRecipient {
        address payer_ = payer();
        address recipient_ = recipient();
        IERC20 token_ = token();

        uint256 recipientBalance = balanceOf(recipient_);

        // This zeroing is important because without it, it's possible for recipient to obtain additional funds
        // from this contract if anyone (e.g. payer) sends it tokens after cancellation.
        // Thanks to this state update, `balanceOf(recipient_)` will only return zero in future calls.
        remainingBalance = 0;

        if (recipientBalance > 0) token_.safeTransfer(recipient_, recipientBalance);
```
## Impact
A malicious recipient may prevent the payer from canceling the payment stream and withdrawing futu

*[Content truncated...]*

---

### Example 11: transferFrom() Lacks notBlackListed Modifier on the Spender msg.sender âœ“Â Fixed

**Source**: ConsenSys
**Protocol**: USDKG
**Impact**: MEDIUM

**Details**:

#### Resolution

Fixed in [commit 0d22c5326e21541df0c718db98004d5a475aa2ea](https://github.com/USDkg/USDkg/commit/0d22c5326e21541df0c718db98004d5a475aa2ea) by putting the `notBlackListed` modifier on `msg.sender` in the `transferFrom()` function as well.


#### Description

The USDKG token has functionality to blacklist users from using it. For example, a `notBlackListed` modifier exists to verify that a user does not belong to a blacklisted list:

**contracts/USDKG.sol:L86-L92**

```
/**
 * @dev Modifier to make a function callable only when sender is not blacklisted.
 */
modifier notBlackListed(address sender) {
    require(!isBlackListed[sender], "user blacklisted");
    _;
}

```

This is present on functions `transfer()` and `transferFrom()` where it is checking the `msg.sender` and `_from` addresses respectively:

**contracts/USDKG.sol:L103**

```
function transfer(address _to, uint256 _value) public whenNotPaused notBlackListed(msg.sender) returns (bool) {

```

**contracts/USDKG.sol:L122**

```
function transferFrom(address _from, address _to, uint256 _value) public whenNotPaused notBlackListed(_from) returns (bool) {

```

However, in the case of `transferFrom()` it would also be valuable to check blacklisting against the spender, i.e. `msg.sender` as well. That is because a malicious or a compromised spender who received approval from a victim may be identified as an attacker prior to them executing, or perhaps continuing the execution of, exploits. For example, one

*[Content truncated...]*

**Reference**: [View Original Finding](https://diligence.consensys.io/audits/2025/01/usdkg/)

---

### Example 12: M-1: Blacklisted accounts can still transact.

**Source**: Sherlock
**Protocol**: Telcoin Platform Audit Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-telcoin-platform-audit-update-judging/issues/4 

## Found by 
0xkmg, Krace, Tendency, ZanyBonzy, ZdravkoHr., blutorque, bughuntoor, cawfree, merlin, neocrao, sa9933, smbv-1923, turvec
## Summary

Accounts that have been blacklisted by the [`BLACKLISTER_ROLE`](https://github.com/sherlock-audit/2024-02-telcoin-platform-audit-update/blob/21920190e0772afa18e7f856a036fea3ef5b9635/telcoin-contracts/contracts/util/abstract/Blacklist.sol#L32) continue to transact normally.

## Vulnerability Detail

Currently, the only real effect of blacklisting an account is the seizure of [`Stablecoin`](https://github.com/sherlock-audit/2024-02-telcoin-platform-audit-update/blob/main/telcoin-contracts/contracts/stablecoin/Stablecoin.sol) funds:

```solidity
/**
 * @notice Overrides Blacklist function to transfer balance of a blacklisted user to the caller.
 * @dev This function is called internally when an account is blacklisted.
 * @param user The blacklisted user whose balance will be transferred.
 */
function _onceBlacklisted(address user) internal override {
  _transfer(user, _msgSender(), balanceOf(user));
}
```

However, following a call to [`addBlackList(address)`](https://github.com/sherlock-audit/2024-02-telcoin-platform-audit-update/blob/21920190e0772afa18e7f856a036fea3ef5b9635/telcoin-contracts/contracts/util/abstract/Blacklist.sol#L72C14-L72C26), the blacklisted account may continue to transact using [`Stablecoin`](https://github.com/she

*[Content truncated...]*

---

### Example 13: Blacklisted STADIUM_ADDRESS address cause fund stuck in the contract forever

**Source**: Codehawks
**Protocol**: Sparkn
**Impact**: MEDIUM

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-08-sparkn/tree/main/src/Distributor.sol#L164">https://github.com/Cyfrin/2023-08-sparkn/tree/main/src/Distributor.sol#L164</a>


## Summary
The vulnerability relates to the immutability of `STADIUM_ADDRESS`. If this address is blacklisted by the token used for rewards, the system becomes unable to make transfers, leading to funds being stuck in the contract indefinitely.

## Vulnerability Details
1. Owner calls `setContest` with the correct `salt`.
2. The Organizer sends USDC as rewards to a pre-determined Proxy address.
3. `STADIUM_ADDRESS` is blacklisted by the USDC operator.
4. When the contest is closed, the Organizer calls `deployProxyAndDistribute` with the registered `contestId` and `implementation` to deploy a proxy and distribute rewards. However, the call to `Distributor._commissionTransfer` reverts at Line 164 due to the blacklisting.
5. USDC held at the Proxy contract becomes stuck forever.

```solidity
// Findings are labeled with '<= FOUND'
// File: src/Distributor.sol
116:    function _distribute(address token, address[] memory winners, uint256[] memory percentages, bytes memory data)
117:        ...
154:        _commissionTransfer(erc20);// <= FOUND
155:        ...
156:    }
				...
163:    function _commissionTransfer(IERC20 token) internal {
164:        token.safeTransfer(STADIUM_ADDRESS, token.balanceOf(address(this)));// <= FOUND: Blacklisted STADIUM_ADDRESS 

*[Content truncated...]*

---

### Example 14: M-3: Blocklisted address can be used to lock the option token minter's fund

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/81 

## Found by 
Vagner, berndartmueller, bin2chen, caventa, ctf\_sec
## Summary

Blocklisted address can be used to lock the option token minter's fund

## Vulnerability Detail

When deploy a token via the teller contract, the contract validate that [receiver address is not address(0)](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L139)

However, a malicious option token creator can save a seemingly favorable strike price and pick a blocklisted address and set the blocklisted address as receiver

https://github.com/d-xo/weird-erc20#tokens-with-blocklists

> Some tokens (e.g. USDC, USDT) have a contract level admin controlled address blocklist. If an address is blocked, then transfers to and from that address are forbidden.

> Malicious or compromised token owners can trap funds in a contract by adding the contract address to the blocklist. This could potentially be the result of regulatory action against the contract itself, against a single user of the contract (e.g. a Uniswap LP), or could also be a part of an extortion attempt against users of the blocked contract.

then user would see the favorable strike price and mint the option token using payout token for call option or use quote token for put option

However, they can never exercise their option because the transaction would revert when [transferri

*[Content truncated...]*

---

### Example 15: M-4: Blacklisted creditor can block all repayment besides emergency closure

**Source**: Sherlock
**Protocol**: Real Wagmi #2
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-10-real-wagmi-judging/issues/83 

## Found by 
0x52, ArmedGoose, Bauer, tsvetanovv

After liquidity is restored to the LP, accumulated fees are sent directly from the vault to the creditor. Some tokens, such as USDC and USDT, have blacklists the prevent users from sending or receiving tokens. If the creditor is blacklisted for the hold token then the fee transfer will always revert. This forces the borrower to defualt. LPs can recover their funds but only after the user has defaulted and they request emergency closure.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-10-real-wagmi/blob/main/wagmi-leverage/contracts/abstract/LiquidityManager.sol#L306-L315

            address creditor = underlyingPositionManager.ownerOf(loan.tokenId);
            // Increase liquidity and transfer liquidity owner reward
            _increaseLiquidity(cache.saleToken, cache.holdToken, loan, amount0, amount1);
            uint256 liquidityOwnerReward = FullMath.mulDiv(
                params.totalfeesOwed,
                cache.holdTokenDebt,
                params.totalBorrowedAmount
            ) / Constants.COLLATERAL_BALANCE_PRECISION;

            Vault(VAULT_ADDRESS).transferToken(cache.holdToken, creditor, liquidityOwnerReward);

The following code is executed for each loan when attempting to repay. Here we see that each creditor is directly transferred their tokens from the vault. If the creditor is blacklisted for holdToken,

*[Content truncated...]*

---

### Example 16: [M-07] Liquidation failure for traders on USDC blacklist

**Source**: Pashov Audit Group
**Protocol**: GainsNetwork-February
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** High

**Likelihood:** Low

## Description

During the process of liquidating an account, the associated trade is unregistered, and any remaining collateral is returned to the trader. In case liquidation happens, the `tradeValueCollateral` is 0.

        function _unregisterTrade(
            ITradingStorage.Trade memory _trade,
            bool _marketOrder,
            int256 _percentProfit,
            uint256 _closingFeeCollateral,
            uint256 _triggerFeeCollateral
        ) internal returns (uint256 tradeValueCollateral) {
            ...
                if (tradeValueCollateral > collateralLeftInStorage) {
                    vault.sendAssets(tradeValueCollateral - collateralLeftInStorage, _trade.user);
                    _transferCollateralToAddress(_trade.collateralIndex, _trade.user, collateralLeftInStorage);
                } else {
                    _sendToVault(_trade.collateralIndex, collateralLeftInStorage - tradeValueCollateral, _trade.user);
                    _transferCollateralToAddress(_trade.collateralIndex, _trade.user, tradeValueCollateral);
                }

                // 4.2 If collateral in vault, just send collateral to trader from vault
            } else {
                vault.sendAssets(tradeValueCollateral, _trade.user);
            }
        }

However, this process is failed if the trader has been blacklisted by the USDC contract. Specifically, the liquidation attempt fails when trying to transfer a `t

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/GainsNetwork-security-review-February.md)

---

## Statistics

- Total findings analyzed: 16
- Examples shown: 16
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## whitelist-blacklist-match-patterns.md
# Whitelist/Blacklist Match Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 5 | 0 | 0 |

**Common Sources**: Sherlock, Codehawks, Code4rena, Spearbit

---

## Detection Checklist

- [ ] Check for whitelist/blacklist match vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Improve dexAllowlist

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

### Example 2: [M-23] Calling updateNodeRunnerWhitelistStatus function always reverts

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L278-L284
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L684-L692
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L426-L492


## Vulnerability details

## Impact
Calling the `updateNodeRunnerWhitelistStatus` function by the DAO supposes to allow the trusted node runners to use and interact with the protocol when `enableWhitelisting` is set to `true`. However, since calling the `updateNodeRunnerWhitelistStatus` function executes `require(isNodeRunnerWhitelisted[_nodeRunner] != isNodeRunnerWhitelisted[_nodeRunner], "Unnecessary update to same status")`, which always reverts, the DAO is unable to whitelist any trusted node runners. Because none of them can be whitelisted, all trusted node runners cannot call functions like `registerBLSPublicKeys` when the whitelisting mode is enabled. As the major functionalities become unavailable, the protocol's usability becomes much limited, and the user experience becomes much degraded.

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L278-L284
```solidity
    function updateNodeRunnerWhitelistStatus(address _nodeRunner, bool isWhitelisted) external onlyDAO {
        require(_nodeRunner != address(0), "Zero address");
        require(

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 3: Token withdrawal fails until someone manually approves spending

**Source**: Codehawks
**Protocol**: Tadle
**Impact**: HIGH

**Details**:

## Summary

The protocol uses a contract called TokenManager to control a capital pool that stores tokens.

When a user wants to withdraw, the TokenManager needs spender allowance on the capital pool, but this is not checked for, so the withdrawal fails.

## Vulnerability Details

We simulate a user creating an offer, closing it and then trying to withdraw. The withdrawal fails because of zero allowance for the TokenManager as a spender of the capital pool.

```Solidity
function test_token_withdrawal_fails() public {
    // Data for creating an offer, not relevant.
    uint256 points = 1000;
    uint256 amountToken = 1000000 * 1e18;
    uint256 collateralRate = 12000;
    uint256 eachTradeTax = 300;

    vm.startPrank(user);
    preMarktes.createOffer(
        CreateOfferParams(
            marketPlace,
            address(mockUSDCToken),
            points,
            amountToken,
            collateralRate,
            eachTradeTax,
            OfferType.Ask,
            OfferSettleType.Turbo
        )
    );

    // Close the offer.
    address offerAddr = GenerateAddress.generateOfferAddress(0);
    address stockAddr = GenerateAddress.generateStockAddress(0);

    preMarktes.closeOffer(stockAddr, offerAddr);

    tokenManager.withdraw(address(mockUSDCToken), TokenBalanceType.MakerRefund);
    vm.stopPrank();
}
```

> ```Solidity
> â”œâ”€ [8858] UpgradeableProxy::withdraw(MockERC20Token: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a], 4)
> â”‚   â”œâ”€ [8339] TokenManager::withdraw(M

*[Content truncated...]*

---

### Example 4: H-1: Bypass the blacklist restriction because the blacklist check is not done when minting or burning

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

### Example 5: M-8: Teller Cannot Be Removed From Callback Contract

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/18 

## Found by 
xiaoming90

## Summary

If a vulnerable Teller is being exploited by an attacker, there is no way for the owner of the Callback Contract to remove the vulnerable Teller from their Callback Contract.

## Vulnerability Detail

The Callback Contract is missing the feature to remove a Teller. Once a Teller has been added to the whitelist (`approvedMarkets` mapping), it is not possible to remove the Teller from the whitelist.

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseCallback.sol#L59

```solidity
File: BondBaseCallback.sol
56:     /* ========== WHITELISTING ========== */
57: 
58:     /// @inheritdoc IBondCallback
59:     function whitelist(address teller_, uint256 id_) external override onlyOwner {
60:         // Check that the market id is a valid, live market on the aggregator
61:         try _aggregator.isLive(id_) returns (bool live) {
62:             if (!live) revert Callback_MarketNotSupported(id_);
63:         } catch {
64:             revert Callback_MarketNotSupported(id_);
65:         }
66: 
67:         // Check that the provided teller is the teller for the market ID on the stored aggregator
68:         // We could pull the teller from the aggregator, but requiring the teller to be passed in
69:         // is more explicit about which contract is being whitelisted
70:         if (teller_ != address(_aggregator.getTeller(id_))) revert Callback_Teller

*[Content truncated...]*

---

### Example 6: M-11: Auctioneer Cannot Be Removed From The Protocol

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/13 

## Found by 
xiaoming90

## Summary

If a vulnerable Auctioneer is being exploited by an attacker, there is no way to remove the vulnerable Auctioneer from the protocol.

## Vulnerability Detail

The protocol is missing the feature to remove an auctioneer. Once an auctioneer has been added to the whitelist, it is not possible to remove the auctioneer from the whitelist.

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondAggregator.sol#L62

```solidity
File: BondAggregator.sol
62:     function registerAuctioneer(IBondAuctioneer auctioneer_) external requiresAuth {
63:         // Restricted to authorized addresses
64: 
65:         // Check that the auctioneer is not already registered
66:         if (_whitelist[address(auctioneer_)])
67:             revert Aggregator_AlreadyRegistered(address(auctioneer_));
68: 
69:         // Add the auctioneer to the whitelist
70:         auctioneers.push(auctioneer_);
71:         _whitelist[address(auctioneer_)] = true;
72:     }
```

## Impact

In the event that a whitelisted Auctioneer is found to be vulnerable and has been actively exploited by an attacker in the wild, the protocol needs to mitigate the issue swiftly by removing the vulnerable Auctioneer from the protocol. However, the mitigation effort will be hindered by the fact there is no way to remove an Auctioneer within the protocol once it has been whitelisted. Thus, it might not be possible

*[Content truncated...]*

---

### Example 7: M-1: Non-whitelisted tokens cannot be added if the limit of token addresses is filled with whitelisted ones

**Source**: Sherlock
**Protocol**: OpenQ
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-02-openq-judging/issues/530 

## Found by 
rvierdiiev, ast3ros, 0xdeadbeef, RaymondFam, XKET, csanuragjain, HollaDieWaldfee, bin2chen, 0xbepresent, kiki\_dev, unforgiven, Breeje, yixxas, hake, libratus, cergyk, Ruhum, CodeFoxInc, Jeiwan, carrot

## Summary
Non-whitelisted tokens cannot be deposited to a bounty contract if too many whitelisted contracts were deposited.
## Vulnerability Detail
The [DepositManagerV1.fundBountyToken](https://github.com/sherlock-audit/2023-02-openq/blob/main/contracts/DepositManager/Implementations/DepositManagerV1.sol#L36) function allows depositing both whitelisted and non-whitelisted tokens by implementing the following check:
1. if a token is whitelisted, it [can be deposited without restrictions](https://github.com/sherlock-audit/2023-02-openq/blob/main/contracts/DepositManager/Implementations/DepositManagerV1.sol#L45);
1. if a token is not whitelisted, it [cannot be deposited if `openQTokenWhitelist.TOKEN_ADDRESS_LIMIT` tokens have already been deposited](https://github.com/sherlock-audit/2023-02-openq/blob/main/contracts/DepositManager/Implementations/DepositManagerV1.sol#L46-L49).

However, while the token addresses limit requirement is only applied to non-whitelisted tokens, whitelisted tokens also increase the counter of token addresses: both non-whitelisted and whitelisted token addresses are [added to the `tokenAddresses` set](https://github.com/sherlock-audit/2023-02-openq/blob/main/contr

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## update-state-after-admin-action-patterns.md
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
Balancerâ€™s `ManagedPool` uses 32-bit values for `startTime` and `endTime` but does not verify if those values exist within that range. When `endTime` is set to \(2^{32}\), it becomes larger than `startTime`, so the `_require(startTime <= endTime, ...)` statement will not revert. When `endTime` is converted to 32 bits, it will get a value of 0, causing the check in `_calculateWeightChangeProgress()` with `if (currentTime >= endTime)` to be true, thus leading to an immediate weight change.

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


