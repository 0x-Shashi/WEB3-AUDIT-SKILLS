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
Balancer’s `ManagedPool` uses 32-bit values for `startTime` and `endTime` but does not verify if those values exist within that range. When `endTime` is set to \(2^{32}\), it becomes larger than `startTime`, so the `_require(startTime <= endTime, ...)` statement will not revert. When `endTime` is converted to 32 bits, it will get a value of 0, causing the check in `_calculateWeightChangeProgress()` with `if (currentTime >= endTime)` to be true, thus leading to an immediate weight change.

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
- `allowance()` doesn’t limit `withdraw()`
- `enableTradingWithWeights` allows the Treasury to change the pool’s weights even if the swap is not disabled
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
The function `diamondCut()` of `LibDiamond` verifies the signed version of the update parameters. It checks whether the signed version is available and if a sufficient amount of time has passed. However, it doesn’t prevent multiple executions, and the signed version remains valid indefinitely.

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
Typically, the contract’s owner is the account that deploys the contract. As a result, the owner is able to perform certain privileged activities.

However, Owner privileges are numerous and there is no timelock structure in the process of using these privileges.
The Owner is assumed to be an EOA, since the documents do not provide information on whether the Owner will be a multisign structure.

In parallel with the private key thefts of the project owners, which have increased recently, this vulnerability has been stated as medium.

Similar vulnerability;
Private keys stolen:

Hackers have stolen cryptocurrency worth around €552 million from a blockchain project linked to the popular online game Axie Infinity, in one of the largest cryptocurrency heists on record. Security issue : PrivateKey of the project officer was stolen:
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
