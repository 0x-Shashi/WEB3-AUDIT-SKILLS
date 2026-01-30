# Don't update state Security Patterns

## Overview

**Frequency**: 47 occurrences (0.09% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 26 | 21 | 0 | 0 |

**Common Sources**: Code4rena, Spearbit, Sherlock

---

## Detection Checklist

- [ ] Check for don't update state vulnerabilities in all external functions
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

### Example 2: makePayment doesn't properly update stack, so most payments don't pay off debt

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
LienToken.sol#615-635

## Description
As we loop through individual payments in `_makePayment`, each is called with:

```solidity
(newStack, spent) = _payment(
    s,
    stack,
    uint8(i),
    totalCapitalAvailable,
    address(msg.sender)
);
```

This call returns the updated stack as `newStack` but then uses the function argument `stack` again in the next iteration of the loop. The `newStack` value is unused until the final iterate, when it is passed along to `_updateCollateralStateHash()`. This means that the new state hash will be the original state with only the final loan repaid, even though all other loans have actually had payments made against them.

## Recommendation
```solidity
uint256 n = stack.length;
newStack = stack;
for (uint256 i; i < n; ) {
    (newStack, spent) = _payment(
        s,
        - stack,
        newStack,
        uint8(i),
        totalCapitalAvailable,
        address(msg.sender)
    );
```

This fixes the issue above, but the solution must also take into account the fix for the loop within `_payment` outlined here in Issue 134. If you follow the suggestion in that issue, then this function should return an extra value (`elementRemoved`) and use that to dictate whether the loop iterates forward, or remains at the same index for the next run.

The final result should look like:

```solidity
function _makePayment(
    LienStorage storage s,
    Stack[] calldata stack,
    uint256 totalCapitalAvailable
) inte

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 3: LienToken payee not reset on transfer

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Security Analysis Report

## Severity: High Risk

### Context
`LienToken.sol#L303-L313`

### Description
The `payee` and `ownerOf` functionalities are detached, meaning that owners may set a `payee`, and the owner may transfer the `LienToken` to a new owner without affecting the `payee`. The `payee` does not reset upon transfer.

### Exploit Scenario
- Owner of a `LienToken` sets themselves as `payee`.
- Owner of `LienToken` sells the lien to a new owner.
- New owner does not update `payee`.
- Payments go to the address set by the old owner.

### Recommendation
Reset `payee` on transfer.

```solidity
function transferFrom(
    address from,
    address to,
    uint256 id
) public override(ERC721, IERC721) {
    LienStorage storage s = _loadLienStorageSlot();
    if (s.lienMeta[id].atLiquidation) {
        revert InvalidState(InvalidStates.COLLATERAL_AUCTION);
    }
    + delete s.lienMeta[id].payee;
    + emit PayeeChanged(id, address(0));
    super.transferFrom(from, to, id);
}
```

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 4: stateHash isn't updated by buyoutLien function

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Security Issue Report

## Severity
**High Risk**

## Context
LienToken.sol#L102-187

## Description
We never update the collateral state hash anywhere in the `buyoutLien` function. As a result, once all checks are passed, payment will be transferred from the buyer to the seller, but the seller will retain ownership of the lien in the system's state.

## Recommendation
We should save the return value of the `_replaceStackAtPositionWithNewLien` function call and use it to call:
```solidity
s.collateralStateHash[collateralId] = keccak256(abi.encode(newUpdatedStack));
```

## Spearbit
Confirmed, the following commit fixes this issue.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 5: Anyone can take a valid commitment combined with a self-registered private vault to steal funds from any vault without owning any collateral

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context
- `VaultImplementation.sol#L279`
- `VaultImplementation.sol#L227`

## Description
The issue stems from the following check in `VaultImplementation._validateCommitment(params, receiver)`:

```solidity
if (
    msg.sender != holder &&
    receiver != holder &&
    receiver != operator &&
    !ROUTER().isValidVault(receiver) // <-- the problematic condition
) {
    ...
}
```

In this `if` block, if `receiver` is a valid vault, the body of the `if` is skipped. A valid vault is one that has been registered in `AstariaRouter` using `newVault` or `newPublicVault`. So for example, any supplied private vault as a receiver would be allowed here and the call to `_validateCommitment` will continue without reverting, at least in this `if` block.

If we backtrack function calls to `_validateCommitment`, we arrive at three exposed endpoints:
- `commitToLiens`
- `buyoutLien`
- `commitToLien`

A call to `commitToLiens` will end up having the receiver be the `AstariaRouter`. A call to `buyoutLien` will set the receiver as the `recipient()` for the vault, which is either the vault itself for public vaults or the owner for private vaults. So, we are only left with `commitToLien`, where the caller can set the value for the receiver directly.

A call to `commitToLien` will initiate a series of function calls, and so the `receiver` is only supplied to `_validateCommitment` to check whether it is allowed to be used, and finally when transferring (`safeTransfer`

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 6: Oracle.removeMember could, in the same epoch, allow members to vote multiple times and other members to not vote at all

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
4. At T4, the oracle admin calls `removeMember(m0)`. This operation swaps `m0`s address from the last position of the array with the position of the member being deleted. After this, it pops the last position of the array. The state changes from:
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

### Example 7: [H-04] Unstaking does not update the mapping sETHUserClaimForKnot

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/syndicate/Syndicate.sol#L245


## Vulnerability details

## Impact

If a user stakes some sETH, and after some time decides to unstake some amount of sETH, later s/he will not be qualified or be less qualified to claim ETH on the remaining staked sETH.

## Proof of Concept

Suppose Alice stakes 5 sETH by calling `stake(...)`.
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/syndicate/Syndicate.sol#L203
So, we will have:
 -  `sETHUserClaimForKnot[BLS][Alice] = (5 * 10^18 * accumulatedETHPerFreeFloatingShare) / PRECISION`
 - `sETHStakedBalanceForKnot[BLS][Alice] = 5 * 10^18`
 - `sETHTotalStakeForKnot[BLS] += 5 * 10^18`

Later, Alice decides to unstake 3 sETH by calling `unstake(...)`.
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/syndicate/Syndicate.sol#L245

So, all ETH owed to Alice will be paid:
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/syndicate/Syndicate.sol#L257

Then, we will have:
 -  `sETHUserClaimForKnot[BLS][Alice] = (5 * 10^18 * accumulatedETHPerFreeFloatingShare) / PRECISION`
 - `sETHStakedBalanceForKnot[BLS][Alice] = 2 * 10^18`
 - `sETHTotalStakeForKnot[BLS] -= 3 * 10^18`

It is clear that the mapping `sETHStakedBalanceForKnot` is decreased as expected, but the mapping

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 8: [H-19] withdrawETH() in GiantPoolBase dont call _distributeETHRewardsToUserForToken() or _onWithdraw() which would make users to lose their remaining rewards 

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantPoolBase.sol#L50-L64
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L180-L193


## Vulnerability details

## Impact
Function `_distributeETHRewardsToUserForToken()` is used to distribute remaining reward of user and it's called in `_onWithdraw()` of `GiantMevAndFeesPool`. but function `withdrawETH()` in `GiantPoolBase` don't call either of them and burn user giant LP token balance so if user withdraw his funds and has some remaining ETH rewards he would lose those rewards because his balance set to zero.

## Proof of Concept
This is `withdrawETH()` code in `GiantPoolBase`:
```
    /// @notice Allow a user to chose to burn their LP tokens for ETH only if the requested amount is idle and available from the contract
    /// @param _amount of LP tokens user is burning in exchange for same amount of ETH
    function withdrawETH(uint256 _amount) external nonReentrant {
        require(_amount >= MIN_STAKING_AMOUNT, "Invalid amount");
        require(lpTokenETH.balanceOf(msg.sender) >= _amount, "Invalid balance");
        require(idleETH >= _amount, "Come back later or withdraw less ETH");

        idleETH -= _amount;

        lpTokenETH.burn(msg.sender, _amount);
        (bool success,) = msg.sender.call{value: _amount}("");
        require(succe

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 9: [H-15] User loses remaining rewards in GiantMevAndFeesPool when new deposits happen because _onDepositETH() set claimed[][] to max without transferring user remaining rewards

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L195-L204
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantPoolBase.sol#L33-L48


## Vulnerability details

## Impact
When `depositETH()` is called in giant pool it calls `_onDepositETH()` which calls `_setClaimedToMax()` to make sure new ETH stakers are not entitled to ETH earned by but this can cause users to lose their remaining rewards when they deposits. code should first transfer user remaining rewards when deposit happens.

## Proof of Concept
This is `depositETH()` code in `GiantPoolBase`:
```
    /// @notice Add ETH to the ETH LP pool at a rate of 1:1. LPs can always pull out at same rate.
    function depositETH(uint256 _amount) public payable {
        require(msg.value >= MIN_STAKING_AMOUNT, "Minimum not supplied");
        require(msg.value == _amount, "Value equal to amount");

        // The ETH capital has not yet been deployed to a liquid staking network
        idleETH += msg.value;

        // Mint giant LP at ratio of 1:1
        lpTokenETH.mint(msg.sender, msg.value);

        // If anything extra needs to be done
        _onDepositETH();

        emit ETHDeposited(msg.sender, msg.value);
    }
```
As you can see it increase user `lpTokenETH` balance and then calls `_onDepositETH()`. This is `_onDepositETH()` and `_setCla

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 10: [H-14] Fund lose in function bringUnusedETHBackIntoGiantPool() of GiantSavETHVaultPool ETH gets back to giant pool but the value of idleETH dont increase

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantSavETHVaultPool.sol#L133-L157
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantPoolBase.sol#L24-L25


## Vulnerability details

## Impact
Variable `idleETH` in giant pools is storing total amount of ETH sat idle ready for either withdrawal or depositing into a liquid staking network and whenever a deposit or withdraw happens contract adjust the value of `idleETH` of contract, but in function `bringUnusedETHBackIntoGiantPool()` which brings unused ETH from savETH vault to giant pool the value of `idleETH` don't get increased which would cause those ETH balance to not be accessible for future staking or withdrawing.

## Proof of Concept
This is `bringUnusedETHBackIntoGiantPool()` code in `GiantSavETHVaultPool()`:
```
    /// @notice Any ETH that has not been utilized by a savETH vault can be brought back into the giant pool
    /// @param _savETHVaults List of savETH vaults where ETH is staked
    /// @param _lpTokens List of LP tokens that the giant pool holds which represents ETH in a savETH vault
    /// @param _amounts Amounts of LP within the giant pool being burnt
    function bringUnusedETHBackIntoGiantPool(
        address[] calldata _savETHVaults,
        LPToken[][] calldata _lpTokens,
        uint256[][] calldata _amounts
    ) external {
        uint2

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 11: [H-12] Sender transferring GiantMevAndFeesPool tokens can afterward experience pool DOS and orphaning of future rewards

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L170-L173


## Vulnerability details

## Impact
When a user transfers away GiantMevAndFeesPool tokens, the pool's claimed[] computed is left unchanged and still corresponds to what they had claimed with their old (higher) number of tokens. (See GiantMevAndFeesPool afterTokenTransfer() - no adjustment is made to claimed[] on the from side.) As a result, their claimed[] may be higher than the max amount they could possibly have claimed for their new (smaller) number of tokens. The erroneous claimed value can cause an integer overflow when the claimed[] value is subtracted, leading to inability for this user to access some functions of the GiantMevAndFeesPool - including such things as being able to transfer their tokens (overflow is triggered in a callback attempting to pay out their rewards). These overflows will occur in SyndicateRewardsProcessor's _previewAccumulatedETH() and _distributeETHRewardsToUserForToken(), the latter of which is called in a number of places. When rewards are later accumulated in the pool, the user will not be able to claim certain rewards owed to them because of the incorrect (high) claimed[] value. The excess rewards will be orphaned in the pool.

## Proof of Concept
This patch demonstrates both DOS and orphaned rewards due to the claimed[] error described above. Note that the patch include

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 12: [H-10] GiantMevAndFeesPool.bringUnusedETHBackIntoGiantPool function loses the addition of the idleETH which allows attackers to steal most of eth from the Giant Pool

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantMevAndFeesPool.sol#L126-L138
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantMevAndFeesPool.sol#L176-L178


## Vulnerability details

## Impact
The contract GiantMevAndFeesPool override the function totalRewardsReceived:
```
return address(this).balance + totalClaimed - idleETH;
```
The function totalRewardsReceived is used as the current rewards balance to caculate the unprocessed rewards in the function `SyndicateRewardsProcessor._updateAccumulatedETHPerLP`
```
uint256 received = totalRewardsReceived();
uint256 unprocessed = received - totalETHSeen;
```

The idleETH will be decreased in the function `batchDepositETHForStaking` for sending eth to the staking pool. But the idleETH wont be increased in the function `bringUnusedETHBackIntoGiantPool` which is used to burn lp tokens in the staking pool, and the staking pool will send the eth back to the giant pool. And then because of the diminution of the idleETH, the `accumulatedETHPerLPShare` is added out of thin air. So the attacker can steal more eth from the GiantMevAndFeesPool.

## Proof of Concept
test:
test/foundry/TakeFromGiantPools.t.sol
```
pragma solidity ^0.8.13;

// SPDX-License-Identifier: MIT

import "forge-std/console.sol";
import {GiantPoolTests} from "./GiantPools.t.sol";
import { LPToken } from "../../contracts/liquid-staking/LPToken.sol";

contract TakeFromGiantP

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 13: [H-09] Incorrect accounting in SyndicateRewardsProcessor results in any LP token holder being able to steal other LP tokens holders ETH from the fees and MEV vault

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/SyndicateRewardsProcessor.sol#L63
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/StakingFundsVault.sol#L88


## Vulnerability details

## Impact
The SyndicateRewardsProcessor's internal `_distributeETHRewardsToUserForToken()` function is called from external `claimRewards()` function in the `StakingFundsVault` contract. This function is called by LP Token holders to claim their accumulated rewards based on their LP Token holdings and already claimed rewards.
The accumulated rewards `due` are calculated as `((accumulatedETHPerLPShare * balance) / PRECISION)` reduced by the previous claimed amount stored in `claimed[_user][_token]`. When the ETH is sent to the `_user` the stored value should be increased by the `due` amount. However in the current code base the `claimed[_user][_token]` is set equal to the calculated `due`.

```solidity
function _distributeETHRewardsToUserForToken(
        address _user,
        address _token,
        uint256 _balance,
        address _recipient
    ) internal {
        require(_recipient != address(0), "Zero address");
        uint256 balance = _balance;
        if (balance > 0) {
            // Calculate how much ETH rewards the address is owed / due 
            uint256 due = ((accumulatedETHPerLPShare * balance) / PRECISION) - claime

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 14: [H-06] BringUnusedETHBackIntoGiantPool can cause stuck ether funds in Giant Pool

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantMevAndFeesPool.sol#L126-L138
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantSavETHVaultPool.sol#L137-L158


## Vulnerability details

## Impact
withdrawUnusedETHToGiantPool will withdraw any eth from the vault if staking has not commenced(knot status is INITIALS_REGISTERED), the eth will be drawn successful to the giant pool. However, idleETH variable is not updated. idleETH  is the available ETH for withdrawing and depositing eth for staking. Since there is no other places that updates idleETH other than depositing eth for staking and withdrawing eth, the eth withdrawn from the vault will be stuck forever. 

## Proof of Concept
place poc in GiantPools.t.sol with `import { MockStakingFundsVault } from "../../contracts/testing/liquid-staking/MockStakingFundsVault.sol";`


```solidity
    function testStuckFundsInGiantMEV() public {

        stakingFundsVault = MockStakingFundsVault(payable(manager.stakingFundsVault()));
        address nodeRunner = accountOne; vm.deal(nodeRunner, 4 ether);
        //address feesAndMevUser = accountTwo; vm.deal(feesAndMevUser, 4 ether);
        //address savETHUser = accountThree; vm.deal(savETHUser, 24 ether);
        address victim = accountFour; vm.deal(victim, 1 ether);


        registerSingleBLSPubKey(nodeRunner, blsPubKeyOne, accountFour);

        emit log_address(address(giantFeesAndMevPoo

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 15: [H-01] Making a payment to the protocol with `_dontMint` parameter will result in lost fund for user.

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: HIGH

**Details**:

User will have their funds lost if they tries to pay the protocol with `_dontMint = False`. A payment made with this parameter set should increase the `creditsOf[]` balance of user.

In `_processPayment()`, `creditsOf[_data.beneficiary]` is updated at the end if there are leftover funds. However, If `metadata` is provided and `_dontMint == true`, it immediately returns.
[JBTiered721Delegate.sol#L524-L590](https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/JBTiered721Delegate.sol#L524-L590)

```solidity
  function _processPayment(JBDidPayData calldata _data) internal override {
    // Keep a reference to the amount of credits the beneficiary already has.
    uint256 _credits = creditsOf[_data.beneficiary];
    ...
    if (
      _data.metadata.length > 36 &&
      bytes4(_data.metadata[32:36]) == type(IJB721Delegate).interfaceId
    ) {
      ...
      // Don't mint if not desired.
      if (_dontMint) return;
      ...
    }
    ...
    // If there are funds leftover, mint the best available with it.
    if (_leftoverAmount != 0) {
      _leftoverAmount = _mintBestAvailableTier(
        _leftoverAmount,
        _data.beneficiary,
        _expectMintFromExtraFunds
      );

      if (_leftoverAmount != 0) {
        // Make sure there are no leftover funds after minting if not expected.
        if (_dontOverspend) revert OVERSPENDING();

        // Increment the leftover amount.
        creditsOf[_data.beneficiary] = _lefto

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-juicebox)

---

### Example 16: [H-02] unstake should update exchange rates first

**Source**: Code4rena
**Protocol**: Covalent
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `unstake` function does not immediately update the exchange rates. It first computes the `validatorSharesRemove = tokensToShares(amount, v.exchangeRate)` **with the old exchange rate**.

Only afterwards, it updates the exchange rates (if the validator is not disabled):

```solidity
// @audit shares are computed here with old rate
uint128 validatorSharesRemove = tokensToShares(amount, v.exchangeRate);
require(validatorSharesRemove > 0, "Unstake amount is too small");

if (v.disabledEpoch == 0) {
    // @audit rates are updated here
    updateGlobalExchangeRate();
    updateValidator(v);
    // ...
}
```

## Impact
More shares for the amount are burned than required and users will lose rewards in the end.

## POC
Demonstrating that users will lose rewards:

1. Assume someone staked `1000 amount` and received `1000 shares`, and `v.exchangeRate = 1.0`. (This user is the single staker)
2. Several epochs pass, interest accrues, and `1000 tokens` accrue for the validator, `tokensGivenToValidator = 1000`. User should be entitled to 1000 in principal + 1000 in rewards = 2000 tokens.
3. But user calls `unstake(1000)`, which sets `validatorSharesRemove = tokensToShares(amount, v.exchangeRate) = 1000 / 1.0 = 1000`. **Afterwards**, the exchange rate is updated: `v.exchangeRate += tokensGivenToValidator / totalShares = 1.0 + 1.0 = 2.0`. The staker is updated with `s.shares -= validatorSharesRemove = 0` and `s.staked -= amount = 0`. And the

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-10-covalent)

---

### Example 17: H-9: `moveQuoteToken()` can cause bucket to go bankrupt but it is not reflected in the accounting

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/83 

## Found by 
yixxas

## Summary
Both `removeQuoteToken()` and `moveQuoteToken()` can be used to completely remove all quote tokens from a bucket. When this happens, if at the same time `bucketCollateral == 0 && lpsRemaining != 0`, then the bucket should be declared bankrupt. This update is done in `removeQuoteToken()` but not in `moveQuoteToken()`.

## Vulnerability Detail
`removeQuoteToken()` has the following check to update bankruptcy time when collateral and quote token remaining is 0, but lps is more than 0. `moveQuoteToken()` is however missing this check. Both this functions has the same effects on the `fromBucket` and the only difference is that `removeQuoteToken()` returns the token to `msg.sender` but `moveQuoteToken()` moves the token to another bucket.

```solidity
if (removeParams.bucketCollateral == 0 && unscaledRemaining == 0 && lpsRemaining != 0) {
	emit BucketBankruptcy(params_.index, lpsRemaining);
	bucket.lps            = 0;
	bucket.bankruptcyTime = block.timestamp;
} else {
	bucket.lps = lpsRemaining;
}
```

## Impact
A future depositor to the bucket will get less lps than expected due to depositing in a bucket that is supposedly bankrupt, hence the lps they get will be diluted with the existing ones in the bucket.

## Code Snippet
https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/libraries/external/LenderActions.sol#L359-L365

## Tool used

Manual Review

## Re

*[Content truncated...]*

---

### Example 18: H-1: RewardsManager doesn't delete old bucket snapshot info on unstaking

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/183 

## Found by 
hyh

## Summary

RewardsManager's unstake() use `delete stakes[tokenId_]` to clear old stake state, but `snapshot` is the nested mapping in the `StakeInfo` structure and will not be reset this way as delete operation do not traverse through nested mappings as it lacks key set information.

## Vulnerability Detail

`stakes[tokenId_]` gets written on staking and `mapping(uint256 => BucketState) snapshot` is written for the *current* list of buckets. This means if this list persists and there were no bucket changes it's ok as new values will be overwritten on next stake.

But, if Bob the staker has changed his composition of buckets and his second stake takes place over another set, possibly intersecting with the first one, old part will persist. If then Bob's `positionIndexes = positionManager.getPositionIndexes(tokenId_)` changed after the second stake, say as a result of PositionManager's moveLiquidity(), and indices from the first set were added there, their snapshot values from the first stake will be reused.

## Impact

If Bob knows this it will be straightforward for him to exploit the mechanics, obtaining extra rewards (interest earned will be counted from the first stake time for old positions) at the expense of other stakers.

## Code Snippet

RewardsManager's unstake() deletes `stakes[tokenId_]`:

https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/RewardsManage

*[Content truncated...]*

---

### Example 19: H-5: removeCollateral miss bankrupcy logic and can make future LPs sharing losses with the current ones

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/133 

## Found by 
hyh, Jeiwan, yixxas

## Summary

LenderActions' removeCollateral() do not checks for bucket solvency after it has removed a collateral from there. This can lead to losses for future depositors of the bucket.

## Vulnerability Detail

Bankrupcy check logic now exist in all asset removing functions. That prevent a situation when a bucket defaults, but next LP deposit makes in solvent again and next LP shared losses with the old ones this way without having such intent.

For example, mergeOrRemoveCollateral() calls _removeMaxCollateral() that do check affected bucket for bankrupcy. removeCollateral() do not check for that despite insolvency situation for a bucket can occur after collateral was removed.

## Impact

When bucket defaults, but no bankrupcy is checked and no such flag is set, the next LP depositors have to bail out previous, i.e. have to share their losses.

That's a loss for next LPs by unconditional transfer from them to the previous ones.

As removeCollateral() is a part of base functionality that to be used frequently and bucket defaults can routinely happen, so there is no low probability prerequisites, and given the loss for future bucket depositors, setting the severity to be high.

## Code Snippet

There is no bucket bankrupcy logic in removeCollateral(), i.e. when there is no quote tokens in the bucket, `lpAmount_ < bucketLPs`, but `bucketCollateral <= collateralAmount_`

*[Content truncated...]*

---

### Example 20: TransitionLoanManager.add does not account for accrued interest since last call

**Source**: Spearbit
**Protocol**: Maple Finance
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
`pool-v2::TransitionLoanManager.sol#L74`

## Description
The `TransitionLoanManager.add` advances the domain start but the accrued interest since the last domain start is not accounted for. It therefore wrongly tracks the `_accountedInterest` variable. If `add` is called several times, the accounting will be wrong.

## Recommendation
Consider tracking the accrued interest or ensure that the `MigrationHelper.addLoansToLM` is called only once in the final migration script, adding all loans at the same time.

```solidity
function add(address loan_) external override nonReentrant {
    ...
    uint256 domainStart_ = domainStart;
    + uint256 accruedInterest;
    if (domainStart_ == 0 || domainStart_ != block.timestamp) {
        + accruedInterest = getAccruedInterest();
        domainStart = _uint48(block.timestamp);
    }
    ...
    + _updateIssuanceParams(issuanceRate += newRate_, accountedInterest + accruedInterest);
}
```

This mimics `LoanManager._advanceGlobal` as long as there are no late payments, but that's also the case for `TransitionLoanManager` as one of the preconditions for the migration is that loans have at least 5 days for any payment to be due.

## Discussion
**Maple:** In theory yes, but realistically we'll add all loans atomically. Even in the largest pool, we have around 30 active loans, which is feasible to do in one transaction. This is not an issue since all loans are added atomically, but we can add this functionali

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/MapleV2.pdf)

---

### Example 21: Order owner isn't zeroed after burning

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- `OrderBook.sol#L821-L823`
- `OrderNFT.sol#L78-L82`
- `OrderNFT.sol#L189`

## Description
The order's owner is not zeroed out when the NFT is burnt. As a result, while the `onBurn()` method records the NFT to have been transferred to the zero address, `ownerOf()` still returns the current order's owner. This allows for unexpected behaviour, like being able to call `approve()` and `safeTransferFrom()` functions on non-existent tokens.

A malicious actor could sell such resurrected NFTs on secondary exchanges for profit even though they have no monetary value. Such NFTs will revert on cancellation or claim attempts since `openOrderAmount` is zero.

### Code Example
```solidity
function testNFTMovementAfterBurn() public {
    _createOrderBook(0, 0);
    address attacker2 = address(0x1337);
    // Step 1: make 2 orders to avoid bal sub overflow when moving burnt NFT in step 3
    uint256 orderIndex1 = _createPostOnlyOrder(Constants.BID, Constants.RAW_AMOUNT);
    _createPostOnlyOrder(Constants.BID, Constants.RAW_AMOUNT);
    CloberOrderBook.OrderKey memory orderKey = CloberOrderBook.OrderKey({
        isBid: Constants.BID,
        priceIndex: Constants.PRICE_INDEX,
        orderIndex: orderIndex1
    });
    uint256 tokenId = orderToken.encodeId(orderKey);
    // Step 2: burn 1 NFT by cancelling one of the orders
    vm.startPrank(Constants.MAKER);
    orderBook.cancel(Constants.MAKER, _toArray(orderKey));
    // verify ownership is still mak

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 22: diamondCut() allows re-execution of old updates

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
**File:** LibDiamond.sol  
**Lines:** 112-115

## Description
When `diamondCut()` is executed, `ds.acceptanceTimes[keccak256(abi.encode(_diamondCut, _init, _calldata))]` is not reset to zero. This means the contract owner can rerun the old updates again without any delay by executing the `diamondCut()` function.

Assume the following:
- `diamondCut()` function is executed to update the facet selector with version_2.
- A bug is found in version_2 and it is rolled back.
- The Owner can still execute the `diamondCut()` function, which will again update the facet selector to version 2 since `ds.acceptanceTimes[keccak256(abi.encode(_diamondCut, _init, _calldata))]` is still valid.

## Recommendation
Reset `ds.acceptanceTimes[keccak256(abi.encode(_diamondCut, _init, _calldata))]` to zero as shown below:

```solidity
function diamondCut(
    IDiamondCut.FacetCut[] memory _diamondCut,
    address _init,
    bytes memory _calldata
) internal {
    ...
    if (ds.facetAddresses.length != 0) {
        uint256 time = ds.acceptanceTimes[keccak256(abi.encode(_diamondCut, _init, _calldata))];
        require(time != 0 && time <= block.timestamp, "LibDiamond: delay not elapsed");
    }
    ds.acceptanceTimes[keccak256(abi.encode(_diamondCut, _init, _calldata))] = 0;
    ...
}
```

## Context
**Fix in PR:** 2222.  
**Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 23: _domainSeparatorV4() not updated after name /symbol change

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- `BridgeToken.sol#L58-L63`
- `OZERC20.sol#L382-L388`
- `OZERC20.sol#L348-L369`
- `draft-EIP712.sol`
- `EIP712.sol#L69-L75`
- `EIP712.sol#L100-L102`

## Description
The `BridgeToken` allows updating the name and symbol of a token. However, the `_CACHED_DOMAIN_SEPARATOR` (of EIP712) isn't updated. This means that `permit()`, which uses `_hashTypedDataV4()` and `_CACHED_DOMAIN_SEPARATOR`, still uses the old value. On the other hand, `DOMAIN_SEPARATOR()` is updated. Both, and especially their combination, can give unexpected results.

### BridgeToken.sol
```solidity
function setDetails(string calldata _newName, string calldata _newSymbol) external override onlyOwner {
    // careful with naming convention change here
    token.name = _newName;
    token.symbol = _newSymbol;
    emit UpdateDetails(_newName, _newSymbol);
}
```

### OZERC20.sol
```solidity
function DOMAIN_SEPARATOR() external view override returns (bytes32) {
    // See {EIP712._buildDomainSeparator}
    return keccak256(
        abi.encode(_TYPE_HASH, keccak256(abi.encode(token.name)), _HASHED_VERSION, block.chainid, address(this))
    );
}

function permit(...) ... {
    ...
    bytes32 _hash = _hashTypedDataV4(_structHash);
    ...
}
```

### draft-EIP712.sol
```solidity
import "./EIP712.sol";
```

### EIP712.sol
```solidity
function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
    return ECDSA.toTypedDataHash(_domainSeparatorV4(), structHash

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 24: [M-21] EIP1559 rewards received by syndicate during the period when it has no registered knots can be lost

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L218-L220><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/syndicate/Syndicate.sol#L154-L157><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/syndicate/Syndicate.sol#L597-L607><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/syndicate/Syndicate.sol#L610-L627><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/syndicate/Syndicate.sol#L174-L197>

When the `deRegisterKnotFromSyndicate` function is called by the DAO, the `_deRegisterKnot` function is eventually called to execute `numberOfRegisteredKnots -= 1`. It is possible that `numberOfRegisteredKnots` is reduced to 0. During the period when the syndicate has no registered knots, the EIP1559 rewards that are received by the syndicate remain in the syndicate since functions like `updateAccruedETHPerShares` do not include any logics for handling such rewards received by the syndicate. Later, when a new knot is registered and mints the derivatives, the node runner can call the `claimRewardsAsNodeRunner` function to receive half ot these rewards received by the syndicate during the period when it has no registered knots. Yet, because such rewards are received by the syndicate before the new knot mints the derivatives, the node runner should not be entitled to these rewards. Moreover, due to the issue mentioned in my other f

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 25: [M-15] GiantMevAndFeesPool.previewAccumulatedETH function: accumulated variable is not updated correctly in for loop leading to result that is too low

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L82
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L91


## Vulnerability details

## Impact
The `GiantMevAndFeesPool.previewAccumulatedETH` function ([https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L82](https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L82)) allows to view the ETH that is accumulated by an address.  

However the formula is not correct.  

In each iteration of the foor loop, `accumulated` is assigned a new value ([https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L91](https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L91)) when actually the value should be updated like this:  
```solidity
accumulated += StakingFundsVault(payable(_stakingFundsVaults[i])).batchPreviewAccumulatedETH(
        address(this),
        _lpTokens[i]
    );
```

Obviously the `accumulated` value must be calculated for all stakingFundVaults not only for one st

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

## Statistics

- Total findings analyzed: 47
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

