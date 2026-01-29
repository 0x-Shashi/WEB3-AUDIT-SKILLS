# Reentrancy Security Patterns

## Overview

**Frequency**: 59 occurrences (0.12% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 39 | 20 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, ConsenSys, TrailOfBits

---

## Detection Checklist

- [ ] Check for reentrancy vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-02] Stealing fund by applying reentrancy attack on removeCollateral, startLiquidationAuction, and purchaseLiquidationAuctionNFT

**Source**: Code4rena
**Protocol**: Backed Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L444


## Vulnerability details

## Impact

By applying reentrancy attack involving the functions `removeCollateral`, `startLiquidationAuction`, and `purchaseLiquidationAuctionNFT`, an Attacker can steal large amount of fund.

## Proof of Concept

 - Bob (a malicious user) deploys a contract to apply the attack. This contract is called `BobContract`. Please note that all the following transactions are going to be done in one transaction.
 - BobContract takes a flash loan of 500K USDC.
 - BobContract buys 10 NFTs with ids 1 to 10 from collection which are allowed to be used as collateral in this project. Suppose, each NFT has price of almost 50k USDC.
 - BobContract adds those NFTs as collateral by calling the function `addCollateral`. So `_vaultInfo[BobContract][collateral.addr].count = 10`.
```
function addCollateral(IPaprController.Collateral[] calldata collateralArr) external override {
        for (uint256 i = 0; i < collateralArr.length;) {
            _addCollateralToVault(msg.sender, collateralArr[i]);
            collateralArr[i].addr.transferFrom(msg.sender, address(this), collateralArr[i].id);
            unchecked {
                ++i;
            }
        }
    }
```
https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L98
 - BobContract borrows the max allowed amount of `PaprToken` that is

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-backed)

---

### Example 2: [H-01] Reentrancy in buy function for ERC777 tokens allows buying funds with considerable discount

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L95><br>
<https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L137><br>
<https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L172><br>
<https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L203>

Current implementation of functions `add`, `remove`, `buy` and `sell` first transfer fractional tokens, and then base tokens.

If this base token is ERC777 (extension of ERC20), we can call this function without updating the base token balance, but updating the fractional token balance.

### Impact

Allows to drain funds of a pairs which implements an ERC-777 token.

### Proof of Concept

```diff
function buy(uint256 outputAmount, uint256 maxInputAmount) public payable returns (uint256 inputAmount) {
    // *** Checks *** //

    // check that correct eth input was sent - if the baseToken equals address(0) then native ETH is used
    require(baseToken == address(0) ? msg.value == maxInputAmount : msg.value == 0, "Invalid ether input");

    // calculate required input amount using xyk invariant
+   @audit Use current balances
    inputAmount = buyQuote(outputAmount);

    // check that the required amount of base tokens is less than the max amount
    require(inputAmount <= maxInputAmount, "Slippage: amount in");

    // *** Eff

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-caviar)

---

### Example 3: Too generic calls in GenericBridgeFacet allow stealing of tokens

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
- Ability to call the LiFi Diamond itself via functions that don’t have `nonReentrant`.
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

### Example 4: Re-entrancy issue for ERC1155 ✓ Fixed

**Source**: ConsenSys
**Protocol**: Bridge Mutual
**Impact**: HIGH

**Details**:

#### Resolution



Addressed by moving `isNFTDistributed = true;` before the token transfers and only transferring tokens to the message sender.


#### Description


ERC1155 tokens have callback functions on some of the transfers, like `safeTransferFrom`, `safeBatchTransferFrom`. During these transfers, the `IERC1155ReceiverUpgradeable(to).onERC1155Received` function is called in the `to` address.


For example, `safeTransferFrom` is used in the `LiquidityMining` contract:


**code/contracts/LiquidityMining.sol:L204-L224**



```
function distributeAllNFT() external {
    require(block.timestamp > getEndLMTime(),
        "2 weeks after liquidity mining time has not expired");
    require(!isNFTDistributed, "NFT is already distributed");

    for (uint256 i = 0; i < leaderboard.length; i++) {
        address[] memory \_groupLeaders = groupsLeaders[leaderboard[i]];

        for (uint256 j = 0; j < \_groupLeaders.length; j++) {
            \_sendNFT(j, \_groupLeaders[j]);
        }
    }

    for (uint256 i = 0; i < topUsers.length; i++) {
        address \_currentAddress = topUsers[i];
        LMNFT.safeTransferFrom(address(this), \_currentAddress, 1, 1, "");
        emit NFTSent(\_currentAddress, 1);
    }

    isNFTDistributed = true;
}

```
During that transfer, the `distributeAllNFT`  function can be called again and again. So multiple transfers will be done for each user.


In addition to that, any receiver of the tokens can revert the transfer. If that happens, nobody wil

*[Content truncated...]*

**Reference**: [View Original Finding](https://consensys.net/diligence/audits/2021/03/bridge-mutual/)

---

### Example 5: [H-20] Possibly reentrancy attacks in _distributeETHRewardsToUserForToken function

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/SyndicateRewardsProcessor.sol#L51-L73
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L146-L167
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantPoolBase.sol#L66-L90
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/StakingFundsVault.sol#L66-L104
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/StakingFundsVault.sol#L110-L143
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/StakingFundsVault.sol#L314-L340


## Vulnerability details

### Author: rotcivegaf

### Impact

The root of the problem are in the `_distributeETHRewardsToUserForToken` who makes a call to distribute the ether rewards. With this call the recipient can execute an reentrancy attack calling several times the different function to steal founds or take advantage of other users/protocol

### Proof of Concept

This functions use the `_distributeETHRewardsToUserForToken`:

#### [`beforeTokenTransfer`, **GiantMevAndFeesPool** contract](https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 6: [H-16] Reentrancy vulnerability in GiantMevAndFeesPool.withdrawETH

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

GiantMevAndFeesPool.withdrawETH calls lpTokenETH.burn, then GiantMevAndFeesPool.beforeTokenTransfer, followed by a call to \_distributeETHRewardsToUserForToken sends ETH to the user, which allows the user to call any function in the fallback. While GiantMevAndFeesPool.withdrawETH has the nonReentrant modifier, GiantMevAndFeesPool.claimRewards does not have the nonReentrant modifier.<br>
When GiantMevAndFeesPool.claimRewards is called in GiantMevAndFeesPool.withdrawETH, the idleETH is reduced but the ETH is not yet sent to the user, which increases totalRewardsReceived and accumulatedETHPerLPShare, thus making the user receive more rewards when calling GiantMevAndFeesPool.claimRewards.

### Proof of Concept

<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantPoolBase.sol#L52-L64>

### Recommended Mitigation Steps

Change to

```diff
function withdrawETH(uint256 _amount) external nonReentrant {
    require(_amount >= MIN_STAKING_AMOUNT, "Invalid amount");
    require(lpTokenETH.balanceOf(msg.sender) >= _amount, "Invalid balance");
    require(idleETH >= _amount, "Come back later or withdraw less ETH");

-  idleETH -= _amount;

    lpTokenETH.burn(msg.sender, _amount);
+  idleETH -= _amount;

    (bool success,) = msg.sender.call{value: _amount}("");
    require(success, "Failed to transfer ETH");

    emit LPBurnedForETH(msg.sender, _amount);
}
```

**[vince0656 (Stakehouse) confirmed](https://github.com

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 7: Reentrancy of fee payment can be used to circumvent max mints per wallet check

**Source**: Spearbit
**Protocol**: SeaDrop
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
`SeaDrop.sol#L586`

## Description
In case of a `mintPublic` call, the function `_checkMintQuantity` checks whether the minter has exceeded the parameter `maxMintsPerWallet`, among other things. However, re-entrancy in the above fee dispersal mechanism can be used to circumvent the check.

The following is an example contract that can be employed by the `feeRecipient` (assume that `maxMintsPerWallet` is 1):

```solidity
contract MaliciousRecipient {
    bool public startAttack;
    address public token;
    SeaDrop public seaDrop;

    fallback() external payable {
        if (startAttack) {
            startAttack = false;
            seaDrop.mintPublic{value: 1 ether}({
                nftContract: token,
                feeRecipient: address(this),
                minterIfNotPayer: address(this),
                quantity: 1
            });
        }
    }

    // Call `attack` with at least 2 ether.
    function attack(SeaDrop _seaDrop, address _token) external payable {
        token = _token;
        seaDrop = _seaDrop;
        startAttack = true;
        _seaDrop.mintPublic{value: 1 ether}({
            nftContract: _token,
            feeRecipient: address(this),
            minterIfNotPayer: address(this),
            quantity: 1
        });
        token = address(0);
        seaDrop = SeaDrop(address(0));
    }
}
```

This is especially problematic when the parameter `PublicDrop.restrictFeeRecipients` is

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Seadrop-Spearbit-Security-Review.pdf)

---

### Example 8: Malicious manager could cause Vault funds to be inaccessible

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

### Example 9: [H-01] Re-entrancy in settleAuction allow stealing all funds

**Source**: Code4rena
**Protocol**: Kuiper
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

Note that the `Basket` contract approved the `Auction` contract with all tokens and the `settleAuction` function allows the auction bonder to transfer all funds out of the basket to themselves.
The only limiting factor is the check afterwards that needs to be abided by. It checks if enough tokens are still in the basket after settlement:

```
// this is the safety check if basket still has all the tokens after removing arbitrary amounts
for (uint256 i = 0; i < pendingWeights.length; i++) {
    uint256 tokensNeeded = basketAsERC20.totalSupply() * pendingWeights[i] * newRatio / BASE / BASE;
    require(IERC20(pendingTokens[i]).balanceOf(address(basket)) >= tokensNeeded);
}
```

The bonder can pass in any `inputTokens`, even malicious ones they created.
This allows them to re-enter the `settleAuction` multiple times for the same auction.

Calling this function at the correct time (such that `bondTimestamp - auctionStart` makes `newRatio < basket.ibRatio()`), the attacker can drain more funds each time, eventually draining the entire basket.

## POC
Assume that the current `basket.ibRatio` is `1e18` (the initial value).
The basket publisher calls `basket.publishNewIndex` with some tokens and weights.
For simplicity, assume that the pending `tokens` are the same as tokens as before, only the weights are different, i.e., this would just rebalance the portfolio.
The function call then starts the auction.

The important step to note is t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-defiprotocol)

---

### Example 10: [H-05] Reentrancy in LiquidStakingManager.sol#withdrawETHForKnow leads to loss of fund from smart wallet

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/LiquidStakingManager.sol#L435
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/LiquidStakingManager.sol#L326
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/LiquidStakingManager.sol#L340
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/LiquidStakingManager.sol#L347


## Vulnerability details

## Impact

Reentrancy in LiquidStakingManager.sol#withdrawETHForKnow leads to loss of fund from smart wallet

## Proof of Concept

the code below violates the check effect pattern, the code banned the public key to mark the public key invalid to not let the msg.sender withdraw again after sending the ETH.

```solidity
    /// @notice Allow node runners to withdraw ETH from their smart wallet. ETH can only be withdrawn until the KNOT has not been staked.
    /// @dev A banned node runner cannot withdraw ETH for the KNOT. 
    /// @param _blsPublicKeyOfKnot BLS public key of the KNOT for which the ETH needs to be withdrawn
    function withdrawETHForKnot(address _recipient, bytes calldata _blsPublicKeyOfKnot) external {
        require(_recipient != address(0), "Zero address");
        require(isBLSPublicKeyBanned(_blsPublicKeyOfKnot) == false,

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 11: [H-11] Protocol insolvent - Permanent freeze of funds

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/LiquidStakingManager.sol#L326><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/LiquidStakingManager.sol#L934><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/LiquidStakingManager.sol#L524><br>

*   Permanent freeze of funds - users who deposited ETH for staking will not be able to receive their funds, rewards or rotate to another token. The protocol becomes insolvent, it cannot pay anything to the users.
*   Protocol's LifecycleStatus state machine is broken

Other impacts:

*   Users deposit funds to an unstakable validator (node runner has already took out his funds)

Impact is also on the Giant Pools that give liquidity to the vaults.

A competitor or malicious actor can cause bad PR for the protocol by causing permanent freeze of user funds at LSD stakehouse.

### Proof of Concept

There are two main bugs that cause the above impact:

1.  Reentrancy bug in `withdrawETHForKnot` function in `LiquidStakingManager.sol`
2.  Improper balance check in `LiquidStakingManager.sol` for deposited node runner funds.

For easier reading and understanding, please follow the below full attack flow diagram when reading through the explanation.

    ┌───────────┐               ┌───────────┐            ┌───────────┐     

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 12: [H-10] BathToken.sol#_deposit() attacker can mint more shares with re-entrancy from hookable tokens

**Source**: Code4rena
**Protocol**: Rubicon
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/rubiconPools/BathToken.sol#L557-L568


## Vulnerability details

`BathToken.sol#_deposit()` calculates the actual transferred amount by comparing the before and after balance, however, since there is no reentrancy guard on this function, there is a risk of re-entrancy attack to mint more shares.

Some token standards, such as ERC777, allow a callback to the source of the funds (the `from` address) before the balances are updated in `transferFrom()`. This callback could be used to re-enter the function and inflate the amount.

https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/rubiconPools/BathToken.sol#L557-L568

```solidity
function _deposit(uint256 assets, address receiver)
    internal
    returns (uint256 shares)
{
    uint256 _pool = underlyingBalance();
    uint256 _before = underlyingToken.balanceOf(address(this));

    // **Assume caller is depositor**
    underlyingToken.transferFrom(msg.sender, address(this), assets);
    uint256 _after = underlyingToken.balanceOf(address(this));
    assets = _after.sub(_before); // Additional check for deflationary tokens
    ...
```

### PoC

With a ERC777 token by using the ERC777TokensSender `tokensToSend` hook to re-enter the `deposit()` function.

Given: 

-   `underlyingBalance()`: `100_000e18 XYZ`.
-   `totalSupply`: `1e18`

The attacker can create a contra

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-rubicon)

---

### Example 13: [H-13] Possible reentrancy and fund theft in withdrawDETH() of GiantSavETHVaultPool because there is no whitelist check for user provided Vaults and there is no reentrancy defense

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantSavETHVaultPool.sol#L62-L102


## Vulnerability details

## Impact
Function `withdrawDETH()` in `GiantSavETHVaultPool` allows a user to burn their giant LP in exchange for dETH that is ready to withdraw from a set of savETH vaults. This function make external calls to user provided addresses without checking those addresses and send increased dETH balance of contract during the call to user. user can provide malicious addresses to contract and then took the execution flow during the transaction and increase dETH balance of contract by other calls and make contract to transfer them to him.

## Proof of Concept
This is `withdrawDETH()` in `GiantSavETHVaultPool`  code:
```
    /// @notice Allow a user to burn their giant LP in exchange for dETH that is ready to withdraw from a set of savETH vaults
    /// @param _savETHVaults List of savETH vaults being interacted with
    /// @param _lpTokens List of savETH vault LP being burnt from the giant pool in exchange for dETH
    /// @param _amounts Amounts of giant LP the user owns which is burnt 1:1 with savETH vault LP and in turn that will give a share of dETH
    function withdrawDETH(
        address[] calldata _savETHVaults,
        LPToken[][] calldata _lpTokens,
        uint256[][] calldata _amounts
    ) external {
        uint256 numOfVaults = _savETHVaults.length;
        require(num

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 14: [H-08] Player can mint more fighter NFTs during claim of rewards by leveraging reentrancy on the `claimRewards() function`

**Source**: Code4rena
**Protocol**: AI Arena
**Impact**: HIGH

**Details**:

When a fighting round ends, winners for the current round get picked and allocated respective rewards. These rewards are fighter NFTs that can be claimed by such winners. When you claim your rewards for a round or several rounds, the `numRoundsClaimed` state variable which stores the number of rounds you've claimed for gets updated to reflect your claim and each winner can only ever claim up to the amounts they win for each given round. That means if you try to batch-claim for two given rounds for which you won 2 fighter NFTs, your NFT count after the claim should be whatever your current balance of NFT is plus 2 fighter NFTs.

The issue here is that there's a way to mint additional fighter NFTs on top of the fighter NFTs you're owed for winning even though the `claimRewards` function has implemented a decent system to prevent over-claims. For one, it's relatively complex to spoof a call pretending to be the `_mergingPoolAddress` to mint but a malicious user doesn't need to worry too much about that to mint more fighters; they just need to leverage using a smart contract for engineering a simple reentrancy.

### Proof of Concept

Consider this call path that allows a malicious user to reach this undesired state:

1.  In-session fight round gets finalized.
2.  An admin picks winners for the just finalized round.
3.  Alice, one of the winners is entitled to 2 fighter NFTs just like Bob and decides to claim rewards for the rounds she participated in but keep in mind she joined t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-02-ai-arena)

---

### Example 15: RocketNodeDistributorDelegate - Reentrancy in distribute() allows node owner to drain distributor funds ✓ Fixed

**Source**: ConsenSys
**Protocol**: Rocket Pool Atlas (v1.2)
**Impact**: HIGH

**Details**:

#### Resolution



Fixed in <https://github.com/rocket-pool/rocketpool/tree/77d7cca65b7c0557cfda078a4fc45f9ac0cc6cc6> by implementing a custom reentrancy guard via a new state variable `lock` that is appended to the end of the storage layout. The reentrancy guard is functionally equivalent to the OpenZeppelin implementation. The method was not refactored to give user funds priority over the node share. Additionally, the client provided the following statement:



> 
> We acknowledge this as a critical issue and have solved with a reentrancy guard.
> 
> 
> 



> 
> We followed OpenZeppelin’s design for a reentrancy guard. We were unable to use it directly as it is hardcoded to use storage slot 0 and because we already have deployment of this delegate in the wild already using storage slot 0 for another purpose, we had to append it to the end of the existing storage layout.
> 
> 
> 




#### Description


The `distribute()` function distributes the contract’s balance between the node operator and the user. The node operator is returned their initial collateral, including a fee. The rest is returned to the RETH token contract as user collateral.


After determining the node owner’s share, the contract transfers `ETH` to the node withdrawal address, which can be the configured withdrawal address or the node address. Both addresses may potentially be a malicious contract that recursively calls back into the `distribute()` function to retrieve the node share multiple times until al

*[Content truncated...]*

**Reference**: [View Original Finding](https://consensys.net/diligence/audits/2023/01/rocket-pool-atlas-v1.2/)

---

### Example 16: [H-01] Reentrancy in `MessageProxyForSchain` leads to replay attacks

**Source**: Code4rena
**Protocol**: SKALE
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

The `postIncomingMessages` function calls `_callReceiverContract(fromChainHash, messages[i], startingCounter + 1)` which gives control to a contract that is potentially attacker controlled *before* updating the `incomingMessageCounter`.

```solidity
for (uint256 i = 0; i < messages.length; i++) {
    // @audit re-entrant, can submit same postIncomingMessages again
    _callReceiverContract(fromChainHash, messages[i], startingCounter + 1);
}
connectedChains[fromChainHash].incomingMessageCounter += messages.length;
```

The attacker can re-enter into the `postIncomingMessages` function and submit the same messages again, creating a replay attack.
Note that the `startingCounter` is the way how messages are prevented from replay attacks here, there are no further nonces.

### Proof of Concept

Attacker can submit two cross-chain messages to be executed:

1.  Transfer 1000 USDC
2.  A call to their attacker-controlled contract, could be masked as a token contract that allows re-entrance on `transfer`.

Some node submits the `postIncomingMessages(params)` transaction, transfers 1000 USDC, then calls the attackers contract, who can themself call `postIncomingMessages(params)` again, receive 1000 USDC a second time, and stop the recursion.

### Recommended Mitigation Steps

Add a `messageInProgressLocker` modifier to `postIncomingMessages` as was done in `MessageProxyForMainnet`.

**cstrangedk (SKALE) resolved:**

Resolved via https://github.com/skalenetwork/IM

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-skale)

---

### Example 17: [H-02] The reentrancy vulnerability in _safeMint can allow an attacker to steal all rewards

**Source**: Code4rena
**Protocol**: XDEFI
**Impact**: HIGH

**Details**:

_Submitted by cccz, also found by cmichel, Fitraldys, kenzo, onewayfunction, and tqts_

There is a reentrancy vulnerability in the \_safeMint function
```solidity
function _safeMint(
    address to,
    uint256 tokenId,
    bytes memory _data
) internal virtual {
    _mint(to, tokenId);
    require(
        _checkOnERC721Received(address(0), to, tokenId, _data),
        "ERC721: transfer to non ERC721Receiver implementer"
    );
}
...
function _checkOnERC721Received(
    address from,
    address to,
    uint256 tokenId,
    bytes memory _data
) private returns (bool) {
    if (to.isContract()) {
        try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, _data) returns (bytes4 retval) {
            return retval == IERC721Receiver.onERC721Received.selector;
```
The lock function changes the totalDepositedXDEFI variable after calling the \_safeMint function
```solidity
function lock(uint256 amount_, uint256 duration_, address destination_) external noReenter returns (uint256 tokenId_) {
    // Lock the XDEFI in the contract.
    SafeERC20.safeTransferFrom(IERC20(XDEFI), msg.sender, address(this), amount_);

    // Handle the lock position creation and get the tokenId of the locked position.
    return _lock(amount_, duration_, destination_);
}
...
    function _lock(uint256 amount_, uint256 duration_, address destination_) internal returns (uint256 tokenId_) {
    // Prevent locking 0 amount in order generate many score-less NFTs, even if it is inefficient, 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-xdefi)

---

### Example 18: Reentrancy in `EscrowManager`

**Source**: MixBytes
**Protocol**: EYWA
**Impact**: HIGH

**Details**:

##### Description

OpenZeppelin ERC721 NFT implementations invoke the receiver whenever the `safeTransferFrom()` or `safeMint()` methods are called.

A hacker can exploit this mechanism by triggering a callback from `EscrowManager` during the execution of methods such as `createLock()` (when `_safeMint()` is invoked), `deboost()` (when `safeTransferFrom()` is invoked), and `withdraw()` (also when `safeTransferFrom()` is invoked), especially when the state of `EscrowManager` is inconsistent. This can corrupt storage variables or result in voting power gain.

**Example 1**: Reentrancy in the `deboost()` method with duplicate boosters.

An attacker can exploit a reentrancy vulnerability in the `deboost()` method, manipulating the boosting mechanism to their advantage:
1. The attacker calls the `deboost()` method and passes the same boosting NFT ID multiple times, e.g., `deboost(escrowId, [1,1,1,1,1,1,1,1])`.
2. During the transfer process, the `deboost()` method triggers a callback to the attacker’s contract.
3. Each time the attacker’s contract receives the NFT, it transfers the NFT back to `EscrowManager`.

As a result, the escrow boosting coverage can be reduced to zero, even though other boosting NFTs may still be present and not withdrawn. This makes subsequent calculations inaccurate, disproportionately **inflating** the attacker’s `lockAmount` and voting power.

In the following proof-of-concept (PoC), after the attacker calls `deboost()`, their voting power **increases**

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/EYWA/DAO/README.md#4-reentrancy-in-escrowmanager)

---

### Example 19: [H-01] Possible reentrancy during redemption/swap

**Source**: Code4rena
**Protocol**: Angle Protocol
**Impact**: HIGH

**Details**:

Redeemers might charge more collaterals during redemption/swap by the reentrancy attack.

### Proof of Concept

Redeemers can redeem the agToken for collaterals in `Redeemer` contract and `_redeem()` burns the agToken and transfers the collaterals.

```solidity
    function _redeem(
        uint256 amount,
        address to,
        uint256 deadline,
        uint256[] memory minAmountOuts,
        address[] memory forfeitTokens
    ) internal returns (address[] memory tokens, uint256[] memory amounts) {
        TransmuterStorage storage ts = s.transmuterStorage();
        if (ts.isRedemptionLive == 0) revert Paused();
        if (block.timestamp > deadline) revert TooLate();
        uint256[] memory subCollateralsTracker;
        (tokens, amounts, subCollateralsTracker) = _quoteRedemptionCurve(amount);
        // Updating the normalizer enables to simultaneously and proportionally reduce the amount
        // of stablecoins issued from each collateral without having to loop through each of them
        _updateNormalizer(amount, false);

        IAgToken(ts.agToken).burnSelf(amount, msg.sender); //@audit-info burn agToken

        address[] memory collateralListMem = ts.collateralList;
        uint256 indexCollateral;
        for (uint256 i; i < amounts.length; ++i) {
            if (amounts[i] < minAmountOuts[i]) revert TooSmallAmountOut();
            // If a token is in the `forfeitTokens` list, then it is not sent as part of the redemption process
            if (amounts[

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-dev-test-repo)

---

### Example 20: H-1: H-01 wstETH-ETH Curve LP Token Price can be manipulated to Cause Unexpected Liquidations

**Source**: Sherlock
**Protocol**: Sentiment Update #2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-12-sentiment-judging/issues/7 

## Found by 
Bahurum, GalloDaSballo

## Summary

The wsteETH-ETH LP token is priced via it's [`virtual_price`](https://github.com/sherlock-audit/2022-12-sentiment/blob/main/oracle/src/curve/StableCurveEthOracle.sol#L72)

Through what [Chainalysis called View only Reentrancy](https://chainsecurity.com/heartbreaks-curve-lp-oracles/), we can reduce the value of `virtual_price`, causing the RiskEngine to trigger a liquidation event.

## Vulnerability Detail

Per some testing I made, we know that the Debt for such an account will be denominated in WETH, this price cannot be tampered.

However, the price of the ETH-wstETH LP Token can be manipulated by calling the RiskEngine while reEntering from the `POOL.remove_liquidity` function.

This is possible because the function will send ETH first, before updating it's internal wstETH balances.

To test the maximum impact I simulated borrowing an infinite amount of WETH (by impersonating the GMX Vault).

If that amount of ETH were available on Arbitrum, we can achieve over 10x in price suppression, effectively making any "normal" account instantly liquidatable.

The estimated cost of the attack is 60 BPS of the total ETH used (due to price impact)

## Impact

Because of the price manipulation, we can trigger unfair liquidations to our advantage, because the cost of manipulation is in the 50BPS range, any time a big enough deposit is made, it becomes profitable

*[Content truncated...]*

---

### Example 21: H-7: Signers can bypass checks to add new modules to a safe by abusing reentrancy

**Source**: Sherlock
**Protocol**: Hats
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-hats-judging/issues/41 

## Found by 
obront, roguereddwarf

## Summary

The `checkAfterExecution()` function has checks to ensure that new modules cannot be added by signers. This is a crucial check, because adding a new module could give them unlimited power to make any changes (with no guards in place) in the future. However, by abusing reentrancy, the parameters used by the check can be changed so that this crucial restriction is violated.

## Vulnerability Detail

The `checkAfterExecution()` is intended to uphold important invariants after each signer transaction is completed. This is intended to restrict certain dangerous signer behaviors, the most important of which is adding new modules. This was an issue caught in the previous audit and fixed by comparing the hash of the modules before execution to the has of the modules after.

Before:
```solidity
(address[] memory modules,) = safe.getModulesPaginated(SENTINEL_OWNERS, enabledModuleCount);
_existingModulesHash = keccak256(abi.encode(modules));
```

After:
```solidity
(address[] memory modules,) = safe.getModulesPaginated(SENTINEL_OWNERS, enabledModuleCount + 1);
if (keccak256(abi.encode(modules)) != _existingModulesHash) {
    revert SignersCannotChangeModules();
}
```
This is further emphasized in the comments, where it is specified:

> /// @notice Post-flight check to prevent `safe` signers from removing this contract guard, changing any modules, or changing the thr

*[Content truncated...]*

---

### Example 22: H-2: Reentrancy in flashAction() allows draining liquidity pools

**Source**: Sherlock
**Protocol**: Arcadia
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-12-arcadia-judging/issues/153 

## Found by 
0xadrii, zzykxx
## Summary
It is possible to drain a liquidity pool/creditor if the pool’s asset is an ERC777 token by triggering a reentrancy flow using flash actions.

## Vulnerability Detail
The following vulnerability describes a complex flow that allows draining any liquidity pool where the underlying asset is an ERC777 token. Before diving into the vulnerability, it is important to properly understand and highlight some concepts from Arcadia that are relevant in order to allow this vulnerability to take place:

- **Flash actions**: flash actions in Arcadia operate in a similar fashion to flash loans. Any account owner will be able to borrow an arbitrary amount from the creditor without putting any collateral as long as the account remains in a healthy state at the end of execution. The following steps summarize what actually happens when `LendingPool.flashAction()` flow is triggered:
    1. The amount borrowed (plus fees) will be minted to the account as debt tokens. This means that the amount borrowed in the flash action **will be accounted as debt** during the whole `flashAction()` execution. If a flash action borrowing 30 tokens is triggered for an account that already has 10 tokens in debt, the debt balance of the account will increase to 40 tokens + fees.
    2. Borrowed asset will be transferred to the `actionTarget`. The `actionTarget` is an **arbitrary address** passed as

*[Content truncated...]*

---

### Example 23: [H-01] Attacker can reenter to mint all the collection supply

**Source**: Code4rena
**Protocol**: NextGen
**Impact**: HIGH

**Details**:

An attacker can reenter the `MinterContract::mint` function, bypassing the `maxCollectionPurchases` check and minting the entire collection supply.

### Proof of Concept

The vulnerability stems from the absence of the [Check Effects Interactions](https://fravoll.github.io/solidity-patterns/checks_effects_interactions.html) pattern. As seen here, `NextGenCore::mint` updates the `tokensMintedAllowlistAddress` and `tokensMintedPerAddress` after making an external call:

```solidity
    // Minting logic is here
    if (phase == 1) {
        tokensMintedAllowlistAddress[_collectionID][_mintingAddress]++;
    } else {
        tokensMintedPerAddress[_collectionID][_mintingAddress]++;
    }
}
```

### Exploitation Steps:

- Attacker calls `MinterContract::mint` with a malicious contract as the receiver.
- The malicious contract executes a crafted `onERC721Received()`.
- `MinterContract::mint` invokes `NextGenCore::mint`, which uses `_safeMint()` internally.
- `_safeMint()` calls `_recipient.onERC721Received()`, leading to the minting of the complete collection supply.

### An example of the attacker `onERC721Received()` implementation:

```solidity
    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) public override returns (bytes4) {
        (, , uint256 circulationSupply, uint256 totalSupply, , ) = nextGenCore
            .retrieveCollectionAdditionalData(1);

        if (circulationSupply == totalSupply)
            return t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-10-nextgen)

---

### Example 24: Reentrancy Vulnerability Allows Draining All Funds

**Source**: SigmaPrime
**Protocol**: Sushi
**Impact**: HIGH

**Details**:

## Description

A reentrancy vulnerability in the function `stakeToken()` allows an attacker to drain the funds of any ERC20 token deposited in the contract.

In `stakeToken()` on line [180], `msg.sender`’s liquidity is updated in the state variable `userStakes`, however the incentive’s total liquidity is not updated until line [202]. In between, on line [194], there is a call to `_claimReward()` which passes execution flow back to the token being transferred. Using a malicious token that can react to transfers, such as an ERC777 token, or a custom attack token, the attacker can reenter the contract in between these two lines and interact with the contract in a partially updated state.

In the partially updated state, `userStake.liquidity` has been increased but the total liquidity of one or more incentives have not been. `userStake.liquidity` is global across all the user’s incentives and is used as a multiplier when rewards are calculated. Therefore, a malicious user may multiply the rewards for unclaimed incentives by an inflated figure and drain tokens.

The steps taken for this attack are as follows, suppose that there are multiple incentives where USDC is the staking token. Bob is the attacker and has created a malicious token contract, ATT.

1. Bob creates an incentive staking USDC for rewards in ATT.
2. Bob deposits some USDC into multiple target incentives and also into his ATT incentive. All target incentives must be staking USDC for some other token. It is these ot

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/sigp/public-audits/blob/master/sushi/bentobox-strategies-staking-contract/review.pdf)

---

### Example 25: Reentrancy risks in interactions with bidAsset

**Source**: TrailOfBits
**Protocol**: Advanced Blockchain
**Impact**: HIGH

**Details**:

## Data Validation

**Type:** Data Validation  
**Target:** contracts/AavePool.sol  

**Difficulty:** Medium  

## Description  
The Bribe Protocol has many reentrancy patterns that may be exploitable if the `bidAsset` ERC20 token is set to an asset with a callback mechanism. Many interactions with the `bidAsset` token do not follow the checks-effects-interactions pattern. If `bidAsset` is set to an asset with a callback mechanism, the failure to use this pattern can lead to exploitable reentrancies.  

For example, the `_bid` function’s use of the reentrant `safeTransferFrom` function allows the caller to execute a double transfer:

```solidity
/// @dev place a bid to proposal specified by `proposalId` with `amount` of bid asset
/// @param proposalId proposal id
/// @param amount amount of bid asset to bid
function _bid (
    uint256 proposalId,
    uint128 amount,
    bool support
) internal virtual {
    require(blockedProposals[proposalId] == false, "PROPOSAL_BLOCKED");
    Bid storage currentBid = bids[proposalId];
    address prevHighestBidder = currentBid.highestBidder;
    uint128 currentHighestBid = currentBid.highestBid;
    uint128 newHighestBid;

    if (prevHighestBidder == address(0)) {
        uint64 endTime = uint64(getAuctionExpiration(proposalId));
        currentBid.endTime = endTime;
    }

    require(currentBid.endTime > block.timestamp, "BID_ENDED");
    // if msg.sender == currentHighestBidder increase the bid amount
    if (prevHighestBidder == msg.se

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/AdvancedBlockchainQ42021.pdf)

---

## Statistics

- Total findings analyzed: 59
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
