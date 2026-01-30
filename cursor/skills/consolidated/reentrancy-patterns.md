# Reentrancy Security Patterns (Consolidated)

> **Critical vulnerability class responsible for the DAO hack ($60M) and countless exploits since.**

---

## Quick Summary

| Attack Type | Description | Severity |
|-------------|-------------|----------|
| Classic Reentrancy | External call before state update allows re-entry | Critical |
| Cross-Function | Attacker re-enters different function sharing state | Critical |
| Cross-Contract | Reentrancy between multiple contracts | Critical |
| Read-Only Reentrancy | View function reads stale state during callback | High |
| ERC777 Callback | tokensReceived/tokensToSend hook exploitation | High |
| ERC721 Callback | onERC721Received hook exploitation | High |
| ERC1155 Callback | onERC1155Received hook exploitation | High |

---

## Detection Strategy

### Code Patterns to Flag
```solidity
// DANGEROUS: External call before state update
function withdraw() external {
    uint amount = balances[msg.sender];
    (bool success,) = msg.sender.call{value: amount}("");  //  External call
    balances[msg.sender] = 0;  //  State update AFTER call = VULNERABLE
}

// SAFE: State update before external call (CEI pattern)
function withdraw() external {
    uint amount = balances[msg.sender];
    balances[msg.sender] = 0;  //  State update FIRST
    (bool success,) = msg.sender.call{value: amount}("");  //  External call AFTER
}
```

### Audit Checklist
- [ ] All external calls happen AFTER state updates (CEI pattern)
- [ ] ReentrancyGuard on ALL external functions, not just obvious ones
- [ ] Check for callbacks: ERC777, ERC721, ERC1155, flash loans
- [ ] Cross-function: Can re-entering function B affect function A's state?
- [ ] Cross-contract: Can external contract callback affect shared state?
- [ ] Read-only: Do view functions return stale data during reentrancy?

### Common Mitigation Patterns
```solidity
// 1. Checks-Effects-Interactions (CEI)
function withdraw() external {
    uint amount = balances[msg.sender];
    require(amount > 0, "No balance");  // Check
    balances[msg.sender] = 0;            // Effect
    payable(msg.sender).transfer(amount); // Interaction
}

// 2. ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Safe is ReentrancyGuard {
    function withdraw() external nonReentrant { ... }
}

// 3. Mutex Lock
bool private locked;
modifier noReentrant() {
    require(!locked, "Reentrant");
    locked = true;
    _;
    locked = false;
}
```

---

## Included Pattern Files

This consolidated file contains full content from:
- reentrancy-patterns.md - Classic reentrancy examples
- read-only-reentrancy-patterns.md - View function exploitation
- cei-patterns.md - Checks-Effects-Interactions violations
- external-call-patterns.md - Dangerous external call patterns
- external-contract-patterns.md - Untrusted external contracts
- call-vs-transfer-patterns.md - ETH transfer method risks
- check-return-value-patterns.md - Unchecked call returns
- transfer-result-check-patterns.md - Transfer success validation
- revert-inside-hook-patterns.md - Callback revert attacks

---

## Real-World Exploits

| Protocol | Loss | Attack Type | Year |
|----------|------|-------------|------|
| The DAO | $60M | Classic reentrancy | 2016 |
| Uniswap/Lendf.Me | $25M | ERC777 reentrancy | 2020 |
| Cream Finance | $130M | Flash loan + reentrancy | 2021 |
| Rari Capital | $80M | Cross-contract reentrancy | 2022 |

---

## Full Pattern Details

---
## reentrancy-patterns.md
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

### Example 4: Re-entrancy issue for ERC1155 Fixed

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

### Example 15: RocketNodeDistributorDelegate - Reentrancy in distribute() allows node owner to drain distributor funds Fixed

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
> We followed OpenZeppelins design for a reentrancy guard. We were unable to use it directly as it is hardcoded to use storage slot 0 and because we already have deployment of this delegate in the wild already using storage slot 0 for another purpose, we had to append it to the end of the existing storage layout.
> 
> 
> 




#### Description


The `distribute()` function distributes the contracts balance between the node operator and the user. The node operator is returned their initial collateral, including a fee. The rest is returned to the RETH token contract as user collateral.


After determining the node owners share, the contract transfers `ETH` to the node withdrawal address, which can be the configured withdrawal address or the node address. Both addresses may potentially be a malicious contract that recursively calls back into the `distribute()` function to retrieve the node share multiple times until al

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
2. During the transfer process, the `deboost()` method triggers a callback to the attackers contract.
3. Each time the attackers contract receives the NFT, it transfers the NFT back to `EscrowManager`.

As a result, the escrow boosting coverage can be reduced to zero, even though other boosting NFTs may still be present and not withdrawn. This makes subsequent calculations inaccurate, disproportionately **inflating** the attackers `lockAmount` and voting power.

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
It is possible to drain a liquidity pool/creditor if the pools asset is an ERC777 token by triggering a reentrancy flow using flash actions.

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

In `stakeToken()` on line [180], `msg.sender`s liquidity is updated in the state variable `userStakes`, however the incentives total liquidity is not updated until line [202]. In between, on line [194], there is a call to `_claimReward()` which passes execution flow back to the token being transferred. Using a malicious token that can react to transfers, such as an ERC777 token, or a custom attack token, the attacker can reenter the contract in between these two lines and interact with the contract in a partially updated state.

In the partially updated state, `userStake.liquidity` has been increased but the total liquidity of one or more incentives have not been. `userStake.liquidity` is global across all the users incentives and is used as a multiplier when rewards are calculated. Therefore, a malicious user may multiply the rewards for unclaimed incentives by an inflated figure and drain tokens.

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

For example, the `_bid` functions use of the reentrant `safeTransferFrom` function allows the caller to execute a double transfer:

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


---
## read-only-reentrancy-patterns.md
# Read-only Reentrancy Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 2 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Cyfrin, Spearbit, ConsenSys

---

## Detection Checklist

- [ ] Check for read-only reentrancy vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Read-only reentrancy

**Source**: Cyfrin
**Protocol**: Beanstalk Wells
**Impact**: HIGH

**Details**:

**Description:** The current implementation is vulnerable to read-only reentrancy, especially in [Wells::removeLiquidity](https://github.com/BeanstalkFarms/Wells/blob/e5441fc78f0fd4b77a898812d0fd22cb43a0af55/src/Well.sol#L440).
The implementation does not strictly follow the [Checks-Effects-Interactions (CEI) pattern](https://fravoll.github.io/solidity-patterns/checks_effects_interactions.html) as it is setting the new reserve values after sending out the tokens. This is not an immediate risk to the protocol itself due to the `nonReentrant` modifier, but this is still vulnerable to [read-only reentrancy](https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/).

Malicious attackers and unsuspecting ecosystem participants can deploy Wells with ERC-777 tokens (which have a callback that can take control) and exploit this vulnerability. This will lead to critical vulnerabilities given that the Wells are to be extended with price functions as defined by pumps - third-party protocols that integrate these on-chain oracles will be at risk.

Pumps are updated before token transfers; however, reserves are only set after. Therefore, pump functions will likely be incorrect on a re-entrant read-only call if `IWell(well).getReserves()` is called but reserves have not been correctly updated. The implementation of `GeoEmaAndCumSmaPump` appears not to be vulnerable, but given that each pump can choose its approach for recording a well's reserves over time, this remains a possible

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-06-16-Beanstalk wells.md)

---

### Example 2: H-13: `BalancerPairOracle` can be manipulated using read-only reentrancy

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/141 

## Found by 
cuthalion0x
## Summary

`BalancerPairOracle.getPrice` makes an external call to `BalancerVault.getPoolTokens` without checking the Balancer Vault's reentrancy guard. As a result, the oracle can be trivially manipulated to liquidate user positions prematurely.

## Vulnerability Detail

In February, the Balancer team disclosed a read-only reentrancy vulnerability in the Balancer Vault. The detailed disclosure can be found [here](https://forum.balancer.fi/t/reentrancy-vulnerability-scope-expanded/4345). In short, all Balancer pools are susceptible to manipulation of their external queries, and all integrations must now take an extra step of precaution when consuming data. Via reentrancy, an attacker can force token balances and BPT supply to be out of sync, creating very inaccurate BPT prices.

Some protocols, such as Sentiment, remained unaware of this issue for a few months and were later [hacked](https://twitter.com/spreekaway/status/1643313471180644360) as a result.

`BalancerPairOracle.getPrice` makes a price calculation of the form `f(balances) / pool.totalSupply()`, so it is clearly vulnerable to synchronization issues between the two data points. A rough outline of the attack might look like this:

```solidity
AttackerContract.flashLoan() ->
    // Borrow lots of tokens and trigger a callback.
    SomeProtocol.flashLoan() ->
        AttackerContract.exploit()

AttackerContract.e

*[Content truncated...]*

---

### Example 3: H-1: H-01 wstETH-ETH Curve LP Token Price can be manipulated to Cause Unexpected Liquidations

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

### Example 4: [M-03] Read-only reentrancy is possible

**Source**: Code4rena
**Protocol**: Angle Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/facets/Swapper.sol#L206> <br><https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/facets/Redeemer.sol#L131> <br><https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/savings/SavingsVest.sol#L110>

The agToken might be minted wrongly as rewards due to the reentrancy attack.

### Proof of Concept

There are `redeem/swap` logics in the `transmuter` contract and all functions don't have a `nonReentrant` modifier.

So the typical reentrancy attack is possible during `redeem/swap` as I mentioned in my other report.

But besides that, the read-only reentrancy attack is possible from the `SavingsVest` contract, and the agToken might be minted/burnt incorrectly like this.

1.  The [collatRatio](https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/savings/SavingsVest.sol#L108) is `BASE_9(100%)` now and Alice starts a swap from collateral to agToken in `Swapper` contract.
2.  In `_swap()`, it mints the agToken after depositing the collaterals.

```solidity
    if (mint) {
        uint128 changeAmount = (amountOut.mulDiv(BASE_27, ts.normalizer, Math.Rounding.Up)).toUint128();
        // The amount of stablecoins issued from a collateral are not stored as absolute variables, but
        // as variables no

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-dev-test-repo)

---

### Example 5: Balancer Read-Only Reentrancy Vulnerability (Changes from dev team added to audit.)

**Source**: Spearbit
**Protocol**: Cron Finance
**Impact**: HIGH

**Details**:

## Security Advisory

**Severity:** High Risk  
**Context:** CronV1Pool.sol#L1250  

**Description:**  
Balancer's read-only reentrancy vulnerability potentially affects the following Cron-Fi TWAMM functions:
- `getVirtualReserves`
- `getVirtualPriceOracle`
- `executeVirtualOrdersToBlock`  

A mitigation was provided by the Balancer team that uses a minimum amount of gas to trigger a reentrancy check. The Balancer vulnerability is discussed in greater detail [here](https://example.com/reentrancy-vulnerability-scope-expanded/4345).

**Recommendation:**  
Install the mitigation into the aforementioned methods, changing them to non-view functions, but documenting that they do not meaningfully modify state. If possible, confirm that the mitigation is not needed by testing the methods without it and removing it if shown to not be a problem.

**TWAMM:** Addressed in commit 5a529da.  
**Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/CronFinance-Spearbit-Security-Review.pdf)

---

### Example 6: Potential Reentrancy Into Strategies

**Source**: ConsenSys
**Protocol**: EigenLabs  EigenLayer
**Impact**: MEDIUM

**Details**:

#### Resolution



*EigenLabs Quick Summary:* The `StrategyBase` contract may be vulnerable to a token contract that employs some sort of callback to a function like `sharesToUnderlyingView`, before the balance change is reflected in the contract. The shares have been decremented, which would lead to an incorrect return value from `sharesToUnderlyingView`.


*EigenLabs Response:* As noted in the report, this is not an issue if the token contract being used does not allow for reentrancy. For now, we will make it clear both in the contracts as well as the docs that our implementation of `StrategyBase.sol` does not support tokens with reentrancy. Because of the way our system is designed, anyone can choose to design a strategy with this in mind!




#### Description


The `StrategyManager` contract is the entry point for deposits into and withdrawals from strategies. More specifically, to deposit into a strategy, a staker calls `depositIntoStrategy` (or anyone calls `depositIntoStrategyWithSignature` with the stakers signature) then the asset is transferred from the staker to the strategy contract. After that, the strategys `deposit` function is called, followed by some bookkeeping in the `StrategyManager`. For withdrawals (and slashing), the `StrategyManager` calls the strategys `withdraw` function, which transfers the given amount of the asset to the given recipient. Both token transfers are a potential source of reentrancy if the token allows it.


The `StrategyManager` us

*[Content truncated...]*

**Reference**: [View Original Finding](https://consensys.net/diligence/audits/2023/03/eigenlabs-eigenlayer/)

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## cei-patterns.md
# CEI Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 2 | 1 | 0 |

**Common Sources**: Sherlock, Cyfrin

---

## Detection Checklist

- [ ] Check for cei vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: M-1: resolveQueuedTrades() ERC777 re-enter to steal funds

**Source**: Sherlock
**Protocol**: Buffer Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-buffer-judging/issues/130 

## Found by 
bin2chen, HonorLt, KingNFT

## Summary
_openQueuedTrade() does not follow the Checks Effects Interactions principle and may lead to re-entry to steal the funds

https://fravoll.github.io/solidity-patterns/checks_effects_interactions.html

## Vulnerability Detail
The prerequisite is that tokenX is ERC777 e.g. sushi
1. resolveQueuedTrades() call _openQueuedTrade()
2. in _openQueuedTrade() call "tokenX.transfer(queuedTrade.user)" if (revisedFee < queuedTrade.totalFee) before set queuedTrade.isQueued = false; 
```solidity
    function _openQueuedTrade(uint256 queueId, uint256 price) internal {
...
        if (revisedFee < queuedTrade.totalFee) {
            tokenX.transfer( //***@audit call transfer , if ERC777 , can re-enter ***/
                queuedTrade.user,
                queuedTrade.totalFee - revisedFee
            );
        }

        queuedTrade.isQueued = false;  //****@audit  change state****/
    }
```
3.if ERC777 re-enter to #cancelQueuedTrade() to get tokenX back,it can close,  because queuedTrade.isQueued still equal true
4. back to _openQueuedTrade()  set queuedTrade.isQueued = false
5.so steal tokenX
## Impact
if tokenX equal ERC777 can steal token
## Code Snippet
https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferRouter.sol#L350

## Tool used

Manual Review

## Recommendation

follow Checks Effects Interactions 

```solidity

*[Content truncated...]*

---

### Example 2: M-2: When tokenX is an ERC777 token, users can bypass maxLiquidity

**Source**: Sherlock
**Protocol**: Buffer Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-buffer-judging/issues/112 

## Found by 
cccz

## Summary
When tokenX is an ERC777 token, users can use callbacks to provide liquidity exceeding maxLiquidity
## Vulnerability Detail
In BufferBinaryPool._provide, when tokenX is an ERC777 token, the tokensToSend function of account will be called in tokenX.transferFrom before sending tokens. When the user calls provide again in tokensToSend, since BufferBinaryPool has not received tokens at this time, totalTokenXBalance() has not increased, and the following checks can be bypassed, so that users can provide liquidity exceeding maxLiquidity.
```solidity
         require(
             balance + tokenXAmount <= maxLiquidity,
             "Pool has already reached it's max limit"
         );
```
## Impact
users can provide liquidity exceeding maxLiquidity.

## Code Snippet
https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryPool.sol#L216-L240
## Tool used

Manual Review

## Recommendation
Change to
```diff
    function _provide(
        uint256 tokenXAmount,
        uint256 minMint,
        address account
    ) internal returns (uint256 mint) {
+        bool success = tokenX.transferFrom(
+            account,
+            address(this),
+            tokenXAmount
+        );
        uint256 supply = totalSupply();
        uint256 balance = totalTokenXBalance();

        require(
            balance + tokenXAmount <= maxLiquidity,
        

*[Content truncated...]*

---

### Example 3: The deposit function is not following CEI pattern

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: LOW

**Details**:

**Severity:** Low

**Description:** The protocol implemented a function `deposit()` to allow users to deposit.
```solidity
DepositVault.sol
37:     function deposit(uint256 amount, address tokenAddress) public payable {
38:         require(amount > 0 || msg.value > 0, "Deposit amount must be greater than 0");
39:         if(msg.value > 0) {
40:             require(tokenAddress == address(0), "Token address must be 0x0 for ETH deposits");
41:             uint256 depositIndex = deposits.length;
42:             deposits.push(Deposit(payable(msg.sender), msg.value, tokenAddress));
43:             emit DepositMade(msg.sender, depositIndex, msg.value, tokenAddress);
44:         } else {
45:             require(tokenAddress != address(0), "Token address must not be 0x0 for token deposits");
46:             IERC20 token = IERC20(tokenAddress);
47:             token.safeTransferFrom(msg.sender, address(this), amount);//@audit-issue against CEI pattern
48:             uint256 depositIndex = deposits.length;
49:             deposits.push(Deposit(payable(msg.sender), amount, tokenAddress));
50:             emit DepositMade(msg.sender, depositIndex, amount, tokenAddress);
51:
52:         }
53:     }
```
Looking at the line L47, we can see that the token transfer happens before updating the accounting state of the protocol against the CEI pattern.
Because the protocol intends to support all ERC20 tokens, the tokens with hooks (e.g. ERC777) can be exploited for reentrancy.
Although we can n

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## external-call-patterns.md
# External Call Security Patterns

## Overview

**Frequency**: 8 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 3 | 0 | 0 |

**Common Sources**: Spearbit, Sherlock, Halborn, Code4rena

---

## Detection Checklist

- [ ] Check for external call vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Too generic calls in GenericBridgeFacet allow stealing of tokens

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

### Example 2: LACK OF EXTERNAL CALLS VALIDATION

**Source**: Halborn
**Protocol**: Account Abstraction Schnorr Signatures SDK
**Impact**: HIGH

**Details**:

##### Description

Non-validated external calls occur when a function invokes an external contract without verifying the return value or handling potential errors.

Several external calls were detected without proper validation.

### Impact

This can lead to reentrancy attacks or unexpected side effects if the external call fails or returns an unexpected result, directly causing a potential impact in the availability or integrity of the environment.

##### Proof of Concept

Listed below, there are some examples of unvalidated calls that may fail or cause an unconsistent or unexpected behavior of the application execution flow.

* `examples/account-address/account_address.ts`

```
async function getAddressAlchemyAASDK(combinedAddresses: Address[], salt: string) {
  const rpcUrl = process.env.ALCHEMY_RPC_URL
  const transport = http(rpcUrl)
  const multiSigSmartAccount = await createMultiSigSmartAccount({
    transport,
    chain: CHAIN,
    combinedAddress: combinedAddresses,
    salt: saltToHex(salt),
    entryPoint: getEntryPoint(CHAIN),
  })

  return multiSigSmartAccount.address
}


```

* `src/helpers/create2.ts`

```
export async function getAccountImplementationAddress(factoryAddress: string, ethersSignerOrProvider: Signer | Provider): Promise<string> {
  const smartAccountFactory = new ethers.Contract(factoryAddress, MultiSigSmartAccountFactory_abi, ethersSignerOrProvider)
  const accountImplementation = await smartAccountFactory.accountImplementation()
  return accoun

*[Content truncated...]*

**Reference**: [View Original Finding](https://www.halborn.com/audits/influx-technologies/account-abstraction-schnorr-signatures-sdk)

---

### Example 3: Bridge with Axelar can be stolen with malicious external call

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- `Executor.sol#L272-L288`
- `Executor.sol#L323-L333`
- `Executor.sol#L269-L288`

## Description
The Executor contract allows users to build an arbitrary payload external call to any address except `address(erc20Proxy)`. `erc20Proxy` is not the only dangerous address to call. By building a malicious external call to the Axelar gateway, exploiters can steal users funds.

The Executor performs swaps at the destination chain. By setting the receiver address to the Executor contract at the destination chain, Li-Fi can help users to get the best price. The Executor inherits `IAxelarExecutable`. The `execute` and `executeWithToken` functions validate the payload and execute the external call.

### IAxelarExecutable.sol#L27-L40
```solidity
function executeWithToken(
    bytes32 commandId,
    string calldata sourceChain,
    string calldata sourceAddress,
    bytes calldata payload,
    string calldata tokenSymbol,
    uint256 amount
) external {
    bytes32 payloadHash = keccak256(payload);
    if (!gateway.validateContractCallAndMint(commandId, sourceChain, sourceAddress, payloadHash, tokenSymbol, amount)) 
        revert NotApprovedByGateway();
    _executeWithToken(sourceChain, sourceAddress, payload, tokenSymbol, amount);
}
```

The nuance lies in the Axelar gateway `AxelarGateway.sol#L133-L148`. Once the receiver calls `validateContractCallAndMint` with a valid payload, the gateway mints the tokens to the receiver and marks it as executed. I

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 4: Malicious call data can steal unclaimed tokens in the Executor contract

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity: High Risk

### Context
`Executor.sol#L211`

### Description
Users can provide a destination contract `args.to` and arbitrary data `_args.callData` when doing a cross-chain transfer. The protocol will provide the allowance to the callee contract and triggers the function call through `ExcessivelySafeCall.excessivelySafeCall`.

```solidity
contract Executor is IExecutor {
    function execute(ExecutorArgs memory _args) external payable override onlyConnext returns (bool, bytes memory) {
        ...
        SafeERC20.safeIncreaseAllowance(IERC20(_args.assetId), _args.to, _args.amount);
        ...
        // Try to execute the callData
        // the low level call will return `false` if its execution reverts
        (success, returnData) = ExcessivelySafeCall.excessivelySafeCall(
            _args.to,
            gas,
            isNative ? _args.amount : 0,
            MAX_COPY,
            _args.callData
        );
        ...
    }
}
```

Since there arent restrictions on the destination contract and calldata, exploiters can steal the tokens from the executor.

**Note:** The executor does have excess tokens, see: Kovan executor.

**Note:** See issue "Tokens can get stuck in Executor contract."

Tokens can be stolen by granting an allowance. Setting 
```solidity
calldata = abi.encodeWithSelector(ERC20.approve.selector, exploiter, type(uint256).max);
args.to = tokenAddress;
```
allows the exploiter to get an infinite allowance of any toke

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 5: Add checks to xcall()

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Vulnerability Report

**Severity**: High Risk  
**Context**: 
- BridgeFacet.sol#L240-L339
- BridgeFacet.sol#L400-L419
- Executor.sol#L142-L280

**Description**:  
The function `xcall()` does some sanity checks; nevertheless, more checks should be added to prevent issues later on in the use of the protocol. 

- If `args.recovery == 0`, then `sendToRecovery()` will send funds to the 0 address, effectively losing them.
- If `params.agent == 0`, then `forceReceiveLocal` cant be used, and funds might be locked forever.
- The `args.params.destinationDomain` should never be `s.domain`, although this is also implicitly checked via `_mustHaveRemote()` assuming a correct configuration.
- If `args.params.slippageTol` is set to something greater than `s.LIQUIDITY_FEE_DENOMINATOR`, then funds can be locked as `xcall()` allows for the user to provide the local asset, avoiding any swap while `_handleExecuteLiquidity()` in `execute()` may attempt to perform a swap on the destination chain.

```solidity
function xcall(XCallArgs calldata _args) external payable nonReentrant whenNotPaused returns (bytes32) {
    // Sanity checks.
    ...
}
```

**Recommendation**:  
Consider adding the following checks:
- `recovery != 0`
- `agent != 0`
- `_args.params.destinationDomain != s.domain`
- `_args.params.slippageTol <= s.LIQUIDITY_FEE_DENOMINATOR`

Also, double-check if any additional checks are useful.

**Connext**: Solved in PR 1536.  
**Spearbit**: Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 6: M-2: Depositing `stETH` to puffer finance will revert due to wrong implementation of `PufETHAdapter._stake` call

**Source**: Sherlock
**Protocol**: Napier Finance - LST/LRT Integrations
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-05-napier-update-judging/issues/21 

## Found by 
Bauer, Drynooo, Ironsidesec, KupiaSec, PNS, blackhole, blutorque, karsar, merlin, no, yamato, zzykxx
## Summary
Reason: `PufETHAdapter._stake` will always revert due to wrong external call implementation.
Impact: Can't deposit to Puffer.
Likelihood: always.


## Vulnerability Detail

https://github.com/sherlock-audit/2024-05-napier-update/blob/c31af59c6399182fd04b40530d79d98632d2bfa7/napier-uups-adapters/src/adapters/puffer/PufETHAdapter.sol#L82

```solidity
File: 2024-05-napier-update\napier-uups-adapters\src\adapters\puffer\PufETHAdapter.sol

66:   function _stake(uint256 stakeAmount) internal override returns (uint256) {
...
74: 
75:     IWETH9(Constants.WETH).withdraw(stakeAmount);
76:     uint256 _stETHAmt = STETH.balanceOf(address(this));
77:     STETH.submit{value: stakeAmount}(address(this));
78:     _stETHAmt = STETH.balanceOf(address(this)) - _stETHAmt;
79:     if (_stETHAmt == 0) revert InvariantViolation();
80: 
81:     // Stake stETH to PufferDepositor
82:  >>> uint256 _pufETHAmt = PUFFER_DEPOSITOR.depositStETH(Permit(block.timestamp, _stETHAmt, 0, 0, 0));
84: 
...
88:   }

```

**Issue flow**:
1. When depositing by calling `PUFFER_DEPOSITOR.depositStETH(Permit)`, `PufETHAdapter` passes only one parameter `Permit` look at line 82 above.
2. But the current `PUFFER_DEPOSITOR.depositStETH` has 2 parameters (Permit, address recipient). Chec

*[Content truncated...]*

---

### Example 7: M-5: `getPositionRisk()` will return a wrong value of risk

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/97 

## Found by 
Ch\_301
## Summary
In order to interact with SPELL the users need to `lend()` some collateral which is known as **Isolated Collateral** and the SoftVault will deposit them into Compound protocol to generate some lending interest (to earn passive yield)  

## Vulnerability Detail
to [liquidate](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L487-L548) a position this function `isLiquidatable()` should return `true`
```solidity
    function isLiquidatable(uint256 positionId) public view returns (bool) {
        return
            getPositionRisk(positionId) >=
            banks[positions[positionId].underlyingToken].liqThreshold;
    }
```
and it is subcall to `getPositionRisk()`
```solidity
    function getPositionRisk(
        uint256 positionId
    ) public view returns (uint256 risk) {
        uint256 pv = getPositionValue(positionId);          
        uint256 ov = getDebtValue(positionId);             
        uint256 cv = getIsolatedCollateralValue(positionId);

        if (
            (cv == 0 && pv == 0 && ov == 0) || pv >= ov // Closed position or Overcollateralized position
        ) {
            risk = 0;
        } else if (cv == 0) {
            // Sth bad happened to isolated underlying token
            risk = Constants.DENOMINATOR;
        } else {
            risk = ((ov - pv) * Constants.DENOMINATOR) / cv;
   

*[Content truncated...]*

---

### Example 8: [M-25] Vault can be created for not-yet-existing ERC20 tokens, which allows attackers to set traps to steal NFTs from Borrowers

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

There is a subtle difference between the implementation of solmates SafeTransferLib and OZs SafeERC20: OZs SafeERC20 checks if the token is a contract or not, solmates SafeTransferLib does not.<br>
See: <https://github.com/Rari-Capital/solmate/blob/main/src/utils/SafeTransferLib.sol#L9><br>
Note that none of the functions in this library check that a token has code at all! That responsibility is delegated to the caller.<br>
As a result, when the tokens address has no code, the transaction will just succeed with no error.<br>
This attack vector was made well-known by the qBridge hack back in Jan 2022.

In AstariaRouter, Vault, PublicVault, VaultImplementation, ClearingHouse, TransferProxy, and WithdrawProxy, the `safetransfer` and `safetransferfrom` don't check the existence of code at the token address. This is a known issue while using solmates libraries.

Hence this can lead to miscalculation of funds and also loss of funds , because if safetransfer() and safetransferfrom() are called on a token address that doesnt have contract in it, it will always return success. Due to this protocol will think that funds has been transferred and successful , and records will be accordingly calculated, but in reality funds were never transferred.

So this will lead to miscalculation and loss of funds.

### Attack scenario (example):

Its becoming popular for protocols to deploy their token across multiple networks and when they do so, a common practice is to deploy the token cont

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

## Statistics

- Total findings analyzed: 8
- Examples shown: 8
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## external-contract-patterns.md
# External Contract Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 4 | 0 | 0 |

**Common Sources**: Sherlock, TrailOfBits

---

## Detection Checklist

- [ ] Check for external contract vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: receiveFlashLoan does not account for fees

**Source**: TrailOfBits
**Protocol**: Lindy Labs Sandclock
**Impact**: HIGH

**Details**:

## Diculty: High

## Type: Data Validation

### Target: 
`src/steth/scWETHv2.sol`, `src/steth/scUSDCv2.sol`

### Description
The `receiveFlashLoan` functions of the `scWETHv2` and `scUSDCv2` vaults ignore the Balancer flash loan fees and repay exactly the amount that was loaned. This is not currently an issue because the Balancer vault does not charge any fees for flash loans. However, if Balancer implements fees for flash loans in the future, the Sandclock vaults would be prevented from withdrawing investments back into the vault.

```solidity
function flashLoan(
    IFlashLoanRecipient recipient,
    IERC20[] memory tokens,
    uint256[] memory amounts,
    bytes memory userData
) external override nonReentrant whenNotPaused {
    uint256[] memory feeAmounts = new uint256[](tokens.length);
    uint256[] memory preLoanBalances = new uint256[](tokens.length);
    for (uint256 i = 0; i < tokens.length; ++i) {
        IERC20 token = tokens[i];
        uint256 amount = amounts[i];
        preLoanBalances[i] = token.balanceOf(address(this));
        feeAmounts[i] = _calculateFlashLoanFeeAmount(amount);
        token.safeTransfer(address(recipient), amount);
    }
    recipient.receiveFlashLoan(tokens, amounts, feeAmounts, userData);
    for (uint256 i = 0; i < tokens.length; ++i) {
        IERC20 token = tokens[i];
        uint256 preLoanBalance = preLoanBalances[i];
        uint256 postLoanBalance = token.balanceOf(address(this));
        uint256 receivedFeeAmount = postLoanBal

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/2023-07-sandclock-securityreview.pdf)

---

### Example 2: M-12: Vault_Synths.sol code does not consider protocol exchange fee when evaluating the Collateral worth

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/120 

## Found by 
ctf\_sec

## Summary

Vault_Synths.sol code does not consider protocol fee.

## Vulnerability Detail

If we look into the good-written documentation:

https://github.com/kree-dotcom/isomorph/blob/789338c8979ab75b8187781a2500908bb26dcdea/docs/Vault_Lyra.md#getwithdrawalfee

I want to quote:

> Because the withdrawalFee of a lyra LP pool can vary we must fetch it each time it is needed to ensure we use an accurate value. LP tokens are devalued by this as a safety measure as any liquidation would include selling the collateral and so should factor in that cost to ensure it is profitable.

In Vault_Lyra.sol, when calculating the collateral of the LP token, the fee is taken into consideration.

```solidity
function priceCollateralToUSD(bytes32 _currencyKey, uint256 _amount) public view override returns(uint256){
     //The LiquidityPool associated with the LP Token is used for pricing
    ILiquidityPoolAvalon LiquidityPool = ILiquidityPoolAvalon(collateralBook.liquidityPoolOf(_currencyKey));
    //we have already checked for stale greeks so here we call the basic price function.
    uint256 tokenPrice = LiquidityPool.getTokenPrice();          
    uint256 withdrawalFee = _getWithdrawalFee(LiquidityPool);
    uint256 USDValue  = (_amount * tokenPrice) / LOAN_SCALE;
    //we remove the Liquidity Pool withdrawalFee 
    //as there's no way to remove the LP position without paying this.
    ui

*[Content truncated...]*

---

### Example 3: M-1: When one of the plugins is broken or paused, `deposit()` or `withdraw()` of the whole Vault contract can malfunction

**Source**: Sherlock
**Protocol**: Mycelium
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-mycelium-judging/tree/main/006-M 

## Found by 
ctf\_sec, IllIllI, berndartmueller, ak1, WATCHPUG

## Summary

One malfunctioning plugin can result in the whole Vault contract malfunctioning.

## Vulnerability Detail

A given plugin can temporally or even permanently becomes malfunctioning (cannot deposit/withdraw) for all sorts of reasons.

Eg, Aave V2 Lending Pool can be paused, which will prevent multiple core functions that the Aave v2 plugin depends on from working, including `lendingPool.deposit()` and `lendingPool.withdraw()`.

https://github.com/aave/protocol-v2/blob/master/contracts/protocol/lendingpool/LendingPool.sol#L54

```soldity
  modifier whenNotPaused() {
    _whenNotPaused();
    _;
  }
```

https://github.com/aave/protocol-v2/blob/master/contracts/protocol/lendingpool/LendingPool.sol#L142-L146

```solidity
  function withdraw(
    address asset,
    uint256 amount,
    address to
  ) external override whenNotPaused returns (uint256) {
```

That's because the deposit will always goes to the first plugin, and withdraw from the last plugin first.

## Impact

When Aave V2 Lending Pool is paused, users won't be able to deposit or withdraw from the vault.

Neither can the owner remove the plugin nor rebalanced it to other plugins to resume operation.

Because withdrawal from the plugin can not be done, and removing a plugin or rebalancing both rely on this.

## Code Snippet

https://github.com/sherlock-audit/2022-

*[Content truncated...]*

---

### Example 4: M-2: Lyra vault underestimates the collateral value

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/242 

## Found by 
hansfriese

## Summary

Lyra vault subtracts the withdrawal fee while calculating the collateral value in USD, and it does not match the actual Lyra Pool implementation.

## Vulnerability Detail

The user's collateral value is estimated using the function `priceCollateralToUSD()` at `Vault_Lyra.sol#L77` as follows.

```solidity
function priceCollateralToUSD(bytes32 _currencyKey, uint256 _amount) public view override returns(uint256){
        //The LiquidityPool associated with the LP Token is used for pricing
    ILiquidityPoolAvalon LiquidityPool = ILiquidityPoolAvalon(collateralBook.liquidityPoolOf(_currencyKey));
    //we have already checked for stale greeks so here we call the basic price function.
    uint256 tokenPrice = LiquidityPool.getTokenPrice();
    uint256 withdrawalFee = _getWithdrawalFee(LiquidityPool);
    uint256 USDValue  = (_amount * tokenPrice) / LOAN_SCALE;
    //we remove the Liquidity Pool withdrawalFee
    //as there's no way to remove the LP position without paying this.
    uint256 USDValueAfterFee = USDValue * (LOAN_SCALE- withdrawalFee)/LOAN_SCALE;
    return(USDValueAfterFee);
}
```

So it is understood that the withdrawal fee is removed to get the reasonable value of the collateral.
But according to the [Lyra Pool implementation](https://github.com/lyra-finance/lyra-protocol/blob/master/contracts/LiquidityPool.sol#L341), the token price used for withdraw

*[Content truncated...]*

---

### Example 5: H-3: Users who deposit Lyra LP as collateral will lose OP vault rewards

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/78 

## Found by 
0x52

## Summary

Optimism currently offers yield farming opportunities for Lyra LPs, see [OP Reward Announcement](https://blog.lyra.finance/incentives-launch/). Every 2 weeks Lyra LPs split a claimable pool. When they use their Lyra LP as collateral, it is transferred to the Lyra vault which means that all OP will be instead claimable by the vault. The vault currently doesn't implement any method to claim or distribute those tokens. The result is a loss of user yield on their Lyra tokens. Aside from the loss of funds, it also highly disincentivizes users from using Lyra tokens as collateral.

## Vulnerability Detail

See summary.

## Impact

Lyra LPs that use their tokens as collateral will lose all their OP rewards

## Code Snippet

[Vault_Lyra.sol](https://github.com/sherlock-audit/2022-11-isomorph/blob/main/contracts/Isomorph/contracts/Vault_Lyra.sol#L1)

## Tool used

Manual Review

## Recommendation

It's unclear how long OP rewards will continue but it seems like other protocols have been getting 6 months of incentives. Since they are temporary I would recommend not integrating reward distribution directly into the contract. I would recommend adding a function to claim rewards to the Isomorph treasury. After the rewards end, the Isomorph should create an airdrop to distribute those tokens to users during that period of time.

## Discussion

**kree-dotcom**

Sponsor confirmed, wi

*[Content truncated...]*

---

### Example 6: H-2: ShortLongSpell#openPosition uses the wrong balanceOf when determining how much collateral to put

**Source**: Sherlock
**Protocol**: Blueberry Update #2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-blueberry-judging/issues/31 

## Found by 
0x52
## Summary

The _doPutCollateral subcall in ShortLongSpell#openPosition uses the balance of the uToken rather than the vault resulting in the vault tokens being left in the contract which will be stolen.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L144-L150

        address vault = strategies[param.strategyId].vault;
        _doPutCollateral(
            vault,
            IERC20Upgradeable(ISoftVault(vault).uToken()).balanceOf(
                address(this)
            )
        );

When putting the collateral the contract is putting vault but it uses the balance of the uToken instead of the balance of the vault.

## Impact

Vault tokens will be left in contract and stolen

## Code Snippet

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L111-L151

## Tool used

Manual Review

## Recommendation

Use the balanceOf vault rather than vault.uToken



## Discussion

**sleepriverfish**

Escalate for 10 USDC

In #Blueberry Update, despite the successful escalation of the issue, no reward was granted for the heightened severity and impact of the vulnerability. However, in #Blueberry Update2, a reward was offered specifically for the detection and reporting of a similar vulnerability.
https://github.com/sherlock-audit/2023-04-bluebe

*[Content truncated...]*

---

### Example 7: M-5: `getPositionRisk()` will return a wrong value of risk

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/97 

## Found by 
Ch\_301
## Summary
In order to interact with SPELL the users need to `lend()` some collateral which is known as **Isolated Collateral** and the SoftVault will deposit them into Compound protocol to generate some lending interest (to earn passive yield)  

## Vulnerability Detail
to [liquidate](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L487-L548) a position this function `isLiquidatable()` should return `true`
```solidity
    function isLiquidatable(uint256 positionId) public view returns (bool) {
        return
            getPositionRisk(positionId) >=
            banks[positions[positionId].underlyingToken].liqThreshold;
    }
```
and it is subcall to `getPositionRisk()`
```solidity
    function getPositionRisk(
        uint256 positionId
    ) public view returns (uint256 risk) {
        uint256 pv = getPositionValue(positionId);          
        uint256 ov = getDebtValue(positionId);             
        uint256 cv = getIsolatedCollateralValue(positionId);

        if (
            (cv == 0 && pv == 0 && ov == 0) || pv >= ov // Closed position or Overcollateralized position
        ) {
            risk = 0;
        } else if (cv == 0) {
            // Sth bad happened to isolated underlying token
            risk = Constants.DENOMINATOR;
        } else {
            risk = ((ov - pv) * Constants.DENOMINATOR) / cv;
   

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## call-vs-transfer-patterns.md
# call vs transfer Security Patterns

## Overview

**Frequency**: 15 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 13 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Cyfrin

---

## Detection Checklist

- [ ] Check for call vs transfer vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] Withdrawals can be locked forever if recipient is a contract

**Source**: Code4rena
**Protocol**: Renzo
**Impact**: HIGH

**Details**:

The [`WithdrawQueue`](https://github.com/code-423n4/2024-04-renzo/blob/519e518f2d8dec9acf6482b84a181e403070d22d/contracts/Withdraw/WithdrawQueue.sol#L303) contract allows users to request withdrawals of their ezETH tokens in exchange for a selected asset, such as ETH or an ERC20 token. After a cooldown period, users can call the [`claim()`](https://github.com/code-423n4/2024-04-renzo/blob/519e518f2d8dec9acf6482b84a181e403070d22d/contracts/Withdraw/WithdrawQueue.sol#L279) function to receive their withdrawn assets.

When the selected asset is ETH, the `claim()` function sends the ETH using the low-level `transfer()` function:

```solidity
payable(msg.sender).transfer(_withdrawRequest.amountToRedeem);
```

However, `transfer()` only forwards 2300 gas, which is not enough for the recipient to execute any non-trivial logic in a `receive()` or fallback function. For instance, it is not enough for Safes (such as [this one](https://etherscan.io/address/0xd1e6626310fd54eceb5b9a51da2ec329d6d4b68a) in use by the protocol) to receive funds, which require `>` 6k gas for the call to reach the implementation contract and emit an event:

*Note: to view the provided image, please see the original submission [here](https://github.com/code-423n4/2024-04-renzo-findings/issues/612).*

In this case, the impact is higher than that reported by [4naly3er](https://github.com/code-423n4/2024-04-renzo/blob/main/4naly3er-report.md#m-4-call-should-be-used-instead-of-transfer-on-an-address-payable) becaus

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-04-renzo)

---

### Example 2: [M-10] address.call{value:x}() should be used instead of payable.transfer()

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/utils/LineLib.sol#L48


## Vulnerability details

## Impact

When withdrawing and refund  ETH, the  contract uses Soliditys `transfer()` function. 

Using Solidity's `transfer()` function has some notable shortcomings when the withdrawer is a smart contract, which can render ETH deposits impossible to withdraw. Specifically, the withdrawal will inevitably fail when:
* The withdrawer smart contract does not implement a payable fallback function.
* The withdrawer smart contract implements a payable fallback function which uses more than 2300 gas units.
* The withdrawer smart contract implements a payable fallback function which needs less than 2300 gas units but is called through a proxy that raises the calls gas usage above 2300.

Risks of reentrancy stemming from the use of this function can be mitigated by tightly following the "Check-Effects-Interactions" pattern and using OpenZeppelin Contracts ReentrancyGuard contract.

## Proof of Concept

```solidity
// Line-of-Credit/contracts/utils/LineLib.sol
48:    payable(receiver).transfer(amount);
```


#### References:

The issues with`transfer()`are outlined [here](https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/
)

For further reference on why using Soliditys `transfer()` is no longer recommended, refer to these [articles](https://blog.openzeppelin.com/reentrancy-after-istanb

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 3: [M-11] Use of `payable.transfer()` may lock user funds

**Source**: Code4rena
**Protocol**: Fractional
**Impact**: MEDIUM

**Details**:

_Submitted by IllIllI, also found by 0x1f8b, 0x29A, Amithuddar, Avci, bardamu, BowTiedWardens, c3phas, cccz, codexploder, cryptphi, hake, horsefacts, hyh, Kthere, Limbooo, MEP, oyc&#95;109, pashov, peritoflores, Ruhum, scaraven, simon135, slywaters, sseefried, StyxRave, tofunmi, TomJ, Treasure-Seeker, TrungOre, Tutturu, Waze, and xiaoming90_

<https://github.com/code-423n4/2022-07-fractional/blob/e2c5a962a94106f9495eb96769d7f60f7d5b14c9/src/modules/Migration.sol#L172>

<https://github.com/code-423n4/2022-07-fractional/blob/e2c5a962a94106f9495eb96769d7f60f7d5b14c9/src/modules/Migration.sol#L325>

### Impact

The use of `payable.transfer()` is heavily frowned upon because it can lead to the locking of funds. The `transfer()` call requires that the recipient has a `payable` callback, only provides 2300 gas for its operation. This means the following cases can cause the transfer to fail:

*   The contract does not have a `payable` callback
*   The contract's `payable` callback spends more than 2300 gas (which is only enough to emit something)
*   The contract is called through a proxy which itself uses up the 2300 gas

If a user falls into one of the above categories, they'll be unable to receive funds from the vault in a migration wrapper. Inaccessible funds means loss of funds, which is Medium severity.

### Proof of Concept

Both `leave()`:

```solidity
File: src/modules/Migration.sol   #1

159           uint256 ethAmount = userProposalEth[_proposalId][msg.sender];
160        

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-fractional)

---

### Example 4: [M-01] Use `call()` rather than `transfer()` on address payable

**Source**: Code4rena
**Protocol**: Golom
**Impact**: MEDIUM

**Details**:

[L154](https://github.com/code-423n4/2022-07-golom/blob/main/contracts/core/GolomTrader.sol#L154) in [GolomTrader.sol](https://github.com/code-423n4/2022-07-golom/blob/main/contracts/core/GolomTrader.sol) uses `.transfer()` to send ether to other addresses. There are a number of issues with using `.transfer()`, as it can fail for a number of reasons (specified in the Proof of Concept).

### Proof of Concept

1.  The destination is a smart contract that doesnt implement a `payable` function or it implements a `payable` function but that function uses more than 2300 gas units.
2.  The destination is a smart contract that doesnt implement a `payable` `fallback` function or it implements a `payable` `fallback` function but that function uses more than 2300 gas units.
3.  The destination is a smart contract but that smart contract is called via an intermediate proxy contract increasing the case requirements to more than 2300 gas units. A further example of unknown destination complexity is that of a multisig wallet that as part of its operation uses more than 2300 gas units.
4.  Future changes or forks in Ethereum result in higher gas fees than transfer provides. The `.transfer()` creates a hard dependency on 2300 gas units being appropriate now and into the future.

### Tools Used

Vim

### Recommended Remediation Steps

Instead use the `.call()` function to transfer ether and avoid some of the limitations of `.transfer()`. This would be accomplished by changing `payEther()` to

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-golom)

---

### Example 5: [M-01] Use call() instead of transfer() when transferring ETH in RubiconRouter

**Source**: Code4rena
**Protocol**: Rubicon
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-05-rubicon/blob/main/contracts/RubiconRouter.sol#L356
https://github.com/code-423n4/2022-05-rubicon/blob/main/contracts/RubiconRouter.sol#L374
https://github.com/code-423n4/2022-05-rubicon/blob/main/contracts/RubiconRouter.sol#L434
https://github.com/code-423n4/2022-05-rubicon/blob/main/contracts/RubiconRouter.sol#L451
https://github.com/code-423n4/2022-05-rubicon/blob/main/contracts/RubiconRouter.sol#L491
https://github.com/code-423n4/2022-05-rubicon/blob/main/contracts/RubiconRouter.sol#L548


## Vulnerability details

## Impact
When transferring ETH, use `call()` instead of `transfer()`.

The `transfer()` function only allows the recipient to use 2300 gas. If the recipient uses more than that, transfers will fail. In the future gas costs might change increasing the likelihood of that happening.

Keep in mind that `call()` introduces the risk of reentrancy. But, as long as the router follows the checks effects interactions pattern it should be fine. It's not supposed to hold any tokens anyway.

## Proof of Concept
See the linked code snippets above.

## Tools Used
none

## Recommended Mitigation Steps
Replace `transfer()` calls with `call()`. Keep in mind to check whether the call was successful by validating the return value:

```sol
(bool success, ) = msg.sender.call{value: amount}("");
require(success, "Transfer failed.")
```

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-rubicon)

---

### Example 6: [H-01] OpenLevV1Libs and LPools doTransferOut functions call native payable.transfer, which can be unusable for smart contract calls

**Source**: Code4rena
**Protocol**: OpenLeverage
**Impact**: HIGH

**Details**:

## Handle

hyh


## Vulnerability details

## Impact

When OpenLev operations use a wrapped native token, the whole user withdraw is being handled with a `payable.transfer()` call.

This is unsafe as `transfer` has hard coded gas budget and can fail when the user is a smart contract. This way any programmatical usage of OpenLevV1 and LPool is at risk.

Whenever the user either fails to implement the payable fallback function or cumulative gas cost of the function sequence invoked on a native token transfer exceeds 2300 gas consumption limit the native tokens sent end up undelivered and the corresponding user funds return functionality will fail each time.

As OpenLevV1 `closeTrade` is affected this includes user's principal funds freeze scenario, so marking the issue as a high severity one.

## Proof of Concept

OpenLevV1Lib and LPool have `doTransferOut` function that calls native token payable.transfer:

OpenLevV1Lib.doTransferOut

https://github.com/code-423n4/2022-01-openleverage/blob/main/openleverage-contracts/contracts/OpenLevV1Lib.sol#L253


LPool.doTransferOut

https://github.com/code-423n4/2022-01-openleverage/blob/main/openleverage-contracts/contracts/liquidity/LPool.sol#L297


LPool.doTransferOut is used in LPool redeem and borrow, while OpenLevV1Lib.doTransferOut is used in OpenLevV1 trade manipulation logic:

closeTrade

https://github.com/code-423n4/2022-01-openleverage/blob/main/openleverage-contracts/contracts/OpenLevV1.sol#L204

https://github.com/code-423n4

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-openleverage)

---

### Example 7: Use call instead of transfer

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** In both of the withdraw functions, `transfer()` is used for native ETH withdrawal.
The transfer() and send() functions forward a fixed amount of 2300 gas. Historically, it has often been recommended to use these functions for value transfers to guard against reentrancy attacks. However, the gas cost of EVM instructions may change significantly during hard forks which may break already deployed contract systems that make fixed assumptions about gas costs. For example. EIP 1884 broke several existing smart contracts due to a cost increase of the SLOAD instruction.

**Impact:** The use of the deprecated transfer() function for an address will inevitably make the transaction fail when:
- The claimer smart contract does not implement a payable function.
- The claimer smart contract does implement a payable fallback which uses more than 2300 gas unit.
- The claimer smart contract implements a payable fallback function that needs less than 2300 gas units but is called through proxy, raising the call's gas usage above 2300.

Additionally, using higher than 2300 gas might be mandatory for some multisig wallets.

**Recommended Mitigation:** Use call() instead of transfer().

**Protocol:**
Agree, transfer was causing issues with smart contract wallets.

**Cyfrin:** Verified in commit [7726ae7](https://github.com/HyperGood/woosh-contracts/commit/7726ae72118cfdf91ceb9129e36662f69f4d42de).

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 8: [M-01] Swap.sol implements potentially dangerous transfer 

**Source**: Code4rena
**Protocol**: Tally
**Impact**: MEDIUM

**Details**:

## Handle

elprofesor


## Vulnerability details

## Impact
The use of `  .transfer()`  in `  Swap.sol`   may have unintended outcomes on the eth being sent to the receiver. Eth may be irretrievable or undelivered if the `msg.sender`   or `  feeRecipient`   is a smart contract. Funds can potentially be lost if;

1. The smart contract fails to implement the payable fallback function 
2. The fallback function uses more than 2300 gas units

The latter situation may occur in the instance of gas cost changes. The impact would mean that any contracts receiving funds would potentially be unable to retrieve funds from the swap.

## Proof of Concept
This issue directly impacts the following lines of code: [L257](https://github.com/code-423n4/2021-10-tally/blob/c585c214edb58486e0564cb53d87e4831959c08b/contracts/swap/Swap.sol#L257), [L173](https://github.com/code-423n4/2021-10-tally/blob/c585c214edb58486e0564cb53d87e4831959c08b/contracts/swap/Swap.sol#L173), [L158](https://github.com/code-423n4/2021-10-tally/blob/c585c214edb58486e0564cb53d87e4831959c08b/contracts/swap/Swap.sol#L158)

Examples of similar issues ranked as medium can be found [here](https://github.com/code-423n4/2021-08-notional-findings/issues/15) and [here, just search for 'M04'](https://blog.openzeppelin.com/opyn-gamma-protocol-audit/). A detailed explanation of why relying on `payable().transfer()` may result in unexpected loss of eth can be found [here](https://consensys.net/diligence/blog/2019/09/stop-using-soliditys

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-10-tally)

---

### Example 9: [M-02] Use of `payable.transfer()` Might Render ETH Impossible to Withdraw

**Source**: Code4rena
**Protocol**: Escher
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/LPDA.sol#L105>

<https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/LPDA.sol#L85-L86>

<https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/FixedPrice.sol#L109>

<https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/OpenEdition.sol#L92>

### Impact

The protocol uses Soliditys `transfer()` when transferring ETH to the recipients. This has some notable shortcomings when the recipient is a smart contract, which can render ETH impossible to transfer. Specifically, the transfer will inevitably fail when the smart contract:

*   does not implement a payable fallback function, or
*   implements a payable fallback function which would incur more than 2300 gas units, or
*   implements a payable fallback function incurring less than 2300 gas units but is called through a proxy that raises the calls gas usage above 2300.

### Proof of Concept

[File: LPDA.sol](https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/LPDA.sol)

    85:            ISaleFactory(factory).feeReceiver().transfer(fee);
    86:            temp.saleReceiver.transfer(totalSale - fee);

    105:        payable(msg.sender).transfer(owed);

[File: FixedPrice.sol#L109](https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/FixedPrice.sol#L109)

    109:        ISaleFactory(factory).feeReceiver().transfer(address(this).balance / 20);

[File: OpenEdition.sol#L92](https://github.com/c

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-escher)

---

### Example 10: [M-11] Usage of deprecated transfer to send ETH

**Source**: Code4rena
**Protocol**: Backd
**Impact**: MEDIUM

**Details**:

_Submitted by peritoflores, also found by JC and StyxRave_

<https://github.com/code-423n4/2022-05-backd/blob/2a5664d35cde5b036074edef3c1369b984d10010/protocol/contracts/swappers/SwapperRouter.sol#L140>

<https://github.com/code-423n4/2022-05-backd/blob/2a5664d35cde5b036074edef3c1369b984d10010/protocol/contracts/swappers/SwapperRouter.sol#L280>

### Impact

Usage of deprecated transfer Swap can revert.

### Proof of Concept

The original `transfer` used to send eth uses a fixed stipend 2300 gas.   This was used to prevent reentrancy.   However this limit your protocol to interact with others contracts that need more than that to process the transaction.

A good article about that:
<https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/>.

### Recommended Mitigation Steps

Used call instead.  For example

        (bool success, ) = msg.sender.call{amount}("");
        require(success, "Transfer failed.");

**[chase-manning (Backd) confirmed](https://github.com/code-423n4/2022-05-backd-findings/issues/180)** 

**[Alex the Entreprenerd (judge) commented](https://github.com/code-423n4/2022-05-backd-findings/issues/180#issuecomment-1159810449):**
 > While submission is lazy in that it doesn't show the ways in which it could revert, (for example most of the times even a transfer to a gnosis-safe will not revert as the gas stipend is sufficient)
> 
> It's true that `transfer`s gas stipend may run out, causing reverts
> 
> For this reason I agree with Med Sev

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-backd)

---

### Example 11: [M-02] instead of `call()` , `transfer()` is used to withdraw the ether

**Source**: Code4rena
**Protocol**: LarvaLabs Meebits
**Impact**: MEDIUM

**Details**:

## Handle

JMukesh


## Vulnerability details

## Impact

function withdraw(uint amount) external {
        require(amount <= ethBalance[msg.sender]);
        ethBalance[msg.sender] = ethBalance[msg.sender].sub(amount);
        msg.sender.transfer(amount);
        emit Withdraw(msg.sender, amount);
    }

To withdraw eth it uses transfer(), this trnansaction will fail inevitably when : - 

1. The withdrwer smart contract does not implement a payable function.

2. Withdrawer smart contract does implement a payable fallback which uses more than 2300 gas unit

3. Thw withdrawer smart contract implements a payable fallback function whicn needs less than 2300 gas unit but is called through proxy that raise the call's gas usage above 2300

https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/




## Proof of Concept

   https://github.com/code-423n4/2021-04-redacted/blob/main/Beebots.sol#L649

## Tools Used

no tool used

## Recommended Mitigation Steps

use call() to send eth

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-04-meebits)

---

### Example 12: [M-04] Send ether with call instead of transfer

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

_Submitted by kenta, also found by Dravee, hyh, Jujic, leastwood, and z3s_

Use call instead of transfer to send ether. And return value must be checked if sending ether is successful or not.
Sending ether with the transfer is no longer recommended.

### Proof of Concept

[RewardDistributor.sol#L181](https://github.com/code-423n4/2022-02-redacted-cartel/blob/main/contracts/RewardDistributor.sol#L181)

### Recommended Mitigation Steps

(bool result, ) = payable(\_account).call{value: \_amount}("");
require(result, "Failed to send Ether");

**[kphed (Redacted Cartel) confirmed](https://github.com/code-423n4/2022-02-redacted-cartel-findings/issues/2)**


**[Alex the Entreprenerd (judge) commented](https://github.com/code-423n4/2022-02-redacted-cartel-findings/issues/2#issuecomment-1059781616):**
 > I believe the function would actually work with most Smart Contract Wallets and proxies. However this could change in the future.
> 
> Agree with the finding.



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-redacted-cartel)

---

### Example 13: [M-03] `transfer()` depends on gas consts

**Source**: Code4rena
**Protocol**: ENS
**Impact**: MEDIUM

**Details**:

[ETHRegistrarController.sol#L183-L185](https://github.com/code-423n4/2022-07-ens/blob/ff6e59b9415d0ead7daf31c2ed06e86d9061ae22/contracts/ethregistrar/ETHRegistrarController.sol#L183-L185)<br>
[ETHRegistrarController.sol#L204](https://github.com/code-423n4/2022-07-ens/blob/ff6e59b9415d0ead7daf31c2ed06e86d9061ae22/contracts/ethregistrar/ETHRegistrarController.sol#L204)<br>

`transfer()` forwards 2300 gas only, which may not be enough in future if the recipient is a contract and gas costs change. it could break existing contracts functionality.

### Proof of Concept

`.transfer` or `.send` method, only 2300 gas will be forwarded to fallback function. Specifically, the SLOAD instruction, will go from costing 200 gas to 800 gas.

If any smart contract has a functionality of register ens and it has fallback function which is making some state change in contract on ether receive, it could use more than 2300 gas and revert every transaction.

For reference, check out:
* <https://docs.soliditylang.org/en/v0.8.15/security-considerations.html?highlight=transfer#sending-and-receiving-ether>
* <https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/>

### Recommended Mitigation Steps

Use `.call` insted `.transfer`

     (bool success, ) = msg.sender.call.value(amount)("");
     require(success, "Transfer failed.");

**[jefflau (ENS) confirmed, but disagreed with severity and commented](https://github.com/code-423n4/2022-07-ens-findings/issues/133#issuecomment-11

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-ens)

---

### Example 14: M-5: `call()` should be used instead of `transfer()` on an address payable

**Source**: Sherlock
**Protocol**: DODO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-dodo-judging/issues/5 

## Found by 
ak1, Nyx, sach1r0, pashov, 0xNazgul, yixxas, 0x4non, virtualfact, Bnke0x0, Tomo, rvierdiiev, 8olidity, ElKu, defsec

## Summary

## Vulnerability Detail
The `transfer()` and `send()` functions forward a fixed amount of 2300 gas. Historically, it has often been recommended to use these functions for value transfers to guard against reentrancy attacks. However, the gas cost of EVM instructions may change significantly during hard forks which may break already deployed contract systems that make fixed assumptions about gas costs. For example. EIP 1884 broke several existing smart contracts due to a cost increase of the SLOAD instruction.

## Impact
The use of the deprecated transfer() function for an address will inevitably make the transaction fail when:

- The claimer smart contract does not implement a payable function.
- The claimer smart contract does implement a payable fallback which uses more than 2300 gas unit.
- The claimer smart contract implements a payable fallback function that needs less than 2300 gas units but is called through proxy, raising the call's gas usage above 2300.
- Additionally, using higher than 2300 gas might be mandatory for some multisig wallets.


## Code Snippet
[DODORouteProxy.sol#L152](https://github.com/sherlock-audit/2022-11-dodo/blob/main/contracts/SmartRoute/DODORouteProxy.sol#L152) `payable(routeFeeReceiver).transfer(restAmount);`
[DODORouteProxy.sol#L4

*[Content truncated...]*

---

### Example 15: M-4: Usage of deprecated transfer() can result in revert.

**Source**: Sherlock
**Protocol**: Harpie
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-harpie-judging/tree/main/007-M 

## Found by 
Lambda, cccz, yixxas, Waze, IEatBabyCarrots, pashov, 0xSmartContract, JohnSmith, Tomo, CodingNameKiki, sach1r0, IllIllI, csanuragjain, gogo

## Summary
The function withdrawPayments() is used by the Owners to withdraw the fees.

## Vulnerability Detail
transfer() uses a fixed amount of gas, which was used to prevent reentrancy. However this limit your protocol to interact with others contracts that need more than that to process the transaction.

Specifically, the withdrawal will inevitably fail when:
1.The withdrawer smart contract does not implement a payable fallback function.
2.The withdrawer smart contract implements a payable fallback function which uses more than 2300 gas units.
3.The withdrawer smart contract implements a payable fallback function which needs less than 2300 gas units but is called through a proxy that raises the calls gas usage above 2300.

## Impact
transfer() uses a fixed amount of gas, which can result in revert.
https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/

## Code Snippet
https://github.com/Harpieio/contracts/blob/97083d7ce8ae9d85e29a139b1e981464ff92b89e/contracts/Vault.sol#L159
https://github.com/Harpieio/contracts/blob/97083d7ce8ae9d85e29a139b1e981464ff92b89e/contracts/Vault.sol#L156-L160

## Tool used

Manual Review

## Recommendation
Use call instead of transfer(). Example:
(bool succeeded, ) = _to.call{value: _a

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 15
- Examples shown: 15
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## check-return-value-patterns.md
# Check Return Value Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 4 | 0 | 0 |

**Common Sources**: Sherlock, Spearbit, Halborn, TrailOfBits

---

## Detection Checklist

- [ ] Check for check return value vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Return value of low-level .call() not checked

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
Locations:
- Receiver.sol#L209
- Receiver.sol#L238
- Receiver.sol#L257

## Description
The low-level primitive `.call()` doesn't revert in the caller's context when the callee reverts. If its return value is not checked, it can lead the caller to falsely believe that the call was successful. The `Receiver.sol` contract uses `.call()` to transfer the native token to the receiver. If the receiver reverts, this can lead to locked ETH in the `Receiver` contract.

## Recommendation
Check the return value and revert if false is returned:

```solidity
-receiver.call{ value: amount }("");
+(bool success, ) = receiver.call{ value: amount }("");
+require(success);
```

## Additional Information
- **LiFi:** Fixed in PR 244.
- **Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-retainer1-Spearbit-Security-Review.pdf)

---

### Example 2: Missing check of return value of transfer and transferFrom

**Source**: TrailOfBits
**Protocol**: Frax Solidity
**Impact**: HIGH

**Details**:

## Frax Solidity Security Assessment

## Difficulty: Medium

## Type: Undefined Behavior

## Target: TWAMM.sol

### Description
Some tokens, such as BAT, do not precisely follow the ERC20 specification and will return
false or fail silently instead of reverting. Because the codebase does not consistently use
OpenZeppelins SafeERC20 library, the return values of calls to `transfer` and
`transferFrom` should be checked. However, return value checks are missing from these
calls in many areas of the code, opening the TWAMM contract (the time-weighted automated
market maker) to severe vulnerabilities.

```solidity
function provideLiquidity(uint256 lpTokenAmount) external {
    require(totalSupply() != 0, 'EC3');
    // execute virtual orders
    longTermOrders.executeVirtualOrdersUntilCurrentBlock(reserveMap);
    // the ratio between the number of underlying tokens and the number of lp tokens
    // must remain invariant after mint
    uint256 amountAIn = lpTokenAmount * reserveMap[tokenA] / totalSupply();
    uint256 amountBIn = lpTokenAmount * reserveMap[tokenB] / totalSupply();
    ERC20(tokenA).transferFrom(msg.sender, address(this), amountAIn);
    ERC20(tokenB).transferFrom(msg.sender, address(this), amountBIn);
}
```
*Figure 20.1: contracts/FPI/TWAMM.sol#L125-136*

### Exploit Scenario
Frax deploys the TWAMM contract. Pools are created with tokens that do not revert on
failure, allowing an attacker to call `provideLiquidity` and mint LP tokens for free; the
attacker does 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/FraxQ42021.pdf)

---

### Example 3: M-5: stakingContext.auraBooster.deposit boolean return value not handled in Boosted3TokenPoolUtils.sol

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/117 

## Found by 
ctf\_sec

## Summary

stakingContext.auraBooster.deposit boolean return value not handled in Boosted3TokenPoolUtils.sol

## Vulnerability Detail

the function _joinPoolAndStake in Boosted3TokenPoolUtils.sol is used extensively when handling the token stake.

However, when entering the stake and interacting with external contract, the logic does not handle the returned boolean value in the code below

```solidity
        // Transfer token to Aura protocol for boosted staking
        stakingContext.auraBooster.deposit(stakingContext.auraPoolId, bptMinted, true); // stake = true
```

In the AuraBooster implmenetation, a Boolean is indeed returned to acknowledge that deposit is completely successfully. 

https://etherscan.io/address/0x7818A1DA7BD1E64c199029E86Ba244a9798eEE10#code#F34#L1

```solidity
    /**
     * @notice  Deposits an "_amount" to a given gauge (specified by _pid), mints a `DepositToken`
     *          and subsequently stakes that on Convex BaseRewardPool
     */
    function deposit(uint256 _pid, uint256 _amount, bool _stake) public returns(bool){
```

## Impact

Notional -> AuraBooster -> BaseRewardPool

Without handling the boolean value explitily, there is risk that transaction may be fail sliently.

Because there are two layers of external call

## Code Snippet

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/i

*[Content truncated...]*

---

### Example 4: M-4: stakingContext.auraRewardPool.withdrawAndUnwrap boolean return value not handled in Boosted3TokenPoolUtils.sol and TwoTokenPoolUtils.sol

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/118 

## Found by 
ctf\_sec

## Summary

stakingContext.auraRewardPool.withdrawAndUnwrap boolean return value not handled in Boosted3TokenPoolUtils.sol and TwoTokenPoolUtils.sol

## Vulnerability Detail

When calling function _unstakeAndExitPool,

the contract withdraw BPT tokens back to the vault for redemption

by calling 

```solidity
stakingContext.auraRewardPool.withdrawAndUnwrap(bptClaim, false);
```

however, the underlying call withdrawAndUnwrap returns boolean value, the contract does not handle the return value.

The see the interface of the IAuraRewardPool already indicate that the underlying call returns value

```solidity
interface IAuraRewardPool {
    function withdrawAndUnwrap(uint256 amount, bool claim) external returns(bool);
```

and the underlying call with BaseRewardConvexPool.sol also returns the boolean

https://github.com/convex-eth/platform/blob/ece5998c54b0354a60f092e0dda1aa1f040ec8bd/contracts/contracts/BaseRewardPool.sol#L238

```solidity
    function withdrawAndUnwrap(uint256 amount, bool claim) public updateReward(msg.sender) returns(bool){
```

## Impact

Because there are stacks of external call:

Notional -> auraRewardPool -> BaseRewardPool,

without handling the return value explicitly, the transaction may risk fails silently.

## Code Snippet

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/internal/pool/Boosted3T

*[Content truncated...]*

---

### Example 5: NON-STANDARD ERC20 TOKENS WILL REVERT

**Source**: Halborn
**Protocol**: Primex Contracts
**Impact**: MEDIUM

**Details**:

##### Description

The library `TokenTransfersLibrary.sol` contains the function to perform ERC20 tokens transfers in the protocol. However, this library uses the interface of `IERC20` from OpenZeppelin which enforces the return value on transfer.

This pattern is not followed by all ERC20 tokens, as for example USDT. If attempting to transfer these tokens, the contract will revert, preventing the transaction to be executed.

Code Location
-------------

[TokenTransfersLibrary.sol#L12-L19](https://github.com/primex-finance/primex_contracts/blob/f809cc0471935013699407dcd9eab63b60cd2e22/src/contracts/libraries/TokenTransfersLibrary.sol#L12-L19)

#### TokenTransfersLibrary.sol

```
function doTransferFromTo(address token, address from, address to, uint256 amount) public returns (uint256) {
    uint256 balanceBefore = IERC20(token).balanceOf(to);
    // The returned value is checked in the assembly code below.
    // Arbitrary `from` should be checked at a higher level. The library function cannot be called by the user.
    // slither-disable-next-line unchecked-transfer arbitrary-send-erc20
    IERC20(token).transferFrom(from, to, amount);

    bool success;

```

[TokenTransfersLibrary.sol#L46-L51](https://github.com/primex-finance/primex_contracts/blob/f809cc0471935013699407dcd9eab63b60cd2e22/src/contracts/libraries/TokenTransfersLibrary.sol#L46-L51)

#### TokenTransfersLibrary.sol

```
function doTransferOut(address token, address to, uint256 amount) public {
    // The retur

*[Content truncated...]*

**Reference**: [View Original Finding](https://www.halborn.com/audits/primex/primex-contracts)

---

### Example 6: H-1: AuraSpell#openPositionFarm fails to return all rewards to user

**Source**: Sherlock
**Protocol**: Blueberry Update #2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-blueberry-judging/issues/29 

## Found by 
0x52, nobody2018
## Summary

When a user adds to an existing position on AuraSpell, the contract burns their current position and remints them a new one. The issues is that WAuraPool will send all reward tokens to the contract but it only sends Aura back to the user, causing all other rewards to be lost.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L256-L261

        for (uint i = 0; i < rewardTokens.length; i++) {
            IERC20Upgradeable(rewardTokens[i]).safeTransfer(
                msg.sender,
                rewards[i]
            );
        }

Inside WAuraPools#burn reward tokens are sent to the user.

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L130-L140

        IBank.Position memory pos = bank.getCurrentPositionInfo();
        if (pos.collateralSize > 0) {
            (uint256 pid, ) = wAuraPools.decodeId(pos.collId);
            if (param.farmingPoolId != pid)
                revert Errors.INCORRECT_PID(param.farmingPoolId);
            if (pos.collToken != address(wAuraPools))
                revert Errors.INCORRECT_COLTOKEN(pos.collToken);
            bank.takeCollateral(pos.collateralSize);
            wAuraPools.burn(pos.collId, pos.collateralSize);
            _doRefundRewards(AURA);
        }

We see above that t

*[Content truncated...]*

---

### Example 7: authAllowedForToken() returns prematurely in certain scenarios causing an authentication DoS

**Source**: Spearbit
**Protocol**: Sudoswap LSSVM2
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
LSSVMPairFactory.sol#L330-L377

## Description
Tokens listed on Nifty or Foundation (therefore returning a valid `niftyRegistry` or `foundationTreasury`) where the `proposedAuthAddress` is not a valid Nifty sender or a valid Foundation Treasury admin will cause an authentication DoS if the token were also listed on Digitalax or ArtBlocks and the `proposedAuthAddress` had admin roles on those platforms.

This happens because the return values of `valid` and `isAdmin` for `isValidNiftySender(proposedAuthAddress)` and `isAdmin(proposedAuthAddress)` respectively are returned as-is instead of returning only if/when they are true, but continuing the checks for authorization otherwise (if/when they are false) on Digitalax and ArtBlocks. 

`toggleSettingsForCollection` and `reclaimPair` (which utilize `authAllowedForToken`) would incorrectly fail for valid `proposedAuthAddress` in such scenarios.

## Recommendation
Check the return values of `valid` and `isAdmin` for `isValidNiftySender(proposedAuthAddress)` and `isAdmin(proposedAuthAddress)` and return if they are true (as done for Digitalax). Continue with the authorization checks otherwise, if/when they are false.

## Sudorandom Labs
Addressed in PR#64.

## Spearbit
Verified that this is fixed by PR#64.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/SudoswapLSSVM2-Spearbit-Security-Review.pdf)

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## transfer-result-check-patterns.md
# Transfer Result Check Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 2 | 0 | 0 |

**Common Sources**: Code4rena, Halborn

---

## Detection Checklist

- [ ] Check for transfer result check vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-02] The check for value transfer success is made after the return statement in `_withdrawFromYieldPool` of `LidoVault`

**Source**: Code4rena
**Protocol**: Sturdy
**Impact**: HIGH

**Details**:

Users can lose their funds

### Proof of Concept

[LidoVault.sol#L142](https://github.com/code-423n4/2022-05-sturdy/blob/78f51a7a74ebe8adfd055bdbaedfddc05632566f/smart-contracts/LidoVault.sol#L142)<br>

The code checks transaction success after returning the transfer value and finishing execution. If the call fails the transaction won't revert since  require(sent, Errors.VT_COLLATERAL_WITHDRAW_INVALID); won't execute.

Users will have withdrawn without getting their funds back.

### Recommended Mitigation Steps

Return the function after the success check

**[sforman2000 (Sturdy) confirmed](https://github.com/code-423n4/2022-05-sturdy-findings/issues/157)**

**[iris112 (Sturdy) commented](https://github.com/code-423n4/2022-05-sturdy-findings/issues/157):**
 > [Fix the issue of return before require sturdyfi/code4rena-may-2022#9](https://github.com/sturdyfi/code4rena-may-2022/pull/9)

**[hickuphh3 (judge) commented](https://github.com/code-423n4/2022-05-sturdy-findings/issues/157#issuecomment-1145546283):**
 > Issue is rather clear-cut.



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-sturdy)

---

### Example 2: NON-STANDARD ERC20 TOKENS WILL REVERT

**Source**: Halborn
**Protocol**: Primex Contracts
**Impact**: MEDIUM

**Details**:

##### Description

The library `TokenTransfersLibrary.sol` contains the function to perform ERC20 tokens transfers in the protocol. However, this library uses the interface of `IERC20` from OpenZeppelin which enforces the return value on transfer.

This pattern is not followed by all ERC20 tokens, as for example USDT. If attempting to transfer these tokens, the contract will revert, preventing the transaction to be executed.

Code Location
-------------

[TokenTransfersLibrary.sol#L12-L19](https://github.com/primex-finance/primex_contracts/blob/f809cc0471935013699407dcd9eab63b60cd2e22/src/contracts/libraries/TokenTransfersLibrary.sol#L12-L19)

#### TokenTransfersLibrary.sol

```
function doTransferFromTo(address token, address from, address to, uint256 amount) public returns (uint256) {
    uint256 balanceBefore = IERC20(token).balanceOf(to);
    // The returned value is checked in the assembly code below.
    // Arbitrary `from` should be checked at a higher level. The library function cannot be called by the user.
    // slither-disable-next-line unchecked-transfer arbitrary-send-erc20
    IERC20(token).transferFrom(from, to, amount);

    bool success;

```

[TokenTransfersLibrary.sol#L46-L51](https://github.com/primex-finance/primex_contracts/blob/f809cc0471935013699407dcd9eab63b60cd2e22/src/contracts/libraries/TokenTransfersLibrary.sol#L46-L51)

#### TokenTransfersLibrary.sol

```
function doTransferOut(address token, address to, uint256 amount) public {
    // The retur

*[Content truncated...]*

**Reference**: [View Original Finding](https://www.halborn.com/audits/primex/primex-contracts)

---

### Example 3: [M-06] Funds locked due to missing transfer check

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

All of the user's funds are unretrievably locked in the `PrizeVault` contract.

A combination of issues allows for the following scenario:

1. Alice invokes [`_withdraw(receiver, assets)`](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L925-L941) (via `burn()` or `withdraw()`).
2. The contract [computes the number of shares to redeem](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L933-L934), via `previewWithdraw(assets)`.
3. The contract [redeems as many shares](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L935-L936), but the ERC 4626-compliant vault returns fewer shares than expected. At this point, the contract holds fewer than `assets` tokens.
4. The contract [attempts to `transfer` assets to the receiver](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L939). This fails due to insufficient funds, but the ERC 20-compliant token does not revert (only returns `false`).
5. At this point, Alice's assets are locked in the `PrizeVault` contract. They cannot be withdrawn at a later point, because the corresponding prize vault and yield vault shares have been burned.

The exploit relies on insufficient handling of two corner cases of [ERC-20](https://eips.ether

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-03-pooltogether)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## revert-inside-hook-patterns.md
# Revert Inside Hook Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 1 | 0 | 0 |

**Common Sources**: Code4rena

---

## Detection Checklist

- [ ] Check for revert inside hook vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-07] GiantLP with a transferHookProcessor cant be burned, users funds will be stuck in the Giant Pool

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantLP.sol#L39-L47
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/GiantMevAndFeesPool.sol#L73-L78
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/SyndicateRewardsProcessor.sol#L51-L57


## Vulnerability details

## Impact
The GiantLP with a transferHookProcessor will call `transferHookProcessor.beforeTokenTransfer(_from, _to, _amount)` when it's transferred / minted / burned. 

But the `to` address is address(0x00) in the erc20 `_burn` function. The GiantMevAndFeesPool.beforeTokenTransfer will call the function `SyndicateRewardsProcessor._distributeETHRewardsToUserForToken` will a zero address check in the first line:
```
function _distributeETHRewardsToUserForToken(...) internal {
    require(_recipient != address(0), "Zero address");
```

So any withdraw function with a operation of burning the GiantLP token with a transferHookProcessor will revert because of the zero address check. The users' funds will be stuck in the Giant Pool contracts.

## Proof of Concept
I wrote a test about `GiantMevAndFeesPool.withdrawETH` function which is used to withdraw eth from the Giant Pool. It will be reverted.

test/foundry/LpBurn.t.sol
```
pragma solidity ^0.8.13;

// SPDX-License-Identifier: MIT
import {GiantPoolTests} from "./GiantPools.t.sol";

contract LpBurnTests is GiantPoolTests {
    function testburn() pub

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 2: [M-11] Lender can reject closing a position

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: MEDIUM

**Details**:

A credit line can be closed by using the `LineOfCredit.depositAndClose()` or `LineOfCredit.close`. The remaining funds deposited by the lender (`credit.deposit`) and the accumulated and paid interest are transferred to the lender.

However, if the used credit token `credit.token` is native ETH (or an ERC-777 token with receiver hooks, and under the assumption that the oracle supports this asset in the first place), the lender can reject the closing of the credit by reverting the token transfer.

### Impact

The lender can prevent the borrower from closing the credit line. This leads to the following consequences:

*   Migrating (rollover) to a new line is not possible (it requires all credits to be closed, see [SecuredLine.sol#L55](https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/SecuredLine.sol#L55))
*   Releasing a spigot and transferring ownership to the borrower is not possible (see [SpigotedLineLib.sol#L195](https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/utils/SpigotedLineLib.sol#L195))
*   Sweeping remaining tokens (e.g. revenue tokens) in the Spigot to the borrower is not possible (see [SpigotedLineLib.sol#L220](https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/utils/SpigotedLineLib.sol#L220>))

### Proof of Concept

[modules/credit/LineOfCredit.sol#L489-L493](https://github.com/debtdao/Line-of-Credit/blob/e8

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 3: [H-03] A majority attack can easily bypass Zora auction stage in OpenseaProposal and steal the NFT from the party.

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: HIGH

**Details**:

_Submitted by Trust_

The PartyGovernance system has many defenses in place to protect against a majority holder stealing the NFT. One of the main protections is that before listing the NFT on Opensea for a proposal-supplied price, it must first try to be auctioned off on Zora. To move from Zora stage to Opensea stage, `\_settleZoraAuction()` is called when executing ListedOnZora step in ListOnOpenseaProposal.sol. If the function returns false, the next step is executed which lists the item on Opensea. It is assumed that if majority attack proposal reaches this stage, it can steal the NFT for free, because it can list the item for negligible price and immediately purchase it from a contract that executes the Opensea proposal.

Indeed, attacker can always make `settleZoraAuction()` return false. Looking at  the code:

    try ZORA.endAuction(auctionId) {
                // Check whether auction cancelled due to a failed transfer during
                // settlement by seeing if we now possess the NFT.
                if (token.safeOwnerOf(tokenId) == address(this)) {
                    emit ZoraAuctionFailed(auctionId);
                    return false;
                }
            } catch (bytes memory errData) {

As the comment already hints, an auction can be cancelled if the NFT transfer to the bidder fails. This is the relevant AuctionHouse code (endAuction):

    {
                // transfer the token to the winner and pay out the participants below
                tr

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 4: [H-02] Rewards of GiantMevAndFeesPool can be locked for all users

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L172
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantLP.sol#L8


## Vulnerability details

## Impact
Any malicious user could make the rewards in GiantMevAndFeesPool inaccessible to all other users...

## Proof of Concept

https://gist.github.com/clems4ever/9b05391cc2192c1b6e8178faa38dfe41

Copy the file in the test suite and run the test.

## Tools Used

forge test

## Recommended Mitigation Steps

Protect the inherited functions of the ERC20 tokens (GiantLP and LPToken) because `transfer` is not protected and can trigger the `before` and `after` hooks. There is the same issue with LPToken and StakingFundsVault.

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


