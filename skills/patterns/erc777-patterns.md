# ERC777 Security Patterns

## Overview

**Frequency**: 11 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 7 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, OpenZeppelin

---

## Detection Checklist

- [ ] Check for erc777 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-10] BathToken.sol#_deposit() attacker can mint more shares with re-entrancy from hookable tokens

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

### Example 2: [H-01] Possible reentrancy during redemption/swap

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

### Example 3: [M-06] [Denial-of-Service] Contract Owner Could Block Users From Withdrawing Their Strike

**Source**: Code4rena
**Protocol**: Putty
**Impact**: MEDIUM

**Details**:

_Submitted by xiaoming90, also found by berndartmueller_

When users withdraw their strike escrowed in Putty contract, Putty will charge a certain amount of fee from the strike amount. The fee will first be sent to the contract owner, and the remaining strike amount will then be sent to the users.

<https://github.com/code-423n4/2022-06-putty/blob/3b6b844bc39e897bd0bbb69897f2deff12dc3893/contracts/src/PuttyV2.sol#L500>

```solidity
function withdraw(Order memory order) public {
	..SNIP..

	// transfer strike to owner if put is expired or call is exercised
	if ((order.isCall && isExercised) || (!order.isCall && !isExercised)) {
		// send the fee to the admin/DAO if fee is greater than 0%
		uint256 feeAmount = 0;
		if (fee > 0) {
			feeAmount = (order.strike * fee) / 1000;
			ERC20(order.baseAsset).safeTransfer(owner(), feeAmount);
		}

		ERC20(order.baseAsset).safeTransfer(msg.sender, order.strike - feeAmount);

		return;
	}
	..SNIP..
}
```

There are two methods on how the owner can deny user from withdrawing their strike amount from the contract

#### Method #1 - Set the `owner()` to `zero` address

Many of the token implementations do not allow transfer to `zero` address ([Reference](https://github.com/d-xo/weird-erc20#revert-on-transfer-to-the-zero-address)). Popular ERC20 implementations such as the following Openzeppelin's ERC20 implementation do not allow transfer to `zero` address, and will revert immediately if the `to` address (recipient) points to a `zero` address d

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-putty)

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

### Example 5: M-1: resolveQueuedTrades() ERC777 re-enter to steal funds

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

### Example 6: M-2: When tokenX is an ERC777 token, users can bypass maxLiquidity

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

### Example 7: [H-04] Staking rewards can be drained

**Source**: Code4rena
**Protocol**: Popcorn
**Impact**: HIGH

**Details**:

If ERC777 tokens are used for rewards, the entire balance of rewards in the staking contract can get drained by an attacker.

### Proof of Concept

ERC777 allow users to register a hook to notify them when tokens are transferred to them.

This hook can be used to reenter the contract and drain the rewards.

The issue is in the `claimRewards` in `MultiRewardStaking`.
The function does not follow the checks-effects-interactions pattern and therefore can be reentered when transferring tokens in the for loop. <br><https://github.com/code-423n4/2023-01-popcorn/blob/d95fc31449c260901811196d617366d6352258cd/src/utils/MultiRewardStaking.sol#L170-L187>

      function claimRewards(address user, IERC20[] memory _rewardTokens) external accrueRewards(msg.sender, user) {
        for (uint8 i; i < _rewardTokens.length; i++) {
          uint256 rewardAmount = accruedRewards[user][_rewardTokens[i]];

          if (rewardAmount == 0) revert ZeroRewards(_rewardTokens[i]);

          EscrowInfo memory escrowInfo = escrowInfos[_rewardTokens[i]];

          if (escrowInfo.escrowPercentage > 0) {
            _lockToken(user, _rewardTokens[i], rewardAmount, escrowInfo);
            emit RewardsClaimed(user, _rewardTokens[i], rewardAmount, true);
          } else {
            _rewardTokens[i].transfer(user, rewardAmount);
            emit RewardsClaimed(user, _rewardTokens[i], rewardAmount, false);
          }

          accruedRewards[user][_rewardTokens[i]] = 0;
        }

As can be seen above, t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-popcorn)

---

### Example 8: Reentrancy risk in depositing to the queue

**Source**: OpenZeppelin
**Protocol**: Pods Finance Ethereum Volatility Vault Audit #1
**Impact**: HIGH

**Details**:

The internal[`_deposit`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/BaseVault.sol#L407)function handles user deposits, transferring a specified amount of`stETH`from`msg.sender`to the vault. Before moving the funds, it adds the deposit to the queue, which is processed later by the[`processQueuedDeposits`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/BaseVault.sol#L371)function.


As the underlying token could have hooks that allow the token sender to execute code before the transfer (e.g., ERC777 standard), a malicious user could use those hooks to re-enter the`deposit`function multiple times.


This re-entrancy will result in an increment in the receiver balance on the queue, even though this balance will not correspond to the actual amount deposited into the vault.


In the current implementation, the`_deposit`function in the`BaseVault`contract is overridden by the[implementation in the`STETHVault`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/STETHVault.sol#L113-L126), which has the correct order of operation. However, the`BaseVault`is likely to be inherited by future vaults, so it is crucial to have the correct`_deposit`implementation in this contract in case it is not overridden.


Consider reordering the calls, doing the transfer first, and then adding th

*[Content truncated...]*

**Reference**: [View Original Finding](https://blog.openzeppelin.com/pods-finance-ethereum-volatility-vault-audit-1/)

---

### Example 9: [M-04] Auction created by ERC777 Tokens with tax can be stolen by re-entrancy attack

**Source**: Code4rena
**Protocol**: SIZE
**Impact**: MEDIUM

**Details**:

The createAuction function lacks the check of re-entrancy. An attacker can use an ERC777 token with tax as the base token to create auctions. By registering ERC777TokensSender interface implementer in the ERC1820Registry contract, the attacker can re-enter the createAuction function and create more than one auction with less token. And the sum of the totalBaseAmount of these auctions will be greater than the token amount received by the SizeSealed contract. Finally, the attacker can take more money from the contract global pool which means stealing tokens from the other auctions and treasury.

### Proof of Concept

Forge test

    // SPDX-License-Identifier: GPL-3.0
    pragma solidity 0.8.17;

    import {Test} from "forge-std/Test.sol";

    import {SizeSealedTest} from "./SizeSealed.t.sol";
    import {ERC777} from "openzeppelin-contracts/contracts/token/ERC777/ERC777.sol";
    import "openzeppelin-contracts/contracts/utils/introspection/IERC1820Registry.sol";
    import {MockSeller} from "./mocks/MockSeller.sol";
    import {MockERC20} from "./mocks/MockERC20.sol";

    contract TaxERC777 is ERC777{
        uint32 tax = 50; // 50% tax rate

        constructor(string memory name_,
            string memory symbol_,
            address[] memory defaultOperators_) ERC777(name_, symbol_, defaultOperators_){}
        
        function mint(address rec, uint256 amount) external{
            super._mint(rec, amount, "", "", false);
        }

        function _beforeTokenTransf

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-size)

---

### Example 10: [M-05] DOS possible while stopping a rental with erc777 tokens

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L265> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L100>

If an order involves erc777 token for a pay order then in the `tokensReceived` callback the renter can create DOS situation resulting in the lender's assets being stuck in the rental safe.

### Proof of Concept

[ERC777 token standard](https://eips.ethereum.org/EIPS/eip-777) which is backward compatible with `erc20` implies that on the transfer of the tokens the recipient can implement a `tokensReceived` hook to notify of any increment of the balance.

Now suppose a pay order is created with an erc 777 consideration asset as there is no restriction on that and also the eip specifies that

    The difference for new contracts implementing ERC-20 is that tokensToSend and tokensReceived hooks take precedence over ERC-20. Even with an ERC-20 transfer and transferFrom call, the token contract MUST check via ERC-1820 if the from and the to address implement tokensToSend and tokensReceived hook respectively. If any hook is implemented, it MUST be called. Note that when calling ERC-20 transfer on a contract, if the contract does not implement tokensReceived, the transfer call SHOULD still be accepted even if this means the tokens will probably be locked.

So the `tokensReceived` hook is optional for a `transfer/transferFrom` call. Hence sendin

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 11: [M-01] User can bypass `entryFee` by sending arbitrary `calldata` to ParaSwap operator

**Source**: Code4rena
**Protocol**: Nested Finance
**Impact**: MEDIUM

**Details**:

_Submitted by 0xDjango_

[NestedFactory.sol#L466](https://github.com/code-423n4/2022-06-nested/blob/b4a153c943d54755711a2f7b80cbbf3a5bb49d76/contracts/NestedFactory.sol#L466)<br>
[ParaswapOperator.sol#L34](https://github.com/code-423n4/2022-06-nested/blob/b4a153c943d54755711a2f7b80cbbf3a5bb49d76/contracts/operators/Paraswap/ParaswapOperator.sol#L34)<br>

Any user is able to bypass the `entryFee` collection when using `NestedFactory.create()` by passing in arbitrary calldata when using the ParaSwap router. High level, a user can pass in calldata to swap from a miniscule amount of input token to an ERC777 with themselves as the recipient and will gain control of execution, at which time they can send a large amount of output token back to the Nested Factory.

If the user sends `1 wei` of input token, the Nested Factory will return an `entryFee` of `0` due to precision loss. The amount of output token returned to the contract via the direct transfer from the user will then be deposited in the vault.

### Proof of Concept

**Steps**

*   User calls `NestedFactory.create()` with a single input order. This input order will define the parameters of the call to Paraswap.
*   The single order defines the following in pseudocode:
    1.  inputToken: Any token, but we'll use address(0) ETH
    2.  amount: 1 wei
    3.  Order(operator=Paraswap, token=USDC, calldata=calldata)

***The calldata used in the call to paraswap would swap from ETH to any ERC777 (NOT USDC), with an attack contrac

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-nested)

---

## Statistics

- Total findings analyzed: 11
- Examples shown: 11
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

