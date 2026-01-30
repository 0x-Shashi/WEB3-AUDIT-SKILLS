# ERC20 Security Patterns

## Overview

**Frequency**: 27 occurrences (0.05% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 10 | 15 | 2 | 0 |

**Common Sources**: Code4rena, Sherlock, Cyfrin, Pashov Audit Group, Shieldify

---

## Detection Checklist

- [ ] Check for erc20 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] Unchecked ERC20 transfers can cause lock up

**Source**: Code4rena
**Protocol**: Reality Cards
**Impact**: HIGH

**Details**:

_Submitted by [axic](https://twitter.com/alexberegszaszi), also found by [gpersoon](https://twitter.com/gpersoon), [pauliax](https://twitter.com/SolidityDev), [Jmukesh](https://twitter.com/MukeshJ_eth), [a_delamo](https://twitter.com/a_delamo), [s1m0](https://twitter.com/_smonica_), [cmichel](https://twitter.com/cmichelio), and [shw](https://github.com/x9453)_

Some major tokens went live before ERC20 was finalized, resulting in a discrepancy whether the transfer functions should (A) return a boolean or (B) revert/fail on error. The current best practice is that they should revert, but return “true” on success. However, not every token claiming ERC20-compatibility is doing this — some only return true/false; some revert, but do not return anything on success. This is a well known issue, heavily discussed since mid-2018.

Today many tools, including OpenZeppelin, offer [a wrapper for “safe ERC20 transfer”](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol):

RealityCards is not using such a wrapper, but instead tries to ensure successful transfers via the `balancedBooks` modifier:

```solidity
modifier balancedBooks {
    _;
    // using >= not == in case anyone sends tokens direct to contract
    require(
        erc20.balanceOf(address(this)) >=
            totalDeposits + marketBalance + totalMarketPots,
        "Books are unbalanced!"
    );
}
```

This modifier is present on most functions, but is missing on `topu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-06-realitycards)

---

### Example 2: [H-01]  Someone can create non-liquidatable auction if the collateral asset fails on transferring to address(0)

**Source**: Code4rena
**Protocol**: Yield
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-07-yield/blob/main/contracts/Witch.sol#L176
https://github.com/code-423n4/2022-07-yield/blob/6ab092b8c10e4dabb470918ae15c6451c861655f/contracts/Witch.sol#L399


## Vulnerability details

## Impact
might lead to systematic debt. Cause errors for liquidators to run normally.

## Proof of Concept
In the function `auction`, there is on input validation around whether the `to` is `address(0)` or not. and if the `auctioneerReward` is set to an value > 0 (as default),  each liquidate call will call `Join` module to pay out to `auctioneer` with the following line:

```jsx
if (auctioneerCut > 0) {
    ilkJoin.exit(auction_.auctioneer, auctioneerCut.u128());
}
```

This line will revert if `auctioneer` is set to `address(0)` on some tokens (revert on transferring to address(0) is a [default behaviour of the OpenZeppelin template](https://www.notion.so/Yield-Witch-555e6981c26b41008d03a504077b4770)). So if someone start an `auction` with `to = address(0)`, this auction becomes un-liquidatable.

A malicious user can run a bot to monitor his own vault, and if the got underwater and they don’t have enough collateral to top up, they can immediately start an auction on their own vault and set actioneer to `0` to avoid actually being liquidated, which breaks the design of the system.


## Recommended Mitigation Steps

Add check while starting an auction:

```jsx
function auction(bytes12 vaultId, address to)
    external
    returns (DataType

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-yield)

---

### Example 3: [H-01] Deprecated `safeApprove()` usage blocks collateral approval to pool

**Source**: Pashov Audit Group
**Protocol**: Hyperlend_2025-11-21
**Impact**: HIGH

**Details**:

_Resolved_

## Severity

**Impact:** Medium

**Likelihood:** High

## Description

Project uses Openzeppelin@v4.9.6, which deprecates `safeApprove()`. Safe approve usage is not safe here because it blocks every approval if approval for the collateral is non-zero:

```solidity
//    function executeOperation()

        for (uint256 i = 0; i < _collateralActions.length; ++i){
            uint256 amount = _collateralActions[i].amount;
            IERC20 token = _collateralActions[i].token;

            //transfer tokens from the caller & approve pool contract to spend them
            token.safeTransferFrom(msg.sender, address(this), amount);
@>          token.safeApprove(address(pool), type(uint256).max);

            //supply tokens on behalf of the msg.sender
            pool.supply(address(token), amount, msg.sender, 0);
        }
```

https://github.com/OpenZeppelin/openzeppelin-contracts/blob/dc44c9f1a4c3b10af99492eed84f83ed244203f6/contracts/token/ERC20/utils/SafeERC20.sol#L45-L54

```solidity
    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOp

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Hyperlend-security-review_2025-11-21.md)

---

### Example 4: [H-02] DoS: Blacklisted user may prevent withdrawExcessRewards()

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

### Example 5: `TokenSaleProposal::buy` implicitly assumes that buy token has 18 decimals resulting in a potential total loss scenario for Dao Pool

**Source**: Cyfrin
**Protocol**: Dexe
**Impact**: HIGH

**Details**:

**Description:** `TokenSaleProposalBuy::buy` is called by users looking to buy the DAO token using a pre-approved token. The exchange rate for this sale is pre-assigned for the specific tier. This function internally calls `TokenSaleProposalBuy::_purchaseWithCommission` to transfer funds from the buyer to the gov pool. Part of the transferred funds are used to pay the DexeDAO commission and balance funds are transferred to the `GovPool` address. To do this, `TokenSaleProposalBuy::_sendFunds` is called.

```solidity
    function _sendFunds(address token, address to, uint256 amount) internal {
        if (token == ETHEREUM_ADDRESS) {
            (bool success, ) = to.call{value: amount}("");
            require(success, "TSP: failed to transfer ether");
        } else {
  >>          IERC20(token).safeTransferFrom(msg.sender, to, amount.from18(token.decimals())); //@audit -> amount is assumed to be 18 decimals
        }
    }
```

Note that this function assumes that the `amount` of ERC20 token is always 18 decimals. The `DecimalsConverter::from18` function converts from a base decimal (18) to token decimals. Note that the amount is directly passed by the buyer and there is no prior normalisation done to ensure the token decimals are converted to 18 decimals before the `_sendFunds` is called.


**Impact:** It is easy to see that for tokens with smaller decimals, eg. USDC with 6 decimals, will cause a total loss to the DAO. In such cases amount is presumed to be 18 decimals & on

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-10-cyfrin-dexe.md)

---

### Example 6: Missing check of return value of transfer and transferFrom

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
OpenZeppelin’s SafeERC20 library, the return values of calls to `transfer` and
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

### Example 7: [M-06] [Denial-of-Service] Contract Owner Could Block Users From Withdrawing Their Strike

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

### Example 8: [H-03] Result of transfer / transferFrom not checked

**Source**: Code4rena
**Protocol**: Spartan Protocol
**Impact**: HIGH

**Details**:

## Handle

gpersoon


## Vulnerability details

## Impact
A call to transferFrom or transfer is frequently done without checking the results.
For certain ERC20 tokens, if insufficient tokens are present, no revert occurs but a result of "false" is returned.
So its important to check this. If you don't you could mint tokens without have received sufficient tokens to do so. So you could loose funds.

Its also a best practice to check this.
See below for example where the result isn't checked.

Note, in some occasions the result is checked (see below for examples).

## Proof of Concept
Highest risk:
.\Dao.sol:                iBEP20(_token).transferFrom(msg.sender, address(this), _amount); // Transfer user's assets to Dao contract
.\Pool.sol:               iBEP20(TOKEN).transfer(member, outputToken); // Transfer the TOKENs to user
.\Pool.sol:               iBEP20(token).transfer(member, outputAmount); // Transfer the swap output to the selected user
.\poolFactory.sol:   iBEP20(_token).transferFrom(msg.sender, _pool, _amount);
.\Router.sol:           iBEP20(_fromToken).transfer(fromPool, iBEP20(_fromToken).balanceOf(address(this))); // Transfer TOKENs from ROUTER to fromPool
.\Router.sol:           iBEP20(_token).transfer(_pool, iBEP20(_token).balanceOf(address(this))); // Transfer TOKEN to pool
.\Router.sol:           iBEP20(_token).transferFrom(msg.sender, _pool, _amount); // Transfer TOKEN to pool
.\Router.sol:           iBEP20(_token).transfer(_recipient, _amount); // Transfer

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-spartan)

---

### Example 9: [M-15]  Blocklisting in payment ERC20 can cause rented NFT to be stuck in Safe

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

### Example 10: M-1: Anyone can spend on behalf of roller periphery

**Source**: Sherlock
**Protocol**: Sense
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/48 

## Found by 
8olidity, 0x52, supernova, ctf\_sec, pashov, cryptphi, minhquanym

## Summary
The approve() function in RollerPeriphery contract allows anyone to spend ERC20 token owned by the contract

## Vulnerability Detail
RollerPeriphery.approve() does not have any access control, this allows any user to be able to call the approve call which would make an ERC20 approve call to the token inputed, and allowing the 'to' address to spend. In the cases where RollerPeriphery owns some ERC20 tokens. The user will be able to transfer the tokens from the contract as a spender.

## Impact
Loss of funds

## Code Snippet
https://github.com/sherlock-audit/2022-11-sense/blob/main/contracts/src/RollerPeriphery.sol#L100-L102

```solidity
function approve(ERC20 token, address to, uint256 amount) public payable {
        token.safeApprove(to, amount);
    }
```

ERC20 approve call is:
```solidity
function approve(address spender, uint256 amount) public virtual returns (bool) {
        allowance[msg.sender][spender] = amount;

        emit Approval(msg.sender, spender, amount);

        return true;
    }
```

## Tool used
Manual Review

## Recommendation
There should be some access control, according to the provided contracts, this function is called by RollerFactory, this can be the only address allowed to call the RollerPeriphery.approve() function.

## Discussion

**jparklev**

We don't expect that the Periphery 

*[Content truncated...]*

---

### Example 11: M-3: `universalApproveMax` will not work for some tokens that don't support approve `type(uint256).max` amount.

**Source**: Sherlock
**Protocol**: DODO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-dodo-judging/issues/41 

## Found by 
Tomo, jayphbee

## Summary
`universalApproveMax` will not work for some tokens that don't support approve `type(uint256).max` amount.

## Vulnerability Detail
There are tokens that doesn't support approve spender `type(uint256).max` amount. So the `universalApproveMax` will not work for some tokens like `UNI` or `COMP` who will revert when approve `type(uint256).max` amount.

## Impact
Tokens that don't support approve `type(uint256).max` amount could not be swapped by calling `externalSwap` function.

## Code Snippet
https://github.com/sherlock-audit/2022-11-dodo/blob/main/contracts/SmartRoute/DODORouteProxy.sol#L181-L183
```solidity
            if (approveTarget != address(0)) {
                IERC20(fromToken).universalApproveMax(approveTarget, fromTokenAmount);
            }
```
https://github.com/sherlock-audit/2022-11-dodo/blob/main/contracts/SmartRoute/lib/UniversalERC20.sol#L36-L48
```solidity
function universalApproveMax(
        IERC20 token,
        address to,
        uint256 amount
    ) internal {
        uint256 allowance = token.allowance(address(this), to);
        if (allowance < amount) {
            if (allowance > 0) {
                token.safeApprove(to, 0);
            }
            token.safeApprove(to, type(uint256).max);
        }
    }
```

## Tool used

Manual Review

## Recommendation
I would suggest approve only the necessay amount of token to the `approveTa

*[Content truncated...]*

---

### Example 12: [H-01] Can deposit native token for free and steal funds

**Source**: Code4rena
**Protocol**: Biconomy
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by CertoraInc_

[LiquidityPool.sol#L151](https://github.com/code-423n4/2022-03-biconomy/blob/db8a1fdddd02e8cc209a4c73ffbb3de210e4a81a/contracts/hyphen/LiquidityPool.sol#L151)<br>

The `depositErc20` function allows setting `tokenAddress = NATIVE` and does not throw an error.<br>
No matter the `amount` chosen, the `SafeERC20Upgradeable.safeTransferFrom(IERC20Upgradeable(tokenAddress), sender, address(this), amount);` call will not revert because it performs a low-level call to `NATIVE = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE`, which is an EOA, and the low-level calls to EOAs always succeed.<br>
Because the `safe*` version is used, the EOA not returning any data does not revert either.<br>

This allows an attacker to deposit infinite native tokens by not paying anything.<br>
The contract will emit the same `Deposit` event as a real `depositNative` call and the attacker receives the native funds on the other chain.

### Recommended Mitigation Steps

Check `tokenAddress != NATIVE` in `depositErc20`.

**[ankurdubey521 (Biconomy) confirmed and commented](https://github.com/code-423n4/2022-03-biconomy-findings/issues/55):**
 > [HP-25: C4 Audit Fixes, Dynamic Fee Changes bcnmy/hyphen-contract#42](https://github.com/bcnmy/hyphen-contract/pull/42)

**[pauliax (judge) commented](https://github.com/code-423n4/2022-03-biconomy-findings/issues/55#issuecomment-1094973634):**
 > Great find, definitely deserves a severity of high.



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-biconomy)

---

### Example 13: [M-02] Use `safeTransfer()` and `safeTransferFrom()` Instead of `transfer()` and `transferFrom()`

**Source**: Shieldify
**Protocol**: Swappee
**Impact**: MEDIUM

**Details**:

## Severity

Medium Risk

## Description

Tokens that do not comply with the ERC20 specification could return false from the transfer
function call to indicate the transfer fails, while the calling contract would not notice the failure if the return
value is not checked. Checking the return value is a requirement, as written in the EIP-20 specification:

"Callers MUST handle false from returns (bool success). Callers MUST NOT assume that
false is never returned!"

Some tokens do not return a bool (e.g. USDT, BNB, OMG) on ERC20 methods. This will make the call break,
making it impossible to use these tokens.

## Location of Affected Code

File: [src/Swappee.sol](https://github.com/smilee-finance/swappee-smart-contracts/blob/16315aa674ffce54e36fadca66da3cf6785150de/src/Swappee.sol)

```solidity
IERC20(inputToken).transferFrom(msg.sender, address(this), amount);
```

```solidity
IERC20(outputToken).transfer(msg.sender, amountOut);
```

```solidity
IERC20(token).transfer(msg.sender, amount);
```

## Impact

It would not revert even though the transaction failed.

## Recommendation

Use `SafeTransferLib` or `SafeERC20`, replace transfer with `safeTransfer()` and `transferFrom()` with `safeTransferFrom()` when transferring `ERC20` tokens.

## Team Response

Fixed.

**Reference**: [View Original Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/Swappee-Security-Review.md)

---

### Example 14: NON-STANDARD ERC20 TOKENS WILL REVERT

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

### Example 15: [M-06] Funds locked due to missing transfer check

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

### Example 16: [M-01] Zero amount token transfers may cause a denial of service during liquidations

**Source**: Code4rena
**Protocol**: Particle Protocol
**Impact**: MEDIUM

**Details**:

Some ERC20 implementations revert on zero value transfers. Since liquidation rewards are based on a fraction of the available position's premiums, this may cause an accidental denial of service that prevents the successful execution of liquidations.

### Impact

Liquidations in the LAMM protocol are incentivized by a reward that is calculated as a fraction of the premiums available in the position.

<https://github.com/code-423n4/2023-12-particle/blob/a3af40839b24aa13f5764d4f84933dbfa8bc8134/contracts/protocol/ParticlePositionManager.sol#L348-L354>

```solidity
348:         // calculate liquidation reward
349:         liquidateCache.liquidationRewardFrom =
350:             ((closeCache.tokenFromPremium) * LIQUIDATION_REWARD_FACTOR) /
351:             uint128(Base.BASIS_POINT);
352:         liquidateCache.liquidationRewardTo =
353:             ((closeCache.tokenToPremium) * LIQUIDATION_REWARD_FACTOR) /
354:             uint128(Base.BASIS_POINT);
```

These amounts are later transferred to the caller, the liquidator, at the end of the `liquidatePosition()` function.

<https://github.com/code-423n4/2023-12-particle/blob/a3af40839b24aa13f5764d4f84933dbfa8bc8134/contracts/protocol/ParticlePositionManager.sol#L376-L378>

```solidity
376:         // reward liquidator
377:         TransferHelper.safeTransfer(closeCache.tokenFrom, msg.sender, liquidateCache.liquidationRewardFrom);
378:         TransferHelper.safeTransfer(closeCache.tokenTo, msg.sender, liquidateCache.liquidationReward

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-12-particle)

---

### Example 17: Fee-on-transfer tokens are not supported

**Source**: Cyfrin
**Protocol**: Swapexchange
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol intends to support all ERC20 tokens but does not support fee-on-transfer tokens.
The protocol utilizes the functions `TransferUtils::_transferERC20()` and `TransferUtils::_transferFromERC20()` to transfer ERC20 tokens.

```solidity
TransferUtils.sol
34:     function _transferERC20(address token, address to, uint256 amount) internal {
35:         IERC20 erc20 = IERC20(token);
36:         require(erc20 != IERC20(address(0)), "Token Address is not an ERC20");
37:         uint256 initialBalance = erc20.balanceOf(to);
38:         require(erc20.transfer(to, amount), "ERC20 Transfer failed");
39:         uint256 balance = erc20.balanceOf(to);
40:         require(balance >= (initialBalance + amount), "ERC20 Balance check failed");//@audit-issue reverts for fee on transfer token
41:     }
```

The implementation verifies that the transfer was successful by checking that the balance of the recipient is greater than or equal to the initial balance plus the amount transferred. This check will fail for fee-on-transfer tokens because the actual received amount will be less than the input amount. (Read [here](https://github.com/d-xo/weird-erc20#fee-on-transfer) about fee-on-transfer tokens)

Although there are very few fee-on-transfer tokens, the protocol can't say it supports all ERC20 tokens if it doesn't support these weird ERC20 tokens.

**Impact:** Fee-on-transfer tokens can not be used for the protocol.
Because of the rarity of these

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-swapexchange.md)

---

### Example 18: Use safe transfer for ERC20 tokens

**Source**: Cyfrin
**Protocol**: Swapexchange
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol intends to support all ERC20 tokens but the implementation uses the original transfer functions.
Some tokens (like USDT) do not implement the EIP20 standard correctly and their transfer/transferFrom function return void instead of a success boolean. Calling these functions with the correct EIP20 function signatures will revert.

```solidity
TransferUtils.sol
34:     function _transferERC20(address token, address to, uint256 amount) internal {
35:         IERC20 erc20 = IERC20(token);
36:         require(erc20 != IERC20(address(0)), "Token Address is not an ERC20");
37:         uint256 initialBalance = erc20.balanceOf(to);
38:         require(erc20.transfer(to, amount), "ERC20 Transfer failed");//@audit-issue will revert for USDT
39:         uint256 balance = erc20.balanceOf(to);
40:         require(balance >= (initialBalance + amount), "ERC20 Balance check failed");
41:     }
```

**Impact:** Tokens that do not correctly implement the EIP20 like USDT, will be unusable in the protocol as they revert the transaction because of the missing return value.

**Recommended Mitigation:** We recommend using OpenZeppelin's SafeERC20 versions with the safeTransfer and safeTransferFrom functions that handle the return value check as well as non-standard-compliant tokens.

**Protocol:** Fixed in commit [564f711](https://github.com/SwapExchangeio/Contracts/commit/564f711c6f915f5a7696739266a1f8059ee9a172)

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-swapexchange.md)

---

### Example 19: [M-13] amount requires to be updated to contract balance increase (1)

**Source**: Code4rena
**Protocol**: FactoryDAO
**Impact**: MEDIUM

**Details**:

_Submitted by MaratCerby, also found by 0x1337, 0x52, 0xYamiDancho, AuditsAreUS, berndartmueller, cccz, CertoraInc, csanuragjain, defsec, Dravee, GimelSec, hickuphh3, horsefacts, hyh, IllIllI, jayjonah8, kenzo, leastwood, mtz, p4st13r4, PPrieditis, reassor, Ruhum, throttle, TrungOre, VAD37, wuwe1, and ych18_

Every time transferFrom or transfer function in ERC20 standard is called there is a possibility that underlying smart contract did not transfer the exact amount entered.

It is required to find out contract balance increase/decrease after the transfer.<br>
This pattern also prevents from re-entrancy attack vector.

### Recommended Mitigation Steps

Recommended code:

```solidity
function fundPool(uint poolId) internal {
    Pool storage pool = pools[poolId];
    bool success = true;
    uint amount;
    for (uint i = 0; i < pool.rewardFunding.length; i++) {
        amount = getMaximumRewards(poolId, i);
        // transfer the tokens from pool-creator to this contract


        uint256 balanceBefore = IERC20(pool.rewardTokens[i]).balanceOf(address(this)); // remembering asset balance before the transfer
        IERC20(pool.rewardTokens[i]).safeTransferFrom(msg.sender, address(this), amount);
        uint256 newAmount = IERC20(pool.rewardTokens[i]).balanceOf(address(this)) - balanceBefore; // updating actual amount to the contract balance increase
        success = success && newAmount == amount; // making sure amounts match

        // bookkeeping to make sure pools don'

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-factorydao)

---

### Example 20: [H-01] Unsafe usage of ERC20 transfer and transferFrom 

**Source**: Code4rena
**Protocol**: FIAT DAO
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-08-fiatdao/blob/fece3bdb79ccacb501099c24b60312cd0b2e4bb2/contracts/VotingEscrow.sol#L425-L428
https://github.com/code-423n4/2022-08-fiatdao/blob/fece3bdb79ccacb501099c24b60312cd0b2e4bb2/contracts/VotingEscrow.sol#L485-L488
https://github.com/code-423n4/2022-08-fiatdao/blob/fece3bdb79ccacb501099c24b60312cd0b2e4bb2/contracts/VotingEscrow.sol#L546
https://github.com/code-423n4/2022-08-fiatdao/blob/fece3bdb79ccacb501099c24b60312cd0b2e4bb2/contracts/VotingEscrow.sol#L657
https://github.com/code-423n4/2022-08-fiatdao/blob/fece3bdb79ccacb501099c24b60312cd0b2e4bb2/contracts/VotingEscrow.sol#L676


## Vulnerability details

## Impact
Some ERC20 tokens functions don't return a boolean, for example USDT, BNB, OMG. So the `VotingEscrow` contract simply won't work with tokens like that as the `token`. 

## Proof of Concept
The USDT's `transfer` and `transferFrom` functions doesn't return a bool, so the call to these functions will revert although the user has enough balance and the `VotingEscrow` contract won't work, assuming that token is USDT.

## Tools Used
Manual auditing - VS Code, some hardhat tests and me :)

## Recommended Mitigation Steps
Use the OpenZepplin's `safeTransfer` and `safeTransferFrom` functions

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-fiatdao)

---

### Example 21: [L-08] `protocolCut` not actually burned during `_mintBox`

**Source**: Pashov Audit Group
**Protocol**: WishWish_2025-11-04
**Impact**: LOW

**Details**:

_Resolved_

Code comments suggest that the `WishWishManager::_mintBox` function calculates a `protocolCut` meant to be burned when users mint boxes. However, instead of invoking a burn function, the code simply transfers the tokens to `address(0)`, which does not reduce the `totalSupply`. As a result, the tokens remain in circulation.

```solidity
// WishWishManager.sol
    function _mintBox(MintData calldata mintData, bytes calldata signature) internal {
...
        if (mintData.fee != 0) {
            uint256 protocolCut = (mintData.fee * $.MINT_FEE_PERCENT) / 1 ether;
            creatorCut = mintData.fee - protocolCut;
            $.wishToken.transferFrom(msg.sender, address(0), protocolCut); // burn protocol fee
            $.wishToken.transferFrom(msg.sender, c.creatorAddress, creatorCut);
            WishWishToken(address($.wishToken)).creditCreator(c.creatorAddress, creatorCut);
        }
...
```

**Note that it is still possible for the protocol to recover the `protocolCut` tokens sent to `address(0)` since the `$.manager` state variable can be updated and the `ERC20::_transfer` function (inherited from Solady) does not have any restrictions against transferring to or from `address(0)`:**

```solidity
// WishWishToken.sol
    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        WishWishTokenStateStorage storage $ = _getStorage();
        if (msg.sender != $.manager) revert TransfersRestricted();
        _transfer(fr

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/WishWish-security-review_2025-11-04.md)

---

### Example 22: H-1: Escrow approvals are not cleared when club is transferred allowing for abuse after transfer

**Source**: Sherlock
**Protocol**: Footium
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-footium-judging/issues/289 

## Found by 
0x52, BenRai, Brenzee, CMierez, J4de, MiloTruck, PokemonAuditSimulator, Quantish, cergyk, ctf\_sec, mstpr-brainbot, pengun, sashik\_eth, shaka, shogoki, toshii
## Summary

Escrow approvals remain even across club token transfers. This allows a malicious club owners to sell their club then drain everything after sale due to previous approvals.

## Vulnerability Detail

ERC20 and ERC721 token approval persist regardless of the owner of the club. The result is that approvals set by one owner can be accessed after a token has been sold or transferred. This allows the following attack:

1) User A owns clubId = 1
2) User A sets approval to themselves
3) User A sells clubId = 1 to User B
4) User A uses persistent approval to drain all players and tokens

## Impact

Malicious approvals can be used to drain club after sale

## Code Snippet

[FootiumEscrow.sol#L75-L81](https://github.com/sherlock-audit/2023-04-footium/blob/main/footium-eth-shareable/contracts/FootiumEscrow.sol#L75-L81)

[FootiumEscrow.sol#L90-L96](https://github.com/sherlock-audit/2023-04-footium/blob/main/footium-eth-shareable/contracts/FootiumEscrow.sol#L90-L96)

## Tool used

Manual Review

## Recommendation

Club escrow system needs to be redesigned

---

### Example 23: M-4: Insufficient support for fee-on-transfer tokens

**Source**: Sherlock
**Protocol**: Buffer Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-buffer-judging/issues/76 

## Found by 
eierina, dipp, KingNFT, rvierdiiev, cccz, supernova, Deivitto, \_\_141345\_\_, jonatascm, pashov

## Summary

The ```BufferBinaryPool.sol``` and ```BufferRouter.sol``` do not support fee-on-transfer tokens. If ```tokenX``` is a fee-on-transfer token, tokens received from users could be less than the amount specified in the transfer.

## Vulnerability Detail

The ```initiateTrade``` function in ```BufferRouter.sol``` receives tokens from the user with amount set to ```initiateTrade```'s ```totalFee``` input. If tokenX is a fee-on-transfer token then the actual amount received by ```BufferRouter.sol``` is less than ```totalFee```. When a trade is opened, the protocol will [send a settlementFee to ```settlementFeeDisbursalContract```](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryOptions.sol#L137-L141) and a [premium to ```BufferBinaryPool.sol```](), where the settlementFee is calculated using the incorrect, inflated totalFee amount. When the totalFee is greater than the fee required [the user is reimbursed the difference](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferRouter.sol#L333-L339). Since the settlementFee is greater than it should be the user receives less reimbursement.

In ```BufferBinaryPool.sol```'s ```lock``` function, the premium for the order is sent from the Options contract to the

*[Content truncated...]*

---

### Example 24: [01] `PrizeVault._tryGetAssetDecimals()` may return erroneous decimals

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: LOW

**Details**:

Some ERC20 assets do not have `decimals()` implemented. As such, when calling `PrizeVault._tryGetAssetDecimals()`, `success == false` when returned by `staticcall()` and `_tryGetAssetDecimals()` returns (false, 0):  

https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol#L772-L783

```solidity
    function _tryGetAssetDecimals(IERC20 asset_) internal view returns (bool, uint8) {
        (bool success, bytes memory encodedDecimals) = address(asset_).staticcall(
            abi.encodeWithSelector(IERC20Metadata.decimals.selector)
        );
        if (success && encodedDecimals.length >= 32) {
            uint256 returnedDecimals = abi.decode(encodedDecimals, (uint256));
            if (returnedDecimals <= type(uint8).max) {
                return (true, uint8(returnedDecimals));
            }
        }
        return (false, 0);
    }
```

According to the logic implemented in the constructor, `_underlyingDecimals` would default to 18:

https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol#L303-L305

```solidity
        IERC20 asset_ = IERC20(yieldVault_.asset());
        (bool success, uint8 assetDecimals) = _tryGetAssetDecimals(asset_);
        _underlyingDecimals = success ? assetDecimals : 18;
```

This can lead to significant discrepancy if the non-standard asset decimals is different than 18. It can affect various contract functionalities, such as asset calculations and distributions, especially

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-03-pooltogether)

---

### Example 25: M-7: Code does not handle ERC20 tokens with special `transfer` implementation

**Source**: Sherlock
**Protocol**: Sense
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/10 

## Found by 
cryptphi, pashov

## Summary
Calls to ERC20::transfer method should always be checked

## Vulnerability Detail
Some ERC20 tokens do not revert on failure in `transfer` but instead return `false` as a return value (for example [ZRX](https://etherscan.io/address/0xe41d2489571d322189246dafa5ebde1f4699f498#code)). Because of this it has become a common practice to use OpenZeppelin's SafeERC20 to handle such weird tokens. If `transfer` fails, but does not revert it can leave tokens stuck in the contract - for example in `eject` in `AutoRoller` we have such a non-checked `transfer`, but if it failed the tokens would get stuck, before the shares used for `eject` were already burned.

## Impact
The impact is potentially permanently lost (stuck) value for users of the protocol, but it needs a special ERC20 token to be used as `underlying` or to be sent in contract by mistake, hence Medium severity.

## Code Snippet
https://github.com/sherlock-audit/2022-11-sense/blob/main/contracts/src/AutoRoller.sol#L656
https://github.com/sherlock-audit/2022-11-sense/blob/main/contracts/src/AutoRoller.sol#L659
https://github.com/sherlock-audit/2022-11-sense/blob/main/contracts/src/AutoRoller.sol#L715

## Tool used

Manual Review

## Recommendation
Use OpenZeppelin's SafeERC20 library to handle such tokens

## Discussion

**jparklev**

We will add the safe transfer functions to the remaining locations

**jparklev

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 27
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

