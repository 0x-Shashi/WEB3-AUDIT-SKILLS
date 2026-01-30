# Token Security Patterns (Consolidated)

> **Tokens are not all the same. Weird token behaviors cause billions in losses.**

---

## Quick Summary

| Token Issue | Description | Severity |
|-------------|-------------|----------|
| Fee-on-Transfer | Actual received < transferred amount | High |
| Rebasing Tokens | Balance changes without transfers | High |
| ERC777 Hooks | Reentrancy via token callbacks | Critical |
| Missing Return | USDT doesn't return bool on transfer | Medium |
| Blacklist Tokens | USDC/USDT can freeze addresses | Medium |
| Pausable Tokens | Token can halt all transfers | Medium |
| Decimals Variance | Not all tokens have 18 decimals | High |
| Approval Race | Double-spend via approve front-running | Medium |

---

## Token Compatibility Matrix

| Token | Decimals | Fee | Rebase | Blacklist | Pausable | Hook |
|-------|----------|-----|--------|-----------|----------|------|
| USDT | 6 | No | No | Yes | Yes | No |
| USDC | 6 | No | No | Yes | Yes | No |
| DAI | 18 | No | No | No | No | No |
| WETH | 18 | No | No | No | No | No |
| stETH | 18 | No | Yes | No | No | No |
| PAXG | 18 | Yes | No | Yes | Yes | No |
| AMPL | 9 | No | Yes | No | No | No |
| ERC777 | 18 | Varies | No | No | No | Yes |

---

## Detection Strategy

### Fee-on-Transfer Detection
```solidity
// VULNERABLE: Assumes amount received = amount sent
function deposit(uint amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount;  // ← Wrong! May receive less
}

// SAFE: Check actual balance change
function deposit(uint amount) external {
    uint balanceBefore = token.balanceOf(address(this));
    token.transferFrom(msg.sender, address(this), amount);
    uint received = token.balanceOf(address(this)) - balanceBefore;
    balances[msg.sender] += received;  // ← Correct
}
```

### SafeERC20 Usage
```solidity
// DANGEROUS: Raw transfer (USDT will fail silently)
token.transfer(to, amount);
token.transferFrom(from, to, amount);
token.approve(spender, amount);

// SAFE: Use SafeERC20
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;

token.safeTransfer(to, amount);
token.safeTransferFrom(from, to, amount);
token.safeApprove(spender, amount);  // Or forceApprove
```

### Approval Race Condition
```solidity
// VULNERABLE: Direct approve allows double-spend
token.approve(spender, newAmount);
// Attacker sees tx, front-runs to spend oldAmount, then spends newAmount

// SAFE: Reset to 0 first
token.safeApprove(spender, 0);
token.safeApprove(spender, newAmount);

// SAFER: Use increaseAllowance/decreaseAllowance or permit
```

### Audit Checklist
- [ ] Using SafeERC20 for all token operations?
- [ ] Checking actual balance received (fee-on-transfer)?
- [ ] Not assuming 18 decimals?
- [ ] Handling potential blacklist/pause?
- [ ] Protected against ERC777 reentrancy?
- [ ] Approval race condition mitigated?
- [ ] Rebasing token accounting correct?

---

## Included Pattern Files

- erc20-patterns.md, erc721-patterns.md, erc777-patterns.md, erc1155-patterns.md
- fee-on-transfer-patterns.md, rebasing-tokens-patterns.md, weird-erc20-patterns.md
- usdc-patterns.md, usdt-patterns.md
- approve-patterns.md, approve-max-patterns.md, allowance-patterns.md
- safeapprove-patterns.md, safetransfer-patterns.md
- mint-vs-safemint-patterns.md, token-existence-patterns.md

---

## Full Pattern Details

---
## erc20-patterns.md
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

Some major tokens went live before ERC20 was finalized, resulting in a discrepancy whether the transfer functions should (A) return a boolean or (B) revert/fail on error. The current best practice is that they should revert, but return â€œtrueâ€ on success. However, not every token claiming ERC20-compatibility is doing this â€” some only return true/false; some revert, but do not return anything on success. This is a well known issue, heavily discussed since mid-2018.

Today many tools, including OpenZeppelin, offer [a wrapper for â€œsafe ERC20 transferâ€](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol):

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

A malicious user can run a bot to monitor his own vault, and if the got underwater and they donâ€™t have enough collateral to top up, they can immediately start an auction on their own vault and set actioneer to `0` to avoid actually being liquidated, which breaks the design of the system.


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
OpenZeppelinâ€™s SafeERC20 library, the return values of calls to `transfer` and
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


---
## erc721-patterns.md
# ERC721 Security Patterns

## Overview

**Frequency**: 21 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 7 | 13 | 1 | 0 |

**Common Sources**: Code4rena, Sherlock, Codehawks, Cyfrin

---

## Detection Checklist

- [ ] Check for erc721 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-06] Some real-world NFT tokens may support both ERC721 and ERC1155 standards, which may break `InfinityExchange::_transferNFTs`

**Source**: Code4rena
**Protocol**: Infinity NFT Marketplace
**Impact**: HIGH

**Details**:

_Submitted by PwnedNoMore_

Many real-world NFT tokens may support both ERC721 and ERC1155 standards, which may break `InfinityExchange::_transferNFTs`, i.e., transferring less tokens than expected.

For example, the asset token of [The Sandbox Game](https://www.sandbox.game/en/), a Top20 ERC1155 token on [Etherscan](https://etherscan.io/tokens-nft1155?sort=7d\&order=desc), supports both ERC1155 and ERC721 interfaces. Specifically, any ERC721 token transfer is regarded as an ERC1155 token transfer with only one item transferred ([token address](https://etherscan.io/token/0xa342f5d851e866e18ff98f351f2c6637f4478db5) and [implementation](https://etherscan.io/address/0x7fbf5c9af42a6d146dcc18762f515692cd5f853b#code#F2#L14)).

Assuming there is a user tries to buy two tokens of Sandbox's ASSETs with the same token id, the actual transferring is carried by `InfinityExchange::_transferNFTs` which first checks ERC721 interface supports and then ERC1155.

```solidity
  function _transferNFTs(
    address from,
    address to,
    OrderTypes.OrderItem calldata item
  ) internal {
    if (IERC165(item.collection).supportsInterface(0x80ac58cd)) {
      _transferERC721s(from, to, item);
    } else if (IERC165(item.collection).supportsInterface(0xd9b67a26)) {
      _transferERC1155s(from, to, item);
    }
  }
```

The code will go into `_transferERC721s` instead of `_transferERC1155s`, since the Sandbox's ASSETs also support ERC721 interface. Then,

```solidity
  function _transferERC721s(


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-infinity)

---

### Example 2: Attacker can destroy user voting power by setting `ERC721Power::totalPower` and all existing NFTs `currentPower` to 0

**Source**: Cyfrin
**Protocol**: Dexe
**Impact**: HIGH

**Details**:

**Description:** Attacker can destroy user voting power by setting `ERC721Power::totalPower` & all existing nfts' `currentPower` to 0 via a permission-less attack contract by exploiting a discrepancy ("<" vs "<=") in `ERC721Power` [L144](https://github.com/dexe-network/DeXe-Protocol/tree/f2fe12eeac0c4c63ac39670912640dc91d94bda5/contracts/gov/ERC721/ERC721Power.sol#L144) & [L172](https://github.com/dexe-network/DeXe-Protocol/tree/f2fe12eeac0c4c63ac39670912640dc91d94bda5/contracts/gov/ERC721/ERC721Power.sol#L172):

```solidity
function recalculateNftPower(uint256 tokenId) public override returns (uint256 newPower) {
    // @audit execution allowed to continue when
    // block.timestamp == powerCalcStartTimestamp
    if (block.timestamp < powerCalcStartTimestamp) {
        return 0;
    }
    // @audit getNftPower() returns 0 when
    // block.timestamp == powerCalcStartTimestamp
    newPower = getNftPower(tokenId);

    NftInfo storage nftInfo = nftInfos[tokenId];

    // @audit as this is the first update since power
    // calculation has just started, totalPower will be
    // subtracted by nft's max power
    totalPower -= nftInfo.lastUpdate != 0 ? nftInfo.currentPower : getMaxPowerForNft(tokenId);
    // @audit totalPower += 0 (newPower = 0 in above line)
    totalPower += newPower;

    nftInfo.lastUpdate = uint64(block.timestamp);
    // @audit will set nft's current power to 0
    nftInfo.currentPower = newPower;
}

function getNftPower(uint256 tokenId) public view ove

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-10-cyfrin-dexe.md)

---

### Example 3: [M-04] `CidNFT`: Broken `tokenURI` function

**Source**: Code4rena
**Protocol**: Canto Identity Protocol
**Impact**: MEDIUM

**Details**:

[`CidNFT#tokenURI`](https://github.com/code-423n4/2023-01-canto-identity/blob/dff8e74c54471f5f3b84c217848234d474477d82/src/CidNFT.sol#L133-L142) does not convert the `uint256 _id` argument to a string before interpolating it in the token URI:

```solidity
    /// @notice Get the token URI for the provided ID
    /// @param _id ID to retrieve the URI for
    /// @return tokenURI The URI of the queried token (path to a JSON file)
    function tokenURI(uint256 _id) public view override returns (string memory) {
        if (ownerOf[_id] == address(0))
            // According to ERC721, this revert for non-existing tokens is required
            revert TokenNotMinted(_id);
        return string(abi.encodePacked(baseURI, _id, ".json"));
    }

```

This means the raw bytes of the 32-byte ABI encoded integer `_id` will be interpolated into the token URI, e.g. `0x0000000000000000000000000000000000000000000000000000000000000001` for ID `#1`.

Most of the resulting UTF-8 strings will be malformed, incorrect, or invalid URIs. For example, token ID `#1` will show up as the invisible "start of heading" control character, and ID `#42` will show as the asterisk symbol `*`. URI-unsafe characters will break the token URIs altogether.

### Impact

*   `CidNFT` tokens will have invalid `tokenURI`s. Offchain tools that read the `tokenURI` view may break or display malformed data.

### Suggestion

Convert the `_id` to a string before calling `abi.encodePacked`. Latest Solmate includes a `LibStri

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-canto-identity)

---

### Example 4: [M-17] The tokenURI method does not check if the NFT has been minted and returns data for the contract that may be a fake NFT

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/Factory.sol#L161
https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/PrivatePoolMetadata.sol#L17


## Vulnerability details

## Impact

- By invoking the [Factory.tokenURI](https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/Factory.sol#L161) method for a maliciously provided NFT id, the returned data may deceive potential users, as the method will return data for a non-existent NFT id that appears to be a genuine PrivatePool. This can lead to a poor user experience or financial loss for users.
- Violation of the [ERC721-Metadata part](https://eips.ethereum.org/EIPS/eip-721) standard

## Proof of Concept

- The [Factory.tokenURI](https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/Factory.sol#L161) and [PrivatePoolMetadata.tokenURI](https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/PrivatePoolMetadata.sol#L17) methods lack any requirements stating that the provided NFT id must be created. We can also see that in the standard implementation by [OpenZeppelin](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/cf86fd9962701396457e50ab0d6cc78aa29a5ebc/contracts/token/ERC721/ERC721.sol#L94), this check is present:
- [Throws if `_tokenId` is not a valid NFT](https://eips.ethereum.org/EIPS/ei

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-caviar)

---

### Example 5: [M-19] `HolographERC721.approve` not EIP-721 compliant

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[HolographERC721.sol#L272](https://github.com/code-423n4/2022-10-holograph/blob/24bc4d8dfeb6e4328d2c6291d20553b1d3eff00b/src/enforcer/HolographERC721.sol#L272)<br>

According to EIP-721, we have for `approve`:

```solidity
///  Throws unless `msg.sender` is the current NFT owner, or an authorized
///  operator of the current owner.
```

An operator in the context of EIP-721 is someone who was approved via `setApprovalForAll`:

```solidity
/// @notice Enable or disable approval for a third party ("operator") to manage
///  all of `msg.sender`'s assets
/// @dev Emits the ApprovalForAll event. The contract MUST allow
///  multiple operators per owner.
/// @param _operator Address to add to the set of authorized operators
/// @param _approved True if the operator is approved, false to revoke approval
function setApprovalForAll(address _operator, bool _approved) external;
```

Besides operators, there are also approved addresses for a token (for which `approve` is used). However, approved addresses can only transfer the token, see for instance the `safeTransferFrom` description:

```solidity
/// @dev Throws unless `msg.sender` is the current owner, an authorized
///  operator, or the approved address for this NFT.
```

`HolographERC721` does not distinguish between authorized operators and approved addresses when it comes to the `approve` function. Because `_isApproved(msg.sender, tokenId)` is used there, an approved address can approve another address, which is a violation of the

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 6: [M-15] `HolographERC721.safeTransferFrom` not compliant with EIP-721

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[HolographERC721.sol#L366](https://github.com/code-423n4/2022-10-holograph/blob/24bc4d8dfeb6e4328d2c6291d20553b1d3eff00b/src/enforcer/HolographERC721.sol#L366)<br>

According to EIP-721, we have the following for `safeTransferFrom`:

```solidity
///  (...) When transfer is complete, this function
///  checks if `_to` is a smart contract (code size > 0). If so, it calls
///  `onERC721Received` on `_to` and throws if the return value is not
///  `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`.
```

According to the specification, the function must therefore always call `onERC721Received`, not only when it has determined via ERC-165 that the contract provides this function. Note that in the EIP, the provided interface for `ERC721TokenReceiver` does not mention ERC-165. For the token itself, we have: `interface ERC721 /* is ERC165 */ {`<br>
However, for the receiver, the provided interface there is just: `interface ERC721TokenReceiver {`<br>
This leads to failed transfers when they should not fail, because many receivers will just implement the `onERC721Received` function (which is sufficient according to the EIP), and not `supportsInterface` for ERC-165 support.

### Proof Of Concept

Let's say a receiver just implements the `IERC721Receiver` from OpenZeppelin: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/IERC721Receiver.sol><br>
Like the provided interface in the EIP itself, this interface does not derive from

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 7: H-3: CouncilMember:burn renders the contract inoperable after the first execution

**Source**: Sherlock
**Protocol**: Telcoin Platform Audit
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-01-telcoin-judging/issues/199 

## Found by 
0xAsen, 0xLogos, 0xadrii, 0xlamide, 0xmystery, 0xpep7, Aamirusmani1552, Arz, BAICE, Bauer, DenTonylifer, HonorLt, Ignite, IvanFitro, Jaraxxus, Kow, Krace, VAD37, alexbabits, almurhasan, araj, bitsurfer, dipp, fibonacci, ggg\_ttt\_hhh, gqrp, grearlake, jah, m4ttm, mstpr-brainbot, popeye, psb01, r0ck3tz, ravikiran.web3, sakshamguruji, sobieski, sonny2k, tives, ubl4nk, vvv, ydlee, zhuying, zzykxx
## Summary
The CouncilMember contract suffers from a critical vulnerability that misaligns the balances array after a successful burn, rendering the contract inoperable.

## Vulnerability Detail

The root cause of the vulnerability is that the `burn` function incorrectly manages the `balances` array, shortening it by one each time an ERC721 token is burned while the latest minted NFT still withholds its unique `tokenId` which maps to the previous value of `balances.length`.
```solidity
// File: telcoin-audit/contracts/sablier/core/CouncilMember.sol
210:    function burn(
        ...
220:        balances.pop(); // <= FOUND: balances.length decreases, while latest minted nft withold its unique tokenId
221:        _burn(tokenId);
222:    }
```

This misalignment between existing `tokenIds` and the `balances` array results in several critical impacts:

1. Holders with tokenId greater than the length of balances cannot claim.
2. Subsequent burns of tokenId greater than balances length will revert.
3. 

*[Content truncated...]*

---

### Example 8: [H-02] An attacker is able to hijack any ERC721 / ERC1155 he borrows because guard is missing validation on the address supplied to function call `setFallbackHandler()`

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: HIGH

**Details**:

### Pre-requisite knowledge & an overview of the features in question

***

1.  **Gnosis safe fallback handlers**: Safes starting with version 1.1.1 allow to specify a fallback handler. A gnosis safe fallback handler is a contract which handles all functions that is unknown to the safe, this feature is meant to provide a great flexibility for the safe user. The safe in particular says "If I see something unknown, then I just let the fallback handler deal with it."

    **Example**: If you want to take a uniswap flash loan using your gnosis safe, you'll have to create a fallback handler contract with the callback function `uniswapV2Call()`. When you decide to take a flash loan using your safe, you'll send a call to `swap()` in the uniswap contract. The uniswap contract will then reach out to your safe contract asking to call `uniswapV2Call()`, but `uniswapV2Call()` isn't actually implemented in the safe contract itself, so your safe will reach out to the fallback handler you created, set as the safe's fallback handler and ask it to handle the `uniswapV2Call()` TX coming from uniswap.

    **Setting a fallback handler**: To set a fallback handler for your safe, you'll have to call the function [`setFallbackHandler()`](https://github.com/safe-global/safe-contracts/blob/b140318af6581e499506b11128a892e3f7a52aeb/contracts/base/FallbackManager.sol#L44) which you can find it's logic in [FallbackManager.sol](https://github.com/safe-global/safe-contracts/blob/main/contracts/base/Fallba

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 9: [H-03] Approval for NFT transfers is not removed after transfer

**Source**: Code4rena
**Protocol**: Visor
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by gpersoon, and pauliax_

The `Visor.transferERC721` does not reset the approval for the NFT.

An approved delegatee can move the NFT out of the contract once.
It could be moved to a market and bought by someone else who then deposits it again to the same vault.
The first delegatee can steal the NFT and move it out of the contract a second time.

Recommend resetting the approval on transfer.

**[xyz-ctrl (Visor) confirmed](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/48#issuecomment-856953219):**
> We will be mitigating this issue for our next release and before these experimental features are introduced in platform.
> PR pending

**[ztcrypto (Visor) commented](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/48#issuecomment-889192312):**
> duplicate of above ones and fixed

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-05-visorfinance)

---

### Example 10: [M-12] paused ERC721/ERC1155 could cause stopRent to revert, potentially causing issues for the lender.

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

Many ERC721/ERC1155 tokens, including well-known games such as Axie Infinity, have a pause functionality inside the contract. This pause functionality will cause the `stopRent` call to always revert and could cause issues, especially for the `PAY` order type.

### Proof of Concept

When `stopRent` /`stopRentBatch` is called, it will eventually trigger `  _reclaimRentedItems ` and execute `reclaimRentalOrder` from the safe to send back tokens to lender.

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L353> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L293> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L166-L183>



```solidity
    function _reclaimRentedItems(RentalOrder memory order) internal {
        // Transfer ERC721s from the renter back to lender.
        bool success = ISafe(order.rentalWallet).execTransactionFromModule(
            // Stop policy inherits the reclaimer package.
            address(this),
            // value.
            0,
            // The encoded call to the `reclaimRentalOrder` function.
            abi.encodeWithSelector(this.reclaimRentalOrder.selector, order),
            // Safe must delegate call to the stop policy so that it is the msg.sender.
            Enum.Operation.DelegateCall
        );

        // Assert that the transfer back to the len

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 11: [H-07] `_transferNFTs()` succeeds even if no transfer is performed

**Source**: Code4rena
**Protocol**: Infinity NFT Marketplace
**Impact**: HIGH

**Details**:

_Submitted by k, also found by 0x29A, 0xf15ers, 0xsanson, antonttc, hyh, PwnedNoMore, and zzzitron_

If an NFT is sold that does not specify support for the ERC-721 or ERC-1155 standard interface, the sale will still succeed. In doing so, the seller will receive funds from the buyer, but the buyer will not receive any NFT from the seller. This could happen in the following cases:

1.  A token that claims to be ERC-721/1155 compliant, but fails to implement the `supportsInterface()` function properly.
2.  An NFT that follows a standard other than ERC-721/1155 and does not implement their EIP-165 interfaces.
3.  A malicious contract that is deployed to take advantage of this behavior.

### Proof of Concept

<https://gist.github.com/kylriley/3bf0e03d79b3d62dd5a9224ca00c4cb9>

### Recommended Mitigation Steps

If neither the ERC-721 nor the ERC-1155 interface is supported the function should revert. An alternative approach would be to attempt a `transferFrom` and check the balance before and after to ensure that it succeeded.

**[nneverlander (Infinity) confirmed and resolved](https://github.com/code-423n4/2022-06-infinity-findings/issues/87#issuecomment-1162963184):**
 > Fixed in https://github.com/infinitydotxyz/exchange-contracts-v2/commit/377c77f0888fea9ca1e087de701b5384a046f760

**[HardlyDifficult (judge) commented](https://github.com/code-423n4/2022-06-infinity-findings/issues/87#issuecomment-1179596601):**
> If `supportsInterface` returns false for both 721 & 1155 then no 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-infinity)

---

### Example 12: M-1: [Tomo-M3] Use safeMint instead of mint for ERC721

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/65 

## Found by 
Tomo

## Summary

Use safeMint instead of mint for ERC721

## Vulnerability Detail

TheÂ `msg.sender`Â will be minted as a proof of staking NFT whenÂ `_stakeToken()`Â is called. 

However, ifÂ `msg.sender` is a contract address that does not support ERC721, the NFT can be frozen in the contract.

As per the documentation of EIP-721:

> A wallet/broker/auction application MUST implement the wallet interface if it will accept safe transfers.
> 

Ref:Â [https://eips.ethereum.org/EIPS/eip-721](https://eips.ethereum.org/EIPS/eip-721)

As per the documentation of ERC721.sol by Openzeppelin

Ref: [https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L274-L285](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L274-L285)

```solidity
/**
 * @dev Mints `tokenId` and transfers it to `to`.
 *
 * WARNING: Usage of this method is discouraged, use {_safeMint} whenever possible
 *
 * Requirements:
 *
 * - `tokenId` must not exist.
 * - `to` cannot be the zero address.
 *
 * Emits a {Transfer} event.
 */
function _mint(address to, uint256 tokenId) internal virtual {
```

## Impact

Users possibly lose their NFTs

## Code Snippet
https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L411
``` solidity
  _mint(msg.sender, _tokenId);
```
## Tool used

Manual Review

## Recommendation

Us

*[Content truncated...]*

---

### Example 13: [M-08] Assets in a Safe can be lost

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

The `Guard.sol` contract is enabled on Safe's and uses the [`_checkTransaction`](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L195-L293) function to ensure that transactions that the Safe executes do not transfer the asset out of the Safe.

The `checkTransaction` function achieves this by isolating the function selector and checking that it is not a disallowed function selector. For instance: `safeTransferFrom`, `transferFrom`, `approve`, `enableModule`, etc.

The list does not, however, check for calls to `burn` the token, neither does it check if it is a `permit`. The sponsor has noted the following:

> The [Guard](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol) contract can only protect against the transfer of tokens that faithfully
implement the ERC721/ERC1155 spec.

But this does not acknowledge the fact that an ERC721/ERC1155 implementation can still be an honest implementation and have extra functionality. In particular, the `burn` function is a common addition to many ERC721 contracts, usually granted through inheriting `ERC721Burnable`.

For example, the following projects all have a `burn` function, and Safe's protected by `Guard.sol` that hold these NFTs will be vulnerable to loss of assets via a malicious renter:

*   [Pudgy Penguins](https://etherscan.io/address/0xbd3531da5cf5857e7cfaa92426877b022e612cf8#writeContract)
*   [Lil Pudgies

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 14: [M-09] Use safeTransferFrom instead of transferFrom for ERC721 transfers

**Source**: Code4rena
**Protocol**: Cally
**Impact**: MEDIUM

**Details**:

_Submitted by hickuphh3, also found by antonttc, berndartmueller, catchup, cccz, dipp, FSchmoede, GimelSec, hake, jah, jayjonah8, joestakey, kebabsec, Kenshin, Kumpa, MiloTruck, minhquanym, peritoflores, rfa, shenwilly, WatchPug, and ynnad_

<https://github.com/code-423n4/2022-05-cally/blob/1849f9ee12434038aa80753266ce6a2f2b082c59/contracts/src/Cally.sol#L199>

<https://github.com/code-423n4/2022-05-cally/blob/1849f9ee12434038aa80753266ce6a2f2b082c59/contracts/src/Cally.sol#L295>

<https://github.com/code-423n4/2022-05-cally/blob/1849f9ee12434038aa80753266ce6a2f2b082c59/contracts/src/Cally.sol#L344>

### Details & Impact

The `transferFrom()` method is used instead of `safeTransferFrom()`, presumably to save gas. I however argue that this isnâ€™t recommended because:

*   [OpenZeppelinâ€™s documentation](https://docs.openzeppelin.com/contracts/4.x/api/token/erc721#IERC721-transferFrom-address-address-uint256-) discourages the use of `transferFrom()`, use `safeTransferFrom()` whenever possible
*   Given that any NFT can be used for the call option, there are a few NFTs (hereâ€™s an [example](https://github.com/sz-piotr/eth-card-game/blob/master/src/ethereum/contracts/ERC721Market.sol#L20-L31)) that have logic in the `onERC721Received()` function, which is only triggered in the `safeTransferFrom()` function and not in `transferFrom()`

### Recommended Mitigation Steps

Call the `safeTransferFrom()` method instead of `transferFrom()` for NFT transfers. Note that the `CallyNft` contrac

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-cally)

---

### Example 15: H-1: Escrow approvals are not cleared when club is transferred allowing for abuse after transfer

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

### Example 16: [M-04] Incorrect implementation of ERC721 may have bad consequences for receiver

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[HolographERC721.sol#L467](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/enforcer/HolographERC721.sol#L467)<br>

HolographERC721.sol is an enforcer contract that fully implements ERC721. In its safeTransferFromFunction there is the following code:

    if (_isContract(to)) {
      require(
        (ERC165(to).supportsInterface(ERC165.supportsInterface.selector) &&
          ERC165(to).supportsInterface(ERC721TokenReceiver.onERC721Received.selector) &&
          ERC721TokenReceiver(to).onERC721Received(address(this), from, tokenId, data) ==
          ERC721TokenReceiver.onERC721Received.selector),
        "ERC721: onERC721Received fail"
      );
    }

If the target address is a contract, the enforcer requires the target's `onERC721Received()` to succeed. However, the call deviates from the [standard](https://eips.ethereum.org/EIPS/eip-721):

    interface ERC721TokenReceiver {
        /// @notice Handle the receipt of an NFT
        /// @dev The ERC721 smart contract calls this function on the recipient
        ///  after a `transfer`. This function MAY throw to revert and reject the
        ///  transfer. Return of other than the magic value MUST result in the
        ///  transaction being reverted.
        ///  Note: the contract address is always the message sender.
        /// @param _operator The address which called `safeTransferFrom` function
        /// @param _from The address which previously owned the token

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 17: M-3: Using `ERC721.transferFrom()` instead of `safeTransferFrom()` may cause the user's NFT to be frozen in a contract that does not support ERC721

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/55 

## Found by 
saian, rvierdiiev, WATCHPUG, Tomo, Bnke0x0, Nyx

## Summary

There are certain smart contracts that do not support ERC721, using `transferFrom()` may result in the NFT being sent to such contracts.

## Vulnerability Detail

In `unstake()`, `_to` is param from user's input.

However, if `_to` is a contract address that does not support ERC721, the NFT can be frozen in that contract.

As per the documentation of EIP-721:

> A wallet/broker/auction application MUST implement the wallet interface if it will accept safe transfers.

Ref: https://eips.ethereum.org/EIPS/eip-721

## Impact

The NFT may get stuck in the contract that does support ERC721.

## Code Snippet

https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L463-L489

## Tool used

Manual Review

## Recommendation

Consider using `safeTransferFrom()` instead of `transferFrom()`.

## Discussion

**zobront**

Fixed: https://github.com/Solidity-Guild/FrankenDAO/pull/10

---

### Example 18: [M-07] Using `transferFrom` on ERC721 tokens

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

_Submitted by shw_

In the function `awardExternalERC721` of contract `PrizePool`, when awarding external ERC721 tokens to the winners, the `transferFrom` keyword is used instead of `safeTransferFrom`. If any winner is a contract and is not aware of incoming ERC721 tokens, the sent tokens could be locked.

Recommend consider changing `transferFrom` to `safeTransferFrom` at line 602. However, it could introduce a DoS attack vector if any winner maliciously rejects the received ERC721 tokens to make the others unable to get their awards. Possible mitigations are to use a `try/catch` statement to handle error cases separately or provide a function for the pool owner to remove malicious winners manually if this happens.

**[asselstine (PoolTogether) confirmed and disagreed with severity](https://github.com/code-423n4/2021-06-pooltogether-findings/issues/115#issuecomment-868021913):**
 > This issue poses no risk to the Prize Pool, so it's more of a `1 (Low Risk` IMO.
>
> This is just about triggering a callback on the ERC721 recipient.  We omitted it originally because we didn't want a revert on the callback to DoS the prize pool.
>
> However, to respect the interface it makes sense to implement it fully.  That being said, if it does throw we must ignore it to prevent DoS attacks.

**[dmvt (judge) commented](https://github.com/code-423n4/2021-06-pooltogether-findings/issues/115#issuecomment-907507608):**
 > I agree with the medium risk rating provided by the warden.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-06-pooltogether)

---

### Example 19: [M-02] A malicious borrower can hijack any NFT with `permit()` function he rents.

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

### Pre-requisite knowledge & an overview of the features in question

***

1.  **ERC-4494: Permit for ERC-721 NFTs**: ERC721-Permit is very similar to ERC20-permit (EIP-2612). ERC721 Permit adds a new `permit()` function. It allows user can sign an ERC721 approve transaction off-chain producing a signature that anyone could use and submit to the permit function. When permit is executed, it will execute the approve function. This allows for meta-transaction support of ERC721 transfers, but it also simply gets rid of the annoyance of needing two transactions: `approve` and `transferFrom`. Additionally, ERC721-Permit, just like ERC20 permit, prevents misuse and replay attacks. A replay attack is when a valid signature is used several times or in places where it's not intended to be used in.

    You can find an implementation of it here, by uniswap: <https://github.com/Uniswap/v3-periphery/blob/main/contracts/base/ERC721Permit.sol>

***

### The Vulnerability & Exploitation Steps

***

ReNFT doesn't account for ERC721 implementing the `permit()` function, allowing a malicious borrower to hijack the token by producing a signature and feeding it to the `permit()` function requesting it to approve his address to transfer the token

**Exploitation Steps**

1.  The attacker rents the NFT token in his rental safe
2.  The attacker creates a signature which he will need to feed to the `permit()` function. The signature is a signed data including info like: 1. the deadline (until when t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 20: M-7: Minting inconsistencies on FootiumPlayer and FootiumClub

**Source**: Sherlock
**Protocol**: Footium
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-footium-judging/issues/342 

## Found by 
0xAsen, 0xHati, 0xLook, 0xPkhatri, 0xRobocop, 0xStalin, 0xeix, 0xhacksmithh, BAHOZ, Bauchibred, Bauer, Dug, GalloDaSballo, Koolex, PTolev, Phantasmagoria, TheNaubit, Tricko, ali\_shehab, cergyk, chaithanya\_gali, ctf\_sec, cuthalion0x, deadrxsezzz, descharre, indijanc, jasonxiale, kiki\_dev, lewisbroadhurst, nzm\_, oualidpro, sashik\_eth, shame, shogoki, tsueti\_, tsvetanovv, wzrdk3lly
## Summary

The `FootiumClub.sol` contract when minting uses `_mint()` instead of `_safeMint()` which can cause to mint a club to a contract who does not support nfts. On the other hand `FootiumPlayer.sol` uses `_safeMint()`.

## Vulnerability Detail

See summary.

## Impact

`FootiumClub.sol` might mint a club NFT to a contract that cannot handle nfts.

## Code Snippet

https://github.com/sherlock-audit/2023-04-footium/blob/main/footium-eth-shareable/contracts/FootiumClub.sol#L65

## Tool used

Manual Review

## Recommendation

Use `_safeMint()` as in FootiumPlayer.

---

### Example 21: No Check for Transferring to Self

**Source**: Codehawks
**Protocol**: stake.link
**Impact**: LOW

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-12-stake-link/tree/main/contracts/core/sdlPool/base/SDLPool.sol#L460-462">https://github.com/Cyfrin/2023-12-stake-link/tree/main/contracts/core/sdlPool/base/SDLPool.sol#L460-462</a>


## Summary

The `_transfer` function is responsible for transferring the ownership of a lock from one address to another. It is a critical part of the ERC721 token standard implementation, which this contract adheres to. However, there is a missing check to ensure that the `_from` address is not the same as the `_to` address. Transferring a lock where the `_from` and `_to` addresses are the same can lead to unintended consequences like the double changing of state variables.

Since the _updateRewards function logic depends on the rewards pool, this could create an exploit depending on the implementation of the rewards pool. 

By adding this check, we can ensure that locks are not transferred to the same address that already owns them, thus mitigating the described vulnerability.

## Recommendations

Add a check to the _transfer function to ensure that `_from` != `_to`.

---

## Statistics

- Total findings analyzed: 21
- Examples shown: 21
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## erc777-patterns.md
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
_openQueuedTrade() does not follow the â€œChecks Effects Interactionsâ€ principle and may lead to re-entry to steal the funds

https://fravoll.github.io/solidity-patterns/checks_effects_interactions.html

## Vulnerability Detail
The prerequisite is that tokenX is ERC777 e.g. â€œsushiâ€
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

follow â€œChecks Effects Interactionsâ€ 

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

The internalÂ [`_deposit`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/BaseVault.sol#L407)Â function handles user deposits, transferring a specified amount ofÂ `stETH`Â fromÂ `msg.sender`Â to the vault. Before moving the funds, it adds the deposit to the queue, which is processed later by theÂ [`processQueuedDeposits`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/BaseVault.sol#L371)Â function.


As the underlying token could have hooks that allow the token sender to execute code before the transfer (e.g., ERC777 standard), a malicious user could use those hooks to re-enter theÂ `deposit`Â function multiple times.


This re-entrancy will result in an increment in the receiver balance on the queue, even though this balance will not correspond to the actual amount deposited into the vault.


In the current implementation, theÂ `_deposit`Â function in theÂ `BaseVault`Â contract is overridden by theÂ [implementation in theÂ `STETHVault`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/STETHVault.sol#L113-L126), which has the correct order of operation. However, theÂ `BaseVault`Â is likely to be inherited by future vaults, so it is crucial to have the correctÂ `_deposit`Â implementation in this contract in case it is not overridden.


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


---
## erc1155-patterns.md
# ERC1155 Security Patterns

## Overview

**Frequency**: 17 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 15 | 2 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, ConsenSys

---

## Detection Checklist

- [ ] Check for erc1155 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-06] Some real-world NFT tokens may support both ERC721 and ERC1155 standards, which may break `InfinityExchange::_transferNFTs`

**Source**: Code4rena
**Protocol**: Infinity NFT Marketplace
**Impact**: HIGH

**Details**:

_Submitted by PwnedNoMore_

Many real-world NFT tokens may support both ERC721 and ERC1155 standards, which may break `InfinityExchange::_transferNFTs`, i.e., transferring less tokens than expected.

For example, the asset token of [The Sandbox Game](https://www.sandbox.game/en/), a Top20 ERC1155 token on [Etherscan](https://etherscan.io/tokens-nft1155?sort=7d\&order=desc), supports both ERC1155 and ERC721 interfaces. Specifically, any ERC721 token transfer is regarded as an ERC1155 token transfer with only one item transferred ([token address](https://etherscan.io/token/0xa342f5d851e866e18ff98f351f2c6637f4478db5) and [implementation](https://etherscan.io/address/0x7fbf5c9af42a6d146dcc18762f515692cd5f853b#code#F2#L14)).

Assuming there is a user tries to buy two tokens of Sandbox's ASSETs with the same token id, the actual transferring is carried by `InfinityExchange::_transferNFTs` which first checks ERC721 interface supports and then ERC1155.

```solidity
  function _transferNFTs(
    address from,
    address to,
    OrderTypes.OrderItem calldata item
  ) internal {
    if (IERC165(item.collection).supportsInterface(0x80ac58cd)) {
      _transferERC721s(from, to, item);
    } else if (IERC165(item.collection).supportsInterface(0xd9b67a26)) {
      _transferERC1155s(from, to, item);
    }
  }
```

The code will go into `_transferERC721s` instead of `_transferERC1155s`, since the Sandbox's ASSETs also support ERC721 interface. Then,

```solidity
  function _transferERC721s(


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-infinity)

---

### Example 2: Re-entrancy issue for ERC1155 âœ“Â Fixed

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

### Example 3: [H-01] StandardPolicyERC1155.sol returns amount == 1 instead of amount == order.amount

**Source**: Code4rena
**Protocol**: Blur Exchange
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-blur/blob/main/contracts/matchingPolicies/StandardPolicyERC1155.sol#L12-L36
https://github.com/code-423n4/2022-10-blur/blob/main/contracts/BlurExchange.sol#L154-L161


## Vulnerability details

## Impact

The ```canMatchMakerAsk``` and ```canMatchMakerBid``` functions in ```StandardPolicyERC1155.sol``` will only return 1 as the amount instead of the order.amount value. This value is then used in the ```_executeTokenTransfer``` call during the execution flow and leads to only 1 ERC1155 token being sent. A buyer matching an ERC1155 order wih amount > 1 would expect to receive amount of tokens if they pay the order's price. The seller, who might also expect more than 1 tokens to be sent, would have set the order's price to be for the amount of tokens and not just for 1 token.

The buyer would lose overspent ETH/WETH to the seller without receiving all tokens as specified in the order.

## Proof of Concept

[StandardPolicyERC1155.sol:canMatchMakerAsk](https://github.com/code-423n4/2022-10-blur/blob/main/contracts/matchingPolicies/StandardPolicyERC1155.sol#L12-L36)

```solidity
    function canMatchMakerAsk(Order calldata makerAsk, Order calldata takerBid)
        external
        pure
        override
        returns (
            bool,
            uint256,
            uint256,
            uint256,
            AssetType
        )
    {
        return (
            (makerAsk.side != takerBid.side) &&
            (makerAsk.pay

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-blur)

---

### Example 4: [H-01] Truncation in `OrderValidator` can lead to resetting the fill and selling more tokens

**Source**: Code4rena
**Protocol**: OpenSea
**Impact**: HIGH

**Details**:

[OrderValidator.sol#L228](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L228)<br>
[OrderValidator.sol#L231](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L231)<br>
[OrderValidator.sol#L237](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L237)<br>
[OrderValidator.sol#L238](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L238)<br>

A partial order's fractions (`numerator` and `denominator`) can be reset to `0` due to a truncation. This can be used to craft malicious orders:

1.  Consider user Alice, who has 100 ERC1155 tokens, who approved all of their tokens to the `marketplaceContract`.
2.  Alice places a `PARTIAL_OPEN` order with 10 ERC1155 tokens and consideration of ETH.
3.  Malory tries to fill the order in the following way:
    1.  Malory tries to fill 50% of the order, but instead of providing the fraction `1 / 2`, Bob provides `2**118 / 2**119`. This sets the `totalFilled` to `2**118` and `totalSize` to `2**119`.
    2.  Malory tries to fill 10% of the order, by providing `1 / 10`. The computation `2**118 / 2**119 + 1 / 10` is done by "cross multiplying" the denominators, leading to the acutal fraction being `numerator = (2**118 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-opensea-seaport)

---

### Example 5: [H-02] OZ ERC1155Supply vulnerability

**Source**: Code4rena
**Protocol**: Overlay Protocol
**Impact**: HIGH

**Details**:

_Submitted by pauliax, also found by hubble and defsec_

#### Impact

Overlay uses OZ contracts version 4.3.2:

```yaml
  dependencies:
    - OpenZeppelin/openzeppelin-contracts@4.3.2
```

and has a contract that inherits from ERC1155Supply:

```solidity
  contract OverlayV1OVLCollateral is ERC1155Supply
```

This version has a recently discovered vulnerability:
<https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-wmpv-c2jp-j2xg>

In your case, function unwind relies on totalSupply when calculating `\_userNotional`, `\_userDebt`, `\_userCost`, and `\_userOi`, so a malicious actor can exploit this vulnerability by first calling 'build' and then on callback 'unwind' in the same transaction before the total supply is updated.

#### Recommended Mitigation Steps

Consider updating to a patched version of 4.3.3.

**[mikeyrf (Overlay) confirmed](https://github.com/code-423n4/2021-11-overlay-findings/issues/127)**

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-overlay)

---

### Example 6: [H-02] An attacker is able to hijack any ERC721 / ERC1155 he borrows because guard is missing validation on the address supplied to function call `setFallbackHandler()`

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: HIGH

**Details**:

### Pre-requisite knowledge & an overview of the features in question

***

1.  **Gnosis safe fallback handlers**: Safes starting with version 1.1.1 allow to specify a fallback handler. A gnosis safe fallback handler is a contract which handles all functions that is unknown to the safe, this feature is meant to provide a great flexibility for the safe user. The safe in particular says "If I see something unknown, then I just let the fallback handler deal with it."

    **Example**: If you want to take a uniswap flash loan using your gnosis safe, you'll have to create a fallback handler contract with the callback function `uniswapV2Call()`. When you decide to take a flash loan using your safe, you'll send a call to `swap()` in the uniswap contract. The uniswap contract will then reach out to your safe contract asking to call `uniswapV2Call()`, but `uniswapV2Call()` isn't actually implemented in the safe contract itself, so your safe will reach out to the fallback handler you created, set as the safe's fallback handler and ask it to handle the `uniswapV2Call()` TX coming from uniswap.

    **Setting a fallback handler**: To set a fallback handler for your safe, you'll have to call the function [`setFallbackHandler()`](https://github.com/safe-global/safe-contracts/blob/b140318af6581e499506b11128a892e3f7a52aeb/contracts/base/FallbackManager.sol#L44) which you can find it's logic in [FallbackManager.sol](https://github.com/safe-global/safe-contracts/blob/main/contracts/base/Fallba

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 7: [H-03] Migration: no check that user-supplied `proposalId` and `vault` match

**Source**: Code4rena
**Protocol**: Fractional
**Impact**: HIGH

**Details**:

_Submitted by kenzo, also found by 0x1f8b, bin2chen, codexploder, dipp, minhtrng, and smiling&#95;heretic_

<https://github.com/code-423n4/2022-07-fractional/blob/main/src/modules/Migration.sol#L111>

<https://github.com/code-423n4/2022-07-fractional/blob/main/src/modules/Migration.sol#L124>

<https://github.com/code-423n4/2022-07-fractional/blob/main/src/modules/Migration.sol#L143>

<https://github.com/code-423n4/2022-07-fractional/blob/main/src/modules/Migration.sol#L157>

<https://github.com/code-423n4/2022-07-fractional/blob/main/src/modules/Migration.sol#L164>

### Vulnerability Details

In Migration, when joining or leaving a migration proposal, Fractional does not check whether the user supplied `proposalId` and `vault` match the actual vault that the proposal belongs to.

This allows the user to trick the accounting.

### Impact

Loss of funds for users.

Malicious users can withdraw tokens from proposals which have not been committed yet.

### Proof of Concept

Let's say Vault A's FERC1155 token is called TOKEN.
Alice has deposited 100 TOKEN in Migration to Vault A on proposal ID 1.

Now Malaclypse creates Vault B with token ERIS as FERC1155 and mints 100 tokens to himself.
He then calls Migration's `join` with amount as 100, Vault B as `vault`, proposal ID as 1.
The function [will get](https://github.com/code-423n4/2022-07-fractional/blob/main/src/modules/Migration.sol#L111) ERIS as the token to deposit.
It [will pull](https://github.com/code-423n4/2022-07-fractiona

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-fractional)

---

### Example 8: [M-12] paused ERC721/ERC1155 could cause stopRent to revert, potentially causing issues for the lender.

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

Many ERC721/ERC1155 tokens, including well-known games such as Axie Infinity, have a pause functionality inside the contract. This pause functionality will cause the `stopRent` call to always revert and could cause issues, especially for the `PAY` order type.

### Proof of Concept

When `stopRent` /`stopRentBatch` is called, it will eventually trigger `  _reclaimRentedItems ` and execute `reclaimRentalOrder` from the safe to send back tokens to lender.

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L353> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L293> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L166-L183>



```solidity
    function _reclaimRentedItems(RentalOrder memory order) internal {
        // Transfer ERC721s from the renter back to lender.
        bool success = ISafe(order.rentalWallet).execTransactionFromModule(
            // Stop policy inherits the reclaimer package.
            address(this),
            // value.
            0,
            // The encoded call to the `reclaimRentalOrder` function.
            abi.encodeWithSelector(this.reclaimRentalOrder.selector, order),
            // Safe must delegate call to the stop policy so that it is the msg.sender.
            Enum.Operation.DelegateCall
        );

        // Assert that the transfer back to the len

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 9: [H-07] `_transferNFTs()` succeeds even if no transfer is performed

**Source**: Code4rena
**Protocol**: Infinity NFT Marketplace
**Impact**: HIGH

**Details**:

_Submitted by k, also found by 0x29A, 0xf15ers, 0xsanson, antonttc, hyh, PwnedNoMore, and zzzitron_

If an NFT is sold that does not specify support for the ERC-721 or ERC-1155 standard interface, the sale will still succeed. In doing so, the seller will receive funds from the buyer, but the buyer will not receive any NFT from the seller. This could happen in the following cases:

1.  A token that claims to be ERC-721/1155 compliant, but fails to implement the `supportsInterface()` function properly.
2.  An NFT that follows a standard other than ERC-721/1155 and does not implement their EIP-165 interfaces.
3.  A malicious contract that is deployed to take advantage of this behavior.

### Proof of Concept

<https://gist.github.com/kylriley/3bf0e03d79b3d62dd5a9224ca00c4cb9>

### Recommended Mitigation Steps

If neither the ERC-721 nor the ERC-1155 interface is supported the function should revert. An alternative approach would be to attempt a `transferFrom` and check the balance before and after to ensure that it succeeded.

**[nneverlander (Infinity) confirmed and resolved](https://github.com/code-423n4/2022-06-infinity-findings/issues/87#issuecomment-1162963184):**
 > Fixed in https://github.com/infinitydotxyz/exchange-contracts-v2/commit/377c77f0888fea9ca1e087de701b5384a046f760

**[HardlyDifficult (judge) commented](https://github.com/code-423n4/2022-06-infinity-findings/issues/87#issuecomment-1179596601):**
> If `supportsInterface` returns false for both 721 & 1155 then no 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-infinity)

---

### Example 10: [H-01] It is possible to create fake ERC1155 `NameWrapper` token for subdomain, which is not owned by `NameWrapper`

**Source**: Code4rena
**Protocol**: ENS
**Impact**: HIGH

**Details**:

[NameWrapper.sol#L820-L821](https://github.com/code-423n4/2022-07-ens/blob/ff6e59b9415d0ead7daf31c2ed06e86d9061ae22/contracts/wrapper/NameWrapper.sol#L820-L821)<br>
[NameWrapper.sol#L524](https://github.com/code-423n4/2022-07-ens/blob/ff6e59b9415d0ead7daf31c2ed06e86d9061ae22/contracts/wrapper/NameWrapper.sol#L524)<br>
[NameWrapper.sol#L572](https://github.com/code-423n4/2022-07-ens/blob/ff6e59b9415d0ead7daf31c2ed06e86d9061ae22/contracts/wrapper/NameWrapper.sol#L572)<br>

Due to re-entrancy possibility in `NameWrapper._transferAndBurnFuses` (called from `setSubnodeOwner` and `setSubnodeRecord`), it is possible to do some stuff in `onERC1155Received` right after transfer but before new owner and new fuses are set. This makes it possible, for example, to unwrap the subdomain, but owner and fuses will still be set even for unwrapped domain, creating fake `ERC1155` `NameWrapper` token for domain, which is not owned by `NameWrapper`.

Fake token creation scenario:

1.  `Account1` registers and wraps `test.eth` domain
2.  `Account1` calls `NameWrapper.setSubnodeOwner` for `sub.test.eth` subdomain with `Account1` as owner (to make NameWrapper owner of subdomain)
3.  `Contract1` smart contract is created, which calls unwrap in its `onERC1155Received` function, and a function to send `sub.test.eth` ERC1155 NameWrapper token back to `Account1`
4.  `Account1` calls `NameWrapper.setSubnodeOwner` for `sub.test.eth` with `Contract1` as new owner, which unwraps domain back to `Account1` but 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-ens)

---

### Example 11: [M-08] Assets in a Safe can be lost

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

The `Guard.sol` contract is enabled on Safe's and uses the [`_checkTransaction`](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L195-L293) function to ensure that transactions that the Safe executes do not transfer the asset out of the Safe.

The `checkTransaction` function achieves this by isolating the function selector and checking that it is not a disallowed function selector. For instance: `safeTransferFrom`, `transferFrom`, `approve`, `enableModule`, etc.

The list does not, however, check for calls to `burn` the token, neither does it check if it is a `permit`. The sponsor has noted the following:

> The [Guard](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol) contract can only protect against the transfer of tokens that faithfully
implement the ERC721/ERC1155 spec.

But this does not acknowledge the fact that an ERC721/ERC1155 implementation can still be an honest implementation and have extra functionality. In particular, the `burn` function is a common addition to many ERC721 contracts, usually granted through inheriting `ERC721Burnable`.

For example, the following projects all have a `burn` function, and Safe's protected by `Guard.sol` that hold these NFTs will be vulnerable to loss of assets via a malicious renter:

*   [Pudgy Penguins](https://etherscan.io/address/0xbd3531da5cf5857e7cfaa92426877b022e612cf8#writeContract)
*   [Lil Pudgies

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 12: [H-03] An attacker can hijack any ERC1155 token he rents due to a design issue in reNFT via reentrancy exploitation

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: HIGH

**Details**:

### Pre-requisite knowledge & an overview of the features in question

***

1.  **Gnosis safe fallback handlers**: Safes starting with version 1.1.1 allow to specify a fallback handler. A gnosis safe fallback handler is a contract which handles all functions that is unknown to the safe, this feature is meant to provide a great flexibility for the safe user. The safe in particular says "If I see something unknown, then I just let the fallback handler deal with it."

    **Example**: If you want to take a uniswap flash loan using your gnosis safe, you'll have to create a fallback handler contract with the callback function `uniswapV2Call()`. When you decide to take a flash loan using your safe, you'll send a call to `swap()` in the uniswap contract. The uniswap contract will then reach out to your safe contract asking to call `uniswapV2Call()`, but `uniswapV2Call()` isn't actually implemented in the safe contract itself, so your safe will reach out to the fallback handler you created, set as the safe's fallback handler and ask it to handle the `uniswapV2Call()` TX coming from uniswap.

    **Setting a fallback handler**: To set a fallback handler for your safe, you'll have to call the function [`setFallbackHandler()`](https://github.com/safe-global/safe-contracts/blob/b140318af6581e499506b11128a892e3f7a52aeb/contracts/base/FallbackManager.sol#L44) which you can find it's logic in [FallbackManager.sol](https://github.com/safe-global/safe-contracts/blob/main/contracts/base/Fallba

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 13: [H-13] Anyone can wipe complete state of any collateral at any point

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-01-astaria/blob/1bfc58b42109b839528ab1c21dc9803d663df898/src/ClearingHouse.sol#L114-L167><br>
<https://github.com/code-423n4/2023-01-astaria/blob/1bfc58b42109b839528ab1c21dc9803d663df898/src/CollateralToken.sol#L524-L545><br>
<https://github.com/code-423n4/2023-01-astaria/blob/1bfc58b42109b839528ab1c21dc9803d663df898/src/LienToken.sol#L497-L510><br>
<https://github.com/code-423n4/2023-01-astaria/blob/1bfc58b42109b839528ab1c21dc9803d663df898/src/LienToken.sol#L623-L656>

The Clearing House is implemented as an ERC1155. This is used to settle up at the end of an auction. The Clearing House's token is listed as one of the Consideration Items, and when Seaport goes to transfer it, it triggers the settlement process.

This settlement process includes deleting the collateral state hash from LienToken.sol, burning all lien tokens, deleting the idToUnderlying mapping, and burning the collateral token. **These changes effectively wipe out all record of the liens, as well as removing any claim the borrower has on their underlying collateral.**

After an auction, this works as intended. The function verifies that sufficient payment has been made to meet the auction criteria, and therefore all these variables should be zeroed out.

However, the issue is that there is no check that this safeTransferFrom function is being called after an auction has completed. In the case that it is called when there is no auction, all the auction criteria will be set to

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

### Example 14: [H-02] Forced buyouts can be performed by malicious buyers

**Source**: Code4rena
**Protocol**: Fractional
**Impact**: HIGH

**Details**:

_Submitted by cccz_

In the end function of the Buyout contract, when the buyout fails, ERC1155 tokens are sent to the proposer. A malicious proposer can start a buyout using a contract that cannot receive ERC1155 tokens, and if the buyout fails, the end function fails because it cannot send ERC1155 tokens to the proposer. This prevents a new buyout from being started.

### Proof of Concept

<https://github.com/code-423n4/2022-07-fractional/blob/8f2697ae727c60c93ea47276f8fa128369abfe51/src/modules/Buyout.sol#L224-L238>

### Recommended Mitigation Steps

Consider saving the status of the proposer after a failed buyout and implementing functions to allow the proposer to withdraw the ERC1155 tokens and eth.

**[Ferret-san (Fractional) confirmed](https://github.com/code-423n4/2022-07-fractional-findings/issues/212)** 

**[HardlyDifficult (judge) commented](https://github.com/code-423n4/2022-07-fractional-findings/issues/212#issuecomment-1217143098):**
 > The 1155 receiver can prevent a failed buyout from ending, which prevents a new one from starting. Agree with severity.



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-fractional)

---

### Example 15: [H-02] Loss of funds in `matchOneToManyOrders()` and `takeOrders()` and `matchOrders()` because code don't check that different ids in one collection are different, so it's possible to sell one id multiple time instead of selling multiple id one time in one collection of order (lack of checks in `doTokenIdsIntersect()` especially for ERC1155 tokens)

**Source**: Code4rena
**Protocol**: Infinity NFT Marketplace
**Impact**: HIGH

**Details**:

_Submitted by unforgiven_

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityOrderBookComplication.sol#L271-L312>

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityOrderBookComplication.sol#L59-L116>

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityExchange.sol#L245-L294>

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityOrderBookComplication.sol#L118-L143>

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityExchange.sol#L330-L364>

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityExchange.sol#L934-L951>

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityOrderBookComplication.sol#L145-L164>

<https://github.com/code-423n4/2022-06-infinity/blob/765376fa238bbccd8b1e2e12897c91098c7e5ac6/contracts/core/InfinityExchange.sol#L171-L243>

### Impact

Function `matchOneToManyOrders()` and `takeOrders()` and `matchOrders()` suppose to match `sell order` to `buy order` and should perform some checks to ensure that user specified parameters in orders which are signed are not violated when order matching happens. but There i

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-infinity)

---

### Example 16: [H-03] getRandomTokenIdFromFund yields wrong probabilities for ERC1155

**Source**: Code4rena
**Protocol**: NFTX
**Impact**: HIGH

**Details**:

## Handle

@cmichelio


## Vulnerability details


## Vulnerability Details

`NFTXVaultUpgradeable.getRandomTokenIdFromFund` does not work with ERC1155 as it does not take the deposited `quantity1155` into account. 

## Impact

Assume `tokenId0` has a count of 100, and `tokenId1` has a count of 1.
Then `getRandomId` would have a pseudo-random 1:1 chance for token 0 and 1 when in reality it should be 100:1.

This might make it easier for an attacker to redeem more valuable NFTs as the probabilities are off.

## Recommended Mitigation Steps

Take the quantities of each token into account (`quantity1155`) which probably requires a design change as it's currently hard to do without iterating over all tokens.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-05-nftx)

---

### Example 17: H-5: Adversary can break deposit queue and cause loss of funds

**Source**: Sherlock
**Protocol**: Y2K
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-03-Y2K-judging/issues/468 

## Found by 
0x52, 0xRobocop, Bauer, HonorLt, Respx, Ruhum, VAD37, bin2chen, immeas, joestakey, jprod15, libratus, ltyu, mstpr-brainbot, nobody2018, roguereddwarf, warRoom, yixxas

## Summary



## Vulnerability Detail

[Carousel.sol#L531-L538](https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/Carousel/Carousel.sol#L531-L538)

    function _mintShares(
        address to,
        uint256 id,
        uint256 amount
    ) internal {
        _mint(to, id, amount, EMPTY);
        _mintEmissions(to, id, amount);
    }

When processing deposits for the deposit queue, it _mintShares to the specified receiver which makes a _mint subcall.

[ERC1155.sol#L263-L278](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/ca822213f2275a14c26167bd387ac3522da67fe9/contracts/token/ERC1155/ERC1155.sol#L263-L278)

    function _mint(address to, uint256 id, uint256 amount, bytes memory data) internal virtual {
        require(to != address(0), "ERC1155: mint to the zero address");

        address operator = _msgSender();
        uint256[] memory ids = _asSingletonArray(id);
        uint256[] memory amounts = _asSingletonArray(amount);

        _beforeTokenTransfer(operator, address(0), to, ids, amounts, data);

        _balances[id][to] += amount;
        emit TransferSingle(operator, address(0), to, id, amount);

        _afterTokenTransfer(operator, address(0), to, ids, amounts, data);

   

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 17
- Examples shown: 17
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## erc2981-patterns.md
# ERC2981 Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 6 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for erc2981 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-07] Royalty recipients will not get fair share of royalties

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

Recipients of NFTs who accept royalties will not get their fair share of royalties. This is because royalties are calculated by dividing the sales price equally amongst all sold NFTs in that purchase. The issue with this is that it assumes all NFTs cost the same amount when it comes time to deal out royalties. If NFTs cost different amounts, then they should be getting an amount of royalties based on that weight relative to the other NFTs. The impact of this is that Royalties will not be distributed evenly at the expense of the more expensive NFT. Meaning that recipients of the expensive NFT will always receive less than they are owed. And the cheaper ones will get more than owed. In short, this is a loss of funds or misdistribution of funds.

### Proof of Concept

The easiest way to test this will to be add this snippet into Milady.sol.

Using this to have access to ERC2981's `setRoyaltyInfo()`:

```solidity
file: Milady.sol
    function setRoyaltyInfo(
        uint256 _royaltyFeeRate,
        address _royaltyRecipient
    ) public {
        royaltyFeeRate = _royaltyFeeRate;
        royaltyRecipient = _royaltyRecipient;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC2981, ERC721) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function royaltyInfo(
        uint256 id,
        uint256 salePrice
    ) public view override returns (address, uint256) {
        return super.royaltyInfo(id, salePrice

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-caviar)

---

### Example 2: [M-04] The `FERC1155.sol` don't respect the EIP2981

**Source**: Code4rena
**Protocol**: Fractional
**Impact**: MEDIUM

**Details**:

_Submitted by 0x29A_

The [EIP-2981: NFT Royalty Standard](https://eips.ethereum.org/EIPS/eip-2981) implementation is incomplete, missing the implementation of `function supportsInterface(bytes4 interfaceID) external view returns (bool);` from the [EIP-165: Standard Interface Detection](https://eips.ethereum.org/EIPS/eip-165).

### Proof of Concept

A marketplace that implemented royalties could check if the NFT has royalties, but if they don't, add the interface of `ERC2981` on the `_registerInterface`, the marketplace can't know if this NFT has royalties.

### Recommended Mitigation Steps

Like in [solmate ERC1155.sol](https://github.com/Rari-Capital/solmate/blob/03e425421b24c4f75e4a3209b019b367847b7708/src/tokens/ERC1155.sol#L137-L146) add the `ERC2981` interfaceId on the `FERC1155` contract

```solidity
    /*//////////////////////////////////////////////////////////////
                              ERC165 LOGIC
    //////////////////////////////////////////////////////////////*/

    function supportsInterface(bytes4 interfaceId) public view  override returns (bool) {
        return
            super.supportsInterface(interfaceId) ||
            interfaceId == 0x2a55205a; // ERC165 Interface ID for ERC2981
    }
```

**[aklatham (Fractional) confirmed](https://github.com/code-423n4/2022-07-fractional-findings/issues/544)** 

**[HardlyDifficult (judge) commented](https://github.com/code-423n4/2022-07-fractional-findings/issues/544#issuecomment-1208112166):**
 > The contr

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-fractional)

---

### Example 3: [M-16] Inappropriate support of EIP-2981

**Source**: Code4rena
**Protocol**: Foundation
**Impact**: MEDIUM

**Details**:

_Submitted by WatchPug_

[NFTMarketCreators.sol#L65-L82](https://github.com/code-423n4/2022-02-foundation/blob/4d8c8931baffae31c7506872bf1100e1598f2754/contracts/mixins/NFTMarketCreators.sol#L65-L82)<br>

```solidity
if (nftContract.supportsERC165Interface(type(IRoyaltyInfo).interfaceId)) {
  try IRoyaltyInfo(nftContract).royaltyInfo{ gas: READ_ONLY_GAS_LIMIT }(tokenId, BASIS_POINTS) returns (
    address receiver,
    uint256 /* royaltyAmount */
  ) {
    if (receiver != address(0)) {
      recipients = new address payable[](1);
      recipients[0] = payable(receiver);
      // splitPerRecipientInBasisPoints is not relevant when only 1 recipient is defined
      if (receiver == seller) {
        return (recipients, splitPerRecipientInBasisPoints, true);
      }
    }
  } catch // solhint-disable-next-line no-empty-blocks
  {
    // Fall through
  }
}
```

The current implementation of EIP-2981 support will always pass a constant `BASIS_POINTS` as the `_salePrice`.

As a result, the recipients that are supposed to receive less than 1 BPS of the salePrice may end up not receiving any royalties.

Furthermore, for the NFTs with the total royalties rate set less than 10% for some reason, the current implementation will scale it up to 10%.

### Recommended Mitigation Steps

1.  Instead of passing a constant of 10,000 as the `_salePrice`, we suggest using the actual `_salePrice`, so there the royalties can be paid for recipients with less than 1 BPS of the royalties.
2.  When the t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-foundation)

---

### Example 4: M-5: Template implementations doesn't validate configurations properly

**Source**: Sherlock
**Protocol**: NFTPort
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-nftport-judging/issues/83 

## Found by 
ElKu, rvierdiiev, obront, pashov, ctf\_sec, joestakey, ak1, JohnnyTime, GimelSec, Dravee, JohnSmith, cccz

## Summary

In past audits, we have seen contract admins claim that invalidated configuration setters are fine since â€œadmins are trustworthyâ€. However, cases such as [Nomad got drained for over $150M](https://twitter.com/samczsun/status/1554260106107179010) and [Misconfiguration in the Acala stablecoin project allows attacker to steal 1.2 billion aUSD](https://web3isgoinggreat.com/single/misconfiguration-in-the-acala-stablecoin-project-allows-attacker-to-steal-1-2-billion-ausd) have shown again and again that even trustable entities can make mistakes. Thus any fields that might potentially result in insolvency of protocol should be thoroughly checked.

NftPort template implementations often ignore checks for config fields. For the rest of the issue, we take `royalty` related fields as an example to illustrate potential consequences of misconfigurations. Notably, lack of check is not limited to `royalty`, but exists among most config fields.

Admins are allowed to set a wrong `royaltiesBps` which is higher than `ROYALTIES_BASIS`. `royaltyInfo()` will accept this invalid `royaltiesBps` and users will pay a large amount of royalty.

## Vulnerability Detail

EIP-2981 (NFT Royalty Standard) defines `royaltyInfo()` function that specifies how much to pay for a given sale price. In genera

*[Content truncated...]*

---

### Example 5: [M-03] Forget to check "Some manifolds contracts of ERC-2981 return (address(this), 0) when royalties are not defined" in 3rd priority - MarketFees.sol

**Source**: Code4rena
**Protocol**: Foundation
**Impact**: MEDIUM

**Details**:

_Submitted by KIntern&#95;NA, also found by bin2chen and Lambda_

Wrong return of `cretorShares` and `creatorRecipients` can make real royalties party can't gain the revenue of sale.

### Proof of concept

Function `getFees()` firstly [call](https://github.com/code-423n4/2022-08-foundation/blob/792e00df429b0df9ee5d909a0a5a6e72bd07cf79/contracts/mixins/shared/MarketFees.sol#L422-L430) to function `internalGetImmutableRoyalties` to get the list of `creatorRecipients` and `creatorShares` if the `nftContract` define ERC2981 royalties.

```solidity
try implementationAddress.internalGetImmutableRoyalties(nftContract, tokenId) returns (
  address payable[] memory _recipients,
  uint256[] memory _splitPerRecipientInBasisPoints
) {
  (creatorRecipients, creatorShares) = (_recipients, _splitPerRecipientInBasisPoints);
} catch // solhint-disable-next-line no-empty-blocks
{
  // Fall through
}
```

***

In the [1st priority](https://github.com/code-423n4/2022-08-foundation/blob/792e00df429b0df9ee5d909a0a5a6e72bd07cf79/contracts/mixins/shared/MarketFees.sol#L236-L255) it check the `nftContract` define the function `royaltyInfo` or not. If yes, it get the return value `receiver` and `royaltyAmount`. In some manifold contracts of erc2981, it `return (address(this), 0)` when royalties are not defined. So we ignore it when the `royaltyAmount = 0`

```solidity
  try IRoyaltyInfo(nftContract).royaltyInfo{ gas: READ_ONLY_GAS_LIMIT }(tokenId, BASIS_POINTS) returns (
    address receiver,
    uint

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-foundation)

---

### Example 6: [M-03] `RoyaltyVault.sol` is Not Equipped to Handle On-Chain Royalties From Secondary Sales

**Source**: Code4rena
**Protocol**: Joyn
**Impact**: MEDIUM

**Details**:

_Submitted by leastwood_

<https://github.com/code-423n4/2022-03-joyn/blob/main/core-contracts/contracts/CoreCollection.sol>

<https://github.com/code-423n4/2022-03-joyn/blob/main/royalty-vault/contracts/RoyaltyVault.sol>

### Impact

The Joyn documentation mentions that Joyn royalty vaults should be equipped to handle revenue generated on a collection's primary and secondary sales. Currently, `CoreCollection.sol` allows the collection owner to receive a fee on each token mint, however, there is no existing implementation which allows the owner of a collection to receive fees on secondary sales.

After discussion with the Joyn team, it appears that this will be gathered from Opensea which does not have an on-chain royalty mechanism. As such, each collection will need to be added manually on Opensea, introducing further centralisation risk. It is also possible for users to avoid paying the secondary fee by using other marketplaces such as Foundation.

### Recommended Mitigation Steps

Consider implementing the necessary functionality to allow for the collection of fees through an on-chain mechanism. `ERC2981` outlines the appropriate behaviour for this.


**[sofianeOuafir (Joyn) confirmed and commented](https://github.com/code-423n4/2022-03-joyn-findings/issues/130#issuecomment-1099679515):**
 > This is a great observation. Something we are aware of and intend to fix as well. ðŸ‘ 



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-joyn)

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## fee-on-transfer-patterns.md
# Fee On Transfer Security Patterns

## Overview

**Frequency**: 66 occurrences (0.13% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 64 | 1 | 0 |

**Common Sources**: Code4rena, Sherlock, Pashov Audit Group, Spearbit, Cyfrin

---

## Detection Checklist

- [ ] Check for fee on transfer vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-01] Incompatibility with fee-on-transfer/inflationary/deflationary/rebasing tokens, on both base tokens and quote tokens, with varying impacts

**Source**: Code4rena
**Protocol**: SIZE
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-size/blob/main/src/SizeSealed.sol#L163><br>
<https://github.com/code-423n4/2022-11-size/blob/main/src/SizeSealed.sol#L96-L105>

The following report describes two issues with how the `SizeSealed` contract incorrectly handles several so-called "weird ERC20" tokens, in which the token's balance can change unexpectedly:

*   How the contract cannot handle fee-on-transfer base tokens, and
*   How the contract incorrectly handles unusual ERC20 tokens in general, with stated impact.

#### Base tokens

Let us first note how the contract attempts to handle sudden balance change to the `baseToken`:

<https://github.com/code-423n4/2022-11-size/blob/main/src/SizeSealed.sol#L96-L105>

```solidity
uint256 balanceBeforeTransfer = ERC20(auctionParams.baseToken).balanceOf(address(this));

SafeTransferLib.safeTransferFrom(
    ERC20(auctionParams.baseToken), msg.sender, address(this), auctionParams.totalBaseAmount
);

uint256 balanceAfterTransfer = ERC20(auctionParams.baseToken).balanceOf(address(this));
if (balanceAfterTransfer - balanceBeforeTransfer != auctionParams.totalBaseAmount) {
    revert UnexpectedBalanceChange();
}
```

The effect is that the operation will revert with the error `UnexpectedBalanceChange()` if the received amount is different from what was transferred.

#### Quote tokens

Unlike base tokens, there is no such check when transferring the `quoteToken` from the bidder:

<https://github.com/code-423n4/2022-11-size/blob/main/src/Siz

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-size)

---

### Example 2: Fee on transfer can block several functions

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: MEDIUM

**Details**:

## Token Transfer Fee Risk Analysis

## Severity
**Medium Risk**

## Context
`AeraVaultV1.sol#L456-L514`

## Description
Some tokens have a fee on transfer, for example USDT. Usually, such a fee is not enabled but could be re-enabled at any time. With this fee enabled:

- The `withdrawFromPool()` function would receive slightly fewer tokens than the amounts requested from Balancer.
- This could cause the next `safeTransfer()` call to fail because there are not enough tokens inside the contract. 
- Consequently, `withdraw()` calls will fail.

The functions `deposit()` and `calculateAndDistributeManagerFees()` can also fail due to similar code.

> **Note:** The function `returnFunds()` is more robust and can handle this problem.

> **Note:** The problem can be alleviated by sending additional tokens directly to the Aera Vault contract to compensate for fees, lowering the severity of the problem to medium.

### Code Snippet
```solidity
function withdraw(uint256[] calldata amounts) ... {
    ...
    withdrawFromPool(amounts); // could get slightly less than amount with a fee on transfer
    ...
    for (uint256 i = 0; i < amounts.length; i++) {
        if (amounts[i] > 0) {
            tokens[i].safeTransfer(owner(), amounts[i]); // could revert if the full amounts[i] isn't available
        }
    }
    ...
}
```

## Recommendation
Check the `balanceOf()` tokens before and after a `safeTransfer()` or `safeTransferFrom()`. Use the difference as the amount of tokens sent/received.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 3: [M-01] Fee on transfer tokens will not behave as expected

**Source**: Code4rena
**Protocol**: Numoen
**Impact**: MEDIUM

**Details**:

In Numoen, it does not specifically restrict the type of ERC20 collateral used for borrowing.

If fee on transfer token(s) is/are entailed, it will specifically make `mint()` revert in Lendgine.sol when checking if `balanceAfter < balanceBefore + collateral`.

### Proof of Concept

[File: Lendgine.sol#L71-L102](https://github.com/code-423n4/2023-01-numoen/blob/main/src/core/Lendgine.sol#L71-L102)

```solidity
  function mint(
    address to,
    uint256 collateral,
    bytes calldata data
  )
    external
    override
    nonReentrant
    returns (uint256 shares)
  {
    _accrueInterest();

    uint256 liquidity = convertCollateralToLiquidity(collateral);
    shares = convertLiquidityToShare(liquidity);

    if (collateral == 0 || liquidity == 0 || shares == 0) revert InputError();
    if (liquidity > totalLiquidity) revert CompleteUtilizationError();
    // next check is for the case when liquidity is borrowed but then was completely accrued
    if (totalSupply > 0 && totalLiquidityBorrowed == 0) revert CompleteUtilizationError();

    totalLiquidityBorrowed += liquidity;
    (uint256 amount0, uint256 amount1) = burn(to, liquidity);
    _mint(to, shares);

    uint256 balanceBefore = Balance.balance(token1);
    IMintCallback(msg.sender).mintCallback(collateral, amount0, amount1, liquidity, data);
    uint256 balanceAfter = Balance.balance(token1);

99:    if (balanceAfter < balanceBefore + collateral) revert InsufficientInputError();

    emit Mint(msg.sender, collateral, s

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-numoen)

---

### Example 4: [M-02] The recipient receives free collateral token if an ERC20 token that deducts a fee on transfer used as baseToken

**Source**: Code4rena
**Protocol**: prePO
**Impact**: MEDIUM

**Details**:

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/Collateral.sol#L45-L61>

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/Collateral.sol#L64-L78>

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/DepositHook.sol#L49-L50>

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/WithdrawHook.sol#L76-L77>

### Impact

*   There are some ERC20 tokens that deduct a fee on every transfer call. If these tokens are used as baseToken then:
    1.  When depositing into the **Collateral** contract, the recipient will receive collateral token more than what they should receive.

    2.  The **DepositRecord** contract will track wrong user deposit amounts and wrong globalNetDepositAmount as the added amount to both will be always more than what was actually deposited.

    3.  When withdrawing from the **Collateral** contract, the user will receive less baseToken amount than what they should receive.

    4.  The treasury will receive less fee and the user will receive more `PPO` tokens that occur in **DepositHook**  and **WithdrawHook**.

### Proof of Concept

Given:
* baseToken is an ERC20 token that deduct a fee on every transfer call.
* **FoT** is the deducted fee on transfer.

1.  The user deposits baseToken to the **Collateral** contract by calling `deposit` function passi

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-prepo)

---

### Example 5: M-8: Complete debt size is not paid off for fee on transfer tokens, but users aren't warned

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/153 

## Found by 
tsvetanovv, rvierdiiev, Avci, obront, chaduke, berndartmueller, Breeje

## Summary

The protocol seems to be intentionally catering to fee on transfer tokens by measuring token balances before and after transfers to determine the value received. However, the mechanism to pay the full debt will not succeed in paying off the debt if it is used with a fee on transfer token.

## Vulnerability Detail

The protocol is clearly designed to ensure it is compatible with fee on transfer tokens. For example, all functions that receive tokens check the balance before and after, and calculate the difference between these values to measure tokens received:
```solidity
function doERC20TransferIn(address token, uint256 amountCall)
    internal
    returns (uint256)
{
    uint256 balanceBefore = IERC20Upgradeable(token).balanceOf(
        address(this)
    );
    IERC20Upgradeable(token).safeTransferFrom(
        msg.sender,
        address(this),
        amountCall
    );
    uint256 balanceAfter = IERC20Upgradeable(token).balanceOf(
        address(this)
    );
    return balanceAfter - balanceBefore;
}
```

There is another feature of the protocol, which is that when loans are being repaid, the protocol gives the option of passing `type(uint256).max` to pay your debt in full:
```solidity
if (amountCall == type(uint256).max) {
    amountCall = oldDebt;
}
```
However, these two features are not compa

*[Content truncated...]*

---

### Example 6: M-1: It doesn't handle fee-on-transfer/deflationary tokens

**Source**: Sherlock
**Protocol**: Bull v Bear
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bullvbear-judging/issues/130 

## Found by 
GimelSec, dipp, tives, Ruhum, rvierdiiev, cccz, Zarf, 0v3rf10w, Tomo, hansfriese, pashov

## Summary

The protocol doesn't handle fee-on-transfer/deflationary tokens, users will be unable to call `settleContract` and `reclaimContract` due to not enough assets in the contract.
Though the protocol uses `allowedAsset` to set the asset as supported as payment, we can't guarantee that the allowed non-deflationary token will always not become a deflationary token, especially upgradeable tokens (for example, USDC).

## Vulnerability Detail

Assume that A token is a deflationary token, and it will take 50% fee when transferring tokens. And the protocol only set 4% fee.

If a user is bear and call `mathOrder` with `order.premium = 100`, the `takerPrice` will be `100 + 100*4% = 104` but the protocol will only get `104 * 50% = 52` tokens in [L354](https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L354). 
Same problem in `order.collateral`, the user will be unable to call `settleContract` because the contract doesn't have enough A tokens.

## Impact

The protocol will be unable to pay enough tokens to users when users want to call `settleContract` or `reclaimContract`.

## Code Snippet

https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L354
https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-p

*[Content truncated...]*

---

### Example 7: [M-01] RoutingFee Can Be Set to `1 Wei` to Evade Fees

**Source**: Shieldify
**Protocol**: Gluex
**Impact**: MEDIUM

**Details**:

## Severity

Medium Risk

## Description

When using the protocol, the user will call `GlueXRouter.swap()` and set the `RouteDescription` as the parameter. The user can control the routing fee and can set it to 1 wei to evade fees.

```solidity
struct RouteDescription {
    IERC20 inputToken;
    IERC20 outputToken;
    address payable inputReceiver;
    address payable outputReceiver;
    uint256 inputAmount;
    uint256 outputAmount;
@>  uint256 routingFee;
    uint256 effectiveOutputAmount;
    uint256 minOutputAmount;
    bool isPermit2;
}
```

The `routingFee` cannot be 0, but it can be 1 wei.

```solidity
function swap(
    Executor executor,
@>  RouteDescription calldata desc,
    Interaction[] calldata interactions
) external payable returns (uint256 finalOutputAmount) {
    // code

    require(desc.routingFee > 0, "Negative routing fee");

    // code
}
```

## Location of Affected Code

File: [contracts/GluexRouter.sol#L35](https://github.com/gluexprotocol/gluex_router/blob/1df4eaef9c3063a3171961e1f8bba3eb83c6b7e1/contracts/GluexRouter.sol#L35)

File: [contracts/GluexRouter.sol#L90](https://github.com/gluexprotocol/gluex_router/blob/1df4eaef9c3063a3171961e1f8bba3eb83c6b7e1/contracts/GluexRouter.sol#L90)

## Impact

Users can evade fees.

## Recommendation

Consider setting the fee at a base percent `(maybe 0.1 - 1%)` and every time a `swap()` happens, a percentage of the fees will go directly to the fee treasury.

## Team Response

Acknowledged, the risk will be mi

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/GlueX-Security-Review.md)

---

### Example 8: Fee-on-transfer tokens are not supported

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

### Example 9: Non-standard ERC20 tokens are not supported

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

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
47:             token.safeTransferFrom(msg.sender, address(this), amount);
48:             uint256 depositIndex = deposits.length;
49:             deposits.push(Deposit(payable(msg.sender), amount, tokenAddress));//@audit-issue fee-on-transfer, rebalancing tokens will cause problems
50:             emit DepositMade(msg.sender, depositIndex, amount, tokenAddress);
51:
52:         }
53:     }
```
Looking at the line L49, we can see that the protocol assumes `amount` of tokens were transferred.
But this does not hold true for some non-standard ERC20 tokens like fee-on-transfer tokens or rebalancing tokens.
(Refer to [here](https://github.com/d-

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 10: [M-01] If the underlying asset is a fee on transfer token, it could break the internal accounting of the vault

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

The `Vault._deposit` function is used by the users to deposit `_assets` to the vault and mint vault shares to the `recipient` address. The amount of `_assets` are transferred to the `Vault` as follows:

      SafeERC20.safeTransferFrom(
        _asset,
        _caller,
        address(this),
        _assetsDeposit != 0 ? _assetsDeposit : _assets
      );

The `Vault.deposit` function uses this `_assets` amount to calculate the number of `shares` to be minted to the `_recipient` address.

The issue here is if the underlying `_asset` is a fee on transfer token then the actual received amount to the vault will be less than what is referred in the `Vault.deposit` function `_assets` input parameter. But the shares to mint is calculated using the entire `_assets` amount.

This issue could be further aggravated since the `_asset` is again `deposited` to the `_yieldVault` and when needing to be redeemed, will be `withdrawn` from the `_yieldVault` as well. These operations will again charge a fee if the `_asset` is a fee on transfer token. Hence, the actual `_asset` amount left for a particular user will be less than the amount they initially transferred in.

Hence, when the user `redeems` the minted shares back to the `_assets`, the contract will not have enough assets to transfer to the `redeemer`, thus reverting the transaction.

### Proof of Concept

```solidity
      SafeERC20.safeTransferFrom(
        _asset,
        _caller,
        address(this),
        _assetsDeposit != 0 ? 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-pooltogether)

---

### Example 11: TRST-M-4 Deposits of fee-on-transfer tokens will favor later depositors, making earlier investors lose funds

**Source**: Trust Security
**Protocol**: Orbital Finance
**Impact**: MEDIUM

**Details**:

**Description:**
When deposits are processed, the percentage of **Denominator** minted to the depositor is 
linear to the contribution, compared to the current balance. 
```solidity
         uint256 T = vlt.virtualTotalBalance(); //will be at least 1
         uint256 D = vlt.D();
         if (functions.willOverflowWhenMultiplied(amt, D)) {
            require(T > amt || T > D, "overflow");
         }
         deltaN = Arithmetic.overflowResistantFraction(amt, D, T);
             vlt.setN(msg.sender, vlt.N(msg.sender) + deltaN);
                  vlt.setD(D + deltaN); //D always kept = sum of all Ns, plus 
                    vlt.initD()
         for (uint256 i = 0; i < tkns.length; i++) {
            if (amts[i] > 0) {
         IERC20(tkns[i]).safeTransferFrom(msg.sender, vaultAddress, amts[i]);
            }
         }
```
The calculation will lead to incorrect results when using fee-on-transfer (tax) tokens. The 
"before-tax" amount of the depositor will be compared to the "after-tax" amount in the 
contract balance. It is exploitable by immediately withdrawing the shares, receiving more 
tokens than the amount contributed (unless fees are higher than the token tax). 

**Recommended mitigation:**
Compare the balance before and after the `safeTransferFrom()` call.

**Team response:**
"amt now calculated by comparing vault balances before and after safeTransferFrom. N and 
D updated afterwards. "

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-28-Orbital Finance.md)

---

### Example 12: [M-03] Tokens with a fee-on-transfer mechanism will break the protocol

**Source**: Pashov Audit Group
**Protocol**: Ipnft
**Impact**: MEDIUM

**Details**:

**Impact:**
High, as some users will lose value

**Likelihood:**
Low, as such tokens are not common

**Description**

The ERC20 logic in all crowd sale contracts as well as in `TimelockedToken` is incompatible with tokens that have a fee-on-transfer mechanism. Such tokens for example is `PAXG`, while `USDT` has a built-in fee-on-transfer mechanism that is currently switched off. One example of this `CrowdSale::startSale` where the following code:

```solidity
sale.auctionToken.safeTransferFrom(msg.sender, address(this), sale.salesAmount);
```

Will work incorrectly if the token has a fee-on-transfer mechanism - the contract will cache `sale.salesAmount` as it's expected balance, but it will actually have `sale.salesAmount - fee` balance. This will result in a revert in the last person to transfer `auctionTokens` out of the contract. Same thing applies for other `transferFrom` calls that transfer tokens into the protocol, for example in `TimelockedToken::lock`.

**Recommendations**

You should cache the balance before a `transferFrom` to the contract and then check it after the transfer and use the difference between them as the newly added balance. This also requires a `nonReentrant` modifier, as otherwise ERC777 tokens can manipulate this. Another fix is to just document and announce you do not support tokens that can have a fee-on-transfer mechanism.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-05-01-IPNFT.md)

---

### Example 13: [M-04] Tokens with a fee-on-transfer mechanism will break the protocol

**Source**: Pashov Audit Group
**Protocol**: Bloom
**Impact**: MEDIUM

**Details**:

**Impact:**
High, as some users will lose value

**Likelihood:**
Low, as such tokens are not common

**Description**

The ERC20 logic in `BloomPool` is incompatible with tokens that have a fee-on-transfer mechanism. Such tokens for example is `PAXG`, while `USDT` has a built-in fee-on-transfer mechanism that is currently switched off. One example of this `BloomPool::depositBorrower` where the following code:

```solidity
UNDERLYING_TOKEN.safeTransferFrom(msg.sender, address(this), amount);
```

This will work incorrectly if the token has a fee-on-transfer mechanism - the contract will cache `amount` as its expected added balance, but it will actually add `amount - fee` balance. This will result in a revert in the last person to withdraw tokens out of the contract. Same thing applies for other `transferFrom` calls that transfer tokens into the protocol, for example in `SwapFacility::_swap`.

**Recommendations**

You should cache the balance before a `transferFrom` to the contract and then check it after the transfer and use the difference between them as the newly added balance. This also requires a `nonReentrant` modifier, as otherwise ERC777 tokens can manipulate this. Another fix is to just document and announce you do not support tokens that can have a fee-on-transfer mechanism.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-05-01-Bloom.md)

---

### Example 14: Fee on transfer tokens

**Source**: Spearbit
**Protocol**: Polygon zkEVM Contracts
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
`PolygonZkEVMBridge.sol#L171`

## Description
The bridge contract will not work properly with a fee on transfer tokens.

1. User A bridges a fee on transfer Token A from Mainnet to Rollover R1 for amount X.
2. In that case, X-fees will be received by the bridge contract on Mainnet, but the deposit receipt of the full amount X will be stored in Merkle.
3. The amount is claimed in R1, and a new TokenPair for Token A is generated, and the full amount X is minted to User A.
4. Now the full amount is bridged back again to Mainnet.
5. When a claim is made on Mainnet, then the contract tries to transfer amount X, but since it received the amount X-fees, it will use the amount from other users, which eventually causes denial of service (DOS) for other users using the same token.

## Recommendation
Use the exact amount that is transferred to the contract, which can be obtained using the sample code below:

```solidity
uint256 balanceBefore = IERC20Upgradeable(token).balanceOf(address(this));
IERC20Upgradeable(token).safeTransferFrom(address(msg.sender), address(this), amount);
uint256 balanceAfter = IERC20Upgradeable(token).balanceOf(address(this));
uint256 transferedAmount = balanceAfter - balanceBefore;

// if you don't want to support fee on transfer token use below:
require(transferedAmount == amount, ...);

// use transferedAmount if you want to support fee on transfer token
```

## Additional Notes
- Polygon-Hermez: Solved in PR 87. To protec

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/zkEVM-bridge-Spearbit-27-March.pdf)

---

### Example 15: [M-04] Auction won't work correctly with fee-on-transfer & rebasing tokens

**Source**: Pashov Audit Group
**Protocol**: Rolling Dutch Auction
**Impact**: MEDIUM

**Details**:

**Impact:**
High, as it can lead to a loss of value

**Likelihood:**
Low, as such tokens are not so common

**Description**

The code in `createAuction` does the following:

```solidity
IERC20(reserveToken).transferFrom(msg.sender, address(this), reserveAmount);
...
...
state.reserves = reserveAmount;
```

so it basically caches the expected transferred amount. This will not work if the `reserveToken` has a fee-on-transfer mechanism, since the actual received amount will be less because of the fee. It is also a problem if the token used had a rebasing mechanism, as this can mean that the contract will hold less balance than what it cached in `state.reserves` for the auction, or it will hold more, which will be stuck in the protocol.

**Recommendations**

You can either explicitly document that you do not support tokens with a fee-on-transfer or rebasing mechanism or you can do the following:

1. For fee-on-transfer tokens, check the balance before and after the transfer and use the difference as the actual amount received.
2. For rebasing tokens, when they go down in value, you should have a method to update the cached `reserves` accordingly, based on the balance held. This is a complex solution.
3. For rebasing tokens, when they go up in value, you should add a method to actually transfer the excess tokens out of the protocol.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-03-01-Rolling Dutch Auction.md)

---

### Example 16: [M-06] Code credits fee-on-transfer tokens for amount stated, not amount transferred

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: MEDIUM

**Details**:

_Submitted by IllIllI, also found by cccz, hake, Meera, rbserver, and robee_

Some ERC20 tokens, such as USDT, allow for charging a fee any time `transfer()` or `transferFrom()` is called. If a contract does not allow for amounts to change after transfers, subsequent transfer operations based on the original amount will `revert()` due to the contract having an insufficient balance.

### Impact

If there is only one user that has use a payment terminal with a fee-on-transfer token to pay a project for its token, that project will be unable to withdraw their funds, because the amount available will be less than the amount stated during deposit, and therefore the token's `transfer()` call will revert during withdrawal. For more users, consider what happens if the token has a 10% fee-on-transfer fee - deposits will be underfunded by 10%, and the projects trying to withdraw the last 10% of deposits/rewards will have their calls revert due to the contract not holding enough tokens. If a whale does a large withdrawal, the extra 10% that that whale gets will mean that *many* projects will not be able to withdraw anything at all.

### Proof of Concept

Because the terminals rely on terminal stores, which only store the initial value provided during the payment, and provide it during distributions, the terminals are unable to use the decreased value when they later are told to distribute funds to a project.

`JBSingleTokenPaymentTerminalStore.recordPaymentFrom()` stores the value passe

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-juicebox)

---

### Example 17: [M-25] Consistently check account balance before and after transfers for Fee-On-Transfer discrepancies

**Source**: Code4rena
**Protocol**: veToken Finance
**Impact**: MEDIUM

**Details**:

_Submitted by Dravee, also found by pauliax_

<https://github.com/code-423n4/2022-05-vetoken/blob/2d7cd1f6780a9bcc8387dea8fecfbd758462c152/contracts/Booster.sol#L356>

<https://github.com/code-423n4/2022-05-vetoken/blob/2d7cd1f6780a9bcc8387dea8fecfbd758462c152/contracts/VE3DRewardPool.sol#L337>

### Vulnerability Details

As arbitrary ERC20 tokens can be passed, the amount here should be calculated every time to take into consideration a possible fee-on-transfer or deflation.

Also, it's a good practice for the future of the solution.

Affected code:

*   File: Booster.sol

```
345:     function deposit(
346:         uint256 _pid,
347:         uint256 _amount,
348:         bool _stake
349:     ) public returns (bool) {
...
356:         IERC20(lptoken).safeTransferFrom(msg.sender, staker, _amount); //@audit medium: not compatible with Fee On Transfer Tokens
...
372:             ITokenMinter(token).mint(address(this), _amount);
...
374:             IERC20(token).safeApprove(rewardContract, _amount);
375:             IRewards(rewardContract).stakeFor(msg.sender, _amount);
...
378:             ITokenMinter(token).mint(msg.sender, _amount);
...
381:         emit Deposited(msg.sender, _pid, _amount);
...
```

*   File: VE3DRewardPool.sol

```
336:     function donate(address _rewardToken, uint256 _amount) external {
337:         IERC20(_rewardToken).safeTransferFrom(msg.sender, address(this), _amount); //@audit medium: not compatible with Fee On Transfer Tokens
338:         rewardT

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-vetoken)

---

### Example 18: [M-05] Inconsistent Order Book Accounting When Working With Transfer-On-Fee or Deflationary Tokens

**Source**: Code4rena
**Protocol**: Rubicon
**Impact**: MEDIUM

**Details**:

_Submitted by xiaoming90, also found by MaratCerby, IllIllI, GimelSec, PP1004, blockdev, berndartmueller, WatchPug, and ilan_

A transfer-on-fee token or a deflationary/rebasing token, causing the received amount to be less than the accounted amount. For instance, a deflationary tokens might charge a certain fee for every transfer() or transferFrom().

Rubicon Finance supports the trading of any ERC20 token, and anyone can liquidity pool for a new token. Thus, it is possible that such a transfer-on-fee token or a deflationary/rebasing token be used in the protocol.

Based on the source code and comment of `BathToken._deposit()`, it appears that the team is aware of this issue, and proactively implemented control (before & after balance checks) to deal with deflationary tokens.

<https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/rubiconPools/BathToken.sol#L557>

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

    (totalSupply == 0) ? shares = assets : shares = (
        assets.mul(totalSupply)
    ).div(_pool);

    //

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-rubicon)

---

### Example 19: [M-04] Protocol doesn't handle fee on transfer tokens

**Source**: Code4rena
**Protocol**: Cudos
**Impact**: MEDIUM

**Details**:

_Submitted by wuwe1, also found by cccz, defsec, dipp, Dravee, GermanKuber, GimelSec, jah, reassor, and WatchPug_

[Gravity.sol#L600](https://github.com/code-423n4/2022-05-cudos/blob/main/solidity/contracts/Gravity.sol#L600)<br>

Since the `_tokenContract` can be any token, it is possible that loans will be created with tokens that support fee on transfer. If a fee on transfer asset token is chosen, other user's funds might be drained.

### Proof of Concept

1.  Assume transfer fee to be 5% and `Gravity.sol` has 200 token.
2.  Alice sendToCosmos 100 token. Now, `Gravity.sol` has 295 token.
3.  Alice calls the send-to-eth method to withdraw 100 token.
4.  `Gravity.sol` ends up having 195 token.

### Recommended Mitigation Steps

Change to

```solidity
	function sendToCosmos(
		address _tokenContract,
		bytes32 _destination,
		uint256 _amount
	) public nonReentrant  {
                uint256 oldBalance = IERC20(_tokenContract).balanceOf(address(this));
		IERC20(_tokenContract).safeTransferFrom(msg.sender, address(this), _amount);
                uint256 receivedAmout = IERC20(_tokenContract).balanceOf(address(this)) - oldBalance;
		state_lastEventNonce = state_lastEventNonce.add(1);
		emit SendToCosmosEvent(
			_tokenContract,
			msg.sender,
			_destination,
			receivedAmout,
			state_lastEventNonce
		);
	}
```

**[mlukanova (Cudos) acknowledged and commented](https://github.com/code-423n4/2022-05-cudos-findings/issues/3#issuecomment-1123721942):**
 > Token transfers are restri

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-cudos)

---

### Example 20: [M-02] Protocol doesn't handle fee on transfer tokens

**Source**: Code4rena
**Protocol**: Backed Protocol
**Impact**: MEDIUM

**Details**:

_Submitted by 0xDjango, also found by cccz, csanuragjain, Dravee, IllIllI, robee, and Ruhum_

[NFTLoanFacilitator.sol#L155-L160](https://github.com/code-423n4/2022-04-backed/blob/e8015d7c4b295af131f017e646ba1b99c8f608f0/contracts/NFTLoanFacilitator.sol#L155-L160)<br>

Since the borrower is able to specify any asset token, it is possible that loans will be created with tokens that support fee on transfer. If a fee on transfer asset token is chosen, the protocol will contain a point of failure on the original `lend()` call.

It is my belief that this is a medium severity vulnerability due to its ability to impact core protocol functionality.

### Proof of Concept

For the first lender to call `lend()`, if the transfer fee % of the asset token is larger than the origination fee %, the second transfer will fail in the following code:

```solidity
ERC20(loanAssetContractAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 facilitatorTake = amount * originationFeeRate / SCALAR;
ERC20(loanAssetContractAddress).safeTransfer(
    IERC721(borrowTicketContract).ownerOf(loanId),
    amount - facilitatorTake
);
```

Example:

*   `originationFee = 2%` Max fee is 5% per comments

*   `feeOnTransfer = 3%`

*   `amount = 100 tokens`

*   Lender transfers `amount`

*   `NFTLoanFacilitator` receives `97`.

*   `facilitatorTake = 2`

*   `NFTLoanFacilitator` attempts to send `100 - 2` to borrower, but only has `97`.

*   Execution reverts.

#### Other considerations:

If the or

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-backed)

---

### Example 21: [M-04] ERC4626 does not work with fee-on-transfer tokens

**Source**: Code4rena
**Protocol**: Tribe
**Impact**: MEDIUM

**Details**:

_Submitted by cmichel_

> The docs/video say `ERC4626.sol` is in scope as its part of `TurboSafe`

The `ERC4626.deposit/mint` functions do not work well with fee-on-transfer tokens as the `amount` variable is the pre-fee amount, including the fee, whereas the `totalAssets` do not include the fee anymore.

This can be abused to mint more shares than desired.

```solidity
function deposit(uint256 amount, address to) public virtual returns (uint256 shares) {
    // Check for rounding error since we round down in previewDeposit.
    require((shares = previewDeposit(amount)) != 0, "ZERO_SHARES");

    // Need to transfer before minting or ERC777s could reenter.
    asset.safeTransferFrom(msg.sender, address(this), amount);

    _mint(to, shares);

    emit Deposit(msg.sender, to, amount, shares);

    afterDeposit(amount, shares);
}
```

### Proof of Concept

A `deposit(1000)` should result in the same shares as two deposits of `deposit(500)` but it does not because `amount` is the pre-fee amount.
Assume a fee-on-transfer of `20%`. Assume current `totalAmount = 1000`, `totalShares = 1000` for simplicity.

*   `deposit(1000) = 1000 / totalAmount * totalShares = 1000 shares`
*   `deposit(500) = 500 / totalAmount * totalShares = 500 shares`. Now the `totalShares` increased by 500 but the `totalAssets` only increased by `(100% - 20%) * 500 = 400`. Therefore, the second `deposit(500) = 500 / (totalAmount + 400) * (newTotalShares) = 500 / (1400) * 1500 = 535.714285714 shares`.

In total

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-tribe-turbo)

---

### Example 22: [M-07] Fee-on-transfer token donations in `Shelter` break withdrawals

**Source**: Code4rena
**Protocol**: Concur Finance
**Impact**: MEDIUM

**Details**:

_Submitted by cmichel, also found by Dravee, IllIllI, and Ruhum_

[Shelter.sol#L34](https://github.com/code-423n4/2022-02-concur/blob/72b5216bfeaa7c52983060ebfc56e72e0aa8e3b0/contracts/Shelter.sol#L34)<br>

The `Sheler.donate` function `transferFrom`s `_amount` and adds the entire `_amount` to `savedTokens[_token]`.<br>
But the actual received token amount from the transfer can be less for fee-on-transfer tokens.

The last person to withdraw will not be able to as `withdraw` uses a share computation for the entire `savedTokens[_token]` amount.<br>
The calculated `amount` will then be higher than the actual contract balance.

```solidity
function donate(IERC20 _token, uint256 _amount) external {
    require(activated[_token] != 0, "!activated");
    savedTokens[_token] += _amount;
    // @audit fee-on-transfer. then fails for last person in `withdraw`
    _token.safeTransferFrom(msg.sender, address(this), _amount);
}

function withdraw(IERC20 _token, address _to) external override {
    // @audit percentage on storage var, not on actual balance
    uint256 amount = savedTokens[_token] * client.shareOf(_token, msg.sender) / client.totalShare(_token);
    // @audit amount might not be in contract anymore as savedTokens[_token] is over-reported
    _token.safeTransfer(_to, amount);
}
```

### Recommended Mitigation Steps

In `donate`, add only the actual transferred amounts (computed by `post-transfer balance - pre-transfer balance`) to `savedTokens[_token]`.

**[leekt (Concur) a

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-concur)

---

### Example 23: [M-06] Consistently check account balance before and after transfers for Fee-On-Transfer discrepencies

**Source**: Code4rena
**Protocol**: Behodler
**Impact**: MEDIUM

**Details**:

_Submitted by Dravee_

Wrong fateBalance bookkeeping for a user.
Wrong fateCreated value emitted.

#### Proof of Concept

Taking into account the FOT is done almost everywhere important in the solution already. That's a known practice in the solution.

However, it's missing here (see @audit-info tags):
```js
File: LimboDAO.sol
383:   function burnAsset(address asset, uint256 amount) public isLive incrementFate {
384:     require(assetApproved[asset], "LimboDAO: illegal asset");
385:     address sender = _msgSender();
386:     require(ERC677(asset).transferFrom(sender, address(this), amount), "LimboDAO: transferFailed"); //@audit-info FOT not taken into account
387:     uint256 fateCreated = fateState[_msgSender()].fateBalance;
388:     if (asset == domainConfig.eye) {
389:       fateCreated = amount * 10; //@audit-info wrong amount due to lack of FOT calculation
390:       ERC677(domainConfig.eye).burn(amount);//@audit-info wrong amount due to lack of FOT calculation
391:     } else {
392:       uint256 actualEyeBalance = IERC20(domainConfig.eye).balanceOf(asset);
393:       require(actualEyeBalance > 0, "LimboDAO: No EYE");
394:       uint256 totalSupply = IERC20(asset).totalSupply();
395:       uint256 eyePerUnit = (actualEyeBalance * ONE) / totalSupply;
396:       uint256 impliedEye = (eyePerUnit * amount) / ONE;//@audit-info wrong amount due to lack of FOT calculation
397:       fateCreated = impliedEye * 20;
398:     }
399:     fateState[_msgSender()].fateBalance += fate

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-behodler)

---

### Example 24: [M-01] UniV2ClassDex.sol#uniClassSell() Tokens with fee on transfer are not fully supported

**Source**: Code4rena
**Protocol**: OpenLeverage
**Impact**: MEDIUM

**Details**:

## Handle

WatchPug


## Vulnerability details

https://github.com/code-423n4/2022-01-openleverage/blob/501e8f5c7ebaf1242572712626a77a3d65bdd3ad/openleverage-contracts/contracts/dex/bsc/UniV2ClassDex.sol#L31-L56

```solidity
function uniClassSell(DexInfo memory dexInfo,
    address buyToken,
    address sellToken,
    uint sellAmount,
    uint minBuyAmount,
    address payer,
    address payee
) internal returns (uint buyAmount){
    address pair = getUniClassPair(buyToken, sellToken, dexInfo.factory);
    IUniswapV2Pair(pair).sync();
    (uint256 token0Reserves, uint256 token1Reserves,) = IUniswapV2Pair(pair).getReserves();
    sellAmount = transferOut(IERC20(sellToken), payer, pair, sellAmount);
    uint balanceBefore = IERC20(buyToken).balanceOf(payee);
    dexInfo.fees = getPairFees(dexInfo, pair);
    if (buyToken < sellToken) {
        buyAmount = getAmountOut(sellAmount, token1Reserves, token0Reserves, dexInfo.fees);
        IUniswapV2Pair(pair).swap(buyAmount, 0, payee, "");
    } else {
        buyAmount = getAmountOut(sellAmount, token0Reserves, token1Reserves, dexInfo.fees);
        IUniswapV2Pair(pair).swap(0, buyAmount, payee, "");
    }

    require(buyAmount >= minBuyAmount, 'buy amount less than min');
    uint bought = IERC20(buyToken).balanceOf(payee).sub(balanceBefore);
    return bought;
}
```

While `uniClassBuy()` correctly checks the actually received amount by comparing the before and after the balance of the receiver, `uniClassSell()` trusted the resu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-openleverage)

---

### Example 25: [M-05] Vault.sol Tokens with fee on transfer are not supported

**Source**: Code4rena
**Protocol**: InsureDAO
**Impact**: MEDIUM

**Details**:

## Handle

WatchPug


## Vulnerability details

There are ERC20 tokens that charge fee for every `transfer()` / `transferFrom()`.

`Vault.sol#addValue()` assumes that the received amount is the same as the transfer amount, and uses it to calculate attributions, balance amounts, etc. While the actual transferred amount can be lower for those tokens.

https://github.com/code-423n4/2022-01-insure/blob/19d1a7819fe7ce795e6d4814e7ddf8b8e1323df3/contracts/Vault.sol#L124-L140

```solidity
function addValue(
    uint256 _amount,
    address _from,
    address _beneficiary
) external override onlyMarket returns (uint256 _attributions) {

    if (totalAttributions == 0) {
        _attributions = _amount;
    } else {
        uint256 _pool = valueAll();
        _attributions = (_amount * totalAttributions) / _pool;
    }
    IERC20(token).safeTransferFrom(_from, address(this), _amount);
    balance += _amount;
    totalAttributions += _attributions;
    attributions[_beneficiary] += _attributions;
}
```

### Recommendation

Consider comparing before and after balance to get the actual transferred amount.

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-insure)

---

## Statistics

- Total findings analyzed: 66
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## rebasing-tokens-patterns.md
# Rebasing Tokens Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 3 | 0 | 0 |

**Common Sources**: Code4rena, Cyfrin

---

## Detection Checklist

- [ ] Check for rebasing tokens vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-05] Aave's share tokens are rebasing breaking current strategy code

**Source**: Code4rena
**Protocol**: Sublime
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by WatchPug and leastwood_

When depositing into Aave through the `AaveYield.lockTokens` contract strategy, one receives the `sharesReceived` amount corresponding to the diff of `aToken` balance, which is just always the deposited amount as aave is a rebasing token and `1.0 aToken = 1.0 underlying` at each deposit / withdrawal.

Note that this `sharesReceived` (the underlying deposit amount) is cached in a `balanceInShares` map in `SavingsAccount.deposit` which makes this share *static* and not dynamically rebasing anymore:

```solidity
function deposit(
    uint256 _amount,
    address _token,
    address _strategy,
    address _to
) external payable override nonReentrant returns (uint256) {
    require(_to != address(0), 'SavingsAccount::deposit receiver address should not be zero address');
    uint256 _sharesReceived = _deposit(_amount, _token, _strategy);
    balanceInShares[_to][_token][_strategy] = balanceInShares[_to][_token][_strategy].add(_sharesReceived);
    emit Deposited(_to, _sharesReceived, _token, _strategy);
    return _sharesReceived;
}

function getTokensForShares(uint256 shares, address asset) public view override returns (uint256 amount) {
    if (shares == 0) return 0;
    address aToken = liquidityToken(asset);

    (, , , , , , , uint256 liquidityIndex, , ) = IProtocolDataProvider(protocolDataProvider).getReserveData(asset);

    // @audit-info tries to do (user shares / total shares) * underlying amount where underly

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-12-sublime)

---

### Example 2: [M-02] The recipient receives free collateral token if an ERC20 token that deducts a fee on transfer used as baseToken

**Source**: Code4rena
**Protocol**: prePO
**Impact**: MEDIUM

**Details**:

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/Collateral.sol#L45-L61>

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/Collateral.sol#L64-L78>

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/DepositHook.sol#L49-L50>

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/WithdrawHook.sol#L76-L77>

### Impact

*   There are some ERC20 tokens that deduct a fee on every transfer call. If these tokens are used as baseToken then:
    1.  When depositing into the **Collateral** contract, the recipient will receive collateral token more than what they should receive.

    2.  The **DepositRecord** contract will track wrong user deposit amounts and wrong globalNetDepositAmount as the added amount to both will be always more than what was actually deposited.

    3.  When withdrawing from the **Collateral** contract, the user will receive less baseToken amount than what they should receive.

    4.  The treasury will receive less fee and the user will receive more `PPO` tokens that occur in **DepositHook**  and **WithdrawHook**.

### Proof of Concept

Given:
* baseToken is an ERC20 token that deduct a fee on every transfer call.
* **FoT** is the deducted fee on transfer.

1.  The user deposits baseToken to the **Collateral** contract by calling `deposit` function passi

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-prepo)

---

### Example 3: Non-standard ERC20 tokens are not supported

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

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
47:             token.safeTransferFrom(msg.sender, address(this), amount);
48:             uint256 depositIndex = deposits.length;
49:             deposits.push(Deposit(payable(msg.sender), amount, tokenAddress));//@audit-issue fee-on-transfer, rebalancing tokens will cause problems
50:             emit DepositMade(msg.sender, depositIndex, amount, tokenAddress);
51:
52:         }
53:     }
```
Looking at the line L49, we can see that the protocol assumes `amount` of tokens were transferred.
But this does not hold true for some non-standard ERC20 tokens like fee-on-transfer tokens or rebalancing tokens.
(Refer to [here](https://github.com/d-

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 4: [M-15] Lack of timelock on `rigidRedemption`, enables to steal yield from other users

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: MEDIUM

**Details**:

The withdraw function of the `LybraEUSDVaultBase` vaults, uses a time softlock to prevent users from hopping in and out of the protocol; to gain access to the yield generated by other users and then leave right away (by charging a small percentage from the withdrawn amount).

The same measure isn't applied to `rigidRedemptions`, which enable a user to withdraw most of the underlying assets at any time after deposit. This enables a user to deposit into the pool right before a rebase is about to happen, get access to the yield generated by other users and leave by calling `rigidRedemption` and withdraw on the tokens left by `rigidRedemption` (the amount charged on the leftovers assets, can be outbalanced by the yield).

Therefore, a malicious user to get access to yield that they didn't generate, effectively stealing it from others. The amount that the user will get access to will vary based on the deposited amounts.

### Proof of Concept

This issue involves 3 functions:

- `withdraw(address onBehalfOf, uint256 amount)` from the `LybraEUSDVaultBase` [contract](https://github.com/code-423n4/2023-06-lybra/blob/7b73ef2fbb542b569e182d9abf79be643ca883ee/contracts/lybra/pools/base/LybraEUSDVaultBase.sol#L98), which internally calls `checkWithdrawal(address user, uint256 amount)` to check that 3 days has passed after deposit and charges the user otherways:

    ```
    withdrawal = block.timestamp - 3 days >= depositedTime[user] ? amount : (amount * 999) / 1000;
    ```

- `rigidRede

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## weird-erc20-patterns.md
# Weird ERC20 Security Patterns

## Overview

**Frequency**: 26 occurrences (0.05% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 20 | 1 | 0 |

**Common Sources**: Code4rena, Sherlock, Cyfrin, Pashov Audit Group, OpenZeppelin

---

## Detection Checklist

- [ ] Check for weird erc20 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01]  Someone can create non-liquidatable auction if the collateral asset fails on transferring to address(0)

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

A malicious user can run a bot to monitor his own vault, and if the got underwater and they donâ€™t have enough collateral to top up, they can immediately start an auction on their own vault and set actioneer to `0` to avoid actually being liquidated, which breaks the design of the system.


## Recommended Mitigation Steps

Add check while starting an auction:

```jsx
function auction(bytes12 vaultId, address to)
    external
    returns (DataType

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-yield)

---

### Example 2: `TokenSaleProposal::buy` implicitly assumes that buy token has 18 decimals resulting in a potential total loss scenario for Dao Pool

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

### Example 3: Missing check of return value of transfer and transferFrom

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
OpenZeppelinâ€™s SafeERC20 library, the return values of calls to `transfer` and
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

### Example 4: [M-01] Incompatibility with fee-on-transfer/inflationary/deflationary/rebasing tokens, on both base tokens and quote tokens, with varying impacts

**Source**: Code4rena
**Protocol**: SIZE
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-size/blob/main/src/SizeSealed.sol#L163><br>
<https://github.com/code-423n4/2022-11-size/blob/main/src/SizeSealed.sol#L96-L105>

The following report describes two issues with how the `SizeSealed` contract incorrectly handles several so-called "weird ERC20" tokens, in which the token's balance can change unexpectedly:

*   How the contract cannot handle fee-on-transfer base tokens, and
*   How the contract incorrectly handles unusual ERC20 tokens in general, with stated impact.

#### Base tokens

Let us first note how the contract attempts to handle sudden balance change to the `baseToken`:

<https://github.com/code-423n4/2022-11-size/blob/main/src/SizeSealed.sol#L96-L105>

```solidity
uint256 balanceBeforeTransfer = ERC20(auctionParams.baseToken).balanceOf(address(this));

SafeTransferLib.safeTransferFrom(
    ERC20(auctionParams.baseToken), msg.sender, address(this), auctionParams.totalBaseAmount
);

uint256 balanceAfterTransfer = ERC20(auctionParams.baseToken).balanceOf(address(this));
if (balanceAfterTransfer - balanceBeforeTransfer != auctionParams.totalBaseAmount) {
    revert UnexpectedBalanceChange();
}
```

The effect is that the operation will revert with the error `UnexpectedBalanceChange()` if the received amount is different from what was transferred.

#### Quote tokens

Unlike base tokens, there is no such check when transferring the `quoteToken` from the bidder:

<https://github.com/code-423n4/2022-11-size/blob/main/src/Siz

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-size)

---

### Example 5: [H-02] The check for value transfer success is made after the return statement in `_withdrawFromYieldPool` of `LidoVault`

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

### Example 6: [M-15]  Blocklisting in payment ERC20 can cause rented NFT to be stuck in Safe

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

### Example 7: [M-09] Variable balance ERC20 support

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: MEDIUM

**Details**:

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/utils/EscrowLib.sol#L94-L96>

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/utils/EscrowLib.sol#L75-L79>

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L273-L280>

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L487-L493>

### Impact

Some ERC20 may be tricky for the balance. Such as:

*   fee on transfer (STA, USDT also has this mode)
*   rebasing (aToken from AAVE)
*   variable balance (stETH, balance could go up and down)

For these tokens, the balance can change over time, even without `transfer()/transferFrom()`. But current accounting stores the spot balance of the asset.

The impacts include:

*   the calculation of collateral value could be inaccurate
*   protocol could lose funds due to the deposit/repay amount being less than the actual transferred amount after fee
*   the amount user withdraw collateral when `_close()` will be inaccurate
    *   some users could lose funds due to under value
    *   some funds could be locked due to the balance inflation
    *   some funds might be locked due to the balance deflation

### Proof of Concept

The spot new deposit amount is stored in the mapping `self.deposited[token].amount` and `credit.deposit`, and la

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 8: M-1: `Cooler.roll()` wouldn't work as expected when `newCollateral = 0`.

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/320 

## Found by 
hansfriese, cccz, Allarious, csanuragjain



## Summary
`Cooler.roll()` is used to increase the loan duration by transferring the additional collateral.

But there will be some problems when `newCollateral = 0`.

## Vulnerability Detail
```solidity
    function roll (uint256 loanID) external {
        Loan storage loan = loans[loanID];
        Request memory req = loan.request;

        if (block.timestamp > loan.expiry) 
            revert Default();

        if (!loan.rollable)
            revert NotRollable();

        uint256 newCollateral = collateralFor(loan.amount, req.loanToCollateral) - loan.collateral;
        uint256 newDebt = interestFor(loan.amount, req.interest, req.duration);

        loan.amount += newDebt;
        loan.expiry += req.duration;
        loan.collateral += newCollateral;
        
        collateral.transferFrom(msg.sender, address(this), newCollateral); //@audit 0 amount
    }
```

In `roll()`, it transfers the `newCollateral` amount of collateral to the contract.

After the borrower repaid most of the debts, `loan.amount` might be very small and `newCollateral` for the original interest might be 0 because of the rounding issue.

Then as we can see from this [one](https://github.com/d-xo/weird-erc20#revert-on-zero-value-transfers), some tokens might revert for 0 amount and `roll()` wouldn't work as expected.

## Impact
There will be 2 impacts.

1. When the 

*[Content truncated...]*

---

### Example 9: [M-01] User can't unstake in case he gets blacklisted by reward token USDC

**Source**: Pashov Audit Group
**Protocol**: Gainsnetwork
**Impact**: MEDIUM

**Details**:

**Severity**

Impact: High. User can't unstake his Gns

Likelihood: Low. USDC blacklisting is not usual operation.

**Description**

USDC is supposed to be used as reward token, note it has blacklist functionality. Thus USDC tokens can't be transferred to/from blacklisted address.

Currently harvested token rewards are transferred in a force manner to staker on any interaction: claim vested tokens, stake, unstake, revoke vesting. Additionally, in `unstakeGns()` all the rewards are processed. Therefore if any of token transfers reverts, user will be unable to harvest and therefore unstake.

While unstake it firstly proccesses rewards for all tokens:

```solidity
    function unstakeGns(uint128 _amountGns) external {
        require(_amountGns > 0, "AMOUNT_ZERO");

        harvestDai();
@>      harvestTokens();

        ... // Main unstake logic
    }
```

And then transfers harvested amount of every reward token, including USDC. As discussed above, USDC transfer can revert:

```solidity
    function _harvestToken(address _token, uint128 _stakedGns) private {
        ... // Main harvest logic

@>      IERC20(_token).transfer(msg.sender, uint256(pendingTokens));

        emit RewardHarvested(msg.sender, _token, pendingTokens);
    }
```

Thus user who got blacklisted by USDC can't harvest all token rewards and therefore unstake. His stake will exist forever, receiving portion of rewards which will never be claimed.

The same scenario is when user tries to claim vested amount.

*

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov Audit Group/2024-01-22-GainsNetwork.md)

---

### Example 10: [M-01] Zero amount token transfers may cause a denial of service during liquidations

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

### Example 11: Fee-on-transfer tokens are not supported

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

### Example 12: Use safe transfer for ERC20 tokens

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

### Example 13: Non-standard ERC20 tokens are not supported

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

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
47:             token.safeTransferFrom(msg.sender, address(this), amount);
48:             uint256 depositIndex = deposits.length;
49:             deposits.push(Deposit(payable(msg.sender), amount, tokenAddress));//@audit-issue fee-on-transfer, rebalancing tokens will cause problems
50:             emit DepositMade(msg.sender, depositIndex, amount, tokenAddress);
51:
52:         }
53:     }
```
Looking at the line L49, we can see that the protocol assumes `amount` of tokens were transferred.
But this does not hold true for some non-standard ERC20 tokens like fee-on-transfer tokens or rebalancing tokens.
(Refer to [here](https://github.com/d-

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 14: Seaport auctions not compatible with USDT

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Security Analysis Report

## Severity
**Medium Risk**

## Context
`CollateralToken.sol#L173`

## Description
As per the ERC20 specification, the `approve()` function is expected to return a boolean:

```solidity
function approve(address _spender, uint256 _value) public returns (bool success)
```

However, USDT deviates from this standard, and its `approve()` method does not have a return value. Hence, if USDT is used as a payment token, the following line reverts in `validateOrder()` as it expects return data but doesn't receive it:

```solidity
paymentToken.approve(address(transferProxy), s.LIEN_TOKEN.getOwed(stack));
```

## Recommendation
Use Solmate's `safeApprove()` function to accommodate USDT's `approve()`:

```solidity
paymentToken.safeApprove(address(transferProxy), s.LIEN_TOKEN.getOwed(stack));
```

## Additional Information
- **Astaria:** Fixed in PR339.
- **Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review-July.pdf)

---

### Example 15: [M-01] If the underlying asset is a fee on transfer token, it could break the internal accounting of the vault

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

The `Vault._deposit` function is used by the users to deposit `_assets` to the vault and mint vault shares to the `recipient` address. The amount of `_assets` are transferred to the `Vault` as follows:

      SafeERC20.safeTransferFrom(
        _asset,
        _caller,
        address(this),
        _assetsDeposit != 0 ? _assetsDeposit : _assets
      );

The `Vault.deposit` function uses this `_assets` amount to calculate the number of `shares` to be minted to the `_recipient` address.

The issue here is if the underlying `_asset` is a fee on transfer token then the actual received amount to the vault will be less than what is referred in the `Vault.deposit` function `_assets` input parameter. But the shares to mint is calculated using the entire `_assets` amount.

This issue could be further aggravated since the `_asset` is again `deposited` to the `_yieldVault` and when needing to be redeemed, will be `withdrawn` from the `_yieldVault` as well. These operations will again charge a fee if the `_asset` is a fee on transfer token. Hence, the actual `_asset` amount left for a particular user will be less than the amount they initially transferred in.

Hence, when the user `redeems` the minted shares back to the `_assets`, the contract will not have enough assets to transfer to the `redeemer`, thus reverting the transaction.

### Proof of Concept

```solidity
      SafeERC20.safeTransferFrom(
        _asset,
        _caller,
        address(this),
        _assetsDeposit != 0 ? 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-pooltogether)

---

### Example 16: Reentrancy risk in depositing to the queue

**Source**: OpenZeppelin
**Protocol**: Pods Finance Ethereum Volatility Vault Audit #1
**Impact**: HIGH

**Details**:

The internalÂ [`_deposit`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/BaseVault.sol#L407)Â function handles user deposits, transferring a specified amount ofÂ `stETH`Â fromÂ `msg.sender`Â to the vault. Before moving the funds, it adds the deposit to the queue, which is processed later by theÂ [`processQueuedDeposits`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/BaseVault.sol#L371)Â function.


As the underlying token could have hooks that allow the token sender to execute code before the transfer (e.g., ERC777 standard), a malicious user could use those hooks to re-enter theÂ `deposit`Â function multiple times.


This re-entrancy will result in an increment in the receiver balance on the queue, even though this balance will not correspond to the actual amount deposited into the vault.


In the current implementation, theÂ `_deposit`Â function in theÂ `BaseVault`Â contract is overridden by theÂ [implementation in theÂ `STETHVault`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/STETHVault.sol#L113-L126), which has the correct order of operation. However, theÂ `BaseVault`Â is likely to be inherited by future vaults, so it is crucial to have the correctÂ `_deposit`Â implementation in this contract in case it is not overridden.


Consider reordering the calls, doing the transfer first, and then adding th

*[Content truncated...]*

**Reference**: [View Original Finding](https://blog.openzeppelin.com/pods-finance-ethereum-volatility-vault-audit-1/)

---

### Example 17: M-2: Users might lose funds as `claimERC20Prize()` doesn't revert for no-revert-on-transfer tokens

**Source**: Sherlock
**Protocol**: Footium
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-footium-judging/issues/86 

## Found by 
0xAsen, 0xGoodess, 0xGusMcCrae, 0xPkhatri, 0xRobocop, 0xStalin, 0xeix, 0xmuxyz, 0xnirlin, 14si2o\_Flint, 8olidity, ACai7, AlexCzm, BAHOZ, Bauchibred, Bauer, Cryptor, DevABDee, Diana, GimelSec, J4de, Koolex, MiloTruck, PRAISE, PTolev, Phantasmagoria, Piyushshukla, PokemonAuditSimulator, Polaris\_tow, Proxy, Quantish, R-Nemes, SanketKogekar, Sulpiride, TheNaubit, Tricko, \_\_141345\_\_, abiih, alliums8520, ast3ros, berlin-101, cergyk, ctf\_sec, cuthalion0x, dacian, ddimitrov22, deadrxsezzz, djxploit, favelanky, georgits, holyhansss, innertia, jasonxiale, josephdara, jprod15, kiki\_dev, l3r0ux, lewisbroadhurst, nzm\_, oot2k, oualidpro, peanuts, ravikiran.web3, sach1r0, santipu\_, sashik\_eth, shaka, shame, thekmj, tibthecat, tsvetanovv, whoismatthewmc1, wzrdk3lly, yy
## Summary

Users can call `claimERC20Prize()` without actually receiving tokens if a no-revert-on-failure token is used, causing a portion of their claimable tokens to become unclaimable.

## Vulnerability Detail

In the `FootiumPrizeDistributor` contract, whitelisted users can call `claimERC20Prize()` to claim ERC20 tokens. The function adds the amount of tokens claimed to the user's total claim amount, and then transfers the tokens to the user:

[FootiumPrizeDistributor.sol#L128-L131](https://github.com/sherlock-audit/2023-04-footium/blob/main/footium-eth-shareable/contracts/FootiumPrizeDistributor.sol#L128-L131)

```solidi

*[Content truncated...]*

---

### Example 18: M-4: If the collateral is a fee-on-transfer token, repayment will be blocked

**Source**: Sherlock
**Protocol**: Teller
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-03-teller-judging/issues/91 

## Found by 
0x2e, 8olidity, BAHOZ, Bauer, Breeje, Delvir0, HexHackers, HonorLt, MiloTruck, Nyx, Vagner, \_\_141345\_\_, ak1, cccz, cducrest-brainbot, ck, ctf\_sec, dacian, deadrxsezzz, dingo, duc, evmboi32, giovannidisiena, innertia, monrel, n33k, nobody2018, saidam017, shaka, sinarette, spyrosonic10, tsvetanovv, tvdung94, whiteh4t9527, yixxas
## Summary

As we all know, some tokens will deduct fees when transferring token. In this way, **the actual amount of token received by the receiver will be less than the amount sent**. If the collateral is this type of token, the amount of collateral recorded in the contract will bigger than the actual amount. **When the borrower repays the loan, the amount of collateral withdrawn will be insufficient, causing tx revert**.

## Vulnerability Detail

The `_bidCollaterals` mapping of `CollateralManager` records the `CollateralInfo` of each bidId. This structure records the collateral information provided by the user when creating a bid for a loan. A lender can accept a loan by calling Â `TellerV2.lenderAcceptBid` that will eventually transfer the user's collateral from the user address to the CollateralEscrowV1 contract corresponding to the loan. The whole process will deduct fee twice.

```solidity
//CollateralManager.sol
function _deposit(uint256 _bidId, Collateral memory collateralInfo)
        internal
        virtual
    {
        ......
        // Pull coll

*[Content truncated...]*

---

### Example 19: [M-02] `_payoutToken[s]()` is not compatible with tokens with missing return value

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[PA1D.sol#L317](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/enforcer/PA1D.sol#L317)<br>
[PA1D.sol#L340](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/enforcer/PA1D.sol#L340)<br>

Payout is blocked and tokens are stuck in contract.

### Proof of Concept

`PA1D._payoutToken()` and `PA1D._payoutTokens()` call `ERC20.transfer()` in a require-statement to send tokens to a list of payout recipients.<br>
Some tokens do not return a bool (e.g. USDT, BNB, OMG) on ERC20 methods. But since the require-statement expects a `bool`, for such a token a `void` return will also cause a revert, despite an otherwise successful transfer. That is, the token payout will always revert for such tokens.

### Recommended Mitigation Steps

Use [OpenZeppelin's SafeERC20](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol), which handles the return value check as well as non-standard-compliant tokens.

**[alexanderattar (Holograph) commented](https://github.com/code-423n4/2022-10-holograph-findings/issues/456#issuecomment-1306632476):**
 > Low priority, but can be updated to ensure compatibility with all ERC20 tokens.

**[alexanderattar (Holograph) linked a PR](https://github.com/code-423n4/2022-10-holograph-findings/issues/456#issuecomment-1306632476):**
 > [Feature/holo 612 royalty smart contract improvements](https://github.com/holographxyz/

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 20: M-3: Incompatability with deflationary / fee-on-transfer tokens

**Source**: Sherlock
**Protocol**: Harpie
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-harpie-judging/tree/main/005-M 

## Found by 
Lambda, cccz, hansfriese, IEatBabyCarrots, rbserver, JohnSmith, minhquanym, Tomo, leastwood, dipp, defsec, HonorLt, IllIllI, saian, csanuragjain

## Summary

https://github.com/Harpieio/contracts/blob/97083d7ce8ae9d85e29a139b1e981464ff92b89e/contracts/Transfer.sol#L93-L100

In case ERC20 token is fee-on-transfer, Vault can loss funds when users withdraw

## Vulnerability Detail

In `Transfer.transferERC20()` function, this function called `logIncomingERC20()` with the exact amount used when it called `safeTransferFrom()`. In case ERC20 token is fee-on-transfer, the actual amount that Vault received may be less than the amount is recorded in `logIncomingERC20()`. 

The result is when a user withdraws his funds from `Vault`, Vault can be lost and it may make unable for later users to withdraw their funds.

## Proof of Concept

Consider the scenario
1. Token X is fee-on-transfer and it took 10% for each transfer. Alice has 1000 token X and Bob has 2000 token X
2. Assume that both Alice and Bob are attacked. Harpie transfers all token of Alice and Bob to Vault. It recorded that the amount stored for token X of Alice is 1000 and Bob is 2000. But since token X has 10% fee, Vault only receives 2700 token X.
3. Now Bob withdraw his funds back. With `amountStored = 2000`, he will transfer 2000 token X out of the Vault and received 1800. 
4. Now the Vault only has 700 token X left and obviou

*[Content truncated...]*

---

### Example 21: M-2: Unsafe ERC20 methods

**Source**: Sherlock
**Protocol**: Telcoin
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-telcoin-judging/issues/82 

## Found by 
0x4non, 0xAgro, yixxas, 0xheynacho, Bnke0x0, WATCHPUG, aphak5010, rotcivegaf, Mukund, hickuphh3, pashov, hyh, Deivitto, rvierdiiev, eierina

## Summary

Using unsafe ERC20 methods can revert the transaction for certain tokens.

## Vulnerability Detail

There are many [Weird ERC20 Tokens](https://www.hacknote.co/17c261f7d8fWbdml/doc/182a568ab5cUOpDM) that won't work correctly using the standard `IERC20` interface.

For example, `IERC20(token).transferFrom()` and `IERC20(token).transfer()` will fail for some tokens as they may not conform to the standard IERC20 interface. And if `_aggregator` does not always consume all the allowance given at L72, the transaction will also revert on the next call, because there are certain tokens that do not allow approval of a non-zero number when the current allowance is not zero (eg, USDT).

## Impact

The contract will malfunction for certain tokens.

## Code Snippet

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/fee-buyback/FeeBuyback.sol#L94-L97

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/fee-buyback/FeeBuyback.sol#L47-L82

## Tool used

Manual Review

## Recommendation

Consider using `SafeERC20` for `transferFrom`, `transfer` and `approve`.

## Discussion

**amshirif**

https://github.com/telcoin/telcoin-staking/pull/6

---

### Example 22: [M-07] Liquidation failure for traders on USDC blacklist

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

### Example 23: [M-14] Fee on transfer token not supported

**Source**: Code4rena
**Protocol**: Popcorn
**Impact**: MEDIUM

**Details**:

If you are making a Lock fund for escrow using a fee on transfer token then contract will receive less amount (X-fees) but will record full amount (X). This becomes a problem as when claim is made then call will fail due to lack of funds. Worse, one user will unknowingly take the missing fees part from another user deposited escrow fund.

### Proof of Concept

1.  User locks token X as escrow which takes fee on transfer
2.  For same, he uses `lock` function which transfers funds from user to contract

<!---->

     function lock(
        IERC20 token,
        address account,
        uint256 amount,
        uint32 duration,
        uint32 offset
      ) external {
    ...
     token.safeTransferFrom(msg.sender, address(this), amount);
    ...
    escrows[id] = Escrow({
          token: token,
          start: start,
          end: start + duration,
          lastUpdateTime: start,
          initialBalance: amount,
          balance: amount,
          account: account
        });
    ...
    }

3.  Since token has fee on transfer, the contract receives only `amount-fees` but the escrow object is created for full `amount`

4.  Lets say escrow duration is over and claim is made using `claimRewards` function

<!---->

    function claimRewards(bytes32[] memory escrowIds) external {
    ...
     uint256 claimable = _getClaimableAmount(escrow);
    ...    
     escrow.token.safeTransfer(escrow.account, claimable);
    ...
    }

5.  Since full duration is over, the claimable amount

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-popcorn)

---

### Example 24: Non-existent permit function

**Source**: OpenZeppelin
**Protocol**: Pods Finance Ethereum Volatility Vault Audit #1
**Impact**: MEDIUM

**Details**:

The vault implements aÂ [`mintWithPermit`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/BaseVault.sol#L131)Â andÂ [`depositWithPermit`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/BaseVault.sol#L106)Â function intended to allow users to transfer assets to the vault in a single transaction. However, the vaultâ€™s underlying asset is intended to beÂ [stETH](https://etherscan.io/address/0x47ebab13b806773ec2a2d16873e2df770d130b50#code#F10#L50)Â which does not have aÂ `permit`Â function. Currently, any user who tries to perform aÂ `mintWithPermit`Â orÂ `depositWithPermit`Â will have their transaction reverted due to the stETH contractâ€™sÂ [fallback](https://etherscan.io/address/0x47ebab13b806773ec2a2d16873e2df770d130b50#code#F1#L279)Â function.


Consider removing theÂ `mintWithPermit`Â andÂ `depositWithPermit`Â functions. We note thatÂ [wstETH](https://etherscan.io/token/0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0#code#L965)Â does have a permit function for future considerations.


***Update:**Â Acknowledged, and will not fix. Pods Finance teamâ€™s statement for this issue:*



> *We decided not to fix this issue because we may implement assets similar to LIDO as the yield source where they may have permit functionality (aTokens, for instance).*
> 
>

**Reference**: [View Original Finding](https://blog.openzeppelin.com/pods-finance-ethereum-volatility-vault-audit-1/)

---

### Example 25: [M-08] Vault is Not Compatible with Fee Tokens and Vaults with Such Tokens Could Be Exploited

**Source**: Code4rena
**Protocol**: Cally
**Impact**: MEDIUM

**Details**:

_Submitted by 0x1337, also found by 0x52, 0xDjango, 0xsanson, berndartmueller, BondiPestControl, BowTiedWardens, cccz, dipp, GimelSec, hake, hickuphh3, horsefacts, hubble, IllIllI, MaratCerby, MiloTruck, minhquanym, PPrieditis, reassor, shenwilly, smiling_heretic, TrungOre, VAD37, and WatchPug_

<https://github.com/code-423n4/2022-05-cally/blob/1849f9ee12434038aa80753266ce6a2f2b082c59/contracts/src/Cally.sol#L198-L200>

<https://github.com/code-423n4/2022-05-cally/blob/1849f9ee12434038aa80753266ce6a2f2b082c59/contracts/src/Cally.sol#L294-L296>

<https://github.com/code-423n4/2022-05-cally/blob/1849f9ee12434038aa80753266ce6a2f2b082c59/contracts/src/Cally.sol#L343-L345>

### Impact

Some ERC20 tokens charge a transaction fee for every transfer (used to encourage staking, add to liquidity pool, pay a fee to contract owner, etc.). If any such token is used in the `createVault()` function, either the token cannot be withdrawn from the contract (due to insufficient token balance), or it could be exploited by other such token holders and the `Cally` contract would lose economic value and some users would be unable to withdraw the underlying asset.

### Proof of Concept

Plenty of ERC20 tokens charge a fee for every transfer (e.g. Safemoon and its forks), in which the amount of token received is less than the amount being sent. When a fee token is used as the `token` in the `createVault()` function, the amount received by the contract would be less than the amount being sent. To be m

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-cally)

---

## Statistics

- Total findings analyzed: 26
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## usdc-patterns.md
# USDC Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 5 | 0 | 0 |

**Common Sources**: Sherlock, Codehawks

---

## Detection Checklist

- [ ] Check for usdc vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-2: Netting and withdraw auction can be frozen permanently

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

### Example 2: M-6: If the recipient is added to the USDC blacklist, then cancel() does not work

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

### Example 3: Blacklisted STADIUM_ADDRESS address cause fund stuck in the contract forever

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

### Example 4: M-3: WithdrawPeriphery#_convertToToken slippage control is broken for any token other than USDC

**Source**: Sherlock
**Protocol**: Rage Trade
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-rage-trade-judging/issues/55 

## Found by 
0x52

## Summary

WithdrawPeriphery allows the user to redeem junior share vaults to any token available on GMX, applying a fixed slippage threshold to all redeems. The slippage calculation always returns the number of tokens to 6 decimals. This works fine for USDC but for other tokens like WETH or WBTC that are 18 decimals the slippage protection is completely ineffective and can lead to loss of funds for users that are withdrawing.

## Vulnerability Detail

    function _convertToToken(address token, address receiver) internal returns (uint256 amountOut) {
        // this value should be whatever glp is received by calling withdraw/redeem to junior vault
        uint256 outputGlp = fsGlp.balanceOf(address(this));

        // using min price of glp because giving in glp
        uint256 glpPrice = _getGlpPrice(false);

        // using max price of token because taking token out of gmx
        uint256 tokenPrice = gmxVault.getMaxPrice(token);

        // apply slippage threshold on top of estimated output amount
        uint256 minTokenOut = outputGlp.mulDiv(glpPrice * (MAX_BPS - slippageThreshold), tokenPrice * MAX_BPS);

        // will revert if atleast minTokenOut is not received
        amountOut = rewardRouter.unstakeAndRedeemGlp(address(token), outputGlp, minTokenOut, receiver);
    }

WithdrawPeriphery allows the user to redeem junior share vaults to any token available on GM

*[Content truncated...]*

---

### Example 5: M-4: Blacklisted creditor can block all repayment besides emergency closure

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

### Example 6: M-4: Protocol won't work with `USDC` even though it is a token specifically mentioned in the docs

**Source**: Sherlock
**Protocol**: Float Capital
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-float-capital-judging/issues/21 

## Found by 
pashov, ctf\_sec, 0x52

## Summary
The protocol has requirements for values (for example 1e18) that would be too big if used with a 6 decimals token like `USDC` - `USDC` is mentioned as a token that will be used in the docs
## Vulnerability Detail
For the mint functionality, a user has to transfer at least 1e18 tokens so that he can mint pool tokens - `if (amount < 1e18) revert InvalidActionAmount(amount);`. If the `paymentToken` used was `USDC` (as pointed out in docs), this would mean he would have to contribute at least 1e12 USDC tokens (more than a billion) which would be pretty much impossible to do. There is also another such check in `MarketExtended::addPoolToExistingMarket` with `require(initialActualLiquidityForNewPool >= 1e12, "Insufficient market seed");` - both need huge amounts when using a low decimals token like USDC that has 6 decimals.

## Impact
The protocol just wouldn't work at all in its current state when using a lower decimals token. Since such a token was mentioned in the docs I set this as a High severity issue.

## Code Snippet
https://github.com/sherlock-audit/2022-11-float-capital/blob/main/contracts/market/template/MarketExtended.sol#L125
https://github.com/sherlock-audit/2022-11-float-capital/blob/main/contracts/market/template/MarketCore.sol#L265
## Tool used

Manual Review

## Recommendation
Drastically lower  the `require` checks so they can work w

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## usdt-patterns.md
# USDT Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 5 | 0 | 0 |

**Common Sources**: Spearbit, Sherlock

---

## Detection Checklist

- [ ] Check for usdt vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Decrease allowance when it is already set a non-zero value

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Analysis Report

## Severity
**High Risk**

## Context
- AxelarFacet.sol#L71
- LibAsset.sol#L52
- FusePoolZap.sol#L64
- Executor.sol#L312

## Description
Non-standard tokens like USDT will revert the transaction when a contract or a user tries to approve an allowance when the spender allowance is already set to a non-zero value. For that reason, the previous allowance should be decreased before increasing the allowance in the related function.

- Performing a direct overwrite of the value in the allowances mapping is susceptible to front-running scenarios by an attacker (e.g., an approved spender). As OpenZeppelin mentioned, `safeApprove` should only be called when setting an initial allowance or when resetting it to zero.

### Function
```solidity
function safeApprove(
    IERC20 token,
    address spender,
    uint256 value
) internal {
    // safeApprove should only be called when setting an initial allowance,
    // or when resetting it to zero. To increase and decrease it, use
    // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'.
    require(
        (value == 0) || (token.allowance(address(this), spender) == 0),
        "SafeERC20: approve from non-zero to non-zero allowance"
    );
    _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
}
```

### Instances of the Issue
There are four instances of this issue:

1. **AxelarFacet.sol** is directly using the `approve` function, which does not check the return value 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 2: safeApprove indepositToken could revert for non-standard token like USDT

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: MEDIUM

**Details**:

## Security Analysis

## Severity
**Medium Risk**

## Context
AeraVaultV1.sol#L893

## Description
Some non-standard tokens like USDT will revert when a contract or a user tries to approve an allowance when the spender allowance has already been set to a non-zero value. In the current code, we have not seen any real problem with this fact because the amount retrieved via `depositToken()` is approved and sent to the Balancer pool via `joinPool()` and `managePoolBalance()`. Balancer transfers the same amount, lowering the approval to 0 again. 

However, if the approval is not lowered to exactly 0 (due to a rounding error or another unforeseen situation), then the next approval in `depositToken()` will fail (assuming a token like USDT is used), blocking all further deposits.

**Note:** Set to medium risk because the probability of this happening is low, but the impact would be high. We also should note that OpenZeppelin has officially deprecated the `safeApprove` function, suggesting to use instead `safeIncreaseAllowance` and `safeDecreaseAllowance`.

## Recommendation
Adopt a safer approach to cover edge cases such as the abovementioned USDT token and implement the following solution:

```solidity
function depositToken(IERC20 token, uint256 amount) internal {
    token.safeTransferFrom(owner(), address(this), amount);
    // - token.safeApprove(address(bVault), amount);
    uint256 allowance = token.allowance(address(this), address(bVault));
    if (allowance > 0) {
        tok

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 3: Not always safeApprove(..., 0)

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- **NomadFacet.sol**: Lines 176-242
- **AssetLogic.sol**: Lines 308-362, 263-295
- **PortalFacet.sol**: Lines 179-197
- **Executor.sol**: Lines 142-339

## Description
Some functions like `_reconcileProcessPortal` of `BaseConnextFacet` and `_swapAssetOut` of `AssetLogic` do `safeApprove(..., 0)` first.

```solidity
contract NomadFacet is BaseConnextFacet {
    function _reconcileProcessPortal(...) {
        ...
        // Edge case with some tokens: Example USDT in ETH Mainnet, after the backUnbacked call there
        // could be a remaining allowance if not the whole amount is pulled by aave.
        // Later, if we try to increase the allowance it will fail. USDT demands if allowance is not 0,
        // it has to be set to 0 first.
        
        // Example:
        [ParaSwapRepayAdapter.sol#L138-L140](https://github.com/aave/aave-v3-periphery/blob/ca184e5278bcbc10d28c3dbbc604041d7cfac50b/contracts/adapters/paraswap/ParaSwapRepayAdapter.sol#L138-L140)
        
        safeApprove(IERC20(adopted), s.aavePool, 0);
        safeIncreaseAllowance(IERC20(adopted), s.aavePool, totalRepayAmount);
        ...
    }
}
```

While the following functions donâ€™t do this:
- `xcall` of `BridgeFacet`
- `_backLoan` of `PortalFacet`
- `_swapAsset` of `AssetLogic`
- `execute` of `Executor`

This could result in problems with tokens like USDT.

```solidity
contract BridgeFacet is BaseConnextFacet {
    function xcall(XCallArgs calldata _args) external pa

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 4: M-17: Did Not Approve To Zero First

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/59 

## Found by 
xiaoming90, 0x52, csanuragjain

## Summary

Allowance was not set to zero first before changing the allowance.

## Vulnerability Detail

Some ERC20 tokens (like USDT) do not work when changing the allowance from an existing non-zero allowance value. For example Tether (USDT)'s `approve()` function will revert if the current approval is not zero, to protect against front-running changes of approvals.

The following  attempt to call the `approve()` function without setting the allowance to zero first.

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/utils/TokenUtils.sol#L18

```solidity
File: TokenUtils.sol
18:     function checkApprove(IERC20 token, address spender, uint256 amount) internal {
19:         if (address(token) == address(0)) return;
20: 
21:         IEIP20NonStandard(address(token)).approve(spender, amount);
22:         _checkReturnCode();
23:     }
```

However, if the token involved is an ERC20 token that does not work when changing the allowance from an existing non-zero allowance value, it will break a number of key functions or features of the protocol as the `TokenUtils.checkApprove` function is utilised extensively within the vault as shown below.

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/internal/pool/TwoTokenPoolUtils.sol#L159

```solidity
File: TwoTokenPoolUtils.

*[Content truncated...]*

---

### Example 5: Seaport auctions not compatible with USDT

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Security Analysis Report

## Severity
**Medium Risk**

## Context
`CollateralToken.sol#L173`

## Description
As per the ERC20 specification, the `approve()` function is expected to return a boolean:

```solidity
function approve(address _spender, uint256 _value) public returns (bool success)
```

However, USDT deviates from this standard, and its `approve()` method does not have a return value. Hence, if USDT is used as a payment token, the following line reverts in `validateOrder()` as it expects return data but doesn't receive it:

```solidity
paymentToken.approve(address(transferProxy), s.LIEN_TOKEN.getOwed(stack));
```

## Recommendation
Use Solmate's `safeApprove()` function to accommodate USDT's `approve()`:

```solidity
paymentToken.safeApprove(address(transferProxy), s.LIEN_TOKEN.getOwed(stack));
```

## Additional Information
- **Astaria:** Fixed in PR339.
- **Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review-July.pdf)

---

### Example 6: M-4: Blacklisted creditor can block all repayment besides emergency closure

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

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## approve-patterns.md
# Approve Security Patterns

## Overview

**Frequency**: 18 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 9 | 9 | 0 | 0 |

**Common Sources**: Code4rena, Spearbit, Sherlock, Codehawks

---

## Detection Checklist

- [ ] Check for approve vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Decrease allowance when it is already set a non-zero value

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Analysis Report

## Severity
**High Risk**

## Context
- AxelarFacet.sol#L71
- LibAsset.sol#L52
- FusePoolZap.sol#L64
- Executor.sol#L312

## Description
Non-standard tokens like USDT will revert the transaction when a contract or a user tries to approve an allowance when the spender allowance is already set to a non-zero value. For that reason, the previous allowance should be decreased before increasing the allowance in the related function.

- Performing a direct overwrite of the value in the allowances mapping is susceptible to front-running scenarios by an attacker (e.g., an approved spender). As OpenZeppelin mentioned, `safeApprove` should only be called when setting an initial allowance or when resetting it to zero.

### Function
```solidity
function safeApprove(
    IERC20 token,
    address spender,
    uint256 value
) internal {
    // safeApprove should only be called when setting an initial allowance,
    // or when resetting it to zero. To increase and decrease it, use
    // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'.
    require(
        (value == 0) || (token.allowance(address(this), spender) == 0),
        "SafeERC20: approve from non-zero to non-zero allowance"
    );
    _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
}
```

### Instances of the Issue
There are four instances of this issue:

1. **AxelarFacet.sol** is directly using the `approve` function, which does not check the return value 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 2: [H-04] Approvals not cleared after key transfer

**Source**: Code4rena
**Protocol**: Unlock Protocol
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

The locks implement three different approval types, see `onlyKeyManagerOrApproved` for an overview:

*   key manager (map `keyManagerOf`)
*   single-person approvals (map `approved`). Cleared by `_clearApproval` or `_setKeyManagerOf`
*   operator approvals (map `managerToOperatorApproved`)

The `MixinTransfer.transferFrom` requires any of the three approval types in the `onlyKeyManagerOrApproved` modifier on the tokenId to authenticate transfers from `from`.

Notice that if the `to` address previously had a key but it expired only the `_setKeyManagerOf` call is performed, which does not clear `approved` if the key manager was already set to 0:

```solidity
function transferFrom(
  address _from,
  address _recipient,
  uint _tokenId
)
  public
  onlyIfAlive
  hasValidKey(_from)
  onlyKeyManagerOrApproved(_tokenId)
{
  // @audit this is skipped if user had a key that expired
  if (toKey.tokenId == 0) {
    toKey.tokenId = _tokenId;
    _recordOwner(_recipient, _tokenId);
    // Clear any previous approvals
    _clearApproval(_tokenId);
  }

  if (previousExpiration <= block.timestamp) {
    // The recipient did not have a key, or had a key but it expired. The new expiration is the sender's key expiration
    // An expired key is no longer a valid key, so the new tokenID is the sender's tokenID
    toKey.expirationTimestamp = fromKey.expirationTimestamp;
    toKey.tokenId = _tokenId;

    // Reset the key Manager to the key owner
    // @audit  doesn't c

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-unlock)

---

### Example 3: [H-02] Approved spender can spend too many tokens

**Source**: Code4rena
**Protocol**: BadgerDAO
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by WatchPug, jonah1005, gzeon, and TomFrench_
The `approve` function has not been overridden and therefore uses the internal *shares*, whereas `transfer(From)` uses the rebalanced amount.

#### Impact
The approved spender may spend more tokens than desired. In fact, the approved amount that can be transferred keeps growing with `pricePerShare`.

Many contracts also use the same amount for the `approve` call as for the amount they want to have transferred in a subsequent `transferFrom` call, and in this case, they approve an amount that is too large (as the approved `shares` amount yields a higher rebalanced amount).

#### Recommended Mitigation Steps

The `_allowances` field should track the rebalanced amounts such that the approval value does not grow. (This does not actually require overriding the `approve` function.)
In `transferFrom`, the approvals should then be subtracted by the *transferred* `amount`, not the `amountInShares`:

```solidity
// _allowances are in rebalanced amounts such that they don't grow
// need to subtract the transferred amount
_approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "ERC20: transfer amount exceeds allowance"));
```

**[tabshaikh (Badger) confirmed and resolved](https://github.com/code-423n4/2021-10-badgerdao-findings/issues/43#issuecomment-957197908):**
 > Fix here: https://github.com/Badger-Finance/rebasing-ibbtc/pull/7

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-10-badgerdao)

---

### Example 4: H-1: If a user approves junior vault tokens to WithdrawPeriphery, anyone can withdraw/redeem his/her token

**Source**: Sherlock
**Protocol**: Rage Trade
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-rage-trade-judging/issues/79 

## Found by 
simon135, cccz, Nyx, GimelSec, clems4ever

## Summary

If users want to withdraw/redeem tokens by WithdrawPeriphery, they should approve token approval to WithdrawPeriphery, then call `withdrawToken()` or `redeemToken()`.
But if users approve `dnGmxJuniorVault` to WithdrawPeriphery, anyone can withdraw/redeem his/her token.

## Vulnerability Detail

Users should approve `dnGmxJuniorVault` before calling `withdrawToken()` or `redeemToken()`:

```solidity
    function withdrawToken(
        address from,
        address token,
        address receiver,
        uint256 sGlpAmount
    ) external returns (uint256 amountOut) {
        // user has approved periphery to use junior vault shares
        dnGmxJuniorVault.withdraw(sGlpAmount, address(this), from);
...

    function redeemToken(
        address from,
        address token,
        address receiver,
        uint256 sharesAmount
    ) external returns (uint256 amountOut) {
        // user has approved periphery to use junior vault shares
        dnGmxJuniorVault.redeem(sharesAmount, address(this), from);
...
```

For better user experience, we always use `approve(WithdrawPeriphery, type(uint256).max)`. It means that if Alice approves the max amount, anyone can withdraw/redeem her tokens anytime.
Another scenario is that if Alice approves 30 amounts, she wants to call `withdrawToken` to withdraw 30 tokens. But in this case Alice sho

*[Content truncated...]*

---

### Example 5: A user can steal an already transfered and bridged reSDL lock because of approval

**Source**: Codehawks
**Protocol**: stake.link
**Impact**: HIGH

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolPrimary.sol#L172-L199">https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolPrimary.sol#L172-L199</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolSecondary.sol#L259-L281">https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolSecondary.sol#L259-L281</a>


## Summary
The reSDL token approval is not deleted when the lock is bridged to an other chain

## Vulnerability Details
When a reSDL token is bridged to an other chain, the `handleOutgoingRESDL()` function is called to make the state changes into the `sdlPool` contract. The function executes the following:

```
    function handleOutgoingRESDL(
        address _sender,
        uint256 _lockId,
        address _sdlReceiver
    )
        external
        onlyCCIPController
        onlyLockOwner(_lockId, _sender)
        updateRewards(_sender)
        updateRewards(ccipController)
        returns (Lock memory)
    {
        Lock memory lock = locks[_lockId];

        delete locks[_lockId].amount;
        delete lockOwners[_lockId];
        balances[_sender] -= 1;

        uint256 totalAmount = lock.amount + lock.boostAmount;
        effectiveBalances[_sender] -= totalAmount;
        effectiveBalances[ccipController] += totalAmount;


*[Content truncated...]*

---

### Example 6: H-11: Sense PTs can never be redeemed

**Source**: Sherlock
**Protocol**: Illuminate
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-illuminate-judging/issues/117 

## Found by 
IllIllI, neumo, Ruhum, 0x52

## Summary

Sense PTs can never be redeemed


## Vulnerability Detail

Most of the protocols that require the user of the `Converter` contract have code that approves the `Converter` for that protocol, but there is no such approval for Sense.


## Impact

_Permanent freezing of funds_

Users will be able to lend and mint using Sense, but when it's time for Illuminate to redeem the Sense PTs, the call will always revert, meaning the associated underlying will be locked in the contract, and users that try to redeem their Illuminate PTs will have lost principal.

While the Illuminate project does have an emergency `withdraw()` function that would allow an admin to rescue the funds and manually distribute them, this would not be trustless and defeats the purpose of having a smart contract.


## Code Snippet
The Sense flavor of `redeem()` requires the use of the `Converter`:
```solidity
// File: src/Redeemer.sol : Redeemer.redeem()   #1

366            // Get the starting balance to verify the amount received afterwards
367            uint256 starting = IERC20(u).balanceOf(address(this));
368    
369            // Get the divider from the adapter
370            ISenseDivider divider = ISenseDivider(ISenseAdapter(a).divider());
371    
372            // Redeem the tokens from the Sense contract
373            ISenseDivider(divider).redeem(a, s, amount);
374   

*[Content truncated...]*

---

### Example 7: Receiver doesn't always reset allowance

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
Receiver.sol#L224-L297

## Description
The function `_swapAndCompleteBridgeTokens()` of Receiver resets the approval to the executor at the end of an ERC20 transfer. However, if there is insufficient gas, the approval is not reset. This allows the executor to access any tokens (of the same type) left in the Receiver.

```solidity
function _swapAndCompleteBridgeTokens(...) {
    ...
    if (LibAsset.isNativeAsset(assetId)) {
        ...
    } else { // case 2: ERC20 asset
        ...
        token.safeIncreaseAllowance(address(executor), amount);
        if (reserveRecoverGas && gasleft() < _recoverGas) {
            token.safeTransfer(receiver, amount);
            ...
            return; // no safeApprove 0
        }
        try executor.swapAndCompleteBridgeTokens{...} {
            ...
        }
        token.safeApprove(address(executor), 0);
    }
}
```

## Recommendation
Only increase the allowance if sufficient gas is available, for example in the following way:

```solidity
function _swapAndCompleteBridgeTokens(...) {
    ...
    if (LibAsset.isNativeAsset(assetId)) {
        ...
    } else { // case 2: ERC20 asset
        ...
        - token.safeIncreaseAllowance(address(executor), amount);
        if (reserveRecoverGas && gasleft() < _recoverGas) {
            token.safeTransfer(receiver, amount);
            ...
            return;
        }
        + token.safeIncreaseAllowance(address(executor), amount);
 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-retainer1-Spearbit-Security-Review.pdf)

---

### Example 8: Multiple ERC4626Router and ERC4626RouterBase functions will always revert

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- `ERC4626Router.sol#L49-58`
- `ERC4626RouterBase.sol#L47`
- `ERC4626RouterBase.sol#L60`

## Description
The intention of the `ERC4626Router.sol` functions is that they are approval-less ways to deposit and redeem:

> For the below, no approval needed, assumes vault is already max approved.

As long as the user has approved the `TRANSFER_PROXY` for WETH, this works for the `depositToVault` function:
- WETH is transferred from the user to the router with `pullTokens`.
- The router approves the vault for the correct amount of WETH.
- `vault.deposit()` is called, which uses `safeTransferFrom` to transfer WETH from the router into the vault.

However, for the `redeemMax` function, it doesn't work:
- Approves the vault to spend the router's WETH.
- `vault.redeem()` is called, which tries to transfer vault tokens from the router to the vault, and then mints withdraw proxy tokens to the receiver.

This error occurs assuming that the vault tokens would be burned, in which case the logic would work. But since they are transferred into the vault until the end of the epoch, we require approvals.

The same issue also exists in these two functions in `ERC4626RouterBase.sol`:
- `redeem()`: this is where the incorrect approval lives, so the same issue occurs when it is called directly.
- `withdraw()`: the same faulty approval exists in this function.

## Recommendation
`redeemMax` should follow the same flow as `deposit` to make this work:
- `redeemMax` 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 9: Facets approve arbitrary addresses for ERC20 tokens

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
Across the following files and lines:
- `AcrossFacet.sol#L103`
- `AmarokFacet.sol#L145`
- `AnyswapFacet.sol#L127`
- `ArbitrumBridge-Facet.sol#L111`
- `CBridgeFacet.sol#L103`
- `GenericBridgeFacet.sol#L111`
- `GnosisBridgeFacet.sol#L119`
- `HopFacet.sol#L106`
- `HyphenFacet.sol#L101`
- `NXTPFacet.sol#L127`
- `OmniBridgeFacet.sol#L88`
- `OptimismBridge-Facet.sol#L100`
- `PolygonBridgeFacet.sol#L101`
- `StargateFacet.sol#L229`
- `WormholeFacet.sol#L94`

## Description
All the facets pointed above approve an address for an ERC20 token, where both these values are provided by the user:

```solidity
LibAsset.maxApproveERC20(IERC20(token), router, amount);
```

The parameter names change depending on the context. So for any ERC20 token that the `LifiDiamond` contract holds, the user can:
- Call any of the functions in these facets to approve another address for that token.
- Use the approved address to transfer tokens out of the `LifiDiamond` contract.

**Note:** Normally, there shouldnâ€™t be any tokens in the `LiFi Diamond` contract, so the risk is limited. Also, see "Hardcode bridge addresses via immutable."

## Recommendation
For each bridge facet, the bridge approval contract address is already known. Store these addresses in an immutable or a storage variable instead of taking them as user input. Only approve and interact with these pre-defined addresses.

## LiFi
Fixed with PR #79, PR #102, PR #103

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 10: [M-19] `HolographERC721.approve` not EIP-721 compliant

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[HolographERC721.sol#L272](https://github.com/code-423n4/2022-10-holograph/blob/24bc4d8dfeb6e4328d2c6291d20553b1d3eff00b/src/enforcer/HolographERC721.sol#L272)<br>

According to EIP-721, we have for `approve`:

```solidity
///  Throws unless `msg.sender` is the current NFT owner, or an authorized
///  operator of the current owner.
```

An operator in the context of EIP-721 is someone who was approved via `setApprovalForAll`:

```solidity
/// @notice Enable or disable approval for a third party ("operator") to manage
///  all of `msg.sender`'s assets
/// @dev Emits the ApprovalForAll event. The contract MUST allow
///  multiple operators per owner.
/// @param _operator Address to add to the set of authorized operators
/// @param _approved True if the operator is approved, false to revoke approval
function setApprovalForAll(address _operator, bool _approved) external;
```

Besides operators, there are also approved addresses for a token (for which `approve` is used). However, approved addresses can only transfer the token, see for instance the `safeTransferFrom` description:

```solidity
/// @dev Throws unless `msg.sender` is the current owner, an authorized
///  operator, or the approved address for this NFT.
```

`HolographERC721` does not distinguish between authorized operators and approved addresses when it comes to the `approve` function. Because `_isApproved(msg.sender, tokenId)` is used there, an approved address can approve another address, which is a violation of the

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 11: [H-03] Approval for NFT transfers is not removed after transfer

**Source**: Code4rena
**Protocol**: Visor
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by gpersoon, and pauliax_

The `Visor.transferERC721` does not reset the approval for the NFT.

An approved delegatee can move the NFT out of the contract once.
It could be moved to a market and bought by someone else who then deposits it again to the same vault.
The first delegatee can steal the NFT and move it out of the contract a second time.

Recommend resetting the approval on transfer.

**[xyz-ctrl (Visor) confirmed](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/48#issuecomment-856953219):**
> We will be mitigating this issue for our next release and before these experimental features are introduced in platform.
> PR pending

**[ztcrypto (Visor) commented](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/48#issuecomment-889192312):**
> duplicate of above ones and fixed

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-05-visorfinance)

---

### Example 12: M-17: Did Not Approve To Zero First

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/59 

## Found by 
xiaoming90, 0x52, csanuragjain

## Summary

Allowance was not set to zero first before changing the allowance.

## Vulnerability Detail

Some ERC20 tokens (like USDT) do not work when changing the allowance from an existing non-zero allowance value. For example Tether (USDT)'s `approve()` function will revert if the current approval is not zero, to protect against front-running changes of approvals.

The following  attempt to call the `approve()` function without setting the allowance to zero first.

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/utils/TokenUtils.sol#L18

```solidity
File: TokenUtils.sol
18:     function checkApprove(IERC20 token, address spender, uint256 amount) internal {
19:         if (address(token) == address(0)) return;
20: 
21:         IEIP20NonStandard(address(token)).approve(spender, amount);
22:         _checkReturnCode();
23:     }
```

However, if the token involved is an ERC20 token that does not work when changing the allowance from an existing non-zero allowance value, it will break a number of key functions or features of the protocol as the `TokenUtils.checkApprove` function is utilised extensively within the vault as shown below.

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/internal/pool/TwoTokenPoolUtils.sol#L159

```solidity
File: TwoTokenPoolUtils.

*[Content truncated...]*

---

### Example 13: [M-01] ``FULL_RESTRICTED`` Stakers can bypass restriction through approvals

**Source**: Code4rena
**Protocol**: Ethena Labs
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-10-ethena/blob/ee67d9b542642c9757a6b826c82d0cae60256509/contracts/StakedUSDe.sol#L225-L238><br>
<https://github.com/code-423n4/2023-10-ethena/blob/ee67d9b542642c9757a6b826c82d0cae60256509/contracts/StakedUSDe.sol#L245-L248>

The `StakedUSDe` contract implements a method to `SOFTLY` or `FULLY` restrict user address, and either transfer to another user or burn.

However there is an underlying issue. A fully restricted address is supposed to be unable to withdraw/redeem, however this issue can be walked around via the approve mechanism.

The openzeppelin `ERC4626` contract allows approved address to withdraw and redeem on behalf of another address so far there is an approval.

```solidity
    function redeem(uint256 shares, address receiver, address owner) public virtual override returns (uint256) 
```

Blacklisted Users can explore this loophole to redeem their funds fully. This is because in the overridden `_withdraw` function, the token owner is not checked for restriction.

```solidity
  function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
  {
    if (hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)) {
      revert OperationNotAllowed();
    }
```

Also in the overridden `_beforeTokenTransfer` there is a clause added to allow burning from restricted addresses:

```s

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-10-ethena)

---

### Example 14: Seaport auctions not compatible with USDT

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Security Analysis Report

## Severity
**Medium Risk**

## Context
`CollateralToken.sol#L173`

## Description
As per the ERC20 specification, the `approve()` function is expected to return a boolean:

```solidity
function approve(address _spender, uint256 _value) public returns (bool success)
```

However, USDT deviates from this standard, and its `approve()` method does not have a return value. Hence, if USDT is used as a payment token, the following line reverts in `validateOrder()` as it expects return data but doesn't receive it:

```solidity
paymentToken.approve(address(transferProxy), s.LIEN_TOKEN.getOwed(stack));
```

## Recommendation
Use Solmate's `safeApprove()` function to accommodate USDT's `approve()`:

```solidity
paymentToken.safeApprove(address(transferProxy), s.LIEN_TOKEN.getOwed(stack));
```

## Additional Information
- **Astaria:** Fixed in PR339.
- **Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review-July.pdf)

---

### Example 15: approve() function can be front-ran resulting in token theft

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: MEDIUM

**Details**:

## Security Advisory

## Severity
**Medium Risk**

## Context
- SharesManager.1.sol#L143
- WLSETH.1.sol#L116-L120

## Description
The `approve()` function has a known race condition that can lead to token theft. If a user calls the `approve` function a second time on a spender that was already allowed, the spender can front-run the transaction and call `transferFrom()` to transfer the previous value and still receive the authorization to transfer the new value.

## Recommendation
Consider implementing functionality that allows a user to increase and decrease their allowance similar to Lido's implementation. This will help prevent users from losing funds from front-running attacks.

- **Alluvial:** Recommendation implemented in SPEARBIT/9.
- **Spearbit:** Acknowledged. Note: if you want to follow the same logic of OpenZeppelin ERC20 implementation, the `_spendAllowance` in both SharesManager and WLSETH should execute `emit Approval(owner, spender, amount);`.
- **Alluvial:** Fixed in PR 151.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 16: [M-29] TRSRY susceptible to loan / withdraw confusion

**Source**: Code4rena
**Protocol**: Olympus DAO
**Impact**: MEDIUM

**Details**:

_Submitted by Trust, also found by 0xSky, datapunk, and tonisives_

<https://github.com/code-423n4/2022-08-olympus/blob/main/src/modules/TRSRY.sol#L64-L102><br>

Treasury allocates approvals in the withdrawApproval mapping which is set via setApprovalFor(). In both withdrawReserves() and in getLoan(), \_checkApproval() is used to verify user has enough approval and subtracts the withdraw / loan amount. Therefore, there is no differentiation in validation between loan approval and withdraw approval. Policies which will use getLoan() (currently none) can simply withdraw the tokens without bookkeeping it as a loan.

### Proof of Concept

1.  Policy P has getLoan permission
2.  setApprovalFor(policy, token, amount) was called to grant P permission to loan amount
3.  P calls withdrawReserves(address, token, amount) and directly withdraws the funds without registering as loan

### Recommended Mitigation Steps

A separate mapping called loanApproval should be implemented, and setLoanApprovalFor() will set it, getLoan() will reduce loanApproval balance.

**[ind-igo (Olympus) confirmed, but disagreed with severity and commented](https://github.com/code-423n4/2022-08-olympus-findings/issues/75#issuecomment-1239657706):**
 > Confirmed. Good suggestion. Would put as low risk though.

**[0xean (judge) commented](https://github.com/code-423n4/2022-08-olympus-findings/issues/75#issuecomment-1250396074):**
 > Currently thinking Medium is appropriate for this issue, but will circle back on it

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-olympus)

---

### Example 17: H-1: Escrow approvals are not cleared when club is transferred allowing for abuse after transfer

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

### Example 18: [M-23] Function `withdraw()` and `redeem()` in ERC4626RouterBase would revert always because they have unnecessary allowance setting

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

<https://github.com/AstariaXYZ/astaria-gpl/blob/4b49fe993d9b807fe68b3421ee7f2fe91267c9ef/src/ERC4626RouterBase.sol#L48><br>
<https://github.com/AstariaXYZ/astaria-gpl/blob/4b49fe993d9b807fe68b3421ee7f2fe91267c9ef/src/ERC4626RouterBase.sol#L62>

Functions withdraw() and redeem()  in ERC4626RouterBase  are used to withdraw user funds from vaults and they call `vault.withdraw()` and `vault.redeem()` and logics in vault transfer user shares and user required to give spending allowance for vault and there is no need for ERC4626RouterBase to set approval for vault and because those approved tokens won't be used and code uses `safeApprove()` so next calls to `withdraw()` and `redeem()` would revert because code would tries to change allowance amount while it's not zero. those functions would revert always and AstariaRouter uses them and user won't be able to use those function and any other protocol integrating with Astaria calling those function would have broken logic. also if UI interact with protocol with router functions then UI would have broken parts too. and functions in router support users to set slippage allowance and without them users have to interact with vault directly and they may lose funds because of the slippage.

### Proof of Concept

This is `withdraw()` and `redeem()` code in ERC4626RouterBase:

      function withdraw(
        IERC4626 vault,
        address to,
        uint256 amount,
        uint256 maxSharesOut
      ) public payable virtual override return

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

## Statistics

- Total findings analyzed: 18
- Examples shown: 18
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## approve-max-patterns.md
# Approve Max Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 2 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for approve max vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-02] Pool.sol & Synth.sol: Failing Max Value Allowance

**Source**: Code4rena
**Protocol**: Spartan Protocol
**Impact**: HIGH

**Details**:

## Handle

hickuphh3


## Vulnerability details

### Impact

In the `_approve` function, if the allowance passed in is `type(uint256).max`, nothing happens (ie. allowance will still remain at previous value). Contract integrations (DEXes for example) tend to hardcode this value to set maximum allowance initially, but this will result in zero allowance given instead.

This also makes the comment `// No need to re-approve if already max` misleading, because the max allowance attainable is `type(uint256).max - 1`, and re-approval does happen in this case.

This affects the `approveAndCall` implementation since it uses `type(uint256).max` as the allowance amount, but the resulting allowance set is zero.

### Recommended Mitigation Steps

Keep it simple, remove the condition.

```jsx
function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "!owner");
        require(spender != address(0), "!spender");
        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }
```

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-spartan)

---

### Example 2: M-3: `universalApproveMax` will not work for some tokens that don't support approve `type(uint256).max` amount.

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

### Example 3: [M-09] broken logic in `configureGmxState()` of PirexGmx contract because it doesn't properly call `safeApprove()` for stakedGmx address

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexGmx.sol#L269-L293>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexGmx.sol#L346-L355>

### Impact

Function `configureGmxState()` of `PirexGmx` is for configuring GMX contract state but logic is using `safeApprove()` improperly, it won't reset approval amount for old `stakedGmx` address This would cause 4 problem:

1.  Different behavior in `setContract()` and `configureGmxState()` for handling `stakeGmx` address changes. in `setContract()` the logic reset approval for old address to zero but in `configureGmxState()` the logic don't reset old address GMX spending approval.
2.  The call to this function would revert if `stakeGmx` address didn't changed but other addresses has been changed so `owner` can't use this to configure contract.
3.  Contract won't reset approval for old `stakedGmx` address which is a threat because contract in that address can steal all the GMX balance any time in the future if that old address had been compromised.
4.  Contract won't reset approval for old `stakedGmx` address, if `owner` use `configureGmxState()` to change the `stakeGmx` value then it won't be possible to set `stakedGmx` value to previous ones by using either `configureGmxState()` or `setContract()` and contract would be in broken state.

### Proof of Concept

This is `configureGmxState()` code in `PirexGmx`:

      

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## allowance-patterns.md
# Allowance Security Patterns

## Overview

**Frequency**: 15 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 9 | 6 | 0 | 0 |

**Common Sources**: Sherlock, Spearbit, Code4rena

---

## Detection Checklist

- [ ] Check for allowance vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: allowance() doesnâ€™t limit withdraw() s

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: HIGH

**Details**:

## High Risk Severity Report

## Context
- **PermissiveWithdrawalValidator.sol**: Lines 17-27
- **IWithdrawalValidator.sol**
- **AeraVaultV1.sol**: Lines 456-514

## Description
The `allowance()` function is meant to limit withdrawal amounts. However, `allowance()` can only read and not alter state because its visibility is set to `view`. Therefore, the `withdraw()` function can be called on demand until the entire Vault/Pool balance has been drained, rendering the `allowance()` function ineffective.

```solidity
function withdraw(uint256[] calldata amounts) ... {
    ...
    uint256[] memory allowances = validator.allowance();
    ...
    for (uint256 i = 0; i < tokens.length; i++) {
        if (amounts[i] > holdings[i] || amounts[i] > allowances[i]) {
            revert Aera__AmountExceedAvailable(... );
        }
    }
}
```

### Note on `allowance()`
```solidity
// can't update state due to view
function allowance() external view override returns (uint256[] memory amounts) {
    amounts = new uint256[](count);
    for (uint256 i = 0; i < count; i++) {
        amounts[i] = ANY_AMOUNT;
    }
}
```

## Recommendation
Remove the `view` keyword from the `allowance()` template, e.g., from both `IWithdrawalValidator.sol` and `PermissiveWithdrawalValidator.sol`, to allow for state updates in future versions of `allowance()`.

## Gauntlet
I would say we need an additional callback to the Validator to notify it of actual withdrawal amounts. In cases where allowance is greater than 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 2: Malicious call data can DOS execute

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
`Executor.sol#L142-L243`

## Description
An attacker can Denial of Service (DOS) the executor contract by giving infinite allowance to normal users. Since the executor increases allowance before triggering an external call, the transaction will always revert if the allowance is already infinite.

```solidity
function execute(ExecutorArgs memory _args) external payable override onlyConnext returns (bool, bytes memory) {
    ...
    if (!isNative && hasValue) {
        SafeERC20.safeIncreaseAllowance(IERC20(_args.assetId), _args.to, _args.amount); // reverts if set to `infinite` before
    }
    ...
    (success, returnData) = ExcessivelySafeCall.excessivelySafeCall(...); // can set to `infinite` allowance
    ...
}
```

## Recommendation
Set the allowance to 0 before using `safeIncreaseAllowance`.

## Note
Also see issue Not always `safeApprove(..., 0)`.

## Connext
Solved in PR 1550.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 3: [H-04] Approvals not cleared after key transfer

**Source**: Code4rena
**Protocol**: Unlock Protocol
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

The locks implement three different approval types, see `onlyKeyManagerOrApproved` for an overview:

*   key manager (map `keyManagerOf`)
*   single-person approvals (map `approved`). Cleared by `_clearApproval` or `_setKeyManagerOf`
*   operator approvals (map `managerToOperatorApproved`)

The `MixinTransfer.transferFrom` requires any of the three approval types in the `onlyKeyManagerOrApproved` modifier on the tokenId to authenticate transfers from `from`.

Notice that if the `to` address previously had a key but it expired only the `_setKeyManagerOf` call is performed, which does not clear `approved` if the key manager was already set to 0:

```solidity
function transferFrom(
  address _from,
  address _recipient,
  uint _tokenId
)
  public
  onlyIfAlive
  hasValidKey(_from)
  onlyKeyManagerOrApproved(_tokenId)
{
  // @audit this is skipped if user had a key that expired
  if (toKey.tokenId == 0) {
    toKey.tokenId = _tokenId;
    _recordOwner(_recipient, _tokenId);
    // Clear any previous approvals
    _clearApproval(_tokenId);
  }

  if (previousExpiration <= block.timestamp) {
    // The recipient did not have a key, or had a key but it expired. The new expiration is the sender's key expiration
    // An expired key is no longer a valid key, so the new tokenID is the sender's tokenID
    toKey.expirationTimestamp = fromKey.expirationTimestamp;
    toKey.tokenId = _tokenId;

    // Reset the key Manager to the key owner
    // @audit  doesn't c

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-unlock)

---

### Example 4: H-3: CryptoPunks NFTs may be stolen via deposit frontrunning

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/140 

## Found by 
Jeiwan

## Summary
Depositing of CryptoPunks NFTs may be front run, a malicious actor may deposit someone else's CryptoPunks NFT.
## Vulnerability Detail
Due to the CryptoPunks NFT collection not implementing the ERC721 standard, depositing of CryptoPunks NFTs is implemented via a direct sale:
1. token owner needs to call [offerPunkForSaleToAddress](https://etherscan.io/address/0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb#code) and set the `toAddress` value to the address of the pool the token will be deposited to;
1. token owner then calls the [addCollateral](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC721Pool.sol#L251) function of the ERC721 pool;
1. the pool [buys the token](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC721Pool.sol#L577) from its owner.

However, `addCollateral` can be called by anyone: the pool will buy the token and will deposit it on the caller's account even if the caller is not the owner of the token.
## Impact
CryptoPunks NFTs owner may lose their NFTs when trying to deposit them to an ERC721 pool. A malicious actor may front run the depositing and deposit the NFTs to their account. The malicious actor may then withdraw the NFTs.
## Code Snippet
[ERC721Pool.sol#L577](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC721Pool.sol#L577)
[CryptoPunksMarket](https://etherscan.io/address/0x

*[Content truncated...]*

---

### Example 5: Receiver doesn't always reset allowance

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
Receiver.sol#L224-L297

## Description
The function `_swapAndCompleteBridgeTokens()` of Receiver resets the approval to the executor at the end of an ERC20 transfer. However, if there is insufficient gas, the approval is not reset. This allows the executor to access any tokens (of the same type) left in the Receiver.

```solidity
function _swapAndCompleteBridgeTokens(...) {
    ...
    if (LibAsset.isNativeAsset(assetId)) {
        ...
    } else { // case 2: ERC20 asset
        ...
        token.safeIncreaseAllowance(address(executor), amount);
        if (reserveRecoverGas && gasleft() < _recoverGas) {
            token.safeTransfer(receiver, amount);
            ...
            return; // no safeApprove 0
        }
        try executor.swapAndCompleteBridgeTokens{...} {
            ...
        }
        token.safeApprove(address(executor), 0);
    }
}
```

## Recommendation
Only increase the allowance if sufficient gas is available, for example in the following way:

```solidity
function _swapAndCompleteBridgeTokens(...) {
    ...
    if (LibAsset.isNativeAsset(assetId)) {
        ...
    } else { // case 2: ERC20 asset
        ...
        - token.safeIncreaseAllowance(address(executor), amount);
        if (reserveRecoverGas && gasleft() < _recoverGas) {
            token.safeTransfer(receiver, amount);
            ...
            return;
        }
        + token.safeIncreaseAllowance(address(executor), amount);
 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-retainer1-Spearbit-Security-Review.pdf)

---

### Example 6: LibSwap may pull tokens that are different from the specified asset

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Security Report

## Severity
**Medium Risk**

## Context
**LibSwap.sol**#L30-L55

## Description
`LibSwap.swap` is responsible for executing swaps. It is designed to swap one asset at a time. The `_swapData.callData` is provided by the user, and the LiFi protocol only checks its signature. As a result, users can build calldata to swap a different asset as specified.

For example, users can set `fromAssetId = dai` while providing `addLiquidity(usdc, dai, ...)` as call data. The Uniswap router would then pull `usdc` and `dai` at the same time. If there are remaining tokens left in the LiFi protocol, users can sweep tokens from the protocol.

```solidity
library LibSwap {
    function swap(bytes32 transactionId, SwapData calldata _swapData) internal {
        ...
        if (!LibAsset.isNativeAsset(fromAssetId)) {
            LibAsset.maxApproveERC20(IERC20(fromAssetId), _swapData.approveTo, fromAmount);
            if (toDeposit != 0) {
                LibAsset.transferFromERC20(fromAssetId, msg.sender, address(this), toDeposit);
            }
        } else {
            nativeValue = fromAmount;
        }
        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory res) = _swapData.callTo.call{ value: nativeValue }(_swapData.callData);
        if (!success) {
            string memory reason = LibUtil.getRevertMsg(res);
            revert(reason);
        }
    }
}
```

## Recommendation
Recommend clearing the allowance after the external 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 7: [M-07] Deposit Feature Of The Vault Will Break If Update To A New Platform

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L73>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L152>

### Proof of Concept

During initialization, the `AutoPxGMX` vault will grant max allowance to the platform (PirexGMX) to spend its GMX tokens in Line 97 of the constructor method below. This is required because the vault needs to deposit GMX tokens to the platform (PirexGMX) contract. During deposit, the platform (PirexGMX) contract will pull the GMX tokens within the vault and send them to GMX protocol for staking. Otherwise, the deposit feature within the vault will not work.

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L73>

```solidity
File: AutoPxGmx.sol
73:     constructor(
74:         address _gmxBaseReward,
75:         address _gmx,
76:         address _asset,
77:         string memory _name,
78:         string memory _symbol,
79:         address _platform,
80:         address _rewardsModule
81:     ) Owned(msg.sender) PirexERC4626(ERC20(_asset), _name, _symbol) {
82:         if (_gmxBaseReward == address(0)) revert ZeroAddress();
83:         if (_gmx == address(0)) revert ZeroAddress();
84:         if (_asset == address(0)) revert ZeroAddress();
85:         if (bytes(_name).length == 0) revert InvalidAssetParam();
86:         if

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 8: H-5: Adding liquidity can be `DoS`ed due to calculation mismatches

**Source**: Sherlock
**Protocol**: Arrakis Valantis SOT Audit
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-03-arrakis-judging/issues/54 

## Found by 
KupiaSec, cu5t0mPe0, juaan, whitehair0330
## Summary

When users add liquidity, they send tokens to the `ArrakisPublicVaultRouter` contract. The `ValantisHOTModulePublic` contract then takes the required tokens from the `ArrakisPublicVaultRouter` contract. However, due to a calculation mismatch, the required amount is often greater than the user-sent amount, causing the transaction to be reverted.

## Vulnerability Detail

Let's consider following scenario:
1. The current state:
    - pool: `reserve0 = 1e18 + 1, reserve1 = 1e18 + 1`
    - vault: `totalSupply = 1e18 + 1`
2. Bob calls the `ArrakisPublicVaultRouter.addLiquidity()` function with the following parameters:
    - `amount0Max = 1e18, amount1Max = 1e18`
3. At [L139](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisPublicVaultRouter.sol#L139), the `_getMintAmounts()` function returns:
    - `(sharesReceived, amount0, amount1) = (1e18 - 1, 1e18 - 1, 1e18 - 1)`
4. The router contract takes `token0` and `token1` from Bob in amounts of `1e18 - 1` each and calls the `_addLiquidity()` function with above parameters.
5. In the `_addLiquidity()` function, `ArrakisMetaVaultPublic.mint(1e18 - 1, Bob)` is invoked at [L898](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisPublicVaultRouter.sol#L898).
6. In the `ArrakisMetaVaultPublic.mint()` function:
    - at [L58](

*[Content truncated...]*

---

### Example 9: M-1: Anyone can spend on behalf of roller periphery

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

### Example 10: [H-26] All user assets which are approved to VaderPoolV2 may be stolen

**Source**: Code4rena
**Protocol**: Vader Protocol
**Impact**: HIGH

**Details**:

_Submitted by TomFrenchBlockchain, also found by cmichel_

#### Impact

Total loss of funds which have been approved on `VaderPoolV2`

#### Proof of Concept

`VaderPoolV2` allows minting of fungible LP tokens with the `mintFungible` function

<https://github.com/code-423n4/2021-11-vader/blob/607d2b9e253d59c782e921bfc2951184d3f65825/contracts/dex-v2/pool/VaderPoolV2.sol#L284-L290>

Crucially this function allows a user supplied value for `from` which specifies where the `nativeAsset` and `foreignAsset` should be pulled from. An attacker can then provide any address which has a token approval onto `VaderPoolV2` and mint themselves LP tokens - stealing the underlying tokens.

#### Recommended Mitigation Steps

Remove `from` argument and use msg.sender instead.

**[SamSteinGG (Vader) disputed)](https://github.com/code-423n4/2021-11-vader-findings/issues/221#issuecomment-979180340):**
 > pool is not meant to be interacted with

**[alcueca (judge) commented](https://github.com/code-423n4/2021-11-vader-findings/issues/221#issuecomment-991472193):**
 > And how are you going to ensure that the pool is not interacted with, @SamSteinGG?

**[SamSteinGG (Vader) confirmed](https://github.com/code-423n4/2021-11-vader-findings/issues/221#issuecomment-995709116):**
 > @alcueca Upon second consideration, the functions relating to the minting of synths and wrapped tokens should have had the onlyRouter modifier and thus are indeed vulnerable. Issue accepted.
>

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-vader)

---

### Example 11: M-7: Rebalancing a negative Perp PnL via a Uniswap V3 token swap is broken due to the lack of token spending allowance

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/339 

## Found by 
0x52, Jeiwan, berndartmueller, koxuan, jprod15, Bahurum, cccz, CRYP70, rvierdiiev, GimelSec

## Summary

The `ISwapper spotSwapper` (i.e., `Uniswapper`) helper contract, used by the `PerpDepository._rebalanceNegativePnlWithSwap` function to perform the actual Uniswap V3 token swap, is missing the required `assetToken` spending allowance due to a lack of calling the `assetToken.approve` function.

## Vulnerability Detail

Rebalancing a negative Perp PnL with the `PerpDepository.rebalance` function calls the `_rebalanceNegativePnlWithSwap` function, which performs a Uniswap swap. However, the required `assetToken` spending allowance for the `ISwapper spotSwapper` (i.e. `Uniswapper`) helper contract is missing. This leads to a revert due to insufficient allowance.

## Impact

Rebalancing a negative Perp PnL via a Uniswap swap is missing the token approval and leads to a revert.

## Code Snippet

[integrations/perp/PerpDepository.sol#L507](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L507)

```solidity
function _rebalanceNegativePnlWithSwap(
    uint256 amount,
    uint256 amountOutMinimum,
    uint160 sqrtPriceLimitX96,
    uint24 swapPoolFee,
    address account
) private returns (uint256, uint256) {
    uint256 normalizedAmount = amount.fromDecimalToDecimal(
        ERC20(quoteToken).decimals(),
        18
    );
    _checkNegativePn

*[Content truncated...]*

---

### Example 12: H-2: Anyone who approved quote tokens to a pool can be forced to take

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/145 

## Found by 
Jeiwan

## Summary
Taking may be executed on behalf of any address who approved spending of quote tokens to a pool: such address will pay quote tokens and will receive collateral.
## Vulnerability Detail
[ERC20Pool](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC20Pool.sol#L403) and [ERC721Pool](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC721Pool.sol#L405) implement the `take` functions, which buy collateral from auction in exchange for quote tokens. The address to pull quote tokens from is specified in the `callee_` argument, which allows anyone to call the functions and pass an address that has previously approved spending of the quote token to the pool. As a result, such an address will pay for the liquidation and will receive the collateral.
## Impact
Anyone can initiate a take on behalf of another user. Such user can be a lender who has previously approved spending of the quote token to the pool. Calling `take` with the user's address specified as the `callee_` argument will result in:
1. the user [receiving collateral](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC20Pool.sol#L450), which may have low value;
1. the user [paying the quote token](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC20Pool.sol#L460) to repay the debt being taken.
## Code Snippet
[ERC20Pool.sol#L460]

*[Content truncated...]*

---

### Example 13: H-1: PerpDespository#reblance and rebalanceLite can be called to drain funds from anyone who has approved PerpDepository

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/288 

## Found by 
clems4ever, dipp, 0xNazgul, DecorativePineapple, ctf\_sec, unforgiven, 0x52, ck, HollaDieWaldfee, GimelSec, chiranz, berndartmueller, yixxas, Zarf, carrot, koxuan, hl\_, Ruhum, kankodu, Bahurum

## Summary

PerpDespository#reblance and rebalanceLite allows anyone to specify the account that pays the quote token. These functions allow a malicious user to abuse any allowance provided to PerpDirectory. rebalance is the worst of the two because the malicious user could sandwich attack the rebalance to steal all the funds and force the unsuspecting user to pay the `shortfall`.

## Vulnerability Detail

    function rebalance(
        uint256 amount,
        uint256 amountOutMinimum,
        uint160 sqrtPriceLimitX96,
        uint24 swapPoolFee,
        int8 polarity,
        address account // @audit user specified payer
    ) external nonReentrant returns (uint256, uint256) {
        if (polarity == -1) {
            return
                _rebalanceNegativePnlWithSwap(
                    amount,
                    amountOutMinimum,
                    sqrtPriceLimitX96,
                    swapPoolFee,
                    account // @audit user address passed directly
                );
        } else if (polarity == 1) {
            // disable rebalancing positive PnL
            revert PositivePnlRebalanceDisabled(msg.sender);
            // return _rebalancePositivePnlWithSwap(amount, am

*[Content truncated...]*

---

### Example 14: M-5: PerpDepository#_rebalanceNegativePnlWithSwap fails to approve vault for quote deposit

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/372 

## Found by 
HonorLt, 0x52, yixxas, Bahurum, rvierdiiev, GimelSec

## Summary

Throughout the entirety of the contract it grants approval to the vault before depositing either quote or asset. In this case there is no approval which means that the deposit call will fail causing PerpDepository#_rebalanceNegativePnlWithSwap to always revert.

## Vulnerability Detail

See summary.

## Impact

PerpDepository#_rebalanceNegativePnlWithSwap won't function

## Code Snippet

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L478-L528

## Tool used

Manual Review

## Recommendation

Add the missing approve call:

        } else if (shortFall < 0) {
            // we got excess tokens in the spot swap. Send them to the account paying for rebalance
            IERC20(quoteToken).transfer(
                account,
                _abs(shortFall)
            );
        }

    +   IERC20(quoteToken).approve(address(vault), quoteAmount); 
        vault.deposit(quoteToken, quoteAmount);

        emit Rebalanced(baseAmount, quoteAmount, shortFall);
        return (baseAmount, quoteAmount);

## Discussion

**WarTech9**

This is a duplicate of #339 

**0x00052**

Two separate issues here. #339 is pointing out it's not approved for the swapper. This one is pointing out it's not approved for the vault. It should be approved for both

**WarTech9**

@0x00052 good catch. You'

*[Content truncated...]*

---

### Example 15: [M-23] Function `withdraw()` and `redeem()` in ERC4626RouterBase would revert always because they have unnecessary allowance setting

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

<https://github.com/AstariaXYZ/astaria-gpl/blob/4b49fe993d9b807fe68b3421ee7f2fe91267c9ef/src/ERC4626RouterBase.sol#L48><br>
<https://github.com/AstariaXYZ/astaria-gpl/blob/4b49fe993d9b807fe68b3421ee7f2fe91267c9ef/src/ERC4626RouterBase.sol#L62>

Functions withdraw() and redeem()  in ERC4626RouterBase  are used to withdraw user funds from vaults and they call `vault.withdraw()` and `vault.redeem()` and logics in vault transfer user shares and user required to give spending allowance for vault and there is no need for ERC4626RouterBase to set approval for vault and because those approved tokens won't be used and code uses `safeApprove()` so next calls to `withdraw()` and `redeem()` would revert because code would tries to change allowance amount while it's not zero. those functions would revert always and AstariaRouter uses them and user won't be able to use those function and any other protocol integrating with Astaria calling those function would have broken logic. also if UI interact with protocol with router functions then UI would have broken parts too. and functions in router support users to set slippage allowance and without them users have to interact with vault directly and they may lose funds because of the slippage.

### Proof of Concept

This is `withdraw()` and `redeem()` code in ERC4626RouterBase:

      function withdraw(
        IERC4626 vault,
        address to,
        uint256 amount,
        uint256 maxSharesOut
      ) public payable virtual override return

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

## Statistics

- Total findings analyzed: 15
- Examples shown: 15
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## safeapprove-patterns.md
# SafeApprove Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 3 | 0 | 0 |

**Common Sources**: Spearbit, Code4rena

---

## Detection Checklist

- [ ] Check for safeapprove vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: safeApprove indepositToken could revert for non-standard token like USDT

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: MEDIUM

**Details**:

## Security Analysis

## Severity
**Medium Risk**

## Context
AeraVaultV1.sol#L893

## Description
Some non-standard tokens like USDT will revert when a contract or a user tries to approve an allowance when the spender allowance has already been set to a non-zero value. In the current code, we have not seen any real problem with this fact because the amount retrieved via `depositToken()` is approved and sent to the Balancer pool via `joinPool()` and `managePoolBalance()`. Balancer transfers the same amount, lowering the approval to 0 again. 

However, if the approval is not lowered to exactly 0 (due to a rounding error or another unforeseen situation), then the next approval in `depositToken()` will fail (assuming a token like USDT is used), blocking all further deposits.

**Note:** Set to medium risk because the probability of this happening is low, but the impact would be high. We also should note that OpenZeppelin has officially deprecated the `safeApprove` function, suggesting to use instead `safeIncreaseAllowance` and `safeDecreaseAllowance`.

## Recommendation
Adopt a safer approach to cover edge cases such as the abovementioned USDT token and implement the following solution:

```solidity
function depositToken(IERC20 token, uint256 amount) internal {
    token.safeTransferFrom(owner(), address(this), amount);
    // - token.safeApprove(address(bVault), amount);
    uint256 allowance = token.allowance(address(this), address(bVault));
    if (allowance > 0) {
        tok

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 2: Seaport auctions not compatible with USDT

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Security Analysis Report

## Severity
**Medium Risk**

## Context
`CollateralToken.sol#L173`

## Description
As per the ERC20 specification, the `approve()` function is expected to return a boolean:

```solidity
function approve(address _spender, uint256 _value) public returns (bool success)
```

However, USDT deviates from this standard, and its `approve()` method does not have a return value. Hence, if USDT is used as a payment token, the following line reverts in `validateOrder()` as it expects return data but doesn't receive it:

```solidity
paymentToken.approve(address(transferProxy), s.LIEN_TOKEN.getOwed(stack));
```

## Recommendation
Use Solmate's `safeApprove()` function to accommodate USDT's `approve()`:

```solidity
paymentToken.safeApprove(address(transferProxy), s.LIEN_TOKEN.getOwed(stack));
```

## Additional Information
- **Astaria:** Fixed in PR339.
- **Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review-July.pdf)

---

### Example 3: [M-23] Function `withdraw()` and `redeem()` in ERC4626RouterBase would revert always because they have unnecessary allowance setting

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

<https://github.com/AstariaXYZ/astaria-gpl/blob/4b49fe993d9b807fe68b3421ee7f2fe91267c9ef/src/ERC4626RouterBase.sol#L48><br>
<https://github.com/AstariaXYZ/astaria-gpl/blob/4b49fe993d9b807fe68b3421ee7f2fe91267c9ef/src/ERC4626RouterBase.sol#L62>

Functions withdraw() and redeem()  in ERC4626RouterBase  are used to withdraw user funds from vaults and they call `vault.withdraw()` and `vault.redeem()` and logics in vault transfer user shares and user required to give spending allowance for vault and there is no need for ERC4626RouterBase to set approval for vault and because those approved tokens won't be used and code uses `safeApprove()` so next calls to `withdraw()` and `redeem()` would revert because code would tries to change allowance amount while it's not zero. those functions would revert always and AstariaRouter uses them and user won't be able to use those function and any other protocol integrating with Astaria calling those function would have broken logic. also if UI interact with protocol with router functions then UI would have broken parts too. and functions in router support users to set slippage allowance and without them users have to interact with vault directly and they may lose funds because of the slippage.

### Proof of Concept

This is `withdraw()` and `redeem()` code in ERC4626RouterBase:

      function withdraw(
        IERC4626 vault,
        address to,
        uint256 amount,
        uint256 maxSharesOut
      ) public payable virtual override return

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## safetransfer-patterns.md
# SafeTransfer Security Patterns

## Overview

**Frequency**: 14 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 9 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Cyfrin

---

## Detection Checklist

- [ ] Check for safetransfer vulnerabilities in all external functions
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

Some major tokens went live before ERC20 was finalized, resulting in a discrepancy whether the transfer functions should (A) return a boolean or (B) revert/fail on error. The current best practice is that they should revert, but return â€œtrueâ€ on success. However, not every token claiming ERC20-compatibility is doing this â€” some only return true/false; some revert, but do not return anything on success. This is a well known issue, heavily discussed since mid-2018.

Today many tools, including OpenZeppelin, offer [a wrapper for â€œsafe ERC20 transferâ€](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol):

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

### Example 2: [M-02] Use `safeTransferFrom` Instead of `transferFrom` for ERC721

**Source**: Code4rena
**Protocol**: Golom
**Impact**: MEDIUM

**Details**:

[GolomTrader.sol#L236](https://github.com/code-423n4/2022-07-golom/blob/7bbb55fca61e6bae29e57133c1e45806cbb17aa4/contracts/core/GolomTrader.sol#L236)<br>

Use of `transferFrom` method for ERC721 transfer is discouraged and recommended to use safeTransferFrom whenever possible by OpenZeppelin.<br>
This is because `transferFrom()` cannot check whether the receiving address know how to handle ERC721 tokens.

In the function shown at below PoC, ERC721 token is sent to `msg.sender` with the `transferFrom` method.<br>
If this `msg.sender` is a contract and is not aware of incoming ERC721 tokens, the sent token could be locked up in the contract forever.

Reference: <https://docs.openzeppelin.com/contracts/3.x/api/token/erc721>

### Proof of Concept
```
GolomTrader.sol:236:            ERC721(o.collection).transferFrom(o.signer, receiver, o.tokenId);
```

### Recommended Mitigation Steps

I recommend to call the `safeTransferFrom()` method instead of `transferFrom()` for NFT transfers.

**[0xsaruman (Golom) confirmed, but disagreed with severity](https://github.com/code-423n4/2022-07-golom-findings/issues/342)**

**[0xsaruman (Golom) resolved and commented](https://github.com/code-423n4/2022-07-golom-findings/issues/342#issuecomment-1236301290):**
 > Resolved https://github.com/golom-protocol/contracts/commit/366c0455547041003c28f21b9afba48dc33dc5c7#diff-63895480b947c0761eff64ee21deb26847f597ebee3c024fb5aa3124ff78f6ccR238



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-golom)

---

### Example 3: H-1: Use safeTransfer/safeTransferFrom consistently instead of transfer/transferFrom

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/335 

## Found by 
tsvetanovv, 0x52, polthedev, wagmi, enckrish, ak1, IllIllI, yongkiws, ctrlc03, zaskoh, Trumpero, TrungOre, Breeje, imare, jonatascm, cccz, Metadev, Nyx, neumo, Atarpara, serial-coder, yixxas, Tricko, 8olidity, Qeew, ahmedovv, libratus, usmannk, MohanVarma, psy4n0n, 0x4non, kiki\_dev, peanuts, 0xhacksmithh, eyexploit, 0xSmartContract, supernova, Zarf, thekmj, ltyu, ck, sach1r0, hansfriese, John, HollaDieWaldfee, HonorLt, rvierdiiev, zaevlad, 0xAgro, Avci, gjaldon, Madalad, ch0bu, bin2chen, Bahurum, seyni, 0xadrii, Deivitto

## Summary
Use safeTransfer/safeTransferFrom consistently instead of transfer/transferFrom
## Vulnerability Detail
Some tokens do not revert on failure, but instead return false (e.g. [ZRX](https://etherscan.io/address/0xe41d2489571d322189246dafa5ebde1f4699f498#code)).
https://github.com/d-xo/weird-erc20/#no-revert-on-failure
tranfser/transferfrom is directly used to send tokens in many places in the contract and the return value is not checked.
If the token send fails, it will cause a lot of serious problems.
For example, in the clear function, if debt token is ZRX, the lender can clear request without providing any debt token.
```solidity
    function clear (uint256 reqID) external returns (uint256 loanID) {
        Request storage req = requests[reqID];

        factory.newEvent(reqID, CoolerFactory.Events.Clear);

        if (!req.active) 
            revert Deact

*[Content truncated...]*

---

### Example 4: [H-03] Result of transfer / transferFrom not checked

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

### Example 5: [H-01] Unsafe handling of underlying tokens

**Source**: Code4rena
**Protocol**: Swivel
**Impact**: HIGH

**Details**:

_Submitted by 0xsanson, also found by 0xRajeev, cmichel, defsec, GalloDaSballo, JMukesh, leastwood, loop, nikitastupin, pants, and pauliax_.

#### Impact

Not every ERC20 token follows OpenZeppelin's recommendation. It's possible (inside ERC20 standard) that a `transferFrom` doesn't revert upon failure but returns `false`.

The code doesn't check these return values. For example `uToken.transferFrom(msg.sender, o.maker, a);` in `initiateVaultFillingZcTokenInitiate` can be exploited by the msg.sender to initiate a trade without sending any underlying.

#### Proof of Concept

`grep 'transfer' Swivel.sol`

#### Tools Used

editor

#### Recommended Mitigation Steps

Consider using [OpenZeppelin's library](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol) with *safe* versions of transfer functions.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-swivel)

---

### Example 6: Use safe transfer for ERC20 tokens

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

### Example 7: [H-01] Unsafe usage of ERC20 transfer and transferFrom 

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

### Example 8: M-2: Users might lose funds as `claimERC20Prize()` doesn't revert for no-revert-on-transfer tokens

**Source**: Sherlock
**Protocol**: Footium
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-footium-judging/issues/86 

## Found by 
0xAsen, 0xGoodess, 0xGusMcCrae, 0xPkhatri, 0xRobocop, 0xStalin, 0xeix, 0xmuxyz, 0xnirlin, 14si2o\_Flint, 8olidity, ACai7, AlexCzm, BAHOZ, Bauchibred, Bauer, Cryptor, DevABDee, Diana, GimelSec, J4de, Koolex, MiloTruck, PRAISE, PTolev, Phantasmagoria, Piyushshukla, PokemonAuditSimulator, Polaris\_tow, Proxy, Quantish, R-Nemes, SanketKogekar, Sulpiride, TheNaubit, Tricko, \_\_141345\_\_, abiih, alliums8520, ast3ros, berlin-101, cergyk, ctf\_sec, cuthalion0x, dacian, ddimitrov22, deadrxsezzz, djxploit, favelanky, georgits, holyhansss, innertia, jasonxiale, josephdara, jprod15, kiki\_dev, l3r0ux, lewisbroadhurst, nzm\_, oot2k, oualidpro, peanuts, ravikiran.web3, sach1r0, santipu\_, sashik\_eth, shaka, shame, thekmj, tibthecat, tsvetanovv, whoismatthewmc1, wzrdk3lly, yy
## Summary

Users can call `claimERC20Prize()` without actually receiving tokens if a no-revert-on-failure token is used, causing a portion of their claimable tokens to become unclaimable.

## Vulnerability Detail

In the `FootiumPrizeDistributor` contract, whitelisted users can call `claimERC20Prize()` to claim ERC20 tokens. The function adds the amount of tokens claimed to the user's total claim amount, and then transfers the tokens to the user:

[FootiumPrizeDistributor.sol#L128-L131](https://github.com/sherlock-audit/2023-04-footium/blob/main/footium-eth-shareable/contracts/FootiumPrizeDistributor.sol#L128-L131)

```solidi

*[Content truncated...]*

---

### Example 9: [M-02] `_payoutToken[s]()` is not compatible with tokens with missing return value

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[PA1D.sol#L317](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/enforcer/PA1D.sol#L317)<br>
[PA1D.sol#L340](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/enforcer/PA1D.sol#L340)<br>

Payout is blocked and tokens are stuck in contract.

### Proof of Concept

`PA1D._payoutToken()` and `PA1D._payoutTokens()` call `ERC20.transfer()` in a require-statement to send tokens to a list of payout recipients.<br>
Some tokens do not return a bool (e.g. USDT, BNB, OMG) on ERC20 methods. But since the require-statement expects a `bool`, for such a token a `void` return will also cause a revert, despite an otherwise successful transfer. That is, the token payout will always revert for such tokens.

### Recommended Mitigation Steps

Use [OpenZeppelin's SafeERC20](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol), which handles the return value check as well as non-standard-compliant tokens.

**[alexanderattar (Holograph) commented](https://github.com/code-423n4/2022-10-holograph-findings/issues/456#issuecomment-1306632476):**
 > Low priority, but can be updated to ensure compatibility with all ERC20 tokens.

**[alexanderattar (Holograph) linked a PR](https://github.com/code-423n4/2022-10-holograph-findings/issues/456#issuecomment-1306632476):**
 > [Feature/holo 612 royalty smart contract improvements](https://github.com/holographxyz/

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 10: M-7: Code does not handle ERC20 tokens with special `transfer` implementation

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

### Example 11: [M-07] Using `transferFrom` on ERC721 tokens

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

_Submitted by shw_

In the function `awardExternalERC721` of contract `PrizePool`, when awarding external ERC721 tokens to the winners, the `transferFrom` keyword is used instead of `safeTransferFrom`. If any winner is a contract and is not aware of incoming ERC721 tokens, the sent tokens could be locked.

Recommend consider changing `transferFrom` to `safeTransferFrom` at line 602. However, it could introduce a DoS attack vector if any winner maliciously rejects the received ERC721 tokens to make the others unable to get their awards. Possible mitigations are to use a `try/catch` statement to handle error cases separately or provide a function for the pool owner to remove malicious winners manually if this happens.

**[asselstine (PoolTogether) confirmed and disagreed with severity](https://github.com/code-423n4/2021-06-pooltogether-findings/issues/115#issuecomment-868021913):**
 > This issue poses no risk to the Prize Pool, so it's more of a `1 (Low Risk` IMO.
>
> This is just about triggering a callback on the ERC721 recipient.  We omitted it originally because we didn't want a revert on the callback to DoS the prize pool.
>
> However, to respect the interface it makes sense to implement it fully.  That being said, if it does throw we must ignore it to prevent DoS attacks.

**[dmvt (judge) commented](https://github.com/code-423n4/2021-06-pooltogether-findings/issues/115#issuecomment-907507608):**
 > I agree with the medium risk rating provided by the warden.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-06-pooltogether)

---

### Example 12: [M-03] Use safeTransfer()/safeTransferFrom() instead of transfer()/transferFrom()

**Source**: Code4rena
**Protocol**: Rubicon
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/RubiconRouter.sol#L251


## Vulnerability details

## Impact

It is a good idea to add a `require()` statement that checks the return value of ERC20 token transfers or to use something like OpenZeppelinâ€™s `safeTransfer()`/`safeTransferFrom()` unless one is sure the given token reverts in case of a failure. Failure to do so will cause silent failures of transfers and affect token accounting in contract.

However, using `require()` to check transfer return values could lead to issues with non-compliant ERC20 tokens which do not return a boolean value. Therefore, it's highly advised to use OpenZeppelinâ€™s `safeTransfer()`/`safeTransferFrom()`.

## Proof of Concept

**RubiconRouter.sol**

[L251](https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/RubiconRouter.sol#L251): `ERC20(route[route.length - 1]).transfer(to, currentAmount);`\
[L303](https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/RubiconRouter.sol#L303): `ERC20(buy_gem).transfer(msg.sender, fill);`\
[L320](https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/RubiconRouter.sol#L320): `ERC20(buy_gem).transfer(msg.sender, fill);`\
[L348](https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/RubiconRouter.sol#L34

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-rubicon)

---

### Example 13: [M-06] `SafeERC20.sol` is imported but not used in the `transferBribes()` function

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

_Submitted by jayjonah8, also found by cccz, cmichel, Dravee, gzeon, hyh, IllIllI, leastwood, NoamYakov, and Omik_

In BribeVault.sol the transferBribes() function uses token.transfer() instead of token.safeTransfer.
Tokens that donâ€™t correctly implement the latest EIP20 spec, like USDT, will be unusable in the protocol as they revert the transaction because of the missing return value.  The fact that the SafeERC20.sol library is imported at the top of the BribeVault.sol implies that safeTransfer should be being used but may have been forgotten.

### Proof of Concept

[BribeVault.sol#L296](https://github.com/code-423n4/2022-02-redacted-cartel/blob/main/contracts/BribeVault.sol#L296)<br>

### Recommended Mitigation Steps

It's recommended to use OpenZeppelinâ€™s SafeERC20 versions with the safeTransfer and safeTransferFrom functions that handle the return value check as well as non-standard-compliant tokens.

**[kphed (Redacted Cartel) confirmed and commented](https://github.com/code-423n4/2022-02-redacted-cartel-findings/issues/4#issuecomment-1040506429):**
 > Good catch!
> 
> Thanks again for participating in our contest jayjonah8, looking forward to more feedback/suggestions/comments.

**[Alex the Entreprenerd (judge) decreased severity to Medium and commented](https://github.com/code-423n4/2022-02-redacted-cartel-findings/issues/4#issuecomment-1059786452):**
 > Agree with the finding, because this is contingent on the specific token failing. I believe Medium severity to be m

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-redacted-cartel)

---

### Example 14: M-1: Use safeTransferFrom() instead of transferFrom().

**Source**: Sherlock
**Protocol**: DODO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-dodo-judging/issues/47 

## Found by 
sach1r0, Nyx, yixxas, 0x4non, Tomo

## Summary

The ERC20.transfer() and ERC20.transferFrom() functions return a boolean value indicating success. This parameter needs to be checked for success. Some tokens do not revert if the transfer failed but return false instead.

## Vulnerability Detail
Some tokens (like USDT) don't correctly implement the EIP20 standard and their transfer/ transferFrom function return void instead of a success boolean. Calling these functions with the correct EIP20 function signatures will always revert.
## Impact
Tokens that don't actually perform the transfer and return false are still counted as a correct transfer and tokens that don't correctly implement the latest EIP20 spec, like USDT, will be unusable in the protocol as they revert the transaction because of the missing return value.
## Code Snippet
https://github.com/sherlock-audit/2022-11-dodo/blob/main/contracts/SmartRoute/DODORouteProxy.sol#L420

https://github.com/sherlock-audit/2022-11-dodo/blob/main/contracts/SmartRoute/DODORouteProxy.sol#L423
## Tool used

Manual Review

## Recommendation
Recommend using OpenZeppelin's SafeERC20 versions with the safeTransfer and safeTransferFrom functions that handle the return value check as well as non-standard-compliant tokens.

## Discussion

**Evert0x**

We think a medium is still valid, although no direct loss of funds, a failed token transfer should be catche

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 14
- Examples shown: 14
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## transferfrom-vs-safetransferfrom-patterns.md
# transferFrom vs safeTransferFrom Security Patterns

## Overview

**Frequency**: 14 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 13 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Pashov Audit Group, Cyfrin

---

## Detection Checklist

- [ ] Check for transferfrom vs safetransferfrom vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-02] Use `safeTransferFrom` Instead of `transferFrom` for ERC721

**Source**: Code4rena
**Protocol**: Golom
**Impact**: MEDIUM

**Details**:

[GolomTrader.sol#L236](https://github.com/code-423n4/2022-07-golom/blob/7bbb55fca61e6bae29e57133c1e45806cbb17aa4/contracts/core/GolomTrader.sol#L236)<br>

Use of `transferFrom` method for ERC721 transfer is discouraged and recommended to use safeTransferFrom whenever possible by OpenZeppelin.<br>
This is because `transferFrom()` cannot check whether the receiving address know how to handle ERC721 tokens.

In the function shown at below PoC, ERC721 token is sent to `msg.sender` with the `transferFrom` method.<br>
If this `msg.sender` is a contract and is not aware of incoming ERC721 tokens, the sent token could be locked up in the contract forever.

Reference: <https://docs.openzeppelin.com/contracts/3.x/api/token/erc721>

### Proof of Concept
```
GolomTrader.sol:236:            ERC721(o.collection).transferFrom(o.signer, receiver, o.tokenId);
```

### Recommended Mitigation Steps

I recommend to call the `safeTransferFrom()` method instead of `transferFrom()` for NFT transfers.

**[0xsaruman (Golom) confirmed, but disagreed with severity](https://github.com/code-423n4/2022-07-golom-findings/issues/342)**

**[0xsaruman (Golom) resolved and commented](https://github.com/code-423n4/2022-07-golom-findings/issues/342#issuecomment-1236301290):**
 > Resolved https://github.com/golom-protocol/contracts/commit/366c0455547041003c28f21b9afba48dc33dc5c7#diff-63895480b947c0761eff64ee21deb26847f597ebee3c024fb5aa3124ff78f6ccR238



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-golom)

---

### Example 2: H-1: Use safeTransfer/safeTransferFrom consistently instead of transfer/transferFrom

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/335 

## Found by 
tsvetanovv, 0x52, polthedev, wagmi, enckrish, ak1, IllIllI, yongkiws, ctrlc03, zaskoh, Trumpero, TrungOre, Breeje, imare, jonatascm, cccz, Metadev, Nyx, neumo, Atarpara, serial-coder, yixxas, Tricko, 8olidity, Qeew, ahmedovv, libratus, usmannk, MohanVarma, psy4n0n, 0x4non, kiki\_dev, peanuts, 0xhacksmithh, eyexploit, 0xSmartContract, supernova, Zarf, thekmj, ltyu, ck, sach1r0, hansfriese, John, HollaDieWaldfee, HonorLt, rvierdiiev, zaevlad, 0xAgro, Avci, gjaldon, Madalad, ch0bu, bin2chen, Bahurum, seyni, 0xadrii, Deivitto

## Summary
Use safeTransfer/safeTransferFrom consistently instead of transfer/transferFrom
## Vulnerability Detail
Some tokens do not revert on failure, but instead return false (e.g. [ZRX](https://etherscan.io/address/0xe41d2489571d322189246dafa5ebde1f4699f498#code)).
https://github.com/d-xo/weird-erc20/#no-revert-on-failure
tranfser/transferfrom is directly used to send tokens in many places in the contract and the return value is not checked.
If the token send fails, it will cause a lot of serious problems.
For example, in the clear function, if debt token is ZRX, the lender can clear request without providing any debt token.
```solidity
    function clear (uint256 reqID) external returns (uint256 loanID) {
        Request storage req = requests[reqID];

        factory.newEvent(reqID, CoolerFactory.Events.Clear);

        if (!req.active) 
            revert Deact

*[Content truncated...]*

---

### Example 3: Use safe transfer for ERC20 tokens

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

### Example 4: [M-03] Use a safe transfer helper library for ERC20 transfers

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: MEDIUM

**Details**:

_Submitted by horsefacts, also found by 0x1f8b, 0x29A, 0x52, 0xf15ers, AlleyCat, apostle0x01, berndartmueller, cccz, Ch&#95;301, Chom, cloudjunky, codexploder, cryptphi, delfin454000, durianSausage, fatherOfBlocks, Franfran, hake, hansfriese, hyh, IllIllI, jonatascm, Kaiziron, Limbooo, m&#95;Rassska, Meera, oyc&#95;109, peritoflores, rajatbeladiya, rbserver, Ruhum, Sm4rty, svskaushik, and zzzitron_

`JBERC20PaymentTerminal#_transferFrom` calls `IERC20#transfer` and `transferFrom` directly. There are two issues with using this interface directly:

1.  `JBERC20PaymentTerminal#_transferFrom` function does not check the return value of these calls. Tokens that return `false` rather than revert to indicate failed transfers may silently fail rather than reverting as expected.

2.  Since the IERC20 interface requires a boolean return value, attempting to transfer ERC20s with [missing return values](https://github.com/d-xo/weird-erc20#missing-return-values) will revert. This means Juicebox payment terminals cannot support a number of popular ERC20s, including USDT and BNB.

[`JBERC20PaymentTerminal#_transferFrom`](https://github.com/jbx-protocol/juice-contracts-v2-code4rena/blob/828bf2f3e719873daa08081cfa0d0a6deaa5ace5/contracts/JBERC20PaymentTerminal.sol#L81-L89):

```solidity
  function _transferFrom(
    address _from,
    address payable _to,
    uint256 _amount
  ) internal override {
    _from == address(this)
      ? IERC20(token).transfer(_to, _amount)
      : IERC20(token).t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-juicebox)

---

### Example 5: [M-09] Use safeTransferFrom instead of transferFrom for ERC721 transfers

**Source**: Code4rena
**Protocol**: Cally
**Impact**: MEDIUM

**Details**:

_Submitted by hickuphh3, also found by antonttc, berndartmueller, catchup, cccz, dipp, FSchmoede, GimelSec, hake, jah, jayjonah8, joestakey, kebabsec, Kenshin, Kumpa, MiloTruck, minhquanym, peritoflores, rfa, shenwilly, WatchPug, and ynnad_

<https://github.com/code-423n4/2022-05-cally/blob/1849f9ee12434038aa80753266ce6a2f2b082c59/contracts/src/Cally.sol#L199>

<https://github.com/code-423n4/2022-05-cally/blob/1849f9ee12434038aa80753266ce6a2f2b082c59/contracts/src/Cally.sol#L295>

<https://github.com/code-423n4/2022-05-cally/blob/1849f9ee12434038aa80753266ce6a2f2b082c59/contracts/src/Cally.sol#L344>

### Details & Impact

The `transferFrom()` method is used instead of `safeTransferFrom()`, presumably to save gas. I however argue that this isnâ€™t recommended because:

*   [OpenZeppelinâ€™s documentation](https://docs.openzeppelin.com/contracts/4.x/api/token/erc721#IERC721-transferFrom-address-address-uint256-) discourages the use of `transferFrom()`, use `safeTransferFrom()` whenever possible
*   Given that any NFT can be used for the call option, there are a few NFTs (hereâ€™s an [example](https://github.com/sz-piotr/eth-card-game/blob/master/src/ethereum/contracts/ERC721Market.sol#L20-L31)) that have logic in the `onERC721Received()` function, which is only triggered in the `safeTransferFrom()` function and not in `transferFrom()`

### Recommended Mitigation Steps

Call the `safeTransferFrom()` method instead of `transferFrom()` for NFT transfers. Note that the `CallyNft` contrac

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-cally)

---

### Example 6: [M-04] Incorrect usage of safeTransferFrom traps fees in Papr Controller

**Source**: Code4rena
**Protocol**: Backed Protocol
**Impact**: MEDIUM

**Details**:

Because the Papr Controller never gives approval for ERC20 transfers, calls to `safeTransferFrom` on the Papr token will revert with insufficient approval. This will trap proceeds from auctions in the contract and prevent the owner/ DAO from collecting fees, motivating the rating of high severity. The root cause of this issue is misusing `safeTransferFrom` to transfer tokens directly out of the contract instead of using `transfer` directly. The contract will hold the token balance and thus does not need approval to transfer tokens, nor can it approve token transfers in the current implementation.

### Proof of Concept

Comment out [this token approval](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/test/paprController/OwnerFunctions.ft.sol#L67) as the controller contract does not implement functionality to call approve. It doesn't make sense to "prank" a contract account in this context because it deviates from the runtime behavior of the deployed contract. That is, it's impossible for the Papr Controller to approve token transfers. Run `forge test -m testSendPaprFromAuctionFeesWorksIfOwner` and observe that it fails because of insufficient approvals. Replace [the call to `safeTransferFrom`](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L383) with a call to `transfer(to, amount)` and rerun the test. It will now pass and correctly achieve the intended behavior.

### Tools Used

Foundr

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-backed)

---

### Example 7: [M-01] Unhandled return values of transfer and transferFrom

**Source**: Code4rena
**Protocol**: Inverse Finance
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L205
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L280
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L399
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L537
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L570
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L602


## Vulnerability details

## Impact
ERC20 implementations are not always consistent. Some implementations of transfer and transferFrom could return â€˜falseâ€™ on failure instead of reverting. It is safer to wrap such calls into require() statements to these failures.


## Proof of Concept
Provide direct links to all referenced code in GitHub. Add screenshots, logs, or any other relevant proof that illustrates the concept.
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L205
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L280
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L399
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L537
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L570
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L602
## Tools Used
Read the codes

## Recommended Mitigation Steps
Check the return value and revert on 0/false or use OpenZeppelinâ€™s SafeERC20 wrappe

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 8: [M-02] `_payoutToken[s]()` is not compatible with tokens with missing return value

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[PA1D.sol#L317](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/enforcer/PA1D.sol#L317)<br>
[PA1D.sol#L340](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/enforcer/PA1D.sol#L340)<br>

Payout is blocked and tokens are stuck in contract.

### Proof of Concept

`PA1D._payoutToken()` and `PA1D._payoutTokens()` call `ERC20.transfer()` in a require-statement to send tokens to a list of payout recipients.<br>
Some tokens do not return a bool (e.g. USDT, BNB, OMG) on ERC20 methods. But since the require-statement expects a `bool`, for such a token a `void` return will also cause a revert, despite an otherwise successful transfer. That is, the token payout will always revert for such tokens.

### Recommended Mitigation Steps

Use [OpenZeppelin's SafeERC20](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol), which handles the return value check as well as non-standard-compliant tokens.

**[alexanderattar (Holograph) commented](https://github.com/code-423n4/2022-10-holograph-findings/issues/456#issuecomment-1306632476):**
 > Low priority, but can be updated to ensure compatibility with all ERC20 tokens.

**[alexanderattar (Holograph) linked a PR](https://github.com/code-423n4/2022-10-holograph-findings/issues/456#issuecomment-1306632476):**
 > [Feature/holo 612 royalty smart contract improvements](https://github.com/holographxyz/

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 9: M-3: Using `ERC721.transferFrom()` instead of `safeTransferFrom()` may cause the user's NFT to be frozen in a contract that does not support ERC721

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/55 

## Found by 
saian, rvierdiiev, WATCHPUG, Tomo, Bnke0x0, Nyx

## Summary

There are certain smart contracts that do not support ERC721, using `transferFrom()` may result in the NFT being sent to such contracts.

## Vulnerability Detail

In `unstake()`, `_to` is param from user's input.

However, if `_to` is a contract address that does not support ERC721, the NFT can be frozen in that contract.

As per the documentation of EIP-721:

> A wallet/broker/auction application MUST implement the wallet interface if it will accept safe transfers.

Ref: https://eips.ethereum.org/EIPS/eip-721

## Impact

The NFT may get stuck in the contract that does support ERC721.

## Code Snippet

https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L463-L489

## Tool used

Manual Review

## Recommendation

Consider using `safeTransferFrom()` instead of `transferFrom()`.

## Discussion

**zobront**

Fixed: https://github.com/Solidity-Guild/FrankenDAO/pull/10

---

### Example 10: M-2: Unsafe ERC20 methods

**Source**: Sherlock
**Protocol**: Telcoin
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-telcoin-judging/issues/82 

## Found by 
0x4non, 0xAgro, yixxas, 0xheynacho, Bnke0x0, WATCHPUG, aphak5010, rotcivegaf, Mukund, hickuphh3, pashov, hyh, Deivitto, rvierdiiev, eierina

## Summary

Using unsafe ERC20 methods can revert the transaction for certain tokens.

## Vulnerability Detail

There are many [Weird ERC20 Tokens](https://www.hacknote.co/17c261f7d8fWbdml/doc/182a568ab5cUOpDM) that won't work correctly using the standard `IERC20` interface.

For example, `IERC20(token).transferFrom()` and `IERC20(token).transfer()` will fail for some tokens as they may not conform to the standard IERC20 interface. And if `_aggregator` does not always consume all the allowance given at L72, the transaction will also revert on the next call, because there are certain tokens that do not allow approval of a non-zero number when the current allowance is not zero (eg, USDT).

## Impact

The contract will malfunction for certain tokens.

## Code Snippet

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/fee-buyback/FeeBuyback.sol#L94-L97

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/fee-buyback/FeeBuyback.sol#L47-L82

## Tool used

Manual Review

## Recommendation

Consider using `SafeERC20` for `transferFrom`, `transfer` and `approve`.

## Discussion

**amshirif**

https://github.com/telcoin/telcoin-staking/pull/6

---

### Example 11: [M-07] Using `transferFrom` on ERC721 tokens

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

_Submitted by shw_

In the function `awardExternalERC721` of contract `PrizePool`, when awarding external ERC721 tokens to the winners, the `transferFrom` keyword is used instead of `safeTransferFrom`. If any winner is a contract and is not aware of incoming ERC721 tokens, the sent tokens could be locked.

Recommend consider changing `transferFrom` to `safeTransferFrom` at line 602. However, it could introduce a DoS attack vector if any winner maliciously rejects the received ERC721 tokens to make the others unable to get their awards. Possible mitigations are to use a `try/catch` statement to handle error cases separately or provide a function for the pool owner to remove malicious winners manually if this happens.

**[asselstine (PoolTogether) confirmed and disagreed with severity](https://github.com/code-423n4/2021-06-pooltogether-findings/issues/115#issuecomment-868021913):**
 > This issue poses no risk to the Prize Pool, so it's more of a `1 (Low Risk` IMO.
>
> This is just about triggering a callback on the ERC721 recipient.  We omitted it originally because we didn't want a revert on the callback to DoS the prize pool.
>
> However, to respect the interface it makes sense to implement it fully.  That being said, if it does throw we must ignore it to prevent DoS attacks.

**[dmvt (judge) commented](https://github.com/code-423n4/2021-06-pooltogether-findings/issues/115#issuecomment-907507608):**
 > I agree with the medium risk rating provided by the warden.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-06-pooltogether)

---

### Example 12: [M-03] ERC20 tokens without return value will DoS reward claiming

**Source**: Pashov Audit Group
**Protocol**: Interpol_2024-12-24
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** Medium

**Likelihood:** Medium

## Description

Several functions throughout the application use the `transfer` function to transfer ERC20 tokens. However, some tokens do not return a `bool` on transfer, and since the ERC20 interface expects the `bool` return value, calling `transfer` on tokens that do not return a `bool` would revert. The following functions suffer from this issue:

- `withdrawERC20` in `HoneyLocker`
- `unstake` in `BeradromeAdapter`
- `unstake` in `BGTStationAdapter`
- `unstake` in `InfraredAdapter`
- `unstake` in `KodiakAdapter`

The following functions also call `transfer` on ERC20, but the call is wrapped in a try-catch block. However, such a call would still revert:

- `claim` in `BeradromeAdapter`
- `claim` in `InfraredAdapter`
- `claim` in `KodiakAdapter`

The impact is rated as medium since the issue can be resolved through a contract upgrade, though users would face a temporary freeze of their assets until the fix is deployed. The likelihood is high given that numerous widely-used tokens in the ecosystem don't strictly follow the ERC20 standard regarding return values.

## Recommendations

Consider using the `SafeTransfer` library for transferring ERC20 tokens. This can still make some transfers revert the whole transaction, therefore consider adding a function to pull tokens out separately.

Alternatively, consider implementing the safe transfer functionality in the adapters on your own and making it not revert on failure, 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Interpol-security-review_2024-12-24.md)

---

### Example 13: [M-03] Use safeTransfer()/safeTransferFrom() instead of transfer()/transferFrom()

**Source**: Code4rena
**Protocol**: Rubicon
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/RubiconRouter.sol#L251


## Vulnerability details

## Impact

It is a good idea to add a `require()` statement that checks the return value of ERC20 token transfers or to use something like OpenZeppelinâ€™s `safeTransfer()`/`safeTransferFrom()` unless one is sure the given token reverts in case of a failure. Failure to do so will cause silent failures of transfers and affect token accounting in contract.

However, using `require()` to check transfer return values could lead to issues with non-compliant ERC20 tokens which do not return a boolean value. Therefore, it's highly advised to use OpenZeppelinâ€™s `safeTransfer()`/`safeTransferFrom()`.

## Proof of Concept

**RubiconRouter.sol**

[L251](https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/RubiconRouter.sol#L251): `ERC20(route[route.length - 1]).transfer(to, currentAmount);`\
[L303](https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/RubiconRouter.sol#L303): `ERC20(buy_gem).transfer(msg.sender, fill);`\
[L320](https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/RubiconRouter.sol#L320): `ERC20(buy_gem).transfer(msg.sender, fill);`\
[L348](https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/RubiconRouter.sol#L34

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-rubicon)

---

### Example 14: [M-03] safeTransferFrom is recommended instead of transfer (1)

**Source**: Code4rena
**Protocol**: FactoryDAO
**Impact**: MEDIUM

**Details**:

_Submitted by MaratCerby, also found by berndartmueller, broccolirob, CertoraInc, cryptphi, danb, gzeon, horsefacts, hyh, joestakey, leastwood, throttle, VAD37, wuwe1, and z3s_

ERC20 standard allows transferF function of some contracts to return bool or return nothing.<br>
Some tokens such as USDT return nothing.<br>
This could lead to funds stuck in the contract without possibility to retrieve them.<br>
Using safeTransferFrom of SafeERC20.sol is recommended instead.<br>

### Proof of Concept

<https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4a9cc8b4918ef3736229a5cc5a310bdc17bf759f/contracts/token/ERC20/utils/SafeERC20.sol>

**[illuzen (FactoryDAO) commented](https://github.com/code-423n4/2022-05-factorydao-findings/issues/22#issuecomment-1121974704):**
 > We support ERC20 contracts, not SafeERC20. Contracts that do not conform to the standard are not supported.

**[illuzen (FactoryDAO) confirmed and resolved](https://github.com/code-423n4/2022-05-factorydao-findings/issues/22#issuecomment-1145530282):**
 > https://github.com/code-423n4/2022-05-factorydao/pull/2



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-factorydao)

---

## Statistics

- Total findings analyzed: 14
- Examples shown: 14
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## mint-vs-safemint-patterns.md
# mint vs safeMint Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 4 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, TrailOfBits

---

## Detection Checklist

- [ ] Check for mint vs safemint vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Minter user can conï¬scate any user tokens

**Source**: TrailOfBits
**Protocol**: Curve DAO
**Impact**: HIGH

**Details**:

## Auditing and Logging
**Type:** Auditing and Logging  
**Target:** ERC20CV.vy  

**Difficulty:** Low  

## Description
ERC20CVâ€™s minter has the unexpected right to move tokens from any users, increasing the risks associated with the minter account.

The administrator of the contract can design a special user called a minter:
```python
@public
def set_minter(_minter: address):
    assert msg.sender == self.admin  # dev: admin only
    self.minter = _minter
```
*Figure 7.1: ERC20CV.vy#L143-L146*  

This privileged user can be wielded to mint new tokens:
```python
@public
def mint(_to: address, _value: uint256):
    """
    @dev Mint an amount of the token and assigns it to an account.
    This encapsulates the modification of balances such that the
    proper events are emitted.
    @param _to The account that will receive the created tokens.
    @param _value The amount that will be created.
    """
    assert msg.sender == self.minter  # dev: minter only
    assert _to != ZERO_ADDRESS          # dev: zero address
    if block.timestamp >= self.start_epoch_time + RATE_REDUCTION_TIME:
        self._update_mining_parameters()
    _total_supply: uint256 = self.total_supply + _value
    assert _total_supply <= self._available_supply()  # dev: exceeds allowable mint amount
    self.total_supply = _total_supply
    self.balanceOf[_to] += _value
    log.Transfer(ZERO_ADDRESS, _to, _value)
```
*Figure 7.2: ERC20CRV.vy#L230-L250*  

However, it is also possible to use the minter to t

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/CurveDAO.pdf)

---

### Example 2: [M-10] Putty position tokens may be minted to non ERC721 receivers

**Source**: Code4rena
**Protocol**: Putty
**Impact**: MEDIUM

**Details**:

_Submitted by horsefacts, also found by 0xc0ffEE, 0xsanson, berndartmueller, BowTiedWardens, csanuragjain, defsec, IllIllI, joestakey, Kenshin, Picodes, shenwilly, Sm4rty, unforgiven, and xiaoming90_

<https://github.com/code-423n4/2022-06-putty/blob/3b6b844bc39e897bd0bbb69897f2deff12dc3893/contracts/src/PuttyV2.sol#L302-L308>

<https://github.com/code-423n4/2022-06-putty/blob/3b6b844bc39e897bd0bbb69897f2deff12dc3893/contracts/src/PuttyV2Nft.sol#L11-L18>

### Vulnerability Details

Putty uses ERC721 `safeTransfer` and `safeTransferFrom` throughout the codebase to ensure that ERC721 tokens are not transferred to non ERC721 receivers. However, the initial position mint in `fillOrder` uses `_mint` rather than `_safeMint` and does not check that the receiver accepts ERC721 token transfers:

[`PuttyV2#fillOrder`](https://github.com/code-423n4/2022-06-putty/blob/3b6b844bc39e897bd0bbb69897f2deff12dc3893/contracts/src/PuttyV2.sol#L302-L308)

```solidity
        // create long/short position for maker
        _mint(order.maker, uint256(orderHash));

        // create opposite long/short position for taker
        bytes32 oppositeOrderHash = hashOppositeOrder(order);
        positionId = uint256(oppositeOrderHash);
        _mint(msg.sender, positionId);
```

[`PuttyV2Nft#_mint`](https://github.com/code-423n4/2022-06-putty/blob/3b6b844bc39e897bd0bbb69897f2deff12dc3893/contracts/src/PuttyV2Nft.sol#L11-L18)

```solidity
    function _mint(address to, uint256 id) internal override {
      

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-putty)

---

### Example 3: M-1: [Tomo-M3] Use safeMint instead of mint for ERC721

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/65 

## Found by 
Tomo

## Summary

Use safeMint instead of mint for ERC721

## Vulnerability Detail

TheÂ `msg.sender`Â will be minted as a proof of staking NFT whenÂ `_stakeToken()`Â is called. 

However, ifÂ `msg.sender` is a contract address that does not support ERC721, the NFT can be frozen in the contract.

As per the documentation of EIP-721:

> A wallet/broker/auction application MUST implement the wallet interface if it will accept safe transfers.
> 

Ref:Â [https://eips.ethereum.org/EIPS/eip-721](https://eips.ethereum.org/EIPS/eip-721)

As per the documentation of ERC721.sol by Openzeppelin

Ref: [https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L274-L285](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L274-L285)

```solidity
/**
 * @dev Mints `tokenId` and transfers it to `to`.
 *
 * WARNING: Usage of this method is discouraged, use {_safeMint} whenever possible
 *
 * Requirements:
 *
 * - `tokenId` must not exist.
 * - `to` cannot be the zero address.
 *
 * Emits a {Transfer} event.
 */
function _mint(address to, uint256 tokenId) internal virtual {
```

## Impact

Users possibly lose their NFTs

## Code Snippet
https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L411
``` solidity
  _mint(msg.sender, _tokenId);
```
## Tool used

Manual Review

## Recommendation

Us

*[Content truncated...]*

---

### Example 4: [M-07] NFT of NFT collection or NFT drop collection can be locked when calling _mint or mintCountTo function to mint it to a contract that does not support ERC721 protocol

**Source**: Code4rena
**Protocol**: Foundation
**Impact**: MEDIUM

**Details**:

_Submitted by rbserver, also found by 0xc0ffEE, 0xsolstars, berndartmueller, Bnke0x0, brgltd, cccz, CodingNameKiki, Deivitto, Diraco, Dravee, durianSausage, erictee, ignacio, IllIllI, joestakey, KIntern&#95;NA, Lambda, LeoS, Noah3o6, oyc&#95;109, ReyAdmirado, Rohan16, Rolezn, Sm4rty, Treasure-Seeker, zeesaw, and zkhorse_

<https://github.com/code-423n4/2022-08-foundation/blob/main/contracts/NFTCollection.sol#L262-L274>

<https://github.com/code-423n4/2022-08-foundation/blob/main/contracts/NFTDropCollection.sol#L171-L187>

### Impact

When calling the following `_mint` or `mintCountTo` function for minting an NFT of a NFT collection or NFT drop collection, the OpenZeppelin's `ERC721Upgradeable` contract's [`_mint`](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/token/ERC721/ERC721Upgradeable.sol#L284-L296) function is used to mint the NFT to a receiver. If such receiver is a contract that does not support the ERC721 protocol, the NFT will be locked and cannot be retrieved.

<https://github.com/code-423n4/2022-08-foundation/blob/main/contracts/NFTCollection.sol#L262-L274>

      function _mint(string calldata tokenCID) private onlyCreator returns (uint256 tokenId) {
        require(bytes(tokenCID).length != 0, "NFTCollection: tokenCID is required");
        require(!cidToMinted[tokenCID], "NFTCollection: NFT was already minted");
        unchecked {
          // Number of tokens cannot overflow 256 bits.
          tokenId = ++latestToke

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-foundation)

---

### Example 5: M-7: Minting inconsistencies on FootiumPlayer and FootiumClub

**Source**: Sherlock
**Protocol**: Footium
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-footium-judging/issues/342 

## Found by 
0xAsen, 0xHati, 0xLook, 0xPkhatri, 0xRobocop, 0xStalin, 0xeix, 0xhacksmithh, BAHOZ, Bauchibred, Bauer, Dug, GalloDaSballo, Koolex, PTolev, Phantasmagoria, TheNaubit, Tricko, ali\_shehab, cergyk, chaithanya\_gali, ctf\_sec, cuthalion0x, deadrxsezzz, descharre, indijanc, jasonxiale, kiki\_dev, lewisbroadhurst, nzm\_, oualidpro, sashik\_eth, shame, shogoki, tsueti\_, tsvetanovv, wzrdk3lly
## Summary

The `FootiumClub.sol` contract when minting uses `_mint()` instead of `_safeMint()` which can cause to mint a club to a contract who does not support nfts. On the other hand `FootiumPlayer.sol` uses `_safeMint()`.

## Vulnerability Detail

See summary.

## Impact

`FootiumClub.sol` might mint a club NFT to a contract that cannot handle nfts.

## Code Snippet

https://github.com/sherlock-audit/2023-04-footium/blob/main/footium-eth-shareable/contracts/FootiumClub.sol#L65

## Tool used

Manual Review

## Recommendation

Use `_safeMint()` as in FootiumPlayer.

---

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## token-existence-patterns.md
# Token Existence Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 4 | 0 | 0 |

**Common Sources**: Code4rena

---

## Detection Checklist

- [ ] Check for token existence vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-06] OperateProxy.callFunction() should check if the callee is a contract

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

### Example 2: [M-17] The tokenURI method does not check if the NFT has been minted and returns data for the contract that may be a fake NFT

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/Factory.sol#L161
https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/PrivatePoolMetadata.sol#L17


## Vulnerability details

## Impact

- By invoking the [Factory.tokenURI](https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/Factory.sol#L161) method for a maliciously provided NFT id, the returned data may deceive potential users, as the method will return data for a non-existent NFT id that appears to be a genuine PrivatePool. This can lead to a poor user experience or financial loss for users.
- Violation of the [ERC721-Metadata part](https://eips.ethereum.org/EIPS/eip-721) standard

## Proof of Concept

- The [Factory.tokenURI](https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/Factory.sol#L161) and [PrivatePoolMetadata.tokenURI](https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/PrivatePoolMetadata.sol#L17) methods lack any requirements stating that the provided NFT id must be created. We can also see that in the standard implementation by [OpenZeppelin](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/cf86fd9962701396457e50ab0d6cc78aa29a5ebc/contracts/token/ERC721/ERC721.sol#L94), this check is present:
- [Throws if `_tokenId` is not a valid NFT](https://eips.ethereum.org/EIPS/ei

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-caviar)

---

### Example 3: [M-03] Put option sellers can prevent exercise by specifying zero amounts, or non-existant tokens

**Source**: Code4rena
**Protocol**: Putty
**Impact**: MEDIUM

**Details**:

_Submitted by IllIllI, also found by 0xNineDec, exd0tpy, and zzzitron_

Put option buyers pay an option premium to the seller for the privilege of being able to 'put' assets to the seller and get the strike price for it rather than the current market price. If they're unable to perform the 'put', they've paid the premium for nothing, and essentially have had funds stolen from them.

### Proof of Concept

If the put option seller includes in `order.erc20Assets`, an amount of zero for any of the assets, or specifies an asset that doesn't currently have any code at its address, the put buyer will be unable to exercise the option, and will have paid the premium for nothing:

```solidity
File: contracts/src/PuttyV2.sol   #1

453               // transfer assets from exerciser to putty
454               _transferERC20sIn(order.erc20Assets, msg.sender);
```

<https://github.com/code-423n4/2022-06-putty/blob/3b6b844bc39e897bd0bbb69897f2deff12dc3893/contracts/src/PuttyV2.sol#L453-L454>

The function reverts if any amount is equal to zero, or the asset doesn't exist:

```solidity
File: contracts/src/PuttyV2.sol   #2

593       function _transferERC20sIn(ERC20Asset[] memory assets, address from) internal {
594           for (uint256 i = 0; i < assets.length; i++) {
595               address token = assets[i].token;
596               uint256 tokenAmount = assets[i].tokenAmount;
597   
598               require(token.code.length > 0, "ERC20: Token is not contract");
599               requ

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-putty)

---

### Example 4: [M-25] Vault can be created for not-yet-existing ERC20 tokens, which allows attackers to set traps to steal NFTs from Borrowers

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

There is a subtle difference between the implementation of solmateâ€™s SafeTransferLib and OZâ€™s SafeERC20: OZâ€™s SafeERC20 checks if the token is a contract or not, solmateâ€™s SafeTransferLib does not.<br>
See: <https://github.com/Rari-Capital/solmate/blob/main/src/utils/SafeTransferLib.sol#L9><br>
Note that none of the functions in this library check that a token has code at all! That responsibility is delegated to the caller.<br>
As a result, when the tokenâ€™s address has no code, the transaction will just succeed with no error.<br>
This attack vector was made well-known by the qBridge hack back in Jan 2022.

In AstariaRouter, Vault, PublicVault, VaultImplementation, ClearingHouse, TransferProxy, and WithdrawProxy, the `safetransfer` and `safetransferfrom` don't check the existence of code at the token address. This is a known issue while using solmateâ€™s libraries.

Hence this can lead to miscalculation of funds and also loss of funds , because if safetransfer() and safetransferfrom() are called on a token address that doesnâ€™t have contract in it, it will always return success. Due to this protocol will think that funds has been transferred and successful , and records will be accordingly calculated, but in reality funds were never transferred.

So this will lead to miscalculation and loss of funds.

### Attack scenario (example):

Itâ€™s becoming popular for protocols to deploy their token across multiple networks and when they do so, a common practice is to deploy the token cont

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


