# Deposit/Reward tokens Security Patterns

## Overview

**Frequency**: 18 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 13 | 5 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Pashov Audit Group, Cyfrin, Spearbit

---

## Detection Checklist

- [ ] Check for deposit/reward tokens vulnerabilities in all external functions
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

### Example 2: [H-02] Malicious Users Can Transfer Vault Collateral To Other Accounts To Extract Additional Yield From The Protocol

**Source**: Code4rena
**Protocol**: Yield
**Impact**: HIGH

**Details**:

_Submitted by leastwood_

`ConvexYieldWrapper.sol` is a wrapper contract for staking convex tokens on the user's behalf, allowing them to earn rewards on their deposit. Users will interact with the `Ladle.sol` contract's `batch()` function which:

*   Approves Ladle to move the tokens.
*   Transfers the tokens to `ConvexYieldWrapper.sol`.
*   Wraps/stakes these tokens.
*   Updates accounting and produces debt tokens within `Ladle.sol`.

`_getDepositedBalance()` takes into consideration the user's total collateral stored in all of their owned vaults. However, as a vault owner, you are allowed to give the vault to another user, move collateral between vaults and add/remove collateral. Therefore, it is possible to manipulate the result of this function by checkpointing one user's balance at a given time, transferring ownership to another user and then create a new checkpoint with this user.

As a result, a user is able to generate protocol yield multiple times over on a single collateral amount. This can be abused to effectively extract all protocol yield.

#### Proof of Concept

Consider the following exploit scenario:

*   Alice owns a vault which has 100 tokens worth of collateral.
*   At that point in time, `_getDepositedBalance()` returns 100 as its result. A checkpoint has also been made on this balance, giving Alice claim to her fair share of the rewards.
*   Alice then calls `Ladle.give()`, transferring the ownership of the vault to Bob and calls `ConvexYieldWrapper.addV

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-yield)

---

### Example 3: [H-02] Tokens can be stolen when depositToken == rewardToken

**Source**: Code4rena
**Protocol**: Streaming Protocol
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `Streaming` contract allows the `deposit` and `reward` tokens to be the same token.

> I believe this is intended, think Sushi reward on Sushi as is the case with `xSushi`.

The reward and deposit balances are also correctly tracked independently in `depositTokenAmount` and `rewardTokenAmount`.
However, when recovering tokens this leads to issues as the token is recovered twice, once for deposits and another time for rewards:

```solidity
function recoverTokens(address token, address recipient) public lock {
    // NOTE: it is the stream creators responsibility to save
    // tokens on behalf of their users.
    require(msg.sender == streamCreator, "!creator");
    if (token == depositToken) {
        require(block.timestamp > endDepositLock, "time");
        // get the balance of this contract
        // check what isnt claimable by either party
        // @audit-info depositTokenAmount updated on stake/withdraw/exit, redeemedDepositTokens increased on claimDepositTokens
        uint256 excess = ERC20(token).balanceOf(address(this)) - (depositTokenAmount - redeemedDepositTokens);
        // allow saving of the token
        ERC20(token).safeTransfer(recipient, excess);

        emit RecoveredTokens(token, recipient, excess);
        return;
    }
    
    if (token == rewardToken) {
        require(block.timestamp > endRewardLock, "time");
        // check current balance vs internal balance
        //
        // NOTE: if a 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-streaming)

---

### Example 4: H-3: LP tokens are not sent back to withdrawing user

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/151 

## Found by 
rvierdiiev, minhtrng, Dug, Jeiwan, obront, chaduke, koxuan, sinarette, Ch\_301, cergyk, evan, berndartmueller, 0x52, Bauer

## Summary

When users withdraw their assets from `IchiVaultSpell.sol`, the function unwinds their position and sends them back their assets, but it never sends them back the amount they requested to withdraw, leaving the tokens stuck in the Spell contract.

## Vulnerability Detail

When a user withdraws from `IchiVaultSpell.sol`, they either call `closePosition()` or `closePositionFarm()`, both of which make an internal call to `withdrawInternal()`.

The following arguments are passed to the function:
- strategyId: an index into the `strategies` array, which specifies the Ichi vault in question
- collToken: the underlying token, which is withdrawn from Compound
- amountShareWithdraw: the number of underlying tokens to withdraw from Compound
- borrowToken: the token that was borrowed from Compound to create the position, one of the underlying tokens of the vault
- amountRepay: the amount of the borrow token to repay to Compound
- amountLpWithdraw: the amount of the LP token to withdraw, rather than trade back into borrow tokens

In order to accomplish these goals, the contract does the following...

1) Removes the LP tokens from the ERC1155 holding them for collateral.
```solidity
doTakeCollateral(strategies[strategyId].vault, lpTakeAmt);
```
2) Calculates the n

*[Content truncated...]*

---

### Example 5: H-2: Users who deposit extra funds into their Ichi farming positions will lose all their ICHI rewards

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/158 

## Found by 
carrot, rvierdiiev, minhtrng, obront, sinarette, tives, berndartmueller, 0x52

## Summary

When a user deposits extra funds into their Ichi farming position using `openPositionFarm()`, the old farming position will be closed down and a new one will be opened. Part of this process is that their ICHI rewards will be sent to the `IchiVaultSpell.sol` contract, but they will not be distributed. They will sit in the contract until the next user (or MEV bot) calls `closePositionFarm()`, at which point they will be stolen by that user.

## Vulnerability Detail

When Ichi farming positions are opened via the `IchiVaultSpell.sol` contract, `openPositionFarm()` is called. It goes through the usual deposit function, but rather than staking the LP tokens directly, it calls `wIchiFarm.mint()`. This function deposits the token into the `ichiFarm`, encodes the deposit as an ERC1155, and sends that token back to the Spell:
```solidity
function mint(uint256 pid, uint256 amount)
    external
    nonReentrant
    returns (uint256)
{
    address lpToken = ichiFarm.lpToken(pid);
    IERC20Upgradeable(lpToken).safeTransferFrom(
        msg.sender,
        address(this),
        amount
    );
    if (
        IERC20Upgradeable(lpToken).allowance(
            address(this),
            address(ichiFarm)
        ) != type(uint256).max
    ) {
        // We only need to do this once per pool, as LP token's all

*[Content truncated...]*

---

### Example 6: H-1: Too few `ICHI` v2 farming reward tokens transferred to the user due to incorrect decimal precision

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/319 

## Found by 
berndartmueller, 0x52

## Summary

The `burn` function in the `WIchiFarm` contract transfers too few `ICHI` **v2** farming reward tokens to the caller due to using 9 decimals instead of 18 decimals for the `ICHI` **v2** token.

## Vulnerability Detail

Closing an ICHI vault spell farming position burns the wrapped ICHI vault LP tokens (`WIchiFarm` ERC-1155 tokens). Farming rewards are harvested from the ICHI farm ([see contract on Etherscan](https://etherscan.io/address/0x275dfe03bc036257cd0a713ee819dbd4529739c8)) and received as `ICHI` **v1** tokens.

The `ICHI` **v1** ERC-20 token uses **9 decimals** ([see token on Etherscan](https://etherscan.io/token/0x903bEF1736CDdf2A537176cf3C64579C3867A881)), whereas the `ICHI` **v2** ERC-20 token uses **18 decimals** ([see token on Etherscan](https://etherscan.io/token/0x111111517e4929D3dcbdfa7CCe55d30d4B6BC4d6)).

Those received `ICHI` **v1** tokens are then converted to **v2** tokens in line 134.

To calculate the user's share of eligible `ICHI` **v2** reward tokens, the reward per share accumulator `stIchiPerShare` at the time of minting the `WIchiFarm` token and the current `enIchiPerShare` accumulator is used.

However, those accumulator values are in **9 decimals** precision (please see the `ichiFarmV2.harvest` function for proof that `pool.accIchiPerShare` uses 9 decimals, otherwise the `ICHI` token transfer would fail due to inflated 

*[Content truncated...]*

---

### Example 7: [H-01] Holders array can be manipulated by transferring or burning with amount 0, stealing rewards or bricking certain functions

**Source**: Code4rena
**Protocol**: Althea Liquid Infrastructure
**Impact**: HIGH

**Details**:

### Lines of code

<https://github.com/code-423n4/2024-02-althea-liquid-infrastructure/blob/main/liquid-infrastructure/contracts/LiquidInfrastructureERC20.sol#L214-L231>

### Impact

`LiquidInfrastructureERC20._beforeTokenTransfer()` checks if the `to` address has a balance of `0`, and if so, adds the address to the holders array.

[LiquidInfrastructureERC20#L142-145](https://github.com/code-423n4/2024-02-althea-liquid-infrastructure/blob/main/liquid-infrastructure/contracts/LiquidInfrastructureERC20.sol#L142-L145)

```solidity
bool exists = (this.balanceOf(to) != 0);
if (!exists) {
    holders.push(to);
}
```

However, the ERC20 contract allows for transferring and burning with `amount = 0`, enabling users to manipulate the holders array.

An approved user that has yet to receive tokens can initiate a transfer from another address to themself with an amount of `0`. This enables them to add their address to the holders array multiple times. Then, `LiquidInfrastructureERC20.distribute()` will loop through the user multiple times and give the user more rewards than it should.

```solidity
for (i = nextDistributionRecipient; i < limit; i++) {
    address recipient = holders[i];
    if (isApprovedHolder(recipient)) {
        uint256[] memory receipts = new uint256[](
            distributableERC20s.length
        );
        for (uint j = 0; j < distributableERC20s.length; j++) {
            IERC20 toDistribute = IERC20(distributableERC20s[j]);
            uint256 entitlement = er

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-02-althea-liquid-infrastructure)

---

### Example 8: H-1: attackers will keep stealing the `rewards` from Convex SPELL

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/101 

## Found by 
Bauer, Ch\_301
## Summary
On [WConvexPools.burn()](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WConvexPools.sol#L201-L235) transfer [CRV + CVX + the extra rewards](https://docs.convexfinance.com/convexfinance/general-information/why-convex/convex-for-liquidity-providers) to Convex SPELL 


## Vulnerability Detail
But [ConvexSpell.openPositionFarm()](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ConvexSpell.sol#L67-L138) only refund CVX to the user.
So the rest rewards will stay in the SPELL intel if someone (could be an attacker) invokes `_doRefund()` within `closePositionFarm()` with the same address tokens 

## Impact
- Convex SPELL steals the user rewards 
- the protocol will lose some fees 
- attackers will keep stealing the rewards from Convex SPELL

## Code Snippet
`WConvexPools.burn()` transfer CRV + CVX + the extra rewards
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WConvexPools.sol#L201-L235
```solidity
        // Transfer LP Tokens
        IERC20Upgradeable(lpToken).safeTransfer(msg.sender, amount);

        // Transfer Reward Tokens
        (rewardTokens, rewards) = pendingRewards(id, amount);

        for (uint i = 0; i < rewardTokens.length; i++) {
            IERC20Upgradeable(rewardTokens[i]).safeTransfer(
                

*[Content truncated...]*

---

### Example 9: H-10: Immediately start getting rewards belonging to others after staking

**Source**: Sherlock
**Protocol**: Tokemak
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/603 

## Found by 
0x73696d616f, 0xGoodess, 0xJuda, 0xTheC0der, 0xdeadbeef, 0xvj, Ch\_301, Kalyan-Singh, MrjoryStewartBaxter, VAD37, berndartmueller, bin2chen, caelumimperium, carrotsmuggler, jecikpo, l3r0ux, lemonmon, pengun, saidam017, talfao, wangxx2026, xiaoming90

Malicious users could abuse the accounting error to immediately start getting rewards belonging to others after staking, leading to a loss of reward tokens.

## Vulnerability Detail

> **Note**
> This issue affects both LMPVault and DV since they use the same underlying reward contract.

Assume a new user called Bob mints 100 LMPVault or DV shares. The ERC20's `_mint` function will be called, which will first increase Bob's balance at Line 267 and then trigger the `_afterTokenTransfer` hook at Line 271.

https://github.com/OpenZeppelin/openzeppelin-contracts/blob/0457042d93d9dfd760dbaa06a4d2f1216fdbe297/contracts/token/ERC20/ERC20.sol#L259

```solidity
File: ERC20.sol
259:     function _mint(address account, uint256 amount) internal virtual {
..SNIP..
262:         _beforeTokenTransfer(address(0), account, amount);
263: 
264:         _totalSupply += amount;
265:         unchecked {
266:             // Overflow not possible: balance + amount is at most totalSupply + amount, which is checked above.
267:             _balances[account] += amount;
268:         }
..SNIP..
271:         _afterTokenTransfer(address(0), account, amount);
272:     }
`

*[Content truncated...]*

---

### Example 10: [H-01] Malicious Users Can Duplicate Protocol Earned Yield By Transferring wCVX Tokens To Another Account

**Source**: Code4rena
**Protocol**: Yield
**Impact**: HIGH

**Details**:

## Handle

leastwood


## Vulnerability details

## Impact

`ConvexYieldWrapper.sol` is a wrapper contract for staking convex tokens on the user's behalf, allowing them to earn rewards on their deposit. Users will interact with the `Ladle.sol` contract's `batch()` function which:
- Approves Ladle to move the tokens.
- Transfers the tokens to `ConvexYieldWrapper.sol`.
- Wraps/stakes these tokens.
- Updates accounting and produces debt tokens within `Ladle.sol`.

During `wrap()` and `unwrap()` actions, `_checkpoint()` is used to update the rewards for the `from_` and `to_` accounts. However, the [reference](https://github.com/convex-eth/platform/blob/main/contracts/contracts/wrappers/ConvexStakingWrapper.sol#L395-L397) contract implements a `_beforeTokenTransfer()` function which has been removed from Yield Protocol's custom implementation.

As a result, it is possible to transfer `wCVX` tokens to another account after an initial checkpoint has been made. By manually calling `user_checkpoint()` on the new account, this user is able to update its deposited balance of the new account while the sender's balance is not updated. This can be repeated to effectively replicate a user's deposited balance over any number of accounts. To claim yield generated by the protocol, the user must only make sure that the account calling `getReward()` holds the tokens for the duration of the call.

## Proof of Concept

The exploit can be outlined through the following steps:
- Alice receives 100 `

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-yield)

---

### Example 11: H-4: Fail to accrue interests on multiple token positions

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/140 

## Found by 
cducrest-brainbot, rvierdiiev, Jeiwan

## Summary

In `BlueBerryBank.sol` the functions `borrow`, `repay`, `lend`, or `withdrawLend` call `poke(token)` to trigger interest accrual on concerned token, but fail to do so for other token debts of the concerned position.  This could lead to wrong calculation of position's debt and whether the position is liquidatable.

## Vulnerability Detail

Whether a position is liquidatable or not is checked at the end of the `execute` function, the execution should revert if the position is liquidatable. 

The calculation of whether a position is liquidatable takes into account all the different debt tokens within the position. However, the debt accrual has been triggered only for one of these tokens, the one concerned by the executed action. For other tokens, the value of `bank.totalDebt` will be lower than what it should be. This results in the debt value of the position being lower than what it should be and a position seen as not liquidatable while it should be liquidatable. 

## Impact

Users may be able to operate on their position leading them in a virtually liquidatable state while not reverting as interests were not applied. This will worsen the debt situation of the bank and lead to overall more liquidatable positions.

## Code Snippet

execute checking isLiquidatable without triggering interests:

https://github.com/sherlock-audit/2023-02-

*[Content truncated...]*

---

### Example 12: Non-standard ERC20 tokens are not supported

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

### Example 13: H-1: AuraSpell#openPositionFarm fails to return all rewards to user

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

### Example 14: M-3: The protocol  will not be able to add liquidity on the curve with another token with a balance.

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/47 

## Found by 
Bauer, nobody2018
## Summary
The `CurveSpell` protocol only ensure approve curve pool to spend its borrow token. Hence, it will not be able to add liquidity on the curve with another token with a balance.

## Vulnerability Detail
The  `openPositionFarm()` function enables user to open a leveraged position in a yield farming strategy by borrowing funds and using them to add liquidity to a Curve pool, while also taking into account certain risk management parameters such as maximum LTV and position size. When add liquidity on curve ,the protocol use the borrowed token and the collateral token, it checks the number of tokens in the pool and creates an array of the supplied token amounts to be passed to the add_liquidity function. Then the curve will transfer the tokens from the protocol and mint lp tokens to the protocol. However, the protocol only ensure approve curve pool to spend its borrow token. Hence, it will not be able to add liquidity on the curve with another token with a balance.
```solidity
 // 3. Add liquidity on curve
        _ensureApprove(param.borrowToken, pool, borrowBalance);
        if (tokens.length == 2) {
            uint256[2] memory suppliedAmts;
            for (uint256 i = 0; i < 2; i++) {
                suppliedAmts[i] = IERC20Upgradeable(tokens[i]).balanceOf(
                    address(this)
                );
            }
            ICurvePool(pool).add_

*[Content truncated...]*

---

### Example 15: claimToTreasury(COMP) steals users' COMP rewards

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: MEDIUM

**Details**:

## Security Report

## Severity
**Medium Risk**

## Context
`compound/MorphoGovernance.sol#L414`

## Description
The `claimToTreasury` function can send a market's underlying tokens that have been accumulated in the contract to the treasury. This is intended to be used for the reserve amounts that accumulate in the contract from P2P matches. However, Compound also pays out rewards in COMP, and COMP is a valid Compound market. 

Sending the COMP reserves will also send the COMP rewards. This is especially concerning as anyone can claim COMP rewards on behalf of Morpho at any time, and the rewards will be sent to the contract. An attacker could even frontrun a `claimToTreasury(cCOMP)` call with a `Comptroller.claimComp(morpho, [cComp])` call to sabotage the reward system, resulting in users being unable to claim their rewards.

## Recommendation
If Morpho wants to support the COMP market, consider separating the COMP reserve from the COMP rewards.

## Morpho Response
Given the changes required and the small likelihood of setting a reserve factor for the COMP asset, and our awareness of this issue, we have decided not to implement it.

## Spearbit Response
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/MorphoV1-Spearbit-Security-Review.pdf)

---

### Example 16: H-3: Users are forced to swap all reward tokens with no slippage protection

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/121 

## Found by 
0x52, Bauer, Breeje, J4de, ctf\_sec, n1punp, nobody2018
## Summary

AuraSpell forces users to swap their reward tokens to debt token but doesn't allow them to specify any slippage values.

## Vulnerability Detail

[AuraSpell.sol#L193-L203
](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L193-L203)

        for (uint256 i = 0; i < rewardTokens.length; i++) {
            uint256 rewards = _doCutRewardsFee(rewardTokens[i]);
            _ensureApprove(rewardTokens[i], address(swapRouter), rewards);
            swapRouter.swapExactTokensForTokens(
                rewards,
                0,
                swapPath[i],
                address(this),
                type(uint256).max
            );
        }

Above all reward tokens are swapped and always use 0 for min out meaning that deposits will be sandwiched and stolen.

## Impact

All reward tokens can be sandwiched and stolen

## Code Snippet

[AuraSpell.sol#L149-L224](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L149-L224)

## Tool used

Manual Review

## Recommendation

Allow user to specify slippage parameters for all reward tokens

---

### Example 17: [M-01] Minting of `fToken` and `xToken` allowed during stability mode

**Source**: Pashov Audit Group
**Protocol**: RWf(x)_2025-08-20
**Impact**: MEDIUM

**Details**:

_Resolved_

## Severity

**Impact:** Medium  

**Likelihood:** Medium  

## Description

The `Market.mint()` function mints both fToken and xToken [based on the current collateral ratio](https://github.com/RegnumAurumAcquisitionCorp/fx-contracts/blob/main/contracts/f(x)/math/FxLowVolatilityMath.sol#L293-L307).  
In the original Aladdin implementation, this function could be called only once. However, RegnumFx [removed this restriction](https://github.com/RegnumAurumAcquisitionCorp/fx-contracts/compare/bbb461cba879349c24c02d87872e93ec0a1a1975...f6e865df2dd46d67a49391d94e54b26e6a8af43c#diff-2c8d19ba3d13b72d110c2a9536e5e9915118ad919b38848357200e91afb683faL252), allowing it to be called multiple times.

When the system enters stability mode, the collateral ratio has fallen below the defined safe threshold. This indicates that additional base tokens need to be deposited to restore the ratio.

Allowing `mint()` during stability mode worsens the problem: each new mint increases the number of fTokens in circulation, which in turn raises the amount of base tokens required to bring the system back to a healthy state. As a result, recovery becomes more difficult, and the system may remain undercollateralized for longer.

The severity chosen for this issue is medium, because only whitelisted managers can use the function, and they are trusted entities that are not interested in making stablecoin depeg.

## Recommendations

Restrict `mint()` from being called when the system is in stabili

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/RWf(x)-security-review_2025-08-20.md)

---

### Example 18: M-12: rewardTokens removed from WAuraPool/WConvexPools will be lost forever

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/128 

## Found by 
0x52
## Summary

pendingRewards pulls a fresh count of reward tokens each time it is called. This is problematic if reward tokens are ever removed from the the underlying Aura/Convex pools because it means that they will no longer be distributed and will be locked in the contract forever.

## Vulnerability Detail

[WAuraPools.sol#L166-L189](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L166-L189)

        uint extraRewardsCount = IAuraRewarder(crvRewarder)
            .extraRewardsLength();
        tokens = new address[](extraRewardsCount + 1);
        rewards = new uint256[](extraRewardsCount + 1);

        tokens[0] = IAuraRewarder(crvRewarder).rewardToken();
        rewards[0] = _getPendingReward(
            stCrvPerShare,
            crvRewarder,
            amount,
            lpDecimals
        );

        for (uint i = 0; i < extraRewardsCount; i++) {
            address rewarder = IAuraRewarder(crvRewarder).extraRewards(i);
            uint256 stRewardPerShare = accExtPerShare[tokenId][i];
            tokens[i + 1] = IAuraRewarder(rewarder).rewardToken();
            rewards[i + 1] = _getPendingReward(
                stRewardPerShare,
                rewarder,
                amount,
                lpDecimals
            );
        }

In the lines above we can see that only tokens that are currently available 

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 18
- Examples shown: 18
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
