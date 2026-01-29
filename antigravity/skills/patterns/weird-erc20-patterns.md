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

The internal [`_deposit`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/BaseVault.sol#L407) function handles user deposits, transferring a specified amount of `stETH` from `msg.sender` to the vault. Before moving the funds, it adds the deposit to the queue, which is processed later by the [`processQueuedDeposits`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/BaseVault.sol#L371) function.


As the underlying token could have hooks that allow the token sender to execute code before the transfer (e.g., ERC777 standard), a malicious user could use those hooks to re-enter the `deposit` function multiple times.


This re-entrancy will result in an increment in the receiver balance on the queue, even though this balance will not correspond to the actual amount deposited into the vault.


In the current implementation, the `_deposit` function in the `BaseVault` contract is overridden by the [implementation in the `STETHVault`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/STETHVault.sol#L113-L126), which has the correct order of operation. However, the `BaseVault` is likely to be inherited by future vaults, so it is crucial to have the correct `_deposit` implementation in this contract in case it is not overridden.


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

The `_bidCollaterals` mapping of `CollateralManager` records the `CollateralInfo` of each bidId. This structure records the collateral information provided by the user when creating a bid for a loan. A lender can accept a loan by calling  `TellerV2.lenderAcceptBid` that will eventually transfer the user's collateral from the user address to the CollateralEscrowV1 contract corresponding to the loan. The whole process will deduct fee twice.

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

The vault implements a [`mintWithPermit`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/BaseVault.sol#L131) and [`depositWithPermit`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/vaults/BaseVault.sol#L106) function intended to allow users to transfer assets to the vault in a single transaction. However, the vault’s underlying asset is intended to be [stETH](https://etherscan.io/address/0x47ebab13b806773ec2a2d16873e2df770d130b50#code#F10#L50) which does not have a `permit` function. Currently, any user who tries to perform a `mintWithPermit` or `depositWithPermit` will have their transaction reverted due to the stETH contract’s [fallback](https://etherscan.io/address/0x47ebab13b806773ec2a2d16873e2df770d130b50#code#F1#L279) function.


Consider removing the `mintWithPermit` and `depositWithPermit` functions. We note that [wstETH](https://etherscan.io/token/0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0#code#L965) does have a permit function for future considerations.


***Update:** Acknowledged, and will not fix. Pods Finance team’s statement for this issue:*



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
