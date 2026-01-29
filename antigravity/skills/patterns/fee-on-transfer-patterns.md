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
