# Decimals Security Patterns

## Overview

**Frequency**: 45 occurrences (0.09% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 21 | 23 | 1 | 0 |

**Common Sources**: Sherlock, Code4rena, Spearbit, Cyfrin, Hans

---

## Detection Checklist

- [ ] Check for decimals vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Loss of Long-Term Swap Proceeds Likely in Pools With Decimal or Price Imbalances

**Source**: Spearbit
**Protocol**: Cron Finance
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
`VirtualOrders.sol#L166`

## Description
This TWAMM implementation tracks the proceeds of long-term swaps efficiently via accumulated values called "scaled proceeds" for each token. In every order block interval (OBI), the scaled proceeds for e.g. the sale of token 0 are incremented by:

```
(quantity of token 1 purchased during the OBI) * 264 = (sales rate of token 0 during the OBI)
```

Then the proceeds of any specific long-term swap can be computed as the product of the difference between the scaled proceeds at the current block (or the expiration block of the order if filled) and the last block for which proceeds were claimed for the order and the order's sales rate, divided by 264:

```
last := min(currentBlock, orderExpiryBlock)
prev := block of last proceeds collection, or block order was placed in if this is the first withdrawal
LT swap proceeds = (scaledProceeds[last] - scaledProceeds[prev]) * (order.salesRate) / 264
```

The value 264 is referred to as the "scaling factor" and is intended to reduce precision loss in the division to determine the increment to the scaled proceeds.

The addition to increment the scaled proceeds and the subtraction to compute its net change is both intentionally done with unchecked arithmeticsince only the difference matters, so long as at most one overflow occurs between claim-of-proceeds events for any given order, the computed proceeds will be correct (up to rounding errors). If two or more overfl

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/CronFinance-Spearbit-Security-Review.pdf)

---

### Example 2: [H-08] Vault.withdraw mixes normalized and standard amounts

**Source**: Code4rena
**Protocol**: yAxis
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `Vault.balance` function uses the `balanceOfThis` function which scales ("normalizes") all balances to 18 decimals.

```
for (uint8 i; i < _tokens.length; i++) {
    address _token = _tokens[i];
    // everything is padded to 18 decimals
    _balance = _balance.add(_normalizeDecimals(_token, IERC20(_token).balanceOf(address(this))));
}
```

Note that `balance()`'s second term `IController(manager.controllers(address(this))).balanceOf()` is not normalized, but it must be.

This leads to many issues through the contracts that use `balance` but don't treat these values as normalized values.
For example, in `Vault.withdraw`, the computed `_amount` value is normalized (in 18 decimals).
But the `uint256 _balance = IERC20(_output).balanceOf(address(this));` value is not normalized but compared to the normalized `_amount` and even subtracted:

```solidity
// @audit compares unnormalzied output to normalized output
if (_balance < _amount) {
    IController _controller = IController(manager.controllers(address(this)));
    // @audit cannot directly subtract unnormalized
    uint256 _toWithdraw = _amount.sub(_balance);
    if (_controller.strategies() > 0) {
        _controller.withdraw(_output, _toWithdraw);
    }
    uint256 _after = IERC20(_output).balanceOf(address(this));
    uint256 _diff = _after.sub(_balance);
    if (_diff < _toWithdraw) {
        _amount = _balance.add(_diff);
    }
}
```

## Impact
Imagine in `withdraw`, the 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-yaxis)

---

### Example 3: [H-07] Vault.balance() mixes normalized and standard amounts

**Source**: Code4rena
**Protocol**: yAxis
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `Vault.balance` function uses the `balanceOfThis` function which scales ("normalizes") all balances to 18 decimals.

```
for (uint8 i; i < _tokens.length; i++) {
    address _token = _tokens[i];
    // everything is padded to 18 decimals
    _balance = _balance.add(_normalizeDecimals(_token, IERC20(_token).balanceOf(address(this))));
}
```

Note that `balance()`'s second term `IController(manager.controllers(address(this))).balanceOf()` is not normalized.
The code is adding a non-normalized amount (for example 6 decimals only for USDC) to a normalized (18 decimals).

## Impact
The result is that the `balance()` will be under-reported.
This leads to receiving wrong shares when `deposit`ing tokens, and a wrong amount when redeeming `tokens`.

## Recommended Mitigation Steps
The second term `IController(manager.controllers(address(this))).balanceOf()` must also be normalized before adding it.
`IController(manager.controllers(address(this))).balanceOf()` uses `_vaultDetails[msg.sender].balance` which directly uses the raw token amounts which are not normalized.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-yaxis)

---

### Example 4: [H-01] CompositeMultiOracle returns wrong decimals for prices?

**Source**: Code4rena
**Protocol**: Yield
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `CompositeMultiOracle.peek/get` functions seem to return wrong prices.
It's unclear what decimals `source.decimals` refers to in this case. Does it refer to `source.source` token decimals?

It chains the price arguments through `_peek` function calls and a single price is computed as:

```solidity
(priceOut, updateTimeOut) = IOracle(source.source).peek(base, quote, 10 ** source.decimals);   // Get price for one unit
// @audit shouldn't this divide by 10 ** IOracle(source.source).decimals() instead?
priceOut = priceIn * priceOut / (10 ** source.decimals);
```

Assume all oracles use 18 decimals (`oracle.decimals()` returns 18) and `source.decimals` refers to the _token decimals_ of `source.source`.

Then going from `USDC -> DAI -> USDT` (`path = [DAI]`) starts with a price of `1e18` in `peek`:
- `_peek(USDC, DAI, 1e18)`: Gets the price of `1e6 USDC` (as USDC has 6 decimals) in DAI with 18 decimals precision (because all oracle precision is set to 18): `priceOut = priceIn * 1e18 / 1e6 = 1e18 * 1e18 / 1e6 = 1e30`
- `_peek(DAI, USDT, 1e30)`: Gets the price of `1e18 DAI` (DAI has 18 decimals) with 18 decimals precision: `priceOut = priceIn * 1e18 / 1e18 = priceIn = 1e30`

It then uses `1e30` as the price to go from `USDC` to `USDT`: `value = price * amount / 1e18 = 1e30 * (1.0 USDC) / 1e18 = 1e30 * 1e6 / 1e18 = 1e18 = 1e12 * 1e6 = 1_000_000_000_000.0 USDT`. Inflating the actual `USDT` amount.

## Recommended Mitigation Steps
The i

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-08-yield)

---

### Example 5: [H-02] Wrong token allocation computation for token decimals != 18 if floor price not reached

**Source**: Code4rena
**Protocol**: Trader Joe
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

In `LaunchEvent.createPair`, when the floor price is not reached (`floorPrice > wavaxReserve * 1e18 / tokenAllocated`), the tokens to be sent to the pool are lowered to match the raised WAVAX at the floor price.

Note that the `floorPrice` is supposed to have a precision of 18:

> /// @param \_floorPrice Price of each token in AVAX, scaled to 1e18

The `floorPrice > (wavaxReserve * 1e18) / tokenAllocated` check is correct but the `tokenAllocated` computation involves the `token` decimals:

```solidity
// @audit should be wavaxReserve * 1e18 / floorPrice
tokenAllocated = (wavaxReserve * 10**token.decimals()) / floorPrice;
```

This computation does not work for `token`s that don't have 18 decimals.

#### Example

Assume I want to sell `1.0 wBTC = 1e8 wBTC` (8 decimals) at `2,000.0 AVAX = 2,000 * 1e18 AVAX`.
The `floorPrice` is `2000e18 * 1e18 / 1e8 = 2e31`

Assume the Launch event only raised `1,000.0 AVAX` - half of the floor price for the issued token amount of `1.0 WBTC` (it should therefore allocate only half a WBTC) - and the token amount will be reduced as: `floorPrice = 2e31 > 1000e18 * 1e18 / 1e8 = 1e31 = actualPrice`.
Then, `tokenAllocated = 1000e18 * 1e8 / 2e31 = 1e29 / 2e31 = 0` and no tokens would be allocated, instead of `0.5 WBTC = 0.5e8 WBTC`.

The computation should be `tokenAllocated = wavaxReserve * 1e18 / floorPrice = 1000e18 * 1e18 / 2e31 = 1e39 / 2e31 = 10e38 / 2e31 = 5e7 = 0.5e8`.

#### Recommendation

The new `tokenAllocated` comp

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-trader-joe)

---

### Example 6: [H-01] Incorrect handling of `pricefeed.decimals()`

**Source**: Code4rena
**Protocol**: Y2k Finance
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-09-y2k-finance/blob/2175c044af98509261e4147edeb48e1036773771/src/oracles/PegOracle.sol#L46-L83>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/2175c044af98509261e4147edeb48e1036773771/src/Controller.sol#L299-L300>

### Impact

Wrong math for handling pricefeed decimals. This code will only work for pricefeeds of 8 decimals, any others give wrong/incorrect data. The maths used can be shown in three lines:

```solidity
nowPrice = (price1 * 10000) / price2;
nowPrice = nowPrice * int256(10**(18 - priceFeed1.decimals()));
return nowPrice / 1000000;
```

Line1: adds 4 decimals
Line2: adds (18 - d) decimals, (where d = pricefeed.decimals())
Line3:  removes 6 decimals

Total: adds (16 - d) decimals

when d=8, the contract correctly returns an 8 decimal number. However, when d = 6, the function will return a 10 decimal number. This is further raised by (18-d = 12) decimals when checking for depeg event, leading to a 22 decimal number which is 4 orders of magnitude incorrect.

if d=18, (like usd-eth pricefeeds) contract fails / returns 0.

All chainlink contracts which give price in eth, operate with 18 decimals. So this can cripple the system if added later.

### Proof of Concept

Running the test  AssertTest.t.sol:testPegOracleMarketCreation and changing the line on

<https://github.com/code-423n4/2022-09-y2k-finance/blob/2175c044af98509261e4147edeb48e1036773771/test/AssertTest.t.sol#L30>

to

```solidity
PegOracle pegOracle3 = new PegOra

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-y2k-finance)

---

### Example 7: `TokenSaleProposal::buy` implicitly assumes that buy token has 18 decimals resulting in a potential total loss scenario for Dao Pool

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

### Example 8: H-1: Too few `ICHI` v2 farming reward tokens transferred to the user due to incorrect decimal precision

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

### Example 9: H-1: debtToMint incorrectly treats feeAdjustment decimals

**Source**: Sherlock
**Protocol**: Opyn Crab Netting
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-opyn-judging/issues/236 

## Found by 
keccak123, hyh

## Summary

_debtToMint() will return `0` decimals amounts and `sqthToSell` in depositAuction() will be insignificant, leading to ignoring the market orders used and depositing auction to be void as no external funding will be brought in.

## Vulnerability Detail

`feeAdjustment = _calcFeeAdjustment()` is `(squeethEthPrice * feeRate) / 10000` and have `18` decimals.

`wSqueethToMint = (_amount * debt) / (collateral + (debt * feeAdjustment))` will have `36` decimals in numerator and the same `36` in denominator, yielding `0` decimals figure. That figure is `sqthToSell`, so no market buying orders will be ever filled.

## Impact

depositAuction() will malfunction all the time, either reverting or producing less WETH and less CRAB than desired, i.e. there will be no deposit auction as market order part is needed to bring in the liquidity to be distributed.

Setting the severity to be high as this is system malfunction with material impact and no prerequisites.

## Code Snippet

feeAdjustment is treated as if it has no decimals:

https://github.com/sherlock-audit/2022-11-opyn/blob/main/crab-netting/src/CrabNetting.sol#L476-L485

```solidity
    /**
     * @dev calculates wSqueeth minted when amount is deposited
     * @param _amount to deposit into crab
     */
    function _debtToMint(uint256 _amount) internal view returns (uint256) {
        uint256 feeAdjustment = _calcFeeA

*[Content truncated...]*

---

### Example 10: H-5: `UniV2LPOracle` will malfunction if token0 or token1's `decimals != 18`

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/026-H 
## Found by 
Lambda, WATCHPUG, 0x52, hyh

## Summary

When one of the LP token's underlying tokens `decimals` is not 18, the price of the LP token calculated by `UniV2LPOracle` will be wrong. 

## Vulnerability Detail

`UniV2LPOracle` is an implementation of Alpha Homora v2's Fair Uniswap's LP Token Pricing Formula:

> The Formula ... of combining fair asset prices and fair asset reserves:

> $$
P = 2\cdot \frac{\sqrt{r_0 \cdot r_1} \cdot \sqrt{p_0\cdot p_1}}{totalSupply},
$$

> where $r_i$ is the asset ii's pool balance and $p_i$ is the asset $i$'s fair price.

However, the current implementation wrongful assumes $r_0$ and $r_1$ are always in 18 decimals.

https://github.com/sentimentxyz/oracle/blob/59b26a3d8c295208437aad36c470386c9729a4bc/src/uniswap/UniV2LPOracle.sol#L39-L50

```solidity
function getPrice(address pair) external view returns (uint) {
    (uint r0, uint r1,) = IUniswapV2Pair(pair).getReserves();

    // 2 * sqrt(r0 * r1 * p0 * p1) / totalSupply
    return FixedPointMathLib.sqrt(
        r0
        .mulWadDown(r1)
        .mulWadDown(oracle.getPrice(IUniswapV2Pair(pair).token0()))
        .mulWadDown(oracle.getPrice(IUniswapV2Pair(pair).token1()))
    )
    .mulDivDown(2e27, IUniswapV2Pair(pair).totalSupply());
}
```

https://github.com/transmissions11/solmate/blob/main/src/utils/FixedPointMathLib.sol

```solidity
uint256 internal constant WAD = 1e18; // The scalar of ETH and

*[Content truncated...]*

---

### Example 11: H-3: Sense redeem is unavailable and funds are frozen for underlyings whose decimals are smaller than the corresponding IBT decimals

**Source**: Sherlock
**Protocol**: Illuminate
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-illuminate-judging/issues/228 

## Found by 
hyh, 0x52

## Summary

Sense version of Redeemer's redeem() compares `amount` of Sense principal token Lender had on its balance vs `redeemed` amount of underlying as a slippage check, requiring that the latter be equal or greater than the former.

As these numbers have different decimals this check blocks the redeem altogether for the tokens whose decimals are smaller than decimals of the corresponding interest bearing token, freezing the funds.

## Vulnerability Detail

Sense version of redeem() assumes that Sense PT has the same decimals as underlying, performing slippage check by directly comparing the amounts.

Sense principal has decimals of the corresponding interest bearing tokens, not the decimals of the underlying. In the compound case IBT decimals are `8` and can be greater or less than underlying's.

For example, `1st July 2023 cUSDC Sense Principal Token` has `8` decimals, as cUSDC does (instead of 6 as USDC):

https://etherscan.io/token/0x869a70c198c937801b26d2701dc8e4e8c4de354a

In this case the slippage check reverts the operation. Sense PT cannot be turned to underlying and will remain on Lender's balance this way.

On the other hand, when underlying decimals are greater than IBT decimals the slippage check becomes a noop.

## Impact

Protocol users can be subject to market manipulations as Sense AMM result isn't checked for the underlyings whose decimals are higher

*[Content truncated...]*

---

### Example 12: H-4: `ERC4626Oracle` Price will be wrong when the ERC4626's `decimals` is different from the underlying tokens decimals

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/025-H 
## Found by 
Lambda, JohnSmith, WATCHPUG, 0x52, berndartmueller, Bahurum

## Summary

EIP-4626 does not require the decimals must be the same as the underlying tokens' decimals, and when it's not, `ERC4626Oracle` will malfunction.

## Vulnerability Detail

In the current implementation, `IERC4626(token).decimals()` is used as the `IERC4626(token).asset()`'s decimals to calculate the ERC4626's price.

However, while most ERC4626s are using the underlying tokens decimals as `decimals`, there are some ERC4626s use a different decimals from underlying tokens decimals since EIP-4626 does not require the decimals must be the same as the underlying tokens decimals:

> Although the convertTo functions should eliminate the need for any use of an EIP-4626 Vaults decimals variable, it is still strongly recommended to mirror the underlying tokens decimals if at all possible, to eliminate possible sources of confusion and simplify integration across front-ends and for other off-chain users.

Ref: https://eips.ethereum.org/EIPS/eip-4626

## Impact

The price of ERC4626 will be significantly underestimated when the underlying token's decimals > ERC4626's decimals, and be significantly overestimated when the underlying token's decimals < ERC4626's decimals.

## Code Snippet

https://github.com/sentimentxyz/oracle/blob/59b26a3d8c295208437aad36c470386c9729a4bc/src/erc4626/ERC4626Oracle.sol#L35-L43

```sol

*[Content truncated...]*

---

### Example 13: [H-07] Incorrect precision assumed from RdpxPriceOracle creates multiple issues related to value inflation/deflation

**Source**: Code4rena
**Protocol**: Dopex
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/amo/UniV2LiquidityAmo.sol#L372> 

<https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/amo/UniV2LiquidityAmo.sol#L381> 

<https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/perp-vault/PerpetualAtlanticVault.sol#L539> 

<https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/core/RdpxV2Core.sol#L1160>

The `RdpxEthPriceOracle`, available in the audit repo [here](https://github.com/dopex-io/rdpx-eth-oracle/blob/5762c2339b1c45b87ff4db172e43cef4a0ff603a/src/RdpxEthOracle.sol), provides the `RdpxV2Core`, the `UniV2LiquidityAmo` and the `PerpetualAtlanticVault` contracts the necessary values for `rdpx` related price calculations.

The issue is that these contracts expect the returned values to be in `1e8` precision (as stated in the natspec [here](https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/core/RdpxV2Core.sol#L1224), [here](https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/amo/UniV2LiquidityAmo.sol#L378) and [here](https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/perp-vault/IPerpetualAtlanticVault.sol#L20C1-L24C65)). But the returned precision [is actually `1e18`](https://github.com/dopex

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-dopex)

---

### Example 14: [H-01] Improper precision of strike price calculation can result in broken protocol

**Source**: Code4rena
**Protocol**: Dopex
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-08-dopex/blob/main/contracts/core/RdpxV2Core.sol#L1189-L1190> 

<https://github.com/code-423n4/2023-08-dopex/blob/main/contracts/perp-vault/PerpetualAtlanticVault.sol#L576-L583>

Due to a lack of adequate precision, the calculated strike price for a PUT option for rDPX is not guaranteed to be 25% OTM, which breaks core assumptions around (1) protecting downside price movement of the rDPX which makes up part of the collateral for dpxETH & (2) not overpaying for PUT option protection.

More specifically, the price of rDPX as used in the `calculateBondCost` function of the RdpxV2Core contract is represented as ETH / rDPX, and is given in 8 decimals of precision. To calculate the strike price which is 25% OTM based on the current price, the logic calls the `roundUp` function on what is effectively 75% of the current spot rDPX price. The issue is with the `roundUp` function of the PerpetualAtlanticVault contract, which effectively imposes a minimum value of 1e6.

Considering approximate recent market prices of `$`2000/ETH and `$`20/rDPX, the current price of rDPX in 8 decimals of precision would be exactly 1e6. Then to calculate the 25% OTM strike price, we would arrive at a strike price of `1e6 * 0.75 = 75e4`. The `roundUp` function will then round up this value to `1e6` as the strike price, and issue the PUT option using that invalid strike price. Obviously this strike price is not 25% OTM, and since its an ITM option, the premium imposed will

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-dopex)

---

### Example 15: Protocol fees are in WAD instead of token decimal units

**Source**: Spearbit
**Protocol**: Primitive
**Impact**: HIGH

**Details**:

## High Risk Report

## Severity
**High Risk**

## Context
`Portfolio.sol#L489`

## Description
When swapping, `deltaInput` is in WAD (not token decimals) units. Therefore, the `protocolFee` will also be in WAD as a percentage of `deltaInput`. This WAD amount is then credited to the REGISTRY:

```solidity
iteration.feeAmount = (deltaInput * _state.fee) / PERCENTAGE;
if (_protocolFee != 0) {
    uint256 protocolFeeAmount = iteration.feeAmount / _protocolFee;
    iteration.feeAmount -= protocolFeeAmount;
    _applyCredit(REGISTRY, _state.tokenInput, protocolFeeAmount);
}
```

The privileged registry can claim these fees using a withdrawal (draw) and the WAD units are not scaled back to token decimal units, resulting in withdrawing more fees than they should have received if the token has less than 18 decimals. This will reduce the global reserve by the increased fee amount and break the accounting and functionality of all pools using the token.

## Recommendation
Generally, some quantities are in WAD units and some in token decimals throughout the protocol. We recommend using WAD units everywhere and only converting from/to token decimal units at the "token boundary", directly at the point of interaction with the token contract through a `transfer` / `transferFrom` / `balanceOf` call.

## Primitive
Resolved in PR 335.

## Spearbit
Fixed.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Primitive-Spearbit-Security-Review.pdf)

---

### Example 16: _slippageTol does not adjust for decimal differences

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Vulnerability Report

## Severity
**Medium Risk**

## Context
AssetLogic.sol#L273

## Description
Users set the slippage tolerance in percentage. The `assetLogic` calculates:

```
minReceived = (_amount * _slippageTol) / s.LIQUIDITY_FEE_DENOMINATOR
```

Then `assetLogic` uses `minReceived` in the swap functions. However, the `minReceived` does not adjust for the decimal differences between `assetIn` and `assetOut`. Users will either always hit the slippage or suffer huge slippage when `assetIn` and `assetOut` have a different number of decimals.

Assume the number of decimals of `assetIn` is 6 and the number of decimals of `assetOut` is 18. The `minReceived` will be set to `10^-12` smaller than the correct value. Users would be vulnerable to sandwich attacks in this case. 

Alternatively, if the number of decimals of `assetIn` is 18 and the number of decimals of `assetOut` is 6, the `minReceived` will be set to `10^12` larger than the correct value. Users would always hit the slippage, and the cross-chain transfer will get stuck.

### Code Snippet
```solidity
library AssetLogic {
    function _swapAsset(... ) ... {
        // Swap the asset to the proper local asset
        uint256 minReceived = (_amount * _slippageTol) / s.LIQUIDITY_FEE_DENOMINATOR;
        ...
        return (pool.swapExact(_amount, _assetIn, _assetOut, minReceived), _assetOut);
        ...
    }
}
```

## Recommendation
Recommend to adjust the value with `swapStorage.tokenPrecisionMultipliers` for inter

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 17: claim() will underflow and revert for all tokens without 18 decimals

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Severity
Medium Risk

## Context
WithdrawProxy.sol#238-244

## Description
In the `claim()` function, the amount to decrease the Y intercept of the vault is calculated as:

```
(s.expected - balance).mulWadDown(10**ERC20(asset()).decimals() - s.withdrawRatio)
```

`s.withdrawRatio` is represented as a WAD (18 decimals). As a result, using any token with a number of decimals under 17 (assuming the withdraw ratio is greater than 10%) will lead to an underflow and cause the function to revert.

In this situation, the token's decimals don't matter. They are captured in `s.expected` and `balance`, and are also the scale at which the vault's y-intercept is measured, so there's no need to adjust for them.

**Note**: I know this isn't a risk in the current implementation, since it's WETH only, but since you are planning to generalize to accept all ERC20s, this is important.

## Recommendation
```solidity
if (balance < s.expected) {
    PublicVault(VAULT()).decreaseYIntercept(
        (s.expected - balance).mulWadDown(
            -10**ERC20(asset()).decimals() - s.withdrawRatio
            + 1e18 - s.withdrawRatio
        )
    );
}
```

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 18: [M-02] Price will not always be 18 decimals, as expected and outlined in the comments

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

The `price()` function is expected to return the price of one fractional tokens, represented in base tokens, to 18 decimals of precision. This is laid out clearly in the comments:

`/// @notice The current price of one fractional token in base tokens with 18 decimals of precision.`<br>
`/// @dev Calculated by dividing the base token reserves by the fractional token reserves.`<br>
`/// @return price The price of one fractional token in base tokens * 1e18.`<br>


However, the formula incorrectly calculates the price to be represented in whatever number of decimals the base token is in. Since there are many common base tokens (such as USDC) that will have fewer than 18 decimals, this will create a large mismatch between expected prices and the prices that result from the function.

### Proof of Concept

Prices are calculated with the following formula, where `ONE = 1e18`:

```solidity
return (_baseTokenReserves() * ONE) / fractionalTokenReserves();
```

We know that `fractionalTokenReserves` will always be represented in 18 decimals. This means that the `ONE` and the
`fractionalTokenReserves` will cancel each other out, and we are left with the `baseTokenReserves` number of decimals for the final price.

As an example:

*   We have `$1000` USDC in reserves, which at 6 decimals is 1e9
*   We have 1000 fractional tokens in reserve, which at 18 decimals is 1e21
*   The price calculation is `1e9 * 1e18 / 1e21 = 1e6`
*   While the value should be 1 token, the 1e6 will be interpreted 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-caviar)

---

### Example 19: [M-19] _handleDeposit and _handleWithdraw do not account for tokens with decimals higher than 18

**Source**: Code4rena
**Protocol**: Tigris Trade
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-12-tigris/blob/main/contracts/Trading.sol#L650
https://github.com/code-423n4/2022-12-tigris/blob/main/contracts/Trading.sol#L675


## Vulnerability details

## Impact 

In `Trading.sol` a [deposit](https://github.com/code-423n4/2022-12-tigris/blob/main/contracts/Trading.sol#L675) or [withdrawal](https://github.com/code-423n4/2022-12-tigris/blob/main/contracts/Trading.sol#L700) of tokens with decimals higher than 18 will always revert. 

This is the case e.g. for `NEAR` which is divisible into 10e24 `yocto` 

## Proof of Concept

Change [00.Mocks.js#L33](https://github.com/code-423n4/2022-12-tigris/blob/main/deploy/test/00.Mocks.js#L33) to:

```
args: ["USDC", "USDC", 24, deployer, ethers.utils.parseUnits("1000", 24)]
```

Then in [07.Trading.js](https://github.com/code-423n4/2022-12-tigris/blob/main/test/07.Trading.js):

```
Opening and closing a position with tigUSD output
Opening and closing a position with <18 decimal token output
```

are going to fail with:
```
Error: VM Exception while processing transaction: reverted with panic code 0x11 (Arithmetic operation underflowed or overflowed outside of an unchecked block)
```

## Tools Used

Visual Studio Code

## Recommended Mitigation Steps

Update calculations in the contract to account for tokens with decimals higher than 18.

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-tigris)

---

### Example 20: [M-05] Tokens with lower number of decimals can result in postponed linear vesting for user

**Source**: Code4rena
**Protocol**: VTVL
**Impact**: MEDIUM

**Details**:

_Submitted by pashov_

[VTVLVesting.sol#L174](https://github.com/code-423n4/2022-09-vtvl/blob/69da6e96f94ff3e02b9bb6175e6de2b3e71d3eb0/contracts/VTVLVesting.sol#L174)<br>

In the `_baseVestedAmount` of `VTVLVesting.sol` we see the following code

```solidity
uint40 finalVestingDurationSecs = _claim.endTimestamp - _claim.startTimestamp; // length of the interval
uint112 linearVestAmount = _claim.linearVestAmount * truncatedCurrentVestingDurationSecs / finalVestingDurationSecs;
```

Lets look at `truncatedCurrentVestingDurationSecs` as just the duration passed from the start of the vesting period for the PoC (this doesnt omit important data in this context).

Now think of the following scenario:

We have a token `$TKN` that has 6 decimals (those are the decimals of both USDT & USDC). We want to distribute 10,000 of those tokens to a user vested over a 10 year period.

10 years in seconds is 315360000 &ast;&ast;&ast;&ast;(this is `finalVestingDurationSecs`)

This means that we will distribute 10,000 &ast; 10^6 = 10 000 000 000 fractions of a token for 315360000 seconds, meaning we will distribute 310 fractions of a token each second - this is `linearVestAmount`

Now, since `finalVestingDurationSecs` is so big (315360000) it will almost always round `linearVestAmount` to zero when dividing by it, up until

`_claim.linearVestAmount * truncatedCurrentVestingDurationSecs` becomes a bigger number than 315360000, but since `_claim.linearVestAmount` is 310 we will need the current ve

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-vtvl)

---

### Example 21: [M-07] Wrong calculation for `yVault` price per share if decimals != 18

**Source**: Code4rena
**Protocol**: JPEG'd
**Impact**: MEDIUM

**Details**:

_Submitted by berndartmueller_

The [yVault.getPricePerFullShare()](https://github.com/code-423n4/2022-04-jpegd/blob/main/contracts/vaults/yVault/yVault.sol#L196) function calculates the price per share by multiplying with `1e18` token decimals with the assumption that the underlying token always has 18 decimals. `yVault` has the same amount of decimals as it's underlying token see ([yVault.decimals()](https://github.com/code-423n4/2022-04-jpegd/blob/main/contracts/vaults/yVault/yVault.sol#L70))

But tokens don't always have `1e18` decimals (e.g. USDC).

### Impact

The price per share calculation does not return the correct price for underlying tokens that do not have 18 decimals. This could lead to paying out too little or too much and therefore to a loss for either the protocol or the user.

### Proof of Concept

Following test will fail with the current implementation when the underlying vault token has 6 decimals:

*NOTE: `units()` helper function was adapted to accept the desired decimals.*

```typescript
it.only("should mint the correct amount of tokens for tokens with 6 decimals", async () => {
  const DECIMALS = 6;

  await token.setDecimals(DECIMALS);
  expect(await yVault.decimals()).to.equal(DECIMALS);

  expect(await yVault.getPricePerFullShare()).to.equal(0);
  await token.mint(user1.address, units(1000, DECIMALS));
  await token.connect(user1).approve(yVault.address, units(1000, DECIMALS));

  await yVault.connect(user1).deposit(units(500, DECIMALS));
  expect(

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-jpegd)

---

### Example 22: H-4: The price from `StableOracleDAI` is returned with the incorrect number of decimals

**Source**: Sherlock
**Protocol**: USSD - Autonomous Secure Dollar
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-USSD-judging/issues/236 

## Found by 
0xStalin, 0xeix, 0xlmanini, Bahurum, Brenzee, Dug, G-Security, PNS, Proxy, SanketKogekar, T1MOH, Vagner, WATCHPUG, ast3ros, ctf\_sec, immeas, juancito, kutugu, n33k, peanuts, pengun, qbs, qpzm, saidam017, sam\_gmk, sashik\_eth, twicek
## Summary

The price returned from the `getPriceUSD` function of the `StableOracleDAI` is scaled up by `1e10`, which results in 28 decimals instead of the intended 18.

## Vulnerability Detail

In `StableOracleDAI` the `getPriceUSD` function is defined as follows...

```solidity
    function getPriceUSD() external view override returns (uint256) {
        address[] memory pools = new address[](1);
        pools[0] = 0x60594a405d53811d3BC4766596EFD80fd545A270;
        uint256 DAIWethPrice = DAIEthOracle.quoteSpecificPoolsWithTimePeriod(
            1000000000000000000, // 1 Eth
            0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2, // WETH (base token)
            0x6B175474E89094C44Da98b954EedeAC495271d0F, // DAI (quote token)
            pools, // DAI/WETH pool uni v3
            600 // period
        );

        uint256 wethPriceUSD = ethOracle.getPriceUSD();

        // chainlink price data is 8 decimals for WETH/USD, so multiply by 10 decimals to get 18 decimal fractional
        //(uint80 roundID, int256 price, uint256 startedAt, uint256 timeStamp, uint80 answeredInRound) = priceFeedDAIETH.latestRoundData();
        (, int256 price,,,) = priceFeedDAIE

*[Content truncated...]*

---

### Example 23: [M-05] Withdrawing ETH collateral with max uint256 amount value reverts transaction

**Source**: Code4rena
**Protocol**: Sturdy
**Impact**: MEDIUM

**Details**:

_Submitted by berndartmueller, also found by WatchPug_

Withdrawing ETH collateral via the `withdrawCollateral` function using `type(uint256).max` for the `_amount` parameter reverts the transaction due to `_asset` being the zero-address and `IERC20Detailed(_asset).decimals()` not working for native ETH.

#### Proof of Concept

[GeneralVault.sol#L121-L124](https://github.com/code-423n4/2022-05-sturdy/blob/78f51a7a74ebe8adfd055bdbaedfddc05632566f/smart-contracts/GeneralVault.sol#L121-L124)

```solidity
if (_amount == type(uint256).max) {
    uint256 decimal = IERC20Detailed(_asset).decimals(); // @audit-info does not work for native ETH. Transaction reverts
    _amount = _amountToWithdraw.mul(this.pricePerShare()).div(10**decimal);
}
```

### Recommended mitigation steps

Check `_asset` and use hard coded decimal value (`18`) for native ETH.

**[sforman2000 (Sturdy) confirmed](https://github.com/code-423n4/2022-05-sturdy-findings/issues/85)**

**[atozICT20 (Sturdy) commented](https://github.com/code-423n4/2022-05-sturdy-findings/issues/85):**
 > [Fix the issue of transaction fails due to calculate ETH's decimals sturdyfi/code4rena-may-2022#7](https://github.com/sturdyfi/code4rena-may-2022/pull/7)

**[hickuphh3 (judge) commented](https://github.com/code-423n4/2022-05-sturdy-findings/issues/85#issuecomment-1145575544):**
 > Good find! Stated in `_asset` description that null address is interpreted as ETH, which isn't a token, and therefore reverts when attempting to fetch its de

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-sturdy)

---

### Example 24: M-5: Exponential and logarithmic price adapters will return incorrect pricing when moving from higher dp token to lower dp token

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/42 

## Found by 
0x52
## Summary

The exponential and logarithmic price adapters do not work correctly when used with token pricing of different decimal places. This is because the resolution of the underlying expWad and lnWad functions is not fit for tokens that aren't 18 dp.

## Vulnerability Detail

[AuctionRebalanceModuleV1.sol#L856-L858](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-protocol/contracts/protocol/modules/v1/AuctionRebalanceModuleV1.sol#L856-L858)

    function _calculateQuoteAssetQuantity(bool isSellAuction, uint256 _componentQuantity, uint256 _componentPrice) private pure returns (uint256) {
        return isSellAuction ? _componentQuantity.preciseMulCeil(_componentPrice) : _componentQuantity.preciseMul(_componentPrice);
    }

The price returned by the adapter is used directly to call _calculateQuoteAssetQuantity which uses preciseMul/preciseMulCeil to convert from component amount to quote amount. Assume we wish to sell 1 WETH for 2,000 USDT. WETH is 18dp while USDT is 6dp giving us the following price:

    1e18 * price / 1e18 = 2000e6

Solving for price gives:

    price = 2000e6

This establishes that the price must be scaled to:

    price dp = 18 - component dp + quote dp

Plugging in our values we see that our scaling of 6 dp makes sense.

[BoundedStepwiseExponentialPriceAdapter.sol#L67-L80](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-proto

*[Content truncated...]*

---

### Example 25: [H-04] Yearn token  shares conversion decimal issue

**Source**: Code4rena
**Protocol**: Sublime
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

The yearn strategy `YearnYield` converts shares to tokens by doing `pricePerFullShare * shares / 1e18`:

    function getTokensForShares(uint256 shares, address asset) public view override returns (uint256 amount) {
        if (shares == 0) return 0;
        // @audit should divided by vaultDecimals 
        amount = IyVault(liquidityToken[asset]).getPricePerFullShare().mul(shares).div(1e18);
    }

But Yearn's `getPricePerFullShare` seems to be [in `vault.decimals()` precision](https://github.com/yearn/yearn-vaults/blob/03b42dacacec2c5e93af9bf3151da364d333c222/contracts/Vault.vy#L1147), i.e., it should convert it as `pricePerFullShare * shares / (10 ** vault.decimals())`.
The vault decimals are the same [as the underlying token decimals](https://github.com/yearn/yearn-vaults/blob/03b42dacacec2c5e93af9bf3151da364d333c222/contracts/Vault.vy#L295-L296)

#### Impact

The token and shares conversions do not work correctly for underlying tokens that do not have 18 decimals.
Too much or too little might be paid out leading to a loss for either the protocol or user.

#### Recommended Mitigation Steps

Divide by `10**vault.decimals()` instead of `1e18` in `getTokensForShares`.
Apply a similar fix in `getSharesForTokens`.

**[ritik99 (Sublime) confirmed](https://github.com/code-423n4/2021-12-sublime-findings/issues/134)**

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-12-sublime)

---

## Statistics

- Total findings analyzed: 45
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

