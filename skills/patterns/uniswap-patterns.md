# Uniswap Security Patterns

## Overview

**Frequency**: 22 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 12 | 9 | 1 | 0 |

**Common Sources**: Sherlock, Code4rena, Spearbit, Trust Security

---

## Detection Checklist

- [ ] Check for uniswap vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-3: Usage of `slot0` is extremely easy to manipulate

**Source**: Sherlock
**Protocol**: RealWagmi
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-real-wagmi-judging/issues/97 

## Found by 
BugBusters, Jaraxxus, ash, bitsurfer, kutugu, ni8mare, rogue-lion-0619, sashik\_eth, shealtielanz, stopthecap, toshii, tsvetanovv
## Summary
Usage of `slot0` is extremely easy to manipulate 

## Vulnerability Detail
Real Wagmi is using  `slot0` to calculate several variables in their codebase:

https://github.com/sherlock-audit/2023-06-real-wagmi/blob/main/concentrator/contracts/Multipool.sol#L589-L596

  [slot0](https://docs.uniswap.org/contracts/v3/reference/core/interfaces/pool/IUniswapV3PoolState#slot0) is the most recent data point and is therefore extremely easy to manipulate.

Multipool directly uses the token values returned by `getAmountsForLiquidity` 

```@solidity
 (uint256 amount0, uint256 amount1) = LiquidityAmounts.getAmountsForLiquidity(
                slots[i].currentSqrtRatioX96,
                TickMath.getSqrtRatioAtTick(position.lowerTick),
                TickMath.getSqrtRatioAtTick(position.upperTick),
                liquidity
            );
```

to calculate the reserves. 

```@solidity
 reserve0 += amount0;
 reserve1 += amount1;
```
Which they are used to calculate the `lpAmount` to mint from the pool. This allows a malicious user to manipulate the amount of the minted by a user.
https://github.com/sherlock-audit/2023-06-real-wagmi/blob/main/concentrator/contracts/Multipool.sol#L483

https://github.com/sherlock-audit/2023-06-real-wagmi/blob/main/concentrator

*[Content truncated...]*

---

### Example 2: [H-17] Second per liquidity inside could overflow `uint256` causing the LP position to be locked in `UniswapV3Staker`

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: HIGH

**Details**:

`UniswapV3Staker` depends on the second per liquidity inside values from the `Uniswap V3 Pool` to calculate the amount of rewards a position should receive. This value represents the amount of second liquidity inside a tick range that is "active" (`tickLower < currentTick < tickUpper`). The second per liquidity inside a specific tick range is supposed to always increase over time.

In the `RewardMath` library, the seconds inside are calculated by taking the current timestamp value and subtracting the value at the moment the position is staked. Since this value increases over time, it should be normal. Additionally, this implementation is similar to [Uniswap Team's implementation](https://github.com/Uniswap/v3-staker/blob/4328b957701de8bed83689aa22c32eda7928d5ab/contracts/libraries/RewardMath.sol#L35).

```solidity
function computeBoostedSecondsInsideX128(
    uint256 stakedDuration,
    uint128 liquidity,
    uint128 boostAmount,
    uint128 boostTotalSupply,
    uint160 secondsPerLiquidityInsideInitialX128,
    uint160 secondsPerLiquidityInsideX128
) internal pure returns (uint160 boostedSecondsInsideX128) {
    // this operation is safe, as the difference cannot be greater than 1/stake.liquidity
    uint160 secondsInsideX128 = (secondsPerLiquidityInsideX128 - secondsPerLiquidityInsideInitialX128) * liquidity;
    // @audit secondPerLiquidityInsideX128 could smaller than secondsPerLiquidityInsideInitialX128
    ...
}
```

However, even though the second per liquidity inside 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 3: [H-02] Use of `slot0` to get `sqrtPriceLimitX96` can lead to price manipulation.

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: HIGH

**Details**:

In `RootBrigdeAgent.sol`, the functions `_gasSwapOut` and `_gasSwapIn` use `UniswapV3.slot0` to get the value of `sqrtPriceX96`, which is used to perform the swap. However, the `sqrtPriceX96` is pulled from `Uniswap.slot0`, which is the most recent data point and can be manipulated easily via `MEV` bots and `Flashloans` with sandwich attacks; which can cause the loss of funds when interacting with the `Uniswap.swap` function.

### Proof of Concept

You can see the `_gasSwapIn` function in `RootBrigdeAgent.sol` [here](https://github.com/code-423n4/2023-05-maia/blob/cfed0dfa3bebdac0993b1b42239b4944eb0b196c/src/ulysses-omnichain/RootBridgeAgent.sol#L674C1-L689C75):

```solidity

     //Get sqrtPriceX96
        (uint160 sqrtPriceX96,,,,,,) = IUniswapV3Pool(poolAddress).slot0();

        // Calculate Price limit depending on pre-set price impact
        uint160 exactSqrtPriceImpact = (sqrtPriceX96 * (priceImpactPercentage / 2)) / GLOBAL_DIVISIONER;

        //Get limit
        uint160 sqrtPriceLimitX96 =
            zeroForOneOnInflow ? sqrtPriceX96 - exactSqrtPriceImpact : sqrtPriceX96 + exactSqrtPriceImpact;

        //Swap imbalanced token as long as we haven't used the entire amountSpecified and haven't reached the price limit
        try IUniswapV3Pool(poolAddress).swap(
            address(this),
            zeroForOneOnInflow,
            int256(_amount),
            sqrtPriceLimitX96,
            abi.encode(SwapCallbackData({tokenIn: gasTokenGlobalAddress}))
```

You can a

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 4: [H-06] Discrepency in the Uniswap V3 position price calculation because of decimals

**Source**: Code4rena
**Protocol**: ParaSpace
**Impact**: HIGH

**Details**:

When the squared root of the Uniswap V3 position is calculated from the [`_getOracleData()` function](https://github.com/code-423n4/2022-11-paraspace/blob/main/paraspace-core/contracts/misc/UniswapV3OracleWrapper.sol#L221-L280), the price may return a very high number (in the case that the token1 decimals are strictly superior to the token0 decimals). See: <https://github.com/code-423n4/2022-11-paraspace/blob/main/paraspace-core/contracts/misc/UniswapV3OracleWrapper.sol#L249-L260>

The reason is that at the denominator, the `1E9` (10&ast;&ast;9) value is hard-coded, but should take into account the delta between both decimals.<br>
As a result, in the case of `token1Decimal > token0Decimal`, the [`getAmountsForLiquidity()`](https://github.com/code-423n4/2022-11-paraspace/blob/main/paraspace-core/contracts/dependencies/uniswap/LiquidityAmounts.sol#L172-L205) is going to return a huge value for the amount of token0 and token1 as the user position liquidity.

The [`getTokenPrice()`](https://github.com/code-423n4/2022-11-paraspace/blob/main/paraspace-core/contracts/misc/UniswapV3OracleWrapper.sol#L156), using this amount of liquidity to [calculate the token price](https://github.com/code-423n4/2022-11-paraspace/blob/main/paraspace-core/contracts/misc/UniswapV3OracleWrapper.sol#L176-L180) is as its turn going to return a huge value.

### Proof of Concept

This POC demonstrates in which case the returned squared root price of the position is over inflated

```solidity
// SPDX-Licens

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-paraspace)

---

### Example 5: H-4: No slippage protection during repayment due to dynamic slippage params and easily influenced `slot0()`

**Source**: Sherlock
**Protocol**: Real Wagmi #2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-10-real-wagmi-judging/issues/109 

## Found by 
0x52, 0xJuda, 0xMaroutis, 0xblackskull, HHK, IceBear, Kral01, MohammedRizwan, Nyx, kaysoft, lil.eth, lucifero, p-tsanev, peanuts, pks\_, talfao, tsvetanovv
The repayment function lacks slippage protection. It relies on slot0() to calculate sqrtLimitPrice, which in turn determines amounts for restoring liquidation. The dynamic calculation of slippage parameters based on these values leaves the function without adequate slippage protection, potentially reducing profit for the repayer.

## Vulnerability Detail
The absence of slippage protection can be attributed to two key reasons. Firstly, the `sqrtPrice` is derived from `slot0()`, **which can be easily manipulated:**
```Solidity
     function _getCurrentSqrtPriceX96(
        bool zeroForA,
        address tokenA,
        address tokenB,
        uint24 fee
    ) private view returns (uint160 sqrtPriceX96) {
        if (!zeroForA) {
            (tokenA, tokenB) = (tokenB, tokenA);
        }
        address poolAddress = computePoolAddress(tokenA, tokenB, fee);
        (sqrtPriceX96, , , , , , ) = IUniswapV3Pool(poolAddress).slot0(); //@audit-issue can be easily manipulated
    }
```
The calculated `sqrtPriceX96` is used to determine the amounts for restoring liquidation and the number of holdTokens to be swapped for saleTokens:
```Solidity
(uint256 holdTokenAmountIn, uint256 amount0, uint256 amount1) = _getHoldTokenAmountIn(
          

*[Content truncated...]*

---

### Example 6: H-14: Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/145 

## Found by 
Bauer, Breeje, ctf\_sec
## Summary

Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

## Vulnerability Detail

In the current implementation in CurveSpell.sol

```solidity
{
	// 2. Swap rewards tokens to debt token
	uint256 rewards = _doCutRewardsFee(CRV);
	_ensureApprove(CRV, address(swapRouter), rewards);
	swapRouter.swapExactTokensForTokens(
		rewards,
		0,
		swapPath,
		address(this),
		type(uint256).max
	);
}
```

the deadline check is set to type(uint256).max, which means the deadline check is disabled!

In IChiSpell. the swap is directedly call on the pool instead of the router

```solidity
SWAP_POOL.swap(
	address(this),
	// if withdraw token is Token0, then swap token1 -> token0 (false)
	!isTokenA,
	amountToSwap.toInt256(),
	isTokenA
		? param.sqrtRatioLimit + deltaSqrt
		: param.sqrtRatioLimit - deltaSqrt, // slippaged price cap
	abi.encode(address(this))
);
```

and it has no deadline check for the transaction when swapping

## Impact

AMMs provide their users with an option to limit the execution of their pending actions, such as swaps or adding and removing liquidity. The most common solution is to include a deadline timestamp as a parameter (for example see Uniswap V2 and Uniswap V3). If such an option is not present, users can unknowingly perform bad trades:

Alice wants to swap 100 tokens for 1 ETH and

*[Content truncated...]*

---

### Example 7: [H-09] UniswapV3 tokens of certain pairs will be wrongly valued, leading to liquidations

**Source**: Code4rena
**Protocol**: ParaSpace
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-11-paraspace/blob/c6820a279c64a299a783955749fdc977de8f0449/paraspace-core/contracts/misc/UniswapV3OracleWrapper.sol#L245>

UniswapV3OracleWrapper is responsible for price feed of UniswapV3 NFT tokens. Its getTokenPrice() is used by the health check calculation in GenericLogic.

getTokenPrice gets price from the oracle and then uses it to calculate value of its liquidity.

    function getTokenPrice(uint256 tokenId) public view returns (uint256) {
        UinswapV3PositionData memory positionData = getOnchainPositionData(
            tokenId
        );
        PairOracleData memory oracleData = _getOracleData(positionData);
        (uint256 liquidityAmount0, uint256 liquidityAmount1) = LiquidityAmounts
            .getAmountsForLiquidity(
                oracleData.sqrtPriceX96,
                TickMath.getSqrtRatioAtTick(positionData.tickLower),
                TickMath.getSqrtRatioAtTick(positionData.tickUpper),
                positionData.liquidity
            );
        (
            uint256 feeAmount0,
            uint256 feeAmount1
        ) = getLpFeeAmountFromPositionData(positionData);
        return
            (((liquidityAmount0 + feeAmount0) * oracleData.token0Price) /
                10**oracleData.token0Decimal) +
            (((liquidityAmount1 + feeAmount1) * oracleData.token1Price) /
                10**oracleData.token1Decimal);
    }

In `_getOracleData`,  sqrtPriceX96 of the holding is calculated, using square root of t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-paraspace)

---

### Example 8: UNI_V3Validator fetches spot prices that may lead to price manipulation attacks

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
`UNI_V3Validator.sol#L126-L130`

## Description
`UNI_V3Validator.validateAndParse()` checks the state of the Uniswap V3 position. This includes checking the LP value through `LiquidityAmounts.getAmountsForLiquidity`.

```solidity
//get pool state
//get slot 0
(uint160 poolSQ96, , , , , , ) = IUniswapV3PoolState(
    V3_FACTORY.getPool(token0, token1, fee)
).slot0();
(uint256 amount0, uint256 amount1) = LiquidityAmounts.getAmountsForLiquidity(
    poolSQ96,
    TickMath.getSqrtRatioAtTick(tickLower),
    TickMath.getSqrtRatioAtTick(tickUpper),
    liquidity
);
```
- **LiquidityAmounts.sol#L177-L221**

When we deep dive into `getAmountsForLiquidity`, we see three cases: 
1. Price is below the range 
2. Price is within the range 
3. Price is above the range

```solidity
function getAmountsForLiquidity(
    uint160 sqrtRatioX96,
    uint160 sqrtRatioAX96,
    uint160 sqrtRatioBX96,
    uint128 liquidity
) internal pure returns (uint256 amount0, uint256 amount1) {
    unchecked {
        if (sqrtRatioAX96 > sqrtRatioBX96)
            (sqrtRatioAX96, sqrtRatioBX96) = (sqrtRatioBX96, sqrtRatioAX96);
        if (sqrtRatioX96 <= sqrtRatioAX96) {
            amount0 = getAmount0ForLiquidity(
                sqrtRatioAX96,
                sqrtRatioBX96,
                liquidity
            );
        } else if (sqrtRatioX96 < sqrtRatioBX96) {
            amount0 = getAmount0ForLiquidity(
                sqrtRatioX96,
                sqrtRatioBX96,
 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review-July.pdf)

---

### Example 9: H-9: UniswapV3 sqrtRatioLimit doesn't provide slippage protection and will result in partial swaps

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/132 

## Found by 
0x52
## Summary

The sqrtRatioLimit for UniV3 doesn't cause the swap to revert upon reaching that value. Instead it just cause the swap to partially fill. This is a [known issue](https://github.com/Uniswap/v3-core/blob/d8b1c635c275d2a9450bd6a78f3fa2484fef73eb/contracts/UniswapV3Pool.sol#L641) with using sqrtRatioLimit as can be seen here where the swap ends prematurely when it has been reached. This is problematic as this is meant to provide the user with slippage protection but doesn't.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/IchiSpell.sol#L209-L223

        if (amountToSwap > 0) {
            SWAP_POOL = IUniswapV3Pool(vault.pool());
            uint160 deltaSqrt = (param.sqrtRatioLimit *
                uint160(param.sellSlippage)) / uint160(Constants.DENOMINATOR);
            SWAP_POOL.swap(
                address(this),
                // if withdraw token is Token0, then swap token1 -> token0 (false)
                !isTokenA,
                amountToSwap.toInt256(),
                isTokenA
                    ? param.sqrtRatioLimit + deltaSqrt
                    : param.sqrtRatioLimit - deltaSqrt, // slippaged price cap
                abi.encode(address(this))
            );
        }

sqrtRatioLimit is used as slippage protection for the user but is ineffective and depending on what tokens are 

*[Content truncated...]*

---

### Example 10: H-10: IchiLpOracle is extemely easy to manipulate due to how IchiVault calculates underlying token balances

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/20 

## Found by 
carrot, obront, ctf\_sec, cergyk, banditx0x, psy4n0n, 0x52

## Summary

`IchiVault#getTotalAmounts` uses the `UniV3Pool.slot0` to determine the number of tokens it has in it's position. `slot0` is the most recent data point and is therefore extremely easy to manipulate. Given that the protocol specializes in leverage, the effects of this manipulation would compound to make malicious uses even easier.

## Vulnerability Detail

[ICHIVault.sol](https://etherscan.io/token/0x683f081dbc729dbd34abac708fa0b390d49f1c39#code#L3098)

    function _amountsForLiquidity(
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity
    ) internal view returns (uint256, uint256) {
        (uint160 sqrtRatioX96, , , , , , ) = IUniswapV3Pool(pool).slot0();
        return
            UV3Math.getAmountsForLiquidity(
                sqrtRatioX96,
                UV3Math.getSqrtRatioAtTick(tickLower),
                UV3Math.getSqrtRatioAtTick(tickUpper),
                liquidity
            );
    }

`IchiVault#getTotalAmounts` uses the `UniV3Pool.slot0` to determine the number of tokens it has in it's position. [slot0](https://docs.uniswap.org/contracts/v3/reference/core/interfaces/pool/IUniswapV3PoolState#slot0) is the most recent data point and can easily be manipulated.

https://github.com/sherlock-audit/2023-02-blueberry/blob/main/contracts/oracle/IchiLpOracle.sol#L27-L36

`IchiLPOrac

*[Content truncated...]*

---

### Example 11: [M-16] Inaccurate swap amount calculation in ReLP leads to stuck tokens and lost liquidity

**Source**: Code4rena
**Protocol**: Dopex
**Impact**: MEDIUM

**Details**:

`ReLPContract` contains logic that removes WETH-RDPX liquidity from Uniswap V2, swaps some amount WETH to RDPX and re-adds the liquidity.

The calculation logic for the amount of tokens to swap is unreliable and sometimes reverts or leaves dust WETH in the reLP contract. WETH cannot be recovered unless another reLP operation is triggered. However, since reLP-ing is accessible to all users in the bonding logic in `RdpxV2Core`, the contract may be **griefed on an ongoing basis, intentional or not.**

The presence of excess WETH also means that the total value of the LP decreases abnormally after each reLP operation.

### Proof of Concept

The following Foundry test demonstrates the vulnerability.

*   Paste the code in a new file `PoC.t.sol` under `tests/`
*   Run the test with `forge test --match-test test_poc_relp_dust -vvv`

<details>

```

    // File: PoC.t.sol
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity 0.8.19;

    import "forge-std/Test.sol";
    import "forge-std/console.sol";

    import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
    import {IERC20WithBurn} from "contracts/interfaces/IERC20WithBurn.sol";
    import {MockToken} from "contracts/mocks/MockToken.sol";
    import {MockRdpxEthPriceOracle} from "contracts/mocks/MockRdpxEthPriceOracle.sol";
    import {ReLPContract} from "contracts/reLP/ReLPContract.sol";
    import {RdpxReserve} from "contracts/reserve/RdpxReserve.sol";
    import {IUniswapV2Factory} from "contracts/unisw

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-dopex)

---

### Example 12: [H-02] Liquidation can be escaped by depositing a Uni v3 position with 0 liquidity

**Source**: Code4rena
**Protocol**: Wild Credit
**Impact**: HIGH

**Details**:

_Submitted by WatchPug_.

When the liquidator is trying to liquidate a undercolldarezed loan by calling `liquidateAccount()`, it calls `_unwrapUniPosition()` -> `uniV3Helper.removeLiquidity()` -> `positionManager.decreaseLiquidity()`.

However, when the Uni v3 position has 0 liquidity, `positionManager.decreaseLiquidity()` will fail.

See: <https://github.com/Uniswap/v3-periphery/blob/main/contracts/NonfungiblePositionManager.sol#L265>

Based on this, a malicious user can escaped liquidation by depositing a Uni v3 position with 0 liquidity.

##### Impact

Undercollateralized debts cannot be liquidated and it leads to bad debts to the protocol.

A malicious user can take advantage of this by creating long positions on the collateral assets and take profit on the way up, and keep taking more debt out of the protocol, while when the price goes down, the debt can not be liquidated and the risks of bad debt are paid by the protocol.

##### Proof of Concept

1.  A malicious user deposits some collateral assets and borrow the max amount of debt;
2.  The user deposits a Uni v3 position with 0 liquidity;
3.  When the market value of the collateral assets decreases, the liquadation will fail as `positionManager.decreaseLiquidity()` reverts.

##### Recommendation

Check if liquidity > 0 when removeLiquidity.

**[talegift (Wild Credit) confirmed](https://github.com/code-423n4/2021-09-wildcredit-findings/issues/30#issuecomment-932861833):**
 > Valid issue. Good catch.
> 
> Severity should

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-wildcredit)

---

### Example 13: M-3: JalaPair potential permanent DoS due to overflow

**Source**: Sherlock
**Protocol**: Jala Swap
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-jala-swap-judging/issues/186 

The protocol has acknowledged this issue.

## Found by 
0k, 0xMojito, 0xRstStn, 0xloscar01, Stoicov, ZanyBonzy, den\_sosnovskyi, deth, fibonacci, giraffe, mahmud, n1punp, santiellena, sunill\_eth, tank
## Summary

In the `JalaPair::_update` function, overflow is intentionally desired in the calculations for `timeElapsed` and `priceCumulative`. This is forked from the UniswapV2 source code, and it’s meant and known to overflow. UniswapV2 was developed using Solidity 0.6.6, where arithmetic operations overflow and underflow by default. However, Jala utilizes Solidity >=0.8.0, where such operations will automatically revert.

## Vulnerability Detail

```solidity
uint32 timeElapsed = blockTimestamp - blockTimestampLast; // overflow is desired
if (timeElapsed > 0 && _reserve0 != 0 && _reserve1 != 0) {
    // * never overflows, and + overflow is desired
    price0CumulativeLast += uint256(UQ112x112.encode(_reserve1).uqdiv(_reserve0)) * timeElapsed;
    price1CumulativeLast += uint256(UQ112x112.encode(_reserve0).uqdiv(_reserve1)) * timeElapsed;
}
```

## Impact

This issue could potentially lead to permanent denial of service for a pool. All the core functionalities such as `mint`, `burn`, or `swap` would be broken. Consequently, all funds would be locked within the contract.

I think issue with High impact and a Low probability (merely due to the extended timeframe for the event's occurrence, it's impo

*[Content truncated...]*

---

### Example 14: [M-04] Wrong init code hash

**Source**: Code4rena
**Protocol**: Numoen
**Impact**: MEDIUM

**Details**:

An init code hash is used to calculate the address of UniswapV2 pair contract. But the init code hash is not same as the latest UniswapV2 repository.

### Proof of Concept

UniswapV2Library.pairFor uses the following value as the init code hash of UniswapV2Pair.

        hex"e18a34eb0e04b04f7a0ac29a6e80748dca96319b42c54d679cb821dca90c6303" // init code hash

But it is different from the [init code hash](https://github.com/Uniswap/v2-periphery/blob/master/contracts/libraries/UniswapV2Library.sol#L24) of the uniswap v2 repository.

I tested this using one of the top UniswapV2 pairs. DAI-USDC is in the third place [here](https://v2.info.uniswap.org/pairs).

The token addresses are as follows:

DAI: 0x6B175474E89094C44Da98b954EedeAC495271d0F

USDC: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48

And the current UniswapV2Factory address is 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f [here](https://docs.uniswap.org/contracts/v2/reference/smart-contracts/factory).

The pair address calculated is 0x6983E2Da04353C31c7C42B0EA900a40B1D5bf845. And we can't find pair contract in the address.

So I think the old version of UniswapV2Factory and pair are used here. And it can cause a risk when liquidity is not enough for the pair.

### Recommended Mitigation Steps

Integrate the latest version of UniswapV2.

**[kyscott18 (Numoen) acknowledged and commented](https://github.com/code-423n4/2023-01-numoen-findings/issues/206#issuecomment-1423227359):**
 > I should have been more specific, but the ini

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-numoen)

---

### Example 15: H-9: Uniswap v3 pool token balance proportion does not necessarily correspond to the price, and it is easy to manipulate.

**Source**: Sherlock
**Protocol**: USSD - Autonomous Secure Dollar
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-USSD-judging/issues/808 

## Found by 
0xRan4212, Bahurum, VAD37, WATCHPUG, curiousapple, mahdikarimi, n33k, nobody2018, simon135
## Summary

`getSupplyProportion()` retrieves Uniswap v3 pool balances, but the proportion of pool tokens doesn't always correspond to the price. If `ownval` is less than `1e6 - threshold`, `USSDamount` may be lower than `DAIamount`, causing L97 `USSDamount - DAIamount` to revert due to underflow. Proportion can be easily manipulated, which can be exploited by attackers.

## Vulnerability Detail

`getSupplyProportion()` retrieves the balances of the Uniswap v3 pool. However, due to the different designs of Uniswap v3 and Uniswap v2, the proportion of pool tokens does not necessarily correspond to the price.

As a result, if `ownval` is less than `1e6 - threshold` (e.g. 0.95), `USSDamount` may be lower than `DAIamount`, causing L97 `USSDamount - DAIamount` to revert due to underflow.

Additionally, the pool contract holds accumulative fees on its balances, which are not impacted by price changes.

---

Furthermore, the proportion can be easily manipulated with minimal cost, which can be exploited by attackers.

If the price of USSD goes over-peg (which can happen naturally), an attacker can take advantage by following these steps:

1. Add single leg liquidity of DAI to the DAI/USSD pool at an exorbitantly high price range, such as 1 DAI == 1000-2000 USSD.
2. Manipulate the price of the collateral ass

*[Content truncated...]*

---

### Example 16: H-7: Not using slippage parameter or deadline while swapping on UniswapV3

**Source**: Sherlock
**Protocol**: USSD - Autonomous Secure Dollar
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-USSD-judging/issues/673 

## Found by 
0xPkhatri, 0xRan4212, 0xRobocop, 0xSmartContract, 0xStalin, 0xeix, 0xpinky, 0xyPhilic, Angry\_Mustache\_Man, Auditwolf, Bahurum, Bauchibred, Bauer, BlockChomper, Brenzee, BugBusters, BugHunter101, CodeFoxInc, Delvir0, Dug, Fanz, HonorLt, J4de, JohnnyTime, Juntao, Kodyvim, Kose, Lilyjjo, Madalad, MohammedRizwan, Nyx, PokemonAuditSimulator, Proxy, RaymondFam, Saeedalipoor01988, Schpiel, SensoYard, T1MOH, TheNaubit, Tricko, Viktor\_Cortess, WATCHPUG, \_\_141345\_\_, anthony, ast3ros, berlin-101, blackhole, blockdev, carrotsmuggler, chaithanya\_gali, chalex.eth, coincoin, ctf\_sec, curiousapple, dacian, evilakela, eyexploit, immeas, innertia, jah, jprod15, juancito, kie, kiki\_dev, kutugu, lil.eth, m4ttm, martin, n33k, ni8mare, nobody2018, peanuts, qbs, qckhp, qpzm, saidam017, sakshamguruji, sam\_gmk, sashik\_eth, shaka, shealtielanz, shogoki, simon135, slightscan, tallo, theOwl, toshii, twicek, warRoom
## Summary

While making a swap on UniswapV3 the caller should use the slippage parameter `amountOutMinimum` and `deadline` parameter to avoid losing funds.

## Vulnerability Detail

[`UniV3SwapInput()`](https://github.com/sherlock-audit/2023-05-USSD/blob/main/ussd-contracts/contracts/USSD.sol#L227-L240) in `USSD` contract does not use the slippage parameter [`amountOutMinimum`](https://github.com/sherlock-audit/2023-05-USSD/blob/main/ussd-contracts/contracts/USSD.sol#L237)  nor [`deadline`](h

*[Content truncated...]*

---

### Example 17: M-20: UniV2Adapter#getExecutionData doesn't properly handle native ETH swaps

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/33 

## Found by 
Chom, 0x52

## Summary

UniV2Adapter#getExecutionData doesn't properly account for native ETH trades which makes them impossible. Neither method selected supports direct ETH trades, and sender/target are not set correctly for TradingUtils_executeTrade to automatically convert

## Vulnerability Detail

    spender = address(Deployments.UNIV2_ROUTER);
    target = address(Deployments.UNIV2_ROUTER);
    // msgValue is always zero for uniswap

    if (
        tradeType == TradeType.EXACT_IN_SINGLE ||
        tradeType == TradeType.EXACT_IN_BATCH
    ) {
        executionCallData = abi.encodeWithSelector(
            IUniV2Router2.swapExactTokensForTokens.selector,
            trade.amount,
            trade.limit,
            data.path,
            from,
            trade.deadline
        );
    } else if (
        tradeType == TradeType.EXACT_OUT_SINGLE ||
        tradeType == TradeType.EXACT_OUT_BATCH
    ) {
        executionCallData = abi.encodeWithSelector(
            IUniV2Router2.swapTokensForExactTokens.selector,
            trade.amount,
            trade.limit,
            data.path,
            from,
            trade.deadline
        );
    }

UniV2Adapter#getExecutionData either returns the swapTokensForExactTokens or swapExactTokensForTokens, neither of with support native ETH. It also doesn't set spender and target like UniV3Adapter, so _executeTrade won't automatically co

*[Content truncated...]*

---

### Example 18: M-21: Deployments.sol uses the wrong address for UNIV2 router which causes all Uniswap V2 calls to fail

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/32 

## Found by 
0x52

## Summary

Deployments.sol accidentally uses the Uniswap V3 router address for UNIV2_ROUTER which causes all Uniswap V2 calls to fail

## Vulnerability Detail

    IUniV2Router2 internal constant UNIV2_ROUTER = IUniV2Router2(0xE592427A0AEce92De3Edee1F18E0157C05861564);

The constant UNIV2_ROUTER contains the address for the Uniswap V3 router, which doesn't contain the "swapExactTokensForTokens" or "swapTokensForExactTokens" methods. As a result, all calls made to Uniswap V2 will revert.

## Impact

Uniswap V2 is totally unusable

## Code Snippet

[Deployments.sol#L25](https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/global/Deployments.sol#L25)

## Tool used

Manual Review

## Recommendation

Change UNIV2_ROUTER to the address of the V2 router:

    IUniV2Router2 internal constant UNIV2_ROUTER = IUniV2Router2(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);

## Discussion

**jeffywu**

@weitianjie2000 I believe this has been fixed subsequently

---

### Example 19: M-1: Calculation underflow/overflow in BalancerPairOracle, which will affect pools in Aura Finance

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/11 

## Found by 
n1punp
## Summary
LP price calculation for Balancer Pair in BalancerPairOracle will produce calculation underflow/overflow (so Aura pools won't work too).

## Vulnerability Detail
- The values r0, r1 can underflow, e.g. if resA < resB --> r0 = 0, so it'll go to the else case --> and so `ratio` will be 0 --> `fairResA` calculation will revert upon dividing by 0.
- There are also other math calculations there that will cause reverts, e.g. ratio ** wB will lead to overflow. What you'd need here is Balancer's implementation of `bpow` or similar.

## Impact
LP price for Balancer-like collateral token will revert in most cases, if not all.

## Code Snippet
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/oracle/BalancerPairOracle.sol#L53-L64

## Tool used

Manual Review

## Recommendation
- Change the calculation logic so it aligns with Alpha's original implementation (with precision control), e.g. https://github.com/AlphaFinanceLab/alpha-homora-v2-contract/blob/master/contracts/oracle/BalancerPairOracle.sol#L42-L53 (you can see there's BONE extra precision in each step)



## Discussion

**n1punp**

Escalate for 10 USDC.
I think this is incorrectly **excluded**. The issue is not related to **flashloan** via **BalancerPairOracle**, but rather an organic math overflow/underflow, since the implementation is directly using 0.8.x's default SafeMath mode. Up

*[Content truncated...]*

---

### Example 20: TRST-M-1 multiplication overflow in getPoolPrice() likely

**Source**: Trust Security
**Protocol**: Rysk Uniswapv3Rangeorderreactor
**Impact**: MEDIUM

**Details**:

**Description:**
`getPoolPrice()` is used in hedgeDelta to get the price directly from Uniswap v3 pool:
```solidity 
    function getPoolPrice() public view returns (uint256 price, uint256 
         inversed){
            (uint160 sqrtPriceX96, , , , , , ) = pool.slot0();
        uint256 p = uint256(sqrtPriceX96) * uint256(sqrtPriceX96) * (10 
        ** token0.decimals());
     // token0/token1 in 1e18 format
          price = p / (2 ** 192);
              inversed = 1e36 / price;
         }

```
The issue is that calculation of p is likely to overflow. sqrtPriceX96 has 96 bits for decimals, 
10** `token0.decimals()` will have 60 bits when decimals is 18, therefore there is only 
(256 – 2 * 96 – 60) / 2 = 2 bits for non-decimal part of sqrtPriceX96. 

**Recommended Mitigation:**
Consider converting the sqrtPrice to a 60x18 format and performing arithmetic operations 
using the PRBMathUD60x18 library.

**Team Response:**
Fixed

**Mitigation Review**
Calculations are now performed safely using the standard FullMath library

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2022-12-23-rysk UniswapV3RangeOrderReactor.md)

---

### Example 21: M-11: AuraSpell#closePositionFarm requires users to swap all reward tokens through same router

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/122 

## Found by 
0x52
## Summary

AuraSpell#closePositionFarm requires users to swap all reward tokens through same router. This is problematic as it is very unlikely that a UniswapV2 router will have good liquidity sources for all tokens and will result in users experiencing forced losses to their reward token.  

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

All tokens are forcibly swapped through a single router.

## Impact

Users will be forced to swap through a router even if it doesn't have good liquidity for all tokens

## Code Snippet

[AuraSpell.sol#L149-L224](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L149-L224)

## Tool used

Manual Review

## Recommendation

Allow users to use an aggregator like paraswap or multiple routers instead of only one single UniswapV2 router.

---

### Example 22: [L-08] UniswapV3Oracle: Reduce minObservations to uint16

**Source**: Code4rena
**Protocol**: Wild Credit
**Impact**: LOW

**Details**:

## Handle

greiart


## Vulnerability details

## Impact

Will help prevent erraneous `minObservations` values from being set (ie. `> 65535`) by the owner without needing checks. Otherwise, the `isPoolValid` will always return false, causing reverts in calling `tokenPrice` and `addPool` functions (and other functions calling these).

## Referenced Codelines

[https://github.com/code-423n4/2021-07-wildcredit/blob/main/contracts/UniswapV3Oracle.sol#L25](https://github.com/code-423n4/2021-07-wildcredit/blob/main/contracts/UniswapV3Oracle.sol#L25)

[https://github.com/code-423n4/2021-07-wildcredit/blob/main/contracts/UniswapV3Oracle.sol#L101](https://github.com/code-423n4/2021-07-wildcredit/blob/main/contracts/UniswapV3Oracle.sol#L101)

## Proof Of Concept

The maximum number of observations available is `65535` (see [https://github.com/Uniswap/uniswap-v3-core/blob/main/contracts/UniswapV3Pool.sol#L39](https://github.com/Uniswap/uniswap-v3-core/blob/main/contracts/UniswapV3Pool.sol#L39)), which is equivalent to `type(uint16).max`.

Hence, 

- `uint public minObservations` can be reduced to `uint16 public minObservations`.
- `(, , , , uint observationSlots , ,) = IUniswapV3Pool(poolAddress).slot0();` becomes `(, , , , uint16 observationSlots , ,) = IUniswapV3Pool(poolAddress).slot0();`

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-wildcredit)

---

## Statistics

- Total findings analyzed: 22
- Examples shown: 22
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

