# Swap Security Patterns

## Overview

**Frequency**: 18 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 12 | 6 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Check for swap vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Tokens are left in the protocol when the swap at the destination chain fails

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
- AmarokFacet.sol#L55-L94
- StargateFacet.sol#L149-L187
- NXTPFacet.sol#L86-L117
- Executor.sol#L125-L221
- XChainExecFacet.sol#L17-L51

## Description
LiFi protocol finds the best bridge route for users. In some cases, it helps users do a swap at the destination chain. With the help of the bridge protocols, the LiFi protocol assists users in triggering `swapAndComplete-BridgeTokensVia{Services}` or `CompleteBridgeTokensVia{Services}` at the destination chain to perform the swap.

Some bridge services will send the tokens directly to the receiver address when the execution fails. For example, Stargate, Amarok, and NXTP conduct the external call in a try-catch clause and send the tokens directly to the receiver when it fails. The tokens will remain in the LiFi protocol in this scenario. If the receiver is the Executor contract, users can freely pull the tokens. 

**Note:** Exploiters can pull the tokens from the LiFi protocol. Please refer to the issue **"Remaining tokens can be swept from the LiFi Diamond or the Executor," Issue #82**. Exploiters can take a more aggressive strategy and force the victim's swap to revert. A possible exploit scenario:

- A victim wants to swap 10K optimism’s BTC into Ethereum mainnet USDC.
- Since DEXs on the mainnet have the best liquidity, the LiFi protocol helps users swap on the mainnet.
- The transaction on the source chain (optimism) succeeds, and the bridge services try to call `Co

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 2: swapOut allows overwrite of token balance

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Analysis Report

## Severity
**Critical Risk**

## Context
- **StableSwapFacet.sol**: Lines 266-281
- **SwapUtils.sol**: Lines 740-781, Lines 417-473

## Description
The `StableSwapFacet` has the function `swapExactOut()` where a user could supply the same `assetIn` address as `assetOut`, which means the indexes for `tokenIndexFrom` and `tokenIndexTo` in the function `swapOut()` are the same.

In the function `swapOut()`, a temporary array is used to store balances. When updating these balances, first `self.balances[tokenIndexFrom]` is updated and then `self.balances[tokenIndexTo]` is updated afterward. 

However, when `tokenIndexFrom == tokenIndexTo`, the second update overwrites the first update, causing token balances to be arbitrarily lowered. This also skews the exchange rates, allowing for swaps where value can be extracted.

**Note:** The protection against this problem is located in the function `getY()`. However, this function is not called from `swapOut()`.

**Note:** The same issue exists in `swapInternalOut()`, which is called from `swapFromLocalAssetIfNeededForExactOut()` via `_swapAssetOut()`. However, via this route, it is not possible to specify arbitrary token indexes. Therefore, there isn’t an immediate risk here.

### Code Snippets
```solidity
contract StableSwapFacet is BaseConnextFacet {
    ...
    function swapExactOut(..., address assetIn, address assetOut, ...) ... {
        return s.swapStorages[canonicalId].swapOut(
            getSwapTo

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 3: [H-16] VaderRouter.calculateOutGivenIn calculates wrong swap

**Source**: Code4rena
**Protocol**: Vader Protocol
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The 3-path hop in `VaderRouter.calculateOutGivenIn` is supposed to first swap **foreign** assets to native assets **in pool0**, and then the received native assets to different foreign assets again **in pool1**.

The first argument of `VaderMath.calculateSwap(amountIn, reserveIn, reserveOut)` must refer to the same token as the second argument `reserveIn`.
The code however mixes these positions up and first performs a swap in `pool1` instead of `pool0`:

```solidity
function calculateOutGivenIn(uint256 amountIn, address[] calldata path)
    external
    view
    returns (uint256 amountOut)
{
  if(...) {
  } else {
    return
        VaderMath.calculateSwap(
            VaderMath.calculateSwap(
                // @audit the inner trade should not be in pool1 for a forward swap. amountIn foreign => next param should be foreignReserve0
                amountIn,
                nativeReserve1,
                foreignReserve1
            ),
            foreignReserve0,
            nativeReserve0
        );
  }

 /** @audit instead should first be trading in pool0!
    VaderMath.calculateSwap(
        VaderMath.calculateSwap(
            amountIn,
            foreignReserve0,
            nativeReserve0
        ),
        nativeReserve1,
        foreignReserve1
    );
  */
```

## Impact
All 3-path swaps computations through `VaderRouter.calculateOutGivenIn` will return the wrong result.
Smart contracts or off-chain scripts/frontends th

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-vader)

---

### Example 4: [H-15] VaderRouter._swap performs wrong swap

**Source**: Code4rena
**Protocol**: Vader Protocol
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The 3-path hop in `VaderRouter._swap` is supposed to first swap **foreign** assets to native assets, and then the received native assets to different foreign assets again.

The `pool.swap(nativeAmountIn, foreignAmountIn)` accepts the foreign amount as the **second** argument.
The code however mixes these positional arguments up and tries to perform a `pool0` foreign -> native swap by using the **foreign** amount as the **native amount**:

```solidity
function _swap(
    uint256 amountIn,
    address[] calldata path,
    address to
) private returns (uint256 amountOut) {
    if (path.length == 3) {
      // ...
      // @audit calls this with nativeAmountIn = amountIn. but should be foreignAmountIn (second arg)
      return pool1.swap(0, pool0.swap(amountIn, 0, address(pool1)), to);
    }
}

// @audit should be this instead
return pool1.swap(pool0.swap(0, amountIn, address(pool1)), 0, to);
```

## Impact
All 3-path swaps through the `VaderRouter` fail in the pool check when `require(nativeAmountIn = amountIn <= nativeBalance - nativeReserve = 0)` is checked, as foreign amount is sent but _native_ amount is specified.

## Recommended Mitigation Steps
Use `return pool1.swap(pool0.swap(0, amountIn, address(pool1)), 0, to);` instead.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-vader)

---

### Example 5: [H-04] Swaps are not split when trade crosses target price

**Source**: Code4rena
**Protocol**: Boot Finance
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by gzeon_

The protocol uses two amplifier values A1 and A2 for the swap, depending on the target price, see `SwapUtils.determineA`.
The swap curve is therefore a join of two different curves at the target price.
When doing a trade that crosses the target price, it should first perform the trade partially with A1 up to the target price, and then the rest of the trade order with A2.

However, the `SwapUtils.swap / _calculateSwap` function does not do this, it only uses the "new A", see `getYC` step 5.

```solidity
// 5. Check if we switched A's during the swap
if (aNew == a){     // We have used the correct A
    return y;
} else {    // We have switched A's, do it again with the new A
    return getY(self, tokenIndexFrom, tokenIndexTo, x, xp, aNew, d);
}
```

#### Impact

Trades that cross the target price and would lead to a new amplifier being used are not split up and use the new amplifier for the *entire trade*.
This can lead to a worse (better) average execution price than manually splitting the trade into two transactions, first up to but below the target price, and a second one with the rest of the trader order size, using both A1 and A2 values.

In the worst case, it could even be possible to make the entire trade with one amplifier and then sell the swap result again using the other amplifier making a profit.

#### Recommended Mitigation Steps

Trades that lead to a change in amplifier value need to be split up into two trades using 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-bootfinance)

---

### Example 6: Pulling tokens by LibSwap.swap() is counterintuitive

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Vulnerability Report

### Severity
**Medium Risk**

### Context
- `LibSwap.sol#L30-L68`
- `SwapperV2.sol#L67-L81`
- `Swapper.sol#L65-L78`
- `Executor.sol#L323-L333`

### Description
The function `LibSwap.swap()` pulls in tokens via `transferFromERC20()` from `msg.sender` when needed. When put in a loop, through `_executeSwaps()`, it can pull in multiple different tokens. It also doesn’t detect accidentally sending native tokens along with ERC20 tokens. This approach is counterintuitive and leads to risks.

Suppose someone wants to swap 100 USDC to 100 DAI and then 100 DAI to 100 USDT. If the first swap somehow gives back fewer tokens (for example, 90 DAI), then `LibSwap.swap()` pulls in 10 extra DAI from `msg.sender`. **Note**: This requires the `msg.sender` to have given multiple allowances to the LiFi Diamond.

Another risk is that an attacker could trick a user into signing a transaction for the LiFi protocol. Within one transaction, it can sweep multiple tokens from the user, potentially clearing out the entire wallet. **Note**: This also requires the `msg.sender` to have given multiple allowances to the LiFi Diamond.

In `Executor.sol`, the tokens are already deposited, so the "pull" functionality is not needed and can even result in additional issues. In `Executor.sol`, it tries to "pull" tokens from `msg.sender` itself. In the best-case scenario of ERC20 implementations (like OpenZeppelin and Solmate), this has no effect. However, some non-standard ERC20 implementat

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 7: H-14: Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

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

### Example 8: [H-07] Missing slippage checks

**Source**: Code4rena
**Protocol**: Spartan Protocol
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by tensors_

There are no minimum amounts out, or checks that frontrunning/slippage is sufficiently mitigated.
This means that anyone with enough capital can force arbitrarily large slippage by sandwiching transactions, close to 100%. See issue page for referenced code.

Recommend adding a minimum amount out parameter. The function reverts if the minimum amount isn't obtained.

**[verifyfirst (Spartan) acknowledge:](https://github.com/code-423n4/2021-07-spartan-findings/issues/85#issuecomment-884593067)**
> We acknowledge the issue for the protocol's AMM, but if this becomes a large issue in the future, the router is easily upgradeable to include a minimum rate parameter.

**[SamusEldburg (Spartan) confirmed and disagreed with severity:](https://github.com/code-423n4/2021-07-spartan-findings/issues/85#issuecomment-889638485)**
> Have changed this to confirmed; even though we already were aware of it; we have discussed and are happy to add in a UI-handed arg for minAmount now rather than reactively in the future. Disagree with severity though; this wasn't a problem with V1 at all.

**[ghoul-sol (Judge) commented](https://github.com/code-423n4/2021-07-spartan-findings/issues/85#issuecomment-894863717):**
> I'll keep high risk as sandwich attacks are very common and risk of getting a bad swap is real.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-spartan)

---

### Example 9: Check slippage of swaps

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
OmniBridgeFacet.sol#L63-L65

## Description
Several bridges check that the output of swaps isn’t 0. However, it could also happen that a swap gives a positive output, but still lower than expected due to slippage, sandwiching, or MEV. Several AMMs will have a mechanism to limit slippage, but it might be useful to add a generic mechanism as multiple swaps in sequence might have a relatively large slippage.

```solidity
function swapAndStartBridgeTokensViaOmniBridge(...) {
    ...
    uint256 amount = _executeAndCheckSwaps(_lifiData, _swapData, payable(msg.sender));
    if (amount == 0) {
        revert InvalidAmount();
    }
    _startBridge(_lifiData, _bridgeData, amount, true);
}
```

## Recommendation
Consider adding a slippage check by specifying a minimum amount of expected tokens. At least add a check for `amount == 0` in all bridges.

## LiFi
Fixed with PR #75.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 10: SwapManager assumes Morpho token is token0 of every token pair

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
`SwapManagerUniV2.sol#L106`

## Description
The `consult` function wrongly assumes that the Morpho token is always the first token (`token0`) in the Morpho <> Reward token token pair. This could lead to inverted prices and a denial of service attack when claiming rewards, as the wrongly calculated expected amount slippage check reverts.

## Recommendation
Consider using similar code to the example UniswapV2 oracle. Note that depending on how this issue is fixed in `consult`, the caller of this function needs to be adjusted as well to return a Morpho token amount as `amountOut`.

## Morpho
Fixed in PR #585.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 11: [H-04] Members lose SPARTA tokens in removeLiquiditySingle()

**Source**: Code4rena
**Protocol**: Spartan Protocol
**Impact**: HIGH

**Details**:

## Handle

0xRajeev


## Vulnerability details

## Impact

When a member calls removeLiquiditySingle() requesting only SPARTA in return, i.e. toBASE = true, the LP tokens are transferred to the Pool to withdraw the constituent SPARTA and TOKENs back to the Router. The withdrawn TOKENs are then transferred back to the Pool to convert to SPARTA and directly transferred to the member from the Pool. However, the member’s SPARTA are left behind in the Router instead of being returned along with converted SPARTA from the Pool. 

In other words, the _member's BASE SPARTA tokens that were removed from the Pool along with the TOKENs are never sent back to the _member because the _token's transferred to the Pool are converted to SPARTA and only those are sent back to member directly from the Pool via swapTo(). 

This effectively results in member losing the SPARTA component of their Pool LP tokens which get left behind in the Router and are possibly claimed by future transactions that remove SPARTA from Router.

## Proof of Concept

LPs sent to Pool: https://github.com/code-423n4/2021-07-spartan/blob/e2555aab44d9760fdd640df9095b7235b70f035e/contracts/Router.sol#L121

SPARTA and TOKENs withdrawn from Pool to Router: https://github.com/code-423n4/2021-07-spartan/blob/e2555aab44d9760fdd640df9095b7235b70f035e/contracts/Router.sol#L122

TOKENs from Router sent to Pool: https://github.com/code-423n4/2021-07-spartan/blob/e2555aab44d9760fdd640df9095b7235b70f035e/contracts/Router.sol#L126

TOKE

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-spartan)

---

### Example 12: H-9: UniswapV3 sqrtRatioLimit doesn't provide slippage protection and will result in partial swaps

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

### Example 13: H-1: Attacker can steal the accumulated topup fees in the `topupproxy` contract's balance

**Source**: Sherlock
**Protocol**: Mover
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-mover-judging/issues/112 

## Found by 
minhquanym, Jeiwan, 0x52, hansfriese, WATCHPUG, GalloDaSballo, berndartmueller

## Summary

The accumulated fees in the `topupproxy` contract's balance can be stolen by an attacker by using malicious `_bridgeTxData` and using `1inch`'s as `targetAddress`.

## Vulnerability Detail

This attack vector is enabled by multiple traits of the `topupproxy` contract:

#### 1. Shared whitelist

Per to deploy script, the same `trustedregistry` will be shared among `exchangeproxy` and `topupproxy`.

Therefore, the 2 whitelisted swap aggregator contracts will also be allowed to be called on `topupproxy`:

- 0x Proxy
- 1inch Proxy

And the 2 whitelisted bridge contracts can be called on `exchangeproxy`:

- Synapse
- Across

#### 2. Unlimited allowance rather than only the amount of the current topup to the bridge's `targetAddress`

At L414, the `targetAddress` will be granted an unlimited allowance rather than just the amount of the current transaction.

https://github.com/sherlock-audit/2022-10-mover/blob/main/cardtopup_contract/contracts/HardenedTopupProxy.sol#L414

#### 3. `1inch` can be used to pull an arbitrary amount of funds from the caller and execute arbitrary call

The design of `1inch`'s `AggregationRouterV4` can be used to pull funds from the `topupproxy` and execute arbitrary external call:

https://polygonscan.com/address/0x1111111254fb6c44bAC0beD2854e76F90643097d#code

See L2309-2321.



*[Content truncated...]*

---

### Example 14: [M-03] Anyone can call AutoPxGmx.compound and perform sandwich attacks with control parameters

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

AutoPxGmx.compound allows anyone to call to compound the reward and get the incentive.

However, AutoPxGmx.compound calls `SWAP_ROUTER`.exactInputSingle with some of the parameters provided by the caller, which allows the user to perform a sandwich attack for profit.

For example, a malicious user could provide the fee parameter to make the token swap occur in a small liquid pool, and could make the amountOutMinimum parameter 1 to make the token swap accept a large slippage, thus making it easier to perform a sandwich attack.

### Proof of Concept

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L242-L278>

### Recommended Mitigation Steps

Consider using poolFee as the fee and using an onchain price oracle to calculate the amountOutMinimum.

**[Picodes (judge) commented](https://github.com/code-423n4/2022-11-redactedcartel-findings/issues/91#issuecomment-1337106500):**
 > Flagging as best as the warden identifies that the main risk is not the possibility to increase fees but the fact that some of the pools will be highly illiquid.

**[drahrealm (Redacted Cartel) disagreed with severity and commented](https://github.com/code-423n4/2022-11-redactedcartel-findings/issues/91#issuecomment-1342052424):**
 > Please refer to:
> https://github.com/code-423n4/2022-11-redactedcartel-findings/issues/185#issuecomment-1341252133

**[Picodes (judge) commented](https://github.com/code-423n4/2022-11-redactedcartel-f

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 15: [M-02] Preventing any user from calling the functions `withdraw`, `redeem`, or `depositGmx` in contract `AutoPxGmx`

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

It is possible that an attacker can prevent any user from calling the functions `withdraw`, `redeem`, or `depositGmx` in contract `AutoPxGmx` by just manipulating the balance of token `gmxBaseReward`, so that during the function `compound` the swap will be reverted.

### Proof of Concept

Whenever a user calls the functions `withdraw`, `redeem`, or `depositGmx` in contract `AutoPxGmx`, the function `compound` is called:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L321>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L345>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L379>

The function `compound` claims token `gmxBaseReward` from `rewardModule`:
<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L262>

Then, if the balance of the token `gmxBaseReward` in custodian of the contract `AutoPxGmx` is not zero, the token `gmxBaseReward` will be swapped to token `GMX` thrrough uniswap V3 by calling the function `exactInputSingle`. Then the total amount of token `GMX` in custodian of the contract `AutoPxGmx` will be deposited in the contract `PirexGmx` to receive token `pxGMX`:

    if (gmxBaseRewardAmountIn != 0) {
                gmxAmountOut = SWAP_ROUTER.exactInputSingle(

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 16: H-10: Balance check for swapToken in ShortLongSpell#_deposit is incorrect and will result in nonfunctional contract

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/133 

## Found by 
0x52, Ch\_301, sinarette
## Summary

The balance checks on ShortLongSpell#_withdraw are incorrect and will make contract basically nonfunctional 

## Vulnerability Detail

swapToken is always vault.uToken. borrowToken is always required to be vault.uToken which means that swapToken == borrowToken. This means that the token borrowed is always required to be swapped. 

[ShortLongSpell.sol#L83-L89](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L83-L89)

        uint256 strTokenAmt = _doBorrow(param.borrowToken, param.borrowAmount);

        // 3. Swap borrowed token to strategy token
        IERC20Upgradeable swapToken = ISoftVault(strategy.vault).uToken();
        // swapData.fromAmount = strTokenAmt;
        PSwapLib.megaSwap(augustusSwapper, tokenTransferProxy, swapData);
        strTokenAmt = swapToken.balanceOf(address(this)) - strTokenAmt; <- @audit-issue will always revert on swap

Because swapToken == borrowToken if there is ever a swap then the swapToken balance will decrease. This causes L89 to always revert when a swap happens, making the contract completely non-functional

## Impact

ShortLongSpell is nonfunctional

## Code Snippet

[ShortLongSpell.sol#L160-L202](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L160-L202)

## Tool used

Manual Revi

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

### Example 18: M-11: AuraSpell#closePositionFarm requires users to swap all reward tokens through same router

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

## Statistics

- Total findings analyzed: 18
- Examples shown: 18
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

