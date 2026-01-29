# Slippage Security Patterns

## Overview

**Frequency**: 36 occurrences (0.07% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 21 | 14 | 1 | 0 |

**Common Sources**: Sherlock, Code4rena, Spearbit, Codehawks, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for slippage vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Overpayment of one side of LP Pair onJoinPool due to sandwich or user error

**Source**: Spearbit
**Protocol**: Cron Finance
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
`CronV1Pool.sol#L2048-L2051`

## Description
Only one of the two incoming tokens is used to determine the amount of pool tokens minted (`amountLP`) on join:

```solidity
amountLP = Math.min(
    _token0InU112.mul(supplyLP).divDown(_token0ReserveU112),
    _token1InU112.mul(supplyLP).divDown(_token1ReserveU112)
);
```

In the event the price moves between the time a minter sends their transaction and when it is included in a block, they may overpay for one of `_token0InU112` or `_token1InU112`. This can occur due to user error, or due to being sandwiched.

### Concrete Example:
```solidity
pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;
import "forge-std/Test.sol";
import "../HelperContract.sol";
import { C } from "../../Constants.sol";
import { ExecVirtualOrdersMem } from "../../Structs.sol";

contract JoinSandwich is HelperContract {
    uint256 WAD = 10**18;

    function testManualJoinSandwich() public {
        address userA = address(this);
        address userB = vm.addr(1323);
        
        // Add some base liquidity from the future attacker.
        addLiquidity(pool, userA, userA, 10**7 * WAD, 10**7 * WAD, 0);
        assertEq(CronV1Pool(pool).balanceOf(userA), 10**7 * WAD - C.MINIMUM_LIQUIDITY);
        
        // Give userB some tokens to LP with.
        token0.transfer(userB, 1_000_000 * WAD);
        token1.transfer(userB, 1_000_000 * WAD);
        addLiquidity(pool, userB, userB, 10**6

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/CronFinance-Spearbit-Security-Review.pdf)

---

### Example 2: [H-01] Hard-coded slippage may freeze user funds during market turbulence

**Source**: Code4rena
**Protocol**: Sturdy
**Impact**: HIGH

**Details**:

_Submitted by jonah1005, also found by berndartmueller, Picodes, IllIllI, sorrynotsorry, and WatchPug_

[GeneralVault.sol#L125](https://github.com/code-423n4/2022-05-sturdy/blob/main/smart-contracts/GeneralVault.sol#L125)<br>
GeneralVault set a hardcoded slippage control of 99%. However, the underlying yield tokens price may go down.<br>
If Luna/UST things happen again, users' funds may get locked.<br>

[LidoVault.sol#L130-L137](https://github.com/code-423n4/2022-05-sturdy/blob/main/smart-contracts/LidoVault.sol#L130-L137)<br>
Moreover, the withdrawal of the lidoVault takes a swap from the curve pool. 1 stEth worth 0.98 ETH at the time of writing.<br>
The vault can not withdraw at the current market.<br>

Given that users' funds would be locked in the lidoVault, I consider this a high-risk issue.

### Proof of Concept

[1 stEth  = 0.98 Eth](https://twitter.com/hasufl/status/1524717773959700481/photo/1)

[LidoVault.sol#L130-L137](https://github.com/code-423n4/2022-05-sturdy/blob/main/smart-contracts/LidoVault.sol#L130-L137)

### Recommended Mitigation Steps

There are different ways to set the slippage.

The first one is to let users determine the maximum slippage they're willing to take.
The protocol front-end should set the recommended value for them.

```solidity
  function withdrawCollateral(
    address _asset,
    uint256 _amount,
    address _to,
    uint256 _minReceiveAmount
  ) external virtual {
      // ...
    require(withdrawAmount >= _minReceiveAmount, Errors.VT_

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-sturdy)

---

### Example 3: H-11: The deposit / withdraw / trade transaction lack of expiration timestamp check and slippage control

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/39 

## Found by 
ctf\_sec

## Summary

The deposit / withdraw / trade transaction lack of expiration timestamp and slippage control

## Vulnerability Detail

Let us look into the heavily forked Uniswap V2 contract addLiquidity function implementation

https://github.com/Uniswap/v2-periphery/blob/0335e8f7e1bd1e8d8329fd300aea2ef2f36dd19f/contracts/UniswapV2Router02.sol#L61

```solidity
// **** ADD LIQUIDITY ****
function _addLiquidity(
	address tokenA,
	address tokenB,
	uint amountADesired,
	uint amountBDesired,
	uint amountAMin,
	uint amountBMin
) internal virtual returns (uint amountA, uint amountB) {
	// create the pair if it doesn't exist yet
	if (IUniswapV2Factory(factory).getPair(tokenA, tokenB) == address(0)) {
		IUniswapV2Factory(factory).createPair(tokenA, tokenB);
	}
	(uint reserveA, uint reserveB) = UniswapV2Library.getReserves(factory, tokenA, tokenB);
	if (reserveA == 0 && reserveB == 0) {
		(amountA, amountB) = (amountADesired, amountBDesired);
	} else {
		uint amountBOptimal = UniswapV2Library.quote(amountADesired, reserveA, reserveB);
		if (amountBOptimal <= amountBDesired) {
			require(amountBOptimal >= amountBMin, 'UniswapV2Router: INSUFFICIENT_B_AMOUNT');
			(amountA, amountB) = (amountADesired, amountBOptimal);
		} else {
			uint amountAOptimal = UniswapV2Library.quote(amountBDesired, reserveB, reserveA);
			assert(amountAOptimal <= amountADesired);
			require(amountAOptimal >= amountAMin

*[Content truncated...]*

---

### Example 4: User may not be able to override slippage on destination

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
BridgeFacet.sol#L741-L746

## Description
If `BridgeFacet.execute()` is executed before `BridgeFacet.forceUpdateSlippage()`, the user won't be able to update slippage on the destination chain. In this case, the slippage specified on the source chain is used. Due to different conditions on these chains, a user may want to specify different slippage values. This can result in user loss, as a slippage higher than necessary will result in the swap trade being sandwiched.

## Recommendation
`xcall()` can take different parameters for source and destination slippage:

```solidity
function xcall(
    uint32 _destination,
    address _to,
    address _asset,
    address _delegate,
    uint256 _amount,
    // uint256 _slippage,
    uint256 _sourceSlippage,
    uint256 _destinationSlippage,
    bytes calldata _callData
) external payable returns (bytes32);
```

Then, `TransferInfo` params should be encoded with `_destinationSlippage` and `_sourceSlippage` should be passed separately to `_xcall()`.

## Connext
We previously had the slippage implemented as separate values but decided to change it back for a couple of reasons:
1. Since the messages chains have variable latency, the `destinationChainSlippage` would be hard to predict at the time of `xcall`, especially for authenticated messages. Users can override this using `forceUpdateSlippage`, but it requires an additional transaction.
2. Adding two parameters to the interface clutters it, and we st

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 5: [M-06] Assets may be lost when calling unprotected `AutoPxGlp::compound` function

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/main/src/vaults/AutoPxGlp.sol#L210>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/main/src/PirexGmx.sol#L497-L516>

### Impact

Compounded assets may be lost because `AutoPxGlp::compound` can be called by anyone and minimum amount of Glp and USDG are under caller's control. The only check concerning minValues is that they are not zero (1 will work, however from the perspective of real tokens e.g. 1e6, or 1e18 it's virtually zero). Additionally, internal smart contract functions use it as well with minimal possible value (e.g. `beforeDeposit` function).

### Proof of Concept

`compound` function calls PirexGmx::depositGlp, that uses external GMX reward router to mint and stake GLP.

<https://snowtrace.io/address/0x82147c5a7e850ea4e28155df107f2590fd4ba327#code>

```solidity
141:     function mintAndStakeGlpETH(uint256 _minUsdg, uint256 _minGlp) external payable nonReentrant returns (uint256) {
    ...
148: uint256 glpAmount = IGlpManager(glpManager).addLiquidityForAccount(address(this), account, weth, msg.value, _minUsdg, _minGlp);
```

Next `GlpManager::addLiquidityForAccount` is called
<https://github.com/gmx-io/gmx-contracts/blob/master/contracts/core/GlpManager.sol#L103>

        function addLiquidityForAccount(address _fundingAccount, address _account, address _token, uint256 _amount, uint256 _minUsdg, uint256 _minGlp) external override nonReentrant returns (uint256) {
            _validateHandler();


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 6: H-4: No slippage protection during repayment due to dynamic slippage params and easily influenced `slot0()`

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

### Example 7: H-4: Deposit transactions lose funds to front-running when multiple fee tiers are available

**Source**: Sherlock
**Protocol**: RealWagmi
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-real-wagmi-judging/issues/105 

## Found by 
crimson-rat-reach
## Summary
Deposit transactions lose funds to front-running when multiple fee tiers are available 

## Vulnerability Detail
The deposit transaction takes in minimum parameters for amount0 and amount1 of tokens that the user wishes to deposit, but no parameter for the minimum number of LP tokens the user expects to receive. A malicious actor can limit the number of LP tokens that the user receives in the following way:

A user Alice submits a transaction to deposit tokens into Multipool where (amount0Desired, amount0Min) > (amount1Desired, amount1Min)

A malicious actor Bob can front-run this transaction if there are multiple feeTiers:
- by first moving the price of feeTier1 to make tokenA very cheap (lots of tokenA in the pool) 
- then moving the price of feeTier2 in opposite direction to make tokenB very cheap (lots of tokenB in the pool) 

This results in reserves being balanced accross feeTiers, and the amounts resulting from `_optimizeAmounts` are balanced as well:
https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L780-L808

So the minimum amounts checks pass and but results as less LP tokens minted, because even though the reserves are balanced, they are also overinflated due to the large swap, and the ratio:
https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c

*[Content truncated...]*

---

### Example 8: H-14: Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

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

### Example 9: H-6: ShortLongSpell#_withdraw checks slippage limit but never applies it making it useless

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/126 

## Found by 
0x52, Ch\_301
## Summary

Slippage limits protect the protocol in the event that a malicious user wants to extract value via swaps, this is an important protection in the event that a user finds a way to trick collateral requirements. Currently the sell slippage is checked but never applied so it is useless.

## Vulnerability Detail

See summary.

## Impact

Slippage limit protections are ineffective for ShortLongSpell

## Code Snippet

[ShortLongSpell.sol#L160-L20](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L160-L202)

## Tool used

Manual Review

## Recommendation

Apply sell slippage after it is checked



## Discussion

**securitygrid**

Escalate for 10 USDC
This is not a valid M/H. The toAmont and expectedAmount in the off-chain parameter [MegaSwapSellData](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/libraries/Paraswap/Utils.sol#L30-L42) structure are the real slippage protection parameters. Just like ExactInputParams/ExactOutputParams of uniswapV3 pool.

**sherlock-admin**

 > Escalate for 10 USDC
> This is not a valid M/H. The toAmont and expectedAmount in the off-chain parameter [MegaSwapSellData](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/libraries/Paraswap/Utils.sol#L30-L42) structure are the real slippage protection par

*[Content truncated...]*

---

### Example 10: [H-07] Missing slippage checks

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

### Example 11: Check slippage of swaps

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

### Example 12: deposit and withdraw functions are susceptible to sandwich attacks

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: HIGH

**Details**:

## High Risk Vulnerability Report

**Severity:** High Risk  
**Context:** AeraVaultV1.sol#L402-L453, AeraVaultV1.sol#L456-L514  
**Description:** Transactions calling the `deposit()` function are susceptible to sandwich attacks where an attacker can extract value from deposits. A similar issue exists in the `withdraw()` function but the minimum check on the pool holdings limits the attack’s impact.

## Scenario Example
(Assuming swap fees are ignored for simplicity):

1. Suppose the Balancer pool contains two tokens, WETH and DAI, with weights of 0.5 each. Currently, there is 1 WETH and 3k DAI in the pool, and the WETH spot price is 3k.
2. The Treasury wants to add another 3k DAI into the Aera vault, so it calls the `deposit()` function.
3. The attacker front-runs the Treasury’s transaction. They swap 3k DAI into the Balancer pool and receive 0.5 WETH. The weights remain 0.5 and 0.5, but because WETH and DAI balances become 0.5 and 6k, WETH’s spot price now becomes 12k.
4. At this point, the Treasury’s transaction adds 3k DAI into the Balancer pool and changes the weights to 0.6 and 0.4.
5. The attacker back-runs the transaction and swaps the 0.5 WETH acquired in step 3 back to DAI, recovering WETH’s spot price to slightly above 3k. According to the current weights, they can receive 9k * (1 - 1/r) = 3.33k DAI from the pool, where r = (2^0.4)^(1/0.6).
6. As a result, the attacker profits 3.33k - 3k = 0.33k DAI.

## Recommendations
Potential mitigations include:

- Adopting a t

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 13: Users are forced to accept any slippage on the destination chain

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
BridgeFacet.sol#L28

## Description
The documentation mentioned that there is a cancel function on the destination domain that allows users to send the funds back to the origin domain, accepting the loss incurred by slippage from the origin pool. However, this feature is not found in the current codebase. If the high slippage rate persists continuously on the destination domain, the users will be forced to accept the high slippage rate. Otherwise, their funds will be stuck in Connext.

## Recommendation
Implement the cancel function on the destination domain to allow users to send funds back to the origin domain if they choose not to accept the high slippage rate on the destination domain.

## Connext
Solved in PR 2456.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 14: Routers are exposed to extreme slippage if they attempt to repay debt before being reconciled

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## High Risk Severity Report

## Context
- NomadFacet.sol#L188-L209
- NomadFacet.sol#L269-L320
- AssetLogic.sol#L228-L250
- AssetLogic.sol#L308-L362

## Description
When routers are reconciled, the local asset may need to be exchanged for the adopted asset in order to repay the unbacked Aave loan. `AssetLogic.swapFromLocalAssetIfNeededForExactOut()` takes two key arguments:
- **_amount**: representing exactly how much of the adopted asset should be received.
- **_maxIn**: which is used to limit slippage and limit how much of the local asset is used in the swap.

Upon failure to swap, the protocol will reset the values for unbacked Aave debt and distribute local tokens to the router. However, if this router partially paid off some of the unbacked Aave debt before being reconciled, **_maxIn** will diverge from **_amount**, allowing value to be extracted in the form of slippage. As a result, routers may receive less than the amount of liquidity they initially provided, leading to router insolvency.

## Recommendation
Instead of using **_amount** to represent **_maxIn**, consider using some sort of user slippage amount. Alternatively, it may be easier/safer to restrict who can use Aave unbacked debt as there is a lot of added complexity in integrating unbacked debt into the protocol.

## Connext
Solved in PR 1585.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 15: M-11: Withdrawals from IchiVaultSpell have no slippage protection so can be frontrun, stealing all user funds

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/130 

## Found by 
rvierdiiev, obront, koxuan, ctf\_sec, tives, cergyk, berndartmueller, 0x52

## Summary

When a user withdraws their position through the `IchiVaultSpell`, part of the unwinding process is to trade one of the released tokens for the other, so the borrow can be returned. This trade is done on Uniswap V3. The parameters are set in such a way that there is no slippage protection, so any MEV bot could see this transaction, aggressively sandwich attack it, and steal the majority of the user's funds.

## Vulnerability Detail

Users who have used the `IchiVaultSpell` to take positions in Ichi will eventually choose to withdraw their funds. They can do this by calling `closePosition()` or `closePositionFarm()`, both of which call to `withdrawInternal()`, which follows loosely the following logic:
- sends the LP tokens back to the Ichi vault for the two underlying tokens (one of which was what was borrowed)
- swaps the non-borrowed token for the borrowed token on UniV3, to ensure we will be able to pay the loan back
- withdraw our underlying token from the Compound fork
- repay the borrow token loan to the Compound fork
- validate that we are still under the maxLTV for our strategy
- send the funds (borrow token and underlying token) back to the user

The issue exists in the swap, where Uniswap is called with the following function:
```solidity
if (amountToSwap > 0) {
    swapPool = IUniswapV3

*[Content truncated...]*

---

### Example 16: [H-01] Minting and burning synths exposes users to unlimited slippage

**Source**: Code4rena
**Protocol**: Vader Protocol
**Impact**: HIGH

**Details**:

_Submitted by TomFrenchBlockchain, also found by cmichel_

#### Impact

The amount of synths minted / assets received when minting or burning synths can be manipulated to an unlimited extent by manipulating the reserves of the pool

#### Proof of Concept

See `VaderPool.mintSynth`:
<https://github.com/code-423n4/2021-11-vader/blob/607d2b9e253d59c782e921bfc2951184d3f65825/contracts/dex-v2/pool/VaderPoolV2.sol#L126-L167>

Here a user sends `nativeDeposit` to the pool and the equivalent amount of `foreignAsset` is minted as a synth to be sent to the user. However the user can't specify the minimum amount of synth that they would accept. A frontrunner can then manipulate the reserves of the pool in order to make `foreignAsset` appear more valuable than it really is so the user receives synths which are worth much less than what `nativeDeposit` is worth. This is equivalent to a swap without a slippage limit.

Burning synths essentially runs the same process in behalf so manipulating the pool in the opposite direction will result in the user getting fewer of `nativeAsset` than they expect.

#### Recommended Mitigation Steps

Add a argument for the minimum amount of synths to mint or nativeAsset to receive.

**[SamSteinGG (Vader) acknowledged and disagreed with severity](https://github.com/code-423n4/2021-11-vader-findings/issues/2#issuecomment-979099464):**
 > We believe the severity should be set to medium as there are no loss of funds and its exploit requires special circumstance

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-vader)

---

### Example 17: [M-02] Slippage controls for calling `bHermes` contract's `ERC4626DepositOnly.deposit` and `ERC4626DepositOnly.mint` functions are missing

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: MEDIUM

**Details**:

[EIPS](<https://eips.ethereum.org/EIPS/eip-4626#security-considerations>) mentions that "if implementors intend to support EOA account access directly, they should consider adding an additional function call for `deposit`/`mint`/`withdraw`/`redeem` with the means to accommodate slippage loss or unexpected deposit/withdrawal limits, since they have no other means to revert the transaction if the exact output amount is not achieved."

Using the `bHermes` contract that inherits the `ERC4626DepositOnly` contract, EOAs can call the `ERC4626DepositOnly.deposit` and `ERC4626DepositOnly.mint` functions directly. However, because no slippage controls can be specified when calling these functions, these function's `shares` and `assets` outputs can be less than expected to these EOAs.

<https://github.com/code-423n4/2023-05-maia/blob/53c7fe9d5e55754960eafe936b6cb592773d614c/src/erc-4626/ERC4626DepositOnly.sol#L32-L44>

```solidity
    function deposit(uint256 assets, address receiver) public virtual returns (uint256 shares) {
        // Check for rounding error since we round down in previewDeposit.
        require((shares = previewDeposit(assets)) != 0, "ZERO_SHARES");

        // Need to transfer before minting or ERC777s could reenter.
        address(asset).safeTransferFrom(msg.sender, address(this), assets);

        _mint(receiver, shares);

        emit Deposit(msg.sender, receiver, assets, shares);

        afterDeposit(assets, shares);
    }
```

<https://github.com/code-423n4/

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 18: M-1: `rebalanceLite` should provide a slippage protection

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/429 

## Found by 
HollaDieWaldfee, hansfriese

## Summary
Users can lose funds while rebalancing.

## Vulnerability Detail
The protocol provides two kinds of rebalancing functions - `rebalance()` and `rebalanceLite()`.
While the function `rebalance()` is protected from an unintended slippage because the caller can specify `amountOutMinimum`, `rebalanceLite()` does not have this protection.
This makes the user vulnerable to unintended slippage due to various scenarios.
```solidity
PerpDepository.sol
597:     function rebalanceLite(
598:         uint256 amount,
599:         int8 polarity,
600:         uint160 sqrtPriceLimitX96,
601:         address account
602:     ) external nonReentrant returns (uint256, uint256) {
603:         if (polarity == -1) {
604:             return
605:                 _rebalanceNegativePnlLite(amount, sqrtPriceLimitX96, account);
606:         } else if (polarity == 1) {
607:             // disable rebalancing positive PnL
608:             revert PositivePnlRebalanceDisabled(msg.sender);
609:             // return _rebalancePositivePnlLite(amount, sqrtPriceLimitX96, account);
610:         } else {
611:             revert InvalidRebalance(polarity);
612:         }
613:     }
614:
615:     function _rebalanceNegativePnlLite(
616:         uint256 amount,
617:         uint160 sqrtPriceLimitX96,
618:         address account
619:     ) private returns (uint256, uint256) {
620:         uin

*[Content truncated...]*

---

### Example 19: H-9: UniswapV3 sqrtRatioLimit doesn't provide slippage protection and will result in partial swaps

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

### Example 20: H-6: User specified slippage allows frontrunning

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/192 

## Found by 
zeroknots, minhtrng, keccak123, peanuts, ck, HollaDieWaldfee, HonorLt, koxuan, GimelSec, wagmi, yixxas, jonatascm

## Summary

`rebalance` and `rebalanceLite` can be called by any user. Assets are taken from a user specified `account` address which has approved PerpDepository. If an address has a non-zero approval for PerpDepository, a frontrunner can use `rebalance` to transfer funds and profit by sandwiching the Uniswap pool swap.

## Vulnerability Detail

When `mint` or `redeem` is called in UXDController, `msg.sender` is where the value is coming from. But `rebalance` allows for the caller to specify [the `account` where funds are coming from](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L452). This means `msg.sender` can be any address. This allows for different scenarios where a frontrunner can profit with these steps.
1. a frontrunner detects a call of `rebalance` transaction in the mempool for a certain account address
2. the frontrunner duplicates the transaction but increases the gas amount (to allow frontrunning the original transaction) and changes the `amountOutMinimum` value to zero
3. the frontrunner can profit by sandwiching the Uniswap swap which now has no slippage setting
4. The user will lose value 

## Impact

An account that is used in `rebalance` can lose value

## Code Snippet

`rebalance` can be frontrun
htt

*[Content truncated...]*

---

### Example 21: H-5: Settlement slippage is not implemented correctly which may lead to some vaults being impossible to settle

**Source**: Sherlock
**Protocol**: Notional
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/42 

## Found by 
0x52

## Summary

The contract is supposed to implement a different max slippage value depending on the settlement type, but these values have no impact because they are never actually applied. Instead, regardless of settlement type or function inputs, max slippage will always be limited to the value of balancerPoolSlippageLimitPercent. This can be problematic because the default value allows only 1% slippage. If settlement slippage goes outside of 1% then settlement of any kind will become impossible. 

## Vulnerability Detail

[Boosted3TokenAuraHelper.sol#L95-L99](https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/external/Boosted3TokenAuraHelper.sol#L95-L99)

        params.minPrimary = poolContext._getTimeWeightedPrimaryBalance(
            oracleContext, strategyContext, bptToSettle
        );

        params.minPrimary = params.minPrimary * strategyContext.vaultSettings.balancerPoolSlippageLimitPercent / 
            uint256(BalancerConstants.VAULT_PERCENT_BASIS);

Boosted3TokenAuraHelper#_executeSettlement first sets params.minPrimary overwriting any value from function input. Next it adjusts minPrimary by balancerPoolSlippageLimitPercent, which is a constant set at pool creation; however it doesn't ever adjust it by Params.DynamicTradeParams.oracleSlippagePercent. This means that the max possible slippage regardless of settle

*[Content truncated...]*

---

### Example 22: [M-01] No slippage protection for Market functions

**Source**: Code4rena
**Protocol**: Canto
**Impact**: MEDIUM

**Details**:

### Proof of Concept

Price for shares inside `Market` is calculated using bonding curve. Currently, `LinearBondingCurve` is supported. This bonging curve [increases each next shares with fixed amount](https://github.com/code-423n4/2023-11-canto/blob/main/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L21) and also [uses `10% / log2(shareIndex)` to calculate fee](https://github.com/code-423n4/2023-11-canto/blob/main/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L35) for the share.

In order to calculate price to [buy shares `getBuyPrice` is used](https://github.com/code-423n4/2023-11-canto/blob/main/1155tech-contracts/src/Market.sol#L152) and to calculate price to [`sell` shares `getSellPrice` is used](https://github.com/code-423n4/2023-11-canto/blob/main/1155tech-contracts/src/Market.sol#L175).

<https://github.com/code-423n4/2023-11-canto/blob/main/1155tech-contracts/src/Market.sol#L132-L145>

```solidity
    function getBuyPrice(uint256 _id, uint256 _amount) public view returns (uint256 price, uint256 fee) {
        // If id does not exist, this will return address(0), causing a revert in the next line
        address bondingCurve = shareData[_id].bondingCurve;
        (price, fee) = IBondingCurve(bondingCurve).getPriceAndFee(shareData[_id].tokenCount + 1, _amount);
    }

    function getSellPrice(uint256 _id, uint256 _amount) public view returns (uint256 price, uint256 fee) {
        // If id does not exist, this will return address(0), causing

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-11-canto)

---

### Example 23: [M-18] Volatile prices and lack of checks on `rigidRedemption()` can cause users to purchase stETH at unwanted prices

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: MEDIUM

**Details**:

### Impact

Volatile prices can cause issue when users try to do [`rigidRedemption`](https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/pools/base/LybraPeUSDVaultBase.sol#L157-L168).

### Proof of Concept

Volatile prices can cause slippage loss when users use `rigidRedemption()`. This function takes PeUSD (stable coin) amount and converts it to WstETH/stETH (variable price). Unfortunately, `rigidRedemption()` does not include `timestamp` or `minAmount` received, meaning this trade can be executed later in time and at a different price than user previously expected.

**Example:**

*   Provider has 100 **wstETH** and **wstETH** price is `$`2000.
*   User wants to buy 10 **wstETH** and has 20,000 in PeUSD, so they calls [`rigidRedemption`](https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/pools/base/LybraPeUSDVaultBase.sol#L157-L168).
*   Now, due to congestion on **ETH** and volatile prices, the transaction could remain stuck in the mempool for a long time.
*   Finally, the transaction gets executed, but now the wstETH price is `$`2100, not the original `$`2000, so the user receives 9.52 **wstETH** instead of 10 (not counting fees)!

### Recommended Mitigation Steps

Because of this scenario and others like it, it is recommended to use some sort of slippage protection when users execute trades.

```jsx
    function rigidRedemption(address provider, uint256 eusdAmount,uint256 minAmountReceived) external virtual {
        depositedAsset[pro

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 24: H-7: User specified slippage allows frontrunning

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/192 

## Found by 
HonorLt, minhtrng, jonatascm, koxuan, yixxas, wagmi, ck, HollaDieWaldfee, zeroknots, GimelSec, peanuts, keccak123

## Summary

`rebalance` and `rebalanceLite` can be called by any user. Assets are taken from a user specified `account` address which has approved PerpDepository. If an address has a non-zero approval for PerpDepository, a frontrunner can use `rebalance` to transfer funds and profit by sandwiching the Uniswap pool swap.

## Vulnerability Detail

When `mint` or `redeem` is called in UXDController, `msg.sender` is where the value is coming from. But `rebalance` allows for the caller to specify [the `account` where funds are coming from](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L452). This means `msg.sender` can be any address. This allows for different scenarios where a frontrunner can profit with these steps.
1. a frontrunner detects a call of `rebalance` transaction in the mempool for a certain account address
2. the frontrunner duplicates the transaction but increases the gas amount (to allow frontrunning the original transaction) and changes the `amountOutMinimum` value to zero
3. the frontrunner can profit by sandwiching the Uniswap swap which now has no slippage setting
4. The user will lose value 

## Impact

An account that is used in `rebalance` can lose value

## Code Snippet

`rebalance` can be frontrun
htt

*[Content truncated...]*

---

### Example 25: [H-02] No slippage protection when interacting with AMM

**Source**: Pashov Audit Group
**Protocol**: GammaSwap_2024-12-30
**Impact**: HIGH

**Details**:

## Severity

**Impact:** High

**Likelihood:** Medium

## Description

- It was noticed that the `amount0Min` & `amount1Min` are set to zero during interactions with the AMM router (Uniswap) for swaps and liquidity additions. These parameters are intended to protect against slippage; setting them to zero exposes transactions to slippage, potentially resulting in receiving or adding smaller amounts than intended.

- This issue was identified across all interactions with the AMM (Uniswap), when swapping, adding liquidity and removing liquidity, where these different interactions has different impacts on the protocol:

\_depositAsset()
\_increaseLiquidity()
\_addMissingAmountsToHedge()
\_decreaseLiquidity()
\_depositAsset()
processWithdrawals()
rebalanceCollateralToRatio()

## Recommendations

Instead of hard-coding the minimum amounts to zero, introduce a state variable to control the slippage percentage (e.g., 80% of the swapped or added amounts, with a setter to update the slippage during high market volatility) and utilize it when interacting with the AMM.

Or, it's recommended to set a minLiquidity received and revert if the total liquidity received of the whole transaction is less than minLiquidity. The minLiquidity can be determined by simulation using current (no manipulated) price.

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/GammaSwap-security-review_2024-12-30.md)

---

## Statistics

- Total findings analyzed: 36
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
