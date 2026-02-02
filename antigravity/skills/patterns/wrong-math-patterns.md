---
id: PAT-WRONG-MATH
title: Wrong Math Security Patterns
category: logic
severity: high
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - wrong
  - incorrect
  - error

finding_count: 107
last_updated: 2026-01-31
---
# Wrong Math Security Patterns

## Overview

**Frequency**: 107 occurrences (0.21% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 67 | 38 | 2 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, Hans, OpenZeppelin

---

## Detection Checklist

- [ ] Check for wrong math vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-02] Users Receive Less Rewards Due To Miscalculations

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexRewards.sol#L305>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexRewards.sol#L281>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexRewards.sol#L373>

### Background

The amount of rewards accrued by global and user states is computed by the following steps:

1.  Calculate seconds elapsed since the last update (`block.timestamp - lastUpdate`)
2.  Calculate the new rewards by multiplying seconds elapsed by the last supply (`(block.timestamp - lastUpdate) * lastSupply`)
3.  Append the new rewards to the existing rewards (`rewards = rewards + (block.timestamp - lastUpdate) * lastSupply`)

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexRewards.sol#L305>

```solidity
/**
    @notice Update global accrual state
    @param  globalState    GlobalState  Global state of the producer token
    @param  producerToken  ERC20        Producer token contract
*/
function _globalAccrue(GlobalState storage globalState, ERC20 producerToken)
	internal
{
    uint256 totalSupply = producerToken.totalSupply();
    uint256 lastUpdate = globalState.lastUpdate;
    uint256 lastSupply = globalState.lastSupply;

    // Calculate rewards, the product of seconds elapsed and last supply
    // Only calculate and update

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 2: [H-01] Too many rewards are distributed when a draw is closed

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: HIGH

**Details**:

<https://github.com/GenerationSoftware/pt-v5-draw-auction/blob/f1c6d14a1772d6609de1870f8713fb79977d51c1/src/RngRelayAuction.sol#L178-L184><br>
<https://github.com/GenerationSoftware/pt-v5-draw-auction/blob/f1c6d14a1772d6609de1870f8713fb79977d51c1/src/RngRelayAuction.sol#L154-L157><br>
<https://github.com/GenerationSoftware/pt-v5-prize-pool/blob/26557afa439934afc080eca6165fe3ce5d4b63cd/src/PrizePool.sol#L366><br>
<https://github.com/GenerationSoftware/pt-v5-prize-pool/blob/26557afa439934afc080eca6165fe3ce5d4b63cd/src/abstract/TieredLiquidityDistributor.sol#L374>

A relayer completes a prize pool draw by calling `rngComplete` in `RngRelayAuction.sol`. This method closes the prize pool draw with the relayed random number and distributes the rewards to the RNG auction recipient and the RNG relay auction recipient. These rewards are calculated based on a fraction of the prize pool reserve rather than an actual value.

However, the current reward calculation mistakenly includes an extra `reserveForOpenDraw` amount just after the draw has been closed. Therefore the fraction over which the rewards are being calculated includes tokens that have not been added to the reserve and will actually only be added to the reserve when the next draw is finalised. As a result, the reward recipients are rewarded too many tokens.

### Proof of Concept

Before deciding whether or not to relay an auction result, a bot can call `computeRewards` to calculate how many rewards they'll be getting based on

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-pooltogether)

---

### Example 3: The lower bound for liquidationInitialAsk for new lines needs to be stricter

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- `LienToken.sol#L376-L381`
- `AstariaRouter.sol#L516`

## Description
`params.lien.details.liquidationInitialAsk` (`Lnew`) is only compared to `params.amount` (`Anew`) whereas in `_appendStack` `newStack[j].lien.details.liquidationInitialAsk` (`Lj`) is compared to `potentialDebt`. 

`potentialDebt` is the aggregated sum of all potential owed amounts at the end of each position/lien. 

So in `_appendStack` we have:

```
onew + on + ... + oj   Lj
```

Where `oj` is `getOwed(newStack[j], newStack[j].point.end)`, which is the amount for the stack slot plus the potential interest at the end of its term. 

So it would make sense to enforce a stricter inequality for `Lnew`:

```
(1 + r(tend  tnow) / 10^18) Anew = onew  Lnew
```

The big issue regarding the current lower bound is when the borrower only takes one lien and for this lien `liquidationInitialAsk == amount` (or they are close). Then at any point during the lien term (maybe very close to the end), the borrower can atomically self-liquidate and settle the Seaport auction in one transaction. This way the borrower can skip paying any interest (they would need to pay OpenSea fees and potentially royalty fees) and plus they would receive liquidation fees.

## Recommendation
Make sure the following stricter lower bound is used instead:

```
(1 + r(tend  tnow) / 10^18) Anew = onew  Lnew
```

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 4: Strategist Interest Rewards will be 10x higher than expected due to incorrect divisor

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## High Risk Report

**Severity:** High Risk  
**Context:** PublicVault.sol#L564  
**Description:**  
`VAULT_FEE` is set as an immutable argument in the construction of new vaults and is intended to be set in basis points. However, when the strategist interest rewards are calculated in `_handleStrategistInterestReward()`, the `VAULT_FEE` is only divided by 1000. The result is that the fee calculated by the function will be 10x higher than expected, and the strategist will be dramatically overpaid.

**Recommendation:**  
```solidity
unchecked {
- uint256 fee = x.mulDivDown(VAULT_FEE(), 1000);
+ uint256 fee = x.mulDivDown(VAULT_FEE(), 10000);
s.strategistUnclaimedShares += convertToShares(fee).safeCastTo88();
}
```

**Astaria:** Resolved based on the following PR 203.  
**Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 5: SponsorVault sponsors full transfer amount in reimburseLiquidityFees()

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

**Severity**: High Risk  
**Context**: BridgeFacet.sol#L660-L663  
**Description**: The `BridgeFacet` passes `args.amount` as `_liquidityFee` when calling `reimburseLiquidityFees`. Instead of sponsoring `liquidityFee`, the sponsor vault would sponsor the full transfer amount to the receiver. 

**Note**: Luckily, the amount in `reimburseLiquidityFees` is capped by `relayerFeeCap`.  
```solidity
function _handleExecuteTransaction(...) ... {
    ...
    (bool success, bytes memory data) = address(s.sponsorVault).call(
        abi.encodeWithSelector(s.sponsorVault.reimburseLiquidityFees.selector, _asset, _args.amount, _args.params.to), 
        ! 
    );
}
```

**Recommendation**: Pass `args.amount * (s.LIQUIDITY_FEE_DENOMINATOR - s.LIQUIDITY_FEE_NUMERATOR) / s.LIQUIDITY_FEE_DENOMINATOR` instead.  
**Connext**: Solved in PR 1551.  
**Spearbit**: Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 6: Deriving price with balanceOf is dangerous

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
`ConnextPriceOracle.sol#L109-L135`

## Description
The function `getPriceFromDex` derives the price by querying the balance of AMMs pools.

```solidity
function getPriceFromDex(address _tokenAddress) public view returns (uint256) {
    PriceInfo storage priceInfo = priceRecords[_tokenAddress];
    ...
    uint256 rawTokenAmount = IERC20Extended(priceInfo.token).balanceOf(priceInfo.lpToken);
    ...
    uint256 rawBaseTokenAmount = IERC20Extended(priceInfo.baseToken).balanceOf(priceInfo.lpToken);
    ...
}
```

Deriving the price with `balanceOf` is dangerous as `balanceOf` may be gamed. Consider Uniswap V2 as an example; exploiters can first send tokens into the pool and pump the price, then absorb the tokens that were previously donated by calling `mint`.

## Recommendation
Consider querying DEXs state through function calls such as Uniswap V2s `getReserves()` which returns the correct state of the pool.

## References
- **Connext**: Solved in PR 1649.
- **Spearbit**: Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 7: Wrong reserve factor computation on P2P rates

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Audit Report

## Severity
**High Risk**

## Context
`MarketsManagerForAave.sol#L413-L418`

## Description
The reserve factor is taken on the entire P2P supply and borrow rates instead of just on the spread of the pool rates. Its currently overcharging suppliers and borrowers and making it possible to earn a worse rate on Morpho than the pool rates.

```solidity
supplyP2PSPY[_marketAddress] =
(meanSPY * (MAX_BASIS_POINTS - reserveFactor[_marketAddress])) /
MAX_BASIS_POINTS;

borrowP2PSPY[_marketAddress] =
(meanSPY * (MAX_BASIS_POINTS + reserveFactor[_marketAddress])) /
MAX_BASIS_POINTS;
```

## Recommendation
Fix the computation. The real reserve factor should apply only on the spread so youre right that this formula is wrong and needs to be updated: 
`a + (1/2  f)(b-a)` where f is the reserve factor.

## Spearbit
Acknowledged, fixed in PR #565.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 8: MatchingEngineForAave is using the wrong totalSupply in updateBorrowers

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Security Risk Assessment

## Severity
**Critical Risk**

## Context
`MatchingEngineForAave.sol#L376-L385`

## Description
The `_poolTokenAddress` is referencing `AToken`, so the `totalStaked` would be the total supply of the `AToken`. In this case, the `totalStaked` should reference the total supply of the `DebtToken`; otherwise, the user would be rewarded for a wrong amount of reward.

## Recommendation
Use the correct token address to query `scaledTotalSupply` as follows:

```solidity
address variableDebtTokenAddress = lendingPool
    .getReserveData(IAToken(_poolTokenAddress).UNDERLYING_ASSET_ADDRESS())
    .variableDebtTokenAddress;

uint256 totalStaked = IScaledBalanceToken(variableDebtTokenAddress).scaledTotalSupply();
```

## Spearbit
Fixed; recommendation was implemented in the PR #554.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 9: [H-08] Vault.withdraw mixes normalized and standard amounts

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

### Example 10: [H-07] Vault.balance() mixes normalized and standard amounts

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

### Example 11: [H-02] `newLeverage` wrongly calculated inside `requestIncreasePositionSize`

**Source**: Pashov Audit Group
**Protocol**: Gainsnetwork May
**Impact**: HIGH

**Details**:

**Severity**

**Impact:** High

**Likelihood:** Medium

**Description**

When users call `increasePositionSize` and request an increase in position size, it will eventually trigger `IncreasePositionSizeUtils.validateRequest` to validate the request. However, when calculating `newLeverage`, it incorrectly calculates `(existingPositionSizeCollateral + positionSizeCollateralDelta * 1e3) / newCollateralAmount` instead of `(existingPositionSizeCollateral + positionSizeCollateralDelta) * 1e3 / newCollateralAmount`, causing the `newLeverage` to be lower than it should be.

```solidity
    function validateRequest(
        ITradingStorage.Trade memory _trade,
        IUpdatePositionSizeUtils.IncreasePositionSizeInput memory _input
    ) internal view returns (uint256 positionSizeCollateralDelta) {
        // ....
        uint256 newCollateralAmount = _trade.collateralAmount + _input.collateralDelta;
        uint256 newLeverage = isLeverageUpdate
            ? _trade.leverage + _input.leverageDelta
>>>         : (existingPositionSizeCollateral + positionSizeCollateralDelta * 1e3) / newCollateralAmount;
        {
            uint256 borrowingFeeCollateral = TradingCommonUtils.getTradeBorrowingFeeCollateral(_trade);
            uint256 openingFeesCollateral = ((_getMultiCollatDiamond().pairOpenFeeP(_trade.pairIndex) *
                2 +
                _getMultiCollatDiamond().pairTriggerOrderFeeP(_trade.pairIndex)) *
                TradingCommonUtils.getPositionSizeCollateralBasis(
 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/GainsNetwork-security-review-May.md)

---

### Example 12: Wrong maths in getNonSlashRate

**Source**: Hans
**Protocol**: Meta
**Impact**: HIGH

**Details**:

**Severity:** High

**Context:** [`MetaManager.sol#L102-L107`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/meta/MetaManager.sol#L102-L107)

**Description:**
The purpose of the `MetaManager::getNonSlashRate` function is to calculate and return the percentage of the deposit that will be redeemed for a given `timeInDays` period. The intended range for the non-slash rate is between 50% and 100%.

However, there is an error in the calculation at line 105. The math is incorrect, and the slope should be in the denominator instead of the numerator.

```solidity
function getNonSlashRate(uint8 timeInDays) internal view returns (uint8) {
uint256 minDays = minExitCycle / Constants.ONE_DAY;
uint256 slope = ((maxExitCycle - minExitCycle) * Constants.PINT) / (50 * Constants.ONE_DAY);
uint256 result = 50 + ((timeInDays - minDays) * slope) / Constants.PINT;//@audit it should be divided by slope and multipled by PINT
return uint8(result) ;
}
```

**Impact**
The incorrect calculation in the original code can result in users being slashed the wrong amount when unstaking, leading to a loss of assets.

**Recommendation:**

```diff
function getNonSlashRate(uint8 timeInDays) internal view returns (uint8) {
uint256 minDays = minExitCycle / Constants.ONE_DAY;
uint256 slope = ((maxExitCycle - minExitCycle) * Constants.PINT) / (50 * Constants.ONE_DAY);
-    uint256 result = 50 + ((timeInDays - minDays) * slope) / Constants.PINT;
+    uint256 result = 50

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### Example 13: TRST-H-1 Incorrect implementation of getProfitSharingE18() greatly reduces Lender's yield

**Source**: Trust Security
**Protocol**: Stella
**Impact**: HIGH

**Details**:

**Description:**
`ProfitSharingModel.getProfitSharingE18()` calculates the share of profit that Lender gets 
based on the APR of the position. According to the formula, the higher the APR, the lower 
the share of profit the Lender gets, but due to the wrong implementation of the 
`getProfitSharingE18()` function, if the APR is smaller than **MAX_ANNUALIZED_YEILD**, the 
base share of 25% is returned, actually 25% should be returned when the APR is larger than 
**MAX_ANNUALIZED_YEILD**.
Considering an APR of 5%, Lender's share of the profit should be 77%, while 
getProfitSharingE18() returns 25%, which greatly reduces Lender's share of the profit.

**Recommended Mitigation:**
Modify `getProfitSharingE18()` as follows 
```solidity
            - if (_annualizedYieldE18 < MAX_ANNUALIZED_YEILD) {
            + if (_annualizedYieldE18 >= MAX_ANNUALIZED_YEILD) { 
            return 0.25e18;
            }
```

**Team response:**
Fixed

**Mitigation Review:**
The team has fixed it as recommended to make the logic correct

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-29-Stella.md)

---

### Example 14: [H-04] Users may be liquidated right after taking maximal debt

**Source**: Code4rena
**Protocol**: Backed Protocol
**Impact**: HIGH

**Details**:

<https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L471>

<https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L317>

### Impact

Since there's no gap between the maximal LTV and the liquidation LTV, user positions may be liquidated as soon as maximal debt is taken, without leaving room for collateral and Papr token prices fluctuations. Users have no chance to add more collateral or reduce debt before being liquidated. This may eventually create more uncovered and bad debt for the protocol.

### Proof of Concept

The protocol allows users to take debt up to the maximal debt, including it ([PaprController.sol#L471](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L471)):

```solidity
if (newDebt > max) revert IPaprController.ExceedsMaxDebt(newDebt, max);
```

However, a position becomes liquidable as soon as user's debt reaches user's maximal debt ([PaprController.sol#L317](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L317)):

```solidity
if (info.debt < _maxDebt(oraclePrice * info.count, cachedTarget)) {
    revert IPaprController.NotLiquidatable();
}
```

Moreover, the same maximal debt calculation is used during borrowing and liquidating, with the same maximal LTV ([PaprController.sol#L556-L559](https://github.com/with-backed/papr/blob/9528f2711ff0c15220

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-backed)

---

### Example 15: Wrong P2P exchange rate calculation

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**Critical Risk**

## Context
MarketsManagerForAave.sol#L436

## Description
`_p2pDelta` is divided by `_poolIndex` and multiplied by `_p2pRate`, nevertheless it should have been multiplied by `_poolIndex` and divided by `_p2pRate` to compute the correct share of the delta. This leads to wrong P2P rates throughout all markets if supply/borrow delta is involved.

## Recommendation
Change order and adjust return values accordingly.

```solidity
uint256 shareOfTheDelta = _p2pDelta
  .wadToRay()
  - .rayMul(_p2pRate)
  - .rayDiv(_poolIndex)
  + .rayMul(_poolIndex)
  + .rayDiv(_p2pRate)
  .rayDiv(_p2pAmount.wadToRay());
```

## Morpho
Fixed in PR #536, `_computeNewP2PExchangeRate` is changed as recommended.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 16: [H-02] Wrong token allocation computation for token decimals != 18 if floor price not reached

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

### Example 17: [H-10] An attacker can steal funds from multi-token vaults

**Source**: Code4rena
**Protocol**: yAxis
**Impact**: HIGH

**Details**:

## Handle

WatchPug


## Vulnerability details

The total balance should NOT be simply added from different tokens' tokenAmounts, considering that the price of tokens may not be the same.

https://github.com/code-423n4/2021-09-yaxis/blob/cf7d9448e70b5c1163a1773adb4709d9d6ad6c99/contracts/v3/Vault.sol#L324

```solidity=316
function balanceOfThis()
    public
    view
    returns (uint256 _balance)
{
    address[] memory _tokens = manager.getTokens(address(this));
    for (uint8 i; i < _tokens.length; i++) {
        address _token = _tokens[i];
        _balance = _balance.add(_normalizeDecimals(_token, IERC20(_token).balanceOf(address(this))));
    }
}
```

https://github.com/code-423n4/2021-09-yaxis/blob/cf7d9448e70b5c1163a1773adb4709d9d6ad6c99/contracts/v3/controllers/Controller.sol#L396

```solidity=381
function harvestStrategy(
    address _strategy,
    uint256 _estimatedWETH,
    uint256 _estimatedYAXIS
)
    external
    override
    notHalted
    onlyHarvester
    onlyStrategy(_strategy)
{
    uint256 _before = IStrategy(_strategy).balanceOf();
    IStrategy(_strategy).harvest(_estimatedWETH, _estimatedYAXIS);
    uint256 _after = IStrategy(_strategy).balanceOf();
    address _vault = _vaultStrategies[_strategy];
    _vaultDetails[_vault].balance = _vaultDetails[_vault].balance.add(_after.sub(_before));
    _vaultDetails[_vault].balances[_strategy] = _after;
    emit Harvest(_strategy);
}
```

https://github.com/code-423n4/2021-09-yaxis/blob/cf7d9448e70b5c1163a1773adb47

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-yaxis)

---

### Example 18: [H-01] Controller.setCap sets wrong vault balance

**Source**: Code4rena
**Protocol**: yAxis
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

The `Controller.setCap` function sets a cap for a strategy and withdraws any excess amounts (`_diff`).
The vault balance is decreased by the entire strategy balance instead of by this `_diff`:

```
// @audit why not sub _diff?
_vaultDetails[_vault].balance = _vaultDetails[_vault].balance.sub(_balance);
```

## Impact
The `_vaultDetails[_vault].balance` variable does not correctly track the actual vault balances anymore, it will usually **underestimate** the vault balance.
This variable is used in `Controller.balanceOf()`, which in turn is used in `Vault.balance()`, which in turn is used to determine how many shares to mint / amount to receive when redeeming shares.
If the value is less, users will lose money as they can redeem fewer tokens.
Also, an attacker can `deposit` and will receive more shares than they should receive. They can then wait until the balance is correctly updated again and withdraw their shares for a higher amount than they deposited. This leads to the vault losing tokens.

## Recommended Mitigation Steps
Sub the `_diff` instead of the `balance`: `_vaultDetails[_vault].balance = _vaultDetails[_vault].balance.sub(_diff);`

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-yaxis)

---

### Example 19: [H-01] veCVXStrategy.manualRebalance has wrong logic

**Source**: Code4rena
**Protocol**: BadgerDAO
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

## Vulnerability Details
The `veCVXStrategy.manualRebalance` function computes two ratios `currentLockRatio` and `newLockRatio` and compares them.

However, these ratios compute different things and are not comparable:
- `currentLockRatio = balanceInLock.mul(10**18).div(totalCVXBalance)` is a **percentage value** with 18 decimals (i.e. `1e18 = 100%`). Its max value can at most be `1e18`.
- `newLockRatio = totalCVXBalance.mul(toLock).div(MAX_BPS)` is a **CVX token amount**. It's unbounded and just depends on the `totalCVXBalance` amount.

The comparison that follows does not make sense:

```solidity
if (newLockRatio <= currentLockRatio) {
  // ...
}
```

## Impact
The rebalancing is broken and does not correctly rebalance.
It usually leads to locking nearly everything if `totalCVXBalance` is high.

## Recommended Mitigation Steps
Judging from the `cvxToLock = newLockRatio.sub(currentLockRatio)` it seems the desired computation is that the "ratios" should actually be in CVX amounts and not in percentages. Therefore, `currentLockRatio` should just be `balanceInLock`. (The variables should be renamed as they aren't really ratios but absolute CVX balance amounts.)

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-bvecvx)

---

### Example 20: [H-01] Reward computation is wrong

**Source**: Code4rena
**Protocol**: Wild Credit
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

The `LendingPair.accrueAccount` function distributes rewards **before** updating the cumulative supply / borrow indexes as well as the index + balance for the user (by minting supply tokens / debt).
This means the percentage of the user's balance to the total is not correct as the total can be updated several times in between.

```solidity
function accrueAccount(address _account) public {
  // distributes before updating accrual state
  _distributeReward(_account);
  accrue();
  _accrueAccountInterest(_account);

  if (_account != feeRecipient()) {
    _accrueAccountInterest(feeRecipient());
  }
}
```

**Example**: Two users deposit the same amounts in the same block. Thus, after some time they should receive the same tokens.
1. User A and B deposit 1000 tokens (in the same block) and are minted 1000 tokens in return. Total supply = `2000`
2. Assume after 50,000 blocks, `A` calls `accrueAccount(A)` which first calls `_distributeReward`. A is paid out 1000/2000 = 50% of the 50,000 blocks reward since deposit. Afterwards, `accrue` + `_accrueAccountInterest(A)` is called and `A` is minted 200 more tokens due to supplier lending rate. The supply **totalSupply is now 2200**.
3. After another 50,000 blocks, `A` calls `accrueAccount(A)` again. which first calls `_distributeReward`. A is paid out 1200/2200 = **54.5454% of the 50,000 blocks reward since deposit.**

From here, you can already see that `A` receives more than 50% of the 100,000 block rewards altho

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-wildcredit)

---

### Example 21: [H-18] Old stakers can steal deposits of new stakers in StakingFundsVault

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/5f853d055d7aa1bebe9e24fd0e863ef58c004339/contracts/liquid-staking/StakingFundsVault.sol#L75
https://github.com/code-423n4/2022-11-stakehouse/blob/5f853d055d7aa1bebe9e24fd0e863ef58c004339/contracts/liquid-staking/StakingFundsVault.sol#L123
https://github.com/code-423n4/2022-11-stakehouse/blob/5f853d055d7aa1bebe9e24fd0e863ef58c004339/contracts/liquid-staking/StakingFundsVault.sol#L63


## Vulnerability details

## Impact
Stakers to the MEV+fees vault can steal funds from the new stakers who staked after a validator was registered and the derivatives were minted. A single staker who staked 4 ETH can steal all funds deposited by new stakers.
## Proof of Concept
`StakingFundsVault` is designed to pull rewards from a Syndicate contract and distributed them pro-rata among LP token holders ([StakingFundsVault.sol#L215-L231](https://github.com/code-423n4/2022-11-stakehouse/blob/5f853d055d7aa1bebe9e24fd0e863ef58c004339/contracts/liquid-staking/StakingFundsVault.sol#L215-L231)):
```solidity
if (i == 0 && !Syndicate(payable(liquidStakingNetworkManager.syndicate())).isNoLongerPartOfSyndicate(_blsPubKeys[i])) {
    // Withdraw any ETH accrued on free floating SLOT from syndicate to this contract
    // If a partial list of BLS keys that have free floating staked are supplied, then partial funds accrued will be fetched
    _claimFundsFromSyndicateForDistribution(
        liquidStakingNetworkManager.syndicate(),
        

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 22: [H-03] Outstanding reserved tokens are incorrectly counted in total redemption weight

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: HIGH

**Details**:

The amounts redeemed in overflow redemption can be calculated incorrectly due to incorrect accounting of the outstanding number of reserved tokens.

### Proof of Concept

Project contributors are allowed to redeem their NFT tokens for a portion of the overflow (excessive funded amounts). The amount a contributor receives is calculated as [overflow &ast; (user's redemption rate / total redemption weight)](https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/abstract/JB721Delegate.sol#L135-L142), where user's redemption weight is [the total contribution floor of all their NFTs](https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/JBTiered721DelegateStore.sol#L532-L539) and total redemption weight is [the total contribution floor of all minted NFTs](https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/JBTiered721DelegateStore.sol#L563-L566). Since the total redemption weight is the sum of individual contributor redemption weights, the amount they can redeem is proportional to their contribution.

However, the total redemption weight calculation incorrectly accounts outstanding reserved tokens ([JBTiered721DelegateStore.sol#L563-L566](https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/JBTiered721DelegateStore.sol#L563-L566)):

```solidity
// Add the tier's contribution 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-juicebox)

---

### Example 23: [H-04] Wrong calculation in function LBRouter._getAmountsIn make user lose a lot of tokens when swap through JoePair (most of them will gifted to JoePair freely)

**Source**: Code4rena
**Protocol**: Trader Joe
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-traderjoe/blob/79f25d48b907f9d0379dd803fc2abc9c5f57db93/src/LBRouter.sol#L725


## Vulnerability details


## Vulnerable detail 
Function `LBRouter._getAmountsIn` is a helper function to return the amounts in with given `amountOut`. This function will check the pair of `_token` and `_tokenNext` is `JoePair` or `LBPair` using `_binStep`.
* If `_binStep == 0`, it will be a `JoePair` otherwise it will be an `LBPair`.
```solidity=
if (_binStep == 0) {
    (uint256 _reserveIn, uint256 _reserveOut, ) = IJoePair(_pair).getReserves();
    if (_token > _tokenPath[i]) {
        (_reserveIn, _reserveOut) = (_reserveOut, _reserveIn);
    }


    uint256 amountOut_ = amountsIn[i];
    // Legacy uniswap way of rounding
    amountsIn[i - 1] = (_reserveIn * amountOut_ * 1_000) / (_reserveOut - amountOut_ * 997) + 1;
} else {
    (amountsIn[i - 1], ) = getSwapIn(ILBPair(_pair), amountsIn[i], ILBPair(_pair).tokenX() == _token);
}
```
As we can see when `_binStep == 0` and `_token < _tokenPath[i]` (in another word  we swap through `JoePair` and pair's`token0` is `_token` and `token1` is `_tokenPath[i]`), it will 
1. Get the reserve of pair (`reserveIn`, `reserveOut`) 
2. Calculate the `_amountIn` by using the formula 
```
amountsIn[i - 1] = (_reserveIn * amountOut_ * 1_000) / (_reserveOut - amountOut_ * 997) + 1
```

But unfortunately the denominator `_reserveOut - amountOut_ * 997` seem incorrect. It should be `(_reserveOut - amountOut_) 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-traderjoe)

---

### Example 24: [H-02] Incorrect output amount calculation for Trader Joe V1 pools

**Source**: Code4rena
**Protocol**: Trader Joe
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-10-traderjoe/blob/main/src/LBRouter.sol#L891><br>
<https://github.com/code-423n4/2022-10-traderjoe/blob/main/src/LBRouter.sol#L896><br>

Output amount is calculated incorrectly for a Trader Joe V1 pool when swapping tokens across multiple pools and some of the pools in the chain are V1 ones. Calculated amounts will always be smaller than expected ones, which will always affect chained swaps that include V1 pools.

### Proof of Concept

[LBRouter](https://github.com/code-423n4/2022-10-traderjoe/blob/main/src/LBRouter.sol#L21) is a high-level contract that serves as the main contract users will interact with. The contract implements a lot of security checks and helper functions that make usage of LBPair contracts easier and more user-friendly. Some examples of such functions:

*   [swapExactTokensForTokensSupportingFeeOnTransferTokens](https://github.com/code-423n4/2022-10-traderjoe/blob/main/src/LBRouter.sol#L531), which makes chained swaps (i.e. swaps between tokens that don't have a pair) of tokens implementing fee on transfer (i.e. there's fee reduced from every transferred amount);
*   [swapExactTokensForAVAXSupportingFeeOnTransferTokens](https://github.com/code-423n4/2022-10-traderjoe/blob/main/src/LBRouter.sol#L561), which is the variation of the above function which takes AVAX as the output token;
*   [swapExactAVAXForTokensSupportingFeeOnTransferTokens](https://github.com/code-423n4/2022-10-traderjoe/blob/main/src/LBRouter.sol#L594),

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-traderjoe)

---

### Example 25: [H-01] StandardPolicyERC1155.sol returns amount == 1 instead of amount == order.amount

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

## Statistics

- Total findings analyzed: 107
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

