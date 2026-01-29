# TWAP Security Patterns

## Overview

**Frequency**: 10 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 7 | 3 | 0 | 0 |

**Common Sources**: Code4rena, Pashov Audit Group, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Check for twap vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: P2P rate can be manipulated as it’s a lazy-updated snapshot

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Severity: High Risk
## Context
MarketsManagerForAave.sol#L408-L411

## Description
The P2P rate is lazy-updated upon interactions with the Morpho protocol. It takes the mid-rate of the current Aave supply and borrow rate. It’s possible to manipulate these rates before triggering an update on Morpho.
```solidity
function _updateSPYs(address _marketAddress) internal {
    DataTypes.ReserveData memory reserveData = lendingPool.getReserveData(
        IAToken(_marketAddress).UNDERLYING_ASSET_ADDRESS()
    );
    uint256 meanSPY = Math.average(
        reserveData.currentLiquidityRate,
        reserveData.currentVariableBorrowRate
    ) / SECONDS_PER_YEAR; // In ray
}
```

## Example
Assume an attacker has a P2P supply position on Morpho and wants to earn a very high APY on it. He does the following actions in a single transaction:
- Borrow all funds on the desired Aave market. (This can be done by borrowing against flashloaned collateral).
- The utilisation rate of the market is now 100%. The borrow rate is the max borrow rate, and the supply rate is `(1.0 - reserveFactor) * maxBorrowRate`. The max borrow rate can be higher than 100% APY, see Aave docs.
- The attacker triggers an update to the P2P rate, for example, by supplying 1 token to the pool `Positions-ManagerForAave.supply(poolTokenAddress, 1, ...)`, triggering `marketsManager.updateSPYs(_poolTokenAddress)`.
- The new mid-rate is computed, which will be `(2.0 - reserveFactor) * maxBorrowRate / 2 ~ maxBorrowRate`.
- The

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 2: [H-05] Synth realise is vulnerable to flash loan attacks

**Source**: Code4rena
**Protocol**: Spartan Protocol
**Impact**: HIGH

**Details**:

## Handle

jonah1005


## Vulnerability details

## Impact
Synth `realise` function calculates `baseValueLP` and `baseValueSynth` base on AMM spot price which is vulnerable to flash loan attack. Synth's lp is subject to `realise` whenever the AMM ratio is different than Synth's debt ratio. 

The attack is not necessarily required flash loan. Big whale of the lp token holders could keep calling realse by shifting token ratio of AMM pool back and forth.


## Proof of Concept
The vulnerability locates at:
https://github.com/code-423n4/2021-07-spartan/blob/e2555aab44d9760fdd640df9095b7235b70f035e/contracts/Synth.sol#L187-L199

Where the formula here is dangerous:
https://github.com/code-423n4/2021-07-spartan/blob/e2555aab44d9760fdd640df9095b7235b70f035e/contracts/Utils.sol#L114-L126

https://github.com/code-423n4/2021-07-spartan/blob/e2555aab44d9760fdd640df9095b7235b70f035e/contracts/Utils.sol#L210-L217
Here's a script for conducting flashloan attack
```python
flashloan_amount = init_amount
user = w3.eth.accounts[0]
marked_token.functions.transfer(user, flashloan_amount).transact()
marked_token.functions.transfer(token_pool.address, flashloan_amount).transact({'from': user})
token_pool.functions.addForMember(user).transact({'from': user})
received_lp = token_pool.functions.balanceOf(user).call() 
synth_balance_before_realise = token_synth.functions.mapSynth_LPBalance(token_pool.address).call()
token_synth.functions.realise(token_pool.address).transact()
token_pool.functions.trans

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-spartan)

---

### Example 3: [H-05] Flash loan price manipulation in purchasePyroFlan()

**Source**: Code4rena
**Protocol**: Behodler
**Impact**: HIGH

**Details**:

## Handle

sirhashalot


## Vulnerability details

## Impact

The comment on [line 54](https://github.com/code-423n4/2022-01-behodler/blob/cedb81273f6daf2ee39ec765eef5ba74f21b2c6e/contracts/FlanBackstop.sol#L54) of FlanBackstop.sol states "the opportunity for price manipulation through flash loans exists", and I agree that this is a serious risk. While the acceptableHighestPrice variable attempts to limit the maximum price change of the flan-stablecoin LP, a flashloan sandwich attack can still occur within this limit and make up for the limitation with larger volumes or multiple flashloan attacks. Flashloan price manipulation is the cause for many major hacks, including [bZx](https://bzx.network/blog/postmortem-ethdenver), [Harvest](https://rekt.news/harvest-finance-rekt/), and others.

## Proof of Concept

[Line 83](https://github.com/code-423n4/2022-01-behodler/blob/cedb81273f6daf2ee39ec765eef5ba74f21b2c6e/contracts/FlanBackstop.sol#L83) of FlanBackstop.sol calculates the price of flan to stablecoin in the Uniswap pool based on the balances at a single point in time. Pool balances at a single point in time can be manipulated with flash loans, which can skew the numbers to the extreme. The single data point of LP balances is used to calculate [the growth variable in line 103](https://github.com/code-423n4/2022-01-behodler/blob/cedb81273f6daf2ee39ec765eef5ba74f21b2c6e/contracts/FlanBackstop.sol#L103), and the growth variable influences the quantity of pyroflan a user receives

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-behodler)

---

### Example 4: [H-09] `PriceOracle` Does Not Filter Price Feed Outliers

**Source**: Code4rena
**Protocol**: Sublime
**Impact**: HIGH

**Details**:

_Submitted by leastwood_

#### Impact

If for whatever reason the Chainlink oracle returns a malformed price due to oracle manipulation or a malfunctioned price, the result will be passed onto users, causing unintended consequences as a result.

In the same time it's possible to construct mitigation mechanics for such cases, so user economics be affected by sustainable price movements only. As price outrages provide a substantial attack surface for the project it's worth adding some complexity to the implementation.

#### Proof of Concept

<https://github.com/code-423n4/2021-12-sublime/blob/main/contracts/PriceOracle.sol#L149-L161>
```solidity
function getLatestPrice(address num, address den) external view override returns (uint256, uint256) {
    uint256 _price;
    uint256 _decimals;
    (_price, _decimals) = getChainlinkLatestPrice(num, den);
    if (_decimals != 0) {
        return (_price, _decimals);
    }
    (_price, _decimals) = getUniswapLatestPrice(num, den);
    if (_decimals != 0) {
        return (_price, _decimals);
    }
    revert("PriceOracle::getLatestPrice - Price Feed doesn't exist");
}
```
The above code outlines how prices are utilised regardless of their actual value (assuming it is always a non-zero value).

#### Recommended Mitigation Steps

Consider querying both the Chainlink oracle and Uniswap pool for latest prices, ensuring that these two values are within some upper/lower bounds of each other. It may also be useful to track historic values and 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-12-sublime)

---

### Example 5: [H-04] Vader TWAP averages wrong

**Source**: Code4rena
**Protocol**: Vader Protocol
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

The vader price in `LiquidityBasedTWAP.getVaderPrice` is computed using the `pastLiquidityWeights` and `pastTotalLiquidityWeight` return values of the `syncVaderPrice`.

The `syncVaderPrice` function does not initialize all weights and the total liquidity weight does not equal the sum of the individual weights because it skips initializing the pair with the previous data if the TWAP update window has not been reached yet:

```solidity
function syncVaderPrice()
    public
    override
    returns (
        uint256[] memory pastLiquidityWeights,
        uint256 pastTotalLiquidityWeight
    )
{
    uint256 _totalLiquidityWeight;
    uint256 totalPairs = vaderPairs.length;
    pastLiquidityWeights = new uint256[](totalPairs);
    pastTotalLiquidityWeight = totalLiquidityWeight[uint256(Paths.VADER)];

    for (uint256 i; i < totalPairs; ++i) {
        IUniswapV2Pair pair = vaderPairs[i];
        ExchangePair storage pairData = twapData[address(pair)];
        // @audit-info lastMeasurement is set in _updateVaderPrice to block.timestamp
        uint256 timeElapsed = block.timestamp - pairData.lastMeasurement;
        // @audit-info update period depends on pair
        // @audit-issue if update period not reached => does not initialize pastLiquidityWeights[i]
        if (timeElapsed < pairData.updatePeriod) continue;

        uint256 pastLiquidityEvaluation = pairData.pastLiquidityEvaluation;
        uint256 currentLiquidityEvaluation = _updateVaderPrice(
  

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-12-vader)

---

### Example 6: H-3: Usage of `slot0` is extremely easy to manipulate

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

### Example 7: [M-04] Ineffective TWAV Implementation

**Source**: Code4rena
**Protocol**: Nibbl
**Impact**: MEDIUM

**Details**:

_Submitted by xiaoming90, also found by hyh_

The current TWAV implementation consists of an array of 4 observations/valuations called `twavObservations`. Whenever, the new valuation is updated, the new cumulative valuation will be appended to the `twavObservations` array and the oldest observation/valuation will be removed from the `twavObservations` array.

Description of current TWAV implementation can be found at <https://github.com/NibblNFT/nibbl-smartcontracts#twavsol>

> *   Time-weighted average valuation
> *   Uses an array of length 4 which stores cumulative valuation and timestamp.
> *   TWAV is calculated between the most and least recent observations recorded in the array.
> *   TWAV array is updated only when the system is in buyout state. In case of buyout rejection, the array is reset.

<https://github.com/code-423n4/2022-06-nibbl/blob/8c3dbd6adf350f35c58b31723d42117765644110/contracts/Twav/Twav.sol#L11>

```solidity
/// @notice current index of twavObservations index
uint8 public twavObservationsIndex;
uint8 private constant TWAV_BLOCK_NUMBERS = 4; //TWAV of last 4 Blocks 
uint32 public lastBlockTimeStamp;

/// @notice record of TWAV 
TwavObservation[TWAV_BLOCK_NUMBERS] public twavObservations;

/// @notice updates twavObservations array
/// @param _blockTimestamp timestamp of the block
/// @param _valuation current valuation
function _updateTWAV(uint256 _valuation, uint32 _blockTimestamp) internal {
    uint32 _timeElapsed; 
    unchecked {
        _timeElap

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-nibbl)

---

### Example 8: [H-06] SynthVault rewards can be gamed

**Source**: Code4rena
**Protocol**: Spartan Protocol
**Impact**: HIGH

**Details**:

## Handle

cmichel


## Vulnerability details

## Vulnerability Details

The `SynthVault._deposit` function adds `weight` for the user that depends on the spot value of the deposit synth amount in `BASE`.
This spot price can be manipulated and the cost of manipulation is relative to the pool's liquidity.
However, the reward (see `calcReward`) is measured in BASE tokens unrelated to the pool.
Therefore, if the pool's liquidity is low and the reward reserve is high, the attack can be profitable:

1. Manipulate the pool spot price of the `iSYNTH(_synth).LayerONE()` pool by dripping a lot of `BASE` into it repeatedly (sending lots of smaller trades is less costly due to the [path-independence of the continuous liquidity model](https://docs.thorchain.org/thorchain-finance/continuous-liquidity-pools)). This increases the `BASE` per `token` price.
2. Call `SynthVault.depositForMember` and deposit a _small_ amount of synth token. The `iUTILS(_DAO().UTILS()).calcSpotValueInBase(iSYNTH(_synth).LayerONE(), _amount)` will return an inflated weight due to the price.
3. Optionally drip more `BASE` into the pool and repeat the deposits
4. Drip back `token` to the pool to rebalance it

The user's `weight` is now inflated compared to the deposited / locked-up amount and they can claim a large share of the rewards.

## Impact
The cost of the attack depends on the pool's liquidity and the profit depends on the reserve.
It could therefore be profitable under certain circumstances.

## Recommende

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-spartan)

---

### Example 9: [M-08] "TWAP" used is an observation-weighted-average-price, not a time-weighted one

**Source**: Code4rena
**Protocol**: Olympus DAO
**Impact**: MEDIUM

**Details**:

_Submitted by IllIllI_

While users are incentivized to call the heartbeat, the incentive may be removed later, or it may be more profitable to use old prices, so users may not call the heartbeat during unfavorable prices, leading to the TWAP price being incorrect, and users getting the wrong price for their assets.

A similar case of an incomplete TWAP algorithm was found to be of [Medium](https://github.com/code-423n4/2022-06-nibbl-findings/issues/191) risk.

### Proof of Concept

A TWAP is a Time-Weighted average price, but the algorithm below does not take into account the time between observations:

```solidity
File: /src/modules/PRICE.sol   #1

134          // Calculate new moving average
135          if (currentPrice > earliestPrice) {
136              _movingAverage += (currentPrice - earliestPrice) / numObs;
137          } else {
138              _movingAverage -= (earliestPrice - currentPrice) / numObs;
139          }
140  
141          // Push new observation into storage and store timestamp taken at
142          observations[nextObsIndex] = currentPrice;
143          lastObservationTime = uint48(block.timestamp);
144:         nextObsIndex = (nextObsIndex + 1) % numObs;
```

<https://github.com/code-423n4/2022-08-olympus/blob/b5e139d732eb4c07102f149fb9426d356af617aa/src/modules/PRICE.sol#L134-L144>

While the `Heart` policy enforces an upper bound on how frequently updates are added to the average, there is no guarantee that users call `beat()` in a timely manner:


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-olympus)

---

### Example 10: [M-01] TWAP price manipulation

**Source**: Pashov Audit Group
**Protocol**: TitanX
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** High

**Likelihood:** Low

## Description

The `_getTwaPrice` function in FarmKeeper and `getQuote` function in UniversalBuyAndBurn are vulnerable to price manipulation in Uniswap V3 pools with low observation cardinality. This vulnerability can lead to inaccurate price calculations, potentially resulting in unfair token swaps or liquidity provisions.

When getting the twap price to prevent slippage in liquidity providing and swapping, the `_getTwaPrice` and `getQuote` functions fallback to the oldest observation if the requested time window is greater than the available price history.

It's a problem because it doesn't consider the pool cardinality. In newly created pools with cardinality initialized to 1, the oldest observation can be manipulated to be the current `block.timestamp`, setting the TWAP price to the current (potentially manipulated) price. Because in uniswap v3 pool, an oracle observation is written by the first swap or liquidity provision in the block. Let's say before the UniversalBuyAndBurn contract performs the swap, a malicious actor front-runs and swaps to manipulate the price because the cardinality is 1, and the oldest observation is 0.

Another consequence is that the `oldestObservation` can be equal to `cardianility * 12 seconds (time per block)` if liquidity changes each block. It means that the TWAP period can be shorter than intended if `oldestObservation < secondsAgo`, potentially increasing slippage risk.

```solidity
  f

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/TitanX-security-review.md)

---

## Statistics

- Total findings analyzed: 10
- Examples shown: 10
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
