# MixBytes - Audit Findings

## Overview

**Total Findings**: 2,437 (4.82% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 380 | 754 | 1303 | 0 |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|
| Front-Running | 3 |
| DOS | 3 |
| 0x | 2 |
| Validation | 2 |
| 1/64 Rule | 1 |
| 51% Attack | 1 |
| API Inconsistency | 1 |
| Access Control | 1 |
| supportsInterface | 1 |
| Liquidation | 1 |

---

## Notable Findings

### 1. `redeemNative()` Reentrancy Enables Permanent Fund Freeze, Systemic Misaccounting, and Liquidation Cascades

**Protocol**: Notional Finance | **Impact**: HIGH

##### Description
The redemption flow in `AbstractYieldStrategy.redeemNative()` is vulnerable to reentrancy that corrupts internal accounting and can permanently freeze a portion of the vault's yield tokens. The `redeemNative()` function calls `AbstractStakingStrategy._redeemShares()`, which for instant redemption delegates to `AbstractYieldStrategy._executeTrade()` and performs an external call during redemption. Not all vault and router entry points are protected against reentrancy, which allows control to reenter from the lending router while `_burnShares()` is still executing. A malicious ...

---

### 2. Incorrect transfer of ERC-20 tokens to non-compatible contract

**Protocol**: EYWA | **Impact**: HIGH

##### Description

- https://gitlab.ubertech.dev/blockchainlaboratory/eywa-dao/-/blob/29465033f28c8d3f09cbc6722e08e44f443bd3b2/contracts/EscrowVoteManagerV1.sol#L136

It was discovered that the `s_emissionManager` contract does not handle ERC20 tokens. However, the following code attempts to transfer ERC20 tokens to this contract:

```solidity
IERC20(s_eywa).safeTransfer(s_emissionManager, m_claimableRewards);
```

Since `s_emissionManager` is not designed to accept or manage ERC20 tokens, any tokens sent to it may become irretrievable.

##### Recommendation
We recommend modifying the contract...

---

### 3. Inflation attack on empty ticks

**Protocol**: Curve Finance | **Impact**: HIGH

##### Description

Each AMM tick represents an empty vault, where shares are issued for collateral. A hacker can manipulate a tick so that it contains just 1 wei share and any amount of collateral. For example, suppose the hacker initially inflates the tick so that it contains 1 wei share and 1 ETH. Next, the hacker sees a victim's transaction in the mempool, which is going to deposit 20 ETH into this tick. The hacker then needs to inflate the tick to contain 1 wei share and 10 ETH + 1 wei right before the victim's transaction.

How many shares will the victim receive in this tick? The victim ...

---

### 4. Reentrancy in `EscrowManager`

**Protocol**: EYWA | **Impact**: HIGH

##### Description

OpenZeppelin ERC721 NFT implementations invoke the receiver whenever the `safeTransferFrom()` or `safeMint()` methods are called.

A hacker can exploit this mechanism by triggering a callback from `EscrowManager` during the execution of methods such as `createLock()` (when `_safeMint()` is invoked), `deboost()` (when `safeTransferFrom()` is invoked), and `withdraw()` (also when `safeTransferFrom()` is invoked), especially when the state of `EscrowManager` is inconsistent. This can corrupt storage variables or result in voting power gain.

**Example 1**: Reentrancy in the `de...

---

### 5. Replay Attack via Balance-Based Nonce

**Protocol**: Barter DAO | **Impact**: HIGH

##### Description
The protocol uses only the user's token balance as a nonce to prevent replay attacks:

```solidity
uint256 currentMakerBalance = order.makerToken.balanceOf(order.maker);
if (currentMakerBalance < order.nonceBalance) {
    revert ReplayAttackDetected(currentMakerBalance, order.nonceBalance);
}
```
https://github.com/BarterLab/superposition-contract/blob/8dfd5bceb02bef6892a574da6862f673a5ea66b6/src/SuperpositionVault.sol#L115-L118

However, once the user's balance increases again (e.g., through receiving tokens from other sources), the same order can be executed multiple times ...

---

### 6. Double Order Attack via Callback Mechanism

**Protocol**: Barter DAO | **Impact**: HIGH

##### Description
The protocol transfers tokens from maker to taker first, and then calls back to the taker (i. e. `msg.sender`) to complete the order:

```solidity
uint256 actualTakerAmount = 
    filledtakerAmount < order.takerAmount ? 
    filledtakerAmount : order.takerAmount;

uint256 balanceBefore = 
    order.takerToken.balanceOf(address(order.maker));

ISuperpositionCallback(msg.sender).superpositionCallback(
        order, actualTakerAmount, callback);

uint256 balanceAfter = 
    order.takerToken.balanceOf(address(order.maker));

// Check that callback provided enough tokens
if (bala...

---

### 7. Inability to Claim Rewards From the Curve Gauge

**Protocol**: Notional Finance | **Impact**: HIGH

##### Description
The `CurveConvex2Token._unstakeLpTokens()` function calls `ICurveGauge(CURVE_GAUGE).withdraw(poolClaim)`, which takes only the `poolClaim` parameter. However, the Curve gauge `withdraw()` function supports an optional `_claim_rewards` flag, which allows claiming rewards during the withdraw call:

```python
@external
@nonreentrant('lock')
def withdraw(_value: uint256, _claim_rewards: bool = False):
```

As implemented, the strategy does not claim rewards when withdrawing from the gauge, so users do not automatically receive accrued rewards when exiting positions.

```solidity
...

---

### 8. Flawed Precision and Scaling Logic in `price()`

**Protocol**: NUTS Finance | **Impact**: HIGH

##### Description
The `price()` function in `ChainlinkCompositeOracleProvider` begins with a 36-decimal fixed-point accumulator (`highPrecisionPrice = PRECISION`). Each feed is then folded into that value, but two subtle arithmetic mistakes distort the final price:

1. **Inverted feeds (`isInverted == true`)**
   The code multiplies the accumulator by `(10**assetDecimals) * (10**feed.decimals()) / feedPrice`.
   Because both exponents are reapplied for every inverted feed, the precision scale increases by `assetDecimals` on each iteration, corrupting the effective price by several orders of ma...

---

### 9. Arithmetic Overflow in `getPrice` When Feeds Return Large Values

**Protocol**: NUTS Finance | **Impact**: HIGH

##### Description
This issue has been identified within the `getPrice` function of the `ChainlinkOracleComposite` contract. 

`getPrice` normalises each feed answer and then multiplies the current composite price by that rate:

```solidity
rate = uint256(price) 
     * 10**(SCALING_DECIMALS - feed.decimals());
compositePrice = (compositePrice * rate) 
               / SCALING_FACTOR; // 36-dec fixed-point
```

If a feed reports `price > 1.16 * 10^(5 + feed.decimals)` (≈ $100 000 when denominated in wei), the term  

```
compositePrice * rate * 10^36
```

exceeds the 256‑bit limit. The call rev...

---

### 10. Infinitely Locked `VotingEscrow` Positions Are Not Accounted During Voting in `GaugeController`

**Protocol**: Yield Basis | **Impact**: HIGH

##### Description

In `VotingEscrow`, an infinite lock sets a constant vote bias equal to the deposit and a slope of 0. However, in `GaugeController.vote_for_gauge_weights()`, vote bias is recalculated as `slope * dt`, ignoring the constant bias from an infinite lock:

```python
## Prepare slopes and biases in memory
old_slope: VotedSlope = self.vote_user_slopes[msg.sender][_gauge_addr]
old_dt: uint256 = max(old_slope.end, block.timestamp) - block.timestamp
old_bias: uint256 = old_slope.slope * old_dt
new_slope: VotedSlope = VotedSlope(
    slope = slope * _user_weight // 10000,  # slope = 0, ...

---

### 11. Loss of Rewards When `LiquidityGauge.totalSupply=0`

**Protocol**: Yield Basis | **Impact**: HIGH

##### Description

The vulnerability lies in **`LiquidityGauge._checkpoint()`**:
```python
## LiquidityGauge._checkpoint()
r.integral_inv_supply = self.integral_inv_supply
if block.timestamp > r.integral_inv_supply.t:
    r.integral_inv_supply.v += unsafe_div(
        10**36 * (block.timestamp - r.integral_inv_supply.t),
        erc4626.erc20.totalSupply  # ← may be 0
    )
    r.integral_inv_supply.t = block.timestamp
```
https://github.com/yield-basis/yb-core/blob/3352c612fc33e48f1a106da41f63810f31bc38be/contracts/dao/LiquidityGauge.vy#L146

If `totalSupply() == 0`, `unsafe_div` returns `0`,...

---

### 12. Uninitialized `specific_emissions_per_gauge` in `GaugeController.add_gauge()`

**Protocol**: Yield Basis | **Impact**: HIGH

##### Description

New gauges don't initialize `specific_emissions_per_gauge[gauge]`, allowing attackers to backrun `add_gauge()`, vote, and claim excess rewards in the same block, due to the extra difference between `specific_emissions - self.specific_emissions_per_gauge[gauge]` (which is `specific_emissions - 0`):
```
if block.timestamp > t:
    
    self.weighted_emissions_per_gauge[gauge] += 
      (specific_emissions - self.specific_emissions_per_gauge[gauge]) 
      * aw // 10**18
    
    self.specific_emissions_per_gauge[gauge] = specific_emissions
```
https://github.com/yield-basis/yb...

---

### 13. Reward Accumulation Manipulation Through Frequent Claims

**Protocol**: DIA | **Impact**: HIGH

##### Description
This issue has been identified within the `claim` function of the `DIAWhitelistedStaking` contract.
Any user can deprive other stakers of rewards by calling the `claim` function multiple times per day. The reward accumulator is updated on each `claim()` call for any user. Consequently, a malicious user can stake the minimum amount and repeatedly call `claim()` throughout the day. Since `daysElapsed` will be rounded down to 0 each time, the `rewardAccumulator` will remain unchanged despite updating `rewardLastUpdateTime`. This results in no rewards being distributed to other s...

---

### 14. Incorrect Reward Calculation When Reward Rate Changes

**Protocol**: DIA | **Impact**: HIGH

##### Description
This issue has been identified within the `getRewardForStakingStore` function of the `DIAWhitelistedStaking` contract.
Currently, rewards are calculated using the current `rewardRatePerDay`, regardless of whether the rate has changed between `currentStore.stakingStartTime` and the present moment. As a result, two identical stakes may receive different rewards depending on when they call `unstake()`.
The issue is classified as **High** severity because it can lead to unfair or inconsistent reward distribution among stakers, potentially undermining trust in the staking mechanis...

---

### 15. Rewards claiming may fail due to potentially decreasing parameters used in calculation

**Protocol**: DIA | **Impact**: HIGH

##### Description
In the `DIAWhitelistedStaking` contract, there is a potential issue in the reward calculation and claiming logic that could lead to reward claims being blocked. The issue arises from the following sequence:
1. In the `updateReward` function, there's an assertion:
```solidity
assert(reward >= currentStore.reward);
```
2. This assertion can fail due to two factors:
- `rewardRatePerDay` can be decreased by the contract owner
- `currentStore.principal` can be decreased during partial principal unstaking
3. When either of these values decreases, the reward calculation in `getRewar...

---


## Statistics

- Total findings from MixBytes: 2,437
- Last updated: 2026-01-29
