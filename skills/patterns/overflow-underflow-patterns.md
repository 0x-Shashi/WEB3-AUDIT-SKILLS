# Overflow/Underflow Security Patterns

## Overview

**Frequency**: 43 occurrences (0.09% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 21 | 22 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, Cyfrin, Trust Security

---

## Detection Checklist

- [ ] Check for overflow/underflow vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [C-01] Withdrawal Calculation Causes Underflow, Locking All User Funds

**Source**: Shieldify
**Protocol**: Terplayer Bvt Staking&Distribution
**Impact**: HIGH

**Details**:

## Severity

Critical Risk

## Description

The withdrawal function includes the user in their own delegation list and uses ceiling division for all calculations. This causes `totalDelegatedAmount` to exceed the requested withdrawal amount, resulting in an underflow when calculating `remainingAmount = amount - totalDelegatedAmount`, which renders all withdrawals unsuccessful.

## Location of Affected Code

File: [src/BvtRewardVault.sol#L155](https://github.com/batoshidao/berabtc-vault-token/blob/c68f412b3c7dfd99d3f6302a42bdf772ededb2a3/src/BvtRewardVault.sol#L155)

```solidity
function withdraw(uint256 amount) external nonReentrant {
  // code

  // Calculate and withdraw from delegated stakes
  for (uint256 i = 0; i < users.length; i++) {
      address user = users[i];
      uint256 delegatedAmount = delegatedStakes[msg.sender][user];
      if (delegatedAmount > 0) {
          uint256 withdrawAmount = (delegatedAmount * amount + stakes[msg.sender] - 1)  / stakes[msg.sender];
          if (withdrawAmount > 0) {
              totalDelegatedAmount += withdrawAmount;
              _delegateWithdraw(msg.sender, user, withdrawAmount);
          }
      }
  }
  // Calculate remaining amount to withdraw from user's own stake
  uint256 remainingAmount = amount - totalDelegatedAmount;
  if (remainingAmount > 0) {
      _delegateWithdraw(msg.sender, msg.sender, remainingAmount);
  }
  // code
}
```

## Impact

All withdrawals fail due to underflow, permanently locking user funds.

## R

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/Terplayer-BVT-Staking&Distribution-Security-Review.md)

---

### Example 2: Loss of Long-Term Swap Proceeds Likely in Pools With Decimal or Price Imbalances

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

### Example 3: [H-02] Underflow of `lpPosition.points` during withdrawLP causes huge reward minting

**Source**: Code4rena
**Protocol**: Neo Tokyo
**Impact**: HIGH

**Details**:

NeoTokyoStaking allows to stake and withdraw LPs. User can stake multiple times on same position which simply results in extended lock time and user can withdraw all of these LPs once lock time is passed.

There is a scenario when withdrawing LPs results in overflow of [lpPosition.points](https://github.com/code-423n4/2023-03-neotokyo/blob/main/contracts/staking/NeoTokyoStaker.sol#L1627). After withdraw if attacker calls `getRewards()` then attacker will get more than 1e64 BYTES tokens as reward.

### Proof of Concept

Affected code block: [NeoTokyoStaker.sol#L1622-L1631](https://github.com/code-423n4/2023-03-neotokyo/blob/main/contracts/staking/NeoTokyoStaker.sol#L1622-L1631)

Affected line: [L1627](https://github.com/code-423n4/2023-03-neotokyo/blob/main/contracts/staking/NeoTokyoStaker.sol#L1627)

From below POC, you can see that Alice is staking twice and some specific amounts which will trigger underflow when Alice withdraw LP. Once staked LPs are unlocked, Alice can withdraw her LPs and call `getReward()` to trigger minting of more than 1e64 BYTES tokens.

Below test can be added in `NeoTokyoStaker.test.js` test file.

```js
		it('Unexpected rewards minting due to underflow of "points"', async function () {
			// Configure the LP token contract address on the staker.
			await NTStaking.connect(owner.signer).configureLP(LPToken.address);
			const amount1 = ethers.utils.parseEther('10.009')
			const amount2 = ethers.utils.parseEther('11.009')
			const lockingDays = 30
			

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-03-neotokyo)

---

### Example 4: Overflow in SegmentedSegmentTree464

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: HIGH

**Details**:

## Security Analysis Report

## Severity
**Critical Risk**

## Context
**File:** SegmentedSegmentTree464.sol  
**Line:** 173

## Description
`SegmentedSegmentTree464.update` needs to perform an overflow check in case the new value is greater than the old value. This overflow check is done when adding the new difference to each node in each layer (using `addClean`). Furthermore, there's a final overflow check by adding up all nodes in the first layer in total (`core`).

However, in total, the nodes in individual groups are added using `DirtyUint64.sumPackedUnsafe`:

```solidity
function total(Core storage core) internal view returns (uint64) {
    return DirtyUint64.sumPackedUnsafe(core.layers[0][0], 0, _C)
           + DirtyUint64.sumPackedUnsafe(core.layers[0][1], 0, _C);
}
```

The nodes in a group can overflow without triggering an overflow & revert. The impact is that the order book depth and claim functionalities break for all users.

```
/ SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
import "forge-std/StdJson.sol";
import "../../contracts/mocks/SegmentedSegmentTree464Wrapper.sol";

contract SegmentedSegmentTree464Test is Test {
    using stdJson for string;
    uint32 private constant _MAX_ORDER = 2**15;
    SegmentedSegmentTree464Wrapper testWrapper;

    function setUp() public {
        testWrapper = new SegmentedSegmentTree464Wrapper();
    }

    function testTotalOverflow() public {
        uint64 half64 = type(uint64).max

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 5: [H-06] Repaying a line of credit with a higher than necessary claimed revenue amount will force the borrower into liquidation

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: HIGH

**Details**:

A borrower can repay (parts) of a credit line with the `SpigotedLine.useAndRepay` function. This function will use `amount` of `unusedTokens[credit.token]` as a repayment. However, if `amount` exceeds the principal and the accrued interest, `credit.principal` will underflow without an error and set the principal value to a very large number.

This a problem because a borrower can unknowingly provide a larger than necessary `amount` to the `SpigotedLine.useAndRepay` function to make sure enough funds are used to fully repay the principal and the remaining interest.

Additionally, a lender can do the same thing as the lender can call this function.

### Impact

The `credit.principal` underflows without an error and will be set to a very large number. This will force a secured line **immediately** into liquidation. Additionally, having a principal value close to `2^256 - 1` will make it hugely expensive to repay the credit line.

### Proof of Concept

[utils/CreditLib.sol#L186](https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/utils/CreditLib.sol#L186)

```solidity
function repay(
  ILineOfCredit.Credit memory credit,
  bytes32 id,
  uint256 amount
)
  external
  returns (ILineOfCredit.Credit memory)
{ unchecked {
    if (amount <= credit.interestAccrued) {
        credit.interestAccrued -= amount;
        credit.interestRepaid += amount;
        emit RepayInterest(id, amount);
        return credit;
    } else {
        uint256 in

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 6: [H-01] implicit underflows

**Source**: Code4rena
**Protocol**: Gro Protocol
**Impact**: HIGH

**Details**:

_Submitted by gpersoon, also found by cmichel_

There are a few underflows that are converted via a typecast afterwards to the expected value. If solidity 0.8.x would be used, then the code would revert.
* `int256(a-b)` where a and b are uint: For example, if `a=1` and `b=2`, then the intermediate result would be `uint(-1) == 2**256-1`
* `int256(-x)` where x is a uint. For example, if `x=1`, then the intermediate result would be `uint(-1) == 2**256-1`

It's better not to have underflows by using the appropriate typecasts. This is especially relevant when moving to solidity 0.8.x.

From `Exposure.sol` [L178](https://github.com/code-423n4/2021-06-gro/blob/main/contracts/insurance/Exposure.sol#L178):
```solidity
function sortVaultsByDelta(..)
..
    for (uint256 i = 0; i < N_COINS; i++) {
        // Get difference between vault current assets and vault target
        int256 delta = int256(unifiedAssets[i] - unifiedTotalAssets.mul(targetPercents[i]).div(PERCENTAGE_DECIMAL_FACTOR)); // underflow in intermediate result
```

From `PnL.sol` [L112](https://github.com/code-423n4/2021-06-gro/blob/main/contracts/pnl/PnL.sol#L112):
```solidity
 function decreaseGTokenLastAmount(bool pwrd, uint256 dollarAmount, uint256 bonus)...
..
 emit LogNewGtokenChange(pwrd, int256(-dollarAmount)); // underflow in intermediate result
```

From `Buoy3Pool.sol` [L87](https://github.com/code-423n4/2021-06-gro/blob/main/contracts/pools/oracle/Buoy3Pool.sol#L87):
```solidity
function safetyCheck() external 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-06-gro)

---

### Example 7: [H-06] Setting new controller can break YVaultLPFarming

**Source**: Code4rena
**Protocol**: JPEG'd
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-04-jpegd/blob/e72861a9ccb707ced9015166fbded5c97c6991b6/contracts/farming/yVaultLPFarming.sol#L170
https://github.com/code-423n4/2022-04-jpegd/blob/e72861a9ccb707ced9015166fbded5c97c6991b6/contracts/vaults/yVault/yVault.sol#L108


## Vulnerability details

## Impact
The accruals in `yVaultLPFarming` will fail if [`currentBalance < previousBalance`](https://github.com/code-423n4/2022-04-jpegd/blob/e72861a9ccb707ced9015166fbded5c97c6991b6/contracts/farming/yVaultLPFarming.sol#L170) in `_computeUpdate`.

```solidity
currentBalance = vault.balanceOfJPEG() + jpeg.balanceOf(address(this));
uint256 newRewards = currentBalance - previousBalance;
```

No funds can be withdrawn anymore as the `withdraw` functions first trigger an `_update`.

The `currentBalance < previousBalance` case can, for example, be triggerd by decreasing the `vault.balanceOfJPEG()` due to calling `yVault.setController`:

```solidity
function setController(address _controller) public onlyOwner {
    // @audit can reduce balanceofJpeg which breaks other masterchef contract
    require(_controller != address(0), "INVALID_CONTROLLER");
    controller = IController(_controller);
}

function balanceOfJPEG() external view returns (uint256) {
    // @audit new controller could return a smaller balance
    return controller.balanceOfJPEG(address(token));
}
```

## Recommended Mitigation Steps
Setting a new controller on a vault must be done very carefully and requires a

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-jpegd)

---

### Example 8: [H-01] Truncation in `OrderValidator` can lead to resetting the fill and selling more tokens

**Source**: Code4rena
**Protocol**: OpenSea
**Impact**: HIGH

**Details**:

[OrderValidator.sol#L228](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L228)<br>
[OrderValidator.sol#L231](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L231)<br>
[OrderValidator.sol#L237](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L237)<br>
[OrderValidator.sol#L238](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/OrderValidator.sol#L238)<br>

A partial order's fractions (`numerator` and `denominator`) can be reset to `0` due to a truncation. This can be used to craft malicious orders:

1.  Consider user Alice, who has 100 ERC1155 tokens, who approved all of their tokens to the `marketplaceContract`.
2.  Alice places a `PARTIAL_OPEN` order with 10 ERC1155 tokens and consideration of ETH.
3.  Malory tries to fill the order in the following way:
    1.  Malory tries to fill 50% of the order, but instead of providing the fraction `1 / 2`, Bob provides `2**118 / 2**119`. This sets the `totalFilled` to `2**118` and `totalSize` to `2**119`.
    2.  Malory tries to fill 10% of the order, by providing `1 / 10`. The computation `2**118 / 2**119 + 1 / 10` is done by "cross multiplying" the denominators, leading to the acutal fraction being `numerator = (2**118 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-opensea-seaport)

---

### Example 9: H-1: Underflow in ```_previewWithdraw``` could prevent withdrawals

**Source**: Sherlock
**Protocol**: Knox Finance
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-09-knox-judging/issues/106 

## Found by 
dipp, \_\_141345\_\_, Trumpero, 0x52, hansfriese, yixxas

## Summary

An underflow in the ```_previewWithdraw``` function in ```AuctionInternal.sol``` due to totalContractsSold exceeding auction.totalContracts could prevent users from withdrawing options.

## Vulnerability Detail

The ```_previewWithdraw``` function returns the fill and refund amounts for a buyer by looping over all orders. A totalContractsSold variable is used to track the amount of contracts sold as the loop iterates over all orders. If the current order's size + totalContractsSold exceeds the auction's totalContracts then the order will only be filled partially. The calculation for the partial fill (remainder) is given on [line 318](https://github.com/sherlock-audit/2022-09-knox/blob/main/knox-contracts/contracts/auction/AuctionInternal.sol#L318). This will lead to an underflow if totalContractsSold > the auction's totalContracts which would happen if there are multiple orders that cause the totalContractsSold variable to exceed totalContracts.

The totalContractsSold variable in ```_previewWithdraw``` could exceed the auction.totalContracts due to the contracts sold before the start of an auction through limit orders not being limited. When an order is added, _finalizeAuction is only called if the auction has started. The ```_finalizeAuction``` function will call the ```_processOrders``` function which will return tru

*[Content truncated...]*

---

### Example 10: Malicious target can make `_endVote()` revert forever by forceUnstaking/staking again

**Source**: Cyfrin
**Protocol**: Streamr
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** In `_endVote()`, we update `forfeitedStakeWei` or `lockedStakeWei[target]` according to the `target`'s staking status.

```solidity
File: contracts\OperatorTokenomics\SponsorshipPolicies\VoteKickPolicy.sol
179:     function _endVote(address target) internal {
180:         address flagger = flaggerAddress[target];
181:         bool flaggerIsGone = stakedWei[flagger] == 0;
182:         bool targetIsGone = stakedWei[target] == 0;
183:         uint reviewerCount = reviewers[target].length;
184:
185:         // release stake locks before vote resolution so that slashings and kickings during resolution aren't affected
186:         // if either the flagger or the target has forceUnstaked or been kicked, the lockedStakeWei was moved to forfeitedStakeWei
187:         if (flaggerIsGone) {
188:             forfeitedStakeWei -= flagStakeWei[target];
189:         } else {
190:             lockedStakeWei[flagger] -= flagStakeWei[target];
191:         }
192:         if (targetIsGone) {
193:             forfeitedStakeWei -= targetStakeAtRiskWei[target];
194:         } else {
195:             lockedStakeWei[target] -= targetStakeAtRiskWei[target]; //@audit revert after forceUnstake() => stake() again
196:         }
```

We consider the target is still active if he has a positive staking amount. But we don't know if he has unstaked and staked again, so the below scenario would be possible.

- The target staked 100 amount and a flagger reported him.
- In `on

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-03-cyfrin-streamr.md)

---

### Example 11: Possible overflow in `_payOutFirstInQueue`

**Source**: Cyfrin
**Protocol**: Streamr
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** In `_payOutFirstInQueue()`, possible revert during `operatorTokenToDataInverse()`.

```solidity
uint amountOperatorTokens = moduleCall(address(exchangeRatePolicy), abi.encodeWithSelector(exchangeRatePolicy.operatorTokenToDataInverse.selector, amountDataWei));
```

If a delegator calls `undelegate()` with `type(uint256).max`, `operatorTokenToDataInverse()` will revert due to uint overflow and the queue logic will be broken forever.

```solidity
   function operatorTokenToDataInverse(uint dataWei) external view returns (uint operatorTokenWei) {
       return dataWei * this.totalSupply() / valueWithoutEarnings();
   }
```

**Impact:** The queue logic will be broken forever because `_payOutFirstInQueue()` keeps reverting.

**Recommended Mitigation:** We should cap `amountDataWei` before calling `operatorTokenToDataInverse()`.

**Client:** Fixed in commit [c62e5d9](https://github.com/streamr-dev/network-contracts/commit/c62e5d90ce8f8c084fe3917f499c967c85a3873b).

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-03-cyfrin-streamr.md)

---

### Example 12: `VoteKickPolicy._endVote()` might revert forever due to underflow

**Source**: Cyfrin
**Protocol**: Streamr
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** In `onFlag()`, `targetStakeAtRiskWei[target]` might be less than the total rewards for the flagger/reviewers due to rounding.

```solidity
File: contracts\OperatorTokenomics\StreamrConfig.sol
22:     /**
23:      * Minimum amount to pay reviewers+flagger
24:      * That is: minimumStakeWei >= (flaggerRewardWei + flagReviewerCount * flagReviewerRewardWei) / slashingFraction
25:      */
26:     function minimumStakeWei() public view returns (uint) {
27:         return (flaggerRewardWei + flagReviewerCount * flagReviewerRewardWei) * 1 ether / slashingFraction;
28:     }
```

- Let's assume `flaggerRewardWei + flagReviewerCount * flagReviewerRewardWei = 100, StreamrConfig.slashingFraction = 0.03e18(3%), minimumStakeWei() = 1000 * 1e18 / 0.03e18 = 10000 / 3 = 3333.`
- If we suppose `stakedWei[target] = streamrConfig.minimumStakeWei()`, then `targetStakeAtRiskWei[target] = 3333 * 0.03e18 / 1e18 = 99.99 = 99.`
- As a result, `targetStakeAtRiskWei[target]` is less than total rewards(=100), and `_endVote()` will revert during the reward distribution due to underflow.

The above scenario is possible only when there is a rounding during `minimumStakeWei` calculation. So it works properly with the default `slashingFraction = 10%`.

**Impact:** The `VoteKickPolicy` wouldn't work as expected and malicious operators won't be kicked forever.

**Recommended Mitigation:** Always round the `minimumStakeWei()` up.

**Client:** Fixed in commit [615b531](https:

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-03-cyfrin-streamr.md)

---

### Example 13: [H-03] Risk of silent overflow in reserves update

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L230-L231> 

<https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L323-L324>

### Vulnerability details

The [`buy()`](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L211) and [`sell()`](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L301) functions update the `virtualBaseTokenReserves` and `virtualNftReserves` variables during each trade. However, these two variables are of type `uint128`, while the values that update them are of type `uint256`. This means that casting to a lower type is necessary, but this casting is performed without first checking that the values being cast can fit into the lower type. As a result, there is a risk of a silent overflow occurring during the casting process.

```solidity
    function buy(uint256[] calldata tokenIds, uint256[] calldata tokenWeights, MerkleMultiProof calldata proof) 
        public
        payable
        returns (uint256 netInputAmount, uint256 feeAmount, uint256 protocolFeeAmount)
    {
        // ~~~ Checks ~~~ //

        // calculate the sum of weights of the NFTs to buy
        uint256 weightSum = sumWeightsAndValidateProof(tokenIds, tokenWeights, proof);

        // calculate the required net input amount and fee amount
        (netInputAmount, feeAmount, protocolFeeAmount) = buyQuote(weightSum);
        ...
        // update the virtual reserves
        virtualBaseTo

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-caviar)

---

### Example 14: [H-02] `UniswapV2PriceOracle.sol` `currentCumulativePrices()` will revert when `priceCumulative` addition overflow

**Source**: Code4rena
**Protocol**: Phuture Finance
**Impact**: HIGH

**Details**:

_Submitted by WatchPug_

[UniswapV2PriceOracle.sol#L62](https://github.com/code-423n4/2022-04-phuture/blob/594459d0865fb6603ba388b53f3f01648f5bb6fb/contracts/UniswapV2PriceOracle.sol#L62)<br>

```solidity
(uint price0Cumulative, uint price1Cumulative, uint32 blockTimestamp) = address(pair).currentCumulativePrices();
```

Because the Solidity version used by the current implementation of `UniswapV2OracleLibrary.sol` is `>=0.8.7`, and there are some breaking changes in Solidity v0.8.0:

> Arithmetic operations revert on underflow and overflow.

Ref: <https://docs.soliditylang.org/en/v0.8.13/080-breaking-changes.html#silent-changes-of-the-semantics>

While in `UniswapV2OracleLibrary.sol`, subtraction overflow is desired at `blockTimestamp - blockTimestampLast` in `currentCumulativePrices()`:

<https://github.com/Uniswap/v2-periphery/blob/master/contracts/libraries/UniswapV2OracleLibrary.sol#L25-L33>

```solidity
if (blockTimestampLast != blockTimestamp) {
    // subtraction overflow is desired
    uint32 timeElapsed = blockTimestamp - blockTimestampLast;
    // addition overflow is desired
    // counterfactual
    price0Cumulative += uint(FixedPoint.fraction(reserve1, reserve0)._x) * timeElapsed;
    // counterfactual
    price1Cumulative += uint(FixedPoint.fraction(reserve0, reserve1)._x) * timeElapsed;
}
```

In another word, `Uniswap/v2-periphery/contracts/libraries/UniswapV2OracleLibrary` only works at solidity < `0.8.0`.

As a result, when `price0Cumulative` or `price1Cumu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-phuture)

---

### Example 15: unchecked may cause under/overflows

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- `LienToken.sol#L424`
- `LienToken.sol#L482`
- `PublicVault.sol#L376`
- `PublicVault.sol#L422`
- `PublicVault.sol#L439`
- `PublicVault.sol#L490`
- `PublicVault.sol#L578`
- `PublicVault.sol#L611`
- `PublicVault.sol#L527`
- `PublicVault.sol#L544`
- `PublicVault.sol#L563`
- `PublicVault.sol#L640`
- `VaultImplementation.sol#L401`
- `WithdrawProxy.sol#L254`
- `WithdrawProxy.sol#L293`

## Description
Unchecked should only be used when there is a guarantee of no underflows or overflows, or when they are taken into account. In the absence of certainty, it's better to avoid unchecked to favor correctness over gas efficiency.

For instance, if by error, `protocolFeeNumerator` is set to be greater than `protocolFeeDenominator`, this block in `_handleProtocolFee()` will underflow:

```solidity
unchecked {
    amount -= fee;
}
```

However, later this reverts due to the ERC20 transfer of an unusually high amount. This is just to demonstrate that unknown bugs can lead to under/overflows.

## Recommendation
Reason about each unchecked and remove them in absence of absolute certainty of safety.

## Astaria
Acknowledged. We'll put checks on setting protocol values to not cross unintended boundaries.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 16: [M-04] After proposed 0.8.0 upgrade kicks in, L2 finalizeInboundTransfer might not work

**Source**: Code4rena
**Protocol**: The Graph
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-thegraph/blob/309a188f7215fa42c745b136357702400f91b4ff/contracts/l2/gateway/L2GraphTokenGateway.sol#L70


## Vulnerability details

## Description

L2GraphTokenGateway uses the onlyL1Counterpart modifier to make sure finalizeInboundTransfer is only called from L1GraphTokenGateway. Its implementation is:

```Solidity
modifier onlyL1Counterpart() {
        require(
            msg.sender == AddressAliasHelper.applyL1ToL2Alias(l1Counterpart),
            "ONLY_COUNTERPART_GATEWAY"
        );
        _;
    }
```

It uses applyL1ToL2Alias defined as:

```
uint160 constant offset = uint160(0x1111000000000000000000000000000000001111);

    /// @notice Utility function that converts the address in the L1 that submitted a tx to
    /// the inbox to the msg.sender viewed in the L2
    /// @param l1Address the address in the L1 that triggered the tx to L2
    /// @return l2Address L2 address as viewed in msg.sender
    function applyL1ToL2Alias(address l1Address) internal pure returns (address l2Address) {
        l2Address = address(uint160(l1Address) + offset);
    }
```

This behavior matches with how Arbitrum augments the sender's address to L2. The issue is that I've spoken with the team and they are [planning](https://github.com/graphprotocol/contracts/pull/725) an upgrade from Solidity 0.7.6 to 0.8.0. Their proposed [changes](https://github.com/graphprotocol/contracts/blob/c4d3cb56cb4032dbb3a0f1b7535b5d94ccf86222/contracts/

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-thegraph)

---

### Example 17: H-7: Overflow in curate() function, results in permanently stuck funds

**Source**: Sherlock
**Protocol**: Axis Finance
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-03-axis-finance-judging/issues/88 

## Found by 
dimulski, merlin
## Summary
The ``Axis-Finance`` protocol has a [curate()](https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/AuctionHouse.sol#L634-L699) function that can be used to set a certain fee to a curator set by the seller for a certain auction. Typically, a curator is providing some service to an auction seller to help the sale succeed. This could be doing diligence on the project and ``vouching`` for them, or something simpler, such as listing the auction on a popular interface. A lot of memecoins have a big supply in the trillions, for example [SHIBA INU](https://etherscan.io/token/0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce#readContract#F2) has a total supply of nearly **1000 trillion tokens** and each token has 18 decimals. With a lot of new memecoins emerging every day due to the favorable bullish conditions and having supply in the trillions, it is safe to assume that  such protocols will interact with the ``Axis-Finance`` protocol. Creating auctions for big amounts, and promising big fees to some celebrities or influencers to promote their project. The funding parameter in the **Routing struct** is of type ``uint96``
```solidity
    struct Routing {
        ...
        uint96 funding; 
        ...
    }
```
The max amount of tokens with 18 decimals a ``uint96`` variable can hold is around 80 billion. The problem arises in the [curate()](h

*[Content truncated...]*

---

### Example 18: `Manager::_transferFee` returns invalid `feeShares` when `fee` is zero

**Source**: Cyfrin
**Protocol**: Yieldfi
**Impact**: MEDIUM

**Details**:

**Description:** When a user deposits directly into `Manager::deposit`, the protocol fee is calculated via the [`Manager::_transferFee`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L226-L242) function:

```solidity
function _transferFee(address _yToken, uint256 _shares, uint256 _fee) internal returns (uint256) {
    if (_fee == 0) {
        return _shares;
    }
    uint256 feeShares = (_shares * _fee) / Constants.HUNDRED_PERCENT;

    IERC20(_yToken).safeTransfer(treasury, feeShares);

    return feeShares;
}
```

The issue is that when `_fee == 0`, the function returns the full `_shares` amount instead of returning `0`. This leads to incorrect logic downstream in [`Manager::_deposit`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L286-L296), where the result is subtracted from the total shares:

```solidity
// transfer fee to treasury, already applied on adjustedShares
uint256 adjustedFeeShares = _transferFee(order.yToken, adjustedShares, _fee);

// Calculate adjusted gas fee shares
uint256 adjustedGasFeeShares = (_gasFeeShares * order.exchangeRateInUnderlying) / currentExchangeRate;

// transfer gas to caller
IERC20(order.yToken).safeTransfer(_caller, adjustedGasFeeShares);

// remaining shares after gas fee
uint256 sharesAfterAllFee = adjustedShares - adjustedFeeShares - adjustedGasFeeShares;
```

If `_fee == 0`, the `adjustedFeeShares`

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-04-24-cyfrin-yieldfi-v2.0.md)

---

### Example 19: FullMath requires overflow behavior

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: HIGH

**Details**:

## Security Audit Summary

## Severity
**High Risk**

## Context
`FullMath.sol#L2`

## Description
UniswapV3s `FullMath.sol` is copied and migrated from an old solidity version to version 0.8, which reverts on overflows. However, the old `FullMath` relies on implicit overflow behavior. The current code will revert on overflows when it should not, which breaks the `SwapManagerUniV3` contract.

## Recommendation
Use the official `FullMath.sol` 0.8 branch that wraps the code in an unchecked statement. See #40.

## Spearbit
Fixed. The Uniswap V3 branch is added as a dependency in PR #550.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 20: [M-02] Twav.sol#_getTwav() will revert when timestamp  4294967296

**Source**: Code4rena
**Protocol**: Nibbl
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-06-nibbl/blob/8c3dbd6adf350f35c58b31723d42117765644110/contracts/Twav/Twav.sol#L35-L42


## Vulnerability details

```solidity
function _getTwav() internal view returns(uint256 _twav){
    if (twavObservations[TWAV_BLOCK_NUMBERS - 1].timestamp != 0) {
        uint8 _index = ((twavObservationsIndex + TWAV_BLOCK_NUMBERS) - 1) % TWAV_BLOCK_NUMBERS;
        TwavObservation memory _twavObservationCurrent = twavObservations[(_index)];
        TwavObservation memory _twavObservationPrev = twavObservations[(_index + 1) % TWAV_BLOCK_NUMBERS];
        _twav = (_twavObservationCurrent.cumulativeValuation - _twavObservationPrev.cumulativeValuation) / (_twavObservationCurrent.timestamp - _twavObservationPrev.timestamp);
    }
}
```

Since `_blockTimestamp` is `uint32`, subtraction underflow is desired at `_twavObservationCurrent.timestamp - _twavObservationPrev.timestamp`.

See: https://github.com/Uniswap/v2-periphery/blob/master/contracts/examples/ExampleOracleSimple.sol#L43

```solidity
function update() external {
    (uint price0Cumulative, uint price1Cumulative, uint32 blockTimestamp) =
        UniswapV2OracleLibrary.currentCumulativePrices(address(pair));
    uint32 timeElapsed = blockTimestamp - blockTimestampLast; // overflow is desired
```

Because the solidity version used by the current implementation is `0.8.10`, and there are some breaking changes in Solidity v0.8.0:

> Arithmetic operations revert on underflow and overflow

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-nibbl)

---

### Example 21: [H-02] Minting and redeeming will break for fully minted tiers with `reserveRate != 0` and `reserveRate`/`MaxReserveRate` tokens burned

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: HIGH

**Details**:

Minting and redeeming become impossible.

### Proof of Concept

    uint256 _numberOfNonReservesMinted = _storedTier.initialQuantity -
      _storedTier.remainingQuantity -
      _reserveTokensMinted;

    uint256 _numerator = uint256(_numberOfNonReservesMinted * _storedTier.reservedRate);

    uint256 _numberReservedTokensMintable = _numerator / JBConstants.MAX_RESERVED_RATE;

    if (_numerator - JBConstants.MAX_RESERVED_RATE * _numberReservedTokensMintable > 0)
      ++_numberReservedTokensMintable;

    return _numberReservedTokensMintable - _reserveTokensMinted;

The lines above are taken from JBTiered721DelegateStore#\_numberOfReservedTokensOutstandingFor and used to calculate and return the available number of reserve tokens that can be minted. Since the return statement doesn't check that \_numberReservedTokensMintable >= \_reserveTokensMinted, it will revert under those circumstances. The issue is that there are legitimate circumstances in which this becomes false. If a tier is fully minted then all reserve tokens are mintable. When the tier begins to redeem, \_numberReservedTokensMintable will fall under \_reserveTokensMinted, permanently breaking minting and redeeming. Minting is broken because all mint functions directly call \_numberOfReservedTokensOutstandingFor. Redeeming is broken because the redeem callback (JB721Delegate#redeemParams) calls \_totalRedemtionWeight which calls \_numberOfReservedTokensOutstandingFor.

Example:

A tier has a reserveRate of 100 (

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-juicebox)

---

### Example 22: [H-05] Attacker can steal entire reserves by abusing fee calculation

**Source**: Code4rena
**Protocol**: Trader Joe
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-10-traderjoe/blob/79f25d48b907f9d0379dd803fc2abc9c5f57db93/src/LBPair.sol#L819-L829><br>
<https://github.com/code-423n4/2022-10-traderjoe/blob/79f25d48b907f9d0379dd803fc2abc9c5f57db93/src/LBToken.sol#L202><br>

Similar to other LP pools, In Trader Joe users can call `mint()` to provide liquidity and receive LP tokens, and `burn()` to return their LP tokens in exchange for underlying assets. Users collect fees using `collectFess(account,binID)`. Fees are implemented using debt model. The fundamental fee calculation is:

        function _getPendingFees(
            Bin memory _bin,
            address _account,
            uint256 _id,
            uint256 _balance
        ) private view returns (uint256 amountX, uint256 amountY) {
            Debts memory _debts = _accruedDebts[_account][_id];

            amountX = _bin.accTokenXPerShare.mulShiftRoundDown(_balance, Constants.SCALE_OFFSET) - _debts.debtX;
            amountY = _bin.accTokenYPerShare.mulShiftRoundDown(_balance, Constants.SCALE_OFFSET) - _debts.debtY;
        }

accTokenXPerShare / accTokenYPerShare is an ever increasing amount that is updated when swap fees are paid to the current active bin.

When liquidity is first minted to user, the \_accruedDebts is updated to match current \_balance &ast; accToken&ast;PerShare. Without this step, user could collect fees for the entire growth of accToken&ast;PerShare from zero to current value. This is done in \_updateUserDebts, called b

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-traderjoe)

---

### Example 23: INTEGER OVERFLOW

**Source**: Halborn
**Protocol**: MonoX
**Impact**: MEDIUM

**Details**:

##### Description

An overflow happens when an arithmetic operation reaches the maximum size of a type. For instance, in `Monoswap.sol`, the `getAmountOut` method is subtracting `fees` from a fixed number and may end up overflowing the integer since the resulting value is not checked to be greater or equal 0. In computer programming, an integer overflow occurs when an arithmetic operation attempts to create a numeric value that is outside of the range that can be represented with a given number of bits  either larger than the maximum or lower than the minimum representable value.

Code Location
-------------

#### Monoswap.sol

```
function getAmountOut(address tokenIn, address tokenOut, 
    uint256 amountIn) public view returns (uint256 tokenInPrice, uint256 tokenOutPrice, 
    uint256 amountOut, uint256 tradeVusdValue) {
    require(amountIn > 0, 'Monoswap: INSUFFICIENT_INPUT_AMOUNT');

    uint256 amountInWithFee = amountIn.mul(1e5-fees)/1e5;
    address vusdAddress = address(vUSD);

```

#### Monoswap.sol

```
function getAmountIn(address tokenIn, address tokenOut, 
    uint256 amountOut) public view returns (uint256 tokenInPrice, uint256 tokenOutPrice, 
    uint256 amountIn, uint256 tradeVusdValue) {
    require(amountOut > 0, 'Monoswap: INSUFFICIENT_INPUT_AMOUNT');

    uint256 amountOutWithFee = amountOut.mul(1e5+fees)/1e5;
    address vusdAddress = address(vUSD);

```

##### Score

Impact: 3  
Likelihood: 3

##### Recommendation

**SOLVED**: MonoX is certain the int

*[Content truncated...]*

**Reference**: [View Original Finding](https://www.halborn.com/audits/monox/monox-smart-contract-security-assessment)

---

### Example 24: M-3: Repaying loans with small amounts of debt tokens can lead to underflowing in the `roll` function

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/263 

## Found by 
tsvetanovv, rvierdiiev, ck, zaskoh, Allarious, Trumpero, Breeje, berndartmueller, jonatascm, Deivitto

## Summary

Due to precision issues when repaying a loan with small amounts of debt tokens, the `loan.amount` can be reduced whereas the `loan.collateral` remains unchanged. This can lead to underflowing in the `roll` function.

## Vulnerability Detail

The `decollateralized` calculation in the `repay` function rounds down to zero if the `repaid` amount is small enough. This allows iteratively repaying a loan with very small amounts of debt tokens without reducing the collateral.

The consequence is that the `roll` function can revert due to underflowing the `newCollateral` calculation once the `loan.collateral` is greater than `collateralFor(loan.amount, req.loanToCollateral)` (`loan.amount` is reduced by repaying the loan)

As any ERC-20 tokens with different decimals can be used, this precision issue is amplified if the decimals of the collateral and debt tokens differ greatly.

## Impact

The `roll` function can revert due to underflowing the `newCollateral` calculation if the `repay` function is (iteratively) called with small amounts of debt tokens.

## Code Snippet

[Cooler.sol#L114](https://github.com/sherlock-audit/2023-01-cooler/blob/main/src/Cooler.sol#L114)

```solidity
function repay (uint256 loanID, uint256 repaid) external {
    Loan storage loan = loans[loanID];

    if

*[Content truncated...]*

---

### Example 25: M-12: PerpDepository.netAssetDeposits variable can prevent users to withdraw with underflow error

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/97 

## Found by 
rvierdiiev

## Summary
PerpDepository.netAssetDeposits variable can prevent users to withdraw with underflow error
## Vulnerability Detail
When user deposits using PerpDepository, then `netAssetDeposits` variable is increased with the base assets amount, provided by depositor.
https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L283-L288
```solidity
    function _depositAsset(uint256 amount) private {
        netAssetDeposits += amount;


        IERC20(assetToken).approve(address(vault), amount);
        vault.deposit(assetToken, amount);
    }
```

Also when user withdraws, this `netAssetDeposits` variable is decreased with base amount that user has received for redeeming his UXD tokens.
https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L294-L302
```solidity
    function _withdrawAsset(uint256 amount, address to) private {
        if (amount > netAssetDeposits) {
            revert InsufficientAssetDeposits(netAssetDeposits, amount);
        }
        netAssetDeposits -= amount;


        vault.withdraw(address(assetToken), amount);
        IERC20(assetToken).transfer(to, amount);
    }
```

The problem here is that when user deposits X assets, then he receives Y UXD tokens. And when later he redeems his Y UXD tokens he can receive more or less than X assets. This can lead to situation 

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 43
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

