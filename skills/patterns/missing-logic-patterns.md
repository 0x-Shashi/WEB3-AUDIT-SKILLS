# Missing-Logic Security Patterns

## Overview

**Frequency**: 33 occurrences (0.07% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 14 | 19 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Hans, Pashov Audit Group, Kann

---

## Detection Checklist

- [ ] Check for missing-logic vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] Incorrect Accounting of currentWithheldETHinInstantWithdrawals

**Source**: Kann
**Protocol**: Mystic Finance
**Impact**: HIGH

**Details**:

## Severity

High

## Description

In the withdraw(address recipient) function, when the withdrawal amount is less than
or equal to currentWithheldETH, the function enters the instant withdrawal path. In this case, the
contract does not call plumeStaking.withdraw(), and the funds are expected to be fully covered by the
ETH already held in currentWithheldETH. However, the code still sets withdrawn = amount and then
unconditionally adds this value back to currentWithheldETH. Immediately after, it subtracts amount
from currentWithheldETH, effectively leaving the value of currentWithheldETH unchanged.

```solidity
} else {
fee = amount * INSTANT_REDEMPTION_FEE / RATIO_PRECISION;
withdrawn = amount;
}
uint256 cachedWithheldETH = currentWithheldETH;
currentWithheldETH += withdrawn; // adding the withdraw amount
withHoldEth += fee;
currentWithheldETH -= amount; // deducting the amount
```

This logic is flawed because the ETH used to fulfill the withdrawal is not newly received; it is already
present in currentWithheldETH, and should simply be subtracted, not first added and then subtracted.
The current logic makes it appear as if no ETH was withdrawn, which results in incorrect accounting
of the withheld pool. If multiple such withdrawals occur, the system will consistently over-report the
available withheld ETH, potentially leading to over-withdrawals or failed withdrawals in the future
when actual funds are not available.

## Team Response

Fixed.

**Reference**: [View Original Finding](https://github.com/Kann-Audits/Kann-Audits/blob/main/reports/md-format/private-audits-reports/Mystic Finance.md)

---

### Example 2: [H-01] All orders can be hijacked to lock rental assets forever by tipping a malicious ERC20

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: HIGH

**Details**:

The `Create` contract is responsible for creating a rental. It achieves this by acting as a Seaport `Zone`, and storing and validating orders as rentals when they are fulfilled on Seaport.

However, one thing it doesn't account for is the fact that Seaport allows for "tipping" in the form of ERC20 tokens as part of the order fulfillment process. This is done by extending the `consideration` array in the order with additional ERC20 tokens.

From the Seaport [docs](https://docs.opensea.io/reference/seaport-overview#order) (emphasis mine):

> The `consideration` contains an array of items that must be received in order to fulfill the order. It contains all of the same components as an offered item, and additionally includes a `recipient` that will receive each item. This array **may be extended by the fulfiller on order fulfillment so as to support "tipping"** (e.g. relayer or referral payments).

This other passage, while discussing a different issue, even highlights the root cause of this vulnerability (the zone does not properly allocate consideration extensions):

> As extensions to the consideration array on fulfillment (i.e. "tipping") can be arbitrarily set by the caller, fulfillments where all matched orders have already been signed for or validated can be frontrun on submission, with the frontrunner modifying any tips. Therefore, it is important that orders fulfilled in this manner either leverage "restricted" order types with a **zone that enforces appropriate allocati

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 3: H-8: Interest component of underlying amount is not withdrawable using the `withdrawLend` function. Such amount is permanently locked in the BlueBerryBank contract

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/109 

## Found by 
berndartmueller, carrot, minhtrng, 0Kage, Jeiwan, chaduke, koxuan, Ruhum, cergyk, rbserver, stent, saian, XKET, GimelSec

## Summary
Soft vault shares are issued against interest bearing tokens issued by `Compound` protocol in exchange for underlying deposits. However, `withdrawLend` function caps the withdrawable amount to initial underlying deposited by user (`pos.underlyingAmount`). Capping underlying amount to initial underlying deposited would mean that a user can burn all his vault shares in `withdrawLend` function and only receive original underlying deposited.

Interest accrued component received from Soft vault (that rightfully belongs to the user) is no longer retrievable because the underlying vault shares are already burnt. Loss to the users is permanent as such interest amount sits permanently locked in Blueberry bank.

## Vulnerability Detail

[`withdrawLend` function in `BlueBerryBank`](https://github.com/sherlock-audit/2023-02-blueberry/blob/main/contracts/BlueBerryBank.sol#L669) allows users to withdraw underlying amount from `Hard` or `Soft` vaults. `Soft` vault shares are backed by interest bearing `cTokens` issued by Compound Protocol

User can request underlying by specifying `shareAmount`. When user tries to send the maximum `shareAmount` to withdraw all the lent amount, notice that the amount withdrawable is limited to the `pos.underlyingAmount` (original depos

*[Content truncated...]*

---

### Example 4: H-5: Users can get around MaxLTV because of lack of strategyId validation

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/129 

## Found by 
8olidity, carrot, Jeiwan, obront, Ch\_301, cergyk, rbserver

## Summary

When a user withdraws some of their underlying token, there is a check to ensure they still meet the Max LTV requirements. However, they are able to arbitrarily enter any `strategyId` that they would like for this check, which could allow them to exceed the LTV for their real strategy while passing the approval.

## Vulnerability Detail

When a user calls `IchiVaultSpell.sol#reducePosition()`, it removes some of their underlying token from the vault, increasing the LTV of any loans they have taken.

As a result, the `_validateMaxLTV(strategyId)` function is called to ensure they remain compliant with their strategy's specified LTV:
```solidity
function _validateMaxLTV(uint256 strategyId) internal view {
    uint256 debtValue = bank.getDebtValue(bank.POSITION_ID());
    (, address collToken, uint256 collAmount, , , , , ) = bank
        .getCurrentPositionInfo();
    uint256 collPrice = bank.oracle().getPrice(collToken);
    uint256 collValue = (collPrice * collAmount) /
        10**IERC20Metadata(collToken).decimals();

    if (
        debtValue >
        (collValue * maxLTV[strategyId][collToken]) / DENOMINATOR
    ) revert EXCEED_MAX_LTV();
}
```
To summarize, this check:
- Pulls the position's total debt value
- Pulls the position's total value of underlying tokens
- Pulls the specified maxLTV for this strate

*[Content truncated...]*

---

### Example 5: H-3: LP tokens are not sent back to withdrawing user

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/151 

## Found by 
rvierdiiev, minhtrng, Dug, Jeiwan, obront, chaduke, koxuan, sinarette, Ch\_301, cergyk, evan, berndartmueller, 0x52, Bauer

## Summary

When users withdraw their assets from `IchiVaultSpell.sol`, the function unwinds their position and sends them back their assets, but it never sends them back the amount they requested to withdraw, leaving the tokens stuck in the Spell contract.

## Vulnerability Detail

When a user withdraws from `IchiVaultSpell.sol`, they either call `closePosition()` or `closePositionFarm()`, both of which make an internal call to `withdrawInternal()`.

The following arguments are passed to the function:
- strategyId: an index into the `strategies` array, which specifies the Ichi vault in question
- collToken: the underlying token, which is withdrawn from Compound
- amountShareWithdraw: the number of underlying tokens to withdraw from Compound
- borrowToken: the token that was borrowed from Compound to create the position, one of the underlying tokens of the vault
- amountRepay: the amount of the borrow token to repay to Compound
- amountLpWithdraw: the amount of the LP token to withdraw, rather than trade back into borrow tokens

In order to accomplish these goals, the contract does the following...

1) Removes the LP tokens from the ERC1155 holding them for collateral.
```solidity
doTakeCollateral(strategies[strategyId].vault, lpTakeAmt);
```
2) Calculates the n

*[Content truncated...]*

---

### Example 6: H-2: Users who deposit extra funds into their Ichi farming positions will lose all their ICHI rewards

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/158 

## Found by 
carrot, rvierdiiev, minhtrng, obront, sinarette, tives, berndartmueller, 0x52

## Summary

When a user deposits extra funds into their Ichi farming position using `openPositionFarm()`, the old farming position will be closed down and a new one will be opened. Part of this process is that their ICHI rewards will be sent to the `IchiVaultSpell.sol` contract, but they will not be distributed. They will sit in the contract until the next user (or MEV bot) calls `closePositionFarm()`, at which point they will be stolen by that user.

## Vulnerability Detail

When Ichi farming positions are opened via the `IchiVaultSpell.sol` contract, `openPositionFarm()` is called. It goes through the usual deposit function, but rather than staking the LP tokens directly, it calls `wIchiFarm.mint()`. This function deposits the token into the `ichiFarm`, encodes the deposit as an ERC1155, and sends that token back to the Spell:
```solidity
function mint(uint256 pid, uint256 amount)
    external
    nonReentrant
    returns (uint256)
{
    address lpToken = ichiFarm.lpToken(pid);
    IERC20Upgradeable(lpToken).safeTransferFrom(
        msg.sender,
        address(this),
        amount
    );
    if (
        IERC20Upgradeable(lpToken).allowance(
            address(this),
            address(ichiFarm)
        ) != type(uint256).max
    ) {
        // We only need to do this once per pool, as LP token's all

*[Content truncated...]*

---

### Example 7: [H-02] A malicious user can avoid unfavorable score updates after alpha/multiplier changes, resulting in accrual of outsized rewards for the attacker at the expense of other users

**Source**: Code4rena
**Protocol**: Venus Protocol
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L397-L405> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L704-L756> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L623-L639> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L827-L833> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L200-L219> 

<https://github.com/code-423n4/2023-09-venus/blob/main/tests/hardhat/Prime/Prime.ts#L294-L301>

Please note: All functions/properties referred to are in the `Prime.sol` contract.

### Impact

A malicious user can accrue outsized rewards at the expense of other users after `updateAlpha()` or `updateMultipliers()` is called.

### Proof of Concept

An attacker can prevent their score from being updated and decreased after the protocol's alpha or multipliers change. This is done by manipulatively decreasing the value of `pendingScoreUpdates`, then ensuring that only other user scores are updated until `pendingScoreUpdates` reaches zero, at which point calls to `updateScores()` will revert with the error `NoScoreUpdatesRequired()`. This can be done via the attacker calling `updateScores()` to update other users' scores first and/or DoSing calls to `updateScores()` that would update the attacker's score (see the issue titled "DoS and gas griefing of Prime.updateScores()").

The core of 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-09-venus)

---

### Example 8: tradingFunction returns wrong invariant at bounds, allowing to steal all pool reserves

**Source**: Spearbit
**Protocol**: Primitive
**Impact**: HIGH

**Details**:

## Critical Risk Report

## Severity
**Critical Risk**

## Context
`NormalStrategyLib.sol#L157-L165`

## Description
The `tradingFunction` computing the invariant value of 

\[ k = \Phi^{-1}(y/K) - \Phi^{-1}(1-x) + \sigma \tau \]

returns the wrong value at the bounds of `x` and `y`. 

- The bounds of `x` are 0 and 1e18.
- The bounds of `y` are 0 and `K`, the strike price.

If `x` or `y` is at these bounds, the corresponding term's computation is skipped and therefore implicitly set to 0, its initialization value.

```solidity
int256 invariantTermX; // Φ¹(1-x)
// @audit if x is at the bounds, the term remains 0
if (self.reserveXPerWad.isBetween(lowerBoundX + 1, upperBoundX - 1)) {
    invariantTermX = Gaussian.ppf(int256(WAD - self.reserveXPerWad));
}
```

```solidity
int256 invariantTermY; // Φ¹(y/K)
// @audit if y is at the bounds, the term remains 0
if (self.reserveYPerWad.isBetween(lowerBoundY + 1, upperBoundY - 1)) {
    invariantTermY = Gaussian.ppf(
        int256(self.reserveYPerWad.divWadUp(self.strikePriceWad))
    );
}
```

Note that \(\Phi^{-1} = \text{Gaussian.ppf}\) is the probit function, which is undefined at 0 and 1.0, but tends towards -infinity at 0 and +infinity at 1.0 = 1e18. (The closest values used in the Solidity approximation are `Gaussian.ppf(1) = -8710427241990476442 ~ -8.71` and `Gaussian.ppf(1e18-1) = 8710427241990476442 ~ 8.71`.)

This fact can be abused by an attacker to steal the pool reserves. For example, the y-term \(\Phi^{-1}(y/K)\) will be

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Primitive-Spearbit-Security-Review-July.pdf)

---

### Example 9: H-1: All fund from Teller contract can be drained because a malicious receiver can call reclaim repeatedly

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/79 

## Found by 
0xcrunch, Jiamin, Juntao, Kow, Musaka, Sm4rty, Yuki, berndartmueller, bin2chen, circlelooper, ctf\_sec, kutugu, stuxy, tnquanghuy0512, tvdung94
## Summary

All fund from Teller contract can be drained because a malicious receiver can call reclaim repeatedly

## Vulnerability Detail

When [mint an option token](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L296), the user is required to transfer the [payout token for a call option](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L277) or [quote token for a put option](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L289)

if after the expiration, the receiver can call reclaim to claim the payout token if the option type is call or claim the quote token if the option type is put

however, the root cause is when reclaim the token, the corresponding option is not burnt ([code](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L395))

```solidity
       // Revert if caller is not receiver
        if (msg.sender != receiver) revert Teller_NotAuthorized();

    

*[Content truncated...]*

---

### Example 10: [M-01] `setGatewayAddress` incorrectly updates address of the gateway

**Source**: Pashov Audit Group
**Protocol**: Subsquid
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** Medium, gateway will still has it's old address

**Likelihood:** Medium, only occurs if the user decides to set a new address for his gateway

## Description

The gateway owner can set a new address for it using `setGatewayAddress` function. Unfortunately, this function only updates `gatewayByAddress` mapping, leaving `Gateway` struct intact

```solidity
  function setGatewayAddress(bytes calldata peerId, address newAddress) public {
    (Gateway storage gateway, bytes32 peerIdHash) = _getGateway(peerId);
    _requireOperator(gateway);

    if (gateway.ownAddress != address(0)) {
>>    delete gatewayByAddress[gateway.ownAddress];
    }

    if (address(newAddress) != address(0)) {
      require(gatewayByAddress[newAddress] == bytes32(0), "Gateway address already registered");
>>     gatewayByAddress[newAddress] = peerIdHash;
    }
```

If the user tries to call `allocateComputationUnits`, the contract will expect the old gateway address in `msg.sender`

```solidity
  function allocateComputationUnits(bytes calldata peerId, uint256[] calldata workerId, uint256[] calldata cus)
    external
    whenNotPaused
  {
    require(workerId.length == cus.length, "Length mismatch");
    (Gateway storage gateway,) = _getGateway(peerId);
>>  require(gateway.ownAddress == msg.sender, "Only gateway can allocate CUs");
```

Coded POC for `GatewayRegistry.unstake.t.sol`

```solidity
  function test_SetAddress() public {
    GatewayRegistry.Gateway memory gt = gatewayRe

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Subsquid-security-review.md)

---

### Example 11: [M-02] `pause/unpause` functionalities not implemented in many pausable contracts

**Source**: Code4rena
**Protocol**: Stader Labs
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-06-stader/blob/main/contracts/SocializingPool.sol#L21> <br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/Auction.sol#L14> <br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/StaderOracle.sol#L17><br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/OperatorRewardsCollector.sol#L16>

The following contracts: `SocializingPool`, `StaderOracle`, `OperatorRewardsCollector` and `Auction` are supposed to be pausable (as they all inherit from `PausableUpgradeable`), but they don't implement the external `pause/unpause` functionalities which means it will never be possible to pause them.

### Proof of Concept

All the following contracts `SocializingPool`, `StaderOracle`, `OperatorRewardsCollector` and `Auction` inherit from the openzeppelin `PausableUpgradeable` extension which means that they contain internal functions `_pause` and `_unpause`.

Because those functions are internal, the contract must implement two other public/external `pause` and `unpause` functions to allow the manager to pause and unpause the contracts when necessary. None of the aforementioned contracts implement those functions, which means even if those contracts are supposed to be pausable (and have the `pause/unpause` functionalities), none of them can be paused.

### Recommended Mitigation Steps

Add public/external `pause` and `unpause` functions in the aforementioned contracts to allow them to be pausable, this can be

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-stader)

---

### Example 12: User's funds are locked temporarily in the PriorityPool contract

**Source**: Cyfrin
**Protocol**: Stake Link
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol intended to utilize the deposit queue for withdrawal to minimize the stake/unstake interaction with the staking pool.
When a user wants to withdraw, they are supposed to call the function `PriorityPool::withdraw()` with the desired amount as a parameter.
```solidity
function withdraw(uint256 _amount) external {//@audit-info LSD token
    if (_amount == 0) revert InvalidAmount();
    IERC20Upgradeable(address(stakingPool)).safeTransferFrom(msg.sender, address(this), _amount);//@audit-info get LSD token from the user
    _withdraw(msg.sender, _amount);
}
```
As we can see in the implementation, the protocol pulls the `_amount` of LSD tokens from the user first and then calls `_withdraw()` where the actual withdrawal utilizing the queue is processed.
```solidity
function _withdraw(address _account, uint256 _amount) internal {
    if (poolStatus == PoolStatus.CLOSED) revert WithdrawalsDisabled();

    uint256 toWithdrawFromQueue = _amount <= totalQueued ? _amount : totalQueued;//@audit-info if the queue is not empty, we use that first
    uint256 toWithdrawFromPool = _amount - toWithdrawFromQueue;

    if (toWithdrawFromQueue != 0) {
        totalQueued -= toWithdrawFromQueue;
        depositsSinceLastUpdate += toWithdrawFromQueue;//@audit-info regard this as a deposit via the queue
    }

    if (toWithdrawFromPool != 0) {
        stakingPool.withdraw(address(this), address(this), toWithdrawFromPool);//@audit-info withdraw from

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-08-25-cyfrin-stake-link.md)

---

### Example 13: M-12: Chainlink's latestRoundData  return stale or incorrect result

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/94 

## Found by 
8olidity, tsvetanovv, WatchDogs, Nyx, Avci, obront, Aymen0909, SPYBOY, HonorLt, csanuragjain, koxuan, evan, rbserver, hl\_, peanuts, Chinmay

## Summary
https://github.com/sherlock-audit/2023-02-blueberry/blob/main/contracts/oracle/ChainlinkAdapterOracle.sol#L76

## Vulnerability Detail

## Impact
On ChainlinkAdapterOracle.sol, you are using latestRoundData, but there is no check if the return value indicates stale data. 
```solidity
function getPrice(address _token) external view override returns (uint256) {
        // remap token if possible
        address token = remappedTokens[_token];
        if (token == address(0)) token = _token;

        uint256 maxDelayTime = maxDelayTimes[token];
        if (maxDelayTime == 0) revert NO_MAX_DELAY(_token);

        // try to get token-USD price
        uint256 decimals = registry.decimals(token, USD);
        (, int256 answer, , uint256 updatedAt, ) = registry.latestRoundData(
            token,
            USD
        );
        if (updatedAt < block.timestamp - maxDelayTime)
            revert PRICE_OUTDATED(_token);

        return (answer.toUint256() * 1e18) / 10**decimals;
    }
```
This could lead to stale prices according to the Chainlink documentation:
https://docs.chain.link/data-feeds/price-feeds/historical-data
Related report:
https://github.com/code-423n4/2021-05-fairside-findings/issues/70

## Code Snippet
https://github.com/sh

*[Content truncated...]*

---

### Example 14: H-9: UniswapV3 sqrtRatioLimit doesn't provide slippage protection and will result in partial swaps

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

### Example 15: H-9: BlueBerryBank#withdrawLend will cause underlying token accounting error if soft/hard vault has withdraw fee

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/33 

## Found by 
y1cunhui, rvierdiiev, csanuragjain, Ruhum, evan, 0x52

## Summary

Soft/hard vaults can have a withdraw fee. This takes a certain percentage from the user when they withdraw. The way that the token accounting works in BlueBerryBank#withdrawLend, it will only remove the amount returned by the hard/soft vault from pos.underlying amount. If there is a withdraw fee, underlying amount will not be decrease properly and the user will be left with phantom collateral that they can still use.

## Vulnerability Detail

        // Cut withdraw fee if it is in withdrawVaultFee Window (2 months)
        if (
            block.timestamp <
            config.withdrawVaultFeeWindowStartTime() +
                config.withdrawVaultFeeWindow()
        ) {
            uint256 fee = (withdrawAmount * config.withdrawVaultFee()) /
                DENOMINATOR;
            uToken.safeTransfer(config.treasury(), fee);
            withdrawAmount -= fee;
        }

Both SoftVault and HardVault implement a withdraw fee. Here we see that withdrawAmount (the return value) is decreased by the fee amount.

        uint256 wAmount;
        if (address(ISoftVault(bank.softVault).uToken()) == token) {
            ISoftVault(bank.softVault).approve(
                bank.softVault,
                type(uint256).max
            );
            wAmount = ISoftVault(bank.softVault).withdraw(shareAmount);
        } else {
    

*[Content truncated...]*

---

### Example 16: H-4: Fail to accrue interests on multiple token positions

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/140 

## Found by 
cducrest-brainbot, rvierdiiev, Jeiwan

## Summary

In `BlueBerryBank.sol` the functions `borrow`, `repay`, `lend`, or `withdrawLend` call `poke(token)` to trigger interest accrual on concerned token, but fail to do so for other token debts of the concerned position.  This could lead to wrong calculation of position's debt and whether the position is liquidatable.

## Vulnerability Detail

Whether a position is liquidatable or not is checked at the end of the `execute` function, the execution should revert if the position is liquidatable. 

The calculation of whether a position is liquidatable takes into account all the different debt tokens within the position. However, the debt accrual has been triggered only for one of these tokens, the one concerned by the executed action. For other tokens, the value of `bank.totalDebt` will be lower than what it should be. This results in the debt value of the position being lower than what it should be and a position seen as not liquidatable while it should be liquidatable. 

## Impact

Users may be able to operate on their position leading them in a virtually liquidatable state while not reverting as interests were not applied. This will worsen the debt situation of the bank and lead to overall more liquidatable positions.

## Code Snippet

execute checking isLiquidatable without triggering interests:

https://github.com/sherlock-audit/2023-02-

*[Content truncated...]*

---

### Example 17: Borrower with bad debt gets mint reward

**Source**: Hans
**Protocol**: Meta
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Context:** [`MUSDManager.sol#L249`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/musd/MUSDManager.sol#L249), [`MUSDManager.sol#L299`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/musd/MUSDManager.sol#L299 "‌"), [`MintRewards.sol#L121`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/reward/MintRewards.sol#L121 "‌"), [`MintRewards.sol#L92`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/reward/MintRewards.sol#L92 "‌")

**Description:**

With the current implementation, it is possible that the borrowers are in bad debt. As confirmed with the protocol team, _“When user's collateral position is under 100%, only the respective amount of mUSD which is equivalent of GLP\*price which is less than is debt position is closed.”_ ([MUSDManager.sol#L249](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/musd/MUSDManager.sol#L249), [MUSDManager.sol#L299](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/musd/MUSDManager.sol#L299 "‌"))

On the other hand, by the protocol’s design, anyone with positive `borrowed` is considered as a mUSD holder and can claim the mint reward. Note that the user does not need to mint additional mUSD. ([MintRewards.sol#L121](https://github.com/getmetafinance/

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### Example 18: On restaking, funds should be unslashed back

**Source**: Hans
**Protocol**: Meta
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Context:** [`MetaManager.sol#L117-L126`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/meta/MetaManager.sol#L117-L126)

**Description:**
In `MetaManager::reStake`, `toMint` is calculated as `getReservedForVesting(caller) + getClaimable(caller)` and it’s essentially the same to `unstakeRate[_user] * (time2fullRedemption[_user] - lastWithdrawTime[_user])`. The problem is that this should be “unslashed” using the `lastSlashRate` to be fair.

For example, a user starts unstaking 100e18 esMETA with 10 days vesting period and after a day he decided to stop unstaking and restake.

In this case, the originally slashed 50e18 esMETA are not fair for him and the protocol should reimburse partial slash.

**Impact**
While this is not a genuine bug, it is more of a recommendation to enhance the protocol's completeness. However, I have classified its severity level as MEDIUM since it is evidently not an intended mechanism to ensure fairness.

**Recommendation:**
Add a new logic to reimburse the slashed amounts partially when the user restakes.

**Meta Team:**

Fixed.

```diff

function reStake() external updateReward(msg.sender) {
address caller = msg.sender;
uint256 toMint = getReservedForVesting(caller) + getClaimable(caller);
+       toMint = (toMint * 100 * Constants.PINT) / (100 - lastSlashRate[caller]);
+       toMint /= Constants.PINT;
if (toMint > 0) {
esMeta.mint(caller, toMint);
unstakeRate[caller] = 0;
time2

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### Example 19: M-1: BalancerPairOracle#getPrice will revert due to division by zero in some cases

**Source**: Sherlock
**Protocol**: Blueberry Update #2
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-05-blueberry-judging/issues/25 

## Found by 
0x52, nobody2018
## Summary

`BalancerPairOracle#getPrice` internally calls `computeFairReserves`, which returns fair reserve amounts given spot reserves, weights, and fair prices. When the parameter `resA` passed to `computeFairReserves` is smaller than `resB`, division by 0 will occur.

## Vulnerability Detail

In `BalancerPairOracle#getPrice`, resA and resB passed to `computeFairReserves` are the balance of TokenA and TokenB of the pool respectively. It is common for the balance of TokenB to be greater than the balance of TokenA.

```solidity
function computeFairReserves(
        uint256 resA,
        uint256 resB,
        uint256 wA,
        uint256 wB,
        uint256 pxA,
        uint256 pxB
    ) internal pure returns (uint256 fairResA, uint256 fairResB) {
    	...
    	//@audit r0 = 0 when resA < resB.
->      uint256 r0 = resA / resB;
        uint256 r1 = (wA * pxB) / (wB * pxA);
        // fairResA = resA * (r1 / r0) ^ wB
        // fairResB = resB * (r0 / r1) ^ wA
        if (r0 > r1) {
            uint256 ratio = r1 / r0;
            fairResA = resA * (ratio ** wB);
            fairResB = resB / (ratio ** wA);
        } else {
->          uint256 ratio = r0 / r1;		// radio = 0 when r0 = 0
->          fairResA = resA / (ratio ** wB);   	// revert divided by 0
            fairResB = resB * (ratio ** wA);
        }
    }
```

Another case is **when the decimals of tokenA is s

*[Content truncated...]*

---

### Example 20: H-1: AuraSpell#openPositionFarm fails to return all rewards to user

**Source**: Sherlock
**Protocol**: Blueberry Update #2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-blueberry-judging/issues/29 

## Found by 
0x52, nobody2018
## Summary

When a user adds to an existing position on AuraSpell, the contract burns their current position and remints them a new one. The issues is that WAuraPool will send all reward tokens to the contract but it only sends Aura back to the user, causing all other rewards to be lost.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L256-L261

        for (uint i = 0; i < rewardTokens.length; i++) {
            IERC20Upgradeable(rewardTokens[i]).safeTransfer(
                msg.sender,
                rewards[i]
            );
        }

Inside WAuraPools#burn reward tokens are sent to the user.

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L130-L140

        IBank.Position memory pos = bank.getCurrentPositionInfo();
        if (pos.collateralSize > 0) {
            (uint256 pid, ) = wAuraPools.decodeId(pos.collId);
            if (param.farmingPoolId != pid)
                revert Errors.INCORRECT_PID(param.farmingPoolId);
            if (pos.collToken != address(wAuraPools))
                revert Errors.INCORRECT_COLTOKEN(pos.collToken);
            bank.takeCollateral(pos.collateralSize);
            wAuraPools.burn(pos.collId, pos.collateralSize);
            _doRefundRewards(AURA);
        }

We see above that t

*[Content truncated...]*

---

### Example 21: M-6: Target raises can be highly damaging for dutch auctions with multiple components

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/45 

## Found by 
0x52
## Summary

Multi-component dutch auctions are fundamentally incompatible with target raises and will lead to inefficient pricing causing loss to set token.

## Vulnerability Detail

The AuctionRebalanceModuleV1 allows targets to be increased when all component targets have been met and there is still excess quote token. When combined with multiple components, it his highly likely that these target raises will lead to inefficient pricing which will cause loss to the set token.

Consider the following a set token has the following composition that has target raises enabled:

40% USDC
30% WBTC
30% WETH

The manager wishes to rebalance the set to the following using USDC as the quote token:

20% USDC
40% WBTC
40% WETH

Assume the WETH portion of the execute within the first hour of the auction. The WBTC on the other hand doesn't execute until 12 hours in. Assume there is excess quote so the target is increased. The issue is that now because of the change in time, the WETH auction is now well above the market price. This buys the WETH for a large loss compared to the market price of WETH.

## Impact

Pricing after target raises will likely be heavily skewed from market prices for some components lead to set token losses

## Code Snippet

[AuctionRebalanceModuleV1.sol#L359-L380](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-protocol/contracts/protocol/modules/v1/AuctionR

*[Content truncated...]*

---

### Example 22: M-1: SetToken can't be unlocked early.

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/38 

## Found by 
0x52, Yuki, auditsea, qandisa
## Summary
SetToken can't be unlocked early

## Vulnerability Detail
The function unlock() is used to unlock the setToken after rebalancing, as how it is right now there are two ways to unlock the setToken.

- can be unlocked once the rebalance duration has elapsed
- can be unlocked early if all targets are met, there is excess or at-target quote asset, and raiseTargetPercentage is zero
```solidity
    function unlock(ISetToken _setToken) external {
        bool isRebalanceDurationElapsed = _isRebalanceDurationElapsed(_setToken);
        bool canUnlockEarly = _canUnlockEarly(_setToken);

        // Ensure that either the rebalance duration has elapsed or the conditions for early unlock are met
        require(isRebalanceDurationElapsed || canUnlockEarly, "Cannot unlock early unless all targets are met and raiseTargetPercentage is zero");

        // If unlocking early, update the state
        if (canUnlockEarly) {
            delete rebalanceInfo[_setToken].rebalanceDuration;
            emit LockedRebalanceEndedEarly(_setToken);
        }

        // Unlock the SetToken
        _setToken.unlock();
    }
```
```solidity
    function _canUnlockEarly(ISetToken _setToken) internal view returns (bool) {
        RebalanceInfo storage rebalance = rebalanceInfo[_setToken];
        return _allTargetsMet(_setToken) && _isQuoteAssetExcessOrAtTarget(_setToken) && rebal

*[Content truncated...]*

---

### Example 23: M-4: Loss of option token from Teller and reward from OTLM if L2 sequencer goes down

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/82 

## Found by 
ctf\_sec, qandisa
## Summary

Loss of option token from Teller and reward from OTLM if L2 sequencer goes down

## Vulnerability Detail

In the current implementation, if the option token expires, the user is not able to [exerise the option at strike price](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L336)

```solidity
    // Validate that option token is not expired
        if (uint48(block.timestamp) >= expiry) revert Teller_OptionExpired(expiry);
```

if the option token expires, the user lose rewards from OTLM as well when [claim the reward](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/liquidity-mining/OTLM.sol#L496)

```solidity
    function _claimRewards() internal returns (uint256) {
        // Claims all outstanding rewards for the user across epochs
        // If there are unclaimed rewards from epochs where the option token has expired, the rewards are lost

        // Get the last epoch claimed by the user
        uint48 userLastEpoch = lastEpochClaimed[msg.sender];

```

and

```solidity
    // If the option token has expired, then the rewards are zero
        if (uint256(optionToken.expiry()) < block.timestamp) return 0;
```

And in the onchain context, the protocol intends to deploy the contract in arbitr

*[Content truncated...]*

---

### Example 24: M-2: Escrow record not cleared on cancellation and order fill

**Source**: Sherlock
**Protocol**: Dinari
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-dinari-judging/issues/56 

## Found by 
Delvir0, bin2chen, bitsurfer, chainNue, ctf\_sec, dirk\_y, hals, volodya
## Summary
In `DirectBuyIssuer.sol`, a market buy requires the operator to take the payment token as escrow prior to filling the order. Checks are in place so that the math works out in terms of how much escrow has been taken vs the order's remaining fill amount. However, if the user cancels the order or fill the order, the escrow record is not cleared. 

The escrow record will exists as a positive amount which can lead to accounting issues.

## Vulnerability Detail
Take the following example:

- Operator broadcasts a `takeEscrow()` transaction around the same time that the user calls `requestCancel()` for the order
- Operator also broadcasts a `cancelOrder()` transaction
- If the `cancelOrder()` transaction is mined before the `takeEscrow()` transaction, then the contract will transfer out token when it should not be able to.

`takeEscrow()` simply checks that the `getOrderEscrow[orderId]` is less than or equal to the requested amount:
```solidity
        bytes32 orderId = getOrderIdFromOrderRequest(orderRequest, salt);
        uint256 escrow = getOrderEscrow[orderId];
        if (amount > escrow) revert AmountTooLarge();


        // Update escrow tracking
        getOrderEscrow[orderId] = escrow - amount;
        // Notify escrow taken
        emit EscrowTaken(orderId, orderRequest.recipient, amount);


        /

*[Content truncated...]*

---

### Example 25: M-1: In case of stock split and reverse split, the Dshare token holder will gain or loss his Dshare token value

**Source**: Sherlock
**Protocol**: Dinari
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-dinari-judging/issues/29 

## Found by 
ast3ros
## Summary

Stock split and reverse split may cause the token accounting to be inaccurate.

## Vulnerability Detail

Stock split and reverse split are very common in the stock market. There are many examples here: https://companiesmarketcap.com/amazon/stock-splits/

For instance, in a 2-for-1 stock split, a shareholder receives an additional share for each share held. However, the DShare token holder still holds only one DShare token after the split. If a DShare token holder owns 100 DShare tokens before the split, he will still own 100 DShare tokens after the split. However, he should own 200 DShare tokens after the split.

Currently, users can buy 1 DShare token at the current market price of the underlying share. https://sbt.dinari.com/tokens

This means that after the stock split, a new Dshare token holder can buy a Dshare at half the price of the previous Dshare token holder. This is unfair to the previous Dshare token holder. In other words, the original Dshare token holder will lose 50% of his Dshare token value after the stock split.

The same logic applies to stock reverse split.

## Impact

The Dshare token holder will gain or loss his Dshare token value after the stock split or reverse split.

## Code Snippet

https://github.com/sherlock-audit/2023-06-dinari/blob/50eb49260ab54e02748c2f6382fd95284d271f06/sbt-contracts/src/BridgedERC20.sol#L13

## Tool used

Manual Revie

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 33
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
