---
id: SEV-HIGH-SEVERITY
title: High Severity Findings
category: severity
severity_level: high
last_updated: 2026-01-31
---
# HIGH Severity Findings

## Overview

**Total Findings**: 8,022 (15.88% of all findings)

## Top Vulnerability Types at HIGH Severity

| Rank | Vulnerability Type | Count |
|------|-------------------|-------|
| 1 | Business Logic | 100 |
| 2 | Wrong Math | 67 |
| 3 | Validation | 52 |
| 4 | Reentrancy | 39 |
| 5 | Front-Running | 39 |
| 6 | Access Control | 27 |
| 7 | Don't update state | 26 |
| 8 | Liquidation | 25 |
| 9 | Oracle | 24 |
| 10 | DOS | 23 |
| 11 | Overflow/Underflow | 21 |
| 12 | Slippage | 21 |
| 13 | Decimals | 21 |
| 14 | First Depositor Issue | 20 |
| 15 | Rounding | 17 |
| 16 | Flash Loan | 16 |
| 17 | ERC1155 | 15 |
| 18 | Missing-Logic | 14 |
| 19 | Vote | 14 |
| 20 | Configuration | 13 |

---

## Representative Examples

### 1. [H-01] Chained signature with checkpoint usage disabled can bypass all checkpointer validation

- **Source**: Code4rena
- **Protocol**: Sequence
- **Tags**: None

<https://github.com/code-423n4/2025-10-sequence/blob/b0e5fb15bf6735ec9aaba02f5eca28a7882d815d/src/modules/auth/BaseSig.sol# L88>

### Finding description and impact

Consider a scenario where (1) the wallet is behind the checkpointer and (2) a chained signature is used; however, bit 6 (`0x40` - the checkpointer usage flag) is zero. As a result, when `BaseSig.recover` is called the below if-block on `BaseSig.sol:88-106` will be skipped:
```

    if (signatureFlag & 0x40 == 0x40 && _checkpointer == address(0)) {
      // Override the checkpointer
      // not ideal, but we don't have much room in the stack
      (_checkpointer, rindex) = _signature.readAddress(rindex);

if (!_ignoreCheckpointer) {
        // Next 3 bytes determine the checkpointer data size
        uint256 checkpointerDataSi...

[View Full Finding](https://code4rena.com/reports/2025-10-sequence)

---

### 2. `redeemNative()` Reentrancy Enables Permanent Fund Freeze, Systemic Misaccounting, and Liquidation Cascades

- **Source**: MixBytes
- **Protocol**: Notional Finance
- **Tags**: None

##### Description
The redemption flow in `AbstractYieldStrategy.redeemNative()` is vulnerable to reentrancy that corrupts internal accounting and can permanently freeze a portion of the vault's yield tokens. The `redeemNative()` function calls `AbstractStakingStrategy._redeemShares()`, which for instant redemption delegates to `AbstractYieldStrategy._executeTrade()` and performs an external call during redemption. Not all vault and router entry points are protected against reentrancy, which allows control to reenter from the lending router while `_burnShares()` is still executing. A malicious token placed on the swap path can exploit this by reentering and invoking `ILendingRouter.initiateWithdraw()` during the redemption.

When reentrancy occurs, the request manager transfers an amount N ...

[View Full Finding](https://github.com/mixbytes/audits_public/blob/master/Notional%20Finance/Notional%20v4/README.md#1-redeemnative-reentrancy-enables-permanent-fund-freeze-systemic-misaccounting-and-liquidation-cascades)

---

### 3. [C-01] Withdrawal Calculation Causes Underflow, Locking All User Funds

- **Source**: Shieldify
- **Protocol**: Terplayer Bvt Staking&Distribution
- **Tags**: Overflow/Underflow

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
      uint256 deleg...

[View Full Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/Terplayer-BVT-Staking&Distribution-Security-Review.md)

---

### 4. [H-01] Incorrect vesting interest calculation enables MEV attacks

- **Source**: Pashov Audit Group
- **Protocol**: LoopVaults_2025-04-30
- **Tags**: None

## Severity

**Impact:** Medium

**Likelihood:** High

## Description

Given that the value of the positions is updated only when `updateInterval` time has passed, the interest is vested to prevent MEV attacks.

However, the implementation of `_vestingInterest()` is incorrect, as it returns 0 when `block.timestamp == lastUpdate` and increases linearly until `vestingDuration` is reached. This means that calling `totalAssets()` just after an update will include all the interest accrued, which makes the update subject to MEV attacks.

```solidity
    function totalAssets() public view override returns (uint256) {
        return lastTotalAssets - _vestingInterest();
    }

    function _vestingInterest() internal view returns (uint256) {
        if (block.timestamp - lastUpdate >= vestingDurat...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/LoopVaults-security-review_2025-04-30.md)

---

### 5. [H-01] Incorrect basket USD value will cause incorrect results

- **Source**: Pashov Audit Group
- **Protocol**: Cove_2024-12-30
- **Tags**: None

## Severity

**Impact:** Medium

**Likelihood:** High

## Description

Upon proposing a token swap, we have the following sequence of function calls:

```solidity
uint256[] memory totalValues = new uint256[](numBaskets);
// 2d array of asset balances for each basket
uint256[][] memory basketBalances = new uint256[][](numBaskets);
_initializeBasketData(self, baskets, basketAssets, basketBalances, totalValues);
// NOTE: for rebalance retries the internal trades must be updated as well
_processInternalTrades(self, internalTrades, baskets, basketBalances);
_validateExternalTrades(self, externalTrades, baskets, totalValues, basketBalances);
if (!_isTargetWeightMet(self, baskets, basketTargetWeights, basketAssets, basketBalances, totalValues)) {
         revert TargetWeightsNotMet();
}
```

The ...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/Cove-security-review_2024-12-30.md)

---

### 6. [H-03] `ExecuteRequest`s are not properly removed from the context queue

- **Source**: Code4rena
- **Protocol**: Initia
- **Tags**: None

The `minievm` cosmos precompile allows a Solidity contract to dispatch a Cosmos SDK message, which is executed after the EVM call is successfully executed.

This is done by calling the cosmos precompile with the `execute_cosmos` or `execute_cosmos_with_options` function selector and passing the encoded message. This will wrap the message with `ExecuteRequest` and append it to the messages slice in the context with the key `types.CONTEXT_KEY_EXECUTE_REQUESTS`.

[`minievm:x/evm/precompiles/cosmos/contract.go# L287-L294`](https://github.com/initia-labs/minievm/blob/744563dc6a642f054b4543db008df22664e4c125/x/evm/precompiles/cosmos/contract.go# L287-L294)
```

287: messages := ctx.Value(types.CONTEXT_KEY_EXECUTE_REQUESTS).(*[]types.ExecuteRequest)
288: *messages = append(*messages, types.Execut...

[View Full Finding](https://code4rena.com/reports/2025-02-initia-cosmos)

---

### 7. [H-03] User can bypass `MAX_EXPIRATION` when extend expiration

- **Source**: Code4rena
- **Protocol**: Initia
- **Tags**: Auction

<https://github.com/code-423n4/2025-01-initia-move/blob/a96f5136c4808f6968564a4592fe2d6ac243a233/usernames-module/sources/name_service.move# L483>

### Finding Description and Impact

In the `extend_expiration` function, the validation for the duration is incorrect, allowing the user to bypass `MAX_EXPIRATION`:
```

 let expiration_date = metadata::get_expiration_date(token);
        let new_expiration_date = if (expiration_date > timestamp) {
            expiration_date + duration
        } else {
            timestamp + duration
        };

        assert!(
=>            new_expiration_date - expiration_date <= MAX_EXPIRATION,
            error::invalid_argument(EMIN_DURATION),
        );

        metadata::update_expiration_date(token, new_expiration_date);
```

The issue arises because...

[View Full Finding](https://code4rena.com/reports/2025-01-initia-move)

---

### 8. [C-03] Unrestricted `diamondCut` allows unauthorized facet modifications

- **Source**: Pashov Audit Group
- **Protocol**: Burve_2025-01-29
- **Tags**: None

## Severity

**Impact:** High

**Likelihood:** High

## Description

## Description

The `SimplexDiamond` contract includes `DiamondCutFacet.diamondCut.selector` in its selectors. This function allows adding, removing, or modifying facet cuts, which determine the contracts functionality. However, **this function is not restricted**, meaning **anyone** can call it to remove or replace any selector or facet.

### **Proof of Concept (PoC)**

The test case below demonstrates how a random user can call `diamondCut` to remove or modify contract functionality, potentially leading to loss of control over the contract.

```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.17;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {BurveDe...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/Burve-security-review_2025-01-29.md)

---

### 9. [H-03] Unstake Causes All Users to Lose Their Rewards

- **Source**: Shieldify
- **Protocol**: Surge
- **Tags**: None

## Severity

High Risk

## Description

The `StakingVault.unstake()` function should reduce the total amount of shares in the current cycle by the shares that get unstaked by the user. Instead, the total amount of shares from all stakes gets deleted.

## Location of Affected Code

File: [StakingVault.sol]()

```solidity
function _unstake(address user) internal returns (StakeInfo memory) {
    // code

    // Decrese total shares and close claimable rewards for every pool
    for (uint256 i; i < REWARD_POOL_COUNT; i++) {
        uint256 poolId = _rewardPools[i].id;
        uint256 cycleId = _rewardPools[i].currentCycleId;

        ClaimableReward storage r = _userRewardPoolClaimableReward[user][poolId];
        require(r.cycleStart != 0, "No claimable reward"); // This should never happen
 ...

[View Full Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/Surge-Security-Review.md)

---

### 10. [H-02] Stale `totalActiveDebt` used in `openTrove` causing incorrect debt update

- **Source**: Pashov Audit Group
- **Protocol**: Roots_2025-02-09
- **Tags**: None

## Severity

**Impact:** Medium

**Likelihood:** High

## Description

In the `TroveManager::openTrove` function, the `totalActiveDebt` is cached into a local variable `supply` before the `_accrueActiveInterests` function is called. The `_accrueActiveInterests` function itself updates the `totalActiveDebt` to reflect accrued interest. However, the `openTrove` function subsequently updates `totalActiveDebt` using the cached `supply` value instead of the potentially updated `totalActiveDebt`.

Specifically, the code caches `totalActiveDebt` in line 754:

```solidity
File: TroveManager.sol
754:    uint256 supply = totalActiveDebt;
```

Then, interest is accrued, potentially updating `totalActiveDebt` in line 761 by calling `_accrueActiveInterests()`:

```solidity
File: TroveManager.sol
761:  ...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/Roots-security-review_2025-02-09.md)

---

### 11. [H-01] `_swap()` is vulnerable to sandwich attacks

- **Source**: Pashov Audit Group
- **Protocol**: Gacha_2025-01-27
- **Tags**: Sandwich Attack

## Severity

**Impact:** High

**Likelihood:** High

## Description

Anyone can buy a ticket from a specified pool, a certain payment token will be used to swap for meme tokens. The swapping process is implemented as below:

```solidity
    function _swap(
        address token,
        uint256 cost
    ) private returns (uint256 actualTokens) {
        Storage storage $ = _getOwnStorage();
        IUniswapV2Router01 uni = IUniswapV2Router01($.uniswapRouter);
        IUniswapV2Factory factory = IUniswapV2Factory($.uniswapFactory);

        address pair = factory.getPair($.paymentToken, token);
        (uint256 wethReserve, uint256 tokenReserve, ) = IUniswapV2Pair(pair)
            .getReserves();
        if (wethReserve == 0 || tokenReserve == 0) revert InvalidPair();

@>      uint256 maxT...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/Gacha-security-review_2025-01-27.md)

---

### 12. [H-02] The flashloan protection for Zappers is insufficient - We can operate on Troves we don't own

- **Source**: Recon Audits
- **Protocol**: Bold Report
- **Tags**: None

**Impact**
The code for the Balancer Vault Flashloan is as follows:

https://etherscan.io/address/0xba12222222228d8ba445958a75a0704d566bf2c8#code

```solidity
   function flashLoan(
        IFlashLoanRecipient recipient,
        IERC20[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external override nonReentrant whenNotPaused {
        InputHelpers.ensureInputLengthMatch(tokens.length, amounts.length);

        uint256[] memory feeAmounts = new uint256[](tokens.length);
        uint256[] memory preLoanBalances = new uint256[](tokens.length);

        // Used to ensure `tokens` is sorted in ascending order, which ensures token uniqueness.
        IERC20 previousToken = IERC20(0);

        for (uint256 i = 0; i < tokens.length; ++i) {
            IERC2...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Recon Audits/2025-03-23-bold-report.md)

---

### 13. Incorrect opcode offset used for Branch Less instruction 

- **Source**: Cantina
- **Protocol**: OpenVM
- **Tags**: None

## Issue Description

## Context
(No context files were provided by the reviewer)

## Description
The `Rv32BranchLessThan256Chip` uses the wrong opcode offset when creating its internal `BranchLessThanCoreChip`. It uses `Rv32LessThan256Opcode::CLASS_OFFSET` instead of `Rv32BranchLessThan256Opcode::CLASS_OFFSET`. This will cause the branch less than instruction to be decoded and executed incorrectly. This affects all 256-bit branch-less-than operations (`BLT`, `BGE`, `BLTU`, `BGEU`), leading to incorrect branch condition evaluation.

## Proof of Concept
This part of the code from the `Int256::build` method shows the issue:

```rust
 extension.rs#L184-L196:
184: let branch_less_than_chip = Rv32BranchLessThan256Chip::new(
185:     Rv32HeapBranchAdapterChip::new(
186:         execution_bus,
1...

[View Full Finding](https://cdn.cantina.xyz/reports/cantina_competition_openvm_january2025.pdf)

---

### 14. Missing constraints in LOADWand STOREW 

- **Source**: Cantina
- **Protocol**: OpenVM
- **Tags**: None

## Context
(No context files were provided by the reviewer)

## Summary
In the recursion VM, the LOADW and STOREW instructions are missing constraints to link the read value to the written value. As a result, a malicious prover can write any value.

## Finding Description
The `NativeLoadStoreCoreAir::eval` function does not constrain anything except the values of the instruction flags given the opcode. In particular, there is no constraint between `cols.data_read` and `cols.data_write`. Also, the `NativeLoadStoreAdapterAir` does not enforce any constraint between `ctx.reads.1` and `ctx.writes`.

## Impact Explanation
This lets a malicious prover write any value for any LOADW or STOREW instructions during the execution of the recursive verifier. This breaks soundness of the recursion VM.

#...

[View Full Finding](https://cdn.cantina.xyz/reports/cantina_competition_openvm_january2025.pdf)

---

### 15. Users can gain tokens during round-trip swaps

- **Source**: TrailOfBits
- **Protocol**: Bunni v2
- **Tags**: None

## Diculty: Low

## Type: Data Validation

### Description

The swap functionality of the BunniSwapMath library is not accurately implemented, allowing users to gain tokens during round-trip swaps (i.e., swapping token0 for token1 and then swapping the same amount of token1 for token0).

The `computeSwap` function in the BunniSwapMath library allows users to swap tokens on a valid pool state. Given an `amountSpecified` and the swap direction, the function calculates the input tokens exchanged for the output tokens. In a zeroForOne swap, the user exchanges token0 for token1, and the pool state is updated to reflect the new token balances and price ratio, as shown in figure 16.1.

```solidity
function computeSwap(BunniComputeSwapInput calldata input,
    uint256 balance0, uint256 balance1)
...

[View Full Finding](https://github.com/trailofbits/publications/blob/master/reviews/2025-01-bacon-labs-bunniv2-securityreview.pdf)

---

### 16. Users can gain free tokens through the BunniSwap swap functionality

- **Source**: TrailOfBits
- **Protocol**: Bunni v2
- **Tags**: None

## Diculty: Low

## Type: Data Validation

## Description
During token swaps, users can receive a nonzero amount of output tokens even when they provide zero input tokens, allowing them to acquire free tokens without contributing any input tokens for the swap.

The `computeSwap` function in the BunniSwapMath library executes swap operations based on a user-specified token amount specified as one of the inputs to the function. As shown in figure 15.1, depending on whether the `amountSpecified` is negative or positive, the swap is configured to be an ExactIn or ExactOut swap.

```solidity
// initialize input and output amounts based on initial info
bool exactIn = amountSpecified < 0;
inputAmount = exactIn ? uint256(-amountSpecified) : 0;
outputAmount = exactIn ? 0 : uint256(amountSpecified)...

[View Full Finding](https://github.com/trailofbits/publications/blob/master/reviews/2025-01-bacon-labs-bunniv2-securityreview.pdf)

---

### 17. [H-03] `activeValidatorCount` is never set or increased

- **Source**: Pashov Audit Group
- **Protocol**: Karak-June
- **Tags**: None

## Severity

**Impact:** Medium

**Likelihood:** High

## Description

In the `NativeVault` contract `Storage.ownerToNode[nodeOwner].activeValidatorCount` keeps track of the total validators with withdrawal credentials pointed to a specific node.

This value is decreased in `NativeVaultLib.validateSnapshotProof` when the balance of a validator in the Beacon Chain is zero.

```solidity
File: NativeVaultLib.sol

        if (newBalanceWei == 0) {
@>          self.ownerToNode[nodeOwner].activeValidatorCount--;
            validatorDetails.status = ValidatorStatus.WITHDRAWN;

            emit ValidatorWithdrawn(nodeOwner, nodeAddress, timestamp, validatorIndex);
        }
```

The value is used in `_startSnapshot` to set the `remainingProofs` field of the `Snapshot` struct.

```solidity
File: N...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/Karak-security-review-June.md)

---

### 18. [C-01] Decreasing position size via leverage update can be abused to steal from diamond

- **Source**: Pashov Audit Group
- **Protocol**: Gainsnetwork May
- **Tags**: None

**Severity**

**Impact:** High

**Likelihood:** High

**Description**

The trader can decrease position size using leverage update, which will then realize the partial profit/loss based on position size delta.

However, in the case of a profit, `handleTradePnl()` will incorrectly send the closing fees to the trader instead of the vault. This allows the trader to receive more profit than expected by stealing from the diamond. Over time, this will slowly drain the diamond as the closing fees are still distributed despite not receiving it.

Suppose the trader has the following position,

- existing leverage = 10
- existing collateral = 100 DAI
- existing position size = 1000 DAI
- existing profit of 500 DAI

And the trader reduces position size by leverage delta,

- delta leverage = 5
- delta...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/GainsNetwork-security-review-May.md)

---

### 19. [H-01] Invalid `DISPUTED_L2_BLOCK_NUMBER` is passed to VM

- **Source**: Code4rena
- **Protocol**: Optimism
- **Tags**: None

The span of the game tree at split depth is far larger than the length between the starting block and the claimed block. When `starting block + trace index + 1 > claimed block`, honest party should continue to commit to the root of the claimed block. However, the `DISPUTED_L2_BLOCK_NUMBER` passed to the VM is always `starting block + trace index + 1`, which means the op-program (at inter-block perspective) will not stop until it reaches the l2 safe head (corresponding to parenthash), and if the claimed block is earlier than the safe head, it can be challenged and will be considered invalid.

### Proof of Concept

Since op-program is out of scope of this audit, this report will not spend too much time in proving *block earlier than safe head can be challenged*, instead it will only show the...

[View Full Finding](https://code4rena.com/reports/2024-07-optimism)

---

### 20. [H-01] Most users won't be able to claim their share of Uniswap fees

- **Source**: Code4rena
- **Protocol**: Vultisig
- **Tags**: None

Users should be able to claim Uniswap fees for their current liquidity position regardless of their pending vestings, or cliff. But most users won't be able to claim those Uniswap fees.

It is also possible that they won't be able to claim their vesting if they accumulate sufficient unclaimed Uniswap fees.

### Vulnerability Details

The root issue is that the `claim()` function collects ALL the owed tokens at once, including the ones from the burnt liquidity, but also the fees corresponding to ALL positions:

```solidity
    (uint128 amountCollected0, uint128 amountCollected1) = pool.collect(
        address(this),
        TICK_LOWER,
        TICK_UPPER,
@>      type(uint128).max,
@>      type(uint128).max
    );
```

<https://github.com/code-423n4/2024-06-vultisig/blob/main/src/ILOPool.s...

[View Full Finding](https://code4rena.com/reports/2024-06-vultisig)

---

### 21. [H-02] Division before multiplication could lead to users losing 50% in `WithdrawalQueue`

- **Source**: Code4rena
- **Protocol**: Gondi
- **Tags**: None

In the `_getAvailable()` function, the calculation performs division before multiplication, which could result in precision loss. The consequence is that users may not be able to withdraw the amount they should receive, leaving some funds locked in the `WithdrawalQueue`.

```solidity
// @audit division before multiplication
function _getAvailable(uint256 _tokenId) private view returns (uint256) {
    return getShares[_tokenId] * _getWithdrawablePerShare() - getWithdrawn[_tokenId]; 
}

/// @notice Get the amount that can be withdrawn per share.
function _getWithdrawablePerShare() private view returns (uint256) {
    return (_totalWithdrawn + _asset.balanceOf(address(this))) / getTotalShares;
}
```

### Proof of Concept

Consider the following scenario:

```solidity
getShares[_tokenId] = 1e8...

[View Full Finding](https://code4rena.com/reports/2024-04-gondi)

---

### 22. [H-04] Since you can reroll with a different fighterType than the NFT you own, you can reroll bypassing maxRerollsAllowed and reroll attributes based on a different fighterType

- **Source**: Code4rena
- **Protocol**: AI Arena
- **Tags**: None

Can reroll attributes based on a different fighterType, and can bypass maxRerollsAllowed.

### Proof of Concept

`maxRerollsAllowed` can be set differently depending on the `fighterType`. Precisely, it increases as the generation of fighterType increases.

```solidity
function incrementGeneration(uint8 fighterType) external returns (uint8) {
    require(msg.sender == _ownerAddress);
@>  generation[fighterType] += 1;
@>  maxRerollsAllowed[fighterType] += 1;
    return generation[fighterType];
}
```

The `reRoll` function does not verify if the `fighterType` given as a parameter is actually the `fighterType` of the given tokenId. Therefore, it can use either 0 or 1 regardless of the actual type of the NFT.

This allows bypassing `maxRerollsAllowed` for additional reRoll, and to call `_create...

[View Full Finding](https://code4rena.com/reports/2024-02-ai-arena)

---

### 23. [H-01] The 51% majority can hijack the party's precious tokens through an arbitrary call proposal if the `AddPartyCardsAuthority` contract is added as an authority in the party.

- **Source**: Code4rena
- **Protocol**: Party Protocol
- **Tags**: 51% Attack

### Pre-requisite knowledge & an overview of the features in question

1. **The [**`AddPartyCardsAuthority`**](https://github.com/code-423n4/2023-10-party/blob/main/contracts/authorities/AddPartyCardsAuthority.sol) contract:** The `AddPartyCardsAuthority` contract is a contract designed to be integrated into a Party and it has only one purpose - to mint new party governance NFT tokens for party members.
    - The party has to add this contract as an authority before it can start minting new party governance NFT tokens for users.
    - The `AddPartyCardsAuthority` contract is deployed on the mainnet on address `0xC534bb3640A66fAF5EAE8699FeCE511e1c331cAD`

2. **The 51% Majority attack:** The PartyDAO team has put a lot of safeguards on a type of proposal called `ArbitraryCallsProposal` to pr...

[View Full Finding](https://code4rena.com/reports/2023-10-party)

---

### 24. Incorrect upper bound check in wExp(x) can produce an overowed result 

- **Source**: Cantina
- **Protocol**: Morpho
- **Tags**: None

## Context: MathLib.sol#L26

## Description
Upper-bound used in `wExp(x)` is not restrict enough:

```solidity
// Revert if x > ln(2^256-1) ~ 177.
require(x <= 177.44567822334599921 ether, ErrorsLib.WEXP_OVERFLOW);
```

As this function accepts `x` in the 18 decimal format and is supposed to return an 18 decimal number, the upper bound should be calculated similarly to Remco's `FixedPointMathLib`:

\[
10^{18} e^{x + \epsilon} \leq 10^{18} e^{x + \epsilon} 10^{18} \leq 2^{256} - 1
\]

So:

\[
x \leq \frac{10^{18} \ln(2^{256} - 1)}{10^{18}} - \epsilon
\]

Here \(\epsilon = \text{LN2\_INT}\).

And so the upper bound would be approximately:

\[
135.305999368893231588 \text{ ether}:
\]

\[
135.305999368893231588 \cdot 10^{18} = \frac{10^{18} \ln(2^{256} - 1)}{10^{18}} - 10^{18} \ln(2)
\]

This ...

[View Full Finding](https://cdn.cantina.xyz/reports/cantina_morpho_blue_irm_oct2023.pdf)

---

### 25. `Boost.setLockStatus()` should update the caller's rewards first.

- **Source**: Hans
- **Protocol**: Meta
- **Tags**: None

**Severity:** High

**Context:** [`Boost.sol#L35-50`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/reward/Boost.sol#L35-50)

**Description:**
In the rewards contracts(`StakeRewards.sol`, `MintRewards.sol`), the staking rewards are multiplied by the boost factor when the users lock their funds.

And users can extend their lock duration using `setLockStatus()` at any time.

But the rewards before the locking time will be boosted also and the user would claim more rewards.

- At day 0, one user stakes funds using `StakeRewards.stake()`.
- At day 90, he still has the staking funds/rewards and he calls `setLockStatus()` to lock his funds for 30 days.
- At day 120, he can withdraw his staking funds as well as the boosted rewards for 120 days. It'...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### 26. [H-16] Attacker can block LayerZero channel due to variable gas cost of saving payload

- **Source**: Code4rena
- **Protocol**: Tapioca DAO
- **Tags**: None

<https://github.com/Tapioca-DAO/tapioca-bar-audit/blob/master/contracts/usd0/BaseUSDO.sol#L399> 

<https://github.com/Tapioca-DAO/tapiocaz-audit/blob/master/contracts/tOFT/BaseTOFT.sol#L442> 

<https://github.com/Tapioca-DAO/tap-token-audit/blob/main/contracts/tokens/BaseTapOFT.sol#L52>

This is an issue that affects `BaseUSDO`, `BaseTOFT`, and `BaseTapOFT` or all the contracts which are sending and receiving LayerZero messages.
The consequence of this is that anyone can with low cost and high frequency keep on blocking the pathway between any two chains, making the whole system unusable.

### Proof of Concept

I will illustrate the concept of blocking the pathway on the example of sending a message through `BaseTOFTs` [`sendToYAndBorrow`](https://github.com/Tapioca-DAO/tapiocaz-audit/blo...

[View Full Finding](https://code4rena.com/reports/2023-07-tapioca)

---

### 27. Protocol fees are double-counted as registry balance and pool reserve

- **Source**: Spearbit
- **Protocol**: Primitive
- **Tags**: None

## Severity: Critical Risk

## Context
Portfolio.sol#L489-L507

## Description
When swapping, the registry is credited a `protocolFee`. However, this fee is always reinvested in the pool, meaning the `virtualX` or `virtualY` pool reserves per liquidity increase by `protocolFee / liquidity`. The protocol fee is now double-counted as the registrys user balance and the pool reserve, while the global reserves are only increased by the protocol fee once in `_increaseReserves(_state.tokenInput, iteration.input)`. A protocol fee breaks the invariant that the global reserve should be greater than the sum of user balances and fees plus the sum of pool reserves.

As the protocol fee is reinvested, LPs can withdraw them. If users and LPs decide to withdraw all their balances, the registry cant with...

[View Full Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Primitive-Spearbit-Security-Review.pdf)

---

### 28. Read-only reentrancy

- **Source**: Cyfrin
- **Protocol**: Beanstalk Wells
- **Tags**: Read-only Reentrancy

**Description:** The current implementation is vulnerable to read-only reentrancy, especially in [Wells::removeLiquidity](https://github.com/BeanstalkFarms/Wells/blob/e5441fc78f0fd4b77a898812d0fd22cb43a0af55/src/Well.sol#L440).
The implementation does not strictly follow the [Checks-Effects-Interactions (CEI) pattern](https://fravoll.github.io/solidity-patterns/checks_effects_interactions.html) as it is setting the new reserve values after sending out the tokens. This is not an immediate risk to the protocol itself due to the `nonReentrant` modifier, but this is still vulnerable to [read-only reentrancy](https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/).

Malicious attackers and unsuspecting ecosystem participants can deploy Wells with ERC-777 tokens (which have a callba...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-06-16-Beanstalk wells.md)

---

### 29. Overpayment of one side of LP Pair onJoinPool due to sandwich or user error

- **Source**: Spearbit
- **Protocol**: Cron Finance
- **Tags**: Slippage

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
import { C } from "../...

[View Full Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/CronFinance-Spearbit-Security-Review.pdf)

---

### 30. [H-01] The call to `MsgValueSimulator` with non zero `msg.value` will call to sender itself which will bypass the `onlySelf` check

- **Source**: Code4rena
- **Protocol**: zkSync
- **Tags**: None

First, I need to clarify, there may be more serious ways to exploit this issue. Due to the lack of time and documents, I cannot complete further exploit. The current exploit has only achieved the impact in the title. I will expand the possibility of further exploit in the poc chapter.

The call to MsgValueSimulator with non zero msg.value will call to sender itself with the msg.data. It means that if you can make a contract or a custom account call to specified address with non zero msg.value (that's very common in withdrawal functions and smart contract wallets), you can make the contract/account call itself. And if you can also control the calldata, you can make the contract/account call its functions by itself.

It will bypass some security check with the msg.sender, or break the accoun...

[View Full Finding](https://code4rena.com/reports/2023-03-zksync)

---


## Statistics

- Total HIGH findings: 8,022
- Examples shown: 30
- Last updated: 2026-01-29

