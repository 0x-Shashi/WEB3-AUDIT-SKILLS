---
id: PAT-CONFIGURATION
title: Configuration Security Patterns
category: configuration
severity: medium
difficulty: beginner
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - configuration
  - parameters
  - settings

finding_count: 24
last_updated: 2026-01-31
---
# Configuration Security Patterns

## Overview

**Frequency**: 24 occurrences (0.05% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 13 | 9 | 2 | 0 |

**Common Sources**: Sherlock, Code4rena, Cyfrin, Hans

---

## Detection Checklist

- [ ] Check for configuration vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-2: Users who deposit extra funds into their Ichi farming positions will lose all their ICHI rewards

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

### Example 2: H-1: Too few `ICHI` v2 farming reward tokens transferred to the user due to incorrect decimal precision

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

### Example 3: H-5: Token Mismatch in SPL Token Deposits

**Source**: Sherlock
**Protocol**: ZetaChain Cross-Chain
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2025-04-zetachain-cross-chain-judging/issues/421 

## Found by 
0xkmr\_, OhmOudits, adeolu, berndartmueller, chinepun, g, mahdiRostami

### Summary

The Gateway Solana program contains a critical vulnerability in its `handle_spl` function within the deposit.rs file. While the program requires a whitelist entry account for the SPL token being deposited, it does not verify that the token being transferred from the user's account actually matches the whitelisted token specified in the transaction context. This mismatch allows an attacker to deposit a non-whitelisted token while claiming it's a different, whitelisted token. The ZetaChain node, which processes these deposits, will incorrectly identify the deposited token based on the mint address in the transaction context rather than the actual token being transferred, potentially leading to incorrect cross-chain asset transfers and economic damage.


snippet of the DepositSplToken context below 

https://github.com/sherlock-audit/2025-04-zetachain-cross-chain/blob/main/protocol-contracts-solana/programs/gateway/src/contexts.rs#L76C1-L89C1
```rust 
#[derive(Accounts)]
pub struct DepositSplToken<'info> {
    /// The account of the signer making the deposit.
    #[account(mut)]
    pub signer: Signer<'info>,

    /// Gateway PDA.
    #[account(mut, seeds = [b"meta"], bump)]
    pub pda: Account<'info, Pda>,

    /// The whitelist entry account for the SPL token.
    #[account(seeds = [b"whi

*[Content truncated...]*

---

### Example 4: H-6: ShortLongSpell#_withdraw checks slippage limit but never applies it making it useless

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

### Example 5: H-2: Loans can be rolled an unlimited number of times

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/215 

## Found by 
0x52, enckrish, IllIllI, cducrest-brainbot, banditx0x, simon135, Allarious, Trumpero, Breeje, neumo, Atarpara, yixxas, libratus, usmannk, ali\_shehab, oxcm, thekmj, HollaDieWaldfee, HonorLt, bin2chen

## Summary

Loans can be rolled an unlimited number of times, without letting the lender decide if has been done too many times already


## Vulnerability Detail

The lender is expected to be able to toggle whether a loan can be rolled or not, but once it's enabled, there is no way to prevent the borrower from rolling an unlimited number of times in the same transaction or in quick succession.


## Impact

If the lender is giving an interest-free loan and assumes that allowing a roll will only extend the term by one, they'll potentially be forced to wait until the end of the universe if the borrower chooses to roll an excessive number of times.

If the borrower is using a quickly-depreciating collateral, the lender may be happy to allow one a one-term extension, but will lose money if the term is rolled multiple times and the borrower defaults thereafter.

The initial value of `loan.rollable` is always `true`, so unless the lender calls `toggleRoll()` in the same transaction that they call `clear()`, a determined attacker will be able to roll as many times as they wish.


## Code Snippet

As long as the borrower is willing to pay the interest up front, they can call `roll()` any number of 

*[Content truncated...]*

---

### Example 6: User's funds are locked temporarily in the PriorityPool contract

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

### Example 7: H-9: UniswapV3 sqrtRatioLimit doesn't provide slippage protection and will result in partial swaps

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

### Example 8: [M-05] DecentEthRouter.sol#_bridgeWithPayload() - Any refunded ETH (native token) will be refunded to the DecentBridgeAdapter, making them stuck

**Source**: Code4rena
**Protocol**: Decent
**Impact**: MEDIUM

**Details**:

### Impact

The current flow of swapping and bridging tokens using the `DecentBridgeAdapter` looks like so:

`bridgeAndExecute` inside `UTB` is called, passing in the `bridgeId` of the `DecentBridgeAdapter`.

```jsx
function bridgeAndExecute(
        BridgeInstructions calldata instructions,
        FeeStructure calldata fees,
        bytes calldata signature
    )
        public
        payable
        retrieveAndCollectFees(fees, abi.encode(instructions, fees), signature)
        returns (bytes memory)
    {
        (
            uint256 amt2Bridge,
            BridgeInstructions memory updatedInstructions
        ) = swapAndModifyPostBridge(instructions);
        return callBridge(amt2Bridge, fees.bridgeFee, updatedInstructions);
    }
```

This then makes a call to `callBridge`, which will call `bridge` on the `DecentBridgeAdapter`.

```jsx
function callBridge(
        uint256 amt2Bridge,
        uint bridgeFee,
        BridgeInstructions memory instructions
    ) private returns (bytes memory) {
        bool native = approveAndCheckIfNative(instructions, amt2Bridge);
        return
            IBridgeAdapter(bridgeAdapters[instructions.bridgeId]).bridge{
                value: bridgeFee + (native ? amt2Bridge : 0)
            }(
                amt2Bridge,
                instructions.postBridge,
                instructions.dstChainId,
                instructions.target,
                instructions.paymentOperator,
                instructions.payload,
               

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-decent)

---

### Example 9: `MetaManager.unclaimedRewards` should work with shares instead of asset amounts.

**Source**: Hans
**Protocol**: Meta
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Context:** [`MetaManager.sol#L174-L197`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/meta/MetaManager.sol#L174-L197)

**Description:**
After the `mUSDManager` calls the `notifyRewardAmount()` function, the rewards are tracked using the `unclaimedRewards` variable when there are no stakers yet.

```solidity
function notifyRewardAmount(uint amount) external {
require(msg.sender == address(mUSDManager), "Fund: Invalid caller");
if (totalStaked() == 0) {
/**
* These rewards are unclaimable by the users
* these tokens are forever locked in the contract
* Happens if esMETA balance is zero
*  a) When dApp - launched before IDO
*  b) When circulation of esMETA is zero (rare-event)
*/
unclaimedRewards += amount;//@audit should track with shares
return;
}
require(amount > 0, "amount = 0");
uint256 share = mUSD.getSharesByMintedMUSD(amount);
rewardPerTokenStored = rewardPerTokenStored + (share * Constants.PINT) / totalStaked();
}

function withdrawToTreasury() external onlyOwner {
require(unclaimedRewards > 0, "Fund: No locked rewards");
IERC20 _mUSD = IERC20(address(mUSD));
_mUSD.transfer(treasury, unclaimedRewards); //@audit should transfer shares
unclaimedRewards = 0;
}
```

When the owner withdraws the unclaimed rewards using `withdrawToTreasury()`, it transfers the mUSD amounts.

But `mUSD._transfer()` works with the shares and the ratio between shares and amounts might be changed at any time.

```solidity
f

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### Example 10: [H-01] Incorrect `blocksPerYear` constant in `WhitepaperInterestRateModel`

**Source**: Code4rena
**Protocol**: Venus Protocol
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-05-venus/blob/8be784ed9752b80e6f1b8b781e2e6251748d0d7e/contracts/WhitePaperInterestRateModel.sol#L17>

The interest rate per block is **5x** greater than it's intended to be for markets that use the Whitepaper interest rate model.

### Proof of Concept

The `WhitePaperInterestRateModel` contract is forked from Compound Finance, which was designed to be deployed on Ethereum Mainnet. The `blocksPerYear` constant inside the contract is used to calculate the interest rate of the market on a per-block basis and is set to **2102400**, which assumes that there are 365 days a year and that the block-time is **15 seconds**.

However, Venus Protocol is deployed on the BNB chain, which has a block-time of only **3 seconds**. This results in the interest rate per block on the BNB chain to be **5x** greater than intended.

Both `baseRatePerBlock` and `multiplierPerBlock` are affected and are **5x** the value they should be. This also implies that the pool's interest rate is also 5 times more sensitive to utilization rate changes than intended. It is impossible for the market to arbitrage and adjust the interest rate back to the intended rate as seen in the PoC graph below. It's likely that arbitrageurs will deposit as much collateral as possible to take advantage of the high supply rate, leading to a utilization ratio close to 0.

The following Python script plots the `WhitePaperInterestRateModel` curves for a 15 second and a 3 second block time.

```py

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-venus)

---

### Example 11: M-3: Cancellation refunds should return tokens to order creator, not recipient

**Source**: Sherlock
**Protocol**: Dinari
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-dinari-judging/issues/61 

## Found by 
0x007, ArmedGoose, Kodyvim, ctf\_sec, dirk\_y, james\_wu, osmanozdemir1, shtesesamoubiq
## Summary
When an order is cancelled, the refund is sent to `order.recipient` instead of the order creator because it is the order creator (requestor) pay the payment token for buy order or pay the dShares for sell order

As is the standard in many L1/L2 bridges, cancelled deposits should be returned to the order creator instead of the recipient. In Dinari's current implementation, a refund acts as a transfer with a middle-man.

## Vulnerability Detail
Simply, the `_cancelOrderAccounting()` function returns the refund to the `order.recipient`:

```solidity
    function _cancelOrderAccounting(OrderRequest calldata orderRequest, bytes32 orderId, OrderState memory orderState)
        internal
        virtual
        override
    {
        ...

        uint256 refund = orderState.remainingOrder + feeState.remainingPercentageFees;

        ...

        if (refund + feeState.feesEarned == orderRequest.quantityIn) {
            _closeOrder(orderId, orderRequest.paymentToken, 0);
            // Refund full payment
            refund = orderRequest.quantityIn;
        } else {
            // Otherwise close order and transfer fees
            _closeOrder(orderId, orderRequest.paymentToken, feeState.feesEarned);
        }


        // Return escrow
        IERC20(orderRequest.paymentToken).safeTransfer(orderRe

*[Content truncated...]*

---

### Example 12: M-8: asking for the wrong address for `balanceOf()`

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/116 

## Found by 
Ch\_301
## Summary

## Vulnerability Detail
ShortLongSpell.[openPosition()](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L143-L150) pass to `_doPutCollateral()` wrong value of `balanceOf()`
```solidity
        // 5. Put collateral - strategy token
        address vault = strategies[param.strategyId].vault;
        _doPutCollateral(
            vault,
            IERC20Upgradeable(ISoftVault(vault).uToken()).balanceOf(
                address(this)
            )
        );
```
the balance should be of `address(vault)`

## Impact
- `openPosition()` will never work

## Code Snippet

## Tool used

Manual Review

## Recommendation
```diff
        // 5. Put collateral - strategy token
        address vault = strategies[param.strategyId].vault;
        _doPutCollateral(
            vault,
-            IERC20Upgradeable(ISoftVault(vault).uToken()).balanceOf(
-                address(this)
+                IERC20Upgradeable(vault).balanceOf(address(this))
            )
        );
```



## Discussion

**Ch-301**

Escalate for 10 USDC

This is a simple finding when you know that `SoftVault` is transferring all `uToken` to Compound to generate yield 

Also of wonder the judge set this as invalid but he submitted both this and #114  in the next contest **Blueberry Update 2**

**sherlock-admin**

 > Escalate for 10 USDC
> 
> This 

*[Content truncated...]*

---

### Example 13: M-5: `getPositionRisk()` will return a wrong value of risk

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/97 

## Found by 
Ch\_301
## Summary
In order to interact with SPELL the users need to `lend()` some collateral which is known as **Isolated Collateral** and the SoftVault will deposit them into Compound protocol to generate some lending interest (to earn passive yield)  

## Vulnerability Detail
to [liquidate](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L487-L548) a position this function `isLiquidatable()` should return `true`
```solidity
    function isLiquidatable(uint256 positionId) public view returns (bool) {
        return
            getPositionRisk(positionId) >=
            banks[positions[positionId].underlyingToken].liqThreshold;
    }
```
and it is subcall to `getPositionRisk()`
```solidity
    function getPositionRisk(
        uint256 positionId
    ) public view returns (uint256 risk) {
        uint256 pv = getPositionValue(positionId);          
        uint256 ov = getDebtValue(positionId);             
        uint256 cv = getIsolatedCollateralValue(positionId);

        if (
            (cv == 0 && pv == 0 && ov == 0) || pv >= ov // Closed position or Overcollateralized position
        ) {
            risk = 0;
        } else if (cv == 0) {
            // Sth bad happened to isolated underlying token
            risk = Constants.DENOMINATOR;
        } else {
            risk = ((ov - pv) * Constants.DENOMINATOR) / cv;
   

*[Content truncated...]*

---

### Example 14: H-2: CurveTricryptoOracle incorrectly assumes that WETH is always the last token in the pool which leads to bad LP pricing

**Source**: Sherlock
**Protocol**: Blueberry Update #3
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-07-blueberry-judging/issues/98 

## Found by 
0x52, Vagner

CurveTricryptoOracle assumes that WETH is always the last token in the pool (`tokens[2]`). This is incorrect for a majority of tricrypto pools and will lead to LP being highly overvalued.

## Vulnerability Detail

[CurveTricryptoOracle.sol#L53-L63](https://github.com/sherlock-audit/2023-07-blueberry/blob/main/blueberry-core/contracts/oracle/CurveTricryptoOracle.sol#L53-L63)

        if (tokens.length == 3) {
            /// tokens[2] is WETH
            uint256 ethPrice = base.getPrice(tokens[2]);
            return
                (lpPrice(
                    virtualPrice,
                    base.getPrice(tokens[1]),
                    ethPrice,
                    base.getPrice(tokens[0])
                ) * 1e18) / ethPrice;
        }

When calculating LP prices, CurveTricryptoOracle#getPrice always assumes that WETH is the second token in the pool. This isn't the case which will cause the LP to be massively overvalued.

There are 6 tricrypto pools currently deployed on mainnet. Half of these pools have an asset other than WETH as token[2]:

        0x4ebdf703948ddcea3b11f675b4d1fba9d2414a14 - CRV
        0x5426178799ee0a0181a89b4f57efddfab49941ec - INV
        0x2889302a794da87fbf1d6db415c1492194663d13 - wstETH

## Impact

LP will be massively overvalued leading to overborrowing and protocol insolvency

## Code Snippet

[CurveTricryptoOracle.sol#L48-L65](https://g

*[Content truncated...]*

---

### Example 15: H-10: Wrong Oracle feed addresses

**Source**: Sherlock
**Protocol**: USSD - Autonomous Secure Dollar
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-USSD-judging/issues/817 

## Found by 
0xGusMcCrae, 0xHati, 0xPkhatri, 0xRobocop, 0xStalin, 0xeix, 0xlmanini, 0xyPhilic, 14si2o\_Flint, ADM, Aymen0909, Bahurum, Bauchibred, Bauer, BenRai, Brenzee, BugHunter101, Delvir0, DevABDee, Dug, G-Security, GimelSec, HonorLt, J4de, JohnnyTime, Juntao, Kirkeelee, Kodyvim, Kose, Lilyjjo, Madalad, PNS, PTolev, PokemonAuditSimulator, Proxy, Saeedalipoor01988, SaharDevep, Schpiel, SensoYard, T1MOH, TheNaubit, Vagner, Viktor\_Cortess, WATCHPUG, \_\_141345\_\_, ashirleyshe, ast3ros, berlin-101, blockdev, chainNue, chalex.eth, ck, ctf\_sec, curiousapple, dacian, evilakela, giovannidisiena, immeas, innertia, juancito, kie, kiki\_dev, kutugu, lil.eth, martin, mrpathfindr, neumo, ni8mare, nobody2018, peanuts, pengun, qpzm, ravikiran.web3, saidam017, sakshamguruji, sam\_gmk, sashik\_eth, shaka, shogoki, simon135, theOwl, the\_endless\_sea, toshii, twicek, ustas, whiteh4t9527
## Summary

Wrong Oracle feed addresses will result in wrong prices.

## Vulnerability Detail

StableOracleWBTC.sol#L17 the address is not the BTC/USD feed address.

StableOracleDAI.sol#L28, `DAIEthOracle` is wrong.

StableOracleDAI.sol#L30, address for `ethOracle` is address zero (a hanging todo).

StableOracleWBGL.sol#L19, the address for staticOracleUniV3 is wrong, the current one is actually the univ3 pool address.

## Impact

Wrong prices for collateral assets.

## Code Snippet

https://github.com/sherlock-audit/2023-05-USS

*[Content truncated...]*

---

### Example 16: H-11: ShortLongSpell#openPosition can cause user unexpected liquidation when increasing position size

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/135 

## Found by 
0x52, Ch\_301
## Summary

When increasing a position, all collateral is sent to the user rather than being kept in the position. This can cause serious issues because this collateral keeps the user from being liquidated. It may unexpectedly leave the user on the brink of liquidation where a small change in price leads to their liquidation.

## Vulnerability Detail

[ShortLongSpell.sol#L129-L141](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L129-L141)

        {
            IBank.Position memory pos = bank.getCurrentPositionInfo();
            address posCollToken = pos.collToken;
            uint256 collSize = pos.collateralSize;
            address burnToken = address(ISoftVault(strategy.vault).uToken());
            if (collSize > 0) {
                if (posCollToken != address(wrapper))
                    revert Errors.INCORRECT_COLTOKEN(posCollToken);
                bank.takeCollateral(collSize);
                wrapper.burn(burnToken, collSize);
                _doRefund(burnToken);
            }
        }

In the above lines we can see that all collateral is burned and the user is sent the underlying tokens. This is problematic as it sends all the collateral to the user, leaving the position collateralized by only the isolated collateral.

Best case the user's transaction reverts but worst case they will be l

*[Content truncated...]*

---

### Example 17: H-8: UserData for balancer pool exits is malformed and will permanently trap users

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/129 

## Found by 
0x52, cuthalion0x
## Summary

UserData for balancer pool exits is malformed and will result in all withdrawal attempts failing, trapping the user permanently. 

## Vulnerability Detail

[AuraSpell.sol#L184-L189](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L184-L189)

    wAuraPools.getVault(lpToken).exitPool(
        IBalancerPool(lpToken).getPoolId(),
        address(this),
        address(this),
        IBalancerVault.ExitPoolRequest(tokens, minAmountsOut, "", false)
    );

We see above that UserData is encoded as "". This is problematic as it doesn't contain the proper data for exiting the pool, causing all exit request to fail and trap the user permanently.

https://etherscan.io/address/0x5c6ee304399dbdb9c8ef030ab642b10820db8f56#code#F9#L50

    function exactBptInForTokenOut(bytes memory self) internal pure returns (uint256 bptAmountIn, uint256 tokenIndex) {
        (, bptAmountIn, tokenIndex) = abi.decode(self, (WeightedPool.ExitKind, uint256, uint256));
    }

UserData is decoded into the data shown above when using ExitKind = 0. Since the exit uses "" as the user data this will be decoded as 0 a.k.a [EXACT_BPT_IN_FOR_ONE_TOKEN_OUT](https://etherscan.io/address/0x5c6ee304399dbdb9c8ef030ab642b10820db8f56#code#F24#L50). This is problematic because the token index and bptAmountIn should also be encoded in user data f

*[Content truncated...]*

---

### Example 18: H-2: AuraSpell#openPositionFarm uses incorrect join type for balancer

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/120 

## Found by 
0x52, cuthalion0x
## Summary

The JoinPoolRequest uses "" for userData meaning that it will decode into 0. This is problematic because join requests of type 0 are "init" type joins and will revert for pools that are already initialized. 

## Vulnerability Detail

https://etherscan.io/address/0x5c6ee304399dbdb9c8ef030ab642b10820db8f56#code#F24#L49

    enum JoinKind { INIT, EXACT_TOKENS_IN_FOR_BPT_OUT, TOKEN_IN_FOR_EXACT_BPT_OUT }

We see above that enum JoinKind is INIT for 0 values.

https://etherscan.io/address/0x5c6ee304399dbdb9c8ef030ab642b10820db8f56#code#F24#L290

            return _joinExactTokensInForBPTOut(balances, normalizedWeights, userData);
        } else if (kind == JoinKind.TOKEN_IN_FOR_EXACT_BPT_OUT) {
            return _joinTokenInForExactBPTOut(balances, normalizedWeights, userData);
        } else {
            _revert(Errors.UNHANDLED_JOIN_KIND);
        }

Here user data is decoded into join type and since it is "" it will decode to type 0 which will result in a revert.

## Impact

Users will be unable to open any farm position on AuraSpell

## Code Snippet

[AuraSpell.sol#L63-L147](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L63-L147)

## Tool used

Manual Review

## Recommendation

Uses JoinKind = 1 for user data

---

### Example 19: H-3: Fully repaying a loan will result in debt payment being lost

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/33 

## Found by 
0x52, wagmi, serial-coder, HonorLt, stent, Avci, libratus, Bahurum, ElKu, berndartmueller

## Summary

When a `loan` is fully repaid the `loan` storage is deleted. Since `loan` is a `storage` reference to the loan, `loan.lender` will return `address(0)` after the `loan` has been deleted. This will result in the `debt` being transferred to `address(0)` instead of the lender. Some ERC20 tokens will revert when being sent to `address(0)` but a large number will simply be sent there and lost forever.

## Vulnerability Detail

    function repay (uint256 loanID, uint256 repaid) external {
        Loan storage loan = loans[loanID];

        if (block.timestamp > loan.expiry) 
            revert Default();
        
        uint256 decollateralized = loan.collateral * repaid / loan.amount;

        if (repaid == loan.amount) delete loans[loanID];
        else {
            loan.amount -= repaid;
            loan.collateral -= decollateralized;
        }

        debt.transferFrom(msg.sender, loan.lender, repaid);
        collateral.transfer(owner, decollateralized);
    }

In `Cooler#repay` the loan storage associated with the loanID being repaid is deleted. `loan` is a storage reference so when `loans[loanID]` is deleted so is `loan`. The result is that `loan.lender` is now `address(0)` and the loan payment will be sent there instead.

## Impact

Lender's funds are sent to `address(0)`

## Code

*[Content truncated...]*

---

### Example 20: [L-03] Contracts are not using their OZ upgradeable counterparts

**Source**: Code4rena
**Protocol**: JPYC
**Impact**: LOW

**Details**:

### Tools Used

Diffchecker

### Description

The non-upgradeable standard version of OpenZeppelins library, such as `Ownable`, `Pausable`, `Address`, `Context`, `SafeERC20`, `ERC1967Upgrade` etc, are inherited / used by both the proxy and the implementation contracts.

As a result, when attempting to use the upgrades plugin mentioned, the following errors are raised:

```solidity
Error: Contract `FiatTokenV1` is not upgrade safe

contracts/v1/FiatTokenV1.sol:58: Variable `totalSupply_` is assigned an initial value
  Move the assignment to the initializer
  https://zpl.in/upgrades/error-004

contracts/v1/Pausable.sol:49: Variable `paused` is assigned an initial value
  Move the assignment to the initializer
  https://zpl.in/upgrades/error-004

contracts/v1/Ownable.sol:28: Contract `Ownable` has a constructor
  Define an initializer instead
  https://zpl.in/upgrades/error-001

contracts/util/Address.sol:186: Use of delegatecall is not allowed
  https://zpl.in/upgrades/error-002
```

Having reviewed these errors, none had any adversarial impact:

*   `totalSupply_` and `paused` are explictly assigned the default values `0` and `false`
*   the implementation contracts utilises the internal `_transferOwnership()` in the initializer, thus transferring ownership to `newOwner` regardless of who the current owner is
*   `Address`'s `delegatecall` is only used by the `ERC1967Upgrade` contract. Comparing both the `Address` and `ERC1967Upgrade` contracts against their upgradeable count

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-jpyc)

---

### Example 21: M-3: Updating the feeManger on config will cause desync between bank and vaults

**Source**: Sherlock
**Protocol**: Blueberry Update #2
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-05-blueberry-judging/issues/32 

## Found by 
0x52
## Summary

When the bank is initialized it caches the current config.feeManager. This is problematic since feeManger can be updated in config. Since it is precached the address in bank will not be updated leading to a desync between contracts the always pull the freshest value for feeManger and bank.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L142

        feeManager = config_.feeManager();

Above we see that feeManger is cached during initialization.

 https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/vault/HardVault.sol#L140-L143

        withdrawAmount = config.feeManager().doCutVaultWithdrawFee(
            address(uToken),
            shareAmount
        );

This is in direct conflict with other contracts the always use the freshest value. This is problematic for a few reasons. The desync will lead to inconsistent fees across the ecosystem either charging users too many fees or not enough.

## Impact

After update users will experience inconsistent fees across the ecosystem

## Code Snippet


https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L142

## Tool used

Manual Review

## Recommendation

BlueBerryBank should always use config.feeManger instead of caching it.

---

### Example 22: M-12: rewardTokens removed from WAuraPool/WConvexPools will be lost forever

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/128 

## Found by 
0x52
## Summary

pendingRewards pulls a fresh count of reward tokens each time it is called. This is problematic if reward tokens are ever removed from the the underlying Aura/Convex pools because it means that they will no longer be distributed and will be locked in the contract forever.

## Vulnerability Detail

[WAuraPools.sol#L166-L189](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L166-L189)

        uint extraRewardsCount = IAuraRewarder(crvRewarder)
            .extraRewardsLength();
        tokens = new address[](extraRewardsCount + 1);
        rewards = new uint256[](extraRewardsCount + 1);

        tokens[0] = IAuraRewarder(crvRewarder).rewardToken();
        rewards[0] = _getPendingReward(
            stCrvPerShare,
            crvRewarder,
            amount,
            lpDecimals
        );

        for (uint i = 0; i < extraRewardsCount; i++) {
            address rewarder = IAuraRewarder(crvRewarder).extraRewards(i);
            uint256 stRewardPerShare = accExtPerShare[tokenId][i];
            tokens[i + 1] = IAuraRewarder(rewarder).rewardToken();
            rewards[i + 1] = _getPendingReward(
                stRewardPerShare,
                rewarder,
                amount,
                lpDecimals
            );
        }

In the lines above we can see that only tokens that are currently available 

*[Content truncated...]*

---

### Example 23: M-11: AuraSpell#closePositionFarm requires users to swap all reward tokens through same router

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

### Example 24: Functions not used internally could be marked external

**Source**: Cyfrin
**Protocol**: Stake Link
**Impact**: LOW

**Details**:

```solidity
File: PriorityPool.sol

89:     function initialize(

278:     function depositQueuedTokens() public {

```

**Client:**
Acknowledged.

**Cyfrin:** Acknowledged.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-08-25-cyfrin-stake-link.md)

---

## Statistics

- Total findings analyzed: 24
- Examples shown: 24
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

