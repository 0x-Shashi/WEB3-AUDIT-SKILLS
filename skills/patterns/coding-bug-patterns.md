# Coding-Bug Security Patterns

## Overview

**Frequency**: 20 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 11 | 8 | 1 | 0 |

**Common Sources**: Sherlock, Cyfrin, Hans

---

## Detection Checklist

- [ ] Check for coding-bug vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-8: Interest component of underlying amount is not withdrawable using the `withdrawLend` function. Such amount is permanently locked in the BlueBerryBank contract

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

### Example 2: Wrong validation in `DefaultUndelegationPolicy.onUndelegate()`

**Source**: Cyfrin
**Protocol**: Streamr
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** In `onUndelegate()`, it checks if the operator owner still holds at least `minimumSelfDelegationFraction` of total supply.

```solidity
   function onUndelegate(address delegator, uint amount) external {
       // limitation only applies to the operator, others can always undelegate
       if (delegator != owner) { return; }

       uint actualAmount = amount < balanceOf(owner) ? amount : balanceOf(owner); //@audit amount:DATA, balanceOf:Operator
       uint balanceAfter = balanceOf(owner) - actualAmount;
       uint totalSupplyAfter = totalSupply() - actualAmount;
       require(1 ether * balanceAfter >= totalSupplyAfter * streamrConfig.minimumSelfDelegationFraction(), "error_selfDelegationTooLow");
   }
```

But `amount` means the DATA token amount and `balanceOf(owner)` indicates the `Operator` token balance and it's impossible to compare them directly.

**Impact:** The operator owner wouldn't be able to undelegate because `onUndelegate()` works unexpectedly.

**Recommended Mitigation:** `onUndelegate()` should compare amounts after converting to the same token.

**Client:** Fixed in commit [9b8c65e](https://github.com/streamr-dev/network-contracts/commit/9b8c65ea31b6bf15fe4ec913a975782f27c0c9a0).

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-03-cyfrin-streamr.md)

---

### Example 3: H-1: attackers will keep stealing the `rewards` from Convex SPELL

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/101 

## Found by 
Bauer, Ch\_301
## Summary
On [WConvexPools.burn()](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WConvexPools.sol#L201-L235) transfer [CRV + CVX + the extra rewards](https://docs.convexfinance.com/convexfinance/general-information/why-convex/convex-for-liquidity-providers) to Convex SPELL 


## Vulnerability Detail
But [ConvexSpell.openPositionFarm()](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ConvexSpell.sol#L67-L138) only refund CVX to the user.
So the rest rewards will stay in the SPELL intel if someone (could be an attacker) invokes `_doRefund()` within `closePositionFarm()` with the same address tokens 

## Impact
- Convex SPELL steals the user rewards 
- the protocol will lose some fees 
- attackers will keep stealing the rewards from Convex SPELL

## Code Snippet
`WConvexPools.burn()` transfer CRV + CVX + the extra rewards
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WConvexPools.sol#L201-L235
```solidity
        // Transfer LP Tokens
        IERC20Upgradeable(lpToken).safeTransfer(msg.sender, amount);

        // Transfer Reward Tokens
        (rewardTokens, rewards) = pendingRewards(id, amount);

        for (uint i = 0; i < rewardTokens.length; i++) {
            IERC20Upgradeable(rewardTokens[i]).safeTransfer(
                

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

### Example 5: H-9: BlueBerryBank#withdrawLend will cause underlying token accounting error if soft/hard vault has withdraw fee

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

### Example 6: Some constants wouldn't work as expected.

**Source**: Hans
**Protocol**: Meta
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Context:** [`Constants.sol#L5`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/lib/Constants.sol#L5)

**Description:**
Two constants `KEEPER_RATE` and `MAX_KEEPER_RATE` are declared like the below.

```solidity
uint256 constant KEEPER_RATE = 0.01e18; //1%
uint256 constant MAX_KEEPER_RATE = 0.05e18; //5%
```

But when we use the `KEEPER_RATE` in `liquidation()/superLiquidation()`, we divide the rate by 100 again.

```solidity
if (provider == msg.sender) {
glp.transfer(msg.sender, reducedGLP);
} else {
reward2keeper = (reducedGLP * rates.getKR()) / 110 / Constants.PINT; //@audit divide by 100 again
glp.transfer(provider, reducedGLP - reward2keeper);
glp.transfer(msg.sender, reward2keeper);
}
```

So the default keeper rate will be 0.01% instead of 1% during the liquidation.

**Impact**
The reward rate for the keepers wouldn't work as expected. Because it will just affect the reward rate for keepers without losing funds, I evaluate the severity to Medium.

**Recommendation:**
Modify the constants or reward calculation formula accordingly.

**Meta Team:**

The keepr rewards and number libraries are consistenly used. And necessary changes have been made in the commit 007c1b9183cdb65a500928173608ebff0a5197ef

```
Constants.sol

library Constants {
// Base constants
uint256 constant PINT = 1e18;
uint256 constant HUNDRED_PERCENT = 100e18; //100

// Collateral constants
uint256 constant BAD_COLLATERAL_LIMIT = 150e

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### Example 7: H-2: ShortLongSpell#openPosition uses the wrong balanceOf when determining how much collateral to put

**Source**: Sherlock
**Protocol**: Blueberry Update #2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-blueberry-judging/issues/31 

## Found by 
0x52
## Summary

The _doPutCollateral subcall in ShortLongSpell#openPosition uses the balance of the uToken rather than the vault resulting in the vault tokens being left in the contract which will be stolen.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L144-L150

        address vault = strategies[param.strategyId].vault;
        _doPutCollateral(
            vault,
            IERC20Upgradeable(ISoftVault(vault).uToken()).balanceOf(
                address(this)
            )
        );

When putting the collateral the contract is putting vault but it uses the balance of the uToken instead of the balance of the vault.

## Impact

Vault tokens will be left in contract and stolen

## Code Snippet

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L111-L151

## Tool used

Manual Review

## Recommendation

Use the balanceOf vault rather than vault.uToken



## Discussion

**sleepriverfish**

Escalate for 10 USDC

In #Blueberry Update, despite the successful escalation of the issue, no reward was granted for the heightened severity and impact of the vulnerability. However, in #Blueberry Update2, a reward was offered specifically for the detection and reporting of a similar vulnerability.
https://github.com/sherlock-audit/2023-04-bluebe

*[Content truncated...]*

---

### Example 8: M-2: price is calculated wrongly in BoundedStepwiseExponentialPriceAdapter

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/39 

## Found by 
0x007, 0x52, Brenzee, auditsea, dany.armstrong90
## Summary
The BoundedStepwiseExponentialPriceAdapter contract is trying to implement price change as `scalingFactor * (e^x - 1)` but the code implements `scalingFactor * e^x - 1`. Since there are no brackets, multiplication would be executed before subtraction. And this has been confirmed with one of the team members.

## Vulnerability Detail
The [getPrice code](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-protocol/contracts/protocol/integration/auction-price/BoundedStepwiseExponentialPriceAdapter.sol#L40-L73) has been simplified as the following when boundary/edge cases are ignored

```solidity
(
    uint256 initialPrice,
    uint256 scalingFactor,
    uint256 timeCoefficient,
    uint256 bucketSize,
    bool isDecreasing,
    uint256 maxPrice,
    uint256 minPrice
) = getDecodedData(_priceAdapterConfigData);

uint256 timeBucket = _timeElapsed / bucketSize;

int256 expArgument = int256(timeCoefficient * timeBucket);

uint256 expExpression = uint256(FixedPointMathLib.expWad(expArgument));

uint256 priceChange = scalingFactor * expExpression - WAD;
```

When timeBucket is 0, we want priceChange to be 0, so that the returned price would be the initial price. Since `e^0 = 1`, we need to subtract 1 (in WAD) from the `expExpression`. 

However, with the incorrect implementation, the returned price would be different than real

*[Content truncated...]*

---

### Example 9: M-3: Cancellation refunds should return tokens to order creator, not recipient

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

### Example 10: M-8: asking for the wrong address for `balanceOf()`

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

### Example 11: M-6: M-03 wrong token address on `ShortLongSpell.sol`

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/114 

## Found by 
Ch\_301
## Summary

## Vulnerability Detail
[ShortLongSpell.openPosition()](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#LL111C4-L151C6) send `uToken` to SoftVault then deposit it into the Compound protocol to earn a passive yield. In return, SPELL receives share tokes of SoftVault  `address(strategy.vault)`  

`WERC20.sol` should receive `address(strategy.vault)` token, but the logic of `ShortLongSpell.sol` subcall (WERC20.sol) `wrapper.burn()` and pass the `uToken` address (please check the Code Snippet part) instead of `strategy.vault` address

## Impact
Short/Long Spell will never work

## Code Snippet
1- https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L128-L141
```solidity
            address burnToken = address(ISoftVault(strategy.vault).uToken());
            if (collSize > 0) {
                if (posCollToken != address(wrapper))
                    revert Errors.INCORRECT_COLTOKEN(posCollToken);
                bank.takeCollateral(collSize);
                wrapper.burn(burnToken, collSize);
                _doRefund(burnToken);
            }
```
2- https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L229-L234
```solidity
        // 1. Take out collateral
        bank.takeCollateral(par

*[Content truncated...]*

---

### Example 12: M-3: The protocol  will not be able to add liquidity on the curve with another token with a balance.

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/47 

## Found by 
Bauer, nobody2018
## Summary
The `CurveSpell` protocol only ensure approve curve pool to spend its borrow token. Hence, it will not be able to add liquidity on the curve with another token with a balance.

## Vulnerability Detail
The  `openPositionFarm()` function enables user to open a leveraged position in a yield farming strategy by borrowing funds and using them to add liquidity to a Curve pool, while also taking into account certain risk management parameters such as maximum LTV and position size. When add liquidity on curve ,the protocol use the borrowed token and the collateral token, it checks the number of tokens in the pool and creates an array of the supplied token amounts to be passed to the add_liquidity function. Then the curve will transfer the tokens from the protocol and mint lp tokens to the protocol. However, the protocol only ensure approve curve pool to spend its borrow token. Hence, it will not be able to add liquidity on the curve with another token with a balance.
```solidity
 // 3. Add liquidity on curve
        _ensureApprove(param.borrowToken, pool, borrowBalance);
        if (tokens.length == 2) {
            uint256[2] memory suppliedAmts;
            for (uint256 i = 0; i < 2; i++) {
                suppliedAmts[i] = IERC20Upgradeable(tokens[i]).balanceOf(
                    address(this)
                );
            }
            ICurvePool(pool).add_

*[Content truncated...]*

---

### Example 13: M-2: AuraSpell openPositionFarm does not join pool

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/46 

## Found by 
Ch\_301, cducrest-brainbot, cuthalion0x, nobody2018
## Summary

The function to open a position for the AuraSpell does not join the pool due to wrong conditional check.

## Vulnerability Detail

The function deposits collateral into the bank, borrow tokens, and attempts to join the pool:

```solidity
    function openPositionFarm(
        OpenPosParam calldata param
    )
        external
        existingStrategy(param.strategyId)
        existingCollateral(param.strategyId, param.collToken)
    {
        ...
        // 1. Deposit isolated collaterals on Blueberry Money Market
        _doLend(param.collToken, param.collAmount);

        // 2. Borrow specific amounts
        uint256 borrowBalance = _doBorrow(
            param.borrowToken,
            param.borrowAmount
        );

        // 3. Add liquidity on Balancer, get BPT
        {
            IBalancerVault vault = wAuraPools.getVault(lpToken);
            _ensureApprove(param.borrowToken, address(vault), borrowBalance);

            (address[] memory tokens, uint256[] memory balances, ) = wAuraPools
                .getPoolTokens(lpToken);
            uint[] memory maxAmountsIn = new uint[](2);
            maxAmountsIn[0] = IERC20(tokens[0]).balanceOf(address(this));
            maxAmountsIn[1] = IERC20(tokens[1]).balanceOf(address(this));

            uint totalLPSupply = IBalancerPool(lpToken).totalSupply();
            // 

*[Content truncated...]*

---

### Example 14: H-12: Pending CRV rewards are not accounted for and can cause unfair liquidations

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/136 

## Found by 
0x52
## Summary

pendingRewards are factored into the health of a position so that the position collateral is fairly assessed. However WCurveGauge#pendingRewards doesn't return the proper reward tokens/amounts meaning that positions aren't valued correctly and users can be unfairly liquidated.

## Vulnerability Detail

[BlueBerryBank.sol#L408-L413](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L408-L413)

            (address[] memory tokens, uint256[] memory rewards) = IERC20Wrapper(
                pos.collToken
            ).pendingRewards(pos.collId, pos.collateralSize);
            for (uint256 i; i < tokens.length; i++) {
                rewardsValue += oracle.getTokenValue(tokens[i], rewards[i]);
            }

When BlueBerryBank is valuing a position it also values the pending rewards since they also have value. 

[WCurveGauge.sol#L106-L114](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WCurveGauge.sol#L106-L114)

    function pendingRewards(
        uint256 tokenId,
        uint256 amount
    )
        public
        view
        override
        returns (address[] memory tokens, uint256[] memory rewards)
    {}

Above we see that WCurveGauge#pendingRewards returns empty arrays when called. This means that pending rewards are not factored in correctly and users can be 

*[Content truncated...]*

---

### Example 15: H-10: Balance check for swapToken in ShortLongSpell#_deposit is incorrect and will result in nonfunctional contract

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

### Example 16: H-8: UserData for balancer pool exits is malformed and will permanently trap users

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

### Example 17: H-7: WAuraPools will irreversibly break if reward tokens are added to pool after deposit

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/127 

## Found by 
0x52, Ch\_301
## Summary

WAuraPools will irreversibly break if reward tokens are added to pool after deposit due to an OOB error on accExtPerShare.

## Vulnerability Detail

[WAuraPools.sol#L166-L189](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L166-L189)

        uint extraRewardsCount = IAuraRewarder(crvRewarder)
            .extraRewardsLength(); <- @audit-issue rewardTokenCount pulled fresh
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

            @audit-issue attempts to pull from array which will be too small if tokens are added
            uint256 stRewardPerShare = accExtPerShare[tokenId][i];
            tokens[i + 1] = IAuraRewarder(rewarder).rewardToken();
            rewards[i + 1] = _getPendingReward(
                stRewardPerShare,
                rewarder,
                amount,
                lpDecimals
            );
        }

accExtPerShare stores the current rewardPerToken when the position is fir

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

### Example 19: Unnecessary parameter amount in withdraw function

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: LOW

**Details**:

**Severity:** Informational

**Description:** The function `withdraw()` has a parameter `amount` but we don't understand the necessity of this parameter.
At line L67, the amount is required to be the same to the whole deposit amount. This means the user does not have a flexibility to choose the withdraw amount, after all it means the parameter was not necessary at all.
```solidity
DepositVault.sol
59:     function withdraw(uint256 amount, uint256 nonce, bytes memory signature, address payable recipient) public {
60:         require(nonce < deposits.length, "Invalid deposit index");
61:         Deposit storage depositToWithdraw = deposits[nonce];
62:         bytes32 withdrawalHash = getWithdrawalHash(Withdrawal(amount, nonce));
63:         address signer = withdrawalHash.recover(signature);
64:         require(signer == depositToWithdraw.depositor, "Invalid signature");
65:         require(!usedWithdrawalHashes[withdrawalHash], "Withdrawal has already been executed");
66:         require(amount == depositToWithdraw.amount, "Withdrawal amount must match deposit amount");//@audit-info only full withdrawal is allowed
67:
68:         usedWithdrawalHashes[withdrawalHash] = true;
69:         depositToWithdraw.amount = 0;
70:
71:         if(depositToWithdraw.tokenAddress == address(0)){
72:             recipient.transfer(amount);
73:         } else {
74:             IERC20 token = IERC20(depositToWithdraw.tokenAddress);
75:             token.safeTransfer(recipient, amount);
76:      

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 20: M-2: ShortLongSpell#openPosition attempts to burn wrong token

**Source**: Sherlock
**Protocol**: Blueberry Update #2
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-05-blueberry-judging/issues/30 

## Found by 
0x52
## Summary

ShortLongSpell#openPosition attempts to burn vault.uToken when it should be using vault instead. The result is that ShortLongSpell#openPosition will be completely nonfunctional when the user is adding to their position

## Vulnerability Detail

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L133-L140

            address burnToken = address(ISoftVault(strategy.vault).uToken());
            if (collSize > 0) {
                if (posCollToken != address(wrapper))
                    revert Errors.INCORRECT_COLTOKEN(posCollToken);
                bank.takeCollateral(collSize);
                wrapper.burn(burnToken, collSize);
                _doRefund(burnToken);
            }

We see above that the contract attempts to withdraw vault.uToken from the wrapper.

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L145-L150

        _doPutCollateral(
            vault,
            IERC20Upgradeable(ISoftVault(vault).uToken()).balanceOf(
                address(this)
            )
        );

This is in direct conflict with the collateral that is actually deposited which is vault. This will cause the function to always revert when adding to an existing position.

## Impact

ShortLongSpell#openPosition will be completely nonfunctional when the user is

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 20
- Examples shown: 20
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
