# Lending Pool Security Patterns

## Overview

**Frequency**: 17 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 7 | 10 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena

---

## Detection Checklist

- [ ] Check for lending pool vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-02] Liquidity providers may lose funds when adding liquidity

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: HIGH

**Details**:

Liquidity providers may lose a portion of provided liquidity in either of the pair tokens. While the `minLpTokenAmount` protects from slippage when adding liquidity, it doesn't protect from providing liquidity at different K.

### Proof of Concept

The `Pair` contract is designed to receive liquidity from liquidity providers ([Pair.sol#L63](https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L63)). First liquidity provider in a pool may provide arbitrary token amounts and set the initial price ([Pair.sol#L425-L426](https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L425-L426)), but all other liquidity providers must provide liquidity proportionally to current pool reserves ([Pair.sol#L420-L423](https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L420-L423)). Since a pool is made of two tokens and liquidity is provided in both tokens, there's a possibility for a discrepancy: token amounts may be provided in different proportions. When this happens, the smaller of the proportions is chosen to calculate the amount of LP tokens minted ([Pair.sol#L420-L423](https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L420-L423)):

```solidity
// calculate amount of lp tokens as a fraction of existing reserves
uint256 baseTokenShare = (baseTokenAmount * lpTokenSupply) / baseTokenReserv

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-caviar)

---

### Example 2: H-1: Pool can be drained

**Source**: Sherlock
**Protocol**: WOOFi Swap
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-03-woofi-swap-judging/issues/68 

The protocol has acknowledged this issue.

## Found by 
mstpr-brainbot
## Summary
The pool can be drained just as it was during the incident that occurred previously.
## Vulnerability Detail
`maxNotionalSwap` and `maxGamma` and the new math formula do not prevent the pool being drainable. Same attack vector that happent previously is still applicable:
https://woo.org/blog/en/woofi-spmm-exploit-post-mortem
https://rekt.news/woo-rekt/

Flashloan 99989999999999999990000 (99_990) WOO
Sell WOO partially (in 10 pieces) assuming maxGamma | maxNotionalSwap doesnt allow us to do it in one go
Sell 20 USDC and get 199779801821639475527975 (199_779) WOO
Repay flashloan, pocket the rest of the 100K WOO.

**Coded PoC:**
```solidity
function test_Exploit() public {
        // Flashloan 99989999999999999990000 (99_990) WOO
        // Sell WOO partially (in 10 pieces) assuming maxGamma | maxNotionalSwap doesnt allow us to do it in one go
        // Sell 20 USDC and get 199779801821639475527975 (199_779) WOO
        // Repay flashloan, pocket the rest of the 100K WOO. 

        // Reference values: 
        // s = 0.1, p = 1, c = 0.0001 

        // bootstrap the pool 
        uint usdcAmount = 100_0000_0_0000000000000_000;
        deal(USDC, ADMIN, usdcAmount);
        deal(WOO, ADMIN, usdcAmount);
        deal(WETH, ADMIN, usdcAmount);
        vm.startPrank(ADMIN);
        IERC20(USDC).approve(address(pool), typ

*[Content truncated...]*

---

### Example 3: H-14: Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

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

### Example 4: [M-05] Pair price may be manipulated by direct transfers

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L391> <br><https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L479-L480> <br><https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L384>

An attacker may manipulate the price of a pair by transferring tokens directly to the pair. Since the `Pair` contract exposes the `price` function, it maybe be used as a price oracle in third-party integrations. Manipulating the price of a pair may allow an attacker to steal funds from such integrations.

### Proof of Concept

The `Pair` contract is a pool of two tokens, a base token and a fractional token. Its main purpose is to allow users to swap the tokens at a fair price. Since the price is calculated based on the reserves of a pair, it can only be changed in two cases:

1.  when initial liquidity is added: the first liquidity provider sets the price of a pool ([Pair.sol#L85-L97](https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L85-L97)); other liquidity providers cannot change the price ([Pair.sol#L421-L423](https://github.com/code-423n4/2022-12-caviar/blob/0212f9dc3b6a418803dbfacda0e340e059b8aae2/src/Pair.sol#L421-L423));
2.  during trades: trading adds and removes tokens from a pool, ensuring the K constant invariant is respected ([Pair.sol#L194-L204](https://github.com/cod

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-caviar)

---

### Example 5: [H-21] bringUnusedETHBackIntoGiantPool in GiantMevAndFeesPool can be used to steal LPTokens

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L126


## Vulnerability details

## Impact
real `LPTokens` can be transferred out of `GiantMevAndFeesPool` through fake `_stakingFundsVaults` provided by an attacker.
https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L126

## Proof of Concept
`bringUnusedETHBackIntoGiantPool` takes in `_stakingFundsVaults`, `_oldLPTokens`, `_newLPTokens` and rotate `_amounts` from old to new tokens. The tokens are thoroughly verified by `burnLPForETH` in `ETHPoolLPFactory`. 
However, theres is no checking for the validity of `_stakingFundsVaults`, nor the relationship between `LPTokens` and `_stakingFundsVaults`. Therefore, an attacker can create fake contracts for `_stakingFundsVaults`, with `burnLPTokensForETH`, that takes `LPTokens` as parameters. The `msg.sender` in `burnLPTokensForETH` is `GiantMevAndFeesPool`, thus the attacker can transfer `LPTokens` that belongs to `GiantMevAndFeesPool` to any addresses it controls.

## Tools Used
manual

## Recommended Mitigation Steps
Always passing liquid staking manager address, checking its real and then requesting either the savETH vault or staking funds vault is a good idea to prove the validity of vaults.

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 6: M-16: `originationFee` may result in the borrower account becoming liquidatable immediately

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/501-M 
## Found by 
WATCHPUG

## Summary

Note: This issue is a part of the extra scope added by Sentiment AFTER the audit contest. This scope was only reviewed by WatchPug and relates to these three PRs:

1. [Lending deposit cap](https://github.com/sentimentxyz/protocol/pull/234)
2. [Fee accrual modification](https://github.com/sentimentxyz/protocol/pull/233)
3. [CRV staking](https://github.com/sentimentxyz/controller/pull/41)

`originationFee` may result in the borrower account becoming liquidatable immediately.

## Vulnerability Detail

When checking `riskEngine.isBorrowAllowed()`, the `originationFee` of the borrow is not considered. Thus, when `originationFee` is large enough, the borrower account becomes liquidatable immediately.

For example:

Let's say USDC's `originationFee` is 30%;

Alice has `100 USDC`, and 0 debt in her account;
Alice borrowed `400 USDC`, received only `280 USDC` after the `originationFee`;
Alice's account is now liquidatable.
Actually, in the case above, Alice's account won't even get liquidated as all the assets are worth (380 USDC) less than the total debt (`400 USDC`).

## Impact

`originationFee` may result in the borrower account becoming liquidatable immediately.

## Code Snippet
https://github.com/sentimentxyz/protocol/blob/f5a9089e87752986af522cc952f95beb037491c8/src/tokens/LToken.sol#L243-L245

```solidity
function updateOriginationFee(uint _originationFee) ext

*[Content truncated...]*

---

### Example 7: [H-06] LPs of VaderPoolV2 can manipulate pool reserves to extract funds from the reserve.

**Source**: Code4rena
**Protocol**: Vader Protocol
**Impact**: HIGH

**Details**:

## Handle

TomFrenchBlockchain


## Vulnerability details

(Resubmission as the form crashed apologies if this is a duplicate)

## Impact
Impermanent loss protection can be exploited to drain the reserve.

## Proof of Concept
In `VaderPoolV2.burn` we calculate the current losses that the LP has made to impermanent loss.

https://github.com/code-423n4/2021-12-vader/blob/fd2787013608438beae361ce1bb6d9ffba466c45/contracts/dex-v2/pool/VaderPoolV2.sol#L265-L296

These losses are then refunded to the LP in VADER tokens from the reserve.

https://github.com/code-423n4/2021-12-vader/blob/fd2787013608438beae361ce1bb6d9ffba466c45/contracts/dex-v2/router/VaderRouterV2.sol#L220

This loss is calculated by the current reserves of the pool so if an LP can manipulate the pool's reserves they can artificially engineer a huge amount of IL in order to qualify for a payout up to the size of their LP position.

https://github.com/code-423n4/2021-12-vader/blob/fd2787013608438beae361ce1bb6d9ffba466c45/contracts/dex/math/VaderMath.sol#L72-L92

The attack is then as follows.
1. Be an LP for a reasonable period of time (IL protection scales linearly up to 100% after a year)
2. Flashloan a huge amount of one of the pool's assets.
3. Trade against the pool with the flashloaned funds to unbalance it such that your LP position has huge IL.
4. Remove your liquidity and receive compensation from the reserve for the IL you have engineered.
5. Re-add your liquidity back to the pool.
6. Trade against the pool

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-12-vader)

---

### Example 8: M-16: Auction timers following liquidity can fall through the floor price causing pool insolvency

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/76 

## Found by 
CRYP70

## Summary
When a borrower cannot pay their debt in an ERC20 pool, their position is liquidated and their assets enter an auction for other users to purchase small pieces of their assets. Because of the incentive that users wish to not pay above the standard market price for a token, users will generally wait until assets on auction are as cheap as possible to purchase however, this is flawed because this guarantees a loss for all lenders participating in the protocol with each user that is liquidated.

## Vulnerability Detail
Consider a situation where a user decides to short a coin through a loan and refuses to take the loss to retain the value of their position. When the auction is kicked off using the `kick()` function on this user, as time moves forward, the price for puchasing these assets becomes increasingly cheaper. These prices can fall through the floor price of the lending pool which will allow anybody to buy tokens for only a fraction of what they were worth originally leading to a state where the pool cant cover the debt of the user who has not paid their loan back with interest. The issue lies in the `_auctionPrice()` function of the `Auctions.sol` contract which calculates the price of the auctioned assets for the taker. This function does not consider the floor price of the pool. The proof of concept below outlines this scenario:

*Proof of Concept:*
```solidity
  

*[Content truncated...]*

---

### Example 9: M-9: Protocol Reserve Within A LToken Vault Can Be Lent Out

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/122-M 
## Found by 
xiaoming90

## Summary

Protocol reserve, which serves as a liquidity backstop or to compensate the protocol, within a LToken vault can be lent out to the borrowers.

## Vulnerability Detail

The purpose of the protocol reserve within a LToken vault is to compensate the protocol or serve as a liquidity backstop. However, based on the current setup, it is possible for the protocol reserve within a Ltoken vault to be lent out.

The following functions within the `LToken` contract show that the protocol reserve is intentionally preserved by removing the protocol reserve from the calculation of total assets within a LToken vault. As such, whenever the Liquidity Providers (LPs) attempt to redeem their LP token, the protocol reserves will stay intact and will not be withdrawn by the LPs.

https://github.com/sherlock-audit/2022-08-sentiment/blob/main/protocol/src/tokens/LToken.sol#L191

```solidity
function totalAssets() public view override returns (uint) {
    return asset.balanceOf(address(this)) + getBorrows() - getReserves();
}
```

https://github.com/sherlock-audit/2022-08-sentiment/blob/main/protocol/src/tokens/LToken.sol#L195

```solidity
function getBorrows() public view returns (uint) {
    return borrows + borrows.mulWadUp(getRateFactor());
}
```

https://github.com/sherlock-audit/2022-08-sentiment/blob/main/protocol/src/tokens/LToken.sol#L176

```solidity
function getReserve

*[Content truncated...]*

---

### Example 10: M-4: Users can fail to closePositionFarm and lose their funds

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/64 

## Found by 
Bauer
## Summary
If self.is_killed in the curve pool contract  becomes true, user may be unable to call the `CurveSpell.closePositionFarm()` function to  repay his debt, resulting in his assets being liquidated.


## Vulnerability Detail
The `CurveSpell.closePositionFarm()` function is used to unwind a position on a strategy that involves farming CRV rewards through staking LP tokens in a Curve pool. Inside the function, the protocol swaps the harvested CRV tokens to the debt token, and calculates the actual amount of LP tokens to remove from the Curve pool. It then removes the LP tokens using the remove_liquidity_one_coin function of the Curve pool. 
```solidity
   int128 tokenIndex;
            for (uint256 i = 0; i < tokens.length; i++) {
                if (tokens[i] == pos.debtToken) {
                    tokenIndex = int128(uint128(i));
                    break;
                }
            }

            ICurvePool(pool).remove_liquidity_one_coin(
                amountPosRemove,
                int128(tokenIndex),
                0
            );
        }

        // 5. Withdraw isolated collateral from Bank
        _doWithdraw(param.collToken, param.amountShareWithdraw);

        // 6. Repay
        {
            // Compute repay amount if MAX_INT is supplied (max debt)
            uint256 amountRepay = param.amountRepay;
            if (amountRepay == type(uint256).max) {

*[Content truncated...]*

---

### Example 11: M-2: AuraSpell openPositionFarm does not join pool

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

### Example 12: [M-06] Withdrawing wrong LPToken from GiantPool leads to loss of funds

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

The `GiantPoolBase.withdrawLPTokens` function (<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantPoolBase.sol#L69>) allows to withdraw LP tokens from a GiantPool by burning an equal amount of GiantLP.

This allows a user to handle the LP tokens directly without the need for a GiantPool as intermediary.

It is not checked however whether the LP tokens to be withdrawn were transferred to the GiantPool in exchange for staking ETH.

I.e. whether the LP token are of any value.

There are two issues associated with this behavior.

1.  A malicious user can create and mint his own LP Token and send it to the GiantPool. Users that want to withdraw LP tokens from the GiantPool can then be tricked into withdrawing worthless attacker LP tokens, thereby burning their GiantLP tokens that are mapped 1:1 to ETH. (-> loss of funds)

2.  This can also mess up internal accounting logic. For every LP token that is owned by a GiantPool there should be a corresponding GiantLP token. Using the described behavior this ratio can be broken such that there are LP token owned by the GiantPool for which there is no GiantLP token. This means some LP token cannot be transferred from the GiantPool and there will always be some amount of LP token "stuck" in the GiantPool.

### Proof of Concept

1.  The attacker deploys his own LPToken contract and sends a huge amount of LP tokens to the GiantPool to pass the check in `GiantPoolBase._

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 13: H-8: UserData for balancer pool exits is malformed and will permanently trap users

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

### Example 14: H-4: Potential flash loan attack vulnerability in `getPrice` function of CurveOracle

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/123 

## Found by 
Bauer, helpMePlease
## Summary
During a security review of the `getPrice` function in the CurveOracle, a potential flash loan attack vulnerability was identified.

## Vulnerability Detail
The `getPrice` function retrieves the spot price of each token in a Curve LP pool, calculates the minimum price among them, and multiplies it by the virtual price of the LP token to determine the USD value of the LP token. If the price of one or more tokens in the pool is manipulated, this can cause the minimum price calculation to be skewed, leading to an incorrect USD value for the LP token. This can be exploited by attackers to make a profit at the expense of other users.

## Impact
This vulnerability could potentially allow attackers to manipulate the price of tokens in Curve LP pools and profit at the expense of other users. If exploited, this vulnerability could result in significant financial losses for affected users.

## Code Snippet
https://github.com/sherlock-audit/2023-04-blueberry/blob/96eb1829571dc46e1a387985bd56989702c5e1dc/blueberry-core/contracts/oracle/CurveOracle.sol#L122

## Tool used

Manual Review

## Recommendation
use TWAP to determine the prices of the underlying assets in the pool.

---

### Example 15: M-1: Calculation underflow/overflow in BalancerPairOracle, which will affect pools in Aura Finance

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/11 

## Found by 
n1punp
## Summary
LP price calculation for Balancer Pair in BalancerPairOracle will produce calculation underflow/overflow (so Aura pools won't work too).

## Vulnerability Detail
- The values r0, r1 can underflow, e.g. if resA < resB --> r0 = 0, so it'll go to the else case --> and so `ratio` will be 0 --> `fairResA` calculation will revert upon dividing by 0.
- There are also other math calculations there that will cause reverts, e.g. ratio ** wB will lead to overflow. What you'd need here is Balancer's implementation of `bpow` or similar.

## Impact
LP price for Balancer-like collateral token will revert in most cases, if not all.

## Code Snippet
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/oracle/BalancerPairOracle.sol#L53-L64

## Tool used

Manual Review

## Recommendation
- Change the calculation logic so it aligns with Alpha's original implementation (with precision control), e.g. https://github.com/AlphaFinanceLab/alpha-homora-v2-contract/blob/master/contracts/oracle/BalancerPairOracle.sol#L42-L53 (you can see there's BONE extra precision in each step)



## Discussion

**n1punp**

Escalate for 10 USDC.
I think this is incorrectly **excluded**. The issue is not related to **flashloan** via **BalancerPairOracle**, but rather an organic math overflow/underflow, since the implementation is directly using 0.8.x's default SafeMath mode. Up

*[Content truncated...]*

---

### Example 16: M-6: `LendingPool#flashAction` is broken when trying to refinance position across `LendingPools` due to improper access control

**Source**: Sherlock
**Protocol**: Arcadia
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-12-arcadia-judging/issues/145 

## Found by 
0x52
## Summary

When refinancing an account, `LendingPool#flashAction` is used to facilitate the transfer. However due to access restrictions on `updateActionTimestampByCreditor`, the call made from the new creditor will revert, blocking any account transfers. This completely breaks refinancing across lenders which is a core functionality of the protocol.

## Vulnerability Detail

[LendingPool.sol#L564-L579](https://github.com/sherlock-audit/2023-12-arcadia/blob/main/lending-v2/src/LendingPool.sol#L564-L579)

    IAccount(account).updateActionTimestampByCreditor();

    asset.safeTransfer(actionTarget, amountBorrowed);

    {
        uint256 accountVersion = IAccount(account).flashActionByCreditor(actionTarget, actionData);
        if (!isValidVersion[accountVersion]) revert LendingPoolErrors.InvalidVersion();
    }

We see above that `account#updateActionTimestampByCreditor` is called before `flashActionByCreditor`.

[AccountV1.sol#L671](https://github.com/sherlock-audit/2023-12-arcadia/blob/main/accounts-v2/src/accounts/AccountV1.sol#L671)

    function updateActionTimestampByCreditor() external onlyCreditor updateActionTimestamp { }

When we look at this function, it can only be called by the current creditor. When refinancing a position, this function is actually called by the pending creditor since the `flashaction` should originate from there. This will cause the call to revert,

*[Content truncated...]*

---

### Example 17: M-12: rewardTokens removed from WAuraPool/WConvexPools will be lost forever

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

## Statistics

- Total findings analyzed: 17
- Examples shown: 17
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

