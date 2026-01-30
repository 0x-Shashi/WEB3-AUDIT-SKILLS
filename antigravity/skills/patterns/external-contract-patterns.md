# External Contract Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 4 | 0 | 0 |

**Common Sources**: Sherlock, TrailOfBits

---

## Detection Checklist

- [ ] Check for external contract vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: receiveFlashLoan does not account for fees

**Source**: TrailOfBits
**Protocol**: Lindy Labs Sandclock
**Impact**: HIGH

**Details**:

## Diculty: High

## Type: Data Validation

### Target: 
`src/steth/scWETHv2.sol`, `src/steth/scUSDCv2.sol`

### Description
The `receiveFlashLoan` functions of the `scWETHv2` and `scUSDCv2` vaults ignore the Balancer flash loan fees and repay exactly the amount that was loaned. This is not currently an issue because the Balancer vault does not charge any fees for flash loans. However, if Balancer implements fees for flash loans in the future, the Sandclock vaults would be prevented from withdrawing investments back into the vault.

```solidity
function flashLoan(
    IFlashLoanRecipient recipient,
    IERC20[] memory tokens,
    uint256[] memory amounts,
    bytes memory userData
) external override nonReentrant whenNotPaused {
    uint256[] memory feeAmounts = new uint256[](tokens.length);
    uint256[] memory preLoanBalances = new uint256[](tokens.length);
    for (uint256 i = 0; i < tokens.length; ++i) {
        IERC20 token = tokens[i];
        uint256 amount = amounts[i];
        preLoanBalances[i] = token.balanceOf(address(this));
        feeAmounts[i] = _calculateFlashLoanFeeAmount(amount);
        token.safeTransfer(address(recipient), amount);
    }
    recipient.receiveFlashLoan(tokens, amounts, feeAmounts, userData);
    for (uint256 i = 0; i < tokens.length; ++i) {
        IERC20 token = tokens[i];
        uint256 preLoanBalance = preLoanBalances[i];
        uint256 postLoanBalance = token.balanceOf(address(this));
        uint256 receivedFeeAmount = postLoanBal

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/2023-07-sandclock-securityreview.pdf)

---

### Example 2: M-12: Vault_Synths.sol code does not consider protocol exchange fee when evaluating the Collateral worth

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/120 

## Found by 
ctf\_sec

## Summary

Vault_Synths.sol code does not consider protocol fee.

## Vulnerability Detail

If we look into the good-written documentation:

https://github.com/kree-dotcom/isomorph/blob/789338c8979ab75b8187781a2500908bb26dcdea/docs/Vault_Lyra.md#getwithdrawalfee

I want to quote:

> Because the withdrawalFee of a lyra LP pool can vary we must fetch it each time it is needed to ensure we use an accurate value. LP tokens are devalued by this as a safety measure as any liquidation would include selling the collateral and so should factor in that cost to ensure it is profitable.

In Vault_Lyra.sol, when calculating the collateral of the LP token, the fee is taken into consideration.

```solidity
function priceCollateralToUSD(bytes32 _currencyKey, uint256 _amount) public view override returns(uint256){
     //The LiquidityPool associated with the LP Token is used for pricing
    ILiquidityPoolAvalon LiquidityPool = ILiquidityPoolAvalon(collateralBook.liquidityPoolOf(_currencyKey));
    //we have already checked for stale greeks so here we call the basic price function.
    uint256 tokenPrice = LiquidityPool.getTokenPrice();          
    uint256 withdrawalFee = _getWithdrawalFee(LiquidityPool);
    uint256 USDValue  = (_amount * tokenPrice) / LOAN_SCALE;
    //we remove the Liquidity Pool withdrawalFee 
    //as there's no way to remove the LP position without paying this.
    ui

*[Content truncated...]*

---

### Example 3: M-1: When one of the plugins is broken or paused, `deposit()` or `withdraw()` of the whole Vault contract can malfunction

**Source**: Sherlock
**Protocol**: Mycelium
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-mycelium-judging/tree/main/006-M 

## Found by 
ctf\_sec, IllIllI, berndartmueller, ak1, WATCHPUG

## Summary

One malfunctioning plugin can result in the whole Vault contract malfunctioning.

## Vulnerability Detail

A given plugin can temporally or even permanently becomes malfunctioning (cannot deposit/withdraw) for all sorts of reasons.

Eg, Aave V2 Lending Pool can be paused, which will prevent multiple core functions that the Aave v2 plugin depends on from working, including `lendingPool.deposit()` and `lendingPool.withdraw()`.

https://github.com/aave/protocol-v2/blob/master/contracts/protocol/lendingpool/LendingPool.sol#L54

```soldity
  modifier whenNotPaused() {
    _whenNotPaused();
    _;
  }
```

https://github.com/aave/protocol-v2/blob/master/contracts/protocol/lendingpool/LendingPool.sol#L142-L146

```solidity
  function withdraw(
    address asset,
    uint256 amount,
    address to
  ) external override whenNotPaused returns (uint256) {
```

That's because the deposit will always goes to the first plugin, and withdraw from the last plugin first.

## Impact

When Aave V2 Lending Pool is paused, users won't be able to deposit or withdraw from the vault.

Neither can the owner remove the plugin nor rebalanced it to other plugins to resume operation.

Because withdrawal from the plugin can not be done, and removing a plugin or rebalancing both rely on this.

## Code Snippet

https://github.com/sherlock-audit/2022-

*[Content truncated...]*

---

### Example 4: M-2: Lyra vault underestimates the collateral value

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/242 

## Found by 
hansfriese

## Summary

Lyra vault subtracts the withdrawal fee while calculating the collateral value in USD, and it does not match the actual Lyra Pool implementation.

## Vulnerability Detail

The user's collateral value is estimated using the function `priceCollateralToUSD()` at `Vault_Lyra.sol#L77` as follows.

```solidity
function priceCollateralToUSD(bytes32 _currencyKey, uint256 _amount) public view override returns(uint256){
        //The LiquidityPool associated with the LP Token is used for pricing
    ILiquidityPoolAvalon LiquidityPool = ILiquidityPoolAvalon(collateralBook.liquidityPoolOf(_currencyKey));
    //we have already checked for stale greeks so here we call the basic price function.
    uint256 tokenPrice = LiquidityPool.getTokenPrice();
    uint256 withdrawalFee = _getWithdrawalFee(LiquidityPool);
    uint256 USDValue  = (_amount * tokenPrice) / LOAN_SCALE;
    //we remove the Liquidity Pool withdrawalFee
    //as there's no way to remove the LP position without paying this.
    uint256 USDValueAfterFee = USDValue * (LOAN_SCALE- withdrawalFee)/LOAN_SCALE;
    return(USDValueAfterFee);
}
```

So it is understood that the withdrawal fee is removed to get the reasonable value of the collateral.
But according to the [Lyra Pool implementation](https://github.com/lyra-finance/lyra-protocol/blob/master/contracts/LiquidityPool.sol#L341), the token price used for withdraw

*[Content truncated...]*

---

### Example 5: H-3: Users who deposit Lyra LP as collateral will lose OP vault rewards

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/78 

## Found by 
0x52

## Summary

Optimism currently offers yield farming opportunities for Lyra LPs, see [OP Reward Announcement](https://blog.lyra.finance/incentives-launch/). Every 2 weeks Lyra LPs split a claimable pool. When they use their Lyra LP as collateral, it is transferred to the Lyra vault which means that all OP will be instead claimable by the vault. The vault currently doesn't implement any method to claim or distribute those tokens. The result is a loss of user yield on their Lyra tokens. Aside from the loss of funds, it also highly disincentivizes users from using Lyra tokens as collateral.

## Vulnerability Detail

See summary.

## Impact

Lyra LPs that use their tokens as collateral will lose all their OP rewards

## Code Snippet

[Vault_Lyra.sol](https://github.com/sherlock-audit/2022-11-isomorph/blob/main/contracts/Isomorph/contracts/Vault_Lyra.sol#L1)

## Tool used

Manual Review

## Recommendation

It's unclear how long OP rewards will continue but it seems like other protocols have been getting 6 months of incentives. Since they are temporary I would recommend not integrating reward distribution directly into the contract. I would recommend adding a function to claim rewards to the Isomorph treasury. After the rewards end, the Isomorph should create an airdrop to distribute those tokens to users during that period of time.

## Discussion

**kree-dotcom**

Sponsor confirmed, wi

*[Content truncated...]*

---

### Example 6: H-2: ShortLongSpell#openPosition uses the wrong balanceOf when determining how much collateral to put

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

### Example 7: M-5: `getPositionRisk()` will return a wrong value of risk

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

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

