# Vault Security Patterns

## Overview

**Frequency**: 9 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 6 | 3 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Pashov Audit Group, Cyfrin, Spearbit

---

## Detection Checklist

- [ ] Check for vault vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-04] Users who deposit in one vault can lose all deposits and receive nothing when counterparty vault has no deposits

**Source**: Code4rena
**Protocol**: Y2k Finance
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-09-y2k-finance/blob/main/src/Controller.sol#L148-L192>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/main/src/Vault.sol#L350-L352>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/main/src/Vault.sol#L203-L234>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/main/src/Vault.sol#L378-L426>

### Impact

For a market, if users only deposit in the hedge vault or only deposit in the risk vault but not in both, then these users will lose their deposits and receive nothing when they call the following `withdraw` function after the depeg event occurs.

If the vault that has deposits is called Vault A, and the counterparty vault that has no deposit is called Vault B, then:

*   As shown by the `triggerDepeg` function below, when executing `insrVault.sendTokens(epochEnd, address(riskVault))` and `riskVault.sendTokens(epochEnd, address(insrVault))`, the deposits of Vault A are transferred to Vault B but nothing is transferred to Vault A since Vault B has no deposit;
*   When `triggerDepeg` executes `insrVault.setClaimTVL(epochEnd, riskVault.idFinalTVL(epochEnd))` and `riskVault.setClaimTVL(epochEnd, insrVault.idFinalTVL(epochEnd))`, Vault B's `idClaimTVL[id]` is set to Vault A's `idFinalTVL(epochEnd))` but Vault A's `idClaimTVL[id]` is set to 0 because Vault B's `idFinalTVL(epochEnd)` is 0.

Because of these, calling the `beforeWithdraw` function below will return a 0 `entitledAmount`, and calling `withdraw` then transfers th

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-y2k-finance)

---

### Example 2: H-4: Victim's fund can be stolen due to rounding error and exchange rate manipulation

**Source**: Sherlock
**Protocol**: Napier
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-01-napier-judging/issues/94 

The protocol has acknowledged this issue.

## Found by 
Bandit, LTDingZhen, cawfree, jennifer37, xAlismx, xiaoming90
## Summary

Victim's funds can be stolen by malicious users by exploiting the rounding error and through exchange rate manipulation.

## Vulnerability Detail

The LST Adaptor attempts to guard against the well-known vault inflation attack by reverting the TX when the amount of shares minted is rounded down to zero in Line 78 below.

https://github.com/sherlock-audit/2024-01-napier/blob/main/napier-v1/src/adapters/BaseLSTAdapter.sol#L71

```solidity
File: BaseLSTAdapter.sol
71:     function prefundedDeposit() external nonReentrant returns (uint256, uint256) {
72:         uint256 bufferEthCache = bufferEth; // cache storage reads
73:         uint256 queueEthCache = withdrawalQueueEth; // cache storage reads
74:         uint256 assets = IWETH9(WETH).balanceOf(address(this)) - bufferEthCache; // amount of WETH deposited at this time
75:         uint256 shares = previewDeposit(assets);
76: 
77:         if (assets == 0) return (0, 0);
78:         if (shares == 0) revert ZeroShares();
```

However, this control alone is not sufficient to guard against vault inflation attacks. 

Let's assume the following scenario (ignoring fee for simplicity's sake):

1. The victim initiates a transaction that deposits 10 ETH as the underlying asset when there are no issued estETH shares.
2. The attacker obse

*[Content truncated...]*

---

### Example 3: H-2: AutoRoller#eject can be used to steal all the yield from vault's YTs

**Source**: Sherlock
**Protocol**: Sense
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/22 

## Found by 
0x52

## Summary

AutoRoller#eject collects all the current yield of the YTs, combines the users share of the PTs and YTs then sends the user the entire target balance of the contract. The problem is that combine claims the yield for ALL YTs, which sends the AutoRoller target assets. Since it sends the user the entire target balance of the contract it accidentally sends the user the yield from all the pool's YTs. 

## Vulnerability Detail

    function eject(
        uint256 shares,
        address receiver,
        address owner
    ) public returns (uint256 assets, uint256 excessBal, bool isExcessPTs) {

        ...

        //@audit call of interest
        (excessBal, isExcessPTs) = _exitAndCombine(shares);

        _burn(owner, shares); // Burn after percent ownership is determined in _exitAndCombine.

        if (isExcessPTs) {
            pt.transfer(receiver, excessBal);
        } else {
            yt.transfer(receiver, excessBal);
        }

        //@audit entire asset (adapter.target) balance transferred to caller, which includes collected YT yield and combined
        asset.transfer(receiver, assets = asset.balanceOf(address(this)));

        emit Ejected(msg.sender, receiver, owner, assets, shares,
            isExcessPTs ? excessBal : 0,
            isExcessPTs ? 0 : excessBal
        );
    }

    function _exitAndCombine(uint256 shares) internal returns (uint256, bool) {

*[Content truncated...]*

---

### Example 4: H-3: AutoRoller#eject can be used to steal all the yield from vault's YTs

**Source**: Sherlock
**Protocol**: Sense
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/22 

## Found by 
0x52

## Summary

AutoRoller#eject collects all the current yield of the YTs, combines the users share of the PTs and YTs then sends the user the entire target balance of the contract. The problem is that combine claims the yield for ALL YTs, which sends the AutoRoller target assets. Since it sends the user the entire target balance of the contract it accidentally sends the user the yield from all the pool's YTs. 

## Vulnerability Detail

    function eject(
        uint256 shares,
        address receiver,
        address owner
    ) public returns (uint256 assets, uint256 excessBal, bool isExcessPTs) {

        ...

        //@audit call of interest
        (excessBal, isExcessPTs) = _exitAndCombine(shares);

        _burn(owner, shares); // Burn after percent ownership is determined in _exitAndCombine.

        if (isExcessPTs) {
            pt.transfer(receiver, excessBal);
        } else {
            yt.transfer(receiver, excessBal);
        }

        //@audit entire asset (adapter.target) balance transferred to caller, which includes collected YT yield and combined
        asset.transfer(receiver, assets = asset.balanceOf(address(this)));

        emit Ejected(msg.sender, receiver, owner, assets, shares,
            isExcessPTs ? excessBal : 0,
            isExcessPTs ? 0 : excessBal
        );
    }

    function _exitAndCombine(uint256 shares) internal returns (uint256, bool) {

*[Content truncated...]*

---

### Example 5: [H-05] Fee calculation mismatch in `mint`, `deposit`, `redeem` and `withdraw`

**Source**: Pashov Audit Group
**Protocol**: Astrolab
**Impact**: HIGH

**Details**:

**Severity**

**Impact:** Medium, fee will be a little higher/lower

**Likelihood:** High, because it happens in every call to mint and deposit functions

**Description**

When users calls `mint(shares)` code calls `_deposit(previewMint(_shares), _shares` and `previewMint(shares) = convertToAssets(shares).addBp()`.
When users calls `deposit(amount)` code calls `_deposit(_amount, previewDeposit(_amount)` and `previewDeposit(amount) = convertToShares(amount).subBp`.

Let's assume that price is 1:1 and fee is 10% and check the both case:

1. If user wants to mint 100 share then he would call `mint(100)` and code would calculate `amount = previewMint(100) = convertToAssets(100).addBp(10%) = 110`. So in the end user would pay 110 asset and receive 100 shares and 10 asset will be fee.
2. If users wants to deposit 110 asset then he would call `deposit(110)` and code would calculate `share = previewDeposit(110) = convertToShare(110).subBp(10%) = 99`. So in the end user would pay 11 asset and receive 99 share and 11 asset will be fee.

As you can see the `deposit()` call overcharge the user. The reason is that code calculates fee based on user-specified amount by using `subBp()` but user-specified amount is supposed to be `amount + fee` so the calculation for fee should be `.... * base / (base +fee)`.

---

When users call `redeem(shares)` code calls `_withdraw(previewRedeem(_shares), _shares)` and `previewRdeem(shares) = convertToAssets(_shares).subBp()`.

When users call `withdraw()

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Astrolab-security-review.md)

---

### Example 6: Inflation attack can cause early users to lose their deposit

**Source**: Cyfrin
**Protocol**: Stakepet
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** A malicious `StakePet` contract creator can steal funds from depositors by launching a typical inflation attack. To execute the attack, the creator can first deposit `1 wei` to get `1 wei` of ownership. Creator can subsequently send a big amount of collateral directly to the `StakePet` contract - this will hugely inflate the value of the single share.

Now, all subsequent pet owners who deposit their collateral will get no ownership in return. The `StakePet::ownershipToMint` function uses `StakePet::totalValue` to calculate the ownership of a new depositor. While the total ownership represented by `s_totalOwnership` remains the same `1 wei`, the `totalValueBefore` is a huge number, thanks to a large direct deposit done by the creator. This ensures that the 1 wei of share represents a huge value of collateral & causes the ownership of new depositors to round to 0.

**Impact:** Potential complete loss of funds for new depositors, given they receive no ownership in exchange for their deposited tokens.

**Proof of Concept:**
- Bob, a malicious actor, initiates the StakePet contract.
- By calling `StakePet::create`, Bob creates a pet depositing a mere `1 wei`, which grants him `1 wei` of ownership.
- Bob then directly transfers a significant amount, like 10 ether, to the `StakePet` contract.
- Consequently, a single `1 wei` share becomes equivalent to `10 ether`.
- An innocent user, Pete, tries to create a pet by calling `StakePet::create` and 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-stakepet.md)

---

### Example 7: M-8: asking for the wrong address for `balanceOf()`

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

### Example 8: Users depositing to a pool with unrealized losses will take on the losses

**Source**: Spearbit
**Protocol**: Maple Finance
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- `pool-v2::Pool.sol#L278`
- `pool-v2::Pool.sol#L275`

## Description
The pool share price used for deposits is always the `totalAssets() / totalSupply`. However, the pool share price when redeeming is `totalAssets() - unrealizedLosses() / totalSupply`. The `unrealizedLosses` value is increased by loan impairments (`LM.impairLoan`) or when starting to trigger a default with a liquidation (`LM.triggerDefault`). The `totalAssets` are only reduced by this value when the loss is realized in `LM.removeLoanImpairment` or `LM.finishCollateralLiquidation`.

This leads to a time window where deposits use a much higher share price than current redemptions and future deposits. Users depositing to the pool during this time window are almost guaranteed to incur losses when they are realized. In the worst case, a `Pool.deposit` might even be (accidentally) front-run by a loan impairment or liquidation.

## Recommendation
Make it very clear to the users when there are unrealized losses and communicate that it is a bad time to deposit. Furthermore, consider adding an `expectedMinimumShares` parameter that is checked against the actual minted shares. This ensures that users don't accidentally lose shares when front-run. Note that this would need to be a new `deposit(uint256 assets_, address receiver_, uint256 expectedMinimumShares_)` function to not break the ERC4626 compatibility. 

The `Pool.mint` function has a similar issue, whereas the `Pool.mintWithP

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/MapleV2.pdf)

---

### Example 9: [M-01] Vault rebalancing can be exploited if two vaults rebalance into the same vault

**Source**: Code4rena
**Protocol**: Mimo DeFi
**Impact**: MEDIUM

**Details**:

_Submitted by 0x52, also found by ayeslick_

User funds stolen.

### Proof of Concept

Swap data is completely arbitrary and can be used to swap though malicious ERC20 tokens allowing control transfer. This control transfer would allow the attacker to call rebalance on a second vault and exploit both as long as both vaults rebalance into the same vault.

Assumptions:<br>
Vault A and C both rebalance into vault B (i.e. value is transferred from vault A and C to vault B)<br>
Vault A and C are both eligible for rebalances<br>

Vault A -<br>
Value: $100<br>
Flashloan value: 50<br>

Vault B -<br>
Value: $100<br>

Vault C -<br>
Value: $100<br>
Flashloan value: 50<br>

1.  User calls rebalance on vault A to trigger it rebalancing to vault B, storing vault B's value as $100

2.  During the swap control is transferred due to use of malicious ERC20 specified in swap data

3.  Malicious token calls rebalance on vault C to trigger a rebalancing to vault B, storing vault B's value as $100 because Vault B's value hasn't been modified yet.

4.  Swap data in vault C rebalance swaps flashloan C to $50 worth of asset B

5.  Vault C rebalance deposits swap funds into vault B

6.  Vault C rebalance withdraws from vault C to pay back flashloan C

7.  Vault C rebalance validates that the value of B = $150 ( 100 + 50 ) and finishes, resuming Vault A rebalance

8.  Vault A rebalance finishes its swap, siphoning off the swapped funds to attacker through the malicious pool

9.  Vault A rebalance doesn

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-mimo)

---

## Statistics

- Total findings analyzed: 9
- Examples shown: 9
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

