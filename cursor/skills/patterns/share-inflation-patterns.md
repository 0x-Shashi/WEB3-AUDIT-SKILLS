# Share Inflation Security Patterns

## Overview

**Frequency**: 12 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 8 | 4 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Cyfrin, MixBytes, Spearbit

---

## Detection Checklist

- [ ] Check for share inflation vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Inflation attack on empty ticks

**Source**: MixBytes
**Protocol**: Curve Finance
**Impact**: HIGH

**Details**:

##### Description

Each AMM tick represents an empty vault, where shares are issued for collateral. A hacker can manipulate a tick so that it contains just 1 wei share and any amount of collateral. For example, suppose the hacker initially inflates the tick so that it contains 1 wei share and 1 ETH. Next, the hacker sees a victim's transaction in the mempool, which is going to deposit 20 ETH into this tick. The hacker then needs to inflate the tick to contain 1 wei share and 10 ETH + 1 wei right before the victim's transaction.

How many shares will the victim receive in this tick? The victim receives 1 wei share due to a rounding error:
```
1 wei share * 20 ETH / (10 ETH + 1 wei) = 1 wei share
```

Now there are 2 wei shares in total in this tick, one for the victim and one for the hacker.

The hacker then self-liquidates and receives 50% of the ether from the entire tick, which is 15 ETH, even though they initially invested 10 ETH. The profit is +5 ETH.

**How does the hacker inflate the collateral in the tick?**

Step 1. Before the frontrunning, the hacker ensures that the tick contains 1 share and 100+ wei ETH. They can do it using the AMM fee, performing `exchange()` back and forth. This is a heavy operation, plus there may be fees if there are other positions before the hacker's ticks. Therefore, this must be done in advance. After that the hacker self-liquidates 99% of their position, leaving one share. If there are no other positions before the hacker, they only spend

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/Curve%20Finance/Curve%20Stablecoin%20(crvUSD)/README.md#2-inflation-attack-on-empty-ticks)

---

### Example 2: [H-01] ERC4626 mint uses wrong `amount`

**Source**: Code4rena
**Protocol**: Tribe
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by 0xliumin, CertoraInc, Picodes, and Ruhum_

> The docs/video say `ERC4626.sol` is in scope as its part of `TurboSafe`

The `ERC4626.mint` function mints `amount` instead of `shares`.
This will lead to issues when the `asset <> shares` are not 1-to-1 as will be the case for most vaults over time.
Usually, the asset amount is larger than the share amount as vaults receive asset yield.
Therefore, when minting, `shares` should be less than `amount`.
Users receive a larger share amount here which can be exploited to drain the vault assets.

```solidity
function mint(uint256 shares, address to) public virtual returns (uint256 amount) {
    amount = previewMint(shares); // No need to check for rounding error, previewMint rounds up.

    // Need to transfer before minting or ERC777s could reenter.
    asset.safeTransferFrom(msg.sender, address(this), amount);
    _mint(to, amount);

    emit Deposit(msg.sender, to, amount, shares);

    afterDeposit(amount, shares);
}
```

### Proof of Concept

Assume `vault.totalSupply() = 1000`, `totalAssets = 1500`

*   call `mint(shares=1000)`. Only need to pay `1000` asset amount but receive `1000` shares => `vault.totalSupply() = 2000`, `totalAssets = 2500`.
*   call `redeem(shares=1000)`. Receive `(1000 / 2000) * 2500 = 1250` amounts. Make a profit of `250` asset tokens.
*   repeat until `shares <> assets` are 1-to-1

### Recommended Mitigation Steps

In `deposit`:

```diff
function mint(uint256 shares, addr

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-tribe-turbo)

---

### Example 3: [H-03] The price of rsETH could be manipulated by the first staker

**Source**: Code4rena
**Protocol**: Kelp DAO
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-11-kelp/blob/c5fdc2e62c5e1d78769f44d6e34a6fb9e40c00f0/src/LRTDepositPool.sol#L95-L110><br>
<https://github.com/code-423n4/2023-11-kelp/blob/c5fdc2e62c5e1d78769f44d6e34a6fb9e40c00f0/src/LRTOracle.sol#L52-L79>

The first staker can potentially manipulate the price of rsETH through a donation attack, causing subsequent stakers to receive no rsETH after depositing. The first staker can exploit this method to siphon funds from other users.

### Proof of Concept

The mining amount of rsETH is calculated in function `getRsETHAmountToMint` which directly utilizes the total value of the asset divided by the price of a single rsETH.

```solidity
    function getRsETHAmountToMint(
        address asset,
        uint256 amount
    )
        public
        view
        override
        returns (uint256 rsethAmountToMint)
    {
        // setup oracle contract
        address lrtOracleAddress = lrtConfig.getContract(LRTConstants.LRT_ORACLE);
        ILRTOracle lrtOracle = ILRTOracle(lrtOracleAddress);

        // calculate rseth amount to mint based on asset amount and asset exchange rate
        rsethAmountToMint = (amount * lrtOracle.getAssetPrice(asset)) / lrtOracle.getRSETHPrice();
    }
```

Subsequently, the price of rsETH is related to its totalSupply and the total value of deposited assets.

```solidity
    function getRSETHPrice() external view returns (uint256 rsETHPrice) {
        address rsETHTokenAddress = lrtConfig.rsETH();
        uint256 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-11-kelp)

---

### Example 4: H-15: Illuminate PTs can be used to mint other Illuminate PTs

**Source**: Sherlock
**Protocol**: Illuminate
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-illuminate-judging/issues/108 

## Found by 
pashov, Bnke0x0, Jeiwan, IllIllI, cccz, kenzo, HonorLt, Nyx, 0x52

## Summary

Attackers can inflate away all PT value by unlimited minting


## Vulnerability Detail

`Lender.mint()` allows anyone to exchange any supported PT for an Illuminate PT, and Illuminate PTs themselves are supported PTs by the function. By minting Illuminate PTs by providing other Illuminate PTs, an attacker can increase the total supply of Illuminate PTs without the new tokens having any asset backing. Redemptions are based on shares of the total Illuminate PT supply, rather than being redemptions of one underlying for one Illuminate PT, so as the total supply grows, the value of each share decreases.


## Impact

_Permanent freezing of funds_

An attacker is able to inflate away the value of Illuminate PTs, making redemptions worthless, which means lenders of the protocol lose all deposited principal. Since the objective of the project is to convert other projects' PTs into Illuminate PTs, PTs of all underlyings and all maturities are affected, meaning 100% of deposited/lent principal are at risk.

While the Illuminate project does have an emergency `withdraw()` function that would allow an admin to rescue the funds and manually distribute them if they're still in the `Lender` contract, an attacker can wait for `Redeemer.redeem()` to have been called, at which point all PTs of the maturity and underlying w

*[Content truncated...]*

---

### Example 5: [H-05] Inflation of ggAVAX share price by first depositor

**Source**: Code4rena
**Protocol**: GoGoPool
**Impact**: HIGH

**Details**:

Inflation of `ggAVAX` share price can be done by depositing as soon as the vault is created.

Impact:

1.  Early depositor will be able steal other depositors funds
2.  Exchange rate is inflated. As a result depositors are not able to deposit small funds.

### Proof of Concept

If `ggAVAX` is not seeded as soon as it is created, a malicious depositor can deposit 1 WEI of AVAX to receive 1 share.<br>
The depositor can donate WAVAX to the vault and call `syncRewards`. This will start inflating the price.

When the attacker front-runs the creation of the vault, the attacker:

1.  Calls `depositAVAX` to receive 1 share
2.  Transfers `WAVAX` to `ggAVAX`
3.  Calls `syncRewards` to inflate exchange rate

The issue exists because the exchange rate is calculated as the ratio between the `totalSupply` of shares and the `totalAssets()`.<br>
When the attacker transfers `WAVAX` and calls `syncRewards()`, the `totalAssets()` increases gradually and therefore the exchange rate also increases.

` convertToShares  `: <https://github.com/code-423n4/2022-12-gogopool/blob/aec9928d8bdce8a5a4efe45f54c39d4fc7313731/contracts/contract/tokens/upgradeable/ERC4626Upgradeable.sol#L123>

    	function convertToShares(uint256 assets) public view virtual returns (uint256) {
    		uint256 supply = totalSupply; // Saves an extra SLOAD if totalSupply is non-zero.

    		return supply == 0 ? assets : assets.mulDivDown(supply, totalAssets());
    	}

Its important to note that while it is true that cycle length

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-gogopool)

---

### Example 6: [H-02] Withdrawers can get more value returned than expected with reentrant call

**Source**: Code4rena
**Protocol**: Sandclock
**Impact**: HIGH

**Details**:

_Submitted by camden, also found by cmichel and harleythedog_

The impact of this is that users can get significantly more UST withdrawn than they would be alotted if they had done non-reentrant withdraw calls.

#### Proof of Concept

Here's an outline of the attack:

Assume the vault has 100 UST in it.
The attacker makes two deposits of 100UST and waits for them to be withdrawable.
The attacker triggers a withdraw one of their deposit positions.
The vault code executes until it reaches this point: <https://github.com/code-423n4/2022-01-sandclock/blob/a90ad3824955327597be00bb0bd183a9c228a4fb/sandclock/contracts/Vault.sol#L565>
Since the attacker is the claimer, the vault will call back to the attacker.
Inside `onDepositBurned`, trigger another 100 UST deposit.
Since `claimers.onWithdraw` has already been called, reducing the amount of shares, but the UST hasn't been transferred yet, the vault will compute the amount of UST to be withdrawn based on an unexpected value for `_totalUnderlyingMinusSponsored` (300).
<https://github.com/code-423n4/2022-01-sandclock/blob/a90ad3824955327597be00bb0bd183a9c228a4fb/sandclock/contracts/Vault.sol#L618>

After the attack, the attacker will have significantly more than if they had withdrawn without reentrancy.

Here's my proof of concept showing a very similar exploit with `deposit`, but I think it's enough to illustrate the point. I have a forge repo if you want to see it, just ping me on discord.
<https://gist.github.com/CamdenClark/abc67b

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-sandclock)

---

### Example 7: [M-04] Malicious users can front-run to cause a denial of service (DoS) for StakedUSDe due to MinShares checks

**Source**: Code4rena
**Protocol**: Ethena Labs
**Impact**: MEDIUM

**Details**:

Malicious users can transfer `USDe` token to `StakedUSDe` protocol directly lead to a denial of service (DoS) for StakedUSDe due to the limit shares check.

### Proof of Concept

User deposit `USDe` token to `StakedUSDe` protocol to get share via invoke external `deposit` function. Let's see how share is calculate:

```solidity
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view virtual returns (uint256) {
        return assets.mulDiv(totalSupply() + 10 ** _decimalsOffset(), totalAssets() + 1, rounding);
    }
```

Since `decimalsOffset() == 0` and totalAssets equal the balance of `USDe` in this protocol

```solidity
    function totalAssets() public view virtual override returns (uint256) {
        return _asset.balanceOf(address(this));
    }
```

$$
f(share) = (USDeAmount \ast totalSupply) / (totalUSDeAssets() + 1)
$$

The minimum share is set to 1 ether.

```solidity
  uint256 private constant MIN_SHARES = 1 ether;
```

Assuming malicious users transfer 1 ether of `USDe` into the protocol and receive ZERO shares, how much tokens does the next user need to pay if they want to exceed the minimum share limit of 1 ether? That would be 1 ether times 1 ether, which is a substantial amount.

I add a test case in `StakedUSDe.t.sol`:

```solidity
  function testMinSharesViolation() public {
    address malicious = vm.addr(100);

    usdeToken.mint(malicious, 1 ether);
    usdeToken.mint(alice, 1000 ether);

    //assume malicious user deposit 1 ethe

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-10-ethena)

---

### Example 8: Inflation attack can cause early users to lose their deposit

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

### Example 9: [H-01] StakedCitadel doesn't use correct balance for internal accounting

**Source**: Code4rena
**Protocol**: BadgerDAO
**Impact**: HIGH

**Details**:

_Submitted by Ruhum, also found by cccz, wuwe1, VAD37, TrungOre, shenwilly, minhquanym, kyliek, danb, gs8nrv, and rayn_

<https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L291-L295>

<https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L772-L776>

<https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L881-L893>

### Impact

The StakedCitadel contract's `balance()` function is supposed to return the balance of the vault + the balance of the strategy. But, it only returns the balance of the vault. The balance is used to determine the number of shares that should be minted when depositing funds into the vault and the number of shares that should be burned when withdrawing funds from it.

Since most of the funds will be located in the strategy, the vault's balance will be very low. Some of the issues that arise from this:

**You can't deposit to a vault that already minted shares but has no balance of the underlying token**:

1.  fresh vault with 0 funds and 0 shares
2.  Alice deposits 10 tokens. She receives 10 shares back (<https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L887-L888>)
3.  Vault's tokens are deposited into the strategy (now `balance == 0` and `totalSupply == 10`)
4.  Bob tries to deposit but the transaction fails because the contract tries to divide by zero: <https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/Sta

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-badger-citadel)

---

### Example 10: SharesManager._mintShares - Depositors may receive zero shares due to front-running

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: MEDIUM

**Details**:

## Medium Risk Report

## Severity 
Medium Risk

## Context 
SharesManager.1.sol#L202

## Description 
The number of shares minted to a depositor is determined by 

\[
\text{shares} = \frac{\text{underlyingAssetValue} \times \text{totalSupply()}}{\text{oldTotalAssetBalance}}
\]

Potential attackers can spot a call to `UserDepositManagerV1._deposit` and front-run it with a transaction that sends wei to the contract (by self-destructing another contract and sending the funds to it), causing the victim to receive fewer shares than expected. 

More specifically, if `oldTotalAssetBalance()` is greater than `underlyingAssetValue * totalSupply()`, then the number of shares the depositor receives will be 0, although `underlyingAssetValue` will still be pulled from the depositors balance. 

An attacker with access to enough liquidity and the mempool data can spot a call to `UserDepositManagerV1._deposit` and front-run it by sending at least 

\[
\text{totalSupplyBefore} \times (\text{underlyingAssetValue} - 1) + 1 \text{ wei}
\]

to the contract. This way, the victim will get 0 shares, but `underlyingAssetValue` will still be pulled from their account balance. 

In this case, the attacker does not necessarily have to be a whitelisted user, and it is important to mention that the funds sent by them cannot be directly claimed back; rather, they will increase the price of the share.

The attack vector mentioned above is the general front-run case. The most profitable attack vector will 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 11: M-4: Front run `distributeRewards()` can steal the newly added rewards

**Source**: Sherlock
**Protocol**: Merit Circle
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-merit-circle-judging/issues/106 

## Found by 
WATCHPUG, hickuphh3, hyh

## Summary

A surge of pointsPerShare on each `distributeRewards()` call can be used by the attacker to steal part of the newly added rewards.

## Vulnerability Detail

Every time the `distributeRewards()` gets called, there will be a surge of `pointsPerShare` for the existing stakeholders.

This enables a well-known attack vector, in which the attacker will deposit a huge amount of underlying tokens and take a large portion of the pool, then trigger the surge, and exit right after.

## Impact

While the existence of the `MIN_LOCK_DURATION` prevented the usage of flashloan, it's still possible for the attackers with sufficient funds or can acquire sufficient funds in other ways.

In which case, the attack is quite practical and effectively steal the major part of the newly added rewards

## Code Snippet

https://github.com/sherlock-audit/2022-10-merit-circle/blob/main/merit-liquidity-mining/contracts/base/BasePool.sol#L95-L98

https://github.com/sherlock-audit/2022-10-merit-circle/blob/main/merit-liquidity-mining/contracts/base/AbstractRewards.sol#L89-L99

## Tool used

Manual Review

## Recommendation

Consider using a `rewardRate`-based gradual release model, pioneered by Synthetix's StakingRewards contract.

See: https://github.com/Synthetixio/synthetix/blob/develop/contracts/StakingRewards.sol#L113-L132

## Discussion

**federava**

Raising the MIN_LO

*[Content truncated...]*

---

### Example 12: M-5: First user can inflate `pointsPerShare` and cause `_correctPoints()` to revert due to overflow

**Source**: Sherlock
**Protocol**: Merit Circle
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-merit-circle-judging/issues/103 

## Found by 
WATCHPUG, bin2chen

## Summary

`pointsPerShare` can be manipulated by the first user and cause `_correctPoints()` to revert later.

## Vulnerability Detail

`POINTS_MULTIPLIER` is an unusually large number as a precision fix for `pointsPerShare`: `type(uint128).max ~= 3.4e38`.

This makes it possible for the first user to manipulate the `pointsPerShare` to near `type(int256).max` and a later regular user can trigger the overflow of `_shares * _shares * ` in `_correctPoints()`.

### PoC

1. `deposit(1 wei)` lock for 10 mins, `mint()` 1 wei of shares;
2. `distributeRewards(1000e18)`, `pointsPerShare += 1000e18 * type(uint128).max / 1` == 3e59;
3. the victim `deposit(100e18)` for 1 year, `mint()` 150e18 shares;
3. `_shares * pointsPerShare == -150e18 * 3e59 == -4.5e+79` which exceeds `type(int256).min`, thus the transaction will revert.

The attacker can also manipulate `pointsPerShare` to a slightly smaller number, so that `_shares * pointsPerShare` will only overflow after a certain amount of deposits.

## Impact

By manipulating the `pointPerShare` precisely, the attacker can make it possible for the system to run normally for a little while and only to explode after a certain amount of deposits, as the `pointsPerShare` will be too large by then and all the `_mint` and `_burn` will revert due to overflow in `_correctPoints()`.

The users who deposited before will be unable to wit

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 12
- Examples shown: 12
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

