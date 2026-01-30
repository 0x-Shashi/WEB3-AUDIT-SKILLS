# ERC4626 Security Patterns

## Overview

**Frequency**: 28 occurrences (0.06% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 10 | 16 | 2 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for erc4626 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: An attacker can freeze all incoming deposits and brick the oracle members' reporting system with only 1 wei

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

**Context:** SharesManager.1.sol#L195-L206

**Description:** An attacker can brick or lock all deposited user funds and also prevent oracle members from reaching a quorum when there are earnings to be distributed as rewards. Consider the following scenario:

1. The attacker forcefully sends 1 wei to the River contract using, e.g., `selfdestruct`. The attacker must ensure this transaction occurs before any other users deposit their funds in the contract. The attacker can observe the mempool and front-run the initial user deposit. Now, `b = _assetBalance() > 0` is at least 1 wei.
   
2. An allowed user tries to deposit funds into the River protocol. The call eventually ends up in `_mintShares(o, x)` and in the first line, `oldTotalAssetBalance = _assetBalance() - x`. Here, `_assetBalance()` represents the updated River balance after accounting for the user deposit `x`. So, `_assetBalance()` is now `b + x + ...` and `oldTotalAssetBalance = b + ...` where the `...` includes the beacon balance sum, deposited amounts for validators in the queue, etc. (which is probably 0 by this point). Therefore, `oldTotalAssetBalance > 0` means that the following if block is skipped:

   ```javascript
   if (oldTotalAssetBalance == 0) {
       _mintRawShares(_owner, _underlyingAssetValue);
       return _underlyingAssetValue;
   }
   ```

   It goes directly to the else block for the first allowed user deposit:

   ```javascript
   else {
       uint256 sharesToMint = 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 2: WithdrawProxy allows redemptions before PublicVault callstransferWithdrawReserve

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
`WithdrawProxy.sol#L172-L175`

## Description
Anytime there is a withdrawal pending (i.e., someone holds WithdrawProxy shares), shares may be redeemed as long as `totalAssets() > 0` and `s.finalAuctionEnd == 0`. Under normal operating conditions, `totalAssets()` becomes greater than 0 when the `PublicVault` calls `transferWithdrawReserve`. 

`totalAssets()` can also be increased to a non-zero value by anyone transferring WETH to the contract. If this occurs and a user attempts to redeem, they will receive a smaller share than they are owed.

### Exploit Scenario
- Depositor redeems from `PublicVault` and receives WithdrawProxy shares.
- Malicious actor deposits a small amount of WETH into the WithdrawProxy.
- Depositor accidentally redeems, or is tricked into redeeming, from the WithdrawProxy while `totalAssets()` is smaller than it should be.
- `PublicVault` properly processes epoch and full `withdrawReserve` is sent to the WithdrawProxy.
- All remaining holders of WithdrawProxy shares receive an outsized share as the previous shares were redeemed for the incorrect value.

## Recommendation

### Option 1
Consider being explicit in opening the WithdrawProxy for redemptions (`redeem/withdraw`) by requiring `s.withdrawReserveReceived` to be a non-zero value:

```solidity
if (s.finalAuctionEnd != 0) {
    // Updated condition
    if (s.finalAuctionEnd != 0 || s.withdrawReserveReceived == 0) {
        // if finalAuctionEnd is 0, no auctions were

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 3: [H-04] First depositor can break minting of shares

**Source**: Code4rena
**Protocol**: Rubicon
**Impact**: HIGH

**Details**:

_Submitted by MiloTruck, also found by cccz, oyc_109, VAD37, PP1004, SmartSek, minhquanym, unforgiven, berndartmueller, WatchPug, CertoraInc, and sorrynotsorry_

The attack vector and impact is the same as [TOB-YEARN-003](https://github.com/yearn/yearn-security/blob/master/audits/20210719\_ToB_yearn_vaultsv2/ToB\_-\_Yearn_Vault_v\_2\_Smart_Contracts_Audit_Report.pdf), where users may not receive shares in exchange for their deposits if the total asset amount has been manipulated through a large donation.

### Proof of Concept

In `BathToken.sol:569-571`, the allocation of shares is calculated as follows:

```js
(totalSupply == 0) ? shares = assets : shares = (
    assets.mul(totalSupply)
).div(_pool);
```

An early attacker can exploit this by:

*   Attacker calls `openBathTokenSpawnAndSignal()` with `initialLiquidityNew = 1`, creating a new bath token with `totalSupply = 1`
*   Attacker transfers a large amount of underlying tokens to the bath token contract, such as `1000000`
*   Using `deposit()`, a victim deposits an amount less than `1000000`, such as `1000`:
    *   `assets = 1000`
    *   `(assets * totalSupply) / _pool = (1000 * 1) / 1000000 = 0.001`, which would round down to `0`
    *   Thus, the victim receives no shares in return for his deposit

To avoid minting 0 shares, subsequent depositors have to deposit equal to or more than the amount transferred by the attacker. Otherwise, their deposits accrue to the attacker who holds the only share.

```js
it("Victim

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-rubicon)

---

### Example 4: [H-01] ERC4626 mint uses wrong `amount`

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

### Example 5: H-1: Attacker can manipulate the pricePerShare to profit from future users' deposits

**Source**: Sherlock
**Protocol**: Mycelium
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-mycelium-judging/tree/main/001-H 

## Found by 
Ruhum, ctf\_sec, cccz, joestakey, ellahi, \_\_141345\_\_, 8olidity, hansfriese, minhquanym, 0x52, caventa, rvierdiiev, Sm4rty, rbserver, IllIllI, sorrynotsorry, JohnSmith, defsec, WATCHPUG, berndartmueller, ak1

## Summary

By manipulating and inflating the pricePerShare to a super high value, the attacker can cause all future depositors to lose a significant portion of their deposits to the attacker due to precision loss.

## Vulnerability Detail

A malicious early user can `deposit()` with `1 wei` of `LINK` token as the first depositor of the Vault, and get `(1 * STARTING_SHARES_PER_LINK) wei` of shares.

Then the attacker can send `STARTING_SHARES_PER_LINK - 1` of `LINK` tokens and inflate the price per share from `1 / STARTING_SHARES_PER_LINK` to 1.0000 .

Then the attacker call `withdraw()` to withdraw `STARTING_SHARES_PER_LINK - 1` shares, and send `1e22` of `LINK` token and inflate the price per share from 1.000 to 1.000e22.

As a result, the future user who deposits `9999e18` will only receive `0` (from `9999e18 * 1 / 10000e18`) of shares token.

They will immediately lose all of their deposits.

## Impact

Users may suffer a significant portion or even 100% of the funds they deposited to the Vault.

## Code Snippet

https://github.com/sherlock-audit/2022-10-mycelium/blob/main/mylink-contracts/src/Vault.sol#L131-142

```solidity
    function deposit(uint256 _amount) exter

*[Content truncated...]*

---

### Example 6: H-4: `ERC4626Oracle` Price will be wrong when the ERC4626's `decimals` is different from the underlying tokens decimals

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/025-H 
## Found by 
Lambda, JohnSmith, WATCHPUG, 0x52, berndartmueller, Bahurum

## Summary

EIP-4626 does not require the decimals must be the same as the underlying tokens' decimals, and when it's not, `ERC4626Oracle` will malfunction.

## Vulnerability Detail

In the current implementation, `IERC4626(token).decimals()` is used as the `IERC4626(token).asset()`'s decimals to calculate the ERC4626's price.

However, while most ERC4626s are using the underlying tokens decimals as `decimals`, there are some ERC4626s use a different decimals from underlying tokens decimals since EIP-4626 does not require the decimals must be the same as the underlying tokens decimals:

> Although the convertTo functions should eliminate the need for any use of an EIP-4626 Vaults decimals variable, it is still strongly recommended to mirror the underlying tokens decimals if at all possible, to eliminate possible sources of confusion and simplify integration across front-ends and for other off-chain users.

Ref: https://eips.ethereum.org/EIPS/eip-4626

## Impact

The price of ERC4626 will be significantly underestimated when the underlying token's decimals > ERC4626's decimals, and be significantly overestimated when the underlying token's decimals < ERC4626's decimals.

## Code Snippet

https://github.com/sentimentxyz/oracle/blob/59b26a3d8c295208437aad36c470386c9729a4bc/src/erc4626/ERC4626Oracle.sol#L35-L43

```sol

*[Content truncated...]*

---

### Example 7: H-4: Victim's fund can be stolen due to rounding error and exchange rate manipulation

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

### Example 8: Multiple ERC4626Router and ERC4626RouterBase functions will always revert

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- `ERC4626Router.sol#L49-58`
- `ERC4626RouterBase.sol#L47`
- `ERC4626RouterBase.sol#L60`

## Description
The intention of the `ERC4626Router.sol` functions is that they are approval-less ways to deposit and redeem:

> For the below, no approval needed, assumes vault is already max approved.

As long as the user has approved the `TRANSFER_PROXY` for WETH, this works for the `depositToVault` function:
- WETH is transferred from the user to the router with `pullTokens`.
- The router approves the vault for the correct amount of WETH.
- `vault.deposit()` is called, which uses `safeTransferFrom` to transfer WETH from the router into the vault.

However, for the `redeemMax` function, it doesn't work:
- Approves the vault to spend the router's WETH.
- `vault.redeem()` is called, which tries to transfer vault tokens from the router to the vault, and then mints withdraw proxy tokens to the receiver.

This error occurs assuming that the vault tokens would be burned, in which case the logic would work. But since they are transferred into the vault until the end of the epoch, we require approvals.

The same issue also exists in these two functions in `ERC4626RouterBase.sol`:
- `redeem()`: this is where the incorrect approval lives, so the same issue occurs when it is called directly.
- `withdraw()`: the same faulty approval exists in this function.

## Recommendation
`redeemMax` should follow the same flow as `deposit` to make this work:
- `redeemMax` 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 9: H-1: A malicious early user/attacker can manipulate the LToken's pricePerShare to take an unfair share of future users' deposits

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/004-H 
## Found by 
kankodu, JohnSmith, PwnPatrol, WATCHPUG, berndartmueller, hyh, \_\_141345\_\_, IllIllI, TomJ

## Summary

A well known attack vector for almost all shares based liquidity pool contracts, where an early user can manipulate the price per share and profit from late users' deposits because of the precision loss caused by the rather large value of price per share.

## Vulnerability Detail

A malicious early user can `deposit()` with `1 wei` of `asset` token as the first depositor of the LToken, and get `1 wei` of shares.

Then the attacker can send `10000e18 - 1` of `asset` tokens and inflate the price per share from 1.0000 to an extreme value of 1.0000e22 ( from `(1 + 10000e18 - 1) / 1`) .

As a result, the future user who deposits `19999e18` will only receive `1 wei` (from `19999e18 * 1 / 10000e18`) of shares token.

They will immediately lose `9999e18` or half of their deposits if they `redeem()` right after the `deposit()`.

## Impact

The attacker can profit from future users' deposits. While the late users will lose part of their funds to the attacker.

## Code Snippet

https://github.com/sentimentxyz/protocol/blob/4e45871e4540df0f189f6c89deb8d34f24930120/src/tokens/utils/ERC4626.sol#L48-L60

```solidity
function deposit(uint256 assets, address receiver) public virtual returns (uint256 shares) {
    beforeDeposit(assets, shares);

    // Check for rounding error since we round d

*[Content truncated...]*

---

### Example 10: [M-16] `vMaia` is ERC-4626 compliant, but the `maxWithdraw` & `maxRedeem` functions are not fully up to EIP-4626's specification

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: MEDIUM

**Details**:

The `maxWithdraw` & `maxRedeem` functions should return the `0` when the withdrawal is paused. But here, it's returning `balanceOf[user]`.

### Proof of Concept

`vMaia Withdrawal` is only allowed once per month during the 1st Tuesday (UTC+0) of the month.

It's checked by the below function:

```

     102       function beforeWithdraw(uint256, uint256) internal override {
                /// @dev Check if unstake period has not ended yet, continue if it is the case.
                if (unstakePeriodEnd >= block.timestamp) return;
        
                uint256 _currentMonth = DateTimeLib.getMonth(block.timestamp);
                if (_currentMonth == currentMonth) revert UnstakePeriodNotLive();
        
                (bool isTuesday, uint256 _unstakePeriodStart) = DateTimeLib.isTuesday(block.timestamp);
                if (!isTuesday) revert UnstakePeriodNotLive();
        
                currentMonth = _currentMonth;
                unstakePeriodEnd = _unstakePeriodStart + 1 days;
    114        }
```

<https://github.com/code-423n4/2023-05-maia/blob/main/src/maia/vMaia.sol#L102C1-L114C6>

```

    173            function maxWithdraw(address user) public view virtual override returns (uint256) {
                      return balanceOf[user];
                  }
              
                  /// @notice Returns the maximum amount of assets that can be redeemed by a user.
                  /// @dev Assumes that the user has already forfeited all utility tokens.
      

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 11: M-15: LToken's implmentation is not fully up to EIP-4626's specification

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/500-M 
## Found by 
WATCHPUG

## Summary

Note: This issue is a part of the extra scope added by Sentiment AFTER the audit contest. This scope was only reviewed by WatchPug and relates to these three PRs:

1. [Lending deposit cap](https://github.com/sentimentxyz/protocol/pull/234)
2. [Fee accrual modification](https://github.com/sentimentxyz/protocol/pull/233)
3. [CRV staking](https://github.com/sentimentxyz/controller/pull/41)

LToken's implmentation is not fully up to EIP-4626's specification. This issue is would actually be considered a Low issue if it were a part of a Sherlock contest. 

## Vulnerability Detail

https://github.com/sentimentxyz/protocol/blob/ccfceb2805cf3595a95198c97b6846c8a0b91506/src/tokens/utils/ERC4626.sol#L185-L187

```solidity
function maxMint(address) public view virtual returns (uint256) {
    return type(uint256).max;
}
```

MUST return the maximum amount of shares mint would allow to be deposited to receiver and not cause a revert, which MUST NOT be higher than the actual maximum that would be accepted (it should underestimate if necessary). This assumes that the user has infinite assets, i.e. MUST NOT rely on balanceOf of asset.

https://eips.ethereum.org/EIPS/eip-4626#:~:text=MUST%20return%20the%20maximum%20amount%20of%20shares,NOT%20rely%20on%20balanceOf%20of%20asset

maxMint() and maxDeposit() should reflect the limitation of maxSupply.

## Impact

Could cause unexp

*[Content truncated...]*

---

### Example 12: M-10: ERC4626Oracle Vulnerable To Price Manipulation

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/133-M 
## Found by 
xiaoming90, IllIllI

## Summary

ERC4626 oracle is vulnerable to price manipulation. This allows an attacker to increase or decrease the price to carry out various attacks against the protocol.

## Vulnerability Detail

The `getPrice` function within the `ERC4626Oracle` contract is vulnerable to price manipulation because the price can be increased or decreased within a single transaction/block.

Based on the `getPrice` function, the price of the LP token of an ERC4626 vault is dependent on the `ERC4626.previewRedeem` and `oracleFacade.getPrice` functions. If the value returns by either `ERC4626.previewRedeem` or `oracleFacade.getPrice` can be manipulated within a single transaction/block, the price of the LP token of an ERC4626 vault is considered to be vulnerable to price manipulation.

https://github.com/sherlock-audit/2022-08-sentiment/blob/main/oracle/src/erc4626/ERC4626Oracle.sol#L8

```solidity
File: ERC4626Oracle.sol
35:     function getPrice(address token) external view returns (uint) {
36:         uint decimals = IERC4626(token).decimals();
37:         return IERC4626(token).previewRedeem(
38:             10 ** decimals
39:         ).mulDivDown(
40:             oracleFacade.getPrice(IERC4626(token).asset()),
41:             10 ** decimals
42:         );
43:     }
```

It was observed that the `ERC4626.previewRedeem` couldbe manipulated within a single transaction/block.

*[Content truncated...]*

---

### Example 13: [M-17] Malicious Users Can Drain The Assets Of Vault. (Due to not being ERC4626 Complaint)

**Source**: Code4rena
**Protocol**: Popcorn
**Impact**: MEDIUM

**Details**:

Malicious users can drain the assets of the vault.

### Proof of Concept

The `withdraw` function users `convertToShares` to convert the assets to the amount of shares. These shares are burned from the users account and the assets are returned to the user.

The function `withdraw` is shown below:

```solidity
function withdraw(
        uint256 assets,
        address receiver,
        address owner
    ) public nonReentrant syncFeeCheckpoint returns (uint256 shares) {
        if (receiver == address(0)) revert InvalidReceiver();

        shares = convertToShares(assets);
/// .... [skipped the code]
```

The function `convertToShares` is shown below:

```solidity
function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply(); // Saves an extra SLOAD if totalSupply is non-zero.

        return
            supply == 0
                ? assets
                : assets.mulDiv(supply, totalAssets(), Math.Rounding.Down);
    }
```

It uses `Math.Rounding.Down` , but it should use `Math.Rounding.Up`

Assume that the vault with the following state:

*   Total Asset = 1000 WETH
*   Total Supply = 10 shares

Assume that Alice wants to withdraw 99 WETH from the vault. Thus, she calls the**`Vault.withdraw(99 WETH)`**function.

The calculation would go like this:

```solidity
assets = 99
return value = assets * supply / totalAssets()
return value = 99 * 10 / 1000
return value = 0
```

The value would be rounded round to zero. This will be 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-popcorn)

---

### Example 14: M-5: Math rounding in AutoRoller.sol is not ERC4626-complicant: previewWithdraw should round up.

**Source**: Sherlock
**Protocol**: Sense
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/30 

## Found by 
ctf\_sec

## Summary

Math rounding in AutoRoller.sol is not ERC4626-complicant: previewWithdraw should round up.

## Vulnerability Detail

Per EIP 4626's Security Considerations (https://eips.ethereum.org/EIPS/eip-4626)

> Finally, ERC-4626 Vault implementers should be aware of the need for specific, opposing rounding directions across the different mutable and view methods, as it is considered most secure to favor the Vault itself during calculations over its users:

> If (1) its calculating how many shares to issue to a user for a certain amount of the underlying tokens they provide or (2) its determining the amount of the underlying tokens to transfer to them for returning a certain amount of shares, it should round down.
If (1) its calculating the amount of shares a user has to supply to receive a given amount of the underlying tokens or (2) its calculating the amount of underlying tokens a user has to provide to receive a certain amount of shares, it should round up.

Then previewWithdraw in AutoRoller.sol should round up.

The original implementation for previewWithdraw in Solmate ERC4626 is:

```solidity
    function previewWithdraw(uint256 assets) public view virtual returns (uint256) {
        uint256 supply = totalSupply; // Saves an extra SLOAD if totalSupply is non-zero.

        return supply == 0 ? assets : assets.mulDivUp(supply, totalAssets());
    }
```

It is roundi

*[Content truncated...]*

---

### Example 15: M-12: Vault Share/Strategy Token Calculation Can Be Broken By First User/Attacker

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/70 

## Found by 
xiaoming90

## Summary

A well-known attack vector for almost all shares-based liquidity pool contracts, where an early user can manipulate the price per share and profit from late users' deposits because of the precision loss caused by the rather large value of price per share.

## Vulnerability Detail

> Note: This issue affects MetaStable2 and Boosted3 balancer leverage vaults

For simplicity's sake, we will simplify the strategy token minting formula as follows. Also, assume that the 1 vault share is equivalent to 1 strategy token for this particular strategy vault, therefore, we will use the term `vault share` and `strategy token` interchangeably here.

```solidity
strategyToken = (totalBPTHeld == 0) ?  bptClaim : (bptClaim * totalStrategyToken) / totalBPTHeld
```

The vault minting formula is taken from the following:

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/internal/strategy/StrategyUtils.sol#L27

```solidity
File: StrategyUtils.sol
26:     /// @notice Converts BPT to strategy tokens
27:     function _convertBPTClaimToStrategyTokens(StrategyContext memory context, uint256 bptClaim)
28:         internal pure returns (uint256 strategyTokenAmount) {
29:         if (context.totalBPTHeld == 0) {
30:             // Strategy tokens are in 8 decimal precision, BPT is in 18. Scale the minted amount down.
31:             retu

*[Content truncated...]*

---

### Example 16: [M-02] Slippage controls for calling `bHermes` contract's `ERC4626DepositOnly.deposit` and `ERC4626DepositOnly.mint` functions are missing

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: MEDIUM

**Details**:

[EIPS](<https://eips.ethereum.org/EIPS/eip-4626#security-considerations>) mentions that "if implementors intend to support EOA account access directly, they should consider adding an additional function call for `deposit`/`mint`/`withdraw`/`redeem` with the means to accommodate slippage loss or unexpected deposit/withdrawal limits, since they have no other means to revert the transaction if the exact output amount is not achieved."

Using the `bHermes` contract that inherits the `ERC4626DepositOnly` contract, EOAs can call the `ERC4626DepositOnly.deposit` and `ERC4626DepositOnly.mint` functions directly. However, because no slippage controls can be specified when calling these functions, these function's `shares` and `assets` outputs can be less than expected to these EOAs.

<https://github.com/code-423n4/2023-05-maia/blob/53c7fe9d5e55754960eafe936b6cb592773d614c/src/erc-4626/ERC4626DepositOnly.sol#L32-L44>

```solidity
    function deposit(uint256 assets, address receiver) public virtual returns (uint256 shares) {
        // Check for rounding error since we round down in previewDeposit.
        require((shares = previewDeposit(assets)) != 0, "ZERO_SHARES");

        // Need to transfer before minting or ERC777s could reenter.
        address(asset).safeTransferFrom(msg.sender, address(this), assets);

        _mint(receiver, shares);

        emit Deposit(msg.sender, receiver, assets, shares);

        afterDeposit(assets, shares);
    }
```

<https://github.com/code-423n4/

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 17: H-1: Public vault : Initial depositor can manipulate the price per share value and future depositors are forced to deposit huge value in vault.

**Source**: Sherlock
**Protocol**: Sense
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/50 

## Found by 
ak1

## Summary
Most of the share based vault implementation will face this issue.
The vault is based on the ERC4626 where the shares are calculated based on the deposit value.
By depositing large amount as initial deposit, initial depositor can influence the future depositors value.

## Vulnerability Detail

Shares are minted based on the deposit value.
https://github.com/sherlock-audit/2022-11-sense/blob/main/contracts/src/RollerPeriphery.sol#L59-L79
Public vault is based on the ERC4626 where the shares are calculated based on the deposit value.

By depositing large amount as initial deposit, first depositor can take advantage over other depositors.

I am sharing reference for this type of issue that already reported and acknowledged. This explain how the share price could be manipulated to  large value.

https://github.com/sherlock-audit/2022-08-sentiment-judging#issue-h-1-a-malicious-early-userattacker-can-manipulate-the-ltokens-pricepershare-to-take-an-unfair-share-of-future-users-deposits:~:text=Issue%20H%2D1%3A%20A%20malicious%20early%20user/attacker%20can%20manipulate%20the%20LToken%27s%20pricePerShare%20to%20take%20an%20unfair%20share%20of%20future%20users%27%20deposits

ERC4626 implementation
    function mint(uint256 shares, address receiver) public virtual returns (uint256 assets) {
        assets = previewMint(shares); // No need to check for rounding error, previewMint round

*[Content truncated...]*

---

### Example 18: [M-07] `PrizeVault.maxDeposit()` doesn't take into account produced fees

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L368-L392><br>
<https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L685><br>
<https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L619>

### Summary

Currently, `PrizeVault.maxDeposit()` calculates the maximum possible amount of deposit without taking into account produced fees. That means if there is already maxed deposited amount of asset that is calculated by the current implementation in `PrizeVault.maxDeposit()`, `yieldFeeRecipient` can't withdraw shares with `PrizeVault.claimYieldFeeShares()` because in that case `_mint()` will revert because of overflow. A lot of low-price tokens can exceed the limit of `type(uint96).max` with ease. For example, to make a deposit with `maxDeposit()` value with LADYS token it's needed only `$13568` (as of 08-03-2024).

### Impact

If a user makes a maximum allowed deposit that is calculated by the current implementation of `PrizeVault.maxDeposit()`, `yieldFeeRecipient` can't withdraw fees if they are available.

### Proof of Concept

Add this test to `PrizeVault.t.sol` and run with:

```
    forge test --match-contract PrizeVaultTest --match-test testMaxDeposit_CalculatesWithoutTakingIntoAccountGeneratedFees
```

```solidity
    function _deposit(address accou

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-03-pooltogether)

---

### Example 19: [M-06] Funds locked due to missing transfer check

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

All of the user's funds are unretrievably locked in the `PrizeVault` contract.

A combination of issues allows for the following scenario:

1. Alice invokes [`_withdraw(receiver, assets)`](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L925-L941) (via `burn()` or `withdraw()`).
2. The contract [computes the number of shares to redeem](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L933-L934), via `previewWithdraw(assets)`.
3. The contract [redeems as many shares](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L935-L936), but the ERC 4626-compliant vault returns fewer shares than expected. At this point, the contract holds fewer than `assets` tokens.
4. The contract [attempts to `transfer` assets to the receiver](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L939). This fails due to insufficient funds, but the ERC 20-compliant token does not revert (only returns `false`).
5. At this point, Alice's assets are locked in the `PrizeVault` contract. They cannot be withdrawn at a later point, because the corresponding prize vault and yield vault shares have been burned.

The exploit relies on insufficient handling of two corner cases of [ERC-20](https://eips.ether

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-03-pooltogether)

---

### Example 20: [M-07] ```trancheTokenAmount``` should be rounded UP when proceeding to a withdrawal or previewing a withdrawal

**Source**: Code4rena
**Protocol**: Centrifuge
**Impact**: MEDIUM

**Details**:

This is good practice when implementing the EIP-4626 vault standard as it is more secure to favour the vault than its users in that case.<br>
This can also lead to issues down the line for other protocol integrating Centrifuge, that may assume that rounding was handled according to EIP-4626 best practices.

### Proof of Concept

When calling the [`processWithdraw`](https://github.com/code-423n4/2023-09-centrifuge/blob/main/src/InvestmentManager.sol#L515) function, the `trancheTokenAmount` is computed through the [`_calculateTrancheTokenAmount`](https://github.com/code-423n4/2023-09-centrifuge/blob/main/src/InvestmentManager.sol#L591) function, which rounds DOWN the number of shares required to be burnt to receive the `currencyAmount` payout/withdrawal.

```solidity
/// @dev Processes user's tranche token redemption after the epoch has been executed on Centrifuge.
/// In case user's redempion order was fullfilled on Centrifuge during epoch execution MaxRedeem and MaxWithdraw
/// are increased and LiquidityPool currency can be transferred to user's wallet on calling processRedeem or processWithdraw.
/// Note: The trancheTokenAmount required to fullfill the redemption order was already locked in escrow upon calling requestRedeem and burned upon collectRedeem.
/// @notice trancheTokenAmount return value is type of uint256 to be compliant with EIP4626 LiquidityPool interface
/// @return trancheTokenAmount the amount of trancheTokens redeemed/burned required to receive the currency

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-09-centrifuge)

---

### Example 21: [M-01] If the underlying asset is a fee on transfer token, it could break the internal accounting of the vault

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

The `Vault._deposit` function is used by the users to deposit `_assets` to the vault and mint vault shares to the `recipient` address. The amount of `_assets` are transferred to the `Vault` as follows:

      SafeERC20.safeTransferFrom(
        _asset,
        _caller,
        address(this),
        _assetsDeposit != 0 ? _assetsDeposit : _assets
      );

The `Vault.deposit` function uses this `_assets` amount to calculate the number of `shares` to be minted to the `_recipient` address.

The issue here is if the underlying `_asset` is a fee on transfer token then the actual received amount to the vault will be less than what is referred in the `Vault.deposit` function `_assets` input parameter. But the shares to mint is calculated using the entire `_assets` amount.

This issue could be further aggravated since the `_asset` is again `deposited` to the `_yieldVault` and when needing to be redeemed, will be `withdrawn` from the `_yieldVault` as well. These operations will again charge a fee if the `_asset` is a fee on transfer token. Hence, the actual `_asset` amount left for a particular user will be less than the amount they initially transferred in.

Hence, when the user `redeems` the minted shares back to the `_assets`, the contract will not have enough assets to transfer to the `redeemer`, thus reverting the transaction.

### Proof of Concept

```solidity
      SafeERC20.safeTransferFrom(
        _asset,
        _caller,
        address(this),
        _assetsDeposit != 0 ? 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-pooltogether)

---

### Example 22: [M-22] `ERC4626RouterBase.withdraw` can only be called once

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

ERC4626RouterBase.withdraw will approve an amount of vault tokens to the vault, but the amount represents the number of asset tokens taken out by vault.withdraw, not the required number of vault tokens, and since it normally requires less than 1 vault token to take out 1 asset token, it will prevent ERC4626RouterBase.withdraw from using all approved vault tokens.

```solidity
  function withdraw(
    IERC4626 vault,
    address to,
    uint256 amount,
    uint256 maxSharesOut
  ) public payable virtual override returns (uint256 sharesOut) {

    ERC20(address(vault)).safeApprove(address(vault), amount);
    if ((sharesOut = vault.withdraw(amount, to, msg.sender)) > maxSharesOut) {
      revert MaxSharesError();
    }
  }
```

and since safeApprove cannot approve a non-zero value to a non-zero value, the second call to ERC4626RouterBase.withdraw will fails in safeApprove.

```solidity
    function safeApprove(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

### Example 23: [M-06] For a public vault, minimum deposit requirement that is enforced by `ERC4626Cloned.deposit` function can be bypassed by `ERC4626Cloned.mint` function or vice versa when share price does not equal one

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

The following `ERC4626Cloned.deposit` function has `require(shares > minDepositAmount(), "VALUE_TOO_SMALL")` as the minimum deposit requirement, and the `ERC4626Cloned.mint` function below has `require(assets > minDepositAmount(), "VALUE_TOO_SMALL")` as the minimum deposit requirement. For a public vault, when the share price becomes different than 1, these functions' minimum deposit requirements are no longer the same. For example, given `S` is the `shares` input value for the `ERC4626Cloned.mint` function and `A` equals `ERC4626Cloned.previewMint(S)`, when the share price is bigger than 1 and `A` equals `minDepositAmount() + 1`, such `A` will violate the `ERC4626Cloned.deposit` function's minimum deposit requirement but the corresponding `S` will not violate the `ERC4626Cloned.mint` function's minimum deposit requirement; in this case, the user can just ignore the `ERC4626Cloned.deposit` function and call `ERC4626Cloned.mint` function to become a liquidity provider. Thus, when the public vault's share price is different than 1, the liquidity provider can call the less restrictive function out of the two so the minimum deposit requirement enforced by one of the two functions is not effective at all; this can result in unexpected deposit amounts and degraded filtering of who can participate as a liquidity provider.

<https://github.com/AstariaXYZ/astaria-gpl/blob/main/src/ERC4626-Cloned.sol#L19-L36>

```solidity
  function deposit(uint256 assets, address receiver)
    public


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

### Example 24: H-3: Early depositors to BufferBinaryPool can manipulate exchange rates to steal funds from later depositors

**Source**: Sherlock
**Protocol**: Buffer Finance
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-buffer-judging/issues/81 

## Found by 
dipp, gandu, rvierdiiev, Ruhum, hansfriese, cccz, 0x52, ctf\_sec, joestakey

## Summary

To calculate the exchange rate for shares in BufferBinaryPool it divides the total supply of shares by the totalTokenXBalance of the vault. The first deposit can mint a very small number of shares then donate tokenX to the vault to grossly manipulate the share price. When later depositor deposit into the vault they will lose value due to precision loss and the adversary will profit.

## Vulnerability Detail

    function totalTokenXBalance()
        public
        view
        override
        returns (uint256 balance)
    {
        return tokenX.balanceOf(address(this)) - lockedPremium;
    }

Share exchange rate is calculated using the total supply of shares and the totalTokenXBalance, which leaves it vulnerable to exchange rate manipulation. As an example, assume tokenX == USDC. An adversary can mint a single share, then donate 1e8 USDC. Minting the first share established a 1:1 ratio but then donating 1e8 changed the ratio to 1:1e8. Now any deposit lower than 1e8 (100 USDC) will suffer from precision loss and the attackers share will benefit from it.

## Impact

Adversary can effectively steal funds from later users through precision loss

## Code Snippet

https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryPool.sol#L405-L412

## Tool used

Manual Revie

*[Content truncated...]*

---

### Example 25: M-1: Vault Inflation Attack

**Source**: Sherlock
**Protocol**: Smilee Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-smilee-finance-judging/issues/22 

## Found by 
kfx, santipu\_

## Summary

An attacker can be the first and only depositor on the vault during the first epoch in order to execute an inflation attack that will steal the deposited funds of all depositors in the next epoch. 

## Vulnerability Detail

A malicious user can perform a donation to execute a classic first depositor/ERC4626 inflation Attack against the new Smilee vaults. The general process of this attack is well-known, and a detailed explanation of this attack can be found in many of the resources such as the following:

- https://blog.openzeppelin.com/a-novel-defense-against-erc4626-inflation-attacks
- https://mixbytes.io/blog/overview-of-the-inflation-attack

In short, to kick-start the attack, the malicious user will often usually mint the smallest possible amount of shares (e.g., 1 wei) and then donate significant assets to the vault to inflate the number of assets per share. Subsequently, it will cause a rounding error when other users deposit.

However, in Smilee there's the problem that the deposits are not processed until the epoch is finished. Therefore, the attacker would need to be the only depositor on the first epoch of the vault; after the second epoch starts, all new depositors will lose all the deposited funds due to a rounding error. 

This scenario may happen for newly deployed vaults with a short maturity period (e.g., 1 day) and/or for vaults with 

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 28
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

