# First Depositor Issue Security Patterns

## Overview

**Frequency**: 26 occurrences (0.05% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 20 | 6 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, Cyfrin, Trust Security

---

## Detection Checklist

- [ ] Check for first depositor issue vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-03] First depositor can break minting of shares

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: HIGH

**Details**:

The attack vector and impact is the same as [TOB-YEARN-003](https://github.com/yearn/yearn-security/blob/master/audits/20210719\_ToB_yearn_vaultsv2/ToB\_-\_Yearn_Vault_v\_2\_Smart_Contracts_Audit_Report.pdf), where users may not receive shares in exchange for their deposits if the total asset amount has been manipulated through a large “donation”.

### Proof of Concept

In `Pair.add()`, the amount of LP token minted is calculated as

```solidity
function addQuote(uint256 baseTokenAmount, uint256 fractionalTokenAmount) public view returns (uint256) {
    uint256 lpTokenSupply = lpToken.totalSupply();
    if (lpTokenSupply > 0) {
        // calculate amount of lp tokens as a fraction of existing reserves
        uint256 baseTokenShare = (baseTokenAmount * lpTokenSupply) / baseTokenReserves();
        uint256 fractionalTokenShare = (fractionalTokenAmount * lpTokenSupply) / fractionalTokenReserves();
        return Math.min(baseTokenShare, fractionalTokenShare);
    } else {
        // if there is no liquidity then init
        return Math.sqrt(baseTokenAmount * fractionalTokenAmount);
    }
}
```

An attacker can exploit using these steps

1.  Create and add `1 wei baseToken - 1 wei quoteToken` to the pair. At this moment, attacker is minted `1 wei LP token` because `sqrt(1 * 1) = 1`
2.  Transfer large amount of `baseToken` and `quoteToken` directly to the pair, such as `1e9 baseToken - 1e9 quoteToken`. Since no new LP token is minted, `1 wei LP token` worths `1e9 baseToken - 1e

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-caviar)

---

### Example 2: [H-05] Underlying assets stealing in `AutoPxGmx` and `AutoPxGlp` via share price manipulation

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/PirexERC4626.sol#L156-L165>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/PirexERC4626.sol#L167-L176>

### Impact

pxGMX and pxGLP tokens can be stolen from depositors in `AutoPxGmx` and `AutoPxGlp` vaults by manipulating the price of a share.

### Proof of Concept

ERC4626 vaults are subject to a share price manipulation attack that allows an attacker to steal underlying tokens from other depositors (this is a [known issue](https://github.com/transmissions11/solmate/issues/178) of Solmate's ERC4626 implementation). Consider this scenario (this is applicable to `AutoPxGmx` and `AutoPxGlp` vaults):

1.  Alice is the first depositor of the `AutoPxGmx` vault;
2.  Alice deposits 1 wei of pxGMX tokens;
3.  in the `deposit` function ([PirexERC4626.sol#L60](https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/PirexERC4626.sol#L60)), the amount of shares is calculated using the `previewDeposit` function:

    ```solidity
    function previewDeposit(uint256 assets)
        public
        view
        virtual
        returns (uint256)
    {
        return convertToShares(assets);
    }

    function convertToShares(uint256 assets)
        public
        view
        virtual
        returns (uint256)
    {
        uint256 supply = totalSupply; // Saves an e

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 3: First pool depositor can be front-run and have part of their deposit stolen

**Source**: Spearbit
**Protocol**: Maple Finance
**Impact**: HIGH

**Details**:

## High Risk Severity Report

## Context
- **File:** pool-v2::Pool.sol
- **Line:** #L73

## Description
The first deposit with a `totalSupply` of zero shares will mint shares equal to the deposited amount. This makes it possible to deposit the smallest unit of a token and profit off a rounding issue in the computation for the minted shares of the next depositor:

```
(shares_ * totalAssets()) / totalSupply_
```

### Example
- The first depositor (victim) wants to deposit **2M USDC** (`2e12`) and submits the transaction.
- The attacker front runs the victim's transaction by calling `deposit(1)` to get 1 share. They then transfer **1M USDC** (`1e12`) to the contract, such that `totalAssets = 1e12 + 1`, `totalSupply = 1`.
- When the victim's transaction is mined, they receive:

```
2e12 / (1e12 + 1) * totalSupply = 1 share
```
(rounded down from `1.9999...`).
- The attacker withdraws their 1 share and gets:

```
3M USDC * 1 / 2 = 1.5M USDC
```
making a **0.5M profit**.

During the migration, an `initialSupply` of shares to be airdropped are already minted at initialization and are not affected by this attack.

## Recommendation
Require a minimum initial shares amount for the first deposit by adjusting the initial mint (when `totalSupply == 0`) such that:
- Mint an `INITIAL_BURN_AMOUNT` of shares to a dead address like address zero.
- Only mint `depositAmount - INITIAL_BURN_AMOUNT` to the recipient.

`INITIAL_BURN_AMOUNT` needs to be chosen large enough such that the cost of the 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/MapleV2.pdf)

---

### Example 4: [H-04] First depositor can break minting of shares

**Source**: Code4rena
**Protocol**: Rubicon
**Impact**: HIGH

**Details**:

_Submitted by MiloTruck, also found by cccz, oyc_109, VAD37, PP1004, SmartSek, minhquanym, unforgiven, berndartmueller, WatchPug, CertoraInc, and sorrynotsorry_

The attack vector and impact is the same as [TOB-YEARN-003](https://github.com/yearn/yearn-security/blob/master/audits/20210719\_ToB_yearn_vaultsv2/ToB\_-\_Yearn_Vault_v\_2\_Smart_Contracts_Audit_Report.pdf), where users may not receive shares in exchange for their deposits if the total asset amount has been manipulated through a large “donation”.

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

### Example 5: [H-01] yVault: First depositor can break minting of shares

**Source**: Code4rena
**Protocol**: JPEG'd
**Impact**: HIGH

**Details**:

_Submitted by hickuphh3, also found by 0xDjango, berndartmueller, cmichel, hyh, and WatchPug_

[yVault.sol#L148-L153](https://github.com/code-423n4/2022-04-jpegd/blob/main/contracts/vaults/yVault/yVault.sol#L148-L153)<br>

The attack vector and impact is the same as [TOB-YEARN-003](https://github.com/yearn/yearn-security/blob/master/audits/20210719\_ToB_yearn_vaultsv2/ToB\_-\_Yearn_Vault_v\_2\_Smart_Contracts_Audit_Report.pdf), where users may not receive shares in exchange for their deposits if the total asset amount has been manipulated through a large “donation”.

### Proof of Concept

*   Attacker deposits 1 wei to mint 1 share
*   Attacker transfers exorbitant amount to the `StrategyPUSDConvex` contract to greatly inflate the share’s price. Note that the strategy deposits its entire balance into Convex when its `deposit()` function is called.
*   Subsequent depositors instead have to deposit an equivalent sum to avoid minting 0 shares. Otherwise, their deposits accrue to the attacker who holds the only share.

Insert this test into [`yVault.ts`](https://github.com/code-423n4/2022-04-jpegd/blob/main/tests/yVault.ts).

```jsx
it.only("will cause 0 share issuance", async () => {
  // mint 10k + 1 wei tokens to user1
  // mint 10k tokens to owner
  let depositAmount = units(10_000);
  await token.mint(user1.address, depositAmount.add(1));
  await token.mint(owner.address, depositAmount);
  // token approval to yVault
  await token.connect(user1).approve(yVault.address, 1);
 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-jpegd)

---

### Example 6: [H-02] First depositor can break minting of shares

**Source**: Code4rena
**Protocol**: prePO
**Impact**: HIGH

**Details**:

_Submitted by GreyArt, also found by 0xDjango, CertoraInc, cmichel, rayn, TomFrenchBlockchain, and WatchPug_

[Collateral.sol#L82-L91](https://github.com/code-423n4/2022-03-prepo/blob/main/contracts/core/Collateral.sol#L82-L91)<br>

The attack vector and impact is the same as [TOB-YEARN-003](https://github.com/yearn/yearn-security/blob/master/audits/20210719\_ToB_yearn_vaultsv2/ToB\_-\_Yearn_Vault_v\_2\_Smart_Contracts_Audit_Report.pdf), where users may not receive shares in exchange for their deposits if the total asset amount has been manipulated through a large “donation”.

### Proof of Concept

*   Attacker deposits 2 wei (so that it is greater than min fee) to mint 1 share
*   Attacker transfers exorbitant amount to `_strategyController` to greatly inflate the share’s price. Note that the `_strategyController` deposits its entire balance to the strategy when its `deposit()` function is called.
*   Subsequent depositors instead have to deposit an equivalent sum to avoid minting 0 shares. Otherwise, their deposits accrue to the attacker who holds the only share.

```jsx
it("will cause 0 share issuance", async () => {
	// 1. first user deposits 2 wei because 1 wei will be deducted for fee
	let firstDepositAmount = ethers.BigNumber.from(2)
	await transferAndApproveForDeposit(
	    user,
	    collateral.address,
	    firstDepositAmount
	)
	
	await collateral
	    .connect(user)
	    .deposit(firstDepositAmount)
	
	// 2. do huge transfer of 1M to strategy to controller
	// to 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-prepo)

---

### Example 7: [H-05] Making `_totalSupply` and `_totalShares` imbalance significantly by providing fake income leads to stealing fund

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: HIGH

**Details**:

If the project has just started, a malicious user can make the `_totalSupply` and `_totalShares` imbalance significantly by providing fake income. By doing so, later, when innocent users deposit and mint, the malicious user can steal protocol's stETH without burning any shares. Moreover, the protocol's income can be stolen as well.

### Proof of Concept

Suppose nothing is deposited in the protocol (it is day 0).

Bob (a malicious user) deposits `$`1000 worth of ether (equal to 1 ETH, assuming ETH price is `$`1000) to mint `200e18 + 1` eUSD. The state will be:
*   `shares[Bob] = 200e18 + 1`
*   `_totalShares = 200e18 + 1`
*   `_totalSupply = 200e18 + 1`
*   `borrowed[Bob] = 200e18 + 1`
*   `poolTotalEUSDCirculation = 200e18 + 1`
*   `depositAsset[Bob] = 1e18`
*   `totalDepositedAsset = 1e18`
*   `stETH.balanceOf(protocol) = 1e18`

<https://github.com/code-423n4/2023-06-lybra/blob/7b73ef2fbb542b569e182d9abf79be643ca883ee/contracts/lybra/pools/LybraStETHVault.sol#L37>

Then, Bob transfers directly `0.2stETH` (worth `$`200) to the protocol. By doing so, Bob is providing a fake excess income in the protocol. So, the state will be:
*   `shares[Bob] = 200e18 + 1`
*   `_totalShares = 200e18 + 1`
*   `_totalSupply = 200e18 + 1`
*   `borrowed[Bob] = 200e18 + 1`
*   `poolTotalEUSDCirculation = 200e18 + 1`
*   `depositAsset[Bob] = 1e18`
*   `totalDepositedAsset = 1e18`
*   `stETH.balanceOf(protocol) = 1e18 + 2e17`

Then, Bob calls `excessIncomeDistribution` to buy this excess income. As

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 8: [H-01] An attacker can manipulate the preDepositvePrice to steal from other users

**Source**: Code4rena
**Protocol**: Asymmetry Finance
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-03-asymmetry/blob/44b5cd94ebedc187a08884a7f685e950e987261c/contracts/SafEth/SafEth.sol#L79><br>
<https://github.com/code-423n4/2023-03-asymmetry/blob/44b5cd94ebedc187a08884a7f685e950e987261c/contracts/SafEth/SafEth.sol#L98>

### Impact

The first user that stakes can manipulate the total supply of sfTokens and by doing so create a rounding error for each subsequent user. In the worst case, an attacker can steal all the funds of the next user.

### Proof of Concept

When the first user enters totalSupply is set to 1e18 on [L79](https://github.com/code-423n4/2023-03-asymmetry/blob/44b5cd94ebedc187a08884a7f685e950e987261c/contracts/SafEth/SafEth.sol#L79):

```solidity
if (totalSupply == 0)
            preDepositPrice = 10 ** 18; // initializes with a price of 1
        else preDepositPrice = (10 ** 18 * underlyingValue) / totalSupply;
```

But the user can immediately unstake most of his safETH such that totalSupply <<  1e18. The attacker can then transfer increase the underlying amount by transferring derivative tokens to the derivative contracts.

For subsequent users, the preDepositPrice will be heavily inflated and the calculation of mintAmount on [L98](https://github.com/code-423n4/2023-03-asymmetry/blob/44b5cd94ebedc187a08884a7f685e950e987261c/contracts/SafEth/SafEth.sol#L98):

```solidity
uint256 mintAmount = (totalStakeValueEth * 10 ** 18) / preDepositPrice;
```

can be very inaccurate. In the worst case it rounds down to 0 for users t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-03-asymmetry)

---

### Example 9: H-1: Attacker can manipulate the pricePerShare to profit from future users' deposits

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

### Example 10: H-4: Victim's fund can be stolen due to rounding error and exchange rate manipulation

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

### Example 11: [H-03] The price of rsETH could be manipulated by the first staker

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

### Example 12: TRST-H-4 First depositor can steal asset tokens of others

**Source**: Trust Security
**Protocol**: Stella
**Impact**: HIGH

**Details**:

**Description:**
The first depositor can be front run by an attacker and as a result will lose a considerable 
part of the assets provided.
When the pool has no share supply, in `_mintInternal()`, the amount of shares to be minted is 
equal to the assets provided. An attacker can abuse of this situation and profit of the 
rounding down operation when calculating the amount of shares if the supply is non-zero. 
```solidity
        function _mintInternal(address _receiver, uint _balanceIncreased, uint _totalAsset
             ) internal returns (uint mintShares) {
                unfreezeTime[_receiver] = block.timestamp + mintFreezeInterval;
        if (freezeBuckets.interval > 0) {
             FreezeBuckets.addToFreezeBuckets(freezeBuckets, _balanceIncreased.toUint96());
        }
                 uint _totalSupply = totalSupply();
                    if (_totalAsset == 0 || _totalSupply == 0) {
                     mintShares = _balanceIncreased + _totalAsset;
                 } else {
             mintShares = (_balanceIncreased * _totalSupply) / _totalAsset;
             }
            if (mintShares == 0) {
        revert ZeroAmount();
        }
        _mint(_receiver, mintShares);
        }
``` 
Consider the following scenario.
1. Alice wants to deposit 2M * 1e6 USDC to a pool.
2. Bob observes Alice's transaction, frontruns to deposit 1 wei USDC to mint 1 wei share, and 
transfers 1 M * 1e6 USDC to the pool.
3. Alice's transaction is executed, since **_totalAsset = 1M *

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-29-Stella.md)

---

### Example 13: [H-10] First vault depositor can steal other's assets

**Source**: Code4rena
**Protocol**: Popcorn
**Impact**: HIGH

**Details**:

The first depositor can be front run by an attacker and as a result will lose a considerable part of the assets provided.

The vault calculates the amount of shares to be minted upon deposit to every user via the `convertToShares()` function:

```solidity
function deposit(uint256 assets, address receiver)
    public
    nonReentrant
    whenNotPaused
    syncFeeCheckpoint
    returns (uint256 shares)
{
    if (receiver == address(0)) revert InvalidReceiver();

    uint256 feeShares = convertToShares(
        assets.mulDiv(uint256(fees.deposit), 1e18, Math.Rounding.Down)
    );

    shares = convertToShares(assets) - feeShares;

    if (feeShares > 0) _mint(feeRecipient, feeShares);

    _mint(receiver, shares);

    asset.safeTransferFrom(msg.sender, address(this), assets);

    adapter.deposit(assets, address(this));

    emit Deposit(msg.sender, receiver, assets, shares);
}

function convertToShares(uint256 assets) public view returns (uint256) {
    uint256 supply = totalSupply(); // Saves an extra SLOAD if totalSupply is non-zero.

    return
        supply == 0
            ? assets
            : assets.mulDiv(supply, totalAssets(), Math.Rounding.Down);
}

```

When the pool has no share supply, the amount of shares to be minted is equal to the assets provided. An attacker can abuse this situation and profit off the rounding down operation when calculating the amount of shares if the supply is non-zero. This attack is enabled by the following components: frontrunning, rou

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-popcorn)

---

### Example 14: First vault deposit can cause excessive rounding

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## ERC4626 Clone Analysis

## Severity
**Medium Risk**

## Context
`ERC4626-Cloned.sol#L130`

## Description
Aside from storage layout/getters, the context above notes the other major departure from Solmate's ERC4626 implementation. The modification requires the initial mint to cost 10 full WETH.

### Code Snippet
```solidity
function mint(
    uint256 shares,
    address receiver
) public virtual returns (uint256 assets) {
    // assets is 10e18, or 10 WETH, whenever totalSupply() == 0
    assets = previewMint(shares); // No need to check for rounding error, previewMint rounds up.
    // Need to transfer before minting or ERC777s could reenter.
    // minter transfers 10 WETH to the vault
    ERC20(asset()).safeTransferFrom(msg.sender, address(this), assets);
    // shares received are based on user input
    _mint(receiver, shares);
    emit Deposit(msg.sender, receiver, assets, shares);
    afterDeposit(assets, shares);
}
```

Astaria highlighted that the code diff from Solmate is in relation to this finding from the previous Sherlock audit. However, the deposit is still unchanged, and the initial deposit may be 1 wei worth of WETH, in return for 1 wad worth of vault shares.

Furthermore, the previously cited issue may still surface by calling `mint` in a way that sets the price per share high (e.g., 10 shares for 10 WETH produces a price per of 1:1e18). Albeit, it comes at a higher cost to the minter to set the initial price that high.

## Recommendation
- Revert the hard

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 15: [H-05] Inflation of ggAVAX share price by first depositor

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

### Example 16: [H-03] StakedCitadel depositors can be attacked by the first depositor with depressing of vault token denomination

**Source**: Code4rena
**Protocol**: BadgerDAO
**Impact**: HIGH

**Details**:

_Submitted by hyh, also found by VAD37, cmichel, 0xDjango, berndartmueller, and danb_

<https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L881-L892>

<https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L293-L295>

### Impact

An attacker can become the first depositor for a recently created StakedCitadel contract, providing a tiny amount of Citadel tokens by calling `deposit(1)` (raw values here, `1` is `1 wei`, `1e18` is `1 Citadel` as it has 18 decimals). Then the attacker can directly transfer, for example, `10^6*1e18 - 1` Citadel to StakedCitadel, effectively setting the cost of `1` of the vault token to be `10^6 * 1e18` Citadel. The attacker will still own 100% of the StakedCitadel's pool being the only depositor.

All subsequent depositors will have their Citadel token investments rounded to `10^6 * 1e18`, due to the lack of precision which initial tiny deposit caused, with the remainder divided between all current depositors, i.e. the subsequent depositors lose value to the attacker.

For example, if the second depositor brings in `1.9*10^6 * 1e18` Citadel, only `1` of new vault to be issued as `1.9*10^6 * 1e18` divided by `10^6 * 1e18` will yield just `1`, which means that `2.9*10^6 * 1e18` total Citadel pool will be divided 50/50 between the second depositor and the attacker, as each have 1 wei of the total 2 wei of vault tokens, i.e. the depositor lost and the attacker gained `0.45*10^6 * 1e18` Cit

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-badger-citadel)

---

### Example 17: [H-03] InsuranceFund depositors can be priced out & deposits can be stolen

**Source**: Code4rena
**Protocol**: Hubble
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by danb_

<https://github.com/code-423n4/2022-02-hubble/blob/8c157f519bc32e552f8cc832ecc75dc381faa91e/contracts/InsuranceFund.sol#L44-L54><br>

The `InsuranceFund.deposit` function mints initial `shares` equal to the deposited amount.<br>
The deposit / withdraw functions also use the VUSD contract balance for the shares computation. (`balance() = vusd.balanceOf(address(this))`)

It's possible to increase the share price to very high amounts and price out smaller depositors.

### Proof of Concept

*   `deposit(_amount = 1)`: Deposit the smallest unit of VUSD as the first depositor. Mint 1 share and set the total supply and VUSD balance to `1`.
*   Perform a direct transfer of `1000.0` VUSD to the `InsuranceFund`. The `balance()` is now `1000e6 + 1`
*   Doing any deposits of less than `1000.0` VUSD will mint zero shares: `shares = _amount * _totalSupply / _pool = 1000e6 * 1 / (1000e6 + 1) = 0`.
*   The attacker can call `withdraw(1)` to burn their single share and receive the entire pool balance, making a profit. (`balance() * _shares / totalSupply() = balance()`)

I give this a high severity as the same concept can be used to always steal the initial insurance fund deposit by frontrunning it and doing the above-mentioned steps, just sending the frontrunned deposit amount to the contract instead of the fixed `1000.0`.
They can then even repeat the steps to always frontrun and steal any deposits.

### Recommended Mitigation Steps

The way [Unisw

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-hubble)

---

### Example 18: M-12: Vault Share/Strategy Token Calculation Can Be Broken By First User/Attacker

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

### Example 19: H-2: Vault is vulnerable to inflation attack which can cause complete loss of user funds

**Source**: Sherlock
**Protocol**: Numa
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/253 

## Found by 
0xlucky, Abhan1041, AestheticBhai, KupiaSec, Oblivionis, ZZhelev, blutorque, jokr, juaan, novaman33, smbv-1923

### Summary

Attacker can attack the first depositors in the vault and can steal all users funds. this attack is also famously known has first deposit bug too. while doing this attack , there is no loss of attacker funds, but there is complete loss of user funds. he can complete this attack by front running and then backrunning , means sandwiching user funds. this problem takes place , due to improper use of exchange rate when total supply is 0. 

### Root Cause

https://github.com/sherlock-audit/2024-12-numa-audit/blob/main/Numa/contracts/lending/CErc20.sol#L60C1-L63C6

https://github.com/sherlock-audit/2024-12-numa-audit/blob/main/Numa/contracts/lending/CToken.sol#L510C1-L515C1

here root cause is total cash in formula is being calculated with balanceOF(address(this)), which can donated direclty too. and price can be inflated

### Internal pre-conditions

_No response_

### External pre-conditions

In this attack , attacker should be the first depositor,  and while deploying on ethereum, he can frontrun and can be the first depositor. 

### Attack Path

while depositing when , total supply of minting token is 0, attacker will deposit , 1 wei of asset and will be minted with 1 wei of share.

so now total supply would be 1 wei. 

now , he wil

*[Content truncated...]*

---

### Example 20: H-1: Public vault : Initial depositor can manipulate the price per share value and future depositors are forced to deposit huge value in vault.

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

### Example 21: [M-09]  A malicious early depositor can manipulate the `LP-Token` price per share to take an unfair share of future user deposits

**Source**: Code4rena
**Protocol**: Dopex
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-08-dopex/blob/main/contracts/perp-vault/PerpetualAtlanticVaultLP.sol#L118> 

<https://github.com/code-423n4/2023-08-dopex/blob/main/contracts/perp-vault/PerpetualAtlanticVaultLP.sol#L283>

A  malicious early depositor can profit from future depositors' deposits. While the late depositors will lose part of their funds to the attacker.

### Vulnerability Details

The first depositor can buy a small number of shares and next he should wait until   owner  settle an options through `RdpxCore` so it will result in calling `addRDPX` in `PerpetualAtlanticVaultLP` by transfering rdpxTokens into it and updating `_rdpxCollateral`, as `rdpx Token` has 18 decimals `https://arbiscan.io/token/0x32eb7902d4134bf98a28b963d26de779af92a212` even small amount of rdpx token result in giving a higher `totalVaultCollateral()` so then it calculates `assets.mulDivDown(supply,totalVaultCollateral);` , then it  will make shares very expensive for the next depositors,

### POC

`copy this test into  /tests/perp-vault/Integration.t.sol`<br>
`forge test --match-path  ./tests/perp-vault/Integration.t.sol   -vvvv`

```js
 function test_second_user_loss_share() external {
  //=============================
  address  hecer  = makeAddr("Hecer");
  address  investor = makeAddr("investor");
  //=============================

 setApprovals(hecer);
 setApprovals(investor);

    mintWeth(1 wei, hecer); // hecker starts with 1 wei 🐱‍👤
    mintWeth(20 ether, investor);
 
 
 consol

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-dopex)

---

### Example 22: Inflation attack can cause early users to lose their deposit

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

### Example 23: M-1: Vault Inflation Attack

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

### Example 24: H-2: First depositor can abuse exchange rate to steal funds from later depositors

**Source**: Sherlock
**Protocol**: Surge
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-surge-judging/issues/125 

## Found by 
0Kage, 0x52, 0xAsen, 0xc0ffEE, 0xhacksmithh, Ace-30, Bobface, Breeje, CRYP70, Chinmay, Cryptor, GimelSec, Juntao, MalfurionWhitehat, RaymondFam, SunSec, TrungOre, VAD37, \_\_141345\_\_, ak1, banditx0x, bin2chen, bytes032, carrot, cccz, chaduke, chainNue, ck, ctf\_sec, dingo, gandu, gryphon, peanuts, rvi, unforgiven, usmannk, y1cunhui
## Summary

Classic issue with vaults. First depositor can deposit a single wei then donate to the vault to greatly inflate share ratio. Due to truncation when converting to shares this can be used to steal funds from later depositors.

## Vulnerability Detail

See summary.

## Impact

First depositor can steal funds due to truncation

## Code Snippet

https://github.com/sherlock-audit/2023-02-surge/blob/main/surge-protocol-v1/src/Pool.sol#L307-L343

## Tool used

[Solidity YouTube Tutorial](https://www.youtube.com/watch?v=dQw4w9WgXcQ)

## Recommendation

Either during creation of the vault or for first depositor, lock a small amount of the deposit to avoid this.



## Discussion

**xeious**

GG. We left this one intentionally. Glad to see this many duplicates.

**xeious**

Fixed

**xeious**

https://github.com/Surge-fi/surge-protocol-v1/commit/35e725cc25a97c0ee4a76fc5523ede90ac4ea130

**IAm0x52**

Fix looks good. First deposit now creates a minimum liquidity that make advantageous manipulation nearly impossible

---

### Example 25: M-5: Early depositors to DnGmxSeniorVault can manipulate exchange rates to steal funds from later depositors

**Source**: Sherlock
**Protocol**: Rage Trade
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-rage-trade-judging/issues/37 

## Found by 
rvierdiiev, tives, peanuts, joestakey, cccz, ctf\_sec, \_\_141345\_\_, 0x52, GimelSec, clems4ever

## Summary

To calculate the exchange rate for shares in DnGmxSeniorVault it divides the total supply of shares by the totalAssets of the vault. The first deposit can mint a very small number of shares then donate aUSDC to the vault to grossly manipulate the share price. When later depositor deposit into the vault they will lose value due to precision loss and the adversary will profit.

## Vulnerability Detail

    function convertToShares(uint256 assets) public view virtual returns (uint256) {
        uint256 supply = totalSupply(); // Saves an extra SLOAD if totalSupply is non-zero.

        return supply == 0 ? assets : assets.mulDivDown(supply, totalAssets());
    }

Share exchange rate is calculated using the total supply of shares and the totalAsset. This can lead to exchange rate manipulation. As an example, an adversary can mint a single share, then donate 1e8 aUSDC. Minting the first share established a 1:1 ratio but then donating 1e8 changed the ratio to 1:1e8. Now any deposit lower than 1e8 (100 aUSDC) will suffer from precision loss and the attackers share will benefit from it.

This same vector is present in DnGmxJuniorVault.

## Impact

Adversary can effectively steal funds from later users

## Code Snippet

https://github.com/sherlock-audit/2022-10-rage-trade/blob/main/d

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 26
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

