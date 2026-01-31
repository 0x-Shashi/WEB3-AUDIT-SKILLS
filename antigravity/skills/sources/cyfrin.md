---
id: SRC-CYFRIN
title: Cyfrin Audit Findings
category: audit-firm
firm_name: 
last_updated: 2026-01-31
---
# Cyfrin - Audit Findings

## Overview

**Total Findings**: 2,133 (4.22% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 199 | 379 | 1187 | 368 |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|
| Code Quality | 6 |
| Overflow/Underflow | 4 |
| Weird ERC20 | 4 |
| Business Logic | 3 |
| Validation | 3 |
| Vote | 3 |
| ERC20 | 3 |
| Documentation | 3 |
| Auditing and Logging | 2 |
| Delegate | 2 |

---

## Notable Findings

### 1. Read-only reentrancy

**Protocol**: Beanstalk Wells | **Impact**: HIGH

**Description:** The current implementation is vulnerable to read-only reentrancy, especially in [Wells::removeLiquidity](https://github.com/BeanstalkFarms/Wells/blob/e5441fc78f0fd4b77a898812d0fd22cb43a0af55/src/Well.sol#L440).
The implementation does not strictly follow the [Checks-Effects-Interactions (CEI) pattern](https://fravoll.github.io/solidity-patterns/checks_effects_interactions.html) as it is setting the new reserve values after sending out the tokens. This is not an immediate risk to the protocol itself due to the `nonReentrant` modifier, but this is still vulnerable to [read-only ...

---

### 2. `TokenBridge::bridgeToken` allows 1-way `ERC721` bridging causing users to permanently lose their nfts

**Protocol**: Linea | **Impact**: HIGH

**Description:** `TokenBridge::bridgeToken` is only intended to support `ERC20` tokens however it quite happily accepts `ERC721` tokens and is able to successfully bridge them over to the L2. But when users attempt to bridge back to the L1 this always reverts resulting in user nfts being permanently stuck inside the `TokenBridge` contract.

This was not introduced in the latest changes but is present in the current mainnet `TokenBridge` [code](https://github.com/Consensys/linea-contracts/blob/main/contracts/tokenBridge/TokenBridge.sol).

**Proof of Concept:** Add new file `contracts/tokenBridg...

---

### 3. Attacker can bypass token sale `maxAllocationPerUser` restriction to buy out the entire tier

**Protocol**: Dexe | **Impact**: HIGH

**Description:** An attacker can bypass the token sale `maxAllocationPerUser` restriction to buy out the entire tier by doing multiple small buys under this limit.

**Impact:** Permanent grief for other users who are unable to buy any of the exploited tier's tokens. Depending on the total supply a buyer could take control of the majority of the tokens by scooping them all up in a token sale, preventing them being distributed as intended and having monopoly control of the market. The `maxAllocationPerUser` restriction is not working as intended and can easily be bypassed by anyone.

**Proof of ...

---

### 4. Attacker can destroy user voting power by setting `ERC721Power::totalPower` and all existing NFTs `currentPower` to 0

**Protocol**: Dexe | **Impact**: HIGH

**Description:** Attacker can destroy user voting power by setting `ERC721Power::totalPower` & all existing nfts' `currentPower` to 0 via a permission-less attack contract by exploiting a discrepancy ("<" vs "<=") in `ERC721Power` [L144](https://github.com/dexe-network/DeXe-Protocol/tree/f2fe12eeac0c4c63ac39670912640dc91d94bda5/contracts/gov/ERC721/ERC721Power.sol#L144) & [L172](https://github.com/dexe-network/DeXe-Protocol/tree/f2fe12eeac0c4c63ac39670912640dc91d94bda5/contracts/gov/ERC721/ERC721Power.sol#L172):

```solidity
function recalculateNftPower(uint256 tokenId) public override returns...

---

### 5. Attacker can combine flashloan with delegated voting to decide a proposal and withdraw their tokens while the proposal is still in Locked state

**Protocol**: Dexe | **Impact**: HIGH

**Description:** Attacker can combine a flashloan with delegated voting to bypass the existing flashloan mitigations, allowing the attacker to decide a proposal & withdraw their tokens while the proposal is still in the Locked state. The entire attack can be performed in 1 transaction via an attack contract.

**Impact:** Attacker can bypass existing flashloan mitigations to decide the outcome of proposals by combining flashloan with delegated voting.

**Proof of Concept:** Add the attack contract to `mock/utils/FlashDelegationVoteAttack.sol`:
```solidity
// SPDX-License-Identifier: MIT
pragma ...

---

### 6. During the yield phase, when using supported vaults, users can't withdraw vault assets they are entitled to

**Protocol**: Strata | **Impact**: HIGH

**Description:** During the yield phase, when using supported vaults, users can't withdraw vault assets they are entitled to.

**Proof of Concept:**
```solidity
function test_yieldPhase_supportedVaults_userCantWithdrawVaultAssets() external {
    // user1 deposits $1000 USDe into the main vault
    uint256 user1AmountInMainVault = 1000e18;
    USDe.mint(user1, user1AmountInMainVault);

    vm.startPrank(user1);
    USDe.approve(address(pUSDe), user1AmountInMainVault);
    uint256 user1MainVaultShares = pUSDe.deposit(user1AmountInMainVault, user1);
    vm.stopPrank();

    assertEq(pUSDe.totalA...

---

### 7. An attacker can drain the entire protocol balance of sUSDe during the yield phase due to incorrect redemption accounting logic in `pUSDeVault::_withdraw`

**Protocol**: Strata | **Impact**: HIGH

**Description:** After transitioning to the yield phase, the entire protocol balance of USDe is deposited into sUSDe and pUSDe can be deposited into the yUSDe vault to earn additional yield from the sUSDe. When initiating a redemption, `yUSDeVault::_withdraw` is called which in turn invokes `pUSDeVault::redeem`:

```solidity
    function _withdraw(address caller, address receiver, address owner, uint256 pUSDeAssets, uint256 shares) internal override {
        if (!withdrawalsEnabled) {
            revert WithdrawalsDisabled();
        }

        if (caller != owner) {
            _spendAllowan...

---

### 8. Reward claiming fails for Berachain RewardVaults due to incorrect interface

**Protocol**: D | **Impact**: HIGH

**Description:** D2 plans to deploy on the newly launched Berachain, which operates on a novel [Proof-of-Liquidity](https://docs.berachain.com/learn/what-is-proof-of-liquidity) model. On Berachain, liquidity providers can stake their LP tokens in [Reward Vaults](https://docs.berachain.com/developers/contracts/reward-vault) to earn `$BGT`, the Berachain Governance Token.

To facilitate staking and withdrawals, the D2 [`Bera_Module`](https://github.com/d2sd2s/d2-contracts/blob/c2fc257605ebc725525028a5c17f30c74202010b/contracts/modules/Bera.sol) includes the functions [`Bera_Module::bera_vault_st...

---

### 9. Incorrect accounting of `tipBalance` can indefinitely stall report execution

**Protocol**: Casimir | **Impact**: HIGH

**Description:** The `receive` fallback function in `CasimirManager` increases `tip` balance if the sender is not the `DelayedWithdrawalRouter`. The implicit assumption here is that all withdrawals, full or partial, are routed via the `DelayedWithdrawalRouter`. While this assumption is true incase of partial withdrawals (rewards), this is an incorrect assumption for full withdrawals where the sender is not the `DelayedWithdrawalRouter` but the `EigenPod` itself.

```solidity
    receive() external payable {
        if (msg.sender != address(eigenWithdrawals)) {
            tipBalance += msg.va...

---

### 10. Self-triggered `Licredity::_afterSwap` back-run enables LP fee farming

**Protocol**: Licredity | **Impact**: HIGH

**Description:** When price hits or goes below 1, [`Licredity::_afterSwap`](https://github.com/Licredity/licredity-v1-core/blob/e8ae10a7d9f27529e39ca277bf56cef01a807817/src/Licredity.sol#L734-L753) auto back-runs a swap to push price up:
```solidity
if (sqrtPriceX96 <= ONE_SQRT_PRICE_X96) {
    // back run swap to revert the effect of the current swap, using exactOut to account for fees
    IPoolManager.SwapParams memory params =
        IPoolManager.SwapParams(false, -balanceDelta.amount0(), MAX_SQRT_PRICE_X96 - 1);
    balanceDelta = poolManager.swap(poolKey, params, "");
```
That back-run p...

---

### 11. USDs stability can be compromised as collateral deposited to Gamma vaults is not considered during liquidation

**Protocol**: The Standard Smart Vault | **Impact**: HIGH

**Description:** Users of The Standard can take out `USDs` stablecoin loans against their collateral deposited into an instance of `SmartVaultV4`. If the collateral value of a Smart Vault falls below 110% of the `USDs` debt value, it can be liquidated in full. Users can also move collateral tokens into Gamma Vaults (aka Hypervisors) that hold LP positions in Uniswap V3 to earn an additional yield on their deposited collateral.

Collateral held as yield positions in Gamma Vaults are represented by Hypervisor tokens transferred to and held by the `SmartVaultV4` contract; however, these tokens ar...

---

### 12. Protocol's invariants can be broken

**Protocol**: Beanstalk Wells | **Impact**: HIGH

**Description:** The protocol intends to provide a generalized framework for constant-function AMM liquidity pools.
We have identified some invariants that should hold at any given time. One of these invariants is `totalSupply() == calcLpTokenSupply(reserves)`, and we can interpret this as the pool's total LP supply should match the calculation of LP from the current `reserves` state values.

This invariant can be broken with valid transactions in the current implementation, leading to several problems. For example, valid liquidity removal might revert, as shown in the PoC test below.

**Impac...

---

### 13. `TokenSaleProposal::buy` implicitly assumes that buy token has 18 decimals resulting in a potential total loss scenario for Dao Pool

**Protocol**: Dexe | **Impact**: HIGH

**Description:** `TokenSaleProposalBuy::buy` is called by users looking to buy the DAO token using a pre-approved token. The exchange rate for this sale is pre-assigned for the specific tier. This function internally calls `TokenSaleProposalBuy::_purchaseWithCommission` to transfer funds from the buyer to the gov pool. Part of the transferred funds are used to pay the DexeDAO commission and balance funds are transferred to the `GovPool` address. To do this, `TokenSaleProposalBuy::_sendFunds` is called.

```solidity
    function _sendFunds(address token, address to, uint256 amount) internal {
 ...

---

### 14. Spot price manipulation can lead to unfair liquidations

**Protocol**: Deriverse Dex | **Impact**: HIGH

**Description:** When perpetual instruments are configured without an oracle feed, the system uses the spot market's `last_px` as the `perp_underlying_px` for liquidation calculations. The spot price (`last_px`) can be manipulated through order book orders or AMM trades, allowing attackers to trigger unfair liquidations of healthy perpetual positions. This vulnerability enables malicious actors to force liquidations at manipulated prices, causing significant financial losses to users.

When no oracle is configured, the spot price directly becomes the perpetual underlying price:

Liquidations a...

---

### 15. Missing Signer Verification in `voting_reset` Function Allows Unauthorized Execution

**Protocol**: Deriverse Dex | **Impact**: HIGH

**Description:** The `voting_reset` function in `src/program/processor/voting_reset.rs` only verifies that the `admin` account's public key matches the operator address, but does not verify that the `admin` account is actually a signer of the transaction. **This allows an attacker to execute the `voting reset` instruction by passing account that matches the operator address but no signing is required, resetting critical voting parameters without proper authorization.**

```rust
    let root_state: &RootState = RootState::from_account_info(root_acc, program_id)?;

    if root_state.operator_add...

---


## Statistics

- Total findings from Cyfrin: 2,133
- Last updated: 2026-01-29

