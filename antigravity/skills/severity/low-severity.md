# LOW Severity Findings

## Overview

**Total Findings**: 25,272 (50.01% of all findings)

## Top Vulnerability Types at LOW Severity

| Rank | Vulnerability Type | Count |
|------|-------------------|-------|
| 1 | Code Quality | 8 |
| 2 | Business Logic | 7 |
| 3 | 0x | 3 |
| 4 | EIP-165 | 3 |
| 5 | Documentation | 3 |
| 6 | ERC20 | 2 |
| 7 | ERC4626 | 2 |
| 8 | 1/64 Rule | 2 |
| 9 | Auditing and Logging | 2 |
| 10 | API Inconsistency | 2 |
| 11 | Access Control | 2 |
| 12 | Upgradable | 2 |
| 13 | supportsInterface | 2 |
| 14 | Missing Check | 2 |
| 15 | Configuration | 2 |
| 16 | Event | 2 |
| 17 | Wrong Math | 2 |
| 18 | Fee On Transfer | 1 |
| 19 | Auction | 1 |
| 20 | Gas Limit | 1 |

---

## Representative Examples

### 1. [L-01] Pawn Duration Not Bound to Signed Quote Allows 730-day Term Tampering

- **Source**: Shieldify
- **Protocol**: Shiny
- **Tags**: None

## Severity

Low Risk

## Description

`PawnShop` verifies an EIP-712 signature over `(tokenId, offerAmount, validUntil, nonce)` but `pawn()` accepts a user-supplied `durationDays` that is **not signed**.
This lets a borrower reuse the _same_ backend+treasury signatures while swapping duration terms:

#### (Case 1): The backend intended a 7-day loan, but the borrower executed it as a 30-day loan.

Impact (max severity scenario):

- If your backend/risk engine prices or approves offers differently per duration (common),
  a borrower can bypass that policy by choosing the more favourable term on-chain.

#### (Case 2): The backend intended a 30-day loan, but the borrower executed it as a 7-day loan.

Impact:

- Direct protocol revenue loss: borrower pays the 7-day fee schedule instead of the ...

[View Full Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/Shiny-Security-Review.md)

---

### 2. [L-07] Implementing `renounceOwnership()` is dangerous

- **Source**: Pashov Audit Group
- **Protocol**: BOB_2025-03-17
- **Tags**: None

`OfframpRegistry.sol` inherits `Ownable2Step`, and renouncing ownership via `renounceOwnership()` is possible since the function is not overridden. Leaving the contract without an owner would prevent offramps from being added/removed, as well as submitters from being authorized/deauthorized, which can lead to numerous undesirable outcomes:

- Malicious/Compromised offramp can grief users by accepting every order without the intention of processing it by sending BTC, locking user funds for 7 days whenever they create an order
- If the relay contract responsible for calling `verifyAndReleaseBtcTransfer()` becomes compromised or experiences a bug leading to downtime, the contract would be bricked since it would no longer be possible to deauthorize the faulty contract and reauthorize a new one...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/BOB-security-review_2025-03-17.md)

---

### 3. Reserved assets could be extracted from the Vault

- **Source**: Cyfrin
- **Protocol**: Accountable
- **Tags**: Auditing and Logging

**Description:** Some strategy functions can release assets without checking if those assets are part of `reservedLiquidity`. `AccountableFixedTerm._loan.drawableFunds` is not verified to be in sync with the queue `reservedLiquidity`. Hence the borrower can inadvertently borrow more funds than they should.

**Impact:** The vault can become insolvent by releasing funds needed to honor a withdrawal.

**Proof of Concept:** Violated in `FixedTerm.acceptLoanLocked(), FixedTerm.borrow(), FixedTerm.pay(), FixedTerm.acceptLoanDynamic(), FixedTerm.claimInterest()`: https://prover.certora.com/output/52567/edb399a43d1849a9b22f027e66b17924/?anonymousKey=3dcf62dfa004381083966b3639b6a485fa2e9501

```solidity
// Reserved liquidity must not exceed total assets
invariant reservedLiquidityBacked(env e)
    ...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-10-16-cyfrin-accountable-v2.0.md)

---

### 4. firstTotalAssets analysis

- **Source**: Spearbit
- **Protocol**: Morpho Vaults v2 Fix Review
- **Tags**: None

## Severity: Low Risk

## Context
- `VaultV2.sol#L30-L34`
- `VaultV2.sol#L179`
- `VaultV2.sol#L563-L571`
- `VaultV2.sol#L578`

## Description
In the NatSpec comments we have:
```solidity
/// FIRST TOTAL ASSETS
/// @dev The variable firstTotalAssets tracks the total assets after the first interest accrual of the
/// transaction.
/// @dev Used to implement a mechanism that prevents bypassing relative caps with flashloans.
/// @dev This mechanism can generate false positives on relative cap breach when such a cap is nearly
/// reached, for big deposits that go through the liquidity adapter.
```
The comment is not quite accurate. We have:

```solidity
function accrueInterest() public {
    (uint256 newTotalAssets, ...) = accrueInterestView();
    // ...
    _totalAssets = newTotalAssets.toUint...

[View Full Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Vaults-v2-fixes-Spearbit-Security-Review-August-2025.pdf)

---

### 5. [L-04] Centralization Risks

- **Source**: Shieldify
- **Protocol**: Spellborne
- **Tags**: None

## Severity

Low Risk

## Description

The current design has centralization issues that put too much power behind a single key and make any key compromise more damaging.

1. The `MANAGER_ROLE` mixes powerful admin actions with simple automation (`lockToken()`, `unlockToken()`) as stated in the documentation:

> Backend calls contract to lock NFT (non-transferable).

> Backend unlocks NFT via contract call.

https://www.notion.so/monstudios/Monsters-283b08fdf0db80c28036c92bfa34abef

This means the backend key used for automation must also hold strong permissions (`pause()`/`unpause()`, `withdraw()` ETH, `setBaseURI()`, `setDefaultRoyalty()` and `setTokenRoyalty()`).

2. In addition, the constructor grants all roles to the deployer, so compromising the deployer gives full control.

## Locat...

[View Full Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/Spellborne-Security-Review.md)

---

### 6. [L-03] Level 5 Users Will Be Obligated to Pay Commissions to Lower Level Users Under Certain Conditions

- **Source**: Shieldify
- **Protocol**: Terplayer Bvt Staking&Distribution
- **Tags**: None

## Severity

Low Risk

## Description

There is a slight chance of a Level 5 user having a Level 0 parent, which will lead to the Level 5 user paying commissions to lower-level users. Right now, the `BondDealer::_getHigherLevelParents` function performs the following check:

```solidity
 @> if (parentLevel > currentLevel || (hop == 0 && parentLevel > 0)) {
```

This will lead to skipping the break line and will actually compute a `higherLevelParents` array for the highest level possible, leading to the Level 5 user paying commissions to lower-level users instead of the protocol.

## Location of Affected Code

File: [src/BondDealer.sol#L270](https://github.com/batoshidao/berabtc-vault-token/blob/c68f412b3c7dfd99d3f6302a42bdf772ededb2a3/src/BondDealer.sol#L270)

```solidity
function _getHigh...

[View Full Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/Terplayer-BVT-Staking&Distribution-Security-Review.md)

---

### 7. [L-08] Updating `attestation_window` may cause missed rewards

- **Source**: Pashov Audit Group
- **Protocol**: Starknet_2025-07-31
- **Tags**: None

_Acknowledged_

When the `set_attestation_window` function is called to modify `attestation_window`, the change is applied directly to the current epoch. 
```rust
fn set_attestation_window(ref self: ContractState, attestation_window: u16) {
    self.roles.only_app_governor();
    assert!(
        attestation_window >= MIN_ATTESTATION_WINDOW, "{}", Error::ATTEST_WINDOW_TOO_SMALL,
    );
    let old_attestation_window = self.attestation_window.read();
    self.attestation_window.write(attestation_window);
    self
        .emit(
            Events::AttestationWindowChanged {
                old_attestation_window, new_attestation_window: attestation_window,
            },
        );
}
```
Since `attestation_window` is involved in calculating `target_attestation_block` and the attestation win...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/Starknet-security-review_2025-07-31.md)

---

### 8. [L-04] Operations that modify the exchange rate can be frontrun

- **Source**: Pashov Audit Group
- **Protocol**: LoopVaults_2025-04-30
- **Tags**: None

`onMorphoSupplyCollateral()` and `onMorphoRepay()` update the `lastTotalAssets` variable with the net profit or loss resulting from the operation. This will instantly modify the exchange rate for shares to assets, which opens the door for frontrunning attacks.

In the case of an increase in the value of the assets, an attacker can make a deposit just before the allocator's call and redeem the shares just after, profiting from the difference in the exchange rate.

In the case of a decrease in the value of the assets, shareholders can redeem their shares just before the allocator's call to avoid incurring losses, increasing the losses for the rest of the shareholders.

**Proof of concept**

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.so...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/LoopVaults-security-review_2025-04-30.md)

---

### 9. [L-04] `swapActive()` can be manipulated to return incorrect state

- **Source**: Pashov Audit Group
- **Protocol**: Reserve_2025-06-02
- **Tags**: None

`swapActive()` is called by critical flows:

1. `stateChangeActive()` --> `swapActive()`.
2. `sync()` --> `_poke()` --> `_closeTrustedFill()` --> `closeFiller()` --> `swapActive()`.

**Case1:**
External integrating protocol calls `stateChangeActive()` and wants to see `(false, false)` before trusting the Folio state. Suppose:

- `sellAmount` is `100`.
- `sellTokenBalance` is `98` i.e. swap is still active and only partial sell has occurred.
- Ideally external protocol should see `(false, true)`.
- Attack scenario: Attacker front runs the call to `stateChangeActive()` and donates `2` sellTokens.
- Now, inside the `swapActive()` function, `if (sellTokenBalance >= sellAmount)` evaluates to `true`, and swap is reported as completed i.e. `false` is returned.
- External protocol trusts an incons...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/Reserve-security-review_2025-06-02.md)

---

### 10. [L-12] User cannot claim reward if his lock is expired

- **Source**: Pashov Audit Group
- **Protocol**: KittenSwap_2025-06-12
- **Tags**: None

In Rebase Reward contract, rewards are distributed to voting escrow locks as additional lock amount. Whenever a user claims reward `deposit_for` function is called in `_getReward` function.

```solidity
    function _getReward(
        uint256 _period,
        uint256 _tokenId,
        address _token,
        address _owner
    ) internal override {
        if (totalVotesInPeriod[_period] > 0) {
            uint256 reward = _earned(_period, _tokenId, _token); reward is not kitten, directly transfer it
            tokenIdRewardClaimedInPeriod[_period][_tokenId][_token] += reward;

            if (reward > 0) {
@>              veKitten.deposit_for(_tokenId, reward);
                emit ClaimReward(_period, _tokenId, _token, _owner);
            }
        }
    }
```

Voting escrow doesn't a...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/KittenSwap-security-review_2025-06-12.md)

---

### 11. [L-07] Stale Price Usage in Inactive Asset Settlement

- **Source**: Code4rena
- **Protocol**: Starknet Perpetual
- **Tags**: None

<https://github.com/starkware-libs/starknet-perpetual/blob/9e48514c6151a9b65ee23b4a6f9bced8c6f2b793/workspace/apps/perpetuals/contracts/src/core/core.cairo# L913-L914>
```

        fn reduce_inactive_asset_position(
            ref self: ContractState,
            operator_nonce: u64,
            position_id_a: PositionId,
            position_id_b: PositionId,
            base_asset_id: AssetId,
            base_amount_a: i64,
        ) {
            /// Validations:
            self.pausable.assert_not_paused();
            self.operator_nonce.use_checked_nonce(:operator_nonce);
            self.assets.validate_assets_integrity();

            let position_a = self.positions.get_position_snapshot(position_id: position_id_a);
            let position_b = self.positions.get_position_snapsh...

[View Full Finding](https://code4rena.com/reports/2025-03-starknet-perpetual)

---

### 12. [L-12] The `_beforeTokenTransfer()` function does not verify whether addresses are whitelisted when `WHITELIST_ENABLED` is set.

- **Source**: Code4rena
- **Protocol**: Ethena Labs
- **Tags**: None

As noted in line 191, the function only checks if the address `to` is not blacklisted. Consequently, unwhitelisted users can still receive UStb when `WHITELIST_ENABLED` is active. This issue appears in several locations.

https://github.com/code-423n4/2024-11-ethena-labs/blob/main/contracts/ustb/UStb.sol#L165-L218

```solidity
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // State 2 - Transfers fully enabled except for blacklisted addresses
        if (transferState == TransferState.FULLY_ENABLED) {

            ...

        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
191   ...

[View Full Finding](https://code4rena.com/reports/2024-11-ethena-labs)

---

### 13. [L-05] `Folio.bid()` strict sell amount causes DoS and auction execution loss

- **Source**: Pashov Audit Group
- **Protocol**: Reserve_2025-06-02
- **Tags**: None

The `Folio.bid()` function enforces that bids specify a strict `sellAmount` such that `minSellAmount == sellAmount == maxSellAmount`.

```solidity
function bid(
    //...
    uint256 sellAmount,
    //...
) external nonReentrant notDeprecated sync returns (uint256 boughtAmt) {
    Auction storage auction = auctions[auctionId];

    // checks auction is ongoing and that boughtAmt is below maxBuyAmount
    (, boughtAmt, ) = _getBid(
        --- SNIPPED ---
        sellAmount,             //> minSellAmount
        sellAmount,             //> maxSellAmount
        maxBuyAmount
    );

    --- SNIPPED ---
}
```

The available sell balance is checked at execution time in `RebalanceLib::getBid()`:

```solidity
require(sellAvailable >= params.minSellAmount, IFolio.Folio__InsufficientSellAvailable(...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/Reserve-security-review_2025-06-02.md)

---

### 14. [L-08] `protocolCut` not actually burned during `_mintBox`

- **Source**: Pashov Audit Group
- **Protocol**: WishWish_2025-11-04
- **Tags**: ERC20, Fee On Transfer, Business Logic

_Resolved_

Code comments suggest that the `WishWishManager::_mintBox` function calculates a `protocolCut` meant to be burned when users mint boxes. However, instead of invoking a burn function, the code simply transfers the tokens to `address(0)`, which does not reduce the `totalSupply`. As a result, the tokens remain in circulation.

```solidity
// WishWishManager.sol
    function _mintBox(MintData calldata mintData, bytes calldata signature) internal {
...
        if (mintData.fee != 0) {
            uint256 protocolCut = (mintData.fee * $.MINT_FEE_PERCENT) / 1 ether;
            creatorCut = mintData.fee - protocolCut;
            $.wishToken.transferFrom(msg.sender, address(0), protocolCut); // burn protocol fee
            $.wishToken.transferFrom(msg.sender, c.creatorAddress, creato...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/WishWish-security-review_2025-11-04.md)

---

### 15. [L-03] Validation in `isValidSignature()` prevents partial fills at good prices

- **Source**: Pashov Audit Group
- **Protocol**: Reserve_2025-06-02
- **Tags**: None

The `CowSwapFiller` contract validates orders with a strict requirement that the order's sell amount must be less than or equal to the filler's current sell amount:

```solidity
function isValidSignature(bytes32 orderHash, bytes calldata signature) external view returns (bytes4) {
    --- SNIPPED ---

    uint256 orderPrice = Math.mulDiv(order.buyAmount, D27, order.sellAmount, Math.Rounding.Floor);
@>  require(order.sellAmount <= sellAmount && orderPrice >= price, CowSwapFiller__OrderCheckFailed(100));

    --- SNIPPED ---
}
```

This creates a timing issue between the time an order is created (off-chain via the CoW Protocol API) and the time it is settled on-chain:

- When a bot submits a CoW Protocol order, it typically uses `Folio.getBid()` to fetch the current `sellAmount` and `buyAmou...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/Reserve-security-review_2025-06-02.md)

---

### 16. [QA-06] Uniswap V3 cant be fully used, contrary to docs

- **Source**: Code4rena
- **Protocol**: Lambo.win
- **Tags**: None

### Proof of Concept

Per the docs, protocol should be able to seamlessly work on both V2 and V3, with even a hint of V4 in the abstract, see here: <https://github.com/code-423n4/2024-12-lambowin/blob/874fafc7b27042c59bdd765073f5e412a3b79192/doc/LamboV2.pdf>

Issue however is that provision is only made for V2 in scope, see:
<https://github.com/code-423n4/2024-12-lambowin/blob/874fafc7b27042c59bdd765073f5e412a3b79192/src/Utils/LaunchPadUtils.sol# L24-L25>
```

    address public constant UNISWAP_ROUTER_ADDRESS = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
```

Note that this address is the router address for V2 and not V3, making any planned calls via V3s Router unreachable.

### Impact

Protocol is not fully compatible with V3.

### Recommended Mitigation Steps
```

-    address public c...

[View Full Finding](https://code4rena.com/reports/2024-12-lambowin)

---

### 17. [L-11] `CurveStableswapOracle.price()` can overestimate the price of the collateral token

- **Source**: Pashov Audit Group
- **Protocol**: StakeDAO_2025-07-21
- **Tags**: None

_Resolved_

The `CurveStableswapOracle.price()` function returns the price of 1 collateral token in terms of the loan token. The first steps of the calculation are:

1. Get the price of the LP token in its "unit of account". For example, for the `cbBTC/wBTC` pool, this will be the price of the LP token in BTC terms.
2. Get the price of the "unit of account" in USD from the base feed. Following the example, this will be the price of BTC in USD.

```solidity
194:     function price() external view returns (uint256) {
195:         // 1. Get the price of the LP token in its "unit of account" (e.g., USD for USDC/crvUSD or ETH for wstETH/wETH).
196:         // This value always has 18 decimals.
197:         uint256 priceLpInPeg = CURVE_POOL.get_virtual_price();
198: 
199:         // 2. Get the p...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/StakeDAO-security-review_2025-07-21.md)

---

### 18. [QA-02] Interface Documentation References Wrong Token Standard

- **Source**: Code4rena
- **Protocol**: THORWallet
- **Tags**: Documentation

### Finding description and impact

The `IERC677Receiver` interface documentation incorrectly references `ERC1363` instead of `ERC677`. This mismatch between the interface name and its documentation could lead to integration issues and developer confusion.

The interface is named `IERC677Receiver` but its documentation comments reference `ERC1363`s `transferAndCall` functionality. While both standards have similar purposes, they have different implementations and requirements. This inconsistency could cause:

* Integration errors if developers implement the wrong standard based on the documentation
* Confusion during code review and maintenance
* Potential compatibility issues with other contracts expecting specific standard implementations
  The impact is low, as this is primarily a docu...

[View Full Finding](https://code4rena.com/reports/2025-02-thorwallet)

---

### 19. TRST-L-1 Attacker can take over GMXAdapter implementation contract

- **Source**: Trust Security
- **Protocol**: Lyra Finance
- **Tags**: None

**Description:**
GMXAdapter inherits from BaseExchangeAdapter. It is an implementation contract for a 
transparent proxy and has the following initializer:
```solidity
       function initialize() external initializer {
         __Ownable_init();
       }
``` 
Therefore, an attacker can call initialize() on the implementation contract and become the 
owner. At this point they can do just about anything to this contract, but it has no impact on 
the proxy as it is using separate storage. If there was a delegatecall coded in GMXAdapter, 
attacker could have used it to call an attackers contract and execute the SELFDESTRUCT 
opcode, killing the implementation. With no implementation, the proxy itself would not be 
functional until it is updated to a new implementation. It is ill-advised to a...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-01-19-Lyra Finance.md)

---

### 20. [L-05] No access control in `initializeVault()` allows unauthorized init

- **Source**: Pashov Audit Group
- **Protocol**: Saffron_2025-07-31
- **Tags**: None

_Resolved_

The `RestrictedVaultFactory` contract restricts vault creation to the current contract owner. However, it fails to override the `initializeVault()`, which is still accessible to the previous owner who is recorded as the vault's creator.

If ownership of the `RestrictedVaultFactory` contract changes after vault creation but before initialization or there are vaults that were left uninitialed, the previous owner can still initialize those vaults with arbitrary parameters, bypassing the intended restricted control.

```solidity
  function initializeVault(
    uint256 vaultId,
    uint256 fixedSideCapacity,
    uint256 variableSideCapacity,
    uint256 duration,
    address variableAsset
  ) public {
    // Get vault info for the vault we want to initialize and make sure msg.sender...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/Saffron-security-review_2025-07-31.md)

---

### 21. [L-10] X-Powered-By: express header leaks technology stack

- **Source**: Pashov Audit Group
- **Protocol**: Initia_2025-06-17
- **Tags**: None

The application responds with the X-Powered-By: Express HTTP header, revealing that it is built with the Express.js framework. This information leakage may assist an attacker in crafting targeted exploits based on known vulnerabilities or misconfigurations in specific versions of Express or related middleware.

Example Response

```
HTTP/1.1 404 Not Found
X-Powered-By: Express
Access-Control-Allow-Origin: *
Content-Type: application/json; charset=utf-8
Content-Length: 63
ETag: W/"3f-BunLb98SCK6azHy0RO08GDnFBek"
Date: Wed, 18 Jun 2025 17:52:36 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

**Recommendation**

Suppress the X-Powered-By header in Express by adding the following middleware : 

```
const express = require('express');
const app = express();

app.disable('x-powered-by');
`...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/Initia-security-review_2025-06-17.md)

---

### 22. [L-20] Missing parent initializer call in `__UUPSUpgradeable_init()`

- **Source**: Pashov Audit Group
- **Protocol**: Hyperhyper_2025-03-30
- **Tags**: None

The `Oracle.sol` contract inherits from `UUPSUpgradeable` but its `init` function fails to call the corresponding parent initializer function, `__UUPSUpgradeable_init()`. While this parent initializer function might be empty in the current version of the OpenZeppelin library used, omitting the call violates the explicit initialization pattern required by OpenZeppelin Upgradeable contracts. This deviation poses risks for forward compatibility should the library be updated with logic in that initializer, and makes the code non-standard and harder to maintain.

Adhere to the standard OpenZeppelin Upgradeable pattern by explicitly calling `__UUPSUpgradeable_init()` within the `Oracle.init()` function.

```solidity
    function init(address owner) public initializer {
        __UUPSUpgradeable_...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/Hyperhyper-security-review_2025-03-30.md)

---

### 23. Static `gasLimit` will result in overpayment

- **Source**: Cyfrin
- **Protocol**: Yieldfi
- **Tags**: None

**Description:** Since [unspent gas is not refunded](https://docs.chain.link/ccip/best-practices#setting-gaslimit), Chainlink recommends carefully setting the `gasLimit` within the `extraArgs` parameter to avoid overpaying for execution.

In [`BridgeCCIP::send`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/ccip/BridgeCCIP.sol#L131), the `gasLimit` is hardcoded to `200_000`, which is also Chainlinks default:

```solidity
extraArgs: Client._argsToBytes(Client.EVMExtraArgsV2({ gasLimit: 200_000, allowOutOfOrderExecution: true })),
```

This hardcoded value directly affects every user bridging tokens, as they will be consistently overpaying for execution costs on the destination chain.

**Recommended Mitigation:** A more efficient app...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-04-24-cyfrin-yieldfi-v2.0.md)

---

### 24. update_folio has error-prone interface that can lock out the owner

- **Source**: TrailOfBits
- **Protocol**: Reserve Protocol Solana DTFs
- **Tags**: Business Logic

## Diculty: High

## Type: Data Validation

## Description

The `update_folio` instruction allows `program_version` and `program_deployment_slot` arguments to be passed independently (figure 9.1). However, if the owner passes one without the other, they risk locking themselves out of the program. The relevant code appears in figure 9.1. The first thing `update_folio` does is call `validate` on line 96, which calls `validate_folio_program_post_init` on line 70 of figure 9.2. The call to `validate_folio_program_post_init` results in a call to `validate_program_registrar`, part of which appears in figure 9.3.

```rust
85    pub fn handler(
86        ctx: Context<UpdateFolio>,
87        program_version: Option<Pubkey>,
88        program_deployment_slot: Option<u64>,
89        folio_fee: Optio...

[View Full Finding](https://github.com/trailofbits/publications/blob/master/reviews/2025-04-reserve-solana-dtfs-securityreview.pdf)

---

### 25. [04] If a deposit pool has more than 1 public pools connected to it, issues will occur for some users after migration

- **Source**: Code4rena
- **Protocol**: Morpheus
- **Tags**: None

Deposit pools can have more than 1 reward pools attached to it. In the case whereby we have 2 reward `rewardPoolIndex_` for Deposit pool A, and there is some staked tokens in each of these reward pool indexes, after migration, some users will be locked out of withdrawing.

<https://github.com/code-423n4/2025-08-morpheus/blob/main/contracts/capital-protocol/DepositPool.sol# L137-L160>
```

function migrate(uint256 rewardPoolIndex_) external onlyOwner {
        require(!isMigrationOver, "DS: the migration is over");
        if (totalDepositedInPublicPools == 0) {
            isMigrationOver = true;
            emit Migrated(rewardPoolIndex_);

            return;
        }

        IRewardPool rewardPool_ = IRewardPool(IDistributor(distributor).rewardPool());
        rewardPool_.onlyExistedR...

[View Full Finding](https://code4rena.com/reports/2025-08-morpheus)

---

### 26. [01] Allowing DSSes that do not implement `ERC165.supportsInterface` function to be registered is problematic

- **Source**: Code4rena
- **Protocol**: Karak
- **Tags**: EIP-165

### Description
https://github.com/code-423n4/2024-07-karak?tab=readme-ov-file#eip-compliance-checklist states that `DSS contract should comply with ERC-165`. Therefore, the protocol requires that each DSS is ERC-165 compliant.

According to https://eips.ethereum.org/EIPS/eip-165#how-a-contract-will-publish-the-interfaces-it-implements, `A contract that is compliant with ERC-165 shall implement the following interface`:

```solidity
interface ERC165 {
    /// @notice Query if a contract implements an interface
    /// @param interfaceID The interface identifier, as specified in ERC-165
    /// @dev Interface identification is specified in ERC-165. This function
    ///  uses less than 30,000 gas.
    /// @return `true` if the contract implements `interfaceID` and
    ///  `interfaceID` is ...

[View Full Finding](https://code4rena.com/reports/2024-07-karak)

---

### 27. [L-07] Missing User Tickets Mapping Update in `JackpotBridgeManager::claimTickets` Function Causes Gas Inefficiency and Incorrect Return Values

- **Source**: Code4rena
- **Protocol**: Megapot
- **Tags**: None

The `claimTickets()` function fails to update the `userTickets` mapping when tickets are transferred, causing `getUserTickets()` to consume excessive gas and return incorrect results.

When `claimTickets()` is called, it transfers tickets via [`_updateTicketOwnership()`](https://github.com/code-423n4/2025-11-megapot/blob/5cda5779d1a157f847dd13700282dc09558806e4/contracts/JackpotBridgeManager.sol# L364-L370):
```

    function _updateTicketOwnership(uint256[] memory _ticketIds, address _recipient) private {
        for (uint256 i = 0; i < _ticketIds.length; i++) {
            uint256 ticketId = _ticketIds[i];
            delete ticketOwner[ticketId];
            IERC721(address(jackpotTicketNFT)).safeTransferFrom(address(this), _recipient, ticketId);
        }
    }
```

This deletes the `t...

[View Full Finding](https://code4rena.com/reports/2025-11-megapot)

---

### 28. [L-04] Missing Validation for Normal Ball Max Range Causes Critical Function Failures Due to Combination Library Limits and Underflow

- **Source**: Code4rena
- **Protocol**: Megapot
- **Tags**: None

The `normalBallMax` parameter can be set to values that break critical functions. The [`Combinations::choose`](https://github.com/code-423n4/2025-11-megapot/blob/5cda5779d1a157f847dd13700282dc09558806e4/contracts/lib/Combinations.sol# L16) function has an artificial limit:
```

        assert(n >= k);
        assert(n <= 128); // Artificial limit to avoid overflow
```

Setting `normalBallMax` above 128 causes `Combinations.choose(normalBallMax, NORMAL_BALL_COUNT)` to revert with a panic. This affects:

1. `_calculateLpPoolCap()` - called during `setNormalBallMax()`:

   
```

       uint256 maxAllowableTickets = Combinations.choose(_normalBallMax, NORMAL_BALL_COUNT) * (MAX_BIT_VECTOR_SIZE - _normalBallMax);
   
```

2. `_setNewDrawingState()` - called by `initializeJackpot()`:

   
```

  ...

[View Full Finding](https://code4rena.com/reports/2025-11-megapot)

---

### 29. [L-03] Incorrect function name in `CoreWriterDecoderAndSanitizer` affects vault

- **Source**: Pashov Audit Group
- **Protocol**: Nucleus_2025-07-29
- **Tags**: None

_Resolved_

The `CoreWriterDecoderAndSanitizer` contract is intended to support Merkle-verified interactions with the Hyperliquid `coreWriter` precompile by decoding and sanitizing calls made through `sendRawAction(bytes)`. This mechanism is crucial for secure and permissioned interactions originating from the BoringVault via the merkle verification system.

However, the decoder function is incorrectly named:

```solidity
function SendRawAction(bytes calldata data) external view returns (bytes memory);
```

This does **not match the function signature** expected by the Merkle call routing system, which dynamically dispatches to a decoder function that must exactly match the target function being called.

This means that **any attempt to call `sendRawAction(bytes)` via the vault will fail M...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/Nucleus-security-review_2025-07-29.md)

---

### 30. [L-03] Merkle Root Is Mutable Mid-Airdrop

- **Source**: Shieldify
- **Protocol**: Spellborne S2Airdrop
- **Tags**: 0x

## Severity

Low Risk

## Description

The owner can change `merkleRoot` at any time. Already-registered users remain unaffected (state stored), but future registrations switch to the new root, which can change eligibility without warning.

## Location of Affected Code

File: [src/S2Airdrop.sol#L160-L163](https://github.com/SlothFi/s2-airdrop/blob/fa331efe0bc68794537d6df645241f61be14be7b/src/S2Airdrop.sol#L160-L163)

```solidity
function setMerkleRoot(bytes32 root) public onlyOwner {
    merkleRoot = root;
    emit MerkleRootSet(root);
}
```

## Impact

Trust/governance risk: operator can exclude/replace users mid-campaign; users and integrators cannot assume a stable eligibility set after launch.

## Recommendation

Freeze the root after a start time, or gate changes behind a timelock/mul...

[View Full Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/Spellborne-S2Airdrop-Security-Review.md)

---


## Statistics

- Total LOW findings: 25,272
- Examples shown: 30
- Last updated: 2026-01-29

