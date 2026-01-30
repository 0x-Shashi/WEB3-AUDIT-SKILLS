# MEDIUM Severity Findings

## Overview

**Total Findings**: 13,814 (27.34% of all findings)

## Top Vulnerability Types at MEDIUM Severity

| Rank | Vulnerability Type | Count |
|------|-------------------|-------|
| 1 | Business Logic | 127 |
| 2 | Validation | 75 |
| 3 | Front-Running | 67 |
| 4 | Fee On Transfer | 64 |
| 5 | DOS | 43 |
| 6 | Wrong Math | 38 |
| 7 | Oracle | 34 |
| 8 | Denial-Of-Service | 26 |
| 9 | Admin | 25 |
| 10 | Stale Price | 24 |
| 11 | Decimals | 23 |
| 12 | Overflow/Underflow | 22 |
| 13 | Chainlink | 21 |
| 14 | Don't update state | 21 |
| 15 | Weird ERC20 | 20 |
| 16 | Reentrancy | 20 |
| 17 | Access Control | 19 |
| 18 | Missing-Logic | 19 |
| 19 | Liquidation | 17 |
| 20 | ERC4626 | 16 |

---

## Representative Examples

### 1. [M-02] Liquidation Can Be Blocked By Pausing or Blacklisting the NFT Contract, Permanently Trapping Expired Loans

- **Source**: Shieldify
- **Protocol**: Shiny
- **Tags**: None

## Severity

Medium Risk

## Description

When a pawn expires, `PawnShop.liquidate(...)` closes the position by burning the escrowed NFT collateral through the NFT’s `burn(...)` function (context).

However, in this system, the NFT is `RWA`, whose burn path is gated by `whenNotPaused`, and whose transfer/burn internals revert if the caller (`auth`) is blacklisted. This means an admin action on `RWA` (pause or blacklist) can cause `PawnShop.liquidate(...)` to revert (problem).

This traps the loan in an unrecoverable state: the borrower cannot redeem after the `deadline`, and the manager cannot liquidate, so the collateral remains stuck in `PawnShop` indefinitely (impact).

## Location of Affected Code

File: [Pawn.sol#L262-L271](https://github.com/ShinyUrban/SmartContracts/blob/f49b5db73b2...

[View Full Finding](https://github.com/shieldify-security/audits-portfolio-md/blob/main/Shiny-Security-Review.md)

---

### 2. Malformed `op::get_fees_notification` Payload in `fee_manager` Breaks Fee Updates

- **Source**: Quantstamp
- **Protocol**: XDAO
- **Tags**: None

**Update**
The team added the `query_id` to the `op::get_fees_notification` payload. The client mentioned that some contracts may need to retrieve the `admin_address` or a custom payload. Although these are optional, they prefer to keep the data in the payload.

Addressed in: `b101b967bc6025143cc19fa3f177aca5edb65e1f`.

**File(s) affected:**`contracts/fee_manager.fc`

**Description:** The `recv_internal()` handler for `op::get_fees` in `fee_manager` constructs the `op::get_fees_notification` payload with extra fields (`.store_slice(data::admin_address)` and `.store_slice(in_msg_body)`) right after the fee dictionary, deviating from the expected format used by `factory`, which expects a `query_id`. As a result, the `factory` contract cannot parse the response correctly, leading to failed fe...

[View Full Finding](https://certificate.quantstamp.com/full/xdao/2670863d-2e1c-42e6-a15c-5572dd4fef85/index.html)

---

### 3. [M-02] `block.timestamp` use in dex swap deadlines may cause poor trading

- **Source**: Pashov Audit Group
- **Protocol**: Hyperhyper_2025-03-30
- **Tags**: None

## Severity

**Impact:** Medium

**Likelihood:** Medium

## Description

In the PositionInteractionFacet.sol contract, when executing DEX swaps, the `deadline` parameter is set to `block.timestamp + 30 minutes`:

```solidity
IV3SwapRouter.ExactOutputSingleParams memory params = IV3SwapRouter.ExactOutputSingleParams({
    tokenIn: assetIn,
    tokenOut: assetOut,
    fee: dex.dexFee,
    recipient: address(this),
    deadline: block.timestamp + 30 minutes,  // Unnecessary buffer
    amountOut: amountOut,
    amountInMaximum: amountInMaximum,
    sqrtPriceLimitX96: sqrtPriceLimitX96
});
```

This implementation is problematic for several reasons:

1. The `30-minute` buffer is unnecessary since the transaction will be executed at the current `block.timestamp` anyway.
2. This extended deadline...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/Hyperhyper-security-review_2025-03-30.md)

---

### 4. [M-03] The proposal expiration logic is incorrect

- **Source**: Code4rena
- **Protocol**: Initia
- **Tags**: None

The `is_proposal_expired` function uses incorrect comparison logic that causes proposals to be marked as expired when they should still be active, and vice versa. This is as a result of the reversed comparison operator in the expiration check.

The impact of this bug is high because valid proposals are incorrectly marked as expired which prevents legitimate voting. Also the voting period enforcement is effectively reversed. This effectively creates a DoS because any multisig wallet created would be unable to execute proposals.

> N/B: This issue is present in `multisig.move` files in both `initia_stdlib` and `minitia_stdlib`

### Proof of Concept

In the `is_proposal_expired` function:

<https://github.com/initia-labs/movevm/blob/7096b76ba9705d4d932808e9c80b72101eafc0a8/precompile/modules/...

[View Full Finding](https://code4rena.com/reports/2025-01-initia-move)

---

### 5. Gas griefing via duplicate entries in `Allowed` class of enforcers

- **Source**: Cyfrin
- **Protocol**: Metamask Delegationframework
- **Tags**: None

**Description:** Multiple enforcer contracts (`AllowedMethodsEnforcer` and `AllowedTargetsEnforcer`) don't validate the uniqueness of entries in their terms data, allowing malicious users to intentionally create delegations with excessive duplicates, dramatically increasing gas costs during validation.

`AllowedMethodsEnforcer`: Allows duplicate method selectors (4 bytes each)
`AllowedTargetsEnforcer`: Allows duplicate target addresses (20 bytes each)

None of these contracts prevent or detect duplicates in their terms data. This allows an attacker to artificially inflate gas costs by including the same entries multiple times, resulting in expensive linear search operations during validation.


```solidity
function getTermsInfo(bytes calldata _terms) public pure returns (bytes4[] memory al...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-03-18-cyfrin-Metamask-DelegationFramework1-v2.0.md)

---

### 6. Inflation Attack on Zero Total Stake

- **Source**: OtterSec
- **Protocol**: Thala LSD + Deps
- **Tags**: None

## Vulnerability Overview

`staking::stake_thAPT_v2` is susceptible to an inflation attack, which may allow the first depositor to exploit subsequent depositors by manipulating the exchange rate. This can be achieved by making an initial deposit, which would depeg the 1:1 initial ratio between the `sthAPT_supply` and the `thAPT_staking` amount due to the staking fee. After this point, the attacker can continue making progressively larger deposits into the pool, resulting in zero minted `sthAPT`, further inflating the price.

### Code Snippet

```rust
// Source: thala_lsd/sources/staking.move
public fun stake_thAPT_v2(coin: Coin<ThalaAPT>): Coin<StakedThalaAPT> acquires TLSD, PauseFlag {
    // ...
    // exchange_rate = thAPT_staking / sthAPT_supply
    // sthAPT_amount = thAPT_amount / ex...

[View Full Finding](https://www.thala.fi/)

---

### 7. [M-04] Price manipulation risk in GammaVault collateral calculation

- **Source**: Pashov Audit Group
- **Protocol**: GammaSwap_2024-12-30
- **Tags**: None

## Severity

**Impact:** Medium

**Likelihood:** Medium

## Description

The GammaVault contract calculates external collateral for GammaPool positions using the current spot price from Uniswap V3, rather than a more manipulation-resistant price source. This creates a potential vulnerability where an attacker could manipulate the spot price to affect collateral calculations and force unfair liquidations.

```solidity
    function _getCollateral(address _gammaPool, uint256 _tokenId) internal override virtual view returns(uint256 collateral) {
        uint160 sqrtPriceX96 = getCurrentPrice(); // @audit collateral is depent on spot price
        uint160 sqrtPriceAX96 = RangedPoolMath.calcSqrtRatioAtTick(s.tickLower);
        uint160 sqrtPriceBX96 = RangedPoolMath.calcSqrtRatioAtTick(s.tickUpp...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/GammaSwap-security-review_2024-12-30.md)

---

### 8. Borrowers can force swaps on escrow suppliers by transferring the loan's NFT to them

- **Source**: Spearbit
- **Protocol**: Collar Protocol
- **Tags**: None

## Severity: Medium Risk

## Context
- **LoansNFT.sol**: Lines 264-265, Lines 425-426

## Description
In `LoansNFT.closeLoan()`, `_isSenderOrKeeperFor()` is called to check if the borrower has approved the keeper to close the loan on their behalf:
```solidity
address borrower = ownerOf(loanId);
require(_isSenderOrKeeperFor(borrower, loanId), "loans: not NFT owner or allowed keeper");
```

Similarly, in `LoansNFT.forecloseLoan()`, `_isSenderOrKeeperFor()` is called to check if the escrow supplier allows the keeper to call `forecloseLoan()` on their behalf:
```solidity
address escrowOwner = escrowNFT.ownerOf(escrowId);
require(_isSenderOrKeeperFor(escrowOwner, loanId), "loans: not escrow owner or allowed keeper");
```

However, since both `closeLoan()` and `forecloseLoan()` use the same `kee...

[View Full Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Collar-Spearbit-Security-Review-December-2024.pdf)

---

### 9. [M-03] Potential avoidance of liquidation

- **Source**: Pashov Audit Group
- **Protocol**: Sharwafinance
- **Tags**: None

**Severity**

**Impact:** High

**Likelihood:** Low

**Description**

Users can deposit ERC721 tokens using the `MarginTrading::provideERC721` function, which can then be used as collateral for borrowing. Additionally, users can execute the `MarginTrading::exercise` function to convert their ERC721 into `baseToken` value, crediting the respective `marginAccount`.

The issue arises when a malicious user deposits ERC721 tokens that are invalid within the protocol context; i.e., they are inactive, expired, or worthless:

```solidity
File: HegicModule.sol
68:     function checkValidityERC721(uint id) external returns(bool) {
69:         if (getPayOffAmount(id) > 0 && isOptionActive(id) && getExpirationTime(id) > block.timestamp) {
70:             return true;
71:         }
72:     }
```

Consi...

[View Full Finding](https://github.com/pashov/audits/blob/master/team/md/SharwaFinance-security-review.md)

---

### 10. _pendingltv[asset] will be set to 0 if 2 consecutive calls to setreservefreeze(asset, true) are executed 

- **Source**: Cantina
- **Protocol**: AAVE
- **Tags**: None

## Context
**File:** PoolConfigurator.sol  
**Line:** 228  

## Description
The function `setReserveFreeze()` was modified in this 3.1 update to set LTV to 0 on freeze, or revert to the previous value in case of unfreezing:

```solidity
function setReserveFreeze(
    address asset,
    bool freeze
) external override onlyRiskOrPoolOrEmergencyAdmins {
    DataTypes.ReserveConfigurationMap memory currentConfig = _pool.getConfiguration(asset);
    currentConfig.setFrozen(freeze);
    if (freeze) {
        _pendingLtv[asset] = currentConfig.getLtv();
        _isPendingLtvSet[asset] = true;
        currentConfig.setLtv(0);
        emit PendingLtvChanged(asset, currentConfig.getLtv());
    } else if (_isPendingLtvSet[asset]) {
        uint256 ltv = _pendingLtv[asset];
        currentConfig.setLt...

[View Full Finding](https://cdn.cantina.xyz/reports/cantina_competition_aave_may2024.pdf)

---

### 11. EIP-1271 non-compliance and denial of service risk for account abstraction wallets in council safe 

- **Source**: Cantina
- **Protocol**: OP Labs
- **Tags**: None

## Context
(No context files were provided by the reviewer)

## Description
Owners using smart contract wallets (account abstraction) are facing a blocking issue when trying to sign transactions on the Council Safe. This is due to the use of incorrect validation logic for smart contract wallet signatures as defined in EIP1271 in the version of the contract used by the Council Safe. 

The problem occurs in the `checkNSignatures` function. The contract calls the `isValidSignature` function with the wrong types of inputs:

```solidity
require(ISignatureValidator(currentOwner).isValidSignature(
    data,
    contractSignature
) == EIP1271_MAGIC_VALUE, ' GS024 ')
```

The `ISignatureValidator` in the EIP1271 takes `(bytes32, bytes)`, while the interface used in this version of the safe defines ...

[View Full Finding](https://cdn.cantina.xyz/reports/cantina_competition_optimism_may2024.pdf)

---

### 12. [M-06] `L1::xRenzoBridge` and `L2::xRenzoBridge` uses the `block.timestamp` as dependency, which can cause issues

- **Source**: Code4rena
- **Protocol**: Renzo
- **Tags**: Timing, block.number vs block.timestamp

In `L1::xRenzoBridge` the `block.timestamp` from L1 is encoded and sent to L2. When the message is delivered from L1 to L2  with `xRenzoBridge::_updatePrice()`, the function checks the `block.timestamp` like this:

```solidity
    if (_timestamp > block.timestamp) {
            revert InvalidTimestamp(_timestamp);
        }
```

This check is done to not allow future timestamps for updating the price But the timestamps between two chains L1 and L2 are different for chain like Arbitrum as there's a possibility that the sequencer fails to post batches on the parent chain (for example, Ethereum) for a period of time.

According to the [Arbitrum docs](<https://docs.arbitrum.io/build-decentralized-apps/arbitrum-vs-ethereum/block-numbers-and-time#block-timestamps-arbitrum-vs-ethereum>):

> **Tim...

[View Full Finding](https://code4rena.com/reports/2024-04-renzo)

---

### 13. [M-05] No incentive to liquidate small positions could result in protocol going underwater

- **Source**: Code4rena
- **Protocol**: DYAD
- **Tags**: None

The DYAD protocol allows users to deposit as little as 1 WEI via the [`deposit()`](https://github.com/code-423n4/2024-04-dyad/blob/main/src/core/VaultManagerV2.sol#L119-L131) function; however, in order to mint the DYAD token the protocol requires user to have a collateral ratio of 150% or above. Liquidators liquidate users for the profit they can make. Currently, the DYAD protocol awards the value of the DYAD token burned (1 DYAD token is always equal to `$1` when calculated in the liquidate function) + 20% of the collateral left to the liquidator.

```solidity
  function liquidate(uint id, uint to) external isValidDNft(id) isValidDNft(to) {
      uint cr = collatRatio(id);
      if (cr >= MIN_COLLATERIZATION_RATIO) revert CrTooHigh();
      dyad.burn(id, msg.sender, dyad.mintedDyad(addre...

[View Full Finding](https://code4rena.com/reports/2024-04-dyad)

---

### 14. [M-02] No incentive to liquidate when `CR = 1` as asset received `` dyad burned

- **Source**: Code4rena
- **Protocol**: DYAD
- **Tags**: None

Right now there are no incentives to liquidate a position with a `CR<1`, as the liquidator will have to burn the full borrowed amount, and will get the full collateral.

But a `CR<1` means collateral is worth less than borrowed amount. So this is a clear loss for the liquidator, meaning no one will liquidate the position.

```solidity
File: src/core/VaultManagerV2.sol
205:   function liquidate( 
206:     uint id, //The ID of the dNFT to be liquidated.
207:     uint to //The address where the collateral will be sent
208:   ) 
...: 	// ... some code ...
215:❌	   dyad.burn(id, msg.sender, dyad.mintedDyad(address(this), id)); //<@audit: caller need to burn full borrowed amount
216: 
217:       uint cappedCr               = cr < 1e18 ? 1e18 : cr; /// == max(1e18, cr)
218:       uint liquidation...

[View Full Finding](https://code4rena.com/reports/2024-04-dyad)

---

### 15. [M-05] The protocol allows borrowing small positions that can create bad debt

- **Source**: Code4rena
- **Protocol**: Wise Lending
- **Tags**: None

The `WiseLending` protocol allows users to borrow small positions. Even if the protocol has a minimum deposit (collateral) amount check to mitigate the small borrowing position from creating bad debt, this protection can be bypassed.

With a small borrowing position, there is no incentive for a liquidator to liquidate the position, as the liquidation profit may not cover the liquidation cost (gas). As a result, small liquidable positions will not be liquidated, leaving bad debt to the protocol.

### Proof of Concept

The protocol allows users to borrow small positions since no minimum borrowing amount is checked in the [`WiseSecurity::checksBorrow()`](https://github.com/code-423n4/2024-02-wise-lending/blob/79186b243d8553e66358c05497e5ccfd9488b5e2/contracts/WiseSecurity/WiseSecurity.sol#L30...

[View Full Finding](https://code4rena.com/reports/2024-02-wise-lending)

---

### 16. [M-04] Withdrawing uncollateralized deposits is possible even though the position is in liquidation mode

- **Source**: Code4rena
- **Protocol**: Wise Lending
- **Tags**: Bypass limit, Liquidation

Users can withdraw uncollateralized deposits even though their position is liquidable, [as opposed to the README](https://github.com/code-423n4/2024-02-wise-lending/blob/main/README.md?plain=1#L137). If the position is in liquidation mode, users should use their uncollateralized deposits to avoid liquidation instead of removing them.

### Proof of Concept

When withdrawing deposits from public pools, at the end of the tx is executed the [`WiseLending._healthStateCheck() function`](https://github.com/code-423n4/2024-02-wise-lending/blob/main/contracts/WiseLending.sol#L77-L90), which depending on the value of the `powerFarmCheck` will determine if the position's collateral is enough to cover the borrows.

- If `powerFarmCheck` is true, it will use the `bare` value of the collateral; meaning,...

[View Full Finding](https://code4rena.com/reports/2024-02-wise-lending)

---

### 17. [M-01] `fetchPrice` can return different prices in the same transaction

- **Source**: Code4rena
- **Protocol**: eBTC Protocol
- **Tags**: None

<https://github.com/code-423n4/2023-10-badger/blob/f2f2e2cf9965a1020661d179af46cb49e993cb7e/packages/contracts/contracts/PriceFeed.sol#L341> 

<https://github.com/code-423n4/2023-10-badger/blob/f2f2e2cf9965a1020661d179af46cb49e993cb7e/packages/contracts/contracts/PriceFeed.sol#L231>

`PriceFeed.sol:fetchPrice()` can return different prices in the same transaction when Chainlink price changes over 50% and the fallback oracle is not set.

In the scenario of the fallback oracle not set and the Chainlink oracle working correctly the status is `usingChainlinkFallbackUntrusted`. If the Chainlink price changes over 50%, the condition of line 340 evaluates to true, so the last good price is returned and the status is set to `bothOraclesUntrusted`.

```solidity
313        // --- CASE 5: Using Chain...

[View Full Finding](https://code4rena.com/reports/2023-10-badger)

---

### 18. [M-02] All bridged funds will be lost for the users using the account abstraction wallet

- **Source**: Code4rena
- **Protocol**: Ondo Finance
- **Tags**: None

### Lines of code

<https://github.com/code-423n4/2023-09-ondo/blob/47d34d6d4a5303af5f46e907ac2292e6a7745f6c/contracts/bridge/SourceBridge.sol#L61-L82><br>
<https://github.com/code-423n4/2023-09-ondo/blob/47d34d6d4a5303af5f46e907ac2292e6a7745f6c/contracts/bridge/DestinationBridge.sol#L85-L114>

### Impact

Users with account abstraction wallets have a different address across different chains for same account, so if someone using an account abstraction wallet bridge the asset, assets will be minted to wrong address and lost permanently.

### Proof of Concept

Account abstraction wallets have been on the rise for quite a time now and have a lot of users. See the below image for the figures by safe wallet (one of the account abstraction wallets):

![https://user-images.githubusercontent.com/...

[View Full Finding](https://code4rena.com/reports/2023-09-ondo)

---

### 19. The off-chain mechanism must be ensured to work in a correct order strictly

- **Source**: Cyfrin
- **Protocol**: Stake Link
- **Tags**: Admin, Timing, Pause

**Severity:** Medium

**Description:** The `PriorityPool` contract relies on the distribution oracle for accounting and the accounting calculation is done off-chain.

According to the communication with the protocol team, the correct workflow for queued deposits can be described as below:
- Whenever there is a new room for deposit in the staking pool, the function `depositQueuedTokens` is called.
- The `PriorityPool` contract is paused by calling `pauseForUpdate()`.
- Accounting calculations happen off-chain using the function `getAccountData()` and `getDepositsSinceLastUpdate()`(`depositsSinceLastUpdate`) variable to compose the latest Merkle tree.
- The distribution oracle calls the function `updateDistribution()` and this will resume the `PriorityPool`.

The only purpose of pausing the ...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-08-25-cyfrin-stake-link.md)

---

### 20. [M-38] DoS of `RootBridgeAgent` due to missing negation of return values for `UniswapV3Pool.swap()`

- **Source**: Code4rena
- **Protocol**: Maia DAO Ecosystem
- **Tags**: Signed/Unsigned, DOS

### Lines of code

<https://github.com/code-423n4/2023-05-maia/blob/main/src/ulysses-omnichain/RootBridgeAgent.sol#L684><br><https://github.com/code-423n4/2023-05-maia/blob/main/src/ulysses-omnichain/RootBridgeAgent.sol#L728>

### Vulnerability details

Both `RootBridgeAgent._gasSwapIn()` and `RootBridgeAgent._gasSwapOut()` do not negate the negative returned value of `UniswapV3Pool.swap()` before casting to `uint256`. That will cause the parent functions `anyExecute()` and `_manageGasOut()` to revert on overflow when casting return values of `_gasSwapIn()` and `_gasSwapOut()` with `SafeCastLib.toUint128()`.

### Impact

Several external functions in `RootBridgeAgent` (such as `anyExecute()`,  `callOut()`, `callOutAndBridge()`, `callOutAndBridgeMultiple()`, etc) are affected by this issue....

[View Full Finding](https://code4rena.com/reports/2023-05-maia)

---

### 21. [M-07] Royalty recipients will not get fair share of royalties

- **Source**: Code4rena
- **Protocol**: Caviar
- **Tags**: ERC2981, Wrong Math, Royalty, NFT

Recipients of NFTs who accept royalties will not get their fair share of royalties. This is because royalties are calculated by dividing the sales price equally amongst all sold NFTs in that purchase. The issue with this is that it assumes all NFTs cost the same amount when it comes time to deal out royalties. If NFTs cost different amounts, then they should be getting an amount of royalties based on that weight relative to the other NFTs. The impact of this is that Royalties will not be distributed evenly at the expense of the more expensive NFT. Meaning that recipients of the expensive NFT will always receive less than they are owed. And the cheaper ones will get more than owed. In short, this is a loss of funds or misdistribution of funds.

### Proof of Concept

The easiest way to test ...

[View Full Finding](https://code4rena.com/reports/2023-04-caviar)

---

### 22. Multiple ERC4626Router and ERC4626RouterBase functions will always revert

- **Source**: Spearbit
- **Protocol**: Astaria
- **Tags**: WETH, ERC4626, Approve

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
- `vault.re...

[View Full Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### 23. [M-02] Coding logic of the contract upgrading renders upgrading contracts impractical

- **Source**: Code4rena
- **Protocol**: GoGoPool
- **Tags**: None

[Link to original code](https://github.com/code-423n4/2022-12-gogopool/blob/main/contracts/contract/ProtocolDAO.sol#L209-L216)

```solidity
File: https://github.com/code-423n4/2022-12-gogopool/blob/main/contracts/contract/ProtocolDAO.sol

205	/// @notice Upgrade a contract by unregistering the existing address, and registring a new address and name
	/// @param newAddr Address of the new contract
	/// @param newName Name of the new contract
	/// @param existingAddr Address of the existing contract to be deleted
209	function upgradeExistingContract(
			address newAddr,
			string memory newName,
			address existingAddr
		) external onlyGuardian {
			registerContract(newAddr, newName);
			unregisterContract(existingAddr);
216	}
```

Function `ProtocolDAO.upgradeExistingContract` handles contra...

[View Full Finding](https://code4rena.com/reports/2022-12-gogopool)

---

### 24. [M-24] Chainlink price feed is not sufficiently validated and can return stale price

- **Source**: Code4rena
- **Protocol**: Tigris Trade
- **Tags**: Stale Price, Oracle, Chainlink

As mentioned by <https://docs.tigris.trade/protocol/oracle>, "Prices provided by the oracle network are also compared to Chainlink's public price feeds for additional security. If prices have more than a 2% difference the transaction is reverted." The Chainlink price verification logic in the following `TradingLibrary.verifyPrice` function serves this purpose. However, besides that `IPrice(_chainlinkFeed).latestAnswer()` uses Chainlink's deprecated `latestAnswer` function, this function also does not guarantee that the price returned by the Chainlink price feed is not stale. When `assetChainlinkPriceInt != 0` is `true`, it is still possible that `assetChainlinkPriceInt` is stale in which the Chainlink price verification would compare the off-chain price against a stale price returned by th...

[View Full Finding](https://code4rena.com/reports/2022-12-tigris)

---

### 25. [M-05] Failure in endpoint can cause minting more than one NFT with the same token id in different chains

- **Source**: Code4rena
- **Protocol**: Tigris Trade
- **Tags**: None

## Lines of code

https://github.com/code-423n4/2022-12-tigris/blob/588c84b7bb354d20cbca6034544c4faa46e6a80e/contracts/GovNFT.sol#L168


## Vulnerability details

## Impact

In the contract `GovNFT`, it is possible to bridge the governance NFT to other chains. It is also stated in the document that:
>NFT holders only earn the profits generated by the platform on the chain that the NFT is on.

It is assumed that there is only one unique NFT per token id. But there is a scenario that can lead to have more than one NFT with the same token id on different chains.

## Proof of Concept

 - Suppose Bob (honest user who owns an NFT with token id X on chain B) plans to bridge this NFT from chain B to chain A. So, Bob calls the function `crossChain` to bridge the NFT from chain B to chain A. Thus, h...

[View Full Finding](https://code4rena.com/reports/2022-12-tigris)

---

### 26. [M-07] ETH will get stuck if all NFTs do not get sold.

- **Source**: Code4rena
- **Protocol**: Escher
- **Tags**: None

<https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/FixedPrice.sol#L73>

<https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/LPDA.sol#L81-L88>

### Impact

In the `buy` function of FixedPrice and LPDA contracts, the transfer of funds to `saleReceiver` only happens when `newId` becomes equal to `finalId`, i.e, when the entire batch of NFTs gets sold completely.

FixedPrice:

```solidity
        if (newId == sale_.finalId) _end(sale);
```

LPDA:

```solidity
        if (newId == temp.finalId) {
            sale.finalPrice = uint80(price);
            uint256 totalSale = price * amountSold;
            uint256 fee = totalSale / 20;
            ISaleFactory(factory).feeReceiver().transfer(fee);
            temp.saleReceiver.transfer(totalSale - fee);
           ...

[View Full Finding](https://code4rena.com/reports/2022-12-escher)

---

### 27. TransitionLoanManager.add does not account for accrued interest since last call

- **Source**: Spearbit
- **Protocol**: Maple Finance
- **Tags**: Don't update state

## Severity: Medium Risk

## Context
`pool-v2::TransitionLoanManager.sol#L74`

## Description
The `TransitionLoanManager.add` advances the domain start but the accrued interest since the last domain start is not accounted for. It therefore wrongly tracks the `_accountedInterest` variable. If `add` is called several times, the accounting will be wrong.

## Recommendation
Consider tracking the accrued interest or ensure that the `MigrationHelper.addLoansToLM` is called only once in the final migration script, adding all loans at the same time.

```solidity
function add(address loan_) external override nonReentrant {
    ...
    uint256 domainStart_ = domainStart;
    + uint256 accruedInterest;
    if (domainStart_ == 0 || domainStart_ != block.timestamp) {
        + accruedInterest = getAccr...

[View Full Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/MapleV2.pdf)

---

### 28. [M-01] `PirexGmx.initiateMigration` can be blocked

- **Source**: Code4rena
- **Protocol**: Redacted Cartel
- **Tags**: Revert By Sending Dust, Initialization

`PirexGmx.initiateMigration` can be blocked so contract will not be able to migrate his funds to another contract using gmx.

### Proof of Concept

PirexGmx was designed with the thought that the current contract can be changed with another during migration.

`PirexGmx.initiateMigration` is the first point in this long process.

<https://github.com/code-423n4/2022-11-redactedcartel/blob/main/src/PirexGmx.sol#L921-L935>

```solidity
    function initiateMigration(address newContract)
        external
        whenPaused
        onlyOwner
    {
        if (newContract == address(0)) revert ZeroAddress();


        // Notify the reward router that the current/old contract is going to perform
        // full account transfer to the specified new contract
        gmxRewardRouterV2.signalTransfer...

[View Full Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### 29. [M-02] Solmate's ERC20 does not check for token contract's existence, which opens up possibility for a honeypot attack

- **Source**: Code4rena
- **Protocol**: SIZE
- **Tags**: SOLMate

When bidding, the contract pulls the quote token from the bidder to itself.

<https://github.com/code-423n4/2022-11-size/blob/main/src/SizeSealed.sol#L163>

```solidity
SafeTransferLib.safeTransferFrom(ERC20(a.params.quoteToken), msg.sender, address(this), quoteAmount);
```

However, since the contract uses Solmate's [SafeTransferLib](https://github.com/transmissions11/solmate/blob/main/src/utils/SafeTransferLib.sol#L9)

> /// @dev Note that none of the functions in this library check that a token has code at all! That responsibility is delegated to the caller.

Therefore if the token address is empty, the transfer will succeed silently, but not crediting the contract with any tokens.

This error opens up room for a honeypot attack similar to the [Qubit Finance hack](https://halborn.com/ex...

[View Full Finding](https://code4rena.com/reports/2022-11-size)

---

### 30. [M-01] Incompatibility with fee-on-transfer/inflationary/deflationary/rebasing tokens, on both base tokens and quote tokens, with varying impacts

- **Source**: Code4rena
- **Protocol**: SIZE
- **Tags**: Weird ERC20, Fee On Transfer

<https://github.com/code-423n4/2022-11-size/blob/main/src/SizeSealed.sol#L163><br>
<https://github.com/code-423n4/2022-11-size/blob/main/src/SizeSealed.sol#L96-L105>

The following report describes two issues with how the `SizeSealed` contract incorrectly handles several so-called "weird ERC20" tokens, in which the token's balance can change unexpectedly:

*   How the contract cannot handle fee-on-transfer base tokens, and
*   How the contract incorrectly handles unusual ERC20 tokens in general, with stated impact.

#### Base tokens

Let us first note how the contract attempts to handle sudden balance change to the `baseToken`:

<https://github.com/code-423n4/2022-11-size/blob/main/src/SizeSealed.sol#L96-L105>

```solidity
uint256 balanceBeforeTransfer = ERC20(auctionParams.baseToken).bala...

[View Full Finding](https://code4rena.com/reports/2022-11-size)

---


## Statistics

- Total MEDIUM findings: 13,814
- Examples shown: 30
- Last updated: 2026-01-29

