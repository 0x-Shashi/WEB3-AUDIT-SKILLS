# Quantstamp - Audit Findings

## Overview

**Total Findings**: 2,443 (4.83% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 226 | 438 | 1779 | 0 |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|
| Access Control | 2 |
| AutoRoll | 1 |
| Block Period | 1 |
| Bond | 1 |
| Authentication | 1 |
| Arbitrum | 1 |
| Account Abstraction | 1 |
| Auditing and Logging | 1 |

---

## Notable Findings

### 1. Unprotected Upgrade at `Registry`

**Protocol**: Ithaca Finance | **Impact**: HIGH

**Update**
Marked as "Fixed" by the client. This has been properly addressed by following the recommendation. Addressed in: `8777981bafe3c34fcebdf1dcfe1731e97686002b`.

**File(s) affected:**`contracts/registry/Registry.sol`

**Description:** In `Registry.sol`, the method `_authorizeUpgrade()` is not protected by any access control. This means that anyone could upgrade the contract to any implementation.

**Exploit Scenario:** The following test script reproduces the issue:

```
describe('Exploit', () => {
    it('any user can upgrade', async () => {
      const precision = 7;
      const accou...

---

### 2. Unsigned Fee Parameters Let Any Signature Holder Drain Funds

**Protocol**: Sequence - Trail Contracts | **Impact**: HIGH

**Update**
Marked as "Fixed" by the client. Addressed in: `f36f3e8a1e00c7227db86f45ba2bff2df440d1ca`although the main fix is in commit `bfc4459`. The client provided the following explanation:

> Fixed in two parts:
> 
> 
> 1.   CRITICAL FIX (`bfc4459`): Added `feeAmount` and `feeCollector` to `TRAILS_INTENT_TYPEHASH`. Fee parameters are now part of the EIP-712 typed data signature, preventing malicious relayers from injecting arbitrary fees or draining user funds.
> 2.   ADDITIONAL VALIDATION (`79ff75f`, `cad0793`, `171b2c3`): Added explicit validation to ensure `permitAmount` exactly matches...

---

### 3. Security Level Constraint Can Be Circumvented

**Protocol**: Bucket Protocol V2 | **Impact**: HIGH

**Update**
Fixed by the client as per recommendation. Addressed in: `49f5916fb915743b929b5c5d28d2647a0e24d14e`.

**File(s) affected:**`bucket_cdp/sources/vault.move`

**Description:** The `update_position()` function throws an error depending on the user's operation and the vault's security level. It is _intended_ that if the user wants to deposit collateral, the user is allowed if the security level is 0 or 2; if the user wants to withdraw collateral, repay a debt, or borrow, the security level must be 0. This behavior is based on the following code block:

```
// check security by actions
  ...

---

### 4. Malicious Deposit with Dust-Sensitive `minAmount` Can Cause Denial of Service on `batchRelease()` Function

**Protocol**: Camp | **Impact**: HIGH

**Update**
Marked as "Fixed" by the client. Addressed in: `b7c7f7e589e706a63e0378b4bd0ae6a8d2fef6e2`.

**File(s) affected:**`CampTimelockEscrowNativeOFT.sol`

**Description:** The `batchRelease()` function in `CampTimelockEscrowNativeOFT` processes deposits sequentially in a loop. When processing each deposit, it calls `_bridgeNativeTokens()`, which internally triggers LayerZero's dust removal mechanism via `_removeDust()`. This function rounds down the amount by removing decimal precision dust to ensure compatibility across chains with different token decimals.

However, a malicious user can ...

---

### 5. Possible Frontrunning of Buy Actions by Changing Token Terms

**Protocol**: Camp - NFT | **Impact**: HIGH

**Update**
Marked as "Fixed" by the client. Addressed in: `b09852d0c0cb9cae668cc523e1fc1e25a58da097`.

**File(s) affected:**`Marketplace.sol`

**Description:** Token access can be bought via the marketplace according to the conditions outlined in the token `terms`. These terms can be updated by the token owner at any point using the `updateTerms()` function. Despite classical frontrunning being mitigated by the private mempool of the Camp network, this can be exploited by speculatively or accidentally frontrunning a call to `buyAccess()` and changing the subscription price, duration, or paymen...

---

### 6. Transferred NFTs May Be Missing Royalty Vault

**Protocol**: Camp - NFT | **Impact**: HIGH

**Update**
Marked as "Fixed" by the client. Addressed in: `efb615e3aef4e38ad324b2e9be5c5da16f0e7c83`.

**File(s) affected:**`IpNFT.sol`

**Description:** The token owners receive royalty payments for subscriptions, and may also be rewarded for dispute settlements. These rewards are paid to the token owner, but not directly to avoid DoS attack vectors. Instead, each token owner is supposed to have a `RoyaltyVault` contract to receive these funds. These contracts are currently created during the minting process. However, when a token is transferred to a new owner, they may not have a vault regis...

---

### 7. Stablecoin Arbitrage Leads to Potential for Vusd to Become Undercollateralized

**Protocol**: vusd-stablecoin | **Impact**: HIGH

**Update**
Marked as "Fixed" by the client. Addressed in: `655b2efc2704480b32a13a2a52886a71520eb8ea`.

**File(s) affected:**`Redeemer.sol, Minter.sol`

**Description:** The core invariant of the protocol is that the VUSD token should always be backed at least 1:1 by the stablecoins held in its treasury. However because VUSD tokens are minted to users based on the oracle price of the stablecoin being deposited, there is an opportunity for arbitrageurs to mint more VUSD with stablecoins that have temporarily deviated slightly above one dollar. They can then immediately redeem this VUSD for anoth...

---

### 8. Allow List Entries Can Be Added and Removed by Any State Allower

**Protocol**: Liquid Collective - Solana | **Impact**: HIGH

**Update**
Marked as "Fixed" by the client. Addressed in: `1854b38bbdfdc51db030e31f4b60889e98fc627b`. The client provided the following explanation:

> Great find! We appreciate the suggested test and have added it to our test suite. We made the suggested change and added the `state` account address to the allowlist entry seed. However, we have also removed the `stake_pool` account from the allowlist entry seed, since the funding authority stored inside the `state` account should already ensure the 1:1 relationship between the `state` account and a given `stake_pool` account.

**File(s) affect...

---

### 9. Closing a Rewardpool Will Block Deposits, Withdrawals, Updates, and Transfers

**Protocol**: Fragmetric Restaking Program | **Impact**: HIGH

**Update**
Marked as "Fixed" by the client. Addressed in: `d71f29ee6150349331749c6602e7ebc648467097`.

**File(s) affected:**`modules/reward/update.rs`

**Description:** A given `RewardAccount` can contain up to 4 pools of the type `RewardPool`. When `fragSol` moves from one user to another, or during minting and burning, the function `update_reward_pools_token_allocation` is invoked to update the reward pools in the given `rewardAccount`.

This happens in the following loop:

```
for reward_pool in self.get_related_pools(&from.user, receipt_token_mint)? {
...
reward_pool.update(effective_delta...

---

### 10. Incorrect Amount Transferred During Token Deposits

**Protocol**: Exceed Finance Liquid Staking & Early Purchase | **Impact**: HIGH

**Update**
Marked as "Fixed" by the client. Addressed in: `8a5ba98aaae2ae916bd19c5252896114f8a72a29`. The client provided the following explanation:

> The code was updated to transfer the exact number of tokens requested, a unit test was added.

**File(s) affected:**`programs/early-purchase/src/instructions/deposit_tokens.rs`

**Description:** The`early_purchase::deposit_tokens::handler()`function is intended to enable a Guardian to deposit a specified quantity of`purchase_mint`tokens (`params.amount_to_deposit`) into the sale token vault `sale_purchase_ata`. However, the`token::transfer`CPI ...

---

### 11. Incorrect Authority Used for Token Transfer Prevents All Redemptions

**Protocol**: Exceed Finance Liquid Staking & Early Purchase | **Impact**: HIGH

**Update**
Marked as "Fixed" by the client. Addressed in: `c3a83a530d0eddb65b0b7a780d02b474e56c4881`. The client provided the following explanation:

> The Sale struct was modified to store its ID and bump so that signer seeds could be constructed in the redeem_receipt instruction. Unit tests were updated to prove that the tokens are transferred and that the distributed amount is accurate.

**File(s) affected:**`programs/early-purchase/src/instructions/redeem_receipt.rs`

**Description:** The`early_purchase::redeem_receipt::handler()`function is responsible for transferring the `purchase_mint`...

---

### 12. Tokens Can Be Redeemed From Any Sale

**Protocol**: Exceed Finance Liquid Staking & Early Purchase | **Impact**: HIGH

**Update**
Marked as "Fixed" by the client. Addressed in: `e57b33c4e7604080c2824c07dba116d77c5d02b5`. The client provided the following explanation:

> The sale key was added to the receipt PDA seeds and new unit tests were created to test this edge case

**File(s) affected:**`programs/early-purchase/src/state/sale.rs`, `programs/early-purchase/src/instructions/purchase_tokens.rs`, `programs/early-purchase/src/instructions/redeem_receipt.rs`

**Description:** Sale accounts can be created by any user and they are assigned as their admins. Additionally, receipt PDAs are derived with the followin...

---

### 13. Validators Can Submit Multiple Attestations to Maliciously Force Wrong Consensus

**Protocol**: Powerloom L2 | **Impact**: HIGH

**File(s) affected:**`DataMarket.sol`

**Description:** The function `submitBatchAttestation()` allows a validator to vote on a given batchCid while providing a `finalizedCidsRootHash`. However, it does not guard against a validator voting again on either a different or the same hash in the same epoch.

This means a single validator can vote multiple times to force a batch to reach the finalization stage.

**Exploit Scenario:**

 This proof of concept shows that a validator can vote twice:

```
it("Testing Attestation Batch flow", async function () {
            const batchCid = "QmbWqxBEKC3P8...

---

### 14. The Legacy Node Vesting Formula Ignores `legacyNodeTokensSentOnL1` Leading to Excessive Reward Distribution

**Protocol**: Powerloom L2 | **Impact**: HIGH

**File(s) affected:**`SnapshotterState.sol`

**Description:** Owners of legacy nodes who have provided KYC details can claim node token rewards after burning their node. The intention of the protocol is to reward the owners `legacyNodeValue` subtracted by `legacyTokensSentOnL1`. These tokens are partly transferred immediately upon burning the tokens (the `initialClaim` amount) with the remaining being vested over time. This remaining amount is set as the `tokensAfterInitialClaim` field in `nodeIdToVestingInfo` here:

```
nodeIdToVestingInfo[_nodeId] = LegacyNodeVestingInfo(
    msg.sender,
   ...

---

### 15. Signature Replay Attack Possible Between Stake, Unstake and Reward Functions Enabling Unauthorized Token Claims

**Protocol**: Sapien | **Impact**: HIGH

**Update**
Marked as "Fixed" by the client. Addressed in: `fa79159`.

![Image 30: Alert icon](https://certificate.quantstamp.com/full/sapien/ffb7e698-6178-46f0-8df8-52e537af70c0/static/media/success-icon-alert.4e26c8d3b65fdf9f4f0789a4086052ba.svg)

**Update**
Marked as "Fixed" by the client. Addressed in: `4ba050c5db3fe00d6c39cad790a6d95834e2a624`. The client provided the following explanation:

> The vulnerability was fixed by implementing EIP-712 typed structured data signing in both contracts.

![Image 31: Alert icon](https://certificate.quantstamp.com/full/sapien/ffb7e698-6178-46f0-8df8-52...

---


## Statistics

- Total findings from Quantstamp: 2,443
- Last updated: 2026-01-29
