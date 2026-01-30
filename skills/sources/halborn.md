# Halborn - Audit Findings

## Overview

**Total Findings**: 2,649 (5.24% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 317 | 378 | 1954 | 0 |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|
| External Call | 1 |
| from=to | 1 |
| Typo / CopyPaste | 1 |
| Chainlink | 1 |
| Cross Chain | 1 |
| ERC20 | 1 |
| Change Validation | 1 |
| Check Return Value | 1 |
| Transfer Result Check | 1 |
| Overflow/Underflow | 1 |

---

## Notable Findings

### 1. LACK OF EXTERNAL CALLS VALIDATION

**Protocol**: Account Abstraction Schnorr Signatures SDK | **Impact**: HIGH

##### Description

Non-validated external calls occur when a function invokes an external contract without verifying the return value or handling potential errors.

Several external calls were detected without proper validation.

### Impact

This can lead to reentrancy attacks or unexpected side effects if the external call fails or returns an unexpected result, directly causing a potential impact in the availability or integrity of the environment.

##### Proof of Concept

Listed below, there are some examples of unvalidated calls that may fail or cause an unconsistent or unexpected behavior ...

---

### 2. ROLE-BASED ACCESS CONTROL MISSING

**Protocol**: MonoX | **Impact**: HIGH

##### Description

In smart contracts, implementing a correct Access Control policy is an essential step to maintain security and decentralization for permissions on a token. All the features of the smart contract , such as mint/burn tokens and pause contracts are given by Access Control. For instance, Ownership is the most common form of Access Control. In other words, the owner of a contract (the account that deployed it by default) can do some administrative tasks on it. Nevertheless, other authorization levels are required to follow the principle of least privilege, also known as least aut...

---

### 3. POOL BLOCKING

**Protocol**: MonoX | **Impact**: HIGH

##### Description

One of MonoX's main objectives is to allow users for listing ERC20 tokens without the need for providing liquidity. Users can set arbitrary prices for tokens they list because the `Monoswap.sol` contract does not verify them against third-party data sources. The price of a given token can be updated only if it has not been swapped for at least `6000` blocks since the last exchange. In consequence, since the contract does not enforce `minimum or maximum transaction amount`, a malicious user can list tokens, price them way above market rate and keep the price on that level by ...

---

### 4. REUSE OF STATIC ENCRYPTION KEY

**Protocol**: Adena Wallet Chrome Extension | **Impact**: HIGH

##### Description

The use of a hardcoded static encryption key to encrypt a dynamically generated UUID, which is then used to encrypt the wallet password, has been detected.

##### Proof of Concept

```
import CryptoJS from 'crypto-js';
import { v4 as uuidv4 } from 'uuid';

// Static cipher key used for encrypting the cryptographic key
const ENCRYPT_CIPHER_KEY = 'r3v4';

export const encryptSha256Password = (password: string): string => {
  return CryptoJS.SHA256(password).toString();
};

// Encrypts a password with a dynamically generated key and returns the encrypted key and password
export...

---

### 5. MNEMONIC PHRASE EXPOSURE IN MEMORY

**Protocol**: Adena Wallet Chrome Extension | **Impact**: HIGH

##### Description

The mnemonic phrase of the wallet is kept unencrypted in memory, even the wallet was locked. As a result, an attacker with access to the users machine could exfiltrate the mnemonic phrase. This makes the wallet web extension vulnerable to Demonic (CVE-2022-32969). The user password in cleartext was also found.

It is important to recognize that the mnemonic risk extends beyond the application state; it could also be leaked into memory when the browser displays the mnemonic in clear text and as long as the process running.

##### Proof of Concept

Observe, for example, the f...

---

### 6. Unaccounted funds in rewards distribution logic

**Protocol**: BTC Hardfork - Enhancement / Update | **Impact**: HIGH

##### Description

The `receiveRewards` function in the **SystemReward** contract processes excess funds by distributing them to members of the `whiteListSet` based on their assigned percentage. However, when a transfer to a whitelist member fails, the `remain` value is still reduced by the intended transfer amount, regardless of whether the funds were successfully sent.

  

The mentioned scenario can result in unallocated funds being disproportionately redirected to other whitelist members, burned, or sent to the foundation. For example, if a transfer fails for one member, their share is eff...

---

### 7. Unintended Reward Period Extension in addRewards() Function

**Protocol**: ION Strategies v1 | **Impact**: HIGH

##### Description

The `addRewards()` function in the `StakerLight` contract contains a logic flaw that allows for the continuous extension of the `periodFinish` variable with each call, regardless of whether the current reward period has ended. Specifically, each time `addRewards()` is called, `periodFinish` is reset to `block.timestamp + rewardsDuration`, which effectively "extends" the current reward period if the function is called before the previous period expires.

```
function addRewards(
    address _from,
    uint256 _amount
) external override onlyOwner validAmount(_amount) updateRe...

---

### 8. Challenge Ids can be overwritten

**Protocol**: Sidekick Contracts | **Impact**: HIGH

##### Description

The `createTransaction()` function in the `Escrow` contract uses a `challenge_id` mapping to track transactions by their challenge identifier. However, there is no check to prevent duplicate `_challengeId` values. When a transaction is created with a `_challengeId` that already exists, the new transaction ID will overwrite the previous mapping entry in `challenge_id[_challengeId]`, making the previous transaction unretrievable through `getTransactionByChallengeId()`.

  

While the transaction data still exists in the `transactions` mapping and can be accessed directly by ID...

---

### 9. Multiple tokens could be minted by the same msg.sender

**Protocol**: Proof-of-Creativity Protocol - Periphery Contracts | **Impact**: HIGH

##### Description

The `StoryBadgeNFT` contract allows users to mint a badge NFT by providing a valid signature. The current implementation uses the `usedSignatures` mapping to track which signatures have been used, ensuring that each `msg.sender` can mint only one token. However, the signature validation process relies on a `signer` address, which can be updated by the contract owner using the `setSigner()` function.

  

The digest used for signature verification is generated using only the `msg.sender` address. This means that if the signer address is changed, a new signature from the new s...

---

### 10. Cross-Organization Signature Replay

**Protocol**: Proof-of-Creativity Protocol - Periphery Contracts | **Impact**: HIGH

##### Description

By using the `OrgStoryNFTFactory` contract, any organization can mint a new `OrgNFT` token and deploy a new `StoryBadgeNFT` contract (or the preferred template) via Beacon Proxy. On these `StoryBadgeNFT` contracts, end users can mint a badge NFT if they provide a valid signature that has been signed by the `signer` address supplied within the `storyftInitParams` used to call the `deployOrgStoryNft()` function.

  

However, it has been noted that the signature digest only includes the `msg.sender` address, which will cause that any valid signature can be reused across organi...

---

### 11. Royalty Tokens can be stolen

**Protocol**: Proof-of-Creativity Protocol - Periphery Contracts | **Impact**: HIGH

##### Description

In order to distribute the Royalty Tokens of a determined IP, the `_distributeRoyaltyTokens()` internal function from the `RoyaltyTokenDistributionWorkflows` contract is called. This function is called from the following functions:

* `mintAndRegisterIpAndAttachPILTermsAndDistributeRoyaltyTokens()`
* `mintAndRegisterIpAndMakeDerivativeAndDistributeRoyaltyTokens()`
* `distributeRoyaltyTokens()`

  

These functions will require the following parameters related to the token distribution:

* `ipId`: The target IP
* `royaltyShares`: The struct containing the token receivers and ...

---

### 12. Workflow permission setting calls are vulnerable to Front-Running attacks

**Protocol**: Proof-of-Creativity Protocol - Periphery Contracts | **Impact**: HIGH

##### Description

Many of the scoped workflow contracts, such as `LicenseAttachmentWorkflows` , need to perform authenticated calls to different IPAccounts (EIP-6551 accounts). In order to implement the access control mechanism, signatures are used.

  

If a valid signature is provided, the workflow contract will perform a call to `PermissionHelper.setBatchPermissionForModules()` , which executes a call to the IPAccount's `executeWithSig()` function, including the intended function selectors that will be called in the signature.

  

However, it has been noted that this signature is used sol...

---

### 13. No Token Distribution in BatchRelease Due to Premature State Updates

**Protocol**: Treasury Vesting | **Impact**: HIGH

##### Description

In the `batchRelease()` function of `TreasuryVesting`, currently separates state updates and token transfers into two separate loops, following the checks-effects-interactions pattern.

```
// Current implementation
function batchRelease(bytes32 category, address[] calldata users) external {

    //...

    // First loop: Updates state
    for (uint256 i = 0; i < users.length; i++) {
        uint256 releasable = getReleasableAmount(users[i], category); // Returns X tokens
        if (releasable > 0) {
            userReleased[users[i]][category] += releasable;  // Updates st...

---

### 14. Mismatch between proposer selection algorithm

**Protocol**: Layer 1 Assessment | **Impact**: HIGH

##### Description

The function `isNextProposer` attempts to determine whether the local node is the next proposer for the upcoming block in a CometBFT consensus system. However, there is a fundamental issue with the logic: it incorrectly applies a simple round-robin algorithm to select the next proposer, while CometBFT uses a weighted round-robin algorithm based on validator voting power. This discrepancy can lead to incorrect proposer selection, which may cause the node to behave incorrectly in the consensus process, potentially leading to missed blocks or other consensus failures:

  

```
...

---

### 15. Missing chargeFee modifier allows spamming the CL

**Protocol**: Layer 1 Assessment | **Impact**: HIGH

##### Description

The `removeOperator`, `redelegate` and `redelegateOnBehalf` **do not have** the `chargeFee` modifier. As none of them requires the user sending funds, it allows a malicious user to spam the CL by sending these events, which requires consumption from the CL.

  

Code Location
-------------

<https://github.com/piplabs/story/blob/e6d2d51550c3eff3f561f8d1b860888ea2bf8060/contracts/src/protocol/IPTokenStaking.sol#L162>

```
    function removeOperator(
        bytes calldata uncmpPubkey,
        address operator
    ) external verifyUncmpPubkeyWithExpectedAddress(uncmpPubkey, m...

---


## Statistics

- Total findings from Halborn: 2,649
- Last updated: 2026-01-29

