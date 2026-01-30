# ConsenSys - Audit Findings

## Overview

**Total Findings**: 1,395 (2.76% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 349 | 462 | 584 | 0 |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|
| Reentrancy | 3 |
| Chain Reorganization Attack | 2 |
| Blacklisted | 1 |
| initializer modifier | 1 |
| Initializer | 1 |
| Initialization | 1 |
| Constructor | 1 |
| Read-only Reentrancy | 1 |
| ECDSA | 1 |
| ERC1155 | 1 |

---

## Notable Findings

### 1. Re-entrancy issue for ERC1155 ✓ Fixed

**Protocol**: Bridge Mutual | **Impact**: HIGH

#### Resolution



Addressed by moving `isNFTDistributed = true;` before the token transfers and only transferring tokens to the message sender.


#### Description


ERC1155 tokens have callback functions on some of the transfers, like `safeTransferFrom`, `safeBatchTransferFrom`. During these transfers, the `IERC1155ReceiverUpgradeable(to).onERC1155Received` function is called in the `to` address.


For example, `safeTransferFrom` is used in the `LiquidityMining` contract:


**code/contracts/LiquidityMining.sol:L204-L224**



```
function distributeAllNFT() external {
    require(block.timesta...

---

### 2. RocketRewardPool - Unpredictable staking rewards as stake can be added just before claiming and rewards may be paid to to operators that do not provide a service to the system  Partially Addressed

**Protocol**: Rocketpool | **Impact**: HIGH

#### Resolution



Partially addressed in branch `rp3.0-updates` ([rocket-pool/[email protected]`b424ca1`](https://github.com/rocket-pool/rocketpool/commit/b424ca1ae1d0c1c5f3fa3f7f6f36051f8e57bbc2)) by changing the withdrawal requirements to `150%` of the effective RPL.


The client provided the following statement:



> 
> Node operators can now only withdraw RPL above their 150% effective RPL stake.
> 
> 
> 




#### Description


Nodes/TrustedNodes earn rewards based on the **current** share of the effective RPL stake provided backing the number of Minipools they run. The reward is paid out...

---

### 3. RocketNodeDistributorDelegate - Reentrancy in distribute() allows node owner to drain distributor funds ✓ Fixed

**Protocol**: Rocket Pool Atlas (v1.2) | **Impact**: HIGH

#### Resolution



Fixed in <https://github.com/rocket-pool/rocketpool/tree/77d7cca65b7c0557cfda078a4fc45f9ac0cc6cc6> by implementing a custom reentrancy guard via a new state variable `lock` that is appended to the end of the storage layout. The reentrancy guard is functionally equivalent to the OpenZeppelin implementation. The method was not refactored to give user funds priority over the node share. Additionally, the client provided the following statement:



> 
> We acknowledge this as a critical issue and have solved with a reentrancy guard.
> 
> 
> 



> 
> We followed OpenZeppelin’s de...

---

### 4. Oracle front-running could deplete reserves over time ✓ Addressed

**Protocol**: Bancor V2 AMM Security Audit | **Impact**: HIGH

#### Resolution



To mitigate this issue, the Bancor team has added a mechanism that adjusts the effective weights once per block based on its internal price feed. The conversion rate re-anchors to the external oracle price once the next oracle update comes in. This mechanism should help to cause the weight rebalancing caused by the external Oracle update to be less pronounced, thereby limiting the profitability of Oracle frontrunning. It should be noted that it also adds another layer of complexity to the system. It is difficult to predict the actual effectiveness and impact of this mitigati...

---

### 5. didTransferShares function has no access control modifier ✓ Fixed

**Protocol**: Forta Delegated Staking | **Impact**: HIGH

#### Resolution



The concerned function has now been restricted to be only called by `STAKING_CONTRACT_ROLE` in a pull request [146](https://github.com/forta-network/forta-contracts/pull/146/files) with final commit hash as `97fbd425b64d793252f39d94b378e2655286d947`


#### Description


The staked tokens (shares) in Forta are meant to be transferable. Similarly, the rewards allocation for these shares for delegated staking is meant to be transferable as well. This allocation for the shares' owner is tracked in the `StakeAllocator`. To enable this, the Forta staking contract `FortaStaking` im...

---

### 6. 18_deploy_RollupRevenueVault.ts – Deployment Script Leaves Contract Uninitialized; fallback Does Not Enforce msg.value  0 ✓ Fixed

**Protocol**: Linea - Burn Mechanism | **Impact**: HIGH

...

Export to GitHub ...

Set external GitHub Repo ...

Export to Clipboard (json)

Export to Clipboard (text)

#### Resolution

Fixed in commit [831c529479faebb380df1478e17f03bf0a3b9b80](https://github.com/Consensys/linea-monorepo/pull/1599/commits/831c529479faebb380df1478e17f03bf0a3b9b80). The Linea team modified the deployment script to call the initialize function with the proper signature and function arguments, and added `require(msg.value > 0, NoEthSent())` in the fallback.

#### Description

The deployment script for `RollupRevenueVault` incorrectly attempts to call a non-existent `in...

---

### 7. Gator - Currency Mismatch for Non-English Users ✓ Fixed

**Protocol**: Metamask - EIP-7715 Permissions Snap | **Impact**: HIGH

...

Export to GitHub ...

Set external GitHub Repo ...

Export to Clipboard (json)

Export to Clipboard (text)

#### Resolution

Fixed in [MetaMask/snap-7715-permissions@`476e653`](https://github.com/MetaMask/snap-7715-permissions/commit/476e6534f9e219ac130f7e9c4f10f6b3f17b12ed) by updating the logic to invoke the Price API with the user’s preferred currency and updating the UI element when falling back to USD. The client provided additional details:

> **Resolution:** Logic was updated to invoke the Price API with the user’s preferred currency, incorporating a fallback mechanism.  
> **Imple...

---

### 8. Kernel - Prototype Pollution via Method Handler Lookup ✓ Fixed

**Protocol**: Metamask - EIP-7715 Permissions Snap | **Impact**: HIGH

...

Export to GitHub ...

Set external GitHub Repo ...

Export to Clipboard (json)

Export to Clipboard (text)

#### Resolution

Fixed in [MetaMask/snap-7715-permissions@`476e653`](https://github.com/MetaMask/snap-7715-permissions/commit/476e6534f9e219ac130f7e9c4f10f6b3f17b12ed) by checking `Object.prototype.hasOwnProperty` on the request struct before accessing it. In `Gator` this is safeguarded by a check for `isMethodAllowedForOrigin`. The client provided additional details:

> **Summary of Finding:** request.method lacked validation, enabling prototype pollution.  
> **Resolution:** We in...

---

### 9. getTermsInfo Reverts Because of Block Gas Limit ✓ Fixed

**Protocol**: Metamask Delegation Framework April 2025 | **Impact**: HIGH

...

Export to GitHub ...

Set external GitHub Repo ...

Export to Clipboard (json)

Export to Clipboard (text)

#### Resolution

Fixed in [49b57f4a55f10d83fe9b1a990a0dd52cced186c8](https://github.com/MetaMask/delegation-framework/commit/49b57f4a55f10d83fe9b1a990a0dd52cced186c8) and [PR 104](https://github.com/MetaMask/delegation-framework/pull/104) by changing how token information gets retrieved in `getTermsInfo()`. In particular, a `uint256 _tokenIndex` argument was added to access specific token configurations immediately as opposed to searching through the whole configuration set.

#### D...

---

### 10. Missing Safe Transfer Validation in Execution Logic  Acknowledged

**Protocol**: Metamask Delegation Framework April 2025 | **Impact**: HIGH

...

Export to GitHub ...

Set external GitHub Repo ...

Export to Clipboard (json)

Export to Clipboard (text)

#### Resolution

Acknowledged by the client with the following note:

> We added a warning in the documentation in this hash: [bfca5f9163eb4c5b1a1ff309a5fc9d6a5815f538](https://github.com/MetaMask/delegation-framework/commit/bfca5f9163eb4c5b1a1ff309a5fc9d6a5815f538)

#### Description

In the `beforeHook` function of the `MultiTokenPeriodEnforcer` contract, there is a validation that the mode of execution is `CALLTYPE_SINGLE` and `EXECTYPE_DEFAULT`, so the ERC-20 token transfers will...

---

### 11. Incorrect Fee Handling During Withdrawals ✓ Fixed

**Protocol**: USDi | **Impact**: HIGH

...

Export to GitHub ...

Set external GitHub Repo ...

Export to Clipboard (json)

Export to Clipboard (text)

#### Resolution

In the `1ae396b8da0f15367703764e3071e8cdffd926a5` commit for fix review the finding has been fixed by applying the fee logic after `amount` is converted to `backingAmount` in `backingToken` units.

#### Description

As a way to generate fees, the contract deducts a portion of the user’s deposit or withdrawal during processing. This behavior is evident in the use of the `getFee()` function and subsequent `backingToken` transfers, such as `backingToken.safeTransfer(tr...

---

### 12. partial_sha256_var_start Messages for Size Smaller Than BLOCK_SIZE Returns the Same Hash State h for All Data

**Protocol**: ZK Email Noir | **Impact**: HIGH

#### Description

As a special case of the issue described in [issue 5.5](#partial_sha256_var_start-with-message-sizes-not-multiple-of-block_size-gives-same-h-state-for-different-data) , when an array of size `N` is smaller than `BLOCK_SIZE`, the function `partial_sha256_var_start` does not even go into the logical loop to perform any hashing due to calculating the number of loops based on `N`:

**lib/src/partial\_hash.nr:L79-L84**

```
let num_blocks = N / BLOCK_SIZE;
let mut msg_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
let mut h: [u32; 8] = [1779033703, 3144134277, 1013904242, 2773480762, ...

---

### 13. partial_sha256_var_interstitial May Give the Same Hash State h for Different Data Objects if They Are Smaller Than message_size

**Protocol**: ZK Email Noir | **Impact**: HIGH

#### Description

`partial_sha256_var_interstitial` function is used with a partially computed sha256 hash created with `partial_sha256_var_start` and a partial message to generate an interstate hash. However, when the input message’s size (`N`) is less than the message size parameter (`message_size`) and the size is not a multiple of `BLOCK_SIZE` (64 bytes), the last unfilled block of the message would not be hashed. In other words, even though the expected amount of data to be hashed is `message_size`, only `BLOCK_SIZE*(N/BLOCK_SIZE)` amount of data will be hashed. Consequently, the remainin...

---

### 14. partial_sha256_var_start With Message Sizes Not Multiple of BLOCK_SIZE Gives Same h State for Different Data

**Protocol**: ZK Email Noir | **Impact**: HIGH

#### Description

The `partial_sha256_var_start` function is designed to hash the initial part of a message and return a hash state `h`. This hash state can then be used with `partial_sha256_var_interstitial` to hash additional parts of the message or with `partial_sha256_var_end` to complete the hash of the entire message.

However, if the size of the hashed part of the message given to `partial_sha256_var_start` is not a multiple of `BLOCK_SIZE` (64 bytes in the provided circuits), the function will not hash the remaining data of the message that is less than the block size, resulting in an ...

---

### 15. Missing Validation of Header Field Sequence Length

**Protocol**: ZK Email Noir | **Impact**: HIGH

#### Description

The `constrain_header_field` function verifies that the claimed header field sequence is completely contained in the header:

**lib/src/headers/mod.nr:L93-L95**

```
// check the range of the sequence is within the header (so we can use get_unchecked)
let end_index = header_field_sequence.index + header_field_sequence.length;
assert(end_index <= header.len(), "Header field out of bounds of header");

```

There is, however, no check that the header field name and the following colon fit into the sequence. Nor is there a check that the sequence length is at most `MAX_HEADER_FI...

---


## Statistics

- Total findings from ConsenSys: 1,395
- Last updated: 2026-01-29

