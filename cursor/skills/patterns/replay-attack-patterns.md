# Replay Attack Security Patterns

## Overview

**Frequency**: 14 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 10 | 0 | 0 |

**Common Sources**: Code4rena, Spearbit, Sherlock, MixBytes, Codehawks

---

## Detection Checklist

- [ ] Check for replay attack vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-04] EIP712MetaTransaction.executeMetaTransaction() failed txs are open to replay attacks

**Source**: Code4rena
**Protocol**: Rolla
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-03-rolla/blob/efe4a3c1af8d77c5dfb5ba110c3507e67a061bdd/quant-protocol/contracts/utils/EIP712MetaTransaction.sol#L86


## Vulnerability details

Any transactions that fail based on some conditions that may change in the future are not safe to be executed again later (e.g. transactions that are based on others actions, or time-dependent etc).

In the current implementation, once the low-level call is failed, the whole tx will be reverted and so that `_nonces[metaAction.from]` will remain unchanged.

As a result, the same tx can be replayed by anyone, using the same signature.

https://github.com/code-423n4/2022-03-rolla/blob/efe4a3c1af8d77c5dfb5ba110c3507e67a061bdd/quant-protocol/contracts/utils/EIP712MetaTransaction.sol#L86

```solidity
    function executeMetaTransaction(
        MetaAction memory metaAction,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) external payable returns (bytes memory) {
        require(
            _verify(metaAction.from, metaAction, r, s, v),
            "signer and signature don't match"
        );

        uint256 currentNonce = _nonces[metaAction.from];

        // intentionally allow this to overflow to save gas,
        // and it's impossible for someone to do 2 ^ 256 - 1 meta txs
        unchecked {
            _nonces[metaAction.from] = currentNonce + 1;
        }

        // Append the metaAction.from at the end so that it can be extracted later
        // from the calling c

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-rolla)

---

### Example 2: Successful transactions are not stored, causing a replay attack on ``redeemDepositsAndInternalBalances``

**Source**: Codehawks
**Protocol**: Beanstalk: The Finale
**Impact**: HIGH

**Details**:

## Summary

in `redeemDepositsAndInternalBalances` there is no validation about the parameters that have been used which should be stored and should not be reused.

As a result, parameters that have already been used can be reused.

## Vulnerability Details

Look at this:

```solidity
function redeemDepositsAndInternalBalances(
        address owner,
        address reciever,
        AccountDepositData[] calldata deposits,
        AccountInternalBalance[] calldata internalBalances,
        uint256 ownerRoots,
        bytes32[] calldata proof,
        uint256 deadline,
        bytes calldata signature
    ) external payable fundsSafu noSupplyChange nonReentrant {
        // verify deposits are valid.
        // note: if the number of contracts that own deposits is small,
        // deposits can be stored in bytecode rather than relying on a merkle tree.
        verifyDepositsAndInternalBalances(owner, deposits, internalBalances, ownerRoots, proof);

        // signature verification.
        verifySignature(owner, reciever, deadline, signature);

function verifyDepositsAndInternalBalances(
        address account,
        AccountDepositData[] calldata deposits,
        AccountInternalBalance[] calldata internalBalances,
        uint256 ownerRoots,
        bytes32[] calldata proof
    ) internal pure {
        bytes32 leaf = keccak256(abi.encode(account, deposits, internalBalances, ownerRoots));
        require(MerkleProof.verify(proof, MERKLE_ROOT, leaf), "Migration: invalid p

*[Content truncated...]*

---

### Example 3: [H-03] Builder can call `Community.escrow` again to reduce debt further using same signatures

**Source**: Code4rena
**Protocol**: Rigor Protocol
**Impact**: HIGH

**Details**:

_Submitted by sseefried, also found by 0xA5DF, Bahurum, bin2chen, byndooa, cccz, GalloDaSballo, hyh, kankodu, Lambda, and minhquanym_

[Community.sol#L509](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Community.sol#L509)<br>

Since there is no nonce in the data decoded at the beginning of function `escrow`, a builder can call the function multiple times reducing their debt as much as they wish.

### Proof of Concept

*   A builder has a debt of $50,000
*   A lender, a builder, and an escrow agent all ~~enter a bar~~ sign a message that will reduce the debt of the builder by $5,000, upon receipt of physical cash.
*   Function `escrow` is called and debt is reduced to $45,000.
*   The builder, using the same `_data` and `_signature` then calls `escrow` a further 9 times reducing their debt to zero.

### Recommended Mitigation Steps

1.  Similar to function `publishProject`, add a new field into the [ProjectDetails](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/interfaces/ICommunity.sol#L19-L32) struct called `escrowNonce`.

2.  Modify function `escrow` to check this nonce and update it after the debt has been reduced.

See the diff below for full changes.

```diff
diff --git a/contracts/Community.sol b/contracts/Community.sol
index 1585670..b834d0e 100644
--- a/contracts/Community.sol
+++ b/contracts/Community.sol
@@ -15,7 +15,7 @@ import {SignatureDecoder} from "./libra

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-rigor)

---

### Example 4: [M-03] Signature replay

**Source**: Code4rena
**Protocol**: InsureDAO
**Impact**: MEDIUM

**Details**:

_Submitted by 0x1f8b_

Signature replay in `PoolTemplate`.

#### Proof of Concept

The `redeem` method of `PoolTemplate` verifies the data stored in `incident`, and the verification logic of this process is performed as following:
```solidity
require(
    MerkleProof.verify(
        _merkleProof,
        _targets,
        keccak256(
            abi.encodePacked(_insurance.target, _insurance.insured)
        )
    ) ||
        MerkleProof.verify(
            _merkleProof,
            _targets,
            keccak256(abi.encodePacked(_insurance.target, address(0)))
        ),
    "ERROR: INSURANCE_EXEMPTED"
);
```

As can be seen, the only data related to the `_insurance` are`  target ` and `insured`, so as the incident has no relation with the`  Insurance `, apparently nothing prevents a user to call `insure` with high amounts, after receive the incident, the only thing that prevents this from being reused is that the owner creates the incident with an `_incidentTimestamp` from the past.

So if an owner create a incident from the future it's possible to create a new `insure` that could be reused by the same affected address.

Another lack of input verification that could facilitate this attack is the `_span=0` in the `insure` method.


#### Recommended Mitigation Steps

It is mandatory to add a check in `applyCover` that`  _incidentTimestamp ` is less than the current date and the `span` argument is greater than 0 in the`  insure ` method.

**[oishun1112 (Insure) confirmed and 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-insure)

---

### Example 5: [M-04] KYCRegistry is susceptible to signature replay attack.

**Source**: Code4rena
**Protocol**: Ondo Finance
**Impact**: MEDIUM

**Details**:

The KYCRegistry contract uses signatures to grant KYC status to the users using the `addKYCAddressViaSignature` function.

However this function does not prevent replaying of signatures in the case where KYC status was revoked from a user.

```solidity
  function addKYCAddressViaSignature( ... ) external {
    require(v == 27 || v == 28, "KYCRegistry: invalid v value in signature");
    require(
      !kycState[kycRequirementGroup][user],
      "KYCRegistry: user already verified"
    );
    require(block.timestamp <= deadline, "KYCRegistry: signature expired");
    bytes32 structHash = keccak256(
      abi.encode(_APPROVAL_TYPEHASH, kycRequirementGroup, user, deadline)
    );

    bytes32 expectedMessage = _hashTypedDataV4(structHash);

    address signer = ECDSA.recover(expectedMessage, v, r, s);
    _checkRole(kycGroupRoles[kycRequirementGroup], signer);

    kycState[kycRequirementGroup][user] = true;
    // ...
  }
```

This function could be exploited in the case when these conditions are true:

*   KYC status was granted to user using a signature with validity up to `deadline`.
*   Before the `deadline` was passed, the KYC status of user was revoked using the `removeKYCAddresses` function.

In the abovementioned conditions, the malicious user can submit the original signature again to the `addKYCAddressViaSignature` function which will forcefully grant the KYC status to the malicious user again.

It should also be noted that due to this bug until the deadline has passe

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-ondo)

---

### Example 6: [M-01] EIP-712 signatures can be re-used in private sales

**Source**: Code4rena
**Protocol**: Foundation
**Impact**: MEDIUM

**Details**:

_Submitted by thankthedark, also found by Afanasyevich and cmichel_

[NFTMarketPrivateSale.sol#L123-L174](https://github.com/code-423n4/2022-02-foundation/blob/main/contracts/mixins/NFTMarketPrivateSale.sol#L123-L174)<br>

Within a NFTMarketPrivateSale contract, buyers are allowed to purchase a seller's NFT. This is done through a seller providing a buyer a EIP-712 signature. The buyer can then call `#buyFromPrivateSaleFor` providing the v, r, and s values of the signature as well as any additional details to generate the message hash. If the signature is valid, then the NFT is transferred to the buyer.

The problem with the code is that EIP-712 signatures can be re-used within a small range of time assuming that the original seller takes back ownership of the NFT. This is because the NFTMarketPrivateSale#buyFromPrivateSaleFor method has no checks to determine if the EIP-712 signature has been used before.

### Proof of Concept

Consider the following example:

1.  Joe the NFT owner sells a NFT to the malicious buyer Rachel via a private sale.
2.  Rachel through this private sale obtains the EIP-712 signature and uses it to purchase a NFT.
3.  Joe the NFT owner purchases back the NFT within two days of the original sale to Rachel.
4.  Joe the NFT owner puts the NFT back on sale.
5.  Rachel, who has the original EIP-712 signature, can re-purchase the NFT by calling `#buyFromPrivateSaleFor` again with the same parameters they provided in the original private sale purchase in st

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-foundation)

---

### Example 7: [M-13] `RentPayload`'s signature can be replayed

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

A malicious user could potentially fulfill all `PAY` orders that own the same value of `zonehash`.

### Proof of Concept

The rental process in `reNFT` can simply be described as follows:

1.  `lender` create either `BASE` or `PAY` order, which includes a `zoneHash`.
2.  `renter` fulfills the rental order by providing certain items, including `fulfiller`, `payload`(a structured data of `RentPayload`), and its corresponding signature.
3.  Once the rental order is created, `Create#validateOrder()` will be executed to verify if the rental order is valid:
    *   decode `payload` and its `signature` from `zoneParams.extraData`
    *   Check if the signature is expired by comparing `payload.expiration` and `block.timestamp`
    *   Recover the signer from `payload` and its `signature` and check if the signer is protocol signer
    *   check if `zonehash` is equal to the derived hash of `payload.metadata`

Let's take a look at `RentPayload` and its referenced structures:

```solidity
struct RentPayload {
    OrderFulfillment fulfillment;
    OrderMetadata metadata;
    uint256 expiration;
    address intendedFulfiller;
}
struct OrderFulfillment {
    // Rental wallet address.
    address recipient;
}
struct OrderMetadata {
    // Type of order being created.
    OrderType orderType;
    // Duration of the rental in seconds.
    uint256 rentDuration;
    // Hooks that will act as middleware for the items in the order.
    Hook[] hooks;
    // Any extra data to be emitted upon order 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 8: [H-04] Project funds can be drained by reusing signatures, in some cases

**Source**: Code4rena
**Protocol**: Rigor Protocol
**Impact**: HIGH

**Details**:

_Submitted by 0xA5DF, also found by Bahurum, bin2chen, byndooa, cryptphi, hansfriese, horsefacts, kaden, Lambda, neumo, panprog, rokinot, scaraven, and sseefried_

[Project.sol#L386-L490](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Project.sol#L386-L490)<br>
[Project.sol#L330-L359](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Project.sol#L330-L359)<br>
[Tasks.sol#L153-L164](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/libraries/Tasks.sol#L153-L164)<br>

This attack path is the results of signatures reusing in 2 functions - `changeOrder()` and `setComplete()`, and a missing modifier at `Tasks.unApprove()` library function.

### Impact

#### Draining the project from funds

Current or previous subcontractor of a task can drain the project out of its funds by running `setComplete()` multiple times.

This can be exploited in 3 scenarios:

*   The price of a task was changed to a price higher than available funds (i.e. `totalLent - _totalAllocated`, and therefore gets unapproved), and than changed back to the original price (or any price that's not higher than available funds)
*   The subcontractor for a task was changed via `changeOrder` and then changed back to the original subcontractor
    *   e.g. - Bob was the original SC, it was changed to Alice, and then back to Bob
*   Similar to the case above, but even if t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-rigor)

---

### Example 9: [M-03] Cross-Chain Signature Replay Attack

**Source**: Code4rena
**Protocol**: Biconomy
**Impact**: MEDIUM

**Details**:

User operations can be replayed on smart accounts accross different chains. This can lead to user's losing funds or any unexpected behaviour that transaction replay attacks usually lead to.

### Proof of Concept

As specified by the [EIP4337](https://eips.ethereum.org/EIPS/eip-4337) standard `to prevent replay attacks ... the signature should depend on chainid`. In [VerifyingSingletonPaymaster.sol#getHash](https://github.com/code-423n4/2023-01-biconomy/blob/main/scw-contracts/contracts/smart-contract-wallet/paymasters/verifying/singleton/VerifyingSingletonPaymaster.sol#L77-L90) the chainId is missing which means that the same UserOperation can be replayed on a different chain for the same smart contract account if the `verifyingSigner` is the same (and most likely this will be the case).

### Recommended Mitigation Steps

Add the chainId in the calculation of the UserOperation hash in [VerifyingSingletonPaymaster.sol#getHash](https://github.com/code-423n4/2023-01-biconomy/blob/main/scw-contracts/contracts/smart-contract-wallet/paymasters/verifying/singleton/VerifyingSingletonPaymaster.sol#L77-L90)

        function getHash(UserOperation calldata userOp)
        public view returns (bytes32) { // @audit change to view
            //can't use userOp.hash(), since it contains also the paymasterAndData itself.
            return keccak256(abi.encode(
                    userOp.getSender(),
                    userOp.nonce,
                    keccak256(userOp.initCode),
         

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-biconomy)

---

### Example 10: Lack of replay protection for mintAllowList andmintSigned

**Source**: Spearbit
**Protocol**: SeaDrop
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- `SeaDrop.sol#L227`
- `SeaDrop.sol#L318`

## Description
In the case of `mintSigned` (minting via signatures) and `mintAllowList` (minting via merkle proofs), there are no checks that prevent re-using the same signature or Merkle proof multiple times. This is indirectly enforced by the `_checkMintQuantity` function that checks the mint statistics using `IERC721SeaDrop(nftContract).getMintStats(minter)` and reverting if the quantity exceeds `maxMintsPerWallet`.

Replays can happen if a wallet does not claim all of `maxMintsPerWallet` in one transaction. For example, assume that `maxMintsPerWallet` is set to 2. A user can call `mintSigned` with a valid signature and `quantity = 1` twice. Typically, contracts try to avoid any forms of signature replays, i.e., a signature can only be used once. This simplifies the security properties. In the current implementation of the `ERC721Seadrop` contract, we couldn't see a way to exploit replay protection to mint beyond what could be minted in a single initial transaction with the maximum value of `quantity` supplied. However, this relies on the contract correctly implementing `IERC721SeaDrop.getMintStats`.

## Recommendation
We recommend implementing replay protection for both cases. Here are some ideas to do this:

1. Consider including the `tokenId` for the signature and passing that along in the `mintSeaDrop` call. This way, even if the signature is replayed, minting the same `tokenId` should not 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Seadrop-Spearbit-Security-Review.pdf)

---

### Example 11: Router signatures can be replayed when executing messages on the destination domain

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Risk Assessment

## Severity
**Medium Risk**

## Context
BridgeFacet.sol#L476-496

## Description
Connext bridge supports near-instant transfers by allowing users to pay a small fee to routers for providing them with liquidity. Gelato relayers are tasked with taking in bids from liquidity providers who sign a message consisting of the `transferId` and path length. The path length variable only guarantees that the message they signed will only be valid if `_args.routers.length - 1` routers are also selected. However, it does not prevent Gelato relayers from re-using the same signature multiple times. As a result, routers may unintentionally provide more liquidity than expected.

## Recommendation
Consider ensuring that a router’s signed message can only be used once for a given `transferId`. It may be useful to track these in a boolean mapping.

## Connext
Solved in PR 1626.

## Spearbit
Verified.

## Note
This still assumes that the sequencer is a centralized role maintained by the Connext team. We understand that this will be addressed in future on-chain changes to incentivize honest behavior and further decentralize the sequencer role. Currently, the sequencer is a centralized role, and will be decentralized in the future.

Consider that the only "attack vector" here (really more of a griefing vector) is that the sequencer has only the potential to favor certain routers over others and cannot steal anyone’s funds. Additionally, we know that the “randomness” of the sequen

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 12: M-2: Cross-chain replay attacks are possible with `changeRecipientAddress()`

**Source**: Sherlock
**Protocol**: Harpie
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-harpie-judging/tree/main/004-M 

## Found by 
minhquanym, JohnSmith, IllIllI

## Summary
Mistakes made on one chain can be re-applied to a new chain

## Vulnerability Detail
There is no `chain.id` in the signed data

## Impact
If a user does a `changeRecipientAddress()` using the wrong network, an attacker can replay the action on the correct chain, and steal the funds a-la the wintermute gnosis safe attack, where the attacker can create the same address that the user tried to, and steal the funds from there

## Code Snippet
https://github.com/Harpieio/contracts/blob/97083d7ce8ae9d85e29a139b1e981464ff92b89e/contracts/Vault.sol#L60-L73

## Tool used

Manual Review

## Recommendation
Include the `chain.id` in what's hashed

## Harpie Team
Added chainId to signature and signature validation. Fix [here](https://github.com/Harpieio/contracts/pull/4/commits/de24a50349ec014163180ba60b5305098f42eb14).

## Lead Senior Watson
This is true assuming the contract address is the same across other chains. Confirmed fix.

---

### Example 13: Signature Replay Allows Unauthorized Use of Permits

**Source**: MixBytes
**Protocol**: P2P.org
**Impact**: MEDIUM

**Details**:

##### Description
This issue has been identified within the signature verification flow of the `isValidSignature` function in the `P2pLendingProxy` contract. 

Currently, signatures are verified against `s_client`, but the contract’s address or any unique identifier is not included in the signed data. An attacker can replay the same signature across multiple `P2pLendingProxy` instances owned by the same user. For example, the replayed signature could authorize unwanted or additional transfers. 

In the context of `Permit2`, such reuse could allow multiple proxies to be drained using a single signature. Moreover, any message a client signs for themselves may inadvertently be valid for their proxies, and vice versa. 

This issue is classified as **medium** severity because, while the proxy contracts are not designed to store tokens on balance, replay attacks still pose a risk of unauthorized operations.

##### Recommendation
We recommend incorporating the contract address (or a unique contract-specific field) into the signed data, such as via an EIP-712 domain separator. By doing so, signatures become valid exclusively for the intended `P2pLendingProxy` contract, mitigating replay across different addresses.

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/P2P.org/Lending%20Proxy/README.md#4-signature-replay-allows-unauthorized-use-of-permits)

---

### Example 14: M-9: Nonces not used in signed data

**Source**: Sherlock
**Protocol**: Harpie
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-harpie-judging/tree/main/160-M 

## Found by 
IllIllI

## Summary
Nonces are not used in the signature checks

## Vulnerability Detail
A nonce can prevent an old value from being used when a new value exists. Without one, two transactions submitted in one order, can appear in a block in a different order

## Impact
If a user is attacked, then tries to change the recipient address to a more secure address, initially chooses an insecure compromised one, but immediately notices the problem, then re-submits as a different, uncompromised address, a malicious miner can change the order of the transactions, so the insecure one is the one that ends up taking effect, letting the attacker transfer the funds

## Code Snippet
https://github.com/Harpieio/contracts/blob/97083d7ce8ae9d85e29a139b1e981464ff92b89e/contracts/Vault.sol#L67-L71

## Tool used

Manual Review

## Recommendation
Include a nonce in what is signed

## Harpie Team
Fixed by changing nonce system to an incremental system. Fix [here](https://github.com/Harpieio/contracts/pull/4/commits/ee6f5cdf52fa5604d4693331189edff6558c9b8a).

## Lead Senior Watson
Not an issue AFAIK, miners can't reorder txs unless they are signed with the same nonce. There would have to be some serious mis-use of this function by the recipient address, i.e. they would have to ask the server to sign for two different addresses and then broadcast the txs with the same nonce for this call. The proposed fix

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 14
- Examples shown: 14
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

