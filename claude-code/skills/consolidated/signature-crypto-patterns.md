# Signature & Cryptography Security Patterns (Consolidated)

> **Cryptographic vulnerabilities allow signature replay, forgery, and authentication bypass.**

---

## Quick Summary

| Issue | Description | Severity |
|-------|-------------|----------|
| Signature Malleability | Same sig can have multiple valid forms | High |
| Missing Nonce | Signature can be replayed | Critical |
| Cross-Chain Replay | Sig valid on multiple chains | High |
| Missing Deadline | Signature never expires | Medium |
| ecrecover Returns Zero | Invalid sig returns address(0) | High |
| Weak Domain Separator | Missing chainId or address in EIP-712 | High |

---

## Detection Strategy

### Signature Malleability
```solidity
// VULNERABLE: Using raw ecrecover
function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public returns (address) {
    return ecrecover(hash, v, r, s);  // s can be flipped!
}

// SAFE: Use OpenZeppelin ECDSA (checks s value)
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
function verify(bytes32 hash, bytes memory signature) public returns (address) {
    return ECDSA.recover(hash, signature);
}
```

### Replay Protection
```solidity
// VULNERABLE: No nonce
function execute(bytes memory sig) external {
    address signer = verify(hash, sig);
    // Can replay same sig multiple times!
}

// SAFE: Use nonce
mapping(address => uint256) public nonces;

function execute(bytes memory sig, uint256 nonce) external {
    require(nonce == nonces[msg.sender]++, "Invalid nonce");
    bytes32 hash = keccak256(abi.encode(data, nonce, block.chainid));
    address signer = ECDSA.recover(hash, sig);
}
```

### EIP-712 Domain Separator
```solidity
// MUST include chainId and contract address
bytes32 DOMAIN_SEPARATOR = keccak256(abi.encode(
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    keccak256(bytes("MyProtocol")),
    keccak256(bytes("1")),
    block.chainid,
    address(this)
));
```

### Audit Checklist
- [ ] Using ECDSA.recover() not raw ecrecover
- [ ] Checking recovered address != address(0)
- [ ] Nonce included in signed message
- [ ] Deadline/expiry included in signed message
- [ ] ChainId included in domain separator
- [ ] Contract address included in domain separator
- [ ] Signature marked as used after verification

---

## Included Pattern Files

- signature-malleability-patterns.md, replay-attack-patterns.md
- nonce-patterns.md, deadline-patterns.md
- eip-712-patterns.md, merkle-tree-patterns.md, abi-encoding-patterns.md

---

## Full Pattern Details

---
## signature-malleability-patterns.md
# Signature Malleability Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 3 | 0 | 0 |

**Common Sources**: Code4rena, MixBytes, Sherlock

---

## Detection Checklist

- [ ] Check for signature malleability vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-03] `SettlementSignatureVerifier` is missing check for duplicate validator signatures

**Source**: Code4rena
**Protocol**: Chakra
**Impact**: HIGH

**Details**:

### Impact

`SettlementSignatureVerifier::verifyECDSA` and `settlement::check_chakra_signatures` lack checks for duplicate validators and allow passing the threshold with a single valid signature.

### Proof of Concept

From the `README`, we see that `validators` arent trusted roles, they simply have to perform their duties and in case they are misbehaving `MANAGER` can remove them. Its not expected they all to decide to perform a sybil attack.

But for this issue single validator can harm the entire protocol because signature verifiers dont check for duplicated validators and one valid signature is enough to pass the check:

### Solidity

[SettlementSignatureVerifier.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/SettlementSignatureVerifier.sol#L207)

```solidity
function verifyECDSA(
    bytes32 msgHash,
    bytes calldata signatures
) internal view returns (bool) {
    require(
        signatures.length % 65 == 0,
        "Signature length must be a multiple of 65"
    );

    uint256 len = signatures.length;
    uint256 m = 0;
    for (uint256 i = 0; i < len; i += 65) {
        bytes memory sig = signatures[i:i + 65];
        if (
            validators[msgHash.recover(sig)] && ++m >= required_validators
        ) {
            return true;
        }
    }

    return false;
}
```

As we can see nowhere do we check whether this sig is contained twice in the `signatures` argument.

Knowing that a single validator can call `Chak

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-08-chakra)

---

### Example 2: [M-01] `cancelSig` will not completely cancel signatures due to malleability vulnerabilities

**Source**: Code4rena
**Protocol**: Nouns DAO
**Impact**: MEDIUM

**Details**:

<https://github.com/nounsDAO/nouns-monorepo/blob/718211e063d511eeda1084710f6a682955e80dcb/packages/nouns-contracts/contracts/governance/NounsDAOV3Proposals.sol#L270-L275><br>
<https://github.com/nounsDAO/nouns-monorepo/blob/718211e063d511eeda1084710f6a682955e80dcb/packages/nouns-contracts/contracts/governance/NounsDAOV3Proposals.sol#L983>

The current version of openzeppelin contracts has a high risk of vulnerability about signature malleability attack: <https://github.com/OpenZeppelin/openzeppelin-contracts/pull/3610>.

So if the signer only cancel one signature, the malicious proposer can still extend a fully valid signature through the previous signature to pass the proposal.

### Proof of Concept
<details>
 
```solidity
// CancelProposalBySigs.t.sol
contract TestSignatureMalleabilityAttack is ZeroState {
    function setUp() public virtual override {
        super.setUp();

        (signerWithVote, signerWithVotePK) = makeAddrAndKey('signerWithVote');

        vm.startPrank(minter);
        nounsToken.mint();
        nounsToken.transferFrom(minter, signerWithVote, 1);
        vm.roll(block.number + 1);
        vm.stopPrank();

        NounsDAOV3Proposals.ProposalTxs memory txs = makeTxs(makeAddr('target'), 0, '', '');
        uint256 expirationTimestamp = block.timestamp + 1234;
        NounsDAOStorageV3.ProposerSignature[] memory proposerSignatures = new NounsDAOStorageV3.ProposerSignature[](1);
        bytes memory signature = signProposal(proposer, signerWithVotePK, tx

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-nounsdao)

---

### Example 3: [H-01] Signature malleability of EVM's `ecrecover` in `verify()`

**Source**: Code4rena
**Protocol**: LarvaLabs Meebits
**Impact**: HIGH

**Details**:

## Handle

0xRajeev


## Vulnerability details

## Impact

EVM's ecrecover is susceptible to signature malleability which allows replay attacks, but that is mitigated here by tracking accepted offers and cancelling it (on L645) specifically to prevent replays. However, if any of the application logic changes, it might make signature malleability a risk for replay attacks.

See reference: https://swcregistry.io/docs/SWC-117

## Proof of Concept

https://github.com/code-423n4/2021-04-redacted/blob/2ec4ce8e98374be2048126485ad8ddacc2d36d2f/Beebots.sol#L575

https://github.com/code-423n4/2021-04-redacted/blob/2ec4ce8e98374be2048126485ad8ddacc2d36d2f/Beebots.sol#L643-L645



## Tools Used

Manual Analysis

## Recommended Mitigation Steps

Consider using OpenZeppelins ECDSA library: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-04-meebits)

---

### Example 4: M-6: Signature malleability not protected against

**Source**: Sherlock
**Protocol**: Harpie
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-harpie-judging/tree/main/010-M 

## Found by 
0xNazgul, pashov, IllIllI, ladboy233, defsec, sirhashalot

## Summary
OpenZeppelin has a vulnerability in versions lower than 4.7.3, which can be exploited by an attacker. The project uses a vulnerable version

## Vulnerability Detail
All of the conditions from the advisory are satisfied: the signature comes in a single `bytes` argument, `ECDSA.recover()` is used, and the signatures themselves are used for replay protection checks
https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-4h98-2769-gh6h

If a user calls `changeRecipientAddress()`, notices a mistake, then calls `changeRecipientAddress()` again, an attacker can use signature malleability to re-submit the first change request, as long as the old request has not expired yet.

## Impact
The wrong, potentially now-malicious, address will be the valid change recipient, which could lead to the loss of funds (e.g. the attacker attacked, the user changed to another compromised address, noticed the issue, then changed to a whole new account address, but the attacker was able to change it back and withdraw the funds to the unprotected address).

## Code Snippet
https://github.com/Harpieio/contracts/blob/97083d7ce8ae9d85e29a139b1e981464ff92b89e/package.json#L23

## Tool used

Manual Review

## Recommendation
Change to version 4.7.3

## Lead Senior Watson
Good find and the fix seems straightforward. Upgrade 

*[Content truncated...]*

---

### Example 5: Signature Replay Allows Unauthorized Use of Permits

**Source**: MixBytes
**Protocol**: P2P.org
**Impact**: MEDIUM

**Details**:

##### Description
This issue has been identified within the signature verification flow of the `isValidSignature` function in the `P2pLendingProxy` contract. 

Currently, signatures are verified against `s_client`, but the contracts address or any unique identifier is not included in the signed data. An attacker can replay the same signature across multiple `P2pLendingProxy` instances owned by the same user. For example, the replayed signature could authorize unwanted or additional transfers. 

In the context of `Permit2`, such reuse could allow multiple proxies to be drained using a single signature. Moreover, any message a client signs for themselves may inadvertently be valid for their proxies, and vice versa. 

This issue is classified as **medium** severity because, while the proxy contracts are not designed to store tokens on balance, replay attacks still pose a risk of unauthorized operations.

##### Recommendation
We recommend incorporating the contract address (or a unique contract-specific field) into the signed data, such as via an EIP-712 domain separator. By doing so, signatures become valid exclusively for the intended `P2pLendingProxy` contract, mitigating replay across different addresses.

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/P2P.org/Lending%20Proxy/README.md#4-signature-replay-allows-unauthorized-use-of-permits)

---

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## replay-attack-patterns.md
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
Consider ensuring that a routers signed message can only be used once for a given `transferId`. It may be useful to track these in a boolean mapping.

## Connext
Solved in PR 1626.

## Spearbit
Verified.

## Note
This still assumes that the sequencer is a centralized role maintained by the Connext team. We understand that this will be addressed in future on-chain changes to incentivize honest behavior and further decentralize the sequencer role. Currently, the sequencer is a centralized role, and will be decentralized in the future.

Consider that the only "attack vector" here (really more of a griefing vector) is that the sequencer has only the potential to favor certain routers over others and cannot steal anyones funds. Additionally, we know that the randomness of the sequen

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

Currently, signatures are verified against `s_client`, but the contracts address or any unique identifier is not included in the signed data. An attacker can replay the same signature across multiple `P2pLendingProxy` instances owned by the same user. For example, the replayed signature could authorize unwanted or additional transfers. 

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


---
## nonce-patterns.md
# Nonce Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 1 | 1 | 0 |

**Common Sources**: Code4rena, Cyfrin, Sherlock

---

## Detection Checklist

- [ ] Check for nonce vulnerabilities in all external functions
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

### Example 2: [H-04] Project funds can be drained by reusing signatures, in some cases

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

### Example 3: Nonstandard usage of nonce

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: LOW

**Details**:

**Severity:** Informational

**Description:** The protocol implemented two withdraw functions `withdrawDeposit()` and `withdraw()`.
While the function `withdrawDeposit()` is designed to be used by the depositor themselves, the function `withdraw()` is designed to be used by anyone who has a signature from the depositor.
The function `withdraw()` has a parameter `nonce` but the usage of this param is not aligned with the general meaning of nonce.
```solidity
DepositVault.sol
59:     function withdraw(uint256 amount, uint256 nonce, bytes memory signature, address payable recipient) public {
60:         require(nonce < deposits.length, "Invalid deposit index");
61:         Deposit storage depositToWithdraw = deposits[nonce];//@audit-info non aligned with common understanding of nonce
62:         bytes32 withdrawalHash = getWithdrawalHash(Withdrawal(amount, nonce));
63:         address signer = withdrawalHash.recover(signature);
64:         require(signer == depositToWithdraw.depositor, "Invalid signature");
65:         require(!usedWithdrawalHashes[withdrawalHash], "Withdrawal has already been executed");
66:         require(amount == depositToWithdraw.amount, "Withdrawal amount must match deposit amount");
67:
68:         usedWithdrawalHashes[withdrawalHash] = true;
69:         depositToWithdraw.amount = 0;
70:
71:         if(depositToWithdraw.tokenAddress == address(0)){
72:             recipient.transfer(amount);
73:         } else {
74:             IERC20 token = IERC20(depo

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 4: M-9: Nonces not used in signed data

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

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## deadline-patterns.md
# Deadline Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 4 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for deadline vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-11: The deposit / withdraw / trade transaction lack of expiration timestamp check and slippage control

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/39 

## Found by 
ctf\_sec

## Summary

The deposit / withdraw / trade transaction lack of expiration timestamp and slippage control

## Vulnerability Detail

Let us look into the heavily forked Uniswap V2 contract addLiquidity function implementation

https://github.com/Uniswap/v2-periphery/blob/0335e8f7e1bd1e8d8329fd300aea2ef2f36dd19f/contracts/UniswapV2Router02.sol#L61

```solidity
// **** ADD LIQUIDITY ****
function _addLiquidity(
	address tokenA,
	address tokenB,
	uint amountADesired,
	uint amountBDesired,
	uint amountAMin,
	uint amountBMin
) internal virtual returns (uint amountA, uint amountB) {
	// create the pair if it doesn't exist yet
	if (IUniswapV2Factory(factory).getPair(tokenA, tokenB) == address(0)) {
		IUniswapV2Factory(factory).createPair(tokenA, tokenB);
	}
	(uint reserveA, uint reserveB) = UniswapV2Library.getReserves(factory, tokenA, tokenB);
	if (reserveA == 0 && reserveB == 0) {
		(amountA, amountB) = (amountADesired, amountBDesired);
	} else {
		uint amountBOptimal = UniswapV2Library.quote(amountADesired, reserveA, reserveB);
		if (amountBOptimal <= amountBDesired) {
			require(amountBOptimal >= amountBMin, 'UniswapV2Router: INSUFFICIENT_B_AMOUNT');
			(amountA, amountB) = (amountADesired, amountBOptimal);
		} else {
			uint amountAOptimal = UniswapV2Library.quote(amountBDesired, reserveB, reserveA);
			assert(amountAOptimal <= amountADesired);
			require(amountAOptimal >= amountAMin

*[Content truncated...]*

---

### Example 2: H-14: Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/145 

## Found by 
Bauer, Breeje, ctf\_sec
## Summary

Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

## Vulnerability Detail

In the current implementation in CurveSpell.sol

```solidity
{
	// 2. Swap rewards tokens to debt token
	uint256 rewards = _doCutRewardsFee(CRV);
	_ensureApprove(CRV, address(swapRouter), rewards);
	swapRouter.swapExactTokensForTokens(
		rewards,
		0,
		swapPath,
		address(this),
		type(uint256).max
	);
}
```

the deadline check is set to type(uint256).max, which means the deadline check is disabled!

In IChiSpell. the swap is directedly call on the pool instead of the router

```solidity
SWAP_POOL.swap(
	address(this),
	// if withdraw token is Token0, then swap token1 -> token0 (false)
	!isTokenA,
	amountToSwap.toInt256(),
	isTokenA
		? param.sqrtRatioLimit + deltaSqrt
		: param.sqrtRatioLimit - deltaSqrt, // slippaged price cap
	abi.encode(address(this))
);
```

and it has no deadline check for the transaction when swapping

## Impact

AMMs provide their users with an option to limit the execution of their pending actions, such as swaps or adding and removing liquidity. The most common solution is to include a deadline timestamp as a parameter (for example see Uniswap V2 and Uniswap V3). If such an option is not present, users can unknowingly perform bad trades:

Alice wants to swap 100 tokens for 1 ETH and

*[Content truncated...]*

---

### Example 3: [M-02] Dangerous use of deadline parameter

**Source**: Code4rena
**Protocol**: Particle Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-12-particle/blob/a3af40839b24aa13f5764d4f84933dbfa8bc8134/contracts/libraries/LiquidityPosition.sol#L144> 

<https://github.com/code-423n4/2023-12-particle/blob/a3af40839b24aa13f5764d4f84933dbfa8bc8134/contracts/libraries/LiquidityPosition.sol#L197> 

<https://github.com/code-423n4/2023-12-particle/blob/a3af40839b24aa13f5764d4f84933dbfa8bc8134/contracts/libraries/LiquidityPosition.sol#L260>

The protocol is using `block.timestamp` as the deadline argument while interacting with the Uniswap NFT Position Manager, which completely defeats the purpose of using a deadline.

### Impact

Actions in the Uniswap NonfungiblePositionManager contract are protected by a `deadline` parameter to limit the execution of pending transactions. Functions that modify the liquidity of the pool check this parameter against the current block timestamp in order to discard expired actions.

These interactions with the Uniswap position are present in the LiquidityPosition library. The functions `mint()`, `increaseLiquidity()` and `decreaseLiquidity()` call their corresponding functions in the Uniswap Position Manager, providing `block.timestamp` as the argument for the `deadline` parameter:

<https://github.com/code-423n4/2023-12-particle/blob/a3af40839b24aa13f5764d4f84933dbfa8bc8134/contracts/libraries/LiquidityPosition.sol#L131-L146>

```solidity
131:         // mint the position
132:         (tokenId, liquidity, amount0Minted, amount1Minted) = Base.UNI_POSITION_MA

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-12-particle)

---

### Example 4: M-4: The deposit - withdraw - trade transaction lack of expiration timestamp check (DeadLine check)

**Source**: Sherlock
**Protocol**: RealWagmi
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-real-wagmi-judging/issues/163 

## Found by 
Avci, Phantasmagoria, kutugu, sashik\_eth, shealtielanz
## Summary
The deposit - withdraw - trade transaction lack of expiration timestamp check (DeadLine check)
## Vulnerability Detail
the protocol missing the DEADLINE check at all in logic. 

this is actually how uniswap implemented the **Deadline**, this protocol also need deadline check like this logic 

https://github.com/Uniswap/v2-periphery/blob/0335e8f7e1bd1e8d8329fd300aea2ef2f36dd19f/contracts/UniswapV2Router02.sol#L61
```solidity

// **** ADD LIQUIDITY ****
function _addLiquidity(
	address tokenA,
	address tokenB,
	uint amountADesired,
	uint amountBDesired,
	uint amountAMin,
	uint amountBMin
) internal virtual returns (uint amountA, uint amountB) {
	// create the pair if it doesn't exist yet
	if (IUniswapV2Factory(factory).getPair(tokenA, tokenB) == address(0)) {
		IUniswapV2Factory(factory).createPair(tokenA, tokenB);
	}
	(uint reserveA, uint reserveB) = UniswapV2Library.getReserves(factory, tokenA, tokenB);
	if (reserveA == 0 && reserveB == 0) {
		(amountA, amountB) = (amountADesired, amountBDesired);
	} else {
		uint amountBOptimal = UniswapV2Library.quote(amountADesired, reserveA, reserveB);
		if (amountBOptimal <= amountBDesired) {
			require(amountBOptimal >= amountBMin, 'UniswapV2Router: INSUFFICIENT_B_AMOUNT');
			(amountA, amountB) = (amountADesired, amountBOptimal);
		} else {
			uint amountAOptimal = UniswapV2Li

*[Content truncated...]*

---

### Example 5: [M-01] Missing deadline checks allow pending transactions to be maliciously executed

**Source**: Code4rena
**Protocol**: Backed Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L208>

<https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L182>

### Summary

The `PaprController` contract does not allow users to submit a deadline for their actions which execute swaps on Uniswap V3. This missing feature enables pending transactions to be maliciously executed at a later point.

### Detailed description

AMMs provide their users with an option to limit the execution of their pending actions, such as swaps or adding and removing liquidity. The most common solution is to include a deadline timestamp as a parameter (for example see [Uniswap V2](https://github.com/Uniswap/v2-periphery/blob/0335e8f7e1bd1e8d8329fd300aea2ef2f36dd19f/contracts/UniswapV2Router02.sol#L229) and [Uniswap V3](https://github.com/Uniswap/v3-periphery/blob/6cce88e63e176af1ddb6cc56e029110289622317/contracts/SwapRouter.sol#L119)). If such an option is not present, users can unknowingly perform bad trades:

1.  Alice wants to swap 100 `tokens` for 1 `ETH` and later sell the 1 `ETH` for 1000 `DAI`.
2.  The transaction is submitted to the mempool, however, Alice chose a transaction fee that is too low for miners to be interested in including her transaction in a block. The transaction stays pending in the mempool for extended periods, which could be hours, days, weeks, or even longer.
3.  When the average gas fee dropped far enough for 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-backed)

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## eip-712-patterns.md
# EIP-712 Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 5 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Codehawks, Spearbit

---

## Detection Checklist

- [ ] Check for eip-712 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] Untyped data signing

**Source**: Code4rena
**Protocol**: Rigor Protocol
**Impact**: HIGH

**Details**:

_Submitted by Lambda, also found by 0x1f8b, 0x52, horsefacts, vlad&#95;bochok, and wastewa_

[Community.sol#L175](https://github.com/code-423n4/2022-08-rigor/blob/e35f5f61be9ff4b8dc5153e313419ac42964d1fd/contracts/Community.sol#L175)<br>
[Community.sol#L213](https://github.com/code-423n4/2022-08-rigor/blob/e35f5f61be9ff4b8dc5153e313419ac42964d1fd/contracts/Community.sol#L213)<br>
[Community.sol#L530](https://github.com/code-423n4/2022-08-rigor/blob/e35f5f61be9ff4b8dc5153e313419ac42964d1fd/contracts/Community.sol#L530)<br>
[Disputes.sol#L91](https://github.com/code-423n4/2022-08-rigor/blob/f2498c86dbd0e265f82ec76d9ec576442e896a87/contracts/Disputes.sol#L91)<br>
[Project.sol#L142](https://github.com/code-423n4/2022-08-rigor/blob/f2498c86dbd0e265f82ec76d9ec576442e896a87/contracts/Project.sol#L142)<br>
[Project.sol#L167](https://github.com/code-423n4/2022-08-rigor/blob/f2498c86dbd0e265f82ec76d9ec576442e896a87/contracts/Project.sol#L167)<br>
[Project.sol#L235](https://github.com/code-423n4/2022-08-rigor/blob/f2498c86dbd0e265f82ec76d9ec576442e896a87/contracts/Project.sol#L235)<br>
[Project.sol#L286](https://github.com/code-423n4/2022-08-rigor/blob/f2498c86dbd0e265f82ec76d9ec576442e896a87/contracts/Project.sol#L286)<br>
[Project.sol#L346](https://github.com/code-423n4/2022-08-rigor/blob/f2498c86dbd0e265f82ec76d9ec576442e896a87/contracts/Project.sol#L346)<br>
[Project.sol#L402](https://github.com/code-423n4/2022-08-rigor/blob/f2498c86dbd0e265f82ec76d9ec576442e896a87/contracts/Project

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-rigor)

---

### Example 2: The digest inSeaDrop.mintSigned is not calculated correctly according to EIP-712

**Source**: Spearbit
**Protocol**: SeaDrop
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
SeaDrop.sol#L308

## Description
The `mintParams` in the calculation of the digest in `mintSigned` is of struct type, so we would need to calculate and use its `hashStruct`, not the actual variable on its own.

## Recommendation
According to EIP-712, the correct digest would be:

```solidity
// Include this typehash at the top of the contract
bytes32 internal constant _MINT_PARAMS_TYPEHASH = keccak256(
    "MintParams("
    "uint256 mintPrice,"
    "uint256 maxTotalMintableByWallet,"
    "uint256 startTime,"
    "uint256 endTime,"
    "uint256 dropStageIndex,"
    "uint256 maxTokenSupplyForStage,"
    "uint256 feeBps,"
    "bool restrictFeeRecipients"
    ")"
);
```

...

```solidity
// hashStruct for mintParams
bytes32 mintParamsHashStruct = keccak256(
    abi.encode(
        _MINT_PARAMS_TYPEHASH,
        mintParams.mintPrice,
        mintParams.maxTotalMintableByWallet,
        mintParams.startTime,
        mintParams.endTime,
        mintParams.dropStageIndex,
        mintParams.maxTokenSupplyForStage,
        mintParams.feeBps,
        mintParams.restrictFeeRecipients
    )
);
```

```solidity
bytes32 digest = keccak256(
    abi.encodePacked(
        // EIP-191: `0x19 ` as set prefix, `0x01 ` as version byte
        bytes2(0x1901),
        _domainSeparator(),
        keccak256(
            abi.encode(
                _SIGNED_MINT_TYPEHASH,
                nftContract,
                minter,
                feeRecipient,
             

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Seadrop-Spearbit-Security-Review.pdf)

---

### Example 3: The `digest` calculation in `deployProxyAndDistributeBySignature` does not follow EIP-712 specification

**Source**: Codehawks
**Protocol**: Sparkn
**Impact**: MEDIUM

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/ProxyFactory.sol#L159">https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/ProxyFactory.sol#L159</a>


## Summary

The calculation of the `digest` done in [`ProxyFactory.deployProxyAndDistributeBySignature()`](https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/ProxyFactory.sol#L159) does not follow the [EIP-712 specification](https://eips.ethereum.org/EIPS/eip-712). It is missing the function's corresponding `typeHash`, as well as the `hashStruct` calculation of the `data` signature parameter, which are both defined in the EIP.

Not following the EIP specification will end up in unexpected integration failures with EIP712-compliant wallets or tooling that perform the encoding in the appropriate way.  

## Vulnerability Details

In [`ProxyFactory.deployProxyAndDistributeBySignature()`](https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/ProxyFactory.sol#L159), the `digest` is calculated as follows:

```solidity
bytes32 digest = _hashTypedDataV4(
    keccak256(
        abi.encode(contestId, data)
    )
);
```
The [EIP-712 specification](https://eips.ethereum.org/EIPS/eip-712#specification) defines the encoding of a message as:

```
"\x19\x01"  domainSeparator  hashStruct(message)
```
In the current impl

*[Content truncated...]*

---

### Example 4: [M-11] Protocol does not implement EIP712 correctly on multiple occasions

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L151-L151> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L373-L375> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L384-L386> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L232-L238> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L636>

Being not EIP712 compliant can lead to issues with integrators and possibly DOS.

### Problem 1

The implementation of the hook hash ([here](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L151C56-L151C56)) is done incorrectly. `hook.extraData` is of type `bytes` which according to EIP712 it is referred to as a `dynamic type`. Dynamic types must be first hashed with `keccak256` to become one 32-byte word before being encoded and hashed together with the typeHash and the other values.

### Mitigation to Problem 1:

```diff
function _deriveHookHash(Hook memory hook) internal view returns (bytes32) {
  // Derive and return the hook as specified by EIP-712.
    return
        keccak256(
-           abi.encode(_HOOK_TYPEHASH, hook.target, hook.itemIndex, hook.extraData)
+           abi.encode(_HOOK_TYPEHAS

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 5: [M-07] EIP-712 typehash is incorrect for several functions in `MetaTxLib`

**Source**: Code4rena
**Protocol**: Lens Protocol
**Impact**: MEDIUM

**Details**:

In `LensHub.sol`, the second parameter of `setProfileMetadataURIWithSig()` is declared as `metadataURI`:

[LensHub.sol#L119-L123](https://github.com/code-423n4/2023-07-lens/blob/main/contracts/LensHub.sol#L119-L123)

```solidity
    function setProfileMetadataURIWithSig(
        uint256 profileId,
        string calldata metadataURI,
        Types.EIP712Signature calldata signature
    ) external override whenNotPaused onlyProfileOwnerOrDelegatedExecutor(signature.signer, profileId) {
```

However, its [EIP-712](https://eips.ethereum.org/EIPS/eip-712) typehash stores the parameter as `metadata` instead:

[Typehash.sol#L33](https://github.com/code-423n4/2023-07-lens/blob/main/contracts/libraries/constants/Typehash.sol#L33)

```solidity
bytes32 constant SET_PROFILE_METADATA_URI = keccak256('SetProfileMetadataURI(uint256 profileId,string metadata,uint256 nonce,uint256 deadline)');
```

The `PostParams` struct (which is used for [`postWithSig()`](https://github.com/code-423n4/2023-07-lens/blob/main/contracts/LensHub.sol#L235-L244)) has `address[] actionModules` and `bytes[] actionModulesInitDatas` as its third and fourth fields:

[Types.sol#L178-L185](https://github.com/code-423n4/2023-07-lens/blob/main/contracts/libraries/constants/Types.sol#L178-L185)

```solidity
    struct PostParams {
        uint256 profileId;
        string contentURI;
        address[] actionModules;
        bytes[] actionModulesInitDatas;
        address referenceModule;
        bytes referenceModuleInit

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-lens)

---

### Example 6: M-1: Incorrect encoding of bytes for EIP712 digest in `TitleGraph` causes signatures generated by common EIP712 tools to be unusable

**Source**: Sherlock
**Protocol**: TITLES Publishing Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-04-titles-judging/issues/74 

## Found by 
0x73696d616f, T1MOH, ZanyBonzy, ast3ros, fugazzi, mt030d
## Summary

The signature in `TitleGraph.acknowledgeEdge()` and `TitleGraph.unacknowledgeEdge()` is generated based on a digest computed from `edgeId` and `data`. However, the `data` bytes argument is not correctly encoded according to the EIP712 specification. Consequently, a signature generated using common EIP712 tools would not pass validation in `TitleGraph.checkSignature()`.

## Vulnerability Detail
According to [EIP712](https://eips.ethereum.org/EIPS/eip-712#definition-of-encodedata):
> The dynamic values bytes and string are encoded as a keccak256 hash of their contents.

```solidity
    modifier checkSignature(bytes32 edgeId, bytes calldata data, bytes calldata signature) {
        bytes32 digest = _hashTypedData(keccak256(abi.encode(ACK_TYPEHASH, edgeId, data)));
        ...
    }
```
However, the `checkSignature()` modifier in the `TitlesGraph` contract reconstructs the digest by encoding the data bytes argument without first applying keccak256 hashing.
As a result, a signature generated using common EIP712 tools (e.g. using the `signTypedData` function from `ethers.js`) would not pass validation in `TitleGraph.checkSignature()`.

### POC
1. EIP712 signature computed by using ethers.js
```js
// main.js
const { ethers } = require("ethers");

async function main() {
    const pk = "0xac0974bec39a17e36ba4a6b4d238ff9

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## merkle-tree-patterns.md
# Merkle Tree Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 1 | 0 | 0 |

**Common Sources**: Spearbit, Codehawks, Code4rena

---

## Detection Checklist

- [ ] Check for merkle tree vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Phony signatures can be used to forge any strategy

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**Critical Risk**

## Context
`VaultImplementation.sol#L249`

## Description
In `in_validateCommitment()`, we check that the merkle root of the strategy has been signed by the strategist or delegate. After the signer is recovered, the following check is performed to validate the signature:

```plaintext
recovered != owner() && recovered != s.delegate && recovered != address(0)
```

This check seems to be miswritten, so that any time `recovered == address(0)`, the check passes. Whenever `ecrecover` is used to check the signed data, it returns `address(0)` in the situation that a phony signature is submitted. 

See this example for how this can be done. The result is that any borrower can pass in any merkle root they'd like, sign it in a way that causes `address(0)` to return from `ecrecover`, and have their commitment validated.

## Recommendation
Modify the check to:

```plaintext
if (
- recovered != owner() && recovered != s.delegate && recovered != address(0)
+ (recovered != owner() && recovered != s.delegate) || recovered == address(0)
) {
    revert IVaultImplementation.InvalidRequest(
        InvalidRequestReason.INVALID_SIGNATURE
    );
}
```

## Acknowledgements
- **Astaria**: Fixed in PR 209.
- **Spearbit**: Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 2: MERKLE.insert does not return the updated tree leaf count

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
Merkle.sol#L74

## Description
The NatSpec comment for `insert` is:

* `@return uint256 Updated count (number of nodes in the tree).`

However, this is not accurate. If the updated count is \(2k(2n + 1)\) where \(k, n \in \mathbb{N} [0]\), then the return value would be \(2n + 1\). Currently, the returned value of `insert` is not being used; otherwise, this could be a significant issue.

## Recommendation
- Cache `tree.count + 1` in another variable and return that, or 
- Do not modify size while inserting the new leaf and calculating the new root.
- Alternatively, modify the return NatSpec comment to indicate the exact value returned.

## Context
Solved in PR 2211.

## Spearbit
Verified. The original function has been removed (with the specific signature). In the new function:

```solidity
function insert(Tree memory tree, bytes32 node) internal pure returns (Tree memory)
```

the returned `Tree` has the correct leaf count.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 3: Successful transactions are not stored, causing a replay attack on ``redeemDepositsAndInternalBalances``

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

### Example 4: [M-01] Merkle Tree criteria can be resolved by wrong tokenIDs

**Source**: Code4rena
**Protocol**: OpenSea
**Impact**: MEDIUM

**Details**:

_Submitted by cmichel, also found by frangio and Spearbit_

[CriteriaResolution.sol#L157](https://github.com/code-423n4/2022-05-opensea-seaport/blob/4140473b1f85d0df602548ad260b1739ddd734a5/contracts/lib/CriteriaResolution.sol#L157)<br>

The protocol allows specifying several tokenIds to accept for a single offer.<br>
A merkle tree is created out of these tokenIds and the root is stored as the `identifierOrCriteria` for the item.<br>
The fulfiller then submits the actual tokenId and a proof that this tokenId is part of the merkle tree.<br>

There are no real verifications on the merkle proof that the supplied tokenId is indeed **a leaf of the merkle tree**.<br>
It's possible to submit an intermediate hash of the merkle tree as the tokenId and trade this NFT instead of one of the requested ones.<br>

This leads to losses for the offerer as they receive a tokenId that they did not specify in the criteria.<br>
Usually, this criteria functionality is used to specify tokenIds with certain traits that are highly valuable. The offerer receives a low-value token that does not have these traits.

### Example

Alice wants to buy either NFT with tokenId 1 or tokenId 2.<br>
She creates a merkle tree of it and the root is `hash(1||2) = 0xe90b7bceb6e7df5418fb78d8ee546e97c83a08bbccc01a0644d599ccd2a7c2e0`.<br>
She creates an offer for this criteria.<br>
An attacker can now acquire the NFT with tokenId `0xe90b7bceb6e7df5418fb78d8ee546e97c83a08bbccc01a0644d599ccd2a7c2e0` (or, generally, any ot

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-opensea-seaport)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## abi-encoding-patterns.md
# ABI Encoding Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 4 | 0 | 0 |

**Common Sources**: Pashov Audit Group, Spearbit, Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for abi encoding vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-04] `CidNFT`: Broken `tokenURI` function

**Source**: Code4rena
**Protocol**: Canto Identity Protocol
**Impact**: MEDIUM

**Details**:

[`CidNFT#tokenURI`](https://github.com/code-423n4/2023-01-canto-identity/blob/dff8e74c54471f5f3b84c217848234d474477d82/src/CidNFT.sol#L133-L142) does not convert the `uint256 _id` argument to a string before interpolating it in the token URI:

```solidity
    /// @notice Get the token URI for the provided ID
    /// @param _id ID to retrieve the URI for
    /// @return tokenURI The URI of the queried token (path to a JSON file)
    function tokenURI(uint256 _id) public view override returns (string memory) {
        if (ownerOf[_id] == address(0))
            // According to ERC721, this revert for non-existing tokens is required
            revert TokenNotMinted(_id);
        return string(abi.encodePacked(baseURI, _id, ".json"));
    }

```

This means the raw bytes of the 32-byte ABI encoded integer `_id` will be interpolated into the token URI, e.g. `0x0000000000000000000000000000000000000000000000000000000000000001` for ID `#1`.

Most of the resulting UTF-8 strings will be malformed, incorrect, or invalid URIs. For example, token ID `#1` will show up as the invisible "start of heading" control character, and ID `#42` will show as the asterisk symbol `*`. URI-unsafe characters will break the token URIs altogether.

### Impact

*   `CidNFT` tokens will have invalid `tokenURI`s. Offchain tools that read the `tokenURI` view may break or display malformed data.

### Suggestion

Convert the `_id` to a string before calling `abi.encodePacked`. Latest Solmate includes a `LibStri

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-canto-identity)

---

### Example 2: [M-01] Wrong collateral refund in liquidation when `liqPrice == priceAfterImpact`

**Source**: Pashov Audit Group
**Protocol**: Ostium_2025-04-06
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** High

**Likelihood:** Low

## Description

When a liquidation is triggered and the Oracle price used results in `liqPrice == priceAfterImpact` during the execution of `executeAutomationCloseOrderCallback()`, the system may incorrectly refund a portion of the user collateral - approximately equal to the `liquidationFee`.

This occurs due to a discrepancy in how `value` and `liqMarginValue` are calculated within the `getTradeValuePure()` function. Under specific conditions (`liqPrice == priceAfterImpact`), `value` can become greater than `liqMarginValue`, even though the position should be fully liquidated.

Within the new `Margin-Based Liquidations` logic, users should not receive any collateral back during liquidation. The entire collateral should be distributed between the `liquidationFee` and the `Vault` to cover losing trade.

However, do to the legacy refund logic that remains in the code:

```solidity
@>      uint256 usdcSentToVault = usdcLeftInStorage - usdcSentToTrader;
        storageT.transferUsdc(address(storageT), address(this), usdcSentToVault);
        vault.receiveAssets(usdcSentToVault, trade.trader);
@>      if (usdcSentToTrader > 0) storageT.transferUsdc(address(storageT), trade.trader, usdcSentToTrader);
```

With combination to the incorrect calculation of `value` and `liqMarginValue`, the `usdcSentToTrader` returned from the `getTradeValue()` function may end up being roughly equal to the `liquidationFee`, resulting in an unintende

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Ostium-security-review_2025-04-06.md)

---

### Example 3: ABI decoding for bytes: memory can be corrupted by maliciously constructing the calldata

**Source**: Spearbit
**Protocol**: SEAPORT
**Impact**: MEDIUM

**Details**:

## Security Analysis Report

## Severity: 
**Medium Risk**

## Context: 
`ConsiderationDecoder.sol#L51-L62`

## Description: 
In the code snippet below, `size` can be made `0` by maliciously crafting the calldata. In this case, the free memory is not incremented.

```solidity
assembly {
    mPtrLength := mload(0x40)
    let size := and(
        add(
            and(calldataload(cdPtrLength), OffsetOrLengthMask),
            AlmostTwoWords
        ),
        OnlyFullWordMask
    )
    calldatacopy(mPtrLength, cdPtrLength, size)
    mstore(0x40, add(mPtrLength, size))
}
```

This has two different consequences:
1. If the memory offset `mPtrLength` is immediately used, then junk values at that memory location can be interpreted as the decoded bytes type. In the case of Seaport 1.2, the likelihood of the current free memory pointing to junk value is low. So, this case has low severity.
2. The consequent memory allocation will also use the value `mPtrLength` to store data in memory. This can lead to corrupting the initial memory data. In the worst case, the next allocation can be tuned so that the first bytes data can be any arbitrary data.

### Steps to Make the Size Calculation Return 0:
1. Find a function call which has `bytes` as a (nested) parameter.
2. Modify the calldata field where the length of the above byte is stored to the new length `0xffffe0`.
3. The calculation will now return `size = 0`.

**Note:** There is an additional requirement that this `bytes` type should be

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Seaport-Spearbit-Security-Review.pdf)

---

### Example 4: M-1: `abi.encodePacked` Allows Hash Collision

**Source**: Sherlock
**Protocol**: NFTPort
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-nftport-judging/issues/118 

## Found by 
keccak123, 0xheynacho

## Summary

From the solidity documentation:
https://docs.soliditylang.org/en/v0.8.17/abi-spec.html?highlight=collisions#non-standard-packed-mode
    > If you use `keccak256(abi.encodePacked(a, b))` and both `a` and `b` are dynamic types, it is easy to craft collisions in the hash value by moving parts of `a` into `b` and vice-versa. More specifically, `abi.encodePacked("a", "bc") == abi.encodePacked("ab", "c")`.

This issue exists in the Factory contract can results in hash collisions, bypassing the `signedOnly` modifier.

## Vulnerability Detail

The issue is in these lines of code:
https://github.com/sherlock-audit/2022-10-nftport/blob/main/evm-minting-master/contracts/Factory.sol#L171
https://github.com/sherlock-audit/2022-10-nftport/blob/main/evm-minting-master/contracts/Factory.sol#L195
https://github.com/sherlock-audit/2022-10-nftport/blob/main/evm-minting-master/contracts/Factory.sol#L222

As the solidity docs describe, two or more dynamic types are passed to `abi.encodePacked`. Moreover, these dynamic values are user-specified function arguments in external functions, meaning anyone can directly specify the value of these arguments when calling the function. The `signedOnly` modifier is supposed to protect functions to permit only function arguments that have been properly signed to be passed to the function logic, but because a collision can be created,

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


