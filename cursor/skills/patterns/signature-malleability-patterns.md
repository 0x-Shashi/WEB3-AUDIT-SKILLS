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

