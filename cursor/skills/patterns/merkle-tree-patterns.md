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
