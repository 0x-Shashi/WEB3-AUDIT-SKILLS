# Documentation Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 1 | 3 | 0 |

**Common Sources**: Cyfrin, Code4rena

---

## Detection Checklist

- [ ] Check for documentation vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [QA-02] Interface Documentation References Wrong Token Standard

**Source**: Code4rena
**Protocol**: THORWallet
**Impact**: LOW

**Details**:

### Finding description and impact

The `IERC677Receiver` interface documentation incorrectly references `ERC1363` instead of `ERC677`. This mismatch between the interface name and its documentation could lead to integration issues and developer confusion.

The interface is named `IERC677Receiver` but its documentation comments reference `ERC1363`’s `transferAndCall` functionality. While both standards have similar purposes, they have different implementations and requirements. This inconsistency could cause:

* Integration errors if developers implement the wrong standard based on the documentation
* Confusion during code review and maintenance
* Potential compatibility issues with other contracts expecting specific standard implementations
  The impact is low, as this is primarily a documentation issue and does not affect the actual functionality of the code.

### Proof of Concept

The interface in [IERC677Receiver.sol](https://github.com/code-423n4/2025-02-thorwallet/blob/98d7e936518ebd80e2029d782ffe763a3732a792/contracts/interfaces/IERC677Receiver.sol# L5-L6):
```

/**
 * @title IERC1363Receiver
 * @dev Interface for any contract that wants to support `transferAndCall` or `transferFromAndCall` from ERC-1363 token contracts.
 */
interface IERC677Receiver {
    function onTokenTransfer(address sender, uint value, bytes calldata data) external;
}
```

The interface is used in `MergeTgt.sol` for handling token transfers, but it’s implementing ERC677 functionality despite the 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2025-02-thorwallet)

---

### Example 2: Use call instead of transfer

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** In both of the withdraw functions, `transfer()` is used for native ETH withdrawal.
The transfer() and send() functions forward a fixed amount of 2300 gas. Historically, it has often been recommended to use these functions for value transfers to guard against reentrancy attacks. However, the gas cost of EVM instructions may change significantly during hard forks which may break already deployed contract systems that make fixed assumptions about gas costs. For example. EIP 1884 broke several existing smart contracts due to a cost increase of the SLOAD instruction.

**Impact:** The use of the deprecated transfer() function for an address will inevitably make the transaction fail when:
- The claimer smart contract does not implement a payable function.
- The claimer smart contract does implement a payable fallback which uses more than 2300 gas unit.
- The claimer smart contract implements a payable fallback function that needs less than 2300 gas units but is called through proxy, raising the call's gas usage above 2300.

Additionally, using higher than 2300 gas might be mandatory for some multisig wallets.

**Recommended Mitigation:** Use call() instead of transfer().

**Protocol:**
Agree, transfer was causing issues with smart contract wallets.

**Cyfrin:** Verified in commit [7726ae7](https://github.com/HyperGood/woosh-contracts/commit/7726ae72118cfdf91ceb9129e36662f69f4d42de).

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 3: Exit fees implementation is inconsistent with documentation

**Source**: Cyfrin
**Protocol**: Stakepet
**Impact**: LOW

**Details**:

**Severity:** Low

**Description:** Inline comments of `StakePet` contract indicate that exit fee is charged as % of the collateral.

```
The contract also has an early exit fee, which is a percentage of the collateral taken if a participant chooses to exit early.
```

However, implementation shows that exit fee is charged as a [percent of yield](https://github.com/Ranama/StakePet/blob/9ba301823b5062d657baa3462224da498dc4bb46/src/StakePet.sol#L559)

```
uint256 earlyExitFee = (uint256(yieldToWithdraw) * EARLY_EXIT_FEE) / BASIS_POINT
```

**Recommended Mitigation:** Consider correcting code documentation to reflect actual implementation

**Client:** Fixed in [54a4dcb](https://github.com/Ranama/StakePet/commit/54a4dcbb696da3138dc0fdd8e7032d664d32b7da)

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-stakepet.md)

---

### Example 4: Closedown condition is inconsistent with the stated documentation of majority agreement

**Source**: Cyfrin
**Protocol**: Stakepet
**Impact**: LOW

**Details**:

**Severity:** Low

**Description:** [Documentation](https://hackmd.io/CPINxScvSE2vo-t8mwY_Og#Risks) states the following:

_"Closing the Contract: If the majority of the pets agree, they can vote to close the contract. Once closed, the remaining funds will be divided among the surviving pets. This is the most beneficial scenario for you, as you’ll earn the base rewards, early withdrawal rewards, and rewards from dead pets."_

Inline comments for the [`StakePet::closedown`](https://github.com/Ranama/StakePet/blob/9ba301823b5062d657baa3462224da498dc4bb46/src/StakePet.sol#L398C2-L398C2) function state the following"

```
    /// @notice Close down the contract if majority wants it, after closedown everyone can withdraw without getting a yield cut and no pet can die.
    function closedown(uint256[] memory _idsOfMajorityThatWantsClosedown) external {
...
}
```

In both cases, condition for closedown is for `majority of pets` to agree for a closedown. However, the check used for `closedown` is that the total collateral of pets wanting a closedown should be atleast 50% of the total collateral. This would mean that a single or few pet owners with large collateral deposits can trigger a closedown even if its not something that a majority of pet owners agree to.

Having 50% of value agreement and having majority agreement could be 2 different things.

**Impact:** The current model can be hijacked by whales who can trigger closedown of contract whenever they wish to. This could create 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-stakepet.md)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
