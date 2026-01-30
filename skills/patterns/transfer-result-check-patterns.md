# Transfer Result Check Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 2 | 0 | 0 |

**Common Sources**: Code4rena, Halborn

---

## Detection Checklist

- [ ] Check for transfer result check vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-02] The check for value transfer success is made after the return statement in `_withdrawFromYieldPool` of `LidoVault`

**Source**: Code4rena
**Protocol**: Sturdy
**Impact**: HIGH

**Details**:

Users can lose their funds

### Proof of Concept

[LidoVault.sol#L142](https://github.com/code-423n4/2022-05-sturdy/blob/78f51a7a74ebe8adfd055bdbaedfddc05632566f/smart-contracts/LidoVault.sol#L142)<br>

The code checks transaction success after returning the transfer value and finishing execution. If the call fails the transaction won't revert since  require(sent, Errors.VT_COLLATERAL_WITHDRAW_INVALID); won't execute.

Users will have withdrawn without getting their funds back.

### Recommended Mitigation Steps

Return the function after the success check

**[sforman2000 (Sturdy) confirmed](https://github.com/code-423n4/2022-05-sturdy-findings/issues/157)**

**[iris112 (Sturdy) commented](https://github.com/code-423n4/2022-05-sturdy-findings/issues/157):**
 > [Fix the issue of return before require sturdyfi/code4rena-may-2022#9](https://github.com/sturdyfi/code4rena-may-2022/pull/9)

**[hickuphh3 (judge) commented](https://github.com/code-423n4/2022-05-sturdy-findings/issues/157#issuecomment-1145546283):**
 > Issue is rather clear-cut.



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-sturdy)

---

### Example 2: NON-STANDARD ERC20 TOKENS WILL REVERT

**Source**: Halborn
**Protocol**: Primex Contracts
**Impact**: MEDIUM

**Details**:

##### Description

The library `TokenTransfersLibrary.sol` contains the function to perform ERC20 tokens transfers in the protocol. However, this library uses the interface of `IERC20` from OpenZeppelin which enforces the return value on transfer.

This pattern is not followed by all ERC20 tokens, as for example USDT. If attempting to transfer these tokens, the contract will revert, preventing the transaction to be executed.

Code Location
-------------

[TokenTransfersLibrary.sol#L12-L19](https://github.com/primex-finance/primex_contracts/blob/f809cc0471935013699407dcd9eab63b60cd2e22/src/contracts/libraries/TokenTransfersLibrary.sol#L12-L19)

#### TokenTransfersLibrary.sol

```
function doTransferFromTo(address token, address from, address to, uint256 amount) public returns (uint256) {
    uint256 balanceBefore = IERC20(token).balanceOf(to);
    // The returned value is checked in the assembly code below.
    // Arbitrary `from` should be checked at a higher level. The library function cannot be called by the user.
    // slither-disable-next-line unchecked-transfer arbitrary-send-erc20
    IERC20(token).transferFrom(from, to, amount);

    bool success;

```

[TokenTransfersLibrary.sol#L46-L51](https://github.com/primex-finance/primex_contracts/blob/f809cc0471935013699407dcd9eab63b60cd2e22/src/contracts/libraries/TokenTransfersLibrary.sol#L46-L51)

#### TokenTransfersLibrary.sol

```
function doTransferOut(address token, address to, uint256 amount) public {
    // The retur

*[Content truncated...]*

**Reference**: [View Original Finding](https://www.halborn.com/audits/primex/primex-contracts)

---

### Example 3: [M-06] Funds locked due to missing transfer check

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

All of the user's funds are unretrievably locked in the `PrizeVault` contract.

A combination of issues allows for the following scenario:

1. Alice invokes [`_withdraw(receiver, assets)`](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L925-L941) (via `burn()` or `withdraw()`).
2. The contract [computes the number of shares to redeem](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L933-L934), via `previewWithdraw(assets)`.
3. The contract [redeems as many shares](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L935-L936), but the ERC 4626-compliant vault returns fewer shares than expected. At this point, the contract holds fewer than `assets` tokens.
4. The contract [attempts to `transfer` assets to the receiver](https://github.com/code-423n4/2024-03-pooltogether/blob/480d58b9e8611c13587f28811864aea138a0021a/pt-v5-vault/src/PrizeVault.sol#L939). This fails due to insufficient funds, but the ERC 20-compliant token does not revert (only returns `false`).
5. At this point, Alice's assets are locked in the `PrizeVault` contract. They cannot be withdrawn at a later point, because the corresponding prize vault and yield vault shares have been burned.

The exploit relies on insufficient handling of two corner cases of [ERC-20](https://eips.ether

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-03-pooltogether)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

