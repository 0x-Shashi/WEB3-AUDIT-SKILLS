---
id: PAT-CODE-QUALITY
title: Code Quality Security Patterns
category: general
severity: medium
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - security
  - vulnerability

finding_count: 10
last_updated: 2026-01-31
---
# Code Quality Security Patterns

## Overview

**Frequency**: 10 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 0 | 8 | 1 |

**Common Sources**: Cyfrin, Cantina, MixBytes, Hans, Code4rena

---

## Detection Checklist

- [ ] Check for code quality vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Debug code in `getPriceByExternal`

**Source**: MixBytes
**Protocol**: Divergence Protocol
**Impact**: HIGH

**Details**:

##### Description
The last instruction of the `getPriceByExternal` function will always return the same price (30_000e18). 
https://github.com/DivergenceProtocol/diver-contracts/blob/e5286f94a7ccb9d6279fae51ea66a8833672628a/src/core/Oracle.sol#L43
It leads to the incorrect settles of battles. An attacker can use this code issue for getting profit from bets. 
##### Recommendation
We recommend removing the `return (30_000e18, 0)` instruction from the function.

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/Divergence%20Protocol/README.md#1-debug-code-in-getpricebyexternal)

---

### Example 2: Unnecessary logical operation

**Source**: Cyfrin
**Protocol**: Swapexchange
**Impact**: LOW

**Details**:

**Severity:** Informational

**Description:** In the function `SwapExchange::calculateMultiSwap()` there is a logical operation that is not necessary in the for loop.

```solidity
SwapExchange.sol
161:         for (uint256 i = 0; i < swapIdCount; i++) {
162:             swapId = multiClaimInput.swapIds[i];
163:             SwapUtils.Swap memory swap = swaps[swapId];
164:             if (swap.tokenB != matchToken) revert Errors.NonMatchingToken();
165:             if (swap.amountB < matchAmount) revert Errors.NonMatchingAmount();
166:             if (matchAmount < swap.amountB) {
167:                 if (!swap.isPartial) revert Errors.NotPartialSwap();
168:                 matchAmount = MathUtils._mulDiv(swap.amountA, matchAmount, swap.amountB);
169:                 complete = complete && false;//@audit-issue INFO unnecessary operation, just set complete=false
170:             }
171:             else {
172:                 matchAmount = swap.amountA;
173:             }
174:             matchToken = swap.tokenA;
175:         }
```

**Protocol:** Fixed in commit [a079c11](https://github.com/SwapExchangeio/Contracts/commit/a079c11cc3bc044c61493040dab1f94de4a0f14a).

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-swapexchange.md)

---

### Example 3: Not proper variable naming

**Source**: Cyfrin
**Protocol**: Swapexchange
**Impact**: LOW

**Details**:

**Severity:** Informational

**Description:** The contract `FeeData` has a internal variable `_feeValue` that is used to calculate the fee.
Across the usage of this variable, it is used as a numerator while calculating the fee percentage.
We recommend renaming this variable to `feeNumerator` to avoid confusion.

```solidity
FeeUtils.sol
16:     function _calculateFees(uint256 amountA, uint256 amountB, uint8 feeType,  uint256 hops, uint256 feeValue, uint256 feeDenominator, uint256 fixedFee)
17:     internal pure returns (uint256) {
18:         if (feeType == Constants.FEE_TYPE_TOKEN_B) {
19:             return MathUtils._mulDiv(amountB, feeValue, feeDenominator) * hops;
20:         }
21:         if (feeType == Constants.FEE_TYPE_TOKEN_A) {
22:             return MathUtils._mulDiv(amountA, feeValue, feeDenominator) * hops;
23:         }
24:         if (feeType == Constants.FEE_TYPE_ETH_FIXED) {
25:             return fixedFee * hops;
26:         }
27:         revert Errors.UnknownFeeType(feeType);
28:     }
```

**Protocol:** Fixed in commit [f6154c9](https://github.com/SwapExchangeio/Contracts/commit/f6154c99edabe7b62d956935a94567c88ee89b3d).

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-swapexchange.md)

---

### Example 4: Functions not used internally could be marked external

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: LOW

**Details**:

**Severity:** Informational

**Description:** Using proper visibility modifiers is a good practice to prevent unintended access to functions.
Furthermore, marking functions as `external` instead of `public` can save gas.

```solidity
File: DepositVault.sol

37:     function deposit(uint256 amount, address tokenAddress) public payable

59:     function withdraw(uint256 amount, uint256 nonce, bytes memory signature, address payable recipient) public

81:     function withdrawDeposit(uint256 depositIndex) public
```

**Recommended Mitigation:** Consider change the visibility modifier to `external` for the functions that are not used internally.

**Client:**
Fixed.

**Cyfrin:** Verified in commit [b21d23e](https://github.com/HyperGood/woosh-contracts/commit/b21d23e661b0f25f0e757dc00ee90e4464730b1b).

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 5: Unnecessary parameter amount in withdraw function

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: LOW

**Details**:

**Severity:** Informational

**Description:** The function `withdraw()` has a parameter `amount` but we don't understand the necessity of this parameter.
At line L67, the amount is required to be the same to the whole deposit amount. This means the user does not have a flexibility to choose the withdraw amount, after all it means the parameter was not necessary at all.
```solidity
DepositVault.sol
59:     function withdraw(uint256 amount, uint256 nonce, bytes memory signature, address payable recipient) public {
60:         require(nonce < deposits.length, "Invalid deposit index");
61:         Deposit storage depositToWithdraw = deposits[nonce];
62:         bytes32 withdrawalHash = getWithdrawalHash(Withdrawal(amount, nonce));
63:         address signer = withdrawalHash.recover(signature);
64:         require(signer == depositToWithdraw.depositor, "Invalid signature");
65:         require(!usedWithdrawalHashes[withdrawalHash], "Withdrawal has already been executed");
66:         require(amount == depositToWithdraw.amount, "Withdrawal amount must match deposit amount");//@audit-info only full withdrawal is allowed
67:
68:         usedWithdrawalHashes[withdrawalHash] = true;
69:         depositToWithdraw.amount = 0;
70:
71:         if(depositToWithdraw.tokenAddress == address(0)){
72:             recipient.transfer(amount);
73:         } else {
74:             IERC20 token = IERC20(depositToWithdraw.tokenAddress);
75:             token.safeTransfer(recipient, amount);
76:      

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 6: Nonstandard usage of nonce

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

### Example 7: The deposit function is not following CEI pattern

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: LOW

**Details**:

**Severity:** Low

**Description:** The protocol implemented a function `deposit()` to allow users to deposit.
```solidity
DepositVault.sol
37:     function deposit(uint256 amount, address tokenAddress) public payable {
38:         require(amount > 0 || msg.value > 0, "Deposit amount must be greater than 0");
39:         if(msg.value > 0) {
40:             require(tokenAddress == address(0), "Token address must be 0x0 for ETH deposits");
41:             uint256 depositIndex = deposits.length;
42:             deposits.push(Deposit(payable(msg.sender), msg.value, tokenAddress));
43:             emit DepositMade(msg.sender, depositIndex, msg.value, tokenAddress);
44:         } else {
45:             require(tokenAddress != address(0), "Token address must not be 0x0 for token deposits");
46:             IERC20 token = IERC20(tokenAddress);
47:             token.safeTransferFrom(msg.sender, address(this), amount);//@audit-issue against CEI pattern
48:             uint256 depositIndex = deposits.length;
49:             deposits.push(Deposit(payable(msg.sender), amount, tokenAddress));
50:             emit DepositMade(msg.sender, depositIndex, amount, tokenAddress);
51:
52:         }
53:     }
```
Looking at the line L47, we can see that the token transfer happens before updating the accounting state of the protocol against the CEI pattern.
Because the protocol intends to support all ERC20 tokens, the tokens with hooks (e.g. ERC777) can be exploited for reentrancy.
Although we can n

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 8: Use modifier instead of repeating the same code block

**Source**: Hans
**Protocol**: Meta
**Impact**: LOW

**Details**:

**Severity:** Low

**Description:**

There are numerous places where the same code block is repeated. These can be replaced with a modifier.

- [IDO.sol#L92](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L92), [IDO.sol#L129](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L129), [IDO.sol#L134](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L134)

- [IDO.sol#L160](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L160), [IDO.sol#L173](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L173), [IDO.sol#L181](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L181)

- [ESMeta.sol#L35](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/meta/ESMeta.sol#L35), [ESMeta.sol#L50](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/meta/ESMeta.sol#L50)

**Meta Team:**

Fixed. Either refactored the code or used modifiers.

(commit : 007c1b9183cdb65a500928173608ebff0a5197ef)

**Hans:**
Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

### Example 9: Interface recommendations 

**Source**: Cantina
**Protocol**: Olas
**Impact**: LOW

**Details**:

## Context
(No context files were provided by the reviewer)

## Description/Recommendation
- **IMech.sol#L15-L21:** `maxDeliveryRate` and `paymentType` can be defined as `view`. This will guarantee that when those interface endpoints are used, `staticcall` is made instead of a regular call.
- **IStaking.sol:** `IStaking.sol` does not seem to be used and perhaps can be removed.

## Valory
Fixed on PR 94.

## Cantina Managed
Fix verified.

**Reference**: [View Original Finding](https://cdn.cantina.xyz/reports/cantina_valory_january2025.pdf)

---

### Example 10: [G-10] Missing events

**Source**: Code4rena
**Protocol**: Visor
**Impact**: GAS

**Details**:

_Submitted by cmichel_

The following events are not used:
- `IInstanceRegistry.InstanceRemoved`

Unused code can hint at programming or architectural errors.  Recommend using it or removing it.

**[xyz-ctrl (Visor) acknowledged but disputed severity](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/44#issuecomment-862607014):**

**[ghoul-sol (Judge) commented](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/44#issuecomment-873480513):**
> Agree with sponsor, it doesnt present a security issue its a non-critical issue.

**[ztcrypto (Visor) commented](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/44#issuecomment-889191547):**
> patch [link](https://github.com/VisorFinance/visor-core/commit/cc22d6e450e16aaa9eb3af1ee4d9e6ac8afe43da#diff-b094db7ce2f99cbcbde7ec178a6754bac666e2192f076807acbd70d49ddd0559)

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-05-visorfinance)

---

## Statistics

- Total findings analyzed: 10
- Examples shown: 10
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

