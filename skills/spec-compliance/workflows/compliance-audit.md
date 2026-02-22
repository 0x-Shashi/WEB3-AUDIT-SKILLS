---
id: SPEC-WF-COMPLIANCE
title: Compliance Audit Workflow
parent: spec-compliance
type: workflow
last_updated: 2025-01-31
---

# Compliance Audit Workflow

9-step workflow for verifying smart contract compliance with EIP/ERC standards.

---

## Step 1: Identify Standards

List all EIPs/ERCs the protocol claims compliance with:

| Source | Where to Look |
|--------|---------------|
| Contract comments | `@dev Implements ERC-20` |
| Import statements | `import IERC20.sol`, `import ERC4626.sol` |
| Natspec | `@notice ERC-721 compliant` |
| Documentation | README, whitepaper, spec documents |
| `supportsInterface()` | ERC-165 interface support declarations |

Create a compliance matrix:

```
| Standard | Claimed? | Contract | Status |
|----------|----------|----------|--------|
| ERC-20 | Yes | Token.sol | [ ] |
| ERC-4626 | Yes | Vault.sol | [ ] |
| EIP-2612 | Yes | Token.sol | [ ] |
| EIP-712 | Implicit | Token.sol | [ ] |
```

---

## Step 2: Interface Completeness Check

For each claimed standard, verify ALL required functions exist with correct signatures:

```solidity
// Method: Compare contract's ABI against standard interface
// Tool: forge inspect Contract abi | jq '.[] | .name'

// Or manually check each required function:
// ERC-20 requires exactly these 6 functions:
// totalSupply(), balanceOf(address), transfer(address,uint256),
// approve(address,uint256), allowance(address,address), transferFrom(address,address,uint256)
```

### Checklist per Standard

- [ ] All required function signatures present
- [ ] All required events declared
- [ ] Return types match specification
- [ ] Parameter types match specification
- [ ] `supportsInterface()` returns `true` for standard's interfaceId (if ERC-165 applicable)

---

## Step 3: Behavioral Compliance

Verify each function behaves per specification (not just exists):

### ERC-20 Behavioral Checks

| Function | Spec Requirement | Test |
|----------|-----------------|------|
| `transfer(to, 0)` | SHOULD succeed | `assertEq(token.transfer(addr, 0), true)` |
| `transfer(to, amount > balance)` | SHOULD revert | `vm.expectRevert()` |
| `transferFrom` | MUST decrease allowance | Check `allowance` before/after |
| `transferFrom` | `type(uint256).max` allowance | Some impls don't decrease infinite allowance |
| `approve(spender, 0)` | MUST succeed | Reset allowance to 0 |
| `transfer` to self | SHOULD succeed | `token.transfer(msg.sender, amount)` |

### ERC-4626 Behavioral Checks

| Function | Spec Requirement | Test |
|----------|-----------------|------|
| `previewDeposit` | MUST return <= actual shares received | Compare preview vs actual |
| `previewMint` | MUST return >= actual assets required | Compare preview vs actual |
| `previewWithdraw` | MUST return >= actual shares burned | Compare preview vs actual |
| `previewRedeem` | MUST return <= actual assets received | Compare preview vs actual |
| `maxDeposit` | MUST return 0 if deposits disabled | Check when paused |
| Rounding | deposit/previewDeposit: DOWN, mint/previewMint: UP | Verify with odd numbers |

---

## Step 4: Event Compliance

Verify correct events emitted at correct times:

| Standard | Event | When |
|----------|-------|------|
| ERC-20 | `Transfer(from, to, value)` | Every balance change (transfer, mint, burn) |
| ERC-20 | `Approval(owner, spender, value)` | Every `approve()` call |
| ERC-721 | `Transfer(from, to, tokenId)` | Mint, transfer, burn |
| ERC-721 | `Approval(owner, approved, tokenId)` | Token-level approval |
| ERC-721 | `ApprovalForAll(owner, operator, approved)` | Operator approval change |
| ERC-1155 | `TransferSingle` or `TransferBatch` | Every transfer |
| ERC-4626 | `Deposit(sender, owner, assets, shares)` | deposit() and mint() |
| ERC-4626 | `Withdraw(sender, receiver, owner, assets, shares)` | withdraw() and redeem() |

Use Foundry's `vm.expectEmit` to verify:

```solidity
function test_transfer_emits_event() public {
    vm.expectEmit(true, true, false, true);
    emit Transfer(alice, bob, 100);
    vm.prank(alice);
    token.transfer(bob, 100);
}
```

---

## Step 5: Edge Case Testing

| Edge Case | What to Test |
|-----------|-------------|
| Zero amount | `transfer(to, 0)`, `deposit(0, receiver)` |
| Max amount | `transfer(to, type(uint256).max)` |
| Self operations | `transfer(msg.sender, amount)`, `approve(msg.sender, amount)` |
| address(0) | `transfer(address(0), amount)` should revert (most standards) |
| Non-existent token | `ownerOf(nonExistentId)` should revert (ERC-721) |
| Empty batch | `safeBatchTransferFrom([], [])` (ERC-1155) |
| First deposit | ERC-4626 with 0 totalSupply |
| Re-entrancy | `safeTransferFrom` with malicious `onERC721Received` callback |

---

## Step 6: Return Value Compliance

| Function | Expected Return | Common Violation |
|----------|----------------|------------------|
| ERC-20 `transfer` | `bool` (true) | Returns void (USDT) |
| ERC-20 `approve` | `bool` (true) | Returns void |
| ERC-20 `transferFrom` | `bool` (true) | Returns void |
| ERC-721 `supportsInterface` | `bool` | Missing ERC-165 |
| ERC-4626 `deposit` | `uint256` (shares) | Wrong share calculation |

**Note:** Non-standard return values (e.g., USDT returning void) are extremely common and must be handled with `SafeERC20.safeTransfer()` by integrating contracts.

---

## Step 7: Revert Conditions

| Standard | When Must Revert |
|----------|------------------|
| ERC-20 | Transfer with insufficient balance |
| ERC-20 | TransferFrom with insufficient allowance |
| ERC-721 | Transfer of non-existent token |
| ERC-721 | Transfer by non-owner/non-approved |
| ERC-721 | `safeTransferFrom` to contract that rejects |
| ERC-1155 | Batch with mismatched array lengths |
| ERC-4626 | Deposit exceeding `maxDeposit` |
| ERC-4626 | Withdraw exceeding `maxWithdraw` |

---

## Step 8: Extension Safety

If the contract extends a standard with custom functionality:

- [ ] Extensions don't break base standard behavior
- [ ] Custom functions don't collide with standard function selectors
- [ ] Added state doesn't interfere with standard state (storage layout)
- [ ] Custom events don't shadow standard events
- [ ] Hooks (e.g., `_beforeTokenTransfer`) don't break standard invariants

---

## Step 9: Report

### Compliance Report Format

```markdown
## [Standard] Compliance Report

### Interface Completeness: [PASS / FAIL]
| Function | Present | Correct Signature |
|----------|---------|-----------|
| transfer | ✔ | ✔ |
| approve | ✔ | ✔ |

### Behavioral Compliance: [PASS / PARTIAL / FAIL]
| Behavior | Expected | Actual | Status |
|----------|----------|--------|--------|
| Zero transfer | Succeeds | Succeeds | ✔ |
| Return values | bool | bool | ✔ |
| Rounding (4626) | DOWN for deposit | DOWN | ✔ |

### Event Compliance: [PASS / FAIL]
| Event | Emitted Correctly |
|-------|---------|
| Transfer | ✔ |
| Approval | ✔ |

### Edge Cases: [PASS / PARTIAL / FAIL]
[Details of any edge case failures]

### Deviations from Standard
[List any intentional or unintentional deviations]
```
