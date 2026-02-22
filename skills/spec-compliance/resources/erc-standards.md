---
id: SPEC-ERC-STD
title: ERC Standards Reference
parent: spec-compliance
type: resource
last_updated: 2025-01-31
---

# ERC Standards Reference

Detailed compliance requirements, common violations, and security implications for major ERC standards.

---

## ERC-20 (Fungible Token)

### Required Interface

| Function | Returns | Must Comply |
|----------|---------|-------------|
| `totalSupply()` | `uint256` | Must return current total supply |
| `balanceOf(address)` | `uint256` | Must return balance of address |
| `transfer(address, uint256)` | `bool` | Must return `true` on success |
| `approve(address, uint256)` | `bool` | Must return `true` on success |
| `allowance(address, address)` | `uint256` | Must return current allowance |
| `transferFrom(address, address, uint256)` | `bool` | Must return `true` on success |

### Required Events

| Event | When |
|-------|------|
| `Transfer(from, to, value)` | On every transfer, including mint (from=0) and burn (to=0) |
| `Approval(owner, spender, value)` | On every `approve()` call |

### Common ERC-20 Violations

| Violation | Impact | Notable Token |
|-----------|--------|---------------|
| Missing `bool` return on `transfer` | Breaks integrations using `IERC20` interface | USDT (returns void) |
| Approve race condition | Front-running approve allows double-spend | All standard ERC20 |
| Fee-on-transfer | Receiver gets less than `amount` | STA, PAXG, USDT (sometimes) |
| Rebasing balance | `balanceOf` changes without transfer events | stETH, AMPL |
| Blacklist/pause | Transfer reverts for certain addresses | USDC, USDT |
| Max supply not enforced | `totalSupply()` can exceed expected maximum | Various |
| Decimals != 18 | Math errors if assuming 18 decimals | USDC (6), WBTC (8) |
| `transfer` returns `false` instead of reverting | Caller must check return value | Some tokens |

### ERC-20 Compliance Checklist

- [ ] `transfer` returns `bool` (true on success)
- [ ] `transferFrom` returns `bool` and decrements allowance
- [ ] `approve` returns `bool` and emits `Approval` event
- [ ] `Transfer` event emitted on every balance change (including mint/burn)
- [ ] `balanceOf` returns correct balance after every operation
- [ ] `totalSupply` equals sum of all `balanceOf` values
- [ ] Zero-amount transfer succeeds (per standard)
- [ ] Self-transfer works correctly (`transfer(msg.sender, amount)`)

---

## ERC-721 (Non-Fungible Token)

### Required Interface

| Function | Returns | Must Comply |
|----------|---------|-------------|
| `balanceOf(address)` | `uint256` | Must revert for address(0) |
| `ownerOf(uint256)` | `address` | Must revert for non-existent token |
| `safeTransferFrom(from, to, tokenId)` | void | Must call `onERC721Received` on recipient |
| `safeTransferFrom(from, to, tokenId, data)` | void | Must call `onERC721Received` with data |
| `transferFrom(from, to, tokenId)` | void | No receiver callback |
| `approve(address, uint256)` | void | Only owner or approved-for-all can call |
| `getApproved(uint256)` | `address` | Must revert for non-existent token |
| `setApprovalForAll(address, bool)` | void | Operator approval |
| `isApprovedForAll(address, address)` | `bool` | Check operator approval |

### Must Implement

- `IERC165` — `supportsInterface(interfaceId)` returns `true` for `0x80ac58cd` (ERC721)

### Key Compliance Rule: `safeTransferFrom`

```solidity
// MUST check if recipient is a contract and call onERC721Received
function safeTransferFrom(address from, address to, uint256 tokenId) public {
    transferFrom(from, to, tokenId);
    if (to.code.length > 0) {
        // MUST call this and verify return value
        require(
            IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, "")
            == IERC721Receiver.onERC721Received.selector,
            "unsafe recipient"
        );
    }
}
```

### Common ERC-721 Violations

| Violation | Impact |
|-----------|--------|
| Missing `onERC721Received` callback | NFTs sent to contracts are permanently locked |
| `ownerOf` doesn't revert for burned tokens | Returns address(0), misleading |
| `balanceOf(address(0))` doesn't revert | Per spec, must revert |
| Missing `ERC165` support | Wallets/marketplaces can't detect NFT interface |
| Enumerable not consistent after burn | `tokenByIndex` returns wrong token |

---

## ERC-1155 (Multi-Token)

### Required Interface

| Function | Key Requirement |
|----------|----------------|
| `safeTransferFrom(from, to, id, amount, data)` | Must call `onERC1155Received` on recipient |
| `safeBatchTransferFrom(from, to, ids, amounts, data)` | Must call `onERC1155BatchReceived` |
| `balanceOf(address, uint256)` | Balance of specific token ID |
| `balanceOfBatch(address[], uint256[])` | Batch query |
| `setApprovalForAll(address, bool)` | Operator approval |
| `isApprovedForAll(address, address)` | Check operator |

### Key Rule

Batch operations MUST be atomic — if any single transfer in a batch fails, the entire batch must revert.

### Common Violations

- Missing receiver callbacks (`onERC1155Received` / `onERC1155BatchReceived`)
- Non-atomic batch operations
- Array length mismatch not checked in `balanceOfBatch`
- Missing `TransferSingle` / `TransferBatch` events

---

## ERC-4626 (Tokenized Vault)

### Required Interface

| Function | Key Requirement |
|----------|----------------|
| `asset()` | Returns underlying asset address |
| `totalAssets()` | Total assets managed by vault |
| `convertToShares(assets)` | Round DOWN |
| `convertToAssets(shares)` | Round DOWN |
| `maxDeposit(receiver)` | Max assets that can be deposited |
| `maxMint(receiver)` | Max shares that can be minted |
| `maxWithdraw(owner)` | Max assets that can be withdrawn |
| `maxRedeem(owner)` | Max shares that can be redeemed |
| `previewDeposit(assets)` | Round DOWN (less favorable to user) |
| `previewMint(shares)` | Round UP (less favorable to user) |
| `previewWithdraw(assets)` | Round UP (less favorable to user) |
| `previewRedeem(shares)` | Round DOWN (less favorable to user) |
| `deposit(assets, receiver)` | Deposit assets, receive shares |
| `mint(shares, receiver)` | Mint shares, pay assets |
| `withdraw(assets, receiver, owner)` | Withdraw assets, burn shares |
| `redeem(shares, receiver, owner)` | Redeem shares, receive assets |

### CRITICAL: Rounding Direction

The ERC-4626 spec mandates specific rounding directions to protect the vault (not the user):

| Function | Rounding | Reason |
|----------|----------|--------|
| `convertToShares` | DOWN | Users get fewer shares |
| `convertToAssets` | DOWN | Users get fewer assets |
| `previewDeposit` | DOWN | Users get fewer shares for their deposit |
| `previewMint` | UP | Users pay more assets per share |
| `previewWithdraw` | UP | Users burn more shares per asset |
| `previewRedeem` | DOWN | Users get fewer assets per share |

### First Depositor Inflation Attack

The most critical ERC-4626 vulnerability:

1. Attacker deposits 1 wei → gets 1 share
2. Attacker donates large amount directly to vault
3. Victim deposits → gets 0 shares (rounds down to 0)
4. Attacker redeems 1 share → gets everything

**Mitigation:** Virtual offset (`_decimalsOffset()`), dead shares, or minimum deposit.

---

## EIP-2612 (Permit)

### Required Interface

```solidity
function permit(
    address owner,
    address spender,
    uint256 value,
    uint256 deadline,
    uint8 v, bytes32 r, bytes32 s
) external;

function nonces(address owner) external view returns (uint256);
function DOMAIN_SEPARATOR() external view returns (bytes32);
```

### Security Risks

| Risk | Description |
|------|-------------|
| Signature replay | Nonce must increment, chainId must be in domain |
| Front-running permit + transferFrom | Attacker uses permit sig before legitimate use |
| Unlimited approval via permit | `value = type(uint256).max` is common but risky |
| Missing deadline check | Expired permits should revert |

---

## EIP-2981 (Royalty Info)

```solidity
function royaltyInfo(uint256 tokenId, uint256 salePrice)
    external view returns (address receiver, uint256 royaltyAmount);
```

**Important:** EIP-2981 is **informational** — it tells marketplaces what royalty to pay but cannot enforce it on-chain. Marketplaces choose whether to honor it.
