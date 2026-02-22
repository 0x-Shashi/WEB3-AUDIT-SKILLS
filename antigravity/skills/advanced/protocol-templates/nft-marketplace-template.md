# NFT Marketplace Audit Template

## Protocol Overview
NFT marketplaces facilitate buying, selling, and trading of non-fungible tokens through order matching, auctions, or direct sales with optional royalty enforcement.

## Architecture Checklist
- [ ] Order creation and validation secure
- [ ] Signature verification correct (EIP-712)
- [ ] Order matching logic handles all edge cases
- [ ] Royalty calculation and distribution correct
- [ ] Fee collection accurate
- [ ] Cancel/invalidation mechanisms work properly
- [ ] Multi-token standard support (ERC721, ERC1155)

## Critical Invariants
```
1. Ownership: seller must own token at execution time
2. Payment: buyer pays correct amount (price + fees + royalties)
3. Signatures: only valid, unexpired, uncancelled signatures execute
4. No Replay: each order executed at most once
5. Royalty: creator receives correct royalty percentage
```

## Attack Vectors

### Order/Signature Exploits
- [ ] Signature replay across chains (missing chainId)
- [ ] Signature replay across marketplaces (missing verifyingContract)
- [ ] Order parameter manipulation (change price after signing)
- [ ] Expired order execution
- [ ] Cancelled order execution (cancel front-running)
- [ ] Bulk cancel bypass

### Price Manipulation
- [ ] Dutch auction price calculation correct (start → end)
- [ ] English auction bid sniping prevention
- [ ] Collection offers — attacker chooses cheapest NFT
- [ ] Trait/attribute-based offers — validation correct

### Payment Exploits
- [ ] ETH/WETH unwrap reentrancy during payment distribution
- [ ] Fee-on-transfer tokens as payment
- [ ] Zero-price order creation
- [ ] Overpayment handling (refund logic)
- [ ] Royalty bypass through wrapper contracts

### NFT-Specific
- [ ] Approval management (approveForAll risks)
- [ ] Transfer hooks (onERC721Received reentrancy)
- [ ] Token ID manipulation
- [ ] Collection contract impersonation
- [ ] Metadata manipulation during listing

### Access Control
- [ ] Admin fee change without timelock
- [ ] Protocol fee extraction vulnerability
- [ ] Pause mechanism coverage
- [ ] Upgrade safety

## Critical Functions to Review Deep
| Function | Risk | Check |
|----------|------|-------|
| `fulfillOrder()` | All payment/ownership | Signature, ownership, amounts |
| `cancelOrder()` | Front-running | Timing, batch cancel |
| `bid()` / `offer()` | Value manipulation | Min bid increment, timing |
| `setRoyalty()` | Bypass | ERC2981 compliance |
| `withdraw()` | Fund extraction | Access control, accounting |

## Integration Risks
- Royalty registry compatibility (ERC2981)
- Seaport/Blur/other marketplace signature compatibility
- NFT collection contract trust (malicious onERC721Received)
- Oracle for floor price (if using floor price features)

## Economic Considerations
- Wash trading detection (self-trades for rewards)
- Royalty enforcement vs marketplace competition
- Gas optimization for bulk operations
- Listed NFT liquidity vs security tradeoffs
