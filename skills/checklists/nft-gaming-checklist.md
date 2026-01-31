---
id: CHECKLIST-NFT-GAMING
title: NFT & Gaming Protocol Audit Checklist
category: checklists
difficulty: intermediate
tags: [nft, gaming, erc721, erc1155, randomness, marketplace]
last_updated: 2026-01-31
---

# NFT & Gaming Protocol Audit Checklist

Quick-reference checklist for auditing NFT collections, marketplaces, and blockchain games.

---

## 🔴 Critical Checks

### Randomness & Fairness
```
[ ] Is randomness source secure? (NOT blockhash, block.timestamp)
[ ] Chainlink VRF or commit-reveal used?
[ ] Can miners/validators manipulate outcomes?
[ ] Is randomness request and fulfillment separated?
[ ] Can users predict or influence random results?
[ ] Is there a delay between request and reveal?
```

### Minting Security
```
[ ] Can users mint more than allowed?
[ ] Is max supply enforced?
[ ] Can minting be front-run for rare items?
[ ] Are minting phases (whitelist, public) secure?
[ ] Can same wallet claim multiple times?
[ ] Is signature verification correct for whitelists?
```

### Ownership & Transfers
```
[ ] Can NFTs be stolen via approval bugs?
[ ] Are safe transfer hooks handled?
[ ] Can locked/staked NFTs be transferred?
[ ] Is ownership tracked correctly on transfers?
[ ] ERC721: tokenOfOwnerByIndex gas issues?
```

---

## 🟠 High Priority Checks

### Marketplace Security
```
[ ] Can listings be bought at old (lower) price?
[ ] Can seller front-run buyer to raise price?
[ ] Is signature replay prevented?
[ ] Are cancelled orders truly cancelled?
[ ] Can orders be filled partially more than once?
[ ] Royalty enforcement correct?
```

### In-Game Assets
```
[ ] Can items be duplicated?
[ ] Can items be stolen from inventory?
[ ] Are item attributes immutable or mutable?
[ ] Can game state be manipulated?
[ ] Are rewards correctly distributed?
```

### Staking/Locking
```
[ ] Can staked NFTs be transferred?
[ ] Are rewards calculated correctly?
[ ] Can rewards be claimed multiple times?
[ ] Is unstaking cooldown enforced?
[ ] Can contract be drained of rewards?
```

---

## 🟡 Medium Priority Checks

### Metadata & URI
```
[ ] Is tokenURI correctly formatted?
[ ] Can metadata be changed after mint?
[ ] Base URI updatable by admin?
[ ] IPFS vs centralized hosting risks?
[ ] Are on-chain attributes accurate?
```

### Royalties
```
[ ] ERC-2981 implemented correctly?
[ ] Are royalties enforced or just suggested?
[ ] Can royalties be bypassed?
[ ] Royalty recipient updatable?
[ ] Maximum royalty percentage capped?
```

### Access Control
```
[ ] Who can mint new tokens?
[ ] Who can burn tokens?
[ ] Who can update metadata?
[ ] Who can pause transfers?
[ ] Admin key security?
```

---

## 🟢 Standard Checks

### ERC-721 Compliance
```
[ ] All required functions implemented?
[ ] Correct event emissions?
[ ] safeTransferFrom checks for receiver?
[ ] Approval/ApprovalForAll correct?
[ ] tokenURI returns valid JSON?
```

### ERC-1155 Compliance
```
[ ] Batch operations work correctly?
[ ] Balance tracking accurate for fungible/non-fungible?
[ ] URI substitution pattern correct?
[ ] Safe transfer callbacks implemented?
```

### Gas Optimization
```
[ ] Enumerable extensions gas-efficient?
[ ] Batch minting available?
[ ] Storage layout optimized?
[ ] Mappings vs arrays appropriate?
```

---

## Common Vulnerability Patterns

### 1. Predictable Randomness
```solidity
// VULNERABLE: Block-based randomness
function mint() external {
    uint256 random = uint256(keccak256(abi.encodePacked(
        block.timestamp,
        block.difficulty,
        msg.sender
    )));
    uint256 rarity = random % 100; // Miner can manipulate!
}

// SECURE: Chainlink VRF
function mint() external {
    requestId = VRF_COORDINATOR.requestRandomWords(...);
}

function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal {
    uint256 rarity = randomWords[0] % 100;
}
```

### 2. Whitelist Signature Replay
```solidity
// VULNERABLE: No nonce
function whitelistMint(bytes memory signature) {
    require(verify(msg.sender, signature), "Invalid");
    _mint(msg.sender, tokenId);
    // Can call again with same signature!
}

// SECURE: Track used signatures
mapping(bytes => bool) public usedSignatures;

function whitelistMint(bytes memory signature) {
    require(!usedSignatures[signature], "Used");
    require(verify(msg.sender, signature), "Invalid");
    usedSignatures[signature] = true;
    _mint(msg.sender, tokenId);
}
```

### 3. Reentrancy via onERC721Received
```solidity
// VULNERABLE: State update after transfer
function claimReward() external {
    uint256 reward = calculateReward(msg.sender);
    nft.safeTransferFrom(address(this), msg.sender, tokenId);
    // Attacker's onERC721Received can reenter here!
    claimed[msg.sender] = true;
}

// SECURE: CEI pattern
function claimReward() external nonReentrant {
    uint256 reward = calculateReward(msg.sender);
    claimed[msg.sender] = true;
    nft.safeTransferFrom(address(this), msg.sender, tokenId);
}
```

### 4. Marketplace Order Manipulation
```solidity
// VULNERABLE: Order can be filled after price change
struct Order {
    address seller;
    uint256 price;
    uint256 tokenId;
}

function buy(bytes32 orderId) external payable {
    Order memory order = orders[orderId];
    require(msg.value >= order.price, "Underpaid");
    // But seller might have updated price!
}

// SECURE: Include all params in signature
function buy(
    address seller,
    uint256 tokenId,
    uint256 price,
    uint256 deadline,
    bytes memory signature
) external payable {
    require(block.timestamp <= deadline, "Expired");
    require(verifyOrder(seller, tokenId, price, deadline, signature));
}
```

---

## Game-Specific Checks

### Play-to-Earn
```
[ ] Can rewards be exploited via bots?
[ ] Is anti-cheat mechanism on-chain or off-chain?
[ ] Can game economy be inflated?
[ ] Are reward rates sustainable?
[ ] Multi-accounting prevention?
```

### Loot Boxes / Gacha
```
[ ] Are odds publicly verifiable?
[ ] Is randomness fair and unpredictable?
[ ] Regulatory compliance (gambling laws)?
[ ] Can odds be changed after purchase?
```

### Battle/PvP Systems
```
[ ] Can battle outcomes be predicted?
[ ] Is matchmaking manipulatable?
[ ] Can battles be simulated off-chain?
[ ] Are combat stats immutable during battle?
```

### Breeding/Combining
```
[ ] Can traits be predicted before breeding?
[ ] Is breeding fee collected correctly?
[ ] Cooldown periods enforced?
[ ] Can rare traits be guaranteed?
```

---

## Integration Points

### OpenSea / Seaport
```
[ ] Zone validation correct?
[ ] Conduit approvals secure?
[ ] Order type handling complete?
[ ] Partial fills handled?
```

### Operator Filter Registry
```
[ ] Blocklist/allowlist enforced?
[ ] Can bypasses circumvent royalties?
[ ] Is registry updatable?
```

### Lending/Renting NFTs
```
[ ] Can rented NFT be sold?
[ ] Rental period enforced?
[ ] Collateral handling secure?
[ ] Revenue sharing correct?
```

---

## Quick Reference

### Common Token Standards
```
ERC-721: Non-fungible (1 of 1)
ERC-1155: Semi-fungible (can be 1 of 1 or 1 of many)
ERC-2981: Royalty Standard
ERC-4907: Rentable NFTs
ERC-6551: Token Bound Accounts
```

### Metadata JSON Structure
```json
{
    "name": "Token #1",
    "description": "Description",
    "image": "ipfs://...",
    "attributes": [
        {"trait_type": "Rarity", "value": "Legendary"}
    ]
}
```

---

## Red Flags 🚩

- [ ] Uses block.timestamp/blockhash for randomness
- [ ] Whitelist without nonce/expiry
- [ ] No reentrancy protection on transfers
- [ ] Unlimited minting by owner
- [ ] Centralized metadata that can be changed
- [ ] No royalty enforcement mechanism
- [ ] Game rewards exploitable by scripts
- [ ] Marketplace orders don't expire
- [ ] Approval for all tokens to unknown contracts
