# NFT and Gaming Protocol Audit Checklist

## 1. NFT Minting
- [ ] **CRITICAL** Maximum supply enforced (can't mint beyond cap)
- [ ] **CRITICAL** Mint price: correct amount charged, excess refunded
- [ ] **HIGH** Minting limits per wallet/transaction enforced
- [ ] **HIGH** Whitelist/allowlist: Merkle proof verification correct
- [ ] **HIGH** Mint phases: timing and access control correct
- [ ] **HIGH** Re-entrancy via ERC721 safeTransferFrom callback
- [ ] **MEDIUM** Free mint griefing: gas cost for attacker low
- [ ] **MEDIUM** Token ID assignment: sequential vs random, predictable?
- [ ] **LOW** Reveal mechanism: metadata not prematurely exposed

## 2. Metadata and Randomness
- [ ] **CRITICAL** Randomness: not using block.timestamp/blockhash for NFT traits
- [ ] **CRITICAL** Chainlink VRF or commit-reveal for fair distribution
- [ ] **HIGH** Metadata URI: immutable or controlled by admin only
- [ ] **HIGH** On-chain metadata: stored and computed correctly
- [ ] **MEDIUM** Provenance hash: committed before mint starts
- [ ] **MEDIUM** Metadata reveal: batch reveal prevents targeted sniping
- [ ] **LOW** IPFS pinning: metadata accessibility not dependent on centralized server

## 3. Marketplace and Trading
- [ ] **CRITICAL** Listing: only owner can list for sale
- [ ] **CRITICAL** Purchase: correct payment to seller and fees to marketplace
- [ ] **HIGH** Royalty enforcement: EIP-2981 implemented correctly
- [ ] **HIGH** Offer/bid system: escrow accounting correct
- [ ] **HIGH** Cancellation: listings and offers can be cancelled by creator
- [ ] **HIGH** Signature-based orders: replay protection (nonce, deadline)
- [ ] **MEDIUM** Auction: bid increments, time extensions, settlement correct
- [ ] **MEDIUM** Bundle sales: multiple NFTs in one transaction
- [ ] **LOW** Fee calculation: marketplace fee + royalty + seller payment = total

## 4. ERC-721 / ERC-1155 Compliance
- [ ] **HIGH** safeTransferFrom: calls onERC721Received/onERC1155Received
- [ ] **HIGH** Approval for all: setApprovalForAll scope and revocation
- [ ] **HIGH** Transfer hooks: don't break protocol state
- [ ] **MEDIUM** Batch transfers (ERC-1155): correct amounts and IDs
- [ ] **MEDIUM** URI functions: return correct metadata per token
- [ ] **LOW** supportsInterface: ERC-165 properly implemented

## 5. GameFi Mechanics
- [ ] **CRITICAL** In-game currency: can't be minted or duplicated by players
- [ ] **CRITICAL** Reward distribution: correct calculation per game action
- [ ] **HIGH** Game state: on-chain vs off-chain consistency
- [ ] **HIGH** Random outcomes: provably fair (VRF or commit-reveal)
- [ ] **HIGH** Item duplication: can't duplicate in-game items via transfers
- [ ] **MEDIUM** Cooldown periods: enforced for game actions
- [ ] **MEDIUM** Leaderboard manipulation: Sybil resistance
- [ ] **LOW** Energy/stamina system: refill rate correct

## 6. Staking NFTs (Play-to-Earn)
- [ ] **CRITICAL** Staked NFT: ownership correctly tracked during staking
- [ ] **CRITICAL** Staking rewards: proportional and not manipulable
- [ ] **HIGH** Unstaking: NFT returned to correct owner
- [ ] **HIGH** Reward token: emission rate sustainable
- [ ] **MEDIUM** NFT level/rarity: correct reward multiplier
- [ ] **MEDIUM** Staking multiple NFTs: combined rewards correct
- [ ] **LOW** Compound staking: re-staking rewards works correctly

## 7. Upgradeable NFTs and Dynamic Metadata
- [ ] **HIGH** Attribute changes: only through authorized game logic
- [ ] **HIGH** Evolution/breeding: resource costs enforced
- [ ] **HIGH** Attribute overflow: levels/stats bounded correctly
- [ ] **MEDIUM** Metadata update: event emitted (EIP-4906)
- [ ] **MEDIUM** History: attribute changes trackable
- [ ] **LOW** Rendering: on-chain SVG generation safe from injection

## 8. Access Control and Admin
- [ ] **HIGH** Admin mint: separate from public mint
- [ ] **HIGH** Withdraw: only admin can withdraw contract balance
- [ ] **HIGH** Base URI: admin-only modification
- [ ] **MEDIUM** Pause: minting/trading can be paused in emergency
- [ ] **MEDIUM** Burn: only owner or approved can burn
- [ ] **LOW** Transfer restriction: soulbound (non-transferable) if intended
