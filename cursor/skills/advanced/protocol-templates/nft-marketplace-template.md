# NFT Marketplace Protocol Template

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                   NFT MARKETPLACE                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌───────────────┐                       ┌───────────────┐      │
│  │   SELLERS     │──── List ───────────▶│  MARKETPLACE  │      │
│  │               │◀─── Payment ─────────│  CONTRACT     │      │
│  └───────────────┘                       └───────┬───────┘      │
│                                                  │               │
│  ┌───────────────┐                               │               │
│  │   BUYERS      │──── Bid/Buy ──────────────────│               │
│  │               │◀─── NFT ──────────────────────│               │
│  └───────────────┘                               │               │
│                                                  │               │
│  ┌───────────────┐                       ┌───────┴───────┐      │
│  │   CREATORS    │◀──────────────────────│   ROYALTY     │      │
│  │               │      Royalties        │   ENGINE      │      │
│  └───────────────┘                       └───────────────┘      │
│                                                  │               │
│                                          ┌───────┴───────┐      │
│                                          │   ESCROW/     │      │
│                                          │   CUSTODY     │      │
│                                          └───────────────┘      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Marketplace Types

### Order Book
- Off-chain order matching
- On-chain settlement
- Examples: OpenSea Seaport

### Automated (AMM-style)
- On-chain pricing curves
- Instant liquidity
- Examples: Sudoswap

### Auction
- English (ascending)
- Dutch (descending)
- Reserve auctions

### Peer-to-Peer
- Direct swaps
- OTC deals
- Escrow services

---

## Critical Functions

### 1. List NFT

```solidity
function list(
    address collection,
    uint256 tokenId,
    uint256 price,
    uint256 expiration
) external {
    // Verify ownership
    // Verify approval
    // Store listing
}
```

**Audit Points:**
- [ ] Ownership verified
- [ ] Approval verified
- [ ] Price validation
- [ ] Expiration handling

### 2. Buy NFT

```solidity
function buy(
    address collection,
    uint256 tokenId
) external payable {
    // Verify listing exists
    // Transfer payment
    // Transfer NFT
    // Pay royalties
    // Pay platform fee
}
```

**Audit Points:**
- [ ] Listing still valid
- [ ] Correct payment amount
- [ ] NFT transferred
- [ ] Royalties paid correctly
- [ ] Fees calculated correctly

### 3. Make Offer/Bid

```solidity
function bid(
    address collection,
    uint256 tokenId,
    uint256 amount
) external {
    // Lock bid amount
    // Store bid
    // Handle previous bid
}
```

**Audit Points:**
- [ ] Bid amount locked
- [ ] Previous bid refunded
- [ ] Bid can be cancelled
- [ ] Expiration handling

### 4. Accept Offer

```solidity
function acceptOffer(
    address collection,
    uint256 tokenId,
    address bidder
) external {
    // Verify seller owns NFT
    // Transfer NFT to bidder
    // Release payment to seller
}
```

**Audit Points:**
- [ ] Offer still valid
- [ ] Seller still owns NFT
- [ ] Correct payment released
- [ ] Royalties handled

### 5. Auction

```solidity
function createAuction(
    address collection,
    uint256 tokenId,
    uint256 startingBid,
    uint256 duration
) external {
    // Transfer NFT to escrow
    // Store auction params
    // Start timer
}
```

**Audit Points:**
- [ ] NFT in escrow
- [ ] Reserve price honored
- [ ] Bid increments
- [ ] Extension mechanism
- [ ] Settlement correct

---

## Common Vulnerabilities

### NFT-01: Signature Replay

**Risk:** Critical

**Description:** Off-chain signatures can be reused.

**Vulnerable Pattern:**
```solidity
function executeOrder(Order memory order, bytes memory sig) {
    require(verify(sig, order), "Invalid sig");
    // No nonce!
    // Order can be replayed!
    _execute(order);
}
```

**Attack:**
1. Seller signs order to sell NFT at 1 ETH
2. Buyer executes, gets NFT
3. Seller buys NFT back
4. Attacker replays original signature
5. NFT sold again at 1 ETH (maybe worth more now)

**Mitigation:**
```solidity
mapping(address => uint256) public nonces;

function executeOrder(Order memory order, bytes memory sig) {
    require(order.nonce == nonces[order.seller]++, "Invalid nonce");
    require(verify(sig, order), "Invalid sig");
    _execute(order);
}
```

---

### NFT-02: Royalty Bypass

**Risk:** Medium

**Description:** Royalties not enforced or can be bypassed.

**Bypass Methods:**
1. Wrap NFT in contract, transfer contract
2. Use marketplace without royalties
3. Private sales (direct transfer)
4. Wash trading between own wallets

**Vulnerable Pattern:**
```solidity
function buy() {
    seller.transfer(price);  // No royalty!
    nft.transferFrom(seller, buyer, tokenId);
}
```

**Mitigation:**
```solidity
function buy() {
    (address receiver, uint256 royalty) = nft.royaltyInfo(tokenId, price);
    if (royalty > 0) {
        payable(receiver).transfer(royalty);
    }
    seller.transfer(price - royalty - platformFee);
    nft.transferFrom(seller, buyer, tokenId);
}
```

---

### NFT-03: Front-Running Purchases

**Risk:** High

**Description:** Attacker front-runs purchase to buy first.

**Scenario:**
1. Rare NFT listed at floor price
2. User submits buy transaction
3. Bot sees in mempool, front-runs
4. Bot buys, relists at higher price

**Mitigation:**
- Private mempools (Flashbots)
- Commit-reveal scheme
- Priority for early viewers

---

### NFT-04: Stale Listing Exploitation

**Risk:** High

**Description:** Old listings at outdated prices get executed.

**Scenario:**
1. User lists NFT at 0.1 ETH
2. Collection moons to 10 ETH floor
3. User forgets to cancel listing
4. Bot buys at 0.1 ETH

**Mitigation:**
- Short expiration defaults
- Easy bulk cancel
- Price floor alerts
- Cancel on transfer

---

### NFT-05: Bid Griefing

**Risk:** Medium

**Description:** Fake bids that can't be fulfilled.

**Attack:**
1. Place high bid with contract that reverts on NFT receive
2. Seller accepts, transaction reverts
3. Seller can't sell to anyone

**Mitigation:**
```solidity
// Pull pattern for bid refunds
function claimRefund() external {
    uint256 amount = pendingRefunds[msg.sender];
    pendingRefunds[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}
```

---

### NFT-06: Auction Sniping

**Risk:** Medium

**Description:** Last-second bids without counter opportunity.

**Scenario:**
1. Auction ending in 10 seconds
2. Sniper bids just before end
3. Previous bidder can't respond
4. Sniper wins at minimal increment

**Mitigation:**
```solidity
function bid(uint256 auctionId) external payable {
    if (auctions[auctionId].endTime - block.timestamp < EXTENSION_WINDOW) {
        auctions[auctionId].endTime += EXTENSION_DURATION;
    }
    // Process bid...
}
```

---

### NFT-07: Flash Loan NFT Attacks

**Risk:** High (if NFT lending exists)

**Description:** Flash borrow NFT to exploit holding requirements.

**Scenario:**
1. Flash borrow blue-chip NFT
2. Mint tokens that require NFT ownership
3. Return NFT
4. Keep minted tokens

**Mitigation:**
- Snapshot ownership at block N-1
- No flash loan capability for sensitive NFTs

---

### NFT-08: Collection Spoofing

**Risk:** High

**Description:** Fake collection mimics legitimate one.

**Attack:**
1. Deploy contract with same name/symbol
2. Mint NFTs with same metadata
3. List on marketplace
4. Users buy thinking it's real

**Mitigation:**
- Verified collections
- Contract address verification
- Creator verification

---

### NFT-09: Metadata Mutability

**Risk:** Medium

**Description:** NFT metadata changed after sale.

**Scenario:**
1. Buy NFT with rare trait
2. Creator changes metadata
3. NFT now has common trait
4. Value destroyed

**Mitigation:**
- Immutable on-chain metadata
- IPFS pinning
- Metadata hash in token

---

### NFT-10: ERC721/1155 Callback Reentrancy

**Risk:** High

**Description:** onERC721Received/onERC1155Received callbacks allow reentrancy.

**Vulnerable Pattern:**
```solidity
function buy(uint256 tokenId) {
    nft.safeTransferFrom(seller, msg.sender, tokenId);  // Callback here!
    listings[tokenId].active = false;  // State update after transfer
}
```

**Attack:**
1. Buy NFT
2. In onERC721Received, buy again
3. Double purchase from same listing

**Mitigation:**
```solidity
function buy(uint256 tokenId) {
    listings[tokenId].active = false;  // State first!
    nft.safeTransferFrom(seller, msg.sender, tokenId);
}
```

---

## Real Exploit Examples

| Protocol | Date | Loss | Vulnerability |
|----------|------|------|---------------|
| OpenSea | Jan 2022 | $1.7M | Stale listings |
| Quixotic | May 2022 | $100K | Signature replay |
| Various | Ongoing | Variable | Royalty bypass |

---

## NFT Marketplace Audit Checklist

### Listings
- [ ] Ownership verified on list
- [ ] Approval verified
- [ ] Expiration enforced
- [ ] Cancel working
- [ ] Price validation

### Purchases
- [ ] Listing still valid
- [ ] Payment amount correct
- [ ] NFT actually transferred
- [ ] Seller actually paid
- [ ] Reentrancy protected

### Bids/Offers
- [ ] Funds locked
- [ ] Expiration enforced
- [ ] Cancel returns funds
- [ ] Accept verifies ownership
- [ ] No griefing possible

### Auctions
- [ ] Reserve price honored
- [ ] Extension mechanism
- [ ] Settlement correct
- [ ] Failed auction returns NFT
- [ ] Bid increments

### Royalties
- [ ] EIP-2981 supported
- [ ] Royalty limits (max %)
- [ ] Creator verification
- [ ] Payment to correct address

### Signatures
- [ ] Nonce included
- [ ] Chain ID included
- [ ] Expiration included
- [ ] EIP-712 format
- [ ] No replay possible

### Access Control
- [ ] Admin functions protected
- [ ] Fee changes timelock
- [ ] Emergency pause

---

## Protocol-Specific Patterns

### OpenSea Seaport
- Zone system for validation
- Conduit for approvals
- Partial fills possible

### LooksRare/X2Y2
- Staking for fee sharing
- Aggregated orders
- Private sales

### Sudoswap
- AMM-style bonding curves
- Pool-based liquidity
- Different curve types

### Blur
- Pool-based bidding
- Aggregated listings
- Points system

---

## Detection Commands

```bash
# Find listing functions
grep -rn "function list\|function createListing" --include="*.sol"

# Find purchase functions
grep -rn "function buy\|function purchase\|function fulfillOrder" --include="*.sol"

# Find royalty handling
grep -rn "royalty\|EIP2981\|royaltyInfo" --include="*.sol"

# Find signature verification
grep -rn "ecrecover\|ECDSA\|EIP712\|signTypedData" --include="*.sol"

# Find NFT callbacks
grep -rn "onERC721Received\|onERC1155Received" --include="*.sol"

# Find auction logic
grep -rn "auction\|bid\|reserve.*price" --include="*.sol"
```
