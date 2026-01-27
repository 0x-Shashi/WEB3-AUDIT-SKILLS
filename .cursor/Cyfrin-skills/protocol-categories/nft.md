# NFT Protocol Security

## Quick Start

NFT protocols handle unique digital assets including minting, transfers, marketplaces, and royalties. Security concerns differ from fungible tokens due to unique ownership and metadata considerations.

**Risk Level:** MEDIUM to HIGH  
**Common Attacks:** Access control, reentrancy in safe transfers, metadata manipulation  
**Key Considerations:** Ownership, royalties, URI handling

## NFT Protocol Types

| Type | Examples | Primary Risks |
|------|----------|---------------|
| Minting | Art collections, PFPs | Access control, supply |
| Marketplace | OpenSea, Blur | Signature replay, royalties |
| Gaming | Loot, Axie | Game logic, item duplication |
| Lending | NFTfi, BendDAO | Valuation, liquidation |
| Fractionalization | Fractional.art | Governance, redemption |

## Most Critical NFT Vulnerabilities

### 1. Access Control in Minting
Unauthorized minting of tokens.

### 2. Reentrancy via onERC721Received
Safe transfer callbacks enable re-entry.

### 3. Signature Replay
Old signatures reused for unauthorized actions.

### 4. Metadata Manipulation
Centralized or manipulable token URIs.

### 5. Royalty Bypasses
Circumventing creator royalties.

## API Query: NFT Vulnerabilities

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "protocolCategory": [{"value": "NFT"}],
      "impact": ["HIGH", "MEDIUM"],
      "qualityScore": 3,
      "sortField": "Quality"
    }
  }'
```

## API Query: NFT Marketplace Issues

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "protocolCategory": [{"value": "NFT Marketplace"}],
      "impact": ["HIGH"]
    }
  }'
```

## API Query: NFT Lending Issues

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "protocolCategory": [{"value": "NFT Lending"}],
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

## Security Considerations by Feature

### Minting
```solidity
// VULNERABLE - Anyone can mint
function mint(uint256 tokenId) external {
    _mint(msg.sender, tokenId);
}

// SECURE - Access controlled
function mint(address to, uint256 tokenId) external onlyMinter {
    require(tokenId <= MAX_SUPPLY, "Exceeds supply");
    require(!_exists(tokenId), "Already minted");
    _safeMint(to, tokenId);
}
```

### Safe Transfer Reentrancy
```solidity
// VULNERABLE - State changes after safeTransfer
function claim(uint256 tokenId) external {
    _safeTransferFrom(address(this), msg.sender, tokenId);
    claimed[tokenId] = true;  // State change AFTER external call
}

// SECURE - State changes before safeTransfer
function claim(uint256 tokenId) external nonReentrant {
    require(!claimed[tokenId], "Already claimed");
    claimed[tokenId] = true;  // State change BEFORE external call
    _safeTransferFrom(address(this), msg.sender, tokenId);
}
```

### Signature Verification
```solidity
// VULNERABLE - No nonce, replayable
function mintWithSignature(uint256 tokenId, bytes calldata signature) external {
    bytes32 hash = keccak256(abi.encodePacked(tokenId, msg.sender));
    require(signer == ECDSA.recover(hash, signature), "Invalid signature");
    _mint(msg.sender, tokenId);
}

// SECURE - With nonce and deadline
function mintWithSignature(
    uint256 tokenId,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
) external {
    require(block.timestamp <= deadline, "Expired");
    require(nonces[msg.sender] == nonce, "Invalid nonce");
    
    bytes32 hash = keccak256(abi.encodePacked(
        tokenId, msg.sender, nonce, deadline, address(this)
    ));
    bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
    require(signer == ECDSA.recover(ethHash, signature), "Invalid signature");
    
    nonces[msg.sender]++;
    _mint(msg.sender, tokenId);
}
```

### Marketplace Orders
```solidity
// SECURE - Order structure with protections
struct Order {
    address seller;
    address collection;
    uint256 tokenId;
    uint256 price;
    uint256 nonce;
    uint256 expiry;
    bytes signature;
}

function executeOrder(Order calldata order) external payable {
    // Verify not expired
    require(block.timestamp <= order.expiry, "Expired");
    
    // Verify not cancelled
    require(!cancelledOrders[order.seller][order.nonce], "Cancelled");
    
    // Verify ownership
    require(IERC721(order.collection).ownerOf(order.tokenId) == order.seller, "Not owner");
    
    // Verify signature
    bytes32 orderHash = hashOrder(order);
    require(verifySignature(order.seller, orderHash, order.signature), "Invalid signature");
    
    // Mark used
    cancelledOrders[order.seller][order.nonce] = true;
    
    // Execute trade
    IERC721(order.collection).transferFrom(order.seller, msg.sender, order.tokenId);
    payable(order.seller).transfer(order.price);
}
```

## Common Vulnerable Patterns

### 1. Missing Ownership Check
```solidity
// VULNERABLE
function list(uint256 tokenId, uint256 price) external {
    listings[tokenId] = Listing({seller: msg.sender, price: price});
    // Doesn't check if msg.sender owns the token
}

// SECURE
function list(uint256 tokenId, uint256 price) external {
    require(nft.ownerOf(tokenId) == msg.sender, "Not owner");
    require(nft.isApprovedForAll(msg.sender, address(this)), "Not approved");
    listings[tokenId] = Listing({seller: msg.sender, price: price});
}
```

### 2. Centralized Metadata
```solidity
// RISKY - Owner can change any URI
function setTokenURI(uint256 tokenId, string calldata uri) external onlyOwner {
    _tokenURIs[tokenId] = uri;
}

// SAFER - Frozen after reveal
bool public frozen;
function freezeMetadata() external onlyOwner {
    frozen = true;
}
function setTokenURI(uint256 tokenId, string calldata uri) external onlyOwner {
    require(!frozen, "Frozen");
    _tokenURIs[tokenId] = uri;
}
```

### 3. Reentrancy in Auction
```solidity
// VULNERABLE
function settleAuction(uint256 tokenId) external {
    Auction memory auction = auctions[tokenId];
    delete auctions[tokenId];
    
    nft.safeTransferFrom(address(this), auction.highestBidder, tokenId);
    // Callback can re-enter here
    
    payable(auction.seller).transfer(auction.highestBid);
}
```

## NFT Security Checklist

### Minting Security
- [ ] Access control on mint functions
- [ ] Supply limits enforced
- [ ] Token ID collision prevention
- [ ] Proper randomization if needed

### Transfer Security
- [ ] Reentrancy protection for safeTransfer
- [ ] Approval validation
- [ ] Ownership checks
- [ ] Hook handling (beforeTransfer/afterTransfer)

### Marketplace Security
- [ ] Signature replay protection (nonces)
- [ ] Order expiration
- [ ] Order cancellation
- [ ] Ownership verification at execution
- [ ] Price validation

### Metadata Security
- [ ] Immutable or frozen option
- [ ] IPFS or on-chain storage
- [ ] Base URI protection
- [ ] Reveal mechanism security

### General
- [ ] Royalty enforcement (EIP-2981)
- [ ] Pausability for emergencies
- [ ] Proper enumeration if needed
- [ ] Event emission

## Test This Query

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 5,
    "filters": {
      "protocolCategory": [{"value": "NFT"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }' | jq '.findings[] | {title, protocol: .protocol_name}'
```

## Cross-Reference

- For reentrancy → See [../vulnerability-tags/reentrancy.md](../vulnerability-tags/reentrancy.md)
- For access control → See [../vulnerability-tags/access-control.md](../vulnerability-tags/access-control.md)
- For front-running (sniping) → See [../vulnerability-tags/front-running.md](../vulnerability-tags/front-running.md)
