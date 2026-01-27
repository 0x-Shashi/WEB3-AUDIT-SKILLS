# Bridge Protocol Security

## Quick Start

Bridges enable cross-chain asset transfers and messaging. They're among the highest-risk protocols due to the complexity of multi-chain coordination and the massive amounts of locked funds they secure.

**Risk Level:** CRITICAL  
**Common Attacks:** Message verification bypass, replay attacks, oracle manipulation  
**Historical Losses:** Over $2 billion lost in bridge exploits

## Bridge Types

| Type | Mechanism | Primary Risks |
|------|-----------|---------------|
| Lock & Mint | Lock on source, mint on dest | Message verification |
| Burn & Mint | Burn on source, mint on dest | Supply tracking |
| Liquidity Pool | Pools on both chains | Liquidity manipulation |
| Validator Set | Multi-sig validators | Collusion, key compromise |
| Optimistic | Fraud proofs | Challenge period |

## Most Critical Bridge Vulnerabilities

### 1. Signature/Message Verification Bypass
Insufficient validation of cross-chain messages.

### 2. Replay Attacks
Same message executed multiple times or across chains.

### 3. Validator/Oracle Compromise
Centralized validation points become targets.

### 4. Merkle Proof Vulnerabilities
Incorrect proof verification.

### 5. Sequencer/Relayer Attacks
Manipulation of message ordering.

## API Query: Bridge Vulnerabilities

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "protocolCategory": [{"value": "Bridge"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

## API Query: Cross-Chain Issues

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "protocolCategory": [{"value": "Cross-Chain"}],
      "impact": ["HIGH"]
    }
  }'
```

## Security Considerations by Feature

### Message Verification
```solidity
// VULNERABLE - Insufficient signature validation
function receiveMessage(bytes calldata message, bytes calldata signature) external {
    address signer = ECDSA.recover(keccak256(message), signature);
    require(isTrustedSigner[signer], "Invalid signer");
    _execute(message);  // Missing: chain ID, nonce, expiry checks
}

// SECURE - Complete validation
function receiveMessage(
    uint256 sourceChain,
    uint256 nonce,
    bytes calldata payload,
    bytes calldata signatures
) external {
    // Verify chain ID
    require(sourceChain != block.chainid, "Same chain");
    require(supportedChains[sourceChain], "Unsupported chain");
    
    // Verify nonce (replay protection)
    require(!usedNonces[sourceChain][nonce], "Already processed");
    usedNonces[sourceChain][nonce] = true;
    
    // Construct message hash
    bytes32 messageHash = keccak256(abi.encode(
        sourceChain,
        block.chainid,
        nonce,
        payload
    ));
    
    // Verify threshold signatures
    address[] memory signers = recoverSigners(messageHash, signatures);
    require(signers.length >= threshold, "Insufficient signatures");
    for (uint i = 0; i < signers.length; i++) {
        require(isValidator[signers[i]], "Invalid validator");
    }
    
    _execute(payload);
}
```

### Token Locking/Minting
```solidity
// SECURE - Proper lock with receipt
function lock(address token, uint256 amount, uint256 destChain) external {
    require(supportedTokens[token], "Unsupported token");
    require(destChain != block.chainid, "Same chain");
    
    uint256 balanceBefore = IERC20(token).balanceOf(address(this));
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    uint256 received = IERC20(token).balanceOf(address(this)) - balanceBefore;
    
    uint256 nonce = lockNonce++;
    
    emit Locked(
        token,
        msg.sender,
        received,
        destChain,
        nonce,
        block.timestamp
    );
}
```

### Multi-Signature Validation
```solidity
// SECURE - Multi-sig with threshold
function verifySignatures(
    bytes32 messageHash,
    bytes[] calldata signatures
) internal view returns (bool) {
    require(signatures.length >= threshold, "Below threshold");
    
    address lastSigner = address(0);
    for (uint i = 0; i < signatures.length; i++) {
        address signer = ECDSA.recover(messageHash, signatures[i]);
        
        // Check signer is valid
        require(isValidator[signer], "Invalid validator");
        
        // Check signatures are in order (prevents duplicates)
        require(signer > lastSigner, "Duplicate or unordered");
        lastSigner = signer;
    }
    
    return true;
}
```

## Common Vulnerable Patterns

### 1. Missing Chain ID Validation
```solidity
// VULNERABLE
function unlock(bytes32 lockId, uint256 amount) external {
    // Doesn't verify message came from correct source chain
}

// SECURE
function unlock(
    uint256 sourceChain,
    bytes32 lockId,
    uint256 amount
) external {
    require(sourceChain == EXPECTED_SOURCE_CHAIN, "Invalid source");
}
```

### 2. Nonce Not Unique Per Chain
```solidity
// VULNERABLE - Same nonce space for all chains
mapping(uint256 => bool) usedNonces;

// SECURE - Nonce per source chain
mapping(uint256 => mapping(uint256 => bool)) usedNonces;  // chainId => nonce => used
```

### 3. Insufficient Validator Threshold
```solidity
// VULNERABLE - Only 1 of 5 required
uint256 public threshold = 1;

// SECURE - Majority required
uint256 public threshold = (validators.length * 2) / 3 + 1;
```

### 4. No Message Expiry
```solidity
// VULNERABLE - Message valid forever
function process(bytes calldata message) external {
    // No timestamp check
}

// SECURE - Expiry enforced
function process(bytes calldata message, uint256 deadline) external {
    require(block.timestamp <= deadline, "Message expired");
}
```

## Bridge Security Checklist

### Message Verification
- [ ] Source chain ID verified
- [ ] Destination chain ID verified
- [ ] Nonce prevents replay (per chain)
- [ ] Message expiry/deadline
- [ ] Threshold signatures required
- [ ] Signer uniqueness enforced

### Token Handling
- [ ] Supported token whitelist
- [ ] Fee-on-transfer handling
- [ ] Amount validation
- [ ] Supply tracking (mint/burn)

### Validator Security
- [ ] Adequate threshold (2/3+)
- [ ] Validator rotation mechanism
- [ ] Slashing conditions
- [ ] Key management procedures

### Operational Security
- [ ] Emergency pause
- [ ] Rate limiting
- [ ] Maximum transfer limits
- [ ] Gradual limit increases
- [ ] Monitoring and alerts

### Protocol Design
- [ ] Fraud proof window (if optimistic)
- [ ] Challenge mechanism
- [ ] Finality considerations
- [ ] Reorg handling

## Major Bridge Exploits to Study

| Bridge | Attack | Loss | Root Cause |
|--------|--------|------|------------|
| Ronin | Key compromise | $625M | 5 of 9 validators compromised |
| Wormhole | Signature bypass | $320M | Missing signature validation |
| Nomad | Proof bypass | $190M | Merkle proof validation |
| Harmony | Key compromise | $100M | Multi-sig compromise |
| Multichain | Compromised MPC | $126M | Centralized custody |

## Test This Query

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 5,
    "filters": {
      "protocolCategory": [{"value": "Bridge"}],
      "impact": ["HIGH"],
      "qualityScore": 5,
      "sortField": "Quality"
    }
  }' | jq '.findings[] | {title, firm: .firm_name}'
```

## Cross-Reference

- For access control → See [../vulnerability-tags/access-control.md](../vulnerability-tags/access-control.md)
- For validation issues → See [../vulnerability-tags/logic-error.md](../vulnerability-tags/logic-error.md)
