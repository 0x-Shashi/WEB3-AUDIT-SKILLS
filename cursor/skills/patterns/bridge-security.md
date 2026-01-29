# Bridge Security Patterns - AI Reference

> **For AI Assistants:** Bridges are high-value targets. Apply these patterns when auditing cross-chain protocols.

---

## Bridge Architecture Types

| Type | Description | Risk Level |
|------|-------------|------------|
| **Lock & Mint** | Lock on source, mint on destination | High - custodial |
| **Burn & Mint** | Burn on source, mint on destination | Medium - coordination |
| **Liquidity Pool** | Swap against pools on both chains | High - liquidity attacks |
| **Atomic Swap** | Trustless exchange using HTLCs | Low - no custody |
| **Canonical** | Official L1<->L2 bridge | Lower - protocol secured |

---

## Critical Bridge Vulnerabilities

### 1. Message Validation Failures
```
Severity: CRITICAL
Category: access-control

Description:
The most common bridge vulnerability - not properly validating 
that a message came from the expected source.

Attack: Attacker sends fake message to destination chain claiming 
they deposited on source chain.

Vulnerable patterns:
```solidity
// VULNERABLE: No sender validation
function receiveMessage(bytes calldata proof) external {
    (address user, uint256 amount) = decode(proof);
    _mint(user, amount);  // Mints without verifying source!
}

// VULNERABLE: Wrong validation
function receiveMessage(bytes calldata data) external {
    require(msg.sender == trustedRelayer);  // Relayer can be compromised!
    _processMessage(data);
}
```

Correct pattern:
```solidity
function receiveMessage(bytes calldata data, bytes32[] calldata proof) external {
    // Verify Merkle proof against source chain state
    bytes32 messageHash = keccak256(data);
    require(
        MerkleProof.verify(proof, sourceChainRoot, messageHash),
        "Invalid proof"
    );
    
    // Verify message not already processed
    require(!processedMessages[messageHash], "Already processed");
    processedMessages[messageHash] = true;
    
    _processMessage(data);
}
```

Key checks:
- [ ] Cryptographic proof of source chain state
- [ ] Message not already processed (replay protection)
- [ ] Correct source chain ID
- [ ] Correct source contract address
```

### 2. Message Replay Attacks
```
Severity: CRITICAL
Category: reentrancy

Description:
Same message processed multiple times, minting tokens repeatedly.

Attack vectors:
- Same message on same chain (missing processed flag)
- Same message on different chain (missing chain ID)
- Same message with different nonces

Vulnerable pattern:
```solidity
function processMessage(bytes calldata data) external {
    // No replay protection!
    (address to, uint256 amount) = abi.decode(data, (address, uint256));
    token.mint(to, amount);
}
```

Correct pattern:
```solidity
mapping(bytes32 => bool) public processedMessages;

function processMessage(bytes calldata data) external {
    bytes32 messageId = keccak256(abi.encodePacked(
        sourceChainId,
        block.chainid,  // Destination chain
        messageNonce,
        data
    ));
    
    require(!processedMessages[messageId], "Already processed");
    processedMessages[messageId] = true;
    
    _execute(data);
}
```
```

### 3. Signature Verification Issues
```
Severity: CRITICAL
Category: signature

Description:
Multi-sig or validator signature verification flaws.

Common issues:
- Signature malleability
- Missing signer uniqueness check
- Threshold bypass
- Reused nonces

Vulnerable patterns:
```solidity
// VULNERABLE: Signature malleability
function verify(bytes32 hash, bytes[] calldata sigs) external {
    for (uint i = 0; i < sigs.length; i++) {
        address signer = ecrecover(hash, sigs[i]);
        require(isValidator[signer], "Invalid signer");
    }
    require(sigs.length >= threshold, "Not enough sigs");
}
// Attack: Same signature with different s value counts twice!

// VULNERABLE: No uniqueness check
function verify(bytes32 hash, bytes[] calldata sigs) external {
    uint validSigs = 0;
    for (uint i = 0; i < sigs.length; i++) {
        address signer = recoverSigner(hash, sigs[i]);
        if (isValidator[signer]) validSigs++;
    }
    require(validSigs >= threshold);
}
// Attack: Submit same valid signature multiple times!
```

Correct pattern:
```solidity
function verify(bytes32 hash, bytes[] calldata sigs) external {
    require(sigs.length >= threshold, "Not enough signatures");
    
    address lastSigner = address(0);
    for (uint i = 0; i < sigs.length; i++) {
        address signer = ECDSA.recover(hash, sigs[i]);  // Handles malleability
        
        require(signer > lastSigner, "Signers not unique/ordered");
        require(isValidator[signer], "Not a validator");
        
        lastSigner = signer;
    }
}
```
```

### 4. Deposit/Withdrawal Mismatch
```
Severity: CRITICAL
Category: accounting

Description:
Mismatch between deposited amount on source and minted amount 
on destination.

Attack vectors:
- Fee-on-transfer tokens
- Rebasing tokens
- Decimal mismatch between chains
- Rounding errors

Vulnerable pattern:
```solidity
// SOURCE CHAIN
function deposit(address token, uint256 amount) external {
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    emit Deposit(token, msg.sender, amount);  // Logs requested amount
}

// DESTINATION CHAIN
function mint(address token, address to, uint256 amount) external {
    wrappedToken[token].mint(to, amount);  // Mints logged amount
}
// Attack: Use fee-on-transfer token, deposit 100, only 98 arrives,
// but 100 is minted on destination!
```

Correct pattern:
```solidity
function deposit(address token, uint256 amount) external {
    uint256 balanceBefore = IERC20(token).balanceOf(address(this));
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    uint256 actualAmount = IERC20(token).balanceOf(address(this)) - balanceBefore;
    
    emit Deposit(token, msg.sender, actualAmount);  // Log actual amount
}
```
```

### 5. Oracle/Relayer Manipulation
```
Severity: HIGH
Category: oracle

Description:
Compromised or malicious relayers/oracles can forge messages.

Risk factors:
- Single relayer (centralization)
- Insufficient validator set
- No fraud proofs
- Oracle manipulation

Mitigation:
- Multiple independent relayers
- Fraud proof mechanisms
- Optimistic verification with challenge period
- On-chain state verification
```

---

## Bridge-Specific Patterns

### Lock & Mint Bridges

#### Locked Token Accounting
```
Severity: HIGH
Category: accounting

Check for:
- Total locked on source >= total minted on destination
- Proper handling of token transfers
- No way to unlock without burning wrapped

Invariant:
sourceChain.lockedBalance >= destinationChain.wrappedTotalSupply
```

#### Unlock Authorization
```
Severity: CRITICAL
Category: access-control

Check for:
- Only burn proof can trigger unlock
- Proper burn verification
- No double-unlock possibility
```

### Liquidity Pool Bridges

#### Pool Imbalance Attacks
```
Severity: HIGH
Category: economic

Description:
Attacker drains pool on one side by manipulating the other.

Check for:
- Maximum single-swap limits
- Rebalancing mechanisms
- Flash loan resistance

Vulnerable pattern:
```solidity
function swap(uint256 amount) external {
    require(poolBalance >= amount);  // No per-tx limit!
    poolBalance -= amount;
    token.transfer(msg.sender, amount);
}
```
```

#### LP Token Value Manipulation
```
Severity: HIGH  
Category: oracle

Check for:
- First depositor attack (vault inflation)
- Flash loan manipulation of LP value
- Proper share calculation
```

---

## Cross-Chain Message Patterns

### 1. Asynchronous Execution
```
Severity: MEDIUM
Category: timing

Description:
Cross-chain messages are asynchronous - state may change between 
send and receive.

Check for:
- State assumptions at receive time
- Revert handling (funds stuck?)
- Timeout mechanisms

Example issue:
```solidity
// Source: User has 100 tokens, initiates bridge
// ... time passes ...
// Destination: Tries to deposit to protocol that now has different rates
// User gets less than expected, no recourse
```

Mitigation:
- Slippage protection in destination logic
- Minimum output amounts
- Refund mechanisms for failed executions
```

### 2. Message Ordering
```
Severity: MEDIUM
Category: logic

Description:
Messages may arrive out of order or some may fail.

Check for:
- Dependency on message order
- Handling of failed predecessor messages
- Nonce gaps

Example:
```solidity
// Message 1: Create position
// Message 2: Add collateral
// If Message 1 fails but Message 2 succeeds, collateral is lost
```
```

### 3. Gas Estimation
```
Severity: MEDIUM
Category: denial-of-service

Description:
Insufficient gas for destination execution causes failures.

Check for:
- Gas estimation for complex destination logic
- Handling of out-of-gas on destination
- Refund mechanisms
```

---

## Bridge Security Checklist

### Message Security
- [ ] Cryptographic proof of source message
- [ ] Replay protection (nonce/hash tracking)
- [ ] Chain ID validation (source and destination)
- [ ] Source contract address validation
- [ ] Message expiration handling

### Signature Security
- [ ] Signature malleability protection (use ECDSA library)
- [ ] Signer uniqueness verification
- [ ] Threshold enforcement
- [ ] Nonce management for signers
- [ ] Key rotation mechanism

### Token Security
- [ ] Fee-on-transfer token handling
- [ ] Rebasing token handling
- [ ] Decimal normalization across chains
- [ ] Token address mapping validation
- [ ] Wrapped token supply invariant

### Access Control
- [ ] Admin key security (multisig, timelock)
- [ ] Pause mechanism
- [ ] Upgrade controls
- [ ] Emergency withdrawal

### Economic Security
- [ ] Per-transaction limits
- [ ] Daily/periodic limits
- [ ] Flash loan resistance
- [ ] Pool balance monitoring
- [ ] Oracle manipulation resistance

### Operational Security
- [ ] Relayer redundancy
- [ ] Monitoring and alerting
- [ ] Incident response plan
- [ ] Recovery mechanisms

---

## Famous Bridge Hacks Reference

| Bridge | Loss | Root Cause |
|--------|------|------------|
| Ronin | $624M | Compromised validator keys (5/9 threshold) |
| Wormhole | $326M | Signature verification bypass |
| Nomad | $190M | Faulty message validation (any message accepted) |
| Harmony | $100M | Compromised multisig (2/5) |
| BNB Bridge | $586M | Merkle proof verification flaw |
| Multichain | $130M | Compromised MPC keys |

### Key Lessons

1. **Ronin**: 5 of 9 validators compromised → Use higher thresholds, distributed validators
2. **Wormhole**: Guardian signature check bypassed → Rigorous signature verification
3. **Nomad**: acceptableRoot allowed any message → Never trust unverified messages
4. **Harmony**: 2 of 5 multisig → Use higher M/N ratios
5. **BNB**: Proof verification bug → Formal verification of proof logic

---

## AI Application Guide

When auditing bridges:

1. **Identify bridge type** (Lock/Mint, Pool, etc.)
2. **Map the message flow** from source to destination
3. **Verify message validation** - the #1 issue
4. **Check replay protection** - must be airtight
5. **Analyze signature scheme** if using validators
6. **Test token handling** for edge cases
7. **Assess centralization** in relayers/validators
8. **Review economic attacks** for pool-based bridges
9. **Check admin controls** - pausable, upgradeable?

### Priority Areas
```
1. Message validation (CRITICAL)
2. Replay protection (CRITICAL)
3. Signature verification (CRITICAL if applicable)
4. Token accounting (HIGH)
5. Access control (HIGH)
6. Economic attacks (MEDIUM-HIGH)
7. Operational security (MEDIUM)
```
