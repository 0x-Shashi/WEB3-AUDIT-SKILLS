---
id: BRIDGE-SPECIFIC-ANTI-PATTERNS
title: Bridge-Specific Anti-Patterns
category: anti-pattern
protocol: bridge
triggers:
  - bridge vulnerability patterns
  - cross-chain security issues
  - message passing exploits
  - validator attack patterns
  - finality vulnerabilities
related_skills:
  - attack-trees/bridge-attack-tree.md
  - patterns/bridge-patterns.md
  - patterns/signature-patterns.md
  - patterns/consensus-patterns.md
---

# Bridge-Specific Anti-Patterns

Comprehensive catalog of vulnerability patterns specific to cross-chain bridges and interoperability protocols.

---

## Overview

Bridge vulnerabilities are uniquely dangerous due to:
- High TVL concentration
- Trust assumptions across chains
- Finality timing differences
- Validator/relayer dependencies
- Complex message verification

---

## Anti-Pattern Categories

| Category | Count | Severity Range |
|----------|-------|----------------|
| [Signature & Verification](#signature-anti-patterns) | 8 | Critical |
| [Message Passing](#message-anti-patterns) | 7 | Critical-High |
| [Validator/Relayer](#validator-anti-patterns) | 7 | Critical-High |
| [Finality & Reorg](#finality-anti-patterns) | 6 | Critical-High |
| [Token Handling](#token-anti-patterns) | 6 | Critical-Medium |
| [Liquidity & Accounting](#liquidity-anti-patterns) | 6 | Critical-Medium |
| [Governance & Admin](#governance-anti-patterns) | 5 | Critical-High |

---

## Signature Anti-Patterns

### BRIDGE-AP-01: Missing Signature Verification

**Description:** Bridge accepts messages without proper signature verification, allowing anyone to submit fake messages.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No signature check
function receiveMessage(
    uint256 sourceChain,
    address sender,
    bytes calldata payload
) external {
    // VULNERABLE: Anyone can call with any payload
    _processMessage(sourceChain, sender, payload);
}
```

**Secure Pattern:**
```solidity
function receiveMessage(
    uint256 sourceChain,
    address sender,
    bytes calldata payload,
    bytes[] calldata signatures
) external {
    // SECURE: Verify signatures meet threshold
    bytes32 messageHash = keccak256(abi.encode(
        sourceChain,
        block.chainid,
        sender,
        payload,
        nonce++
    ));
    
    uint256 validSignatures = 0;
    address lastSigner = address(0);
    
    for (uint256 i = 0; i < signatures.length; i++) {
        address signer = ECDSA.recover(messageHash, signatures[i]);
        
        // SECURE: Check signer is validator
        require(isValidator[signer], "Invalid signer");
        // SECURE: Check no duplicate signatures
        require(signer > lastSigner, "Duplicate or unsorted");
        
        lastSigner = signer;
        validSignatures++;
    }
    
    require(validSignatures >= threshold, "Insufficient signatures");
    
    _processMessage(sourceChain, sender, payload);
}
```

**Real-World Instances:**
- Ronin Bridge: $625M (signature verification bypass)
- Wormhole: $320M (signature verification flaw)

---

### BRIDGE-AP-02: Signature Replay Attack

**Description:** Signatures can be replayed to execute same message multiple times.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No nonce or message ID
function processMessage(
    bytes calldata message,
    bytes calldata signature
) external {
    address signer = ECDSA.recover(keccak256(message), signature);
    require(isValidator[signer], "Invalid signer");
    
    // VULNERABLE: Same message can be replayed
    _execute(message);
}
```

**Secure Pattern:**
```solidity
mapping(bytes32 => bool) public processedMessages;

function processMessage(
    bytes calldata message,
    uint256 nonce,
    bytes calldata signature
) external {
    bytes32 messageId = keccak256(abi.encode(message, nonce, block.chainid));
    
    // SECURE: Check message not already processed
    require(!processedMessages[messageId], "Already processed");
    processedMessages[messageId] = true;
    
    address signer = ECDSA.recover(messageId, signature);
    require(isValidator[signer], "Invalid signer");
    
    _execute(message);
}
```

---

### BRIDGE-AP-03: Cross-Chain Signature Replay

**Description:** Signatures valid on one chain can be replayed on another chain.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No chain ID in signed message
function verifySignature(
    address sender,
    uint256 amount,
    bytes calldata signature
) internal view returns (bool) {
    bytes32 hash = keccak256(abi.encode(sender, amount));
    address signer = ECDSA.recover(hash, signature);
    return isValidator[signer];
}
```

**Secure Pattern:**
```solidity
function verifySignature(
    uint256 sourceChain,
    address sender,
    uint256 amount,
    uint256 nonce,
    bytes calldata signature
) internal view returns (bool) {
    // SECURE: Include both source and destination chain IDs
    bytes32 hash = keccak256(abi.encode(
        sourceChain,
        block.chainid,  // Destination chain
        sender,
        amount,
        nonce,
        address(this)   // Contract address
    ));
    
    address signer = ECDSA.recover(
        ECDSA.toEthSignedMessageHash(hash), 
        signature
    );
    
    return isValidator[signer];
}
```

**Real-World Instances:**
- Nomad Bridge: $190M (message replay across chains)

---

### BRIDGE-AP-04: Insufficient Signature Threshold

**Description:** Threshold too low relative to validator set, enabling collusion.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: 2-of-5 threshold (only 2 compromised validators needed)
uint256 public constant THRESHOLD = 2;
uint256 public constant TOTAL_VALIDATORS = 5;

function verifySignatures(bytes32 hash, bytes[] calldata sigs) internal view {
    uint256 valid = 0;
    for (uint256 i = 0; i < sigs.length; i++) {
        if (isValidator[ECDSA.recover(hash, sigs[i])]) valid++;
    }
    require(valid >= THRESHOLD, "Insufficient");  // VULNERABLE: Too low
}
```

**Secure Pattern:**
```solidity
// SECURE: 5-of-7 or higher threshold (>66%)
uint256 public threshold;
uint256 public validatorCount;

function setThreshold(uint256 _threshold) external onlyGovernance {
    // SECURE: Require >66% threshold
    require(_threshold * 3 > validatorCount * 2, "Threshold too low");
    // SECURE: Require at least 3 signatures
    require(_threshold >= 3, "Minimum 3 signatures");
    threshold = _threshold;
}

function verifySignatures(bytes32 hash, bytes[] calldata sigs) internal view {
    require(sigs.length >= threshold, "Not enough signatures");
    
    uint256 valid = 0;
    address lastSigner = address(0);
    
    for (uint256 i = 0; i < sigs.length; i++) {
        address signer = ECDSA.recover(hash, sigs[i]);
        require(isValidator[signer], "Not validator");
        require(signer > lastSigner, "Not sorted/duplicate");
        lastSigner = signer;
        valid++;
    }
    
    require(valid >= threshold, "Insufficient valid signatures");
}
```

---

### BRIDGE-AP-05: Validator Key Compromise

**Description:** Validator keys stored insecurely or single key controls too much.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Single admin can update all validators
function updateValidators(address[] calldata newValidators) external onlyOwner {
    for (uint256 i = 0; i < newValidators.length; i++) {
        validators[i] = newValidators[i];
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Timelock + multi-sig for validator changes
uint256 public constant VALIDATOR_CHANGE_DELAY = 7 days;

struct PendingValidatorChange {
    address[] newValidators;
    uint256 executeAfter;
    bool executed;
}

mapping(uint256 => PendingValidatorChange) public pendingChanges;
uint256 public changeNonce;

function proposeValidatorChange(address[] calldata newValidators) 
    external 
    onlyGovernance  // Requires multi-sig
{
    // SECURE: Rate limit changes
    require(
        block.timestamp > lastValidatorChange + MIN_CHANGE_INTERVAL,
        "Too frequent"
    );
    
    pendingChanges[changeNonce++] = PendingValidatorChange({
        newValidators: newValidators,
        executeAfter: block.timestamp + VALIDATOR_CHANGE_DELAY,
        executed: false
    });
    
    emit ValidatorChangeProposed(changeNonce - 1, newValidators);
}

function executeValidatorChange(uint256 nonce) external {
    PendingValidatorChange storage change = pendingChanges[nonce];
    
    require(!change.executed, "Already executed");
    require(block.timestamp >= change.executeAfter, "Too early");
    
    change.executed = true;
    lastValidatorChange = block.timestamp;
    
    // Update validators
    for (uint256 i = 0; i < change.newValidators.length; i++) {
        validators[i] = change.newValidators[i];
    }
    
    emit ValidatorsUpdated(change.newValidators);
}
```

---

### BRIDGE-AP-06: Signature Malleability

**Description:** ECDSA signatures can be modified to create valid alternate signatures.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Standard ecrecover without malleability check
function verify(bytes32 hash, bytes memory sig) internal pure returns (address) {
    (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);
    return ecrecover(hash, v, r, s);
}
```

**Secure Pattern:**
```solidity
// SECURE: Check s value to prevent malleability
function verify(bytes32 hash, bytes memory sig) internal pure returns (address) {
    (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);
    
    // SECURE: Reject high s values (EIP-2)
    require(
        uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
        "Invalid s value"
    );
    
    require(v == 27 || v == 28, "Invalid v value");
    
    address signer = ecrecover(hash, v, r, s);
    require(signer != address(0), "Invalid signature");
    
    return signer;
}

// Or use OpenZeppelin's ECDSA library which handles this
function verifySecure(bytes32 hash, bytes memory sig) internal pure returns (address) {
    return ECDSA.recover(ECDSA.toEthSignedMessageHash(hash), sig);
}
```

---

### BRIDGE-AP-07: Missing Signer Uniqueness Check

**Description:** Same validator signature counted multiple times.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No duplicate check
function verifySignatures(bytes32 hash, bytes[] calldata sigs) internal view {
    uint256 valid = 0;
    
    for (uint256 i = 0; i < sigs.length; i++) {
        address signer = ECDSA.recover(hash, sigs[i]);
        if (isValidator[signer]) {
            valid++;  // VULNERABLE: Same signer counted multiple times
        }
    }
    
    require(valid >= threshold, "Insufficient");
}
```

**Secure Pattern:**
```solidity
function verifySignatures(bytes32 hash, bytes[] calldata sigs) internal view {
    require(sigs.length >= threshold, "Not enough signatures");
    
    address lastSigner = address(0);
    uint256 valid = 0;
    
    for (uint256 i = 0; i < sigs.length; i++) {
        address signer = ECDSA.recover(hash, sigs[i]);
        
        // SECURE: Require sorted order (ensures uniqueness)
        require(signer > lastSigner, "Signatures not sorted or duplicate");
        require(isValidator[signer], "Not a validator");
        
        lastSigner = signer;
        valid++;
    }
    
    require(valid >= threshold, "Insufficient valid signatures");
}
```

---

### BRIDGE-AP-08: Precompile Signature Issues

**Description:** Using precompiles incorrectly for signature verification.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: ecrecover returns 0 on failure, not revert
function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
    address signer = ecrecover(hash, v, r, s);
    // VULNERABLE: If signer is 0, might still pass validator check
    return signer;
}

// If validators[address(0)] is somehow true...
function isValid(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external view returns (bool) {
    address signer = verify(hash, v, r, s);
    return validators[signer];  // VULNERABLE: Could match address(0)
}
```

**Secure Pattern:**
```solidity
function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
    // SECURE: Validate signature parameters
    require(v == 27 || v == 28, "Invalid v");
    require(uint256(r) != 0 && uint256(s) != 0, "Invalid r or s");
    
    address signer = ecrecover(hash, v, r, s);
    
    // SECURE: Explicit zero check
    require(signer != address(0), "Invalid signature");
    
    return signer;
}
```

---

## Message Anti-Patterns

### BRIDGE-AP-09: Arbitrary Message Execution

**Description:** Bridge executes arbitrary calldata without proper validation.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Executes any calldata
function executeMessage(
    address target,
    bytes calldata data
) external onlyRelayer {
    // VULNERABLE: No validation of target or data
    (bool success,) = target.call(data);
    require(success, "Call failed");
}
```

**Secure Pattern:**
```solidity
mapping(address => bool) public allowedTargets;
mapping(bytes4 => bool) public allowedSelectors;

function executeMessage(
    address target,
    bytes calldata data
) external onlyRelayer {
    // SECURE: Whitelist targets
    require(allowedTargets[target], "Target not allowed");
    
    // SECURE: Whitelist function selectors
    bytes4 selector = bytes4(data[:4]);
    require(allowedSelectors[selector], "Selector not allowed");
    
    // SECURE: Additional validation
    require(target != address(this), "Cannot call self");
    require(target.code.length > 0, "Target not a contract");
    
    (bool success, bytes memory result) = target.call(data);
    require(success, string(result));
    
    emit MessageExecuted(target, selector, data);
}
```

---

### BRIDGE-AP-10: Message Hash Collision

**Description:** Different messages can produce the same hash due to poor encoding.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: abi.encodePacked can have collisions
function getMessageHash(
    address sender,
    address receiver,
    bytes calldata data
) internal pure returns (bytes32) {
    // VULNERABLE: "ab" + "c" == "a" + "bc"
    return keccak256(abi.encodePacked(sender, receiver, data));
}
```

**Secure Pattern:**
```solidity
function getMessageHash(
    uint256 sourceChain,
    uint256 destChain,
    address sender,
    address receiver,
    uint256 nonce,
    bytes calldata data
) internal pure returns (bytes32) {
    // SECURE: abi.encode prevents collisions
    return keccak256(abi.encode(
        sourceChain,
        destChain,
        sender,
        receiver,
        nonce,
        keccak256(data)  // Hash data separately
    ));
}
```

---

### BRIDGE-AP-11: Missing Message Sequence Validation

**Description:** Messages processed out of order, enabling exploits.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No sequence enforcement
mapping(bytes32 => bool) public processed;

function processMessage(bytes32 messageId, bytes calldata data) external {
    require(!processed[messageId], "Already processed");
    processed[messageId] = true;
    
    // VULNERABLE: Messages can be processed in any order
    _execute(data);
}
```

**Secure Pattern:**
```solidity
// SECURE: Enforce sequential processing
mapping(uint256 => uint256) public nextNonce;  // sourceChain => nonce

function processMessage(
    uint256 sourceChain,
    uint256 nonce,
    bytes calldata data
) external {
    // SECURE: Require sequential nonces
    require(nonce == nextNonce[sourceChain], "Invalid nonce");
    nextNonce[sourceChain] = nonce + 1;
    
    _execute(data);
}

// Alternative: Allow out of order with bitmap
mapping(uint256 => mapping(uint256 => uint256)) public processedBitmap;

function processMessageOutOfOrder(
    uint256 sourceChain,
    uint256 nonce,
    bytes calldata data
) external {
    uint256 wordIndex = nonce / 256;
    uint256 bitIndex = nonce % 256;
    uint256 word = processedBitmap[sourceChain][wordIndex];
    uint256 mask = 1 << bitIndex;
    
    require(word & mask == 0, "Already processed");
    processedBitmap[sourceChain][wordIndex] = word | mask;
    
    _execute(data);
}
```

---

### BRIDGE-AP-12: Source Chain Spoofing

**Description:** Attacker claims message is from trusted chain when it's not.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Trusts claimed source chain
function receiveMessage(
    uint256 claimedSourceChain,  // User-provided, not verified
    bytes calldata message
) external {
    require(trustedChains[claimedSourceChain], "Untrusted chain");
    
    // VULNERABLE: No verification that message actually came from that chain
    _processFromChain(claimedSourceChain, message);
}
```

**Secure Pattern:**
```solidity
// SECURE: Verify message origin cryptographically
function receiveMessage(
    uint256 sourceChain,
    bytes calldata message,
    bytes32[] calldata proof,  // Merkle proof from source chain
    bytes calldata blockHeader
) external {
    // SECURE: Verify block header from source chain light client
    require(
        lightClients[sourceChain].verifyBlockHeader(blockHeader),
        "Invalid block header"
    );
    
    // SECURE: Verify message is in block via merkle proof
    bytes32 messageHash = keccak256(message);
    bytes32 root = extractMessagesRoot(blockHeader);
    
    require(
        MerkleProof.verify(proof, root, messageHash),
        "Invalid merkle proof"
    );
    
    _processFromChain(sourceChain, message);
}
```

---

### BRIDGE-AP-13: Return Value Not Checked

**Description:** Bridge doesn't check return value of message execution.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Return value ignored
function executeMessage(address target, bytes calldata data) external {
    target.call(data);  // VULNERABLE: Success not checked
    emit MessageExecuted(target);
}
```

**Secure Pattern:**
```solidity
function executeMessage(address target, bytes calldata data) external {
    // SECURE: Check return value
    (bool success, bytes memory returnData) = target.call(data);
    
    if (!success) {
        // SECURE: Propagate revert reason
        if (returnData.length > 0) {
            assembly {
                revert(add(returnData, 32), mload(returnData))
            }
        } else {
            revert("Message execution failed");
        }
    }
    
    emit MessageExecuted(target, data, returnData);
}
```

---

### BRIDGE-AP-14: Reentrancy in Message Processing

**Description:** Message execution allows reentrancy to manipulate state.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No reentrancy protection
function processAndCredit(
    address user,
    uint256 amount
) external onlyBridge {
    // External call before state update
    (bool success,) = user.call{value: amount}("");
    require(success, "Transfer failed");
    
    // VULNERABLE: State updated after external call
    processedAmount[user] += amount;
}
```

**Secure Pattern:**
```solidity
function processAndCredit(
    address user,
    uint256 amount
) external onlyBridge nonReentrant {
    // SECURE: State update before external call (CEI pattern)
    processedAmount[user] += amount;
    
    // External call after state update
    (bool success,) = user.call{value: amount}("");
    require(success, "Transfer failed");
}
```

---

### BRIDGE-AP-15: Message Expiration Missing

**Description:** Messages valid indefinitely, enabling delayed attacks.

**Severity:** Medium

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No expiration
function processMessage(
    bytes32 messageId,
    bytes calldata data
) external {
    require(!processed[messageId], "Already processed");
    // VULNERABLE: Old messages still valid
    _execute(data);
}
```

**Secure Pattern:**
```solidity
uint256 public constant MESSAGE_EXPIRY = 1 days;

function processMessage(
    bytes32 messageId,
    uint256 timestamp,
    bytes calldata data,
    bytes calldata signature
) external {
    // SECURE: Check message not expired
    require(
        block.timestamp <= timestamp + MESSAGE_EXPIRY,
        "Message expired"
    );
    
    // SECURE: Include timestamp in signed message
    bytes32 hash = keccak256(abi.encode(messageId, timestamp, data));
    require(verifySignature(hash, signature), "Invalid signature");
    
    require(!processed[messageId], "Already processed");
    processed[messageId] = true;
    
    _execute(data);
}
```

---

## Validator Anti-Patterns

### BRIDGE-AP-16: Centralized Validator Set

**Description:** Too few validators or single entity controls majority.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Only 3 validators, all from same entity
address[] public validators = [
    0x1111...,  // Company wallet 1
    0x2222...,  // Company wallet 2
    0x3333...   // Company wallet 3
];

uint256 public constant THRESHOLD = 2;  // 2-of-3
```

**Secure Pattern:**
```solidity
// SECURE: Diverse, decentralized validator set
uint256 public constant MIN_VALIDATORS = 7;
uint256 public constant MAX_SAME_ENTITY = 2;  // Max validators from same entity

mapping(address => bool) public isValidator;
mapping(address => address) public validatorEntity;  // validator => controlling entity
mapping(address => uint256) public entityValidatorCount;

function addValidator(address validator, address entity) external onlyGovernance {
    require(!isValidator[validator], "Already validator");
    require(entityValidatorCount[entity] < MAX_SAME_ENTITY, "Entity limit reached");
    
    isValidator[validator] = true;
    validatorEntity[validator] = entity;
    entityValidatorCount[entity]++;
    validatorCount++;
    
    // SECURE: Update threshold to maintain security
    _updateThreshold();
}

function _updateThreshold() internal {
    // SECURE: Threshold must be > 66%
    threshold = (validatorCount * 2 / 3) + 1;
    require(threshold >= 3, "Need more validators");
}
```

---

### BRIDGE-AP-17: Validator Liveness Failure

**Description:** Validators can go offline, blocking bridge operations.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No mechanism to handle offline validators
function processMessage(bytes[] calldata signatures) external {
    require(signatures.length >= threshold, "Not enough signatures");
    // If validators are offline, bridge is stuck
}
```

**Secure Pattern:**
```solidity
// SECURE: Track validator activity and allow rotation
mapping(address => uint256) public lastActivity;
uint256 public constant INACTIVITY_PERIOD = 7 days;

function markActive(address validator) internal {
    lastActivity[validator] = block.timestamp;
}

function removeInactiveValidator(address validator) external {
    require(
        block.timestamp > lastActivity[validator] + INACTIVITY_PERIOD,
        "Validator still active"
    );
    
    isValidator[validator] = false;
    validatorCount--;
    _updateThreshold();
    
    emit ValidatorRemoved(validator, "Inactive");
}

// SECURE: Emergency mode if too many validators offline
function enableEmergencyMode() external onlyGovernance {
    require(
        activeValidatorCount() < threshold,
        "Enough validators online"
    );
    
    emergencyMode = true;
    emergencyActivatedAt = block.timestamp;
    
    emit EmergencyModeEnabled();
}
```

---

### BRIDGE-AP-18: Validator Slashing Evasion

**Description:** Malicious validators not properly punished.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No slashing mechanism
function reportMisbehavior(address validator, bytes calldata proof) external {
    // Nothing happens to misbehaving validator
    emit MisbehaviorReported(validator);
}
```

**Secure Pattern:**
```solidity
mapping(address => uint256) public validatorStake;
uint256 public constant MIN_STAKE = 100 ether;
uint256 public constant SLASH_AMOUNT = 10 ether;

function slash(
    address validator,
    bytes calldata proof,
    SlashReason reason
) external {
    require(isValidator[validator], "Not validator");
    
    // SECURE: Verify proof of misbehavior
    require(verifySlashingProof(validator, proof, reason), "Invalid proof");
    
    // SECURE: Slash stake
    uint256 slashAmount = calculateSlashAmount(reason);
    validatorStake[validator] -= slashAmount;
    
    // SECURE: Remove if stake too low
    if (validatorStake[validator] < MIN_STAKE) {
        isValidator[validator] = false;
        validatorCount--;
        _updateThreshold();
    }
    
    // SECURE: Reward reporter
    uint256 reward = slashAmount / 10;
    payable(msg.sender).transfer(reward);
    
    emit ValidatorSlashed(validator, slashAmount, reason);
}
```

---

### BRIDGE-AP-19: Relayer Censorship

**Description:** Relayers can censor specific messages or users.

**Severity:** Medium

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Single relayer can censor
function relayMessage(bytes calldata message) external onlyRelayer {
    // Single relayer decides what gets relayed
    _process(message);
}
```

**Secure Pattern:**
```solidity
// SECURE: Permissionless relaying with incentives
function relayMessage(
    bytes calldata message,
    bytes calldata proof
) external {
    // SECURE: Anyone can relay
    require(verifyMessage(message, proof), "Invalid message");
    
    bytes32 messageId = keccak256(message);
    require(!relayed[messageId], "Already relayed");
    relayed[messageId] = true;
    
    _process(message);
    
    // SECURE: Reward relayer
    uint256 reward = calculateRelayReward(message);
    payable(msg.sender).transfer(reward);
    
    emit MessageRelayed(messageId, msg.sender, reward);
}

// SECURE: Self-relay option
function selfRelay(
    bytes calldata message,
    bytes calldata proof
) external payable {
    // Users can relay their own messages
    require(msg.value >= SELF_RELAY_FEE, "Insufficient fee");
    
    require(verifyMessage(message, proof), "Invalid message");
    require(extractSender(message) == msg.sender, "Not your message");
    
    _process(message);
}
```

---

### BRIDGE-AP-20: Oracle Manipulation by Validators

**Description:** Validators can manipulate price/state oracles used by bridge.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Validators submit prices without constraint
function submitPrice(address token, uint256 price) external onlyValidator {
    prices[token] = price;  // VULNERABLE: Any price accepted
}
```

**Secure Pattern:**
```solidity
// SECURE: Bounded price updates with consensus
mapping(address => uint256[]) public priceSubmissions;
mapping(address => mapping(address => bool)) public hasSubmitted;

function submitPrice(address token, uint256 price) external onlyValidator {
    require(!hasSubmitted[token][msg.sender], "Already submitted");
    
    // SECURE: Price must be within bounds of external oracle
    uint256 externalPrice = chainlinkOracle.getPrice(token);
    require(
        price > externalPrice * 95 / 100 && 
        price < externalPrice * 105 / 100,
        "Price out of bounds"
    );
    
    hasSubmitted[token][msg.sender] = true;
    priceSubmissions[token].push(price);
    
    // SECURE: Use median when enough submissions
    if (priceSubmissions[token].length >= threshold) {
        prices[token] = calculateMedian(priceSubmissions[token]);
        _resetSubmissions(token);
    }
}
```

---

### BRIDGE-AP-21: Hot Wallet Concentration

**Description:** Bridge funds in hot wallet accessible by validators.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: All funds in one hot wallet
address public hotWallet;

function withdraw(address token, uint256 amount, address to) external onlyValidator {
    IERC20(token).transferFrom(hotWallet, to, amount);
}
```

**Secure Pattern:**
```solidity
// SECURE: Multi-tier wallet system
address public hotWallet;      // Small amount for fast operations
address public warmWallet;     // Medium amount, time-delayed
address public coldWallet;     // Majority, multi-sig + timelock

uint256 public constant HOT_WALLET_LIMIT = 100 ether;
uint256 public constant WARM_WALLET_LIMIT = 1000 ether;

function withdraw(address token, uint256 amount, address to) external {
    if (amount <= HOT_WALLET_LIMIT) {
        // Fast path from hot wallet
        require(verifySignatures(/* threshold signatures */));
        _transferFrom(hotWallet, to, amount);
    } else if (amount <= WARM_WALLET_LIMIT) {
        // Time-delayed from warm wallet
        require(verifySignatures(/* higher threshold */));
        _queueTransfer(warmWallet, to, amount, WARM_DELAY);
    } else {
        // Multi-sig + timelock from cold wallet
        require(verifySignatures(/* all validators */));
        _queueTransfer(coldWallet, to, amount, COLD_DELAY);
    }
}
```

---

### BRIDGE-AP-22: No Validator Rotation

**Description:** Same validators indefinitely increases compromise risk.

**Severity:** Medium

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Validators never change
address[] public validators = [/* initial set */];
// No rotation mechanism
```

**Secure Pattern:**
```solidity
// SECURE: Mandatory rotation
uint256 public constant ROTATION_PERIOD = 90 days;
uint256 public lastRotation;

mapping(uint256 => address[]) public validatorSets;
uint256 public currentSet;

function rotateValidators(address[] calldata newValidators) external onlyGovernance {
    require(
        block.timestamp >= lastRotation + ROTATION_PERIOD,
        "Too early for rotation"
    );
    
    // SECURE: Validate new set
    require(newValidators.length >= MIN_VALIDATORS, "Too few validators");
    require(validateDiversity(newValidators), "Insufficient diversity");
    
    // SECURE: Overlap requirement for continuity
    uint256 overlap = countOverlap(validatorSets[currentSet], newValidators);
    require(overlap >= MIN_OVERLAP, "Not enough continuity");
    
    currentSet++;
    validatorSets[currentSet] = newValidators;
    lastRotation = block.timestamp;
    
    emit ValidatorsRotated(currentSet, newValidators);
}
```

---

## Finality Anti-Patterns

### BRIDGE-AP-23: Insufficient Confirmation Wait

**Description:** Bridge accepts transactions before sufficient confirmations.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Accepts 1 confirmation
function processDeposit(
    bytes32 txHash,
    uint256 blockNumber
) external onlyRelayer {
    // VULNERABLE: Can be reorged
    if (block.number >= blockNumber + 1) {
        _creditUser(txHash);
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Chain-specific confirmation requirements
mapping(uint256 => uint256) public requiredConfirmations;

constructor() {
    // Different chains need different confirmations
    requiredConfirmations[1] = 12;       // Ethereum mainnet
    requiredConfirmations[56] = 15;      // BSC
    requiredConfirmations[137] = 256;    // Polygon
    requiredConfirmations[42161] = 0;    // Arbitrum (L1 finality)
}

function processDeposit(
    uint256 sourceChain,
    bytes32 txHash,
    uint256 blockNumber,
    bytes calldata proof
) external {
    uint256 required = requiredConfirmations[sourceChain];
    
    // SECURE: Verify finality via light client
    require(
        lightClient[sourceChain].isFinalized(blockNumber, required),
        "Not finalized"
    );
    
    require(verifyProof(sourceChain, txHash, blockNumber, proof), "Invalid proof");
    
    _creditUser(txHash);
}
```

**Real-World Instances:**
- Multiple bridges exploited via reorg attacks on low-confirmation chains

---

### BRIDGE-AP-24: Reorg Handling Missing

**Description:** Bridge doesn't handle chain reorganizations.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No reorg handling
function recordDeposit(bytes32 txHash, uint256 blockNumber) external {
    deposits[txHash] = Deposit(blockNumber, msg.sender, block.timestamp);
    // VULNERABLE: What if this block gets reorged?
}
```

**Secure Pattern:**
```solidity
// SECURE: Reorg-aware deposit handling
mapping(bytes32 => Deposit) public pendingDeposits;
mapping(bytes32 => bool) public finalizedDeposits;

function recordDeposit(
    bytes32 txHash,
    uint256 blockNumber,
    bytes32 blockHash
) external onlyRelayer {
    pendingDeposits[txHash] = Deposit({
        blockNumber: blockNumber,
        blockHash: blockHash,
        timestamp: block.timestamp,
        finalized: false
    });
    
    emit DepositRecorded(txHash, blockNumber);
}

function finalizeDeposit(
    bytes32 txHash,
    bytes calldata finalityProof
) external {
    Deposit storage deposit = pendingDeposits[txHash];
    require(deposit.timestamp > 0, "Deposit not found");
    require(!deposit.finalized, "Already finalized");
    
    // SECURE: Verify the recorded block is still canonical
    require(
        lightClient.verifyCanonical(deposit.blockNumber, deposit.blockHash, finalityProof),
        "Block not canonical (reorged)"
    );
    
    deposit.finalized = true;
    finalizedDeposits[txHash] = true;
    
    _processDeposit(txHash);
}

// SECURE: Handle reorgs
function reportReorg(bytes32 txHash, bytes calldata reorgProof) external {
    Deposit storage deposit = pendingDeposits[txHash];
    require(!deposit.finalized, "Already finalized");
    
    // Verify the block was reorged out
    require(
        lightClient.verifyReorg(deposit.blockNumber, deposit.blockHash, reorgProof),
        "Block not reorged"
    );
    
    // Cancel the deposit
    delete pendingDeposits[txHash];
    
    emit DepositCancelled(txHash, "Reorg detected");
}
```

---

### BRIDGE-AP-25: Optimistic Finality Without Fraud Proofs

**Description:** Optimistic bridges without proper fraud proof mechanism.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Optimistic without fraud proofs
uint256 public constant CHALLENGE_PERIOD = 7 days;

function submitMessage(bytes32 messageHash) external onlyRelayer {
    messages[messageHash] = Message({
        submittedAt: block.timestamp,
        executed: false
    });
}

function executeMessage(bytes32 messageHash) external {
    Message storage msg = messages[messageHash];
    require(block.timestamp >= msg.submittedAt + CHALLENGE_PERIOD, "Still in challenge period");
    // VULNERABLE: No fraud proof mechanism
    _execute(messageHash);
}
```

**Secure Pattern:**
```solidity
// SECURE: Full fraud proof system
function submitMessage(
    bytes32 messageHash,
    bytes calldata message,
    bytes calldata stateProof
) external {
    require(relayerBond[msg.sender] >= REQUIRED_BOND, "Insufficient bond");
    
    messages[messageHash] = Message({
        submitter: msg.sender,
        submittedAt: block.timestamp,
        message: message,
        stateProof: stateProof,
        challenged: false,
        executed: false
    });
}

function challengeMessage(
    bytes32 messageHash,
    bytes calldata fraudProof
) external {
    Message storage msg = messages[messageHash];
    require(!msg.executed, "Already executed");
    require(
        block.timestamp < msg.submittedAt + CHALLENGE_PERIOD,
        "Challenge period ended"
    );
    
    // SECURE: Verify fraud proof
    require(verifyFraudProof(msg.message, msg.stateProof, fraudProof), "Invalid fraud proof");
    
    // SECURE: Slash submitter
    uint256 bond = relayerBond[msg.submitter];
    relayerBond[msg.submitter] = 0;
    
    // Reward challenger
    payable(msg.sender).transfer(bond / 2);
    // Rest goes to treasury
    payable(treasury).transfer(bond / 2);
    
    // Cancel message
    msg.challenged = true;
    
    emit MessageChallenged(messageHash, msg.sender);
}

function executeMessage(bytes32 messageHash) external {
    Message storage msg = messages[messageHash];
    require(!msg.executed, "Already executed");
    require(!msg.challenged, "Message challenged");
    require(
        block.timestamp >= msg.submittedAt + CHALLENGE_PERIOD,
        "Challenge period not ended"
    );
    
    msg.executed = true;
    _execute(msg.message);
}
```

---

### BRIDGE-AP-26: L1/L2 Message Race Condition

**Description:** Race conditions between L1 and L2 message processing.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// L1 Contract
function initiateWithdrawal(uint256 amount) external {
    l2Messenger.sendMessage(abi.encode(msg.sender, amount));
    // VULNERABLE: L2 might process before L1 state is finalized
}

// L2 Contract  
function processWithdrawal(address user, uint256 amount) external onlyL1Messenger {
    // VULNERABLE: What if L1 reverts?
    _credit(user, amount);
}
```

**Secure Pattern:**
```solidity
// L1 Contract - SECURE
function initiateWithdrawal(uint256 amount) external {
    // SECURE: Lock funds first
    token.transferFrom(msg.sender, address(this), amount);
    
    bytes32 withdrawalId = keccak256(abi.encode(
        msg.sender,
        amount,
        block.number,
        withdrawalNonce++
    ));
    
    pendingWithdrawals[withdrawalId] = PendingWithdrawal({
        user: msg.sender,
        amount: amount,
        initiated: block.timestamp,
        completed: false
    });
    
    // Send message to L2
    l2Messenger.sendMessage(abi.encode(withdrawalId, msg.sender, amount));
}

// L2 Contract - SECURE
function processWithdrawal(
    bytes32 withdrawalId,
    address user,
    uint256 amount
) external onlyL1Messenger {
    // SECURE: Record but don't execute immediately
    pendingCredits[withdrawalId] = PendingCredit({
        user: user,
        amount: amount,
        l1Confirmed: false
    });
}

function finalizeWithdrawal(
    bytes32 withdrawalId,
    bytes calldata l1FinalityProof
) external {
    PendingCredit storage credit = pendingCredits[withdrawalId];
    require(!credit.l1Confirmed, "Already confirmed");
    
    // SECURE: Verify L1 finality
    require(
        l1LightClient.verifyFinalizedWithdrawal(withdrawalId, l1FinalityProof),
        "L1 not finalized"
    );
    
    credit.l1Confirmed = true;
    _credit(credit.user, credit.amount);
}
```

---

### BRIDGE-AP-27: Timestamp Manipulation

**Description:** Relying on timestamps for finality decisions.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Uses block.timestamp which can be manipulated
function isFinalized(uint256 depositTime) public view returns (bool) {
    return block.timestamp >= depositTime + FINALITY_DELAY;
    // VULNERABLE: Miners can manipulate timestamp slightly
}
```

**Secure Pattern:**
```solidity
// SECURE: Use block numbers instead of timestamps
function isFinalized(uint256 depositBlock) public view returns (bool) {
    return block.number >= depositBlock + FINALITY_BLOCKS;
}

// Or combine both for safety
function isFinalized(uint256 depositBlock, uint256 depositTime) public view returns (bool) {
    // SECURE: Both conditions must be met
    return block.number >= depositBlock + FINALITY_BLOCKS &&
           block.timestamp >= depositTime + FINALITY_DELAY;
}
```

---

### BRIDGE-AP-28: No Finality Proof Verification

**Description:** Accepting finality claims without cryptographic verification.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Trusts relayer's claim
function processFinalized(
    bytes32 blockHash,
    bool isFinalized
) external onlyRelayer {
    if (isFinalized) {
        finalizedBlocks[blockHash] = true;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Cryptographic finality verification
function processFinalized(
    bytes32 blockHash,
    bytes calldata finalityProof,
    bytes[] calldata validatorSignatures
) external {
    // SECURE: Verify finality proof matches source chain consensus
    require(
        verifyConsensusProof(blockHash, finalityProof),
        "Invalid consensus proof"
    );
    
    // SECURE: Verify validator signatures on finality attestation
    bytes32 attestation = keccak256(abi.encode(
        "FINALITY",
        sourceChainId,
        blockHash
    ));
    
    require(
        verifyValidatorSignatures(attestation, validatorSignatures),
        "Invalid validator signatures"
    );
    
    finalizedBlocks[blockHash] = true;
    
    emit BlockFinalized(blockHash);
}
```

---

## Token Anti-Patterns

### BRIDGE-AP-29: Wrapped Token Mint Without Verification

**Description:** Minting wrapped tokens without verifying lock on source chain.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Mints without verification
function mint(address to, uint256 amount) external onlyRelayer {
    // VULNERABLE: No proof that tokens were locked on source chain
    wrappedToken.mint(to, amount);
}
```

**Secure Pattern:**
```solidity
function mint(
    address to,
    uint256 amount,
    bytes32 lockTxHash,
    bytes calldata lockProof
) external {
    // SECURE: Verify lock on source chain
    require(
        verifyLockTransaction(lockTxHash, to, amount, lockProof),
        "Invalid lock proof"
    );
    
    // SECURE: Prevent double-mint
    require(!processedLocks[lockTxHash], "Already processed");
    processedLocks[lockTxHash] = true;
    
    wrappedToken.mint(to, amount);
    
    emit TokensMinted(to, amount, lockTxHash);
}
```

---

### BRIDGE-AP-30: Wrapped/Native Token Accounting Mismatch

**Description:** Mismatch between locked native tokens and minted wrapped tokens.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No tracking of total locked vs minted
function lock(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    // Send message to mint on destination
}

function unlock(uint256 amount) external {
    // VULNERABLE: No check if enough is locked
    token.transfer(msg.sender, amount);
}
```

**Secure Pattern:**
```solidity
uint256 public totalLocked;
uint256 public totalMinted;  // Tracked via cross-chain messages

function lock(uint256 amount) external {
    uint256 balanceBefore = token.balanceOf(address(this));
    token.transferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - balanceBefore;
    
    totalLocked += received;
    
    // SECURE: Emit event for cross-chain tracking
    emit TokensLocked(msg.sender, received, totalLocked);
}

function unlock(address to, uint256 amount, bytes calldata burnProof) external {
    // SECURE: Verify burn on other chain
    require(verifyBurn(burnProof, amount), "Invalid burn proof");
    
    // SECURE: Check liquidity
    require(totalLocked >= amount, "Insufficient locked tokens");
    
    totalLocked -= amount;
    token.transfer(to, amount);
    
    emit TokensUnlocked(to, amount, totalLocked);
}

// SECURE: Invariant check
function checkInvariant() external view returns (bool) {
    return totalLocked == token.balanceOf(address(this));
}
```

---

### BRIDGE-AP-31: Fee-on-Transfer Token Handling

**Description:** Bridge doesn't account for fee-on-transfer tokens.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Assumes full amount received
function lockTokens(address token, uint256 amount) external {
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    // VULNERABLE: If token has transfer fee, received less than amount
    _sendMintMessage(msg.sender, amount);
}
```

**Secure Pattern:**
```solidity
function lockTokens(address token, uint256 amount) external {
    uint256 balanceBefore = IERC20(token).balanceOf(address(this));
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    uint256 balanceAfter = IERC20(token).balanceOf(address(this));
    
    // SECURE: Use actual received amount
    uint256 received = balanceAfter - balanceBefore;
    require(received > 0, "No tokens received");
    
    _sendMintMessage(msg.sender, received);
}
```

---

### BRIDGE-AP-32: Rebasing Token Handling

**Description:** Bridge doesn't handle rebasing tokens correctly.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Stores amount, not shares
mapping(address => uint256) public deposits;

function deposit(uint256 amount) external {
    rebasingToken.transferFrom(msg.sender, address(this), amount);
    deposits[msg.sender] += amount;  // VULNERABLE: Amount will change with rebase
}

function withdraw() external {
    uint256 amount = deposits[msg.sender];
    deposits[msg.sender] = 0;
    rebasingToken.transfer(msg.sender, amount);  // May fail after rebase
}
```

**Secure Pattern:**
```solidity
// SECURE: Track shares, not amounts
mapping(address => uint256) public depositShares;

function deposit(uint256 amount) external {
    uint256 shares = rebasingToken.getSharesByPooledEth(amount);
    rebasingToken.transferFrom(msg.sender, address(this), amount);
    depositShares[msg.sender] += shares;
}

function withdraw() external {
    uint256 shares = depositShares[msg.sender];
    depositShares[msg.sender] = 0;
    
    uint256 amount = rebasingToken.getPooledEthByShares(shares);
    rebasingToken.transfer(msg.sender, amount);
}
```

---

### BRIDGE-AP-33: Token Decimal Mismatch

**Description:** Different decimal precision between chains causes errors.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No decimal normalization
function bridgeTokens(address token, uint256 amount) external {
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    // VULNERABLE: Destination chain might have different decimals
    _sendMessage(destChain, token, amount);
}
```

**Secure Pattern:**
```solidity
// SECURE: Normalize to standard precision
uint8 public constant STANDARD_DECIMALS = 18;

mapping(address => uint8) public tokenDecimals;
mapping(uint256 => mapping(address => uint8)) public destTokenDecimals;

function bridgeTokens(
    address token, 
    uint256 amount,
    uint256 destChain
) external {
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    
    // SECURE: Normalize amount
    uint8 sourceDecimals = tokenDecimals[token];
    uint8 destDecimals = destTokenDecimals[destChain][token];
    
    uint256 normalizedAmount;
    if (sourceDecimals > destDecimals) {
        uint256 factor = 10 ** (sourceDecimals - destDecimals);
        normalizedAmount = amount / factor;
        // SECURE: Check for dust
        require(normalizedAmount > 0, "Amount too small");
        // Refund dust
        uint256 dust = amount - (normalizedAmount * factor);
        if (dust > 0) {
            IERC20(token).transfer(msg.sender, dust);
        }
    } else {
        uint256 factor = 10 ** (destDecimals - sourceDecimals);
        normalizedAmount = amount * factor;
    }
    
    _sendMessage(destChain, token, normalizedAmount);
}
```

---

### BRIDGE-AP-34: Non-Standard Token Behavior

**Description:** Bridge doesn't handle tokens with non-standard behavior.

**Severity:** Medium

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Assumes standard ERC20 behavior
function bridgeToken(address token, uint256 amount) external {
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    // VULNERABLE: Some tokens don't return bool
    // VULNERABLE: Some tokens have blocklists
    // VULNERABLE: Some tokens have transfer limits
}
```

**Secure Pattern:**
```solidity
// SECURE: Use SafeERC20 and validate token
using SafeERC20 for IERC20;

mapping(address => bool) public approvedTokens;
mapping(address => TokenConfig) public tokenConfigs;

struct TokenConfig {
    bool hasFeeOnTransfer;
    bool isRebasing;
    bool hasBlocklist;
    uint256 maxTransferAmount;
}

function bridgeToken(address token, uint256 amount) external {
    require(approvedTokens[token], "Token not approved");
    
    TokenConfig memory config = tokenConfigs[token];
    
    // SECURE: Check transfer limits
    if (config.maxTransferAmount > 0) {
        require(amount <= config.maxTransferAmount, "Exceeds max transfer");
    }
    
    uint256 balanceBefore = IERC20(token).balanceOf(address(this));
    
    // SECURE: SafeERC20 handles non-standard returns
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    
    uint256 received = IERC20(token).balanceOf(address(this)) - balanceBefore;
    
    _sendMessage(token, received, config);
}
```

---

## Liquidity Anti-Patterns

### BRIDGE-AP-35: Liquidity Pool Drain

**Description:** Bridge liquidity pool can be drained through exploits.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No rate limiting
function withdraw(uint256 amount) external {
    require(verifyWithdrawal(msg.sender, amount), "Invalid");
    // VULNERABLE: Can drain entire pool in one tx
    token.transfer(msg.sender, amount);
}
```

**Secure Pattern:**
```solidity
// SECURE: Rate limiting and circuit breakers
uint256 public constant HOURLY_LIMIT = 1000000e18;
uint256 public constant DAILY_LIMIT = 10000000e18;

mapping(uint256 => uint256) public hourlyWithdrawn;
mapping(uint256 => uint256) public dailyWithdrawn;

function withdraw(uint256 amount) external {
    require(verifyWithdrawal(msg.sender, amount), "Invalid");
    
    uint256 currentHour = block.timestamp / 1 hours;
    uint256 currentDay = block.timestamp / 1 days;
    
    // SECURE: Hourly limit
    require(
        hourlyWithdrawn[currentHour] + amount <= HOURLY_LIMIT,
        "Hourly limit exceeded"
    );
    hourlyWithdrawn[currentHour] += amount;
    
    // SECURE: Daily limit
    require(
        dailyWithdrawn[currentDay] + amount <= DAILY_LIMIT,
        "Daily limit exceeded"
    );
    dailyWithdrawn[currentDay] += amount;
    
    // SECURE: Per-transaction limit
    require(amount <= MAX_SINGLE_WITHDRAWAL, "Amount too large");
    
    token.transfer(msg.sender, amount);
    
    emit Withdrawal(msg.sender, amount);
}

// SECURE: Circuit breaker
function emergencyPause() external {
    uint256 currentHour = block.timestamp / 1 hours;
    
    if (hourlyWithdrawn[currentHour] > HOURLY_LIMIT * 80 / 100) {
        _pause();
        emit EmergencyPauseTriggered("High withdrawal volume");
    }
}
```

---

### BRIDGE-AP-36: Asymmetric Liquidity Attack

**Description:** Attacker exploits liquidity imbalances across chains.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No cross-chain liquidity check
function swap(uint256 amount, uint256 destChain) external {
    token.transferFrom(msg.sender, address(this), amount);
    // VULNERABLE: Destination might not have liquidity
    _sendSwapMessage(destChain, msg.sender, amount);
}
```

**Secure Pattern:**
```solidity
// SECURE: Track cross-chain liquidity
mapping(uint256 => uint256) public chainLiquidity;
mapping(uint256 => uint256) public pendingOutflows;

function swap(uint256 amount, uint256 destChain) external {
    // SECURE: Check destination has liquidity
    uint256 availableLiquidity = chainLiquidity[destChain] - pendingOutflows[destChain];
    require(availableLiquidity >= amount, "Insufficient destination liquidity");
    
    // SECURE: Reserve liquidity
    pendingOutflows[destChain] += amount;
    
    token.transferFrom(msg.sender, address(this), amount);
    chainLiquidity[block.chainid] += amount;
    
    _sendSwapMessage(destChain, msg.sender, amount);
}

// Called when swap completes on destination
function confirmSwap(uint256 sourceChain, uint256 amount) external onlyBridge {
    pendingOutflows[block.chainid] -= amount;
    chainLiquidity[block.chainid] -= amount;
}
```

---

### BRIDGE-AP-37: LP Token Price Manipulation

**Description:** Bridge LP tokens can have their price manipulated.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: LP price from spot reserves
function getLPPrice() public view returns (uint256) {
    return totalAssets() * 1e18 / totalSupply();
    // VULNERABLE: totalAssets() can be manipulated
}
```

**Secure Pattern:**
```solidity
// SECURE: TWAP-based LP pricing
function getLPPrice() public view returns (uint256) {
    // SECURE: Use time-weighted assets
    uint256 twapAssets = getTwapAssets(30 minutes);
    uint256 supply = totalSupply();
    
    if (supply == 0) return 1e18;
    
    uint256 lpPrice = twapAssets * 1e18 / supply;
    
    // SECURE: Sanity check against last known price
    require(
        lpPrice > lastLPPrice * 90 / 100 &&
        lpPrice < lastLPPrice * 110 / 100,
        "Price deviation too high"
    );
    
    return lpPrice;
}
```

---

### BRIDGE-AP-38: Deposit/Withdrawal Frontrunning

**Description:** LP deposits/withdrawals can be frontrun for profit.

**Severity:** Medium

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No protection against frontrunning
function deposit(uint256 amount) external returns (uint256 shares) {
    shares = amount * totalSupply() / totalAssets();
    token.transferFrom(msg.sender, address(this), amount);
    _mint(msg.sender, shares);
}
```

**Secure Pattern:**
```solidity
// SECURE: Slippage protection + commit-reveal
mapping(address => DepositRequest) public pendingDeposits;

function requestDeposit(uint256 amount, uint256 minShares) external {
    pendingDeposits[msg.sender] = DepositRequest({
        amount: amount,
        minShares: minShares,
        requestTime: block.timestamp
    });
    
    token.transferFrom(msg.sender, address(this), amount);
}

function executeDeposit() external {
    DepositRequest memory request = pendingDeposits[msg.sender];
    require(request.amount > 0, "No pending deposit");
    require(
        block.timestamp >= request.requestTime + DEPOSIT_DELAY,
        "Too early"
    );
    
    delete pendingDeposits[msg.sender];
    
    uint256 shares = request.amount * totalSupply() / totalAssets();
    
    // SECURE: Slippage protection
    require(shares >= request.minShares, "Slippage too high");
    
    _mint(msg.sender, shares);
}
```

---

### BRIDGE-AP-39: Accounting Precision Loss

**Description:** Share/asset calculations lose precision over time.

**Severity:** Medium

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Precision loss accumulates
function deposit(uint256 assets) external returns (uint256 shares) {
    shares = assets * totalShares / totalAssets;  // Rounds down
    // Many small deposits accumulate precision loss
}
```

**Secure Pattern:**
```solidity
// SECURE: Virtual offset for precision
uint256 internal constant PRECISION_OFFSET = 1e6;

function deposit(uint256 assets) external returns (uint256 shares) {
    // SECURE: Use offset to prevent precision attacks
    shares = (assets * (totalShares + PRECISION_OFFSET)) / (totalAssets + PRECISION_OFFSET);
    
    require(shares > 0, "Zero shares");
    
    _mint(msg.sender, shares);
    
    // SECURE: Verify exchange rate didn't change significantly
    uint256 newRate = (totalAssets + assets) * 1e18 / (totalShares + shares);
    require(
        newRate >= lastRate * 999 / 1000,
        "Rate decreased too much"
    );
}
```

---

### BRIDGE-AP-40: First Depositor Inflation Attack

**Description:** First depositor can manipulate share price to steal from others.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No protection for first deposit
function deposit(uint256 assets) external returns (uint256 shares) {
    if (totalSupply() == 0) {
        shares = assets;  // VULNERABLE: Attacker deposits 1 wei
    } else {
        shares = assets * totalSupply() / totalAssets();
    }
    _mint(msg.sender, shares);
}
// Attack: Deposit 1 wei, donate large amount, second depositor gets 0 shares
```

**Secure Pattern:**
```solidity
uint256 public constant MINIMUM_LIQUIDITY = 1000;

function deposit(uint256 assets) external returns (uint256 shares) {
    require(assets > 0, "Zero assets");
    
    if (totalSupply() == 0) {
        // SECURE: Burn minimum liquidity
        shares = assets - MINIMUM_LIQUIDITY;
        require(shares > 0, "Insufficient initial deposit");
        _mint(address(0xdead), MINIMUM_LIQUIDITY);
    } else {
        shares = assets * totalSupply() / totalAssets();
        require(shares > 0, "Zero shares calculated");
    }
    
    token.transferFrom(msg.sender, address(this), assets);
    _mint(msg.sender, shares);
}
```

---

## Governance Anti-Patterns

### BRIDGE-AP-41: Unprotected Admin Functions

**Description:** Critical admin functions without proper access control.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Single admin with no timelock
function setValidator(address validator, bool status) external onlyOwner {
    isValidator[validator] = status;  // Instant change
}

function setThreshold(uint256 _threshold) external onlyOwner {
    threshold = _threshold;  // Can be set to 1
}
```

**Secure Pattern:**
```solidity
// SECURE: Multi-sig + timelock + constraints
uint256 public constant TIMELOCK_DELAY = 2 days;

struct PendingChange {
    bytes32 changeType;
    bytes data;
    uint256 executeAfter;
    bool executed;
}

mapping(uint256 => PendingChange) public pendingChanges;

function proposeValidatorChange(address validator, bool status) 
    external 
    onlyMultisig 
{
    uint256 id = ++changeNonce;
    pendingChanges[id] = PendingChange({
        changeType: "VALIDATOR",
        data: abi.encode(validator, status),
        executeAfter: block.timestamp + TIMELOCK_DELAY,
        executed: false
    });
    
    emit ChangeProposed(id, "VALIDATOR", abi.encode(validator, status));
}

function executeChange(uint256 id) external {
    PendingChange storage change = pendingChanges[id];
    require(!change.executed, "Already executed");
    require(block.timestamp >= change.executeAfter, "Too early");
    
    change.executed = true;
    
    if (change.changeType == "VALIDATOR") {
        (address validator, bool status) = abi.decode(change.data, (address, bool));
        
        // SECURE: Additional constraints
        if (!status) {
            require(validatorCount > MIN_VALIDATORS, "Too few validators");
        }
        
        isValidator[validator] = status;
    }
    
    emit ChangeExecuted(id);
}
```

---

### BRIDGE-AP-42: Emergency Pause Abuse

**Description:** Emergency pause can be misused to freeze user funds.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Indefinite pause with no escape
function pause() external onlyOwner {
    _pause();  // Can pause forever
}

function withdraw() external whenNotPaused {
    // Users can never withdraw if paused
}
```

**Secure Pattern:**
```solidity
// SECURE: Time-limited pause with escape hatch
uint256 public pausedAt;
uint256 public constant MAX_PAUSE_DURATION = 7 days;

function pause() external onlyEmergencyAdmin {
    require(!paused(), "Already paused");
    pausedAt = block.timestamp;
    _pause();
    
    emit Paused(msg.sender, pausedAt);
}

function unpause() external onlyMultisig {
    _unpause();
    pausedAt = 0;
}

// SECURE: Auto-unpause after max duration
function forceUnpause() external {
    require(paused(), "Not paused");
    require(
        block.timestamp >= pausedAt + MAX_PAUSE_DURATION,
        "Max pause duration not reached"
    );
    
    _unpause();
    pausedAt = 0;
    
    emit ForcedUnpause(block.timestamp);
}

// SECURE: Emergency withdrawal even when paused
function emergencyWithdraw() external {
    require(
        paused() && block.timestamp >= pausedAt + EMERGENCY_WITHDRAW_DELAY,
        "Not available"
    );
    
    uint256 amount = userDeposits[msg.sender];
    userDeposits[msg.sender] = 0;
    token.transfer(msg.sender, amount);
}
```

---

### BRIDGE-AP-43: Upgrade Without Migration

**Description:** Contract upgraded without proper state migration.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Upgrade changes storage layout
contract BridgeV1 {
    address public owner;
    mapping(address => uint256) public balances;
}

contract BridgeV2 {
    // VULNERABLE: New variable shifts storage
    bool public paused;  // Now at slot 0!
    address public owner;  // Shifted to slot 1
    mapping(address => uint256) public balances;  // Shifted
}
```

**Secure Pattern:**
```solidity
// SECURE: Storage gap pattern
contract BridgeV1 {
    address public owner;
    mapping(address => uint256) public balances;
    
    // SECURE: Reserve storage slots for future use
    uint256[50] private __gap;
}

contract BridgeV2 {
    address public owner;
    mapping(address => uint256) public balances;
    
    // SECURE: New variables use gap slots
    bool public paused;  // Uses first gap slot
    
    uint256[49] private __gap;  // Reduced by 1
}

// SECURE: Migration function
function migrate() external onlyOwner {
    require(!migrated, "Already migrated");
    migrated = true;
    
    // Perform any necessary state migrations
    _migrateState();
}
```

---

### BRIDGE-AP-44: Governance Token Flash Loan Attack

**Description:** Flash loaning governance tokens to pass malicious proposals.

**Severity:** Critical

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Snapshot at vote time
function vote(uint256 proposalId, bool support) external {
    uint256 votes = govToken.balanceOf(msg.sender);  // Current balance
    proposals[proposalId].votes += votes;
}
```

**Secure Pattern:**
```solidity
// SECURE: Snapshot before proposal
function propose(bytes calldata action) external returns (uint256) {
    uint256 proposalId = ++proposalCount;
    
    proposals[proposalId] = Proposal({
        action: action,
        snapshotBlock: block.number - 1,  // SECURE: Past block
        votingEnds: block.timestamp + VOTING_PERIOD,
        executed: false
    });
    
    return proposalId;
}

function vote(uint256 proposalId, bool support) external {
    Proposal storage proposal = proposals[proposalId];
    
    // SECURE: Use historical balance
    uint256 votes = govToken.getPastVotes(msg.sender, proposal.snapshotBlock);
    
    require(votes > 0, "No voting power");
    require(!hasVoted[proposalId][msg.sender], "Already voted");
    
    hasVoted[proposalId][msg.sender] = true;
    
    if (support) {
        proposal.forVotes += votes;
    } else {
        proposal.againstVotes += votes;
    }
}
```

---

### BRIDGE-AP-45: Missing Rate Limiting on Critical Actions

**Description:** Critical actions can be performed too frequently.

**Severity:** High

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No rate limiting
function updateValidators(address[] calldata newValidators) external onlyGovernance {
    // Can be called multiple times rapidly
    validators = newValidators;
}
```

**Secure Pattern:**
```solidity
// SECURE: Rate limiting on critical actions
mapping(bytes4 => uint256) public lastActionTime;
mapping(bytes4 => uint256) public actionCooldown;

modifier rateLimited(bytes4 action) {
    require(
        block.timestamp >= lastActionTime[action] + actionCooldown[action],
        "Action on cooldown"
    );
    lastActionTime[action] = block.timestamp;
    _;
}

constructor() {
    actionCooldown[this.updateValidators.selector] = 7 days;
    actionCooldown[this.updateThreshold.selector] = 3 days;
    actionCooldown[this.updateFees.selector] = 1 days;
}

function updateValidators(address[] calldata newValidators) 
    external 
    onlyGovernance 
    rateLimited(this.updateValidators.selector)
{
    validators = newValidators;
}
```

---

## Quick Reference Table

| ID | Name | Severity | Category |
|----|------|----------|----------|
| BRIDGE-AP-01 | Missing Signature Verification | Critical | Signature |
| BRIDGE-AP-02 | Signature Replay | Critical | Signature |
| BRIDGE-AP-03 | Cross-Chain Replay | Critical | Signature |
| BRIDGE-AP-04 | Insufficient Threshold | Critical | Signature |
| BRIDGE-AP-05 | Validator Key Compromise | Critical | Signature |
| BRIDGE-AP-06 | Signature Malleability | High | Signature |
| BRIDGE-AP-07 | Missing Uniqueness Check | Critical | Signature |
| BRIDGE-AP-08 | Precompile Issues | High | Signature |
| BRIDGE-AP-09 | Arbitrary Execution | Critical | Message |
| BRIDGE-AP-10 | Hash Collision | Critical | Message |
| BRIDGE-AP-11 | Missing Sequence | High | Message |
| BRIDGE-AP-12 | Source Chain Spoofing | Critical | Message |
| BRIDGE-AP-13 | Return Value Unchecked | High | Message |
| BRIDGE-AP-14 | Message Reentrancy | Critical | Message |
| BRIDGE-AP-15 | No Expiration | Medium | Message |
| BRIDGE-AP-16 | Centralized Validators | Critical | Validator |
| BRIDGE-AP-17 | Liveness Failure | High | Validator |
| BRIDGE-AP-18 | Slashing Evasion | High | Validator |
| BRIDGE-AP-19 | Relayer Censorship | Medium | Validator |
| BRIDGE-AP-20 | Oracle Manipulation | High | Validator |
| BRIDGE-AP-21 | Hot Wallet Concentration | Critical | Validator |
| BRIDGE-AP-22 | No Rotation | Medium | Validator |
| BRIDGE-AP-23 | Insufficient Confirmations | Critical | Finality |
| BRIDGE-AP-24 | No Reorg Handling | Critical | Finality |
| BRIDGE-AP-25 | No Fraud Proofs | Critical | Finality |
| BRIDGE-AP-26 | L1/L2 Race Condition | High | Finality |
| BRIDGE-AP-27 | Timestamp Manipulation | High | Finality |
| BRIDGE-AP-28 | No Finality Proof | Critical | Finality |
| BRIDGE-AP-29 | Mint Without Verification | Critical | Token |
| BRIDGE-AP-30 | Accounting Mismatch | Critical | Token |
| BRIDGE-AP-31 | Fee-on-Transfer | High | Token |
| BRIDGE-AP-32 | Rebasing Token | High | Token |
| BRIDGE-AP-33 | Decimal Mismatch | High | Token |
| BRIDGE-AP-34 | Non-Standard Token | Medium | Token |
| BRIDGE-AP-35 | Liquidity Drain | Critical | Liquidity |
| BRIDGE-AP-36 | Asymmetric Liquidity | High | Liquidity |
| BRIDGE-AP-37 | LP Price Manipulation | Critical | Liquidity |
| BRIDGE-AP-38 | Deposit Frontrunning | Medium | Liquidity |
| BRIDGE-AP-39 | Precision Loss | Medium | Liquidity |
| BRIDGE-AP-40 | First Depositor Attack | Critical | Liquidity |
| BRIDGE-AP-41 | Unprotected Admin | Critical | Governance |
| BRIDGE-AP-42 | Pause Abuse | High | Governance |
| BRIDGE-AP-43 | Upgrade Without Migration | Critical | Governance |
| BRIDGE-AP-44 | Governance Flash Loan | Critical | Governance |
| BRIDGE-AP-45 | No Rate Limiting | High | Governance |

---

## See Also

- **Attack Tree:** [bridge-attack-tree.md](../attack-trees/bridge-attack-tree.md)
- **Bridge Patterns:** [bridge-patterns.md](../patterns/bridge-patterns.md)
- **Signature Patterns:** [signature-patterns.md](../patterns/signature-patterns.md)
- **Related:** [cross-chain-patterns.md](../patterns/cross-chain-patterns.md)

---

**Last Updated:** 2025
**Version:** 1.0
