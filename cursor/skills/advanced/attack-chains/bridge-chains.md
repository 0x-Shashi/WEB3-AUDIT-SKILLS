# Bridge Attack Chains

## Overview

Bridges connect blockchains and handle massive value. Attacks can:

- Drain bridge reserves
- Mint unbacked tokens
- Steal cross-chain messages
- Exploit finality differences

---

## Chain 1: Signature Replay + Cross-Chain Mint

**Components:**
1. Signature-based verification
2. No nonce or chain ID in signature
3. Mint on destination chain

**Attack Flow:**
```
1. Capture valid bridge signature on Chain A
2. Replay signature on Chain B
3. Mint tokens on Chain B
4. Repeat across all supported chains
```

**Real Example:** Wormhole ($326M), Ronin ($625M)

**Vulnerable Pattern:**
```solidity
function processMessage(bytes memory message, bytes memory signature) {
    address signer = recoverSigner(message, signature);
    require(validators[signer], "Invalid validator");
    // No chain ID check!
    // No nonce check!
    mint(parseAmount(message), parseRecipient(message));
}
```

**Secure Pattern:**
```solidity
function processMessage(bytes memory message, bytes memory signature) {
    // Decode with chain ID and nonce
    (uint256 chainId, uint256 nonce, address recipient, uint256 amount) = 
        abi.decode(message, (uint256, uint256, address, uint256));
    
    require(chainId == block.chainid, "Wrong chain");
    require(!usedNonces[nonce], "Replay");
    usedNonces[nonce] = true;
    
    address signer = recoverSigner(message, signature);
    require(validators[signer], "Invalid validator");
    
    mint(amount, recipient);
}
```

---

## Chain 2: Fake Proof + Optimistic Bridge

**Components:**
1. Optimistic bridge with challenge period
2. Insufficient proof verification
3. Challenge can be DOSed

**Attack Flow:**
```
1. Submit fake withdrawal proof
2. DOS challengers (gas griefing, etc.)
3. Wait for challenge period to expire
4. Claim funds with unchallenged fake proof
```

**Detection:**
```solidity
// Check challenge mechanism
function challenge(bytes32 messageHash, bytes memory proof) {
    // Is this DOSable?
    // Is proof verification sufficient?
}
```

**Mitigation:**
- Robust fraud proof verification
- Multiple challengers
- Challenge incentives
- Emergency pause mechanism

---

## Chain 3: Finality Difference + Double Spend

**Components:**
1. Chain A has fast finality (PoS)
2. Chain B has slow finality (PoW)
3. Bridge doesn't wait for finality

**Attack Flow:**
```
1. Send tx on Chain B (slow finality)
2. Bridge processes before finality
3. Tokens minted on Chain A
4. Reorg/rollback on Chain B
5. Original tx invalidated, tokens already minted
```

**Real Example:** Ethereum Classic 51% attacks

**Vulnerable Pattern:**
```solidity
// Listening to Chain B events
function onEvent(bytes memory proof) {
    // Only checks 1 confirmation
    require(verifyProof(proof), "Invalid");
    mint(...);
}
```

**Secure Pattern:**
```solidity
// Require sufficient confirmations
uint256 constant REQUIRED_CONFIRMATIONS = 64;

function onEvent(bytes memory proof, uint256 blockNumber) {
    require(
        getConfirmations(blockNumber) >= REQUIRED_CONFIRMATIONS,
        "Insufficient confirmations"
    );
    // Process...
}
```

---

## Chain 4: Admin Key Compromise + Unlimited Mint

**Components:**
1. Centralized bridge with admin keys
2. Admin can mint arbitrarily
3. Poor key management

**Attack Flow:**
```
1. Compromise admin private key (phishing, hack)
2. Mint unlimited tokens on destination
3. Dump on markets before detected
```

**Real Example:** Ronin ($625M)

**Mitigation:**
- Multi-signature requirements (5/9+)
- Hardware security modules
- Timelock on admin actions
- Rate limiting on mints

---

## Chain 5: L1L2 Message Spoofing

**Components:**
1. L1 to L2 message passing
2. Insufficient sender verification
3. Anyone can send messages

**Attack Flow:**
```
1. Send fake message from L1
2. L2 contract trusts the message
3. Execute malicious action on L2
```

**Vulnerable Pattern (L2):**
```solidity
function onL1Message(address l1Sender, bytes memory data) {
    // Not checking if l1Sender is the real bridge!
    processData(data);
}
```

**Secure Pattern:**
```solidity
function onL1Message(address l1Sender, bytes memory data) {
    require(l1Sender == trustedL1Bridge, "Invalid sender");
    require(msg.sender == l2Messenger, "Invalid messenger");
    processData(data);
}
```

---

## Chain 6: Withdrawal Proof Forgery

**Components:**
1. Merkle proof verification
2. Weak proof validation
3. State manipulation

**Attack Flow:**
```
1. Craft fake Merkle proof
2. Claim non-existent deposits
3. Withdraw funds from bridge
```

**Real Example:** Nomad ($190M)

**Vulnerable Pattern:**
```solidity
// The actual Nomad bug (simplified)
function process(bytes32 _messageHash) {
    // messages[_messageHash] was 0 (uninitialized)
    // But 0 was accidentally set as PROVEN status!
    require(messages[_messageHash] == PROVEN);  // 0 == 0, passes!
}
```

**Secure Pattern:**
```solidity
function process(bytes32 _messageHash, bytes memory _proof) {
    require(messages[_messageHash] == UNPROCESSED);
    require(verifyMerkleProof(_messageHash, _proof, root));
    messages[_messageHash] = PROCESSED;
}
```

---

## Chain 7: Token Mapping Confusion

**Components:**
1. Bridge maps tokens between chains
2. Attacker deploys fake token
3. Bridge accepts fake as real

**Attack Flow:**
```
1. Deploy token on Chain A with same symbol as legit token
2. Bridge maps your token to real token on Chain B
3. Deposit worthless fake tokens
4. Withdraw real tokens on Chain B
```

**Mitigation:**
- Whitelist-only token support
- Canonical token registries
- Careful mapping verification

---

## Bridge Security Checklist

### Message Verification
- [ ] Chain ID in signed messages
- [ ] Nonce to prevent replay
- [ ] Multi-sig requirement
- [ ] Threshold high enough (5/9+)

### Finality
- [ ] Sufficient confirmations required
- [ ] Chain-specific confirmation counts
- [ ] Handling of reorgs

### Access Control
- [ ] Admin keys in multi-sig
- [ ] Timelock on sensitive operations
- [ ] Rate limiting on mints/burns
- [ ] Emergency pause mechanism

### Proof Verification
- [ ] Merkle proofs validated
- [ ] State roots verified
- [ ] Fraud proof system if optimistic

---

## Bridge Attack Statistics

| Bridge | Date | Loss | Root Cause |
|--------|------|------|------------|
| Ronin | Mar 2022 | $625M | Admin key compromise |
| Wormhole | Feb 2022 | $326M | Signature bypass |
| Nomad | Aug 2022 | $190M | Proof verification |
| Harmony | Jun 2022 | $100M | Admin key compromise |
| BNB Bridge | Oct 2022 | $586M | Proof verification |

---

## Detection Commands

```bash
# Find message verification
grep -rn "ecrecover\|ECDSA\|verify.*signature" --include="*.sol"

# Find replay protection
grep -rn "nonce\|chainId\|chain.*id" --include="*.sol"

# Find admin functions
grep -rn "onlyOwner\|onlyAdmin\|admin.*only" --include="*.sol"

# Find proof verification
grep -rn "merkle\|proof\|verify.*root" --include="*.sol"

# Find message handlers
grep -rn "onMessage\|handleMessage\|receiveMessage" --include="*.sol"
```
