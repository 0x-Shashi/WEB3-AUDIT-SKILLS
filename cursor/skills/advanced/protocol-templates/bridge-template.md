# Bridge Protocol Template

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    BRIDGE ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│     CHAIN A (Source)              CHAIN B (Destination)         │
│  ┌───────────────────┐         ┌───────────────────┐           │
│  │   Bridge Contract │         │   Bridge Contract │           │
│  │   ─────────────   │         │   ─────────────   │           │
│  │   Lock tokens     │         │   Mint tokens     │           │
│  │   Emit event      │         │   Verify proof    │           │
│  │   Store proof     │         │   Release funds   │           │
│  └─────────┬─────────┘         └─────────┬─────────┘           │
│            │                              │                      │
│            │    ┌─────────────────┐      │                      │
│            └───▶│   RELAYER/      │◀─────┘                      │
│                 │   VALIDATOR     │                              │
│                 │   NETWORK       │                              │
│                 └─────────────────┘                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Bridge Types

### Lock-and-Mint
1. Lock tokens on source chain
2. Mint wrapped tokens on destination
3. Burn wrapped to unlock original

### Liquidity Network
1. LPs on both chains
2. Swap through LP pools
3. Faster but capital intensive

### Optimistic
1. Submit proof, assume valid
2. Challenge period
3. Slash if fraud proven

### ZK-Based
1. Generate ZK proof of source state
2. Verify proof on destination
3. No trust assumptions

---

## Critical Functions

### 1. Deposit/Lock

```solidity
function deposit(
    address token,
    uint256 amount,
    uint256 destinationChain,
    address recipient
) external {
    // Lock tokens
    // Generate message
    // Store/emit for relayers
}
```

**Audit Points:**
- [ ] Token actually locked (not just event)
- [ ] Message format correct
- [ ] Chain ID validated
- [ ] Recipient validated

### 2. Withdraw/Release

```solidity
function withdraw(
    bytes memory message,
    bytes memory proof
) external {
    // Verify proof
    // Check not already processed
    // Release tokens
}
```

**Audit Points:**
- [ ] Proof verification robust
- [ ] Replay prevention (nonce)
- [ ] Chain ID in message
- [ ] Amount limits

### 3. Message Verification

```solidity
function verifyMessage(
    bytes32 messageHash,
    bytes[] signatures
) internal returns (bool) {
    // Check signature threshold
    // Validate signers
}
```

**Audit Points:**
- [ ] Threshold sufficient (5/9+)
- [ ] No signature malleability
- [ ] All signers validated
- [ ] Hash includes all params

---

## Common Vulnerabilities

### BRIDGE-01: Signature Replay

**Risk:** Critical

**Description:** Same signature works on multiple chains or multiple times.

**Vulnerable Pattern:**
```solidity
function process(bytes memory sig, address to, uint256 amount) {
    require(verify(sig, to, amount), "Bad sig");
    // No chainId!
    // No nonce!
    token.mint(to, amount);
}
```

**Attack:**
1. Get valid signature on Chain A
2. Replay on Chain B, C, D...
3. Mint unlimited tokens

**Mitigation:**
```solidity
struct Message {
    uint256 sourceChain;
    uint256 destChain;
    uint256 nonce;
    address recipient;
    uint256 amount;
}

mapping(bytes32 => bool) public processedMessages;

function process(Message memory msg, bytes memory sig) {
    require(msg.destChain == block.chainid, "Wrong chain");
    
    bytes32 hash = keccak256(abi.encode(msg));
    require(!processedMessages[hash], "Already processed");
    processedMessages[hash] = true;
    
    require(verify(sig, hash), "Bad sig");
    // Process...
}
```

---

### BRIDGE-02: Insufficient Validator Threshold

**Risk:** Critical

**Description:** Low threshold allows small group to collude.

**Vulnerable Pattern:**
```solidity
uint256 constant THRESHOLD = 2;  // Only 2 of 5 needed!
uint256 constant VALIDATORS = 5;
```

**Attack:**
- Compromise 2 validators
- Sign arbitrary withdrawals
- Drain bridge

**Mitigation:**
- Minimum 66% threshold
- Geographic/organizational distribution
- Hardware security modules

---

### BRIDGE-03: Finality Issues

**Risk:** Critical

**Description:** Processing before source chain finality allows double-spends.

**Vulnerable Pattern:**
```solidity
function onNewBlock(uint256 blockNumber, bytes memory proof) {
    // Only 1 confirmation required!
    process(proof);
}
```

**Attack:**
1. Deposit on PoW chain
2. Bridge processes immediately
3. Reorg/51% attack on source
4. Original deposit reversed
5. Tokens already minted on destination

**Mitigation:**
```solidity
uint256 constant REQUIRED_CONFIRMATIONS = 64;  // ETH post-merge

function process(uint256 blockNumber, bytes memory proof) {
    require(
        getCurrentBlock() - blockNumber >= REQUIRED_CONFIRMATIONS,
        "Insufficient confirmations"
    );
    // Process...
}
```

---

### BRIDGE-04: Message Spoofing (L1↔L2)

**Risk:** Critical

**Description:** Fake messages accepted from untrusted sources.

**Vulnerable Pattern:**
```solidity
// On L2
function handleL1Message(address sender, bytes memory data) external {
    // Anyone can call!
    processData(data);
}
```

**Mitigation:**
```solidity
function handleL1Message(address sender, bytes memory data) external {
    require(msg.sender == L2_MESSENGER, "Only messenger");
    require(sender == TRUSTED_L1_BRIDGE, "Invalid L1 sender");
    processData(data);
}
```

---

### BRIDGE-05: Proof Verification Bypass

**Risk:** Critical

**Description:** Proof verification can be bypassed or is incorrectly implemented.

**Real Example:** Nomad Bridge ($190M)

**Vulnerable Pattern:**
```solidity
// The Nomad bug (simplified)
mapping(bytes32 => uint256) public messages;
uint256 constant UNPROVEN = 0;
uint256 constant PROVEN = 0;  // BUG: Same as UNPROVEN!

function process(bytes32 hash) {
    require(messages[hash] == PROVEN);  // 0 == 0, always passes!
}
```

**Mitigation:**
- Use enums with explicit non-zero values
- Multiple verification steps
- Comprehensive testing

---

### BRIDGE-06: Token Mapping Confusion

**Risk:** High

**Description:** Wrong token mappings allow minting wrong tokens.

**Vulnerable Pattern:**
```solidity
// Map any token to any token
function setMapping(address source, address dest) external onlyOwner {
    tokenMappings[source] = dest;  // No validation!
}
```

**Attack:**
1. Map worthless token to USDC
2. Deposit worthless tokens
3. Mint USDC on destination

**Mitigation:**
- Whitelist approach
- Canonical token registries
- Timelock on mappings

---

### BRIDGE-07: Admin Key Compromise

**Risk:** Critical

**Description:** Compromised admin keys allow unlimited minting.

**Real Examples:** Ronin ($625M), Harmony ($100M)

**Pattern:**
```solidity
function mint(address to, uint256 amount) external onlyAdmin {
    token.mint(to, amount);  // Unlimited power
}
```

**Mitigation:**
- Multi-sig (5/9 minimum)
- Timelock on sensitive operations
- Hardware security modules
- Rate limiting

---

### BRIDGE-08: Optimistic Bridge Challenge DOS

**Risk:** High

**Description:** Challengers blocked from submitting fraud proofs.

**Attack:**
1. Submit fake withdrawal
2. DOS/grief challengers during challenge period
3. Claim after period expires

**Mitigation:**
- Multiple challenge paths
- Bond for submissions
- Emergency pause capability

---

## Real Exploit Examples

| Bridge | Date | Loss | Root Cause |
|--------|------|------|------------|
| Ronin | Mar 2022 | $625M | Admin key compromise |
| Wormhole | Feb 2022 | $326M | Signature verification bypass |
| Nomad | Aug 2022 | $190M | Proof verification bug |
| Harmony | Jun 2022 | $100M | Multi-sig compromise |
| BNB Bridge | Oct 2022 | $586M | Proof verification |
| Multichain | Jul 2023 | $126M | Admin key compromise |

---

## Bridge Audit Checklist

### Message Security
- [ ] Chain ID in all messages
- [ ] Nonce/unique ID for replay protection
- [ ] All params in signed hash
- [ ] No signature malleability

### Proof Verification
- [ ] Merkle proofs validated
- [ ] State roots verified
- [ ] No bypass paths
- [ ] Edge cases tested

### Validator Security
- [ ] Threshold >= 66%
- [ ] Validator set protected
- [ ] Rotation mechanism
- [ ] Slashing for misbehavior

### Finality
- [ ] Sufficient confirmations
- [ ] Chain-specific requirements
- [ ] Reorg handling

### Token Handling
- [ ] Correct mappings
- [ ] Decimal handling
- [ ] Fee-on-transfer
- [ ] Lock/mint/burn accounting

### Access Control
- [ ] Multi-sig admin
- [ ] Timelock on changes
- [ ] Rate limits
- [ ] Emergency pause

---

## Detection Commands

```bash
# Find signature verification
grep -rn "ecrecover\|ECDSA\|verify.*sig" --include="*.sol"

# Find replay protection
grep -rn "nonce\|processed\|used.*message" --include="*.sol"

# Find chain ID usage
grep -rn "chainId\|chain.*id\|block.chainid" --include="*.sol"

# Find threshold checks
grep -rn "threshold\|quorum\|required.*sigs" --include="*.sol"

# Find merkle verification
grep -rn "merkle\|proof\|root.*verify" --include="*.sol"

# Find message handlers
grep -rn "handleMessage\|onMessage\|receive.*message" --include="*.sol"
```

---

## Protocol-Specific Patterns

### L2 Rollups (Optimism, Arbitrum)
- Native message passing
- Retryable tickets
- Check L1→L2 sender validation

### Wormhole Style
- Guardian network
- VAA verification
- Check guardian set

### Axelar/LayerZero
- General message passing
- Check relayer trust model
- Verify endpoint security
