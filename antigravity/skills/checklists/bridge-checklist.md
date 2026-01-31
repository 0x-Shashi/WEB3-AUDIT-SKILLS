---
id: CHECKLIST-BRIDGE
title: Cross-Chain Bridge Audit Checklist
category: checklists
difficulty: advanced
tags: [bridge, cross-chain, message-passing, l2, interoperability]
last_updated: 2026-01-31
---

# Cross-Chain Bridge Audit Checklist

Quick-reference checklist for auditing bridge protocols. Bridges are high-value targets - extra scrutiny required.

---

## 🔴 Critical Checks (Must Pass)

### Message Verification
```
[ ] Are signatures from valid validators/relayers?
[ ] Is signature threshold sufficient (>2/3)?
[ ] Can signature verification be bypassed?
[ ] Are message hashes computed correctly?
[ ] Is the signing scheme secure (ECDSA, BLS, etc.)?
```

### Replay Protection
```
[ ] Are message nonces enforced?
[ ] Can same message be processed twice?
[ ] Is nonce incremented before or after processing?
[ ] Are nonces chain-specific?
[ ] Can old nonces be reused after overflow?
```

### Merkle/Proof Verification
```
[ ] Is merkle root from trusted source?
[ ] Are merkle proofs validated correctly?
[ ] Can proof be forged to verify against 0x00 root?
[ ] Is proof length validated?
[ ] Are leaf/node hashes domain-separated?
```

### Source Chain Validation
```
[ ] Is the source chain verified?
[ ] Can messages from fake source chains be processed?
[ ] Is source contract address verified?
[ ] Can source chain ID be spoofed?
```

---

## 🟠 High Priority Checks

### Finality & Timing
```
[ ] Is source chain finality waited for?
[ ] What happens during source chain reorg?
[ ] Is there a challenge period for optimistic bridges?
[ ] Are timestamps validated?
[ ] L2→L1: Is withdrawal delay enforced?
```

### Token Handling
```
[ ] Lock-and-mint vs burn-and-mint correct?
[ ] Can more tokens be minted than locked?
[ ] Are wrapped token addresses validated?
[ ] Fee-on-transfer tokens handled?
[ ] Token decimals match across chains?
```

### Rate Limiting & Circuit Breakers
```
[ ] Is there a maximum transfer size?
[ ] Is there hourly/daily volume limit?
[ ] Can bridge be paused in emergency?
[ ] Who can trigger emergency pause?
[ ] Is pause mechanism decentralized enough?
```

---

## 🟡 Medium Priority Checks

### Validator/Relayer Security
```
[ ] How many validators/relayers?
[ ] What's the threshold for consensus?
[ ] Can validators be added/removed?
[ ] Is there slashing for malicious validators?
[ ] Key rotation mechanism exists?
```

### Upgrade Security
```
[ ] Are contracts upgradeable?
[ ] Is there a timelock on upgrades?
[ ] Can upgrade introduce new vulnerabilities?
[ ] Are proxy storage slots safe?
[ ] Can upgrade be blocked by guardian?
```

### Message Ordering
```
[ ] Do messages need to be processed in order?
[ ] Can out-of-order processing cause issues?
[ ] Are dependent messages handled correctly?
[ ] What happens to stuck messages?
```

---

## 🟢 Standard Checks

### Access Control
```
[ ] Who can update validator set?
[ ] Who can pause/unpause?
[ ] Who can update fee parameters?
[ ] Who can withdraw stuck funds?
[ ] Are roles properly separated?
```

### Economic Security
```
[ ] Is validator stake > bridge TVL?
[ ] Is there insurance/coverage?
[ ] What's the cost to attack vs profit?
[ ] Are fees sufficient for security?
```

### Event & Monitoring
```
[ ] All cross-chain messages emit events?
[ ] Are events indexed for monitoring?
[ ] Can anomalies be detected in real-time?
[ ] Is there off-chain monitoring?
```

---

## Bridge Type-Specific Checks

### Lock & Mint Bridges
```
[ ] Locked amount == minted amount?
[ ] Can mint without corresponding lock?
[ ] Are lock events reliably relayed?
[ ] What if lock tx reverts after mint?
```

### Burn & Mint Bridges
```
[ ] Burned amount == minted amount?
[ ] Is burn confirmed before mint?
[ ] Can tokens be minted without burn proof?
[ ] Total supply constant across chains?
```

### Liquidity Bridges
```
[ ] LP incentives sustainable?
[ ] Rebalancing mechanism safe?
[ ] Imbalanced liquidity handling?
[ ] Can LP be drained by attackers?
```

### Optimistic Bridges
```
[ ] Challenge period sufficient (7+ days)?
[ ] Are watchers incentivized?
[ ] Can fraud proofs be submitted?
[ ] Is bond sufficient for challenges?
```

### ZK Bridges
```
[ ] ZK proof system audited?
[ ] Are proofs verified on-chain?
[ ] Can invalid proofs pass verification?
[ ] Is trusted setup compromised?
```

---

## Common Vulnerability Patterns

### 1. Signature Verification Bypass
```solidity
// VULNERABLE: Wormhole-style bug
function verify(bytes memory data, uint256 guardianCount) {
    for (uint i = 0; i < guardianCount; i++) { // guardianCount from user input!
        // If guardianCount = 0, loop never runs
    }
}

// SECURE: Validate guardian count
function verify(bytes memory data, uint256 guardianCount) {
    require(guardianCount >= MIN_GUARDIANS, "Too few guardians");
    require(guardianCount <= MAX_GUARDIANS, "Too many guardians");
}
```

### 2. Merkle Root Initialization Bug
```solidity
// VULNERABLE: Nomad-style bug
mapping(bytes32 => bool) public validRoots;

function initialize() {
    // validRoots[bytes32(0)] defaults to false but...
}

function process(bytes32 root, bytes memory proof) {
    require(validRoots[root], "Invalid root");
    // If validRoots[0x00] was accidentally set to true...
}
```

### 3. Message Replay
```solidity
// VULNERABLE: No replay protection
function processMessage(bytes memory message) {
    _execute(message); // Can be called multiple times
}

// SECURE: Track processed messages
mapping(bytes32 => bool) public processed;

function processMessage(bytes memory message) {
    bytes32 hash = keccak256(message);
    require(!processed[hash], "Already processed");
    processed[hash] = true;
    _execute(message);
}
```

### 4. Cross-Chain Reentrancy
```solidity
// VULNERABLE: State not locked during cross-chain call
function bridgeOut(uint256 amount) {
    balances[msg.sender] -= amount;
    sendCrossChainMessage(...); // What if this calls back?
}

// SECURE: Use reentrancy guard
function bridgeOut(uint256 amount) nonReentrant {
    balances[msg.sender] -= amount;
    sendCrossChainMessage(...);
}
```

---

## L2 Bridge Specific Checks

### Optimistic Rollup (Arbitrum/Optimism)
```
[ ] 7-day challenge period enforced?
[ ] Can challenge period be bypassed?
[ ] Fast exit mechanism secure?
[ ] Sequencer censorship handled?
```

### ZK Rollup (zkSync/StarkNet)
```
[ ] ZK proof verified before finalization?
[ ] Escape hatch available if sequencer down?
[ ] Data availability guaranteed?
[ ] Proof generation cannot be monopolized?
```

### Native Bridges
```
[ ] Uses official bridge contracts?
[ ] Deposit/withdrawal flow correct?
[ ] Finalization timing understood?
[ ] Failure modes handled?
```

---

## Quick Reference

### Bridge Security Hierarchy
```
1. Native L1↔L2 bridges (highest trust - protocol level)
2. ZK bridges (trust math)
3. Optimistic bridges (trust fraud provers)
4. Multisig bridges (trust validators)
5. Single-signer bridges (lowest trust)
```

### Key Metrics
```
TVL vs Security Budget: Should be TVL < Validator Stake
Challenge Period: Optimistic bridges need 7+ days
Validator Threshold: Should be >2/3 for BFT
Max Single Transfer: Should be capped
```

---

## Red Flags 🚩

- [ ] Less than 5 validators/signers
- [ ] Single point of failure in validation
- [ ] No replay protection
- [ ] Upgradeable with no timelock
- [ ] Challenge period < 7 days (optimistic)
- [ ] No rate limiting on large transfers
- [ ] Validator set controlled by single entity
- [ ] No monitoring or alerting system
- [ ] TVL >> economic security (stake/bonds)
- [ ] Message format allows arbitrary execution
