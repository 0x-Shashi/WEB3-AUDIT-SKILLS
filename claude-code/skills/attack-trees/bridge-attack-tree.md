---
id: BRIDGE-ATTACK-TREE
title: Cross-Chain Bridge Attack Tree
category: attack-tree
protocol: bridge
triggers:
  - bridge attack paths
  - how to attack bridge
  - cross-chain vulnerabilities
  - bridge exploit tree
related_skills:
  - patterns/bridge-patterns.md
  - patterns/signature-patterns.md
  - patterns/oracle-patterns.md
  - exploit-forensics/poly-network-2021.md
  - exploit-forensics/wormhole-2022.md
  - exploit-forensics/ronin-2022.md
---

# Cross-Chain Bridge Attack Tree

Visual decision path for attacking cross-chain bridges. Bridges are high-value targets with unique attack surfaces.

---

## ROOT: Steal Funds from Bridge

```
ROOT: Steal Funds from Bridge
│
├── [A] Signature/Validation Exploits
│   │
│   ├── [A1] Signature Replay
│   │   ├── Condition: No nonce/uniqueness check
│   │   ├── Action: Replay valid signature multiple times
│   │   ├── Result: Mint tokens on dest chain repeatedly
│   │   └── Check: patterns/signature-patterns.md#replay
│   │
│   ├── [A2] Cross-Chain Replay
│   │   ├── Condition: No chain ID in signature
│   │   ├── Action: Replay signature on different chain
│   │   ├── Result: Drain bridge on all chains
│   │   └── Check: patterns/signature-patterns.md#chain-id
│   │
│   ├── [A3] Signature Malleability
│   │   ├── Condition: Using ecrecover without malleability check
│   │   ├── Action: Modify signature (s → n-s)
│   │   ├── Result: Bypass used-signature tracking
│   │   └── Check: patterns/signature-patterns.md#malleability
│   │
│   ├── [A4] Insufficient Validator Threshold
│   │   ├── Condition: Threshold too low (e.g., 1-of-9)
│   │   ├── Action: Compromise single validator
│   │   ├── Result: Approve malicious transfers
│   │   └── Check: patterns/bridge-patterns.md#validator-threshold
│   │
│   ├── [A5] Validator Key Compromise
│   │   ├── Condition: Validator private keys not secured
│   │   ├── Action: Phish/hack validator keys
│   │   ├── Result: Sign malicious bridge messages
│   │   └── Check: patterns/bridge-patterns.md#key-management
│   │
│   └── [A6] Missing Signature Verification
│       ├── Condition: Signature check missing or flawed
│       ├── Action: Submit unsigned message
│       ├── Result: Mint unbacked tokens
│       └── Check: patterns/signature-patterns.md#verification
│
├── [B] State Synchronization Attacks
│   │
│   ├── [B1] Race Condition
│   │   ├── Condition: Lock on source not confirmed before mint on dest
│   │   ├── Action: Withdraw on source → Mint on dest
│   │   ├── Result: Double-spend across chains
│   │   └── Check: patterns/bridge-patterns.md#confirmation-depth
│   │
│   ├── [B2] Reorg Attack
│   │   ├── Condition: Insufficient confirmation blocks
│   │   ├── Action: Trigger reorg after bridge confirms
│   │   ├── Result: Tokens minted but source reverted
│   │   └── Check: patterns/bridge-patterns.md#reorg-safety
│   │
│   ├── [B3] Nonce Desync
│   │   ├── Condition: Nonce tracking inconsistent
│   │   ├── Action: Cause nonce mismatch between chains
│   │   ├── Result: DoS or double-process messages
│   │   └── Check: patterns/bridge-patterns.md#nonce-tracking
│   │
│   └── [B4] Message Out-of-Order
│       ├── Condition: Messages processed in wrong order
│       ├── Action: Process msg N before msg N-1
│       ├── Result: Incorrect state on destination
│       └── Check: patterns/bridge-patterns.md#message-ordering
│
├── [C] Token Handling Exploits
│   │
│   ├── [C1] Mint Without Lock
│   │   ├── Condition: Dest chain mints without verifying source lock
│   │   ├── Action: Call mint directly on dest chain
│   │   ├── Result: Mint unbacked tokens
│   │   └── Check: patterns/bridge-patterns.md#mint-verification
│   │
│   ├── [C2] Unlock Without Burn
│   │   ├── Condition: Source unlocks without verifying dest burn
│   │   ├── Action: Unlock tokens without burning wrapped
│   │   ├── Result: Steal locked tokens
│   │   └── Check: patterns/bridge-patterns.md#burn-verification
│   │
│   ├── [C3] Fee-on-Transfer Token
│   │   ├── Condition: Bridge doesn't handle transfer fees
│   │   ├── Action: Bridge fee-on-transfer token
│   │   ├── Result: Mint more on dest than locked on source
│   │   └── Check: patterns/token-patterns.md#fee-on-transfer
│   │
│   ├── [C4] Rebasing Token
│   │   ├── Condition: Bridge doesn't handle rebasing
│   │   ├── Action: Lock rebasing token → Rebase → Unlock more
│   │   ├── Result: Drain bridge via rebase
│   │   └── Check: patterns/token-patterns.md#rebase
│   │
│   ├── [C5] Decimal Mismatch
│   │   ├── Condition: Different decimals on source/dest
│   │   ├── Action: Lock 1e6 (6 decimals) → Mint 1e18 (18 decimals)
│   │   ├── Result: Inflate tokens 1 trillion times
│   │   └── Check: patterns/bridge-patterns.md#decimal-handling
│   │
│   └── [C6] Native vs Wrapped Confusion
│       ├── Condition: Bridge handles both native and wrapped
│       ├── Action: Lock wrapped → Unlock native
│       ├── Result: Steal native tokens
│       └── Check: patterns/bridge-patterns.md#token-type
│
├── [D] Oracle/Relayer Manipulation
│   │
│   ├── [D1] Malicious Relayer
│   │   ├── Condition: Single relayer, no verification
│   │   ├── Action: Run malicious relayer
│   │   ├── Result: Submit false messages
│   │   └── Check: patterns/bridge-patterns.md#relayer-trust
│   │
│   ├── [D2] Oracle Manipulation
│   │   ├── Condition: Bridge uses price oracle
│   │   ├── Action: Manipulate oracle price
│   │   ├── Result: Bridge assets at wrong price
│   │   └── Check: patterns/oracle-patterns.md#bridge-oracle
│   │
│   ├── [D3] Front-Running Relayer
│   │   ├── Condition: Anyone can relay messages
│   │   ├── Action: Front-run user's bridge tx
│   │   ├── Result: Steal relay rewards
│   │   └── Check: patterns/bridge-patterns.md#relayer-competition
│   │
│   └── [D4] Censorship by Relayer
│       ├── Condition: Relayer can choose which messages to relay
│       ├── Action: Censor user withdrawals
│       ├── Result: DoS user funds
│       └── Check: patterns/bridge-patterns.md#censorship-resistance
│
├── [E] Smart Contract Exploits
│   │
│   ├── [E1] Reentrancy on Unlock
│   │   ├── Condition: Unlock calls external contract before state update
│   │   ├── Action: Reenter unlock function
│   │   ├── Result: Drain locked funds
│   │   └── Check: patterns/reentrancy-patterns.md#bridge
│   │
│   ├── [E2] Initialization Attack
│   │   ├── Condition: Bridge not initialized or re-initializable
│   │   ├── Action: Initialize bridge with malicious parameters
│   │   ├── Result: Set self as owner/validator
│   │   └── Check: patterns/access-control-patterns.md#initialization
│   │
│   ├── [E3] Upgrade Attack
│   │   ├── Condition: Proxy upgrade not secured
│   │   ├── Action: Upgrade to malicious implementation
│   │   ├── Result: Steal all bridge funds
│   │   └── Check: patterns/upgrade-patterns.md#bridge
│   │
│   ├── [E4] Delegate Call Exploit
│   │   ├── Condition: Unsafe delegatecall in bridge
│   │   ├── Action: Delegatecall to malicious contract
│   │   ├── Result: Arbitrary code execution
│   │   └── Check: patterns/delegatecall-patterns.md#bridge
│   │
│   └── [E5] Access Control Bypass
│       ├── Condition: Missing or weak access control
│       ├── Action: Call admin functions as non-admin
│       ├── Result: Mint/unlock without proper authorization
│       └── Check: patterns/access-control-patterns.md#bridge
│
├── [F] Economic Attacks
│   │
│   ├── [F1] Liquidity Drain
│   │   ├── Condition: Bridge has limited liquidity on dest
│   │   ├── Action: Bridge large amount → Drain liquidity
│   │   ├── Result: DoS other users
│   │   └── Check: patterns/bridge-patterns.md#liquidity-management
│   │
│   ├── [F2] Fee Manipulation
│   │   ├── Condition: Bridge fees calculated incorrectly
│   │   ├── Action: Exploit fee calculation
│   │   ├── Result: Bridge for free or negative cost
│   │   └── Check: patterns/bridge-patterns.md#fee-calculation
│   │
│   ├── [F3] MEV Sandwich
│   │   ├── Condition: Bridge swap visible in mempool
│   │   ├── Action: Front-run → Bridge → Back-run
│   │   ├── Result: Extract value from bridge users
│   │   └── Check: patterns/mev-patterns.md#bridge-sandwich
│   │
│   └── [F4] Slippage Exploit
│       ├── Condition: No slippage protection
│       ├── Action: Manipulate price during bridge
│       ├── Result: User receives far less than expected
│       └── Check: patterns/bridge-patterns.md#slippage
│
└── [G] Protocol-Specific Attacks
    │
    ├── [G1] Merkle Proof Forgery
    │   ├── Condition: Merkle root not properly verified
    │   ├── Action: Forge proof for non-existent message
    │   ├── Result: Process fake bridge messages
    │   └── Check: patterns/merkle-patterns.md#bridge
    │
    ├── [G2] Light Client Attack
    │   ├── Condition: Light client validation insufficient
    │   ├── Action: Provide invalid block headers
    │   ├── Result: Fool bridge about source chain state
    │   └── Check: patterns/bridge-patterns.md#light-client
    │
    ├── [G3] Hash Collision
    │   ├── Condition: Using short hash for message ID
    │   ├── Action: Create collision in message hash
    │   ├── Result: Replace legitimate message
    │   └── Check: patterns/cryptography-patterns.md#hash-collision
    │
    └── [G4] Validator Set Update Attack
        ├── Condition: Validator set update not secured
        ├── Action: Update validator set to attacker-controlled
        ├── Result: Approve any malicious message
        └── Check: patterns/bridge-patterns.md#validator-rotation
```

---

## Audit Workflow

**How to use this tree:**

1. **Identify bridge type** - Lock/Mint, Burn/Unlock, Liquidity Pool, Atomic Swap
2. **Map validator architecture** - Multisig, MPC, Light client, Optimistic
3. **Check message flow** - Source → Relayer → Validators → Destination
4. **Test each vulnerability** - Focus on signature and state sync
5. **Verify confirmations** - Ensure sufficient finality

---

## Quick Reference by Attack Type

| Attack Type | Most Common Branch | Severity | Ease |
|-------------|-------------------|----------|------|
| Signature Replay | [A1] Signature Replay | Critical | Easy |
| Validator Compromise | [A5] Validator Key Compromise | Critical | Hard |
| Double-Spend | [B1] Race Condition | Critical | Medium |
| Unbacked Mint | [C1] Mint Without Lock | Critical | Easy |
| Decimal Exploit | [C5] Decimal Mismatch | Critical | Medium |
| Reentrancy | [E1] Reentrancy on Unlock | Critical | Medium |

---

## Real-World Exploits Mapped

| Exploit | Year | Loss | Attack Branch | Details |
|---------|------|------|---------------|---------|
| Poly Network | 2021 | $610M | [E5] Access Control Bypass | exploit-forensics/poly-network-2021.md |
| Wormhole | 2022 | $326M | [A6] Missing Signature Verification | exploit-forensics/wormhole-2022.md |
| Ronin Bridge | 2022 | $625M | [A5] Validator Key Compromise | exploit-forensics/ronin-2022.md |
| Nomad Bridge | 2022 | $190M | [E2] Initialization Attack | exploit-forensics/nomad-2022.md |
| Harmony Horizon | 2022 | $100M | [A5] Validator Key Compromise | exploit-forensics/harmony-2022.md |

---

## Checklist (Copy for Audit)

```markdown
## Bridge Attack Surface

### Signatures [A]
- [ ] [A1] Signature replay protection (nonce/used-signature tracking)
- [ ] [A2] Chain ID included in signature
- [ ] [A3] Signature malleability handled (OpenZeppelin ECDSA lib)
- [ ] [A4] Validator threshold sufficient (>66%)
- [ ] [A5] Validator keys secured (MPC/hardware wallets)
- [ ] [A6] Signature verification present and correct

### State Sync [B]
- [ ] [B1] No race conditions (source confirmed before dest mint)
- [ ] [B2] Sufficient confirmation depth (protect against reorgs)
- [ ] [B3] Nonce tracking consistent across chains
- [ ] [B4] Messages processed in order

### Token Handling [C]
- [ ] [C1] Mint requires verified lock on source
- [ ] [C2] Unlock requires verified burn on dest
- [ ] [C3] Fee-on-transfer tokens handled or blocked
- [ ] [C4] Rebasing tokens blocked or handled
- [ ] [C5] Decimal conversion correct
- [ ] [C6] Native vs wrapped tokens clearly separated

### Oracle/Relayer [D]
- [ ] [D1] Relayer trustlessness or verification
- [ ] [D2] Oracle manipulation resistant
- [ ] [D3] Relayer competition fair
- [ ] [D4] Censorship resistance mechanisms

### Smart Contract [E]
- [ ] [E1] Reentrancy protection on unlock
- [ ] [E2] Initialization secured
- [ ] [E3] Upgrade mechanism secured
- [ ] [E4] No unsafe delegatecall
- [ ] [E5] Access control on critical functions

### Economic [F]
- [ ] [F1] Liquidity management adequate
- [ ] [F2] Fee calculation correct
- [ ] [F3] MEV protection
- [ ] [F4] Slippage protection

### Protocol-Specific [G]
- [ ] [G1] Merkle proofs validated
- [ ] [G2] Light client secure
- [ ] [G3] Hash collision resistant
- [ ] [G4] Validator set updates secured
```
