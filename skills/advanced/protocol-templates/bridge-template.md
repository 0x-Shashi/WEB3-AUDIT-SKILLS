# Bridge Audit Template

## Protocol Overview
Cross-chain bridges transfer assets and messages between blockchains using various trust models (multisig, optimistic, ZK-proof, light client).

## Architecture Checklist
- [ ] Message format and encoding secure
- [ ] Signature/proof verification implementation correct
- [ ] Validator/guardian set management secure
- [ ] Token locking/minting/burning accounting consistent
- [ ] Cross-chain message replay prevention
- [ ] Finality requirements appropriate per chain
- [ ] Admin key management documented

## Critical Invariants
```
1. Conservation: tokens_locked(source) == tokens_minted(destination)
2. No Replay: each message processed exactly once
3. Authenticity: every processed message was legitimately sent
4. Ordering: messages processed in valid order (if required)
5. Liveness: messages eventually delivered (no permanent stuck)
```

## Attack Vectors

### Message Verification
- [ ] Signature forgery (weak verification, wrong hash)
- [ ] Fake guardian/validator injection
- [ ] Threshold bypass (n-of-m with wrong n or m)
- [ ] Merkle proof manipulation
- [ ] Hash collision attacks on message IDs
- [ ] ZK proof soundness (for ZK bridges)

### Replay & Ordering
- [ ] Cross-chain message replay (same message, different chain)
- [ ] Same-chain replay (process same message twice)
- [ ] Nonce management (gaps, overflow, reuse)
- [ ] Out-of-order message processing exploits

### Token Accounting
- [ ] Mint without deposit (verification bypass)
- [ ] Double withdrawal (race condition)
- [ ] Token mapping manipulation (fake token pairs)
- [ ] Decimal mismatch between chains
- [ ] Wrapped token depegging from underlying

### Finality
- [ ] Insufficient confirmation requirements
- [ ] Reorg attack (deposit on source, reorg, keep both)
- [ ] Chain-specific finality differences not handled

### Admin / Operational
- [ ] Guardian key compromise (Ronin: $624M)
- [ ] Upgrade path bypasses timelock
- [ ] Emergency pause doesn't cover all paths
- [ ] Fund recovery mechanism abuse

## Critical Functions to Review Deep
| Function | Risk | Check |
|----------|------|-------|
| `verifyMessage()` | Bypass → total drain | Every validation step |
| `executeMessage()` | Arbitrary execution | Access control, reentrancy |
| `deposit()` / `lock()` | Accounting | Balance tracking, events |
| `withdraw()` / `mint()` | Unauthorized mint | Proof validation, replay |
| `updateGuardians()` | Takeover | Threshold, timelock |

## Integration Risks
- Relayer liveness and incentives
- Source/destination chain differences (gas, finality, opcodes)
- Token standard differences across chains
- Bridge aggregator routing risks

## Economic Considerations
- Total bridge TVL vs validator stake (economic security)
- Cost to compromise vs value at risk
- Relayer fee incentive alignment
- Insurance/recovery fund adequacy
