# TON Vulnerability Patterns

## Critical
- **Unbounded storage growth**: Attacker can force contract to store data, increasing storage fees
- **Message chain gas exhaustion**: Multi-hop messages run out of gas mid-chain
- **Missing bounce handling**: Not processing bounced messages leads to fund loss

## High
- **Replay attacks**: Same message processed twice without nonce
- **Cell overflow**: Exceeding 1023 bits per cell or 4 references
- **Workchain confusion**: Not validating workchain ID in addresses

## Medium
- **Storage fee drain**: Contract balance drained by storage fees over time
- **Message ordering**: Sharding means messages arrive in unpredictable order
- **Tick-tock abuse**: Automatic execution contracts can be expensive

## TON-Specific Considerations
- Actor model: contracts communicate via async messages
- No atomic cross-contract calls (unlike EVM)
- Storage fees: contracts pay rent for stored data
- Sharding: contracts on different shards have ordering challenges
- Bounce mechanism: failed messages send remaining gas back

## Checklist
- [ ] Bounce messages handled in all external receivers
- [ ] Gas attached to outbound messages sufficient for recipient
- [ ] Storage growth bounded (no unlimited data storage by users)
- [ ] Message replay protection (seqno or unique ID)
- [ ] Workchain ID validated in addresses
- [ ] Cell serialization doesn't exceed limits
