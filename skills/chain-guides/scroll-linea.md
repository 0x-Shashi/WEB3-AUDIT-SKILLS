# Scroll & Linea Security Guide

## Chain Overview

### Scroll
- **Type:** zkRollup L2 (zkEVM)
- **VM:** zkEVM (Type 2 - EVM equivalent)
- **Proving:** zk-SNARK proofs
- **Finality:** ~20 min (proof generation) + L1 finality
- **Gas Token:** ETH

### Linea
- **Type:** zkRollup L2 (zkEVM)
- **VM:** zkEVM (Type 2)
- **Operator:** Consensys
- **Finality:** ~20 min + L1 finality
- **Gas Token:** ETH

## Shared zkEVM Security Considerations

### 1. EVM Equivalence Gaps
zkEVMs aim for EVM equivalence but have subtle differences:

```solidity
// Potentially different behavior in zkEVM:
// 1. Some precompiles may not be supported (ecPairing gas costs differ)
// 2. CREATE2 address calculation may differ in edge cases
// 3. Stack depth limits may be enforced differently
// 4. Gas metering for certain opcodes differs
```

**Key differences to check:**
- `SELFDESTRUCT` behavior (may be no-op or restricted)
- `BLOCKHASH` for older blocks (may not be available)
- `DIFFICULTY` / `PREVRANDAO` (returns 0 or fixed value)
- Precompile gas costs (especially bn128, ecrecover)

### 2. Prover Soundness
- Zero-knowledge proofs must be mathematically sound
- Prover bugs can allow invalid state transitions
- Current systems have training wheels (admin can override)
- **Audit check:** Understand the trust assumptions of the proving system

### 3. Upgrade Keys and Admin Controls
Both Scroll and Linea currently have admin keys:
- Contract upgrades possible through multisig
- Sequencer can be paused/restarted
- Proving can be overridden in emergencies
- **Audit check:** Protocol should consider admin key compromise scenario

### 4. Data Availability
- Transaction data posted to Ethereum L1 (calldata or blobs)
- State diffs may be used instead of full transaction data
- **Audit check:** Can protocol state be fully reconstructed from L1 data?

### 5. Sequencer and Prover Centralization
- Single sequencer operated by team
- Proving infrastructure centralized
- Censorship is possible (but force-inclusion via L1 may exist)
- Prover downtime means delayed finality

### 6. Cross-Chain Messaging

```
L1 → L2: Message queue, included in next batch
L2 → L1: Requires proof finalization (~20 min+)
```

- Messages must wait for proof generation and verification
- Longer delay than optimistic rollups for L2→L1 (no 7-day window, but proof time)
- Message format differs between Scroll and Linea

### 7. Gas and Fees
- L2 execution fee + L1 data publication fee
- Gas costs for certain opcodes may differ from Ethereum
- Proof generation cost amortized across batch
- **Audit check:** Gas-intensive patterns may cost more or less than expected

## zkEVM-Specific Audit Checklist

- [ ] Opcode compatibility verified (no unsupported opcodes used)
- [ ] Precompile behavior matches Ethereum (especially cryptographic ones)
- [ ] Admin upgrade keys and their impact assessed
- [ ] Sequencer centralization risks identified
- [ ] Cross-chain message delay factored into protocol logic
- [ ] Proof finalization time impact on protocol operations
- [ ] Gas cost differences for specific opcodes identified
- [ ] `SELFDESTRUCT` not relied upon
- [ ] `BLOCKHASH` usage limited to recent blocks
- [ ] Force-inclusion mechanism understood for censorship resistance
- [ ] Data availability: can state be reconstructed from L1?

## Scroll-Specific Notes
- Chain ID: 534352
- Bridge: `ScrollMessenger` contract for L1<>L2
- Block time: ~3 seconds

## Linea-Specific Notes
- Chain ID: 59144
- Bridge: `MessageService` contract for L1<>L2
- Operated by Consensys (MetaMask integration)
- Block time: ~2-3 seconds

## Common Vulnerabilities on zkEVMs

| Vulnerability | Description |
|--------------|-------------|
| Opcode mismatch | Using opcodes that behave differently |
| Precompile gas | Cryptographic operations cost differently |
| Proof delay exploitation | Timing attacks during proof generation |
| Admin key compromise | Upgradeable contracts with limited multisig |
| Gas estimation errors | Different gas costs cause unexpected failures |
