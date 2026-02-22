# Optimism Security Guide

## Chain Overview

- **Type:** Optimistic Rollup L2
- **VM:** EVM-equivalent (Bedrock)
- **Consensus:** Sequencer + fault proofs
- **Finality:** ~7 day challenge period
- **Gas Token:** ETH

## Key Security Considerations

### 1. Cross-Domain Messaging
```
L1 → L2: CrossDomainMessenger (auto-relayed by sequencer)
L2 → L1: CrossDomainMessenger (7-day withdrawal period)
```

**Critical risks:**
- L1→L2 messages are not instant; there's a relay delay
- L2→L1 withdrawals can be challenged during 7 days
- `msg.sender` on L2 = `CrossDomainMessenger`, NOT the L1 sender
- Must use `xDomainMessageSender()` to get the actual L1 caller

```solidity
// [VULNERABLE] Wrong sender check
function onL1Message(bytes calldata data) external {
    require(msg.sender == l1Contract); // WRONG - msg.sender is the messenger
}

// [SAFE] Proper cross-domain sender check
function onL1Message(bytes calldata data) external {
    require(msg.sender == address(crossDomainMessenger));
    require(crossDomainMessenger.xDomainMessageSender() == l1Contract);
}
```

### 2. Output Proposals and Fault Proofs
- Output roots posted to L1 periodically
- Challengers can dispute within challenge window
- **Audit check:** Protocol logic should not depend on un-finalized outputs

### 3. EVM Equivalence Gaps
Bedrock is EVM-equivalent but not identical:
- `PUSH0` opcode supported (post-Canyon)
- `SELFDESTRUCT` behavior differs (may not refund)
- `PREVRANDAO` returns sequencer-controlled value (not random!)
- `block.number` and `block.timestamp` are L2 values

```solidity
// [VULNERABLE] Using PREVRANDAO for randomness on Optimism
function random() public view returns (uint256) {
    return block.prevrandao; // Sequencer-controlled on OP!
}
```

### 4. Gas and Fees (Bedrock)
```
Total Fee = L2 execution fee + L1 data fee
L1 Data Fee = (calldata_gas * l1_base_fee * dynamic_overhead) * scalar
```
- L1 fee component can spike with L1 gas prices
- `GasPriceOracle` precompile at `0x420000000000000000000000000000000000000F`
- **After Ecotone:** Uses blobs, reducing L1 data cost

### 5. System Contracts
Key predeploy contracts:
- `L2CrossDomainMessenger (0x4200...07)` - Cross-chain messaging
- `L2StandardBridge (0x4200...10)` - Token bridging
- `L2ToL1MessagePasser (0x4200...16)` - Withdrawal initiation
- `GasPriceOracle (0x4200...0F)` - Fee calculation
- `L1Block (0x4200...15)` - L1 block attributes

### 6. Deposit Transactions
- Special transaction type for L1→L2 deposits
- Cannot be censored (guaranteed inclusion)
- `tx.origin` is aliased for contract-initiated deposits
- Gas limit is bounded; complex L2 execution may fail

## Optimism-Specific Audit Checklist

- [ ] Cross-domain sender validated via `xDomainMessageSender()`
- [ ] Not using `msg.sender` directly for L1→L2 authenticated calls
- [ ] Withdrawal delay (7 days) impact analyzed
- [ ] `PREVRANDAO` not used as randomness source
- [ ] L1 data fee component accounted for in gas calculations
- [ ] System contract addresses correct (0x4200... predeploys)
- [ ] Force-inclusion via L1 deposits considered
- [ ] Block number/timestamp semantics understood (L2 values)
- [ ] Deposit transaction gas limits adequate for L2 execution
- [ ] `SELFDESTRUCT` behavior differences handled

## Common Vulnerabilities on Optimism

| Vulnerability | Description |
|--------------|-------------|
| Cross-domain spoofing | Not validating xDomainMessageSender |
| Withdrawal timing | Protocol assumes instant L2→L1 finality |
| PREVRANDAO abuse | Using sequencer-controlled value as randomness |
| Gas underestimation | Not accounting for L1 data cost component |
| Deposit failures | L1→L2 deposit with insufficient L2 gas |
