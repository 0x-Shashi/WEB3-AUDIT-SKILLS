# L2 Security Patterns - AI Reference

> **For AI Assistants:** Layer 2 networks have unique vulnerabilities. Apply these patterns when auditing L2 deployments.

---

## Overview

| L2 Network | Type | Key Concerns |
|------------|------|--------------|
| Arbitrum | Optimistic Rollup | Sequencer, delayed inbox, retryable tickets |
| Optimism | Optimistic Rollup | Cross-domain messaging, gas price oracle |
| zkSync | ZK Rollup | Account abstraction, bytecode differences |
| Base | Optimistic Rollup | Similar to Optimism (OP Stack) |
| Polygon zkEVM | ZK Rollup | EVM equivalence gaps |
| StarkNet | Validity Rollup | Cairo language, different model |
| Scroll | ZK Rollup | EVM compatibility |

---

## Universal L2 Vulnerabilities

### 1. Sequencer Dependence
```
Severity: MEDIUM-HIGH
Category: centralization

Description:
L2s rely on sequencers to order transactions. Sequencer downtime 
or malicious behavior can affect protocol operation.

Check for:
- Does protocol assume continuous sequencer operation?
- Is there a fallback for sequencer downtime?
- Can sequencer censor specific transactions?

Vulnerable pattern:
```solidity
// Protocol relies on timely execution
function auction() external {
    require(block.timestamp < deadline);  // Sequencer can delay
}
```

Mitigation:
- Allow for sequencer downtime in time-sensitive logic
- Implement forced inclusion via L1 (where available)
- Add grace periods for time-sensitive operations
```

### 2. L1 to L2 Message Replay
```
Severity: HIGH
Category: cross-chain

Description:
Messages from L1 to L2 may be replayed if not properly validated.

Check for:
- Unique message identifiers
- Nonce tracking for cross-layer messages
- Proper sender validation

Vulnerable pattern:
```solidity
function receiveMessage(bytes calldata data) external {
    // No replay protection!
    _processMessage(data);
}
```

Mitigation:
- Use message nonces
- Track processed message hashes
- Validate message origin chain
```

### 3. Block.number Differences
```
Severity: MEDIUM
Category: logic

Description:
block.number on L2 may not match L1 and behaves differently.
Some L2s have faster block times, others have L1 block number.

Check for:
- Logic assuming specific block times
- Block-based randomness
- Block-based locks/delays

Vulnerable pattern:
```solidity
// Assumes ~12s blocks like L1
uint256 public constant BLOCKS_PER_DAY = 7200;

function canWithdraw() external view returns (bool) {
    return block.number > depositBlock + BLOCKS_PER_DAY;
}
```

Mitigation:
- Use block.timestamp instead of block.number for time
- Query actual block time if needed
- Document block time assumptions
```

### 4. Gas Price Oracle Manipulation
```
Severity: MEDIUM
Category: oracle

Description:
L2 gas prices can vary significantly and may be manipulable.

Check for:
- Reliance on tx.gasprice for logic
- Gas price assumptions for MEV protection
- Refund calculations based on gas price

Vulnerable pattern:
```solidity
function submit() external {
    require(tx.gasprice <= maxGasPrice);  // L2 gas is different
}
```
```

---

## Arbitrum-Specific Patterns

### 1. ArbSys Precompile
```
Severity: INFO
Category: l2-specific

Description:
Arbitrum has ArbSys precompile at 0x64 for L2-specific operations.

Key functions:
- arbBlockNumber(): L2 block number
- arbBlockHash(): L2 block hash
- sendTxToL1(): Send message to L1
- wasMyCallersAddressAliased(): Check address aliasing

Check for:
- Using block.number when arbBlockNumber is needed
- Proper use of address aliasing
```

### 2. Address Aliasing
```
Severity: HIGH
Category: access-control

Description:
When L1 contracts call L2, the address is "aliased" by adding 
0x1111000000000000000000000000000000001111.

Check for:
- L1->L2 calls expecting msg.sender to be L1 contract address
- Access control based on L1 sender

Vulnerable pattern:
```solidity
// On L2
function executeFromL1() external {
    // msg.sender is ALIASED, not the actual L1 address!
    require(msg.sender == l1Contract);  // WRONG
}
```

Mitigation:
```solidity
function undoL1ToL2Alias(address l2Address) internal pure returns (address l1Address) {
    uint160 offset = uint160(0x1111000000000000000000000000000000001111);
    l1Address = address(uint160(l2Address) - offset);
}
```
```

### 3. Retryable Tickets
```
Severity: MEDIUM
Category: cross-chain

Description:
Arbitrum retryable tickets can be auto-redeemed or manually redeemed.
Failed auto-redemption needs manual retry or ticket expires.

Check for:
- Assumption that L1->L2 messages always succeed
- Handling of failed retryable tickets
- Ticket expiration (7 days default)

Mitigation:
- Handle failed ticket scenarios
- Provide mechanism to retry failed tickets
- Monitor ticket status
```

### 4. Delayed Inbox
```
Severity: MEDIUM
Category: timing

Description:
Users can force-include transactions via L1 delayed inbox,
bypassing sequencer (after ~24h delay).

Check for:
- Assumption that sequencer ordering is final
- Time-sensitive operations that could be bypassed

Security consideration:
- Malicious sequencer can be bypassed
- ~24h delay for force inclusion
```

---

## Optimism / Base (OP Stack) Patterns

### 1. Cross Domain Messenger
```
Severity: HIGH
Category: cross-chain

Description:
CrossDomainMessenger is the official way to send L1<->L2 messages.

Check for:
- Proper use of CrossDomainMessenger
- Validation of xDomainMessageSender()
- Handling of failed messages

Vulnerable pattern:
```solidity
function receiveFromL1(uint256 amount) external {
    // Anyone can call!
    _mint(msg.sender, amount);
}
```

Correct pattern:
```solidity
function receiveFromL1(uint256 amount) external {
    require(
        msg.sender == address(crossDomainMessenger),
        "Not messenger"
    );
    require(
        crossDomainMessenger.xDomainMessageSender() == l1Bridge,
        "Wrong sender"
    );
    _mint(address(this), amount);
}
```
```

### 2. L1Block Predeploy
```
Severity: INFO
Category: l2-specific

Description:
Optimism has L1Block predeploy at 0x4200000000000000000000000000000000000015
providing L1 block info.

Available data:
- number: L1 block number
- timestamp: L1 block timestamp
- basefee: L1 base fee
- hash: L1 block hash
- sequenceNumber: L2 sequence number

Check for:
- Confusion between L1 and L2 block numbers
- Using wrong block reference for timing
```

### 3. Gas Price Oracle
```
Severity: MEDIUM
Category: oracle

Description:
OP Stack has gas price oracle at 0x420000000000000000000000000000000000000F.

Check for:
- Reliance on L2 gas price for security
- L1 data fee calculations

Note:
- L2 execution gas is separate from L1 data gas
- Total fee = L2 execution + L1 data fee
```

### 4. Deposit Transactions
```
Severity: MEDIUM
Category: cross-chain

Description:
Deposits from L1 to L2 are guaranteed to execute (different from Arbitrum).

Check for:
- L1 deposit failures (reverts) lose funds
- msg.value handling in deposit receivers

Mitigation:
- Test deposit receivers thoroughly
- Handle all edge cases in receiver
```

---

## zkSync-Specific Patterns

### 1. Native Account Abstraction
```
Severity: MEDIUM
Category: account-abstraction

Description:
zkSync has native account abstraction. EOAs work differently.

Check for:
- Assumptions about msg.sender being EOA
- ecrecover usage (works but different internally)
- Paymaster interactions

Considerations:
- Accounts can have custom validation logic
- Paymasters can pay for user gas
```

### 2. Bytecode Differences
```
Severity: HIGH
Category: l2-specific

Description:
zkSync compiles to zkEVM bytecode which has differences.

Check for:
- contract.code.length may differ
- extcodesize behavior
- CREATE2 address calculation is different

Vulnerable pattern:
```solidity
function isContract(address account) internal view returns (bool) {
    uint256 size;
    assembly { size := extcodesize(account) }
    return size > 0;  // May not work as expected on zkSync
}
```
```

### 3. System Contracts
```
Severity: INFO
Category: l2-specific

Description:
zkSync has system contracts for L2 functionality.

Key contracts:
- ContractDeployer: Deploy contracts
- NonceHolder: Nonce management
- L1Messenger: L1 communication
- MsgValueSimulator: Handle msg.value

Check for:
- Direct interaction with system contracts
- Assumptions about standard EVM behavior
```

### 4. L1->L2 Priority Queue
```
Severity: MEDIUM
Category: cross-chain

Description:
L1->L2 transactions go through priority queue with processing delay.

Check for:
- Timing assumptions for L1 deposits
- Handling of queued transactions
- Order of priority vs regular transactions
```

---

## Polygon zkEVM Patterns

### 1. EVM Equivalence Gaps
```
Severity: MEDIUM
Category: l2-specific

Description:
Polygon zkEVM aims for EVM equivalence but has some gaps.

Check for:
- Unsupported opcodes (check docs)
- Gas cost differences
- Precompile differences
```

### 2. Bridge Security
```
Severity: HIGH
Category: cross-chain

Description:
Polygon zkEVM uses ZK proofs for bridge security.

Check for:
- Proper use of bridge contracts
- Message validation on destination
- Handling of bridge delays
```

---

## Cross-L2 Considerations

### 1. Chain ID Validation
```
Severity: HIGH
Category: signature

Description:
When contracts deploy across multiple L2s, ensure chain ID validation.

Check for:
- Signatures include chain ID (EIP-712)
- Replay protection across chains
- Contract addresses may differ across L2s

Vulnerable pattern:
```solidity
function executeWithSig(bytes calldata sig, bytes calldata data) external {
    address signer = recover(keccak256(data), sig);  // No chain ID!
}
```
```

### 2. Bridge Token Standards
```
Severity: MEDIUM
Category: composability

Description:
Different L2s have different canonical bridge token implementations.

Check for:
- Token address differences across L2s
- Bridge token vs native token differences
- Wrapped token behaviors
```

### 3. Finality Differences
```
Severity: MEDIUM
Category: timing

Description:
Different L2s have different finality guarantees.

| L2 | Soft Finality | Hard Finality |
|----|---------------|---------------|
| Arbitrum | ~1 min | ~7 days (challenge) |
| Optimism | ~1 min | ~7 days (challenge) |
| zkSync | ~1 min | ~1 hour (proof) |
| Polygon zkEVM | ~1 min | ~30 min (proof) |

Check for:
- Assumptions about finality in cross-chain logic
- Withdrawal delay handling
```

---

## L2 Audit Checklist

### General
- [ ] Check block.number assumptions
- [ ] Verify block.timestamp behavior
- [ ] Review gas price/cost assumptions
- [ ] Test sequencer downtime scenarios
- [ ] Verify chain ID in signatures

### Cross-Chain
- [ ] Validate message sender properly
- [ ] Handle message replay protection
- [ ] Consider message failure scenarios
- [ ] Verify address aliasing (Arbitrum)
- [ ] Test bridge deposit/withdrawal flows

### Network-Specific
- [ ] Check for unsupported opcodes
- [ ] Verify precompile availability
- [ ] Test account abstraction interactions (zkSync)
- [ ] Review system contract usage
- [ ] Verify CREATE2 address calculations
```

---

## AI Application Guide

When auditing L2 contracts:

1. **Identify the target L2** from chain ID or deployment context
2. **Apply universal L2 patterns** first
3. **Apply network-specific patterns** for the target L2
4. **Check cross-chain messaging** if protocol bridges
5. **Verify assumptions** about block times, gas, finality
6. **Test edge cases** for sequencer downtime/failures

