---
id: CHAIN-SCROLL-LINEA
title: Scroll & Linea (zkEVM) Security Guide
category: chain-guides
chain: scroll-linea
language: solidity
difficulty: intermediate
tags: [scroll, linea, zkevm, l2, compatibility]
last_updated: 2026-01-31
---

# Scroll & Linea (zkEVM) Security Guide

## Overview

Scroll and Linea are zkEVM L2s aiming for maximum EVM compatibility. While they execute Solidity code, subtle differences in gas costs, precompiles, and opcodes create security considerations.

```
┌─────────────────────────────────────────────────────────────────┐
│                    zkEVM ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  L2 (SCROLL/LINEA)                    L1 (ETHEREUM)             │
│  ┌─────────────────────────────┐    ┌──────────────────┐       │
│  │  Sequencer                  │    │                  │       │
│  │  ┌─────────┐               │    │  Rollup Contract │       │
│  │  │ EVM     │  ZK Prover    │    │  ┌────────────┐  │       │
│  │  │Execution│──────────────│────│  │ State Root │  │       │
│  │  └─────────┘               │    │  │ ZK Proof   │  │       │
│  │                            │    │  └────────────┘  │       │
│  └─────────────────────────────┘    └──────────────────┘       │
│                                                                 │
│  COMPATIBILITY LEVELS:                                          │
│  • Scroll: Type 2 zkEVM (EVM-equivalent)                       │
│  • Linea: Type 2 zkEVM (EVM-equivalent)                        │
│  • Both aim for bytecode compatibility                          │
│  • Some opcodes/precompiles may differ                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Compatibility Matrix

### Opcode Support

| Opcode | Scroll | Linea | Notes |
|--------|--------|-------|-------|
| `SELFDESTRUCT` | ⚠️ | ⚠️ | Deprecated, may behave differently |
| `DIFFICULTY` | Returns 0 | Returns 0 | Use `PREVRANDAO` |
| `BLOCKHASH` | Limited | Limited | May not work for old blocks |
| `PUSH0` | ✅ | ✅ | Supported post-Shanghai |
| `BLOBHASH` | ❌ | ❌ | Not supported yet |

### Precompile Support

| Precompile | Scroll | Linea | Notes |
|------------|--------|-------|-------|
| ecrecover (0x1) | ✅ | ✅ | Full support |
| SHA256 (0x2) | ✅ | ✅ | Full support |
| RIPEMD160 (0x3) | ⚠️ | ⚠️ | Higher gas cost |
| modexp (0x5) | ⚠️ | ⚠️ | Gas differences |
| ecAdd (0x6) | ✅ | ✅ | Full support |
| ecMul (0x7) | ✅ | ✅ | Full support |
| ecPairing (0x8) | ✅ | ✅ | Gas differences |
| blake2f (0x9) | ⚠️ | ⚠️ | May not be supported |

---

## Attack Vector 1: Gas Cost Differences

### ZK-Unfriendly Operations

```solidity
// Some operations are expensive in ZK circuits

contract GasAnalysis {
    // EXPENSIVE in zkEVM:
    
    // 1. Keccak256 - requires many constraints
    function expensiveHash(bytes memory data) external pure returns (bytes32) {
        return keccak256(data);  // Much more expensive than L1
    }
    
    // 2. SLOAD/SSTORE - storage proofs are costly
    mapping(uint256 => uint256) public data;
    
    function manyStorageOps() external {
        for (uint i = 0; i < 100; i++) {
            data[i] = i;  // Each SSTORE is expensive
        }
    }
    
    // 3. ecrecover - signature verification in ZK
    function verifySig(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external pure returns (address) {
        return ecrecover(hash, v, r, s);  // Higher gas
    }
}

// ATTACK: Griefing via ZK-expensive operations
// Attacker submits transactions that are cheap on L1
// But very expensive to prove, potentially DoS-ing the prover
```

### Gas Limit Considerations

```solidity
// zkEVM may have different effective gas limits

contract GasLimitIssue {
    // VULNERABILITY: Works on L1, might fail on zkEVM
    function processLargeArray(uint256[] calldata data) external {
        // Might exceed zkEVM gas limit even if within block limit
        for (uint i = 0; i < data.length; i++) {
            // Process...
            heavyComputation(data[i]);
        }
    }
}

// DEFENSE: Test gas usage specifically on target zkEVM
// Add explicit bounds
function processLargeArraySafe(
    uint256[] calldata data,
    uint256 maxItems
) external {
    uint256 limit = data.length > maxItems ? maxItems : data.length;
    for (uint i = 0; i < limit; i++) {
        heavyComputation(data[i]);
    }
}
```

---

## Attack Vector 2: Sequencer Centralization

### Single Sequencer Risks

```
Current state: Both Scroll and Linea have centralized sequencers

RISKS:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  1. CENSORSHIP                                                  │
│     Sequencer can refuse to include transactions                │
│     User's funds could be temporarily frozen                    │
│                                                                 │
│  2. MEV EXTRACTION                                              │
│     Sequencer has full ordering control                         │
│     Can sandwich, front-run without competition                 │
│                                                                 │
│  3. DOWNTIME                                                    │
│     If sequencer goes offline, chain halts                      │
│     No transactions processed until recovery                    │
│                                                                 │
│  4. FORCED INCLUSION (Escape Hatch)                             │
│     Both support L1→L2 messages that bypass sequencer           │
│     But may have delays (24-48 hours)                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Forced Inclusion Mechanism

```solidity
// If censored, users can force include via L1

// Scroll: ScrollMessenger
interface IScrollMessenger {
    function sendMessage(
        address target,
        uint256 value,
        bytes calldata message,
        uint256 gasLimit
    ) external payable;
}

// Linea: MessageService
interface IMessageService {
    function sendMessage(
        address to,
        uint256 fee,
        bytes calldata calldata_
    ) external payable;
}

// Contract should handle both normal and forced inclusion
contract RobustContract {
    // Don't assume instant transaction inclusion
    // Allow for delays in time-sensitive operations
    
    function withdraw(uint256 amount) external {
        // If using deadline, make it generous
        // User might need to force include via L1
        require(block.timestamp < deadline + 48 hours);
        _withdraw(msg.sender, amount);
    }
}
```

---

## Attack Vector 3: L1↔L2 Bridge Vulnerabilities

### Message Verification

```solidity
// Scroll L1→L2 Message

contract L2Receiver {
    address public l1Sender;
    IScrollMessenger public messenger;
    
    // VULNERABLE: Not verifying message origin
    function handleMessage(bytes calldata data) external {
        // WRONG: Anyone can call!
        _processData(data);
    }
    
    // SECURE: Verify message came from L1
    function handleMessageSecure(bytes calldata data) external {
        // Check caller is messenger
        require(msg.sender == address(messenger), "Not messenger");
        
        // Check L1 sender
        require(
            messenger.xDomainMessageSender() == l1Sender,
            "Wrong L1 sender"
        );
        
        _processData(data);
    }
}
```

### Finality Considerations

```solidity
// L2 blocks are not final until proven on L1

contract FinalityAware {
    // CONSIDERATION: Deposits from L1 might reorg
    
    // Scroll: ~4 hours for L2 finality
    // Linea: ~2-8 hours for L2 finality
    
    function handleL1Deposit(uint256 amount) external {
        // Even after message received, L1 could reorg
        // Before ZK proof is verified on L1, state is not final
        
        // For high-value operations, consider waiting for finality
        deposits[msg.sender] = Deposit({
            amount: amount,
            timestamp: block.timestamp,
            finalized: false
        });
    }
    
    // Finalize after sufficient time
    function finalizeDeposit(address user) external {
        Deposit storage dep = deposits[user];
        require(
            block.timestamp > dep.timestamp + FINALITY_DELAY,
            "Not finalized"
        );
        dep.finalized = true;
    }
}
```

---

## Attack Vector 4: Block Property Differences

### Timestamp Behavior

```solidity
// Block timestamps may differ from L1

contract TimestampIssue {
    // Scroll/Linea: Timestamps are L2 sequencer timestamps
    // May not match L1 exactly
    
    // VULNERABILITY: Relying on L1 timestamp assumptions
    function timeSensitive() external {
        // block.timestamp is L2 time, not L1
        // Sequencer controls this (within bounds)
    }
}
```

### Block Number

```solidity
// block.number is L2 block number, not L1

contract BlockNumberIssue {
    // VULNERABILITY: Assuming L1 block pace
    
    // L1: ~12 seconds per block
    // Scroll: ~3 seconds per block
    // Linea: ~2-3 seconds per block
    
    uint256 public constant BLOCKS_PER_DAY = 7200;  // L1 assumption!
    
    function calculateReward(uint256 startBlock) external view returns (uint256) {
        uint256 blocks = block.number - startBlock;
        // WRONG: blocks accumulate 4x faster on L2!
        return blocks * REWARD_PER_BLOCK;
    }
    
    // CORRECT: Use timestamp instead
    function calculateRewardSafe(uint256 startTime) external view returns (uint256) {
        uint256 elapsed = block.timestamp - startTime;
        return elapsed * REWARD_PER_SECOND;
    }
}
```

---

## Attack Vector 5: Contract Deployment Differences

### CREATE2 Address Calculation

```solidity
// CREATE2 addresses should be same across chains IF:
// - Same deployer address
// - Same bytecode
// - Same salt

// RISK: Bytecode might differ if:
// 1. Compiler optimization settings differ
// 2. Metadata hash differs
// 3. Constructor arguments encoded differently

contract DeterministicDeploy {
    function deploy(bytes32 salt, bytes memory bytecode) external returns (address) {
        address deployed;
        assembly {
            deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(deployed != address(0), "Deploy failed");
        return deployed;
    }
}

// BEST PRACTICE: Verify deployment addresses on each chain
// Don't assume cross-chain determinism without testing
```

### Contract Size Limits

```solidity
// zkEVM may have different practical size limits

// EIP-170: 24KB max contract size
// zkEVM: Same limit, but ZK proving may struggle with very large contracts

// RECOMMENDATION: Keep contracts smaller
// Split functionality across multiple contracts
// Use proxy patterns for upgradeability
```

---

## Scroll-Specific Considerations

### Scroll's Architecture

```solidity
// Scroll-specific contracts

// L1 Contracts:
// - ScrollChain: L2 state commitments
// - L1MessageQueue: L1→L2 messages
// - L1ScrollMessenger: Cross-chain messaging

// L2 Contracts:
// - L2ScrollMessenger: Cross-chain messaging
// - L1GasPriceOracle: L1 gas price data

// Getting L1 data fee
interface IL1GasPriceOracle {
    function getL1Fee(bytes memory data) external view returns (uint256);
}

contract ScrollGasEstimate {
    IL1GasPriceOracle constant L1_ORACLE = IL1GasPriceOracle(0x5300000000000000000000000000000000000002);
    
    function estimateTotalFee(bytes memory txData) external view returns (uint256) {
        uint256 l1Fee = L1_ORACLE.getL1Fee(txData);
        // Total = L2 execution gas + L1 data fee
        return l1Fee;  // Plus L2 gas
    }
}
```

---

## Linea-Specific Considerations

### Linea's Architecture

```solidity
// Linea-specific contracts

// L1 Contracts:
// - LineaRollup: Main rollup contract
// - L1MessageService: Cross-chain messaging

// L2 Contracts:
// - L2MessageService: Cross-chain messaging
// - L1Block: L1 block data (proposed)

// Linea message passing
interface IMessageService {
    function sendMessage(
        address _to,
        uint256 _fee,
        bytes calldata _calldata
    ) external payable;
    
    function claimMessage(
        address _from,
        address _to,
        uint256 _fee,
        uint256 _value,
        address payable _feeRecipient,
        bytes calldata _calldata,
        uint256 _nonce
    ) external;
}
```

---

## Audit Checklist

### zkEVM Compatibility

```markdown
## Compatibility Review

### Opcodes
□ No reliance on SELFDESTRUCT?
□ DIFFICULTY/PREVRANDAO handled correctly?
□ BLOCKHASH usage limited/alternative?
□ No unsupported opcodes?

### Precompiles
□ Gas estimates account for zkEVM costs?
□ Blake2f usage verified?
□ Modexp gas costs acceptable?

### Block Properties
□ block.number usage appropriate for L2?
□ Timestamp assumptions correct?
□ No L1-specific block pacing assumptions?
```

### L2 Security

```markdown
## L2-Specific Security

### Sequencer Risks
□ Application handles sequencer censorship?
□ Forced inclusion path available?
□ MEV protection considered?

### Bridge Security
□ L1→L2 messages verify sender?
□ L2→L1 messages use correct interface?
□ Finality delays accounted for?

### Gas
□ ZK-unfriendly operations minimized?
□ Gas limits tested on target chain?
□ L1 data fees accounted for?
```

### Cross-Chain

```markdown
## Cross-Chain Deployment

### Deployment
□ CREATE2 addresses verified on each chain?
□ Constructor arguments identical?
□ Compiler settings match?

### Configuration
□ Chain-specific addresses updated?
□ Bridge/messenger addresses correct?
□ Gas parameters tuned per chain?
```

---

## Code Examples

### Safe Cross-Chain Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract zkEVMSafeContract {
    // Chain-agnostic messenger interface
    address public immutable messenger;
    address public immutable l1Target;
    
    // Use timestamp, not block number for timing
    uint256 public constant LOCK_PERIOD = 1 days;
    
    mapping(address => uint256) public lockUntil;
    mapping(address => uint256) public balances;
    
    constructor(address _messenger, address _l1Target) {
        messenger = _messenger;
        l1Target = _l1Target;
    }
    
    // Receive message from L1
    function handleL1Message(
        address user,
        uint256 amount
    ) external {
        // Verify messenger
        require(msg.sender == messenger, "Not messenger");
        
        // Verify L1 sender (chain-specific)
        // Scroll: xDomainMessageSender()
        // Linea: sender() in context
        
        // Process deposit with delay for finality
        balances[user] += amount;
        lockUntil[user] = block.timestamp + LOCK_PERIOD;
    }
    
    function withdraw(uint256 amount) external {
        require(block.timestamp >= lockUntil[msg.sender], "Locked");
        require(balances[msg.sender] >= amount, "Insufficient");
        
        balances[msg.sender] -= amount;
        
        // Transfer...
    }
    
    // Minimize ZK-expensive operations
    // Use events instead of storage where possible
    event Action(address indexed user, uint256 indexed id, bytes data);
    
    function logAction(uint256 id, bytes calldata data) external {
        // Events are cheaper than storage in zkEVM
        emit Action(msg.sender, id, data);
    }
}
```

---

## Related Resources

- [Scroll Documentation](https://docs.scroll.io/)
- [Linea Documentation](https://docs.linea.build/)
- [zkEVM Differences Guide](https://docs.scroll.io/en/developers/ethereum-and-scroll-differences/)
- [EVM Equivalence](https://vitalik.eth.limo/general/2022/08/04/zkevm.html)
