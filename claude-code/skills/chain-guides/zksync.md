---
id: CHAIN-ZKSYNC
title: zkSync Era Security Guide
category: chain-guides
chain: zksync
difficulty: advanced
tags: [zksync, l2, zk-rollup, era, zkevm]
last_updated: 2026-01-31
---

# zkSync Era Security Guide

## Overview

zkSync Era is a ZK-rollup L2 that uses zero-knowledge proofs for transaction validity. While EVM-compatible, there are significant differences that affect security.

## Key Differences from Ethereum L1

| Aspect | Ethereum L1 | zkSync Era |
|--------|-------------|------------|
| Finality | ~15 minutes | ~1 hour (proof time) |
| Execution | EVM | zkEVM (differences!) |
| Account Model | EOA vs Contract | All accounts are contracts |
| Gas | Standard EVM | Different gas costs |
| Opcodes | Full EVM | Some unsupported/modified |

## Critical Vulnerability Categories

### 1. Account Abstraction (Native AA)

All accounts on zkSync are smart contracts, including EOAs.

```solidity
// zkSync native AA considerations

// 1. msg.sender behavior
// Even for "EOA" transactions, msg.sender is a contract

// 2. tx.origin
// STILL points to the transaction initiator
// BUT it's technically a contract

// 3. Signature validation
// Custom accounts can have custom signature schemes

// VULNERABLE - Assumes EOA behavior
contract NaiveContract {
    function withdraw() external {
        require(msg.sender == tx.origin, "No contracts");  // May not work as expected!
    }
}

// SECURE - Use proper AA checks
contract AACompatibleContract {
    function withdraw() external {
        // Check if caller has code
        uint256 size;
        address sender = msg.sender;
        assembly { size := extcodesize(sender) }
        
        // On zkSync, ALL accounts have code
        // So this check is meaningless
        
        // Instead, rely on signature verification or access control
        require(isAuthorized(msg.sender), "Not authorized");
    }
}
```

### 2. EVM Opcode Differences

Several opcodes behave differently or are unsupported.

```solidity
// UNSUPPORTED OPCODES on zkSync Era
// - SELFDESTRUCT: Does NOT destroy contract, only sends ETH
// - EXTCODECOPY: Limited support
// - CODECOPY: May behave differently for deployed bytecode

// VULNERABLE - Relies on SELFDESTRUCT
contract SelfDestructible {
    function destroy() external onlyOwner {
        selfdestruct(payable(owner));  // Contract still exists!
    }
}

// SECURE - Don't rely on selfdestruct
contract Pausable {
    bool public paused;
    
    function pause() external onlyOwner {
        paused = true;
        // Transfer funds out instead of selfdestruct
        payable(owner).transfer(address(this).balance);
    }
}
```

### 3. Gas Costs Are Different

zkSync has its own gas schedule.

```solidity
// Gas differences:
// 1. Storage operations: Different costs
// 2. Precompiles: Some missing or different
// 3. Memory: Different expansion costs

// VULNERABLE - Hardcoded gas limits
contract GasLimited {
    function externalCall(address target) external {
        (bool success,) = target.call{gas: 10000}("");  // May not be enough!
        require(success, "Call failed");
    }
}

// SECURE - Dynamic gas handling
contract GasFlexible {
    function externalCall(address target) external {
        // Let zkSync handle gas or use gasleft()
        (bool success,) = target.call{gas: gasleft() / 2}("");
        require(success, "Call failed");
    }
}
```

### 4. CREATE/CREATE2 Behavior

Deployment works but with differences.

```solidity
// CREATE2 on zkSync:
// 1. Address derivation is DIFFERENT
// 2. Uses bytecode hash, not initcode

// VULNERABLE - Assumes Ethereum CREATE2 addresses
contract Factory {
    function predictAddress(bytes32 salt, bytes memory code) 
        external view returns (address) 
    {
        // This formula is WRONG for zkSync!
        return address(uint160(uint(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            keccak256(code)
        )))));
    }
}

// SECURE - Use zkSync's address derivation
import "@matterlabs/zksync-contracts/l2/system-contracts/Constants.sol";

contract ZkFactory {
    function predictAddress(bytes32 salt, bytes32 bytecodeHash) 
        external view returns (address) 
    {
        return L2ContractHelper.computeCreate2Address(
            address(this),
            salt,
            bytecodeHash,
            keccak256("")  // constructor args hash
        );
    }
}
```

### 5. Block Properties

```solidity
// Block property differences:

// block.number - L2 batch number (not L1!)
// block.timestamp - L2 timestamp
// block.coinbase - Operator address
// block.difficulty/prevrandao - Not meaningful for ZK

// Getting L1 information
interface ISystemContext {
    function getBlockNumber() external view returns (uint256);
    function getBlockTimestamp() external view returns (uint256);
    function getTxNumberInBlock() external view returns (uint256);
}

address constant SYSTEM_CONTEXT = 0x000000000000000000000000000000000000800B;
```

### 6. L1 <-> L2 Communication

zkSync has its own bridge and messaging system.

```solidity
// L1 -> L2 Communication
interface IZkSync {
    function requestL2Transaction(
        address _contractL2,
        uint256 _l2Value,
        bytes calldata _calldata,
        uint256 _l2GasLimit,
        uint256 _l2GasPerPubdataByteLimit,
        bytes[] calldata _factoryDeps,
        address _refundRecipient
    ) external payable returns (bytes32 txHash);
}

// L2 -> L1 Communication
interface IL1Messenger {
    function sendToL1(bytes memory _message) external returns (bytes32);
}

address constant L1_MESSENGER = 0x0000000000000000000000000000000000008008;
```

```solidity
// SECURE L1 -> L2 message handling
contract L2Receiver {
    address public l1Sender;
    address constant BOOTLOADER_ADDRESS = 0x0000000000000000000000000000000000008001;
    
    function receiveFromL1(bytes calldata data) external {
        // For L1 -> L2 transactions, msg.sender is an aliased address
        require(
            undoL1ToL2Alias(msg.sender) == l1Sender,
            "Invalid sender"
        );
        
        _processData(data);
    }
    
    function undoL1ToL2Alias(address aliased) internal pure returns (address) {
        // zkSync uses same aliasing as Arbitrum
        uint160 offset = uint160(0x1111000000000000000000000000000000001111);
        return address(uint160(aliased) - offset);
    }
}
```

### 7. Precompile Availability

```solidity
// Precompile differences on zkSync:

// AVAILABLE:
// - ecrecover (0x01)
// - sha256 (0x02)
// - keccak256 (native)

// NOT AVAILABLE or DIFFERENT:
// - RIPEMD160 (0x03) - Not available
// - Identity (0x04) - Limited
// - ModExp (0x05) - Not available
// - EcAdd (0x06) - Limited
// - EcMul (0x07) - Limited
// - EcPairing (0x08) - Not available

// VULNERABLE - Uses unavailable precompile
contract CryptoOps {
    function verifyBLS(bytes memory data) external view returns (bool) {
        // ecPairing not available!
        (bool success, bytes memory result) = address(8).staticcall(data);
        return success && abi.decode(result, (bool));
    }
}
```

## System Contracts

zkSync Era has system contracts for core functionality:

```solidity
// Key system contract addresses
address constant BOOTLOADER = 0x0000000000000000000000000000000000008001;
address constant ACCOUNT_CODE_STORAGE = 0x0000000000000000000000000000000000008002;
address constant NONCE_HOLDER = 0x0000000000000000000000000000000000008003;
address constant KNOWN_CODES_STORAGE = 0x0000000000000000000000000000000000008004;
address constant IMMUTABLE_SIMULATOR = 0x0000000000000000000000000000000000008005;
address constant CONTRACT_DEPLOYER = 0x0000000000000000000000000000000000008006;
address constant FORCE_DEPLOYER = 0x0000000000000000000000000000000000008007;
address constant L1_MESSENGER = 0x0000000000000000000000000000000000008008;
address constant MSG_VALUE_SYSTEM_CONTRACT = 0x0000000000000000000000000000000000008009;
address constant ETH_TOKEN = 0x000000000000000000000000000000000000800A;
address constant SYSTEM_CONTEXT = 0x000000000000000000000000000000000000800B;
address constant BOOTLOADER_UTILITIES = 0x000000000000000000000000000000000000800C;
address constant COMPRESSOR = 0x000000000000000000000000000000000000800E;
```

## Audit Checklist

```
[ ] No reliance on SELFDESTRUCT
[ ] No unsupported precompiles
[ ] Gas limits are flexible, not hardcoded
[ ] CREATE2 address derivation is zkSync-specific
[ ] Account abstraction compatibility
[ ] L1 <-> L2 message sender verification
[ ] No assumptions about msg.sender being EOA
[ ] System contract interactions are safe
[ ] No reliance on block.difficulty/prevrandao
[ ] Factory patterns use zkSync's deployer
```

## Deployment Differences

```solidity
// Deploying contracts on zkSync requires different approach:

// 1. Use zkSync's ContractDeployer
interface IContractDeployer {
    function create(
        bytes32 _salt,
        bytes32 _bytecodeHash,
        bytes calldata _input
    ) external payable returns (address newAddress);
    
    function create2(
        bytes32 _salt,
        bytes32 _bytecodeHash,
        bytes calldata _input
    ) external payable returns (address newAddress);
}

address constant CONTRACT_DEPLOYER = 0x0000000000000000000000000000000000008006;

// 2. Bytecode must be known beforehand
// zkSync compiles separately, bytecode hash is different

// 3. Constructor args are passed differently
```

## Testing on zkSync

```bash
# Use zkSync-specific tools
npm install -D @matterlabs/hardhat-zksync-deploy @matterlabs/hardhat-zksync-solc

# Compile for zkSync
npx hardhat compile --network zkSyncTestnet

# Deploy using zkSync deployer
npx hardhat deploy-zksync --network zkSyncTestnet
```
