---
id: ATTACK-ACCOUNT-ABSTRACTION
title: Account Abstraction (ERC-4337) Attacks
category: attack-patterns
difficulty: advanced
tags: [erc-4337, account-abstraction, bundler, paymaster, entrypoint]
last_updated: 2026-01-31
---

# Account Abstraction (ERC-4337) Attacks

## Overview

Account Abstraction (AA) enables smart contract wallets with flexible validation and gas payment. The UserOp → Bundler → EntryPoint architecture creates unique attack surfaces.

```
┌─────────────────────────────────────────────────────────────────┐
│                 ERC-4337 ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  USER                BUNDLER              ENTRYPOINT            │
│  ┌──────────┐       ┌──────────┐        ┌──────────────┐       │
│  │ UserOp   │──────►│ Mempool  │───────►│ handleOps() │       │
│  │ (signed) │       │ Bundle   │        │ validate()  │       │
│  └──────────┘       └──────────┘        │ execute()   │       │
│                          │              └──────────────┘       │
│                          │                     │                │
│       ┌──────────────────┼─────────────────────┤                │
│       │                  │                     │                │
│       ▼                  ▼                     ▼                │
│  ┌─────────┐      ┌──────────┐         ┌───────────┐           │
│  │ Account │      │ Paymaster│         │  Factory  │           │
│  │ Wallet  │      │ (gas $)  │         │ (deploy)  │           │
│  └─────────┘      └──────────┘         └───────────┘           │
│                                                                 │
│  ATTACK SURFACES:                                               │
│  • Bundler manipulation          • Paymaster exploitation       │
│  • Signature replay              • Factory manipulation         │
│  • Storage access violations     • Gas griefing                 │
│  • Validation-execution mismatch                                │
└─────────────────────────────────────────────────────────────────┘
```

---

## ERC-4337 Components

### UserOperation Structure

```solidity
struct UserOperation {
    address sender;          // Smart wallet address
    uint256 nonce;           // Replay protection
    bytes initCode;          // Factory + creation data (if new wallet)
    bytes callData;          // Execution data
    uint256 callGasLimit;    // Gas for execution
    uint256 verificationGasLimit;  // Gas for validation
    uint256 preVerificationGas;    // Gas for bundler overhead
    uint256 maxFeePerGas;    // Max fee (like EIP-1559)
    uint256 maxPriorityFeePerGas;  // Max tip
    bytes paymasterAndData;  // Paymaster address + data
    bytes signature;         // Validation signature
}
```

### EntryPoint Flow

```solidity
// EntryPoint.handleOps() flow
contract EntryPoint {
    function handleOps(
        UserOperation[] calldata ops,
        address payable beneficiary
    ) external {
        for (uint i = 0; i < ops.length; i++) {
            // Phase 1: Validation
            _validateUserOp(ops[i]);
            _validatePaymaster(ops[i]);
            
            // Phase 2: Execution
            _executeUserOp(ops[i]);
        }
        
        // Pay bundler
        _payBeneficiary(beneficiary);
    }
}
```

---

## Attack Vector 1: Bundler Manipulation

### Front-Running UserOps

```
Bundler can see UserOps before they're on-chain

ATTACK:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  1. User submits UserOp: "Swap 1000 USDC for ETH"               │
│                                                                 │
│  2. Malicious bundler sees UserOp in mempool                    │
│                                                                 │
│  3. Bundler front-runs:                                         │
│     - Buy ETH (price up)                                        │
│     - Include user's UserOp (worse rate)                        │
│     - Sell ETH (take profit)                                    │
│                                                                 │
│  4. User gets sandwiched                                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Bundle Ordering Attacks

```solidity
// Bundler controls ordering within bundle

contract MaliciousBundler {
    function createMaliciousBundle(
        UserOperation[] memory userOps
    ) internal returns (UserOperation[] memory) {
        // ATTACK 1: Reorder for MEV extraction
        // Put profitable UserOps after attacker's setup txs
        
        // ATTACK 2: Censorship
        // Exclude competitor's UserOps
        
        // ATTACK 3: Delay
        // Hold UserOps to exploit time-sensitive operations
    }
}

// DEFENSE: Use trusted bundlers or bundler reputation systems
```

### Bundler Selection

```markdown
## Bundler Trust Model

TRUSTED BUNDLERS:
- Flashbots Protect (MEV protection)
- Pimlico, Alchemy, Stackup (commercial)
- Self-hosted (full control)

DEFENSES:
□ Use private mempool (encrypt UserOps)
□ Set tight deadlines in UserOp
□ Use bundler aggregators for redundancy
□ Monitor bundler behavior on-chain
```

---

## Attack Vector 2: Signature Replay

### Cross-Chain Replay

```solidity
// UserOp signed for Chain A replayed on Chain B

// VULNERABLE: Missing chain ID in signed data
contract VulnerableAccount {
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256) {
        // WRONG: userOpHash doesn't include chainId
        require(
            owner.isValidSignature(userOpHash, userOp.signature),
            "Invalid signature"
        );
        return 0;
    }
}

// SECURE: EntryPoint's userOpHash includes chainId
// The standard EntryPoint already includes address(this) and chainId
// But custom implementations might miss this!

function getUserOpHash(UserOperation calldata userOp) public view returns (bytes32) {
    return keccak256(abi.encode(
        userOp.hash(),
        address(this),  // EntryPoint address
        block.chainid   // Chain ID
    ));
}
```

### Nonce Management Issues

```solidity
// ERC-4337 uses 2D nonce (key + sequence)

contract NonceManager {
    // nonces[account][key] = sequence
    mapping(address => mapping(uint192 => uint64)) public nonces;
    
    // ATTACK: Use different keys to bypass nonce
    // UserOp 1: key=0, seq=0
    // UserOp 2: key=1, seq=0  // Different key, resets sequence!
    
    // This is a FEATURE for parallel transactions
    // But custom implementations might not handle correctly
}

// VULNERABILITY in custom accounts:
contract VulnerableNonceHandling {
    uint256 public nonce;
    
    function validateUserOp(...) external {
        // WRONG: Only checks nonce matches, doesn't verify increment
        require(userOp.nonce == nonce);
        // Missing: nonce++
        
        // ATTACK: Replay same UserOp multiple times!
    }
}
```

---

## Attack Vector 3: Paymaster Exploitation

### Gas Drainage

```solidity
// Paymaster sponsors gas, attacker drains it

contract VulnerablePaymaster {
    // VULNERABLE: No per-user limits
    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory, uint256) {
        // Checks user is whitelisted
        require(whitelist[userOp.sender], "Not whitelisted");
        
        // ATTACK: Whitelisted user submits 1000 UserOps
        // Each costs 1M gas
        // Paymaster pays for all = drained
        
        return ("", 0);  // Accept to sponsor
    }
}

// SECURE: Rate limiting
contract SecurePaymaster {
    mapping(address => uint256) public dailyUsage;
    uint256 public constant DAILY_LIMIT = 10 ether;
    
    function validatePaymasterUserOp(...) external returns (bytes memory, uint256) {
        uint256 cost = calculateCost(userOp);
        
        require(
            dailyUsage[userOp.sender] + cost <= DAILY_LIMIT,
            "Daily limit exceeded"
        );
        
        dailyUsage[userOp.sender] += cost;
        return ("", 0);
    }
}
```

### Validation vs Execution Mismatch

```solidity
// Paymaster validates conditions that can change before execution

contract VulnerableTimePaymaster {
    // Sponsors gas if within time window
    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external view returns (bytes memory, uint256) {
        // Check time at VALIDATION
        require(block.timestamp < deadline, "Expired");
        return ("", 0);
    }
    
    // ATTACK:
    // 1. Submit UserOp just before deadline
    // 2. Bundler delays inclusion
    // 3. Execution happens after deadline
    // 4. Paymaster still pays! (validated before deadline)
}

// SECURE: Use postOp to verify conditions still hold
contract SecureTimePaymaster {
    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost
    ) external {
        // Re-check conditions at EXECUTION time
        require(block.timestamp < deadline, "Expired");
        // If failed, paymaster can refuse to pay
    }
}
```

### Paymaster Reentrancy

```solidity
// Paymaster postOp can be reentered

contract VulnerablePaymasterReentrancy {
    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost
    ) external {
        // Refund user
        address user = abi.decode(context, (address));
        
        // VULNERABLE: External call before state update
        (bool success,) = user.call{value: refundAmount}("");
        
        processedCosts[user] += actualGasCost;  // State updated after call
        
        // ATTACK: User's receive() calls back into paymaster
    }
}
```

---

## Attack Vector 4: Factory Manipulation

### Counterfactual Address Attacks

```solidity
// Account address is deterministic: CREATE2(factory, salt, initCode)

contract AccountFactory {
    function createAccount(
        address owner,
        uint256 salt
    ) external returns (address) {
        return Create2.deploy(
            0,
            bytes32(salt),
            abi.encodePacked(
                type(SmartAccount).creationCode,
                abi.encode(owner)
            )
        );
    }
}

// ATTACK: Front-run account creation
// 1. User calculates their future account address
// 2. User funds this address (before account deployed)
// 3. Attacker front-runs with different owner parameter
// 4. Attacker controls account, steals funds!

// DEFENSE: Include msg.sender in address derivation
function createAccount(
    address owner,
    uint256 salt
) external returns (address) {
    bytes32 finalSalt = keccak256(abi.encode(owner, salt));
    // Now only 'owner' can create account with this address
}
```

### Malicious Factory

```solidity
// Factory can deploy backdoored accounts

contract MaliciousFactory {
    function createAccount(address owner) external returns (address) {
        // Deploys account with backdoor
        return address(new BackdooredAccount(owner, address(this)));
    }
}

contract BackdooredAccount {
    address public owner;
    address public backdoor;  // Factory can also control!
    
    function execute(address dest, uint256 value, bytes calldata func) external {
        require(msg.sender == owner || msg.sender == backdoor);
        // Backdoor can drain account!
    }
}

// DEFENSE: Use audited, canonical factories only
```

---

## Attack Vector 5: Storage Access Violations

### ERC-4337 Storage Rules

```solidity
// During validation, accounts/paymasters have LIMITED storage access
// This prevents "time-of-check time-of-use" attacks

// ALLOWED during validation:
// - Account's own storage
// - Account's associated storage (staked entities)

// FORBIDDEN during validation:
// - Other accounts' storage
// - Global contract storage
// - External calls that access arbitrary storage

contract ViolatingAccount {
    function validateUserOp(...) external {
        // VIOLATION: Reading global state
        uint256 price = oracle.getPrice();  // Forbidden!
        
        // ATTACK: Price at validation ≠ price at execution
        // Account could fail execution but validation passed
        // Bundler wastes gas
    }
}
```

### Bundler Storage Tracking

```javascript
// Bundlers must trace storage access during simulation

async function simulateValidation(userOp) {
    const trace = await provider.send("debug_traceCall", [{
        to: entryPoint,
        data: encodeValidateUserOp(userOp)
    }, "latest", {
        tracer: "storageAccessTracer"
    }]);
    
    // Check for violations
    for (const access of trace.storageAccesses) {
        if (isViolation(access, userOp.sender)) {
            throw new Error("Storage access violation");
        }
    }
}
```

---

## Attack Vector 6: Gas Griefing

### Execution Revert Griefing

```solidity
// Account validates successfully but execution always reverts

contract GriefingAccount {
    function validateUserOp(...) external returns (uint256) {
        // Validation passes
        return 0;
    }
    
    function execute(...) external {
        // Always revert during execution
        revert("Gotcha bundler!");
        
        // Bundler paid gas for validation
        // But gets nothing for execution
    }
}

// DEFENSE: Bundlers simulate full execution before including
// EntryPoint charges account for gas even on revert
```

### Gas Estimation Manipulation

```solidity
// Return different gas based on simulation vs real execution

contract GasManipulator {
    function validateUserOp(...) external returns (uint256) {
        if (tx.origin == address(0)) {
            // Simulation (eth_call uses zero origin)
            return 0;  // Report low gas
        } else {
            // Real execution
            consumeLotsOfGas();  // Use more than estimated
        }
    }
}

// DEFENSE: Bundlers add safety margin to gas estimates
// EntryPoint enforces gas limits
```

---

## Audit Checklist

### Account Security

```markdown
## Smart Account Audit Checklist

### Signature Validation
□ Signature scheme secure (ECDSA, ERC-1271)?
□ userOpHash properly constructed?
□ No signature malleability?
□ Replay protection with nonce?

### Access Control
□ validateUserOp only callable by EntryPoint?
□ execute() properly restricted?
□ Upgrade mechanism secure?
□ Recovery mechanism safe?

### Storage Access
□ No forbidden storage access in validation?
□ No external calls that could be manipulated?
□ Associated storage properly staked?

### Gas Handling
□ Execution can't grief bundler?
□ Gas limits properly enforced?
□ Can always pay for gas (not locked)?
```

### Paymaster Security

```markdown
## Paymaster Audit Checklist

### Validation Logic
□ Proper rate limiting?
□ User verification robust?
□ Can't be drained by spam?
□ Validation conditions re-checked in postOp?

### Economic Security
□ Deposit management secure?
□ Can always cover sponsored gas?
□ Withdrawal restrictions appropriate?
□ No reentrancy in postOp?

### Integration
□ Handles all PostOpModes correctly?
□ Context encoding/decoding safe?
□ Compatible with intended accounts?
```

### Factory Security

```markdown
## Factory Audit Checklist

### Deployment
□ Address derivation includes owner?
□ Can't front-run account creation?
□ initCode matches expected bytecode?
□ Deployed account is correct implementation?

### Access Control
□ Factory can't backdoor accounts?
□ No admin functions that affect deployed accounts?
□ Upgrade path safe (if upgradeable)?
```

---

## Code Examples

### Secure Account Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@account-abstraction/contracts/core/BaseAccount.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureSmartAccount is BaseAccount {
    using ECDSA for bytes32;
    
    address public owner;
    IEntryPoint private immutable _entryPoint;
    
    constructor(IEntryPoint entryPoint_, address owner_) {
        _entryPoint = entryPoint_;
        owner = owner_;
    }
    
    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }
    
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256) {
        // Standard ECDSA validation
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        
        if (owner != hash.recover(userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }
        
        return 0;  // Success
    }
    
    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external {
        _requireFromEntryPoint();
        _call(dest, value, func);
    }
    
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }
}
```

---

## Related Resources

- [ERC-4337 Specification](https://eips.ethereum.org/EIPS/eip-4337)
- [Account Abstraction Documentation](https://docs.alchemy.com/docs/account-abstraction)
- [EntryPoint Contract](https://github.com/eth-infinitism/account-abstraction)
- [Bundler Specification](https://github.com/eth-infinitism/bundler-spec)
