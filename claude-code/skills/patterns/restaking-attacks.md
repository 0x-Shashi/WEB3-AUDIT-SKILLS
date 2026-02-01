---
id: ATTACK-RESTAKING
title: Restaking & AVS Attacks
category: attack-patterns
difficulty: expert
tags: [restaking, eigenlayer, avs, slashing, operator]
last_updated: 2026-01-31
---

# Restaking & AVS Attacks

## Overview

Restaking extends staked asset security to additional services (AVSs). This creates complex trust relationships and new attack surfaces involving slashing, operators, and withdrawal queues.

```
┌─────────────────────────────────────────────────────────────────┐
│                  RESTAKING ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STAKERS              OPERATORS              AVS                │
│  ┌──────┐            ┌──────────┐          ┌──────────┐        │
│  │Stake │───────────►│ Delegate │─────────►│ Secure   │        │
│  │ ETH  │            │ to Ops   │          │ Services │        │
│  └──────┘            └──────────┘          └──────────┘        │
│     │                     │                      │              │
│     │                     │                      │              │
│     ▼                     ▼                      ▼              │
│  ┌────────────────────────────────────────────────────┐        │
│  │              ATTACK SURFACES                       │        │
│  │  • Slashing manipulation                           │        │
│  │  • Operator collusion                              │        │
│  │  • Withdrawal queue attacks                        │        │
│  │  • AVS-level exploits                              │        │
│  │  • Cross-AVS contagion                             │        │
│  └────────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

---

## EigenLayer Architecture

### Core Components

```solidity
// EigenLayer Contracts Overview

contract StrategyManager {
    // Deposits ETH/LSTs into strategies
    mapping(address => mapping(IStrategy => uint256)) public stakerStrategyShares;
    
    function depositIntoStrategy(
        IStrategy strategy,
        IERC20 token,
        uint256 amount
    ) external returns (uint256 shares);
}

contract DelegationManager {
    // Delegates stake to operators
    mapping(address => address) public delegatedTo;
    
    function delegateTo(
        address operator,
        SignatureWithExpiry memory approverSignatureAndExpiry,
        bytes32 approverSalt
    ) external;
    
    // Withdrawals have delay
    function queueWithdrawals(
        QueuedWithdrawalParams[] calldata queuedWithdrawalParams
    ) external returns (bytes32[] memory);
    
    function completeQueuedWithdrawal(
        Withdrawal calldata withdrawal,
        IERC20[] calldata tokens,
        uint256 middlewareTimesIndex,
        bool receiveAsTokens
    ) external;
}

contract Slasher {
    // AVSs can slash operators
    function slashOperator(
        address operator,
        uint256 amount
    ) external onlyAVS;
}
```

---

## Attack Vector 1: Slashing Manipulation

### Unjust Slashing

```solidity
// AVS can slash delegated stake - what if AVS is malicious?

contract MaliciousAVS {
    ISlasher public slasher;
    
    // Claim operator misbehaved (even if they didn't)
    function fakeSlash(address operator, uint256 amount) external {
        // If slasher trusts this AVS without verification...
        slasher.slashOperator(operator, amount);
        // Operator and all delegators lose stake!
    }
}

// ATTACK SCENARIO:
// 1. Create AVS with malicious slashing logic
// 2. Attract operators with good rewards
// 3. Wait for substantial delegation
// 4. Slash all operators unjustly
// 5. Extract slashed funds
```

### Slashing Protection Vulnerabilities

```solidity
// Common slashing protection patterns and their weaknesses

contract SlashingProtection {
    // Pattern 1: Time-delayed slashing
    // WEAKNESS: Delay might be too short to respond
    uint256 public constant SLASHING_DELAY = 7 days;
    
    mapping(bytes32 => uint256) public pendingSlashes;
    
    function initiateSlash(address operator, uint256 amount) external {
        bytes32 slashId = keccak256(abi.encode(operator, amount, block.timestamp));
        pendingSlashes[slashId] = block.timestamp + SLASHING_DELAY;
    }
    
    // Pattern 2: Challenge period
    // WEAKNESS: Challenge cost might be prohibitive
    function challengeSlash(bytes32 slashId, bytes calldata proof) external {
        // Requires bond to challenge
        require(msg.value >= CHALLENGE_BOND);
        // Expensive for small stakers to challenge
    }
    
    // Pattern 3: Multi-sig approval
    // WEAKNESS: Collusion among signers
    function executeSlash(bytes32 slashId, bytes[] calldata signatures) external {
        require(signatures.length >= THRESHOLD);
        // All signers could be same entity
    }
}
```

### Defense Patterns

```solidity
// Secure slashing implementation

contract SecureSlashing {
    // 1. Require cryptographic proof of misbehavior
    function slashWithProof(
        address operator,
        bytes calldata misbehaviorProof,
        bytes calldata signedCommitment
    ) external {
        // Verify operator actually signed conflicting data
        require(
            verifyMisbehavior(operator, misbehaviorProof, signedCommitment),
            "Invalid proof"
        );
        _slash(operator);
    }
    
    // 2. Proportional slashing (not all-or-nothing)
    function calculateSlashAmount(
        uint256 severity,
        uint256 operatorStake
    ) public pure returns (uint256) {
        // Mild offense: 1%, Severe: 10%, Critical: 100%
        uint256 percentage = severity == 1 ? 100 : severity == 2 ? 1000 : 10000;
        return operatorStake * percentage / 10000;
    }
    
    // 3. Veto power for extreme cases
    address public guardian;
    
    function vetoSlash(bytes32 slashId) external {
        require(msg.sender == guardian);
        delete pendingSlashes[slashId];
    }
}
```

---

## Attack Vector 2: Operator Collusion

### Multi-AVS Attack

```
Operator runs services for multiple AVSs with same stake

ATTACK:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Operator Stake: 100 ETH                                        │
│                                                                 │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                │
│  │   AVS A    │  │   AVS B    │  │   AVS C    │                │
│  │ Secures    │  │ Secures    │  │ Secures    │                │
│  │ $50M       │  │ $30M       │  │ $20M       │                │
│  └────────────┘  └────────────┘  └────────────┘                │
│        │               │               │                        │
│        └───────────────┼───────────────┘                        │
│                        │                                        │
│         All secured by same 100 ETH!                            │
│         Total secured: $100M with only 100 ETH collateral       │
│                                                                 │
│  ATTACK: Misbehave on ALL AVSs simultaneously                   │
│  - Steal $100M from AVSs                                        │
│  - Lose only 100 ETH (slashed once, secures all)                │
│  - Profit: $100M - 100 ETH = ~$99.7M                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Detection & Prevention

```solidity
// Check for over-leveraged operators

contract OperatorRiskChecker {
    struct OperatorProfile {
        uint256 totalStake;
        uint256 totalSecured;  // Sum across all AVSs
        uint256 numAVSs;
    }
    
    function calculateRiskRatio(
        address operator
    ) external view returns (uint256) {
        OperatorProfile memory profile = getOperatorProfile(operator);
        
        // Risk ratio = Total secured / Total stake
        // Should be bounded (e.g., max 10x)
        return profile.totalSecured * 1e18 / profile.totalStake;
    }
    
    function isOperatorOverLeveraged(
        address operator
    ) external view returns (bool) {
        uint256 riskRatio = calculateRiskRatio(operator);
        return riskRatio > MAX_LEVERAGE_RATIO;  // e.g., 10x
    }
}

// AVS-side protection
contract SecureAVS {
    uint256 public constant MAX_OPERATOR_LEVERAGE = 5e18;  // 5x
    
    function registerOperator(address operator) external {
        uint256 leverage = riskChecker.calculateRiskRatio(operator);
        require(
            leverage <= MAX_OPERATOR_LEVERAGE,
            "Operator over-leveraged"
        );
        _registerOperator(operator);
    }
}
```

---

## Attack Vector 3: Withdrawal Queue Attacks

### Queue Manipulation

```solidity
// Withdrawal delays create attack opportunities

contract WithdrawalQueue {
    uint256 public constant WITHDRAWAL_DELAY = 7 days;
    
    mapping(address => Withdrawal[]) public withdrawals;
    
    struct Withdrawal {
        uint256 amount;
        uint256 unlockTime;
    }
    
    // ATTACK 1: Time the market during withdrawal delay
    // 1. See large withdrawal queued
    // 2. Manipulate price during 7-day window
    // 3. Profit from price movement
    
    // ATTACK 2: Slash before withdrawal completes
    // 1. Operator queues withdrawal
    // 2. AVS detects and slashes before completion
    // 3. Funds slashed instead of withdrawn
}
```

### Correlated Withdrawal Attack

```
Mass withdrawals can destabilize AVS security

ATTACK:
1. Accumulate large stake across multiple accounts
2. Delegate to operators across target AVS
3. Simultaneously queue withdrawals
4. AVS security drops dramatically
5. Attack AVS during vulnerability window
6. Complete withdrawals (if not slashed)

DEFENSE: 
- Rate limit withdrawals
- Require minimum notice period
- Security buffer requirements
```

### Defense Implementation

```solidity
contract SecureWithdrawals {
    uint256 public constant MAX_WITHDRAWAL_RATE = 10;  // 10% per day
    uint256 public constant MIN_SECURITY_BUFFER = 150;  // 150% collateralization
    
    uint256 public lastWithdrawalWindow;
    uint256 public withdrawnThisWindow;
    
    function queueWithdrawal(uint256 amount) external {
        // Check rate limit
        if (block.timestamp > lastWithdrawalWindow + 1 days) {
            lastWithdrawalWindow = block.timestamp;
            withdrawnThisWindow = 0;
        }
        
        uint256 maxAllowed = totalStaked * MAX_WITHDRAWAL_RATE / 100;
        require(
            withdrawnThisWindow + amount <= maxAllowed,
            "Withdrawal rate exceeded"
        );
        
        // Check security buffer
        uint256 remainingStake = totalStaked - withdrawnThisWindow - amount;
        uint256 requiredStake = totalSecured * 100 / MIN_SECURITY_BUFFER;
        require(
            remainingStake >= requiredStake,
            "Would breach security buffer"
        );
        
        withdrawnThisWindow += amount;
        _queueWithdrawal(msg.sender, amount);
    }
}
```

---

## Attack Vector 4: AVS-Level Exploits

### Malicious AVS Design

```solidity
// AVS that steals from stakers through subtle mechanisms

contract MaliciousAVS {
    // ATTACK 1: Excessive fees
    function claimRewards() external {
        uint256 rewards = calculateRewards(msg.sender);
        uint256 fee = rewards * 99 / 100;  // 99% fee!
        // Users get almost nothing
    }
    
    // ATTACK 2: Locked stake
    function unstake() external {
        // Always reverts, stake is trapped
        revert("Maintenance mode");
    }
    
    // ATTACK 3: Fake slashing
    function triggerSlashing() external onlyOwner {
        // Slash all operators, take the funds
        for (uint i = 0; i < operators.length; i++) {
            slasher.slash(operators[i], stakes[operators[i]]);
        }
    }
}
```

### AVS Audit Checklist

```markdown
## AVS Security Checklist

### Slashing Logic
□ Slashing requires cryptographic proof?
□ Challenge period for disputed slashes?
□ Slashing amounts proportional to offense?
□ Cannot slash more than operator's stake?
□ Slashed funds distributed fairly?

### Reward Distribution
□ Reward calculation transparent?
□ No excessive fees hidden in logic?
□ Rewards claimable without restrictions?
□ Unclaimed rewards don't expire unfairly?

### Stake Management
□ Unstaking always possible (with delay)?
□ No hidden lock-up extensions?
□ Stake accounting accurate?
□ No precision loss in share calculations?

### Governance
□ Upgrade mechanism has timelock?
□ Critical parameters have bounds?
□ Emergency functions are limited?
□ Governance cannot rug stakers?
```

---

## Attack Vector 5: Cross-AVS Contagion

### Shared Operator Failure

```
One AVS failure spreads to others through shared operators

SCENARIO:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  AVS A: Gets exploited, slashes all operators                   │
│                         │                                       │
│                         ▼                                       │
│  Operators: Lose significant stake                              │
│                         │                                       │
│          ┌──────────────┼──────────────┐                        │
│          ▼              ▼              ▼                        │
│       AVS B          AVS C          AVS D                       │
│  (Same operators, now under-secured)                            │
│                                                                 │
│  CONTAGION: All AVSs now vulnerable!                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Isolation Mechanisms

```solidity
// Strategies for limiting contagion

contract IsolatedAVS {
    // Strategy 1: Dedicated stake (not shared)
    mapping(address => uint256) public dedicatedStake;
    
    function stakeDedicated(uint256 amount) external {
        // This stake can ONLY secure this AVS
        // Not counted toward other AVS requirements
        _transferStake(msg.sender, address(this), amount);
        dedicatedStake[msg.sender] += amount;
    }
    
    // Strategy 2: Insurance fund
    uint256 public insuranceFund;
    
    function contributeInsurance() external payable {
        insuranceFund += msg.value;
    }
    
    function coverShortfall(uint256 amount) internal {
        if (amount > operatorStake) {
            uint256 shortfall = amount - operatorStake;
            require(insuranceFund >= shortfall, "Insurance insufficient");
            insuranceFund -= shortfall;
        }
    }
    
    // Strategy 3: Operator diversification requirements
    uint256 public constant MAX_OPERATOR_SHARE = 20;  // Max 20% per operator
    
    function verifyDiversification() public view returns (bool) {
        for (uint i = 0; i < operators.length; i++) {
            uint256 share = operatorStakes[operators[i]] * 100 / totalStaked;
            if (share > MAX_OPERATOR_SHARE) return false;
        }
        return true;
    }
}
```

---

## Audit Framework

### Restaking Protocol Audit

```markdown
## Core Protocol Review

### Delegation Security
□ Delegation signature cannot be replayed?
□ Delegation can be revoked?
□ Operator cannot steal delegated funds directly?
□ Delegation metadata stored correctly?

### Withdrawal Security
□ Withdrawal delay sufficient for slashing?
□ Queue cannot be manipulated?
□ Withdrawals cannot bypass delay?
□ Funds always retrievable eventually?

### Slashing Security
□ Only authorized slashers can slash?
□ Slashing amounts bounded?
□ Slashing cannot exceed actual stake?
□ Slashing distribution is fair?

### Share Accounting
□ Deposit/withdraw share math correct?
□ No inflation attacks possible?
□ Rounding always favors protocol?
□ Total shares = sum of user shares?

## Integration Review

### AVS Registration
□ AVS registration permissioned or open?
□ Malicious AVS can be deregistered?
□ AVS cannot drain operator stake unfairly?
□ AVS parameters publicly verifiable?

### Operator Requirements
□ Minimum stake requirements enforced?
□ Operator leverage limits enforced?
□ Performance requirements clear?
□ Exit conditions well-defined?
```

---

## Code Examples

### Secure Restaking Pattern

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureRestakingAVS {
    // Minimum operator stake
    uint256 public constant MIN_OPERATOR_STAKE = 32 ether;
    
    // Maximum leverage ratio
    uint256 public constant MAX_LEVERAGE = 5e18;  // 5x
    
    // Slashing requires proof
    struct SlashProof {
        bytes32 commitment1;
        bytes32 commitment2;
        bytes signature1;
        bytes signature2;
        // Proof that same operator signed conflicting commitments
    }
    
    // Register with checks
    function registerOperator(address operator) external {
        uint256 stake = getOperatorStake(operator);
        require(stake >= MIN_OPERATOR_STAKE, "Insufficient stake");
        
        uint256 leverage = getOperatorLeverage(operator);
        require(leverage <= MAX_LEVERAGE, "Over-leveraged");
        
        _register(operator);
    }
    
    // Slash with proof
    function slashOperator(
        address operator,
        SlashProof calldata proof
    ) external {
        // Verify operator actually double-signed
        require(
            verifyDoubleSign(operator, proof),
            "Invalid slash proof"
        );
        
        // Calculate proportional slash
        uint256 slashAmount = calculateSlashAmount(operator);
        
        // Execute slash through EigenLayer
        eigenLayerSlasher.slash(operator, slashAmount);
        
        emit OperatorSlashed(operator, slashAmount);
    }
    
    // Withdrawal with rate limiting
    function initiateWithdrawal(uint256 amount) external {
        require(
            !wouldBreach SecurityBuffer(amount),
            "Security buffer breach"
        );
        
        require(
            !exceedsWithdrawalRate(amount),
            "Rate limit exceeded"
        );
        
        _queueWithdrawal(msg.sender, amount);
    }
}
```

---

## Related Resources

- [EigenLayer Documentation](https://docs.eigenlayer.xyz/)
- [EigenLayer Whitepaper](https://docs.eigenlayer.xyz/overview/whitepaper)
- [Restaking Risk Framework](https://research.eigenlayer.xyz/)
- [AVS Security Guidelines](https://docs.eigenlayer.xyz/developers/avs-guidelines)
