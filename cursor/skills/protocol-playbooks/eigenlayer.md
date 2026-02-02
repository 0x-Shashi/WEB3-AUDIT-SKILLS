---
id: PLAYBOOK-EIGENLAYER
title: EigenLayer Integration Playbook
category: protocol-playbooks
protocol: eigenlayer
version: mainnet
difficulty: advanced
tags: [eigenlayer, restaking, avs, operator, slashing]
last_updated: 2026-01-31
---

# EigenLayer Integration Playbook

> **Attack Surface:** See [attack-trees/liquid-staking-attack-tree.md](../attack-trees/liquid-staking-attack-tree.md)

Comprehensive guide for integrating with EigenLayer - the restaking protocol that extends Ethereum security.

---

## Protocol Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        EigenLayer                                 │
├────────────────────┬─────────────────┬───────────────────────────┤
│     Restaking      │    Operators    │          AVS              │
│     (Stakers)      │                 │  (Actively Validated      │
│                    │                 │       Services)           │
├────────────────────┼─────────────────┼───────────────────────────┤
│ • Native ETH       │ • Run AVS       │ • Oracles                 │
│ • LSTs (stETH,     │   software      │ • Bridges                 │
│   rETH, etc.)      │ • Earn rewards  │ • DA layers               │
│ • Delegate to      │ • Risk slashing │ • Sequencers              │
│   operators        │                 │ • Keeper networks         │
└────────────────────┴─────────────────┴───────────────────────────┘

Flow: Staker → Deposits → Delegates → Operator → Registers → AVS
```

## Key Contracts

| Contract | Address (Mainnet) | Purpose |
|----------|-------------------|---------|
| StrategyManager | `0x858646372CC42E1A627fcE94aa7A7033e7CF075A` | Manages staking strategies |
| DelegationManager | `0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A` | Handles delegation |
| Slasher | `0xD92145c07f8Ed1D392c1B88017934E301CC1c3Cd` | Slashing logic |
| EigenPodManager | `0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338` | Native ETH restaking |
| AVSDirectory | `0x135DDa560e946695d6f155dACaFC6f1F25C1F5AF` | AVS registration |

---

## Core Concepts

### 1. Restaking Types

```solidity
// Type 1: Native Restaking (ETH)
// Validator points withdrawal credentials to EigenPod
// Full 32 ETH is restaked

// Type 2: LST Restaking
// Deposit liquid staking tokens (stETH, rETH, cbETH, etc.)
// Via StrategyManager
interface IStrategyManager {
    function depositIntoStrategy(
        IStrategy strategy,
        IERC20 token,
        uint256 amount
    ) external returns (uint256 shares);
    
    function queueWithdrawal(
        uint256[] calldata strategyIndexes,
        IStrategy[] calldata strategies,
        uint256[] calldata shares,
        address withdrawer,
        bool undelegateIfPossible
    ) external returns (bytes32);
}
```

### 2. Delegation Flow

```solidity
interface IDelegationManager {
    // Staker delegates all restaked assets to operator
    function delegateTo(
        address operator,
        SignatureWithExpiry memory approverSignatureAndExpiry,
        bytes32 approverSalt
    ) external;
    
    // Staker undelegates (starts withdrawal queue)
    function undelegate(address staker) external returns (bytes32[] memory);
    
    // Complete withdrawal after delay
    function completeQueuedWithdrawal(
        Withdrawal calldata withdrawal,
        IERC20[] calldata tokens,
        uint256 middlewareTimesIndex,
        bool receiveAsTokens
    ) external;
}

struct Withdrawal {
    address staker;
    address delegatedTo;
    address withdrawer;
    uint256 nonce;
    uint32 startBlock;
    IStrategy[] strategies;
    uint256[] shares;
}
```

### 3. Operator Registration

```solidity
// Operators must register with EigenLayer and each AVS
interface IDelegationManager {
    function registerAsOperator(
        OperatorDetails calldata registeringOperatorDetails,
        string calldata metadataURI
    ) external;
}

struct OperatorDetails {
    address earningsReceiver;    // Where rewards go
    address delegationApprover;  // Who can delegate (0 = anyone)
    uint32 stakerOptOutWindowBlocks;  // Min notice for stakers
}

// Then register with AVS
interface IAVSDirectory {
    function registerOperatorToAVS(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature
    ) external;
}
```

---

## Integration Patterns

### Depositing LSTs

```solidity
contract LSTRestaker {
    IStrategyManager public strategyManager;
    IStrategy public stETHStrategy;
    IERC20 public stETH;
    
    function restakeStETH(uint256 amount) external returns (uint256 shares) {
        // 1. Transfer stETH from user
        stETH.transferFrom(msg.sender, address(this), amount);
        
        // 2. Approve strategy manager
        stETH.approve(address(strategyManager), amount);
        
        // 3. Deposit into strategy
        shares = strategyManager.depositIntoStrategy(
            stETHStrategy,
            stETH,
            amount
        );
        
        // User now has shares in the strategy
        // Can delegate to operator
    }
}
```

### Native ETH Restaking

```solidity
// Native restaking requires running a validator
// Withdrawal credentials point to EigenPod

contract NativeRestaker {
    IEigenPodManager public eigenPodManager;
    
    // Create an EigenPod for the user
    function createPod() external returns (address pod) {
        pod = eigenPodManager.createPod();
        // User must set this pod as validator withdrawal credentials
    }
    
    // After validator exits, stake ETH in pod
    function stakeInPod(
        bytes calldata pubkey,
        bytes calldata signature,
        bytes32 depositDataRoot
    ) external payable {
        IEigenPod pod = eigenPodManager.ownerToPod(msg.sender);
        pod.stake{value: msg.value}(pubkey, signature, depositDataRoot);
    }
}
```

### Delegating to Operator

```solidity
function delegateToOperator(address operator) external {
    // Optional: Operator can require approval signature
    ISignatureUtils.SignatureWithExpiry memory noSig = 
        ISignatureUtils.SignatureWithExpiry({
            signature: "",
            expiry: 0
        });
    
    delegationManager.delegateTo(
        operator,
        noSig,
        bytes32(0)
    );
}
```

### Withdrawing

```solidity
function initiateWithdrawal(
    IStrategy[] calldata strategies,
    uint256[] calldata shares
) external returns (bytes32 withdrawalRoot) {
    uint256[] calldata strategyIndexes = new uint256[](strategies.length);
    
    // Queue the withdrawal
    withdrawalRoot = strategyManager.queueWithdrawal(
        strategyIndexes,
        strategies,
        shares,
        msg.sender,  // withdrawer
        true         // undelegate if possible
    );
    
    // Must wait for withdrawal delay before completing
}

function completeWithdrawal(
    IDelegationManager.Withdrawal calldata withdrawal,
    IERC20[] calldata tokens
) external {
    // After delay period (7 days), complete withdrawal
    delegationManager.completeQueuedWithdrawal(
        withdrawal,
        tokens,
        0,     // middlewareTimesIndex
        true   // receiveAsTokens
    );
}
```

---

## AVS Integration

### Building an AVS

```solidity
// AVS must implement registration and task validation

interface IAVS {
    // Called when operator registers
    function registerOperator(
        address operator,
        bytes calldata quorumNumbers
    ) external;
    
    // Called when operator deregisters
    function deregisterOperator(
        address operator,
        bytes calldata quorumNumbers
    ) external;
    
    // Define slashing conditions
    function getSlashableStake(
        address operator,
        uint32 referenceBlockNumber
    ) external view returns (uint256);
}

// Example: Simple Oracle AVS
contract OracleAVS is IAVS {
    mapping(address => bool) public registeredOperators;
    mapping(bytes32 => mapping(address => bytes32)) public submissions;
    
    function registerOperator(address operator, bytes calldata) external {
        // Verify operator is registered with EigenLayer
        require(
            delegationManager.isOperator(operator),
            "Not an operator"
        );
        registeredOperators[operator] = true;
    }
    
    function submitData(bytes32 taskId, bytes32 data) external {
        require(registeredOperators[msg.sender], "Not registered");
        submissions[taskId][msg.sender] = data;
    }
    
    // Slash if operator submits wrong data
    function reportMisbehavior(
        address operator,
        bytes32 taskId,
        bytes32 correctData
    ) external {
        require(
            submissions[taskId][operator] != correctData,
            "Data was correct"
        );
        
        // Trigger slashing via Slasher contract
        slasher.freezeOperator(operator);
    }
}
```

---

## Security Considerations

###  Critical Checks

```
[ ] Slashing conditions clearly defined and bounded?
[ ] Withdrawal delay properly enforced (7 days)?
[ ] Operator registration validated?
[ ] Delegation approvals checked?
[ ] Reward distribution accurate?
```

### Slashing Risks

```solidity
// Operators can be slashed by any AVS they're registered with
// Slashing affects ALL delegated stake

// RISK: Malicious AVS slashing honest operators
// MITIGATION: Carefully vet AVSs before registering

// RISK: Cascading slashing across multiple AVSs
// MITIGATION: Slashing caps and veto period

interface ISlasher {
    // Freeze operator (first step of slashing)
    function freezeOperator(address operator) external;
    
    // Check if operator is frozen
    function isFrozen(address operator) external view returns (bool);
    
    // Operator can be slashed while frozen
    // Has veto period to challenge
}
```

### Withdrawal Queue Manipulation

```solidity
// VULNERABLE: Not accounting for pending withdrawals
function getAvailableStake(address staker) external view returns (uint256) {
    return strategyManager.stakerStrategyShares(staker, strategy);
    // Doesn't account for queued withdrawals!
}

// SECURE: Check withdrawal queue
function getAvailableStake(address staker) external view returns (uint256) {
    uint256 total = strategyManager.stakerStrategyShares(staker, strategy);
    uint256 queued = getQueuedWithdrawals(staker);
    return total - queued;
}
```

---

## Common Vulnerabilities

### 1. Double Delegation

```solidity
// VULNERABLE: Not checking existing delegation
function autoDelegate(address operator) external {
    delegationManager.delegateTo(operator, noSig, bytes32(0));
    // Reverts if already delegated!
}

// SECURE: Check delegation status
function autoDelegate(address operator) external {
    if (delegationManager.delegatedTo(msg.sender) == address(0)) {
        delegationManager.delegateTo(operator, noSig, bytes32(0));
    }
}
```

### 2. Insufficient Withdrawal Delay

```solidity
// Withdrawal delay is 7 days (50,400 blocks at 12s)
// This allows time for slashing if misbehavior detected

// VULNERABLE: AVS assuming instant withdrawals
function claimRewards() external {
    uint256 stake = getStake(msg.sender);
    // Stake might be in withdrawal queue!
}

// SECURE: Account for escrow period
function claimRewards() external {
    uint256 activeStake = getActiveStake(msg.sender);
    // Only count stake not in withdrawal
}
```

### 3. Operator Key Management

```solidity
// Operators have significant responsibility
// Key compromise = potential slashing

// BEST PRACTICES:
// - Use multisig for operator registration
// - Implement key rotation mechanisms
// - Monitor for unauthorized AVS registrations
```

### 4. Reward Distribution Errors

```solidity
// VULNERABLE: Proportional rewards without snapshotting
function distributeRewards(uint256 amount) external {
    for (uint i = 0; i < stakers.length; i++) {
        uint256 share = stakes[stakers[i]] / totalStake;
        rewards[stakers[i]] += amount * share;
    }
    // Stakes could change during distribution!
}

// SECURE: Snapshot-based distribution
function distributeRewards(uint256 amount, uint256 blockNumber) external {
    for (uint i = 0; i < stakers.length; i++) {
        uint256 share = getStakeAtBlock(stakers[i], blockNumber);
        rewards[stakers[i]] += amount * share / totalStakeAtBlock(blockNumber);
    }
}
```

---

## Integration Checklist

### For Stakers
```
[ ] Understand slashing risks of operator's AVSs
[ ] Know the 7-day withdrawal delay
[ ] Verify operator reputation and track record
[ ] Monitor operator's AVS registrations
```

### For Operators
```
[ ] Secure key management (multisig recommended)
[ ] Carefully vet AVSs before registration
[ ] Maintain sufficient infrastructure uptime
[ ] Monitor for slashing events
[ ] Clear communication with delegators
```

### For AVS Builders
```
[ ] Define clear, fair slashing conditions
[ ] Implement slashing caps
[ ] Provide veto/challenge mechanism
[ ] Document operator requirements
[ ] Ensure reward distribution is accurate
```

---

## Quick Reference

### Key Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Withdrawal Delay | 7 days | Time for slashing if needed |
| Max Slashing | Protocol-defined | Limit slashing per event |
| Min Stake | Strategy-dependent | Minimum deposit |

### Supported LSTs

| Token | Strategy Address | 
|-------|-----------------|
| stETH | 0x93c4b944D05dfe6df7645A86cd2206016c51564D |
| rETH | 0x1BeE69b7dFFfA4E2d53C2a2Df135C388AD25dCD2 |
| cbETH | 0x54945180dB7943c0ed0FEE7EdaB2Bd24620256bc |
| wBETH | 0x7CA911E83dabf90C90dD3De5411a10F1A6112184 |

### Withdrawal States

```
1. Queued - Withdrawal initiated, in delay period
2. Pending - Delay passed, awaiting completion
3. Completed - Funds returned to withdrawer
```

---

## Red Flags 

- [ ] Operator registered with unknown/unaudited AVS
- [ ] No slashing caps defined by AVS
- [ ] AVS can slash without challenge period
- [ ] Operator using single-key (not multisig)
- [ ] Rewards distributed without stake snapshots
- [ ] Ignoring withdrawal delay in calculations
- [ ] Not verifying operator registration status
- [ ] AVS with unlimited slashing authority
