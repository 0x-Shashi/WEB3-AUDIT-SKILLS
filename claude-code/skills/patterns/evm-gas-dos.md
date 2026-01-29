# EVM, Gas & DoS Vulnerability Patterns

> **AI Skill**: This file contains EVM-specific, gas-related, and denial-of-service vulnerability patterns extracted from real audit reports.

## Quick Reference Index

| Category | Pattern | Severity |
|----------|---------|----------|
| [Gas](#1-gas-vulnerabilities) | Transaction Costs, L1→L2 Gas | Medium-High |
| [DoS](#2-dos-vulnerabilities) | Replay Attacks, Block Gas Limit | Medium-High |
| [Context](#3-context-vulnerabilities) | msg.value, msg.sender | Medium-High |
| [Cross-Layer](#4-cross-layer-vulnerabilities) | L1↔L2 Sync, Upgrade Failures | High |
| [Data Location](#5-data-location-vulnerabilities) | Storage vs Memory, Calldata | Medium |

---

## 1. Gas Vulnerabilities

### 1.1 L1→L2 Transaction Gas Miscalculation

**Vulnerability**: Incorrect gas check allows L1→L2 transaction without sufficient gas for both overhead AND intrinsic costs.

**Context**: zkSync, Arbitrum, Optimism L1→L2 bridging

**Formula**:
```
totalGasLimit = overhead + actualGasLimit
actualGasLimit = intrinsicCosts + executionCosts
```

**Pattern to Look For**:
```solidity
// VULNERABLE: Only checks minimal priority gas, not total required
require(
    getMinimalPriorityTransactionGasLimit(encodedLength, factoryDeps, gasPerPubdata)
    <= transaction.gasLimit,  // Only checks gasLimit, not total
    "Insufficient gas"
);

// Later: Transaction fails because overhead wasn't accounted
function processL1Tx() {
    let gasLimitForTx = _totalGasLimit - overhead;  // May underflow or leave nothing for execution
}
```

**Secure Pattern**:
```solidity
require(
    transaction.gasLimit >= getOverhead() + getIntrinsicCosts() + MIN_EXECUTION_GAS,
    "Insufficient total gas"
);
```

**Audit Checklist**:
- [ ] Does L1→L2 gas calculation include overhead?
- [ ] Does it include intrinsic costs?
- [ ] Does it include minimum execution gas?
- [ ] Can underflow occur when subtracting overhead?

---

### 1.2 Unit Mismatch in Transaction Encoding

**Vulnerability**: Using different units (bytes vs words) in gas calculations causes 32x overcharge.

**Pattern to Look For**:
```solidity
// In Solidity: uses BOOTLOADER_TX_ENCODING_SPACE (bytes)
uint256 overheadForLength = Math.ceilDiv(
    _encodingLength * batchOverheadGas,
    BOOTLOADER_TX_ENCODING_SPACE  // e.g., 1_000_000 bytes
);

// In bootloader: uses BOOTLOADER_MEMORY_FOR_TXS (words = bytes/32)
let overheadForLength := ceilDiv(
    safeMul(txEncodeLen, totalBatchOverhead),
    BOOTLOADER_MEMORY_FOR_TXS()  // e.g., 31_250 words (1M/32)
);
// Result: overhead is 32x larger than expected!
```

**Audit Checklist**:
- [ ] Are units consistent across L1 and L2 calculations?
- [ ] Are bytes vs words clearly documented?
- [ ] Is there unit conversion where needed?

---

### 1.3 L1→L2 Revert Consumes All Gas

**Vulnerability**: Near call opcode (zkSync) doesn't return unspent gas on REVERT, unlike EVM's 63/64 rule.

**Pattern to Look For**:
```yul
// zkSync near call - no gas refund on revert
// If L2 transaction reverts, ALL gas is consumed (like deprecated THROW)

function executeL1Tx() {
    // Uses near call - exempt from 63/64 rule
    // On REVERT: gas NOT returned to caller
    nearCallPanic()  // Consumes all remaining gas
}
```

**Impact**: Users lose entire gas payment even for simple reverts.

**Audit Checklist**:
- [ ] Does L1→L2 path use near call?
- [ ] Is gas refunded on revert?
- [ ] Is this behavior documented for users?

---

## 2. DoS Vulnerabilities

### 2.1 EIP-155 Replay Attack

**Vulnerability**: Not enforcing EIP-155 chain ID signature allows transaction replay from other networks.

**Pattern to Look For**:
```rust
// VULNERABLE: Only checks chain ID if present in legacy tx
let should_check_chain_id = if matches!(
    transaction_type, TransactionType::LegacyTransaction
) && common_data.extract_chain_id().is_some()  // Only if chain_id exists!
{
    U256([1, 0, 0, 0])
} else {
    U256::zero()  // No chain ID check for EIP-155 unprotected txs
};
```

**Attack Scenario**:
1. User signs tx on network without EIP-155
2. Attacker replays tx on your network
3. Transaction executes, attacker profits from gas/value

**Secure Pattern**:
```rust
// ALWAYS require chain ID in signature
require(
    transaction.chain_id == EXPECTED_CHAIN_ID,
    "Invalid chain ID"
);
```

---

### 2.2 Wrong ProfitManager Causes Revert

**Vulnerability**: Single ProfitManager in constructor breaks multi-market systems.

**Pattern to Look For**:
```solidity
contract GuildToken {
    ProfitManager public profitManager;  // Set once in constructor
    
    constructor(address _profitManager) {
        profitManager = ProfitManager(_profitManager);  // Fixed forever!
    }
    
    // When called from different market's term:
    function notifyGaugeLoss(address gauge) external {
        require(msg.sender == address(profitManager), "UNAUTHORIZED");  // Reverts!
        // Different market uses different ProfitManager
    }
}
```

**Impact**: Cross-market operations fail, bad debt cannot be processed.

**Secure Pattern**:
```solidity
// Dynamic ProfitManager per gauge/market
mapping(address => address) public gaugeProfitManagers;

function notifyGaugeLoss(address gauge) external {
    require(msg.sender == gaugeProfitManagers[gauge], "UNAUTHORIZED");
}
```

---

### 2.3 Same-Block Stake/Unstake Exploit

**Vulnerability**: Flash loan stake → claim rewards → unstake in same block dilutes long-term staker rewards.

**Pattern to Look For**:
```solidity
// VULNERABLE: No cooldown between stake and claim/unstake
function stake(uint256 amount) external {
    stakes[msg.sender] += amount;
    // No timestamp recorded
}

function claimRewards() external {
    uint256 reward = calculateReward(msg.sender);
    _transfer(msg.sender, reward);
    // Attacker stakes 1M, claims, unstakes in same tx
}
```

**Attack Flow**:
1. Flash loan large amount
2. Stake into protocol
3. Trigger reward distribution (e.g., repay loan with interest)
4. Claim share of rewards
5. Unstake
6. Repay flash loan

**Secure Patterns**:
```solidity
// Option 1: Block same-block unstake
mapping(address => uint256) public stakeTimestamp;

function stake(uint256 amount) external {
    stakeTimestamp[msg.sender] = block.timestamp;
    stakes[msg.sender] += amount;
}

function unstake(uint256 amount) external {
    require(block.timestamp > stakeTimestamp[msg.sender], "Same block");
    // ...
}

// Option 2: Warm-up period for reward eligibility
function claimRewards() external {
    require(
        block.timestamp >= stakeTimestamp[msg.sender] + WARMUP_PERIOD,
        "Warmup not complete"
    );
}
```

---

## 3. Context Vulnerabilities

### 3.1 L2 ETH Inaccessible via L1 Transactions

**Vulnerability**: L1→L2 transactions use msg.value from L1, ignoring user's L2 balance.

**Pattern to Look For**:
```solidity
// L1 -> L2 transaction
function requestL2Transaction(
    address _contractL2,
    uint256 _l2Value,
    bytes calldata _calldata
) external payable {
    // msg.value comes from L1 payment
    // User cannot use their existing L2 ETH balance
    require(msg.value >= _l2Value + baseCost, "Insufficient ETH");
}
```

**Impact**: User with ETH on L2 cannot use it for L1→L2 transactions. Critical if malicious upgrade scheduled - users trapped.

**Audit Checklist**:
- [ ] Can users access L2 balances via L1 calls?
- [ ] Is there alternative withdrawal path?
- [ ] Can protocol freeze user L2 funds?

---

### 3.2 Deposit Limit Bypass via Failed Deposits

**Vulnerability**: Deposit limits not tracked until actually enforced; failed deposits can reset counters.

**Pattern to Look For**:
```solidity
// VULNERABLE: Only tracks if limit exists
function _verifyDepositLimit(address token, address depositor, uint256 amount, bool claiming) {
    if (_claiming) {
        totalDeposited[token][depositor] -= amount;  // Reduces counter
    } else {
        totalDeposited[token][depositor] += amount;
        // ONLY checks limit if already enforced
        if (limitData.depositLimitation) {
            require(totalDeposited[token][depositor] <= limitData.depositCap);
        }
    }
}
```

**Attack Scenario**:
1. Token has no limit initially
2. Attacker deposits large amount, intentionally fails
3. Later, token limit imposed
4. Attacker claims failed deposit → reduces counter
5. Attacker can now deposit more than cap

**Secure Pattern**:
```solidity
// Always track deposits, regardless of current limits
totalDeposited[token][depositor] += amount;  // Always track
if (limitData.depositLimitation) {
    require(totalDeposited <= cap);
}
```

---

### 3.3 EOA Repayers Affected by Changing Credit Multiplier

**Vulnerability**: EOA must mint CreditTokens before repaying; if bad debt generated between mint and repay, multiplier changes.

**Pattern to Look For**:
```solidity
function repay(bytes32 loanId) external {
    // User pre-calculated debt and minted exact CreditTokens
    uint256 loanDebt = getLoanDebt(loanId);  // Uses CURRENT creditMultiplier
    // If bad debt occurred since user calculated, this is now HIGHER
    
    CreditToken.transferFrom(msg.sender, address(this), loanDebt);
    // User doesn't have enough - reverts!
}

function getLoanDebt(bytes32 loanId) public view returns (uint256) {
    uint256 creditMultiplier = profitManager.creditMultiplier();
    // If creditMultiplier decreased, loanDebt increased
    return (borrowAmount * borrowCreditMultiplier) / creditMultiplier;
}
```

**Impact**: Honest repayers suddenly owe more due to others' bad debt.

**Secure Pattern**:
```solidity
// Allow atomic mint-and-repay
function repayWithPegToken(bytes32 loanId, uint256 pegTokenAmount) external {
    uint256 loanDebt = getLoanDebt(loanId);
    uint256 creditNeeded = _mintCredit(pegTokenAmount);  // Atomic
    require(creditNeeded >= loanDebt, "Insufficient");
    _repay(loanId, loanDebt);
}
```

---

## 4. Cross-Layer Vulnerabilities

### 4.1 L1/L2 Upgrade Synchronization Failure

**Vulnerability**: L2 upgrade fails but L1 protocol version advances anyway; state becomes inconsistent.

**Pattern to Look For**:
```solidity
// L1 executes batches without checking L2 upgrade outcome
function executeBatches(StoredBatchInfo[] calldata batches) external {
    // Process batches...
    
    if (batchWhenUpgradeHappened <= newTotalBatchesExecuted) {
        delete s.l2SystemContractsUpgradeTxHash;
        // Protocol version already advanced even if L2 upgrade failed!
    }
}
```

**Problem**: L2 upgrade tx has unique hash with nonce = protocol version. If L2 upgrade reverts, version is wrong.

**Secure Pattern**:
```solidity
function executeBatches(StoredBatchInfo[] calldata batches) external {
    // ...
    if (batchWhenUpgradeHappened <= newTotalBatchesExecuted) {
        // Check L2 upgrade success
        if (!proveL1ToL2TransactionStatus(upgradeHash, SUCCEEDED)) {
            s.protocolVersion = s.previousProtocolVersion;  // Rollback
        }
    }
}
```

---

### 4.2 Transaction Ordering in Cross-Layer Operations

**Vulnerability**: L1→L2 message order assumptions can be violated by sequencer.

**Pattern to Look For**:
```solidity
// Assumes deposit processes before operation
function depositAndOperate() external {
    bridge.deposit(token, amount);  // L1 → L2 message 1
    bridge.operate(data);            // L1 → L2 message 2
    // Sequencer may reorder!
}
```

**Audit Checklist**:
- [ ] Are cross-layer operations atomic?
- [ ] Can sequencer reorder messages?
- [ ] Are nonces enforced for ordering?

---

## 5. Data Location Vulnerabilities

### 5.1 Storage vs Memory Pointer Confusion

**Vulnerability**: Using `memory` creates copy; changes don't persist.

**Pattern to Look For**:
```solidity
// VULNERABLE: Memory copy, changes lost
function updateBalance(address user) internal {
    UserData memory data = userData[user];  // Copy!
    data.balance += 100;
    // Changes NOT saved to storage
}

// CORRECT: Storage pointer, changes persist
function updateBalance(address user) internal {
    UserData storage data = userData[user];  // Pointer!
    data.balance += 100;
    // Changes saved
}
```

**Detection**: Look for `memory` keyword with subsequent modifications that seem intended to persist.

---

### 5.2 Calldata Modification Attempt

**Vulnerability**: Attempting to modify calldata parameter (read-only).

**Pattern to Look For**:
```solidity
// VULNERABLE: Calldata is immutable
function process(uint256[] calldata data) external {
    data[0] = 100;  // Compile error - good
    // But indirect modifications may not error
}
```

---

### 5.3 Log Sorter Queue Manipulation (zkSync)

**Vulnerability**: Sorted queue in log sorter can be manipulated to emit reverted logs.

**Technical Detail**:
```
Sorted queue pattern: wr rw wr rw
- Two adjacent logs with same timestamp
- Same written value
- All four logs are reverted
- But queue adds 2nd and 4th to result (wrong!)

Required constraint: First popped = write only (not consecutive rollbacks)
```

---

## 6. Finding Report Template

Based on Cyfrin's finding layout:

```markdown
### [S-#] TITLE (Root Cause + Impact)

**Description:** 
Clear explanation of the vulnerability mechanism.

**Impact:** 
- Severity: Critical/High/Medium/Low
- Who is affected
- Financial impact estimate

**Proof of Concept:**
```solidity
// Minimal reproduction code
function testVulnerability() public {
    // Setup
    // Attack
    // Assert impact
}
```

**Recommended Mitigation:** 
Specific code changes to fix the issue.
```

---

## Audit Integration Prompts

### For Gas Audits
```
Analyze this cross-layer transaction for:
1. Gas calculation completeness (overhead + intrinsic + execution)
2. Unit consistency (bytes vs words)
3. Gas refund behavior on revert
4. Potential gas griefing vectors
```

### For DoS Audits
```
Check this protocol for denial of service vectors:
1. EIP-155 replay protection
2. Flash loan stake/unstake in same block
3. Manager/registry single points of failure
4. Block gas limit issues in loops
```

### For L1↔L2 Audits
```
Review cross-layer synchronization for:
1. Message ordering guarantees
2. Upgrade failure handling
3. Protocol version consistency
4. User fund accessibility during failures
```

---

## Cross-Reference Sources

| Pattern | Source Report | Protocol |
|---------|--------------|----------|
| L1→L2 Gas | Code4rena 2023-10 | zkSync |
| Unit Mismatch | Code4rena 2023-10 | zkSync |
| Revert Gas | Code4rena 2023-10 | zkSync |
| EIP-155 Replay | Code4rena 2023-10 | zkSync |
| Wrong Manager | Code4rena 2023-12 | ECG |
| Same-Block Stake | Code4rena 2023-12 | ECG |
| L2 ETH Access | Code4rena 2023-10 | zkSync |
| Deposit Limits | Code4rena 2023-10 | zkSync |
| Credit Multiplier | Code4rena 2023-12 | ECG |
| L1/L2 Sync | Code4rena 2023-10 | zkSync |

---

## Related Skills

- [vulnerability-patterns.md](vulnerability-patterns.md) - General patterns
- [l2-security.md](l2-security.md) - L2-specific patterns
- [defi-vulnerabilities.md](defi-vulnerabilities.md) - DeFi patterns
