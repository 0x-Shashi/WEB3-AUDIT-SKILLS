# Deep Dive Chain

## Overview

Intensive analysis of specific modules or vulnerability classes.

**Duration:** 2-4 hours  
**Output:** Detailed analysis with exploit scenarios

---

## When to Use

- Focus on specific module
- Follow up on quick scan findings
- Investigate suspected vulnerability
- Competition deep-dives
- Complex logic review

---

## Chain Steps

```

                    DEEP DIVE CHAIN                              

                                                                 
  Step 1: Focus Selection                           [10 min]    
   Identify target module                                     
   Map dependencies                                           
   Understand intended behavior                               
                                                                 
  Step 2: Exhaustive Pattern Scan                   [45 min]    
   All patterns on target                                     
   Edge case analysis                                         
   State transition mapping                                   
                                                                 
  Step 3: Attack Chain Construction                 [60 min]    
   Identify attack entry points                               
   Build exploit paths                                        
   Consider multi-tx attacks                                  
   Flash loan integration                                     
                                                                 
  Step 4: Exploit Scenario Development              [45 min]    
   Write PoC outline                                          
   Calculate exploit economics                                
   Consider real-world feasibility                            
                                                                 
  Step 5: Impact Assessment                         [20 min]    
   Maximum damage calculation                                 
   Affected parties                                           
   Recovery difficulty                                        
                                                                 

```

---

## Step 1: Focus Selection

### Module Identification

```bash
# List all contracts in target area
ls -la contracts/lending/

# Get module overview
head -100 contracts/lending/LendingPool.sol

# Map imports
grep -n "import" contracts/lending/LendingPool.sol
```

### Dependency Mapping

```
Target: LendingPool.sol
 imports Oracle.sol
 imports Token.sol
 imports ReentrancyGuard.sol
 called by Router.sol
```

### Understand Intent

Read comments, documentation, and test files:
```bash
# Find tests for target
find . -name "*LendingPool*test*"

# Read natspec comments
grep -A5 "/// @" contracts/lending/LendingPool.sol
```

---

## Step 2: Exhaustive Pattern Scan

### Function-by-Function Analysis

For each function in target:

1. **Inputs**: What can user control?
2. **State Changes**: What gets modified?
3. **External Calls**: What gets called?
4. **Outputs**: What's returned?

```bash
# List all functions
grep -n "function " contracts/lending/LendingPool.sol

# For each function, trace:
# - Parameters
# - State reads
# - State writes
# - External calls
# - Return values
```

### Edge Cases

| Edge Case | Check |
|-----------|-------|
| Zero values | What if amount = 0? |
| Max values | What if amount = type(uint256).max? |
| First user | What if no previous deposits? |
| Last user | What if user withdraws all? |
| Self-reference | What if user = address(this)? |
| Reentrant | What if called recursively? |

### State Transition Map

```
deposit()  balances[user] += amount
          totalSupply += amount
          emit Deposit()
         
withdraw()  balances[user] -= amount  
           totalSupply -= amount
           transfer(user, amount)   EXTERNAL CALL
           emit Withdraw()
```

---

## Step 3: Attack Chain Construction

### Entry Point Analysis

```
ENTRY POINTS:
 deposit(amount)     - Requires tokens
 withdraw(amount)    - Requires balance
 borrow(amount)      - Requires collateral
 liquidate(user)     - Requires user underwater
 flashLoan(amount)   - No requirements!
```

### Attack Path Template

```
ATTACK PATH:
1. Initial State
   - Protocol has X value
   - Attacker has Y value
   
2. Attack Actions
   a) [Action 1]
   b) [Action 2]
   c) [Action 3]
   
3. Final State
   - Protocol has X - Z value
   - Attacker has Y + Z value
   
4. Requirements
   - [Condition needed]
   - [Timing requirement]
```

### Multi-Transaction Attacks

Consider attacks spanning multiple blocks:
- Price manipulation over time (TWAP gaming)
- Governance attacks
- Front-running setups

### Flash Loan Integration

```
WITH FLASH LOAN:
1. Borrow large amount
2. Manipulate price / Exploit vulnerability
3. Extract value
4. Repay flash loan
5. Keep profit

CHECK:
- Can flash loan amplify attack?
- What's the max flash borrow available?
- Which protocols offer flash loans?
```

---

## Step 4: Exploit Scenario Development

### PoC Outline

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract Exploit is Test {
    function setUp() public {
        // Setup: Deploy contracts, fund accounts
    }
    
    function testExploit() public {
        // Step 1: Initial state
        uint256 protocolBalanceBefore = token.balanceOf(protocol);
        
        // Step 2: Attack
        // ... attack code ...
        
        // Step 3: Verify
        uint256 protocolBalanceAfter = token.balanceOf(protocol);
        assertLt(protocolBalanceAfter, protocolBalanceBefore);
    }
}
```

### Economic Analysis

```
EXPLOIT ECONOMICS:
 Attack Cost
    Gas: ~500,000 gas  50 gwei = 0.025 ETH
    Flash loan fee: 0.09% of borrowed
    Slippage: estimated 2%

 Potential Profit
    Protocol TVL: $10M
        Max extractable: $X

 Net Profit: $X - costs
```

### Feasibility Assessment

| Factor | Assessment |
|--------|------------|
| Technical difficulty | Low/Medium/High |
| Capital required | Amount |
| Time window | Block count |
| Detection risk | Low/Medium/High |
| Frontrun risk | Low/Medium/High |

---

## Step 5: Impact Assessment

### Maximum Damage Calculation

```
IMPACT ANALYSIS:

Scenario 1: Single Transaction
- Max loss: $X

Scenario 2: Sustained Attack
- Max loss: $Y over N blocks

Scenario 3: Total Protocol Drain
- Conditions: [list]
- Max loss: Total TVL
```

### Affected Parties

| Party | Impact |
|-------|--------|
| LPs | Lose deposits |
| Borrowers | Lose collateral |
| Token holders | Price crash |
| Protocol | Reputation, TVL |

### Recovery Difficulty

```
RECOVERY:
 Can attack be reversed? [Yes/No]
 Can attacker be identified? [Yes/No]
 Is insurance available? [Yes/No]
 Time to full recovery: [Estimate]
```

---

## Deep Dive Report Template

```markdown
# Deep Dive Analysis: [Module Name]

## Target
- Contract: [address/file]
- Functions: [list]
- TVL at Risk: [amount]

## Vulnerability Identified

### Description
[Detailed description]

### Root Cause
[Technical root cause]

### Attack Scenario
[Step by step]

## Proof of Concept

```solidity
// PoC code
```

## Impact
- Severity: [Critical/High/Medium/Low]
- Max Loss: [amount]
- Likelihood: [percentage]

## Remediation
[Fix recommendation]
```

---

## Deep Dive Checklist

### Before Starting
- [ ] Target module identified
- [ ] Dependencies mapped
- [ ] Normal behavior understood
- [ ] Test environment ready

### During Analysis
- [ ] All functions reviewed
- [ ] Edge cases considered
- [ ] Attack paths mapped
- [ ] Flash loan integration checked
- [ ] Multi-tx attacks considered

### After Completion
- [ ] PoC outlined
- [ ] Economics calculated
- [ ] Impact assessed
- [ ] Fix recommended
