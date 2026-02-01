---
id: METHOD-SYMBOLIC-EXECUTION
title: Symbolic Execution & Formal Verification
category: methodology
difficulty: expert
tags: [symbolic, formal-verification, halmos, hevm, certora]
last_updated: 2026-01-31
---

# Symbolic Execution & Formal Verification

## Overview

Symbolic execution explores ALL possible execution paths by treating inputs as symbols rather than concrete values. This provides mathematical guarantees about code behavior.

```
┌─────────────────────────────────────────────────────────────────┐
│              SYMBOLIC EXECUTION vs FUZZING                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  FUZZING (Random Testing)          SYMBOLIC (Exhaustive)       │
│  ┌─────────────────────┐          ┌─────────────────────┐      │
│  │ Input: Random values│          │ Input: Symbolic x,y │      │
│  │ x = 42, y = 17      │          │ x = α, y = β        │      │
│  │                     │          │                     │      │
│  │ Tests ONE path      │          │ Tests ALL paths     │      │
│  │ per execution       │          │ simultaneously      │      │
│  └─────────────────────┘          └─────────────────────┘      │
│                                                                 │
│  Coverage: Statistical            Coverage: Mathematical        │
│  "Probably no bugs"               "Proven no bugs"              │
│                                   (within scope)                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Tools Overview

| Tool | Type | Language | Best For |
|------|------|----------|----------|
| **Halmos** | Symbolic testing | Solidity (Foundry) | Property testing |
| **HEVM** | Symbolic EVM | Solidity | Equivalence checking |
| **Certora** | Formal verification | CVL spec language | Full verification |
| **Kontrol** | Symbolic execution | K framework | Complex proofs |
| **Pyrometer** | Abstract interpretation | Solidity | Taint analysis |

---

## Halmos (Foundry Integration)

### Installation & Setup

```bash
# Install Halmos
pip install halmos

# Run symbolic tests
halmos --contract MyContract

# With specific function
halmos --contract MyContract --function test_symbolic
```

### Basic Symbolic Test

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract SymbolicTest is Test, SymTest {
    Vault vault;
    
    function setUp() public {
        vault = new Vault();
    }
    
    // Prove: deposit then withdraw returns same amount
    function test_depositWithdrawSymmetry(uint256 amount) public {
        // Assumptions (constraints on symbolic input)
        vm.assume(amount > 0);
        vm.assume(amount <= type(uint128).max);
        
        // Give tokens
        deal(address(token), address(this), amount);
        token.approve(address(vault), amount);
        
        // Execute
        uint256 shares = vault.deposit(amount, address(this));
        uint256 returned = vault.redeem(shares, address(this), address(this));
        
        // Assert (must hold for ALL valid inputs)
        assertEq(returned, amount, "Asymmetric deposit/withdraw");
    }
    
    // Prove: no overflow in calculation
    function test_noOverflow(uint256 a, uint256 b) public {
        vm.assume(a <= type(uint128).max);
        vm.assume(b <= type(uint128).max);
        
        // This should not overflow
        uint256 result = vault.calculateReward(a, b);
        
        // Verify result is bounded
        assertLe(result, type(uint256).max);
    }
}
```

### Proving Invariants

```solidity
// Prove invariant holds for ANY sequence of operations
function test_invariant_solvency(
    uint256 depositAmount,
    uint256 withdrawShares
) public {
    vm.assume(depositAmount > 0);
    vm.assume(depositAmount <= 1e30);
    
    // Initial state
    deal(address(token), user1, depositAmount);
    
    // Deposit
    vm.prank(user1);
    token.approve(address(vault), depositAmount);
    vm.prank(user1);
    vault.deposit(depositAmount, user1);
    
    // Bound withdraw to available shares
    uint256 userShares = vault.balanceOf(user1);
    withdrawShares = bound(withdrawShares, 0, userShares);
    
    // Withdraw
    if (withdrawShares > 0) {
        vm.prank(user1);
        vault.redeem(withdrawShares, user1, user1);
    }
    
    // INVARIANT: Vault assets >= implied value of shares
    uint256 totalAssets = vault.totalAssets();
    uint256 totalSupply = vault.totalSupply();
    
    if (totalSupply > 0) {
        uint256 impliedValue = vault.convertToAssets(totalSupply);
        assertGe(totalAssets, impliedValue, "Insolvency detected");
    }
}
```

---

## HEVM (Equivalence Checking)

### Basic Usage

```bash
# Install HEVM
nix-env -iA hevm -f https://github.com/dapphub/dapptools/archive/master.tar.gz

# Run symbolic test
hevm symbolic --code $(cat out/Contract.bin) --sig "test(uint256)"
```

### Equivalence Proof

```solidity
// Prove two implementations are equivalent

contract OriginalMath {
    function sqrt(uint256 x) external pure returns (uint256) {
        // Original implementation
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        uint256 y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
        return y;
    }
}

contract OptimizedMath {
    function sqrt(uint256 x) external pure returns (uint256) {
        // Optimized implementation (prove it's equivalent)
        if (x == 0) return 0;
        uint256 result = 1;
        uint256 x1 = x;
        if (x1 >= 0x100000000000000000000000000000000) { x1 >>= 128; result <<= 64; }
        if (x1 >= 0x10000000000000000) { x1 >>= 64; result <<= 32; }
        if (x1 >= 0x100000000) { x1 >>= 32; result <<= 16; }
        if (x1 >= 0x10000) { x1 >>= 16; result <<= 8; }
        if (x1 >= 0x100) { x1 >>= 8; result <<= 4; }
        if (x1 >= 0x10) { x1 >>= 4; result <<= 2; }
        if (x1 >= 0x4) { result <<= 1; }
        result = (result + x / result) >> 1;
        result = (result + x / result) >> 1;
        result = (result + x / result) >> 1;
        result = (result + x / result) >> 1;
        result = (result + x / result) >> 1;
        result = (result + x / result) >> 1;
        result = (result + x / result) >> 1;
        return result < x / result ? result : x / result;
    }
}

// Equivalence test
contract EquivalenceTest is SymTest {
    OriginalMath original;
    OptimizedMath optimized;
    
    function setUp() public {
        original = new OriginalMath();
        optimized = new OptimizedMath();
    }
    
    // Prove: optimized.sqrt(x) == original.sqrt(x) for all x
    function test_sqrt_equivalence(uint256 x) public {
        uint256 result1 = original.sqrt(x);
        uint256 result2 = optimized.sqrt(x);
        
        assertEq(result1, result2, "Implementations differ");
    }
}
```

---

## Certora (Full Formal Verification)

### Spec Language (CVL)

```cvl
// vault.spec

methods {
    function totalSupply() external returns (uint256) envfree;
    function totalAssets() external returns (uint256) envfree;
    function balanceOf(address) external returns (uint256) envfree;
    function deposit(uint256, address) external returns (uint256);
    function redeem(uint256, address, address) external returns (uint256);
}

// Ghost variables for tracking
ghost uint256 sumOfBalances {
    init_state axiom sumOfBalances == 0;
}

// Hook to update ghost on balance changes
hook Sstore balanceOf[KEY address user] uint256 newBalance (uint256 oldBalance) {
    sumOfBalances = sumOfBalances + newBalance - oldBalance;
}

// RULE: Total supply equals sum of balances
invariant totalSupplyIsSumOfBalances()
    totalSupply() == sumOfBalances
    {
        preserved with (env e) {
            require e.msg.sender != 0;
        }
    }

// RULE: Solvency - assets cover liabilities
invariant solvency()
    totalSupply() == 0 || totalAssets() > 0
    {
        preserved {
            require totalSupply() <= 10^30;
            require totalAssets() <= 10^30;
        }
    }

// RULE: Deposit increases shares
rule depositIncreasesShares(uint256 amount, address receiver) {
    env e;
    
    uint256 sharesBefore = balanceOf(receiver);
    uint256 sharesReturned = deposit(e, amount, receiver);
    uint256 sharesAfter = balanceOf(receiver);
    
    assert sharesAfter == sharesBefore + sharesReturned;
    assert amount > 0 => sharesReturned > 0;
}

// RULE: No front-running attack possible
rule noFrontRunning(uint256 amount) {
    env e1; env e2;
    
    // User1 deposits
    uint256 shares1 = deposit(e1, amount, e1.msg.sender);
    
    // User2 front-runs with same amount
    uint256 shares2 = deposit(e2, amount, e2.msg.sender);
    
    // Same deposit should give proportionally fair shares
    // (within rounding tolerance)
    assert shares1 >= shares2 - 1;
    assert shares2 >= shares1 - 1;
}
```

### Running Certora

```bash
# Install
pip install certora-cli

# Run verification
certoraRun contracts/Vault.sol:Vault \
    --verify Vault:specs/vault.spec \
    --solc solc8.20 \
    --msg "Vault verification"
```

---

## Common Symbolic Patterns

### 1. Path Explosion Handling

```solidity
// PROBLEM: Loops cause path explosion
for (uint i = 0; i < users.length; i++) {  // Unbounded!
    balances[users[i]] += amount;
}

// SOLUTION: Bound the loop
function test_bounded(uint256 amount) public {
    // Assume bounded array length
    vm.assume(users.length <= 10);
    
    // Now symbolic execution is tractable
}

// OR: Use loop invariants
// @invariant: sum(balances) == totalSupply
```

### 2. External Call Abstraction

```solidity
// PROBLEM: External calls are hard to model
uint256 price = oracle.getPrice();  // What values can this return?

// SOLUTION: Abstract with assumptions
function test_withOracleAssumptions(uint256 price) public {
    // Model oracle as returning any value in range
    vm.assume(price >= 1e6);    // Min $0.01
    vm.assume(price <= 1e12);   // Max $1M
    
    // Mock the oracle
    vm.mockCall(
        address(oracle),
        abi.encodeWithSelector(oracle.getPrice.selector),
        abi.encode(price)
    );
    
    // Now test with symbolic price
    vault.liquidate(position);
}
```

### 3. Timestamp/Block Handling

```solidity
// PROBLEM: Block properties are symbolic
function test_timeDependency(uint256 timestamp) public {
    // Bound to realistic range
    vm.assume(timestamp >= block.timestamp);
    vm.assume(timestamp <= block.timestamp + 365 days);
    
    // Set symbolic time
    vm.warp(timestamp);
    
    // Test time-dependent logic
    uint256 reward = staking.calculateReward(user);
    
    // Prove monotonicity: later time = more reward
    // (if staking logic is correct)
}
```

### 4. Storage Layout Verification

```solidity
// Prove upgrade doesn't corrupt storage

contract OriginalStorage {
    uint256 public value1;      // Slot 0
    address public admin;       // Slot 1
    mapping(address => uint256) public balances;  // Slot 2
}

contract UpgradedStorage {
    uint256 public value1;      // Slot 0 - same
    address public admin;       // Slot 1 - same
    mapping(address => uint256) public balances;  // Slot 2 - same
    uint256 public newValue;    // Slot 3 - new (safe!)
    // UNSAFE would be: inserting newValue between existing slots
}

function test_storageCompatibility() public {
    // Deploy original
    OriginalStorage original = new OriginalStorage();
    original.value1 = 42;
    original.admin = address(0xABC);
    original.balances[user] = 100;
    
    // Upgrade (in practice, use proxy)
    UpgradedStorage upgraded = UpgradedStorage(address(original));
    
    // Verify storage preserved
    assertEq(upgraded.value1(), 42);
    assertEq(upgraded.admin(), address(0xABC));
    assertEq(upgraded.balances(user), 100);
}
```

---

## When to Use Each Approach

### Use Fuzzing When:
- Exploring large input spaces quickly
- Finding edge cases
- Testing integration behavior
- Limited time/resources

### Use Symbolic Execution When:
- Proving properties exhaustively
- Checking equivalence
- Verifying critical invariants
- Mathematical guarantees needed

### Use Formal Verification (Certora) When:
- High-value protocol (>$100M TVL)
- Complex invariants
- Regulatory/compliance requirements
- Need mathematical proof

---

## Limitations

### Path Explosion
```
Symbolic execution explores 2^n paths for n branches
- 10 if statements = 1,024 paths
- 20 if statements = 1,048,576 paths
- Loops make it worse

Mitigation:
- Bound loops
- Abstract external calls
- Use compositional verification
```

### SMT Solver Timeouts
```
Complex arithmetic can timeout:
- Division with symbolic divisor
- Modular exponentiation
- Non-linear multiplication

Mitigation:
- Simplify expressions
- Add assumptions to constrain search
- Use simpler approximations
```

### State Space Size
```
Storage with many variables = huge state space

Mitigation:
- Focus on specific properties
- Use abstraction
- Verify components separately
```

---

## Best Practices

### 1. Start with Critical Properties

```solidity
// Identify the MOST important invariants first
// 1. Solvency - can users get their funds?
// 2. Access control - can only admins admin?
// 3. Accounting - do balances sum correctly?
```

### 2. Incremental Verification

```solidity
// Don't try to verify everything at once

// Step 1: Single function properties
test_deposit_increases_balance()

// Step 2: Two-function relationships
test_deposit_withdraw_symmetry()

// Step 3: Invariants over many functions
invariant_solvency()

// Step 4: Full system properties
```

### 3. Document Assumptions

```solidity
// Be explicit about what's assumed

function test_liquidation(uint256 price) public {
    // ASSUMPTION: Oracle returns price in 18 decimals
    // ASSUMPTION: Price is non-zero and bounded
    // ASSUMPTION: No flash loan in same block
    
    vm.assume(price >= 1e10);  // Min $0.00000001
    vm.assume(price <= 1e30);  // Max realistic price
    
    // Test...
}
```

---

## Related Resources

- [Halmos Documentation](https://github.com/a16z/halmos)
- [Certora Documentation](https://docs.certora.com/)
- [HEVM](https://github.com/ethereum/hevm)
- [Formal Verification of DeFi Protocols (Trail of Bits)](https://blog.trailofbits.com/)
