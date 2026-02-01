---
id: METHOD-INVARIANT-TESTING
title: Invariant Testing Methodology
category: methodology
difficulty: advanced
tags: [invariant, fuzzing, foundry, stateful, testing]
last_updated: 2026-01-31
---

# Invariant Testing Methodology

## Overview

Invariant testing (stateful fuzzing) automatically explores sequences of function calls to find violations of protocol invariants. Unlike unit tests that check specific scenarios, invariant tests explore the entire state space.

```
┌─────────────────────────────────────────────────────────────────┐
│                    INVARIANT TESTING                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│   │ Random      │    │ Execute     │    │ Check       │        │
│   │ Function    │───►│ Function    │───►│ Invariants  │        │
│   │ Selection   │    │ Call        │    │ Still Hold  │        │
│   └─────────────┘    └─────────────┘    └──────┬──────┘        │
│         ▲                                      │                │
│         │              ┌───────────┐           │                │
│         └──────────────│  Repeat   │◄──────────┘                │
│                        │ 1000s of  │     ✓ Pass                 │
│                        │   times   │                            │
│                        └───────────┘                            │
│                              │                                  │
│                              ▼ ✗ Fail                           │
│                     ┌───────────────┐                           │
│                     │ Shrink to     │                           │
│                     │ Minimal Repro │                           │
│                     └───────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Core Invariant Types

### 1. Accounting Invariants

```solidity
// Total supply should equal sum of balances
invariant_totalSupplyEqualsBalances:
    totalSupply == sum(balanceOf[user] for all users)

// Pool reserves should match actual token balances
invariant_reservesMatchBalance:
    reserve0 == token0.balanceOf(pool)
    reserve1 == token1.balanceOf(pool)

// Total shares should equal sum of user shares
invariant_sharesAccountingCorrect:
    totalShares == sum(shares[user] for all users)
```

### 2. Solvency Invariants

```solidity
// Protocol should never be insolvent
invariant_protocolSolvent:
    totalAssets >= totalLiabilities

// Collateral should always exceed debt
invariant_overcollateralized:
    for each position:
        collateralValue >= debtValue * minCollateralRatio

// Vault should have enough to cover withdrawals
invariant_vaultSolvent:
    vault.totalAssets() >= sum(expectedWithdrawals)
```

### 3. Access Control Invariants

```solidity
// Only owner can be owner
invariant_ownerUnchangedUnlessTransferred:
    owner == previousOwner || 
    (msg.sender == previousOwner && owner == newOwner)

// Admin roles should be limited
invariant_adminCountBounded:
    adminCount <= MAX_ADMINS
```

### 4. State Machine Invariants

```solidity
// Auction states should follow valid transitions
invariant_validAuctionState:
    auctionState ∈ {NotStarted, Active, Ended, Settled}
    
    // Valid transitions only:
    // NotStarted -> Active (start)
    // Active -> Ended (end or timeout)
    // Ended -> Settled (settle)
```

---

## Foundry Invariant Setup

### Basic Configuration

```solidity
// foundry.toml
[invariant]
runs = 1000           // Number of sequences
depth = 50            // Calls per sequence
fail_on_revert = false // Continue on reverts
dictionary_weight = 40 // Use values from storage
```

### Handler Pattern

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract VaultHandler is Test {
    Vault public vault;
    IERC20 public token;
    
    // Track ghost variables for invariant checking
    uint256 public ghost_depositSum;
    uint256 public ghost_withdrawSum;
    
    address[] public actors;
    address internal currentActor;
    
    modifier useActor(uint256 actorIndexSeed) {
        currentActor = actors[bound(actorIndexSeed, 0, actors.length - 1)];
        vm.startPrank(currentActor);
        _;
        vm.stopPrank();
    }
    
    constructor(Vault _vault, IERC20 _token) {
        vault = _vault;
        token = _token;
        
        // Setup actors
        for (uint i = 0; i < 10; i++) {
            address actor = address(uint160(0x1000 + i));
            actors.push(actor);
            
            // Give actors tokens
            deal(address(token), actor, 1000000e18);
            vm.prank(actor);
            token.approve(address(vault), type(uint256).max);
        }
    }
    
    // Fuzzed deposit function
    function deposit(uint256 actorSeed, uint256 amount) external useActor(actorSeed) {
        amount = bound(amount, 1, token.balanceOf(currentActor));
        
        uint256 sharesBefore = vault.balanceOf(currentActor);
        vault.deposit(amount, currentActor);
        uint256 sharesAfter = vault.balanceOf(currentActor);
        
        ghost_depositSum += amount;
    }
    
    // Fuzzed withdraw function
    function withdraw(uint256 actorSeed, uint256 shares) external useActor(actorSeed) {
        uint256 maxShares = vault.balanceOf(currentActor);
        if (maxShares == 0) return;
        
        shares = bound(shares, 1, maxShares);
        
        uint256 assets = vault.redeem(shares, currentActor, currentActor);
        ghost_withdrawSum += assets;
    }
    
    // Helper for invariant tests
    function reduceActors(
        uint256 acc,
        function(uint256, address) external view returns (uint256) fn
    ) external view returns (uint256) {
        for (uint i = 0; i < actors.length; i++) {
            acc = fn(acc, actors[i]);
        }
        return acc;
    }
}
```

### Invariant Test Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "./VaultHandler.sol";

contract VaultInvariantTest is Test {
    Vault public vault;
    IERC20 public token;
    VaultHandler public handler;
    
    function setUp() public {
        token = new MockERC20("Test", "TST", 18);
        vault = new Vault(address(token));
        handler = new VaultHandler(vault, token);
        
        // Target only the handler for fuzzing
        targetContract(address(handler));
    }
    
    // INVARIANT: Total assets >= total supply value
    function invariant_solvency() public view {
        uint256 totalAssets = vault.totalAssets();
        uint256 totalSupply = vault.totalSupply();
        
        if (totalSupply > 0) {
            uint256 impliedAssets = vault.convertToAssets(totalSupply);
            assertGe(totalAssets, impliedAssets, "Vault is insolvent");
        }
    }
    
    // INVARIANT: Sum of deposits - withdrawals = total assets
    function invariant_accountingCorrect() public view {
        uint256 netDeposits = handler.ghost_depositSum() - handler.ghost_withdrawSum();
        uint256 totalAssets = vault.totalAssets();
        
        // Allow for rounding errors (up to 1 wei per operation)
        uint256 tolerance = handler.ghost_depositSum() / 1e18;
        assertApproxEqAbs(totalAssets, netDeposits, tolerance);
    }
    
    // INVARIANT: No shares without assets
    function invariant_noSharesWithoutAssets() public view {
        if (vault.totalSupply() > 0) {
            assertGt(vault.totalAssets(), 0, "Shares exist without assets");
        }
    }
    
    // Call summary for debugging
    function invariant_callSummary() public view {
        console.log("Deposits:", handler.ghost_depositSum());
        console.log("Withdrawals:", handler.ghost_withdrawSum());
        console.log("Total Assets:", vault.totalAssets());
        console.log("Total Shares:", vault.totalSupply());
    }
}
```

---

## Advanced Patterns

### 1. Multi-Contract Handlers

```solidity
// Test interactions between multiple contracts

contract LendingHandler {
    LendingPool pool;
    Oracle oracle;
    
    function deposit(...) external { ... }
    function borrow(...) external { ... }
    function liquidate(...) external { ... }
}

contract OracleHandler {
    Oracle oracle;
    
    // Simulate price changes
    function setPrice(uint256 priceSeed) external {
        uint256 price = bound(priceSeed, 1e6, 1e12);  // $0.01 to $1M
        oracle.setPrice(price);
    }
}

contract InvariantTest {
    function setUp() public {
        // Target both handlers
        targetContract(address(lendingHandler));
        targetContract(address(oracleHandler));
    }
    
    // Now fuzzer will call both handlers
    function invariant_alwaysOvercollateralized() public {
        for (uint i = 0; i < positions.length; i++) {
            Position memory pos = pool.getPosition(i);
            if (pos.debt > 0) {
                uint256 collateralValue = pos.collateral * oracle.getPrice() / 1e18;
                assertGe(collateralValue, pos.debt * MIN_CR / 100);
            }
        }
    }
}
```

### 2. Bounded Invariants

```solidity
// Some invariants should hold within bounds

function invariant_exchangeRateBounded() public view {
    uint256 rate = vault.convertToAssets(1e18);
    
    // Rate should be within expected range
    // Initial rate is 1:1, should only go up (yield) or down slightly (losses)
    assertGe(rate, 0.9e18, "Rate dropped too much");
    assertLe(rate, 10e18, "Rate increased unreasonably");
}
```

### 3. Conditional Invariants

```solidity
// Invariants that only apply in certain states

function invariant_noWithdrawalsDuringPause() public view {
    if (vault.paused()) {
        // During pause, no withdrawals should have succeeded
        // Track this via ghost variables
        assertEq(
            handler.ghost_withdrawsDuringPause(), 
            0, 
            "Withdrawal succeeded during pause"
        );
    }
}
```

### 4. Cross-Function Invariants

```solidity
// Invariants about relationships between functions

function invariant_depositWithdrawSymmetry() public {
    // If I deposit X and immediately withdraw, I should get ~X back
    uint256 amount = 100e18;
    
    vm.startPrank(testUser);
    uint256 sharesMinted = vault.deposit(amount, testUser);
    uint256 assetsReturned = vault.redeem(sharesMinted, testUser, testUser);
    vm.stopPrank();
    
    // Should get back at least 99.9% (accounting for rounding)
    assertGe(assetsReturned, amount * 999 / 1000);
}
```

---

## Common Invariants by Protocol Type

### DEX/AMM

```solidity
// Constant product (for Uniswap V2 style)
invariant_constantProduct:
    reserve0 * reserve1 >= k  // Can only increase due to fees

// No free tokens
invariant_noArbitrage:
    outputAmount <= inputAmount * (reserve1 / reserve0) * (1 - fee)

// LP share value non-decreasing
invariant_lpValuePreserved:
    totalAssets / totalShares >= previousRate
```

### Lending

```solidity
// Total borrows <= total deposits
invariant_borrowsLtDeposits:
    totalBorrows <= totalDeposits

// Interest accrues correctly  
invariant_interestIncreasing:
    borrowIndex >= previousBorrowIndex

// Health factor respected
invariant_healthFactor:
    for each position:
        if debt > 0: healthFactor >= 1.0 OR position is liquidatable
```

### Vaults

```solidity
// Share price non-decreasing (for yield vaults)
invariant_sharePriceNonDecreasing:
    currentPricePerShare >= previousPricePerShare

// Total assets matches strategy balances
invariant_assetsTracked:
    totalAssets == idleAssets + sum(strategyAllocations)
```

---

## Debugging Failed Invariants

### 1. Read the Shrunk Sequence

```bash
# Foundry outputs the minimal failing sequence
[FAIL. Reason: Invariant violated]
Sequence:
    sender=0x... handler.deposit(42, 1000000000000000000)
    sender=0x... handler.withdraw(7, 500000000000000000)
    sender=0x... handler.deposit(13, 1)  # <-- This breaks it!
```

### 2. Add Logging

```solidity
function invariant_debug() public view {
    console.log("=== State Dump ===");
    console.log("Total Supply:", vault.totalSupply());
    console.log("Total Assets:", vault.totalAssets());
    console.log("Ghost Deposits:", handler.ghost_depositSum());
    
    for (uint i = 0; i < actors.length; i++) {
        console.log("Actor", i, "shares:", vault.balanceOf(actors[i]));
    }
}
```

### 3. Replay the Sequence

```solidity
function test_replayFailure() public {
    // Replay exact sequence from fuzzer output
    vm.prank(actor1);
    handler.deposit(42, 1000000000000000000);
    
    vm.prank(actor2);
    handler.withdraw(7, 500000000000000000);
    
    vm.prank(actor1);
    handler.deposit(13, 1);  // Should fail here
    
    // Check invariant manually
    assertGe(vault.totalAssets(), vault.totalSupply());
}
```

---

## Best Practices

### 1. Start Simple, Add Complexity

```solidity
// Start with basic invariants
function invariant_basic() { assertGe(totalAssets, 0); }

// Then add more specific ones
function invariant_accounting() { ... }

// Finally, complex cross-contract invariants
function invariant_systemWide() { ... }
```

### 2. Use Ghost Variables

```solidity
// Track cumulative values in handler
uint256 public ghost_totalDeposited;
uint256 public ghost_totalWithdrawn;
uint256 public ghost_totalFees;

// Use in invariants
function invariant_feeAccounting() public view {
    uint256 expected = ghost_totalDeposited - ghost_totalWithdrawn - ghost_totalFees;
    assertApproxEqAbs(vault.totalAssets(), expected, tolerance);
}
```

### 3. Bound Inputs Realistically

```solidity
function deposit(uint256 amount) external {
    // Don't use unbounded amounts
    amount = bound(amount, 1, 1000000e18);  // $1 to $1M
    
    // Check preconditions
    if (token.balanceOf(actor) < amount) return;
    
    // Execute
    vault.deposit(amount, actor);
}
```

### 4. Exclude Functions When Needed

```solidity
function setUp() public {
    // Exclude admin functions from fuzzing
    bytes4[] memory selectors = new bytes4[](1);
    selectors[0] = vault.pause.selector;
    
    targetSelector(FuzzSelector({
        addr: address(vault),
        selectors: selectors
    }));
    
    excludeContract(address(vault));  // Only use handler
}
```

---

## Running Invariant Tests

```bash
# Basic run
forge test --match-contract InvariantTest

# With more runs
forge test --match-contract InvariantTest -vvv \
    --fuzz-runs 10000

# With seed for reproducibility
forge test --match-contract InvariantTest \
    --fuzz-seed 12345

# Profile gas usage
forge test --match-contract InvariantTest --gas-report
```

---

## Related Resources

- [Foundry Book - Invariant Testing](https://book.getfoundry.sh/forge/invariant-testing)
- [Trail of Bits - Building Secure Smart Contracts](https://github.com/crytic/building-secure-contracts)
- [Example: Maple Finance Invariants](https://github.com/maple-labs/maple-core-v2)
