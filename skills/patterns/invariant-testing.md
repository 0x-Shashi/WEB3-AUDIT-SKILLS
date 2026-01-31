---
id: PAT-INVARIANT-TESTING
title: Invariant Testing Security Patterns
category: general
severity: medium
difficulty: beginner
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - security
  - vulnerability


last_updated: 2026-01-31
---
# Invariant Test Generator - AI Reference

> **For AI Assistants:** Use these templates to generate Foundry invariant/fuzz tests for smart contracts.

---

## Overview

Invariant testing is a powerful technique where the fuzzer tries to break 
protocol invariants through random sequences of actions.

**Key concepts:**
- **Invariant**: A property that must ALWAYS be true
- **Actor/Handler**: Contract that fuzzer calls to interact with protocol
- **Target**: The contracts being tested
- **Ghost Variables**: Tracking variables that mirror expected state

---

## Basic Invariant Test Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";

// Import your contracts
import {YourProtocol} from "../src/YourProtocol.sol";
import {YourToken} from "../src/YourToken.sol";

contract YourProtocolInvariantTest is StdInvariant, Test {
    YourProtocol public protocol;
    YourToken public token;
    Handler public handler;
    
    function setUp() public {
        // Deploy contracts
        token = new YourToken();
        protocol = new YourProtocol(address(token));
        
        // Deploy handler
        handler = new Handler(protocol, token);
        
        // Target the handler for fuzzing
        targetContract(address(handler));
        
        // Optional: Exclude specific functions
        // bytes4[] memory selectors = new bytes4[](1);
        // selectors[0] = Handler.skipMe.selector;
        // targetSelector(FuzzSelector({
        //     addr: address(handler),
        //     selectors: selectors
        // }));
    }
    
    // INVARIANT 1: Total supply should never exceed max
    function invariant_maxSupply() public view {
        assertLe(token.totalSupply(), token.MAX_SUPPLY());
    }
    
    // INVARIANT 2: Protocol balance should match accounting
    function invariant_balanceAccounting() public view {
        assertEq(
            token.balanceOf(address(protocol)),
            protocol.totalDeposited()
        );
    }
    
    // INVARIANT 3: Sum of all user balances equals total
    function invariant_userBalances() public view {
        uint256 sum = handler.ghost_depositSum();
        assertEq(sum, protocol.totalDeposited());
    }
    
    // Call summary for debugging
    function invariant_callSummary() public view {
        console2.log("Deposit calls:", handler.ghost_depositCount());
        console2.log("Withdraw calls:", handler.ghost_withdrawCount());
        console2.log("Total deposited:", handler.ghost_depositSum());
    }
}
```

---

## Handler Contract Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {YourProtocol} from "../src/YourProtocol.sol";
import {YourToken} from "../src/YourToken.sol";

contract Handler is Test {
    YourProtocol public protocol;
    YourToken public token;
    
    // Ghost variables for tracking
    uint256 public ghost_depositSum;
    uint256 public ghost_withdrawSum;
    uint256 public ghost_depositCount;
    uint256 public ghost_withdrawCount;
    
    // Actor tracking
    address[] public actors;
    address internal currentActor;
    
    // Bounded values
    uint256 constant MAX_DEPOSIT = 1_000_000e18;
    
    modifier useActor(uint256 actorIndexSeed) {
        currentActor = actors[bound(actorIndexSeed, 0, actors.length - 1)];
        vm.startPrank(currentActor);
        _;
        vm.stopPrank();
    }
    
    constructor(YourProtocol _protocol, YourToken _token) {
        protocol = _protocol;
        token = _token;
        
        // Create actors
        for (uint256 i = 0; i < 10; i++) {
            address actor = makeAddr(string(abi.encodePacked("actor", i)));
            actors.push(actor);
            
            // Fund actors
            deal(address(token), actor, 1_000_000e18);
            
            // Approve protocol
            vm.prank(actor);
            token.approve(address(protocol), type(uint256).max);
        }
    }
    
    // HANDLER FUNCTION: Deposit
    function deposit(uint256 amount, uint256 actorSeed) public useActor(actorSeed) {
        amount = bound(amount, 1, MAX_DEPOSIT);
        
        uint256 balance = token.balanceOf(currentActor);
        if (balance < amount) return;  // Skip if insufficient
        
        protocol.deposit(amount);
        
        // Update ghost variables
        ghost_depositSum += amount;
        ghost_depositCount++;
    }
    
    // HANDLER FUNCTION: Withdraw
    function withdraw(uint256 amount, uint256 actorSeed) public useActor(actorSeed) {
        uint256 deposited = protocol.balanceOf(currentActor);
        if (deposited == 0) return;  // Skip if nothing to withdraw
        
        amount = bound(amount, 1, deposited);
        
        protocol.withdraw(amount);
        
        // Update ghost variables
        ghost_withdrawSum += amount;
        ghost_withdrawCount++;
    }
    
    // HANDLER FUNCTION: Transfer (if applicable)
    function transfer(
        uint256 amount, 
        uint256 fromSeed, 
        uint256 toSeed
    ) public {
        address from = actors[bound(fromSeed, 0, actors.length - 1)];
        address to = actors[bound(toSeed, 0, actors.length - 1)];
        
        if (from == to) return;
        
        uint256 balance = protocol.balanceOf(from);
        if (balance == 0) return;
        
        amount = bound(amount, 1, balance);
        
        vm.prank(from);
        protocol.transfer(to, amount);
    }
}
```

---

## Common Invariants by Protocol Type

### Vault/Staking Invariants

```solidity
// Total shares * price per share >= total assets (no loss)
function invariant_noLoss() public view {
    if (vault.totalSupply() == 0) return;
    
    uint256 expectedAssets = vault.totalSupply() * vault.pricePerShare() / 1e18;
    assertGe(vault.totalAssets(), expectedAssets * 99 / 100); // 1% tolerance for rounding
}

// Sum of all shares equals total supply
function invariant_shareAccounting() public view {
    uint256 sumShares;
    for (uint i = 0; i < handler.actorCount(); i++) {
        sumShares += vault.balanceOf(handler.actors(i));
    }
    assertEq(sumShares, vault.totalSupply());
}

// No shares without assets (except initial state)
function invariant_noEmptyVault() public view {
    if (vault.totalSupply() > 0) {
        assertGt(vault.totalAssets(), 0);
    }
}

// First depositor attack prevention
function invariant_noInflation() public view {
    if (vault.totalSupply() > 0 && vault.totalAssets() > 0) {
        // Price per share shouldn't be astronomical
        assertLe(vault.pricePerShare(), 1e36);
    }
}
```

### Lending Protocol Invariants

```solidity
// Collateral ratio must be maintained
function invariant_collateralization() public view {
    for (uint i = 0; i < handler.actorCount(); i++) {
        address user = handler.actors(i);
        uint256 debt = lending.getBorrowBalance(user);
        uint256 collateral = lending.getCollateralValue(user);
        
        if (debt > 0) {
            assertGe(
                collateral * 100 / debt,
                lending.minCollateralRatio()
            );
        }
    }
}

// Total borrows <= Total liquidity supplied
function invariant_liquidity() public view {
    assertLe(lending.totalBorrows(), lending.totalSupply());
}

// Interest accrual is monotonic
function invariant_interestAccrual() public view {
    assertGe(lending.borrowIndex(), handler.ghost_lastBorrowIndex());
}

// Bad debt tracking
function invariant_noBadDebt() public view {
    assertEq(lending.badDebt(), 0);
}
```

### AMM/DEX Invariants

```solidity
// Constant product (x * y = k)
function invariant_constantProduct() public view {
    uint256 reserve0 = amm.reserve0();
    uint256 reserve1 = amm.reserve1();
    
    // K should only increase (from fees)
    assertGe(reserve0 * reserve1, handler.ghost_initialK());
}

// LP tokens redeemable for fair share
function invariant_lpRedemption() public view {
    uint256 totalSupply = amm.totalSupply();
    if (totalSupply == 0) return;
    
    uint256 reserve0 = amm.reserve0();
    uint256 reserve1 = amm.reserve1();
    
    // Any LP holder should get proportional reserves
    for (uint i = 0; i < handler.actorCount(); i++) {
        address user = handler.actors(i);
        uint256 lpBalance = amm.balanceOf(user);
        
        uint256 expectedToken0 = reserve0 * lpBalance / totalSupply;
        uint256 expectedToken1 = reserve1 * lpBalance / totalSupply;
        
        // Verify they'd get at least this much
        (uint256 out0, uint256 out1) = amm.getRedeemableAmounts(lpBalance);
        assertGe(out0, expectedToken0 * 99 / 100);
        assertGe(out1, expectedToken1 * 99 / 100);
    }
}

// No free tokens
function invariant_noFreeTokens() public view {
    assertEq(
        token0.balanceOf(address(amm)),
        amm.reserve0()
    );
    assertEq(
        token1.balanceOf(address(amm)),
        amm.reserve1()
    );
}
```

### ERC20 Token Invariants

```solidity
// Sum of balances equals total supply
function invariant_balanceSum() public view {
    uint256 sum;
    for (uint i = 0; i < handler.actorCount(); i++) {
        sum += token.balanceOf(handler.actors(i));
    }
    sum += token.balanceOf(address(handler));  // Handler balance
    
    assertEq(sum, token.totalSupply());
}

// Total supply never exceeds max
function invariant_maxSupply() public view {
    assertLe(token.totalSupply(), token.MAX_SUPPLY());
}

// Zero address has zero balance
function invariant_zeroAddress() public view {
    assertEq(token.balanceOf(address(0)), 0);
}
```

### NFT/ERC721 Invariants

```solidity
// Owner count matches balance
function invariant_ownerBalance() public view {
    for (uint i = 0; i < handler.actorCount(); i++) {
        address user = handler.actors(i);
        uint256 balance = nft.balanceOf(user);
        uint256 counted = 0;
        
        for (uint j = 0; j < nft.totalSupply(); j++) {
            if (nft.ownerOf(j) == user) counted++;
        }
        
        assertEq(balance, counted);
    }
}

// Every token has valid owner
function invariant_validOwners() public view {
    for (uint i = 0; i < nft.totalSupply(); i++) {
        address owner = nft.ownerOf(i);
        assertTrue(owner != address(0));
    }
}
```

---

## Ghost Variable Patterns

```solidity
contract Handler is Test {
    // Track deposits/withdrawals
    uint256 public ghost_totalDeposited;
    uint256 public ghost_totalWithdrawn;
    
    // Track per-user
    mapping(address => uint256) public ghost_userDeposits;
    mapping(address => uint256) public ghost_userWithdrawals;
    
    // Track call counts
    uint256 public ghost_depositCalls;
    uint256 public ghost_withdrawCalls;
    uint256 public ghost_failedCalls;
    
    // Track state snapshots
    uint256 public ghost_lastTotalSupply;
    uint256 public ghost_lastPrice;
    
    // Track bounds
    uint256 public ghost_minDeposit = type(uint256).max;
    uint256 public ghost_maxDeposit = 0;
    
    function deposit(uint256 amount) public {
        // ... do deposit ...
        
        // Update ghosts
        ghost_totalDeposited += amount;
        ghost_userDeposits[currentActor] += amount;
        ghost_depositCalls++;
        
        if (amount < ghost_minDeposit) ghost_minDeposit = amount;
        if (amount > ghost_maxDeposit) ghost_maxDeposit = amount;
        
        ghost_lastTotalSupply = token.totalSupply();
    }
}
```

---

## Foundry Configuration

```toml
# foundry.toml
[invariant]
runs = 256
depth = 15
fail_on_revert = false
call_override = false
dictionary_weight = 80
include_storage = true
include_push_bytes = true
shrink_run_limit = 5000
```

---

## Command Line

```bash
# Run all invariant tests
forge test --match-contract Invariant

# Run specific invariant
forge test --match-test invariant_balanceAccounting

# With verbosity for debugging
forge test --match-contract Invariant -vvvv

# With specific seed for reproduction
forge test --match-contract Invariant --fuzz-seed 12345
```

---

## AI Generation Guide

When generating invariant tests:

1. **Identify protocol type** (Vault, Lending, AMM, etc.)
2. **List core invariants**:
   - Accounting invariants (sums, balances)
   - Security invariants (access, bounds)
   - Economic invariants (ratios, prices)
3. **Create handler with bounded actions**
4. **Add ghost variables for tracking**
5. **Write invariant assertions**

### Template Prompt for AI
```
Generate Foundry invariant tests for a [PROTOCOL_TYPE] with:
- Main contract: [CONTRACT_NAME]
- Key functions: [deposit, withdraw, swap, etc.]
- Critical invariants: [describe what must always be true]
- Token: [ERC20/ERC721/native]
```

