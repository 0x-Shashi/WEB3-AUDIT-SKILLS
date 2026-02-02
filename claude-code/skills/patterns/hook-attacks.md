---
id: ATTACK-HOOKS
title: Hook-Based Protocol Attacks
category: attack-patterns
difficulty: advanced
tags: [hooks, uniswap-v4, callbacks, balancer, aave]
last_updated: 2026-01-31
---

# Hook-Based Protocol Attacks

## Overview

Hooks allow custom code execution at specific points in protocol operations. While powerful for extensibility, they create significant attack surfaces through callback manipulation, reentrancy, and state corruption.

```
┌─────────────────────────────────────────────────────────────────┐
│                     HOOK ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PROTOCOL OPERATION          HOOK POINTS                        │
│  ┌────────────────────────────────────────────────────────┐    │
│  │                                                        │    │
│  │  Pre-Hook ──► Core Logic ──► Post-Hook                 │    │
│  │     │              │              │                    │    │
│  │     ▼              ▼              ▼                    │    │
│  │  [Custom]     [Protocol]     [Custom]                  │    │
│  │   Code         Code           Code                     │    │
│  │                                                        │    │
│  └────────────────────────────────────────────────────────┘    │
│                          │                                      │
│                          ▼                                      │
│              ┌───────────────────────┐                          │
│              │    ATTACK SURFACES    │                          │
│              │  • Reentrancy         │                          │
│              │  • State manipulation │                          │
│              │  • Gas griefing       │                          │
│              │  • Access bypass      │                          │
│              │  • MEV extraction     │                          │
│              └───────────────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Uniswap V4 Hooks

### Hook Points

```solidity
// Uniswap V4 Hook Callbacks
interface IHooks {
    // Pool initialization
    function beforeInitialize(...) external returns (bytes4);
    function afterInitialize(...) external returns (bytes4);
    
    // Liquidity operations
    function beforeAddLiquidity(...) external returns (bytes4);
    function afterAddLiquidity(...) external returns (bytes4);
    function beforeRemoveLiquidity(...) external returns (bytes4);
    function afterRemoveLiquidity(...) external returns (bytes4);
    
    // Swaps
    function beforeSwap(...) external returns (bytes4);
    function afterSwap(...) external returns (bytes4);
    
    // Donations
    function beforeDonate(...) external returns (bytes4);
    function afterDonate(...) external returns (bytes4);
}
```

### Hook Address Encoding

```solidity
// Hook permissions encoded in address (leading bits)
// This is a unique Uniswap V4 security mechanism

/*
Address bits encode which hooks are enabled:
bit 0: beforeInitialize
bit 1: afterInitialize
bit 2: beforeAddLiquidity
...

Hook must be deployed to address matching its permissions!
*/

// ATTACK: Can't fake permissions (address is cryptographic commitment)
// But can deploy malicious hook to valid address via CREATE2 grinding
```

---

## Attack Vector 1: Hook Reentrancy

### Classic Reentrancy via Hooks

```solidity
// Hook called during swap enables reentrancy

contract MaliciousHook is IHooks {
    IPoolManager public poolManager;
    bool public attacking;
    
    function afterSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        BalanceDelta delta,
        bytes calldata hookData
    ) external returns (bytes4) {
        if (!attacking) {
            attacking = true;
            
            // ATTACK: Reenter pool during swap
            // State might be inconsistent!
            poolManager.swap(key, anotherSwapParams, "");
            
            attacking = false;
        }
        
        return IHooks.afterSwap.selector;
    }
}
```

### Cross-Function Reentrancy

```solidity
// Reenter different function during hook

contract CrossFunctionReentrancy is IHooks {
    function afterSwap(...) external returns (bytes4) {
        // Swap is in progress
        // Reenter via liquidity operation
        
        poolManager.modifyLiquidity(
            key,
            liquidityParams,
            ""
        );
        
        // Liquidity state might conflict with swap state!
        return IHooks.afterSwap.selector;
    }
}
```

### Defense Patterns

```solidity
// Uniswap V4's approach: Lock mechanism

contract PoolManager {
    // Reentrancy lock
    address public lockedBy;
    
    modifier lock() {
        if (lockedBy != address(0)) revert PoolLocked();
        lockedBy = msg.sender;
        _;
        lockedBy = address(0);
    }
    
    function swap(...) external lock returns (BalanceDelta) {
        // Hook can't reenter while locked
        _callHook(hooks.beforeSwap, ...);
        
        // But hook CAN call other functions that don't need lock
        // CAREFUL: What functions don't have lock?
    }
}

// Better: Per-pool locks
mapping(PoolId => bool) public poolLocked;
```

---

## Attack Vector 2: State Manipulation

### Pre-Hook State Corruption

```solidity
// Hook modifies state that affects core logic

contract StateManipulationHook is IHooks {
    function beforeSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata hookData
    ) external returns (bytes4) {
        // ATTACK: Manipulate oracle price before swap
        // Core logic will use manipulated price!
        
        oracle.setPrice(manipulatedPrice);
        
        return IHooks.beforeSwap.selector;
    }
}
```

### Post-Hook State Cleanup Failure

```solidity
// Hook fails to clean up state after operation

contract MessyHook is IHooks {
    uint256 public tempValue;
    
    function beforeSwap(...) external returns (bytes4) {
        tempValue = calculateSomething();
        return IHooks.beforeSwap.selector;
    }
    
    function afterSwap(...) external returns (bytes4) {
        // VULNERABILITY: If swap reverts, tempValue persists
        // Next operation might use stale tempValue
        
        processResult(tempValue);
        tempValue = 0;  // Only cleared if afterSwap succeeds
        
        return IHooks.afterSwap.selector;
    }
}

// DEFENSE: Reset state in finally block or separate function
```

### Return Value Manipulation

```solidity
// Hook return values can affect protocol behavior

contract ReturnManipulationHook is IHooks {
    function beforeSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata hookData
    ) external returns (bytes4, BeforeSwapDelta) {
        // Uniswap V4 hooks can return deltas
        // These modify the swap amounts!
        
        BeforeSwapDelta delta = BeforeSwapDelta({
            // Take extra tokens from swapper
            specified: toInt128(-1000),
            // Give fewer tokens to swapper  
            unspecified: toInt128(1000)
        });
        
        return (IHooks.beforeSwap.selector, delta);
    }
}
```

---

## Attack Vector 3: Gas Griefing

### Unbounded Gas Consumption

```solidity
// Hook consumes excessive gas

contract GasGriefingHook is IHooks {
    function beforeSwap(...) external returns (bytes4) {
        // ATTACK: Consume all available gas
        while (gasleft() > 10000) {
            // Expensive operations
            keccak256(abi.encodePacked(block.timestamp));
        }
        
        return IHooks.beforeSwap.selector;
    }
}

// Impact: 
// - Swaps become very expensive
// - Might hit block gas limit
// - DoS the pool
```

### Conditional Gas Attacks

```solidity
// Hook consumes different gas based on conditions

contract ConditionalGasHook is IHooks {
    function afterSwap(...) external returns (bytes4) {
        if (isTargetVictim(sender)) {
            // Normal gas for attacker
            return IHooks.afterSwap.selector;
        } else {
            // Excessive gas for victims
            consumeExcessiveGas();
            return IHooks.afterSwap.selector;
        }
    }
}
```

### Defense

```solidity
// Gas limits for hooks

contract PoolManagerWithGasLimits {
    uint256 public constant MAX_HOOK_GAS = 500000;
    
    function _callHook(
        function(...) external returns (bytes4) hook,
        ...
    ) internal {
        uint256 gasBefore = gasleft();
        
        bytes4 result = hook{gas: MAX_HOOK_GAS}(...);
        
        require(result == expectedSelector, "Hook failed");
        
        // If hook used too much gas, it reverted due to gas limit
    }
}
```

---

## Attack Vector 4: Access Control Bypass

### Privilege Escalation via Hooks

```solidity
// Hook gains elevated privileges

contract PrivilegeEscalationHook is IHooks {
    function afterSwap(
        address sender,
        PoolKey calldata key,
        ...
    ) external returns (bytes4) {
        // Hook is called BY pool manager
        // msg.sender = pool manager (privileged!)
        
        // ATTACK: Call other contracts as pool manager
        // If pool manager is authorized somewhere...
        
        vulnerableContract.privilegedFunction();
        // Works because msg.sender is pool manager!
        
        return IHooks.afterSwap.selector;
    }
}
```

### Hook Impersonation

```solidity
// Attacker deploys hook that impersonates legitimate one

// Legitimate hook at address 0xHOOK1
// Attacker creates pool pointing to 0xHOOK2 (malicious)

// Users think they're using HOOK1 but actually using HOOK2

// DEFENSE: 
// - Verify hook address before interacting
// - Use hook registries
// - Check hook bytecode hash
```

---

## Attack Vector 5: MEV Extraction

### Sandwich via Hooks

```solidity
// Hook enables sandwich attacks

contract SandwichHook is IHooks {
    function beforeSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata hookData
    ) external returns (bytes4) {
        // Front-run: Buy before user
        if (isTargetSwap(sender, params)) {
            executeOwnSwap(BUY, largeAmount);
        }
        
        return IHooks.beforeSwap.selector;
    }
    
    function afterSwap(...) external returns (bytes4) {
        // Back-run: Sell after user
        if (wasTargetSwap) {
            executeOwnSwap(SELL, largeAmount);
        }
        
        return IHooks.afterSwap.selector;
    }
}
```

### JIT Liquidity via Hooks

```solidity
// Hook provides just-in-time liquidity for MEV

contract JITHook is IHooks {
    function beforeSwap(...) external returns (bytes4) {
        // Detect large swap incoming
        if (params.amountSpecified > threshold) {
            // Add liquidity right before swap
            // Capture fees from the swap
            addConcentratedLiquidity(
                params.sqrtPriceLimitX96,
                largeAmount
            );
        }
        
        return IHooks.beforeSwap.selector;
    }
    
    function afterSwap(...) external returns (bytes4) {
        // Remove liquidity right after
        // Profit = fees earned - gas costs
        removeLiquidity();
        
        return IHooks.afterSwap.selector;
    }
}
```

---

## Attack Vector 6: Flash Accounting Exploits

### Uniswap V4 Flash Accounting

```solidity
// V4 uses "flash accounting" - settle balances at end of tx

contract FlashAccountingExploit is IHooks {
    function afterSwap(...) external returns (bytes4) {
        // At this point, balances are NOT settled
        // Pool manager tracks deltas
        
        // ATTACK: Manipulate before settlement
        // Take actions that affect final settlement
        
        // If hook can influence other pools...
        // Might be able to offset debts
        
        return IHooks.afterSwap.selector;
    }
}
```

### Delta Manipulation

```solidity
// Hook affects delta calculations

contract DeltaManipulationHook is IHooks {
    function afterSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        BalanceDelta delta,
        bytes calldata hookData
    ) external returns (bytes4, int128) {
        // Hooks can return delta adjustments
        // This affects how much user owes/receives
        
        // ATTACK: Return incorrect delta
        int128 maliciousDelta = -1000e18;  // Take extra from user
        
        return (IHooks.afterSwap.selector, maliciousDelta);
    }
}
```

---

## Audit Checklist

### Hook Security Review

```markdown
## Hook Contract Audit

### Reentrancy
□ Can hook reenter pool manager?
□ Can hook reenter itself?
□ Cross-function reentrancy possible?
□ State consistent during hook execution?

### State Management
□ Pre-hook state changes affect core logic?
□ Post-hook cleanup guaranteed?
□ Temporary state properly scoped?
□ Failed transactions clean up state?

### Access Control
□ Hook permissions match deployed address?
□ Hook can't impersonate other actors?
□ Privilege escalation prevented?
□ Hook registration verified?

### Gas Usage
□ Gas consumption bounded?
□ No conditional gas bombs?
□ Loops bounded?
□ External calls limited?

### Value Flow
□ Delta calculations correct?
□ Can't steal from swappers?
□ Fee extraction reasonable?
□ Flash accounting handled correctly?
```

### Pool with Hook Review

```markdown
## Pool + Hook Integration Audit

### Configuration
□ Hook address valid for permissions claimed?
□ Hook bytecode verified?
□ Hook parameters safe?
□ Upgrade mechanism secure?

### Interaction Safety
□ Pool operations safe with this hook?
□ MEV extraction limited?
□ User protection maintained?
□ Emergency shutdown possible?

### Economic Security
□ Hook fees reasonable?
□ No value extraction attacks?
□ Liquidity providers protected?
□ Swappers protected?
```

---

## Code Examples

### Safe Hook Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IHooks} from "@uniswap/v4-core/contracts/interfaces/IHooks.sol";
import {BaseHook} from "@uniswap/v4-periphery/contracts/BaseHook.sol";

contract SafeHook is BaseHook {
    // Reentrancy guard
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;
    uint256 private _status = NOT_ENTERED;
    
    modifier nonReentrant() {
        require(_status != ENTERED, "Reentrant call");
        _status = ENTERED;
        _;
        _status = NOT_ENTERED;
    }
    
    // Gas limit for operations
    uint256 public constant MAX_OPERATION_GAS = 200000;
    
    function beforeSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata hookData
    ) external override nonReentrant returns (bytes4, BeforeSwapDelta, uint24) {
        // Bound gas usage
        uint256 startGas = gasleft();
        
        // Safe operations only
        _safeBeforeSwap(sender, key, params, hookData);
        
        // Verify gas usage
        require(
            startGas - gasleft() < MAX_OPERATION_GAS,
            "Excessive gas"
        );
        
        return (
            IHooks.beforeSwap.selector,
            BeforeSwapDelta(0, 0),  // No delta modification
            0  // No fee override
        );
    }
    
    function _safeBeforeSwap(...) internal {
        // Implement safe logic here
        // No external calls
        // No state that affects core protocol
        // Bounded computation
    }
}
```

---

## Related Resources

- [Uniswap V4 Documentation](https://docs.uniswap.org/concepts/protocol/concentrated-liquidity)
- [Hook Examples](https://github.com/Uniswap/v4-periphery/tree/main/contracts/hooks/examples)
- [Balancer Hooks](https://docs.balancer.fi/concepts/hooks/)
- [Hook Security Best Practices](https://blog.uniswap.org/v4-security-considerations)
