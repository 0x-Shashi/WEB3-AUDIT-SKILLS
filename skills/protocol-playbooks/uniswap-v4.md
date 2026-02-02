---
id: PROTOCOL-UNISWAP-V4
title: Uniswap V4 Security Playbook
category: protocol-playbook
protocol: uniswap-v4
difficulty: advanced
tags: [dex, amm, hooks, singleton, flash-accounting]
last_updated: 2026-01-31
---

# Uniswap V4 Security Playbook

> **Attack Surface:** See [attack-trees/dex-attack-tree.md](../attack-trees/dex-attack-tree.md)

## Protocol Overview

Uniswap V4 introduces revolutionary changes: singleton architecture, hooks, and flash accounting. These changes require entirely new security considerations.

## Architecture Changes from V3

| Aspect | V3 | V4 |
|--------|----|----|
| Pool Contracts | One per pair | Singleton for all |
| Customization | None | Hooks |
| Gas Model | Full transfer each swap | Flash accounting |
| Fee Structure | Fixed tiers | Dynamic via hooks |
| Oracles | Built-in TWAP | Via hooks |

## Critical Security Areas

### 1. Hook Security

Hooks are the primary attack surface in V4.

```solidity
// HOOK PERMISSIONS (flags in address)
// beforeInitialize, afterInitialize
// beforeAddLiquidity, afterAddLiquidity
// beforeRemoveLiquidity, afterRemoveLiquidity
// beforeSwap, afterSwap
// beforeDonate, afterDonate

// VULNERABLE HOOK - Unbounded state changes
contract VulnerableHook is BaseHook {
    function beforeSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata hookData
    ) external override returns (bytes4) {
        // Attacker can drain gas by passing large hookData
        for (uint i = 0; i < hookData.length; i++) {
            // Process each byte
        }
        return BaseHook.beforeSwap.selector;
    }
}

// SECURE HOOK - Bounded operations
contract SecureHook is BaseHook {
    uint256 constant MAX_HOOK_DATA = 256;
    
    function beforeSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata hookData
    ) external override returns (bytes4) {
        require(hookData.length <= MAX_HOOK_DATA, "Data too long");
        
        // Process bounded data
        if (hookData.length > 0) {
            _processHookData(hookData);
        }
        
        return BaseHook.beforeSwap.selector;
    }
}
```

### 2. Hook Address Requirements

Hook addresses must have specific flags encoded in the address.

```solidity
// Hook permissions are encoded in the address
// The address must match the permissions declared

import {Hooks} from "@uniswap/v4-core/contracts/libraries/Hooks.sol";

// Example: Hook that needs beforeSwap
// Address must have bit 7 set (beforeSwap flag)

function validateHookAddress(address hook) internal pure {
    Hooks.Permissions memory permissions = Hooks.Permissions({
        beforeInitialize: false,
        afterInitialize: false,
        beforeAddLiquidity: false,
        afterAddLiquidity: false,
        beforeRemoveLiquidity: false,
        afterRemoveLiquidity: false,
        beforeSwap: true,   // We need this
        afterSwap: false,
        beforeDonate: false,
        afterDonate: false
    });
    
    // Validate the hook address has correct flags
    Hooks.validateHookAddress(IHooks(hook), permissions);
}

// Mining valid hook addresses requires CREATE2
contract HookDeployer {
    function deploy(bytes32 salt, bytes memory creationCode) 
        external returns (address) 
    {
        address deployed;
        assembly {
            deployed := create2(0, add(creationCode, 32), mload(creationCode), salt)
        }
        // Must mine salt to get address with correct permission flags
        return deployed;
    }
}
```

### 3. Flash Accounting Vulnerabilities

V4 uses a delta-based accounting system.

```solidity
// VULNERABLE - Assuming immediate token transfers
contract NaiveIntegration {
    function doSwap(PoolKey memory key, uint256 amountIn) external {
        // WRONG: V4 doesn't transfer tokens immediately
        token.transferFrom(msg.sender, address(poolManager), amountIn);
        
        poolManager.swap(key, params, "");
        
        // Tokens aren't where you expect!
    }
}

// SECURE - Using flash accounting properly
contract ProperIntegration {
    using CurrencyLibrary for Currency;
    
    function doSwap(PoolKey memory key, uint256 amountIn) external {
        // Lock to enter flash accounting context
        poolManager.lock(abi.encode(SwapData({
            key: key,
            amountIn: amountIn,
            user: msg.sender
        })));
    }
    
    function lockAcquired(bytes calldata data) external returns (bytes memory) {
        require(msg.sender == address(poolManager), "Not pool manager");
        
        SwapData memory swapData = abi.decode(data, (SwapData));
        
        // Perform swap - creates delta
        BalanceDelta delta = poolManager.swap(
            swapData.key, 
            params, 
            ""
        );
        
        // Settle negative delta (tokens owed to pool)
        if (delta.amount0() < 0) {
            // Must pay tokens
            swapData.key.currency0.transfer(
                address(poolManager),
                uint256(-delta.amount0())
            );
            poolManager.settle(swapData.key.currency0);
        }
        
        // Take positive delta (tokens owed to us)
        if (delta.amount1() > 0) {
            poolManager.take(
                swapData.key.currency1,
                swapData.user,
                uint256(delta.amount1())
            );
        }
        
        return "";
    }
}
```

### 4. Reentrancy via Hooks

```solidity
// VULNERABLE - Hook reenters during swap
contract ReentrantHook is BaseHook {
    function beforeSwap(...) external override returns (bytes4) {
        // Reenters pool manager during swap
        poolManager.swap(anotherKey, params, "");  // DANGEROUS
        return BaseHook.beforeSwap.selector;
    }
}

// The PoolManager has reentrancy guards but hooks can still cause issues
// by manipulating state in unexpected ways

// SECURE - Track and prevent reentrancy
contract SafeHook is BaseHook {
    bool private locked;
    
    modifier noReentrant() {
        require(!locked, "Reentrant");
        locked = true;
        _;
        locked = false;
    }
    
    function beforeSwap(...) external override noReentrant returns (bytes4) {
        // Safe operations only
        _updateInternalState();
        return BaseHook.beforeSwap.selector;
    }
}
```

### 5. Delta Resolution Issues

```solidity
// CRITICAL: All deltas must be resolved before lock exits

function lockAcquired(bytes calldata data) external returns (bytes memory) {
    // Do operations...
    BalanceDelta delta = poolManager.swap(...);
    
    // VULNERABLE - Not settling all deltas
    if (delta.amount0() < 0) {
        // Settle token0...
    }
    // Forgot to take token1! Lock will revert
    
    // SECURE - Resolve all deltas
    _settleDelta(delta.amount0(), key.currency0);
    _takeDelta(delta.amount1(), key.currency1);
    
    return "";
}

function _settleDelta(int128 amount, Currency currency) internal {
    if (amount < 0) {
        currency.transfer(address(poolManager), uint256(-amount));
        poolManager.settle(currency);
    }
}

function _takeDelta(int128 amount, Currency currency) internal {
    if (amount > 0) {
        poolManager.take(currency, msg.sender, uint256(amount));
    }
}
```

### 6. Dynamic Fee Manipulation

```solidity
// Hooks can implement dynamic fees

contract DynamicFeeHook is BaseHook {
    // VULNERABLE - Fee can be manipulated
    function getFee(PoolKey calldata key) external view returns (uint24) {
        // Using spot price for fee calculation
        // Can be manipulated with flash loans
        uint256 price = getSpotPrice(key);
        return calculateFee(price);
    }
}

// SECURE - Use TWAP or bounded fees
contract SafeDynamicFeeHook is BaseHook {
    uint24 constant MIN_FEE = 100;   // 0.01%
    uint24 constant MAX_FEE = 10000; // 1%
    
    function getFee(PoolKey calldata key) external view returns (uint24) {
        // Use TWAP, not spot price
        uint256 twapPrice = getTWAPPrice(key, 30 minutes);
        uint24 calculatedFee = calculateFee(twapPrice);
        
        // Bound the fee
        if (calculatedFee < MIN_FEE) return MIN_FEE;
        if (calculatedFee > MAX_FEE) return MAX_FEE;
        return calculatedFee;
    }
}
```

### 7. Pool Key Validation

```solidity
// PoolKey structure
struct PoolKey {
    Currency currency0;
    Currency currency1;
    uint24 fee;
    int24 tickSpacing;
    IHooks hooks;
}

// VULNERABLE - Not validating pool key
function interact(PoolKey calldata key) external {
    // Key could point to malicious pool/hook
    poolManager.swap(key, params, "");
}

// SECURE - Validate pool key
function interact(PoolKey calldata key) external {
    // Verify pool exists
    require(poolManager.getSlot0(key.toId()).sqrtPriceX96 != 0, "Pool not initialized");
    
    // Verify hook is trusted
    require(trustedHooks[address(key.hooks)], "Untrusted hook");
    
    // Verify token ordering
    require(Currency.unwrap(key.currency0) < Currency.unwrap(key.currency1), "Wrong order");
    
    poolManager.swap(key, params, "");
}
```

## Audit Checklist

```
[ ] Hook address has correct permission flags
[ ] Hook operations are gas-bounded
[ ] All deltas are resolved in lockAcquired
[ ] No reentrancy in hooks
[ ] Pool keys are validated
[ ] Dynamic fees are bounded and manipulation-resistant
[ ] Hook data is validated and bounded
[ ] Flash accounting is properly handled
[ ] Singleton interactions are correctly locked
[ ] Token ordering is correct (currency0 < currency1)
```

## Integration Patterns

### Safe Swap Integration
```solidity
contract SwapRouter {
    IPoolManager public immutable poolManager;
    
    function swap(
        PoolKey memory key,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96
    ) external returns (int256 amount0, int256 amount1) {
        bytes memory result = poolManager.lock(
            abi.encode(SwapCallbackData({
                key: key,
                params: IPoolManager.SwapParams({
                    zeroForOne: zeroForOne,
                    amountSpecified: amountSpecified,
                    sqrtPriceLimitX96: sqrtPriceLimitX96
                }),
                sender: msg.sender
            }))
        );
        
        (amount0, amount1) = abi.decode(result, (int256, int256));
    }
}
```

## Known Attack Vectors

| Attack | Target | Mitigation |
|--------|--------|------------|
| Hook gas griefing | Hook callbacks | Bound hook data size |
| Fee manipulation | Dynamic fee hooks | Use TWAP, bound fees |
| Delta imbalance | Flash accounting | Resolve all deltas |
| Hook reentrancy | Hook state | Reentrancy guards |
| Pool key spoofing | Pool interactions | Validate pool existence |
