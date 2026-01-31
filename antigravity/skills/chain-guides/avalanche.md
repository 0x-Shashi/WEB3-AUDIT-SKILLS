---
id: CHAIN-AVALANCHE
title: Avalanche C-Chain Security Guide
category: chain-guides
chain: avalanche
difficulty: intermediate
tags: [avalanche, avax, c-chain, subnet, evm]
last_updated: 2026-01-31
---

# Avalanche C-Chain Security Guide

## Overview

Avalanche C-Chain is an EVM-compatible chain using Avalanche consensus. It offers sub-second finality and subnet capabilities.

## Key Differences from Ethereum

| Aspect | Ethereum | Avalanche C-Chain |
|--------|----------|-------------------|
| Consensus | PoS | Snowball (DAG-based) |
| Block Time | ~12 sec | ~2 sec |
| Finality | ~15 min | ~1-2 seconds |
| Architecture | Single chain | Multi-chain (X, P, C) |
| Native Token | ETH | AVAX |

## Critical Security Areas

### 1. Sub-Second Finality

Avalanche has near-instant finality. This affects timing assumptions.

```solidity
// Finality is ~1-2 seconds on Avalanche
// Much faster than Ethereum's ~15 minutes

// IMPLICATION: Time-based logic needs adjustment
contract AvalancheTimeLogic {
    // On Ethereum, might use 12 block confirmations (~2.4 min)
    // On Avalanche, finality is nearly instant
    
    uint256 public constant CONFIRMATION_TIME = 5;  // 5 seconds is plenty
    
    mapping(bytes32 => uint256) public pendingTx;
    
    function initiate(bytes32 txHash) external {
        pendingTx[txHash] = block.timestamp;
    }
    
    function finalize(bytes32 txHash) external {
        require(
            block.timestamp >= pendingTx[txHash] + CONFIRMATION_TIME,
            "Wait for finality"
        );
        _process(txHash);
    }
}
```

### 2. AVAX vs ETH Semantics

AVAX is the native token. Similar to ETH but different symbol.

```solidity
// AVAX handling is identical to ETH
// Use msg.value, payable, etc.

// WAVAX is Wrapped AVAX (like WETH)
address constant WAVAX = 0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7;

interface IWAVAX {
    function deposit() external payable;
    function withdraw(uint256) external;
}

contract AVAXHandler {
    IWAVAX public wavax = IWAVAX(0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7);
    
    function wrapAVAX() external payable {
        wavax.deposit{value: msg.value}();
    }
    
    function unwrapAVAX(uint256 amount) external {
        wavax.withdraw(amount);
        payable(msg.sender).transfer(amount);
    }
}
```

### 3. Trader Joe Integration

Trader Joe is the main DEX on Avalanche. It has V1 (Uniswap V2 fork) and V2 (Liquidity Book).

```solidity
// Trader Joe V2 uses "Liquidity Book" model
// Different from traditional AMMs

interface ILBRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        uint256[] memory pairBinSteps,
        IERC20[] memory tokenPath,
        address to,
        uint256 deadline
    ) external returns (uint256 amountOut);
}

// SECURE integration
contract TraderJoeIntegration {
    ILBRouter public router = ILBRouter(0xb4315e873dBcf96Ffd0acd8EA43f689D8c20fB30);
    
    function safeLBSwap(
        IERC20 tokenIn,
        IERC20 tokenOut,
        uint256 amountIn,
        uint256 minAmountOut,
        uint256 binStep  // Liquidity Book parameter
    ) external {
        tokenIn.approve(address(router), amountIn);
        
        IERC20[] memory path = new IERC20[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;
        
        uint256[] memory binSteps = new uint256[](1);
        binSteps[0] = binStep;
        
        router.swapExactTokensForTokens(
            amountIn,
            minAmountOut,
            binSteps,
            path,
            msg.sender,
            block.timestamp + 300
        );
    }
}
```

### 4. Subnet Considerations

Avalanche supports subnets - custom chains with their own rules.

```solidity
// Subnet security considerations:
// 1. Different validator sets per subnet
// 2. Cross-subnet communication needs bridges
// 3. Subnet-specific tokens may not work on C-Chain

// When interacting with subnet assets:
contract SubnetAware {
    mapping(address => bool) public cChainTokens;
    mapping(address => address) public subnetBridgedTokens;
    
    function depositToken(address token, uint256 amount) external {
        // Verify it's a C-Chain native or properly bridged token
        require(
            cChainTokens[token] || subnetBridgedTokens[token] != address(0),
            "Unknown token origin"
        );
        
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }
}
```

### 5. Avalanche Bridge

The official bridge connects Ethereum to Avalanche.

```solidity
// Avalanche Bridge (AB) wraps Ethereum tokens
// Bridged tokens have ".e" suffix (e.g., USDC.e)

// Native USDC on Avalanche: 0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E
// Bridged USDC.e: 0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664

// IMPORTANT: These are different tokens!
contract AvalancheUSDC {
    IERC20 public nativeUSDC = IERC20(0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E);
    IERC20 public bridgedUSDC = IERC20(0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664);
    
    // Handle both or be explicit about which one
    function deposit(address token, uint256 amount) external {
        require(
            token == address(nativeUSDC) || token == address(bridgedUSDC),
            "Invalid USDC"
        );
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }
}
```

### 6. Gas and Fee Structure

Avalanche has dynamic fees similar to EIP-1559.

```solidity
// Avalanche C-Chain uses EIP-1559 style fees
// Base fee adjusts based on demand
// Tips go to validators

// Gas costs are generally similar to Ethereum
// But blocks are faster, so throughput is higher

// CONSIDERATION: Fee spikes during high activity
contract FeeAware {
    uint256 public maxBaseFee = 100 gwei;
    
    modifier reasonableFee() {
        require(block.basefee <= maxBaseFee, "Fee too high");
        _;
    }
    
    function executeTrade() external reasonableFee {
        // Proceed when fees are reasonable
    }
}
```

### 7. Chainlink on Avalanche

```solidity
// Chainlink feeds available on Avalanche

address constant AVAX_USD = 0x0A77230d17318075983913bC2145DB16C7366156;
address constant ETH_USD = 0x976B3D034E162d8bD72D6b9C989d545b839003b0;
address constant BTC_USD = 0x2779D32d5166BAaa2B2b658333bA7e6Ec0C65743;
address constant USDC_USD = 0xF096872672F44d6EBA71458D74fe67F9a77a23B9;

// SECURE price fetching
contract AvalanchePriceFeed {
    AggregatorV3Interface public avaxUsdFeed = 
        AggregatorV3Interface(0x0A77230d17318075983913bC2145DB16C7366156);
    
    function getAVAXPrice() external view returns (uint256) {
        (, int256 price, , uint256 updatedAt, ) = avaxUsdFeed.latestRoundData();
        
        require(price > 0, "Invalid price");
        require(block.timestamp - updatedAt < 1 hours, "Stale price");
        
        return uint256(price);
    }
}
```

### 8. AAVE/Benqi Lending

Major lending protocols on Avalanche.

```solidity
// Benqi (native) and Aave V3 are major lenders
// Similar interfaces to mainnet versions

// Benqi QiTokens (like cTokens)
interface IQiToken {
    function mint(uint256 mintAmount) external returns (uint256);
    function redeem(uint256 redeemTokens) external returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
    function repayBorrow(uint256 repayAmount) external returns (uint256);
}

// Audit same patterns as Compound/Aave
```

## Audit Checklist

```
[ ] Fast finality implications considered
[ ] AVAX vs ETH naming clear
[ ] Trader Joe LB integration correct
[ ] Bridge token handling (native vs .e)
[ ] Subnet token origins verified
[ ] Gas fee spikes handled
[ ] Chainlink feeds validated
[ ] Lending protocol patterns checked
```

## Key Addresses

```solidity
// Avalanche C-Chain Mainnet
address constant WAVAX = 0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7;
address constant NATIVE_USDC = 0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E;
address constant BRIDGED_USDC = 0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664;
address constant USDT = 0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7;

// Trader Joe
address constant JOE_ROUTER_V1 = 0x60aE616a2155Ee3d9A68541Ba4544862310933d4;
address constant LB_ROUTER = 0xb4315e873dBcf96Ffd0acd8EA43f689D8c20fB30;

// Benqi
address constant BENQI_COMPTROLLER = 0x486Af39519B4Dc9a7fCcd318217352830E8AD9b4;
```
