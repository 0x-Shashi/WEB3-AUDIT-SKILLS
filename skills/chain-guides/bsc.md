---
id: CHAIN-BSC
title: BNB Smart Chain Security Guide
category: chain-guides
chain: bsc
difficulty: intermediate
tags: [bsc, bnb, binance, evm, sidechain]
last_updated: 2026-01-31
---

# BNB Smart Chain (BSC) Security Guide

## Overview

BSC is an EVM-compatible chain run by 21 validators (Proof of Staked Authority). It has Ethereum compatibility but different security assumptions.

## Key Differences from Ethereum

| Aspect | Ethereum | BSC |
|--------|----------|-----|
| Consensus | PoS | PoSA (21 validators) |
| Block Time | ~12 sec | ~3 sec |
| Validators | ~900k | 21 (rotated) |
| Finality | ~15 min | ~45 sec |
| Governance | Decentralized | Binance-influenced |

## Critical Security Areas

### 1. Validator Centralization

Only 21 validators create blocks. This affects security assumptions.

```solidity
// Security implications of 21 validators:
// 1. Easier censorship (15 validators needed)
// 2. Faster finality
// 3. Potential for coordinated attacks

// CONSIDERATION: High-value operations need extra protection
contract HighValueProtection {
    uint256 public constant FINALITY_BLOCKS = 15;  // ~45 seconds
    
    mapping(bytes32 => uint256) public pendingWithdrawals;
    
    function initiateWithdrawal(uint256 amount) external returns (bytes32) {
        bytes32 id = keccak256(abi.encode(msg.sender, amount, block.number));
        pendingWithdrawals[id] = block.number;
        return id;
    }
    
    function finalizeWithdrawal(bytes32 id) external {
        uint256 initiatedBlock = pendingWithdrawals[id];
        require(initiatedBlock > 0, "Not initiated");
        require(
            block.number >= initiatedBlock + FINALITY_BLOCKS,
            "Wait for finality"
        );
        
        delete pendingWithdrawals[id];
        _processWithdrawal(id);
    }
}
```

### 2. BNB vs ETH Handling

BNB is the native token. Similar semantics to ETH but watch for assumptions.

```solidity
// Common issue: Hardcoded ETH references
// VULNERABLE
contract WrongToken {
    // Comments/variable names reference ETH but it's BNB
    uint256 public ethBalance;  // Misleading!
    
    function depositETH() external payable {  // Actually deposits BNB
        ethBalance += msg.value;
    }
}

// SECURE - Clear naming
contract ClearNaming {
    uint256 public bnbBalance;
    
    function depositBNB() external payable {
        bnbBalance += msg.value;
        emit BNBDeposited(msg.sender, msg.value);
    }
}
```

### 3. BEP-20 Token Standard

BEP-20 is essentially ERC-20 but watch for differences.

```solidity
// BEP-20 == ERC-20 interface
// BUT: Some BSC tokens have non-standard implementations

// Common issues:
// 1. BUSD: Has blacklist (like USDC)
// 2. Some tokens: No return value on transfer (like USDT)
// 3. Some tokens: Fee on transfer

// SECURE - Use SafeERC20
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract SafeBSCTokens {
    using SafeERC20 for IERC20;
    
    function safeDeposit(IERC20 token, uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        
        // Handle fee-on-transfer
        _credit(msg.sender, received);
    }
}
```

### 4. PancakeSwap Integration

PancakeSwap is the main DEX - similar to Uniswap V2 but with differences.

```solidity
// PancakeSwap V2 is a Uniswap V2 fork
// Same interface, different addresses

interface IPancakeRouter {
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    
    function getAmountsOut(uint amountIn, address[] calldata path)
        external view returns (uint[] memory amounts);
}

// SECURE swap integration
contract PancakeIntegration {
    IPancakeRouter public router = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    
    function safeSwap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minAmountOut
    ) external {
        IERC20(tokenIn).approve(address(router), amountIn);
        
        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;
        
        // Always use deadline and minAmountOut
        router.swapExactTokensForTokens(
            amountIn,
            minAmountOut,
            path,
            msg.sender,
            block.timestamp + 300  // 5 minute deadline
        );
    }
}
```

### 5. Cross-Chain Bridge Security

BSC has multiple bridges - each with different trust assumptions.

```solidity
// Main BSC bridges:
// 1. Binance Bridge (centralized)
// 2. Multichain (was Anyswap) - compromised in 2023
// 3. Celer cBridge
// 4. LayerZero

// CRITICAL: Verify bridge token authenticity
// Many "bridged" tokens exist - some are scams

contract BridgeTokenVerifier {
    // Maintain whitelist of legitimate bridged tokens
    mapping(address => bool) public verifiedBridgedTokens;
    
    // Example verified tokens
    constructor() {
        // Binance-Peg BUSD
        verifiedBridgedTokens[0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56] = true;
        // Binance-Peg ETH
        verifiedBridgedTokens[0x2170Ed0880ac9A755fd29B2688956BD959F933F8] = true;
    }
    
    function deposit(address token, uint256 amount) external {
        require(verifiedBridgedTokens[token], "Unverified token");
        // Proceed with deposit
    }
}
```

### 6. Flash Loan Sources

BSC has different flash loan providers.

```solidity
// Flash loan sources on BSC:
// 1. PancakeSwap (flash swaps)
// 2. DODO
// 3. Venus Protocol

// VULNERABLE - Not accounting for flash loan attacks
contract FlashVulnerable {
    function getPrice() external view returns (uint256) {
        // Using spot price from PancakeSwap
        // Can be manipulated via flash loan
        return pancakeOracle.getSpotPrice();
    }
}

// SECURE - Use TWAP or Chainlink
contract FlashSecure {
    AggregatorV3Interface public priceFeed;
    
    function getPrice() external view returns (uint256) {
        // Chainlink is flash-loan resistant
        (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
        require(block.timestamp - updatedAt < 1 hours, "Stale price");
        return uint256(price);
    }
}
```

### 7. BSC-Specific Scam Patterns

BSC has high scam activity. Extra validation needed.

```solidity
// Common BSC scam patterns:
// 1. Honeypot tokens (can buy, can't sell)
// 2. Fake liquidity locks
// 3. Proxy upgrades to rug
// 4. Hidden mint functions

// AUDIT FOCUS:
// [ ] Can all users sell tokens?
// [ ] Is liquidity actually locked?
// [ ] Check for hidden admin functions
// [ ] Verify contract source matches deployed bytecode
```

## Chainlink on BSC

```solidity
// Chainlink is available on BSC
// Use for reliable price feeds

address constant BNB_USD_FEED = 0x0567F2323251f0Aab15c8dFb1967E4e8A7D42aeE;
address constant ETH_USD_FEED = 0x9ef1B8c0E4F7dc8bF5719Ea496883DC6401d5b2e;
address constant BTC_USD_FEED = 0x264990fbd0A4796A3E3d8E37C4d5F87a3aCa5Ebf;
```

## Audit Checklist

```
[ ] Validator centralization risks assessed
[ ] BNB/ETH naming clarity
[ ] BEP-20 token edge cases handled (SafeERC20)
[ ] Bridge token authenticity verified
[ ] Flash loan attack vectors checked
[ ] PancakeSwap integration secure
[ ] Price oracle flash-resistant
[ ] Scam pattern checks complete
```

## Key Addresses

```solidity
// BSC Mainnet
address constant WBNB = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;
address constant BUSD = 0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56;
address constant USDT = 0x55d398326f99059fF775485246999027B3197955;
address constant USDC = 0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d;

// PancakeSwap
address constant PANCAKE_ROUTER = 0x10ED43C718714eb63d5aA57B78B54704E256024E;
address constant PANCAKE_FACTORY = 0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73;
```
