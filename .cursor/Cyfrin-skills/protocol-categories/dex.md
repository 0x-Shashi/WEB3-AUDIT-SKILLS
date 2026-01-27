# DEX (Decentralized Exchange) Security

## Quick Start

DEXs enable trustless token swapping through automated market makers (AMMs) or order books. They're critical DeFi infrastructure and prime targets for MEV extraction and price manipulation.

**Risk Level:** HIGH  
**Common Attacks:** Sandwich attacks, price manipulation, reentrancy  
**Key Considerations:** Slippage, MEV, liquidity management

## DEX Types

| Type | Examples | Mechanism | Primary Risks |
|------|----------|-----------|---------------|
| AMM | Uniswap, Curve | x*y=k | Price manipulation, impermanent loss |
| Order Book | dYdX, Serum | Bid/ask matching | Front-running, order manipulation |
| Aggregator | 1inch, Paraswap | Route optimization | Bad routes, callback attacks |
| Concentrated | Uniswap V3 | Range positions | Position management, JIT liquidity |

## Most Critical DEX Vulnerabilities

### 1. Price/Slippage Manipulation
MEV bots sandwich user transactions for profit.

### 2. Spot Price Oracle Usage
Using AMM reserves as price source enables flash loan attacks.

### 3. Missing Slippage Protection
Users receive far fewer tokens than expected.

### 4. Reentrancy in Swaps
External calls during swap enable re-entry attacks.

### 5. Fee Calculation Errors
Incorrect fee logic leads to value extraction.

## API Query: DEX Vulnerabilities

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "protocolCategory": [{"value": "DEX"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

## API Query: Front-Running Issues

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "protocolCategory": [{"value": "DEX"}],
      "tags": [{"value": "Front-running"}],
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

## API Query: AMM-Specific Issues

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "keywords": "AMM liquidity pool swap",
      "impact": ["HIGH", "MEDIUM"],
      "qualityScore": 3
    }
  }'
```

## Security Considerations by Feature

### Swap Implementation
```solidity
// VULNERABLE - No slippage, no deadline
function swap(address tokenIn, uint256 amountIn) external returns (uint256) {
    uint256 amountOut = calculateOutput(amountIn);
    IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
    IERC20(tokenOut).transfer(msg.sender, amountOut);
    return amountOut;
}

// SECURE - With protections
function swap(
    address tokenIn,
    uint256 amountIn,
    uint256 minAmountOut,  // Slippage protection
    uint256 deadline       // Deadline protection
) external returns (uint256) {
    require(block.timestamp <= deadline, "Expired");
    
    uint256 amountOut = calculateOutput(amountIn);
    require(amountOut >= minAmountOut, "Slippage");
    
    IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
    IERC20(tokenOut).transfer(msg.sender, amountOut);
    
    return amountOut;
}
```

### Liquidity Addition
```solidity
// VULNERABLE - No minimum LP tokens
function addLiquidity(uint256 amountA, uint256 amountB) external {
    uint256 liquidity = calculateLiquidity(amountA, amountB);
    _mint(msg.sender, liquidity);
}

// SECURE - With minimums and deadline
function addLiquidity(
    uint256 amountA,
    uint256 amountB,
    uint256 minLiquidity,
    uint256 deadline
) external returns (uint256 liquidity) {
    require(block.timestamp <= deadline, "Expired");
    
    liquidity = calculateLiquidity(amountA, amountB);
    require(liquidity >= minLiquidity, "Insufficient liquidity");
    
    // Handle first depositor attack
    if (totalSupply() == 0) {
        liquidity = sqrt(amountA * amountB) - MINIMUM_LIQUIDITY;
        _mint(address(0), MINIMUM_LIQUIDITY);  // Lock minimum
    }
    
    _mint(msg.sender, liquidity);
}
```

### Price Calculation
```solidity
// VULNERABLE - Spot price from reserves
function getPrice() public view returns (uint256) {
    return reserve0 * 1e18 / reserve1;  // Flash loanable
}

// SECURE - TWAP
function getPrice() public view returns (uint256) {
    return twapOracle.consult(token0, 30 minutes);
}
```

## Common Vulnerable Patterns

### 1. Sandwich-able Swaps
```solidity
// User submits: swap(1000 USDC -> ETH, min: 0.49 ETH)
// MEV bot:
//   1. Buy ETH (price rises)
//   2. User's swap executes at worse price
//   3. Sell ETH (profit)
```

### 2. First LP Attack
```solidity
// Attacker:
// 1. Deposit 1 wei of each token
// 2. Donate 1000 tokens to pool directly
// 3. LP token now worth ~1000 tokens each
// 4. Next LP depositor gets 0 tokens (rounding)
```

### 3. Price Oracle Exploitation
```solidity
// Using DEX price in lending protocol:
// 1. Flash loan tokens
// 2. Swap to manipulate reserve ratio
// 3. Lending protocol reads bad price
// 4. Borrow more than allowed
// 5. Swap back, repay flash loan
```

### 4. Router Callback Attacks
```solidity
// VULNERABLE - Untrusted callback
function swap(address recipient, bytes calldata data) external {
    // Transfer tokens
    ICallback(recipient).callback(data);  // Attacker controls this
}

// SECURE - Validate callback
function swap(address recipient, bytes calldata data) external {
    require(isValidRouter[msg.sender], "Invalid caller");
    // Transfer tokens
    ICallback(recipient).callback(data);
}
```

## DEX Security Checklist

### Swap Security
- [ ] Slippage protection (minAmountOut)
- [ ] Transaction deadline
- [ ] Reentrancy protection
- [ ] Proper fee calculation
- [ ] Valid token pair validation

### Liquidity Security
- [ ] First depositor attack prevention
- [ ] Minimum liquidity lock
- [ ] Proper LP token minting formula
- [ ] Withdrawal slippage protection
- [ ] Same-block add/remove protection

### Price/Oracle
- [ ] No spot price usage for external protocols
- [ ] TWAP available if needed
- [ ] Price bounds/sanity checks
- [ ] Flash loan resistance

### MEV Protection
- [ ] Private transaction options (Flashbots)
- [ ] Time-weighted execution option
- [ ] Commit-reveal for large trades
- [ ] Auction mechanisms if needed

### General
- [ ] Emergency pause functionality
- [ ] Fee bounds (min/max)
- [ ] Proper event emission
- [ ] Access control for admin functions

## Top DEX Exploits to Study

| Protocol | Attack | Loss | Root Cause |
|----------|--------|------|------------|
| Curve | Reentrancy | $70M | Vyper compiler bug |
| SushiSwap | Router | $3M | Callback vulnerability |
| Saddle | Flash loan | $10M | Pool imbalance |
| Balancer | Flash loan | $500K | Price manipulation |

## Test This Query

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 5,
    "filters": {
      "protocolCategory": [{"value": "DEX"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }' | jq '.findings[] | {title, tags: [.issues_issuetagscore[]?.tags_tag.title]}'
```

## Cross-Reference

- For front-running → See [../vulnerability-tags/front-running.md](../vulnerability-tags/front-running.md)
- For price manipulation → See [../vulnerability-tags/price-manipulation.md](../vulnerability-tags/price-manipulation.md)
- For flash loans → See [../vulnerability-tags/flash-loan.md](../vulnerability-tags/flash-loan.md)
- For DeFi general → See [defi.md](defi.md)
