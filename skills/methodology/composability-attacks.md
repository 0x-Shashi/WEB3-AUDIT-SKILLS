---
id: METHOD-COMPOSABILITY
title: Protocol Composability Attack Patterns
category: methodology
difficulty: expert
triggers: [composability risk, cross-protocol attack, flash loan composability, token hook attack, donation attack, JIT liquidity]
related_skills: [methodology/economic-attack-modeling.md, patterns/flash-loan-patterns.md, patterns/oracle-patterns.md]
tags: [composability, flash-loan, oracle, cross-protocol, defi]
last_updated: 2026-01-31
---

# Protocol Composability Attack Patterns

## Overview

DeFi's "money legos" architecture creates emergent attack surfaces when protocols interact. Individual protocols may be secure in isolation but vulnerable when composed. This guide covers cross-protocol attack patterns.

---

## 1. Composability Risk Model

### 1.1 The Composability Stack

```
┌─────────────────────────────────────────────┐
│  Application Layer (Aggregators, Vaults)    │
├─────────────────────────────────────────────┤
│  Protocol Layer (Lending, DEX, Perps)       │
├─────────────────────────────────────────────┤
│  Token Layer (ERC20, ERC721, Rebasing)      │
├─────────────────────────────────────────────┤
│  Oracle Layer (Chainlink, TWAP, Spot)       │
├─────────────────────────────────────────────┤
│  Liquidity Layer (AMMs, Order Books)        │
└─────────────────────────────────────────────┘

Each layer trusts the layers below.
Vulnerabilities can cascade UP the stack.
```

### 1.2 Trust Relationship Matrix

```solidity
// Protocol A (Lending)
interface IProtocolA {
    function deposit(address token, uint256 amount) external;
    function borrow(address token, uint256 amount) external;
    function getCollateralValue(address user) external view returns (uint256);
}

// Protocol B (Yield Aggregator)
interface IProtocolB {
    function depositUnderlying(uint256 amount) external;
    function getSharePrice() external view returns (uint256);  // Used as collateral price!
}

// Trust Chain:
// User → Protocol A → Protocol B → Underlying AMM → Oracle
// Compromise ANY link = potential exploit
```

---

## 2. Flash Loan Composability Attacks

### 2.1 Oracle Price Manipulation

```solidity
// ATTACK: Use flash loan to manipulate price, exploit lending protocol

interface IFlashLender {
    function flashLoan(uint256 amount, bytes calldata data) external;
}

contract OracleManipulationAttack {
    IFlashLender flashLender;
    ILendingProtocol lender;  // Uses AMM for price
    IAMM amm;
    
    function attack() external {
        // 1. Flash loan large amount
        flashLender.flashLoan(10_000_000e18, "");
    }
    
    function onFlashLoan(uint256 amount) external {
        // 2. Swap to manipulate AMM price
        amm.swap(tokenA, tokenB, amount);
        // Price of tokenA is now artificially low
        
        // 3. Deposit cheap tokenA as collateral
        // Lending protocol uses AMM spot price
        lender.deposit(tokenA, manipulatedAmount);
        
        // 4. Borrow against inflated collateral value
        lender.borrow(tokenB, maxBorrow);
        
        // 5. Swap back to restore price
        amm.swap(tokenB, tokenA, amount);
        
        // 6. Repay flash loan
        // Keep profit from overborrowing
    }
}
```

### 2.2 Liquidity Amplification Attack

```solidity
// ATTACK: Use one protocol's liquidity to attack another

contract LiquidityAmplification {
    function attack() external {
        // 1. Flash loan from Protocol A
        protocolA.flashLoan(amount);
    }
    
    function onFlashLoan(uint256 amount) external {
        // 2. Deposit to Protocol B, get receipt tokens
        protocolB.deposit(amount);
        bTokens = protocolB.balanceOf(address(this));
        
        // 3. Use receipt tokens as collateral in Protocol C
        protocolC.depositCollateral(bTokens);
        
        // 4. Borrow from Protocol C
        protocolC.borrow(amount * 0.8);  // 80% LTV
        
        // 5. Repeat cycle (leverage loop)
        // Each iteration amplifies exposure
        
        // 6. Execute attack with amplified position
        // Manipulate price, force liquidations, etc.
        
        // 7. Unwind and repay flash loan
    }
}
```

### 2.3 Reentrancy via External Protocol

```solidity
// ATTACK: Reenter through external protocol callback

contract CrossProtocolReentrancy {
    function attack() external {
        // 1. Start normal operation
        protocolA.withdraw(amount);
    }
    
    // Protocol A uses Protocol B for some operation
    // Protocol B has callback mechanism
    
    function protocolBCallback() external {
        // 2. This is called during Protocol A's withdraw
        // Protocol A's state is inconsistent
        
        // 3. Call back into Protocol A
        protocolA.withdraw(amount);  // Reentrancy!
    }
}
```

---

## 3. Token Standard Composability Issues

### 3.1 Rebasing Token Attacks

```solidity
// VULNERABLE: Protocol doesn't account for rebasing

contract VulnerableVault {
    mapping(address => uint256) public deposits;
    
    function deposit(uint256 amount) external {
        rebasingToken.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;  // Records nominal amount
    }
    
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount);
        deposits[msg.sender] -= amount;
        rebasingToken.transfer(msg.sender, amount);
        // After negative rebase, vault doesn't have enough tokens!
    }
}

// ATTACK:
// 1. Deposit 100 tokens (records 100)
// 2. Wait for negative rebase (vault now has 90 tokens total)
// 3. Another user deposited 100, now has claim to 100
// 4. First user withdraws 100, second user can only get 80
```

### 3.2 Fee-on-Transfer Token Attacks

```solidity
// VULNERABLE: Assumes received == sent
contract VulnerableSwap {
    function swap(address tokenIn, uint256 amountIn) external {
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        
        // Assumes we received amountIn
        uint256 amountOut = calculateOutput(amountIn);  // WRONG!
        
        // Actually received amountIn - fee
        // User gets more output than deserved
    }
}

// SAFE: Check actual received
contract SafeSwap {
    function swap(address tokenIn, uint256 amountIn) external {
        uint256 balanceBefore = IERC20(tokenIn).balanceOf(address(this));
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        uint256 actualReceived = IERC20(tokenIn).balanceOf(address(this)) - balanceBefore;
        
        uint256 amountOut = calculateOutput(actualReceived);  // Correct
    }
}
```

### 3.3 ERC777 Callback Attacks

```solidity
// ERC777 tokens have send/receive hooks
// Can be used for reentrancy even without ETH

contract VulnerableMarket {
    function buy(uint256 amount) external {
        uint256 price = getPrice(amount);
        
        // ERC777 tokensReceived hook triggers HERE
        paymentToken.transferFrom(msg.sender, address(this), price);
        
        // State updated AFTER callback
        inventory[msg.sender] += amount;
    }
}

// ATTACK via ERC777 callback
contract ERC777Attacker is IERC777Recipient {
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata data,
        bytes calldata operatorData
    ) external {
        // Callback during transferFrom
        // Market state not yet updated
        
        if (attackCount < 5) {
            attackCount++;
            market.buy(amount);  // Reenter!
        }
    }
}
```

---

## 4. Oracle Composability Attacks

### 4.1 Multi-Oracle Arbitrage

```solidity
// Protocol A uses Oracle X
// Protocol B uses Oracle Y
// Oracles can have different prices

contract OracleArbitrage {
    function attack() external {
        // Get prices from both oracles
        uint256 priceX = oracleX.getPrice(token);  // $100
        uint256 priceY = oracleY.getPrice(token);  // $105
        
        // Protocol A thinks token worth $100
        // Protocol B thinks token worth $105
        
        // 1. Borrow token from Protocol A at $100 valuation
        protocolA.depositCollateral(usdc, 100);
        protocolA.borrow(token, 1);  // Worth $100 collateral
        
        // 2. Use as collateral in Protocol B at $105 valuation
        protocolB.deposit(token, 1);  // Worth $105
        protocolB.borrow(usdc, 84);  // 80% of $105
        
        // 3. Profit: Started with $100 USDC, now have $184 USDC exposure
        // Repeat for leverage
    }
}
```

### 4.2 Delayed Oracle Exploitation

```solidity
// VULNERABLE: Protocol uses oracle that updates slowly

contract DelayedOracleExploit {
    function attack() external {
        // 1. Real market price crashes 20% (e.g., $100 → $80)
        
        // 2. Protocol's oracle still shows $100 (update delay)
        uint256 oraclePrice = protocol.getPrice(token);  // Still $100
        
        // 3. Buy token on DEX at $80
        dex.swap(usdc, token, marketRate);
        
        // 4. Deposit to protocol at $100 valuation
        protocol.deposit(token, amount);  // Valued at $100
        
        // 5. Borrow against inflated collateral
        protocol.borrow(usdc, amount * 0.8);  // 80% of $100
        
        // 6. When oracle updates, position underwater
        // Protocol takes the loss
    }
}
```

### 4.3 Cross-Chain Oracle Manipulation

```solidity
// Oracles on different chains may not be synchronized
// Arbitrage between chains during price divergence

contract CrossChainOracleAttack {
    function attackOnChainA() external {
        // Price on Chain A oracle: $100
        // Real price (Chain B): $80
        
        // Exploit the stale Chain A price
        protocolOnChainA.borrow(inflatedAmount);
        
        // Bridge to Chain B
        bridge.send(amount);
    }
    
    function receiveOnChainB(uint256 amount) external {
        // Repay at actual price on Chain B
        protocolOnChainB.repay(amount);
        
        // Keep difference as profit
    }
}
```

---

## 5. Liquidity-Based Attacks

### 5.1 Withdrawal Race Condition

```solidity
// Multiple protocols share same liquidity source
// Mass withdrawal from one affects others

contract LiquidityCrisis {
    // Protocol A and B both rely on same AMM for liquidity
    
    function triggerCrisis() external {
        // 1. Large flash loan
        flashLoan.borrow(hugeAmount);
        
        // 2. Drain AMM liquidity
        amm.removeLiquidity(maxAmount);
        
        // 3. Protocol A users can't withdraw (no liquidity)
        // 4. Protocol B liquidations fail (can't sell collateral)
        
        // 5. Create bad debt or DoS
    }
}
```

### 5.2 Liquidity Fragmentation Attack

```solidity
// Split liquidity across pools to maximize slippage

contract FragmentationAttack {
    function attack() external {
        // Target protocol uses AMM for pricing
        
        // 1. Provide liquidity to multiple small pools
        pool1.addLiquidity(small);
        pool2.addLiquidity(small);
        pool3.addLiquidity(small);
        
        // 2. Remove from main pool
        mainPool.removeLiquidity(large);
        
        // 3. Protocol now routes through fragmented pools
        // Higher slippage = worse prices for users
        // Attacker captures MEV
    }
}
```

### 5.3 JIT Liquidity Attack

```solidity
// Just-In-Time liquidity manipulation

contract JITAttack {
    // Frontrun: Add liquidity right before large swap
    // Capture fees from the swap
    // Backrun: Remove liquidity immediately after
    
    function frontrun(SwapParams memory params) external {
        // Detected large swap in mempool
        amm.addLiquidity(amount, range);  // Concentrated liquidity
    }
    
    function backrun() external {
        // Swap executed, fees captured
        amm.removeLiquidity(lpTokens);
        // Profit = swap fees - gas
    }
}
```

---

## 6. Yield Aggregator Attack Vectors

### 6.1 Strategy Manipulation

```solidity
// VULNERABLE: Aggregator trusts strategy reports

contract VulnerableAggregator {
    mapping(address => Strategy) public strategies;
    
    function deposit(uint256 amount) external {
        // Calculate shares based on strategy's reported value
        uint256 totalValue = strategy.totalValue();  // Can be manipulated!
        uint256 shares = amount * totalSupply / totalValue;
        
        _mint(msg.sender, shares);
    }
}

// ATTACK:
// 1. Strategy reports inflated totalValue
// 2. New depositors get fewer shares
// 3. Attacker's existing shares worth more
```

### 6.2 Harvest Front-Running

```solidity
// Aggregator auto-compounds yield
// Attacker front-runs harvest

contract HarvestFrontrun {
    function attack(address aggregator) external {
        // 1. Watch for pending harvest transaction
        
        // 2. Front-run: Deposit large amount
        uint256 sharesBefore = aggregator.totalSupply();
        aggregator.deposit(largeAmount);
        
        // 3. Harvest executes, yield distributed to all shares
        // Attacker's new shares get portion of yield
        
        // 4. Back-run: Withdraw immediately
        aggregator.withdraw(myShares);
        
        // Profit: portion of yield with minimal time exposure
    }
}
```

### 6.3 Donation Attack on Share Price

```solidity
// VULNERABLE: Share price based on balance
contract VulnerableVault {
    function pricePerShare() public view returns (uint256) {
        if (totalSupply == 0) return 1e18;
        return totalAssets() * 1e18 / totalSupply;
    }
    
    function totalAssets() public view returns (uint256) {
        return underlying.balanceOf(address(this));  // Donation affects this!
    }
}

// ATTACK:
// 1. Be first depositor, get 1 share for 1 wei
// 2. Donate large amount directly to vault
// 3. pricePerShare is now huge
// 4. Next depositor's amount rounds down to 0 shares
// 5. Attacker withdraws donated amount + victim's deposit
```

---

## 7. Cross-Protocol Liquidation Cascades

### 7.1 Cascade Trigger Attack

```solidity
contract CascadeAttack {
    function triggerCascade() external {
        // 1. Identify interconnected positions
        // User A has collateral in Protocol X
        // Protocol X deposits to Protocol Y
        // Protocol Y uses Oracle Z
        
        // 2. Manipulate Oracle Z (flash loan, large trade)
        flashLoan.borrow(amount);
        dex.swap(largeAmount);  // Move price
        
        // 3. Protocol Y liquidates Protocol X's position
        protocolY.liquidate(protocolXAddress);
        
        // 4. Protocol X now has less collateral
        // Triggers liquidation of User A
        protocolX.liquidate(userA);
        
        // 5. User A's liquidation affects User B, etc.
        // Cascade of liquidations
        
        // 6. Restore price, repay flash loan
        // Profit from liquidation bonuses
    }
}
```

### 7.2 Liquidation Blocker

```solidity
// ATTACK: Prevent liquidations to create bad debt

contract LiquidationBlocker {
    // Make liquidation economically infeasible
    
    function blockLiquidation() external {
        // 1. Borrow from protocol
        protocol.borrow(amount);
        
        // 2. Create complex position that's expensive to liquidate
        // - Use tokens with callback hooks
        // - Spread collateral across many assets
        // - Use rebasing tokens
        
        // 3. When underwater, liquidators can't profitably liquidate
        // - Gas cost > liquidation bonus
        // - Price impact makes it unprofitable
        
        // 4. Protocol accumulates bad debt
    }
}
```

---

## 8. Composability Audit Checklist

### 8.1 External Protocol Integration

```markdown
□ Map all external protocol dependencies
□ Identify trust assumptions for each
□ Test with manipulated external state
□ Verify behavior if external protocol pauses
□ Check oracle source for each external protocol
□ Assess liquidation cascade risk
```

### 8.2 Token Compatibility

```markdown
□ List all supported token types
□ Test with rebasing tokens
□ Test with fee-on-transfer tokens
□ Test with ERC777 tokens (hooks)
□ Test with tokens that return false
□ Test with tokens that don't return value
□ Test with extremely high/low decimals
```

### 8.3 Flash Loan Resistance

```markdown
□ All price sources resistant to flash manipulation
□ TWAP windows appropriate for asset volatility
□ No single-block arbitrage opportunities
□ State changes atomic (no intermediate states)
□ Reentrancy protection on all external calls
```

### 8.4 Liquidity Assumptions

```markdown
□ Protocol functions if external liquidity removed
□ Liquidations work with reduced liquidity
□ No assumptions about minimum AMM liquidity
□ Slippage protection on all swaps
□ Circuit breakers for extreme conditions
```

---

## 9. Defense Patterns

### 9.1 Time-Weighted Operations

```solidity
// Resist single-block manipulation
contract TimeWeightedProtocol {
    mapping(address => uint256) public lastActionTime;
    uint256 public constant MIN_DELAY = 1 hours;
    
    function sensitiveAction() external {
        require(
            block.timestamp >= lastActionTime[msg.sender] + MIN_DELAY,
            "Too soon"
        );
        lastActionTime[msg.sender] = block.timestamp;
        // Execute action
    }
}
```

### 9.2 Multi-Oracle Validation

```solidity
contract MultiOracleProtocol {
    function getPrice(address token) public view returns (uint256) {
        uint256 chainlinkPrice = chainlinkOracle.getPrice(token);
        uint256 twapPrice = uniswapTwap.getPrice(token);
        
        // Require both within tolerance
        uint256 deviation = abs(chainlinkPrice - twapPrice) * 10000 / chainlinkPrice;
        require(deviation < MAX_DEVIATION, "Oracle deviation");
        
        return (chainlinkPrice + twapPrice) / 2;
    }
}
```

### 9.3 Deposit Delay

```solidity
// Prevent flash loan deposit attacks
contract DelayedDeposit {
    struct Deposit {
        uint256 amount;
        uint256 timestamp;
    }
    
    mapping(address => Deposit) public pendingDeposits;
    uint256 public constant DEPOSIT_DELAY = 1 hours;
    
    function initiateDeposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        pendingDeposits[msg.sender] = Deposit(amount, block.timestamp);
    }
    
    function finalizeDeposit() external {
        Deposit memory d = pendingDeposits[msg.sender];
        require(block.timestamp >= d.timestamp + DEPOSIT_DELAY, "Pending");
        
        delete pendingDeposits[msg.sender];
        _deposit(msg.sender, d.amount);
    }
}
```

---

## 10. Real-World Composability Exploits

| Exploit | Amount | Composability Vector |
|---------|--------|---------------------|
| Cream Finance | $130M | Flash loan → yVault price manipulation → Lending |
| Harvest Finance | $34M | Flash loan → Curve pool manipulation → Vault |
| Yearn yDAI | $11M | Flash loan → Aave → Curve → yVault |
| Alpha Homora | $37M | Flash loan → Ironbank → Lending amplification |
| Rari Fuse | $80M | Reentrancy through external protocol callback |

---

## Summary

| Attack Category | Key Defense |
|----------------|-------------|
| Flash Loan Manipulation | TWAP oracles, multi-block operations |
| Token Standard Issues | Explicit token type handling |
| Oracle Composability | Multi-oracle validation |
| Liquidity Attacks | Slippage limits, circuit breakers |
| Liquidation Cascades | Position limits, cascade simulation |
| Yield Aggregation | Donation protection, delayed deposits |

**Golden Rule**: When auditing a protocol, you're auditing its entire dependency graph. Map every external interaction and assume each can be manipulated.
