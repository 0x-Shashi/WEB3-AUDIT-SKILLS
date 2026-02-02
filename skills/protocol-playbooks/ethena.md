---
id: PLAYBOOK-ETHENA
title: Ethena Integration Playbook
category: protocol-playbooks
protocol: ethena
version: v2
difficulty: advanced
tags: [ethena, usde, susde, stablecoin, delta-neutral, yield]
last_updated: 2026-01-31
---

# Ethena Integration Playbook

> **Attack Surface:** See [attack-trees/stablecoin-attack-tree.md](../attack-trees/stablecoin-attack-tree.md)

## Protocol Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      ETHENA PROTOCOL                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐     │
│  │   Deposit   │      │   USDe      │      │   sUSDe     │     │
│  │  stETH/ETH  │ ───▶ │ (Stablecoin)│ ───▶ │ (Staking)   │     │
│  └─────────────┘      └──────┬──────┘      └─────────────┘     │
│                              │                                  │
│         ┌────────────────────┼────────────────────┐            │
│         ▼                    ▼                    ▼            │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐     │
│  │   stETH     │      │  Short Perp │      │  Funding    │     │
│  │   Collateral│      │  Position   │      │  Revenue    │     │
│  │   (Long)    │      │  (Hedge)    │      │  (Yield)    │     │
│  └─────────────┘      └─────────────┘      └─────────────┘     │
│         │                    │                    │            │
│         └────────────────────┼────────────────────┘            │
│                              ▼                                  │
│                    DELTA NEUTRAL = $1                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Concepts

### 1. Delta-Neutral Strategy

```solidity
// USDe is backed by:
// 1. Long stETH (or other LSTs) - earns staking yield
// 2. Short ETH perp position - earns funding (usually positive)

// Example:
// Deposit: 1 stETH (~$2000)
// Hedge: Short 1 ETH perp
// Result: ~$2000 USDe, delta-neutral to ETH price

// If ETH goes up:
//   stETH gains value (+)
//   Short perp loses value (-)
//   Net = 0 (still $2000)

// If ETH goes down:
//   stETH loses value (-)
//   Short perp gains value (+)
//   Net = 0 (still $2000)
```

### 2. Yield Sources

```
sUSDe Yield Components:
├── Staking Yield (~3-5% APY)
│   └── stETH/rETH native staking rewards
├── Funding Rate Yield (Variable, ~10-30% APY in bull markets)
│   └── Shorts receive funding when rate is positive
└── Basis Spread (Small)
    └── Spot vs perp price differences
```

### 3. Key Contracts

| Contract | Address (Ethereum) | Purpose |
|----------|-------------------|---------|
| USDe | `0x4c9EDD5852cd905f086C759E8383e09bff1E68B3` | Stablecoin token |
| sUSDe | `0x9D39A5DE30e57443BfF2A8307A4256c8797A3497` | Staking token |
| StakedUSDeV2 | `0x9D39A5DE30e57443BfF2A8307A4256c8797A3497` | Staking vault |
| Minting | Various | Mint/redeem USDe |

---

## Integration Patterns

### Staking USDe for sUSDe

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IStakedUSDe {
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
    function convertToShares(uint256 assets) external view returns (uint256);
    function convertToAssets(uint256 shares) external view returns (uint256);
    function cooldownDuration() external view returns (uint24);
    function cooldownAssets(address owner) external view returns (uint256);
    function cooldowns(address owner) external view returns (uint104 cooldownEnd, uint152 underlyingAmount);
    function unstake(address receiver) external;
}

contract EthenaIntegration {
    IERC20 public constant USDe = IERC20(0x4c9EDD5852cd905f086C759E8383e09bff1E68B3);
    IStakedUSDe public constant sUSDe = IStakedUSDe(0x9D39A5DE30e57443BfF2A8307A4256c8797A3497);
    
    // Stake USDe to get sUSDe (yield-bearing)
    function stake(uint256 amount) external returns (uint256 shares) {
        USDe.transferFrom(msg.sender, address(this), amount);
        USDe.approve(address(sUSDe), amount);
        
        shares = sUSDe.deposit(amount, msg.sender);
    }
    
    // Initiate unstaking (starts cooldown)
    function initiateUnstake(uint256 shares) external {
        // Transfer sUSDe from user
        IERC20(address(sUSDe)).transferFrom(msg.sender, address(this), shares);
        
        // This starts the cooldown period
        sUSDe.redeem(shares, address(this), address(this));
    }
    
    // Complete unstaking after cooldown
    function completeUnstake() external {
        (uint104 cooldownEnd,) = sUSDe.cooldowns(address(this));
        require(block.timestamp >= cooldownEnd, "Cooldown not complete");
        
        sUSDe.unstake(msg.sender);
    }
}
```

### Checking Yield/Exchange Rate

```solidity
// sUSDe is a rebasing vault token (ERC4626-like)
// Exchange rate increases as yield accrues

function getExchangeRate() external view returns (uint256) {
    // 1 sUSDe = X USDe (increases over time)
    return sUSDe.convertToAssets(1e18);
}

function getCurrentAPY() external view returns (uint256) {
    // APY is variable based on:
    // 1. stETH staking yield
    // 2. Funding rate on perp positions
    // 3. Current leverage of the protocol
    
    // Ethena publishes this off-chain
    // On-chain, you can track rate of exchange rate growth
}
```

---

## Security Considerations

### 1. Negative Funding Rate Risk

```solidity
// CRITICAL: Funding rates can go negative in bear markets
// When negative, shorts PAY longs

// Risk scenario:
// - Market dumps, everyone wants to short
// - Funding goes deeply negative (-100% APY annualized)
// - Ethena's short positions lose money
// - USDe backing decreases

// Mitigations:
// 1. Insurance fund to cover negative periods
// 2. Reserve fund from positive funding periods
// 3. Diversification across venues
```

### 2. Custodial/CEX Risk

```solidity
// Ethena holds perp positions on CEXs via custodians
// "Off-exchange settlement" - collateral held separately

// Risks:
// - Custodian compromise (Copper, Ceffu, Fireblocks)
// - CEX insolvency (positions stuck)
// - Oracle manipulation on CEXs

// Audit checks:
// [ ] Custodian security audited?
// [ ] Multi-sig/MPC for custodian access?
// [ ] Real-time proof of reserves?
// [ ] Insurance coverage?
```

### 3. De-peg Scenarios

```solidity
// USDe can de-peg if:
// 1. Negative funding exceeds reserves
// 2. stETH de-pegs significantly  
// 3. Mass redemptions exceed liquidity
// 4. Custodian/CEX failure

// Check redemption mechanics:
// - Is instant redemption available?
// - What's the redemption queue?
// - Are there redemption fees during stress?
```

### 4. Cooldown Period Risks

```solidity
// sUSDe has a cooldown period (typically 7-14 days)

// Risk: Can't exit during crisis
function getCooldownDuration() external view returns (uint256) {
    return sUSDe.cooldownDuration(); // Returns duration in seconds
}

// Integration must account for this:
// - Don't stake funds needed for liquidity
// - Consider sUSDe as "locked" capital
// - Monitor governance for cooldown changes
```

---

## Common Vulnerabilities

### 1. Exchange Rate Manipulation

```solidity
// sUSDe uses an exchange rate that increases with yield
// Similar to ERC4626 inflation attacks

// VULNERABLE: First depositor can inflate rate
function deposit(uint256 assets) external {
    uint256 shares = convertToShares(assets);
    // If totalShares == 0, attacker can manipulate
}

// Ethena mitigation: Bootstrap with initial deposit
// Always verify: shares > 0 on deployment
```

### 2. Stale Oracle Prices

```solidity
// Ethena uses oracles for collateral valuation

// Check:
// - Oracle freshness requirements
// - Deviation thresholds
// - Fallback mechanisms

// Attack: Stale price allows minting more USDe than collateral value
```

### 3. Flash Loan Arbitrage

```solidity
// If USDe de-pegs, arbitrageurs can:
// 1. Flash loan
// 2. Buy cheap USDe
// 3. Redeem for collateral
// 4. Profit

// This is INTENDED behavior (keeps peg)
// But integrators must be aware of price volatility
```

### 4. Reentrancy in Staking

```solidity
// ALWAYS check for reentrancy when integrating

// Safe pattern
function stake(uint256 amount) external nonReentrant {
    // State changes before external calls
    balances[msg.sender] += amount;
    
    // External calls last
    USDe.transferFrom(msg.sender, address(this), amount);
    sUSDe.deposit(amount, msg.sender);
}
```

---

## Risk Parameters

| Parameter | Value | Risk Level |
|-----------|-------|------------|
| Cooldown Period | 7-14 days | Medium |
| Negative Funding Threshold | -10% APY | High |
| stETH Collateral Ratio | ~50% | Medium |
| CEX Concentration | ~40% Binance | High |
| Insurance Fund | $50M+ | Medium |

---

## Audit Checklist

### Token Security
```
[ ] USDe is standard ERC20, no fee-on-transfer?
[ ] sUSDe exchange rate monotonically increases?
[ ] No inflation attack vector on sUSDe?
[ ] Cooldown properly enforced?
[ ] Blacklist functionality reviewed?
```

### Yield Mechanism
```
[ ] Yield calculation is transparent?
[ ] Negative yield periods handled?
[ ] Yield distribution is fair (no front-running)?
[ ] Reserve fund is sufficient?
```

### Integration Safety
```
[ ] Cooldown period factored into design?
[ ] Slippage protection on conversions?
[ ] Emergency unstake mechanism?
[ ] Oracle dependencies documented?
```

### Custodial Risks
```
[ ] Custodian audit reports reviewed?
[ ] Proof of reserves mechanism?
[ ] Insurance coverage verified?
[ ] CEX diversification adequate?
```

---

## Quick Reference

| Metric | Value |
|--------|-------|
| Base APY (staking) | ~3-5% |
| Funding APY (variable) | 0-30%+ |
| Cooldown Period | 7-14 days |
| Min Mint Amount | 100 USDe |
| Redemption Fee | 0-0.1% |
| Collateral Types | stETH, WETH, USDT |

---

## Code Examples

### Safe Integration Pattern

```solidity
contract SafeEthenaVault {
    IERC20 public USDe;
    IStakedUSDe public sUSDe;
    
    mapping(address => uint256) public cooldownEndTime;
    mapping(address => uint256) public pendingWithdrawals;
    
    function depositUSDe(uint256 amount) external {
        require(amount >= 100e18, "Min 100 USDe");
        
        USDe.transferFrom(msg.sender, address(this), amount);
        USDe.approve(address(sUSDe), amount);
        
        uint256 sharesBefore = IERC20(address(sUSDe)).balanceOf(address(this));
        sUSDe.deposit(amount, address(this));
        uint256 sharesReceived = IERC20(address(sUSDe)).balanceOf(address(this)) - sharesBefore;
        
        // Track user's share
        userShares[msg.sender] += sharesReceived;
    }
    
    function initiateWithdraw(uint256 shares) external {
        require(userShares[msg.sender] >= shares, "Insufficient shares");
        
        userShares[msg.sender] -= shares;
        
        // Redeem starts cooldown
        uint256 assets = sUSDe.redeem(shares, address(this), address(this));
        
        pendingWithdrawals[msg.sender] += assets;
        cooldownEndTime[msg.sender] = block.timestamp + sUSDe.cooldownDuration();
    }
    
    function completeWithdraw() external {
        require(block.timestamp >= cooldownEndTime[msg.sender], "Cooldown active");
        require(pendingWithdrawals[msg.sender] > 0, "Nothing to withdraw");
        
        uint256 amount = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;
        
        sUSDe.unstake(msg.sender);
    }
    
    mapping(address => uint256) public userShares;
}
```

---

## Related Resources

- [Ethena Docs](https://ethena-labs.gitbook.io/ethena-labs)
- [sUSDe Contract](https://etherscan.io/address/0x9D39A5DE30e57443BfF2A8307A4256c8797A3497)
- [Risk Dashboard](https://app.ethena.fi/dashboards/risk)
- [Proof of Reserves](https://ethena.fi/transparency)
