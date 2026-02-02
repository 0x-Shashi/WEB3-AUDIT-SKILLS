---
id: PLAYBOOK-FLUID
title: Fluid (Instadapp) Integration Playbook
category: protocol-playbooks
protocol: fluid
version: v1
difficulty: advanced
tags: [fluid, instadapp, lending, dex, liquidity, defi]
last_updated: 2026-01-31
---

# Fluid (Instadapp) Integration Playbook

> **Attack Surface:** See [attack-trees/lending-attack-tree.md](../attack-trees/lending-attack-tree.md) | [attack-trees/dex-attack-tree.md](../attack-trees/dex-attack-tree.md)

## Protocol Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                       FLUID PROTOCOL                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    LIQUIDITY LAYER                       │   │
│  │         (Unified Liquidity for Lending + DEX)           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                    │                    │                       │
│         ┌─────────▼─────────┐ ┌────────▼────────┐              │
│         │   Fluid Lending   │ │   Fluid DEX     │              │
│         │   (fTokens)       │ │  (AMM + Range)  │              │
│         └─────────┬─────────┘ └────────┬────────┘              │
│                   │                    │                        │
│         ┌─────────▼─────────┐ ┌────────▼────────┐              │
│         │    Borrowers      │ │   Liquidity     │              │
│         │    (Vaults)       │ │   Providers     │              │
│         └───────────────────┘ └─────────────────┘              │
│                                                                 │
│  Key Innovation: Borrowed funds earn DEX fees!                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Concepts

### 1. Liquidity Layer

```solidity
// Fluid's core innovation: unified liquidity
// Deposited assets serve BOTH lending and DEX

// Traditional:
// Aave deposit → Only earns lending APY
// Uniswap LP → Only earns swap fees

// Fluid:
// Fluid deposit → Earns lending APY + swap fees
// Higher capital efficiency
```

### 2. Smart Collateral & Debt

```solidity
// Borrowers can use their DEBT as DEX liquidity
// "Smart Debt" - borrowed funds earn trading fees

Example:
1. Deposit ETH as collateral
2. Borrow USDC (creates debt)
3. Debt USDC is used in DEX liquidity
4. Earn swap fees on your borrowed amount
5. Fees offset borrow interest

// Net cost = Borrow Rate - Swap Fee Yield
```

### 3. Key Contracts

| Contract | Purpose |
|----------|---------|
| Liquidity | Core liquidity layer |
| VaultFactory | Creates lending vaults |
| VaultT1 | Basic collateral vault |
| VaultT2 | Smart collateral vault |
| FluidDex | DEX with range orders |
| fToken | Interest-bearing tokens |

---

## Integration Patterns

### Supplying Liquidity

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFluidLiquidity {
    function operate(
        address token,
        int256 supplyAmount,
        int256 borrowAmount,
        address withdrawTo,
        address borrowTo,
        bytes calldata data
    ) external payable returns (uint256 memVar);
}

interface IFToken {
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
}

contract FluidIntegration {
    IFluidLiquidity public liquidity;
    IFToken public fUSDC;
    IERC20 public USDC;
    
    // Supply USDC, receive fUSDC (yield-bearing)
    function supply(uint256 amount) external returns (uint256 shares) {
        USDC.transferFrom(msg.sender, address(this), amount);
        USDC.approve(address(fUSDC), amount);
        
        shares = fUSDC.deposit(amount, msg.sender);
    }
    
    // Withdraw USDC by redeeming fUSDC
    function withdraw(uint256 shares) external returns (uint256 assets) {
        // fUSDC transferFrom would be needed if user holds directly
        assets = fUSDC.redeem(shares, msg.sender, msg.sender);
    }
}
```

### Opening a Vault (Borrow Position)

```solidity
interface IFluidVault {
    function operate(
        uint256 nftId,      // 0 for new position
        int256 colAmount,   // Positive = deposit, negative = withdraw
        int256 debtAmount,  // Positive = borrow, negative = repay
        address to          // Recipient of borrowed tokens
    ) external returns (uint256 nftId_, int256 newCol_, int256 newDebt_);
}

contract VaultIntegration {
    IFluidVault public vault;
    IERC20 public collateralToken;
    IERC20 public debtToken;
    
    // Open new position: deposit collateral, borrow debt
    function openPosition(
        uint256 collateralAmount,
        uint256 borrowAmount
    ) external returns (uint256 nftId) {
        collateralToken.transferFrom(msg.sender, address(this), collateralAmount);
        collateralToken.approve(address(vault), collateralAmount);
        
        (nftId,,) = vault.operate(
            0,                          // 0 = new position
            int256(collateralAmount),   // Deposit collateral
            int256(borrowAmount),       // Borrow debt
            msg.sender                  // Send borrowed tokens to user
        );
        
        // NFT representing position is minted to this contract
        // Transfer to user or track internally
    }
    
    // Add collateral to existing position
    function addCollateral(uint256 nftId, uint256 amount) external {
        collateralToken.transferFrom(msg.sender, address(this), amount);
        collateralToken.approve(address(vault), amount);
        
        vault.operate(
            nftId,
            int256(amount),  // Deposit more collateral
            0,               // No debt change
            address(0)
        );
    }
    
    // Repay debt
    function repayDebt(uint256 nftId, uint256 amount) external {
        debtToken.transferFrom(msg.sender, address(this), amount);
        debtToken.approve(address(vault), amount);
        
        vault.operate(
            nftId,
            0,                       // No collateral change
            -int256(amount),         // Repay debt (negative)
            address(0)
        );
    }
}
```

### Smart Collateral/Debt (DEX Integration)

```solidity
// Smart vaults automatically deploy collateral/debt as DEX liquidity

interface IFluidVaultT2 {
    // T2 vaults have DEX integration built-in
    function operate(
        uint256 nftId,
        int256 colAmount,
        int256 debtAmount,
        int256 colSharesMinMax,  // Slippage protection
        int256 debtSharesMinMax, // Slippage protection
        address to
    ) external returns (
        uint256 nftId_,
        int256 supplyAmt_,
        int256 borrowAmt_
    );
}

// When using T2 vaults:
// - Collateral earns DEX fees automatically
// - Debt earns DEX fees automatically  
// - Net APY = Supply APY + DEX fees - Borrow APY + DEX fees
```

---

## Security Considerations

### 1. Liquidation Mechanics

```solidity
// Fluid uses a liquidation engine similar to other lending protocols
// But with added complexity due to DEX integration

// Liquidation threshold varies by vault type
// Check: Is liquidation penalty fair?
// Check: Is there liquidation delay for DEX unwinding?

interface IFluidVaultLiquidate {
    function liquidate(
        uint256 nftId,
        uint256 debtAmt,
        uint256 colPerUnitDebt,  // Expected collateral per debt unit
        address to,
        bool absorb              // Send to protocol vs liquidator
    ) external returns (uint256 actualCol, uint256 actualDebt);
}

// Audit checks:
// [ ] Can liquidators extract more value than allowed?
// [ ] Is oracle price used for liquidation fresh?
// [ ] DEX positions unwound at fair price?
```

### 2. Oracle Dependencies

```solidity
// Fluid uses multiple oracle sources
// Critical for: collateral valuation, liquidation, DEX pricing

// Check oracle setup:
// - Primary oracle (Chainlink?)
// - Fallback oracle
// - Staleness checks
// - Deviation bounds

// Specific risk: DEX TWAP manipulation
// If attacker manipulates DEX prices, can they:
// - Avoid liquidation?
// - Borrow more than collateral value?
// - Liquidate healthy positions?
```

### 3. DEX Integration Risks

```solidity
// Smart collateral/debt creates new attack surfaces

// Risk 1: Impermanent loss on collateral
// Collateral value can decrease due to IL
// Liquidation threshold must account for this

// Risk 2: MEV on DEX operations
// When vault operations touch DEX:
// - Front-running deposit/withdrawals
// - Sandwich attacks on rebalances

// Risk 3: DEX liquidity manipulation
// Attacker drains liquidity → affects vault health
```

### 4. Reentrancy Risks

```solidity
// Multiple external calls in operate()

// Vulnerable pattern:
function operate(...) external {
    // 1. Calculate amounts
    // 2. Transfer collateral IN
    // 3. Transfer debt OUT ← Reentrancy point
    // 4. Update state
}

// Safe pattern (CEI):
function operate(...) external nonReentrant {
    // 1. Validate inputs
    // 2. Update state FIRST
    // 3. External calls LAST
}

// Verify Fluid implements proper reentrancy guards
```

---

## Common Vulnerabilities

### 1. Share Inflation Attack

```solidity
// fTokens use share-based accounting (like ERC4626)
// First depositor attack possible

// Attack:
// 1. Deposit 1 wei, get 1 share
// 2. Donate large amount directly to contract
// 3. Exchange rate inflated
// 4. Next depositor gets 0 shares for reasonable deposit

// Mitigation: Check for virtual shares/assets
```

### 2. Collateral Factor Manipulation

```solidity
// If collateral factor is dynamic or governance-controlled

// Attack:
// 1. Open max leverage position
// 2. Governance lowers collateral factor
// 3. Position instantly liquidatable
// 4. Loss to user, profit to liquidators

// Check: Timelock on parameter changes
```

### 3. Interest Rate Manipulation

```solidity
// Utilization-based interest rates can be gamed

// Attack:
// 1. Flash loan to spike utilization
// 2. Interest rate spikes
// 3. Existing borrowers pay more
// 4. Attacker profits from rate arbitrage

// Mitigation: Time-weighted rates, caps
```

### 4. Cross-Function Reentrancy

```solidity
// With unified liquidity, state is shared

// Dangerous:
// - Supply in lending
// - Callback during transfer
// - Manipulate DEX in callback
// - Return to lending with stale state

// All functions touching shared state must be protected
```

---

## Audit Checklist

### Liquidity Layer
```
[ ] Supply/withdraw accounting correct?
[ ] Interest accrual calculation verified?
[ ] No share inflation attack vector?
[ ] Utilization limits enforced?
```

### Vault Operations
```
[ ] Collateral/debt ratios properly checked?
[ ] Liquidation threshold appropriate?
[ ] NFT ownership properly tracked?
[ ] Reentrancy guards on all entry points?
```

### DEX Integration
```
[ ] DEX operations can't manipulate vault health?
[ ] Slippage protection enforced?
[ ] MEV protection considered?
[ ] Impermanent loss accounted for in liquidations?
```

### Oracle Security
```
[ ] Multiple oracle sources?
[ ] Staleness checks implemented?
[ ] Fallback mechanism exists?
[ ] TWAP vs spot price for what operations?
```

---

## Rate Calculations

```solidity
// Supply APY
supplyAPY = borrowAPY * utilization * (1 - protocolFee)

// Utilization
utilization = totalBorrow / totalSupply

// With DEX integration:
effectiveSupplyAPY = supplyAPY + dexFeeYield
effectiveBorrowAPY = borrowAPY - dexFeeYield  // If debt earns fees

// Example:
// Supply APY: 3%
// DEX Fee Yield: 5%
// Effective Supply APY: 8%
```

---

## Quick Reference

| Parameter | Typical Value |
|-----------|---------------|
| Max LTV | 80-90% |
| Liquidation Threshold | 85-95% |
| Liquidation Penalty | 5-10% |
| Protocol Fee | 10-20% of interest |
| Min Borrow | Varies by asset |

---

## Related Resources

- [Fluid Docs](https://docs.fluid.instadapp.io/)
- [Instadapp Docs](https://docs.instadapp.io/)
- [Contract Addresses](https://docs.fluid.instadapp.io/contracts)
- [Security Audits](https://github.com/Instadapp/audits)
