---
id: PLAYBOOK-MAKERDAO
title: MakerDAO Integration Playbook
category: protocol-playbooks
protocol: makerdao
version: multi-collateral-dai
difficulty: advanced
tags: [maker, dai, cdp, vault, liquidation, psm]
last_updated: 2026-01-31
---

# MakerDAO Integration Playbook

> **Attack Surface:** See [attack-trees/stablecoin-attack-tree.md](../attack-trees/stablecoin-attack-tree.md) | [attack-trees/governance-attack-tree.md](../attack-trees/governance-attack-tree.md)

Comprehensive guide for integrating with and auditing MakerDAO (Maker Protocol) - the largest CDP-based stablecoin system.

---

## Protocol Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      MakerDAO System                        │
├─────────────┬───────────────┬──────────────┬───────────────┤
│   Vaults    │   DAI Token   │   Oracles    │   Governance  │
│  (CDPs)     │  (Stablecoin) │  (Prices)    │   (MKR)       │
├─────────────┼───────────────┼──────────────┼───────────────┤
│ • Collateral│ • ERC20       │ • OSM        │ • Voting      │
│ • Debt      │ • 1:1 USD peg │ • Medianizer │ • Executive   │
│ • Stability │ • Minting     │ • Delays     │ • Spells      │
│   Fee       │ • Burning     │              │               │
└─────────────┴───────────────┴──────────────┴───────────────┘
```

## Key Contracts

| Contract | Address (Mainnet) | Purpose |
|----------|-------------------|---------|
| Vat | `0x35D1b3F3D7966A1DFe207aa4514C12a259A0492B` | Core vault engine |
| Dai | `0x6B175474E89094C44Da98b954EesE495efd43D1b` | DAI stablecoin |
| Jug | `0x19c0976f590D67707E62397C87829d896Dc0f1F1` | Stability fee collector |
| Dog | `0x135954d155898D42C90D2a57824C690e0c7BEf1B` | Liquidation engine |
| Spot | `0x65C79fcB50Ca1594B025960e539eD7A9a6D434A3` | Price feed interface |
| PSM | `0x89B78CfA322F6C5dE0aBcEecab66Aee45393cC5A` | Peg Stability Module |

---

## Core Concepts

### 1. Vault (CDP) Mechanics

```solidity
// Vault represents a collateralized debt position
struct Vault {
    bytes32 ilk;      // Collateral type identifier
    address urn;      // Vault address
    uint256 ink;      // Collateral amount (wad - 18 decimals)
    uint256 art;      // Normalized debt (wad)
}

// Actual debt = art * rate (from Vat.ilks[ilk].rate)
// Collateralization ratio = (ink * price) / (art * rate)
```

### 2. Key Calculations

```solidity
// Collateralization Ratio
uint256 collateralValue = ink * price;  // In DAI
uint256 debt = art * rate;               // In DAI
uint256 ratio = collateralValue * 100 / debt;

// Maximum DAI borrowable
uint256 maxDebt = (ink * price * 100) / liquidationRatio;

// Stability Fee (continuously compounding)
// rate = rate * (1 + stabilityFee)^timePassed
// Accrued via Jug.drip(ilk)
```

### 3. Peg Stability Module (PSM)

```solidity
// Swap USDC → DAI at 1:1 (minus fee)
// Keeps DAI pegged to $1

interface IPSM {
    function sellGem(address usr, uint256 gemAmt) external;  // USDC → DAI
    function buyGem(address usr, uint256 gemAmt) external;   // DAI → USDC
    
    // Fees (tin = sell fee, tout = buy fee)
    function tin() external view returns (uint256);   // e.g., 0 (0%)
    function tout() external view returns (uint256);  // e.g., 0 (0%)
}
```

---

## Integration Patterns

### Opening a Vault

```solidity
// 1. Create a vault (urn)
address urn = manager.open(ilk, address(this));

// 2. Deposit collateral
gem.approve(gemJoin, amount);
gemJoin.join(urn, amount);

// 3. Lock collateral and generate DAI
manager.frob(
    cdpId,
    int256(collateralAmount),  // dink: collateral to lock
    int256(daiAmount)           // dart: DAI to generate
);

// 4. Withdraw DAI
daiJoin.exit(address(this), daiAmount);
```

### Closing a Vault

```solidity
// 1. Approve DAI
dai.approve(daiJoin, debt);

// 2. Pay back DAI
daiJoin.join(urn, debt);

// 3. Unlock collateral and pay debt
manager.frob(
    cdpId,
    -int256(collateralAmount),  // Negative = unlock
    -int256(debtAmount)          // Negative = repay
);

// 4. Withdraw collateral
gemJoin.exit(address(this), collateralAmount);
```

### Using the PSM

```solidity
// USDC → DAI
usdc.approve(psmGemJoin, amount);
psm.sellGem(recipient, amount);  // Receive DAI

// DAI → USDC
dai.approve(daiJoin, amount);
psm.buyGem(recipient, amount);   // Receive USDC
```

---

## Security Considerations

###  Critical Checks

```
[ ] Collateralization ratio always above liquidation threshold?
[ ] Stability fees accrued before debt calculations?
[ ] Oracle price delays (OSM) considered?
[ ] Debt ceiling (line) not exceeded?
[ ] Dust limit (minimum debt) enforced?
```

### Oracle Security

```solidity
// Maker uses Oracle Security Module (OSM) with 1-hour delay
// Current price vs next price

interface IOsm {
    function peek() external view returns (bytes32, bool);  // Current price
    function peep() external view returns (bytes32, bool);  // Next price (in 1 hour)
    function hop() external view returns (uint16);          // Update interval
}

// VULNERABILITY: Using next price before it's active
// SECURE: Always use peek() for current valid price
```

### Liquidation Risks

```solidity
// Liquidations happen via Dog.bark()
// Collateral is auctioned via Clipper contracts

// RISK: Flash crash liquidation
// Price drops → OSM updates (1hr delay) → Liquidations

// MITIGATION: 
// - Monitor OSM.peep() for upcoming price
// - Keep buffer above liquidation ratio
// - Use automation (Gelato, Chainlink Keepers)
```

---

## Common Vulnerabilities

### 1. Not Accruing Stability Fees

```solidity
// VULNERABLE: Reading stale debt
function getDebt(bytes32 ilk, address urn) external view returns (uint256) {
    (uint256 ink, uint256 art) = vat.urns(ilk, urn);
    (, uint256 rate,,,) = vat.ilks(ilk);
    return art * rate / RAY;  // Rate might be stale!
}

// SECURE: Drip before reading
function getDebt(bytes32 ilk, address urn) external returns (uint256) {
    jug.drip(ilk);  // Update rate first
    (uint256 ink, uint256 art) = vat.urns(ilk, urn);
    (, uint256 rate,,,) = vat.ilks(ilk);
    return art * rate / RAY;
}
```

### 2. Ignoring Dust Limit

```solidity
// VULNERABLE: Creating vault with too little debt
function openVault(uint256 collateral, uint256 debt) external {
    // Maker has minimum debt requirement per vault
    manager.frob(cdpId, int(collateral), int(debt));
    // Reverts if debt < dust limit!
}

// SECURE: Check dust limit
function openVault(uint256 collateral, uint256 debt) external {
    (,,,, uint256 dust) = vat.ilks(ilk);
    require(debt >= dust, "Below dust limit");
    manager.frob(cdpId, int(collateral), int(debt));
}
```

### 3. Not Handling RAY/WAD Precision

```solidity
// Maker uses mixed precision:
// WAD = 10^18 (for amounts)
// RAY = 10^27 (for rates)
// RAD = 10^45 (for Vat internal accounting)

// VULNERABLE: Wrong precision
uint256 debt = art * rate;  // This is in RAD (45 decimals)!

// SECURE: Proper conversion
uint256 debt = art * rate / RAY;  // Convert to WAD (18 decimals)
```

### 4. Oracle Manipulation via Flash Loan

```solidity
// Maker's OSM has 1-hour delay - can't be flash manipulated
// BUT: Integrations might use other oracles

// VULNERABLE: Using spot price from DEX
uint256 price = uniswapPair.getReserves().token0 / token1;

// SECURE: Use Maker's delayed oracle
(bytes32 price, bool valid) = osm.peek();
require(valid, "Oracle invalid");
```

---

## Integration Checklist

### Before Integration
```
[ ] Understand ilk parameters (line, dust, mat, chop)
[ ] Know the oracle delay (typically 1 hour)
[ ] Account for stability fee accrual
[ ] Handle DAI/gem decimal differences
[ ] Plan for liquidation scenarios
```

### Contract Implementation
```
[ ] Call jug.drip() before debt calculations
[ ] Check debt ceiling before generating DAI
[ ] Enforce dust limit on vault operations
[ ] Use correct precision (WAD/RAY/RAD)
[ ] Handle oracle validity checks
```

### Operational
```
[ ] Monitor collateralization ratio
[ ] Set up liquidation protection
[ ] Track stability fee accumulation
[ ] Watch for governance parameter changes
```

---

## Key Parameters by Collateral Type

| Collateral | Stability Fee | Liquidation Ratio | Dust |
|------------|---------------|-------------------|------|
| ETH-A | 2.0% | 145% | 15,000 DAI |
| ETH-B | 4.0% | 130% | 30,000 DAI |
| ETH-C | 0.5% | 170% | 5,000 DAI |
| WSTETH-A | 1.5% | 160% | 15,000 DAI |
| WBTC-A | 2.0% | 145% | 15,000 DAI |
| USDC-A (PSM) | 0% | 100% | N/A |

---

## Quick Reference

### Important Formulas
```
Debt = art × rate / RAY
Collateral Value = ink × price
Collateralization Ratio = Collateral Value / Debt × 100%
Max Debt = Collateral Value × 100 / Liquidation Ratio
Liquidation Price = Debt × Liquidation Ratio / ink
```

### Key MCD Functions
```solidity
// Vat (Core Engine)
vat.urns(ilk, urn)          // Get vault (ink, art)
vat.ilks(ilk)               // Get ilk params (Art, rate, spot, line, dust)
vat.frob(ilk, u, v, w, dink, dart)  // Modify vault

// Manager (User-friendly wrapper)
manager.open(ilk, usr)      // Create CDP
manager.frob(cdp, dink, dart)  // Modify CDP
manager.flux(cdp, dst, wad)    // Move collateral
manager.move(cdp, dst, rad)    // Move DAI

// Jug (Stability Fees)
jug.drip(ilk)               // Accrue stability fee
```
