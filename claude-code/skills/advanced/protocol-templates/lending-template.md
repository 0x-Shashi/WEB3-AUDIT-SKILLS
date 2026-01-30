# Lending Protocol Template

## Architecture Overview

```

                     LENDING PROTOCOL                             

                                                                  
                               
     LENDERS      Deposit    POOL/VAULT        
    (Supply)      Interest                      
                               
                                                                 
                                                
    BORROWERS     Borrow                
    (Demand)      Collateral + Interest                
                                                
                                                                 
                               
   LIQUIDATORS    Liquidate   COLLATERAL         
                  Bonus    MANAGER           
                               
                                                                 
                                                
                                              ORACLE           
                                             (Prices)          
                                                
                                                                  

```

---

## Core Concepts

### Health Factor

```
Health Factor = (Collateral Value * LTV) / Debt Value

HF > 1 = Safe
HF < 1 = Liquidatable
```

### Interest Rate Model

```
Utilization = Borrowed / Supplied

Rate = BaseRate + Utilization * Slope
(Often with kink point for high utilization)
```

### Collateralization

```
Max Borrow = Collateral Value * Collateral Factor

Example:
$1000 ETH at 75% CF = Can borrow up to $750
```

---

## Critical Functions

### 1. Supply/Deposit

```solidity
function deposit(address asset, uint256 amount) {
    // Pull tokens
    // Update interest
    // Mint receipt tokens
}
```

**Audit Points:**
- [ ] Correct share calculation
- [ ] Interest updated before
- [ ] First depositor attack
- [ ] Receipt token math

### 2. Borrow

```solidity
function borrow(address asset, uint256 amount) {
    // Check health factor
    // Check available liquidity
    // Transfer tokens
    // Update debt
}
```

**Audit Points:**
- [ ] Health factor checked after
- [ ] Liquidity available
- [ ] Debt correctly recorded
- [ ] Interest accrued

### 3. Repay

```solidity
function repay(address asset, uint256 amount) {
    // Accept tokens
    // Update interest
    // Reduce debt
}
```

**Audit Points:**
- [ ] Overpayment handling
- [ ] Interest calculation
- [ ] Debt cleared correctly

### 4. Withdraw

```solidity
function withdraw(address asset, uint256 amount) {
    // Check health factor (if collateral)
    // Burn receipt tokens
    // Transfer tokens
}
```

**Audit Points:**
- [ ] Health factor maintained
- [ ] Available liquidity
- [ ] Share calculation

### 5. Liquidate

```solidity
function liquidate(
    address borrower,
    address collateralAsset,
    address debtAsset,
    uint256 repayAmount
) {
    // Check borrower underwater
    // Accept debt payment
    // Transfer collateral + bonus
}
```

**Audit Points:**
- [ ] Health factor checked
- [ ] Correct bonus calculation
- [ ] No self-liquidation exploits
- [ ] Partial liquidation handled

---

## Common Vulnerabilities

### LEND-01: Oracle Manipulation  Bad Debt

**Risk:** Critical

**Description:** Manipulated price enables borrowing against inflated collateral or unfair liquidations.

**Attack Scenario:**
1. Deposit obscure token as collateral
2. Manipulate price upward
3. Borrow max against inflated price
4. Never repay, default
5. Protocol has worthless collateral

**Vulnerable Pattern:**
```solidity
function getCollateralValue(address token) view returns (uint256) {
    return dexPair.getReserves();  // Manipulatable!
}
```

**Mitigation:**
- Chainlink oracles
- TWAP with sufficient window
- Price deviation checks
- Collateral caps

---

### LEND-02: Interest Rate Manipulation

**Risk:** High

**Description:** Sudden utilization changes cause extreme interest rate spikes.

**Attack:**
1. Flash borrow all liquidity
2. Interest rate spikes
3. Existing borrowers face massive interest
4. Force liquidations

**Mitigation:**
- Interest rate caps
- Time-weighted rates
- Flash loan restrictions on utilization

---

### LEND-03: Liquidation DOS

**Risk:** High

**Description:** Borrower can prevent their liquidation.

**Attack Patterns:**
1. **Gas griefing:** Callback consumes all gas
2. **Revert on receive:** Contract reverts on token receive
3. **Blocklist:** Get collateral token blacklisted

**Vulnerable Pattern:**
```solidity
function liquidate(address borrower, ...) {
    // Transfer collateral to liquidator
    collateral.transfer(liquidator, amount);  // What if reverts?
}
```

**Mitigation:**
```solidity
// Use pull pattern
function claimLiquidation(uint256 liquidationId) {
    // Liquidator claims separately
}
```

---

### LEND-04: Precision Loss in Interest

**Risk:** Medium

**Description:** Interest calculations lose precision over time.

**Vulnerable Pattern:**
```solidity
uint256 interest = principal * rate / YEAR;  // Truncates!
// If calculated frequently, compounds incorrectly
```

**Mitigation:**
- Use ray math (27 decimals)
- Compound correctly
- Index-based tracking

---

### LEND-05: Flash Loan Price Manipulation

**Risk:** Critical

**Description:** Flash loan used to manipulate oracle for instant profit.

**Attack:**
1. Flash borrow ETH
2. Dump on DEX  crash price
3. Liquidate underwater positions
4. Profit from liquidation bonus
5. Repay flash loan

**Mitigation:**
- TWAP oracles (not spot)
- Price deviation limits
- Chainlink (off-chain)

---

### LEND-06: Share Inflation Attack

**Risk:** Critical

**Description:** First depositor inflates share price to steal from later depositors.

**Attack:**
1. Deposit 1 wei  1 share
2. Donate large amount to vault
3. Share price = huge
4. Next depositor's amount rounds to 0 shares
5. First depositor withdraws with extra funds

**Mitigation:**
```solidity
constructor() {
    // Mint dead shares
    _mint(address(0), 1000);
}
```

---

### LEND-07: Cross-Asset Manipulation

**Risk:** High

**Description:** Borrow one asset to manipulate price of another.

**Attack:**
1. Deposit tokenA as collateral
2. Borrow tokenB
3. Dump tokenB  crash its price
4. tokenA now worth more relatively
5. Borrow more, repeat

---

### LEND-08: Liquidation Threshold Gaming

**Risk:** Medium

**Description:** Borrow exactly at threshold to grief liquidators.

**Attack:**
1. Borrow to exactly HF = 1.0
2. Tiny price movements trigger liquidations
3. Liquidator loses to gas costs
4. Position remains bad indefinitely

---

## Real Exploit Examples

| Protocol | Date | Loss | Vulnerability |
|----------|------|------|---------------|
| Cream Finance | Oct 2021 | $130M | Oracle manipulation |
| Euler | Mar 2023 | $197M | Donate + liquidation |
| Mango Markets | Oct 2022 | $117M | Oracle manipulation |
| Inverse Finance | Apr 2022 | $15M | Oracle manipulation |

---

## Interest Rate Model Audit

### Common Models

**Linear:**
```
rate = baseRate + utilization * slope
```

**Kinked:**
```
if utilization < kink:
    rate = baseRate + utilization * slope1
else:
    rate = baseRate + kink * slope1 + (utilization - kink) * slope2
```

**Audit Points:**
- [ ] Utilization capped at 100%
- [ ] Rate can't overflow
- [ ] Kink point reasonable
- [ ] Max rate not extreme

---

## Lending Audit Checklist

### Oracle Security
- [ ] Chainlink or TWAP (not spot)
- [ ] Staleness check
- [ ] Price deviation limits
- [ ] Fallback oracles

### Liquidation
- [ ] Health factor checked correctly
- [ ] Bonus reasonable (5-10%)
- [ ] No DOS possible
- [ ] Bad debt handling

### Interest
- [ ] Precision handling
- [ ] Correct compounding
- [ ] Rate limits
- [ ] Utilization caps

### Collateral
- [ ] Correct factors per asset
- [ ] Caps per collateral
- [ ] No manipulation paths
- [ ] Cross-margin handled

### Access Control
- [ ] Parameter changes protected
- [ ] Timelock on updates
- [ ] Emergency pause
- [ ] Guardian roles

### Token Handling
- [ ] Fee-on-transfer
- [ ] Rebasing tokens
- [ ] Decimal handling
- [ ] Zero address

---

## Protocol-Specific Patterns

### Aave Forks
- aToken receipt tokens
- Variable/stable rates
- Check flash loan fees
- E-mode for correlated assets

### Compound Forks
- cToken receipt tokens
- Comptroller for validation
- Check interest accrual
- COMP distribution exploits

### Maker/DAI Forks
- CDPs/Vaults
- Stability fee
- Liquidation auctions
- Check auction timing

---

## Detection Commands

```bash
# Find collateral logic
grep -rn "collateral\|healthFactor\|liquidat" --include="*.sol"

# Find oracle usage
grep -rn "getPrice\|latestAnswer\|getReserves" --include="*.sol"

# Find interest calculations
grep -rn "interest\|rate\|accrual\|compound" --include="*.sol"

# Find share calculations
grep -rn "totalSupply\|_mint.*shares\|share.*price" --include="*.sol"

# Find liquidation bonus
grep -rn "bonus\|penalty\|discount" --include="*.sol"
```
