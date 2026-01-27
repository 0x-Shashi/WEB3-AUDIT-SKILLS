# Lending Protocol Security

## Quick Start

Lending protocols allow users to supply assets for interest and borrow against collateral. They're high-value targets because they hold large amounts of user funds and rely heavily on accurate price data.

**Risk Level:** CRITICAL  
**Common Attacks:** Oracle manipulation, liquidation exploits, flash loan attacks  
**Key Dependencies:** Accurate price oracles, proper collateral management

## Lending Protocol Architecture

```
User Deposits Asset
       ↓
   Mint Shares/Tokens
       ↓
   Add to Pool Liquidity
       ↓
   Borrower Posts Collateral
       ↓
   Borrow Up to LTV Limit
       ↓
   Interest Accrues
       ↓
   Repay or Get Liquidated
```

## Most Critical Lending Vulnerabilities

### 1. Oracle Price Manipulation
**Impact:** Complete fund drainage  
**Vector:** Manipulate collateral/debt price to borrow more than allowed

### 2. Liquidation Logic Errors
**Impact:** Bad debt, unfair liquidations  
**Vector:** Incorrect health factor calculation, wrong incentives

### 3. Interest Rate Manipulation
**Impact:** Interest theft, fund extraction  
**Vector:** Manipulate utilization for favorable rates

### 4. Flash Loan Attacks
**Impact:** Protocol insolvency  
**Vector:** Borrow → manipulate → profit → repay in single tx

### 5. First Depositor Attacks
**Impact:** Share price manipulation  
**Vector:** Donate tokens to inflate share price

## API Query: Lending Vulnerabilities

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "protocolCategory": [{"value": "Lending"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

## API Query: Lending + Oracle Issues

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "protocolCategory": [{"value": "Lending"}],
      "tags": [{"value": "Oracle"}],
      "impact": ["HIGH"]
    }
  }'
```

## API Query: Liquidation Issues

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "keywords": "liquidation health factor",
      "protocolCategory": [{"value": "Lending"}],
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

## Security Considerations by Feature

### Collateral Management
```solidity
// VULNERABLE - No validation
function deposit(address token, uint256 amount) external {
    deposits[msg.sender][token] += amount;
    IERC20(token).transferFrom(msg.sender, address(this), amount);
}

// SECURE - Validate collateral
function deposit(address token, uint256 amount) external {
    require(isAllowedCollateral[token], "Invalid collateral");
    require(amount >= minDeposit[token], "Below minimum");
    // Check for fee-on-transfer tokens
    uint256 before = IERC20(token).balanceOf(address(this));
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    uint256 received = IERC20(token).balanceOf(address(this)) - before;
    deposits[msg.sender][token] += received;
}
```

### Borrowing Logic
```solidity
// VULNERABLE - Can borrow more than collateral allows
function borrow(address token, uint256 amount) external {
    borrowed[msg.sender][token] += amount;
    IERC20(token).transfer(msg.sender, amount);
}

// SECURE - Check health factor
function borrow(address token, uint256 amount) external {
    borrowed[msg.sender][token] += amount;
    require(getHealthFactor(msg.sender) >= MIN_HEALTH_FACTOR, "Undercollateralized");
    IERC20(token).transfer(msg.sender, amount);
}
```

### Price Oracle Integration
```solidity
// VULNERABLE - No validation
function getCollateralValue(address user) public view returns (uint256) {
    (, int256 price,,,) = oracle.latestRoundData();
    return deposits[user] * uint256(price) / 1e8;
}

// SECURE - Full validation
function getCollateralValue(address user) public view returns (uint256) {
    (
        uint80 roundId,
        int256 price,
        ,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = oracle.latestRoundData();
    
    require(price > 0, "Invalid price");
    require(updatedAt > block.timestamp - MAX_STALENESS, "Stale price");
    require(answeredInRound >= roundId, "Round incomplete");
    
    return deposits[user] * uint256(price) / 1e8;
}
```

### Liquidation Logic
```solidity
// VULNERABLE - No profit for liquidator, no bad debt handling
function liquidate(address user) external {
    require(getHealthFactor(user) < MIN_HEALTH_FACTOR, "Healthy");
    // Just transfer collateral...
}

// SECURE - Proper incentives and protections
function liquidate(
    address user,
    address collateralToken,
    uint256 debtToRepay
) external nonReentrant {
    require(getHealthFactor(user) < MIN_HEALTH_FACTOR, "Healthy");
    
    // Calculate collateral to seize (with liquidation bonus)
    uint256 collateralValue = debtToRepay * (100 + LIQUIDATION_BONUS) / 100;
    uint256 collateralAmount = collateralValue * 1e18 / getPrice(collateralToken);
    
    // Handle case where collateral < debt (bad debt)
    if (collateralAmount > deposits[user][collateralToken]) {
        collateralAmount = deposits[user][collateralToken];
        // Protocol absorbs bad debt
        badDebt += calculateBadDebt(user);
    }
    
    // Transfer repayment from liquidator
    IERC20(debtToken).transferFrom(msg.sender, address(this), debtToRepay);
    
    // Update state
    borrowed[user] -= debtToRepay;
    deposits[user][collateralToken] -= collateralAmount;
    
    // Transfer collateral to liquidator
    IERC20(collateralToken).transfer(msg.sender, collateralAmount);
}
```

## Common Vulnerable Patterns

### 1. Missing Oracle Validation
```solidity
// All oracle calls need:
// - Price > 0 check
// - Staleness check
// - Round completeness check
// - L2 sequencer check (if applicable)
```

### 2. Same-Block Manipulation
```solidity
// Attacker can:
// 1. Flash loan
// 2. Deposit collateral
// 3. Borrow maximum
// 4. Withdraw collateral (if allowed)
// 5. Not repay

// Prevention: Block same-block deposit/borrow
```

### 3. Interest Rate Manipulation
```solidity
// Attacker can:
// 1. Flash loan large amount
// 2. Deposit to lower utilization
// 3. Borrow at low rate (if supported)
// 4. Withdraw
// 5. Keep low-rate loan

// Prevention: TWAP-based interest rates
```

### 4. Collateral Factor Bypass
```solidity
// VULNERABLE
function borrow(uint256 amount) external {
    // Only checks at borrow time
    require(getHealthFactor(msg.sender) >= MIN_HF, "Unhealthy");
}

// User can:
// 1. Deposit collateral
// 2. Borrow maximum
// 3. Withdraw some collateral (if no check)
// 4. Be undercollateralized
```

## Lending Security Checklist

### Oracle Security
- [ ] Chainlink or equivalent trusted oracle
- [ ] Staleness checks (appropriate for asset)
- [ ] Round completeness validation
- [ ] Price > 0 validation
- [ ] L2 sequencer checks (if on L2)
- [ ] Fallback oracle mechanism

### Liquidation Security
- [ ] Correct health factor calculation
- [ ] Appropriate liquidation threshold
- [ ] Liquidation bonus incentivizes liquidators
- [ ] Bad debt handling mechanism
- [ ] No self-liquidation exploits
- [ ] Partial liquidation support

### Flash Loan Protection
- [ ] Same-block borrow/withdraw blocked
- [ ] Interest accrual per-block
- [ ] Governance uses snapshots
- [ ] Rate limits on large operations

### Collateral Management
- [ ] Whitelist for collateral tokens
- [ ] Fee-on-transfer token handling
- [ ] Rebasing token considerations
- [ ] Decimal handling across tokens
- [ ] Dust threshold for positions

### Interest Rate Model
- [ ] Utilization bounds (not > 100%)
- [ ] Reasonable rate bounds
- [ ] Proper accrual mechanism
- [ ] No manipulation via flash loans

## Top Lending Exploits to Study

| Protocol | Attack | Loss | Root Cause |
|----------|--------|------|------------|
| Euler | Donation attack | $197M | Share inflation |
| Cream | Flash loan | $130M | Oracle manipulation |
| Aave | Near miss | - | Chainlink multisig |
| Compound | Oracle | $90M | Incorrect price feed |
| Venus | Oracle | $200M | Price manipulation |

## Test This Query

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 5,
    "filters": {
      "protocolCategory": [{"value": "Lending"}],
      "impact": ["HIGH"],
      "qualityScore": 5,
      "sortField": "Quality"
    }
  }' | jq '.findings[] | {title, firm: .firm_name}'
```

## Cross-Reference

- For oracle security → See [../vulnerability-tags/oracle.md](../vulnerability-tags/oracle.md)
- For flash loan attacks → See [../vulnerability-tags/flash-loan.md](../vulnerability-tags/flash-loan.md)
- For price manipulation → See [../vulnerability-tags/price-manipulation.md](../vulnerability-tags/price-manipulation.md)
- For DeFi general → See [defi.md](defi.md)
