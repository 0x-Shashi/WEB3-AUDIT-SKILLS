# DeFi Protocol Security

## Quick Start

DeFi (Decentralized Finance) protocols handle financial operations on-chain. They're among the highest-risk smart contracts due to the direct access to user funds and complex financial logic.

**Risk Level:** HIGH  
**Common Attacks:** Flash loans, oracle manipulation, reentrancy  
**Total Value at Risk:** Billions of dollars across DeFi protocols

## DeFi Sub-Categories

| Sub-Category | Examples | Primary Risks |
|--------------|----------|---------------|
| AMM/DEX | Uniswap, Curve | Price manipulation, MEV |
| Lending | Aave, Compound | Oracle attacks, liquidation |
| Yield Aggregator | Yearn, Beefy | Strategy risks, composability |
| Staking | Lido, Rocket Pool | Reward calculation, slashing |
| Derivatives | GMX, dYdX | Settlement, funding rates |

## Most Critical DeFi Vulnerabilities (Ranked)

### 1. Oracle/Price Manipulation
Attackers manipulate price feeds to exploit protocol logic.

### 2. Flash Loan Attacks
Borrowed capital amplifies other vulnerabilities.

### 3. Reentrancy
External calls before state updates enable fund drainage.

### 4. Access Control
Missing authorization on sensitive functions.

### 5. Logic Errors in Financial Calculations
Incorrect fee calculations, rounding errors, etc.

## API Query: DeFi HIGH Severity Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "protocolCategory": [{"value": "DeFi"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality",
      "sortDirection": "Desc"
    }
  }'
```

## API Query: DeFi + Specific Vulnerability

```bash
# Oracle issues in DeFi
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "protocolCategory": [{"value": "DeFi"}],
      "tags": [{"value": "Oracle"}, {"value": "Price Manipulation"}],
      "impact": ["HIGH"]
    }
  }'
```

## API Query: Recent DeFi Issues

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "protocolCategory": [{"value": "DeFi"}],
      "impact": ["HIGH", "MEDIUM"],
      "reported": {"value": "60"},
      "sortField": "Recency"
    }
  }'
```

## Security Considerations by Feature

### Token Swaps
- **Slippage protection** - Always have `minAmountOut`
- **Deadline** - Prevent stale transactions
- **Price validation** - Don't trust spot prices
- **Reentrancy** - CEI pattern for swaps

### Liquidity Provision
- **First depositor attack** - Virtual offsets
- **Impermanent loss** - Clear documentation
- **Share calculation** - Proper rounding
- **Flash loan resistance** - Same-block checks

### Fee Calculations
- **Rounding direction** - Favor protocol
- **Fee bounds** - Min/max limits
- **Fee collection** - Separate from user funds
- **Overflow protection** - Safe math

### Reward Distribution
- **Reward rate calculation** - Time-weighted
- **Claiming logic** - Prevent double claims
- **Dust handling** - Minimum thresholds
- **Update triggers** - When to accrue

## Common Vulnerable Patterns

### 1. Spot Price Usage
```solidity
// DANGEROUS
function getPrice() public view returns (uint256) {
    (uint112 r0, uint112 r1,) = pair.getReserves();
    return uint256(r0) * 1e18 / uint256(r1);
}

// SECURE - Use TWAP or Chainlink
```

### 2. Missing Reentrancy Guard
```solidity
// DANGEROUS
function withdraw(uint256 amount) external {
    (bool success,) = msg.sender.call{value: amount}("");
    balances[msg.sender] -= amount;  // After external call
}

// SECURE
function withdraw(uint256 amount) external nonReentrant {
    balances[msg.sender] -= amount;  // Before external call
    (bool success,) = msg.sender.call{value: amount}("");
}
```

### 3. No Flash Loan Protection
```solidity
// DANGEROUS - Can deposit and withdraw same block
function deposit() external { /* ... */ }
function withdraw() external { /* ... */ }

// SECURE - Block same-block operations
mapping(address => uint256) depositBlock;
function withdraw() external {
    require(block.number > depositBlock[msg.sender], "Same block");
}
```

## DeFi Security Checklist

### Price/Oracle Security
- [ ] Using TWAP or Chainlink (not spot prices)
- [ ] Staleness checks on oracle data
- [ ] Fallback oracles
- [ ] Price deviation bounds

### Flash Loan Resistance
- [ ] Same-block deposit/withdraw protection
- [ ] Virtual balance tracking
- [ ] Governance uses snapshots
- [ ] Rate limiting on critical operations

### Reentrancy Protection
- [ ] ReentrancyGuard on state-changing functions
- [ ] CEI pattern followed
- [ ] Cross-contract reentrancy considered
- [ ] Read-only reentrancy addressed

### Access Control
- [ ] Admin functions protected
- [ ] Role-based access where needed
- [ ] Two-step ownership transfer
- [ ] Emergency functions secured

### Financial Logic
- [ ] Rounding favors protocol
- [ ] Fee calculations verified
- [ ] Overflow/underflow protected
- [ ] Edge cases handled (0, first, max)

### General
- [ ] Pausability for emergencies
- [ ] Upgrade mechanism if needed
- [ ] Proper event emission
- [ ] Comprehensive testing

## Top DeFi Exploits to Study

| Protocol | Attack Type | Loss |
|----------|-------------|------|
| Euler Finance | Donation attack | $197M |
| Curve Finance | Reentrancy | $70M |
| BonqDAO | Oracle manipulation | $120M |
| Mango Markets | Price manipulation | $110M |
| Cream Finance | Flash loan | $130M |

## Test This Query

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 5,
    "filters": {
      "protocolCategory": [{"value": "DeFi"}],
      "impact": ["HIGH"],
      "qualityScore": 5,
      "sortField": "Quality"
    }
  }' | jq '.findings[] | {title, firm: .firm_name, tags: [.issues_issuetagscore[]?.tags_tag.title] | unique}'
```

## Cross-Reference

- For oracle issues → See [../vulnerability-tags/oracle.md](../vulnerability-tags/oracle.md)
- For flash loans → See [../vulnerability-tags/flash-loan.md](../vulnerability-tags/flash-loan.md)
- For reentrancy → See [../vulnerability-tags/reentrancy.md](../vulnerability-tags/reentrancy.md)
- For lending specifics → See [lending.md](lending.md)
- For DEX specifics → See [dex.md](dex.md)
