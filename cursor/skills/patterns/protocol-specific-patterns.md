# Protocol-Specific Audit Patterns

> **AI Skill**: This file contains protocol-specific vulnerability patterns and audit focus areas based on 50+ real audit reports from production protocols.

## Protocol Categories

| Category | Example Protocols | Key Risks |
|----------|------------------|-----------|
| [Perpetuals/Derivatives](#1-perpetuals--derivatives) | GMX, Synthetix, MUX | Oracle manipulation, liquidation, funding |
| [AMMs/DEXs](#2-amms--dexs) | MIMSwap, Smardex, Poolshark | Price manipulation, LP attacks, MEV |
| [Lending](#3-lending-protocols) | Dolomite, K33Loans, Impermax | Bad debt, interest accrual, collateral |
| [Bridges](#4-bridge-protocols) | Bridges Exchange, USDT0 | Message validation, replay, signatures |
| [Stablecoins](#5-stablecoin-protocols) | Ethena, M0, AbracadabraMoney | Depeg, redemption, collateral |
| [Vaults/Yield](#6-vault--yield-protocols) | BeefyFinance, Umami, Reliquary | Share manipulation, donation, harvest |
| [NFT/GameFi](#7-nft--gamefi-protocols) | YugaLabs, Animecoin, NFTR | Mint manipulation, metadata, randomness |
| [Governance](#8-governance-protocols) | GMX Governance, Ethereal | Vote manipulation, timelock, delegation |

---

## 1. Perpetuals & Derivatives

**Example Protocols**: GMX (365 findings over 11 months), Synthetix, MUX, PariFi

### Critical Focus Areas

#### 1.1 Oracle & Price Feeds
```
Check for:
- Price staleness handling
- Chainlink sequencer uptime checks (L2)
- Price deviation thresholds
- Multi-oracle fallback mechanisms
- Block timestamp vs oracle timestamp
```

**Vulnerability Pattern**:
```solidity
// VULNERABLE: No sequencer check on L2
function getPrice() external view returns (uint256) {
    (, int256 price,,,) = priceFeed.latestRoundData();
    return uint256(price);  // What if sequencer is down?
}

// SECURE: L2 sequencer check
function getPrice() external view returns (uint256) {
    // Check sequencer uptime first (Arbitrum, Optimism)
    (, int256 answer, uint256 startedAt,,) = sequencerUptimeFeed.latestRoundData();
    require(answer == 0, "Sequencer down");
    require(block.timestamp - startedAt > GRACE_PERIOD, "Grace period not passed");
    
    // Then get price
    (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt < STALENESS_THRESHOLD, "Stale price");
    return uint256(price);
}
```

#### 1.2 Position Management
```
Check for:
- Maximum position size limits
- Leverage calculation accuracy
- Position update atomicity
- Fee calculation precision
- PnL calculation edge cases
```

**Vulnerability Pattern**:
```solidity
// VULNERABLE: PnL calculation can overflow
function calculatePnL(Position memory pos, uint256 currentPrice) returns (int256) {
    int256 priceDelta = int256(currentPrice) - int256(pos.entryPrice);
    return priceDelta * int256(pos.size);  // Can overflow for large positions!
}

// SECURE: Use safe math
function calculatePnL(Position memory pos, uint256 currentPrice) returns (int256) {
    int256 priceDelta = int256(currentPrice) - int256(pos.entryPrice);
    return (priceDelta * int256(pos.size)) / int256(pos.entryPrice);
}
```

#### 1.3 Liquidation Mechanics
```
Check for:
- Liquidation threshold accuracy
- Partial vs full liquidation logic
- Liquidator incentives
- Bad debt handling
- Cascade liquidation scenarios
```

#### 1.4 Funding Rate
```
Check for:
- Funding rate calculation frequency
- Rate limits/caps
- Payment direction logic
- Accumulator precision
```

### Audit Prompt for Perpetuals
```
Analyze this perpetual/derivatives protocol for:
1. Oracle manipulation via flash loans or price lag
2. Position size limits and leverage caps
3. Liquidation race conditions and threshold manipulation
4. Funding rate edge cases (overflow, frequency attacks)
5. Fee bypass or manipulation vectors
6. Cross-margin vs isolated margin edge cases
```

---

## 2. AMMs & DEXs

**Example Protocols**: MIMSwap, Smardex, Poolshark, GammaStrategies

### Critical Focus Areas

#### 2.1 Liquidity Pool Security
```
Check for:
- First depositor attack (share inflation)
- Donation attacks
- LP token manipulation
- Imbalanced pool exploitation
- Minimum liquidity requirements
```

**Vulnerability Pattern**:
```solidity
// VULNERABLE: First depositor attack
function deposit(uint256 amount) returns (uint256 shares) {
    if (totalSupply == 0) {
        shares = amount;  // First depositor sets price
    } else {
        shares = amount * totalSupply / totalAssets;
    }
    _mint(msg.sender, shares);
}

// SECURE: Burn initial shares
function deposit(uint256 amount) returns (uint256 shares) {
    if (totalSupply == 0) {
        shares = amount - MINIMUM_LIQUIDITY;
        _mint(address(0), MINIMUM_LIQUIDITY);  // Burn initial shares
    } else {
        shares = amount * totalSupply / totalAssets;
    }
    _mint(msg.sender, shares);
}
```

#### 2.2 Swap Security
```
Check for:
- Slippage protection implementation
- Fee calculation accuracy
- Token balance tracking (before/after)
- Reentrancy in swap callbacks
- k-value invariant maintenance
```

#### 2.3 Concentrated Liquidity (Uniswap V3 style)
```
Check for:
- Tick boundary handling
- Price range edge cases
- Position NFT security
- Fee accrual accuracy
- Out-of-range position handling
```

### Audit Prompt for AMMs
```
Review this AMM/DEX for:
1. First depositor/donation attack vectors
2. Swap path manipulation and routing attacks
3. Fee bypass or extraction opportunities
4. k-value invariant violations
5. MEV/sandwich attack resistance
6. Token compatibility (rebasing, fee-on-transfer)
```

---

## 3. Lending Protocols

**Example Protocols**: Dolomite, K33Loans, Impermax, MagnifyCash

### Critical Focus Areas

#### 3.1 Interest Rate Model
```
Check for:
- Utilization rate calculation
- Interest accrual frequency
- Rate manipulation via flash loans
- Compound interest precision
```

#### 3.2 Collateral Management
```
Check for:
- Collateral factor accuracy
- Cross-collateralization logic
- Collateral withdrawal checks
- Price-based vs value-based calculations
```

**Vulnerability Pattern**:
```solidity
// VULNERABLE: Check collateral after withdrawal
function withdraw(uint256 amount) external {
    collateral[msg.sender] -= amount;  // State change
    require(isHealthy(msg.sender), "Unhealthy");  // Check after
    token.transfer(msg.sender, amount);  // External call
}

// SECURE: Check before state change
function withdraw(uint256 amount) external {
    require(wouldBeHealthy(msg.sender, amount), "Would be unhealthy");
    collateral[msg.sender] -= amount;
    token.transfer(msg.sender, amount);
}
```

#### 3.3 Liquidation
```
Check for:
- Liquidation bonus calculation
- Partial liquidation support
- Bad debt socialization
- Liquidator whitelist (if any)
- Grace period handling
```

#### 3.4 Isolation Mode
```
Check for:
- Isolation tier enforcement
- Debt ceiling per asset
- Cross-borrowing restrictions
```

### Audit Prompt for Lending
```
Analyze this lending protocol for:
1. Interest rate manipulation via utilization
2. Oracle-based price manipulation for collateral
3. Liquidation threshold gaming
4. Flash loan attack vectors (borrow/repay same block)
5. Bad debt accumulation scenarios
6. Share/debt accounting precision issues
```

---

## 4. Bridge Protocols

**Example Protocols**: Bridges Exchange, USDT0, L2 bridges

### Critical Focus Areas

#### 4.1 Message Validation
```
Check for:
- Source chain verification
- Message hash uniqueness
- Nonce management
- Expiry handling
- Replay protection
```

**Vulnerability Pattern**:
```solidity
// VULNERABLE: No chain ID in message
function processMessage(bytes32 messageHash, bytes memory signature) external {
    require(!processed[messageHash], "Already processed");
    processed[messageHash] = true;
    // Replay possible on other chains with same contract address!
}

// SECURE: Include chain ID
function processMessage(
    uint256 sourceChainId,
    bytes32 messageHash,
    bytes memory signature
) external {
    bytes32 fullHash = keccak256(abi.encode(sourceChainId, block.chainid, messageHash));
    require(!processed[fullHash], "Already processed");
    processed[fullHash] = true;
}
```

#### 4.2 Signature Verification
```
Check for:
- EIP-712 compliance
- ecrecover return value check
- Signature malleability
- Multi-sig threshold validation
```

#### 4.3 Token Handling
```
Check for:
- Lock/mint vs burn/unlock consistency
- Token address mapping correctness
- Decimal handling across chains
- Native token handling
```

### Audit Prompt for Bridges
```
Review this bridge for:
1. Cross-chain replay attacks
2. Message validation completeness
3. Signature verification security
4. Relayer manipulation vectors
5. Token supply consistency across chains
6. Finality assumptions per chain
```

---

## 5. Stablecoin Protocols

**Example Protocols**: Ethena, M0, AbracadabraMoney

### Critical Focus Areas

#### 5.1 Peg Maintenance
```
Check for:
- Redemption mechanism security
- Minting rate limits
- Collateralization ratio checks
- Emergency pause functionality
```

#### 5.2 Yield Distribution
```
Check for:
- Yield source security
- Distribution frequency
- Rebase mechanics (if applicable)
- Yield manipulation vectors
```

#### 5.3 Collateral Management
```
Check for:
- Accepted collateral types
- Collateral ratio enforcement
- Liquidation of under-collateralized positions
- Depeg scenario handling
```

### Audit Prompt for Stablecoins
```
Analyze this stablecoin protocol for:
1. Depeg scenario handling and recovery
2. Collateral value manipulation
3. Redemption/minting arbitrage
4. Yield source sustainability and security
5. Governance attack on parameters
6. Emergency mechanism effectiveness
```

---

## 6. Vault & Yield Protocols

**Example Protocols**: BeefyFinance, Umami, Reliquary, KeyFinance

### Critical Focus Areas

#### 6.1 Share Calculation
```
Check for:
- Share inflation attacks
- Rounding direction (favor protocol)
- Deposit/withdraw atomicity
- Fee on deposit/withdraw
```

**Vulnerability Pattern**:
```solidity
// VULNERABLE: Rounding favors user
function withdraw(uint256 shares) returns (uint256 assets) {
    assets = shares * totalAssets / totalShares;  // Can round up
    totalShares -= shares;
    token.transfer(msg.sender, assets);  // More assets than owed
}

// SECURE: Round down for user withdrawals
function withdraw(uint256 shares) returns (uint256 assets) {
    assets = shares.mulDivDown(totalAssets, totalShares);  // Round down
    totalShares -= shares;
    token.transfer(msg.sender, assets);
}
```

#### 6.2 Strategy Security
```
Check for:
- Strategy migration safety
- Harvest timing attacks
- Emergency withdrawal
- Strategy composability risks
```

#### 6.3 Reward Distribution
```
Check for:
- Reward token handling
- Distribution frequency
- Reward manipulation via deposits
- Vesting schedule enforcement
```

### Audit Prompt for Vaults
```
Review this vault/yield protocol for:
1. Share price manipulation via donation
2. Harvest sandwich attacks
3. Strategy migration fund safety
4. Reward dilution attacks
5. Emergency withdrawal functionality
6. Composability risks with underlying protocols
```

---

## 7. NFT & GameFi Protocols

**Example Protocols**: YugaLabs, Animecoin, NFTR, UltiBets

### Critical Focus Areas

#### 7.1 Minting Security
```
Check for:
- Mint limit enforcement
- Whitelist verification
- Price manipulation
- Randomness source for traits
```

#### 7.2 Metadata Security
```
Check for:
- URI manipulation
- Reveal mechanism security
- On-chain vs off-chain data
```

#### 7.3 Game Mechanics
```
Check for:
- Random number generation
- Reward distribution fairness
- Anti-cheat mechanisms
- Economy inflation controls
```

### Audit Prompt for NFT/GameFi
```
Analyze this NFT/GameFi protocol for:
1. Mint function access control and limits
2. Randomness manipulation for rare items
3. Game economy exploits
4. Metadata tampering vectors
5. Transfer restriction bypass
6. Marketplace integration security
```

---

## 8. Governance Protocols

**Example Protocols**: GMX Governance, Ethereal, DAO frameworks

### Critical Focus Areas

#### 8.1 Voting Mechanism
```
Check for:
- Vote counting accuracy
- Snapshot timing
- Flash loan voting attacks
- Vote delegation security
```

**Vulnerability Pattern**:
```solidity
// VULNERABLE: No snapshot, flash loan voting
function vote(uint256 proposalId, bool support) external {
    uint256 votes = token.balanceOf(msg.sender);  // Current balance!
    // Attacker flash loans tokens, votes, returns
}

// SECURE: Snapshot-based voting
function vote(uint256 proposalId, bool support) external {
    uint256 snapshotBlock = proposals[proposalId].snapshotBlock;
    uint256 votes = token.getPastVotes(msg.sender, snapshotBlock);
}
```

#### 8.2 Proposal Execution
```
Check for:
- Timelock enforcement
- Guardian/veto power
- Execution success verification
- Reentrancy in execution
```

#### 8.3 Parameter Changes
```
Check for:
- Rate limits on changes
- Sanity bounds on parameters
- Multi-step change requirements
```

### Audit Prompt for Governance
```
Review this governance protocol for:
1. Flash loan voting attacks
2. Proposal execution security
3. Timelock bypass vectors
4. Parameter change bounds
5. Vote delegation manipulation
6. Guardian/emergency power abuse
```

---

## Cross-Protocol Patterns

### Common Findings Across All Protocols

| Finding | Frequency | Severity |
|---------|-----------|----------|
| Missing access control | Very High | High-Critical |
| Incorrect rounding | High | Medium-High |
| Missing events | High | Low-Info |
| Unchecked return values | Medium | Medium |
| Timestamp dependence | Medium | Low-Medium |
| Gas griefing | Medium | Low-Medium |

### Universal Audit Checklist

```
For ANY protocol, always check:
 Access control on all state-changing functions
 Reentrancy protection on external calls
 Return value checks on token transfers
 Slippage/deadline protection on swaps
 Oracle staleness checks
 Proper event emission
 Pausability for emergencies
 Upgrade mechanism security (if upgradeable)
 Admin key management
 Input validation and bounds checking
```

---

## Related Skills

- [vulnerability-patterns.md](vulnerability-patterns.md) - General patterns
- [defi-vulnerabilities.md](defi-vulnerabilities.md) - DeFi patterns
- [bridge-security.md](bridge-security.md) - Bridge security
- [l2-security.md](l2-security.md) - L2 patterns

