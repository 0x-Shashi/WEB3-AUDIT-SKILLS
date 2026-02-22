---
id: CYFRIN-WF-PRE-DEV
title: Pre-Development Security Research Workflow
parent: cyfrin-findings
type: workflow
last_updated: 2025-01-31
---

# Pre-Development Research Workflow

Use the Solodit findings database **before writing smart contract code** to learn what goes wrong in similar protocols, build security requirements from historical failures, and create test cases based on real attack vectors. This shifts security left — preventing vulnerabilities instead of finding them.

---

## When to Use

- Before starting development of a new smart contract or protocol
- When adding a new feature to an existing protocol (e.g., adding liquidation to a lending protocol)
- When integrating with external protocols (DEXs, oracles, bridges)
- When choosing between different implementation approaches (e.g., ERC4626 vs custom vault)

---

## Workflow Steps

### Step 1: Classify Your Protocol

Determine which protocol categories apply to what you're building:

```
Building a lending protocol?
  → Query: protocol_type=lending
  → Also check: oracle-manipulation, liquidation, interest-rate

Building a DEX/AMM?
  → Query: protocol_type=dex
  → Also check: slippage, mev, flash-loan, token-integration

Building a vault/yield aggregator?
  → Query: protocol_type=yield
  → Also check: erc4626, first-depositor, reward-distribution

Building a bridge?
  → Query: protocol_type=bridge
  → Also check: replay-attack, message-verification, finality

Building a governance system?
  → Query: protocol_type=governance
  → Also check: flash-loan-voting, timelock, quorum
```

### Step 2: Compile Historical Vulnerabilities for Your Protocol Type

Query the database for all Critical and High findings in your protocol category:

```bash
# Get all critical + high findings for your protocol type
GET /findings?protocol_type=lending&severity=critical&per_page=100&sort=date_desc
GET /findings?protocol_type=lending&severity=high&per_page=100&sort=date_desc
```

Organize findings by the specific feature/component they affect:

**Example for Lending Protocol:**

| Component | Finding Count | Top Issue |
|-----------|---------------|-----------|
| Price Oracle integration | 145 | Missing freshness check |
| Liquidation engine | 108 | Incorrect health factor math |
| Interest rate model | 63 | Rounding direction errors |
| Collateral management | 54 | Reentrancy via token callbacks |
| Borrow/repay logic | 38 | Flash loan manipulation |
| Admin functions | 81 | Missing access control |
| Token accounting | 29 | Fee-on-transfer token handling |

### Step 3: Build Security Requirements from Findings

Convert each historical vulnerability category into a concrete security requirement:

```markdown
## Security Requirements: Lending Protocol

### REQ-ORACLE-001: Price Feed Freshness
All Chainlink price feeds MUST validate the `updatedAt` timestamp.
Stale prices (older than configurable threshold) MUST revert.
Source: 145+ oracle manipulation findings in Solodit database.

### REQ-ORACLE-002: L2 Sequencer Check
On L2 deployments (Arbitrum, Optimism), the sequencer uptime feed 
MUST be checked before using any Chainlink price data.
Source: Multiple L2-specific findings where sequencer downtime caused stale prices.

### REQ-ORACLE-003: Fallback Oracle
The system MUST have a fallback oracle mechanism (e.g., TWAP from Uniswap V3) 
if the primary Chainlink feed becomes unavailable.
Source: Single-oracle-dependency findings across 20+ protocols.

### REQ-LIQ-001: Health Factor Calculation
Health factor MUST be calculated as: 
(collateral_value * liquidation_threshold) / debt_value
Rounding MUST favor the protocol (round down health factor).
Source: 108 liquidation logic findings.

### REQ-LIQ-002: Bad Debt Handling
The system MUST handle scenarios where collateral value < debt value.
Bad debt MUST be socialized across depositors or covered by a reserve fund.
Source: Multiple "bad debt" findings in Aave, Compound forks.

### REQ-REENT-001: CEI Pattern
All external calls MUST follow Checks-Effects-Interactions pattern.
All state-changing functions that make external calls MUST use ReentrancyGuard.
Source: 59 reentrancy findings, 66% rated HIGH severity.

### REQ-TOKEN-001: Non-Standard ERC20 Handling
The system MUST handle fee-on-transfer tokens (actual received != amount passed).
The system MUST handle rebasing tokens (balance changes without transfer).
The system MUST handle tokens with non-standard decimals (not 18).
Source: 22+ token integration findings across lending protocols.

### REQ-ACCESS-001: Initializer Protection
All proxy-pattern contracts MUST protect initializers against front-running.
Use OpenZeppelin's `initializer` modifier on init functions.
Source: 81 access control findings, multiple "front-run initialize" Critical findings.

### REQ-MATH-001: Rounding Direction
Division operations MUST round in favor of the protocol:
- Share calculation: round DOWN when minting, round UP when burning
- Interest accrual: round UP (protocol collects more)
- Collateral ratio: round DOWN (more conservative)
Source: 29 precision/rounding findings across lending and vault protocols.
```

### Step 4: Design Secure Architecture from Day One

Use findings data to make architectural decisions:

| Decision | Insecure Choice | Secure Choice | Finding Evidence |
|----------|----------------|---------------|------------------|
| Oracle design | Single spot price (e.g., `getReserves()`) | TWAP + Chainlink with freshness check | 145+ oracle findings |
| Reentrancy protection | No guard on external calls | CEI + OpenZeppelin ReentrancyGuard on all state-changing functions | 59 reentrancy findings |
| Token accounting | Trust `msg.value` or `amount` parameter | Measure actual balance change: `balanceAfter - balanceBefore` | 22+ token integration findings |
| Access control | Custom role checks | OpenZeppelin AccessControl or Ownable2Step | 81 access control findings |
| Upgrade mechanism | UUPS without timelock | TransparentUpgradeableProxy with 48h timelock | Multiple proxy upgrade findings |
| Share pricing | Simple `totalAssets / totalSupply` | Add virtual shares/assets offset (EIP-4626 inflation protection) | 28 ERC4626 findings |

### Step 5: Create Test Cases from Historical Attack Vectors

For each security requirement, derive specific test cases based on real attacks:

```solidity
// Test derived from: REQ-ORACLE-001 (Price Feed Freshness)  
// Based on: 145+ oracle manipulation findings
function test_staleOracleReverts() public {
    // Advance time beyond freshness threshold
    vm.warp(block.timestamp + STALENESS_THRESHOLD + 1);
    
    // Oracle should revert on stale price
    vm.expectRevert("Stale price");
    oracle.getPrice(address(token));
}

// Test derived from: REQ-REENT-001 (CEI Pattern)
// Based on: Reentrancy finding in Backed Protocol (Code4rena)
function test_reentrancyProtection() public {
    // Deploy attacker contract that tries reentrant call
    ReentrancyAttacker attacker = new ReentrancyAttacker(address(pool));
    
    // Fund attacker
    token.transfer(address(attacker), 100e18);
    
    // Attempt reentrant attack — should fail
    vm.expectRevert(); // ReentrancyGuard or state inconsistency
    attacker.attack();
}

// Test derived from: REQ-TOKEN-001 (Fee-on-Transfer Tokens)
// Based on: Token integration findings across 20+ protocols
function test_feeOnTransferTokenHandling() public {
    // Deploy fee-on-transfer token (2% fee)
    FeeToken feeToken = new FeeToken(2);
    
    // Deposit 100 tokens — only 98 should be credited
    feeToken.approve(address(pool), 100e18);
    pool.deposit(address(feeToken), 100e18);
    
    // Verify actual balance, not parameter value
    assertEq(pool.deposits(address(this)), 98e18);
}

// Test derived from: REQ-LIQ-002 (Bad Debt Handling)
// Based on: Bad debt findings in Aave, Compound forks
function test_badDebtSocialization() public {
    // Create undercollateralized position (price crash)
    oracle.setPrice(address(collateral), 1); // Price crashes to near-zero
    
    // Liquidate — collateral < debt, creating bad debt
    pool.liquidate(borrower);
    
    // Verify bad debt is handled (not silently ignored)
    assertTrue(pool.badDebt() > 0 || pool.reserveFund() < initialReserve);
}

// Test derived from: REQ-MATH-001 (Rounding Direction)
// Based on: First depositor attack findings (28 ERC4626 findings)
function test_firstDepositorInflationAttack() public {
    // Attacker deposits 1 wei
    vm.prank(attacker);
    vault.deposit(1, attacker);
    
    // Attacker donates large amount directly to vault
    token.transfer(address(vault), 10000e18);
    
    // Victim deposits — should NOT lose funds to rounding
    vm.prank(victim);
    uint256 shares = vault.deposit(10000e18, victim);
    
    // Victim should receive proportional shares (not zero)
    assertTrue(shares > 0);
    assertTrue(vault.previewRedeem(shares) >= 9999e18); // Near full value
}
```

### Step 6: Reference During Development

Keep the security requirements and test cases accessible during development:

```
project/
├── docs/
│   ├── SECURITY-REQUIREMENTS.md    ← Generated in Step 3
│   └── THREAT-MODEL.md             ← From audit-preparation workflow
├── test/
│   ├── security/
│   │   ├── Reentrancy.t.sol        ← From Step 5
│   │   ├── OracleManipulation.t.sol
│   │   ├── AccessControl.t.sol
│   │   └── TokenIntegration.t.sol
│   └── unit/
│       └── ...
└── src/
    └── ...
```

---

## Integration with Other Skills

| Skill | Integration Point |
|-------|-------------------|
| `patterns/` | Reference specific vulnerability patterns during architectural decisions |
| `checklists/` | Use security requirements as a dev-time checklist |
| `fix-patterns/` | Apply proven fix patterns from the start instead of patching later |
| `anti-patterns/` | Avoid known anti-patterns during initial development |
| `methodology/` | Follow secure development methodology from design through deployment |

---

## Time Budget

| Step | Estimated Time |
|------|---------------|
| Step 1: Protocol classification | 5 minutes |
| Step 2: Historical data gathering | 15 minutes |
| Step 3: Security requirements | 30 minutes |
| Step 4: Architecture decisions | 30 minutes |
| Step 5: Test case creation | 45 minutes |
| Step 6: Documentation setup | 15 minutes |
| **Total** | **~2.5 hours** |

This upfront investment prevents vulnerabilities that would cost **10x–100x more** to fix if discovered during a post-development audit.
