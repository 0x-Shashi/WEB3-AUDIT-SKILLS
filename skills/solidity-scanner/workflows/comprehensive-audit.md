---
id: comprehensive-audit-workflow
title: Comprehensive Audit Workflow
category: workflow
parent_skill: solidity-scanner/SKILL.md
triggers:
  - full audit
  - comprehensive audit
  - protocol audit
  - client engagement
  - pre-launch audit
tags:
  - audit
  - comprehensive
  - workflow
  - methodology
last_updated: 2026-02-24
---

# Comprehensive Audit Workflow

## Purpose

Full in-depth security audit for protocol launches, major upgrades, or client engagements. This workflow is designed for engagements where completeness and rigor are prioritized over speed, typically spanning 4–10 days depending on codebase size.

## Scope Calibration

### Time Estimates by Codebase Size

| SLOC (in scope) | Recommended Duration | Auditors | Effort (person-days) |
|---|---|---|---|
| < 500 | 3–4 days | 1 | 3–4 |
| 500–1500 | 5–7 days | 1–2 | 5–10 |
| 1500–3000 | 7–10 days | 2 | 14–20 |
| 3000–5000 | 10–14 days | 2–3 | 20–35 |
| 5000+ | 14–21 days | 3+ | 35–60 |

### Pre-Engagement Checklist

```markdown
- [ ] Scope defined: which contracts/files are in scope
- [ ] Compiler version and optimization settings documented
- [ ] Deployment chain(s) specified (Ethereum, Arbitrum, etc.)
- [ ] Access to documentation, specs, or whitepaper
- [ ] Access to test suite (and test coverage report)
- [ ] Previous audit reports provided (if any)
- [ ] Known issues or accepted risks listed
- [ ] Point of contact for questions during audit
- [ ] Commit hash pinned for audit scope
- [ ] Deliverable format agreed (PDF, Markdown, JSON)
```

---

## Phase 1: Context Building (Day 1)

**Goal**: Understand the protocol deeply before looking for bugs. 80% of critical findings come from understanding what the protocol is *supposed* to do.

### Step 1.1: Documentation Review

```markdown
- [ ] Read all documentation: README, docs site, whitepaper
- [ ] Read deployment scripts to understand constructor args and initialization
- [ ] Read test files to understand developer's mental model
- [ ] Note any documented invariants or assumptions
```

### Step 1.2: Architecture Mapping

```markdown
- [ ] Draw contract inheritance diagram
      ContractA → ContractB → ContractC (base)
- [ ] Identify contract categories:
      Core:     Vault.sol, Pool.sol, Router.sol
      Tokens:   ShareToken.sol, RewardToken.sol
      Oracles:  PriceFeed.sol, TWAPOracle.sol
      Admin:    Timelock.sol, Governance.sol
      Libraries: Math.sol, SafeCast.sol
- [ ] Map contract interactions (which contracts call which)
- [ ] Identify proxy patterns: transparent, UUPS, beacon, diamond
- [ ] List all imported libraries and their versions
```

### Step 1.3: Entry Point Enumeration

```markdown
- [ ] List all external/public functions per contract
      Command: slither . --print function-summary
- [ ] Categorize by function type:
      User actions:    deposit(), withdraw(), swap(), claim()
      Admin actions:   setFee(), pause(), upgrade(), migrate()
      Keeper actions:  harvest(), rebalance(), liquidate()
      View functions:  balanceOf(), totalAssets(), getPrice()
- [ ] Identify which functions transfer tokens or ETH
- [ ] Identify which functions modify critical state variables
```

### Step 1.4: Dependency Analysis

```markdown
- [ ] List all external protocol integrations:
      DEX:        Uniswap V3, Curve, Balancer
      Lending:    Aave V3, Compound V3
      Oracles:    Chainlink, Pyth, UMA
      Bridging:   LayerZero, Axelar, Wormhole
- [ ] For each dependency, note:
      - Which functions are called
      - What assumptions are made about return values
      - What happens if dependency fails/pauses
      - Version of dependency being used
- [ ] Check: can any dependency be changed by admin?
```

### Step 1.5: Invariant Documentation

Write down every invariant you can identify — explicit and implicit:

```
Protocol Invariants (to verify throughout audit):
1. totalAssets >= sum of all user deposits minus withdrawals minus fees
2. totalShares == sum of all user share balances
3. No user can withdraw more than their proportional share
4. Fee cannot exceed MAX_FEE (e.g., 10%)
5. Only authorized roles can call admin functions
6. Oracle prices are always fresh and within expected range
7. Contract ETH balance should equal tracked deposits (no stuck ETH)
8. [Add protocol-specific invariants]
```

**Quality Gate**: Before proceeding to Phase 2, you should be able to explain:
- What does this protocol do in one sentence?
- How does a user make money using this protocol?
- What are the main risks for users? For the protocol?

---

## Phase 2: Automated Analysis (Day 1–2)

**Goal**: Cast a wide net with tools, then manually triage results.

### Step 2.1: Static Analysis

```bash
# Slither — comprehensive detector suite
slither . --config-file slither.config.json 2>&1 | tee slither-output.txt

# Slither — specific prints for analysis
slither . --print human-summary          # Overview of codebase
slither . --print contract-summary       # Contract hierarchy
slither . --print function-summary       # All functions with visibility
slither . --print vars-and-auth          # State variables and who can modify
slither . --print modifiers              # Modifier usage
slither . --print call-graph             # Who calls whom

# Aderyn — Rust-based, catches different patterns
aderyn . --output aderyn-report.md

# 4naly3er — gas optimizations and low-severity patterns
npx 4naly3r .
```

### Step 2.2: Symbolic Execution (for core contracts only)

```bash
# Mythril — on critical contracts (vault, pool, router)
myth analyze src/Vault.sol --solc-json mythril.config.json --execution-timeout 300
```

Only run Mythril on high-value contracts. It is slow but finds deep bugs that static analysis misses: integer overflows across multiple transactions, path constraint violations, unprotected selfdestruct paths.

### Step 2.3: Test Coverage Analysis

```bash
# Foundry coverage
forge coverage --report summary
forge coverage --report lcov

# Identify uncovered code paths — these are high-priority targets
# Lines with 0% coverage are never tested and more likely to have bugs
```

### Step 2.4: Triage Automated Findings

Create a triage table:

| # | Tool | Detector | File:Line | Verdict | Notes |
|---|------|----------|-----------|---------|-------|
| 1 | Slither | reentrancy-eth | Vault.sol:142 | TP — write finding | State update after external call |
| 2 | Slither | reentrancy-benign | Token.sol:55 | FP | Transfer to self, no callback |
| 3 | Aderyn | unchecked-return | Router.sol:88 | TP — verify | Low-level call without success check |
| 4 | Mythril | integer-overflow | Math.sol:23 | FP | Solidity 0.8+ handles this |

**Quality Gate**: All automated findings triaged as TP (true positive), FP (false positive), or needs-investigation.

---

## Phase 3: Manual Review — Access Control (Day 2)

**Goal**: Verify that only authorized users can perform privileged actions.

### Step 3.1: Role Mapping

```markdown
Document every role and its permissions:

OWNER (0x1234...):
  ├── setFee()            — can set protocol fee (bounded to MAX_FEE?)
  ├── pause()/unpause()   — can freeze all user actions
  ├── upgradeTo()         — can upgrade contract logic
  ├── setOracle()         — can change price oracle address
  └── revokeRole()        — can remove other roles

OPERATOR (0x5678...):
  ├── rebalance()         — can move funds between strategies
  └── harvest()           — can trigger yield collection

KEEPER (bot):
  ├── liquidate()         — can liquidate underwater positions
  └── compoundRewards()   — can reinvest accumulated rewards

USER (anyone):
  ├── deposit()           — provide tokens, receive shares
  ├── withdraw()          — burn shares, receive tokens
  └── transfer()          — move shares to another user
```

### Step 3.2: Access Control Verification

```markdown
For each privileged function, verify:
- [ ] Correct modifier (onlyOwner, onlyRole, etc.)
- [ ] Modifier implementation is sound (not bypassable)
- [ ] Role assignment is protected (only admin can grant roles)
- [ ] Role revocation works correctly
- [ ] Two-step ownership transfer (if applicable)
- [ ] Address(0) cannot hold roles

For each admin power, assess impact:
- [ ] Can admin steal user funds? (If yes → centralization risk)
- [ ] Can admin freeze user funds indefinitely? (If yes → centralization risk)
- [ ] Can admin change critical parameters without timelock?
- [ ] Is there a MAX bound on admin-settable fees/rates?
```

### Step 3.3: Initialization & Upgrade Safety

```markdown
- [ ] All initializable contracts use initializer modifier
- [ ] initializer prevents re-initialization
- [ ] Base contracts use onlyInitializing
- [ ] _disableInitializers() in constructor (UUPS/TransparentProxy)
- [ ] Storage layout is compatible between upgrade versions
    - No reordering of existing state variables
    - New variables added at the end only
    - __gap arrays present in upgradeable base contracts
- [ ] upgradeTo/upgradeToAndCall has correct access control
- [ ] Implementation contracts cannot be initialized directly
```

**Quality Gate**: Complete role-permission matrix documented. All admin powers with centralization risk flagged.

---

## Phase 4: Manual Review — Core Logic (Day 2–3)

**Goal**: Verify that every computation, state transition, and business logic rule is correct.

### Step 4.1: Token Flow Tracing

For each user action that moves tokens, trace the full path:

```
DEPOSIT PATH:
1. User calls deposit(assets, receiver)
2. Require checks: amount > 0, not paused
3. Calculate shares: assets * totalSupply / totalAssets
4. Rounding: round DOWN (fewer shares = safe for vault)
5. State update: _mint(receiver, shares)
6. Token transfer: safeTransferFrom(msg.sender, address(this), assets)
7. Event: emit Deposit(msg.sender, receiver, assets, shares)

VERIFY:
- [ ] CEI pattern maintained (checks → effects → interactions)?
- [ ] Rounding direction favors the protocol?
- [ ] State accurately reflects deposited amount?
- [ ] Fee-on-transfer tokens would cause accounting mismatch?
```

### Step 4.2: Mathematical Verification

```markdown
For each formula in the protocol:

1. Share Calculation
   Formula: shares = assets * totalSupply / totalAssets
   Edge cases:
   - [ ] totalAssets = 0 → division by zero
   - [ ] totalSupply = 0 → first-depositor scenario
   - [ ] Very large values → multiplication overflow (mulDiv?)
   - [ ] Rounding: always in protocol's favor?

2. Interest/Reward Accrual
   Formula: reward = principal * rate * timeDelta / SECONDS_PER_YEAR
   Edge cases:
   - [ ] rate = 0 → no rewards (correct)
   - [ ] timeDelta very large → overflow
   - [ ] Multiple compounds per block → compounding difference
   - [ ] Precision: sufficient decimals to avoid truncating to 0?

3. Liquidation Threshold
   Formula: healthFactor = collateralValue * LTV / debtValue
   Edge cases:
   - [ ] debtValue = 0 → division by zero
   - [ ] Price flash crash → cascading liquidations
   - [ ] Partial liquidation → does it improve health factor?
```

### Step 4.3: Reentrancy Analysis

```markdown
Check EVERY external call (transfers, callbacks, cross-contract calls):

For each external call:
1. Is there state that was read BEFORE the call but updated AFTER?
2. Can the callee re-enter this contract or any related contract?
3. Are there nonReentrant guards? On which functions?
4. Cross-contract: does Contract A call Contract B, which calls back to A?

External call types to check:
- [ ] ERC20.transfer / safeTransfer → no callback (safe)
- [ ] ERC20.safeTransferFrom → no callback (safe)
- [ ] ETH transfer via call{value:} → CALLBACK POSSIBLE
- [ ] ERC721.safeTransferFrom → onERC721Received callback
- [ ] ERC777.send → tokensReceived callback
- [ ] ERC1155.safeTransferFrom → onERC1155Received callback
- [ ] External contract call → arbitrary callback possible
- [ ] Flash loan callback → borrower executes arbitrary code

Dangerous pattern:
    function withdraw(uint256 shares) external {
        uint256 assets = convertToAssets(shares); // READ state
        (bool ok,) = msg.sender.call{value: assets}(""); // EXTERNAL CALL
        _burn(msg.sender, shares); // WRITE state AFTER call ← BUG
    }

Safe pattern (CEI):
    function withdraw(uint256 shares) external nonReentrant {
        uint256 assets = convertToAssets(shares); // READ
        _burn(msg.sender, shares); // WRITE (effect before interaction)
        (bool ok,) = msg.sender.call{value: assets}(""); // EXTERNAL CALL
        require(ok);
    }
```

### Step 4.4: State Machine Verification

```markdown
If the protocol has entities with states (orders, positions, proposals):

1. Define the state machine:
   PROPOSED → ACTIVE → EXECUTED
   PROPOSED → CANCELLED
   ACTIVE → EXPIRED

2. For each transition, verify:
   - [ ] Only valid transitions are possible
   - [ ] Authorization is correct for each transition
   - [ ] State data is correctly updated
   - [ ] Tokens/ETH are correctly handled at each transition

3. Check for stuck states:
   - [ ] Can any entity become permanently locked?
   - [ ] Is there an emergency escape mechanism?
   - [ ] What happens if a dependency goes down during a transition?
```

**Quality Gate**: All token paths traced. All formulas verified with edge cases. All external calls checked for reentrancy.

---

## Phase 5: Manual Review — External Interactions (Day 3)

**Goal**: Verify that integrations with oracles, DEXes, lending protocols, and bridges are safe.

### Step 5.1: Oracle Security

```markdown
Chainlink Integration:
- [ ] latestRoundData() used (not latestAnswer())
- [ ] All 5 return values checked:
      (uint80 roundId, int256 answer, uint256 startedAt,
       uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
- [ ] answer > 0 check present
- [ ] Staleness check: block.timestamp - updatedAt <= HEARTBEAT
- [ ] HEARTBEAT matches actual Chainlink heartbeat for this feed:
      ETH/USD: 3600s (1 hour)
      BTC/USD: 3600s
      Stablecoin/USD: 86400s (24 hours)
- [ ] Sequencer uptime feed checked (L2s: Arbitrum, Optimism, Base)
- [ ] Decimal handling correct (most Chainlink feeds return 8 decimals)

DEX Price Integration:
- [ ] NOT using spot price (slot0, getReserves)
- [ ] Using TWAP with adequate time window (≥ 30 minutes)
- [ ] Flash loan resistance verified
- [ ] Low-liquidity manipulation risk assessed

Multi-Oracle Setup:
- [ ] Fallback oracle in case primary fails
- [ ] Deviation check between oracles
- [ ] Circuit breaker if price moves too far too fast
```

### Step 5.2: Token Compatibility

```markdown
If protocol accepts arbitrary ERC20 tokens, check compatibility with:

Standard ERC20:            USDC, WETH, DAI — expected behavior
Fee-on-transfer:           USDT (with fee flag), STA, PAXG
  → balance before/after transfer differs from amount parameter
  → Protocol must use pre/post balance check, not transfer amount

Rebasing tokens:           stETH, AMPL, OHM
  → balanceOf() changes without transfer
  → Internal accounting becomes stale

ERC20 with no return value: USDT (doesn't return bool on transfer)
  → Must use SafeERC20.safeTransfer, not raw transfer()

ERC20 with > 18 decimals:  YAM (24 decimals)
  → Multiplication overflow risk

ERC20 with < 6 decimals:   GUSD (2 decimals)
  → Precision loss in calculations

Tokens with blocklists:    USDC, USDT — can block addresses
  → User funds can become stuck if address is blocklisted

Tokens with permit:        DAI (non-standard), USDC, most modern ERC20
  → Check for permit front-running
  → Permit replay across chains (check chainId in domain separator)

Upgradeable tokens:        USDC, USDT
  → Behavior can change post-deployment without protocol code change
```

### Step 5.3: Flash Loan Resistance

```markdown
For each user action that reads and acts on external state:
- [ ] Can the external state be manipulated via flash loan?
- [ ] Is there a multi-block delay requirement?
- [ ] Does the protocol use time-weighted data?

Common flash loan attack surfaces:
1. DEX spot price → use TWAP instead
2. Token balance in pool → don't use pool balance as price input
3. Governance voting → snapshot-based voting, not live balance
4. Collateral ratio → use oracle price, not market price
```

### Step 5.4: MEV and Front-Running

```markdown
- [ ] Can user transactions be sandwiched?
    Deposit: user deposits at price X, front-runner moves price first
    Swap: user swaps with slippage, front-runner captures the difference
- [ ] Are there deadline parameters on time-sensitive operations?
    Missing deadline → transaction can be held and executed later
- [ ] Is there slippage protection?
    Missing minAmountOut → user can receive 0 tokens
- [ ] Commit-reveal scheme where needed?
    Auctions, voting, random reveals
```

**Quality Gate**: All oracle integrations verified. Token compatibility matrix completed. Flash loan attack surfaces assessed.

---

## Phase 6: Attack Chains (Day 3–4)

**Goal**: Combine individual observations into multi-step attack scenarios.

### Step 6.1: Build Attack Scenarios

For each potential attack, write a structured scenario:

```markdown
Attack Scenario: Flash Loan Oracle Manipulation

Prerequisites:
- Protocol uses Uniswap V2 spot price for collateral valuation
- Attacker can take flash loan from Aave/dYdX

Attack Steps:
1. Attacker takes flash loan of 10,000 ETH from Aave
2. Attacker dumps ETH into Uniswap V2 ETH/TOKEN pool
3. TOKEN price pumps relative to ETH (spot manipulation)
4. Attacker deposits TOKEN as collateral (valued at inflated price)
5. Attacker borrows ETH against inflated collateral
6. Attacker repays flash loan
7. Protocol is left with under-collateralized position

Impact: Attacker drains lending pool. Loss = borrowed amount - flash loan fee.

Mitigation: Use Chainlink oracle or Uniswap V3 TWAP (≥ 30 min window).
```

### Step 6.2: Validate with PoC (Proof of Concept)

Write a Foundry test for each viable attack chain:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract OracleManipulationPoC is Test {
    // Protocol contracts
    IVault vault;
    IOracle oracle;

    // External protocols
    IUniswapV2Pair pair;

    address attacker = makeAddr("attacker");

    function setUp() public {
        // Fork mainnet at specific block
        vm.createSelectFork("mainnet", 18_500_000);

        // Deploy or reference protocol contracts
        vault = IVault(0x...);
        oracle = IOracle(0x...);
        pair = IUniswapV2Pair(0x...);
    }

    function test_OracleManipulation() public {
        // Record state before attack
        uint256 vaultBalanceBefore = IERC20(token).balanceOf(address(vault));

        vm.startPrank(attacker);

        // Step 1: Flash loan (simulated with deal)
        deal(address(weth), attacker, 10_000 ether);

        // Step 2: Manipulate pool price
        weth.transfer(address(pair), 10_000 ether);
        pair.swap(0, amountOut, attacker, "");

        // Step 3: Deposit at inflated price
        token.approve(address(vault), type(uint256).max);
        vault.deposit(tokenAmount, attacker);

        // Step 4: Borrow against inflated collateral
        vault.borrow(borrowAmount, attacker);

        vm.stopPrank();

        // Verify: vault lost funds
        uint256 vaultBalanceAfter = IERC20(token).balanceOf(address(vault));
        assertLt(vaultBalanceAfter, vaultBalanceBefore, "Vault should have lost funds");
    }
}
```

### Step 6.3: Common Attack Chain Templates

```markdown
1. Flash Loan + Oracle Manipulation (lending/vaults)
2. Share Inflation + First Depositor (ERC4626 vaults)
3. Cross-Function Reentrancy + State Desync (DeFi protocols)
4. Governance Flashloan + Instant Execution (DAOs)
5. Bridge Message Replay + Chain Fork (cross-chain)
6. Liquidation Cascade + Oracle Delay (lending)
7. Sandwich + Missing Slippage (DEX routers)
8. Donation + Exchange Rate Manipulation (yield vaults)
9. Storage Collision + Proxy Upgrade (upgradeable contracts)
10. Permit Replay + Cross-Chain Deployment (multi-chain)
```

**Quality Gate**: All viable attack chains documented with impact assessment. PoC written for each confirmed vulnerability.

---

## Phase 7: Report Writing (Day 4+)

**Goal**: Produce a clear, actionable report that helps the development team fix every issue.

### Finding Template

````markdown
## [S-01] Title: Brief Description of the Vulnerability

### Severity: Critical / High / Medium / Low / Informational

### Description
[2-3 sentences explaining the vulnerability, what code is affected, and why it's a problem]

### Impact
[Concrete impact: "Attacker can drain X from vault" or "Users can lose deposited funds"]

### Affected Code
[Link to file and line number]
```solidity
// Vulnerable code
function withdraw(uint256 shares) external {
    uint256 assets = convertToAssets(shares);
    IERC20(token).safeTransfer(msg.sender, assets); // external call
    _burn(msg.sender, shares); // state update AFTER external call
}
```

### Proof of Concept
[Foundry test or step-by-step reproduction]

### Recommended Fix
```solidity
// Fixed code
function withdraw(uint256 shares) external nonReentrant {
    uint256 assets = convertToAssets(shares);
    _burn(msg.sender, shares); // state update BEFORE external call
    IERC20(token).safeTransfer(msg.sender, assets);
}
```

### References
- [Link to similar past exploit or audit finding]
````

### Report Structure

```markdown
1. Executive Summary
   - Protocol overview (1 paragraph)
   - Audit scope and methodology
   - Key findings summary table
   - Overall risk assessment

2. Findings Summary Table
   | ID | Title | Severity | Status |
   |----|-------|----------|--------|
   | C-01 | Oracle manipulation drains vault | Critical | Open |
   | H-01 | Reentrancy in withdraw | High | Open |
   | M-01 | Missing slippage protection | Medium | Open |

3. Detailed Findings (grouped by severity)
   - Critical
   - High
   - Medium
   - Low
   - Informational

4. Centralization Risks (explicit section)

5. Systemic Risks & Recommendations

6. Appendix
   - Tool outputs
   - Test coverage report
   - Gas optimization suggestions
```

### Quality Checklist for Report

```markdown
- [ ] Every finding has: title, severity, description, impact, affected code, PoC, fix
- [ ] Severity is justified per platform criteria (see severity-guide.md)
- [ ] No duplicate findings (same root cause = one finding)
- [ ] Fix recommendations are specific and correct (verified they don't introduce new bugs)
- [ ] Code references point to correct file and line number
- [ ] Executive summary is understandable by non-technical stakeholders
- [ ] Spelling and grammar checked
- [ ] PoC tests pass when run against audited commit
```

---

## Post-Audit: Fix Review

After the development team applies fixes, perform a fix review:

```markdown
For each finding:
- [ ] Fix addresses the root cause (not just the symptom)
- [ ] Fix is complete (all instances of the pattern are fixed)
- [ ] Fix does not introduce new vulnerabilities
- [ ] Fix does not break existing functionality (tests still pass)
- [ ] Fix is minimal (no unnecessary code changes mixed in)

See: fix-review/SKILL.md for detailed fix review methodology
```

## Deliverables

| Deliverable | Format | Contents |
|---|---|---|
| Audit Report | PDF + Markdown | Full findings, PoCs, fixes, executive summary |
| Findings Sheet | CSV/JSON | Machine-readable finding list with severity, status |
| Fix Recommendations | Inline in report | Specific code changes per finding |
| Executive Summary | 1-page PDF | Non-technical summary for stakeholders |
| Test Coverage Report | HTML/Markdown | Coverage metrics pre-audit |
| Invariant Test Suite | Foundry tests | Reusable security invariant tests (optional) |
