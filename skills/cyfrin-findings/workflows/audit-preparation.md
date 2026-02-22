---
id: CYFRIN-WF-AUDIT-PREP
title: Audit Preparation Workflow
parent: cyfrin-findings
type: workflow
last_updated: 2025-01-31
---

# Audit Preparation Workflow

Use the Solodit findings database to build a targeted threat model and audit checklist **before** starting code review. This workflow turns 50,530+ historical findings into a protocol-specific pre-audit brief.

---

## When to Use

- At the start of any new smart contract audit engagement
- When onboarding to a protocol type you haven't audited before
- When refreshing your knowledge before a re-audit of an upgraded protocol

---

## Prerequisites

- Solodit API key (set in `X-API-Key` header)
- Protocol type identified (lending, DEX, bridge, yield, governance, etc.)
- Target chain identified (Ethereum, Arbitrum, Optimism, etc.)
- Protocol documentation/README reviewed for architecture understanding

---

## Workflow Steps

### Step 1: Identify Protocol Type and Architecture

Before querying, classify the protocol:

| Protocol Feature | Classification |
|------------------|---------------|
| Users deposit collateral and borrow | **Lending** |
| Token swaps via liquidity pools | **DEX / AMM** |
| Moves tokens between L1 and L2 (or L2 to L2) | **Bridge** |
| Users deposit tokens to earn yield | **Yield / Vault** |
| Token holders vote on proposals | **Governance** |
| Manages a stablecoin peg | **Stablecoin** |
| Tokenizes real-world assets | **RWA** |
| Trades futures/options/perpetuals | **Derivatives** |

Many protocols span multiple categories (e.g., Aave is Lending + Governance + Yield). Query each category separately.

### Step 2: Query Historical Findings for Protocol Type

```bash
# Get critical and high findings for the protocol type
GET /findings?protocol_type=lending&severity=critical&per_page=50&sort=severity_desc
GET /findings?protocol_type=lending&severity=high&per_page=50&sort=severity_desc

# Get all findings for similar protocols by name
GET /findings?protocol=compound&per_page=50
GET /findings?protocol=aave&per_page=50
```

Parse the results and group by vulnerability category:

```
Example output for protocol_type=lending:
├── oracle-manipulation: 145 findings (32%)
├── liquidation-logic: 108 findings (24%)  
├── access-control: 81 findings (18%)
├── interest-rate-calculation: 63 findings (14%)
├── reentrancy: 54 findings (12%)
├── flash-loan: 38 findings
├── rounding/precision: 29 findings
├── token-integration: 22 findings
└── governance: 15 findings
```

### Step 3: Extract Top Risk Areas

From the frequency analysis, identify the top 5 vulnerability categories for this protocol type. These become your primary focus areas during code review.

**Lending Protocol Example — Top 5 Risk Areas:**

1. **Oracle Manipulation** (32% of historical findings)
   - Missing freshness checks on Chainlink `latestRoundData()`
   - Spot price manipulation via flash loans
   - Incorrect decimal handling across different price feeds
   - Missing sequencer uptime checks on L2 chains

2. **Liquidation Logic** (24%)
   - Incorrect health factor calculation
   - Liquidation front-running (MEV)
   - Bad debt socialization errors
   - Partial liquidation precision loss

3. **Access Control** (18%)
   - Unprotected admin functions
   - Missing role checks on critical state changes
   - Proxy initializer front-running

4. **Interest Rate Calculation** (14%)
   - Compound interest rounding errors
   - Rate model manipulation via large deposits/withdrawals
   - Utilization rate edge cases at 0% and 100%

5. **Reentrancy** (12%)
   - Cross-function reentrancy via token callbacks
   - Read-only reentrancy affecting price calculations
   - ERC777/ERC721 callback reentrancy

### Step 4: Build Targeted Checklist

Convert each risk area into specific checklist items based on the historical findings:

```markdown
## Pre-Audit Checklist: Lending Protocol

### Oracle Security
- [ ] Chainlink `latestRoundData()` — check `updatedAt` freshness
- [ ] Chainlink `latestRoundData()` — check `answeredInRound >= roundId`
- [ ] Price feed decimal normalization across different assets
- [ ] L2 sequencer uptime check (Arbitrum/Optimism)
- [ ] Fallback oracle mechanism if primary feed fails
- [ ] TWAP vs spot price — verify manipulation resistance

### Liquidation Logic
- [ ] Health factor calculation — verify formula correctness
- [ ] Liquidation bonus — check it doesn't exceed collateral
- [ ] Partial liquidation — verify rounding doesn't leave dust
- [ ] Bad debt handling — what happens when collateral < debt?
- [ ] Liquidation front-running — are there MEV protections?
- [ ] Self-liquidation — can a user liquidate themselves profitably?

### Access Control
- [ ] Initializer — protected against front-running?
- [ ] Admin functions — proper role checks?
- [ ] Pause mechanism — who can pause/unpause?
- [ ] Upgrade mechanism — timelock on proxy upgrades?
- [ ] Emergency withdrawal — proper access control?

### Interest Rate
- [ ] Utilization rate — edge cases at 0% and 100%
- [ ] Interest accrual — compound vs simple, rounding direction
- [ ] Rate model — can it be manipulated via flash loans?
- [ ] Interest index — overflow protection for long-running markets

### Reentrancy
- [ ] External calls — CEI pattern followed?
- [ ] Token callbacks — ERC721/ERC777 receive hooks
- [ ] Read-only reentrancy — view functions used in state-changing contexts
- [ ] Cross-contract reentrancy — calls between protocol modules
```

### Step 5: Identify Common False Positives

Historical findings also reveal common false positives for each protocol type — issues that look like vulnerabilities but aren't:

| False Positive | Why It's Not Exploitable |
|----------------|--------------------------|
| "Centralization risk — admin can rug" | Intentional design in many protocols; documented in protocol docs |
| "Missing zero-address check in constructor" | Constructor is called once at deployment by deployer |
| "Floating pragma" | Low risk if testing covers the deployed compiler version |
| "No events emitted" | Informational unless the protocol relies on event-based indexing |

### Step 6: Compile Pre-Audit Brief

Combine all findings into a structured brief:

```markdown
# Pre-Audit Brief: [Protocol Name]

## Protocol Type: Lending
## Chain: Ethereum + Arbitrum
## Date: [Date]

## Historical Context
- [X] findings analyzed from Solodit database for lending protocols
- Top risk areas: Oracle (32%), Liquidation (24%), Access Control (18%)
- Similar protocols audited: Aave (87 findings), Compound (62 findings)

## Priority Focus Areas
1. Oracle integration — especially Chainlink freshness and L2 sequencer
2. Liquidation mechanics — health factor, bad debt, MEV protection
3. Access control — initializer protection, admin role management

## Targeted Checklist
[Include checklist from Step 4]

## Known False Positives
[Include table from Step 5]

## Reference Findings
[Include links to most relevant historical findings]
```

---

## Integration with Other Skills

| Skill | How It Connects |
|-------|----------------|
| `checklists/` | Use generated checklist as input to formal checklist templates |
| `protocol-playbooks/` | Cross-reference with protocol-specific playbook for the type |
| `attack-trees/` | Map top risk areas to attack tree nodes with probability weights |
| `patterns/` | Deep-dive into each top vulnerability category using pattern files |
| `scoring/` | Use historical finding density to weight risk scores |

---

## Time Budget

| Step | Estimated Time |
|------|---------------|
| Step 1: Protocol classification | 5 minutes |
| Step 2: Database querying | 10 minutes |
| Step 3: Risk area extraction | 15 minutes |
| Step 4: Checklist building | 20 minutes |
| Step 5: False positives | 5 minutes |
| Step 6: Brief compilation | 15 minutes |
| **Total** | **~70 minutes** |
