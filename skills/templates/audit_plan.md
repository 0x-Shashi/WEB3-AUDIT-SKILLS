# Audit Plan: [Protocol Name]

<!--
  WHAT: Your roadmap for the security audit. Tracks phases, attack tree progress, and deliverables.
  WHY: Context resets after ~50 tool calls. This file keeps your audit goals and progress persistent.
  WHEN: Create FIRST before exploring any code. Update after each phase completes.
-->

## Protocol Info

| Field | Value |
|-------|-------|
| **Protocol** | [Name] |
| **Type** | Lending / DEX / Bridge / Vault / Stablecoin / Perpetuals / Other |
| **Chain(s)** | Ethereum / Arbitrum / Optimism / Polygon / etc. |
| **Commit** | [commit hash] |
| **Scope** | [contracts in scope] |
| **Timeline** | [start date] - [end date] |

## Goal

<!--
  One clear sentence describing the audit deliverable.
  EXAMPLE: "Complete security assessment of Aave V3 fork with focus on oracle integration and liquidation logic."
-->
Complete security assessment of [Protocol] with focus on [High-Value Targets].

## Current Phase

<!--
  Quick reference for where you are. Update as you progress.
-->
Phase 1: Protocol Understanding

## Phases

### Phase 1: Protocol Understanding
<!--
  GOAL: Build mental model of the protocol before hunting bugs.
  DELIVERABLE: Filled threat_model.md, identified attack tree to follow.
-->
- [ ] Read whitepaper/docs
- [ ] Identify protocol type (Lending/DEX/Bridge/etc.)
- [ ] Load attack tree from `attack-trees/` folder
- [ ] Fill out `threat_model.md`
- [ ] Identify high-value targets (TVL handlers, oracles, admin functions)
- **Status:** in_progress

### Phase 2: Attack Surface Mapping
<!--
  GOAL: Systematically walk the attack tree branches.
  DELIVERABLE: Checked branches marked below, suspicious code in findings_report.md.
-->
- [ ] Follow attack tree branches systematically
- [ ] Mark checked branches in "Attack Tree Progress" section
- [ ] Document suspicious code in `findings_report.md`
- [ ] Apply anti-patterns from `anti-patterns/` folder
- **Status:** pending

### Phase 3: PoC Development
<!--
  GOAL: Verify findings are exploitable with Foundry tests.
  DELIVERABLE: Working PoC for each High/Critical finding.
-->
- [ ] Write Foundry tests for each finding
- [ ] Verify exploitability
- [ ] Calculate profit/loss for each exploit
- [ ] Update `progress.md` exploit attempts table
- **Status:** pending

### Phase 4: Report Generation
<!--
  GOAL: Compile professional audit report.
  DELIVERABLE: Complete findings with severity, recommendations, and fixes.
-->
- [ ] Compile findings with severity using CVSS
- [ ] Add root cause analysis
- [ ] Add recommendations for each finding
- [ ] Final review
- **Status:** pending

---

## Attack Tree Progress

<!--
  CHECK OFF branches as you review them.
  Copy from the relevant attack-trees/*.md file based on protocol type.
  
  EXAMPLE for Lending:
  Load from: attack-trees/lending-attack-tree.md
-->

### [A] Oracle Manipulation
- [ ] [A1] Stale Oracle Price
- [ ] [A2] Flash Loan + Spot Price Manipulation
- [ ] [A3] Zero/Negative Price
- [ ] [A4] No Fallback Oracle
- [ ] [A5] No Deviation Check

### [B] Liquidation Mechanism
- [ ] [B1] Self-Liquidation
- [ ] [B2] Liquidation DoS
- [ ] [B3] MEV Liquidation Front-Running
- [ ] [B4] Cascading Liquidations

### [C] Accounting/Shares
- [ ] [C1] First Depositor Attack
- [ ] [C2] Rounding Direction Errors
- [ ] [C3] Interest Rate Manipulation
- [ ] [C4] Donation Attack

### [D] Reentrancy
- [ ] [D1] Classic State-After-External-Call
- [ ] [D2] Cross-Function Reentrancy
- [ ] [D3] Read-Only Reentrancy
- [ ] [D4] ERC777/ERC1155 Callback Reentrancy

### [E] Flash Loan Attacks
- [ ] [E1] Flash Loan Governance Voting
- [ ] [E2] Interest Rate Spike
- [ ] [E3] Flash Loan + Oracle

### [F] Access Control
- [ ] [F1] Unprotected Initialize
- [ ] [F2] Missing Modifiers
- [ ] [F3] tx.origin Authentication

### [G] Economic/MEV
- [ ] [G1] Sandwich Attacks
- [ ] [G2] JIT Liquidity
- [ ] [G3] Backrunning

---

## Key Questions

<!--
  Questions to answer during the audit.
  EXAMPLE:
    1. What oracle does this protocol use? (Chainlink, Uniswap TWAP, custom)
    2. Are there any tokens with non-standard behavior? (fee-on-transfer, rebasing)
    3. What admin privileges exist? (pause, upgrade, parameter changes)
-->
1. [Question to answer]
2. [Question to answer]
3. [Question to answer]

## Contracts Reviewed

<!--
  Track which contracts you've reviewed.
  THE 2-CONTRACT RULE: After reviewing 2 contracts, update findings_report.md.
-->
| Contract | Lines | Status | Notes |
|----------|-------|--------|-------|
| [Contract.sol] | [XXX] | not_started / in_progress / complete | |

## Session Notes

<!--
  Brief notes from each audit session.
-->
### Session 1: [Date]
- Started Phase 1
- [Notes]

---

## Errors Encountered

<!--
  Log ALL errors during the audit.
  EXAMPLE: Foundry test fails, RPC issues, contract verification problems.
-->
| Error | Attempt | Resolution |
|-------|---------|------------|
|       | 1       |            |

---

## Related Resources

- **Attack Tree:** `attack-trees/[protocol-type]-attack-tree.md`
- **Anti-Patterns:** `anti-patterns/*.md`
- **Patterns:** `patterns/*.md`
- **Exploit Forensics:** `exploit-forensics/*.md`

---

*Update this file after completing each phase.*
*The 2-Contract Rule: After reviewing 2 contracts, update findings_report.md.*
