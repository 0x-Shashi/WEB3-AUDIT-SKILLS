---
id: METH-CODEBASE-RECON
title: Codebase Recon Methodology
category: methodology
severity: high
chains: [ethereum, solana, cosmos, aptos, all]
languages: [solidity, rust, move, typescript]
tags:
  - reconnaissance
  - code-review
  - architecture-mapping
  - entry-points
  - trust-boundaries
  - data-flow
  - question-bank
  - audit-preparation
last_updated: 2026-02-27
description: >-
  Use when beginning a new audit engagement to systematically map the codebase
  before hunting for vulnerabilities — applies the 5-phase Recon Pyramid
  (Overview → Architecture → Modules → Functions → Details) to build a
  complete mental model. Different from audit-context-building which
  covers WHAT context to document — this covers HOW to systematically
  discover and map an unfamiliar codebase in the first hours of an audit.
---

# Codebase Recon Methodology

## Overview

The first hours of an audit determine its effectiveness. Random code browsing
wastes time. Systematic recon builds a complete mental model that makes
vulnerability hunting faster and more thorough.

**Core principle**: Move from the broadest overview to the finest detail.
Never jump to function-level analysis before understanding the architecture.
The Recon Pyramid ensures nothing is missed.

### The 5-Phase Recon Pyramid

```
         ┌─────────┐
         │ Details  │  Phase 5: Security-critical implementation details
        ┌┴─────────┴┐
        │ Functions  │  Phase 4: Function-level security analysis
       ┌┴───────────┴┐
       │   Modules    │  Phase 3: Module interaction and data flow
      ┌┴─────────────┴┐
      │  Architecture  │  Phase 2: System design and trust boundaries
     ┌┴───────────────┴┐
     │    Overview      │  Phase 1: Project scope and technology stack
     └─────────────────┘
```

**Time allocation for a 1-week audit**:
- Phase 1: 1-2 hours (first morning)
- Phase 2: 2-4 hours (first day)
- Phase 3: 4-8 hours (day 1-2)
- Phase 4: Remainder of audit
- Phase 5: Interwoven with Phase 4

## Phase 1: Project Overview

**Goal**: Understand WHAT the project does and WHY it exists in under 2 hours.

### 1.1 Documentation Scan

Read (in this order):
1. README.md — project purpose, architecture overview
2. Documentation site (if any) — user-facing features
3. Deployment scripts — what gets deployed, in what order
4. Test files — what the developers think is important to test
5. Recent PRs/commits — what's actively changing

### 1.2 Technology Mapping Template

| Property | Value |
|----------|-------|
| **Language(s)** | e.g., Solidity 0.8.20, Rust/Anchor 0.32 |
| **Framework** | e.g., Foundry, Hardhat, Anchor |
| **Chain(s)** | e.g., Ethereum mainnet, Solana |
| **Token standards** | e.g., ERC-20, ERC-721, SPL Token |
| **Oracle provider** | e.g., Chainlink, Pyth, Switchboard |
| **External dependencies** | e.g., OpenZeppelin 5.0, @solana/spl-token |
| **Proxy pattern** | e.g., UUPS, Transparent, none |
| **Governance** | e.g., Timelock, multisig, single owner |
| **Lines of code (in scope)** | e.g., 3,200 Solidity + 800 test |
| **Compiler/toolchain version** | e.g., solc 0.8.20, anchor 0.32.1 |

### 1.3 File Inventory

```bash
# Quick line count by file (Solidity)
find contracts/ -name "*.sol" -exec wc -l {} \; | sort -n

# Quick line count by file (Rust/Anchor)
find programs/ -name "*.rs" -exec wc -l {} \; | sort -n

# Identify largest files (these get the most audit time)
find . -name "*.sol" -o -name "*.rs" | xargs wc -l | sort -n | tail -20
```

## Phase 2: Architecture Mapping

**Goal**: Map the system's trust boundaries, privileged roles, and
component relationships.

### 2.1 Entry Point Mapping

An entry point is any function that external users, keepers, or other
protocols can call. Map EVERY entry point.

| Entry Point | Caller | Auth Required | State Changes | Value Flow |
|-------------|--------|---------------|---------------|------------|
| `deposit()` | User | None (permissionless) | Increases balance | User → Vault |
| `withdraw()` | User | Balance owner only | Decreases balance | Vault → User |
| `liquidate()` | Keeper | None (permissionless) | Closes position | Borrower → Liquidator |
| `setOracle()` | Admin | Owner/multisig | Changes oracle addr | None |
| `pause()` | Guardian | Guardian role | Halts protocol | None |

**For Solana programs**: Every instruction in the `#[program]` module
is an entry point. Map the account constraints for each.

### 2.2 Trust Boundary Identification

Draw the trust boundary diagram:

```
┌─────────────────────────────────────────────┐
│                TRUSTED ZONE                  │
│  ┌─────────┐     ┌──────────┐               │
│  │ Protocol │────▶│ Treasury │               │
│  │ Logic    │     │ Vault    │               │
│  └────┬─────┘     └──────────┘               │
│       │                                      │
│  TRUST BOUNDARY ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
│       │                                      │
│  ┌────▼─────┐     ┌──────────┐  ┌────────┐  │
│  │ Oracle    │     │ External │  │ User   │  │
│  │ Provider  │     │ Protocol │  │ Input  │  │
│  └──────────┘     └──────────┘  └────────┘  │
│           UNTRUSTED ZONE                     │
└─────────────────────────────────────────────┘
```

**Questions for each boundary crossing**:
- What data crosses this boundary?
- Who validates the data?
- What happens if the data is malicious?
- Can the boundary be bypassed?

### 2.3 Privilege Mapping

| Role | Permissions | How Set | Risk If Compromised |
|------|-------------|---------|---------------------|
| Owner | Can upgrade, pause, set parameters | Constructor/initializer | Total loss |
| Guardian | Can pause only | Set by Owner | DoS (pause grief) |
| Keeper | Can liquidate, rebalance | Permissionless | MEV extraction |
| User | Deposit, withdraw, trade | Permissionless | Loss of own funds |

**Critical questions**:
- Can Owner rug users? (upgradeability, parameter changes)
- Is there a timelock on privileged operations?
- Can any role be renounced?
- What's the multisig threshold?

## Phase 3: Module Interaction and Data Flow

**Goal**: Understand how data flows between modules and where
transformations occur.

### 3.1 Data Flow Tracing

For each critical operation (deposit, withdraw, liquidate, trade):

```
[Input] → [Validation] → [Computation] → [State Change] → [External Effect]

Example: Borrow operation
User calls borrow(amount, collateral)
  → Validate: sufficient collateral (read oracle)
  → Compute: borrow capacity = collateral_value * LTV_ratio
  → Check: amount <= borrow_capacity
  → State: decrease available liquidity, create debt position
  → External: transfer tokens to user
```

**What to look for at each step**:
- Input: What's user-controlled? What's from trusted sources?
- Validation: Are ALL inputs validated? Ranges, types, ownership?
- Computation: Any precision loss? Overflow? Division by zero?
- State Change: Is the order correct? (Effects before interactions?)
- External Effect: Return value checked? Reentrancy possible?

### 3.2 State Dependency Graph

Map which state variables affect which operations:

```
oracle_price ──────┬──► collateral_value() ──► can_borrow()
                   │                           │
interest_rate ─────┤                           ▼
                   └──► accrued_interest() ──► health_factor()
                                               │
total_borrowed ────────────────────────────────┘
```

**Critical state variables** (touch these → likely High/Critical findings):
- Token balances / reserves
- Oracle prices / exchange rates
- Interest rates / fee parameters
- Access control mappings
- Paused/active flags
- Nonces / sequence numbers

### 3.3 External Integration Points

| Integration | Protocol | Data Flow | Trust Level |
|-------------|----------|-----------|-------------|
| Price oracle | Pyth | Price, confidence | Semi-trusted |
| DEX swap | Jupiter | Swap result | Untrusted |
| Token transfer | SPL Token | Transfer result | Trusted (verified program) |
| Cross-chain | Wormhole | Message | Semi-trusted |

## Phase 4: Function-Level Security Analysis

**Goal**: Analyze each function for specific vulnerability patterns.

### 4.1 Function Triage

Not all functions need equal audit depth. Prioritize:

| Priority | Criteria | Example |
|----------|----------|---------|
| P0 — Critical | Moves funds, changes auth, upgrades | `withdraw`, `setOwner`, `upgrade` |
| P1 — High | Changes protocol parameters, uses oracle | `setInterestRate`, `liquidate` |
| P2 — Medium | State changes, user-facing | `deposit`, `createPosition` |
| P3 — Low | View functions, internal helpers | `getBalance`, `calculateFee` |

### 4.2 Per-Function Analysis Template

For each P0/P1 function:

```
FUNCTION: [name]
CALLER: [who can call this]
AUTH: [what checks are performed]
INPUTS: [list all parameters + types]
STATE READ: [what state is read]
STATE WRITE: [what state is written]
EXTERNAL CALLS: [any external calls made]
RETURN VALUE: [what is returned]
INVARIANTS: [what must always be true after this function]
ATTACK SURFACE: [how could this be abused]
```

## Phase 5: Security-Critical Details

**Goal**: Verify implementation details that determine whether
the architecture is correctly realized.

### 5.1 Detail Checklist

- [ ] **Rounding direction**: Does the protocol round in its own favor? (Floor for withdrawals, ceil for debt)
- [ ] **Fee ordering**: Are fees deducted before or after the operation? (before = user pays less)
- [ ] **Initialization**: Can contracts be re-initialized? (missing `initializer` guard)
- [ ] **Upgrade safety**: Are storage layouts compatible across upgrades?
- [ ] **Decimal handling**: Do all token amounts use the correct decimals? (6 vs 18 vs 8)
- [ ] **Timestamp usage**: Is `block.timestamp` used for anything security-critical?
- [ ] **Gas/CU limits**: Can any operation exceed block gas/CU limits? (DoS vector)

## Security Question Bank

### Architecture Questions (Phase 2)

1. What is the worst thing that can happen if the admin key is compromised?
2. Can the protocol be drained in a single transaction?
3. Are there any circular dependencies between contracts/programs?
4. What happens if the oracle goes offline for 1 hour? 24 hours?
5. Is there a kill switch / emergency pause? Who controls it?
6. Can the protocol operate without ANY external dependencies?
7. Are there any implicit ordering assumptions between transactions?

### Authentication & Authorization Questions

8. For each privileged function: what's the MINIMUM required to call it?
9. Is there signature replay protection? (nonce or deadline)
10. Can a delegate exceed their intended permissions?
11. Are there any functions that should be restricted but aren't?
12. Can authorization be front-run? (approve → transferFrom race)
13. For multisig operations: can a single signer grief the process?

### Input Validation Questions

14. For each external input: what's the valid range? Is it enforced?
15. Can zero-value inputs cause division by zero or degenerate behavior?
16. Are array lengths bounded? Can unbounded arrays cause DoS?
17. Are string/bytes inputs length-limited?
18. Can negative values be passed where only positive are expected?

### Cryptography Questions

19. Are signatures EIP-712 typed or raw hash?
20. Is the signature domain separator chain-specific?
21. Can signatures be replayed across chains/contracts?
22. Is `ecrecover` checked for `address(0)` return?
23. Are hash functions used correctly? (keccak256 vs sha256 vs poseidon)

### Business Logic Questions

24. Can a user extract more value than they deposited?
25. Can fees be avoided through specific transaction patterns?
26. Does the protocol handle zero-liquidity edge cases?
27. Can flash loans be used to manipulate any state?
28. Are there any race conditions between cooperating transactions?
29. Can dust amounts accumulate to create accounting errors?
30. What happens at extreme market conditions? (99% drop)

### Smart Contract Specific Questions

31. For upgradeable contracts: is the upgrade process safe? (timelock, 2-step)
32. For proxies: is the implementation slot correct? (ERC-1967)
33. For Solana: are all account constraints present? (owner, signer, seeds)
34. For CPI/cross-contract: is the callee program verified?
35. Are all return values from external calls checked?

### Error Handling Questions

36. Does the protocol fail-safe or fail-open?
37. Can error conditions be triggered intentionally for DoS?
38. Are error messages informative without leaking sensitive state?
39. Do all revert paths leave state consistent?

## Recon Checklist

### Phase 1: Project Basics
- [ ] Read README and documentation
- [ ] Identify all languages and frameworks
- [ ] Count lines of code per file
- [ ] Identify deploy scripts and configuration
- [ ] Review test coverage and test patterns

### Phase 2: Architecture
- [ ] Map all entry points with caller permissions
- [ ] Draw trust boundary diagram
- [ ] Map all privileged roles and their powers
- [ ] Identify upgrade mechanisms
- [ ] Review governance and timelock configuration

### Phase 3: Data Flow
- [ ] Trace complete flow for each critical operation
- [ ] Map state dependency graph
- [ ] Identify all external integration points
- [ ] Catalog all oracle usage
- [ ] Map token flow (where do tokens come from / go to)

### Phase 4: Function Analysis
- [ ] Triage all functions by priority
- [ ] Complete per-function analysis for P0/P1 functions
- [ ] Cross-reference against known vulnerability patterns
- [ ] Run automated tools (slither, semgrep, clippy)
- [ ] Execute sharp edges sweep per language

### Phase 5: Details
- [ ] Verify rounding direction in all calculations
- [ ] Check initialization guards
- [ ] Verify decimal handling across all token types
- [ ] Confirm storage layout safety for upgrades
- [ ] Review gas/CU consumption for DoS vectors

### Completion Criteria
- [ ] Can explain every entry point and its purpose
- [ ] Can draw the trust boundary diagram from memory
- [ ] Have mapped all privileged roles and their scope
- [ ] Have identified the top 5 riskiest areas
- [ ] Have documented all assumptions made by the protocol
- [ ] Recon notes are sufficient for another auditor to continue

## Recon Output Template

### [Protocol Name] — Audit Recon Notes

```markdown
## Protocol Summary
- Purpose: [one sentence]
- Chain: [target chain(s)]
- Languages: [Solidity/Rust/Move]
- In-scope LOC: [total lines]
- External dependencies: [list]

## Architecture
[Trust boundary diagram here]

## Entry Points (sorted by risk)
[Entry point table from Phase 2.1]

## Privileged Roles
[Role table from Phase 2.3]

## Critical Data Flows
[Flow diagrams from Phase 3.1]

## Top 5 Risk Areas
1. [Area] — [Why risky] — [What to look for]
2. ...

## Assumptions to Verify
1. [Assumption the protocol makes]
2. ...

## Questions for Protocol Team
1. [Unanswered question from recon]
2. ...
```

## Integration with Other Skills

| Skill | Relationship |
|-------|-------------|
| [Audit Context Building](../audit-context-building/) | Context building documents WHAT; recon discovers HOW |
| [Audit Plan Execution](methodology/audit-plan-execution.md) | Recon output feeds directly into plan decomposition |
| [Sharp Edges Detection](methodology/sharp-edges-detection.md) | Phase 4 triggers language-specific edge scanning |
| [Parallel Audit Agents](methodology/parallel-audit-agents.md) | Recon defines scope boundaries for agent dispatch |
| [Trust Boundary Identification](../advanced/) | Phase 2 creates the trust map used throughout audit |
