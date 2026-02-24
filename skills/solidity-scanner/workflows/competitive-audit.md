---
id: competitive-audit-workflow
title: Competitive Audit Workflow
category: workflow
parent_skill: solidity-scanner/SKILL.md
triggers:
  - contest audit
  - code4rena
  - sherlock
  - codehawks
  - cantina
  - audit contest
  - bug bounty
tags:
  - competitive
  - contest
  - workflow
  - code4rena
  - sherlock
last_updated: 2026-02-24
---

# Competitive Audit Workflow

## Purpose

Optimized for audit contests (Code4rena, Sherlock, CodeHawks, Cantina) where speed, unique findings, and clear impact matter. This workflow maximizes finding count and quality within a time-boxed engagement.

## Contest Preparation (Before Contest Starts)

### Pre-Contest Checklist

```markdown
- [ ] Read contest README and scope document
- [ ] Identify protocol type (AMM, lending, vault, bridge, governance, etc.)
- [ ] Note SLOC (lines of code in scope) — calibrate effort
- [ ] Check if protocol is a fork (Compound, Aave, Uniswap fork?)
- [ ] Review previous audits of same protocol (if any)
- [ ] Load relevant protocol playbook from protocol-playbooks/
- [ ] Set up local environment: clone repo, compile, run tests
- [ ] Pre-load relevant checklist from checklists/
```

### SLOC-Based Time Allocation

| SLOC Range | Recommended Time | Strategy |
|---|---|---|
| < 500 | 4–8 hours | Read every line. Focus on logic bugs. |
| 500–1500 | 1–2 days | Systematic pass. Tool sweep + manual review. |
| 1500–3000 | 2–4 days | Prioritize high-value contracts. Skim libraries. |
| 3000+ | 4–7 days | Focus on core logic. Accept you can't cover everything. |

---

## Strategy: Time-Boxed Passes

### Pass 1: Reconnaissance & Quick Wins (First 20%)

**Time budget**: 20% of total contest time (e.g., 2 hours of a 10-hour day)

**Objectives**: Understand protocol, find obvious bugs, set up tools.

```markdown
Step 1: Protocol Mapping (30 min)
- [ ] Read all documentation (README, docs, natspec)
- [ ] Draw contract architecture diagram
- [ ] Identify entry points (external/public functions)
- [ ] List all privileged roles and their powers
- [ ] Map token flows: deposit → internal → withdraw
- [ ] Identify which contracts hold funds (highest priority)

Step 2: Automated Tool Sweep (15 min)
- [ ] Run Slither: slither . --config-file slither.config.json
- [ ] Run Aderyn: aderyn . --output report.md
- [ ] Scan tool output for Critical/High findings
- [ ] Bookmark findings for manual verification

Step 3: Quick Win Patterns (45 min)
- [ ] grep all external functions for missing access control
- [ ] grep all external calls for unchecked return values
- [ ] Check all initialize() functions for initializer modifier
- [ ] Check for tx.origin usage
- [ ] Look for selfdestruct/SELFDESTRUCT
- [ ] Check for hardcoded addresses or magic numbers
- [ ] Verify compiler version is pinned (not floating pragma)
```

**Submit immediately**: Any confirmed Critical/High findings found here. Don't wait.

---

### Pass 2: Money Flows (Next 30%)

**Time budget**: 30% of total contest time

**Objectives**: Follow every path that touches money.

```markdown
Step 4: Token Flow Analysis (focus area)
- [ ] Trace every deposit path end-to-end
    - Start: user calls deposit/swap/stake
    - Middle: internal accounting, share calculation, state updates
    - End: tokens arrive in protocol contract
- [ ] Trace every withdrawal path end-to-end
    - Verify CEI pattern
    - Check for reentrancy
    - Verify correct amount calculation
- [ ] Check for fee-on-transfer token compatibility
    - Does protocol accept arbitrary tokens?
    - Is there a pre/post balance check?
- [ ] Check for rebasing token compatibility
    - Does balanceOf() change without transfer?
    - Will internal accounting become inconsistent?

Step 5: Share/Token Math
- [ ] Verify exchange rate calculation:
    shares = assets * totalSupply / totalAssets
    assets = shares * totalAssets / totalSupply
- [ ] Check rounding direction:
    - Deposit: round DOWN (user gets fewer shares = safe for protocol)
    - Withdraw: round DOWN (user gets fewer assets = safe for protocol)
- [ ] First depositor / inflation attack:
    - What happens when totalSupply == 0?
    - Can attacker donate to inflate share price?
    - Is there a virtual offset or min deposit?
- [ ] Check for division by zero:
    - What if totalSupply == 0 and someone withdraws?
    - What if denominator can be user-controlled?

Step 6: Oracle Checks
- [ ] Identify all price sources
- [ ] Chainlink: staleness check present?
    (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
    require(answer > 0, "Invalid");
    require(block.timestamp - updatedAt <= HEARTBEAT, "Stale");
- [ ] DEX price: spot or TWAP?
    - slot0() = SPOT = VULNERABLE
    - observe() with time window = TWAP = SAFER
- [ ] Can price source be manipulated via flash loan?
- [ ] Decimal mismatch: does oracle return 8 decimals, protocol expect 18?

Step 7: Liquidation Logic (if lending protocol)
- [ ] Can healthy positions be liquidated?
- [ ] Can underwater positions avoid liquidation?
- [ ] Is liquidation incentive correct and bounded?
- [ ] Can liquidator profit be extracted via flash loan?
- [ ] What happens during oracle downtime?
```

---

### Pass 3: Protocol Logic & Edge Cases (Next 30%)

**Time budget**: 30% of total contest time

**Objectives**: Understand what the protocol is supposed to do, find where it doesn't.

```markdown
Step 8: Specification Compliance
- [ ] Read each function's natspec/comments
- [ ] Does the implementation match the documented behavior?
- [ ] Are invariants documented? Test them mentally:
    - "Total deposits should never exceed vault balance"
    - "A user's shares should always be redeemable"
    - "Fee should never exceed MAX_FEE"
- [ ] Check all require/revert messages — do they guard the right conditions?

Step 9: Edge Cases
- [ ] Zero amount: deposit(0), withdraw(0), transfer(0)
- [ ] Maximum amount: deposit(type(uint256).max)
- [ ] Empty arrays: batchTransfer([])
- [ ] Self-interaction: transfer(msg.sender, amount) — does it fail?
- [ ] Contract as user: what if msg.sender is a contract?
- [ ] Multiple calls in same block: any assumptions about one-tx-per-block?

Step 10: State Machine Analysis
- [ ] List all states a position/order/proposal can be in
- [ ] Can states be reached out of order?
    (e.g., settle before fill, close before open)
- [ ] Can a state transition be replayed?
- [ ] Are there stuck states? (can position be permanently locked?)
- [ ] Race conditions: can two users trigger conflicting transitions?

Step 11: Access Control Deep Dive
- [ ] Map all roles: owner, admin, operator, keeper, guardian
- [ ] For each role, list all callable functions:
    owner: setFee, pause, upgrade, migrate
    keeper: harvest, rebalance, liquidate
- [ ] Can any role escalate privileges?
- [ ] What happens if role address is compromised?
- [ ] Is role assignment protected? (can owner give admin to attacker?)
- [ ] Timelock on role changes?
```

---

### Pass 4: Deep Analysis & Attack Chains (Final 20%)

**Time budget**: 20% of total contest time

**Objectives**: Find complex, high-value findings that other auditors miss.

```markdown
Step 12: Multi-Step Attack Chains
- [ ] Flash loan + oracle manipulation:
    1. Borrow via flash loan
    2. Manipulate AMM price
    3. Perform protocol action at manipulated price
    4. Repay flash loan
    → Profit from price differential

- [ ] Flash loan + share inflation:
    1. Deposit 1 wei into empty vault
    2. Donate large amount directly to vault
    3. First depositor gets 1 share worth a lot
    4. Next depositor's shares round to 0

- [ ] Reentrancy + cross-contract state:
    1. Call withdraw() on Contract A
    2. External call callback re-enters Contract B
    3. Contract B reads stale state from Contract A
    4. Incorrect action taken based on stale state

- [ ] Governance attack:
    1. Flash-borrow governance tokens
    2. Vote on malicious proposal
    3. If proposal executes instantly → full control
    4. If timelock → check for bypass

Step 13: Integration Risk Analysis
- [ ] What external protocols does this integrate with?
- [ ] What assumptions does it make about external protocols?
    - "Chainlink always returns fresh data" → FALSE during congestion
    - "Uniswap V3 pools always have liquidity" → FALSE for low-cap tokens
    - "USDC/USDT always maintain $1 peg" → FALSE during depegs
- [ ] What if external protocol is upgraded/paused/deprecated?
- [ ] Can external protocol callback into this protocol? (composability risk)

Step 14: Cross-Function Interaction Matrix
- Build a matrix of all state-changing functions:

| Function | Reads | Writes | External Calls |
|----------|-------|--------|----------------|
| deposit() | totalAssets, totalShares | userShares, totalShares | safeTransferFrom |
| withdraw() | totalAssets, totalShares, userShares | userShares, totalShares | safeTransfer |
| harvest() | totalAssets | totalAssets | swap, claim |

- Check: can calling harvest() between deposit() and withdraw() cause issues?
- Check: can two functions modify the same state inconsistently?
```

---

## Finding Submission Strategy

### Quality Criteria for Winning Findings

| Aspect | What Judges Want |
|---|---|
| **Clear impact** | "Attacker can drain $5M from vault" — not "there might be an issue" |
| **PoC code** | Working Foundry test that demonstrates the exploit |
| **Root cause** | Precise identification of which code line(s) cause the bug |
| **Fix recommendation** | Specific code change, not "add a check" |
| **Referenced precedent** | "Same pattern caused $60M loss in The DAO" |

### Submission Timing Strategy

| Severity | When to Submit | Why |
|---|---|---|
| Critical | Immediately upon confirmation | Don't risk someone else finding it first |
| High | Within 1–2 hours of finding | Validate thoroughly but don't over-polish |
| Medium | After Pass 3 | Group related mediums under one root cause |
| Low/QA | Final submission batch | Consolidate into organized QA report |

### Deduplication Awareness

Contest judges deduplicate findings by **root cause**. Your finding gets grouped with others who found the same bug. To stand out:

1. **Be first** — earlier submissions often become the "selected" report
2. **Be most comprehensive** — include all variant instances
3. **Best PoC** — clear, minimal, reproducible
4. **Best impact description** — concrete dollar amounts or specific user impact

---

## Common Contest-Winning Pattern Categories

Based on analysis of 500+ winning findings from C4, Sherlock, and CodeHawks:

| Pattern | Win Rate | Why It Wins |
|---|---|---|
| **Oracle manipulation** | Very High | Concrete impact, flash loan PoC, well-understood by judges |
| **Cross-function reentrancy** | High | Missed by tools, requires deep code understanding |
| **Incorrect accounting** | High | Protocol-specific, hard to find without understanding the math |
| **ERC4626 inflation** | Medium | Well-known pattern, often found by multiple auditors (duplicated) |
| **Missing slippage** | Medium | Easy to find, medium impact, often duplicated |
| **Access control** | Medium | Low-hanging fruit, many duplicates |
| **Centralization risk** | Low | Often dismissed as "accepted risk" |
| **Gas optimization** | Very Low | Low payout pool, many competitors |

### Highest ROI Focus Areas

```
Time-to-find vs Payout, ranked:

1. Protocol-specific logic bugs  → Unique findings, high payout, low competition
2. Complex attack chains         → Few duplicates, high severity
3. Oracle/price manipulation     → High severity, moderate competition
4. Cross-function reentrancy     → High severity, missed by tools
5. Share math / rounding         → Medium severity, moderate competition
6. Token compatibility           → Medium severity, requires specific knowledge
7. Missing access control        → Easy to find, highly duplicated
8. Gas optimization              → Very low payout, very high competition
```

## Post-Contest Checklist

```markdown
- [ ] All findings submitted before deadline
- [ ] Each finding has: summary, impact, PoC (if applicable), fix
- [ ] QA report consolidated and organized
- [ ] No duplicate submissions (check your own findings for overlap)
- [ ] Links to relevant code are correct (file + line number)
- [ ] Severity justification matches platform criteria
```
