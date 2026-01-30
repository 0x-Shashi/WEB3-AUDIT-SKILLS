# Audit Preparation Workflow

Maximize the value of professional audits by finding and fixing obvious issues first.

---

## Purpose

Use this workflow when:
- 1-2 weeks before external audit
- Before submitting to audit contest
- Final internal security review
- Pre-deployment checklist

**Time Required:** 2-4 hours for thorough preparation

---

## Phase 1: Protocol Classification (15 min)

### Document Your Protocol

```markdown
## Protocol Overview

**Name:** [Protocol Name]
**Category:** [DeFi/Lending/DEX/etc.]
**Languages:** [Solidity 0.8.x / Rust / etc.]

### Key Features
1. [Feature 1]
2. [Feature 2]
3. [Feature 3]

### External Dependencies
- Oracle: [Chainlink/Pyth/custom]
- Tokens: [Supported token types]
- Protocols: [Integrated protocols]

### Value at Risk
- Expected TVL: [Amount]
- Max single transaction: [Amount]

### Trust Assumptions
1. [Admin is trusted]
2. [Oracle is accurate]
3. [etc.]
```

---

## Phase 2: Category-Specific Research (30 min)

### Query Protocol Category

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "protocolCategory": ["YOUR_CATEGORY"],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

### Extract Top 20 Risks

From the results, identify the 20 most relevant risks:

```markdown
## Top 20 Risks for [Category]

| # | Risk | Severity | Relevant to Us? | Checked? |
|---|------|----------|-----------------|----------|
| 1 | [Risk name] | HIGH | Yes/No | [ ] |
| 2 | ... | ... | ... | [ ] |
```

---

## Phase 3: Create Master Checklist (45 min)

### Query by Vulnerability Tag

For each relevant tag, build a checklist:

```bash
# Reentrancy checks
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "filters": {
      "tags": ["reentrancy"],
      "impact": ["HIGH", "MEDIUM"],
      "qualityScore": 3
    }
  }'
```

### Master Checklist Template

```markdown
# Pre-Audit Security Checklist

## Reentrancy
- [ ] All external calls follow CEI pattern
- [ ] ReentrancyGuard on state-changing functions
- [ ] Read-only reentrancy considered (view functions with external calls)
- [ ] Cross-function reentrancy checked
- [ ] Cross-contract reentrancy checked

## Oracle Security
- [ ] Staleness check implemented
- [ ] Price deviation bounds set
- [ ] Fallback oracle configured
- [ ] Flash loan manipulation resistant
- [ ] Multiple oracle sources (if critical)

## Access Control
- [ ] All admin functions protected
- [ ] Role separation implemented
- [ ] Multi-sig for critical operations
- [ ] Timelock for parameter changes
- [ ] No unprotected initializers

## Token Handling
- [ ] SafeERC20 used for all transfers
- [ ] Fee-on-transfer tokens handled
- [ ] Rebasing tokens considered
- [ ] Return value checked (if not using SafeERC20)
- [ ] Approval race condition handled

## Arithmetic
- [ ] Solidity 0.8+ or SafeMath
- [ ] Unchecked blocks reviewed
- [ ] Division by zero prevented
- [ ] Rounding direction verified
- [ ] Precision loss acceptable

## Denial of Service
- [ ] No unbounded loops with external input
- [ ] Push patterns avoided (use pull)
- [ ] Gas limits considered
- [ ] External call failures handled

## Input Validation
- [ ] All user inputs validated
- [ ] Array lengths bounded
- [ ] Zero address checks
- [ ] Zero amount checks
- [ ] Slippage parameters enforced

## Flash Loan Resistance
- [ ] Same-block manipulation prevented
- [ ] TWAP used for prices (if needed)
- [ ] State changes atomic
- [ ] Governance has voting delays

## Upgrade Security (if applicable)
- [ ] Storage layout documented
- [ ] No storage collisions
- [ ] Initializer protected
- [ ] Upgrade timelock
- [ ] Rollback plan exists
```

---

## Phase 4: Run Automated Tools (30 min)

### Slither

```bash
slither . --print human-summary
slither . --checklist
slither . 2>&1 | tee slither-output.txt
```

### Echidna (if configured)

```bash
echidna . --contract MyContract --config echidna.yaml
```

### Other Tools

```bash
# Foundry tests
forge test -vvv

# Coverage
forge coverage

# Gas snapshots
forge snapshot
```

---

## Phase 5: Address Known Issues (60 min)

### Prioritize Findings

From automated tools and checklist:

```markdown
## Issues to Address Before Audit

### Must Fix (HIGH risk)
1. [ ] [Issue description] - [File:Line]
2. [ ] ...

### Should Fix (MEDIUM risk)
1. [ ] [Issue description] - [File:Line]
2. [ ] ...

### Nice to Fix (LOW risk)
1. [ ] [Issue description] - [File:Line]
2. [ ] ...

### Won't Fix (Acknowledged)
1. [Issue] - Reason: [Why acceptable]
```

---

## Phase 6: Documentation Preparation (30 min)

### Create Audit Package

```markdown
# Audit Package

## Repository
- URL: [GitHub URL]
- Commit: [Frozen commit hash]
- Branch: [audit-ready branch]

## Build Instructions
```bash
git clone [repo]
cd [repo]
npm install  # or forge install
npm run compile  # or forge build
npm test  # or forge test
```

## Scope
### In Scope
| File | Lines | Description |
|------|-------|-------------|
| contracts/Vault.sol | 450 | Main vault logic |
| contracts/Oracle.sol | 120 | Price feed integration |

### Out of Scope
- External libraries (OpenZeppelin)
- Test files
- Mock contracts

## Known Issues
[List any known issues that are accepted risks]

## Areas of Concern
1. [Specific concern area]
2. [Another concern]

## Previous Audits
- [Audit 1] - [Date] - [Link]

## Contact
- Security: security@protocol.com
- Technical: dev@protocol.com
```

---

## Phase 7: Final Verification (15 min)

### Pre-Audit Readiness Checklist

```markdown
## Audit Readiness Verification

### Code Quality
- [ ] All tests passing
- [ ] Code compiles without warnings
- [ ] Comments explain complex logic
- [ ] NatSpec on all public functions

### Documentation
- [ ] Architecture diagram exists
- [ ] Scope document complete
- [ ] Known issues documented
- [ ] Build instructions verified

### Security
- [ ] Master checklist completed
- [ ] Automated tools run
- [ ] HIGH/MEDIUM issues addressed
- [ ] Known issues documented

### Repository
- [ ] Commit hash frozen
- [ ] Dependencies pinned
- [ ] Clean git history on audit branch
- [ ] Access granted to auditors

### Team
- [ ] Technical contact assigned
- [ ] Available for questions
- [ ] Response time SLA defined
```

---

## Output: Audit Preparation Summary

```markdown
# [Protocol] Audit Preparation Summary

## Date: [Date]
## Audit Start: [Date]
## Commit: [Hash]

## Preparation Summary
- Solodit findings reviewed: [Number]
- Checklist items verified: [Number]
- Automated tool issues: [Number]
- Issues fixed pre-audit: [Number]
- Known issues documented: [Number]

## Top Concerns for Auditors
1. [Concern 1] - [Context]
2. [Concern 2] - [Context]

## Risk Areas Identified
| Area | Risk Level | Notes |
|------|------------|-------|
| Oracle integration | HIGH | Complex multi-source |
| Liquidation logic | MEDIUM | Edge cases |

## Automated Tool Results
| Tool | Issues | Status |
|------|--------|--------|
| Slither | 5 | All reviewed |
| Echidna | 0 | Invariants hold |

## Attachments
- slither-output.txt
- checklist-completed.md
- scope-document.md
```

---

## Benefits

By completing this workflow before audit:

1. **Save audit time** - Auditors focus on deep issues, not obvious bugs
2. **Better findings** - More time for complex vulnerability research
3. **Lower cost** - Faster audit turnaround
4. **Smoother process** - Clear documentation reduces questions
5. **Better security** - Issues fixed before deployment risk

