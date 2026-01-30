# Pre-Development Research Workflow

Research common vulnerabilities BEFORE writing code to build security in from the start.

---

## Purpose

Use this workflow when:
- Starting a new smart contract project
- Adding major new features to existing protocol
- Entering unfamiliar DeFi territory
- Building on a new blockchain platform

**Time Required:** 30-60 minutes

---

## Step 1: Identify Your Protocol Category

Determine which category best fits your project:

| Category | Examples | Key Risks |
|----------|----------|-----------|
| Lending | Aave, Compound | Oracle attacks, liquidation bugs |
| DEX | Uniswap, Curve | Price manipulation, MEV |
| Staking | Lido, Rocket Pool | Reward calculation, slashing |
| Governance | Compound Gov | Flash loan voting |
| Bridge | Wormhole, Stargate | Message verification |
| NFT | OpenSea | Access control, royalties |
| Yield | Yearn | Strategy risks, composability |

---

## Step 2: Query HIGH Severity for Your Category

```bash
# Replace CATEGORY with your protocol type
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "protocolCategory": ["CATEGORY"],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

**Action:** Read each finding title and summary. Create initial checklist.

---

## Step 3: Query MEDIUM Severity

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "protocolCategory": ["CATEGORY"],
      "impact": ["MEDIUM"],
      "qualityScore": 3,
      "sortField": "Quality"
    }
  }'
```

**Action:** Add to checklist. Note conditional risks.

---

## Step 4: Identify Core Components

Based on your design, list components you'll implement:

| Component | Query Keywords |
|-----------|---------------|
| Token transfers | `"token transfer ERC20"` |
| Oracle integration | `"oracle price chainlink"` |
| Staking/rewards | `"staking reward calculation"` |
| Governance | `"governance voting proposal"` |
| Liquidations | `"liquidation health factor"` |
| Flash loans | `"flash loan callback"` |
| Upgrades | `"proxy upgrade delegatecall"` |

---

## Step 5: Query Component-Specific Vulnerabilities

For each component:

```bash
# Example: Oracle integration
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "keywords": "oracle price stale manipulation",
      "tags": ["oracle"],
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

---

## Step 6: Extract Prevention Patterns

From each finding, extract:

1. **Vulnerability Pattern** - What causes the issue
2. **Attack Scenario** - How it's exploited
3. **Prevention** - How to avoid it
4. **Detection** - How to test for it

### Example Extraction

**Finding:** "Oracle price manipulation via flash loan"

| Aspect | Details |
|--------|---------|
| Pattern | Using spot price from AMM |
| Attack | Flash loan  manipulate pool  use wrong price |
| Prevention | Use TWAP or Chainlink; add flash loan resistance |
| Detection | Test with large swaps; check for manipulation scenarios |

---

## Step 7: Create Security Checklist

Build a checklist from findings:

### Oracle Security
- [ ] Use Chainlink or TWAP, not spot prices
- [ ] Check for stale price data
- [ ] Validate price deviation bounds
- [ ] Test flash loan manipulation scenarios

### Access Control
- [ ] Critical functions protected by role
- [ ] Multi-sig for admin actions
- [ ] Timelock for parameter changes
- [ ] Emergency pause functionality

### Reentrancy
- [ ] Follow CEI pattern (Checks-Effects-Interactions)
- [ ] Use ReentrancyGuard on state-changing functions
- [ ] Test with malicious callback contracts

---

## Step 8: Document Assumptions

List all assumptions your protocol makes:

```markdown
## Security Assumptions

1. Oracle prices are accurate within X%
2. Admin keys are held by trusted multisig
3. External tokens follow ERC20 standard
4. Users will not interact via malicious contracts
5. Gas prices remain reasonable for liquidations
```

**For each assumption:** Query Solodit for violations:

```bash
curl -X POST ... -d '{
  "filters": {
    "keywords": "assumption violated trusted admin",
    "impact": ["HIGH"]
  }
}'
```

---

## Step 9: Create Test Plan

Based on findings, create security test scenarios:

### Unit Tests
- [ ] Edge cases from findings (zero amounts, max values)
- [ ] Access control enforcement
- [ ] Arithmetic bounds

### Integration Tests
- [ ] Multi-step attack scenarios
- [ ] Cross-contract interactions
- [ ] External dependency failures

### Fuzz Tests
- [ ] Property-based tests for invariants
- [ ] Random input combinations
- [ ] Stateful fuzzing for complex flows

---

## Step 10: Architecture Review

Before writing code, validate architecture decisions:

```bash
# Query for architecture-related issues
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "keywords": "architecture design pattern upgrade",
      "protocolCategory": ["CATEGORY"],
      "impact": ["HIGH", "MEDIUM"],
      "sortField": "Quality"
    }
  }'
```

---

## Output: Research Summary

Create a document with:

```markdown
# [Protocol Name] - Pre-Development Security Research

## Protocol Overview
- Category: [Lending/DEX/etc.]
- Key Components: [List]
- External Dependencies: [List]

## Top Risks (from Solodit Research)
1. [Risk 1 - Severity] - [Source finding]
2. [Risk 2 - Severity] - [Source finding]
3. ...

## Security Checklist
- [ ] Item 1
- [ ] Item 2
- ...

## Architecture Decisions
- Decision 1: [Choice] because [finding evidence]
- Decision 2: ...

## Assumptions & Mitigations
| Assumption | Risk if Violated | Mitigation |
|------------|-----------------|------------|
| ... | ... | ... |

## Test Plan
- [Test categories and priorities]

## Resources
- [Links to relevant findings]
- [Links to secure implementations]
```

---

## Next Steps

After completing pre-development research:

1. **Share with team** - Get review on assumptions
2. **Reference during development** - Keep checklist visible
3. **Update as you build** - Add new concerns discovered
4. **Use for audit prep** - Foundation for security review

