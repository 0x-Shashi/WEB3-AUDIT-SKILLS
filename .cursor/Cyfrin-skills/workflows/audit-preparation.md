# Audit Preparation Workflow

## Purpose

Comprehensive security review before submitting code for external audit. This maximizes the value of expensive external audits by finding and fixing obvious issues first.

## When to Use

- Before submitting to audit contest
- Before engaging professional auditors
- Final internal security review
- Pre-deployment checklist

## Time Required

2-4 hours for thorough preparation

## Step-by-Step Workflow

### Step 1: Protocol Classification

Document your protocol:

```markdown
## Protocol Overview
- Category: [DeFi/Lending/DEX/etc.]
- Languages: [Solidity/Rust/etc.]
- Key Features: [List main features]
- External Dependencies: [Oracles, tokens, protocols]
- Value at Risk: [Expected TVL]
```

### Step 2: Query Category-Specific Issues

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "protocolCategory": [{"value": "YourCategory"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

### Step 3: Create Tag-Based Audit Checklist

For each major vulnerability tag relevant to your protocol:

```bash
# Reentrancy
curl -X POST ... -d '{"filters": {"tags": [{"value": "Reentrancy"}], "impact": ["HIGH"]}}'

# Oracle
curl -X POST ... -d '{"filters": {"tags": [{"value": "Oracle"}], "impact": ["HIGH"]}}'

# Access Control
curl -X POST ... -d '{"filters": {"tags": [{"value": "Access Control"}], "impact": ["HIGH"]}}'

# Continue for all relevant tags...
```

### Step 4: Build Comprehensive Checklist

Based on findings, create a complete checklist:

```markdown
## Pre-Audit Security Checklist

### Reentrancy (X findings reviewed)
- [ ] All external calls use CEI pattern
- [ ] ReentrancyGuard on state-changing functions
- [ ] Cross-contract reentrancy considered
- [ ] Read-only reentrancy addressed

### Access Control (X findings reviewed)
- [ ] All admin functions have modifiers
- [ ] Role hierarchy is correct
- [ ] No privilege escalation paths
- [ ] Two-step ownership transfer

### Oracle Security (X findings reviewed)
- [ ] Price freshness validated
- [ ] Round completeness checked
- [ ] Price bounds enforced
- [ ] Fallback oracle available
- [ ] L2 sequencer check (if applicable)

### Flash Loan Protection (X findings reviewed)
- [ ] Same-block restrictions where needed
- [ ] Governance uses snapshots
- [ ] Interest accrues per-block

### Input Validation (X findings reviewed)
- [ ] All parameters validated
- [ ] Bounds checked
- [ ] Edge cases handled

### Math Operations (X findings reviewed)
- [ ] No overflow/underflow
- [ ] Rounding direction correct
- [ ] Precision handling proper
```

### Step 5: Execute Checklist Against Code

Go through each item and verify in your codebase:

```markdown
## Audit Preparation Report

### Checklist Results

| Category | Items | Passed | Failed | N/A |
|----------|-------|--------|--------|-----|
| Reentrancy | 4 | 3 | 1 | 0 |
| Access Control | 4 | 4 | 0 | 0 |
| Oracle | 5 | 4 | 0 | 1 |
| Flash Loan | 3 | 2 | 1 | 0 |

### Issues Found (Pre-Audit)
1. [Issue] - [Severity] - [Location] - [Status: Fixed/Accepted]
2. [Issue] - [Severity] - [Location] - [Status: Fixed/Accepted]

### Known Risks (Documented)
1. [Risk] - [Mitigation/Acceptance reason]
```

### Step 6: Document Known Issues

Create a "known issues" document for auditors:

```markdown
## Known Issues and Design Decisions

### Accepted Risks
1. **[Risk Name]**
   - Description: [What and why]
   - Mitigation: [What you've done]
   - Residual Risk: [What remains]

### Design Decisions
1. **[Decision]**
   - Rationale: [Why this approach]
   - Alternatives Considered: [What else you looked at]
   - Trade-offs: [What you accepted]
```

### Step 7: Prepare Audit Package

Create comprehensive documentation:

```markdown
## Audit Package Contents

1. **Protocol Overview**
   - Architecture diagram
   - Component descriptions
   - Trust assumptions

2. **Security Model**
   - Threat model
   - Trust boundaries
   - Known risks

3. **Code Documentation**
   - NatSpec complete
   - README per contract
   - Test coverage report

4. **Pre-Audit Results**
   - This checklist
   - Known issues
   - Previous audits (if any)
```

## Query Templates for Audit Prep

### All HIGH Severity for Category
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 100,
    "filters": {
      "protocolCategory": [{"value": "YourCategory"}],
      "impact": ["HIGH"],
      "qualityScore": 4
    }
  }'
```

### Feature-Specific Deep Dive
```bash
# For each major feature in your protocol
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "keywords": "your feature keywords",
      "impact": ["HIGH", "MEDIUM"],
      "qualityScore": 3
    }
  }'
```

### Similar Protocol Research
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "keywords": "similar protocol name",
      "impact": ["HIGH"]
    }
  }'
```

## Output

After completing audit preparation:

1. **Completed checklist** with all items verified
2. **Pre-audit issues** found and fixed
3. **Known issues document** for auditors
4. **Audit package** with full documentation
5. **Confidence assessment** on each component

## Success Metrics

Good audit preparation means:
- External auditors find fewer obvious issues
- Audit time focused on complex vulnerabilities
- Better ROI on audit spend
- Faster turnaround time
