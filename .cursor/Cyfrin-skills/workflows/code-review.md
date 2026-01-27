# Code Review Workflow

## Purpose

Systematically review code for security issues by querying relevant vulnerability patterns from the Solodit database. Use this during pull request reviews or feature implementation.

## When to Use

- Reviewing a pull request with security implications
- Completing a feature before merging
- Self-review before committing
- Pair programming security checks

## Time Required

15-30 minutes per significant feature

## Step-by-Step Workflow

### Step 1: Identify Code Patterns

Scan the code for security-relevant patterns:

```
□ External calls (to other contracts)
□ Token transfers (ERC20, ERC721, ETH)
□ State changes after external calls
□ Price/oracle usage
□ Access control modifiers
□ Mathematical operations
□ User-supplied parameters
□ Time-dependent logic
□ Loop operations
```

### Step 2: Query by Patterns Found

For each pattern identified, query Solodit:

#### External Calls Present
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 15,
    "filters": {
      "tags": [{"value": "Reentrancy"}],
      "impact": ["HIGH"],
      "qualityScore": 4
    }
  }'
```

#### Token Transfers Present
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 15,
    "filters": {
      "keywords": "transfer ERC20 token",
      "impact": ["HIGH", "MEDIUM"],
      "qualityScore": 3
    }
  }'
```

#### Price/Oracle Usage
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 15,
    "filters": {
      "tags": [{"value": "Oracle"}, {"value": "Price Manipulation"}],
      "impact": ["HIGH"]
    }
  }'
```

### Step 3: Map Findings to Code

For each relevant finding, check if your code has similar patterns:

```markdown
## Finding: [Title from Solodit]
- Pattern in finding: [Description]
- Present in our code? [Yes/No/Partial]
- Location if yes: [File:Line]
- Mitigation applied? [Yes/No]
- Action required: [Description]
```

### Step 4: Create Review Checklist

Based on findings, create a specific checklist for this code:

```markdown
## Security Review Checklist for [PR/Feature Name]

### Reentrancy
- [ ] All state changes before external calls
- [ ] ReentrancyGuard on vulnerable functions
- [ ] Cross-contract reentrancy considered

### Access Control
- [ ] Admin functions properly protected
- [ ] No missing modifiers
- [ ] Role validation complete

### Input Validation
- [ ] All user inputs validated
- [ ] Bounds checked
- [ ] Edge cases handled (0, max, first)

### Math Operations
- [ ] No overflow/underflow possible
- [ ] Rounding direction favors protocol
- [ ] Division by zero prevented
```

### Step 5: Document Review Results

Record the review in a structured format:

```markdown
## Security Review: [Feature/PR]
Date: [Date]
Reviewer: [Name]
Solodit Findings Referenced: [Count]

### Issues Found
1. [Issue description + severity]
2. [Issue description + severity]

### Issues Resolved
1. [How each issue was fixed]

### Accepted Risks
1. [Any known issues accepted and why]
```

## Quick Review Queries

### For Any Code Change
```bash
# General security patterns
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "impact": ["HIGH"],
      "qualityScore": 5,
      "sortField": "Quality"
    }
  }'
```

### For Function-Specific Keywords
```bash
# Replace "yourKeyword" with function-related term
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 15,
    "filters": {
      "keywords": "yourKeyword",
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

## Code Pattern Quick Reference

| Code Pattern | Query Tags | Priority |
|--------------|------------|----------|
| `call{}()` | Reentrancy | HIGH |
| `delegatecall` | Logic Error, Access Control | HIGH |
| `transfer/transferFrom` | Reentrancy, Logic Error | MEDIUM |
| `latestRoundData` | Oracle | HIGH |
| `getReserves` | Price Manipulation | HIGH |
| `onlyOwner/onlyAdmin` | Access Control | HIGH |
| `block.timestamp` | Front-running, Logic Error | MEDIUM |
| `for/while loops` | DoS, Gas | MEDIUM |

## Output

After completing this workflow, you should have:

1. **Pattern identification** - What risky patterns exist in the code
2. **Relevant findings** - Matching vulnerabilities from Solodit
3. **Specific checklist** - Tailored to this code review
4. **Issue list** - Found problems with severity
5. **Resolution status** - How each issue was addressed

## Next Steps

- For deeper function-level analysis → [function-security-check.md](function-security-check.md)
- For comprehensive audit prep → [audit-preparation.md](audit-preparation.md)
