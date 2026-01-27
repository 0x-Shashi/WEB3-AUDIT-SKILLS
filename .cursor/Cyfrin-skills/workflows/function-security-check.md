# Function Security Check Workflow

## Purpose

Quick security validation for a single function or code pattern. Use this for rapid checks during development without a full code review.

## When to Use

- Just finished writing a function
- Unsure about a specific pattern
- Quick validation during coding
- Checking a pattern before using it

## Time Required

5-15 minutes per function

## Step-by-Step Workflow

### Step 1: Identify Function Type

What does your function do?

| Function Type | Common Keywords |
|--------------|-----------------|
| Token transfer | transfer, send, withdraw |
| Swap | swap, exchange, trade |
| Stake/Deposit | stake, deposit, supply |
| Unstake/Withdraw | unstake, withdraw, redeem |
| Price query | getPrice, oracle, feed |
| Admin action | set, update, pause, admin |
| Liquidation | liquidate, seize, repay |
| Claim/Harvest | claim, harvest, collect |

### Step 2: Quick Query by Function Type

```bash
# Replace "functionType" with relevant keywords
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 10,
    "filters": {
      "keywords": "functionType",
      "impact": ["HIGH"],
      "qualityScore": 4
    }
  }'
```

### Step 3: Check Against Top Findings

Review top 5 findings and verify:

1. Does your function have the same pattern?
2. Is the mitigation already applied?
3. Any edge cases you missed?

### Step 4: Pattern-Specific Check

Based on function patterns, run specific checks:

#### If function has external calls:
```solidity
// Check for:
// 1. State changes BEFORE external call
// 2. ReentrancyGuard modifier
// 3. No callback exploitation
```

#### If function handles tokens:
```solidity
// Check for:
// 1. Return value handling (SafeERC20)
// 2. Fee-on-transfer handling
// 3. Rebasing token handling
// 4. Proper approval patterns
```

#### If function has access control:
```solidity
// Check for:
// 1. Modifier present
// 2. Correct role checked
// 3. Two-step for critical changes
```

## Quick Reference Queries

### Withdraw Function
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 10,
    "filters": {
      "keywords": "withdraw reentrancy",
      "impact": ["HIGH"],
      "qualityScore": 4
    }
  }'
```

### Swap Function
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 10,
    "filters": {
      "keywords": "swap slippage",
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

### Deposit Function
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 10,
    "filters": {
      "keywords": "deposit first",
      "impact": ["HIGH"]
    }
  }'
```

### Admin Function
```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 10,
    "filters": {
      "tags": [{"value": "Access Control"}],
      "impact": ["HIGH"]
    }
  }'
```

## Function Checklist Templates

### Transfer/Withdraw Function
```markdown
- [ ] Reentrancy protection (CEI or modifier)
- [ ] Amount validation (> 0, <= balance)
- [ ] Recipient validation (not zero address)
- [ ] State updated before transfer
- [ ] Events emitted
```

### Deposit/Stake Function
```markdown
- [ ] Token amount validated
- [ ] Fee-on-transfer handling
- [ ] First depositor attack prevention
- [ ] Share calculation correct
- [ ] Events emitted
```

### Swap Function
```markdown
- [ ] Slippage protection (minAmountOut)
- [ ] Deadline parameter
- [ ] Price source validated
- [ ] Reentrancy protection
- [ ] Events emitted
```

### Admin Function
```markdown
- [ ] Access control modifier
- [ ] Parameter bounds checking
- [ ] Two-step if critical
- [ ] Timelock if needed
- [ ] Events emitted
```

## Output

After this quick check:

1. **Confidence level** - How confident are you in the function?
2. **Known risks** - What risks have you explicitly accepted?
3. **Mitigation status** - What protections are in place?

## When to Escalate

Escalate to full [code-review.md](code-review.md) workflow if:

- Function interacts with multiple contracts
- Complex state changes involved
- High value at risk
- Uncertainty remains after quick check
