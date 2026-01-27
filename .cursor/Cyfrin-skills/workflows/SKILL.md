# Workflows Skill

## Quick Start

This folder contains practical workflows for using the Solodit API at different stages of smart contract development and security research. Each workflow is a step-by-step guide optimized for specific use cases.

## Available Workflows

| Workflow | When to Use | Time Required |
|----------|-------------|---------------|
| [Pre-Development Research](pre-development-research.md) | Before writing code | 30-60 min |
| [Code Review](code-review.md) | During development | 15-30 min per feature |
| [Function Security Check](function-security-check.md) | Per function/pattern | 5-15 min |
| [Audit Preparation](audit-preparation.md) | Before external audit | 2-4 hours |
| [Vulnerability Learning](vulnerability-learning.md) | Ongoing education | Variable |

## Workflow Selection Matrix

| Your Situation | Recommended Workflow |
|----------------|---------------------|
| "Starting a new DeFi project" | Pre-Development Research |
| "Just wrote a new function" | Function Security Check |
| "Reviewing PR with security implications" | Code Review |
| "About to submit for external audit" | Audit Preparation |
| "Want to learn security patterns" | Vulnerability Learning |

## Quick Workflow Decision Tree

```
What are you doing?
│
├─► Starting new project
│   └─► [Pre-Development Research](pre-development-research.md)
│
├─► Writing/reviewing code
│   ├─► Single function → [Function Security Check](function-security-check.md)
│   └─► Full feature → [Code Review](code-review.md)
│
├─► Preparing for audit
│   └─► [Audit Preparation](audit-preparation.md)
│
└─► Learning/researching
    └─► [Vulnerability Learning](vulnerability-learning.md)
```

## Common Workflow Patterns

### Pattern 1: New Feature Development

1. **Research phase** (Pre-Development Research)
   - Identify similar protocols
   - Find common vulnerabilities
   - Create security requirements

2. **Implementation phase** (Function Security Check × N)
   - Check each function as you write it
   - Verify against known patterns

3. **Review phase** (Code Review)
   - Full feature security review
   - Cross-functional checks

### Pattern 2: Quick Security Validation

```bash
# For a specific function type
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 10,
    "filters": {
      "keywords": "your function keyword",
      "impact": ["HIGH"],
      "qualityScore": 4
    }
  }' | jq '.findings[] | {title, description: .description[0:200]}'
```

### Pattern 3: Comprehensive Security Audit

1. **Identify protocol category**
2. **Query by category + HIGH severity**
3. **Query by specific tags found in code**
4. **Query by similar protocols**
5. **Compile checklist from findings**
6. **Execute checklist against code**

## Integration with Development

### CI/CD Integration

```bash
#!/bin/bash
# pre-commit-security-check.sh

# Extract function names from changed files
FUNCTIONS=$(git diff --cached --name-only | xargs grep -h "function " | head -5)

for func in $FUNCTIONS; do
  # Query Solodit for relevant findings
  curl -s -X POST ... | jq '.findings | length' > /tmp/findings_count
  count=$(cat /tmp/findings_count)
  
  if [ "$count" -gt 0 ]; then
    echo "⚠️  Found $count relevant security findings for $func"
    echo "Run 'security-check $func' for details"
  fi
done
```

### IDE Integration Concept

```javascript
// Pseudo-code for IDE extension
async function onFunctionHover(functionName, functionBody) {
  const keywords = extractSecurityKeywords(functionBody);
  const findings = await querySolodit({
    keywords: keywords.join(" "),
    impact: ["HIGH", "MEDIUM"],
    pageSize: 5
  });
  
  if (findings.length > 0) {
    showSecurityWarning(functionName, findings);
  }
}
```

## Workflow Efficiency Tips

### 1. Cache Common Queries
```javascript
const commonQueries = {
  reentrancy: { tags: [{ value: "Reentrancy" }], impact: ["HIGH"] },
  oracle: { tags: [{ value: "Oracle" }], impact: ["HIGH"] },
  accessControl: { tags: [{ value: "Access Control" }], impact: ["HIGH"] }
};
```

### 2. Build Protocol-Specific Filters
```javascript
// For lending protocol development
const lendingFilters = {
  protocolCategory: [{ value: "Lending" }],
  tags: [{ value: "Oracle" }, { value: "Liquidation" }],
  impact: ["HIGH"]
};
```

### 3. Progressive Refinement
1. Start broad: `{ keywords: "swap" }`
2. Add category: `+ protocolCategory: ["DEX"]`
3. Add severity: `+ impact: ["HIGH"]`
4. Add quality: `+ qualityScore: 4`

## Test This Workflow Skill

```bash
# Quick test: Find workflow-relevant findings
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 5,
    "filters": {
      "impact": ["HIGH"],
      "qualityScore": 5,
      "sortField": "Quality"
    }
  }' | jq '.findings[] | {title, tags: [.issues_issuetagscore[]?.tags_tag.title] | unique}'
```

## Cross-Reference

- For vulnerability details → See [../vulnerability-tags/SKILL.md](../vulnerability-tags/SKILL.md)
- For protocol specifics → See [../protocol-categories/SKILL.md](../protocol-categories/SKILL.md)
- For API details → See [../api-integration/SKILL.md](../api-integration/SKILL.md)
