---
id: CYFRIN-RESPONSE-PARSING
title: Response Parsing and Data Normalization Guide
parent: cyfrin-findings
type: resource
last_updated: 2025-01-31
---

# Response Parsing Guide

This guide covers how to extract, normalize, categorize, and apply findings data from the Solodit API to enhance smart contract audits.

---

## Response Structure

Every `/findings` response contains two top-level objects:

```json
{
  "data": [ /* array of finding objects */ ],
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 50530,
    "total_pages": 1011
  }
}
```

Each finding object contains these key fields:

| Field | Type | Always Present | Description |
|-------|------|----------------|-------------|
| `id` | string | Yes | Unique finding identifier |
| `title` | string | Yes | Finding title (often prefixed with severity tag like `[H-02]`) |
| `severity` | string | Yes | `critical`, `high`, `medium`, `low`, or `info` |
| `description` | string | Yes | Detailed vulnerability explanation |
| `impact` | string | Usually | What an attacker can achieve |
| `recommendation` | string | Usually | How to fix the issue |
| `protocol` | string | Yes | Protocol name |
| `protocol_type` | string | Usually | Protocol category (lending, dex, etc.) |
| `chain` | string | Usually | Target blockchain |
| `category` | string | Yes | Primary vulnerability category |
| `tags` | array | Sometimes | Additional classification tags |
| `date` | string | Yes | Publication date (ISO 8601) |
| `auditor` | string | Yes | Audit firm or contest platform |
| `url` | string | Yes | Direct link to finding on Solodit |
| `code_references` | array | Sometimes | File paths, line numbers, code snippets |

---

## Extracting Key Information

### 1. Severity Normalization

Different audit platforms use slightly different severity naming. Normalize to a standard scale:

```javascript
function normalizeSeverity(raw) {
  const severity = raw.toLowerCase().trim();
  const map = {
    'critical': 'CRITICAL',
    'crit': 'CRITICAL',
    'high': 'HIGH',
    'h': 'HIGH',
    'medium': 'MEDIUM',
    'med': 'MEDIUM',
    'm': 'MEDIUM',
    'low': 'LOW',
    'l': 'LOW',
    'info': 'INFO',
    'informational': 'INFO',
    'gas': 'INFO',
    'qa': 'INFO',
    'non-critical': 'INFO'
  };
  return map[severity] || 'UNKNOWN';
}
```

### 2. Title Parsing

Finding titles often contain embedded severity and index info:

```javascript
function parseTitle(title) {
  // Examples:
  // "[H-02] Cross-function reentrancy allows draining of lending pool"
  // "[M-15] Incorrect rounding in share price calculation"
  // "Critical: Unprotected initialize function"
  
  const bracketMatch = title.match(/^\[([A-Z])-(\d+)\]\s*(.+)/);
  if (bracketMatch) {
    return {
      severityCode: bracketMatch[1],  // "H"
      index: parseInt(bracketMatch[2]), // 2
      cleanTitle: bracketMatch[3]       // "Cross-function reentrancy..."
    };
  }
  
  const colonMatch = title.match(/^(Critical|High|Medium|Low):\s*(.+)/i);
  if (colonMatch) {
    return {
      severityCode: colonMatch[1][0].toUpperCase(),
      index: null,
      cleanTitle: colonMatch[2]
    };
  }
  
  return { severityCode: null, index: null, cleanTitle: title };
}
```

### 3. Category Extraction

Map findings to the vulnerability taxonomy used in the skills system:

```javascript
const CATEGORY_MAP = {
  // Primary categories (from Solodit tags)
  'reentrancy': 'reentrancy',
  'oracle-manipulation': 'oracle-manipulation',
  'access-control': 'access-control',
  'flash-loan': 'flash-loan',
  'front-running': 'front-running',
  'mev': 'front-running',
  'rounding': 'precision',
  'precision': 'precision',
  'integer-overflow': 'precision',
  'dos': 'denial-of-service',
  'gas-griefing': 'denial-of-service',
  'logic-error': 'logic-error',
  'token-integration': 'token-integration',
  'erc20': 'token-integration',
  'erc721': 'token-integration',
  'erc4626': 'vault-patterns',
  'signature': 'cryptography',
  'replay': 'cryptography',
  'upgrade': 'proxy-patterns',
  'proxy': 'proxy-patterns',
  'initialization': 'proxy-patterns',
  'governance': 'governance',
  'timelock': 'governance',
  'bridge': 'cross-chain',
  'cross-chain': 'cross-chain',
  'liquidation': 'lending-patterns',
  'collateral': 'lending-patterns',
  'interest-rate': 'lending-patterns'
};

function mapCategory(rawCategory, tags = []) {
  // Check primary category
  const primary = CATEGORY_MAP[rawCategory];
  if (primary) return primary;
  
  // Check tags for secondary mapping
  for (const tag of tags) {
    const mapped = CATEGORY_MAP[tag];
    if (mapped) return mapped;
  }
  
  return 'uncategorized';
}
```

---

## Pattern Identification

Group findings to identify recurring vulnerability patterns:

### Frequency Analysis

```javascript
function analyzeFrequency(findings) {
  const categoryCount = {};
  const severityCount = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  const protocolTypeCount = {};
  const auditorCount = {};
  
  for (const finding of findings) {
    // Count by category
    const cat = finding.category || 'unknown';
    categoryCount[cat] = (categoryCount[cat] || 0) + 1;
    
    // Count by severity
    const sev = normalizeSeverity(finding.severity);
    severityCount[sev] = (severityCount[sev] || 0) + 1;
    
    // Count by protocol type
    if (finding.protocol_type) {
      protocolTypeCount[finding.protocol_type] = (protocolTypeCount[finding.protocol_type] || 0) + 1;
    }
    
    // Count by auditor
    auditorCount[finding.auditor] = (auditorCount[finding.auditor] || 0) + 1;
  }
  
  return {
    byCategory: sortDescending(categoryCount),
    bySeverity: severityCount,
    byProtocolType: sortDescending(protocolTypeCount),
    byAuditor: sortDescending(auditorCount),
    total: findings.length
  };
}
```

### Identifying Recurring Patterns

When grouping findings by category, look for:

1. **Common code patterns**: Similar function signatures, state variable layouts, or call sequences
2. **Protocol type correlation**: Which vulnerability types are most common in which protocol types
3. **Severity trends**: Whether a vulnerability type tends toward Critical/High or Medium/Low
4. **Temporal trends**: Whether certain attack vectors are increasing or decreasing in frequency
5. **Auditor distribution**: Whether certain auditors find more of a specific vulnerability type

---

## Applying Findings to Current Audit

### Step 1: Protocol Type Matching

```
Target: Lending protocol
→ Query: ?protocol_type=lending&severity=critical&per_page=50
→ Parse: Extract top 5 categories by frequency
→ Result: oracle-manipulation (32%), liquidation-logic (24%), access-control (18%), 
          interest-rate (14%), reentrancy (12%)
```

### Step 2: Code Pattern Comparison

For each finding in the results, extract the vulnerable code pattern and compare against the current codebase:

| Finding Pattern | What to Search For in Target |
|-----------------|------------------------------|
| Missing oracle freshness check | `latestRoundData()` without timestamp validation |
| Unprotected external call before state update | `call{value:` or `.transfer(` before state changes |
| Missing zero-address check | Constructor/initializer params without `require(addr != address(0))` |
| Unchecked return value | External calls without checking `success` boolean |
| Integer division before multiplication | `a / b * c` patterns (should be `a * c / b`) |

### Step 3: Mitigation Cross-Reference

For each matched pattern, extract the `recommendation` field from historical findings and verify the target codebase applies the fix:

```javascript
function extractMitigations(findings) {
  return findings
    .filter(f => f.recommendation && f.recommendation.length > 20)
    .map(f => ({
      vulnerability: f.title,
      category: f.category,
      mitigation: f.recommendation,
      protocol: f.protocol,
      severity: f.severity
    }));
}
```

### Step 4: Report Integration

Reference historical findings in audit reports for credibility:

```markdown
### Finding: Missing Oracle Freshness Check

**Severity**: HIGH

**Description**: The `getPrice()` function calls `latestRoundData()` without 
validating the `updatedAt` timestamp, allowing stale price data to be used.

**Historical Context**: This vulnerability has been identified in 145+ audit 
findings across lending and DEX protocols (Source: Solodit database). Notable 
instances include [Finding-XYZ in Aave V2] and [Finding-ABC in Compound].

**Recommendation**: Add a freshness check: 
`require(block.timestamp - updatedAt < STALENESS_THRESHOLD, "Stale price");`
```

---

## Output Formats

### Raw JSON (for programmatic use)

The default API response format. Use for integration into automated tools and scripts.

### Structured Summary (for audit preparation)

```javascript
function formatSummary(findings) {
  const analysis = analyzeFrequency(findings);
  
  return {
    overview: {
      total: analysis.total,
      severity: analysis.bySeverity,
      topCategories: Object.entries(analysis.byCategory).slice(0, 10)
    },
    topFindings: findings
      .filter(f => ['critical', 'high'].includes(f.severity.toLowerCase()))
      .slice(0, 20)
      .map(f => ({
        title: f.title,
        severity: f.severity,
        category: f.category,
        protocol: f.protocol,
        key_insight: f.description.substring(0, 200)
      })),
    checklist: Object.keys(analysis.byCategory).slice(0, 15).map(cat => ({
      category: cat,
      count: analysis.byCategory[cat],
      action: `Review all ${cat} patterns in target codebase`
    }))
  };
}
```

### Pattern Database Entry (for skills system)

```javascript
function toPatternEntry(findings, category) {
  const filtered = findings.filter(f => f.category === category);
  const analysis = analyzeFrequency(filtered);
  
  return {
    id: `PAT-${category.toUpperCase().replace(/-/g, '_')}`,
    title: `${category} Security Patterns`,
    finding_count: filtered.length,
    severity_distribution: analysis.bySeverity,
    examples: filtered.slice(0, 25).map(f => ({
      title: f.title,
      source: f.auditor,
      protocol: f.protocol,
      impact: f.severity.toUpperCase(),
      details: f.description,
      recommendation: f.recommendation
    }))
  };
}
```

---

## Data Quality Considerations

| Consideration | Impact | Mitigation |
|---------------|--------|------------|
| Missing `impact` field | Can't assess exploitability | Use severity as proxy |
| Inconsistent category names | Noisy frequency analysis | Apply `CATEGORY_MAP` normalization |
| Duplicate findings (contest platforms) | Inflated counts | Deduplicate by title similarity |
| Invalid/disputed findings | False positives in patterns | Filter by `status=confirmed` if available |
| Missing code references | Can't do code pattern matching | Rely on description text analysis |
| Different severity scales | Inconsistent severity counts | Apply `normalizeSeverity()` |
