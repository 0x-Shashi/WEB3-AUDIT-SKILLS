# Response Parsing

## Quick Start

This guide covers how to understand and extract actionable insights from Solodit API responses. Learn to parse the response structure, identify key fields, and build useful summaries from findings.

## Complete Response Structure

```json
{
  "findings": [
    {
      "id": "12345",
      "slug": "h-01-reentrancy-in-withdraw-function",
      "title": "Reentrancy in withdraw function allows draining of funds",
      "content": "## Summary\nThe withdraw function...",
      "summary": "Attacker can drain funds via reentrancy",
      "kind": "MARKDOWN",
      "impact": "HIGH",
      "quality_score": 4,
      "general_score": 3,
      "report_date": "2025-01-15",
      "auditfirm_id": "abc123",
      "firm_name": "Cyfrin",
      "firm_logo_square": "https://...",
      "auditfirms_auditfirm": {
        "name": "Cyfrin",
        "logo_square": "https://..."
      },
      "protocol_id": "def456",
      "protocol_name": "ExampleDeFi",
      "protocols_protocol": {
        "name": "ExampleDeFi",
        "protocols_protocolcategoryscore": [
          {
            "protocols_protocolcategory": {"title": "DeFi"},
            "score": 5
          }
        ]
      },
      "contest_id": "ghi789",
      "contest_link": "https://...",
      "contest_prize_txt": "$50,000",
      "sponsor_name": "ExampleDeFi",
      "sponsor_link": "https://...",
      "finders_count": 3,
      "issues_issue_finders": [
        {"wardens_warden": {"handle": "auditor1"}},
        {"wardens_warden": {"handle": "auditor2"}}
      ],
      "issues_issuetagscore": [
        {"tags_tag": {"title": "Reentrancy"}},
        {"tags_tag": {"title": "Access Control"}}
      ],
      "source_link": "https://...",
      "github_link": "https://...",
      "pdf_link": "https://...",
      "pdf_page_from": 15,
      "bookmarked": false,
      "read": false
    }
  ],
  "metadata": {
    "totalResults": 50000,
    "currentPage": 1,
    "pageSize": 50,
    "totalPages": 1000,
    "elapsed": 0.123
  },
  "rateLimit": {
    "limit": 20,
    "remaining": 19,
    "reset": 1706400000
  }
}
```

## Key Fields to Extract

### Critical Information Fields

| Field | Purpose | Use Case |
|-------|---------|----------|
| `title` | One-line vulnerability summary | Quick scanning, reports |
| `impact` | Severity level | Prioritization |
| `content` | Full markdown description | Deep analysis |
| `summary` | AI-generated summary | Quick understanding |
| `quality_score` | Finding quality (0-5) | Filter reliability |
| `general_score` | Rarity score (0-5) | Unique findings |

### Source Information

| Field | Purpose | Use Case |
|-------|---------|----------|
| `firm_name` | Audit company | Credibility |
| `protocol_name` | Affected protocol | Context |
| `report_date` | When reported | Recency |
| `source_link` | Original report | Deep dive |
| `github_link` | Code reference | Technical analysis |

### Classification Fields

| Field | Purpose | Use Case |
|-------|---------|----------|
| `issues_issuetagscore` | Vulnerability tags | Categorization |
| `protocols_protocolcategoryscore` | Protocol categories | Context |
| `finders_count` | Number of discoverers | Rarity assessment |

## Parsing Examples

### JavaScript/TypeScript

```javascript
async function parseFindings(response) {
  const { findings, metadata, rateLimit } = response;
  
  // Extract key information from each finding
  const parsed = findings.map(finding => ({
    // Basic info
    id: finding.id,
    title: finding.title,
    severity: finding.impact,
    quality: finding.quality_score,
    rarity: finding.general_score,
    
    // Summary (prefer AI summary, fallback to first 200 chars of content)
    summary: finding.summary || finding.content?.substring(0, 200) + '...',
    
    // Source
    firm: finding.firm_name,
    protocol: finding.protocol_name,
    date: finding.report_date,
    
    // Tags
    tags: finding.issues_issuetagscore?.map(t => t.tags_tag.title) || [],
    
    // Categories
    categories: finding.protocols_protocol?.protocols_protocolcategoryscore
      ?.map(c => c.protocols_protocolcategory.title) || [],
    
    // Links
    reportLink: finding.source_link,
    codeLink: finding.github_link,
    
    // Finders
    findersCount: finding.finders_count,
    finders: finding.issues_issue_finders?.map(f => f.wardens_warden.handle) || []
  }));
  
  return {
    findings: parsed,
    total: metadata.totalResults,
    page: metadata.currentPage,
    pages: metadata.totalPages,
    rateLimitRemaining: rateLimit.remaining
  };
}

// Usage
const response = await fetch(/* API call */);
const data = await response.json();
const parsed = parseFindings(data);

parsed.findings.forEach(f => {
  console.log(`[${f.severity}] ${f.title}`);
  console.log(`  Quality: ${f.quality}/5 | Rarity: ${f.rarity}/5`);
  console.log(`  Tags: ${f.tags.join(', ')}`);
  console.log(`  By: ${f.firm}`);
  console.log(`---`);
});
```

### Python

```python
def parse_findings(response):
    findings = response.get('findings', [])
    metadata = response.get('metadata', {})
    rate_limit = response.get('rateLimit', {})
    
    parsed = []
    for finding in findings:
        parsed.append({
            # Basic info
            'id': finding.get('id'),
            'title': finding.get('title'),
            'severity': finding.get('impact'),
            'quality': finding.get('quality_score'),
            'rarity': finding.get('general_score'),
            
            # Summary
            'summary': finding.get('summary') or 
                      (finding.get('content', '')[:200] + '...'),
            
            # Source
            'firm': finding.get('firm_name'),
            'protocol': finding.get('protocol_name'),
            'date': finding.get('report_date'),
            
            # Tags
            'tags': [t['tags_tag']['title'] 
                    for t in finding.get('issues_issuetagscore', [])],
            
            # Categories
            'categories': [c['protocols_protocolcategory']['title']
                          for c in finding.get('protocols_protocol', {})
                          .get('protocols_protocolcategoryscore', [])],
            
            # Links
            'report_link': finding.get('source_link'),
            'code_link': finding.get('github_link'),
            
            # Finders
            'finders_count': finding.get('finders_count'),
            'finders': [f['wardens_warden']['handle']
                       for f in finding.get('issues_issue_finders', [])]
        })
    
    return {
        'findings': parsed,
        'total': metadata.get('totalResults'),
        'page': metadata.get('currentPage'),
        'pages': metadata.get('totalPages'),
        'rate_limit_remaining': rate_limit.get('remaining')
    }

# Usage
import requests

response = requests.post(url, headers=headers, json=payload)
data = response.json()
parsed = parse_findings(data)

for f in parsed['findings']:
    print(f"[{f['severity']}] {f['title']}")
    print(f"  Quality: {f['quality']}/5 | Tags: {', '.join(f['tags'])}")
```

### Bash/jq

```bash
# Parse and format findings using jq
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{"page": 1, "pageSize": 10, "filters": {"impact": ["HIGH"]}}' \
  | jq '.findings[] | {
      title: .title,
      severity: .impact,
      quality: .quality_score,
      firm: .firm_name,
      tags: [.issues_issuetagscore[]?.tags_tag.title]
    }'
```

## Extracting Actionable Insights

### 1. Build a Vulnerability Summary

```javascript
function buildVulnerabilitySummary(findings) {
  const summary = {
    totalFindings: findings.length,
    bySeverity: {},
    byTag: {},
    byFirm: {},
    topVulnerabilities: []
  };
  
  findings.forEach(f => {
    // Count by severity
    summary.bySeverity[f.impact] = (summary.bySeverity[f.impact] || 0) + 1;
    
    // Count by tag
    f.issues_issuetagscore?.forEach(tag => {
      const tagName = tag.tags_tag.title;
      summary.byTag[tagName] = (summary.byTag[tagName] || 0) + 1;
    });
    
    // Count by firm
    if (f.firm_name) {
      summary.byFirm[f.firm_name] = (summary.byFirm[f.firm_name] || 0) + 1;
    }
  });
  
  // Top 5 findings by quality
  summary.topVulnerabilities = findings
    .sort((a, b) => b.quality_score - a.quality_score)
    .slice(0, 5)
    .map(f => ({
      title: f.title,
      severity: f.impact,
      quality: f.quality_score
    }));
  
  return summary;
}
```

### 2. Generate Security Checklist

```javascript
function generateChecklist(findings) {
  const checklist = [];
  const seenTags = new Set();
  
  findings.forEach(f => {
    f.issues_issuetagscore?.forEach(tag => {
      const tagName = tag.tags_tag.title;
      if (!seenTags.has(tagName)) {
        seenTags.add(tagName);
        checklist.push({
          category: tagName,
          check: `Verify protection against ${tagName}`,
          severity: f.impact,
          example: f.title
        });
      }
    });
  });
  
  return checklist.sort((a, b) => {
    const severityOrder = { HIGH: 0, MEDIUM: 1, LOW: 2, GAS: 3 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });
}
```

### 3. Extract Code Patterns

```javascript
function extractCodePatterns(findings) {
  return findings
    .filter(f => f.content && f.quality_score >= 3)
    .map(f => {
      // Extract code blocks from markdown content
      const codeBlocks = f.content.match(/```[\s\S]*?```/g) || [];
      
      return {
        title: f.title,
        severity: f.impact,
        tags: f.issues_issuetagscore?.map(t => t.tags_tag.title),
        codeExamples: codeBlocks.slice(0, 3) // First 3 code blocks
      };
    })
    .filter(f => f.codeExamples.length > 0);
}
```

## Building Summaries from Multiple Findings

### Aggregation Template

```javascript
function aggregateFindings(findings, groupBy = 'tag') {
  const groups = {};
  
  findings.forEach(f => {
    let keys = [];
    
    if (groupBy === 'tag') {
      keys = f.issues_issuetagscore?.map(t => t.tags_tag.title) || ['Untagged'];
    } else if (groupBy === 'severity') {
      keys = [f.impact];
    } else if (groupBy === 'firm') {
      keys = [f.firm_name || 'Unknown'];
    }
    
    keys.forEach(key => {
      if (!groups[key]) {
        groups[key] = {
          count: 0,
          highCount: 0,
          avgQuality: 0,
          examples: []
        };
      }
      
      groups[key].count++;
      if (f.impact === 'HIGH') groups[key].highCount++;
      groups[key].avgQuality += f.quality_score;
      
      if (groups[key].examples.length < 3) {
        groups[key].examples.push(f.title);
      }
    });
  });
  
  // Calculate averages
  Object.keys(groups).forEach(key => {
    groups[key].avgQuality = (groups[key].avgQuality / groups[key].count).toFixed(1);
  });
  
  return groups;
}
```

## Handling Metadata

### Pagination Handling

```javascript
async function fetchAllFindings(filters, maxPages = 10) {
  const allFindings = [];
  let page = 1;
  let totalPages = 1;
  
  while (page <= totalPages && page <= maxPages) {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Cyfrin-API-Key': API_KEY
      },
      body: JSON.stringify({
        page,
        pageSize: 100,
        filters
      })
    });
    
    const data = await response.json();
    allFindings.push(...data.findings);
    
    totalPages = data.metadata.totalPages;
    
    // Respect rate limits
    if (data.rateLimit.remaining < 5) {
      const waitTime = (data.rateLimit.reset * 1000) - Date.now();
      await new Promise(r => setTimeout(r, Math.max(waitTime, 0)));
    }
    
    page++;
  }
  
  return allFindings;
}
```

### Rate Limit Monitoring

```javascript
function checkRateLimit(response) {
  const { rateLimit } = response;
  
  console.log(`Rate limit: ${rateLimit.remaining}/${rateLimit.limit}`);
  
  if (rateLimit.remaining <= 5) {
    console.warn(`⚠️ Warning: Only ${rateLimit.remaining} requests remaining`);
    const resetTime = new Date(rateLimit.reset * 1000);
    console.warn(`Resets at: ${resetTime.toISOString()}`);
  }
  
  if (rateLimit.remaining === 0) {
    throw new Error('Rate limit exceeded. Wait for reset.');
  }
  
  return rateLimit.remaining;
}
```

## Test This Parsing

```bash
# Get sample response for parsing
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 5,
    "filters": {
      "impact": ["HIGH"],
      "qualityScore": 4
    }
  }' | jq '{
    total: .metadata.totalResults,
    findings: [.findings[] | {
      title: .title,
      severity: .impact,
      quality: .quality_score,
      firm: .firm_name,
      tags: [.issues_issuetagscore[]?.tags_tag.title] | unique
    }],
    rateLimit: .rateLimit.remaining
  }'
```

**Expected Output:**
```json
{
  "total": 5000,
  "findings": [
    {
      "title": "Example vulnerability title",
      "severity": "HIGH",
      "quality": 5,
      "firm": "Cyfrin",
      "tags": ["Reentrancy", "Access Control"]
    }
  ],
  "rateLimit": 19
}
```

## Checklist for Response Parsing

- [ ] Handle null/undefined fields gracefully
- [ ] Extract tags from nested `issues_issuetagscore` structure
- [ ] Extract categories from nested `protocols_protocolcategoryscore`
- [ ] Calculate derived metrics (averages, counts)
- [ ] Monitor rate limit headers
- [ ] Implement pagination for large result sets
- [ ] Cache parsed results to avoid re-processing
- [ ] Build actionable summaries and checklists
