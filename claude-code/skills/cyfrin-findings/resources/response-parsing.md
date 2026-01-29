# Response Parsing Guide

How to extract actionable insights from Cyfrin Solodit API responses.

---

## Response Structure Overview

```json
{
  "findings": [...],           // Array of finding objects
  "metadata": {...},           // Pagination info
  "rateLimit": {...}           // Rate limit status
}
```

---

## Extracting Key Information

### Essential Fields

```javascript
// For each finding, extract:
const essential = {
  // Identity
  id: finding.id,
  title: finding.title,
  
  // Severity
  severity: finding.impact,        // HIGH, MEDIUM, LOW, GAS
  
  // Content
  summary: finding.summary,        // AI-generated summary
  content: finding.content,        // Full markdown description
  
  // Quality Indicators
  qualityScore: finding.quality_score,    // 0-5
  rarityScore: finding.general_score,     // 0-5
  
  // Source
  firm: finding.firm_name,
  protocol: finding.protocol_name,
  reportUrl: finding.report_url,
  date: finding.report_date,
  
  // Tags
  tags: finding.issues_issuetagscore?.map(t => t.tags_tag.title) || []
};
```

### Parsing Tags

```javascript
function extractTags(finding) {
  if (!finding.issues_issuetagscore) return [];
  
  return finding.issues_issuetagscore.map(tagScore => ({
    name: tagScore.tags_tag.title,
    slug: tagScore.tags_tag.slug,
    score: tagScore.score
  }));
}

// Get primary vulnerability type
function getPrimaryTag(finding) {
  const tags = extractTags(finding);
  if (tags.length === 0) return null;
  
  // Sort by score, highest first
  return tags.sort((a, b) => b.score - a.score)[0].name;
}
```

---

## Content Extraction Patterns

### Extract Vulnerability Pattern

The `content` field is markdown. Extract code patterns:

```javascript
function extractCodeBlocks(content) {
  const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g;
  const blocks = [];
  
  let match;
  while ((match = codeBlockRegex.exec(content)) !== null) {
    blocks.push({
      language: match[1] || 'text',
      code: match[2].trim()
    });
  }
  
  return blocks;
}

// Usage
const blocks = extractCodeBlocks(finding.content);
const solidityBlocks = blocks.filter(b => b.language === 'solidity');
```

### Extract Mitigation/Recommendation

```javascript
function extractMitigation(content) {
  // Common section headers for mitigations
  const patterns = [
    /#+\s*(?:Mitigation|Recommendation|Fix|Remediation|Solution)\s*\n([\s\S]*?)(?=\n#|\n---|$)/i,
    /\*\*(?:Mitigation|Recommendation|Fix)\*\*[:\s]*([\s\S]*?)(?=\n\n|\n#|$)/i
  ];
  
  for (const pattern of patterns) {
    const match = content.match(pattern);
    if (match) return match[1].trim();
  }
  
  return null;
}
```

### Extract Impact Description

```javascript
function extractImpact(content) {
  const patterns = [
    /#+\s*(?:Impact|Severity|Risk)\s*\n([\s\S]*?)(?=\n#|\n---|$)/i,
    /\*\*(?:Impact|Risk)\*\*[:\s]*([\s\S]*?)(?=\n\n|\n#|$)/i
  ];
  
  for (const pattern of patterns) {
    const match = content.match(pattern);
    if (match) return match[1].trim();
  }
  
  return null;
}
```

---

## Grouping and Analysis

### Group by Vulnerability Type

```javascript
function groupByVulnerability(findings) {
  const groups = {};
  
  for (const finding of findings) {
    const primaryTag = getPrimaryTag(finding) || 'uncategorized';
    
    if (!groups[primaryTag]) {
      groups[primaryTag] = [];
    }
    groups[primaryTag].push(finding);
  }
  
  return groups;
}
```

### Group by Severity

```javascript
function groupBySeverity(findings) {
  return {
    HIGH: findings.filter(f => f.impact === 'HIGH'),
    MEDIUM: findings.filter(f => f.impact === 'MEDIUM'),
    LOW: findings.filter(f => f.impact === 'LOW'),
    GAS: findings.filter(f => f.impact === 'GAS')
  };
}
```

### Get Tag Statistics

```javascript
function getTagStatistics(findings) {
  const tagCounts = {};
  
  for (const finding of findings) {
    const tags = extractTags(finding);
    for (const tag of tags) {
      tagCounts[tag.name] = (tagCounts[tag.name] || 0) + 1;
    }
  }
  
  // Sort by count
  return Object.entries(tagCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([tag, count]) => ({ tag, count }));
}
```

---

## Building Summaries

### Generate Finding Summary

```javascript
function generateSummary(finding) {
  return {
    title: finding.title,
    severity: finding.impact,
    type: getPrimaryTag(finding),
    protocol: finding.protocol_name,
    date: finding.report_date,
    quality: finding.quality_score,
    
    // One-liner
    oneLiner: finding.summary || finding.title,
    
    // Source reference
    source: `${finding.firm_name} - ${finding.protocol_name}`
  };
}
```

### Generate Research Report

```javascript
function generateResearchReport(findings) {
  const bySeverity = groupBySeverity(findings);
  const byType = groupByVulnerability(findings);
  const tagStats = getTagStatistics(findings);
  
  return {
    totalFindings: findings.length,
    
    bySeverity: {
      high: bySeverity.HIGH.length,
      medium: bySeverity.MEDIUM.length,
      low: bySeverity.LOW.length,
      gas: bySeverity.GAS.length
    },
    
    topVulnerabilities: tagStats.slice(0, 10),
    
    findings: findings.map(generateSummary)
  };
}
```

---

## Pagination Handling

### Fetch All Results

```javascript
async function fetchAllFindings(baseFilters, maxPages = 10) {
  const allFindings = [];
  let page = 1;
  let totalPages = 1;
  
  while (page <= totalPages && page <= maxPages) {
    const response = await queryAPI({
      page,
      pageSize: 100,
      filters: baseFilters
    });
    
    allFindings.push(...response.findings);
    totalPages = response.metadata.totalPages;
    page++;
    
    // Respect rate limits
    if (response.rateLimit.remaining < 5) {
      await sleep(5000);
    }
  }
  
  return allFindings;
}
```

---

## Output Formatting

### Markdown Output

```javascript
function toMarkdown(findings) {
  let md = '# Security Findings Research\n\n';
  
  const bySeverity = groupBySeverity(findings);
  
  for (const severity of ['HIGH', 'MEDIUM', 'LOW']) {
    const group = bySeverity[severity];
    if (group.length === 0) continue;
    
    md += `## ${severity} Severity (${group.length})\n\n`;
    
    for (const finding of group) {
      md += `### ${finding.title}\n\n`;
      md += `**Source:** ${finding.firm_name} - ${finding.protocol_name}\n\n`;
      md += `**Tags:** ${extractTags(finding).map(t => t.name).join(', ')}\n\n`;
      md += `${finding.summary || ''}\n\n`;
      md += '---\n\n';
    }
  }
  
  return md;
}
```

### JSON Output for Checklist

```javascript
function toChecklist(findings) {
  const byType = groupByVulnerability(findings);
  
  return Object.entries(byType).map(([type, group]) => ({
    category: type,
    count: group.length,
    checkItems: group.map(f => ({
      check: f.title,
      severity: f.impact,
      source: f.report_url
    }))
  }));
}
```

---

## Rate Limit Monitoring

### Track Rate Limits

```javascript
class RateLimitTracker {
  constructor() {
    this.limit = 20;
    this.remaining = 20;
    this.resetTime = null;
  }
  
  update(rateLimit) {
    this.limit = rateLimit.limit;
    this.remaining = rateLimit.remaining;
    this.resetTime = new Date(rateLimit.reset * 1000);
  }
  
  canMakeRequest() {
    return this.remaining > 0;
  }
  
  async waitIfNeeded() {
    if (this.remaining > 0) return;
    
    const now = new Date();
    const waitMs = this.resetTime - now + 1000; // +1s buffer
    
    if (waitMs > 0) {
      console.log(`Rate limited. Waiting ${waitMs}ms...`);
      await sleep(waitMs);
    }
  }
}
```

---

## Error Handling

```javascript
async function safeQuery(params) {
  try {
    const response = await queryAPI(params);
    return { success: true, data: response };
  } catch (error) {
    if (error.status === 429) {
      // Rate limited
      const retryAfter = error.retryAfter || 60;
      await sleep(retryAfter * 1000);
      return safeQuery(params); // Retry
    }
    
    if (error.status === 401) {
      return { 
        success: false, 
        error: 'Invalid API key. Check CYFRIN_API_KEY.' 
      };
    }
    
    return { 
      success: false, 
      error: error.message 
    };
  }
}
```
