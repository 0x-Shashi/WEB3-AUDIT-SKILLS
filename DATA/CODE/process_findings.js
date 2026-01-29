/**
 * Phase 2: Data Processing & Skill Generation Pipeline
 * 
 * Transforms raw Solodit findings into structured AI-consumable skill files
 * 
 * Input: DATA/raw/all_findings.json (50,530 findings)
 * Output: skills/ directory with organized pattern files
 */

const fs = require('fs');
const path = require('path');

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
  // Input files (relative to DATA folder)
  INPUT_FILE: path.join(__dirname, '..', 'raw', 'all_findings.json'),
  METADATA_FILE: path.join(__dirname, '..', 'raw', 'metadata.json'),
  
  // Output directory (skills folder at project root level)
  OUTPUT_DIR: path.join(__dirname, '..', '..', 'skills'),
  
  // Subdirectories
  PATTERNS_DIR: 'patterns',
  SEVERITY_DIR: 'severity',
  SOURCES_DIR: 'sources',
  CATEGORIES_DIR: 'categories',
  
  // Generation parameters
  MIN_EXAMPLES_PER_PATTERN: 5,
  MAX_EXAMPLES_PER_PATTERN: 25,
  MIN_TAG_FREQUENCY: 3,        // Only create files for tags with 3+ occurrences
  MIN_CONTENT_LENGTH: 100,     // Minimum content length for quality examples
  
  // Quality weights for scoring
  SEVERITY_SCORES: {
    'CRITICAL': 100,
    'HIGH': 75,
    'MEDIUM': 50,
    'LOW': 25,
    'GAS': 10
  }
};

// ============================================================================
// LOGGING UTILITY
// ============================================================================

class Logger {
  constructor() {
    this.startTime = Date.now();
  }
  
  elapsed() {
    return ((Date.now() - this.startTime) / 1000).toFixed(1);
  }
  
  log(msg) { console.log(`[${this.elapsed()}s] ${msg}`); }
  info(msg) { console.log(`[${this.elapsed()}s] ℹ️  ${msg}`); }
  success(msg) { console.log(`[${this.elapsed()}s] ✅ ${msg}`); }
  warn(msg) { console.log(`[${this.elapsed()}s] ⚠️  ${msg}`); }
  error(msg) { console.log(`[${this.elapsed()}s] ❌ ${msg}`); }
  step(num, total, msg) { console.log(`\n[${num}/${total}] ${msg}`); }
}

const logger = new Logger();

// ============================================================================
// DATA LOADING
// ============================================================================

function loadAllData() {
  logger.info('Loading raw findings data...');
  
  if (!fs.existsSync(CONFIG.INPUT_FILE)) {
    throw new Error(`Input file not found: ${CONFIG.INPUT_FILE}`);
  }
  
  const findingsRaw = fs.readFileSync(CONFIG.INPUT_FILE, 'utf8');
  const findings = JSON.parse(findingsRaw);
  
  let metadata = {};
  if (fs.existsSync(CONFIG.METADATA_FILE)) {
    metadata = JSON.parse(fs.readFileSync(CONFIG.METADATA_FILE, 'utf8'));
  }
  
  logger.success(`Loaded ${findings.length.toLocaleString()} findings`);
  
  return { findings, metadata };
}

// ============================================================================
// DATA EXTRACTION HELPERS
// ============================================================================

/**
 * Extract tags from a finding (handles nested structure)
 */
function extractTags(finding) {
  const tags = [];
  if (finding.issues_issuetagscore && Array.isArray(finding.issues_issuetagscore)) {
    finding.issues_issuetagscore.forEach(tagScore => {
      const title = tagScore?.tags_tag?.title;
      if (title) tags.push(title);
    });
  }
  return tags;
}

/**
 * Extract protocol categories from a finding
 */
function extractCategories(finding) {
  const categories = [];
  if (finding.protocols_protocol?.protocols_protocolcategoryscore) {
    finding.protocols_protocol.protocols_protocolcategoryscore.forEach(catScore => {
      const title = catScore?.protocols_protocolcategory?.title;
      if (title) categories.push(title);
    });
  }
  return categories;
}

/**
 * Extract audit firm name
 */
function extractFirm(finding) {
  return finding.firm_name || finding.auditfirms_auditfirm?.name || 'Unknown';
}

/**
 * Extract protocol name
 */
function extractProtocol(finding) {
  return finding.protocol_name || finding.protocols_protocol?.name || 'Unknown';
}

/**
 * Extract code blocks from content
 */
function extractCodeBlocks(content) {
  if (!content) return [];
  const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g;
  const blocks = [];
  let match;
  while ((match = codeBlockRegex.exec(content)) !== null) {
    blocks.push({
      language: match[1] || 'solidity',
      code: match[2].trim()
    });
  }
  return blocks;
}

// ============================================================================
// GROUPING & INDEXING
// ============================================================================

function groupFindings(findings) {
  logger.info('Grouping findings by category...');
  
  const grouped = {
    byTag: new Map(),
    bySeverity: new Map(),
    byFirm: new Map(),
    byCategory: new Map(),
    byProtocol: new Map()
  };
  
  // Initialize severity groups
  ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'GAS'].forEach(sev => {
    grouped.bySeverity.set(sev, []);
  });
  
  findings.forEach(finding => {
    // By severity
    const severity = finding.impact || 'LOW';
    if (grouped.bySeverity.has(severity)) {
      grouped.bySeverity.get(severity).push(finding);
    }
    
    // By tag
    const tags = extractTags(finding);
    tags.forEach(tag => {
      if (!grouped.byTag.has(tag)) {
        grouped.byTag.set(tag, []);
      }
      grouped.byTag.get(tag).push(finding);
    });
    
    // By firm (source)
    const firm = extractFirm(finding);
    if (!grouped.byFirm.has(firm)) {
      grouped.byFirm.set(firm, []);
    }
    grouped.byFirm.get(firm).push(finding);
    
    // By category
    const categories = extractCategories(finding);
    categories.forEach(cat => {
      if (!grouped.byCategory.has(cat)) {
        grouped.byCategory.set(cat, []);
      }
      grouped.byCategory.get(cat).push(finding);
    });
    
    // By protocol
    const protocol = extractProtocol(finding);
    if (!grouped.byProtocol.has(protocol)) {
      grouped.byProtocol.set(protocol, []);
    }
    grouped.byProtocol.get(protocol).push(finding);
  });
  
  logger.success(`Grouped by: ${grouped.byTag.size} tags, ${grouped.bySeverity.size} severities, ${grouped.byFirm.size} firms, ${grouped.byCategory.size} categories`);
  
  return grouped;
}

// ============================================================================
// QUALITY SCORING
// ============================================================================

function scoreFinding(finding) {
  let score = 0;
  
  // Severity score (0-100)
  const severity = finding.impact || 'LOW';
  score += CONFIG.SEVERITY_SCORES[severity] || 25;
  
  // Content length score (0-50)
  const contentLength = (finding.content || '').length;
  if (contentLength > 500) score += 50;
  else if (contentLength > 200) score += 30;
  else if (contentLength > 100) score += 15;
  
  // Has code examples (0-30)
  const codeBlocks = extractCodeBlocks(finding.content);
  if (codeBlocks.length > 0) score += 30;
  
  // Has source link (0-10)
  if (finding.source_link) score += 10;
  
  // Quality/rarity scores from API (0-10)
  score += (finding.quality_score || 0) * 2;
  score += (finding.general_score || 0) * 2;
  
  return score;
}

function selectBestExamples(findings, maxCount = CONFIG.MAX_EXAMPLES_PER_PATTERN) {
  // Score all findings
  const scored = findings.map(f => ({
    finding: f,
    score: scoreFinding(f)
  }));
  
  // Sort by score descending
  scored.sort((a, b) => b.score - a.score);
  
  // Filter for minimum content quality
  const quality = scored.filter(s => 
    (s.finding.content || '').length >= CONFIG.MIN_CONTENT_LENGTH
  );
  
  // Take top N, avoiding similar titles (simple dedup)
  const selected = [];
  const seenTitles = new Set();
  
  for (const item of quality) {
    // Simple title similarity check
    const titleKey = (item.finding.title || '').toLowerCase().slice(0, 50);
    if (!seenTitles.has(titleKey)) {
      selected.push(item.finding);
      seenTitles.add(titleKey);
      if (selected.length >= maxCount) break;
    }
  }
  
  return selected;
}

// ============================================================================
// MARKDOWN GENERATION
// ============================================================================

/**
 * Escape markdown special characters in text
 */
function escapeMarkdown(text) {
  if (!text) return '';
  return text.replace(/[<>]/g, '');
}

/**
 * Generate a pattern markdown file for a specific tag/vulnerability type
 */
function generatePatternMarkdown(tagName, findings, allFindings) {
  const examples = selectBestExamples(findings);
  
  // Calculate severity distribution
  const severityDist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, GAS: 0 };
  findings.forEach(f => {
    const sev = f.impact || 'LOW';
    if (severityDist[sev] !== undefined) severityDist[sev]++;
  });
  
  // Get common firms
  const firmCounts = new Map();
  findings.forEach(f => {
    const firm = extractFirm(f);
    firmCounts.set(firm, (firmCounts.get(firm) || 0) + 1);
  });
  const topFirms = Array.from(firmCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name]) => name);
  
  const percentage = ((findings.length / allFindings.length) * 100).toFixed(2);
  
  let md = `# ${tagName} Security Patterns

## Overview

**Frequency**: ${findings.length.toLocaleString()} occurrences (${percentage}% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| ${severityDist.CRITICAL} | ${severityDist.HIGH} | ${severityDist.MEDIUM} | ${severityDist.LOW} | ${severityDist.GAS} |

**Common Sources**: ${topFirms.join(', ')}

---

## Detection Checklist

- [ ] Check for ${tagName.toLowerCase()} vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

`;

  // Add examples
  examples.forEach((finding, idx) => {
    const firm = extractFirm(finding);
    const protocol = extractProtocol(finding);
    const codeBlocks = extractCodeBlocks(finding.content);
    
    md += `### Example ${idx + 1}: ${escapeMarkdown(finding.title || 'Untitled')}

**Source**: ${firm}
**Protocol**: ${protocol}
**Impact**: ${finding.impact || 'Unknown'}

`;
    
    // Add truncated content (first 1500 chars to keep file sizes manageable)
    const content = (finding.content || '').trim();
    if (content.length > 0) {
      const truncated = content.length > 1500 ? content.slice(0, 1500) + '\n\n*[Content truncated...]*' : content;
      md += `**Details**:\n\n${truncated}\n\n`;
    }
    
    // Add source link if available
    if (finding.source_link) {
      md += `**Reference**: [View Original Finding](${finding.source_link})\n\n`;
    }
    
    md += `---\n\n`;
  });

  md += `## Statistics

- Total findings analyzed: ${findings.length.toLocaleString()}
- Examples shown: ${examples.length}
- Data source: Cyfrin Solodit (${allFindings.length.toLocaleString()} total findings)
- Last updated: ${new Date().toISOString().split('T')[0]}
`;

  return md;
}

/**
 * Generate severity-based markdown file
 */
function generateSeverityMarkdown(severity, findings, allFindings) {
  const examples = selectBestExamples(findings, 50); // More examples for severity files
  
  const percentage = ((findings.length / allFindings.length) * 100).toFixed(2);
  
  // Group by tag within severity
  const tagCounts = new Map();
  findings.forEach(f => {
    extractTags(f).forEach(tag => {
      tagCounts.set(tag, (tagCounts.get(tag) || 0) + 1);
    });
  });
  const topTags = Array.from(tagCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20);
  
  let md = `# ${severity} Severity Findings

## Overview

**Total Findings**: ${findings.length.toLocaleString()} (${percentage}% of all findings)

## Top Vulnerability Types at ${severity} Severity

| Rank | Vulnerability Type | Count |
|------|-------------------|-------|
`;

  topTags.forEach(([tag, count], idx) => {
    md += `| ${idx + 1} | ${tag} | ${count} |\n`;
  });

  md += `
---

## Representative Examples

`;

  examples.slice(0, 30).forEach((finding, idx) => {
    const firm = extractFirm(finding);
    const protocol = extractProtocol(finding);
    const tags = extractTags(finding);
    
    md += `### ${idx + 1}. ${escapeMarkdown(finding.title || 'Untitled')}

- **Source**: ${firm}
- **Protocol**: ${protocol}
- **Tags**: ${tags.length > 0 ? tags.join(', ') : 'None'}

`;
    
    // Shorter content for severity files
    const content = (finding.content || '').trim();
    if (content.length > 0) {
      const truncated = content.length > 800 ? content.slice(0, 800) + '...' : content;
      md += `${truncated}\n\n`;
    }
    
    if (finding.source_link) {
      md += `[View Full Finding](${finding.source_link})\n\n`;
    }
    
    md += `---\n\n`;
  });

  md += `
## Statistics

- Total ${severity} findings: ${findings.length.toLocaleString()}
- Examples shown: ${Math.min(examples.length, 30)}
- Last updated: ${new Date().toISOString().split('T')[0]}
`;

  return md;
}

/**
 * Generate source/firm-based markdown file
 */
function generateSourceMarkdown(firmName, findings, allFindings) {
  const examples = selectBestExamples(findings, 20);
  const percentage = ((findings.length / allFindings.length) * 100).toFixed(2);
  
  // Severity distribution
  const severityDist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, GAS: 0 };
  findings.forEach(f => {
    const sev = f.impact || 'LOW';
    if (severityDist[sev] !== undefined) severityDist[sev]++;
  });
  
  // Top tags
  const tagCounts = new Map();
  findings.forEach(f => {
    extractTags(f).forEach(tag => {
      tagCounts.set(tag, (tagCounts.get(tag) || 0) + 1);
    });
  });
  const topTags = Array.from(tagCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);
  
  let md = `# ${firmName} - Audit Findings

## Overview

**Total Findings**: ${findings.length.toLocaleString()} (${percentage}% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| ${severityDist.CRITICAL} | ${severityDist.HIGH} | ${severityDist.MEDIUM} | ${severityDist.LOW} | ${severityDist.GAS} |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|
`;

  topTags.forEach(([tag, count]) => {
    md += `| ${tag} | ${count} |\n`;
  });

  md += `
---

## Notable Findings

`;

  examples.slice(0, 15).forEach((finding, idx) => {
    const protocol = extractProtocol(finding);
    
    md += `### ${idx + 1}. ${escapeMarkdown(finding.title || 'Untitled')}

**Protocol**: ${protocol} | **Impact**: ${finding.impact || 'Unknown'}

`;
    
    const content = (finding.content || '').trim();
    if (content.length > 0) {
      const truncated = content.length > 600 ? content.slice(0, 600) + '...' : content;
      md += `${truncated}\n\n`;
    }
    
    md += `---\n\n`;
  });

  md += `
## Statistics

- Total findings from ${firmName}: ${findings.length.toLocaleString()}
- Last updated: ${new Date().toISOString().split('T')[0]}
`;

  return md;
}

// ============================================================================
// MASTER FILES GENERATION
// ============================================================================

function generateMasterChecklist(grouped, allFindings) {
  // Sort tags by frequency
  const tagsByFreq = Array.from(grouped.byTag.entries())
    .map(([tag, findings]) => ({ tag, count: findings.length }))
    .sort((a, b) => b.count - a.count);
  
  let md = `# 🛡️ Smart Contract Security Master Checklist

*Based on ${allFindings.length.toLocaleString()} real audit findings from Code4rena, Sherlock, Cyfrin, and 20+ audit platforms*

---

## 🔴 CRITICAL PRIORITY (Top 20 Most Common)

`;

  // Top 20
  tagsByFreq.slice(0, 20).forEach((item, idx) => {
    const pct = ((item.count / allFindings.length) * 100).toFixed(2);
    const filename = item.tag.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '-patterns.md';
    
    md += `### ${idx + 1}. ${item.tag} (${item.count} occurrences - ${pct}%)

- [ ] Review all instances for ${item.tag.toLowerCase()} vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

📚 **Pattern Reference**: [patterns/${filename}](patterns/${filename})

---

`;
  });

  md += `## 🟡 HIGH PRIORITY (Ranks 21-50)

| Rank | Vulnerability Type | Count | % of Total |
|------|-------------------|-------|------------|
`;

  tagsByFreq.slice(20, 50).forEach((item, idx) => {
    const pct = ((item.count / allFindings.length) * 100).toFixed(3);
    md += `| ${idx + 21} | ${item.tag} | ${item.count} | ${pct}% |\n`;
  });

  md += `

## 🟢 MEDIUM PRIORITY (Ranks 51-100)

| Rank | Vulnerability Type | Count |
|------|-------------------|-------|
`;

  tagsByFreq.slice(50, 100).forEach((item, idx) => {
    md += `| ${idx + 51} | ${item.tag} | ${item.count} |\n`;
  });

  md += `

---

## 📊 Statistics

- **Total Vulnerabilities Analyzed**: ${allFindings.length.toLocaleString()}
- **Unique Vulnerability Types**: ${tagsByFreq.length}
- **Checklist Coverage**: Top ${Math.min(100, tagsByFreq.length)} vulnerability types
- **Last Updated**: ${new Date().toISOString().split('T')[0]}

## 📁 Quick Links

- [All Pattern Files](patterns/)
- [Severity Analysis](severity/)
- [Audit Source Analysis](sources/)
- [Full Statistics](STATISTICS.md)
- [Searchable Index](INDEX.md)
`;

  return md;
}

function generateStatistics(findings, grouped, metadata) {
  const severityCounts = {};
  grouped.bySeverity.forEach((list, sev) => {
    severityCounts[sev] = list.length;
  });
  
  const topTags = Array.from(grouped.byTag.entries())
    .map(([tag, list]) => ({ tag, count: list.length }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 50);
  
  const topFirms = Array.from(grouped.byFirm.entries())
    .map(([firm, list]) => ({ firm, count: list.length }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);
  
  const topCategories = Array.from(grouped.byCategory.entries())
    .map(([cat, list]) => ({ category: cat, count: list.length }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  let md = `# 📊 Solodit Findings Statistics

*Comprehensive analysis of ${findings.length.toLocaleString()} security findings*

---

## Overview

| Metric | Value |
|--------|-------|
| Total Findings | ${findings.length.toLocaleString()} |
| Unique Tags | ${grouped.byTag.size} |
| Audit Firms | ${grouped.byFirm.size} |
| Protocol Categories | ${grouped.byCategory.size} |
| Protocols Audited | ${grouped.byProtocol.size} |

---

## Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| CRITICAL | ${severityCounts.CRITICAL || 0} | ${(((severityCounts.CRITICAL || 0) / findings.length) * 100).toFixed(2)}% |
| HIGH | ${severityCounts.HIGH || 0} | ${(((severityCounts.HIGH || 0) / findings.length) * 100).toFixed(2)}% |
| MEDIUM | ${severityCounts.MEDIUM || 0} | ${(((severityCounts.MEDIUM || 0) / findings.length) * 100).toFixed(2)}% |
| LOW | ${severityCounts.LOW || 0} | ${(((severityCounts.LOW || 0) / findings.length) * 100).toFixed(2)}% |
| GAS | ${severityCounts.GAS || 0} | ${(((severityCounts.GAS || 0) / findings.length) * 100).toFixed(2)}% |

---

## Top 50 Vulnerability Types

| Rank | Vulnerability | Count | % of Total |
|------|--------------|-------|------------|
`;

  topTags.forEach((item, idx) => {
    const pct = ((item.count / findings.length) * 100).toFixed(3);
    md += `| ${idx + 1} | ${item.tag} | ${item.count} | ${pct}% |\n`;
  });

  md += `

---

## Top 20 Audit Firms

| Rank | Firm | Findings | % of Total |
|------|------|----------|------------|
`;

  topFirms.forEach((item, idx) => {
    const pct = ((item.count / findings.length) * 100).toFixed(2);
    md += `| ${idx + 1} | ${item.firm} | ${item.count} | ${pct}% |\n`;
  });

  md += `

---

## Top 20 Protocol Categories

| Rank | Category | Findings | % of Total |
|------|----------|----------|------------|
`;

  topCategories.forEach((item, idx) => {
    const pct = ((item.count / findings.length) * 100).toFixed(2);
    md += `| ${idx + 1} | ${item.category} | ${item.count} | ${pct}% |\n`;
  });

  md += `

---

## Data Source

- **Provider**: Cyfrin Solodit API
- **Extraction Date**: ${new Date().toISOString().split('T')[0]}
- **Total Records**: ${findings.length.toLocaleString()}
`;

  return md;
}

function generateIndex(grouped, outputDir) {
  let md = `# 📚 Security Findings Index

*Searchable index of all security patterns and findings*

---

## 🔍 Quick Navigation

- [Pattern Files](#pattern-files) - By vulnerability type
- [Severity Files](#severity-files) - By impact level
- [Source Files](#source-files) - By audit firm
- [Master Checklist](MASTER_CHECKLIST.md) - Prioritized checklist
- [Statistics](STATISTICS.md) - Comprehensive stats

---

## Pattern Files

Organized by vulnerability type:

| Vulnerability Type | Findings | File |
|-------------------|----------|------|
`;

  const tagsByFreq = Array.from(grouped.byTag.entries())
    .map(([tag, list]) => ({ tag, count: list.length }))
    .filter(item => item.count >= CONFIG.MIN_TAG_FREQUENCY)
    .sort((a, b) => b.count - a.count);

  tagsByFreq.forEach(item => {
    const filename = item.tag.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '-patterns.md';
    md += `| ${item.tag} | ${item.count} | [${filename}](patterns/${filename}) |\n`;
  });

  md += `

---

## Severity Files

| Severity | Findings | File |
|----------|----------|------|
| HIGH | ${grouped.bySeverity.get('HIGH')?.length || 0} | [high-severity.md](severity/high-severity.md) |
| MEDIUM | ${grouped.bySeverity.get('MEDIUM')?.length || 0} | [medium-severity.md](severity/medium-severity.md) |
| LOW | ${grouped.bySeverity.get('LOW')?.length || 0} | [low-severity.md](severity/low-severity.md) |
| GAS | ${grouped.bySeverity.get('GAS')?.length || 0} | [gas-optimizations.md](severity/gas-optimizations.md) |

---

## Source Files

Top audit firms by findings:

| Audit Firm | Findings | File |
|-----------|----------|------|
`;

  const topFirms = Array.from(grouped.byFirm.entries())
    .map(([firm, list]) => ({ firm, count: list.length }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 15);

  topFirms.forEach(item => {
    const filename = item.firm.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '.md';
    md += `| ${item.firm} | ${item.count} | [${filename}](sources/${filename}) |\n`;
  });

  md += `

---

## Usage

### For AI Assistants
Reference these files when performing security audits:
1. Start with [MASTER_CHECKLIST.md](MASTER_CHECKLIST.md) for prioritized checks
2. Deep-dive into specific [patterns/](patterns/) for vulnerability details
3. Check [severity/](severity/) for impact-based analysis

### For Developers
1. Use as a security review checklist
2. Learn from real-world examples
3. Understand common vulnerability patterns

---

*Generated from ${grouped.byTag.size} vulnerability types and ${Array.from(grouped.byFirm.values()).reduce((sum, list) => sum + list.length, 0).toLocaleString()} findings*
`;

  return md;
}

// ============================================================================
// FILE WRITING
// ============================================================================

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function writeFile(filePath, content) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, content, 'utf8');
}

function toFilename(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

// ============================================================================
// MAIN PROCESSING PIPELINE
// ============================================================================

async function processAllFindings() {
  console.log('━'.repeat(60));
  console.log('🚀 PHASE 2: DATA PROCESSING & SKILL GENERATION');
  console.log('━'.repeat(60));
  console.log();
  
  const totalSteps = 7;
  
  // Step 1: Load data
  logger.step(1, totalSteps, 'Loading data...');
  const { findings, metadata } = loadAllData();
  
  // Step 2: Group findings
  logger.step(2, totalSteps, 'Grouping findings...');
  const grouped = groupFindings(findings);
  
  // Step 3: Setup output directories
  logger.step(3, totalSteps, 'Setting up output directories...');
  ensureDir(CONFIG.OUTPUT_DIR);
  ensureDir(path.join(CONFIG.OUTPUT_DIR, CONFIG.PATTERNS_DIR));
  ensureDir(path.join(CONFIG.OUTPUT_DIR, CONFIG.SEVERITY_DIR));
  ensureDir(path.join(CONFIG.OUTPUT_DIR, CONFIG.SOURCES_DIR));
  logger.success('Directories created');
  
  // Step 4: Generate pattern files
  logger.step(4, totalSteps, 'Generating pattern files...');
  let patternCount = 0;
  const tagEntries = Array.from(grouped.byTag.entries())
    .filter(([tag, list]) => list.length >= CONFIG.MIN_TAG_FREQUENCY)
    .sort((a, b) => b[1].length - a[1].length);
  
  for (const [tag, tagFindings] of tagEntries) {
    const filename = toFilename(tag) + '-patterns.md';
    const filepath = path.join(CONFIG.OUTPUT_DIR, CONFIG.PATTERNS_DIR, filename);
    const content = generatePatternMarkdown(tag, tagFindings, findings);
    writeFile(filepath, content);
    patternCount++;
    
    if (patternCount % 20 === 0) {
      logger.info(`Generated ${patternCount}/${tagEntries.length} pattern files...`);
    }
  }
  logger.success(`Generated ${patternCount} pattern files`);
  
  // Step 5: Generate severity files
  logger.step(5, totalSteps, 'Generating severity files...');
  const severityMap = {
    'HIGH': 'high-severity.md',
    'MEDIUM': 'medium-severity.md',
    'LOW': 'low-severity.md',
    'GAS': 'gas-optimizations.md'
  };
  
  for (const [severity, filename] of Object.entries(severityMap)) {
    const sevFindings = grouped.bySeverity.get(severity) || [];
    if (sevFindings.length > 0) {
      const filepath = path.join(CONFIG.OUTPUT_DIR, CONFIG.SEVERITY_DIR, filename);
      const content = generateSeverityMarkdown(severity, sevFindings, findings);
      writeFile(filepath, content);
    }
  }
  logger.success('Generated severity files');
  
  // Step 6: Generate source files (top 15 firms)
  logger.step(6, totalSteps, 'Generating source files...');
  const topFirms = Array.from(grouped.byFirm.entries())
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 15);
  
  for (const [firm, firmFindings] of topFirms) {
    const filename = toFilename(firm) + '.md';
    const filepath = path.join(CONFIG.OUTPUT_DIR, CONFIG.SOURCES_DIR, filename);
    const content = generateSourceMarkdown(firm, firmFindings, findings);
    writeFile(filepath, content);
  }
  logger.success(`Generated ${topFirms.length} source files`);
  
  // Step 7: Generate master files
  logger.step(7, totalSteps, 'Generating master files...');
  
  // Master checklist
  const checklistPath = path.join(CONFIG.OUTPUT_DIR, 'MASTER_CHECKLIST.md');
  writeFile(checklistPath, generateMasterChecklist(grouped, findings));
  logger.success('Generated MASTER_CHECKLIST.md');
  
  // Statistics
  const statsPath = path.join(CONFIG.OUTPUT_DIR, 'STATISTICS.md');
  writeFile(statsPath, generateStatistics(findings, grouped, metadata));
  logger.success('Generated STATISTICS.md');
  
  // Index
  const indexPath = path.join(CONFIG.OUTPUT_DIR, 'INDEX.md');
  writeFile(indexPath, generateIndex(grouped, CONFIG.OUTPUT_DIR));
  logger.success('Generated INDEX.md');
  
  // Final summary
  console.log();
  console.log('━'.repeat(60));
  console.log('✨ PROCESSING COMPLETE');
  console.log('━'.repeat(60));
  console.log();
  console.log('📊 Summary:');
  console.log(`   - Input: ${findings.length.toLocaleString()} findings`);
  console.log(`   - Pattern files: ${patternCount}`);
  console.log(`   - Severity files: ${Object.keys(severityMap).length}`);
  console.log(`   - Source files: ${topFirms.length}`);
  console.log(`   - Master files: 3 (CHECKLIST, STATISTICS, INDEX)`);
  console.log(`   - Total files: ${patternCount + Object.keys(severityMap).length + topFirms.length + 3}`);
  console.log();
  console.log(`📁 Output: ${CONFIG.OUTPUT_DIR}`);
  console.log();
  console.log('✅ Ready for Phase 3: Integration with Cursor/Antigravity/Claude Code');
  console.log('━'.repeat(60));
}

// Run if called directly
if (require.main === module) {
  processAllFindings()
    .then(() => process.exit(0))
    .catch(err => {
      logger.error(`Processing failed: ${err.message}`);
      console.error(err);
      process.exit(1);
    });
}

module.exports = { processAllFindings };
