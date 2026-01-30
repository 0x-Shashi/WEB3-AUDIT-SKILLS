/**
 * Solodit Response Parser
 * 
 * Utilities for parsing and formatting Solodit API responses
 * into actionable audit data.
 */

class SoloditParser {
  /**
   * Parse raw API response into structured findings
   * 
   * @param {Object} response - Raw API response
   * @returns {Array} Parsed findings
   */
  static parseFindings(response) {
    if (!response?.data?.findings) {
      return [];
    }

    return response.data.findings.map(finding => ({
      id: finding.id,
      title: finding.title,
      severity: this.normalizeSeverity(finding.severity),
      category: finding.category || 'unknown',
      description: finding.description,
      impact: finding.impact,
      recommendation: finding.recommendation,
      codeSnippet: finding.code_snippet,
      references: finding.references || [],
      protocol: {
        name: finding.protocol_name,
        type: finding.protocol_type,
        chain: finding.chain
      },
      audit: {
        firm: finding.audit_firm,
        date: finding.audit_date,
        reportUrl: finding.report_url
      },
      tags: finding.tags || [],
      createdAt: finding.created_at,
      updatedAt: finding.updated_at
    }));
  }

  /**
   * Normalize severity levels
   * 
   * @param {string} severity - Raw severity
   * @returns {string} Normalized severity
   */
  static normalizeSeverity(severity) {
    const severityMap = {
      'critical': 'CRITICAL',
      'crit': 'CRITICAL',
      'c': 'CRITICAL',
      'high': 'HIGH',
      'h': 'HIGH',
      'medium': 'MEDIUM',
      'med': 'MEDIUM',
      'm': 'MEDIUM',
      'low': 'LOW',
      'l': 'LOW',
      'informational': 'INFO',
      'info': 'INFO',
      'i': 'INFO',
      'gas': 'GAS',
      'g': 'GAS'
    };

    return severityMap[severity?.toLowerCase()] || 'UNKNOWN';
  }

  /**
   * Group findings by severity
   * 
   * @param {Array} findings - Parsed findings
   * @returns {Object} Findings grouped by severity
   */
  static groupBySeverity(findings) {
    const groups = {
      CRITICAL: [],
      HIGH: [],
      MEDIUM: [],
      LOW: [],
      INFO: [],
      GAS: [],
      UNKNOWN: []
    };

    findings.forEach(finding => {
      const severity = finding.severity || 'UNKNOWN';
      if (groups[severity]) {
        groups[severity].push(finding);
      } else {
        groups.UNKNOWN.push(finding);
      }
    });

    return groups;
  }

  /**
   * Group findings by category
   * 
   * @param {Array} findings - Parsed findings
   * @returns {Object} Findings grouped by category
   */
  static groupByCategory(findings) {
    const groups = {};

    findings.forEach(finding => {
      const category = finding.category || 'uncategorized';
      if (!groups[category]) {
        groups[category] = [];
      }
      groups[category].push(finding);
    });

    return groups;
  }

  /**
   * Format finding for display
   * 
   * @param {Object} finding - Parsed finding
   * @param {string} format - Output format (text, markdown, json)
   * @returns {string} Formatted finding
   */
  static formatFinding(finding, format = 'markdown') {
    switch (format) {
      case 'json':
        return JSON.stringify(finding, null, 2);
      
      case 'text':
        return this._formatAsText(finding);
      
      case 'markdown':
      default:
        return this._formatAsMarkdown(finding);
    }
  }

  /**
   * Format finding as plain text
   * @private
   */
  static _formatAsText(finding) {
    return `
[${finding.severity}] ${finding.title}
${'='.repeat(50)}
Category: ${finding.category}
Protocol: ${finding.protocol?.name || 'N/A'} (${finding.protocol?.type || 'N/A'})

Description:
${finding.description}

Impact:
${finding.impact || 'Not specified'}

Recommendation:
${finding.recommendation || 'Not specified'}

${finding.codeSnippet ? `Code:\n${finding.codeSnippet}` : ''}

Source: ${finding.audit?.firm || 'Unknown'} - ${finding.audit?.date || 'Unknown date'}
    `.trim();
  }

  /**
   * Format finding as Markdown
   * @private
   */
  static _formatAsMarkdown(finding) {
    const severityEmoji = {
      'CRITICAL': '🔴',
      'HIGH': '🟠',
      'MEDIUM': '🟡',
      'LOW': '🟢',
      'INFO': 'ℹ️',
      'GAS': '⛽'
    };

    return `
## ${severityEmoji[finding.severity] || '❓'} [${finding.severity}] ${finding.title}

**Category:** ${finding.category}  
**Protocol:** ${finding.protocol?.name || 'N/A'} (${finding.protocol?.type || 'N/A'})  
**Chain:** ${finding.protocol?.chain || 'N/A'}

### Description
${finding.description}

### Impact
${finding.impact || '_Not specified_'}

### Recommendation
${finding.recommendation || '_Not specified_'}

${finding.codeSnippet ? `### Code\n\`\`\`solidity\n${finding.codeSnippet}\n\`\`\`` : ''}

### Source
- **Audit Firm:** ${finding.audit?.firm || 'Unknown'}
- **Date:** ${finding.audit?.date || 'Unknown'}
${finding.audit?.reportUrl ? `- **Report:** [View Report](${finding.audit.reportUrl})` : ''}

---
    `.trim();
  }

  /**
   * Generate summary statistics
   * 
   * @param {Array} findings - Parsed findings
   * @returns {Object} Summary statistics
   */
  static getSummary(findings) {
    const bySeverity = this.groupBySeverity(findings);
    const byCategory = this.groupByCategory(findings);

    return {
      total: findings.length,
      bySeverity: {
        critical: bySeverity.CRITICAL.length,
        high: bySeverity.HIGH.length,
        medium: bySeverity.MEDIUM.length,
        low: bySeverity.LOW.length,
        info: bySeverity.INFO.length,
        gas: bySeverity.GAS.length
      },
      byCategory: Object.entries(byCategory).map(([category, items]) => ({
        category,
        count: items.length
      })).sort((a, b) => b.count - a.count),
      topCategories: Object.entries(byCategory)
        .sort((a, b) => b[1].length - a[1].length)
        .slice(0, 5)
        .map(([cat]) => cat)
    };
  }

  /**
   * Extract unique tags from findings
   * 
   * @param {Array} findings - Parsed findings
   * @returns {Array} Unique tags with counts
   */
  static extractTags(findings) {
    const tagCounts = {};

    findings.forEach(finding => {
      (finding.tags || []).forEach(tag => {
        tagCounts[tag] = (tagCounts[tag] || 0) + 1;
      });
    });

    return Object.entries(tagCounts)
      .map(([tag, count]) => ({ tag, count }))
      .sort((a, b) => b.count - a.count);
  }

  /**
   * Filter findings by multiple criteria
   * 
   * @param {Array} findings - Parsed findings
   * @param {Object} criteria - Filter criteria
   * @returns {Array} Filtered findings
   */
  static filterFindings(findings, criteria = {}) {
    return findings.filter(finding => {
      // Filter by severity
      if (criteria.severity && finding.severity !== criteria.severity.toUpperCase()) {
        return false;
      }

      // Filter by category
      if (criteria.category && finding.category !== criteria.category) {
        return false;
      }

      // Filter by keyword in title/description
      if (criteria.keyword) {
        const keyword = criteria.keyword.toLowerCase();
        const inTitle = finding.title?.toLowerCase().includes(keyword);
        const inDesc = finding.description?.toLowerCase().includes(keyword);
        if (!inTitle && !inDesc) {
          return false;
        }
      }

      // Filter by protocol type
      if (criteria.protocolType && finding.protocol?.type !== criteria.protocolType) {
        return false;
      }

      // Filter by chain
      if (criteria.chain && finding.protocol?.chain !== criteria.chain) {
        return false;
      }

      return true;
    });
  }
}

module.exports = SoloditParser;

