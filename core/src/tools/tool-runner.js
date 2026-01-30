/**
 * Unified Tool Runner
 * 
 * Orchestrate multiple security analysis tools and merge results.
 * Provides a unified interface for running Slither, Mythril, and Aderyn.
 * 
 * Usage:
 *   const runner = new ToolRunner();
 *   const results = await runner.runAll('./contracts');
 */

const SlitherRunner = require('./slither-runner');
const MythrilRunner = require('./mythril-runner');
const AderynRunner = require('./aderyn-runner');

class ToolRunner {
  constructor(options = {}) {
    this.slither = new SlitherRunner(options.slither);
    this.mythril = new MythrilRunner(options.mythril);
    this.aderyn = new AderynRunner(options.aderyn);
    
    // Default tools to run
    this.defaultTools = options.tools || ['slither', 'aderyn'];
  }

  /**
   * Check which tools are installed
   * 
   * @returns {Promise<Object>} Installation status for all tools
   */
  async checkTools() {
    const [slither, mythril, aderyn] = await Promise.all([
      this.slither.checkInstallation(),
      this.mythril.checkInstallation(),
      this.aderyn.checkInstallation()
    ]);

    return {
      slither,
      mythril,
      aderyn,
      available: [
        slither.installed && 'slither',
        mythril.installed && 'mythril',
        aderyn.installed && 'aderyn'
      ].filter(Boolean)
    };
  }

  /**
   * Run all available/specified tools
   * 
   * @param {string} target - Path to analyze
   * @param {Object} options - Analysis options
   * @returns {Promise<Object>} Combined results from all tools
   */
  async runAll(target, options = {}) {
    const tools = options.tools || this.defaultTools;
    const results = {
      target,
      timestamp: new Date().toISOString(),
      tools: {},
      combined: {
        findings: [],
        summary: {
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
          gas: 0
        }
      }
    };

    // Run tools in parallel
    const promises = [];

    if (tools.includes('slither')) {
      promises.push(
        this.slither.analyze(target, options.slither).then(r => ({ tool: 'slither', result: r }))
      );
    }

    if (tools.includes('mythril')) {
      promises.push(
        this.mythril.analyze(target, options.mythril).then(r => ({ tool: 'mythril', result: r }))
      );
    }

    if (tools.includes('aderyn')) {
      promises.push(
        this.aderyn.analyze(target, options.aderyn).then(r => ({ tool: 'aderyn', result: r }))
      );
    }

    const toolResults = await Promise.all(promises);

    // Process each tool's results
    for (const { tool, result } of toolResults) {
      results.tools[tool] = result;

      if (result.success && result.findings) {
        // Add source tool to each finding
        const findingsWithSource = result.findings.map(f => ({
          ...f,
          source: tool,
          sourceId: `${tool}:${f.id}`
        }));

        results.combined.findings.push(...findingsWithSource);
      }
    }

    // Calculate summary
    for (const finding of results.combined.findings) {
      results.combined.summary.total++;
      switch (finding.severity) {
        case 'CRITICAL': results.combined.summary.critical++; break;
        case 'HIGH': results.combined.summary.high++; break;
        case 'MEDIUM': results.combined.summary.medium++; break;
        case 'LOW': results.combined.summary.low++; break;
        case 'INFO': results.combined.summary.info++; break;
        case 'GAS': results.combined.summary.gas++; break;
      }
    }

    // Deduplicate similar findings
    if (options.dedupe !== false) {
      results.combined.findings = this._deduplicateFindings(results.combined.findings);
      results.combined.deduplicated = true;
    }

    // Sort by severity
    results.combined.findings.sort((a, b) => {
      const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, GAS: 5 };
      return (severityOrder[a.severity] || 99) - (severityOrder[b.severity] || 99);
    });

    return results;
  }

  /**
   * Run quick scan with all available tools
   * 
   * @param {string} target - Path to analyze
   * @returns {Promise<Object>} Combined quick scan results
   */
  async quickScan(target) {
    const toolStatus = await this.checkTools();
    
    return this.runAll(target, {
      tools: toolStatus.available,
      slither: { severity: ['high', 'medium'] },
      mythril: { transactionCount: 2, maxDepth: 12 },
      aderyn: { exclude: ['test/', 'tests/', 'script/', 'scripts/'] }
    });
  }

  /**
   * Run deep analysis (slower, more thorough)
   * 
   * @param {string} target - Path to analyze
   * @returns {Promise<Object>} Deep analysis results
   */
  async deepScan(target) {
    const toolStatus = await this.checkTools();
    
    return this.runAll(target, {
      tools: toolStatus.available,
      mythril: { transactionCount: 10, maxDepth: 50, timeout: 900 },
      dedupe: true
    });
  }

  /**
   * Run specific security checks across tools
   * 
   * @param {string} target - Path to analyze
   * @param {string} checkType - Type of check (reentrancy, access-control, etc.)
   * @returns {Promise<Object>} Targeted check results
   */
  async runCheck(target, checkType) {
    const results = {
      target,
      checkType,
      timestamp: new Date().toISOString(),
      findings: []
    };

    switch (checkType) {
      case 'reentrancy':
        const reentracyResults = await this.slither.checkReentrancy(target);
        if (reentracyResults.success) {
          results.findings = reentracyResults.findings;
        }
        break;

      case 'access-control':
        const accessResults = await this.slither.checkAccessControl(target);
        if (accessResults.success) {
          results.findings = accessResults.findings;
        }
        break;

      case 'high-severity':
        const highResults = await this.slither.checkHighSeverity(target);
        if (highResults.success) {
          results.findings = highResults.findings;
        }
        break;

      default:
        results.error = `Unknown check type: ${checkType}`;
    }

    return results;
  }

  /**
   * Deduplicate similar findings from different tools
   * @private
   */
  _deduplicateFindings(findings) {
    const seen = new Map();
    const deduped = [];

    for (const finding of findings) {
      // Create a key based on severity, first file, and first line
      const firstElement = finding.elements?.[0];
      const key = `${finding.severity}:${firstElement?.file || 'unknown'}:${firstElement?.startLine || 0}`;
      
      if (!seen.has(key)) {
        seen.set(key, finding);
        deduped.push(finding);
      } else {
        // Merge sources if same finding from different tools
        const existing = seen.get(key);
        if (existing.source !== finding.source) {
          existing.alsoFoundBy = existing.alsoFoundBy || [];
          existing.alsoFoundBy.push(finding.source);
        }
      }
    }

    return deduped;
  }

  /**
   * Format results for display
   * 
   * @param {Object} results - Analysis results
   * @param {string} format - Output format (text, markdown, json)
   * @returns {string} Formatted output
   */
  formatResults(results, format = 'text') {
    switch (format) {
      case 'json':
        return JSON.stringify(results, null, 2);

      case 'markdown':
        return this._formatMarkdown(results);

      case 'text':
      default:
        return this._formatText(results);
    }
  }

  /**
   * Format as markdown
   * @private
   */
  _formatMarkdown(results) {
    let output = `# Security Analysis Report\n\n`;
    output += `**Target:** ${results.target}\n`;
    output += `**Date:** ${results.timestamp}\n\n`;
    
    output += `## Summary\n\n`;
    const s = results.combined.summary;
    output += `| Severity | Count |\n|----------|-------|\n`;
    output += `| Critical | ${s.critical} |\n`;
    output += `| High | ${s.high} |\n`;
    output += `| Medium | ${s.medium} |\n`;
    output += `| Low | ${s.low} |\n`;
    output += `| Info | ${s.info} |\n`;
    output += `| Gas | ${s.gas} |\n`;
    output += `| **Total** | **${s.total}** |\n\n`;

    if (results.combined.findings.length > 0) {
      output += `## Findings\n\n`;
      
      for (const finding of results.combined.findings) {
        output += `### [${finding.severity}] ${finding.title}\n\n`;
        output += `**Source:** ${finding.source}`;
        if (finding.alsoFoundBy?.length) {
          output += ` (also: ${finding.alsoFoundBy.join(', ')})`;
        }
        output += `\n\n`;
        
        if (finding.description) {
          output += `${finding.description}\n\n`;
        }
        
        if (finding.elements?.length > 0) {
          output += `**Locations:**\n`;
          for (const el of finding.elements) {
            output += `- ${el.file || 'unknown'}`;
            if (el.startLine) output += `:${el.startLine}`;
            if (el.name) output += ` (${el.name})`;
            output += `\n`;
          }
          output += `\n`;
        }
      }
    }

    return output;
  }

  /**
   * Format as plain text
   * @private
   */
  _formatText(results) {
    let output = `=== Security Analysis Report ===\n\n`;
    output += `Target: ${results.target}\n`;
    output += `Date: ${results.timestamp}\n\n`;
    
    const s = results.combined.summary;
    output += `Summary:\n`;
    output += `  Critical: ${s.critical}\n`;
    output += `  High: ${s.high}\n`;
    output += `  Medium: ${s.medium}\n`;
    output += `  Low: ${s.low}\n`;
    output += `  Info: ${s.info}\n`;
    output += `  Gas: ${s.gas}\n`;
    output += `  Total: ${s.total}\n\n`;

    if (results.combined.findings.length > 0) {
      output += `Findings:\n`;
      output += `${'='.repeat(50)}\n\n`;
      
      for (const finding of results.combined.findings) {
        output += `[${finding.severity}] ${finding.title}\n`;
        output += `Source: ${finding.source}\n`;
        
        if (finding.description) {
          output += `${finding.description}\n`;
        }
        
        if (finding.elements?.length > 0) {
          output += `Locations:\n`;
          for (const el of finding.elements) {
            output += `  - ${el.file || 'unknown'}`;
            if (el.startLine) output += `:${el.startLine}`;
            output += `\n`;
          }
        }
        output += `\n${'-'.repeat(50)}\n\n`;
      }
    }

    return output;
  }
}

module.exports = ToolRunner;

