/**
 * Slither Runner — Automated static analysis with parsed output
 * 
 * Runs Slither against a Solidity project and parses the JSON output
 * into structured findings that can be fed directly to AI assistants.
 * 
 * @module slither-runner
 */

import { existsSync, writeFileSync, readFileSync, mkdirSync } from 'fs';
import { join, basename } from 'path';
import { execSync } from 'child_process';

/**
 * Slither detector severity mapping
 */
const DETECTOR_SEVERITY = {
  'High': 'HIGH',
  'Medium': 'MEDIUM',
  'Low': 'LOW',
  'Informational': 'INFO',
  'Optimization': 'GAS'
};

/**
 * Default detectors to exclude (too noisy for AI consumption)
 */
const DEFAULT_EXCLUDE_DETECTORS = [
  'solc-version',
  'naming-convention',
  'constable-states',
  'immutable-states',
  'too-many-digits',
  'similar-names'
];

/**
 * High-signal detectors to always prioritize
 */
const PRIORITY_DETECTORS = [
  'reentrancy-eth',
  'reentrancy-no-eth',
  'reentrancy-benign',
  'reentrancy-events',
  'arbitrary-send-eth',
  'arbitrary-send-erc20',
  'suicidal',
  'controlled-delegatecall',
  'uninitialized-state',
  'uninitialized-storage',
  'locked-ether',
  'incorrect-equality',
  'weak-prng',
  'tx-origin',
  'unchecked-lowlevel',
  'unchecked-transfer',
  'unchecked-send'
];


export class SlitherRunner {
  constructor(projectDir, options = {}) {
    this.projectDir = projectDir;
    this.outputDir = options.outputDir || join(projectDir, '.web3-audit');
    this.excludeDetectors = options.excludeDetectors || DEFAULT_EXCLUDE_DETECTORS;
    this.filterPaths = options.filterPaths || ['node_modules', 'lib', 'test', 'tests', 'script'];
  }

  /**
   * Check if Slither is installed and accessible
   * @returns {Object} { installed, version, path }
   */
  checkInstallation() {
    try {
      const version = execSync('slither --version', { encoding: 'utf-8', timeout: 10000 }).trim();
      return { installed: true, version, path: 'slither' };
    } catch {
      return {
        installed: false,
        version: null,
        suggestion: 'Install Slither: pip install slither-analyzer (or pipx install slither-analyzer)'
      };
    }
  }

  /**
   * Run Slither and return structured results
   * @param {Object} options - { detectors, filterPaths, strict, printers }
   * @returns {Object} { success, findings, summary, rawOutput }
   */
  run(options = {}) {
    const check = this.checkInstallation();
    if (!check.installed) {
      return { success: false, error: 'Slither not installed', suggestion: check.suggestion };
    }

    // Build command
    const args = ['slither', '.', '--json', '-'];

    // Filter paths
    const filterPaths = options.filterPaths || this.filterPaths;
    if (filterPaths.length > 0) {
      args.push('--filter-paths', filterPaths.join('|'));
    }

    // Exclude noisy detectors
    const exclude = options.excludeDetectors || this.excludeDetectors;
    if (exclude.length > 0) {
      args.push('--exclude', exclude.join(','));
    }

    // Specific detectors only
    if (options.detectors) {
      args.push('--detect', options.detectors.join(','));
    }

    const cmd = args.join(' ');

    try {
      let output;
      try {
        output = execSync(cmd, {
          cwd: this.projectDir,
          encoding: 'utf-8',
          timeout: 300000, // 5 min timeout
          stdio: ['pipe', 'pipe', 'pipe'],
          maxBuffer: 50 * 1024 * 1024, // 50MB buffer
        });
      } catch (err) {
        // Slither exits non-zero when it finds issues — that's normal
        output = err.stdout || '';
        if (!output && err.stderr) {
          // Real error (compilation failure, etc.)
          return {
            success: false,
            error: 'Slither execution failed',
            stderr: err.stderr,
            suggestion: 'Ensure the project compiles: forge build (or npx hardhat compile)'
          };
        }
      }

      // Parse JSON output
      const parsed = this._parseOutput(output);

      // Save results
      this._saveResults(parsed);

      return {
        success: true,
        findings: parsed.findings,
        summary: parsed.summary,
        detectorResults: parsed.detectorResults,
        forAI: this._formatForAI(parsed)
      };

    } catch (err) {
      return {
        success: false,
        error: err.message,
        suggestion: 'Check that the project compiles and Slither is installed correctly'
      };
    }
  }

  /**
   * Run only high-priority detectors (fast scan)
   */
  runPriority() {
    return this.run({ detectors: PRIORITY_DETECTORS });
  }

  /**
   * Run Slither printers for project overview
   * @param {string} printer - Printer name (human-summary, inheritance-graph, contract-summary)
   */
  runPrinter(printer = 'human-summary') {
    const check = this.checkInstallation();
    if (!check.installed) {
      return { success: false, error: 'Slither not installed', suggestion: check.suggestion };
    }

    try {
      const filterArgs = this.filterPaths.length > 0
        ? `--filter-paths "${this.filterPaths.join('|')}"`
        : '';
      const output = execSync(
        `slither . --print ${printer} ${filterArgs}`,
        {
          cwd: this.projectDir,
          encoding: 'utf-8',
          timeout: 120000,
          stdio: ['pipe', 'pipe', 'pipe'],
        }
      );
      return { success: true, output };
    } catch (err) {
      return { success: true, output: (err.stdout || '') + (err.stderr || '') };
    }
  }

  // ─── Internal Parsing ───────────────────────────────────────

  _parseOutput(output) {
    let json;
    try {
      json = JSON.parse(output);
    } catch {
      // Try to extract JSON from mixed output
      const jsonMatch = output.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        try { json = JSON.parse(jsonMatch[0]); } catch { /* ignore */ }
      }
    }

    if (!json || !json.results) {
      return { findings: [], summary: { total: 0 }, detectorResults: [] };
    }

    const detectors = json.results.detectors || [];
    const findings = [];

    for (const det of detectors) {
      findings.push({
        id: det.check,
        severity: DETECTOR_SEVERITY[det.impact] || det.impact,
        confidence: det.confidence,
        title: det.check.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
        description: det.description,
        elements: (det.elements || []).map(el => ({
          type: el.type,
          name: el.name,
          source: el.source_mapping ? {
            file: el.source_mapping.filename_relative || el.source_mapping.filename_short,
            lines: el.source_mapping.lines,
            startLine: el.source_mapping.lines?.[0],
            endLine: el.source_mapping.lines?.[el.source_mapping.lines.length - 1]
          } : null
        })),
        firstMarkdown: det.first_markdown_element || '',
        detector: det.check,
        impact: det.impact,
        isPriority: PRIORITY_DETECTORS.includes(det.check)
      });
    }

    // Sort: priority first, then by severity
    const sevOrder = { 'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3, 'GAS': 4 };
    findings.sort((a, b) => {
      if (a.isPriority !== b.isPriority) return a.isPriority ? -1 : 1;
      return (sevOrder[a.severity] || 5) - (sevOrder[b.severity] || 5);
    });

    const summary = {
      total: findings.length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low: findings.filter(f => f.severity === 'LOW').length,
      info: findings.filter(f => f.severity === 'INFO').length,
      gas: findings.filter(f => f.severity === 'GAS').length,
      priority: findings.filter(f => f.isPriority).length
    };

    return { findings, summary, detectorResults: detectors };
  }

  /**
   * Format findings into a markdown-like summary for AI consumption
   */
  _formatForAI(parsed) {
    const { findings, summary } = parsed;
    const lines = [];

    lines.push('# Slither Static Analysis Results\n');
    lines.push(`**Total findings:** ${summary.total} (${summary.high} High, ${summary.medium} Medium, ${summary.low} Low, ${summary.info} Info, ${summary.gas} Gas)`);
    lines.push(`**Priority findings:** ${summary.priority}\n`);

    if (findings.length === 0) {
      lines.push('No findings detected.\n');
      return lines.join('\n');
    }

    // Priority findings first
    const priority = findings.filter(f => f.isPriority);
    if (priority.length > 0) {
      lines.push('## ⚠ Priority Findings (Investigate First)\n');
      for (const f of priority) {
        lines.push(`### [${f.severity}] ${f.title}`);
        lines.push(`**Detector:** \`${f.detector}\` | **Confidence:** ${f.confidence}\n`);
        lines.push(f.description);
        if (f.elements.length > 0) {
          lines.push('\n**Locations:**');
          for (const el of f.elements) {
            if (el.source) {
              lines.push(`- ${el.type} \`${el.name}\` in ${el.source.file}:${el.source.startLine || '?'}`);
            }
          }
        }
        lines.push('');
      }
    }

    // Other findings
    const other = findings.filter(f => !f.isPriority);
    if (other.length > 0) {
      lines.push('## Other Findings\n');
      for (const f of other) {
        lines.push(`- **[${f.severity}]** ${f.title} — ${f.description.split('\n')[0]}`);
      }
    }

    lines.push('\n---');
    lines.push('*Cross-reference these with skills/patterns/ for deeper analysis.*');

    return lines.join('\n');
  }

  _saveResults(parsed) {
    try {
      if (!existsSync(this.outputDir)) {
        mkdirSync(this.outputDir, { recursive: true });
      }
      writeFileSync(
        join(this.outputDir, 'slither-results.json'),
        JSON.stringify(parsed, null, 2)
      );
      writeFileSync(
        join(this.outputDir, 'slither-results.md'),
        this._formatForAI(parsed)
      );
    } catch { /* ignore save errors */ }
  }
}

export default SlitherRunner;
