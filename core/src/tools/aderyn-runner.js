/**
 * Aderyn Runner — Rust-based Solidity static analysis
 * 
 * Runs Aderyn against a Solidity project and parses the output
 * into structured findings for AI consumption.
 * 
 * @module aderyn-runner
 */

import { existsSync, writeFileSync, readFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { execSync } from 'child_process';

/**
 * Aderyn severity mapping
 */
const SEVERITY_MAP = {
  'High': 'HIGH',
  'Medium': 'MEDIUM', 
  'Low': 'LOW',
  'NC': 'INFO'
};

export class AderynRunner {
  constructor(projectDir, options = {}) {
    this.projectDir = projectDir;
    this.outputDir = options.outputDir || join(projectDir, '.web3-audit');
    this.excludePaths = options.excludePaths || ['lib', 'node_modules', 'test', 'tests', 'script'];
  }

  /**
   * Check if Aderyn is installed
   */
  checkInstallation() {
    try {
      const output = execSync('aderyn --version', { encoding: 'utf-8', timeout: 10000 }).trim();
      const version = output.match(/[\d.]+/)?.[0] || output;
      return { installed: true, version, path: 'aderyn' };
    } catch {
      return {
        installed: false,
        version: null,
        suggestion: 'Install Aderyn: cargo install aderyn (requires Rust toolchain)'
      };
    }
  }

  /**
   * Run Aderyn and return structured results
   * @param {Object} options - { outputFormat }
   */
  run(options = {}) {
    const check = this.checkInstallation();
    if (!check.installed) {
      return { success: false, error: 'Aderyn not installed', suggestion: check.suggestion };
    }

    // Ensure output directory exists
    if (!existsSync(this.outputDir)) {
      mkdirSync(this.outputDir, { recursive: true });
    }

    const jsonOut = join(this.outputDir, 'aderyn-results.json');
    const args = ['aderyn', '.', '--output', jsonOut];

    // Exclude paths
    for (const p of this.excludePaths) {
      if (existsSync(join(this.projectDir, p))) {
        args.push('--exclude', p);
      }
    }

    const cmd = args.join(' ');

    try {
      let stderr = '';
      try {
        execSync(cmd, {
          cwd: this.projectDir,
          encoding: 'utf-8',
          timeout: 300000,
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      } catch (err) {
        stderr = err.stderr || '';
        // Aderyn may exit non-zero but still produce output
        if (!existsSync(jsonOut)) {
          return {
            success: false,
            error: 'Aderyn execution failed',
            stderr,
            suggestion: 'Ensure the project compiles with forge build'
          };
        }
      }

      // Parse results
      const parsed = this._parseResults(jsonOut);
      
      // Save formatted output
      const aiFormatted = this._formatForAI(parsed);
      writeFileSync(join(this.outputDir, 'aderyn-results.md'), aiFormatted);

      return {
        success: true,
        findings: parsed.findings,
        summary: parsed.summary,
        forAI: aiFormatted
      };

    } catch (err) {
      return {
        success: false,
        error: err.message,
        suggestion: 'Ensure the project compiles and Aderyn is installed'
      };
    }
  }

  // ─── Internal Parsing ───────────────────────────────────────

  _parseResults(jsonPath) {
    try {
      const raw = JSON.parse(readFileSync(jsonPath, 'utf-8'));
      const findings = [];

      // Aderyn outputs findings grouped by severity
      const sections = [
        { key: 'high_issues', severity: 'HIGH' },
        { key: 'medium_issues', severity: 'MEDIUM' },
        { key: 'low_issues', severity: 'LOW' },
        { key: 'nc_issues', severity: 'INFO' }
      ];

      for (const section of sections) {
        const issues = raw[section.key]?.issues || [];
        for (const issue of issues) {
          findings.push({
            severity: section.severity,
            title: issue.title || 'Untitled',
            description: issue.description || '',
            instances: (issue.instances || []).map(inst => ({
              file: inst.contract_path || '',
              line: inst.line_no || null,
              src: inst.src || ''
            })),
            instanceCount: issue.instances?.length || 0
          });
        }
      }

      const summary = {
        total: findings.length,
        instances: findings.reduce((s, f) => s + f.instanceCount, 0),
        high: findings.filter(f => f.severity === 'HIGH').length,
        medium: findings.filter(f => f.severity === 'MEDIUM').length,
        low: findings.filter(f => f.severity === 'LOW').length,
        info: findings.filter(f => f.severity === 'INFO').length
      };

      return { findings, summary, raw };

    } catch (err) {
      return { findings: [], summary: { total: 0 }, error: err.message };
    }
  }

  _formatForAI(parsed) {
    const { findings, summary } = parsed;
    const lines = [];

    lines.push('# Aderyn Static Analysis Results\n');
    lines.push(`**Total findings:** ${summary.total} (${summary.high} High, ${summary.medium} Medium, ${summary.low} Low, ${summary.info} Info)`);
    lines.push(`**Total instances:** ${summary.instances}\n`);

    if (findings.length === 0) {
      lines.push('No findings detected.\n');
      return lines.join('\n');
    }

    const sevOrder = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];

    for (const sev of sevOrder) {
      const sevFindings = findings.filter(f => f.severity === sev);
      if (sevFindings.length === 0) continue;

      lines.push(`## ${sev} Severity (${sevFindings.length})\n`);
      for (const f of sevFindings) {
        lines.push(`### [${f.severity}] ${f.title}`);
        lines.push(f.description);
        if (f.instances.length > 0) {
          lines.push('\n**Instances:**');
          for (const inst of f.instances.slice(0, 10)) { // Cap at 10 shown
            lines.push(`- ${inst.file}${inst.line ? ':' + inst.line : ''}`);
          }
          if (f.instances.length > 10) {
            lines.push(`- ... and ${f.instances.length - 10} more`);
          }
        }
        lines.push('');
      }
    }

    lines.push('\n---');
    lines.push('*Cross-reference these with skills/patterns/ for deeper analysis.*');

    return lines.join('\n');
  }
}

export default AderynRunner;
