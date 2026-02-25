/**
 * Mythril Runner — Symbolic execution for Solidity
 * 
 * Runs Mythril against Solidity contracts for deep symbolic analysis.
 * Slower than Slither but catches different bug classes.
 * 
 * @module mythril-runner
 */

import { existsSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { execSync } from 'child_process';

export class MythrilRunner {
  constructor(projectDir, options = {}) {
    this.projectDir = projectDir;
    this.outputDir = options.outputDir || join(projectDir, '.web3-audit');
    this.executionTimeout = options.timeout || 300; // seconds
    this.maxDepth = options.maxDepth || 22;
  }

  /**
   * Check if Mythril is installed
   */
  checkInstallation() {
    try {
      const output = execSync('myth version', { encoding: 'utf-8', timeout: 15000 }).trim();
      return { installed: true, version: output, path: 'myth' };
    } catch {
      return {
        installed: false,
        version: null,
        suggestion: 'Install Mythril: pip install mythril (or Docker: docker pull mythril/myth)'
      };
    }
  }

  /**
   * Run Mythril on a specific contract file
   * @param {string} contractFile - Path to .sol file (relative to project)
   * @param {Object} options - { solcVersion, maxDepth, timeout }
   */
  run(contractFile, options = {}) {
    const check = this.checkInstallation();
    if (!check.installed) {
      return { success: false, error: 'Mythril not installed', suggestion: check.suggestion };
    }

    const fullPath = join(this.projectDir, contractFile);
    if (!existsSync(fullPath)) {
      return { success: false, error: `File not found: ${contractFile}` };
    }

    if (!existsSync(this.outputDir)) {
      mkdirSync(this.outputDir, { recursive: true });
    }

    const maxDepth = options.maxDepth || this.maxDepth;
    const timeout = options.timeout || this.executionTimeout;
    const solcVersion = options.solcVersion ? `--solv ${options.solcVersion}` : '';

    const cmd = `myth analyze ${fullPath} -o json --max-depth ${maxDepth} --execution-timeout ${timeout} ${solcVersion}`.trim();

    try {
      let output;
      try {
        output = execSync(cmd, {
          cwd: this.projectDir,
          encoding: 'utf-8',
          timeout: (timeout + 60) * 1000,
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      } catch (err) {
        output = err.stdout || '';
        if (!output) {
          return {
            success: false,
            error: 'Mythril execution failed',
            stderr: err.stderr || err.message,
            suggestion: 'Ensure correct solc version and contract compiles'
          };
        }
      }

      const parsed = this._parseOutput(output, contractFile);

      // Save results
      const safeName = contractFile.replace(/[/\\]/g, '_').replace('.sol', '');
      writeFileSync(join(this.outputDir, `mythril-${safeName}.json`), JSON.stringify(parsed, null, 2));
      writeFileSync(join(this.outputDir, `mythril-${safeName}.md`), this._formatForAI(parsed, contractFile));

      return {
        success: true,
        findings: parsed.findings,
        summary: parsed.summary,
        forAI: this._formatForAI(parsed, contractFile)
      };

    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  // ─── Internal ───────────────────────────────────────────────

  _parseOutput(output, contractFile) {
    let json;
    try {
      json = JSON.parse(output);
    } catch {
      return { findings: [], summary: { total: 0 }, error: 'Failed to parse Mythril output' };
    }

    const issues = json.issues || [];
    const findings = issues.map(issue => ({
      severity: issue.severity || 'Medium',
      title: issue.title || 'Unknown',
      description: issue.description || '',
      swcId: issue.swc_id || null,
      contract: issue.contract || contractFile,
      function: issue.function || '',
      address: issue.address || '',
      txSequence: issue.tx_sequence || null
    }));

    const summary = {
      total: findings.length,
      high: findings.filter(f => f.severity === 'High').length,
      medium: findings.filter(f => f.severity === 'Medium').length,
      low: findings.filter(f => f.severity === 'Low').length
    };

    return { findings, summary };
  }

  _formatForAI(parsed, contractFile) {
    const { findings, summary } = parsed;
    const lines = [];

    lines.push(`# Mythril Symbolic Analysis — ${contractFile}\n`);
    lines.push(`**Total issues:** ${summary.total} (${summary.high} High, ${summary.medium} Medium, ${summary.low} Low)\n`);

    if (findings.length === 0) {
      lines.push('No issues detected by symbolic execution.\n');
      return lines.join('\n');
    }

    for (const f of findings) {
      lines.push(`### [${f.severity}] ${f.title}`);
      if (f.swcId) lines.push(`**SWC-ID:** SWC-${f.swcId}`);
      lines.push(`**Function:** ${f.function || 'unknown'}`);
      lines.push(`\n${f.description}`);
      if (f.txSequence) {
        lines.push(`\n**Transaction Sequence:**`);
        lines.push('```json');
        lines.push(JSON.stringify(f.txSequence, null, 2));
        lines.push('```');
      }
      lines.push('');
    }

    lines.push('\n---');
    lines.push('*Mythril findings are verified via symbolic execution — higher confidence than pattern matching.*');

    return lines.join('\n');
  }
}

export default MythrilRunner;
