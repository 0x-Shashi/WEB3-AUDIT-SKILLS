/**
 * Aderyn Runner
 * 
 * Execute Aderyn security analysis and parse results.
 * Aderyn is a Rust-based Solidity static analyzer by Cyfrin.
 * It's fast and designed for modern Solidity codebases.
 * 
 * Requirements:
 *   cargo install aderyn
 * 
 * Usage:
 *   const runner = new AderynRunner();
 *   const results = await runner.analyze('./contracts');
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

class AderynRunner {
  constructor(options = {}) {
    this.command = options.command || 'aderyn';
    this.timeout = options.timeout || 300000; // 5 minutes default
  }

  /**
   * Check if Aderyn is installed
   * 
   * @returns {Promise<Object>} Version info or error
   */
  async checkInstallation() {
    return new Promise((resolve) => {
      const proc = spawn(this.command, ['--version']);
      let output = '';

      proc.stdout.on('data', (data) => {
        output += data.toString();
      });

      proc.on('close', (code) => {
        if (code === 0) {
          resolve({ installed: true, version: output.trim() });
        } else {
          resolve({ 
            installed: false, 
            error: 'Aderyn not found. Install with: cargo install aderyn' 
          });
        }
      });

      proc.on('error', () => {
        resolve({ 
          installed: false, 
          error: 'Aderyn not found. Install with: cargo install aderyn' 
        });
      });
    });
  }

  /**
   * Analyze a project directory
   * 
   * @param {string} target - Path to project (directory with foundry.toml/hardhat.config)
   * @param {Object} options - Analysis options
   * @returns {Promise<Object>} Analysis results
   */
  async analyze(target, options = {}) {
    const targetPath = path.resolve(target);
    
    if (!fs.existsSync(targetPath)) {
      return {
        success: false,
        error: `Target not found: ${targetPath}`
      };
    }

    // Aderyn outputs to file by default, we'll use JSON output
    const outputFile = options.outputFile || path.join(targetPath, 'aderyn-report.json');
    
    const args = [];

    // Root path (project directory)
    args.push('--root', targetPath);

    // Output format
    args.push('--output', outputFile);

    // Scope (specific directories to analyze)
    if (options.scope) {
      args.push('--scope', options.scope);
    }

    // Exclude patterns
    if (options.exclude) {
      options.exclude.forEach(pattern => {
        args.push('--exclude', pattern);
      });
    }

    // Source directory
    if (options.src) {
      args.push('--src', options.src);
    }

    return this._execute(args, targetPath, outputFile, options);
  }

  /**
   * Quick analysis with default settings
   * 
   * @param {string} target - Path to project
   * @returns {Promise<Object>} Analysis results
   */
  async quickAnalyze(target) {
    return this.analyze(target, {
      exclude: ['test/', 'tests/', 'script/', 'scripts/']
    });
  }

  /**
   * Full analysis including tests
   * 
   * @param {string} target - Path to project
   * @returns {Promise<Object>} Analysis results
   */
  async fullAnalyze(target) {
    return this.analyze(target);
  }

  /**
   * Analyze with Foundry project structure
   * 
   * @param {string} target - Path to Foundry project
   * @returns {Promise<Object>} Analysis results
   */
  async analyzeFoundry(target) {
    return this.analyze(target, {
      src: 'src',
      exclude: ['test/', 'script/']
    });
  }

  /**
   * Analyze with Hardhat project structure
   * 
   * @param {string} target - Path to Hardhat project
   * @returns {Promise<Object>} Analysis results
   */
  async analyzeHardhat(target) {
    return this.analyze(target, {
      src: 'contracts',
      exclude: ['test/', 'scripts/']
    });
  }

  /**
   * Execute Aderyn command
   * @private
   */
  _execute(args, targetPath, outputFile, options = {}) {
    return new Promise((resolve) => {
      const proc = spawn(this.command, args, {
        cwd: options.cwd || targetPath,
        timeout: this.timeout
      });

      let stderr = '';

      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      proc.on('close', (code) => {
        if (code === 0 || fs.existsSync(outputFile)) {
          try {
            const reportContent = fs.readFileSync(outputFile, 'utf-8');
            const results = JSON.parse(reportContent);
            
            // Clean up the temp file if we created it
            if (!options.keepOutput) {
              try {
                fs.unlinkSync(outputFile);
              } catch (e) {
                // Ignore cleanup errors
              }
            }

            resolve({
              success: true,
              exitCode: code,
              findings: this._parseFindings(results),
              summary: this._getSummary(results),
              raw: results
            });
          } catch (e) {
            resolve({
              success: false,
              error: `Failed to parse Aderyn output: ${e.message}`,
              exitCode: code
            });
          }
        } else {
          resolve({
            success: false,
            error: stderr || 'Analysis failed',
            exitCode: code
          });
        }
      });

      proc.on('error', (error) => {
        resolve({
          success: false,
          error: error.message
        });
      });
    });
  }

  /**
   * Parse Aderyn JSON output into structured findings
   * @private
   */
  _parseFindings(results) {
    const findings = [];

    // Parse high issues
    if (results.high_issues?.issues) {
      results.high_issues.issues.forEach(issue => {
        findings.push(this._formatIssue(issue, 'HIGH'));
      });
    }

    // Parse medium issues
    if (results.medium_issues?.issues) {
      results.medium_issues.issues.forEach(issue => {
        findings.push(this._formatIssue(issue, 'MEDIUM'));
      });
    }

    // Parse low issues
    if (results.low_issues?.issues) {
      results.low_issues.issues.forEach(issue => {
        findings.push(this._formatIssue(issue, 'LOW'));
      });
    }

    // Parse NC (Non-Critical) issues
    if (results.nc_issues?.issues) {
      results.nc_issues.issues.forEach(issue => {
        findings.push(this._formatIssue(issue, 'INFO'));
      });
    }

    return findings;
  }

  /**
   * Format a single issue
   * @private
   */
  _formatIssue(issue, severity) {
    return {
      id: issue.detector_name || 'unknown',
      title: issue.title,
      severity: severity,
      description: issue.description,
      elements: issue.instances?.map(instance => ({
        type: 'code',
        file: instance.contract_path,
        startLine: instance.line_no,
        snippet: instance.src
      })) || [],
      instanceCount: issue.instances?.length || 0
    };
  }

  /**
   * Get summary statistics
   * @private
   */
  _getSummary(results) {
    return {
      high: results.high_issues?.count || 0,
      medium: results.medium_issues?.count || 0,
      low: results.low_issues?.count || 0,
      info: results.nc_issues?.count || 0,
      filesAnalyzed: results.files_summary?.files_analyzed || 0,
      totalIssues: (
        (results.high_issues?.count || 0) +
        (results.medium_issues?.count || 0) +
        (results.low_issues?.count || 0) +
        (results.nc_issues?.count || 0)
      )
    };
  }
}

module.exports = AderynRunner;
