/**
 * Slither Runner
 * 
 * Execute Slither static analysis and parse results.
 * Slither is the most widely used Solidity static analyzer.
 * 
 * Requirements:
 *   pip install slither-analyzer
 * 
 * Usage:
 *   const runner = new SlitherRunner();
 *   const results = await runner.analyze('./contracts');
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

class SlitherRunner {
  constructor(options = {}) {
    this.command = options.command || 'slither';
    this.timeout = options.timeout || 300000; // 5 minutes default
    this.defaultArgs = [
      '--json', '-',
      '--exclude-informational',
      '--exclude-optimization'
    ];
  }

  /**
   * Check if Slither is installed
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
            error: 'Slither not found. Install with: pip install slither-analyzer' 
          });
        }
      });

      proc.on('error', () => {
        resolve({ 
          installed: false, 
          error: 'Slither not found. Install with: pip install slither-analyzer' 
        });
      });
    });
  }

  /**
   * Run Slither analysis on a project or file
   * 
   * @param {string} target - Path to project or Solidity file
   * @param {Object} options - Analysis options
   * @returns {Promise<Object>} Analysis results
   */
  async analyze(target, options = {}) {
    const targetPath = path.resolve(target);
    
    // Check if target exists
    if (!fs.existsSync(targetPath)) {
      return {
        success: false,
        error: `Target not found: ${targetPath}`
      };
    }

    // Build arguments
    const args = [...this.defaultArgs];
    
    // Add specific detectors if provided
    if (options.detectors) {
      args.push('--detect', options.detectors.join(','));
    }
    
    // Exclude specific detectors
    if (options.exclude) {
      args.push('--exclude', options.exclude.join(','));
    }
    
    // Filter by severity
    if (options.severity) {
      if (!options.severity.includes('info')) {
        args.push('--exclude-informational');
      }
      if (!options.severity.includes('low')) {
        args.push('--exclude-low');
      }
      if (!options.severity.includes('medium')) {
        args.push('--exclude-medium');
      }
      if (!options.severity.includes('high')) {
        args.push('--exclude-high');
      }
    }

    // Solc remappings
    if (options.remappings) {
      options.remappings.forEach(remap => {
        args.push('--solc-remaps', remap);
      });
    }

    // Add target
    args.push(targetPath);

    return this._execute(args, options);
  }

  /**
   * Run specific detectors only
   * 
   * @param {string} target - Path to analyze
   * @param {Array} detectors - List of detector names
   * @returns {Promise<Object>} Analysis results
   */
  async runDetectors(target, detectors) {
    return this.analyze(target, { detectors });
  }

  /**
   * Run reentrancy checks only
   * 
   * @param {string} target - Path to analyze
   * @returns {Promise<Object>} Reentrancy findings
   */
  async checkReentrancy(target) {
    return this.runDetectors(target, [
      'reentrancy-eth',
      'reentrancy-no-eth',
      'reentrancy-benign',
      'reentrancy-events',
      'reentrancy-unlimited-gas'
    ]);
  }

  /**
   * Run access control checks
   * 
   * @param {string} target - Path to analyze
   * @returns {Promise<Object>} Access control findings
   */
  async checkAccessControl(target) {
    return this.runDetectors(target, [
      'unprotected-upgrade',
      'suicidal',
      'arbitrary-send-erc20',
      'arbitrary-send-eth',
      'protected-vars',
      'missing-zero-check'
    ]);
  }

  /**
   * Run high severity checks only
   * 
   * @param {string} target - Path to analyze
   * @returns {Promise<Object>} High severity findings
   */
  async checkHighSeverity(target) {
    const args = [
      '--json', '-',
      '--exclude-informational',
      '--exclude-optimization',
      '--exclude-low',
      '--exclude-medium',
      path.resolve(target)
    ];
    return this._execute(args);
  }

  /**
   * Get list of all available detectors
   * 
   * @returns {Promise<Object>} List of detectors
   */
  async listDetectors() {
    return new Promise((resolve) => {
      const proc = spawn(this.command, ['--list-detectors-json']);
      let output = '';

      proc.stdout.on('data', (data) => {
        output += data.toString();
      });

      proc.on('close', (code) => {
        if (code === 0) {
          try {
            const detectors = JSON.parse(output);
            resolve({ success: true, detectors });
          } catch (e) {
            resolve({ success: false, error: 'Failed to parse detector list' });
          }
        } else {
          resolve({ success: false, error: 'Failed to list detectors' });
        }
      });
    });
  }

  /**
   * Execute Slither command
   * @private
   */
  _execute(args, options = {}) {
    return new Promise((resolve) => {
      const proc = spawn(this.command, args, {
        cwd: options.cwd || process.cwd(),
        timeout: this.timeout
      });

      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      proc.on('close', (code) => {
        // Slither returns non-zero if findings exist, so don't treat as error
        try {
          const results = JSON.parse(stdout);
          resolve({
            success: true,
            exitCode: code,
            findings: this._parseFindings(results),
            raw: results
          });
        } catch (e) {
          // JSON parse failed
          if (stderr.includes('Error')) {
            resolve({
              success: false,
              error: stderr || 'Analysis failed',
              exitCode: code
            });
          } else {
            resolve({
              success: true,
              exitCode: code,
              findings: [],
              message: 'No findings or unable to parse output'
            });
          }
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
   * Parse Slither JSON output into structured findings
   * @private
   */
  _parseFindings(results) {
    if (!results?.results?.detectors) {
      return [];
    }

    return results.results.detectors.map(detector => ({
      id: detector.check,
      title: detector.check.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
      severity: this._mapSeverity(detector.impact),
      confidence: detector.confidence,
      description: detector.description,
      elements: detector.elements?.map(el => ({
        type: el.type,
        name: el.name,
        file: el.source_mapping?.filename_relative,
        lines: el.source_mapping?.lines,
        startLine: el.source_mapping?.lines?.[0],
        endLine: el.source_mapping?.lines?.[el.source_mapping?.lines?.length - 1]
      })) || [],
      markdown: detector.markdown,
      firstMarkdownElement: detector.first_markdown_element
    }));
  }

  /**
   * Map Slither severity to standard severity
   * @private
   */
  _mapSeverity(impact) {
    const mapping = {
      'High': 'HIGH',
      'Medium': 'MEDIUM',
      'Low': 'LOW',
      'Informational': 'INFO',
      'Optimization': 'GAS'
    };
    return mapping[impact] || 'UNKNOWN';
  }
}

module.exports = SlitherRunner;
