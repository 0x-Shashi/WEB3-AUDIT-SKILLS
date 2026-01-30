/**
 * Mythril Runner
 * 
 * Execute Mythril security analysis and parse results.
 * Mythril is an EVM bytecode security analyzer with symbolic execution.
 * 
 * Requirements:
 *   pip install mythril
 * 
 * Usage:
 *   const runner = new MythrilRunner();
 *   const results = await runner.analyze('./Contract.sol');
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

class MythrilRunner {
  constructor(options = {}) {
    this.command = options.command || 'myth';
    this.timeout = options.timeout || 600000; // 10 minutes default (Mythril is slower)
    this.defaultArgs = [
      '-o', 'json',
      '--execution-timeout', '300'
    ];
  }

  /**
   * Check if Mythril is installed
   * 
   * @returns {Promise<Object>} Version info or error
   */
  async checkInstallation() {
    return new Promise((resolve) => {
      const proc = spawn(this.command, ['version']);
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
            error: 'Mythril not found. Install with: pip install mythril' 
          });
        }
      });

      proc.on('error', () => {
        resolve({ 
          installed: false, 
          error: 'Mythril not found. Install with: pip install mythril' 
        });
      });
    });
  }

  /**
   * Analyze a Solidity file
   * 
   * @param {string} filePath - Path to Solidity file
   * @param {Object} options - Analysis options
   * @returns {Promise<Object>} Analysis results
   */
  async analyze(filePath, options = {}) {
    const absPath = path.resolve(filePath);
    
    if (!fs.existsSync(absPath)) {
      return {
        success: false,
        error: `File not found: ${absPath}`
      };
    }

    const args = ['analyze', ...this.defaultArgs];

    // Execution timeout
    if (options.timeout) {
      const idx = args.indexOf('--execution-timeout');
      if (idx > -1) {
        args[idx + 1] = String(options.timeout);
      }
    }

    // Transaction count (depth)
    if (options.transactionCount) {
      args.push('-t', String(options.transactionCount));
    }

    // Max depth
    if (options.maxDepth) {
      args.push('--max-depth', String(options.maxDepth));
    }

    // Solc version
    if (options.solcVersion) {
      args.push('--solv', options.solcVersion);
    }

    // Solc remappings
    if (options.remappings) {
      options.remappings.forEach(remap => {
        args.push('--solc-args', `--allow-paths . --base-path . ${remap}`);
      });
    }

    // Strategy
    if (options.strategy) {
      args.push('--strategy', options.strategy);
    }

    args.push(absPath);

    return this._execute(args, options);
  }

  /**
   * Analyze bytecode (deployed contract)
   * 
   * @param {string} bytecode - Contract bytecode
   * @param {Object} options - Analysis options
   * @returns {Promise<Object>} Analysis results
   */
  async analyzeByteCode(bytecode, options = {}) {
    const args = ['analyze', '-c', bytecode, ...this.defaultArgs];

    if (options.timeout) {
      const idx = args.indexOf('--execution-timeout');
      if (idx > -1) {
        args[idx + 1] = String(options.timeout);
      }
    }

    return this._execute(args, options);
  }

  /**
   * Analyze deployed contract on mainnet
   * 
   * @param {string} address - Contract address
   * @param {Object} options - Analysis options (requires RPC URL)
   * @returns {Promise<Object>} Analysis results
   */
  async analyzeAddress(address, options = {}) {
    if (!options.rpcUrl) {
      return {
        success: false,
        error: 'RPC URL required for on-chain analysis'
      };
    }

    const args = [
      'analyze',
      '-a', address,
      '--rpc', options.rpcUrl,
      ...this.defaultArgs
    ];

    return this._execute(args, options);
  }

  /**
   * Quick analysis (fewer transactions)
   * 
   * @param {string} filePath - Path to Solidity file
   * @returns {Promise<Object>} Analysis results
   */
  async quickAnalyze(filePath) {
    return this.analyze(filePath, {
      transactionCount: 2,
      maxDepth: 12,
      timeout: 60
    });
  }

  /**
   * Deep analysis (more transactions, more time)
   * 
   * @param {string} filePath - Path to Solidity file
   * @returns {Promise<Object>} Analysis results
   */
  async deepAnalyze(filePath) {
    return this.analyze(filePath, {
      transactionCount: 10,
      maxDepth: 50,
      timeout: 900, // 15 minutes
      strategy: 'bfs'
    });
  }

  /**
   * Execute Mythril command
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
        try {
          const results = JSON.parse(stdout);
          resolve({
            success: true,
            exitCode: code,
            findings: this._parseFindings(results),
            raw: results
          });
        } catch (e) {
          if (stdout.includes('No issues')) {
            resolve({
              success: true,
              exitCode: code,
              findings: [],
              message: 'No issues found'
            });
          } else {
            resolve({
              success: false,
              error: stderr || stdout || 'Analysis failed',
              exitCode: code
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
   * Parse Mythril JSON output into structured findings
   * @private
   */
  _parseFindings(results) {
    if (!results?.issues) {
      return [];
    }

    return results.issues.map(issue => ({
      id: issue.swcID || issue.title?.replace(/\s+/g, '-').toLowerCase(),
      title: issue.title,
      severity: this._mapSeverity(issue.severity),
      description: issue.description,
      swcId: issue.swcID,
      swcTitle: issue.swcTitle,
      elements: [{
        type: 'function',
        name: issue.function,
        file: issue.filename,
        address: issue.address,
        startLine: issue.lineno,
        code: issue.code
      }],
      txSequence: issue.tx_sequence
    }));
  }

  /**
   * Map Mythril severity to standard severity
   * @private
   */
  _mapSeverity(severity) {
    const mapping = {
      'High': 'HIGH',
      'Medium': 'MEDIUM',
      'Low': 'LOW'
    };
    return mapping[severity] || 'MEDIUM';
  }
}

module.exports = MythrilRunner;

