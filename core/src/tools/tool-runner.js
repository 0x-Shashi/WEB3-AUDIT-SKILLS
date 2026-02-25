/**
 * Tool Runner — Framework-aware project detection and test execution
 * 
 * Detects Foundry/Hardhat projects and provides a unified interface to:
 *   - Compile contracts
 *   - Run tests
 *   - Execute specific test files (PoC exploit tests)
 *   - Get project metadata (compiler version, contract list, etc.)
 * 
 * @module tool-runner
 */

import { existsSync, readFileSync, readdirSync } from 'fs';
import { join, basename } from 'path';
import { execSync, spawn } from 'child_process';

/**
 * Supported frameworks and their detection signatures
 */
const FRAMEWORKS = {
  foundry: {
    name: 'Foundry',
    configFiles: ['foundry.toml'],
    srcDirs: ['src', 'contracts'],
    testDirs: ['test', 'tests'],
    compile: 'forge build',
    test: 'forge test',
    testVerbose: 'forge test -vvvv',
    testFile: (file) => `forge test --match-path ${file} -vvvv`,
    testContract: (name) => `forge test --match-contract ${name} -vvvv`,
    testFunction: (name) => `forge test --match-test ${name} -vvvv`,
    coverage: 'forge coverage',
    gasReport: 'forge test --gas-report',
    snapshot: 'forge snapshot',
    clean: 'forge clean',
  },
  hardhat: {
    name: 'Hardhat',
    configFiles: ['hardhat.config.js', 'hardhat.config.ts'],
    srcDirs: ['contracts'],
    testDirs: ['test', 'tests'],
    compile: 'npx hardhat compile',
    test: 'npx hardhat test',
    testVerbose: 'npx hardhat test --verbose',
    testFile: (file) => `npx hardhat test ${file}`,
    testContract: (name) => `npx hardhat test --grep "${name}"`,
    testFunction: (name) => `npx hardhat test --grep "${name}"`,
    coverage: 'npx hardhat coverage',
    gasReport: 'REPORT_GAS=true npx hardhat test',
    clean: 'npx hardhat clean',
  },
  brownie: {
    name: 'Brownie',
    configFiles: ['brownie-config.yaml'],
    srcDirs: ['contracts'],
    testDirs: ['tests'],
    compile: 'brownie compile',
    test: 'brownie test',
    testVerbose: 'brownie test -v',
    testFile: (file) => `brownie test ${file} -v`,
    clean: 'brownie compile --all',
  }
};

/**
 * Detect and interact with Solidity project frameworks
 */
export class ToolRunner {
  constructor(projectDir) {
    this.projectDir = projectDir;
    this.framework = null;
    this.frameworkConfig = null;
    this._detect();
  }

  /**
   * Detect which framework the project uses
   */
  _detect() {
    for (const [key, fw] of Object.entries(FRAMEWORKS)) {
      for (const configFile of fw.configFiles) {
        if (existsSync(join(this.projectDir, configFile))) {
          this.framework = key;
          this.frameworkConfig = fw;
          return;
        }
      }
    }
  }

  /**
   * Get detected framework info
   */
  getFramework() {
    if (!this.framework) {
      return {
        detected: false,
        message: 'No supported framework detected. Expected foundry.toml, hardhat.config.js/ts, or brownie-config.yaml',
        suggestion: 'Initialize with: forge init (Foundry) or npx hardhat init (Hardhat)'
      };
    }

    return {
      detected: true,
      framework: this.framework,
      name: this.frameworkConfig.name,
      configFile: this.frameworkConfig.configFiles.find(f => existsSync(join(this.projectDir, f)))
    };
  }

  /**
   * Get project metadata — contracts, compiler version, structure
   */
  getProjectInfo() {
    const info = this.getFramework();
    if (!info.detected) return info;

    // Find source directory
    const srcDir = this.frameworkConfig.srcDirs.find(d => existsSync(join(this.projectDir, d)));
    const testDir = this.frameworkConfig.testDirs.find(d => existsSync(join(this.projectDir, d)));

    // Count and list Solidity files
    const sourceFiles = srcDir ? this._findSolFiles(join(this.projectDir, srcDir)) : [];
    const testFiles = testDir ? this._findSolFiles(join(this.projectDir, testDir)) : [];

    // Parse compiler version from config
    const compilerVersion = this._getCompilerVersion();

    return {
      ...info,
      srcDir: srcDir || null,
      testDir: testDir || null,
      sourceFiles: sourceFiles.map(f => f.replace(this.projectDir, '').replace(/^[/\\]/, '')),
      testFiles: testFiles.map(f => f.replace(this.projectDir, '').replace(/^[/\\]/, '')),
      sourceCount: sourceFiles.length,
      testCount: testFiles.length,
      compilerVersion
    };
  }

  /**
   * Compile the project
   * @returns {Object} { success, output, errors }
   */
  compile() {
    return this._exec(this.frameworkConfig.compile);
  }

  /**
   * Run all tests
   * @param {Object} options - { verbose, gasReport }
   * @returns {Object} { success, output, summary }
   */
  runTests(options = {}) {
    let cmd = options.verbose ? this.frameworkConfig.testVerbose : this.frameworkConfig.test;
    if (options.gasReport && this.frameworkConfig.gasReport) {
      cmd = this.frameworkConfig.gasReport;
    }
    const result = this._exec(cmd);
    result.summary = this._parseTestOutput(result.output);
    return result;
  }

  /**
   * Run a specific test file (e.g., a PoC exploit test)
   * @param {string} testFile - Path to test file
   * @returns {Object} { success, output, summary }
   */
  runTestFile(testFile) {
    if (!this.frameworkConfig.testFile) {
      return { success: false, output: '', error: 'Framework does not support single-file test execution' };
    }
    const cmd = this.frameworkConfig.testFile(testFile);
    const result = this._exec(cmd);
    result.summary = this._parseTestOutput(result.output);
    return result;
  }

  /**
   * Run tests matching a contract name
   * @param {string} contractName - Contract name to match
   */
  runTestContract(contractName) {
    if (!this.frameworkConfig.testContract) {
      return { success: false, output: '', error: 'Framework does not support contract-based test filtering' };
    }
    const cmd = this.frameworkConfig.testContract(contractName);
    const result = this._exec(cmd);
    result.summary = this._parseTestOutput(result.output);
    return result;
  }

  /**
   * Run tests matching a function name
   * @param {string} functionName - Test function name
   */
  runTestFunction(functionName) {
    if (!this.frameworkConfig.testFunction) {
      return { success: false, output: '', error: 'Framework does not support function-based test filtering' };
    }
    const cmd = this.frameworkConfig.testFunction(functionName);
    const result = this._exec(cmd);
    result.summary = this._parseTestOutput(result.output);
    return result;
  }

  /**
   * Run code coverage
   */
  runCoverage() {
    if (!this.frameworkConfig.coverage) {
      return { success: false, output: '', error: 'Framework does not support coverage' };
    }
    return this._exec(this.frameworkConfig.coverage);
  }

  /**
   * Generate a command string for the AI to suggest running
   * (used by adapters that can't exec directly)
   */
  getCommand(action, ...args) {
    const fw = this.frameworkConfig;
    if (!fw) return null;

    switch (action) {
      case 'compile': return fw.compile;
      case 'test': return fw.test;
      case 'testVerbose': return fw.testVerbose;
      case 'testFile': return fw.testFile?.(args[0]);
      case 'testContract': return fw.testContract?.(args[0]);
      case 'testFunction': return fw.testFunction?.(args[0]);
      case 'coverage': return fw.coverage;
      case 'gasReport': return fw.gasReport;
      case 'clean': return fw.clean;
      default: return null;
    }
  }

  // ─── Internal ───────────────────────────────────────────────

  _exec(cmd, timeoutMs = 120000) {
    try {
      const output = execSync(cmd, {
        cwd: this.projectDir,
        encoding: 'utf-8',
        timeout: timeoutMs,
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, FORCE_COLOR: '0' }
      });
      return { success: true, output, errors: null };
    } catch (err) {
      return {
        success: false,
        output: (err.stdout || '') + '\n' + (err.stderr || ''),
        errors: err.stderr || err.message
      };
    }
  }

  _findSolFiles(dir, maxDepth = 5, depth = 0) {
    if (depth >= maxDepth || !existsSync(dir)) return [];
    const results = [];
    try {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isFile() && entry.name.endsWith('.sol')) {
          results.push(full);
        } else if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'lib') {
          results.push(...this._findSolFiles(full, maxDepth, depth + 1));
        }
      }
    } catch { /* ignore */ }
    return results;
  }

  _getCompilerVersion() {
    if (this.framework === 'foundry') {
      try {
        const toml = readFileSync(join(this.projectDir, 'foundry.toml'), 'utf-8');
        const match = toml.match(/solc\s*=\s*["']([^"']+)["']/);
        if (match) return match[1];
        // Check pragma in source files
        return this._getPragmaVersion();
      } catch { /* ignore */ }
    } else if (this.framework === 'hardhat') {
      try {
        const configPath = this.frameworkConfig.configFiles
          .map(f => join(this.projectDir, f))
          .find(f => existsSync(f));
        if (configPath) {
          const config = readFileSync(configPath, 'utf-8');
          const match = config.match(/version:\s*["']([^"']+)["']/);
          if (match) return match[1];
        }
      } catch { /* ignore */ }
    }
    return this._getPragmaVersion();
  }

  _getPragmaVersion() {
    const srcDir = this.frameworkConfig?.srcDirs.find(d => existsSync(join(this.projectDir, d)));
    if (!srcDir) return 'unknown';
    const files = this._findSolFiles(join(this.projectDir, srcDir), 2);
    if (files.length === 0) return 'unknown';
    try {
      const content = readFileSync(files[0], 'utf-8');
      const match = content.match(/pragma\s+solidity\s+([^;]+)/);
      return match ? match[1].trim() : 'unknown';
    } catch { return 'unknown'; }
  }

  _parseTestOutput(output) {
    if (!output) return null;

    // Foundry output parsing
    const foundryMatch = output.match(/(\d+)\s+passed.*?(\d+)\s+failed/i);
    if (foundryMatch) {
      return { passed: parseInt(foundryMatch[1]), failed: parseInt(foundryMatch[2]) };
    }

    // Hardhat/Mocha output parsing  
    const mochaMatch = output.match(/(\d+)\s+passing.*?(\d+)\s+failing/i);
    if (mochaMatch) {
      return { passed: parseInt(mochaMatch[1]), failed: parseInt(mochaMatch[2]) };
    }

    // Passing only
    const passOnly = output.match(/(\d+)\s+pass(?:ed|ing)/i);
    if (passOnly) {
      return { passed: parseInt(passOnly[1]), failed: 0 };
    }

    return null;
  }
}

export default ToolRunner;
