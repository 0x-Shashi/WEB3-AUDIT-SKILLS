/**
 * Setup Validator — Validates the complete Web3 Audit Skills installation
 * 
 * Checks:
 *  1. Node.js version
 *  2. Skills directory existence and content
 *  3. Plugin.json integrity
 *  4. Capability-to-file resolution
 *  5. Chain scanner availability
 *  6. Core intelligence modules
 *  7. AI instruction files
 *  
 * @module setup-validator
 */

import { existsSync, readdirSync, readFileSync, statSync } from 'fs';
import { join } from 'path';

export class SetupValidator {
  constructor(rootDir, skillsDir, pluginJsonPath) {
    this.rootDir = rootDir;
    this.skillsDir = skillsDir;
    this.pluginJsonPath = pluginJsonPath;
  }

  /**
   * Run all validation checks
   * @param {Object} options 
   * @returns {Object} Validation results
   */
  async runAll(options = {}) {
    const checks = [];
    const failures = [];

    // 1. Node version check
    checks.push(this._checkNodeVersion());

    // 2. Skills directory
    checks.push(this._checkSkillsDirectory());

    // 3. Plugin.json
    checks.push(this._checkPluginJson());

    // 4. Core pattern files
    checks.push(this._checkPatternFiles());

    // 5. Intelligence modules
    checks.push(this._checkIntelligenceModules());

    // 6. AI instruction files
    checks.push(this._checkAIInstructions());

    // 7. Chain scanners
    checks.push(this._checkChainScanners());

    // 8. Route map and navigation
    checks.push(this._checkNavigation());

    // Aggregate
    const passCount = checks.filter(c => c.status === 'pass').length;
    const failCount = checks.filter(c => c.status === 'fail').length;
    const warnings = checks.filter(c => c.status === 'warn').length;

    for (const check of checks) {
      if (check.status === 'fail') {
        failures.push(check);
      }
    }

    return {
      passed: failCount === 0,
      checks,
      failures,
      passCount,
      failCount,
      warnings
    };
  }

  // ─── Individual Checks ──────────────────────────────────────

  _checkNodeVersion() {
    const version = process.version;
    const major = parseInt(version.slice(1).split('.')[0], 10);
    
    if (major >= 18) {
      return { check: 'node-version', label: `Node.js ${version}`, status: 'pass' };
    } else {
      return {
        check: 'node-version',
        label: `Node.js ${version}`,
        status: 'fail',
        message: 'Node.js >= 18.0.0 required',
        fix: 'Install Node.js 18+ from https://nodejs.org'
      };
    }
  }

  _checkSkillsDirectory() {
    if (!existsSync(this.skillsDir)) {
      return {
        check: 'skills-directory',
        label: 'Skills directory',
        status: 'fail',
        message: 'skills/ directory not found',
        fix: 'Ensure you cloned the full repository'
      };
    }

    const entries = readdirSync(this.skillsDir, { withFileTypes: true });
    const dirs = entries.filter(e => e.isDirectory()).length;
    const files = entries.filter(e => e.isFile()).length;

    if (dirs < 5) {
      return {
        check: 'skills-directory',
        label: 'Skills directory',
        status: 'warn',
        message: `Only ${dirs} subdirectories found — expected 20+`
      };
    }

    return {
      check: 'skills-directory',
      label: `Skills directory (${dirs} categories, ${files} root files)`,
      status: 'pass'
    };
  }

  _checkPluginJson() {
    if (!existsSync(this.pluginJsonPath)) {
      return {
        check: 'plugin-json',
        label: 'Plugin configuration',
        status: 'fail',
        message: 'claude-code/plugin.json not found',
        fix: 'Ensure claude-code/plugin.json exists in the repository'
      };
    }

    try {
      const content = readFileSync(this.pluginJsonPath, 'utf-8');
      const plugin = JSON.parse(content);

      const issues = [];
      if (!plugin.name) issues.push('missing "name"');
      if (!plugin.version) issues.push('missing "version"');
      
      // Handle both array and object formats for capabilities/chains
      const capCount = Array.isArray(plugin.capabilities) 
        ? plugin.capabilities.length 
        : (plugin.capabilities ? Object.keys(plugin.capabilities).length : 0);
      const chainCount = Array.isArray(plugin.supported_chains)
        ? plugin.supported_chains.length
        : (plugin.supported_chains ? Object.keys(plugin.supported_chains).length : 0);
      
      if (capCount === 0) issues.push('missing "capabilities"');
      if (chainCount === 0) issues.push('missing "supported_chains"');

      if (issues.length > 0) {
        return {
          check: 'plugin-json',
          label: 'Plugin configuration',
          status: 'warn',
          message: issues.join(', ')
        };
      }

      return {
        check: 'plugin-json',
        label: `Plugin v${plugin.version} (${capCount} capabilities, ${chainCount} chains)`,
        status: 'pass'
      };
    } catch (err) {
      return {
        check: 'plugin-json',
        label: 'Plugin configuration',
        status: 'fail',
        message: `Invalid JSON: ${err.message}`,
        fix: 'Fix the JSON syntax in claude-code/plugin.json'
      };
    }
  }

  _checkPatternFiles() {
    const patternsDir = join(this.skillsDir, 'patterns');
    
    if (!existsSync(patternsDir)) {
      return {
        check: 'pattern-files',
        label: 'Pattern files',
        status: 'fail',
        message: 'skills/patterns/ directory not found',
        fix: 'Ensure the full skills directory was cloned'
      };
    }

    const files = this._countFiles(patternsDir, '.md');
    if (files < 50) {
      return {
        check: 'pattern-files',
        label: `Pattern files (${files} found)`,
        status: 'warn',
        message: `Expected 100+ pattern files, found ${files}`
      };
    }

    return {
      check: 'pattern-files',
      label: `Pattern files (${files} .md files)`,
      status: 'pass'
    };
  }

  _checkIntelligenceModules() {
    const modules = [
      'intelligence/pattern-matcher.js',
      'intelligence/severity-scorer.js',
      'intelligence/vulnerability-classifier.js',
      'intelligence/semantic-search.js'
    ];

    const found = [];
    const missing = [];

    for (const mod of modules) {
      const fullPath = join(this.rootDir, 'core/src', mod);
      if (existsSync(fullPath)) {
        const stat = statSync(fullPath);
        if (stat.size > 0) {
          found.push(mod);
        } else {
          missing.push(`${mod} (empty)`);
        }
      } else {
        missing.push(mod);
      }
    }

    if (missing.length > 0) {
      return {
        check: 'intelligence-modules',
        label: `Intelligence modules (${found.length}/${modules.length})`,
        status: missing.every(m => m.includes('empty')) ? 'warn' : 'fail',
        message: `Missing/empty: ${missing.join(', ')}`,
        details: missing,
        fix: 'These modules power the live analysis engine'
      };
    }

    return {
      check: 'intelligence-modules',
      label: `Intelligence modules (${found.length}/${modules.length})`,
      status: 'pass'
    };
  }

  _checkAIInstructions() {
    const files = [
      { path: 'AI-INSTRUCTIONS.md', label: 'AI-INSTRUCTIONS.md' },
      { path: 'skills/ROUTE-MAP.md', label: 'ROUTE-MAP.md' },
      { path: 'skills/MASTER_CHECKLIST.md', label: 'MASTER_CHECKLIST.md' },
      { path: 'skills/INDEX.md', label: 'INDEX.md' }
    ];

    const found = [];
    const missing = [];

    for (const f of files) {
      const fullPath = join(this.rootDir, f.path);
      if (existsSync(fullPath)) {
        const stat = statSync(fullPath);
        if (stat.size > 100) {
          found.push(f.label);
        } else {
          missing.push(`${f.label} (too small)`);
        }
      } else {
        missing.push(f.label);
      }
    }

    if (missing.length > 0) {
      return {
        check: 'ai-instructions',
        label: `AI instruction files (${found.length}/${files.length})`,
        status: 'warn',
        message: `Missing: ${missing.join(', ')}`,
        details: missing
      };
    }

    return {
      check: 'ai-instructions',
      label: `AI instruction files (${found.length}/${files.length})`,
      status: 'pass'
    };
  }

  _checkChainScanners() {
    const scannerMap = {
      'ethereum': 'solidity-scanner',
      'solana': 'solana-scanner',
      'starknet': 'starknet-scanner',
      'cosmos': 'cosmos-scanner',
      'sui': 'sui-scanner',
      'aptos': 'aptos-scanner',
      'ton': 'ton-scanner',
      'fuel': 'fuel-scanner',
      'aztec': 'aztec-scanner'
    };

    const active = [];
    const inactive = [];

    for (const [chain, dir] of Object.entries(scannerMap)) {
      const scannerDir = join(this.skillsDir, dir);
      if (existsSync(scannerDir)) {
        const files = this._countFiles(scannerDir, '.md');
        if (files > 0) {
          active.push({ chain, dir, files });
        } else {
          inactive.push(chain);
        }
      } else {
        inactive.push(chain);
      }
    }

    const label = `Chain scanners (${active.length}/${Object.keys(scannerMap).length} active)`;
    const details = active.map(a => `${a.chain}: ${a.dir}/ (${a.files} files)`);

    if (active.length === 0) {
      return {
        check: 'chain-scanners',
        label,
        status: 'fail',
        message: 'No chain scanner directories found',
        fix: 'Ensure skills/ contains scanner subdirectories (e.g., solidity-scanner/)'
      };
    }

    if (inactive.length > active.length) {
      return { check: 'chain-scanners', label, status: 'warn', message: `Inactive: ${inactive.join(', ')}`, details };
    }

    return { check: 'chain-scanners', label, status: 'pass', details };
  }

  _checkNavigation() {
    const navFiles = [
      { path: 'skills/ROUTE-MAP.md', label: 'Route Map' },
      { path: 'skills/INDEX.md', label: 'Skills Index' },
      { path: 'skills/MASTER_CHECKLIST.md', label: 'Master Checklist' },
      { path: 'skills/TRIGGERS.md', label: 'Triggers' },
      { path: 'skills/SCHEMA.md', label: 'Schema' }
    ];

    const found = [];
    const missing = [];

    for (const f of navFiles) {
      if (existsSync(join(this.rootDir, f.path))) {
        found.push(f.label);
      } else {
        missing.push(f.label);
      }
    }

    if (missing.length > 2) {
      return {
        check: 'navigation',
        label: `Navigation files (${found.length}/${navFiles.length})`,
        status: 'warn',
        message: `Missing: ${missing.join(', ')}`
      };
    }

    return {
      check: 'navigation',
      label: `Navigation files (${found.length}/${navFiles.length})`,
      status: 'pass'
    };
  }

  // ─── Utilities ──────────────────────────────────────────────

  /**
   * Recursively count files with a given extension
   */
  _countFiles(dir, ext) {
    let count = 0;
    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isFile() && entry.name.endsWith(ext)) {
          count++;
        } else if (entry.isDirectory()) {
          count += this._countFiles(join(dir, entry.name), ext);
        }
      }
    } catch {
      // Ignore read errors
    }
    return count;
  }
}

export default SetupValidator;
