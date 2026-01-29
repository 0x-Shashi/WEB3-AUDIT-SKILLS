/**
 * Project Detector
 * 
 * Detect blockchain project type, framework, and configuration.
 * Supports Ethereum, Solana, Move, and other ecosystems.
 * 
 * Usage:
 *   const detector = new ProjectDetector();
 *   const info = await detector.detect('./my-project');
 */

const path = require('path');
const fs = require('fs');

class ProjectDetector {
  constructor() {
    // Framework detection rules
    this.frameworks = {
      // Ethereum/EVM
      foundry: {
        files: ['foundry.toml'],
        srcDir: 'src',
        testDir: 'test',
        scriptDir: 'script',
        ecosystem: 'ethereum'
      },
      hardhat: {
        files: ['hardhat.config.js', 'hardhat.config.ts'],
        srcDir: 'contracts',
        testDir: 'test',
        scriptDir: 'scripts',
        ecosystem: 'ethereum'
      },
      truffle: {
        files: ['truffle-config.js', 'truffle.js'],
        srcDir: 'contracts',
        testDir: 'test',
        scriptDir: 'migrations',
        ecosystem: 'ethereum'
      },
      brownie: {
        files: ['brownie-config.yaml'],
        srcDir: 'contracts',
        testDir: 'tests',
        scriptDir: 'scripts',
        ecosystem: 'ethereum'
      },
      dapptools: {
        files: ['Makefile', '.dapprc'],
        srcDir: 'src',
        testDir: 'src',
        ecosystem: 'ethereum'
      },
      
      // Solana
      anchor: {
        files: ['Anchor.toml'],
        srcDir: 'programs',
        testDir: 'tests',
        ecosystem: 'solana'
      },
      native_solana: {
        files: ['Cargo.toml'],
        checkContent: { 'Cargo.toml': 'solana-program' },
        srcDir: 'src',
        testDir: 'tests',
        ecosystem: 'solana'
      },
      
      // Move
      aptos: {
        files: ['Move.toml'],
        checkContent: { 'Move.toml': 'AptosFramework' },
        srcDir: 'sources',
        testDir: 'tests',
        ecosystem: 'aptos'
      },
      sui: {
        files: ['Move.toml'],
        checkContent: { 'Move.toml': 'Sui' },
        srcDir: 'sources',
        testDir: 'tests',
        ecosystem: 'sui'
      },
      
      // CosmWasm
      cosmwasm: {
        files: ['Cargo.toml'],
        checkContent: { 'Cargo.toml': 'cosmwasm-std' },
        srcDir: 'src',
        testDir: 'tests',
        ecosystem: 'cosmos'
      },
      
      // NEAR
      near: {
        files: ['Cargo.toml', 'package.json'],
        checkContent: { 'Cargo.toml': 'near-sdk' },
        srcDir: 'src',
        testDir: 'tests',
        ecosystem: 'near'
      }
    };
  }

  /**
   * Detect project type and configuration
   * 
   * @param {string} projectPath - Path to project directory
   * @returns {Promise<Object>} Project information
   */
  async detect(projectPath) {
    const absPath = path.resolve(projectPath);
    
    if (!fs.existsSync(absPath)) {
      return {
        detected: false,
        error: `Path not found: ${absPath}`
      };
    }

    const result = {
      detected: false,
      path: absPath,
      name: path.basename(absPath),
      framework: null,
      ecosystem: null,
      srcDir: null,
      testDir: null,
      scriptDir: null,
      language: null,
      dependencies: [],
      config: {}
    };

    // Try each framework
    for (const [framework, rules] of Object.entries(this.frameworks)) {
      const detected = await this._checkFramework(absPath, rules);
      
      if (detected) {
        result.detected = true;
        result.framework = framework;
        result.ecosystem = rules.ecosystem;
        result.srcDir = rules.srcDir;
        result.testDir = rules.testDir;
        result.scriptDir = rules.scriptDir;
        break;
      }
    }

    // Detect language
    result.language = this._detectLanguage(absPath, result.ecosystem);

    // Read dependencies
    result.dependencies = await this._getDependencies(absPath, result.framework);

    // Read framework config
    result.config = await this._getConfig(absPath, result.framework);

    // Get source files
    if (result.detected && result.srcDir) {
      result.sourceFiles = await this._getSourceFiles(absPath, result.srcDir, result.language);
    }

    return result;
  }

  /**
   * Check if a framework is detected
   * @private
   */
  async _checkFramework(projectPath, rules) {
    // Check required files exist
    const hasFiles = rules.files.some(f => 
      fs.existsSync(path.join(projectPath, f))
    );
    
    if (!hasFiles) return false;

    // Check file content if required
    if (rules.checkContent) {
      for (const [file, content] of Object.entries(rules.checkContent)) {
        const filePath = path.join(projectPath, file);
        if (!fs.existsSync(filePath)) continue;
        
        const fileContent = fs.readFileSync(filePath, 'utf-8');
        if (!fileContent.includes(content)) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Detect primary programming language
   * @private
   */
  _detectLanguage(projectPath, ecosystem) {
    switch (ecosystem) {
      case 'ethereum':
        // Check for Vyper
        if (this._hasFiles(projectPath, '**/*.vy')) {
          return 'vyper';
        }
        return 'solidity';
        
      case 'solana':
      case 'cosmos':
      case 'near':
        return 'rust';
        
      case 'aptos':
      case 'sui':
        return 'move';
        
      default:
        // Guess based on files
        if (this._hasFiles(projectPath, '**/*.sol')) return 'solidity';
        if (this._hasFiles(projectPath, '**/*.rs')) return 'rust';
        if (this._hasFiles(projectPath, '**/*.move')) return 'move';
        return 'unknown';
    }
  }

  /**
   * Check if files matching pattern exist
   * @private
   */
  _hasFiles(projectPath, pattern) {
    // Simple check - just look for common locations
    const ext = pattern.match(/\*\.(\w+)$/)?.[1];
    if (!ext) return false;

    const checkDirs = ['src', 'contracts', 'sources', 'programs'];
    
    for (const dir of checkDirs) {
      const dirPath = path.join(projectPath, dir);
      if (fs.existsSync(dirPath)) {
        const files = fs.readdirSync(dirPath, { recursive: true });
        if (files.some(f => f.toString().endsWith(`.${ext}`))) {
          return true;
        }
      }
    }
    
    return false;
  }

  /**
   * Get project dependencies
   * @private
   */
  async _getDependencies(projectPath, framework) {
    const deps = [];

    // NPM dependencies
    const packagePath = path.join(projectPath, 'package.json');
    if (fs.existsSync(packagePath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf-8'));
        if (pkg.dependencies) {
          deps.push(...Object.entries(pkg.dependencies).map(([name, version]) => ({
            name,
            version,
            type: 'npm'
          })));
        }
        if (pkg.devDependencies) {
          deps.push(...Object.entries(pkg.devDependencies).map(([name, version]) => ({
            name,
            version,
            type: 'npm-dev'
          })));
        }
      } catch (e) {
        // Ignore parse errors
      }
    }

    // Foundry dependencies (lib folder)
    if (framework === 'foundry') {
      const libPath = path.join(projectPath, 'lib');
      if (fs.existsSync(libPath)) {
        const libs = fs.readdirSync(libPath);
        for (const lib of libs) {
          if (fs.statSync(path.join(libPath, lib)).isDirectory()) {
            deps.push({
              name: lib,
              type: 'foundry-lib'
            });
          }
        }
      }
    }

    // Cargo dependencies
    const cargoPath = path.join(projectPath, 'Cargo.toml');
    if (fs.existsSync(cargoPath)) {
      try {
        const cargoContent = fs.readFileSync(cargoPath, 'utf-8');
        // Simple TOML parsing for dependencies
        const depSection = cargoContent.match(/\[dependencies\]([\s\S]*?)(?:\[|$)/);
        if (depSection) {
          const lines = depSection[1].split('\n');
          for (const line of lines) {
            const match = line.match(/^(\w[\w-]*)\s*=/);
            if (match) {
              deps.push({
                name: match[1],
                type: 'cargo'
              });
            }
          }
        }
      } catch (e) {
        // Ignore parse errors
      }
    }

    return deps;
  }

  /**
   * Get framework configuration
   * @private
   */
  async _getConfig(projectPath, framework) {
    const config = {};

    switch (framework) {
      case 'foundry':
        const foundryPath = path.join(projectPath, 'foundry.toml');
        if (fs.existsSync(foundryPath)) {
          const content = fs.readFileSync(foundryPath, 'utf-8');
          // Extract some key settings
          const srcMatch = content.match(/src\s*=\s*["']([^"']+)["']/);
          const testMatch = content.match(/test\s*=\s*["']([^"']+)["']/);
          const solcMatch = content.match(/solc_version\s*=\s*["']([^"']+)["']/);
          
          if (srcMatch) config.src = srcMatch[1];
          if (testMatch) config.test = testMatch[1];
          if (solcMatch) config.solcVersion = solcMatch[1];
        }
        break;

      case 'hardhat':
        // Read hardhat config (simplified)
        const hhPath = path.join(projectPath, 'hardhat.config.js');
        const hhTsPath = path.join(projectPath, 'hardhat.config.ts');
        
        if (fs.existsSync(hhPath) || fs.existsSync(hhTsPath)) {
          config.type = fs.existsSync(hhTsPath) ? 'typescript' : 'javascript';
        }
        break;

      case 'anchor':
        const anchorPath = path.join(projectPath, 'Anchor.toml');
        if (fs.existsSync(anchorPath)) {
          const content = fs.readFileSync(anchorPath, 'utf-8');
          const clusterMatch = content.match(/cluster\s*=\s*["']([^"']+)["']/);
          if (clusterMatch) config.cluster = clusterMatch[1];
        }
        break;
    }

    return config;
  }

  /**
   * Get list of source files
   * @private
   */
  async _getSourceFiles(projectPath, srcDir, language) {
    const srcPath = path.join(projectPath, srcDir);
    if (!fs.existsSync(srcPath)) return [];

    const ext = {
      solidity: '.sol',
      vyper: '.vy',
      rust: '.rs',
      move: '.move'
    }[language] || '.sol';

    const files = [];
    
    const walk = (dir) => {
      const items = fs.readdirSync(dir);
      for (const item of items) {
        const itemPath = path.join(dir, item);
        const stat = fs.statSync(itemPath);
        
        if (stat.isDirectory()) {
          walk(itemPath);
        } else if (item.endsWith(ext)) {
          files.push(path.relative(projectPath, itemPath));
        }
      }
    };

    walk(srcPath);
    return files;
  }

  /**
   * Get recommended tools for a project
   * 
   * @param {Object} projectInfo - Project info from detect()
   * @returns {Array} Recommended tools
   */
  getRecommendedTools(projectInfo) {
    const tools = [];

    switch (projectInfo.ecosystem) {
      case 'ethereum':
        tools.push({
          name: 'slither',
          description: 'Static analysis for Solidity',
          install: 'pip install slither-analyzer'
        });
        tools.push({
          name: 'aderyn',
          description: 'Fast Rust-based Solidity analyzer',
          install: 'cargo install aderyn'
        });
        tools.push({
          name: 'mythril',
          description: 'Symbolic execution analyzer',
          install: 'pip install mythril'
        });
        break;

      case 'solana':
        tools.push({
          name: 'anchor-test',
          description: 'Anchor framework testing',
          install: 'anchor build && anchor test'
        });
        tools.push({
          name: 'cargo-audit',
          description: 'Rust dependency auditing',
          install: 'cargo install cargo-audit'
        });
        break;

      case 'aptos':
      case 'sui':
        tools.push({
          name: 'move-prover',
          description: 'Formal verification for Move',
          install: 'See Move documentation'
        });
        break;
    }

    return tools;
  }
}

module.exports = ProjectDetector;
