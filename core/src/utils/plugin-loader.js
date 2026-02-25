/**
 * Plugin Loader — Reads plugin.json and resolves capabilities to actual files
 * 
 * Bridges the gap between static JSON metadata and the real skill files on disk.
 * Each capability is validated against the skills directory to determine if it's
 * actually backed by content.
 * 
 * @module plugin-loader
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import { join } from 'path';

/**
 * Maps plugin.json capability names to skills directory paths/patterns
 * This is the bridge that makes metadata actionable.
 */
const CAPABILITY_REGISTRY = {
  'solidity-scanning': {
    label: 'Solidity Scanning',
    directories: ['solidity-scanner', 'patterns'],
    requiredFiles: ['patterns/reentrancy-patterns.md', 'patterns/access-control-patterns.md'],
    description: 'Core Solidity vulnerability pattern matching'
  },
  'solana-scanning': {
    label: 'Solana Scanning',
    directories: ['solana-scanner'],
    requiredFiles: [],
    description: 'Solana/Anchor program security analysis'
  },
  'cairo-scanning': {
    label: 'Cairo Scanning',
    directories: ['cairo-scanner'],
    requiredFiles: [],
    description: 'StarkNet Cairo contract analysis'
  },
  'move-scanning': {
    label: 'Move Scanning',
    directories: ['move-scanner'],
    requiredFiles: [],
    description: 'Aptos/Sui Move module analysis'
  },
  'cosmos-scanning': {
    label: 'Cosmos Scanning',
    directories: ['cosmos-scanner'],
    requiredFiles: [],
    description: 'Cosmos SDK module analysis'
  },
  'ton-scanning': {
    label: 'TON Scanning',
    directories: ['ton-scanner'],
    requiredFiles: [],
    description: 'TON FunC/Tact contract analysis'
  },
  'attack-chain-detection': {
    label: 'Attack Chain Detection',
    directories: ['attack-chains', 'attack-trees'],
    requiredFiles: [],
    description: 'Multi-step attack path analysis'
  },
  'protocol-template-matching': {
    label: 'Protocol Templates',
    directories: ['protocol-playbooks', 'templates'],
    requiredFiles: [],
    description: 'Protocol-specific audit playbooks'
  },
  'variant-analysis': {
    label: 'Variant Analysis',
    directories: ['variant-analysis'],
    requiredFiles: [],
    description: 'Find variants of known vulnerabilities'
  },
  'static-analysis-integration': {
    label: 'Static Analysis',
    directories: ['static-analysis'],
    requiredFiles: [],
    description: 'Slither, Aderyn, Mythril integration'
  },
  'token-compatibility-analysis': {
    label: 'Token Compatibility',
    directories: ['token-analyzer'],
    requiredFiles: [],
    description: 'ERC20/721/1155 compatibility checks'
  },
  'audit-report-generation': {
    label: 'Report Generation',
    directories: ['report-writer', 'templates'],
    requiredFiles: [],
    description: 'Structured audit report creation'
  },
  'severity-classification': {
    label: 'Severity Classification',
    directories: ['severity', 'scoring'],
    requiredFiles: [],
    description: 'CVSS-like severity scoring'
  },
  'cyfrin-findings-search': {
    label: 'Cyfrin Findings',
    directories: ['cyfrin-findings'],
    requiredFiles: [],
    description: 'Search real audit findings database'
  },
  'spec-compliance-checking': {
    label: 'Spec Compliance',
    directories: ['spec-compliance'],
    requiredFiles: [],
    description: 'EIP/ERC specification compliance'
  },
  'differential-review': {
    label: 'Differential Review',
    directories: ['differential-review'],
    requiredFiles: [],
    description: 'Diff-based upgrade security review'
  },
  'fix-verification': {
    label: 'Fix Verification',
    directories: ['fix-review', 'fix-patterns'],
    requiredFiles: [],
    description: 'Verify vulnerability fixes are correct'
  }
};

/**
 * Maps chain names to scanner directories and validation patterns
 */
const CHAIN_REGISTRY = {
  'ethereum': { scanner: 'solidity-scanner', aliases: ['evm', 'eth'] },
  'arbitrum': { scanner: 'solidity-scanner', guide: 'chain-guides' },
  'optimism': { scanner: 'solidity-scanner', guide: 'chain-guides' },
  'base': { scanner: 'solidity-scanner', guide: 'chain-guides' },
  'polygon': { scanner: 'solidity-scanner', guide: 'chain-guides' },
  'bsc': { scanner: 'solidity-scanner', guide: 'chain-guides' },
  'avalanche': { scanner: 'solidity-scanner', guide: 'chain-guides' },
  'solana': { scanner: 'solana-scanner' },
  'starknet': { scanner: 'starknet-scanner' },
  'cosmos': { scanner: 'cosmos-scanner' },
  'sui': { scanner: 'sui-scanner' },
  'aptos': { scanner: 'aptos-scanner' },
  'ton': { scanner: 'ton-scanner' },
  'zksync': { scanner: 'solidity-scanner', guide: 'chain-guides' },
  'scroll': { scanner: 'solidity-scanner', guide: 'chain-guides' },
  'linea': { scanner: 'solidity-scanner', guide: 'chain-guides' },
  'fuel': { scanner: 'fuel-scanner' },
  'aztec': { scanner: 'aztec-scanner' }
};


export class PluginLoader {
  constructor(pluginJsonPath, skillsDir) {
    this.pluginJsonPath = pluginJsonPath;
    this.skillsDir = skillsDir;
  }

  /**
   * Load and resolve plugin.json — validates capabilities and chains
   * against the actual skills directory on disk.
   * 
   * @returns {Object} Resolved plugin data with active/inactive status
   */
  async load() {
    if (!existsSync(this.pluginJsonPath)) {
      throw new Error(`plugin.json not found at ${this.pluginJsonPath}`);
    }

    const raw = JSON.parse(readFileSync(this.pluginJsonPath, 'utf-8'));

    // Resolve capabilities — handle both array and object formats
    let capabilityNames;
    if (Array.isArray(raw.capabilities)) {
      capabilityNames = raw.capabilities;
    } else if (raw.capabilities && typeof raw.capabilities === 'object') {
      capabilityNames = Object.keys(raw.capabilities);
    } else {
      capabilityNames = [];
    }
    const resolvedCapabilities = capabilityNames.map(capName => {
      return this._resolveCapability(capName);
    });

    // Resolve chains — handle both array and object formats
    let chainNames;
    if (Array.isArray(raw.supported_chains)) {
      chainNames = raw.supported_chains;
    } else if (raw.supported_chains && typeof raw.supported_chains === 'object') {
      chainNames = Object.keys(raw.supported_chains);
    } else {
      chainNames = [];
    }
    const supportedChains = chainNames.map(chainName => {
      return this._resolveChain(chainName);
    });

    return {
      name: raw.name,
      version: raw.version || '0.0.0',
      description: raw.description || '',
      author: raw.author || 'unknown',
      capabilities: raw.capabilities,
      resolvedCapabilities,
      supported_chains: supportedChains,
      skills_directory: raw.skills_directory,
      raw
    };
  }

  /**
   * Get only the active (file-backed) capabilities
   */
  async getActiveCapabilities() {
    const plugin = await this.load();
    return plugin.resolvedCapabilities.filter(c => c.active);
  }

  /**
   * Get only the active chains (scanner directory exists)
   */
  async getActiveChains() {
    const plugin = await this.load();
    return plugin.supported_chains.filter(c => c.active);
  }

  /**
   * Get capability details for a specific capability name
   */
  getCapabilityInfo(capName) {
    return this._resolveCapability(capName);
  }

  // ─── Internal Resolution ────────────────────────────────────

  _resolveCapability(capName) {
    const registry = CAPABILITY_REGISTRY[capName];

    if (!registry) {
      return {
        name: capName,
        active: false,
        fileCount: 0,
        label: capName,
        description: 'Unknown capability — not in registry',
        directories: [],
        files: []
      };
    }

    // Check which directories exist and count files
    let totalFiles = 0;
    const activeDirs = [];
    const allFiles = [];

    for (const dir of registry.directories) {
      const dirPath = join(this.skillsDir, dir);
      if (existsSync(dirPath)) {
        const files = this._listMdFiles(dirPath);
        totalFiles += files.length;
        activeDirs.push(dir);
        allFiles.push(...files.map(f => `${dir}/${f}`));
      }
    }

    // Check required files
    const missingRequired = [];
    for (const reqFile of registry.requiredFiles) {
      if (!existsSync(join(this.skillsDir, reqFile))) {
        missingRequired.push(reqFile);
      }
    }

    const active = totalFiles > 0 && missingRequired.length === 0;

    return {
      name: capName,
      active,
      label: registry.label,
      description: registry.description,
      fileCount: totalFiles,
      directories: activeDirs,
      missingRequired,
      files: allFiles
    };
  }

  _resolveChain(chainName) {
    const registry = CHAIN_REGISTRY[chainName];

    if (!registry) {
      return { name: chainName, active: false, scanner: null };
    }

    const scannerDir = join(this.skillsDir, registry.scanner);
    const scannerExists = existsSync(scannerDir);
    const hasFiles = scannerExists && this._listMdFiles(scannerDir).length > 0;

    return {
      name: chainName,
      active: hasFiles,
      scanner: registry.scanner,
      guide: registry.guide || null
    };
  }

  _listMdFiles(dir) {
    try {
      return readdirSync(dir).filter(f => f.endsWith('.md'));
    } catch {
      return [];
    }
  }
}

export default PluginLoader;
