/**
 * Project Detector — Analyzes the skills directory structure
 * 
 * Provides statistics, file counts, and structural analysis
 * used by the CLI info and verify commands.
 * 
 * @module project-detector
 */

import { existsSync, readdirSync, statSync } from 'fs';
import { join } from 'path';

export class ProjectDetector {
  constructor(skillsDir) {
    this.skillsDir = skillsDir;
  }

  /**
   * Get aggregate statistics about the skills directory
   * @returns {Object} Stats including file counts, sizes, categories
   */
  async getStats() {
    if (!existsSync(this.skillsDir)) {
      return { patternFiles: 0, totalFiles: 0, categories: 0, totalSizeMB: '0.00' };
    }

    const entries = readdirSync(this.skillsDir, { withFileTypes: true });
    const categories = entries.filter(e => e.isDirectory()).length;

    // Count pattern files specifically
    const patternsDir = join(this.skillsDir, 'patterns');
    const patternFiles = existsSync(patternsDir) ? this._countFiles(patternsDir, '.md') : 0;

    // Count total files recursively
    const { count: totalFiles, size: totalSize } = this._countFilesWithSize(this.skillsDir);

    return {
      patternFiles,
      totalFiles,
      categories,
      totalSizeMB: (totalSize / (1024 * 1024)).toFixed(2)
    };
  }

  /**
   * Detect what type of protocol the user's project is
   * by scanning for common file/directory patterns
   * 
   * @param {string} projectDir - Path to the user's project
   * @returns {Object} Detected protocol type and recommended skills
   */
  async detectProtocolType(projectDir) {
    if (!existsSync(projectDir)) {
      return { type: 'unknown', confidence: 0, recommendations: [] };
    }

    const indicators = {
      lending: ['LendingPool', 'Comptroller', 'CToken', 'borrow', 'liquidat', 'collateral'],
      dex: ['swap', 'Router', 'Factory', 'Pool', 'pair', 'amm', 'liquidity'],
      vault: ['Vault', 'Strategy', 'yield', 'deposit', 'withdraw', 'shares', 'ERC4626'],
      bridge: ['Bridge', 'cross-chain', 'relay', 'messenger', 'L1', 'L2'],
      nft: ['ERC721', 'ERC1155', 'tokenURI', 'mint', 'royalt', 'marketplace'],
      governance: ['Governor', 'proposal', 'vote', 'timelock', 'dao', 'quorum'],
      staking: ['stake', 'unstake', 'restake', 'delegate', 'reward', 'epoch'],
      token: ['ERC20', 'transfer', 'approve', 'allowance', 'totalSupply']
    };

    const scores = {};
    const solidityFiles = this._findFiles(projectDir, '.sol', 3); // max depth 3

    for (const file of solidityFiles) {
      try {
        const content = require('fs').readFileSync(file, 'utf-8').toLowerCase();
        for (const [type, keywords] of Object.entries(indicators)) {
          scores[type] = scores[type] || 0;
          for (const kw of keywords) {
            if (content.includes(kw.toLowerCase())) {
              scores[type]++;
            }
          }
        }
      } catch {
        // skip unreadable files
      }
    }

    // Find best match
    const sorted = Object.entries(scores).sort((a, b) => b[1] - a[1]);
    if (sorted.length === 0 || sorted[0][1] === 0) {
      return { type: 'unknown', confidence: 0, recommendations: [] };
    }

    const [type, score] = sorted[0];
    const confidence = Math.min(score / 10, 1);

    return {
      type,
      confidence,
      solidityFiles: solidityFiles.length,
      recommendations: this._getRecommendations(type)
    };
  }

  // ─── Internal Helpers ───────────────────────────────────────

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
    } catch { /* ignore */ }
    return count;
  }

  _countFilesWithSize(dir) {
    let count = 0;
    let size = 0;
    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        if (entry.isFile()) {
          count++;
          try { size += statSync(fullPath).size; } catch { /* ignore */ }
        } else if (entry.isDirectory()) {
          const sub = this._countFilesWithSize(fullPath);
          count += sub.count;
          size += sub.size;
        }
      }
    } catch { /* ignore */ }
    return { count, size };
  }

  _findFiles(dir, ext, maxDepth, currentDepth = 0) {
    if (currentDepth >= maxDepth) return [];
    const results = [];
    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        if (entry.isFile() && entry.name.endsWith(ext)) {
          results.push(fullPath);
        } else if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
          results.push(...this._findFiles(fullPath, ext, maxDepth, currentDepth + 1));
        }
      }
    } catch { /* ignore */ }
    return results;
  }

  _getRecommendations(type) {
    const map = {
      lending: ['patterns/lending-pool-patterns.md', 'patterns/oracle-patterns.md', 'patterns/liquidation-patterns.md', 'patterns/flash-loan-patterns.md'],
      dex: ['patterns/swap-patterns.md', 'patterns/slippage-patterns.md', 'patterns/uniswap-patterns.md', 'patterns/sandwich-attack-patterns.md'],
      vault: ['patterns/vault-patterns.md', 'patterns/erc4626-patterns.md', 'patterns/first-depositor-issue-patterns.md', 'patterns/share-inflation-patterns.md'],
      bridge: ['patterns/bridge-patterns.md', 'patterns/cross-chain-patterns.md', 'patterns/replay-attack-patterns.md'],
      nft: ['patterns/erc721-patterns.md', 'patterns/erc1155-patterns.md', 'patterns/mint-vs-safemint-patterns.md', 'patterns/royalty-patterns.md'],
      governance: ['patterns/dao-patterns.md', 'patterns/vote-patterns.md', 'patterns/flash-loan-patterns.md'],
      staking: ['patterns/reentrancy-patterns.md', 'patterns/precision-loss-patterns.md', 'patterns/deposit-reward-tokens-patterns.md'],
      token: ['patterns/erc20-patterns.md', 'patterns/weird-erc20-patterns.md', 'patterns/fee-on-transfer-patterns.md', 'patterns/approve-patterns.md']
    };
    return map[type] || [];
  }
}

export default ProjectDetector;
