/**
 * Pattern Matcher - Core Intelligence Module
 * 
 * Matches Solidity code against known vulnerability patterns from the skills directory.
 * Powers real-time pattern detection for AI-assisted auditing.
 * 
 * @module pattern-matcher
 */

import { readFileSync, readdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Default skills directory (relative to core/)
const DEFAULT_SKILLS_DIR = join(__dirname, '../../../skills');

/**
 * Vulnerability pattern definitions with regex and context
 */
const VULNERABILITY_PATTERNS = {
  // Reentrancy patterns
  reentrancy: {
    name: 'Reentrancy',
    severity: 'Critical',
    patterns: [
      {
        id: 'external-call-before-state',
        regex: /\.call\{.*value.*\}.*\n(?:(?!balances|_balances|mapping).)*/gm,
        description: 'External call with value before state update',
        skillFile: 'patterns/reentrancy-antipatterns.md'
      },
      {
        id: 'transfer-before-state',
        regex: /transfer\(.*\).*\n(?:(?!balances|_balances|mapping).)*/gm,
        description: 'Transfer before state update',
        skillFile: 'patterns/reentrancy-antipatterns.md'
      },
      {
        id: 'missing-reentrancy-guard',
        regex: /function\s+\w+\([^)]*\)\s+external(?!\s+nonReentrant)/gm,
        description: 'External function without reentrancy guard',
        skillFile: 'patterns/reentrancy-antipatterns.md'
      }
    ],
    attackTree: 'attack-trees/reentrancy-attack-tree.md'
  },

  // Oracle manipulation patterns
  oracle: {
    name: 'Oracle Manipulation',
    severity: 'High',
    patterns: [
      {
        id: 'spot-price-usage',
        regex: /getReserves\(\).*\n.*reserve[01]\s*[\/\*]/gm,
        description: 'Using spot price from reserves (manipulable)',
        skillFile: 'patterns/oracle-antipatterns.md'
      },
      {
        id: 'missing-staleness-check',
        regex: /latestRoundData\(\)(?!.*updatedAt|.*staleness)/gm,
        description: 'Chainlink price without staleness check',
        skillFile: 'patterns/oracle-antipatterns.md'
      },
      {
        id: 'missing-price-validation',
        regex: /latestRoundData\(\)(?!.*require.*price\s*>)/gm,
        description: 'Missing price > 0 validation',
        skillFile: 'patterns/oracle-antipatterns.md'
      }
    ],
    attackTree: 'attack-trees/oracle-attack-tree.md'
  },

  // Access control patterns
  accessControl: {
    name: 'Access Control',
    severity: 'High',
    patterns: [
      {
        id: 'missing-access-control',
        regex: /function\s+(set\w+|update\w+|withdraw|admin|owner)\s*\([^)]*\)\s*external(?!\s+only)/gim,
        description: 'Sensitive function without access control',
        skillFile: 'patterns/access-control-antipatterns.md'
      },
      {
        id: 'tx-origin-auth',
        regex: /require\s*\(\s*tx\.origin\s*==/gm,
        description: 'Using tx.origin for authentication',
        skillFile: 'patterns/access-control-antipatterns.md'
      },
      {
        id: 'single-step-ownership',
        regex: /function\s+transferOwnership[^}]+owner\s*=\s*\w+[^}]*\}/gm,
        description: 'Single-step ownership transfer',
        skillFile: 'patterns/access-control-antipatterns.md'
      }
    ],
    attackTree: 'attack-trees/access-control-attack-tree.md'
  },

  // Integer overflow/underflow patterns
  arithmetic: {
    name: 'Arithmetic Issues',
    severity: 'Medium',
    patterns: [
      {
        id: 'unchecked-user-input',
        regex: /unchecked\s*\{[^}]*msg\.sender|unchecked\s*\{[^}]*_amount/gm,
        description: 'Unchecked arithmetic with user input',
        skillFile: 'patterns/solidity-antipatterns.md'
      },
      {
        id: 'division-before-multiplication',
        regex: /\/\s*\w+\s*\*\s*\w+/gm,
        description: 'Division before multiplication (precision loss)',
        skillFile: 'patterns/solidity-antipatterns.md'
      }
    ],
    attackTree: 'attack-trees/arithmetic-attack-tree.md'
  },

  // Flash loan patterns
  flashLoan: {
    name: 'Flash Loan Vulnerability',
    severity: 'High',
    patterns: [
      {
        id: 'single-block-price',
        regex: /block\.timestamp|block\.number(?!.*TWAP|.*twap|.*average)/gm,
        description: 'Single-block price check (flash loan vulnerable)',
        skillFile: 'patterns/flash-loan-patterns.md'
      },
      {
        id: 'balance-based-auth',
        regex: /balanceOf\([^)]+\)\s*>=?\s*\d+.*(?:vote|governance|proposal)/gim,
        description: 'Balance-based governance (flash loan attack vector)',
        skillFile: 'patterns/flash-loan-patterns.md'
      }
    ],
    attackTree: 'attack-trees/flash-loan-attack-tree.md'
  },

  // Unsafe external calls
  externalCalls: {
    name: 'Unsafe External Calls',
    severity: 'Medium',
    patterns: [
      {
        id: 'unchecked-transfer',
        regex: /\.transfer\([^)]+\)(?!\s*;?\s*(?:require|if|assert))/gm,
        description: 'Transfer without success check',
        skillFile: 'patterns/solidity-antipatterns.md'
      },
      {
        id: 'unchecked-call',
        regex: /\.call\{[^}]*\}\([^)]*\)(?!\s*;?\s*(?:require|if))/gm,
        description: 'Low-level call without success check',
        skillFile: 'patterns/solidity-antipatterns.md'
      },
      {
        id: 'unsafe-delegatecall',
        regex: /delegatecall\([^)]*(?:msg\.data|abi\.encode)/gm,
        description: 'Delegatecall with user-controlled data',
        skillFile: 'patterns/solidity-antipatterns.md'
      }
    ],
    attackTree: 'attack-trees/external-calls-attack-tree.md'
  },

  // Signature issues
  signatures: {
    name: 'Signature Issues',
    severity: 'High',
    patterns: [
      {
        id: 'missing-nonce',
        regex: /ecrecover\([^)]+\)(?!.*nonce)/gm,
        description: 'Signature verification without nonce',
        skillFile: 'patterns/signature-patterns.md'
      },
      {
        id: 'missing-deadline',
        regex: /permit\([^)]+\)(?!.*deadline|.*expiry)/gim,
        description: 'Permit without deadline check',
        skillFile: 'patterns/signature-patterns.md'
      }
    ],
    attackTree: 'attack-trees/signature-attack-tree.md'
  }
};

/**
 * Pattern Matcher class for vulnerability detection
 */
export class PatternMatcher {
  constructor(skillsDir = DEFAULT_SKILLS_DIR) {
    this.skillsDir = skillsDir;
    this.patterns = VULNERABILITY_PATTERNS;
    this.customPatterns = [];
  }

  /**
   * Match code against all vulnerability patterns
   * @param {string} code - Solidity source code
   * @returns {Array} Array of matched vulnerabilities
   */
  matchAll(code) {
    const matches = [];

    for (const [category, vuln] of Object.entries(this.patterns)) {
      for (const pattern of vuln.patterns) {
        const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
        let match;

        while ((match = regex.exec(code)) !== null) {
          matches.push({
            category,
            name: vuln.name,
            severity: vuln.severity,
            patternId: pattern.id,
            description: pattern.description,
            match: match[0],
            index: match.index,
            line: this._getLineNumber(code, match.index),
            skillFile: pattern.skillFile,
            attackTree: vuln.attackTree,
            recommendation: this._getRecommendation(pattern.id)
          });
        }
      }
    }

    // Sort by severity then line number
    const severityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3 };
    matches.sort((a, b) => {
      const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
      return sevDiff !== 0 ? sevDiff : a.line - b.line;
    });

    return matches;
  }

  /**
   * Match code against specific category
   * @param {string} code - Solidity source code
   * @param {string} category - Category name (e.g., 'reentrancy', 'oracle')
   * @returns {Array} Array of matched vulnerabilities
   */
  matchCategory(code, category) {
    if (!this.patterns[category]) {
      throw new Error(`Unknown category: ${category}`);
    }

    const vuln = this.patterns[category];
    const matches = [];

    for (const pattern of vuln.patterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match;

      while ((match = regex.exec(code)) !== null) {
        matches.push({
          category,
          name: vuln.name,
          severity: vuln.severity,
          patternId: pattern.id,
          description: pattern.description,
          match: match[0],
          index: match.index,
          line: this._getLineNumber(code, match.index),
          skillFile: pattern.skillFile,
          attackTree: vuln.attackTree
        });
      }
    }

    return matches;
  }

  /**
   * Add custom pattern
   * @param {Object} pattern - Pattern definition
   */
  addPattern(pattern) {
    this.customPatterns.push(pattern);
    
    if (!this.patterns[pattern.category]) {
      this.patterns[pattern.category] = {
        name: pattern.name,
        severity: pattern.severity,
        patterns: []
      };
    }
    
    this.patterns[pattern.category].patterns.push({
      id: pattern.id,
      regex: new RegExp(pattern.regex, pattern.flags || 'gm'),
      description: pattern.description,
      skillFile: pattern.skillFile || null
    });
  }

  /**
   * Load skill file content
   * @param {string} skillFile - Relative path to skill file
   * @returns {string|null} File content or null if not found
   */
  loadSkillFile(skillFile) {
    const fullPath = join(this.skillsDir, skillFile);
    
    if (existsSync(fullPath)) {
      return readFileSync(fullPath, 'utf-8');
    }
    
    return null;
  }

  /**
   * Get relevant skill files for detected vulnerabilities
   * @param {Array} matches - Array of matched vulnerabilities
   * @returns {Object} Map of skill file paths to content
   */
  getRelevantSkills(matches) {
    const skills = {};
    const seenFiles = new Set();

    for (const match of matches) {
      if (match.skillFile && !seenFiles.has(match.skillFile)) {
        seenFiles.add(match.skillFile);
        const content = this.loadSkillFile(match.skillFile);
        if (content) {
          skills[match.skillFile] = content;
        }
      }

      if (match.attackTree && !seenFiles.has(match.attackTree)) {
        seenFiles.add(match.attackTree);
        const content = this.loadSkillFile(match.attackTree);
        if (content) {
          skills[match.attackTree] = content;
        }
      }
    }

    return skills;
  }

  /**
   * Get line number from character index
   * @private
   */
  _getLineNumber(code, index) {
    return code.substring(0, index).split('\n').length;
  }

  /**
   * Get recommendation for pattern
   * @private
   */
  _getRecommendation(patternId) {
    const recommendations = {
      'external-call-before-state': 'Apply Checks-Effects-Interactions pattern and use ReentrancyGuard',
      'missing-reentrancy-guard': 'Add nonReentrant modifier from OpenZeppelin',
      'spot-price-usage': 'Use TWAP oracle with minimum 30-minute window',
      'missing-staleness-check': 'Add staleness check: require(block.timestamp - updatedAt <= HEARTBEAT)',
      'missing-access-control': 'Add appropriate access control modifier (onlyOwner, onlyRole)',
      'tx-origin-auth': 'Replace tx.origin with msg.sender',
      'single-step-ownership': 'Use Ownable2Step for two-step ownership transfer',
      'unchecked-user-input': 'Remove unchecked block or validate input bounds',
      'unchecked-transfer': 'Use SafeERC20.safeTransfer instead',
      'unchecked-call': 'Check return value: require(success, "Call failed")',
      'missing-nonce': 'Include nonce in signed message to prevent replay',
      'missing-deadline': 'Add deadline parameter and validation'
    };

    return recommendations[patternId] || 'Review skill file for detailed guidance';
  }

  /**
   * Get summary statistics
   * @param {Array} matches - Array of matched vulnerabilities
   * @returns {Object} Summary statistics
   */
  getSummary(matches) {
    const summary = {
      total: matches.length,
      bySeverity: { Critical: 0, High: 0, Medium: 0, Low: 0 },
      byCategory: {}
    };

    for (const match of matches) {
      summary.bySeverity[match.severity]++;
      summary.byCategory[match.category] = (summary.byCategory[match.category] || 0) + 1;
    }

    return summary;
  }
}

/**
 * Convenience function for quick pattern matching
 * @param {string} code - Solidity source code
 * @param {string} skillsDir - Path to skills directory
 * @returns {Object} Matches and relevant skills
 */
export function matchPatternToCode(code, skillsDir = DEFAULT_SKILLS_DIR) {
  const matcher = new PatternMatcher(skillsDir);
  const matches = matcher.matchAll(code);
  const skills = matcher.getRelevantSkills(matches);
  const summary = matcher.getSummary(matches);

  return {
    matches,
    skills,
    summary
  };
}

export default PatternMatcher;
