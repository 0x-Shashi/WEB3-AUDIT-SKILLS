/**
 * Pattern Matcher
 * 
 * Regex-based vulnerability pattern detection for Solidity and other languages.
 * Detects common security issues through code pattern analysis.
 * 
 * Usage:
 *   const matcher = new PatternMatcher();
 *   const findings = matcher.analyze(code, 'solidity');
 */

class PatternMatcher {
  constructor() {
    // Initialize pattern library
    this.patterns = this._initializePatterns();
  }

  /**
   * Initialize all vulnerability patterns
   * @private
   */
  _initializePatterns() {
    return {
      solidity: this._getSolidityPatterns(),
      rust: this._getRustPatterns(),
      move: this._getMovePatterns()
    };
  }

  /**
   * Solidity vulnerability patterns
   * @private
   */
  _getSolidityPatterns() {
    return [
      // ==================== Critical ====================
      {
        id: 'reentrancy-eth',
        name: 'Reentrancy with ETH Transfer',
        severity: 'CRITICAL',
        category: 'reentrancy',
        pattern: /\.call\{value:\s*[^}]+\}\s*\([^)]*\)[\s\S]{0,100}(?:balances|balance|amounts?)\s*\[/gi,
        description: 'External call with value before state update - classic reentrancy vulnerability',
        recommendation: 'Use checks-effects-interactions pattern or ReentrancyGuard'
      },
      {
        id: 'delegatecall-to-untrusted',
        name: 'Delegatecall to Untrusted Target',
        severity: 'CRITICAL',
        category: 'access-control',
        pattern: /\.delegatecall\s*\([^)]*(?:msg\.data|_data|data|calldata)/gi,
        description: 'Delegatecall with user-controlled target can lead to contract takeover',
        recommendation: 'Never delegatecall to untrusted addresses'
      },
      {
        id: 'selfdestruct-arbitrary',
        name: 'Unprotected Selfdestruct',
        severity: 'CRITICAL',
        category: 'access-control',
        pattern: /selfdestruct\s*\([^)]+\)/gi,
        negativePattern: /onlyOwner|require\s*\([^)]*owner|modifier\s+onlyAdmin/,
        description: 'Selfdestruct can be called, potentially by anyone',
        recommendation: 'Add access control or remove selfdestruct'
      },
      {
        id: 'arbitrary-send-eth',
        name: 'Arbitrary ETH Send',
        severity: 'CRITICAL',
        category: 'access-control',
        pattern: /(?:payable\s*\(\s*)?(?:msg\.sender|_to|to|recipient|receiver)\s*(?:\)|)\s*\.(?:call|transfer|send)\s*[{(]/gi,
        description: 'ETH can be sent to arbitrary address without proper validation',
        recommendation: 'Validate recipient addresses and implement access control'
      },

      // ==================== High ====================
      {
        id: 'tx-origin-auth',
        name: 'tx.origin Authentication',
        severity: 'HIGH',
        category: 'access-control',
        pattern: /require\s*\([^)]*tx\.origin|if\s*\([^)]*tx\.origin/gi,
        description: 'Using tx.origin for authentication is vulnerable to phishing attacks',
        recommendation: 'Use msg.sender instead of tx.origin'
      },
      {
        id: 'unchecked-call',
        name: 'Unchecked External Call',
        severity: 'HIGH',
        category: 'unchecked-return',
        pattern: /\.call\{[^}]*\}\s*\([^)]*\)\s*;/gi,
        negativePattern: /\(\s*bool\s+\w+\s*,|\(\s*success\s*,|require\s*\(/,
        description: 'Return value of external call is not checked',
        recommendation: 'Check the return value of call and handle failures'
      },
      {
        id: 'unsafe-erc20-transfer',
        name: 'Unsafe ERC20 Transfer',
        severity: 'HIGH',
        category: 'unchecked-return',
        pattern: /IERC20\s*\([^)]+\)\s*\.transfer\s*\([^)]+\)\s*;/gi,
        negativePattern: /require\s*\(|SafeERC20|safeTransfer/,
        description: 'ERC20 transfer return value not checked - some tokens dont revert',
        recommendation: 'Use SafeERC20 from OpenZeppelin'
      },
      {
        id: 'block-timestamp-manipulation',
        name: 'Block Timestamp Dependence',
        severity: 'HIGH',
        category: 'timestamp',
        pattern: /block\.timestamp\s*[<>=!]+\s*\d+|require\s*\([^)]*block\.timestamp/gi,
        description: 'Miners can manipulate block.timestamp within ~15 second window',
        recommendation: 'Avoid precise timestamp comparisons for critical logic'
      },
      {
        id: 'integer-overflow-unchecked',
        name: 'Unchecked Arithmetic',
        severity: 'HIGH',
        category: 'arithmetic',
        pattern: /unchecked\s*\{[\s\S]*?[+\-*/][\s\S]*?\}/gi,
        description: 'Unchecked block can cause overflow/underflow',
        recommendation: 'Ensure arithmetic operations cannot overflow'
      },
      {
        id: 'missing-zero-check',
        name: 'Missing Zero Address Check',
        severity: 'HIGH',
        category: 'validation',
        pattern: /(?:owner|admin|token|receiver|recipient)\s*=\s*_?\w+\s*;/gi,
        negativePattern: /require\s*\([^)]*!=\s*address\s*\(\s*0\s*\)|address\s*\(\s*0\s*\)\s*!=|_\w+\s*!=\s*address\s*\(0\)/,
        description: 'Critical address assigned without zero address check',
        recommendation: 'Add require(address != address(0)) check'
      },

      // ==================== Medium ====================
      {
        id: 'reentrancy-no-eth',
        name: 'Reentrancy (No ETH)',
        severity: 'MEDIUM',
        category: 'reentrancy',
        pattern: /\.call\s*\([^)]*\)[\s\S]{0,100}(?:balances|amounts?|state)\s*\[/gi,
        description: 'External call before state update - potential reentrancy',
        recommendation: 'Use checks-effects-interactions pattern'
      },
      {
        id: 'front-running-vulnerable',
        name: 'Front-Running Vulnerability',
        severity: 'MEDIUM',
        category: 'front-running',
        pattern: /(?:swap|trade|buy|sell|bid|auction)\s*\([^)]*\)\s*(?:external|public)/gi,
        description: 'Function may be vulnerable to front-running/sandwich attacks',
        recommendation: 'Implement slippage protection or commit-reveal schemes'
      },
      {
        id: 'oracle-manipulation',
        name: 'Oracle Price Manipulation Risk',
        severity: 'MEDIUM',
        category: 'oracle',
        pattern: /getReserves|getAmountOut|getPrice|latestRoundData|spot.*price/gi,
        description: 'Single-block oracle query may be manipulable via flash loans',
        recommendation: 'Use TWAP oracles or Chainlink with proper validation'
      },
      {
        id: 'flashloan-callback',
        name: 'Flash Loan Callback',
        severity: 'MEDIUM',
        category: 'flash-loan',
        pattern: /(?:executeOperation|onFlashLoan|flashLoanCallback|uniswapV\d+Call)/gi,
        description: 'Flash loan callback detected - ensure proper validation',
        recommendation: 'Validate caller is the expected pool/lender'
      },
      {
        id: 'centralization-risk',
        name: 'Centralization Risk',
        severity: 'MEDIUM',
        category: 'centralization',
        pattern: /onlyOwner|onlyAdmin|onlyRole|hasRole\s*\([^)]*ADMIN/gi,
        description: 'Admin-controlled functions create centralization risk',
        recommendation: 'Consider timelocks, multisig, or DAO governance'
      },
      {
        id: 'approve-race-condition',
        name: 'ERC20 Approve Race Condition',
        severity: 'MEDIUM',
        category: 'race-condition',
        pattern: /function\s+approve\s*\([^)]*uint256/gi,
        negativePattern: /increaseAllowance|decreaseAllowance/,
        description: 'Standard approve is vulnerable to race condition',
        recommendation: 'Use increaseAllowance/decreaseAllowance pattern'
      },

      // ==================== Low ====================
      {
        id: 'missing-event-emission',
        name: 'Missing Event Emission',
        severity: 'LOW',
        category: 'best-practice',
        pattern: /function\s+set\w+\s*\([^)]*\)\s*(?:external|public)[^{]*\{[^}]*(?:=\s*_?\w+)[^}]*\}/gi,
        negativePattern: /emit\s+\w+/,
        description: 'State-changing function does not emit an event',
        recommendation: 'Emit events for important state changes'
      },
      {
        id: 'public-variable-shadowing',
        name: 'Variable Shadowing',
        severity: 'LOW',
        category: 'code-quality',
        pattern: /function\s+\w+\s*\([^)]*(?:address|uint256|bytes32)\s+(\w+)/gi,
        description: 'Function parameter may shadow state variable',
        recommendation: 'Use different names for parameters and state variables'
      },
      {
        id: 'floating-pragma',
        name: 'Floating Pragma',
        severity: 'LOW',
        category: 'best-practice',
        pattern: /pragma\s+solidity\s*\^/gi,
        description: 'Floating pragma allows compilation with different versions',
        recommendation: 'Lock the pragma version (e.g., pragma solidity 0.8.20)'
      },
      {
        id: 'outdated-solidity',
        name: 'Outdated Solidity Version',
        severity: 'LOW',
        category: 'best-practice',
        pattern: /pragma\s+solidity\s*(?:\^|>=|=)?\s*0\.[0-7]\./gi,
        description: 'Using outdated Solidity version with known issues',
        recommendation: 'Upgrade to Solidity 0.8.x or later'
      },
      {
        id: 'magic-numbers',
        name: 'Magic Numbers',
        severity: 'LOW',
        category: 'code-quality',
        pattern: /(?:require|if|while|for)\s*\([^)]*(?<![0-9])[1-9]\d{2,}(?![0-9])/gi,
        description: 'Hardcoded numeric values reduce code readability',
        recommendation: 'Define constants with descriptive names'
      },

      // ==================== Gas ====================
      {
        id: 'gas-storage-loop',
        name: 'Storage Read in Loop',
        severity: 'GAS',
        category: 'gas-optimization',
        pattern: /for\s*\([^)]+\)\s*\{[\s\S]*?(?:storage|\.length)[^}]*\}/gi,
        description: 'Reading from storage in a loop is expensive',
        recommendation: 'Cache storage values in memory before loops'
      },
      {
        id: 'gas-string-error',
        name: 'Long Revert Strings',
        severity: 'GAS',
        category: 'gas-optimization',
        pattern: /require\s*\([^,]+,\s*"[^"]{33,}"\s*\)/gi,
        description: 'Long revert strings increase deployment and runtime cost',
        recommendation: 'Use custom errors or shorter messages'
      },
      {
        id: 'gas-public-to-external',
        name: 'Public Function Could Be External',
        severity: 'GAS',
        category: 'gas-optimization',
        pattern: /function\s+\w+\s*\([^)]*\)\s*public\s+(?!view|pure)/gi,
        description: 'Public functions cost more than external for large inputs',
        recommendation: 'Use external for functions only called from outside'
      }
    ];
  }

  /**
   * Rust/Solana vulnerability patterns
   * @private
   */
  _getRustPatterns() {
    return [
      {
        id: 'missing-signer-check',
        name: 'Missing Signer Check',
        severity: 'CRITICAL',
        category: 'access-control',
        pattern: /AccountInfo[^;]*(?!.*is_signer)/gi,
        description: 'Account used without verifying it signed the transaction',
        recommendation: 'Add signer check: require!(account.is_signer)'
      },
      {
        id: 'missing-owner-check',
        name: 'Missing Owner Check',
        severity: 'HIGH',
        category: 'access-control',
        pattern: /Account<'info,\s*\w+>(?!.*constraint\s*=.*owner)/gi,
        description: 'Account ownership not verified',
        recommendation: 'Add owner constraint in account validation'
      },
      {
        id: 'arbitrary-cpi',
        name: 'Arbitrary CPI',
        severity: 'CRITICAL',
        category: 'access-control',
        pattern: /invoke(?:_signed)?\s*\(\s*&[\s\S]*?program_id/gi,
        description: 'Cross-program invocation with potentially arbitrary program',
        recommendation: 'Validate program ID before CPI calls'
      },
      {
        id: 'integer-overflow-rust',
        name: 'Potential Integer Overflow',
        severity: 'MEDIUM',
        category: 'arithmetic',
        pattern: /\.checked_(?:add|sub|mul|div)\s*\([^)]+\)\s*\.unwrap\(\)/gi,
        description: 'Checked math with unwrap can panic',
        recommendation: 'Handle None case properly instead of unwrap'
      },
      {
        id: 'pda-validation',
        name: 'Missing PDA Validation',
        severity: 'HIGH',
        category: 'validation',
        pattern: /find_program_address|create_program_address/gi,
        negativePattern: /bump|seeds/,
        description: 'PDA derivation without proper seed validation',
        recommendation: 'Store and validate bump seeds'
      }
    ];
  }

  /**
   * Move vulnerability patterns
   * @private
   */
  _getMovePatterns() {
    return [
      {
        id: 'missing-capability-check',
        name: 'Missing Capability Check',
        severity: 'CRITICAL',
        category: 'access-control',
        pattern: /public\s+entry\s+fun\s+\w+[^{]*\{(?![\s\S]*?assert!)/gi,
        description: 'Entry function without capability/permission check',
        recommendation: 'Add capability check with assert!'
      },
      {
        id: 'unsafe-abort',
        name: 'Missing Abort Code',
        severity: 'LOW',
        category: 'best-practice',
        pattern: /abort\s*$/gim,
        description: 'Abort without error code makes debugging difficult',
        recommendation: 'Use abort with specific error codes'
      },
      {
        id: 'resource-leak',
        name: 'Potential Resource Leak',
        severity: 'MEDIUM',
        category: 'resource-safety',
        pattern: /move_from<[^>]+>\s*\([^)]+\)/gi,
        negativePattern: /move_to|drop/,
        description: 'Resource extracted but may not be properly handled',
        recommendation: 'Ensure all extracted resources are moved or dropped'
      }
    ];
  }

  /**
   * Analyze code for vulnerability patterns
   * 
   * @param {string} code - Source code to analyze
   * @param {string} language - Programming language (solidity, rust, move)
   * @param {Object} options - Analysis options
   * @returns {Array} Array of findings
   */
  analyze(code, language = 'solidity', options = {}) {
    const patterns = this.patterns[language] || this.patterns.solidity;
    const findings = [];

    for (const pattern of patterns) {
      // Skip if severity filter doesn't match
      if (options.severity && !options.severity.includes(pattern.severity)) {
        continue;
      }

      // Skip if category filter doesn't match
      if (options.category && pattern.category !== options.category) {
        continue;
      }

      const matches = this._findMatches(code, pattern);
      
      for (const match of matches) {
        findings.push({
          id: pattern.id,
          name: pattern.name,
          severity: pattern.severity,
          category: pattern.category,
          description: pattern.description,
          recommendation: pattern.recommendation,
          location: match.location,
          line: match.line,
          column: match.column,
          snippet: match.snippet,
          confidence: match.confidence
        });
      }
    }

    // Sort by severity
    const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, GAS: 4, INFO: 5 };
    findings.sort((a, b) => 
      (severityOrder[a.severity] || 99) - (severityOrder[b.severity] || 99)
    );

    return findings;
  }

  /**
   * Find pattern matches in code
   * @private
   */
  _findMatches(code, pattern) {
    const matches = [];
    const lines = code.split('\n');
    
    let match;
    const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
    
    while ((match = regex.exec(code)) !== null) {
      // Check negative pattern (false positive reduction)
      if (pattern.negativePattern) {
        const context = code.slice(
          Math.max(0, match.index - 200),
          Math.min(code.length, match.index + match[0].length + 200)
        );
        if (pattern.negativePattern.test(context)) {
          continue; // Skip this match
        }
      }

      // Calculate line number
      const beforeMatch = code.slice(0, match.index);
      const lineNumber = (beforeMatch.match(/\n/g) || []).length + 1;
      const lineStart = beforeMatch.lastIndexOf('\n') + 1;
      const column = match.index - lineStart + 1;

      // Extract snippet (3 lines of context)
      const startLine = Math.max(0, lineNumber - 2);
      const endLine = Math.min(lines.length, lineNumber + 2);
      const snippet = lines.slice(startLine, endLine).join('\n');

      // Calculate confidence based on context
      const confidence = this._calculateConfidence(code, match, pattern);

      matches.push({
        location: match.index,
        line: lineNumber,
        column,
        snippet,
        matchedText: match[0],
        confidence
      });
    }

    return matches;
  }

  /**
   * Calculate confidence score for a match
   * @private
   */
  _calculateConfidence(code, match, pattern) {
    let confidence = 0.7; // Base confidence

    // Boost if in function body
    const beforeMatch = code.slice(Math.max(0, match.index - 500), match.index);
    if (/function\s+\w+/.test(beforeMatch)) {
      confidence += 0.1;
    }

    // Reduce if in comment
    const lineStart = code.lastIndexOf('\n', match.index) + 1;
    const lineContent = code.slice(lineStart, match.index);
    if (lineContent.includes('//') || lineContent.includes('/*')) {
      confidence -= 0.5;
    }

    // Reduce if in string
    if (/["'`]/.test(code.charAt(match.index - 1))) {
      confidence -= 0.4;
    }

    // High severity patterns get slight boost
    if (pattern.severity === 'CRITICAL' || pattern.severity === 'HIGH') {
      confidence += 0.05;
    }

    return Math.max(0, Math.min(1, confidence));
  }

  /**
   * Analyze a file
   * 
   * @param {string} filePath - Path to file
   * @param {Object} options - Analysis options
   * @returns {Object} Analysis results
   */
  analyzeFile(filePath, options = {}) {
    const fs = require('fs');
    const path = require('path');

    if (!fs.existsSync(filePath)) {
      return { success: false, error: `File not found: ${filePath}` };
    }

    const code = fs.readFileSync(filePath, 'utf-8');
    const ext = path.extname(filePath);
    
    let language = 'solidity';
    if (ext === '.rs') language = 'rust';
    if (ext === '.move') language = 'move';

    const findings = this.analyze(code, language, options);

    return {
      success: true,
      file: filePath,
      language,
      findings,
      summary: this._getSummary(findings)
    };
  }

  /**
   * Get findings summary
   * @private
   */
  _getSummary(findings) {
    return {
      total: findings.length,
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low: findings.filter(f => f.severity === 'LOW').length,
      gas: findings.filter(f => f.severity === 'GAS').length
    };
  }

  /**
   * Get all available patterns
   * 
   * @param {string} language - Language filter
   * @returns {Array} Pattern definitions
   */
  getPatterns(language = null) {
    if (language) {
      return this.patterns[language] || [];
    }
    return Object.entries(this.patterns).flatMap(([lang, patterns]) =>
      patterns.map(p => ({ ...p, language: lang }))
    );
  }

  /**
   * Add custom pattern
   * 
   * @param {string} language - Target language
   * @param {Object} pattern - Pattern definition
   */
  addPattern(language, pattern) {
    if (!this.patterns[language]) {
      this.patterns[language] = [];
    }
    this.patterns[language].push(pattern);
  }
}

module.exports = PatternMatcher;
