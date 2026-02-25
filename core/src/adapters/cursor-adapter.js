/**
 * Cursor Adapter — .cursorrules-based integration for Cursor IDE
 * 
 * Cannot execute tools directly; instead generates .cursorrules
 * and formats prompts for Cursor's AI chat.
 * 
 * @module cursor-adapter
 */

import { BaseAdapter } from './base-adapter.js';
import { readFileSync, existsSync, writeFileSync } from 'fs';
import { join } from 'path';

export class CursorAdapter extends BaseAdapter {
  constructor(options = {}) {
    super('cursor', options);
  }

  canExecuteTools() {
    return false; // Cursor can run terminal commands but not MCP tools
  }

  getCapabilities() {
    return {
      ...super.getCapabilities(),
      supportsMCP: false,
      platform: 'Cursor IDE',
      configFile: '.cursorrules',
      outputMethod: 'prompt-copy'
    };
  }

  getSystemPrompt() {
    return `# Web3 Audit Skills — Cursor Rules

You are a smart contract security auditor with access to a knowledge base of 50,530 real vulnerability findings from professional audits.

## Skills Location
All security knowledge is in the \`skills/\` folder. Read the relevant pattern files before auditing.

## Workflow
Follow the 6-phase audit workflow in \`skills/methodology/llm-audit-workflow.md\`.

## Running Tools
You can run these commands in the integrated terminal:

### Static Analysis
\`\`\`bash
# Run Slither
npx web3-audit scan --slither --project /path/to/project

# Run Aderyn  
npx web3-audit scan --aderyn --project /path/to/project

# Run all tools
npx web3-audit scan --all --project /path/to/project
\`\`\`

### Testing (auto-detects Foundry/Hardhat)
\`\`\`bash
# Compile
npx web3-audit scan --compile --project /path/to/project

# Run tests
npx web3-audit scan --test --project /path/to/project

# Run specific PoC test
npx web3-audit scan --test-file test/Exploit.t.sol --project /path/to/project
\`\`\`

### Pattern Matching
\`\`\`bash
# Scan a file for vulnerability patterns
npx web3-audit scan --patterns --file src/Vault.sol
\`\`\`

## Severity Levels
| Severity | Criteria |
|----------|----------|
| CRITICAL | Direct loss of funds, protocol insolvency |
| HIGH | Significant damage, theft possible under conditions |
| MEDIUM | Limited impact, edge case exploitation |
| LOW | Minor issues, informational |

## Key Pattern Files
Read these based on protocol type:
- DeFi: \`skills/patterns/defi-vulnerabilities.md\`, \`skills/patterns/oracle-patterns.md\`
- Vault: \`skills/patterns/vault-patterns.md\`, \`skills/patterns/erc4626-patterns.md\`
- Token: \`skills/patterns/erc20-patterns.md\`, \`skills/patterns/weird-erc20-patterns.md\`
- NFT: \`skills/patterns/erc721-patterns.md\`, \`skills/patterns/nft-patterns.md\`
`;
  }

  getPhasePrompt(phase, context = {}) {
    // For Cursor, wrap the prompt with a terminal command suggestion
    const basePrompt = this._getBasePrompt(phase, context);
    
    return `${basePrompt}

---
**To run automated scans, execute in terminal:**
\`\`\`bash
npx web3-audit scan --all --project .
\`\`\`
Then paste the results back here for analysis.`;
  }

  formatScanResults(results) {
    // Same as base format — Cursor uses markdown
    const sections = ['# Scan Results\n'];

    if (results.slither?.forAI) sections.push(results.slither.forAI);
    if (results.aderyn?.forAI) sections.push(results.aderyn.forAI);
    if (results.mythril?.forAI) sections.push(results.mythril.forAI);

    sections.push('\nPaste these results into Cursor chat for AI-assisted analysis.');
    return sections.join('\n\n');
  }

  /**
   * Generate .cursorrules file for the user's project
   * @param {string} projectDir - Target project directory
   */
  generateRulesFile(projectDir) {
    const rules = this.getSystemPrompt();
    const rulesPath = join(projectDir, '.cursorrules');
    writeFileSync(rulesPath, rules);
    return rulesPath;
  }

  _getBasePrompt(phase, context) {
    const prompts = {
      'protocol-mapper': 'Analyze the smart contracts in this project. Build a protocol map: Purpose, Assets, Trust Assumptions, Critical State Variables, Critical Flows, Invariants. Do NOT look for bugs yet.',
      'hypothesis-generator': 'Based on the protocol understanding, generate 10-15 testable attack hypotheses. Each must be neutral, testable, and grounded in the design.',
      'code-path-explorer': `Validate this hypothesis: ${context.hypothesis || '[paste hypothesis]'}. Trace execution paths and identify edge cases.`,
      'adversarial-reviewer': `Review this finding skeptically: ${context.finding || '[paste finding]'}. Default stance: skeptical.`,
      'finding-drafter': `Format this finding for submission: ${context.finding || '[paste finding]'}. Include Severity, Impact, Vulnerable Code, Attack Scenario, Fix.`,
      'scan-paranoid': 'Perform a broad paranoid scan. List anything suspicious, fragile, or inconsistent. Prefer false positives.',
      'scan-access': 'Focused scan on access control, initialization, admin actions, upgrade paths, pause/emergency logic.',
      'scan-accounting': 'Focused scan on accounting: balance updates, virtual vs real, state ordering, rounding, precision.',
      'scan-low-noise': 'Conservative scan — subtle, non-obvious issues only. 5-10 items max.'
    };
    return prompts[phase] || `Unknown phase: ${phase}`;
  }
}

export default CursorAdapter;
