/**
 * Claude Code Adapter — MCP-native integration for Claude Code
 * 
 * Uses the MCP server for direct tool execution.
 * Formats prompts and results for Claude's conversation model.
 * 
 * @module claude-adapter
 */

import { BaseAdapter } from './base-adapter.js';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

export class ClaudeCodeAdapter extends BaseAdapter {
  constructor(options = {}) {
    super('claude-code', options);
  }

  async initialize(context) {
    await super.initialize(context);
    
    // Load AI instructions
    const aiInstructionsPath = join(this.rootDir, 'AI-INSTRUCTIONS.md');
    if (existsSync(aiInstructionsPath)) {
      this.aiInstructions = readFileSync(aiInstructionsPath, 'utf-8');
    }
  }

  canExecuteTools() {
    return true; // MCP server integration
  }

  getCapabilities() {
    return {
      ...super.getCapabilities(),
      supportsMCP: true,
      supportsStreaming: true,
      platform: 'Claude Code / Claude Desktop',
      configFile: 'claude-code/plugin.json'
    };
  }

  getSystemPrompt() {
    return this.aiInstructions || this._getDefaultSystemPrompt();
  }

  getPhasePrompt(phase, context = {}) {
    const prompts = this._getPhasePrompts();
    const template = prompts[phase];
    
    if (!template) {
      throw new Error(`Unknown phase: ${phase}. Available: ${Object.keys(prompts).join(', ')}`);
    }

    // Inject context variables
    let prompt = template;
    for (const [key, value] of Object.entries(context)) {
      prompt = prompt.replace(new RegExp(`\\{\\{${key}\\}\\}`, 'g'), value);
    }

    return prompt;
  }

  formatScanResults(results) {
    const sections = [];

    sections.push('# Automated Scan Results\n');
    sections.push('The following static analysis tools were run against the target project.\n');
    sections.push('Use these results to accelerate your manual review — prioritize High/Critical findings.\n');

    if (results.slither) {
      sections.push('---\n');
      sections.push(results.slither.forAI || '## Slither: No results');
    }

    if (results.aderyn) {
      sections.push('---\n');
      sections.push(results.aderyn.forAI || '## Aderyn: No results');
    }

    if (results.mythril) {
      sections.push('---\n');
      sections.push(results.mythril.forAI || '## Mythril: No results');
    }

    if (results.framework) {
      sections.push('---\n');
      sections.push('## Project Framework\n');
      sections.push(`- **Framework:** ${results.framework.name}`);
      sections.push(`- **Source files:** ${results.framework.sourceCount}`);
      sections.push(`- **Test files:** ${results.framework.testCount}`);
      sections.push(`- **Compiler:** ${results.framework.compilerVersion}`);
    }

    sections.push('\n---\n');
    sections.push('## Next Steps\n');
    sections.push('1. Review High-severity findings from Slither/Aderyn first');
    sections.push('2. Cross-reference with `skills/patterns/` for deeper context');
    sections.push('3. Generate attack hypotheses using Phase 2 of the audit workflow');
    sections.push('4. Write PoC tests for confirmed vulnerabilities using the detected framework');

    return sections.join('\n');
  }

  getMCPConfig() {
    return {
      mcpServers: {
        'web3-audit': {
          command: 'node',
          args: [join(this.rootDir, 'core/src/mcp-server.js')]
        }
      }
    };
  }

  // ─── Internal ───────────────────────────────────────────────

  _getDefaultSystemPrompt() {
    return `You are a smart contract security auditor with access to a knowledge base of 50,530 real vulnerability findings.

Your tools:
- match_vulnerabilities: Scan Solidity code for known patterns
- calculate_severity: Score vulnerability severity
- classify_vulnerability: Categorize findings with CWE/SWC mappings
- search_patterns: Search the vulnerability pattern database
- get_attack_tree: Get systematic attack exploration guides
- get_protocol_playbook: Get protocol-specific audit playbooks
- run_slither: Run Slither static analysis
- run_aderyn: Run Aderyn static analysis
- run_tests: Execute Foundry/Hardhat tests
- run_test_file: Run a specific PoC test file

Follow the 6-phase audit workflow in skills/methodology/llm-audit-workflow.md.`;
  }

  _getPhasePrompts() {
    return {
      'protocol-mapper': `[ROLE: Protocol Mapper]

You are a senior Web3 security auditor. Analyze the provided smart contracts and documentation.

Your task is NOT to find bugs yet. Build a precise mental model of the protocol.

{{contracts}}

Output: Protocol Purpose, Assets, Trust Assumptions, Critical State Variables, Critical Flows, Invariants.

After mapping, run the automated scan tools to gather static analysis data.`,

      'hypothesis-generator': `[ROLE: Attack Hypothesis Generator]

Based on the protocol map and scan results below, generate 10-15 testable attack hypotheses.

{{protocol_map}}
{{scan_results}}

Focus on: loss of funds, protocol insolvency, irreversible accounting corruption.
Each hypothesis must be neutral, testable, and grounded in the protocol design.

For each hypothesis, suggest which Foundry/Hardhat test to write to validate it.`,

      'code-path-explorer': `[ROLE: Code Path Explorer]

Validate this specific hypothesis against the code:

{{hypothesis}}

Trace execution paths. Identify edge cases. Check for missing validations.
If the hypothesis is valid, draft a PoC test using the project's test framework.

Use run_test_file to execute the PoC if you write one.`,

      'adversarial-reviewer': `[ROLE: Adversarial Reviewer]

Review this finding with skeptical triage mindset:

{{finding}}

Default stance: skeptical. Verify claimed behavior against actual code.
If the PoC test passed, reference the test results.
If no PoC exists, flag that as a gap.`,

      'finding-drafter': `[ROLE: Finding Drafter]

Format this validated finding for report submission:

{{finding}}
{{poc_results}}

Include: Severity, Category, Summary, Impact, Vulnerable Code, Attack Scenario, PoC reference, Recommended Fix.`,

      'scan-paranoid': `[SCAN: Paranoid Greedy]

Run automated scans first, then perform broad manual review.

Step 1: Run Slither (use run_slither tool)
Step 2: Run Aderyn if available (use run_aderyn tool)
Step 3: Review scan results
Step 4: List anything suspicious, fragile, non-obvious, or inconsistent

Prefer false positives over false negatives.`,

      'scan-access': `[SCAN: Access & Lifecycle]

Step 1: Run static analysis tools
Step 2: Focus scan on access control, initialization, admin/privileged actions, upgrade paths, pause/emergency logic.

Do NOT assume correct usage or trusted actors.`,

      'scan-accounting': `[SCAN: Accounting & State]

Step 1: Run static analysis tools
Step 2: Focus on balance/supply updates, virtual vs real accounting, order of state updates, rounding, precision, zero-state behavior.`,

      'scan-low-noise': `[SCAN: Low Noise High Quality]

Step 1: Run static analysis tools (priority detectors only)
Step 2: Conservative review — identify subtle, non-obvious issues only.
Output a short, curated list (5-10 items max). Avoid generic findings.`
    };
  }
}

export default ClaudeCodeAdapter;
