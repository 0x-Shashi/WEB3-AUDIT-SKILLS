/**
 * Generic Adapter — Platform-agnostic AI integration
 * 
 * Works with any AI assistant (ChatGPT, Copilot, Aider, local LLMs, etc.)
 * by outputting formatted markdown that can be copy-pasted or piped.
 * 
 * Also serves as the fallback/CLI adapter when no specific platform is detected.
 * 
 * @module generic-adapter
 */

import { BaseAdapter } from './base-adapter.js';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

export class GenericAdapter extends BaseAdapter {
  constructor(options = {}) {
    super('generic', options);
  }

  canExecuteTools() {
    return false;
  }

  getCapabilities() {
    return {
      ...super.getCapabilities(),
      platform: 'Any AI assistant (ChatGPT, Copilot, Aider, local LLMs, CLI)',
      configFile: null,
      outputMethod: 'markdown-output'
    };
  }

  getSystemPrompt() {
    return `# Web3 Smart Contract Security Auditor

You are a smart contract security auditor. You have access to vulnerability pattern files in the skills/ directory.

## Quick Reference

### Audit Workflow
1. **Protocol Mapping** — Understand the protocol (no bugs yet)
2. **Hypothesis Generation** — Generate 10-15 testable attack scenarios
3. **Code Path Exploration** — Validate hypotheses one at a time
4. **Adversarial Review** — Skeptically triage findings
5. **Finding Draft** — Format for report submission
6. **SCAN Modes** — Quick targeted scans (Paranoid, Access, Accounting, Low-Noise)

### Available CLI Commands
\`\`\`bash
npx web3-audit scan --all --project /path/to/project    # Run all static analysis tools
npx web3-audit scan --slither --project /path/to/project # Slither only
npx web3-audit scan --aderyn --project /path/to/project  # Aderyn only
npx web3-audit scan --compile --project /path/to/project # Compile project
npx web3-audit scan --test --project /path/to/project    # Run tests
npx web3-audit info                                       # Show capabilities
\`\`\`

### Severity Levels
- **CRITICAL**: Direct loss of funds, protocol insolvency
- **HIGH**: Significant damage, theft possible under conditions
- **MEDIUM**: Limited impact, edge case exploitation
- **LOW**: Minor issues, informational

### Key Files to Read
- \`skills/methodology/llm-audit-workflow.md\` — Full workflow playbook
- \`skills/ROUTE-MAP.md\` — Protocol type → skill file mapping
- \`skills/MASTER_CHECKLIST.md\` — Complete audit checklist
- \`skills/patterns/\` — 161 vulnerability pattern files
`;
  }

  getPhasePrompt(phase, context = {}) {
    const prompts = {
      'protocol-mapper': this._protocolMapper(context),
      'hypothesis-generator': this._hypothesisGenerator(context),
      'code-path-explorer': this._codePathExplorer(context),
      'adversarial-reviewer': this._adversarialReviewer(context),
      'finding-drafter': this._findingDrafter(context),
      'scan-paranoid': this._scanMode('paranoid', context),
      'scan-access': this._scanMode('access', context),
      'scan-accounting': this._scanMode('accounting', context),
      'scan-low-noise': this._scanMode('low-noise', context)
    };

    const prompt = prompts[phase];
    if (!prompt) {
      throw new Error(`Unknown phase: ${phase}. Available: ${Object.keys(prompts).join(', ')}`);
    }
    return prompt;
  }

  formatScanResults(results) {
    const sections = [];

    sections.push('# Static Analysis Results\n');
    sections.push('Copy the following into your AI conversation to provide scan context.\n');
    sections.push('---\n');

    if (results.slither?.forAI) {
      sections.push(results.slither.forAI);
      sections.push('');
    }
    if (results.aderyn?.forAI) {
      sections.push(results.aderyn.forAI);
      sections.push('');
    }
    if (results.mythril?.forAI) {
      sections.push(results.mythril.forAI);
      sections.push('');
    }
    if (results.framework) {
      sections.push('## Project Info');
      sections.push(`- Framework: ${results.framework.name}`);
      sections.push(`- Sources: ${results.framework.sourceCount} files`);
      sections.push(`- Tests: ${results.framework.testCount} files`);
      sections.push(`- Compiler: ${results.framework.compilerVersion}`);
      sections.push('');
    }

    sections.push('---');
    sections.push('Now analyze these results and cross-reference with the vulnerability patterns.');

    return sections.join('\n');
  }

  // ─── Phase Prompts ─────────────────────────────────────────

  _protocolMapper(ctx) {
    let prompt = `[ROLE: Protocol Mapper]

You are a senior Web3 security auditor. Analyze the provided smart contracts.

Your task is NOT to find bugs yet. Build a precise mental model:

1. Protocol Purpose — What problem does it solve?
2. Assets — What assets are at risk?
3. Trust Assumptions — External dependencies, privileged roles, upgradeability
4. Critical State Variables — Variables whose corruption leads to loss
5. Critical Flows — User flows and admin flows involving assets
6. Invariants — What must always be true?`;

    if (ctx.scanResults) {
      prompt += `\n\n## Automated Scan Results (for reference)\n${ctx.scanResults}`;
    }
    return prompt;
  }

  _hypothesisGenerator(ctx) {
    let prompt = `[ROLE: Attack Hypothesis Generator]

Generate 10-15 testable attack hypotheses. Focus on scenarios leading to:
- Loss of funds
- Protocol insolvency
- Irreversible accounting corruption

Each hypothesis must include:
- Threat model (who is the adversary, what can they do?)
- Attack idea (high-level description)
- Required conditions
- What to inspect in code
- Suggested test command (for the project's framework)`;

    if (ctx.protocol_map) {
      prompt += `\n\n## Protocol Map\n${ctx.protocol_map}`;
    }
    if (ctx.scanResults) {
      prompt += `\n\n## Scan Results\n${ctx.scanResults}`;
    }
    return prompt;
  }

  _codePathExplorer(ctx) {
    return `[ROLE: Code Path Explorer]

Validate this specific hypothesis:
${ctx.hypothesis || '{{paste hypothesis here}}'}

Rules:
- Trace execution paths step by step
- Identify edge cases and missing checks
- Analyze exactly ONE hypothesis — do not expand scope
- If valid, suggest a concrete PoC test to write
- If invalid, explain what prevents exploitation`;
  }

  _adversarialReviewer(ctx) {
    return `[ROLE: Adversarial Reviewer]

Review this finding with skeptical triage mindset:
${ctx.finding || '{{paste finding here}}'}

Default stance: skeptical. The finding must be justified by code.
- Verify claimed behavior against actual code
- List counterarguments
- What would block acceptance by a triager?
- If a PoC test exists, reference its results`;
  }

  _findingDrafter(ctx) {
    return `[ROLE: Finding Drafter]

Format this finding for report submission:
${ctx.finding || '{{paste finding here}}'}

Required format:
- **Severity:** CRITICAL / HIGH / MEDIUM / LOW
- **Category:** (e.g., reentrancy, oracle, access-control)
- **Summary:** 1-2 sentences
- **Impact:** What happens if exploited?
- **Vulnerable Code:** File:line reference
- **Attack Scenario:** Step by step
- **PoC:** Test file reference or command to run
- **Recommended Fix:** Corrected code`;
  }

  _scanMode(mode, ctx) {
    const modes = {
      'paranoid': `[SCAN: Paranoid Greedy]

First, run: npx web3-audit scan --all --project .

Then perform broad paranoid scan:
- Missing or weak checks
- Unusual state transitions
- Edge states (zero supply, init, shutdown)
- Cross-contract interactions
- Anything that "looks wrong"

Prefer false positives over false negatives.`,

      'access': `[SCAN: Access & Lifecycle]

First, run: npx web3-audit scan --all --project .

Focus on:
- Access control and permissions
- Initialization and configuration
- Admin / privileged actions
- Upgrade or migration paths
- Pause / emergency / shutdown logic`,

      'accounting': `[SCAN: Accounting & State]

First, run: npx web3-audit scan --all --project .

Focus on:
- Balance and supply updates
- Virtual vs real accounting
- Order of state updates (CEI pattern)
- Rounding and precision
- Reset / zero-state behavior`,

      'low-noise': `[SCAN: Low Noise High Quality]

First, run: npx web3-audit scan --slither --project . (priority detectors only)

Conservative review — subtle, non-obvious issues only:
- Implicit assumptions not enforced in code
- Edge-case state transitions
- Cross-module interactions
- Invariants relying on ordering/timing

Output 5-10 items max. No generic findings.`
    };

    return modes[mode] || modes['paranoid'];
  }
}

export default GenericAdapter;
