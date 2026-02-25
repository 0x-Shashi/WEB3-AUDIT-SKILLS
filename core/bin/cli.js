#!/usr/bin/env node
/**
 * Web3 Audit Skills - CLI
 * 
 * Provides automated setup, validation, and info commands.
 * 
 * Usage:
 *   npx web3-audit setup      # Initialize and validate installation
 *   npx web3-audit verify     # Verify everything works correctly
 *   npx web3-audit info       # Show plugin capabilities and stats
 *   npx web3-audit doctor     # Diagnose issues
 */

import { dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';
import { SetupValidator } from '../src/utils/setup-validator.js';
import { PluginLoader } from '../src/utils/plugin-loader.js';
import { ProjectDetector } from '../src/utils/project-detector.js';
import { ToolRunner } from '../src/tools/tool-runner.js';
import { SlitherRunner } from '../src/tools/slither-runner.js';
import { AderynRunner } from '../src/tools/aderyn-runner.js';
import { createAdapter, listAdapters } from '../src/adapters/index.js';
import { ReferenceValidator } from '../src/utils/reference-validator.js';
import { TriggerEngine } from '../src/intelligence/trigger-engine.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = join(__dirname, '../..');
const SKILLS_DIR = join(ROOT_DIR, 'skills');
const PLUGIN_JSON = join(ROOT_DIR, 'claude-code/plugin.json');

// ─── ANSI Colors ───────────────────────────────────────────────
const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgGreen: '\x1b[42m',
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
};

const PASS = `${c.green}✔${c.reset}`;
const FAIL = `${c.red}✘${c.reset}`;
const WARN = `${c.yellow}⚠${c.reset}`;
const INFO = `${c.blue}ℹ${c.reset}`;
const BULLET = `${c.dim}·${c.reset}`;

// ─── CLI Entry Point ───────────────────────────────────────────
const args = process.argv.slice(2);
const command = args[0] || 'help';
const flags = new Set(args.slice(1));

try {
  switch (command) {
    case 'setup':
      await runSetup();
      break;
    case 'verify':
    case 'test':
      await runVerify();
      break;
    case 'info':
      await runInfo();
      break;
    case 'doctor':
      await runDoctor();
      break;
    case 'scan':
      await runScan();
      break;
    case 'adapters':
      showAdapters();
      break;
    case 'check-refs':
      await runCheckRefs();
      break;
    case 'triggers':
      await runTriggers();
      break;
    case 'help':
    case '--help':
    case '-h':
      printHelp();
      break;
    case '--version':
    case '-v':
      await printVersion();
      break;
    default:
      console.error(`${FAIL} Unknown command: ${command}\n`);
      printHelp();
      process.exit(1);
  }
} catch (err) {
  console.error(`\n${FAIL} Fatal error: ${err.message}`);
  if (flags.has('--verbose')) {
    console.error(err.stack);
  }
  process.exit(1);
}

// ─── Commands ──────────────────────────────────────────────────

/**
 * Setup: validate environment + plugin + skills in one shot
 */
async function runSetup() {
  const silent = flags.has('--silent');
  
  if (!silent) {
    console.log(`\n${c.bold}${c.cyan}┌─────────────────────────────────────────────┐${c.reset}`);
    console.log(`${c.bold}${c.cyan}│      Web3 Audit Skills — Setup              │${c.reset}`);
    console.log(`${c.bold}${c.cyan}└─────────────────────────────────────────────┘${c.reset}\n`);
  }

  const validator = new SetupValidator(ROOT_DIR, SKILLS_DIR, PLUGIN_JSON);
  const results = await validator.runAll();

  if (!silent) {
    printValidationResults(results);
  }

  if (results.passed) {
    if (!silent) {
      console.log(`\n${c.bgGreen}${c.white}${c.bold} SETUP COMPLETE ${c.reset}`);
      console.log(`\n  Next steps:`);
      console.log(`  ${BULLET} Start MCP server:   ${c.cyan}npm start${c.reset}`);
      console.log(`  ${BULLET} Run verification:   ${c.cyan}npm run verify${c.reset}`);
      console.log(`  ${BULLET} Show capabilities:  ${c.cyan}npm run info${c.reset}\n`);
    }
    process.exit(0);
  } else {
    if (!silent) {
      console.log(`\n${c.bgRed}${c.white}${c.bold} SETUP FAILED ${c.reset}`);
      console.log(`  Run ${c.cyan}npx web3-audit doctor${c.reset} for detailed diagnostics.\n`);
    }
    process.exit(1);
  }
}

/**
 * Verify: strict validation that installation works end-to-end
 */
async function runVerify() {
  console.log(`\n${c.bold}Verifying Web3 Audit Skills installation...${c.reset}\n`);

  const validator = new SetupValidator(ROOT_DIR, SKILLS_DIR, PLUGIN_JSON);
  const results = await validator.runAll();

  printValidationResults(results);

  // Run a live pattern-match test
  console.log(`\n${c.bold}Running live pattern-matching test...${c.reset}\n`);

  try {
    const { PatternMatcher } = await import('../src/intelligence/pattern-matcher.js');
    const matcher = new PatternMatcher(SKILLS_DIR);

    // Test with known-vulnerable code
    const testCode = `
      function withdraw(uint amount) external {
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
      }
    `;
    const matches = matcher.matchAll(testCode);

    if (matches.length > 0) {
      console.log(`  ${PASS} Pattern matcher found ${c.bold}${matches.length}${c.reset} vulnerabilities in test code`);
      for (const m of matches) {
        console.log(`    ${BULLET} [${m.severity}] ${m.description}`);
      }
    } else {
      console.log(`  ${WARN} Pattern matcher returned 0 matches — patterns may need review`);
    }
  } catch (err) {
    console.log(`  ${FAIL} Pattern matcher failed: ${err.message}`);
  }

  // Final verdict
  const strict = flags.has('--strict');
  if (results.passed && results.warnings === 0) {
    console.log(`\n${c.bgGreen}${c.white}${c.bold} ALL CHECKS PASSED ${c.reset}\n`);
    process.exit(0);
  } else if (results.passed && !strict) {
    console.log(`\n${c.bgYellow}${c.white}${c.bold} PASSED WITH WARNINGS ${c.reset}\n`);
    process.exit(0);
  } else {
    console.log(`\n${c.bgRed}${c.white}${c.bold} VERIFICATION FAILED ${c.reset}\n`);
    process.exit(1);
  }
}

/**
 * Info: display plugin capabilities, stats, and chain support
 */
async function runInfo() {
  console.log(`\n${c.bold}${c.cyan}Web3 Audit Skills — Plugin Info${c.reset}\n`);

  const loader = new PluginLoader(PLUGIN_JSON, SKILLS_DIR);
  const plugin = await loader.load();

  // Version & metadata
  console.log(`  ${c.bold}Name:${c.reset}    ${plugin.name}`);
  console.log(`  ${c.bold}Version:${c.reset} ${plugin.version}`);
  console.log(`  ${c.bold}Author:${c.reset}  ${plugin.author || 'unknown'}`);

  // Capabilities (resolved)
  console.log(`\n  ${c.bold}Capabilities (${plugin.resolvedCapabilities.length}):${c.reset}`);
  for (const cap of plugin.resolvedCapabilities) {
    const status = cap.active ? PASS : FAIL;
    const fileCount = cap.fileCount > 0 ? `${c.dim}(${cap.fileCount} files)${c.reset}` : `${c.red}(missing)${c.reset}`;
    console.log(`    ${status} ${cap.name} ${fileCount}`);
  }

  // Chains
  console.log(`\n  ${c.bold}Supported Chains (${plugin.supported_chains.length}):${c.reset}`);
  const chainRows = [];
  for (let i = 0; i < plugin.supported_chains.length; i += 4) {
    chainRows.push(plugin.supported_chains.slice(i, i + 4).map(ch => {
      const status = ch.active ? PASS : `${c.dim}-${c.reset}`;
      return `${status} ${ch.name}`;
    }).join('   '));
  }
  chainRows.forEach(row => console.log(`    ${row}`));

  // Skills directory stats
  const detector = new ProjectDetector(SKILLS_DIR);
  const stats = await detector.getStats();
  console.log(`\n  ${c.bold}Skills Directory:${c.reset}`);
  console.log(`    ${BULLET} Pattern files:      ${c.bold}${stats.patternFiles}${c.reset}`);
  console.log(`    ${BULLET} Total skill files:  ${c.bold}${stats.totalFiles}${c.reset}`);
  console.log(`    ${BULLET} Skill categories:   ${c.bold}${stats.categories}${c.reset}`);
  console.log(`    ${BULLET} Total size:         ${c.bold}${stats.totalSizeMB} MB${c.reset}`);
  console.log('');
}

/**
 * Doctor: in-depth diagnostics with fix suggestions
 */
async function runDoctor() {
  console.log(`\n${c.bold}${c.cyan}Web3 Audit Skills — Doctor${c.reset}`);
  console.log(`${c.dim}Running comprehensive diagnostics...${c.reset}\n`);

  const validator = new SetupValidator(ROOT_DIR, SKILLS_DIR, PLUGIN_JSON);
  const results = await validator.runAll({ verbose: true });

  printValidationResults(results);

  // Show fix suggestions for failures
  if (results.failures.length > 0) {
    console.log(`\n${c.bold}Suggested Fixes:${c.reset}\n`);
    for (const failure of results.failures) {
      console.log(`  ${FAIL} ${c.bold}${failure.check}${c.reset}`);
      console.log(`    ${c.dim}Problem:${c.reset} ${failure.message}`);
      if (failure.fix) {
        console.log(`    ${c.dim}Fix:${c.reset}     ${c.cyan}${failure.fix}${c.reset}`);
      }
      console.log('');
    }
  }

  if (results.passed) {
    console.log(`${c.bgGreen}${c.white}${c.bold} NO ISSUES FOUND ${c.reset}\n`);
  }
}

/**
 * Scan: run static analysis tools and framework commands against a target project
 */
async function runScan() {
  // Parse flags for project path and tool selection
  const projectFlag = args.find(a => a.startsWith('--project='));
  const fileFlag = args.find(a => a.startsWith('--file='));
  const testFileFlag = args.find(a => a.startsWith('--test-file='));
  const adapterFlag = args.find(a => a.startsWith('--adapter='));
  
  const projectDir = projectFlag ? resolve(projectFlag.split('=')[1]) : process.cwd();
  const adapter = createAdapter(adapterFlag ? adapterFlag.split('=')[1] : 'generic');

  const runSlither = flags.has('--slither') || flags.has('--all');
  const runAderyn = flags.has('--aderyn') || flags.has('--all');
  const doCompile = flags.has('--compile');
  const doTest = flags.has('--test');
  const doTestFile = testFileFlag;
  const doPatterns = flags.has('--patterns') && fileFlag;
  const doDetect = flags.has('--detect');

  // If no specific flag, default to --detect + --all
  const noFlags = !runSlither && !runAderyn && !doCompile && !doTest && !doTestFile && !doPatterns && !doDetect;

  console.log(`\n${c.bold}${c.cyan}Web3 Audit Skills — Scan${c.reset}`);
  console.log(`${c.dim}Target: ${projectDir}${c.reset}\n`);

  const results = { framework: null, slither: null, aderyn: null };

  // 1. Detect framework
  const toolRunner = new ToolRunner(projectDir);
  const fwInfo = toolRunner.getProjectInfo();

  if (fwInfo.detected) {
    console.log(`  ${PASS} Detected ${c.bold}${fwInfo.name}${c.reset} project`);
    console.log(`    ${BULLET} Sources: ${fwInfo.sourceCount} files in ${fwInfo.srcDir || 'N/A'}`);
    console.log(`    ${BULLET} Tests: ${fwInfo.testCount} files in ${fwInfo.testDir || 'N/A'}`);
    console.log(`    ${BULLET} Compiler: ${fwInfo.compilerVersion}`);
    results.framework = fwInfo;
  } else if (noFlags || doDetect) {
    console.log(`  ${WARN} No Foundry/Hardhat project detected in ${projectDir}`);
    console.log(`    ${BULLET} ${fwInfo.suggestion || 'Expected foundry.toml or hardhat.config.js'}`);
  }

  // 2. Compile
  if (doCompile && fwInfo.detected) {
    console.log(`\n  ${INFO} Compiling with ${fwInfo.name}...`);
    const compileResult = toolRunner.compile();
    if (compileResult.success) {
      console.log(`  ${PASS} Compilation successful`);
    } else {
      console.log(`  ${FAIL} Compilation failed`);
      console.log(`    ${c.dim}${compileResult.errors?.split('\n')[0] || 'Unknown error'}${c.reset}`);
    }
  }

  // 3. Run tests
  if (doTest && fwInfo.detected) {
    console.log(`\n  ${INFO} Running tests with ${fwInfo.name}...`);
    const testResult = toolRunner.runTests({ verbose: flags.has('--verbose') });
    if (testResult.success) {
      const s = testResult.summary;
      console.log(`  ${PASS} Tests: ${c.green}${s?.passed || '?'} passed${c.reset}, ${s?.failed ? c.red + s.failed + ' failed' + c.reset : '0 failed'}`);
    } else {
      console.log(`  ${FAIL} Tests failed`);
      const s = testResult.summary;
      if (s) console.log(`    ${BULLET} ${s.passed} passed, ${s.failed} failed`);
    }
  }

  // 3b. Run specific test file
  if (doTestFile && fwInfo.detected) {
    const testFile = testFileFlag.split('=')[1];
    console.log(`\n  ${INFO} Running test: ${testFile}...`);
    const testResult = toolRunner.runTestFile(testFile);
    if (testResult.success) {
      console.log(`  ${PASS} Test passed`);
    } else {
      console.log(`  ${FAIL} Test failed`);
    }
    if (testResult.output) {
      // Print last 20 lines of output
      const lines = testResult.output.trim().split('\n');
      const tail = lines.slice(-20);
      for (const line of tail) {
        console.log(`    ${c.dim}${line}${c.reset}`);
      }
    }
  }

  // 4. Slither
  if (runSlither || noFlags) {
    console.log(`\n  ${INFO} Running Slither static analysis...`);
    const slither = new SlitherRunner(projectDir);
    const check = slither.checkInstallation();
    
    if (!check.installed) {
      console.log(`  ${WARN} Slither not installed — ${c.dim}${check.suggestion}${c.reset}`);
    } else {
      console.log(`    ${BULLET} Slither ${check.version}`);
      const scanResult = slither.run();
      results.slither = scanResult;
      
      if (scanResult.success) {
        const s = scanResult.summary;
        console.log(`  ${PASS} Slither completed: ${c.bold}${s.total}${c.reset} findings`);
        console.log(`    ${BULLET} ${c.red}${s.high} High${c.reset}  ${c.yellow}${s.medium} Medium${c.reset}  ${s.low} Low  ${s.info} Info  ${s.gas} Gas`);
        if (s.priority > 0) {
          console.log(`    ${BULLET} ${c.red}${c.bold}${s.priority} priority findings — investigate first${c.reset}`);
        }
      } else {
        console.log(`  ${FAIL} Slither failed: ${scanResult.error}`);
        if (scanResult.suggestion) console.log(`    ${BULLET} ${scanResult.suggestion}`);
      }
    }
  }

  // 5. Aderyn
  if (runAderyn || noFlags) {
    console.log(`\n  ${INFO} Running Aderyn static analysis...`);
    const aderyn = new AderynRunner(projectDir);
    const check = aderyn.checkInstallation();
    
    if (!check.installed) {
      console.log(`  ${WARN} Aderyn not installed — ${c.dim}${check.suggestion}${c.reset}`);
    } else {
      console.log(`    ${BULLET} Aderyn ${check.version}`);
      const scanResult = aderyn.run();
      results.aderyn = scanResult;
      
      if (scanResult.success) {
        const s = scanResult.summary;
        console.log(`  ${PASS} Aderyn completed: ${c.bold}${s.total}${c.reset} findings (${s.instances} instances)`);
        console.log(`    ${BULLET} ${c.red}${s.high} High${c.reset}  ${c.yellow}${s.medium} Medium${c.reset}  ${s.low} Low  ${s.info} Info`);
      } else {
        console.log(`  ${FAIL} Aderyn failed: ${scanResult.error}`);
      }
    }
  }

  // 6. Pattern matching on a specific file
  if (doPatterns) {
    const filePath = fileFlag.split('=')[1];
    console.log(`\n  ${INFO} Pattern matching: ${filePath}...`);
    try {
      const { readFileSync } = await import('fs');
      const code = readFileSync(resolve(projectDir, filePath), 'utf-8');
      const { PatternMatcher } = await import('../src/intelligence/pattern-matcher.js');
      const matcher = new PatternMatcher(SKILLS_DIR);
      const matches = matcher.matchAll(code);
      const summary = matcher.getSummary(matches);
      
      console.log(`  ${PASS} Found ${c.bold}${summary.total}${c.reset} potential vulnerabilities`);
      for (const m of matches.slice(0, 15)) {
        console.log(`    ${BULLET} [${m.severity}] L${m.line}: ${m.description}`);
      }
      if (matches.length > 15) {
        console.log(`    ${c.dim}... and ${matches.length - 15} more${c.reset}`);
      }
    } catch (err) {
      console.log(`  ${FAIL} Pattern match failed: ${err.message}`);
    }
  }

  // Summary
  console.log(`\n  ${c.dim}─────────────────────────────────${c.reset}`);
  const hasResults = results.slither?.success || results.aderyn?.success;
  if (hasResults) {
    console.log(`\n  ${c.bold}Results saved to:${c.reset} ${projectDir}/.web3-audit/`);
    console.log(`    ${BULLET} slither-results.md  — formatted for AI consumption`);
    console.log(`    ${BULLET} aderyn-results.md   — formatted for AI consumption`);
    console.log(`    ${BULLET} *.json              — raw structured data`);
    console.log(`\n  ${c.bold}Next:${c.reset} Feed results into your AI assistant:`);
    console.log(`    ${BULLET} Claude Code: results are available via MCP tools`);
    console.log(`    ${BULLET} Other: copy .web3-audit/*.md into your AI chat`);
  } else if (noFlags) {
    console.log(`\n  ${WARN} No static analysis tools found. Install one:`);
    console.log(`    ${BULLET} Slither: ${c.cyan}pip install slither-analyzer${c.reset}`);
    console.log(`    ${BULLET} Aderyn:  ${c.cyan}cargo install aderyn${c.reset}`);
  }
  console.log('');
}

/**
 * Show available adapters
 */
function showAdapters() {
  console.log(`\n${c.bold}Available AI Adapters:${c.reset}\n`);
  for (const adapter of listAdapters()) {
    console.log(`  ${c.bold}${adapter.name}${c.reset} — ${adapter.label}`);
    console.log(`    Features: ${adapter.features.join(', ')}`);
  }
  console.log(`\n  Usage: ${c.cyan}npx web3-audit scan --adapter=cursor --project .${c.reset}\n`);
}

// ─── Helpers ───────────────────────────────────────────────────

function printValidationResults(results) {
  for (const check of results.checks) {
    if (check.status === 'pass') {
      console.log(`  ${PASS} ${check.label}`);
    } else if (check.status === 'warn') {
      console.log(`  ${WARN} ${check.label} — ${c.yellow}${check.message}${c.reset}`);
    } else {
      console.log(`  ${FAIL} ${check.label} — ${c.red}${check.message}${c.reset}`);
    }
    
    // Print sub-items if verbose
    if (check.details && check.details.length > 0) {
      for (const detail of check.details) {
        console.log(`      ${BULLET} ${detail}`);
      }
    }
  }

  console.log(`\n  ${c.dim}─────────────────────────────────${c.reset}`);
  console.log(`  ${PASS} ${results.passCount} passed   ${WARN} ${results.warnings} warnings   ${FAIL} ${results.failCount} failed`);
}

// ─── Check References ──────────────────────────────────────────
async function runCheckRefs() {
  console.log(`\n${c.bold}Web3 Audit Skills — Reference Validator${c.reset}\n`);

  const validator = new ReferenceValidator(SKILLS_DIR);
  const results = await validator.validateAll();

  for (const file of results.files) {
    const status = file.broken === 0
      ? `${PASS} ${c.green}${file.file}${c.reset}`
      : `${FAIL} ${c.red}${file.file}${c.reset}`;
    console.log(`  ${status}  (${file.valid}/${file.totalRefs} valid)`);

    for (const issue of file.issues) {
      const lines = issue.lines.map(l => `L${l}`).join(', ');
      console.log(`    ${c.red}✗${c.reset} ${issue.reference} ${c.dim}(${lines})${c.reset}`);
      if (issue.suggestion) {
        console.log(`      ${c.yellow}→ Did you mean: ${issue.suggestion}?${c.reset}`);
      }
    }
  }

  const { summary } = results;
  console.log(`\n  ${'─'.repeat(45)}`);
  if (summary.totalBroken === 0) {
    console.log(`  ${PASS} All ${summary.totalRefs} references valid across ${summary.totalFiles} files\n`);
  } else {
    console.log(`  ${FAIL} ${summary.totalBroken} broken reference${summary.totalBroken > 1 ? 's' : ''} found (${summary.totalValid}/${summary.totalRefs} valid)\n`);
    process.exit(1);
  }
}

function printHelp() {
  console.log(`
${c.bold}Web3 Audit Skills${c.reset} — AI-powered smart contract security auditing

${c.bold}USAGE${c.reset}
  npx web3-audit <command> [flags]

${c.bold}COMMANDS${c.reset}
  setup       Initialize and validate the installation
  verify      Run full verification (setup + live pattern test)
  info        Show plugin capabilities, chains, and stats
  doctor      Diagnose issues with detailed fix suggestions
  scan        Run static analysis and framework tools
  check-refs  Validate all file references in navigation docs
  triggers    Resolve skill files for a query or detect code patterns
  adapters    List available AI platform adapters

${c.bold}SCAN FLAGS${c.reset}
  --project=<dir>      Target project directory (default: cwd)
  --all                Run all available analysis tools
  --slither            Run Slither static analysis
  --aderyn             Run Aderyn static analysis
  --compile            Compile project (Foundry/Hardhat)
  --test               Run project tests
  --test-file=<path>   Run a specific test file (PoC)
  --patterns --file=<path>  Pattern-match a Solidity file
  --detect             Detect project framework only
  --adapter=<name>     AI platform adapter (claude-code, cursor, generic)

${c.bold}GENERAL FLAGS${c.reset}
  --silent    Suppress output (setup only, for postinstall)
  --strict    Treat warnings as failures (verify only)
  --verbose   Show detailed diagnostics

${c.bold}QUICK START${c.reset}
  ${c.cyan}git clone${c.reset} https://github.com/0x-Shashi/WEB3-AUDIT-SKILLS.git
  ${c.cyan}cd${c.reset} WEB3-AUDIT-SKILLS
  ${c.cyan}npm install${c.reset}        ${c.dim}# auto-runs setup${c.reset}
  ${c.cyan}npm run verify${c.reset}     ${c.dim}# validate everything works${c.reset}
  ${c.cyan}npm start${c.reset}          ${c.dim}# launch MCP server${c.reset}

${c.bold}SCAN EXAMPLE${c.reset}
  ${c.cyan}npx web3-audit scan --all --project ~/myprotocol${c.reset}
  ${c.cyan}npx web3-audit scan --test-file=test/Exploit.t.sol --project .${c.reset}
`);
}

async function runTriggers() {
  const engine = new TriggerEngine(SKILLS_DIR);
  // args[0] is the command itself ('triggers'), positional args start at args[1]
  const positionalArgs = args.slice(1).filter(a => !a.startsWith('--'));
  const query = positionalArgs[0];
  const codeFlag = flags.has('--code');
  const listFlag = flags.has('--list');
  const patternsFlag = flags.has('--patterns');

  if (listFlag) {
    console.log(`\n${c.bold}Available Triggers${c.reset}\n`);
    const triggers = engine.listTriggers();
    const categories = {};
    for (const t of triggers) {
      if (!categories[t.category]) categories[t.category] = [];
      categories[t.category].push(t);
    }
    for (const [cat, items] of Object.entries(categories)) {
      console.log(`  ${c.cyan}${c.bold}${cat}${c.reset}`);
      for (const t of items) {
        console.log(`    ${t.keywords.join(', ')} ${c.dim}→ ${t.fileCount} file(s)${c.reset}`);
      }
      console.log();
    }
    return;
  }

  if (patternsFlag) {
    console.log(`\n${c.bold}Code Pattern Detectors${c.reset}\n`);
    const patterns = engine.listCodePatterns();
    for (const p of patterns) {
      console.log(`  ${c.cyan}${p.id}${c.reset}  ${p.label} ${c.dim}→ ${p.fileCount} file(s)${c.reset}`);
    }
    console.log();
    return;
  }

  if (codeFlag) {
    // --code <file>: detect code patterns in a Solidity file
    const filePath = positionalArgs[0];
    if (!filePath) {
      console.error(`${FAIL} Usage: npx web3-audit triggers --code <file.sol>`);
      process.exit(1);
    }
    const { readFile } = await import('fs/promises');
    const absPath = resolve(filePath);
    let code;
    try {
      code = await readFile(absPath, 'utf-8');
    } catch {
      console.error(`${FAIL} Cannot read file: ${absPath}`);
      process.exit(1);
    }
    const result = await engine.processCode(code, { loadContent: false });
    console.log(`\n${c.bold}Code Pattern Detection${c.reset} — ${filePath}\n`);
    if (result.detections.length === 0) {
      console.log(`  ${c.dim}No patterns detected.${c.reset}\n`);
      return;
    }
    for (const d of result.detections) {
      console.log(`  ${PASS} ${c.cyan}${d.id}${c.reset} — ${d.label}`);
    }
    console.log(`\n  ${c.bold}Recommended skill files:${c.reset}`);
    for (const f of result.files) {
      const exists = result.missingFiles?.includes(f) ? `${c.red}(missing)${c.reset}` : `${c.green}✓${c.reset}`;
      console.log(`    ${exists} ${f}`);
    }
    console.log();
    return;
  }

  // Default: resolve triggers for a query string
  if (!query) {
    console.error(`${FAIL} Usage: npx web3-audit triggers "<query>"`);
    console.error(`         npx web3-audit triggers --code <file.sol>`);
    console.error(`         npx web3-audit triggers --list`);
    console.error(`         npx web3-audit triggers --patterns`);
    process.exit(1);
  }

  const result = await engine.process(query, { loadContent: false });
  console.log(`\n${c.bold}Trigger Resolution${c.reset} — "${query}"\n`);

  if (!result.success) {
    console.log(`  ${c.dim}No matching triggers.${c.reset}\n`);
    if (result.suggestions?.length > 0) {
      console.log(`  ${c.bold}Try:${c.reset}`);
      for (const s of result.suggestions) {
        console.log(`    ${c.cyan}${s.category}${c.reset}: ${s.examples.join(', ')}`);
      }
      console.log();
    }
    return;
  }

  console.log(`  ${c.bold}Category:${c.reset} ${result.category}`);
  console.log(`  ${c.bold}Matched:${c.reset}  ${result.matchedTriggers.join(', ')}`);
  console.log(`  ${c.bold}Files:${c.reset}    ${result.fileCount}\n`);

  for (const f of result.files) {
    const missing = result.missingFiles?.includes(f);
    const icon = missing ? `${c.red}✗${c.reset}` : `${c.green}✓${c.reset}`;
    console.log(`    ${icon} ${f}`);
  }
  console.log();
}

async function printVersion() {
  const loader = new PluginLoader(PLUGIN_JSON, SKILLS_DIR);
  const plugin = await loader.load();
  console.log(`web3-audit-skills v${plugin.version}`);
}
