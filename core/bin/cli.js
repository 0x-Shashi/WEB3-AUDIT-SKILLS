#!/usr/bin/env node

/**
 * Web3 Audit CLI
 * 
 * Command-line interface for the Web3 Security Audit System.
 * 
 * Commands:
 *   web3audit scan <path>     - Run security analysis
 *   web3audit search <query>  - Search Solodit findings
 *   web3audit analyze <file>  - Pattern-based analysis
 *   web3audit report <path>   - Generate audit report
 *   web3audit status          - Show tool installation status
 */

const { Command } = require('commander');
const chalk = require('chalk');
const ora = require('ora');
const path = require('path');
const fs = require('fs');

const { SoloditClient, SoloditParser } = require('../src/api');
const { ToolRunner, SlitherRunner, MythrilRunner, AderynRunner } = require('../src/tools');
const { FindingDatabase } = require('../src/db');
const { PatternMatcher, SeverityScorer, SemanticSearch, VulnerabilityClassifier } = require('../src/intelligence');

const program = new Command();

// Package info
const pkg = require('../package.json');

program
  .name('web3audit')
  .description('Web3 Security Audit CLI - Analyze smart contracts and search security findings')
  .version(pkg.version);

// ==================== Scan Command ====================

program
  .command('scan <path>')
  .description('Run security analysis on contracts')
  .option('-t, --tools <tools>', 'Tools to use (comma-separated: slither,mythril,aderyn)', 'slither,aderyn')
  .option('-s, --severity <levels>', 'Filter by severity (comma-separated: critical,high,medium,low)', 'critical,high,medium')
  .option('-o, --output <file>', 'Output file path')
  .option('-f, --format <format>', 'Output format (text, markdown, json)', 'markdown')
  .option('--quick', 'Quick scan mode (faster but less thorough)')
  .option('--deep', 'Deep scan mode (slower but more thorough)')
  .option('--save', 'Save findings to database')
  .action(async (targetPath, options) => {
    const spinner = ora('Initializing scan...').start();
    
    try {
      const absPath = path.resolve(targetPath);
      
      if (!fs.existsSync(absPath)) {
        spinner.fail(`Path not found: ${absPath}`);
        process.exit(1);
      }

      // Check available tools
      const runner = new ToolRunner();
      const toolStatus = await runner.checkTools();
      
      const requestedTools = options.tools.split(',').map(t => t.trim());
      const availableRequested = requestedTools.filter(t => toolStatus.available.includes(t));
      
      if (availableRequested.length === 0) {
        spinner.fail('No requested tools are available');
        console.log('\nInstallation commands:');
        console.log('  Slither: pip install slither-analyzer');
        console.log('  Mythril: pip install mythril');
        console.log('  Aderyn:  cargo install aderyn');
        process.exit(1);
      }

      spinner.text = `Running analysis with: ${availableRequested.join(', ')}...`;

      let results;
      if (options.deep) {
        results = await runner.deepScan(absPath);
      } else if (options.quick) {
        results = await runner.quickScan(absPath);
      } else {
        results = await runner.runAll(absPath, { tools: availableRequested });
      }

      spinner.succeed('Analysis complete');

      // Filter by severity
      if (options.severity) {
        const severities = options.severity.split(',').map(s => s.trim().toUpperCase());
        results.combined.findings = results.combined.findings.filter(f => 
          severities.includes(f.severity)
        );
      }

      // Format output
      const output = runner.formatResults(results, options.format);

      // Save to file or print
      if (options.output) {
        fs.writeFileSync(options.output, output);
        console.log(chalk.green(`\n✓ Report saved to: ${options.output}`));
      } else {
        console.log('\n' + output);
      }

      // Save to database
      if (options.save) {
        const db = new FindingDatabase();
        await db.init();
        
        const projectId = db.createProject({
          name: path.basename(absPath),
          path: absPath,
          type: detectProjectType(absPath)
        });
        
        const auditId = db.startAudit(projectId);
        
        for (const finding of results.combined.findings) {
          db.addFinding({
            audit_id: auditId,
            project_id: projectId,
            external_id: finding.sourceId,
            title: finding.title,
            severity: finding.severity,
            description: finding.description,
            file_path: finding.elements?.[0]?.file,
            start_line: finding.elements?.[0]?.startLine,
            source: finding.source
          });
        }
        
        db.completeAudit(auditId);
        db.close();
        
        console.log(chalk.green(`✓ ${results.combined.findings.length} findings saved to database`));
      }

      // Print summary
      const s = results.combined.summary;
      console.log('\n' + chalk.bold('Summary:'));
      if (s.critical > 0) console.log(chalk.red(`  Critical: ${s.critical}`));
      if (s.high > 0) console.log(chalk.red(`  High: ${s.high}`));
      if (s.medium > 0) console.log(chalk.yellow(`  Medium: ${s.medium}`));
      if (s.low > 0) console.log(chalk.blue(`  Low: ${s.low}`));
      if (s.info > 0) console.log(chalk.gray(`  Info: ${s.info}`));
      console.log(chalk.bold(`  Total: ${s.total}`));

    } catch (error) {
      spinner.fail(`Scan failed: ${error.message}`);
      if (process.env.DEBUG) console.error(error);
      process.exit(1);
    }
  });

// ==================== Search Command ====================

program
  .command('search <query>')
  .description('Search Solodit security findings database')
  .option('-p, --protocol <name>', 'Filter by protocol name')
  .option('-s, --severity <level>', 'Filter by severity')
  .option('-c, --category <category>', 'Filter by category')
  .option('-l, --limit <number>', 'Maximum results', '10')
  .option('-f, --format <format>', 'Output format (text, markdown, json)', 'text')
  .action(async (query, options) => {
    const spinner = ora('Searching Solodit database...').start();
    
    try {
      const client = new SoloditClient();
      const parser = new SoloditParser();
      
      let results;
      
      if (options.protocol) {
        results = await client.searchByProtocol(options.protocol, {
          limit: parseInt(options.limit)
        });
      } else if (options.severity) {
        results = await client.searchBySeverity(options.severity, {
          limit: parseInt(options.limit)
        });
      } else {
        results = await client.searchFindings(query, {
          limit: parseInt(options.limit),
          category: options.category
        });
      }

      spinner.succeed(`Found ${results.length} results`);

      if (results.length === 0) {
        console.log(chalk.yellow('\nNo findings found. Try a different query.'));
        return;
      }

      // Parse and format
      const parsed = parser.parseFindings(results);
      
      switch (options.format) {
        case 'json':
          console.log(JSON.stringify(parsed, null, 2));
          break;
        case 'markdown':
          for (const finding of parsed) {
            console.log(parser.formatFinding(finding, 'markdown'));
          }
          break;
        default:
          for (const finding of parsed) {
            console.log(parser.formatFinding(finding, 'text'));
          }
      }

      // Show summary
      const summary = parser.getSummary(parsed);
      console.log('\n' + chalk.bold('Summary:'));
      console.log(`  Total: ${summary.total}`);
      Object.entries(summary.bySeverity).forEach(([sev, count]) => {
        if (count > 0) {
          const color = sev === 'HIGH' || sev === 'CRITICAL' ? chalk.red :
                       sev === 'MEDIUM' ? chalk.yellow : chalk.blue;
          console.log(`  ${sev}: ${color(count)}`);
        }
      });

    } catch (error) {
      spinner.fail(`Search failed: ${error.message}`);
      if (process.env.DEBUG) console.error(error);
      process.exit(1);
    }
  });

// ==================== Similar Command ====================

program
  .command('similar <file>')
  .description('Find similar vulnerabilities in Solodit for a code snippet')
  .option('-l, --limit <number>', 'Maximum results', '5')
  .action(async (file, options) => {
    const spinner = ora('Analyzing code and searching for similar findings...').start();
    
    try {
      const absPath = path.resolve(file);
      
      if (!fs.existsSync(absPath)) {
        spinner.fail(`File not found: ${absPath}`);
        process.exit(1);
      }

      const code = fs.readFileSync(absPath, 'utf-8');
      const client = new SoloditClient();
      const parser = new SoloditParser();
      
      const results = await client.findSimilar(code, {
        limit: parseInt(options.limit)
      });

      if (results.length === 0) {
        spinner.succeed('No similar findings found');
        return;
      }

      spinner.succeed(`Found ${results.length} potentially similar findings`);

      const parsed = parser.parseFindings(results);
      for (const finding of parsed) {
        console.log(parser.formatFinding(finding, 'text'));
      }

    } catch (error) {
      spinner.fail(`Search failed: ${error.message}`);
      if (process.env.DEBUG) console.error(error);
      process.exit(1);
    }
  });

// ==================== Analyze Command (Pattern Matching) ====================

program
  .command('analyze <file>')
  .description('Run pattern-based vulnerability analysis on a file')
  .option('-l, --language <lang>', 'Language (solidity, rust, move)', 'solidity')
  .option('-s, --severity <levels>', 'Filter by severity', 'critical,high,medium')
  .option('-c, --category <category>', 'Filter by category')
  .option('--score', 'Calculate severity scores')
  .option('--classify', 'Add vulnerability classification')
  .option('-o, --output <file>', 'Output file path')
  .option('-f, --format <format>', 'Output format (text, markdown, json)', 'text')
  .action(async (file, options) => {
    const spinner = ora('Analyzing code patterns...').start();
    
    try {
      const absPath = path.resolve(file);
      
      if (!fs.existsSync(absPath)) {
        spinner.fail(`File not found: ${absPath}`);
        process.exit(1);
      }

      const code = fs.readFileSync(absPath, 'utf-8');
      const matcher = new PatternMatcher();
      
      // Detect language from extension if not specified
      let language = options.language;
      const ext = path.extname(absPath);
      if (ext === '.rs') language = 'rust';
      if (ext === '.move') language = 'move';

      // Filter options
      const filterOptions = {};
      if (options.severity) {
        filterOptions.severity = options.severity.split(',').map(s => s.trim().toUpperCase());
      }
      if (options.category) {
        filterOptions.category = options.category;
      }

      // Run pattern analysis
      let findings = matcher.analyze(code, language, filterOptions);
      spinner.succeed(`Found ${findings.length} potential issues`);

      // Score findings if requested
      if (options.score) {
        const scorer = new SeverityScorer();
        findings = scorer.scoreFindings(findings);
        
        const riskSummary = scorer.getRiskSummary(findings);
        console.log('\n' + chalk.bold('Risk Assessment:'));
        console.log(`  Overall Risk: ${colorRisk(riskSummary.overallRisk)}`);
        console.log(`  Risk Score: ${riskSummary.riskScore}/10`);
      }

      // Classify findings if requested
      if (options.classify) {
        const classifier = new VulnerabilityClassifier();
        findings = classifier.classifyAll(findings);
      }

      // Format output
      let output;
      switch (options.format) {
        case 'json':
          output = JSON.stringify(findings, null, 2);
          break;
        case 'markdown':
          output = formatAnalysisMarkdown(absPath, findings);
          break;
        default:
          output = formatAnalysisText(absPath, findings);
      }

      if (options.output) {
        fs.writeFileSync(options.output, output);
        console.log(chalk.green(`\n✓ Report saved to: ${options.output}`));
      } else {
        console.log('\n' + output);
      }

      // Print summary
      const summary = {
        critical: findings.filter(f => f.severity === 'CRITICAL').length,
        high: findings.filter(f => f.severity === 'HIGH').length,
        medium: findings.filter(f => f.severity === 'MEDIUM').length,
        low: findings.filter(f => f.severity === 'LOW').length,
        gas: findings.filter(f => f.severity === 'GAS').length
      };

      console.log('\n' + chalk.bold('Summary:'));
      if (summary.critical > 0) console.log(chalk.red(`  Critical: ${summary.critical}`));
      if (summary.high > 0) console.log(chalk.red(`  High: ${summary.high}`));
      if (summary.medium > 0) console.log(chalk.yellow(`  Medium: ${summary.medium}`));
      if (summary.low > 0) console.log(chalk.blue(`  Low: ${summary.low}`));
      if (summary.gas > 0) console.log(chalk.gray(`  Gas: ${summary.gas}`));

    } catch (error) {
      spinner.fail(`Analysis failed: ${error.message}`);
      if (process.env.DEBUG) console.error(error);
      process.exit(1);
    }
  });

// ==================== Report Command ====================

program
  .command('report')
  .description('Generate audit report from database')
  .option('-p, --project <id>', 'Project ID')
  .option('-a, --audit <id>', 'Audit ID')
  .option('-o, --output <file>', 'Output file path', 'audit-report.md')
  .option('-f, --format <format>', 'Output format (markdown, json)', 'markdown')
  .action(async (options) => {
    const spinner = ora('Generating report...').start();
    
    try {
      const db = new FindingDatabase();
      await db.init();

      let findings;
      let title = 'Security Audit Report';

      if (options.audit) {
        const audit = db.getAudit(parseInt(options.audit));
        if (!audit) {
          spinner.fail(`Audit not found: ${options.audit}`);
          process.exit(1);
        }
        findings = db.queryFindings({ audit_id: parseInt(options.audit), excludeFalsePositives: true });
        title = `Audit Report: ${audit.name}`;
      } else if (options.project) {
        const project = db.getProject(parseInt(options.project));
        if (!project) {
          spinner.fail(`Project not found: ${options.project}`);
          process.exit(1);
        }
        findings = db.queryFindings({ project_id: parseInt(options.project), excludeFalsePositives: true });
        title = `Security Report: ${project.name}`;
      } else {
        // List all findings
        findings = db.queryFindings({ excludeFalsePositives: true });
      }

      const stats = db.getStats(options.project ? { project_id: parseInt(options.project) } : {});
      db.close();

      if (options.format === 'json') {
        const report = { title, stats, findings };
        fs.writeFileSync(options.output, JSON.stringify(report, null, 2));
      } else {
        const report = generateMarkdownReport(title, stats, findings);
        fs.writeFileSync(options.output, report);
      }

      spinner.succeed(`Report saved to: ${options.output}`);
      
      console.log('\n' + chalk.bold('Report Summary:'));
      console.log(`  Total Findings: ${stats.total}`);
      console.log(`  Critical: ${chalk.red(stats.bySeverity.critical)}`);
      console.log(`  High: ${chalk.red(stats.bySeverity.high)}`);
      console.log(`  Medium: ${chalk.yellow(stats.bySeverity.medium)}`);
      console.log(`  Low: ${chalk.blue(stats.bySeverity.low)}`);

    } catch (error) {
      spinner.fail(`Report generation failed: ${error.message}`);
      if (process.env.DEBUG) console.error(error);
      process.exit(1);
    }
  });

// ==================== Status Command ====================

program
  .command('status')
  .description('Show tool installation status')
  .action(async () => {
    const spinner = ora('Checking tools...').start();
    
    const runner = new ToolRunner();
    const status = await runner.checkTools();
    
    spinner.stop();

    console.log(chalk.bold('\nSecurity Analysis Tools Status:\n'));

    // Slither
    if (status.slither.installed) {
      console.log(chalk.green('✓ Slither') + ` - ${status.slither.version}`);
    } else {
      console.log(chalk.red('✗ Slither') + ' - Not installed');
      console.log(chalk.gray('  Install: pip install slither-analyzer'));
    }

    // Mythril
    if (status.mythril.installed) {
      console.log(chalk.green('✓ Mythril') + ` - ${status.mythril.version}`);
    } else {
      console.log(chalk.red('✗ Mythril') + ' - Not installed');
      console.log(chalk.gray('  Install: pip install mythril'));
    }

    // Aderyn
    if (status.aderyn.installed) {
      console.log(chalk.green('✓ Aderyn') + ` - ${status.aderyn.version}`);
    } else {
      console.log(chalk.red('✗ Aderyn') + ' - Not installed');
      console.log(chalk.gray('  Install: cargo install aderyn'));
    }

    console.log('\n' + chalk.bold('Available tools: ') + status.available.join(', ') || 'None');
  });

// ==================== DB Commands ====================

const dbCmd = program.command('db').description('Database operations');

dbCmd
  .command('list')
  .description('List projects and audits')
  .action(async () => {
    const db = new FindingDatabase();
    await db.init();

    const projects = db.listProjects();
    
    if (projects.length === 0) {
      console.log(chalk.yellow('No projects found. Run a scan with --save to add findings.'));
      return;
    }

    console.log(chalk.bold('\nProjects:\n'));
    
    for (const project of projects) {
      console.log(`  [${project.id}] ${project.name}`);
      console.log(chalk.gray(`      Path: ${project.path}`));
      console.log(chalk.gray(`      Type: ${project.type}`));
      
      const stats = db.getStats({ project_id: project.id });
      console.log(`      Findings: ${stats.total} (H:${stats.bySeverity.high} M:${stats.bySeverity.medium} L:${stats.bySeverity.low})`);
      console.log('');
    }

    db.close();
  });

dbCmd
  .command('findings')
  .description('List findings')
  .option('-p, --project <id>', 'Filter by project ID')
  .option('-s, --severity <level>', 'Filter by severity')
  .option('--status <status>', 'Filter by status')
  .option('-l, --limit <number>', 'Maximum results', '20')
  .action(async (options) => {
    const db = new FindingDatabase();
    await db.init();

    const filters = {
      limit: parseInt(options.limit),
      excludeFalsePositives: true
    };

    if (options.project) filters.project_id = parseInt(options.project);
    if (options.severity) filters.severity = options.severity.toUpperCase();
    if (options.status) filters.status = options.status;

    const findings = db.queryFindings(filters);
    db.close();

    if (findings.length === 0) {
      console.log(chalk.yellow('No findings match the criteria.'));
      return;
    }

    console.log(chalk.bold(`\nFindings (${findings.length}):\n`));

    for (const f of findings) {
      const sevColor = f.severity === 'HIGH' || f.severity === 'CRITICAL' ? chalk.red :
                       f.severity === 'MEDIUM' ? chalk.yellow : chalk.blue;
      
      console.log(`  [${f.id}] ${sevColor(`[${f.severity}]`)} ${f.title}`);
      if (f.file_path) console.log(chalk.gray(`      ${f.file_path}:${f.start_line || '?'}`));
      console.log(chalk.gray(`      Source: ${f.source} | Status: ${f.status}`));
      console.log('');
    }
  });

dbCmd
  .command('fix <id>')
  .description('Mark finding as fixed')
  .option('-n, --notes <notes>', 'Fix notes')
  .action(async (id, options) => {
    const db = new FindingDatabase();
    await db.init();
    
    db.markFixed(parseInt(id), options.notes);
    db.close();
    
    console.log(chalk.green(`✓ Finding ${id} marked as fixed`));
  });

dbCmd
  .command('fp <id>')
  .description('Mark finding as false positive')
  .option('-r, --reason <reason>', 'Reason for marking as false positive')
  .action(async (id, options) => {
    const db = new FindingDatabase();
    await db.init();
    
    db.markFalsePositive(parseInt(id), options.reason);
    db.close();
    
    console.log(chalk.green(`✓ Finding ${id} marked as false positive`));
  });

// ==================== Helper Functions ====================

function detectProjectType(projectPath) {
  if (fs.existsSync(path.join(projectPath, 'foundry.toml'))) return 'foundry';
  if (fs.existsSync(path.join(projectPath, 'hardhat.config.js'))) return 'hardhat';
  if (fs.existsSync(path.join(projectPath, 'hardhat.config.ts'))) return 'hardhat';
  if (fs.existsSync(path.join(projectPath, 'truffle-config.js'))) return 'truffle';
  if (fs.existsSync(path.join(projectPath, 'brownie-config.yaml'))) return 'brownie';
  if (fs.existsSync(path.join(projectPath, 'Anchor.toml'))) return 'anchor';
  if (fs.existsSync(path.join(projectPath, 'Move.toml'))) return 'move';
  return 'unknown';
}

function generateMarkdownReport(title, stats, findings) {
  let report = `# ${title}\n\n`;
  report += `**Generated:** ${new Date().toISOString()}\n\n`;
  
  report += `## Summary\n\n`;
  report += `| Severity | Count |\n|----------|-------|\n`;
  report += `| Critical | ${stats.bySeverity.critical} |\n`;
  report += `| High | ${stats.bySeverity.high} |\n`;
  report += `| Medium | ${stats.bySeverity.medium} |\n`;
  report += `| Low | ${stats.bySeverity.low} |\n`;
  report += `| Info | ${stats.bySeverity.info} |\n`;
  report += `| **Total** | **${stats.total}** |\n\n`;

  report += `## Findings\n\n`;

  // Group by severity
  const grouped = {
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL'),
    HIGH: findings.filter(f => f.severity === 'HIGH'),
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM'),
    LOW: findings.filter(f => f.severity === 'LOW'),
    INFO: findings.filter(f => f.severity === 'INFO')
  };

  for (const [severity, items] of Object.entries(grouped)) {
    if (items.length === 0) continue;
    
    report += `### ${severity} (${items.length})\n\n`;
    
    for (const f of items) {
      report += `#### ${f.title}\n\n`;
      report += `**ID:** ${f.id} | **Source:** ${f.source} | **Status:** ${f.status}\n\n`;
      
      if (f.file_path) {
        report += `**Location:** \`${f.file_path}:${f.start_line || '?'}\`\n\n`;
      }
      
      if (f.description) {
        report += `${f.description}\n\n`;
      }
      
      if (f.recommendation) {
        report += `**Recommendation:** ${f.recommendation}\n\n`;
      }
      
      report += `---\n\n`;
    }
  }

  return report;
}

function colorRisk(risk) {
  switch (risk) {
    case 'CRITICAL': return chalk.bgRed.white(` ${risk} `);
    case 'HIGH': return chalk.red(risk);
    case 'MEDIUM': return chalk.yellow(risk);
    case 'LOW': return chalk.blue(risk);
    default: return risk;
  }
}

function formatAnalysisText(filePath, findings) {
  let output = `=== Pattern Analysis Report ===\n\n`;
  output += `File: ${filePath}\n`;
  output += `Date: ${new Date().toISOString()}\n`;
  output += `Findings: ${findings.length}\n\n`;

  if (findings.length === 0) {
    output += 'No issues detected.\n';
    return output;
  }

  output += `${'='.repeat(50)}\n\n`;

  for (const f of findings) {
    const sevColor = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? '!!' : 
                     f.severity === 'MEDIUM' ? '!' : '';
    
    output += `${sevColor}[${f.severity}] ${f.name}\n`;
    output += `ID: ${f.id} | Category: ${f.category}\n`;
    output += `Line: ${f.line || '?'}\n`;
    
    if (f.description) {
      output += `\n${f.description}\n`;
    }
    
    if (f.recommendation) {
      output += `\nRecommendation: ${f.recommendation}\n`;
    }

    if (f.score !== undefined) {
      output += `\nScore: ${f.score}/10 (${f.adjustedSeverity})\n`;
    }

    if (f.classification) {
      output += `Classification: ${f.classification.categoryName}`;
      if (f.classification.swcId) output += ` (${f.classification.swcId})`;
      output += `\n`;
    }

    if (f.snippet) {
      output += `\nCode:\n${f.snippet}\n`;
    }
    
    output += `\n${'-'.repeat(50)}\n\n`;
  }

  return output;
}

function formatAnalysisMarkdown(filePath, findings) {
  let output = `# Pattern Analysis Report\n\n`;
  output += `**File:** \`${filePath}\`\n`;
  output += `**Date:** ${new Date().toISOString()}\n`;
  output += `**Findings:** ${findings.length}\n\n`;

  if (findings.length === 0) {
    output += '✅ No issues detected.\n';
    return output;
  }

  // Summary table
  const summary = {
    critical: findings.filter(f => f.severity === 'CRITICAL').length,
    high: findings.filter(f => f.severity === 'HIGH').length,
    medium: findings.filter(f => f.severity === 'MEDIUM').length,
    low: findings.filter(f => f.severity === 'LOW').length,
    gas: findings.filter(f => f.severity === 'GAS').length
  };

  output += `## Summary\n\n`;
  output += `| Severity | Count |\n|----------|-------|\n`;
  output += `| Critical | ${summary.critical} |\n`;
  output += `| High | ${summary.high} |\n`;
  output += `| Medium | ${summary.medium} |\n`;
  output += `| Low | ${summary.low} |\n`;
  output += `| Gas | ${summary.gas} |\n\n`;

  output += `## Findings\n\n`;

  for (const f of findings) {
    output += `### [${f.severity}] ${f.name}\n\n`;
    output += `**ID:** \`${f.id}\` | **Category:** ${f.category} | **Line:** ${f.line || '?'}\n\n`;
    
    if (f.description) {
      output += `${f.description}\n\n`;
    }
    
    if (f.recommendation) {
      output += `**Recommendation:** ${f.recommendation}\n\n`;
    }

    if (f.score !== undefined) {
      output += `**Score:** ${f.score}/10 → ${f.adjustedSeverity}\n\n`;
    }

    if (f.classification) {
      output += `**Classification:** ${f.classification.categoryName}`;
      if (f.classification.swcId) output += ` (${f.classification.swcId})`;
      if (f.classification.cweIds?.length) output += ` | CWE: ${f.classification.cweIds.join(', ')}`;
      output += `\n\n`;
    }

    if (f.snippet) {
      output += `\`\`\`solidity\n${f.snippet}\n\`\`\`\n\n`;
    }
    
    output += `---\n\n`;
  }

  return output;
}

// Parse and run
program.parse();

