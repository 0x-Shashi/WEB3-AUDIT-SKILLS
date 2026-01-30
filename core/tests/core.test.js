/**
 * Core Module Tests
 * 
 * Run with: npm test
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');

// Import modules
const { SoloditClient, SoloditParser } = require('../src/api');
const { SlitherRunner, MythrilRunner, AderynRunner, ToolRunner } = require('../src/tools');
const { FindingDatabase } = require('../src/db');
const ProjectDetector = require('../src/utils/project-detector');

// Test results
const results = {
  passed: 0,
  failed: 0,
  tests: []
};

function test(name, fn) {
  try {
    fn();
    results.passed++;
    results.tests.push({ name, status: 'passed' });
    console.log(`  ✓ ${name}`);
  } catch (error) {
    results.failed++;
    results.tests.push({ name, status: 'failed', error: error.message });
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${error.message}`);
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    results.passed++;
    results.tests.push({ name, status: 'passed' });
    console.log(`  ✓ ${name}`);
  } catch (error) {
    results.failed++;
    results.tests.push({ name, status: 'failed', error: error.message });
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${error.message}`);
  }
}

// ==================== Tests ====================

console.log('\n=== Web3 Audit Core Tests ===\n');

// API Tests
console.log('Solodit Client:');

test('SoloditClient instantiation', () => {
  const client = new SoloditClient();
  assert(client !== null);
  assert(typeof client.searchFindings === 'function');
});

test('SoloditClient has correct methods', () => {
  const client = new SoloditClient();
  assert(typeof client.searchByPattern === 'function');
  assert(typeof client.searchByProtocol === 'function');
  assert(typeof client.searchBySeverity === 'function');
  assert(typeof client.findSimilar === 'function');
});

test('SoloditParser instantiation', () => {
  const parser = new SoloditParser();
  assert(parser !== null);
  assert(typeof parser.parseFindings === 'function');
});

test('SoloditParser severity normalization', () => {
  const parser = new SoloditParser();
  const findings = parser.parseFindings([
    { severity: 'High' },
    { severity: 'MEDIUM' },
    { severity: 'low' },
    { severity: 'Critical' }
  ]);
  assert.strictEqual(findings[0].severity, 'HIGH');
  assert.strictEqual(findings[1].severity, 'MEDIUM');
  assert.strictEqual(findings[2].severity, 'LOW');
  assert.strictEqual(findings[3].severity, 'CRITICAL');
});

test('SoloditParser groupBySeverity', () => {
  const parser = new SoloditParser();
  const findings = parser.parseFindings([
    { severity: 'High', title: 'A' },
    { severity: 'High', title: 'B' },
    { severity: 'Medium', title: 'C' }
  ]);
  const grouped = parser.groupBySeverity(findings);
  assert.strictEqual(grouped.HIGH.length, 2);
  assert.strictEqual(grouped.MEDIUM.length, 1);
});

// Tool Runner Tests
console.log('\nTool Runners:');

test('SlitherRunner instantiation', () => {
  const runner = new SlitherRunner();
  assert(runner !== null);
  assert(typeof runner.analyze === 'function');
});

test('MythrilRunner instantiation', () => {
  const runner = new MythrilRunner();
  assert(runner !== null);
  assert(typeof runner.analyze === 'function');
});

test('AderynRunner instantiation', () => {
  const runner = new AderynRunner();
  assert(runner !== null);
  assert(typeof runner.analyze === 'function');
});

test('ToolRunner instantiation', () => {
  const runner = new ToolRunner();
  assert(runner !== null);
  assert(typeof runner.runAll === 'function');
  assert(typeof runner.quickScan === 'function');
});

test('ToolRunner formatResults - text', () => {
  const runner = new ToolRunner();
  const mockResults = {
    target: './test',
    timestamp: new Date().toISOString(),
    combined: {
      findings: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, gas: 0 }
    }
  };
  const output = runner.formatResults(mockResults, 'text');
  assert(output.includes('Security Analysis Report'));
});

test('ToolRunner formatResults - markdown', () => {
  const runner = new ToolRunner();
  const mockResults = {
    target: './test',
    timestamp: new Date().toISOString(),
    combined: {
      findings: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, gas: 0 }
    }
  };
  const output = runner.formatResults(mockResults, 'markdown');
  assert(output.includes('# Security Analysis Report'));
});

// Database Tests
console.log('\nFinding Database:');

const testDbPath = path.join(__dirname, 'test-findings.json');

test('FindingDatabase instantiation (JSON mode)', () => {
  const db = new FindingDatabase(testDbPath);
  assert(db !== null);
  assert(db.useJson === true); // Falls back to JSON without better-sqlite3
});

testAsync('FindingDatabase CRUD operations', async () => {
  const db = new FindingDatabase(testDbPath);
  await db.init();
  
  // Create project
  const projectId = db.createProject({
    name: 'Test Project',
    path: '/test/path',
    type: 'foundry'
  });
  assert(projectId > 0);
  
  // Start audit
  const auditId = db.startAudit(projectId, 'Test Audit');
  assert(auditId > 0);
  
  // Add finding
  const findingId = db.addFinding({
    audit_id: auditId,
    project_id: projectId,
    title: 'Test Finding',
    severity: 'HIGH',
    description: 'Test description',
    source: 'test'
  });
  assert(findingId > 0);
  
  // Query findings
  const findings = db.queryFindings({ project_id: projectId });
  assert(findings.length === 1);
  assert.strictEqual(findings[0].title, 'Test Finding');
  
  // Get stats
  const stats = db.getStats({ project_id: projectId });
  assert.strictEqual(stats.total, 1);
  assert.strictEqual(stats.bySeverity.high, 1);
  
  // Mark as fixed
  db.markFixed(findingId, 'Fixed in test');
  const updated = db.getFinding(findingId);
  assert.strictEqual(updated.status, 'fixed');
  
  // Clean up
  db.reset();
  db.close();
  
  // Remove test file
  if (fs.existsSync(testDbPath)) {
    fs.unlinkSync(testDbPath);
  }
});

testAsync('FindingDatabase tags', async () => {
  const db = new FindingDatabase(testDbPath);
  await db.init();
  
  const projectId = db.createProject({ name: 'Tag Test', path: '/tag/test' });
  const findingId = db.addFinding({
    project_id: projectId,
    title: 'Tagged Finding',
    severity: 'MEDIUM'
  });
  
  db.addTags(findingId, ['reentrancy', 'critical-path']);
  const finding = db.getFinding(findingId);
  assert(finding.tags.includes('reentrancy'));
  assert(finding.tags.includes('critical-path'));
  
  db.reset();
  db.close();
  
  if (fs.existsSync(testDbPath)) {
    fs.unlinkSync(testDbPath);
  }
});

// Project Detector Tests
console.log('\nProject Detector:');

test('ProjectDetector instantiation', () => {
  const detector = new ProjectDetector();
  assert(detector !== null);
  assert(typeof detector.detect === 'function');
});

test('ProjectDetector has framework definitions', () => {
  const detector = new ProjectDetector();
  assert(detector.frameworks.foundry !== undefined);
  assert(detector.frameworks.hardhat !== undefined);
  assert(detector.frameworks.anchor !== undefined);
});

test('ProjectDetector getRecommendedTools for Ethereum', () => {
  const detector = new ProjectDetector();
  const tools = detector.getRecommendedTools({ ecosystem: 'ethereum' });
  assert(tools.some(t => t.name === 'slither'));
  assert(tools.some(t => t.name === 'aderyn'));
});

test('ProjectDetector getRecommendedTools for Solana', () => {
  const detector = new ProjectDetector();
  const tools = detector.getRecommendedTools({ ecosystem: 'solana' });
  assert(tools.some(t => t.name === 'anchor-test'));
});

// Summary
console.log('\n=== Test Summary ===');
console.log(`Passed: ${results.passed}`);
console.log(`Failed: ${results.failed}`);
console.log(`Total: ${results.passed + results.failed}`);

if (results.failed > 0) {
  console.log('\nFailed tests:');
  results.tests.filter(t => t.status === 'failed').forEach(t => {
    console.log(`  - ${t.name}: ${t.error}`);
  });
  process.exit(1);
}

console.log('\n✓ All tests passed!\n');

