/**
 * Intelligence Module Tests
 * 
 * Run with: node tests/intelligence.test.js
 */

const assert = require('assert');
const path = require('path');

// Import modules
const { 
  PatternMatcher, 
  SeverityScorer, 
  SemanticSearch, 
  VulnerabilityClassifier 
} = require('../src/intelligence');

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

// Sample Solidity code for testing
const sampleVulnerableCode = `
pragma solidity ^0.8.0;

contract Vulnerable {
    mapping(address => uint256) public balances;
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        
        // Vulnerable: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        
        balances[msg.sender] -= amount;
    }
    
    function unsafeAuth() external {
        require(tx.origin == msg.sender);
    }
    
    function uncheckedMath() external pure returns (uint256) {
        unchecked {
            return 1 - 2;
        }
    }
}
`;

const sampleSafeCode = `
pragma solidity 0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Safe is ReentrancyGuard {
    mapping(address => uint256) public balances;
    
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
`;

// ==================== Tests ====================

console.log('\n=== Intelligence Module Tests ===\n');

// Pattern Matcher Tests
console.log('Pattern Matcher:');

test('PatternMatcher instantiation', () => {
  const matcher = new PatternMatcher();
  assert(matcher !== null);
  assert(typeof matcher.analyze === 'function');
});

test('PatternMatcher detects reentrancy', () => {
  const matcher = new PatternMatcher();
  const findings = matcher.analyze(sampleVulnerableCode, 'solidity');
  const reentrancy = findings.find(f => f.category === 'reentrancy');
  assert(reentrancy !== undefined, 'Should detect reentrancy');
});

test('PatternMatcher detects tx.origin', () => {
  const matcher = new PatternMatcher();
  const findings = matcher.analyze(sampleVulnerableCode, 'solidity');
  const txOrigin = findings.find(f => f.id === 'tx-origin-auth');
  assert(txOrigin !== undefined, 'Should detect tx.origin usage');
});

test('PatternMatcher detects unchecked arithmetic', () => {
  const matcher = new PatternMatcher();
  const findings = matcher.analyze(sampleVulnerableCode, 'solidity');
  const unchecked = findings.find(f => f.id === 'integer-overflow-unchecked');
  assert(unchecked !== undefined, 'Should detect unchecked block');
});

test('PatternMatcher filters by severity', () => {
  const matcher = new PatternMatcher();
  const findings = matcher.analyze(sampleVulnerableCode, 'solidity', {
    severity: ['CRITICAL', 'HIGH']
  });
  const lowSeverity = findings.find(f => f.severity === 'LOW' || f.severity === 'MEDIUM');
  assert(lowSeverity === undefined, 'Should not include low/medium severity');
});

test('PatternMatcher includes line numbers', () => {
  const matcher = new PatternMatcher();
  const findings = matcher.analyze(sampleVulnerableCode, 'solidity');
  assert(findings.every(f => typeof f.line === 'number'), 'All findings should have line numbers');
});

test('PatternMatcher has Rust patterns', () => {
  const matcher = new PatternMatcher();
  const patterns = matcher.getPatterns('rust');
  assert(patterns.length > 0, 'Should have Rust patterns');
});

test('PatternMatcher has Move patterns', () => {
  const matcher = new PatternMatcher();
  const patterns = matcher.getPatterns('move');
  assert(patterns.length > 0, 'Should have Move patterns');
});

// Severity Scorer Tests
console.log('\nSeverity Scorer:');

test('SeverityScorer instantiation', () => {
  const scorer = new SeverityScorer();
  assert(scorer !== null);
  assert(typeof scorer.calculateScore === 'function');
});

test('SeverityScorer calculates score', () => {
  const scorer = new SeverityScorer();
  const finding = {
    severity: 'HIGH',
    category: 'reentrancy',
    description: 'Attacker can steal funds through reentrancy'
  };
  const result = scorer.calculateScore(finding);
  assert(result.score >= 0 && result.score <= 10, 'Score should be 0-10');
  assert(result.breakdown !== undefined, 'Should include breakdown');
});

test('SeverityScorer adjusts based on context', () => {
  const scorer = new SeverityScorer();
  const finding = {
    severity: 'MEDIUM',
    category: 'oracle',
    description: 'Price manipulation possible'
  };
  
  const highTvlScore = scorer.calculateScore(finding, { tvl: 200000000 });
  const lowTvlScore = scorer.calculateScore(finding, { tvl: 1000000 });
  
  assert(highTvlScore.score > lowTvlScore.score, 'High TVL should increase score');
});

test('SeverityScorer batch scoring', () => {
  const scorer = new SeverityScorer();
  const findings = [
    { severity: 'HIGH', category: 'reentrancy' },
    { severity: 'MEDIUM', category: 'oracle' }
  ];
  const scored = scorer.scoreFindings(findings);
  assert(scored.every(f => f.score !== undefined), 'All should have scores');
});

test('SeverityScorer risk summary', () => {
  const scorer = new SeverityScorer();
  const scoredFindings = [
    { severity: 'HIGH', category: 'reentrancy', score: 8.5, adjustedSeverity: 'HIGH' },
    { severity: 'MEDIUM', category: 'oracle', score: 5.0, adjustedSeverity: 'MEDIUM' }
  ];
  const summary = scorer.getRiskSummary(scoredFindings);
  assert(summary.overallRisk !== undefined);
  assert(summary.riskScore !== undefined);
});

// Semantic Search Tests
console.log('\nSemantic Search:');

test('SemanticSearch instantiation', () => {
  const search = new SemanticSearch();
  assert(search !== null);
  assert(typeof search.findSimilar === 'function');
});

test('SemanticSearch cosine similarity', () => {
  const search = new SemanticSearch();
  const vec1 = [1, 0, 0];
  const vec2 = [1, 0, 0];
  const vec3 = [0, 1, 0];
  
  assert.strictEqual(search.cosineSimilarity(vec1, vec2), 1, 'Same vectors should be 1');
  assert.strictEqual(search.cosineSimilarity(vec1, vec3), 0, 'Orthogonal should be 0');
});

testAsync('SemanticSearch generates embedding', async () => {
  const search = new SemanticSearch();
  const embedding = await search._generateEmbedding('reentrancy vulnerability');
  assert(Array.isArray(embedding), 'Should return array');
  assert(embedding.length === search.embeddingDimension, 'Should match dimension');
});

testAsync('SemanticSearch finds similar', async () => {
  const search = new SemanticSearch();
  const candidates = [
    { id: 1, text: 'Reentrancy attack in withdraw function' },
    { id: 2, text: 'Integer overflow in token transfer' },
    { id: 3, text: 'External call before state update allows reentrancy' }
  ];
  
  const results = await search.findSimilar('reentrancy vulnerability', candidates, { limit: 2 });
  assert(results.length <= 2, 'Should respect limit');
});

// Vulnerability Classifier Tests
console.log('\nVulnerability Classifier:');

test('VulnerabilityClassifier instantiation', () => {
  const classifier = new VulnerabilityClassifier();
  assert(classifier !== null);
  assert(typeof classifier.classify === 'function');
});

test('VulnerabilityClassifier classifies reentrancy', () => {
  const classifier = new VulnerabilityClassifier();
  const finding = {
    title: 'Reentrancy in withdraw function',
    description: 'External call before state update allows attacker to drain funds'
  };
  const result = classifier.classify(finding);
  assert.strictEqual(result.category, 'reentrancy');
  assert(result.attackVectors.includes('external-call'));
});

test('VulnerabilityClassifier maps SWC', () => {
  const classifier = new VulnerabilityClassifier();
  const finding = {
    title: 'Integer Overflow',
    description: 'Unchecked arithmetic can overflow'
  };
  const result = classifier.classify(finding);
  assert(result.swcId === 'SWC-101' || result.category === 'arithmetic');
});

test('VulnerabilityClassifier generates tags', () => {
  const classifier = new VulnerabilityClassifier();
  const finding = {
    title: 'Oracle Price Manipulation',
    severity: 'HIGH',
    description: 'Flash loan can manipulate spot price'
  };
  const result = classifier.classify(finding);
  assert(result.tags.length > 0, 'Should generate tags');
  assert(result.tags.includes('oracle') || result.tags.includes('high'));
});

test('VulnerabilityClassifier batch classification', () => {
  const classifier = new VulnerabilityClassifier();
  const findings = [
    { title: 'Reentrancy', description: 'External call before state' },
    { title: 'Access Control', description: 'Missing owner check' }
  ];
  const classified = classifier.classifyAll(findings);
  assert(classified.every(f => f.classification !== undefined));
});

test('VulnerabilityClassifier has taxonomy', () => {
  const classifier = new VulnerabilityClassifier();
  const taxonomy = classifier.getTaxonomy();
  assert(taxonomy.reentrancy !== undefined);
  assert(taxonomy['access-control'] !== undefined);
  assert(taxonomy.oracle !== undefined);
});

test('VulnerabilityClassifier search', () => {
  const classifier = new VulnerabilityClassifier();
  const findings = [
    { title: 'A', classification: { category: 'reentrancy', attackVectors: ['external-call'], impact: [], tags: [] } },
    { title: 'B', classification: { category: 'oracle', attackVectors: ['flash-loan'], impact: [], tags: [] } }
  ];
  const results = classifier.search(findings, { category: 'reentrancy' });
  assert.strictEqual(results.length, 1);
  assert.strictEqual(results[0].title, 'A');
});

test('VulnerabilityClassifier statistics', () => {
  const classifier = new VulnerabilityClassifier();
  const findings = [
    { classification: { category: 'reentrancy', attackVectors: ['external-call'], impact: ['funds-theft'] } },
    { classification: { category: 'reentrancy', attackVectors: ['external-call'], impact: ['funds-theft'] } },
    { classification: { category: 'oracle', attackVectors: ['flash-loan'], impact: ['funds-theft'] } }
  ];
  const stats = classifier.getStatistics(findings);
  assert.strictEqual(stats.byCategory.reentrancy, 2);
  assert.strictEqual(stats.byCategory.oracle, 1);
});

// Integration Test
console.log('\nIntegration:');

testAsync('Full pipeline: Pattern -> Score -> Classify', async () => {
  const matcher = new PatternMatcher();
  const scorer = new SeverityScorer();
  const classifier = new VulnerabilityClassifier();
  
  // 1. Find patterns
  let findings = matcher.analyze(sampleVulnerableCode, 'solidity');
  assert(findings.length > 0, 'Should find patterns');
  
  // 2. Score findings
  findings = scorer.scoreFindings(findings);
  assert(findings.every(f => f.score !== undefined), 'Should have scores');
  
  // 3. Classify findings
  findings = classifier.classifyAll(findings);
  assert(findings.every(f => f.classification !== undefined), 'Should have classifications');
  
  // Check complete finding
  const finding = findings[0];
  assert(finding.id !== undefined);
  assert(finding.severity !== undefined);
  assert(finding.score !== undefined);
  assert(finding.classification.category !== undefined);
});

// Summary
setTimeout(() => {
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

  console.log('\n✓ All intelligence tests passed!\n');
}, 100);

