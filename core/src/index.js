/**
 * Web3 Audit Core Module
 * 
 * Main entry point for the Web3 Security Audit System.
 * 
 * Usage:
 *   const { SoloditClient, ToolRunner, FindingDatabase } = require('@web3audit/core');
 *   
 *   // Search Solodit
 *   const client = new SoloditClient();
 *   const findings = await client.searchFindings('reentrancy');
 *   
 *   // Run analysis
 *   const runner = new ToolRunner();
 *   const results = await runner.runAll('./contracts');
 *   
 *   // Store findings
 *   const db = new FindingDatabase();
 *   await db.init();
 *   db.addFinding(finding);
 *   
 *   // Intelligence layer
 *   const matcher = new PatternMatcher();
 *   const vulns = matcher.analyze(code, 'solidity');
 */

// API clients
const { SoloditClient, SoloditParser } = require('./api');

// Analysis tools
const { 
  SlitherRunner, 
  MythrilRunner, 
  AderynRunner, 
  ToolRunner 
} = require('./tools');

// Database
const { FindingDatabase } = require('./db');

// Intelligence
const {
  PatternMatcher,
  SeverityScorer,
  SemanticSearch,
  VulnerabilityClassifier
} = require('./intelligence');

// Utilities
const ProjectDetector = require('./utils/project-detector');

// Export everything
module.exports = {
  // API
  SoloditClient,
  SoloditParser,
  
  // Tools
  SlitherRunner,
  MythrilRunner,
  AderynRunner,
  ToolRunner,
  
  // Database
  FindingDatabase,
  
  // Intelligence
  PatternMatcher,
  SeverityScorer,
  SemanticSearch,
  VulnerabilityClassifier,
  
  // Utilities
  ProjectDetector,
  
  // Version
  version: require('../package.json').version
};

