/**
 * Web3 Audit Skills - Intelligence Module
 * 
 * Core exports for pattern matching, severity scoring, and vulnerability classification.
 * Used by the MCP server for real-time AI-assisted auditing.
 */

export { PatternMatcher, matchPatternToCode } from './intelligence/pattern-matcher.js';
export { SeverityScorer, calculateSeverity } from './intelligence/severity-scorer.js';
export { VulnerabilityClassifier, classifyVulnerability } from './intelligence/vulnerability-classifier.js';
export { SemanticSearch, searchPatterns } from './intelligence/semantic-search.js';

// Default export for convenience
export default {
  PatternMatcher,
  SeverityScorer,
  VulnerabilityClassifier,
  SemanticSearch
};
