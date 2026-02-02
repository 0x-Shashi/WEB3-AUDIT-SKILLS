/**
 * Intelligence Module - Index
 * 
 * Exports all intelligence components for the MCP server.
 */

export { PatternMatcher, matchPatternToCode } from './pattern-matcher.js';
export { SeverityScorer, calculateSeverity } from './severity-scorer.js';
export { VulnerabilityClassifier, classifyVulnerability } from './vulnerability-classifier.js';
export { SemanticSearch, searchPatterns } from './semantic-search.js';
