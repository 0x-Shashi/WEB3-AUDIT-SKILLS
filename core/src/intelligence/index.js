/**
 * Intelligence Module Exports
 * 
 * Advanced analysis capabilities for smart contract security.
 */

const PatternMatcher = require('./pattern-matcher');
const SeverityScorer = require('./severity-scorer');
const SemanticSearch = require('./semantic-search');
const VulnerabilityClassifier = require('./vulnerability-classifier');

module.exports = {
  PatternMatcher,
  SeverityScorer,
  SemanticSearch,
  VulnerabilityClassifier
};

