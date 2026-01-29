/**
 * Severity Scorer
 * 
 * Algorithmic severity scoring based on impact, likelihood, and context.
 * Uses CVSS-like scoring adapted for smart contract vulnerabilities.
 * 
 * Usage:
 *   const scorer = new SeverityScorer();
 *   const score = scorer.calculateScore(finding, context);
 */

class SeverityScorer {
  constructor() {
    // Base scores for each severity level
    this.baseSeverityScores = {
      CRITICAL: 9.5,
      HIGH: 7.5,
      MEDIUM: 5.0,
      LOW: 2.5,
      INFO: 1.0,
      GAS: 0.5
    };

    // Impact weights
    this.impactWeights = {
      fundsAtRisk: 3.0,
      accessControl: 2.5,
      dataIntegrity: 2.0,
      availability: 1.5,
      governance: 2.0,
      gasEfficiency: 0.5
    };

    // Likelihood modifiers
    this.likelihoodModifiers = {
      alwaysExploitable: 1.0,
      requiresSpecificConditions: 0.7,
      requiresPrivilegedAccess: 0.5,
      theoreticalOnly: 0.3,
      unlikelyInPractice: 0.2
    };

    // Context modifiers
    this.contextModifiers = {
      // Protocol type
      defi: 1.2,
      nft: 0.9,
      dao: 1.1,
      bridge: 1.5,
      oracle: 1.3,
      general: 1.0,

      // TVL ranges
      highTvl: 1.3,      // >$100M
      mediumTvl: 1.1,    // $10M-$100M
      lowTvl: 0.9,       // <$10M

      // Code maturity
      production: 1.2,
      testnet: 0.8,
      development: 0.6,

      // Audit status
      unaudited: 1.3,
      previouslyAudited: 0.9,
      multipleAudits: 0.8
    };

    // Category-specific base impacts
    this.categoryImpacts = {
      'reentrancy': { fundsAtRisk: 1.0, accessControl: 0.3 },
      'access-control': { accessControl: 1.0, fundsAtRisk: 0.7 },
      'arithmetic': { fundsAtRisk: 0.8, dataIntegrity: 0.5 },
      'oracle': { fundsAtRisk: 0.9, dataIntegrity: 0.6 },
      'flash-loan': { fundsAtRisk: 0.9, availability: 0.3 },
      'front-running': { fundsAtRisk: 0.7, dataIntegrity: 0.4 },
      'timestamp': { dataIntegrity: 0.6, fundsAtRisk: 0.4 },
      'centralization': { governance: 0.9, accessControl: 0.5 },
      'validation': { dataIntegrity: 0.7, fundsAtRisk: 0.5 },
      'unchecked-return': { fundsAtRisk: 0.6, dataIntegrity: 0.4 },
      'gas-optimization': { gasEfficiency: 1.0 },
      'best-practice': { dataIntegrity: 0.3 },
      'code-quality': { dataIntegrity: 0.2 }
    };
  }

  /**
   * Calculate comprehensive severity score
   * 
   * @param {Object} finding - The vulnerability finding
   * @param {Object} context - Context information (protocol type, TVL, etc.)
   * @returns {Object} Detailed score breakdown
   */
  calculateScore(finding, context = {}) {
    // Get base score from severity
    const baseSeverity = this.baseSeverityScores[finding.severity] || 5.0;

    // Calculate impact score
    const impactScore = this._calculateImpactScore(finding);

    // Calculate likelihood score
    const likelihoodScore = this._calculateLikelihoodScore(finding);

    // Calculate context modifier
    const contextModifier = this._calculateContextModifier(context);

    // Calculate confidence adjustment
    const confidenceAdjustment = finding.confidence || 0.8;

    // Combined score formula
    // Base * (0.4 * Impact + 0.3 * Likelihood + 0.3 * Context) * Confidence
    const rawScore = baseSeverity * (
      0.4 * (impactScore / 10) +
      0.3 * likelihoodScore +
      0.3 * contextModifier
    ) * confidenceAdjustment;

    // Normalize to 0-10 scale
    const finalScore = Math.min(10, Math.max(0, rawScore));

    // Determine final severity level
    const adjustedSeverity = this._scoreToSeverity(finalScore);

    return {
      score: Math.round(finalScore * 10) / 10,
      originalSeverity: finding.severity,
      adjustedSeverity,
      severityChanged: finding.severity !== adjustedSeverity,
      breakdown: {
        baseSeverity,
        impactScore: Math.round(impactScore * 10) / 10,
        likelihoodScore: Math.round(likelihoodScore * 100) / 100,
        contextModifier: Math.round(contextModifier * 100) / 100,
        confidenceAdjustment
      },
      recommendations: this._getScoreRecommendations(finding, finalScore)
    };
  }

  /**
   * Calculate impact score based on vulnerability category
   * @private
   */
  _calculateImpactScore(finding) {
    const categoryImpact = this.categoryImpacts[finding.category] || {};
    let totalImpact = 0;
    let maxImpact = 0;

    for (const [impactType, weight] of Object.entries(this.impactWeights)) {
      const categoryWeight = categoryImpact[impactType] || 0;
      totalImpact += categoryWeight * weight;
      maxImpact += weight;
    }

    // Additional impact factors from finding details
    if (finding.description) {
      const desc = finding.description.toLowerCase();
      
      // Boost for certain keywords
      if (desc.includes('steal') || desc.includes('drain')) totalImpact *= 1.2;
      if (desc.includes('lock') || desc.includes('freeze')) totalImpact *= 1.1;
      if (desc.includes('bypass')) totalImpact *= 1.15;
      if (desc.includes('arbitrary')) totalImpact *= 1.2;
    }

    // Normalize to 0-10 scale
    return (totalImpact / maxImpact) * 10;
  }

  /**
   * Calculate likelihood score
   * @private
   */
  _calculateLikelihoodScore(finding) {
    let likelihood = 0.5; // Default medium likelihood

    // Adjust based on category
    const highLikelihoodCategories = ['reentrancy', 'access-control', 'arithmetic'];
    const lowLikelihoodCategories = ['front-running', 'timestamp', 'centralization'];

    if (highLikelihoodCategories.includes(finding.category)) {
      likelihood = 0.8;
    } else if (lowLikelihoodCategories.includes(finding.category)) {
      likelihood = 0.4;
    }

    // Adjust based on confidence
    if (finding.confidence) {
      likelihood *= (0.5 + finding.confidence * 0.5);
    }

    // Adjust based on description keywords
    if (finding.description) {
      const desc = finding.description.toLowerCase();
      
      if (desc.includes('anyone can')) likelihood *= 1.3;
      if (desc.includes('attacker')) likelihood *= 1.2;
      if (desc.includes('requires admin') || desc.includes('requires owner')) likelihood *= 0.6;
      if (desc.includes('edge case')) likelihood *= 0.7;
      if (desc.includes('theoretical')) likelihood *= 0.5;
    }

    return Math.min(1.0, likelihood);
  }

  /**
   * Calculate context modifier based on project context
   * @private
   */
  _calculateContextModifier(context) {
    let modifier = 1.0;

    // Protocol type
    if (context.protocolType && this.contextModifiers[context.protocolType]) {
      modifier *= this.contextModifiers[context.protocolType];
    }

    // TVL
    if (context.tvl) {
      if (context.tvl > 100000000) {
        modifier *= this.contextModifiers.highTvl;
      } else if (context.tvl > 10000000) {
        modifier *= this.contextModifiers.mediumTvl;
      } else {
        modifier *= this.contextModifiers.lowTvl;
      }
    }

    // Code maturity
    if (context.maturity && this.contextModifiers[context.maturity]) {
      modifier *= this.contextModifiers[context.maturity];
    }

    // Audit status
    if (context.auditStatus && this.contextModifiers[context.auditStatus]) {
      modifier *= this.contextModifiers[context.auditStatus];
    }

    // Normalize modifier to reasonable range
    return Math.min(1.5, Math.max(0.5, modifier));
  }

  /**
   * Convert numeric score to severity level
   * @private
   */
  _scoreToSeverity(score) {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score >= 2.0) return 'LOW';
    if (score >= 1.0) return 'INFO';
    return 'GAS';
  }

  /**
   * Get recommendations based on score
   * @private
   */
  _getScoreRecommendations(finding, score) {
    const recommendations = [];

    if (score >= 9.0) {
      recommendations.push('IMMEDIATE: This issue requires immediate attention before deployment');
      recommendations.push('Consider halting deployment until resolved');
    } else if (score >= 7.0) {
      recommendations.push('HIGH PRIORITY: Fix before mainnet deployment');
      recommendations.push('Add comprehensive test coverage for this scenario');
    } else if (score >= 4.0) {
      recommendations.push('Should be addressed in next release');
      recommendations.push('Document any accepted risks');
    } else if (score >= 2.0) {
      recommendations.push('Consider fixing for code quality');
      recommendations.push('May be acceptable with documentation');
    }

    // Category-specific recommendations
    if (finding.category === 'reentrancy') {
      recommendations.push('Consider using ReentrancyGuard from OpenZeppelin');
      recommendations.push('Follow checks-effects-interactions pattern');
    } else if (finding.category === 'oracle') {
      recommendations.push('Use time-weighted average prices (TWAP)');
      recommendations.push('Add circuit breakers for extreme price movements');
    } else if (finding.category === 'access-control') {
      recommendations.push('Implement role-based access control');
      recommendations.push('Consider multi-sig for critical functions');
    }

    return recommendations;
  }

  /**
   * Batch score multiple findings
   * 
   * @param {Array} findings - Array of findings
   * @param {Object} context - Context information
   * @returns {Array} Scored findings
   */
  scoreFindings(findings, context = {}) {
    return findings.map(finding => {
      const scoreResult = this.calculateScore(finding, context);
      return {
        ...finding,
        ...scoreResult
      };
    });
  }

  /**
   * Get risk summary for a set of findings
   * 
   * @param {Array} scoredFindings - Array of scored findings
   * @returns {Object} Risk summary
   */
  getRiskSummary(scoredFindings) {
    if (scoredFindings.length === 0) {
      return {
        overallRisk: 'LOW',
        riskScore: 0,
        summary: 'No vulnerabilities detected'
      };
    }

    // Calculate aggregate risk
    const scores = scoredFindings.map(f => f.score || 0);
    const maxScore = Math.max(...scores);
    const avgScore = scores.reduce((a, b) => a + b, 0) / scores.length;
    
    // Weighted combination (max matters more than average)
    const riskScore = maxScore * 0.7 + avgScore * 0.3;

    // Count by adjusted severity
    const counts = {
      critical: scoredFindings.filter(f => f.adjustedSeverity === 'CRITICAL').length,
      high: scoredFindings.filter(f => f.adjustedSeverity === 'HIGH').length,
      medium: scoredFindings.filter(f => f.adjustedSeverity === 'MEDIUM').length,
      low: scoredFindings.filter(f => f.adjustedSeverity === 'LOW').length
    };

    // Determine overall risk level
    let overallRisk;
    if (counts.critical > 0 || riskScore >= 9.0) {
      overallRisk = 'CRITICAL';
    } else if (counts.high > 0 || riskScore >= 7.0) {
      overallRisk = 'HIGH';
    } else if (counts.medium > 0 || riskScore >= 4.0) {
      overallRisk = 'MEDIUM';
    } else {
      overallRisk = 'LOW';
    }

    return {
      overallRisk,
      riskScore: Math.round(riskScore * 10) / 10,
      maxScore: Math.round(maxScore * 10) / 10,
      avgScore: Math.round(avgScore * 10) / 10,
      counts,
      summary: this._generateRiskSummary(overallRisk, counts, scoredFindings.length)
    };
  }

  /**
   * Generate risk summary text
   * @private
   */
  _generateRiskSummary(overallRisk, counts, total) {
    const parts = [];

    if (counts.critical > 0) {
      parts.push(`${counts.critical} critical issue${counts.critical > 1 ? 's' : ''}`);
    }
    if (counts.high > 0) {
      parts.push(`${counts.high} high severity issue${counts.high > 1 ? 's' : ''}`);
    }
    if (counts.medium > 0) {
      parts.push(`${counts.medium} medium severity issue${counts.medium > 1 ? 's' : ''}`);
    }

    if (parts.length === 0) {
      return `Found ${total} low severity or informational issues.`;
    }

    return `Found ${parts.join(', ')} out of ${total} total findings. Overall risk: ${overallRisk}.`;
  }

  /**
   * Compare two vulnerabilities for priority
   * 
   * @param {Object} a - First finding (scored)
   * @param {Object} b - Second finding (scored)
   * @returns {number} Comparison result (-1, 0, 1)
   */
  comparePriority(a, b) {
    // First compare by score
    if (a.score !== b.score) {
      return b.score - a.score; // Higher score first
    }

    // Then by likelihood
    if (a.breakdown?.likelihoodScore !== b.breakdown?.likelihoodScore) {
      return (b.breakdown?.likelihoodScore || 0) - (a.breakdown?.likelihoodScore || 0);
    }

    // Then by confidence
    return (b.confidence || 0) - (a.confidence || 0);
  }
}

module.exports = SeverityScorer;
