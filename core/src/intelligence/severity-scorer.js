/**
 * Severity Scorer - Calculates CVSS-like severity scores for vulnerabilities
 * 
 * @module severity-scorer
 */

/**
 * CVSS v3.1 Base Score Calculator (simplified for smart contracts)
 */
const CVSS_WEIGHTS = {
  attackVector: {
    NETWORK: 0.85,      // Remote exploitation (default for SC)
    ADJACENT: 0.62,
    LOCAL: 0.55,
    PHYSICAL: 0.2
  },
  attackComplexity: {
    LOW: 0.77,          // Easy to exploit
    HIGH: 0.44          // Requires specific conditions
  },
  privilegesRequired: {
    NONE: 0.85,         // Anyone can exploit
    LOW: 0.62,          // Requires basic user
    HIGH: 0.27          // Requires admin/owner
  },
  userInteraction: {
    NONE: 0.85,         // No user action needed
    REQUIRED: 0.62      // Victim must take action
  },
  scope: {
    UNCHANGED: 1.0,     // Impact limited to contract
    CHANGED: 1.08       // Impact spreads to other components
  },
  impact: {
    NONE: 0,
    LOW: 0.22,
    HIGH: 0.56
  }
};

/**
 * Smart contract specific severity factors
 */
const SC_FACTORS = {
  // Fund exposure
  fundsAtRisk: {
    NONE: 0,
    LIMITED: 0.3,       // Bounded loss
    SIGNIFICANT: 0.6,   // Large but partial
    TOTAL: 1.0          // Complete drain possible
  },
  
  // Exploitation requirements
  flashLoanRequired: {
    YES: 0.9,           // Slightly easier
    NO: 1.0
  },
  
  // Time sensitivity
  timeWindow: {
    UNLIMITED: 1.0,     // Can exploit anytime
    BLOCK: 0.8,         // Must be in same block
    TRANSACTION: 0.7    // Must be in same tx
  },
  
  // Reversibility
  reversibility: {
    IRREVERSIBLE: 1.0,  // Permanent damage
    REVERSIBLE: 0.7     // Can be fixed
  }
};

/**
 * Severity Scorer class
 */
export class SeverityScorer {
  /**
   * Calculate severity score for a vulnerability
   * @param {Object} factors - Vulnerability characteristics
   * @returns {Object} Score and severity rating
   */
  calculate(factors) {
    const {
      attackVector = 'NETWORK',
      attackComplexity = 'LOW',
      privilegesRequired = 'NONE',
      userInteraction = 'NONE',
      scope = 'UNCHANGED',
      confidentialityImpact = 'NONE',
      integrityImpact = 'HIGH',
      availabilityImpact = 'LOW',
      fundsAtRisk = 'LIMITED',
      flashLoanRequired = 'NO',
      timeWindow = 'UNLIMITED',
      reversibility = 'IRREVERSIBLE'
    } = factors;

    // Calculate exploitability sub-score
    const exploitability = 8.22 *
      CVSS_WEIGHTS.attackVector[attackVector] *
      CVSS_WEIGHTS.attackComplexity[attackComplexity] *
      CVSS_WEIGHTS.privilegesRequired[privilegesRequired] *
      CVSS_WEIGHTS.userInteraction[userInteraction];

    // Calculate impact sub-score
    const impactBase = 1 - (
      (1 - CVSS_WEIGHTS.impact[confidentialityImpact]) *
      (1 - CVSS_WEIGHTS.impact[integrityImpact]) *
      (1 - CVSS_WEIGHTS.impact[availabilityImpact])
    );

    let impact;
    if (scope === 'UNCHANGED') {
      impact = 6.42 * impactBase;
    } else {
      impact = 7.52 * (impactBase - 0.029) - 3.25 * Math.pow(impactBase - 0.02, 15);
    }

    // Base CVSS score
    let baseScore;
    if (impact <= 0) {
      baseScore = 0;
    } else if (scope === 'UNCHANGED') {
      baseScore = Math.min(exploitability + impact, 10);
    } else {
      baseScore = Math.min(1.08 * (exploitability + impact), 10);
    }

    // Apply smart contract specific modifiers
    const scModifier = 
      SC_FACTORS.fundsAtRisk[fundsAtRisk] *
      SC_FACTORS.flashLoanRequired[flashLoanRequired] *
      SC_FACTORS.timeWindow[timeWindow] *
      SC_FACTORS.reversibility[reversibility];

    // Final score (weighted average)
    const finalScore = Math.round((baseScore * 0.7 + scModifier * 10 * 0.3) * 10) / 10;

    return {
      score: Math.min(finalScore, 10),
      severity: this._getSeverityRating(finalScore),
      exploitability: Math.round(exploitability * 10) / 10,
      impact: Math.round(impact * 10) / 10,
      scModifier: Math.round(scModifier * 100) / 100,
      factors
    };
  }

  /**
   * Quick severity estimation from vulnerability type
   * @param {string} vulnType - Vulnerability type
   * @returns {Object} Estimated severity
   */
  estimateFromType(vulnType) {
    const presets = {
      'reentrancy': {
        attackComplexity: 'LOW',
        privilegesRequired: 'NONE',
        integrityImpact: 'HIGH',
        fundsAtRisk: 'TOTAL',
        reversibility: 'IRREVERSIBLE'
      },
      'oracle-manipulation': {
        attackComplexity: 'HIGH',
        privilegesRequired: 'NONE',
        integrityImpact: 'HIGH',
        fundsAtRisk: 'SIGNIFICANT',
        flashLoanRequired: 'YES'
      },
      'access-control': {
        attackComplexity: 'LOW',
        privilegesRequired: 'NONE',
        integrityImpact: 'HIGH',
        fundsAtRisk: 'TOTAL',
        reversibility: 'IRREVERSIBLE'
      },
      'integer-overflow': {
        attackComplexity: 'HIGH',
        privilegesRequired: 'NONE',
        integrityImpact: 'HIGH',
        fundsAtRisk: 'SIGNIFICANT'
      },
      'front-running': {
        attackComplexity: 'HIGH',
        privilegesRequired: 'NONE',
        integrityImpact: 'LOW',
        fundsAtRisk: 'LIMITED'
      },
      'dos': {
        attackComplexity: 'LOW',
        privilegesRequired: 'NONE',
        availabilityImpact: 'HIGH',
        integrityImpact: 'NONE',
        fundsAtRisk: 'NONE'
      }
    };

    const preset = presets[vulnType.toLowerCase()] || {};
    return this.calculate(preset);
  }

  /**
   * Get severity rating from score
   * @private
   */
  _getSeverityRating(score) {
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score >= 0.1) return 'Low';
    return 'Informational';
  }
}

/**
 * Convenience function for quick severity calculation
 * @param {Object} factors - Vulnerability characteristics
 * @returns {Object} Score and severity rating
 */
export function calculateSeverity(factors) {
  const scorer = new SeverityScorer();
  return scorer.calculate(factors);
}

export default SeverityScorer;
