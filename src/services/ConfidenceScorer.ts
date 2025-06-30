// This file will contain the ConfidenceScorer class
// Add necessary imports here
export class ConfidenceScorer {
  static scoreAIFindings(aiFindings, validationResults, sourceMetadata) {
    const scores = {
      sourceCredibility: this.scoreSourceCredibility(sourceMetadata),
      dataConsistency: this.scoreDataConsistency(aiFindings),
      validationAlignment: this.scoreValidationAlignment(aiFindings, validationResults),
      temporalConsistency: this.scoreTemporalConsistency(aiFindings),
      crossReferenceScore: this.scoreCrossReferences(aiFindings)
    };

    const weightedScore = (
      scores.sourceCredibility * 0.25 +
      scores.dataConsistency * 0.2 +
      scores.validationAlignment * 0.3 +
      scores.temporalConsistency * 0.15 +
      scores.crossReferenceScore * 0.1
    );

    return {
      overall: this.normalizeConfidence(weightedScore),
      breakdown: scores,
      recommendation: this.generateConfidenceRecommendation(weightedScore),
      flags: this.generateConfidenceFlags(scores, aiFindings)
    };
  }

  static scoreSourceCredibility(sourceMetadata) {
    const credibilityScores = {
      'CISA': 1.0,
      'NVD': 0.95,
      'MITRE': 0.9,
      'GitHub': 0.7,
      'Exploit-DB': 0.8,
      'vendor-official': 0.85,
      'security-research': 0.75,
      'ai-generated': 0.3
    };

    const sources = sourceMetadata?.discoveredSources || [];
    if (sources.length === 0) return 0.5;

    const avgCredibility = sources.reduce((sum, source) => {
      return sum + (credibilityScores[source] || 0.5);
    }, 0) / sources.length;

    return Math.min(avgCredibility, 1.0);
  }

  static scoreDataConsistency(aiFindings) {
    let consistencyScore = 1.0;

    // Check for logical inconsistencies
    if (aiFindings.cisaKev?.listed && !aiFindings.activeExploitation?.confirmed) {
      consistencyScore -= 0.2;
    }

    if ((aiFindings.exploitDiscovery?.totalCount || 0) > 10) {
      consistencyScore -= 0.3;
    }

    if (aiFindings.overallThreatLevel === 'LOW' && aiFindings.cisaKev?.listed) {
      consistencyScore -= 0.4;
    }

    return Math.max(consistencyScore, 0);
  }

  static scoreValidationAlignment(aiFindings, validationResults) {
    if (!validationResults) return 0.5;

    let alignmentScore = 1.0;
    let totalValidations = 0;

    // CISA KEV alignment - adjusted for AI web search validation
    if (validationResults.cisaKev) {
      totalValidations++;

      // For AI web search validation, consider high confidence + source as verification
      const aiWebSearchValid = validationResults.cisaKev.validationMethod === 'AI_WEB_SEARCH' &&
                               validationResults.cisaKev.confidence === 'HIGH' &&
                               validationResults.cisaKev.sourceProvided;

      if (!validationResults.cisaKev.verified && !aiWebSearchValid) {
        alignmentScore -= 0.3; // Reduced penalty for AI web search method
      }
    }

    // Exploit validation alignment
    if (validationResults.exploits) {
      totalValidations++;
      if (!validationResults.exploits.verified) {
        alignmentScore -= 0.3;
      }
    }

    // Vendor advisory alignment
    if (validationResults.vendorAdvisories) {
      totalValidations++;
      if (!validationResults.vendorAdvisories.verified) {
        alignmentScore -= 0.2;
      }
    }

    return totalValidations > 0 ? Math.max(alignmentScore, 0) : 0.5;
  }

  static scoreTemporalConsistency(aiFindings) {
    const now = new Date();
    let temporalScore = 1.0;

    // Unrealistic future dates
    if (aiFindings.cisaKev?.dueDate) {
      const dueDate = new Date(aiFindings.cisaKev.dueDate);
      if (dueDate > new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000)) {
        temporalScore -= 0.3;
      }
    }

    return temporalScore;
  }

  static scoreCrossReferences(aiFindings) {
    let crossRefScore = 0.5;

    if (aiFindings.cisaKev?.listed && aiFindings.activeExploitation?.confirmed) {
      crossRefScore += 0.3;
    }

    if (aiFindings.exploitDiscovery?.found && aiFindings.activeExploitation?.confirmed) {
      crossRefScore += 0.2;
    }

    return Math.min(crossRefScore, 1.0);
  }

  static normalizeConfidence(score) {
    if (score >= 0.8) return 'HIGH';
    if (score >= 0.6) return 'MEDIUM';
    if (score >= 0.4) return 'LOW';
    return 'VERY_LOW';
  }

  static generateConfidenceRecommendation(score) {
    if (score >= 0.8) {
      return 'High confidence - findings likely accurate';
    } else if (score >= 0.6) {
      return 'Medium confidence - verify critical claims';
    } else if (score >= 0.4) {
      return 'Low confidence - manual verification required';
    } else {
      return 'Very low confidence - treat as unverified intelligence';
    }
  }

  static generateConfidenceFlags(scores, aiFindings) {
    const flags = [];

    if (scores.sourceCredibility < 0.5) {
      flags.push('LOW_SOURCE_CREDIBILITY');
    }

    if (scores.dataConsistency < 0.7) {
      flags.push('DATA_INCONSISTENCY');
    }

    if (scores.validationAlignment < 0.6) {
      flags.push('VALIDATION_MISMATCH');
    }

    if (aiFindings.intelligenceSummary?.analysisMethod === 'ADVANCED_HEURISTICS') {
      flags.push('HEURISTIC_ANALYSIS');
    }

    if ((aiFindings.exploitDiscovery?.totalCount || 0) === 0 &&
        aiFindings.cisaKev?.listed) {
      flags.push('MISSING_EXPLOIT_DATA');
    }

    return flags;
  }
}
