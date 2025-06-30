// Assuming ConfidenceScorer class definition was part of the 'master' branch conflict
// and is being extracted here. If its definition is not found in the prior conflict,
// this file will need to be populated with its actual code.

export class ConfidenceScorer {
  static scoreAIFindings(aiFindings, validationResults, sourceMetadata) {
    const scores = {
      // @ts-ignore
      sourceCredibility: this.scoreSourceCredibility(sourceMetadata),
      // @ts-ignore
      dataConsistency: this.scoreDataConsistency(aiFindings),
      // @ts-ignore
      validationAlignment: this.scoreValidationAlignment(aiFindings, validationResults),
      // @ts-ignore
      temporalConsistency: this.scoreTemporalConsistency(aiFindings),
      // @ts-ignore
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
      // @ts-ignore
      overall: this.normalizeConfidence(weightedScore),
      breakdown: scores,
      // @ts-ignore
      recommendation: this.generateConfidenceRecommendation(weightedScore),
      // @ts-ignore
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
      // @ts-ignore
      return sum + (credibilityScores[source] || 0.5);
    }, 0) / sources.length;

    return Math.min(avgCredibility, 1.0);
  }

  static scoreDataConsistency(aiFindings) {
    let consistencyScore = 1.0;

    if (aiFindings.cisaKev?.listed && !aiFindings.activeExploitation?.confirmed) {
      consistencyScore -= 0.2;
    }

    if ((aiFindings.exploitDiscovery?.totalCount || 0) > 10 && (aiFindings.exploitDiscovery?.totalCount || 0) < 50) { // Adjusted condition
      consistencyScore -= 0.1; // Reduced penalty for moderately high exploit count
    } else if ((aiFindings.exploitDiscovery?.totalCount || 0) >= 50) {
      consistencyScore -= 0.3; // Keep higher penalty for very high counts
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

    if (validationResults.cisaKev) {
      totalValidations++;
      const aiWebSearchValid = validationResults.cisaKev.validationMethod === 'AI_WEB_SEARCH' &&
                               validationResults.cisaKev.confidence === 'HIGH' &&
                               validationResults.cisaKev.sourceProvided;
      if (!validationResults.cisaKev.verified && !aiWebSearchValid) {
        alignmentScore -= 0.3;
      }
    }

    if (validationResults.exploits) {
      totalValidations++;
      if (!validationResults.exploits.verified) {
        alignmentScore -= 0.3;
      }
    }

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

    if (aiFindings.cisaKev?.dueDate) {
      try {
        const dueDate = new Date(aiFindings.cisaKev.dueDate);
        // @ts-ignore
        if (isNaN(dueDate)) { // Check if dueDate is invalid
          temporalScore -= 0.1; // Penalize for invalid date format
        } else if (dueDate > new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000)) {
          temporalScore -= 0.3;
        }
      } catch (e) {
        temporalScore -= 0.1; // Penalize if date parsing fails
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
      return 'High confidence - findings likely accurate. Standard operational procedures recommended.';
    } else if (score >= 0.6) {
      return 'Medium confidence - verify critical claims before taking high-impact actions. Consider enhanced monitoring.';
    } else if (score >= 0.4) {
      return 'Low confidence - manual verification of all claims is required. Treat findings as preliminary intelligence.';
    } else {
      return 'Very low confidence - do not rely on findings without extensive manual verification from trusted sources.';
    }
  }

  static generateConfidenceFlags(scores, aiFindings) {
    const flags = [];

    if (scores.sourceCredibility < 0.5) {
      flags.push('LOW_SOURCE_CREDIBILITY');
    }
    if (scores.dataConsistency < 0.7) {
      flags.push('POTENTIAL_DATA_INCONSISTENCY');
    }
    if (scores.validationAlignment < 0.6) {
      flags.push('VALIDATION_MISMATCH_DETECTED');
    }
    if (aiFindings.intelligenceSummary?.analysisMethod === 'ADVANCED_HEURISTICS') {
      flags.push('HEURISTIC_ANALYSIS_FALLBACK');
    }
    if ((aiFindings.exploitDiscovery?.totalCount || 0) === 0 && aiFindings.cisaKev?.listed && aiFindings.activeExploitation?.confirmed) {
      flags.push('MISSING_EXPLOIT_DETAILS_DESPITE_KEV_AND_ACTIVE_EXPLOITATION');
    }
     if ((aiFindings.exploitDiscovery?.totalCount || 0) > 10 && (aiFindings.exploitDiscovery?.totalCount || 0) < 50) {
      flags.push('HIGH_NUMBER_OF_POTENTIAL_EXPLOITS_REPORTED');
    } else if ((aiFindings.exploitDiscovery?.totalCount || 0) >= 50) {
      flags.push('VERY_HIGH_NUMBER_OF_POTENTIAL_EXPLOITS_REPORTED');
    }

    return flags;
  }
}
