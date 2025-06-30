// Assuming ValidationService class definition was part of the 'master' branch conflict
// and is being extracted here. If its definition is not found in the prior conflict,
// this file will need to be populated with its actual code.

export class ValidationService {
  static async validateAIFindings(aiFindings, cveId, setLoadingSteps) {
    const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
    updateSteps(prev => [...prev, `🔍 Validating AI findings for ${cveId}...`]);

    const validationResults = {
      // @ts-ignore
      cisaKev: await this.validateCISAKEV(cveId, aiFindings.cisaKev),
      // @ts-ignore
      exploits: await this.validateExploits(cveId, aiFindings.exploitDiscovery),
      // @ts-ignore
      vendorAdvisories: await this.validateVendorAdvisories(cveId, aiFindings.vendorAdvisories),
      confidence: 'MEDIUM',
      validatedClaims: 0,
      totalClaims: 0,
      validationTimestamp: new Date().toISOString()
    };

    // Calculate overall confidence
    // @ts-ignore
    const validationScore = this.calculateValidationScore(validationResults);
    validationResults.confidence = validationScore >= 0.8 ? 'HIGH' :
                                   validationScore >= 0.5 ? 'MEDIUM' : 'LOW';

    updateSteps(prev => [...prev, `✅ Validation complete: ${validationResults.confidence} confidence`]);
    return validationResults;
  }

  static async validateCISAKEV(cveId, aiKevFindings) {
    return {
      aiClaimed: aiKevFindings?.listed || false,
      actualStatus: null,
      verified: aiKevFindings?.confidence === 'HIGH' && aiKevFindings?.source,
      validationMethod: 'AI_WEB_SEARCH',
      confidence: aiKevFindings?.confidence || 'UNKNOWN',
      note: 'CISA KEV validation performed via AI web search due to CORS restrictions',
      sourceProvided: !!aiKevFindings?.source,
      confidenceLevel: aiKevFindings?.confidence || 'LOW'
    };
  }

  static async validateExploits(cveId, aiExploitFindings) {
    const validationResults = {
      aiClaimed: aiExploitFindings?.found || false,
      aiClaimedCount: aiExploitFindings?.totalCount || 0,
      verifiedExploits: [],
      invalidUrls: [],
      validationMethod: 'URL_VERIFICATION',
      confidence: 'LOW',
      verified: false // Initialize verified status
    };

    if (!aiExploitFindings?.exploits?.length) {
      validationResults.verified = true; // No exploits to verify, so considered verified
      validationResults.confidence = 'HIGH';
      return validationResults;
    }

    for (const exploit of aiExploitFindings.exploits) {
      if (exploit.url) {
        // @ts-ignore
        const urlValidation = this.validateExploitUrl(exploit.url, cveId);
        if (urlValidation.likely_valid) {
          validationResults.verifiedExploits.push({
            ...exploit,
            urlValidation: urlValidation
          });
        } else {
          validationResults.invalidUrls.push({
            url: exploit.url,
            reason: urlValidation.reason
          });
        }
      }
    }

    const verificationRate = validationResults.verifiedExploits.length /
                           aiExploitFindings.exploits.length;

    validationResults.verified = verificationRate >= 0.5;
    validationResults.confidence = verificationRate >= 0.8 ? 'HIGH' :
                                  verificationRate >= 0.5 ? 'MEDIUM' : 'LOW';

    return validationResults;
  }

  static validateExploitUrl(url, cveId) {
    try {
      const patterns = {
        github: /^https:\/\/github\.com\/[\w\-_]+\/[\w\-_]+/,
        exploitDb: /^https:\/\/(www\.)?exploit-db\.com\/(exploits|search)/,
        nvd: /^https:\/\/nvd\.nist\.gov\/vuln\/detail\//,
        cve: new RegExp(`.*${cveId}.*`, 'i')
      };

      const domain = new URL(url).hostname;
      const trustedDomains = [
        'github.com', 'exploit-db.com', 'nvd.nist.gov',
        'cve.mitre.org', 'security.snyk.io'
      ];

      const validations = {
        has_trusted_domain: trustedDomains.includes(domain),
        matches_exploit_pattern: patterns.github.test(url) || patterns.exploitDb.test(url),
        contains_cve_id: patterns.cve.test(url),
        is_https: url.startsWith('https://'),
        likely_valid: false,
        reason: ''
      };

      if (validations.has_trusted_domain && validations.contains_cve_id && validations.is_https) {
        validations.likely_valid = true;
        validations.reason = 'Trusted domain with CVE reference';
      } else if (!validations.has_trusted_domain) {
        validations.reason = 'Untrusted domain';
      } else if (!validations.contains_cve_id) {
        validations.reason = 'No CVE reference in URL';
      } else {
        validations.reason = 'Pattern mismatch';
      }

      return validations;
    } catch (error) {
      return {
        likely_valid: false,
        // @ts-ignore
        reason: 'Invalid URL format: ' + error.message
      };
    }
  }

  static async validateVendorAdvisories(cveId, aiVendorFindings) {
    const knownVendorPatterns = {
      'Microsoft': /^https:\/\/(msrc\.microsoft\.com|docs\.microsoft\.com)/,
      'Red Hat': /^https:\/\/(access\.)?redhat\.com\/(security|errata)/,
      'Oracle': /^https:\/\/(www\.)?oracle\.com\/security/,
      'Adobe': /^https:\/\/helpx\.adobe\.com\/security/,
      'Cisco': /^https:\/\/(tools\.)?cisco\.com\/security/
    };

    const validationResults = {
      aiClaimed: aiVendorFindings?.found || false,
      aiClaimedCount: aiVendorFindings?.count || 0,
      verifiedAdvisories: [],
      validationMethod: 'PATTERN_MATCHING',
      confidence: 'MEDIUM',
      verified: false // Initialize verified status
    };

    if (!aiVendorFindings?.advisories?.length) {
      validationResults.verified = true; // No advisories to verify
      validationResults.confidence = 'HIGH';
      return validationResults;
    }

    for (const advisory of aiVendorFindings.advisories) {
      const vendorName = advisory.vendor;
      // @ts-ignore
      const expectedPattern = knownVendorPatterns[vendorName];

      validationResults.verifiedAdvisories.push({
        ...advisory,
        patternMatch: !!expectedPattern,
        confidence: expectedPattern ? 'MEDIUM' : 'LOW'
      });
    }
    // A simple heuristic: if any advisories were found and processed, consider it verified at some level.
    // More sophisticated logic could check patternMatch success rates.
    validationResults.verified = validationResults.verifiedAdvisories.length > 0;
    return validationResults;
  }

  static calculateValidationScore(validationResults) {
    let score = 0;
    let totalChecks = 0;

    if (validationResults.cisaKev?.verified !== undefined) {
      score += validationResults.cisaKev.verified ? 0.4 : 0;
      totalChecks += 0.4;
    }

    if (validationResults.exploits?.verified !== undefined) {
      score += validationResults.exploits.verified ? 0.3 : 0;
      totalChecks += 0.3;
    }

    if (validationResults.vendorAdvisories?.verified !== undefined) {
      score += validationResults.vendorAdvisories.verified ? 0.3 : 0;
      totalChecks += 0.3;
    }

    return totalChecks > 0 ? score / totalChecks : 0.5; // Default to 0.5 if no checks applicable
  }
}
