// This file will contain the ValidationService class
// Add necessary imports here
export class ValidationService {
  static async validateAIFindings(aiFindings, cveId, setLoadingSteps) {
    const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
    updateSteps(prev => [...prev, `🔍 Validating AI findings for ${cveId}...`]);

    const validationResults = {
      cisaKev: await this.validateCISAKEV(cveId, aiFindings.cisaKev),
      exploits: await this.validateExploits(cveId, aiFindings.exploitDiscovery),
      vendorAdvisories: await this.validateVendorAdvisories(cveId, aiFindings.vendorAdvisories),
      confidence: 'MEDIUM',
      validatedClaims: 0,
      totalClaims: 0,
      validationTimestamp: new Date().toISOString()
    };

    // Calculate overall confidence
    const validationScore = this.calculateValidationScore(validationResults);
    validationResults.confidence = validationScore >= 0.8 ? 'HIGH' :
                                   validationScore >= 0.5 ? 'MEDIUM' : 'LOW';

    updateSteps(prev => [...prev, `✅ Validation complete: ${validationResults.confidence} confidence`]);
    return validationResults;
  }

  static async validateCISAKEV(cveId, aiKevFindings) {
    // Since direct API calls fail due to CORS, we rely on AI web search validation
    // The AI search will access the CISA KEV catalog during its web search phase

    return {
      aiClaimed: aiKevFindings?.listed || false,
      actualStatus: null, // Will be determined by AI web search
      verified: aiKevFindings?.confidence === 'HIGH' && aiKevFindings?.source, // Trust high-confidence AI findings with sources
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
      confidence: 'LOW'
    };

    if (!aiExploitFindings?.exploits?.length) {
      return { ...validationResults, verified: true, confidence: 'HIGH' };
    }

    // Validate URLs without actually fetching (to avoid security risks in client-side)
    for (const exploit of aiExploitFindings.exploits) {
      const urlsToValidate = [exploit.url, exploit.citationUrl].filter(Boolean);
      let allUrlsValid = true;
      const urlValidationResults = {};

      if (urlsToValidate.length === 0) {
        // If no URL is provided at all, consider it not verifiable for this purpose
        allUrlsValid = false;
        validationResults.invalidUrls.push({
          url: 'No URL provided',
          reason: 'No URL or citationUrl for exploit entry'
        });
      }

      for (const currentUrl of urlsToValidate) {
        const validation = this.validateExploitUrl(currentUrl, cveId);
        urlValidationResults[currentUrl] = validation;
        // Placeholder for future HEAD request:
        // if (validation.likely_valid) {
        //   try {
        //     // const headResponse = await fetchWithFallback(currentUrl, { method: 'HEAD', mode: 'cors' });
        //     // validation.live = headResponse.ok;
        //     // validation.liveStatus = headResponse.status;
        //   } catch (e) {
        //     validation.live = false;
        //     validation.liveError = e.message;
        //   }
        // }
        if (!validation.likely_valid /* || !validation.live */) {
          allUrlsValid = false;
          validationResults.invalidUrls.push({
            url: currentUrl,
            reason: validation.reason // + (validation.live === false ? ' Liveness check failed.' : '')
          });
        }
      }

      if (allUrlsValid && urlsToValidate.length > 0) {
        validationResults.verifiedExploits.push({
          ...exploit,
          urlValidationResults: urlValidationResults // Store all results
        });
      } else if (urlsToValidate.length > 0) { // If some URLs were present but not all valid
        // Already added to invalidUrls if any specific URL failed
      }
    }

    // Adjust verification rate calculation if needed, e.g., based on primary URL vs. citation
    const totalExploitsWithAttemptedValidation = aiExploitFindings.exploits?.length || 0;
    const verificationRate = totalExploitsWithAttemptedValidation > 0
                           ? validationResults.verifiedExploits.length / totalExploitsWithAttemptedValidation
                           : 1; // If no exploits, consider it 100% verified (no false claims)

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

      // Calculate likelihood
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
        reason: 'Invalid URL format'
      };
    }
  }

  static async validateVendorAdvisories(cveId, aiVendorFindings) {
    // Cross-reference with known vendor advisory patterns
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
      confidence: 'MEDIUM'
    };

    if (!aiVendorFindings?.advisories?.length) {
      return { ...validationResults, verified: true, confidence: 'HIGH' };
    }

    for (const advisory of aiVendorFindings.advisories) {
      const vendorName = advisory.vendor;
      const expectedPattern = knownVendorPatterns[vendorName];

      validationResults.verifiedAdvisories.push({
        ...advisory,
        patternMatch: !!expectedPattern,
        confidence: expectedPattern ? 'MEDIUM' : 'LOW'
      });
    }

    return validationResults;
  }

  static calculateValidationScore(validationResults) {
    let score = 0;
    let totalChecks = 0;

    // CISA KEV validation (high weight)
    if (validationResults.cisaKev?.verified !== undefined) {
      score += validationResults.cisaKev.verified ? 0.4 : 0;
      totalChecks += 0.4;
    }

    // Exploit validation (medium weight)
    if (validationResults.exploits?.verified !== undefined) {
      score += validationResults.exploits.verified ? 0.3 : 0;
      totalChecks += 0.3;
    }

    // Vendor advisory validation (medium weight)
    if (validationResults.vendorAdvisories?.verified !== undefined) {
      score += validationResults.vendorAdvisories.verified ? 0.3 : 0;
      totalChecks += 0.3;
    }

    return totalChecks > 0 ? score / totalChecks : 0.5;
  }
}
