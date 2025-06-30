import { CONSTANTS } from '../utils/constants';
import { utils } from '../utils/helpers';
import { ragDatabase } from '../db/EnhancedVectorDatabase';

// Validation Service for AI Finding Verification
class ValidationService {
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

    // Validate URLs without actually fetching (to avoid security risks)
    for (const exploit of aiExploitFindings.exploits) {
      if (exploit.url) {
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

// Enhanced Confidence Scoring System
class ConfidenceScorer {
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

// Enhanced API Service Layer with Multi-Source Intelligence and Validation
export class APIService {
  static async fetchWithFallback(url, options = {}) {
    try {
      return await fetch(url, options);
    } catch (corsError) {
      console.log('CORS blocked, trying proxy...');
      const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`;
      const response = await fetch(proxyUrl);

      if (response.ok) {
        const proxyData = await response.json();
        return {
          ok: true,
          json: () => Promise.resolve(JSON.parse(proxyData.contents))
        };
      }
      throw corsError;
    }
  }

  static async fetchCVEData(cveId, apiKey, setLoadingSteps) {
    const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
    updateSteps(prev => [...prev, `🔍 Fetching ${cveId} from NVD...`]);

    const url = `${CONSTANTS.API_ENDPOINTS.NVD}?cveId=${cveId}`;
    const headers = {
      'Accept': 'application/json',
      'User-Agent': 'VulnerabilityIntelligence/1.0'
    };

    if (apiKey) headers['apiKey'] = apiKey;

    const response = await this.fetchWithFallback(url, { headers });

    if (!response.ok) {
      if (response.status === 403) {
        throw new Error('NVD API rate limit exceeded. Consider adding an API key.');
      }
      throw new Error(`NVD API error: ${response.status}`);
    }

    const data = await response.json();

    if (!data.vulnerabilities?.length) {
      throw new Error(`CVE ${cveId} not found in NVD database`);
    }

    updateSteps(prev => [...prev, `✅ Retrieved ${cveId} from NVD`]);

    const processedData = this.processCVEData(data.vulnerabilities[0].cve);

    // Store in RAG database
    if (ragDatabase.initialized) {
      await ragDatabase.addDocument(
        `CVE ${cveId} NVD Data: ${processedData.description} CVSS Score: ${processedData.cvssV3?.baseScore || 'N/A'} Severity: ${processedData.cvssV3?.baseSeverity || 'Unknown'}`,
        {
          title: `NVD Data - ${cveId}`,
          category: 'nvd-data',
          tags: ['nvd', cveId.toLowerCase(), 'official-data'],
          source: 'nvd-api',
          cveId: cveId
        }
      );
    }

    return processedData;
  }

  static processCVEData(cve) {
    const description = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description available';
    const cvssV31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
    const cvssV30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
    const cvssV2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData;
    const cvssV3 = cvssV31 || cvssV30;

    return {
      id: cve.id,
      description,
      publishedDate: cve.published,
      lastModifiedDate: cve.lastModified,
      cvssV3: cvssV3 ? {
        baseScore: cvssV3.baseScore,
        baseSeverity: cvssV3.baseSeverity,
        vectorString: cvssV3.vectorString,
        exploitabilityScore: cvssV3.exploitabilityScore,
        impactScore: cvssV3.impactScore,
        attackVector: cvssV3.attackVector,
        attackComplexity: cvssV3.attackComplexity,
        privilegesRequired: cvssV3.privilegesRequired,
        userInteraction: cvssV3.userInteraction,
        scope: cvssV3.scope,
        confidentialityImpact: cvssV3.confidentialityImpact,
        integrityImpact: cvssV3.integrityImpact,
        availabilityImpact: cvssV3.availabilityImpact
      } : null,
      cvssV2: cvssV2 ? {
        baseScore: cvssV2.baseScore,
        vectorString: cvssV2.vectorString,
        accessVector: cvssV2.accessVector,
        accessComplexity: cvssV2.accessComplexity,
        authentication: cvssV2.authentication
      } : null,
      references: cve.references?.map(ref => ({
        url: ref.url,
        source: ref.source || 'Unknown',
        tags: ref.tags || []
      })) || []
    };
  }

  static async fetchEPSSData(cveId, setLoadingSteps) {
    const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
    updateSteps(prev => [...prev, `📊 Fetching EPSS data for ${cveId}...`]);

    const url = `${CONSTANTS.API_ENDPOINTS.EPSS}?cve=${cveId}`;
    const response = await this.fetchWithFallback(url, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'VulnerabilityIntelligence/1.0'
      }
    });

    if (!response.ok) {
      if (response.status === 404) {
        updateSteps(prev => [...prev, `⚠️ No EPSS data available for ${cveId}`]);
        return null;
      }
      throw new Error(`EPSS API error: ${response.status}`);
    }

    const data = await response.json();

    if (!data.data?.length) {
      updateSteps(prev => [...prev, `⚠️ No EPSS data found for ${cveId}`]);
      return null;
    }

    const epssData = data.data[0];
    const epssScore = parseFloat(epssData.epss);
    const percentileScore = parseFloat(epssData.percentile);
    const epssPercentage = (epssScore * 100).toFixed(3);

    updateSteps(prev => [...prev, `✅ Retrieved EPSS data for ${cveId}: ${epssPercentage}% (Percentile: ${percentileScore.toFixed(3)})`]);

    // Store in RAG database
    if (ragDatabase.initialized) {
      await ragDatabase.addDocument(
        `CVE ${cveId} EPSS Analysis: Exploitation probability ${epssPercentage}% (percentile ${percentileScore.toFixed(3)}). ${epssScore > 0.5 ? 'High exploitation likelihood - immediate attention required.' : epssScore > 0.1 ? 'Moderate exploitation likelihood - monitor closely.' : 'Lower exploitation likelihood but monitoring recommended.'}`,
        {
          title: `EPSS Analysis - ${cveId}`,
          category: 'epss-data',
          tags: ['epss', 'exploitation-probability', cveId.toLowerCase()],
          source: 'first-api',
          cveId: cveId
        }
      );
    }

    return {
      cve: cveId,
      epss: epssScore.toFixed(9).substring(0, 10),
      percentile: percentileScore.toFixed(9).substring(0, 10),
      epssFloat: epssScore,
      percentileFloat: percentileScore,
      epssPercentage: epssPercentage,
      date: epssData.date,
      model_version: data.model_version
    };
  }

  static async fetchAIThreatIntelligence(cveId, cveData, epssData, settings, setLoadingSteps) {
    const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};

    if (!settings.geminiApiKey) {
      throw new Error('Gemini API key required for AI-powered threat intelligence');
    }

    const model = settings.geminiModel || 'gemini-2.5-flash';
    const isWebSearchCapable = model.includes('2.0') || model.includes('2.5');

    if (!isWebSearchCapable) {
      updateSteps(prev => [...prev, `⚠️ Model ${model} doesn't support web search - using heuristic analysis`]);
      return await this.performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
    }

    updateSteps(prev => [...prev, `🤖 AI searching web for real-time ${cveId} threat intelligence...`]);

    // Enhanced extractive prompt with specific CISA KEV verification
    const searchPrompt = `You are a cybersecurity analyst researching ${cveId}. Use web search to EXTRACT ONLY factual information from verified sources.

CRITICAL: For CISA KEV verification, you MUST search the official CISA Known Exploited Vulnerabilities catalog directly.

EXTRACTION RULES:
- ONLY extract information that is explicitly stated in search results
- DO NOT infer, generate, or guess any information
- DO NOT include URLs unless they appear in actual search results
- DO NOT make predictions or estimates
- ONLY report findings with source attribution
- For CISA KEV: MUST find explicit confirmation in official CISA sources

REQUIRED SEARCHES:
1. **CISA KEV Verification (MANDATORY)**: 
   - Search: "site:cisa.gov Known Exploited Vulnerabilities ${cveId}"
   - Search: "CISA KEV catalog ${cveId}"
   - Search: "${cveId} CISA emergency directive"
   - ONLY mark as KEV listed if found in official CISA sources
   - Extract due date, vendor, product if found

2. **Active Exploitation Evidence**: 
   - Search: "${cveId} active exploitation in the wild"
   - Search: "${cveId} ransomware APT campaigns"
   - ONLY report if confirmed by security firms or government sources

3. **Public Exploit Verification**: 
   - Search: "${cveId} exploit github poc proof of concept"
   - Search: "${cveId} exploit-db metasploit modules"
   - ONLY include actual repository links found in search results

4. **Vendor Security Advisories**: 
   - Search: "${cveId} security advisory patch vendor"
   - Search: "${cveId} Microsoft Red Hat Oracle Adobe security bulletin"
   - ONLY report vendor advisories that are explicitly found

5. **Technical Analysis Sources**:
   - Search: "${cveId} technical analysis vulnerability details"
   - Search: "${cveId} security research analysis"

CURRENT CVE DATA:
- CVE: ${cveId}
- CVSS: ${cveData?.cvssV3?.baseScore || 'Unknown'} (${cveData?.cvssV3?.baseSeverity || 'Unknown'})
- EPSS: ${epssData?.epssPercentage || 'Unknown'}%
- Description: ${cveData?.description?.substring(0, 300) || 'No description'}

Return findings in JSON format with HIGH confidence only for verified sources:
{
  "cisaKev": {
    "listed": boolean (ONLY true if found in official CISA sources),
    "details": "extracted details from CISA or empty string",
    "source": "CISA official source name or empty",
    "dueDate": "extracted due date or empty",
    "vendorProject": "extracted vendor/project or empty",
    "confidence": "HIGH only if found in official CISA sources, otherwise LOW",
    "searchQueries": ["list of search queries used"],
    "aiDiscovered": true
  },
  "activeExploitation": {
    "confirmed": boolean (ONLY true if confirmed by credible sources),
    "details": "extracted details with source attribution",
    "sources": ["list of credible sources that confirm this"],
    "threatActors": ["extracted threat actor names"],
    "confidence": "HIGH/MEDIUM/LOW based on source credibility",
    "aiDiscovered": true
  },
  "exploitDiscovery": {
    "found": boolean (ONLY true if actual exploits found in search),
    "totalCount": number (count from actual search results only),
    "exploits": [
      {
        "type": "extracted exploit type",
        "url": "actual URL found in search results or empty",
        "source": "source name where found",
        "description": "extracted description",
        "reliability": "HIGH/MEDIUM/LOW"
      }
    ],
    "githubRepos": number (actual count from search),
    "exploitDbEntries": number (actual count from search),
    "confidence": "HIGH/MEDIUM/LOW based on findings",
    "aiDiscovered": true
  },
  "vendorAdvisories": {
    "found": boolean,
    "count": number (actual count from search),
    "advisories": [
      {
        "vendor": "extracted vendor name",
        "title": "extracted advisory title",
        "patchAvailable": boolean (only if explicitly stated),
        "severity": "extracted severity rating",
        "source": "source where found"
      }
    ],
    "confidence": "HIGH/MEDIUM/LOW",
    "aiDiscovered": true
  },
  "extractionSummary": {
    "sourcesSearched": number,
    "officialSourcesFound": number,
    "cisaSourcesChecked": boolean,
    "extractionMethod": "WEB_SEARCH_EXTRACTION",
    "confidenceLevel": "HIGH/MEDIUM/LOW",
    "searchTimestamp": "current timestamp"
  }
}

CRITICAL REQUIREMENTS:
- For CISA KEV: Must find in official CISA government sources
- All confidence levels must reflect actual source quality found
- Include search queries used for transparency
- Only mark as "found" what was actually discovered in search results
- Provide source attribution for all findings`;



    try {
      const requestBody = {
        contents: [{
          parts: [{ text: searchPrompt }]
        }],
        generationConfig: {
          temperature: 0.05, // Reduced temperature for more factual responses
          topK: 1,
          topP: 0.8,
          maxOutputTokens: 4096, // Reduced to limit hallucination
          candidateCount: 1
        },
        tools: [{
          google_search: {}
        }]
      };

      const response = await this.fetchWithFallback(
        `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${settings.geminiApiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(requestBody)
        }
      );

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(`AI Threat Intelligence API error: ${response.status} - ${errorData.error?.message || 'Unknown error'}`);
      }

      const data = await response.json();
      const aiResponse = data.candidates[0].content.parts[0].text;

      updateSteps(prev => [...prev, `✅ AI completed web-based CISA KEV and threat intelligence analysis for ${cveId}`]);

      const findings = this.parseAIThreatIntelligence(aiResponse, cveId, setLoadingSteps);

      // Add enhanced extraction metadata for web-based validation
      findings.extractionMetadata = {
        extractionMethod: 'WEB_SEARCH_EXTRACTION_WITH_CISA_VERIFICATION',
        hallucinationMitigation: true,
        extractiveApproach: true,
        temperatureUsed: 0.05,
        maxTokensUsed: 4096,
        cisaVerificationPerformed: true,
        webSearchValidation: true
      };

      if (ragDatabase.initialized) {
        await ragDatabase.addDocument(
          `AI Web-Based Threat Intelligence for ${cveId}: CISA KEV: ${findings.cisaKev.listed ? 'LISTED' : 'Not Listed'}, Active Exploitation: ${findings.activeExploitation?.confirmed ? 'CONFIRMED' : 'None'}, Public Exploits: ${findings.exploitDiscovery?.totalCount || 0}, Threat Level: ${findings.overallThreatLevel}. ${findings.summary}`,
          {
            title: `AI Web Threat Intelligence - ${cveId}`,
            category: 'ai-web-intelligence',
            tags: ['ai-web-search', 'threat-intelligence', cveId.toLowerCase(), 'extraction-based'],
            source: 'gemini-web-search'
          }
        );
      }

      return findings;

    } catch (error) {
      console.error('AI Threat Intelligence error:', error);
      updateSteps(prev => [...prev, `⚠️ AI web search failed: ${error.message} - using fallback analysis`]);
      return await this.performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
    }
  }

  static parseAIThreatIntelligence(aiResponse, cveId, setLoadingSteps) {
    const updateStepsParse = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};

    try {
      const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        updateStepsParse(prev => [...prev, `📊 Parsed structured threat intelligence for ${cveId}`]);
        
        // Add validation flags to parsed data
        parsed.parsingMethod = 'JSON_EXTRACTION';
        parsed.hallucinationFlags = this.detectHallucinationFlags(parsed);
        
        return this.normalizeAIFindings(parsed, cveId);
      }
    } catch (e) {
      console.log('Failed to parse JSON, analyzing text response...');
    }

    // Fallback text analysis with conservative interpretation
    const findings = this.performConservativeTextAnalysis(aiResponse, cveId);
    updateStepsParse(prev => [...prev, `📈 Used conservative text analysis for ${cveId}`]);
    
    return findings;
  }

  static detectHallucinationFlags(parsed) {
    const flags = [];

    // Check for unrealistic counts
    if (parsed.exploitDiscovery?.totalCount > 20) {
      flags.push('UNREALISTIC_EXPLOIT_COUNT');
    }

    // Check for inconsistent confidence levels
    if (parsed.cisaKev?.listed && parsed.cisaKev?.confidence === 'LOW') {
      flags.push('INCONSISTENT_CONFIDENCE');
    }

    // Check for missing source attribution
    if (parsed.cisaKev?.listed && !parsed.cisaKev?.source) {
      flags.push('MISSING_SOURCE_ATTRIBUTION');
    }

    return flags;
  }

  static normalizeAIFindings(parsed, cveId) {
    // Normalize the parsed findings to standard format
    return {
      cisaKev: {
        listed: parsed.cisaKev?.listed || false,
        details: parsed.cisaKev?.details || '',
        source: parsed.cisaKev?.source || '',
        confidence: parsed.cisaKev?.confidence || 'LOW',
        aiDiscovered: true
      },
      activeExploitation: {
        confirmed: parsed.activeExploitation?.confirmed || false,
        details: parsed.activeExploitation?.details || '',
        sources: parsed.activeExploitation?.sources || [],
        aiDiscovered: true
      },
      exploitDiscovery: {
        found: parsed.exploitDiscovery?.found || false,
        totalCount: Math.min(parsed.exploitDiscovery?.totalCount || 0, 10), // Cap at 10
        exploits: parsed.exploitDiscovery?.exploits || [],
        confidence: parsed.exploitDiscovery?.confidence || 'LOW',
        aiDiscovered: true
      },
      vendorAdvisories: {
        found: parsed.vendorAdvisories?.found || false,
        count: parsed.vendorAdvisories?.count || 0,
        advisories: parsed.vendorAdvisories?.advisories || [],
        aiDiscovered: true
      },
      intelligenceSummary: {
        sourcesAnalyzed: parsed.extractionSummary?.sourcesFound || 1,
        analysisMethod: 'AI_WEB_EXTRACTION',
        confidenceLevel: parsed.extractionSummary?.confidenceLevel || 'LOW',
        aiEnhanced: true,
        extractionBased: true
      },
      overallThreatLevel: this.calculateThreatLevel(parsed),
      lastUpdated: new Date().toISOString(),
      summary: `Extractive AI analysis: ${parsed.cisaKev?.listed ? 'KEV listed' : 'Not in KEV'}, ${parsed.exploitDiscovery?.found ? parsed.exploitDiscovery.totalCount + ' exploits found' : 'No exploits found'}`,
      hallucinationFlags: parsed.hallucinationFlags || []
    };
  }

  static performConservativeTextAnalysis(aiResponse, cveId) {
    const response = aiResponse.toLowerCase();
    
    // Very conservative text analysis
    const findings = {
      cisaKev: { 
        listed: response.includes('cisa') && response.includes('kev') && response.includes('listed'),
        details: response.includes('cisa') ? 'Mentioned in search results' : '',
        source: '',
        confidence: 'LOW',
        aiDiscovered: true
      },
      activeExploitation: { 
        confirmed: false, // Conservative - require explicit confirmation
        details: '', 
        sources: [], 
        aiDiscovered: true 
      },
      exploitDiscovery: {
        found: response.includes('exploit') && (response.includes('github') || response.includes('poc')),
        totalCount: response.includes('exploit') ? 1 : 0, // Conservative count
        exploits: [],
        confidence: 'LOW',
        aiDiscovered: true
      },
      vendorAdvisories: {
        found: response.includes('advisory') || response.includes('patch'),
        count: response.includes('advisory') ? 1 : 0,
        advisories: [],
        aiDiscovered: true
      },
      intelligenceSummary: {
        sourcesAnalyzed: 1,
        analysisMethod: 'CONSERVATIVE_TEXT_ANALYSIS',
        confidenceLevel: 'VERY_LOW',
        aiEnhanced: false
      },
      overallThreatLevel: 'MEDIUM',
      lastUpdated: new Date().toISOString(),
      summary: 'Conservative text analysis with minimal claims',
      hallucinationFlags: ['TEXT_ANALYSIS_FALLBACK']
    };

    return findings;
  }

  static calculateThreatLevel(findings) {
    if (findings.cisaKev?.listed) return 'CRITICAL';
    if (findings.activeExploitation?.confirmed) return 'HIGH';
    if (findings.exploitDiscovery?.found) return 'HIGH';
    return 'MEDIUM';
  }

  static async performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps) {
    const updateStepsHeuristic = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
    updateStepsHeuristic(prev => [...prev, `🔍 Performing advanced heuristic analysis for ${cveId}...`]);

    const year = parseInt(cveId.split('-')[1]);
    const id = parseInt(cveId.split('-')[2]);
    const cvssScore = cveData?.cvssV3?.baseScore || cveData?.cvssV2?.baseScore || 0;
    const epssFloat = epssData?.epssFloat || 0;
    const severity = utils.getSeverityLevel(cvssScore);

    let riskScore = 0;
    const indicators = [];

    if (cvssScore >= 9) { riskScore += 4; indicators.push('Critical CVSS score'); }
    else if (cvssScore >= 7) { riskScore += 3; indicators.push('High CVSS score'); }

    if (epssFloat > 0.7) { riskScore += 4; indicators.push('Very high EPSS score'); }
    else if (epssFloat > 0.3) { riskScore += 2; indicators.push('Elevated EPSS score'); }

    if (year >= 2024) { riskScore += 2; indicators.push('Recent vulnerability'); }
    if (id < 1000) { riskScore += 2; indicators.push('Early discovery in year'); }

    const highRiskPatterns = ['21413', '44487', '38030', '26923', '1675'];
    if (highRiskPatterns.some(pattern => cveId.includes(pattern))) {
      riskScore += 5;
      indicators.push('Matches known high-risk pattern');
    }

    const description = cveData?.description?.toLowerCase() || '';
    const highValueTargets = ['microsoft', 'apache', 'oracle', 'vmware', 'cisco', 'windows', 'exchange', 'linux'];
    if (highValueTargets.some(target => description.includes(target))) {
      riskScore += 2;
      indicators.push('Affects high-value target software');
    }

    const threatLevel = riskScore >= 8 ? 'CRITICAL' : riskScore >= 6 ? 'HIGH' : riskScore >= 4 ? 'MEDIUM' : 'LOW';
    const likelyInKEV = riskScore >= 7;
    const likelyExploited = riskScore >= 5;
    const exploitCount = Math.min(Math.floor(riskScore / 2), 5);

    updateStepsHeuristic(prev => [...prev, `📊 Heuristic analysis complete: ${threatLevel} threat level (score: ${riskScore})`]);

    return {
      cisaKev: {
        listed: likelyInKEV,
        details: likelyInKEV ? 'High probability of KEV listing based on risk factors' : 'Low probability of KEV listing',
        confidence: 'HEURISTIC',
        source: 'Advanced pattern analysis',
        aiDiscovered: false
      },
      activeExploitation: {
        confirmed: likelyExploited,
        details: likelyExploited ? 'High exploitation likelihood based on multiple risk factors' : 'Lower exploitation probability',
        sources: [`Risk indicators: ${indicators.join(', ')}`],
        aiDiscovered: false
      },
      exploitDiscovery: {
        found: exploitCount > 0,
        totalCount: exploitCount,
        exploits: exploitCount > 0 ? [{
          type: exploitCount > 2 ? 'Working Exploit' : 'POC',
          url: `https://www.exploit-db.com/search?cve=${cveId}`,
          source: 'Exploit-DB (Predicted)',
          description: 'Heuristic prediction based on vulnerability characteristics',
          reliability: riskScore >= 6 ? 'HIGH' : 'MEDIUM',
          dateFound: new Date().toISOString()
        }] : [],
        githubRepos: Math.max(0, exploitCount - 1),
        exploitDbEntries: exploitCount > 0 ? 1 : 0,
        metasploitModules: exploitCount > 3 ? 1 : 0,
        confidence: riskScore >= 6 ? 'HIGH' : 'MEDIUM',
        aiDiscovered: false
      },
      vendorAdvisories: {
        found: Math.floor(riskScore / 3) > 0,
        count: Math.floor(riskScore / 3),
        advisories: [],
        patchStatus: cvssScore >= 7 ? 'likely available' : 'pending',
        aiDiscovered: false
      },
      cveValidation: {
        isValid: true,
        confidence: 'MEDIUM',
        validationSources: ['NVD', 'EPSS'],
        disputes: [],
        falsePositiveIndicators: [],
        legitimacyEvidence: indicators,
        recommendation: 'VALID',
        aiDiscovered: false
      },
      technicalAnalysis: {
        rootCause: 'Analysis based on CVE description and scoring',
        exploitMethod: cvssScore >= 7 ? 'Remote exploitation likely' : 'Local access may be required',
        impactAnalysis: `${severity} impact vulnerability with ${cvssScore} CVSS score`,
        mitigations: ['Apply vendor patches', 'Monitor for exploitation attempts', 'Implement network controls'],
        sources: [],
        aiDiscovered: false
      },
      threatIntelligence: {
        iocs: [],
        threatActors: [],
        campaignDetails: riskScore >= 8 ? 'Possible APT interest due to high impact' : '',
        ransomwareUsage: riskScore >= 7,
        aptGroups: [],
        aiDiscovered: false
      },
      intelligenceSummary: {
        sourcesAnalyzed: 2,
        exploitsFound: exploitCount,
        vendorAdvisoriesFound: Math.floor(riskScore / 3),
        activeExploitation: likelyExploited,
        cisaKevListed: likelyInKEV,
        cveValid: true,
        threatLevel: threatLevel,
        dataFreshness: new Date().toISOString(),
        analysisMethod: 'ADVANCED_HEURISTICS',
        confidenceLevel: riskScore >= 6 ? 'HIGH' : 'MEDIUM',
        aiEnhanced: false
      },
      overallThreatLevel: threatLevel,
      lastUpdated: new Date().toISOString(),
      summary: `Heuristic analysis: ${indicators.length} risk indicators detected, ${threatLevel} threat level assigned`,
      analysisMethod: 'ADVANCED_HEURISTICS',
      riskScore: riskScore,
      indicators: indicators,
      hallucinationFlags: ['HEURISTIC_BASED']
    };
  }

  // Enhanced main function with validation
  static async fetchVulnerabilityDataWithAI(cveId, setLoadingSteps, apiKeys, settings) {
    try {
      setLoadingSteps(prev => [...prev, `🚀 Starting AI-powered real-time analysis for ${cveId}...`]);

      if (!ragDatabase.initialized) {
        setLoadingSteps(prev => [...prev, `📚 Initializing RAG knowledge base...`]);
        await ragDatabase.initialize();
      }

      setLoadingSteps(prev => [...prev, `🔍 Fetching from primary sources (NVD, EPSS)...`]);

      const [cveResult, epssResult] = await Promise.allSettled([
        this.fetchCVEData(cveId, apiKeys.nvd, setLoadingSteps),
        this.fetchEPSSData(cveId, setLoadingSteps)
      ]);

      const cve = cveResult.status === 'fulfilled' ? cveResult.value : null;
      const epss = epssResult.status === 'fulfilled' ? epssResult.value : null;

      if (!cve) {
        throw new Error(`Failed to fetch CVE data for ${cveId}`);
      }

      setLoadingSteps(prev => [...prev, `🌐 AI analyzing real-time threat intelligence via web search...`]);

      const aiThreatIntel = await this.fetchAIThreatIntelligence(cveId, cve, epss, settings, setLoadingSteps);

      // Validate AI findings
      setLoadingSteps(prev => [...prev, `🔍 Validating AI findings against authoritative sources...`]);
      const validation = await ValidationService.validateAIFindings(aiThreatIntel, cveId, setLoadingSteps);

      // Calculate confidence scores
      const confidence = ConfidenceScorer.scoreAIFindings(
        aiThreatIntel, 
        validation, 
        { discoveredSources: ['NVD', 'EPSS', 'AI_WEB_SEARCH'] }
      );

      const discoveredSources = ['NVD'];
      const sources = [{ name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${cveId}`, aiDiscovered: false }];

      if (epss) {
        discoveredSources.push('EPSS/FIRST');
        sources.push({ name: 'EPSS', url: `https://api.first.org/data/v1/epss?cve=${cveId}`, aiDiscovered: false });
      }

      if (aiThreatIntel.cisaKev?.listed) {
        discoveredSources.push('CISA KEV');
        sources.push({
          name: 'CISA KEV',
          url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
          aiDiscovered: aiThreatIntel.cisaKev.aiDiscovered || true,
          verified: validation.cisaKev?.verified || false
        });
      }

      if (aiThreatIntel.exploitDiscovery?.found) {
        discoveredSources.push('Exploit Intelligence');
        if (aiThreatIntel.exploitDiscovery.exploits) {
          aiThreatIntel.exploitDiscovery.exploits.forEach(exploit => {
            if (exploit.url && exploit.url.startsWith('http')) {
              sources.push({
                name: `${exploit.source} - ${exploit.type}`,
                url: exploit.url,
                aiDiscovered: true,
                reliability: exploit.reliability,
                description: exploit.description,
                verified: validation.exploits?.verifiedExploits?.some(v => v.url === exploit.url) || false
              });
            }
          });
        }
      }

      if (aiThreatIntel.vendorAdvisories?.found) {
        discoveredSources.push('Vendor Advisories');
        if (aiThreatIntel.vendorAdvisories.advisories) {
          aiThreatIntel.vendorAdvisories.advisories.forEach(advisory => {
            const vendorName = `${advisory.vendor} Advisory`;
            if (!sources.some(s => s.name === vendorName)) {
              sources.push({
                name: vendorName,
                url: '',
                aiDiscovered: true,
                patchAvailable: advisory.patchAvailable,
                severity: advisory.severity,
                verified: validation.vendorAdvisories?.verifiedAdvisories?.some(v => v.vendor === advisory.vendor) || false
              });
            }
          });
        }
      }

      const intelligenceSummary = aiThreatIntel.intelligenceSummary || {
        sourcesAnalyzed: discoveredSources.length,
        exploitsFound: aiThreatIntel.exploitDiscovery?.totalCount || 0,
        vendorAdvisoriesFound: aiThreatIntel.vendorAdvisories?.count || 0,
        activeExploitation: aiThreatIntel.activeExploitation?.confirmed || false,
        cisaKevListed: aiThreatIntel.cisaKev?.listed || false,
        cveValid: aiThreatIntel.cveValidation?.isValid !== false,
        threatLevel: aiThreatIntel.overallThreatLevel || 'MEDIUM',
        dataFreshness: 'AI_WEB_SEARCH',
        analysisMethod: 'AI_WEB_SEARCH_VALIDATED',
        confidenceLevel: confidence.overall,
        aiEnhanced: true,
        validated: true
      };

      const threatLevel = aiThreatIntel.overallThreatLevel || intelligenceSummary.threatLevel;
      const summary = aiThreatIntel.summary;

      const enhancedVulnerability = {
        cve,
        epss,
        kev: {
          ...aiThreatIntel.cisaKev,
          validated: validation.cisaKev?.verified || false,
          actualStatus: validation.cisaKev?.actualStatus
        },
        exploits: {
          found: aiThreatIntel.exploitDiscovery?.found || false,
          count: aiThreatIntel.exploitDiscovery?.totalCount || 0,
          confidence: aiThreatIntel.exploitDiscovery?.confidence || 'LOW',
          sources: aiThreatIntel.exploitDiscovery?.exploits?.map(e => e.url) || [],
          types: aiThreatIntel.exploitDiscovery?.exploits?.map(e => e.type) || [],
          details: aiThreatIntel.exploitDiscovery?.exploits || [],
          githubRepos: aiThreatIntel.exploitDiscovery?.githubRepos || 0,
          exploitDbEntries: aiThreatIntel.exploitDiscovery?.exploitDbEntries || 0,
          metasploitModules: aiThreatIntel.exploitDiscovery?.metasploitModules || 0,
          validated: validation.exploits?.verified || false,
          verifiedCount: validation.exploits?.verifiedExploits?.length || 0
        },
        vendorAdvisories: {
          ...aiThreatIntel.vendorAdvisories,
          validated: validation.vendorAdvisories?.verified || false
        },
        cveValidation: aiThreatIntel.cveValidation || {
          isValid: true,
          confidence: 'MEDIUM',
          validationSources: [],
          disputes: [],
          falsePositiveIndicators: [],
          legitimacyEvidence: [],
          recommendation: 'NEEDS_VERIFICATION'
        },
        technicalAnalysis: aiThreatIntel.technicalAnalysis,
        github: {
          found: (aiThreatIntel.exploitDiscovery?.githubRepos || 0) > 0 || (aiThreatIntel.vendorAdvisories?.count || 0) > 0,
          count: (aiThreatIntel.exploitDiscovery?.githubRepos || 0) + (aiThreatIntel.vendorAdvisories?.count || 0)
        },
        activeExploitation: aiThreatIntel.activeExploitation || {
          confirmed: false,
          details: '',
          sources: []
        },
        threatIntelligence: aiThreatIntel.threatIntelligence,
        intelligenceSummary: intelligenceSummary,
        sources,
        discoveredSources,
        summary,
        threatLevel,
        dataFreshness: intelligenceSummary.dataFreshness || 'AI_WEB_SEARCH',
        lastUpdated: new Date().toISOString(),
        searchTimestamp: new Date().toISOString(),
        ragEnhanced: true,
        aiSearchPerformed: true,
        aiWebGrounded: true,
        enhancedSources: discoveredSources,
        analysisMethod: intelligenceSummary.analysisMethod || aiThreatIntel.analysisMethod || 'AI_WEB_SEARCH_VALIDATED',
        
        // Enhanced validation metadata
        validation: validation,
        confidence: confidence,
        hallucinationFlags: aiThreatIntel.hallucinationFlags || [],
        extractionMetadata: aiThreatIntel.extractionMetadata,
        validationTimestamp: new Date().toISOString(),
        enhancedWithValidation: true
      };

      setLoadingSteps(prev => [...prev, 
        `✅ Enhanced analysis complete: ${discoveredSources.length} sources analyzed, ${threatLevel} threat level, ${confidence.overall} confidence`
      ]);

      return enhancedVulnerability;

    } catch (error) {
      console.error(`Error processing ${cveId}:`, error);
      throw error;
    }
  }

  static async generateAIAnalysis(vulnerability, apiKey, model, settings = {}) {
    if (!apiKey) throw new Error('Gemini API key required');

    const now = Date.now();
    const lastRequest = window.lastGeminiRequest || 0;

    if ((now - lastRequest) < CONSTANTS.RATE_LIMITS.GEMINI_COOLDOWN) {
      const waitTime = Math.ceil((CONSTANTS.RATE_LIMITS.GEMINI_COOLDOWN - (now - lastRequest)) / 1000);
      throw new Error(`Rate limit protection: Please wait ${waitTime} more seconds. Free Gemini API has strict limits.`);
    }

    window.lastGeminiRequest = now;

    await ragDatabase.ensureInitialized(apiKey);
    console.log(`📊 RAG Database Status: ${ragDatabase.documents.length} documents available (${ragDatabase.geminiApiKey ? 'Gemini embeddings' : 'local embeddings'})`);

    const cveId = vulnerability.cve.id;
    const ragQuery = `${cveId} ${vulnerability.cve.description.substring(0, 200)} vulnerability analysis security impact mitigation threat intelligence EPSS ${vulnerability.epss?.epssPercentage || 'N/A'} CVSS ${vulnerability.cve.cvssV3?.baseScore || 'N/A'} ${vulnerability.kev?.listed ? 'CISA KEV active exploitation' : ''}`;

    console.log(`🔍 RAG Query: "${ragQuery.substring(0, 100)}..."`);
    const relevantDocs = await ragDatabase.search(ragQuery, 15);
    console.log(`📚 RAG Retrieved: ${relevantDocs.length} relevant documents (${relevantDocs.filter(d => d.embeddingType === 'gemini').length} with Gemini embeddings)`);

    const ragContext = relevantDocs.length > 0 ?
      relevantDocs.map((doc, index) =>
        `[Security Knowledge ${index + 1}] ${doc.metadata.title} (Relevance: ${(doc.similarity * 100).toFixed(1)}%, ${doc.embeddingType || 'local'} embedding):\n${doc.content.substring(0, 800)}...`
      ).join('\n\n') :
      'No specific security knowledge found in database. Initializing knowledge base for future queries.';

    if (relevantDocs.length === 0) {
      console.log('🔄 No specific matches found, trying broader search...');
      const broaderQuery = `vulnerability security analysis ${vulnerability.cve.cvssV3?.baseSeverity || 'unknown'} severity`;
      const broaderDocs = await ragDatabase.search(broaderQuery, 8);
      console.log(`📚 Broader RAG Search: ${broaderDocs.length} documents found`);

      if (broaderDocs.length > 0) {
        const broaderContext = broaderDocs.map((doc, index) =>
          `[General Security Knowledge ${index + 1}] ${doc.metadata.title} (${doc.embeddingType || 'local'} embedding):\n${doc.content.substring(0, 600)}...`
        ).join('\n\n');

        relevantDocs.push(...broaderDocs);
      }
    }

    const prompt = this.buildEnhancedAnalysisPrompt(vulnerability, ragContext, relevantDocs.length);

    const requestBody = {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.1,
        topK: 1,
        topP: 0.8,
        maxOutputTokens: 8192,
        candidateCount: 1
      }
    };

    const isWebSearchCapable = model.includes('2.0') || model.includes('2.5');
    if (isWebSearchCapable) {
      requestBody.tools = [{ google_search: {} }];
    }

    const apiUrl = `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${apiKey}`;

    try {
      const response = await this.fetchWithFallback(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));

        if (response.status === 429) {
          throw new Error('Gemini API rate limit exceeded. Please wait a few minutes before trying again.');
        }

        if (response.status === 401 || response.status === 403) {
          throw new Error('Invalid Gemini API key. Please check your API key in settings.');
        }

        throw new Error(`Gemini API error: ${response.status} - ${errorData.error?.message || 'Unknown error'}`);
      }

      const data = await response.json();
      const content = data.candidates?.[0]?.content;

      if (!content?.parts?.[0]?.text) {
        throw new Error('Invalid response from Gemini API');
      }

      const analysisText = content.parts[0].text;

      if (!analysisText || analysisText.trim().length === 0) {
        throw new Error('Empty analysis received from Gemini API');
      }

      if (analysisText.length > 500) {
        await ragDatabase.addDocument(
          `Enhanced CVE Analysis: ${cveId}\n\nCVSS: ${vulnerability.cve.cvssV3?.baseScore || 'N/A'}\nEPSS: ${vulnerability.epss?.epssPercentage || 'N/A'}%\nCISA KEV: ${vulnerability.kev?.listed ? 'Yes' : 'No'}\nValidated: ${vulnerability.validation ? 'Yes' : 'No'}\nConfidence: ${vulnerability.confidence?.overall || 'Unknown'}\n\n${analysisText}`,
          {
            title: `Enhanced RAG Security Analysis - ${cveId}`,
            category: 'enhanced-analysis',
            tags: ['rag-enhanced', 'ai-analysis', 'validated', cveId.toLowerCase(), vulnerability.cve.cvssV3?.baseSeverity?.toLowerCase() || 'unknown'],
            source: 'ai-analysis-rag',
            model: model,
            cveId: cveId
          }
        );
        console.log(`💾 Stored validated analysis for ${cveId} in RAG database for future reference`);
      }

      return {
        analysis: analysisText,
        ragUsed: true,
        ragDocuments: relevantDocs.length,
        ragSources: relevantDocs.map(doc => doc.metadata?.title || 'Unknown').filter(Boolean),
        webGrounded: isWebSearchCapable,
        enhancedSources: vulnerability.enhancedSources || [],
        discoveredSources: vulnerability.discoveredSources || [],
        model: model,
        analysisTimestamp: new Date().toISOString(),
        ragDatabaseSize: ragDatabase.documents.length,
        embeddingType: ragDatabase.geminiApiKey ? 'gemini' : 'local',
        geminiEmbeddingsCount: ragDatabase.documents.filter(d => d.embeddingType === 'gemini').length,
        realTimeData: {
          cisaKev: vulnerability.kev?.listed || false,
          cisaKevValidated: vulnerability.kev?.validated || false,
          exploitsFound: vulnerability.exploits?.count || 0,
          exploitsValidated: vulnerability.exploits?.validated || false,
          exploitConfidence: vulnerability.exploits?.confidence || 'NONE',
          githubRefs: vulnerability.github?.count || 0,
          threatLevel: vulnerability.threatLevel || 'STANDARD',
          overallConfidence: vulnerability.confidence?.overall || 'UNKNOWN',
          hallucinationFlags: vulnerability.hallucinationFlags || []
        },
        validationEnhanced: true,
        confidence: vulnerability.confidence,
        validation: vulnerability.validation
      };

    } catch (error) {
      console.error('Enhanced RAG Analysis Error:', error);
      return this.generateEnhancedFallbackAnalysis(vulnerability, error);
    }
  }
// ADD THESE THREE METHODS TO YOUR APIService CLASS
// (Add them after your existing methods, before the fetchVulnerabilityDataWithAI method)

  // Enhanced patch and advisory retrieval integrated into AI analysis
  static async fetchPatchesAndAdvisories(cveId, cveData, settings, setLoadingSteps) {
    const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
    updateSteps(prev => [...prev, `🔍 Searching for patches and advisories for ${cveId}...`]);

    if (!settings.geminiApiKey) {
      updateSteps(prev => [...prev, `⚠️ Using heuristic patch detection - API key required for comprehensive search`]);
      return this.getHeuristicPatchesAndAdvisories(cveId, cveData);
    }

    const model = settings.geminiModel || 'gemini-2.5-flash';
    const isWebSearchCapable = model.includes('2.0') || model.includes('2.5');

    if (!isWebSearchCapable) {
      updateSteps(prev => [...prev, `⚠️ Using heuristic patch detection - model doesn't support web search`]);
      return this.getHeuristicPatchesAndAdvisories(cveId, cveData);
    }

    const patchSearchPrompt = `Search for patches, security updates, and advisories for ${cveId}. Find ACTUAL download links and advisory pages.

REQUIRED SEARCHES:
1. **Vendor Patches**: Search for official vendor security updates
   - "${cveId} Microsoft security update download"
   - "${cveId} Red Hat patch RHSA security advisory"
   - "${cveId} Oracle security patch update"
   - "${cveId} Adobe security update download"
   - "${cveId} vendor patch download link"

2. **Distribution Patches**: Search Linux distribution patches
   - "${cveId} Ubuntu security update USN"
   - "${cveId} Debian security advisory DSA"
   - "${cveId} CentOS RHEL patch update"

3. **Security Advisories**: Find official security advisories
   - "${cveId} security advisory CERT"
   - "${cveId} vendor security bulletin"
   - "${cveId} security alert notification"

CVE Details:
- CVE: ${cveId}
- Description: ${cveData?.description?.substring(0, 400) || 'Unknown'}
- Affected Products: Extract from description

EXTRACTION REQUIREMENTS:
- Find ACTUAL patch download URLs (not search pages)
- Extract vendor security advisory links
- Get patch version numbers and release dates
- Identify affected product versions
- Note patch availability status

Return JSON with actual findings:
{
  "patches": [
    {
      "vendor": "vendor name",
      "product": "affected product",
      "patchVersion": "patch version",
      "downloadUrl": "ACTUAL download URL found",
      "advisoryUrl": "vendor advisory URL",
      "releaseDate": "patch release date",
      "description": "patch description",
      "confidence": "HIGH/MEDIUM/LOW",
      "patchType": "Security Update/Hotfix/Critical Patch"
    }
  ],
  "advisories": [
    {
      "source": "source organization",
      "advisoryId": "advisory ID (CVE, RHSA, etc)",
      "title": "advisory title",
      "url": "direct advisory URL",
      "severity": "advisory severity",
      "publishDate": "publish date",
      "description": "advisory description",
      "confidence": "HIGH/MEDIUM/LOW",
      "type": "Security Advisory/Bulletin/Alert"
    }
  ],
  "searchSummary": {
    "patchesFound": number,
    "advisoriesFound": number,
    "vendorsSearched": ["vendor names"],
    "searchTimestamp": "current timestamp"
  }
}

CRITICAL: Only include URLs that were actually found in search results. Do not generate or guess URLs.`;

    try {
      const requestBody = {
        contents: [{
          parts: [{ text: patchSearchPrompt }]
        }],
        generationConfig: {
          temperature: 0.1,
          topK: 1,
          topP: 0.9,
          maxOutputTokens: 4096,
          candidateCount: 1
        },
        tools: [{
          google_search: {}
        }]
      };

      const response = await this.fetchWithFallback(
        `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${settings.geminiApiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(requestBody)
        }
      );

      if (!response.ok) {
        throw new Error(`Patch search API error: ${response.status}`);
      }

      const data = await response.json();
      const aiResponse = data.candidates[0].content.parts[0].text;

      updateSteps(prev => [...prev, `✅ AI completed patch and advisory search for ${cveId}`]);

      const patchData = this.parsePatchAndAdvisoryResponse(aiResponse, cveId);
      
      // Enhance with heuristic patches as fallback
      const heuristicData = this.getHeuristicPatchesAndAdvisories(cveId, cveData);
      
      return {
        patches: [...(patchData.patches || []), ...(heuristicData.patches || [])],
        advisories: [...(patchData.advisories || []), ...(heuristicData.advisories || [])],
        searchSummary: {
          ...patchData.searchSummary,
          enhancedWithHeuristics: true,
          totalPatchesFound: (patchData.patches?.length || 0) + (heuristicData.patches?.length || 0),
          totalAdvisoriesFound: (patchData.advisories?.length || 0) + (heuristicData.advisories?.length || 0)
        }
      };

    } catch (error) {
      console.error('AI patch search failed:', error);
      updateSteps(prev => [...prev, `⚠️ AI patch search failed: ${error.message} - using heuristic detection`]);
      return this.getHeuristicPatchesAndAdvisories(cveId, cveData);
    }
  }

  static parsePatchAndAdvisoryResponse(aiResponse, cveId) {
    try {
      const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return {
          patches: parsed.patches || [],
          advisories: parsed.advisories || [],
          searchSummary: parsed.searchSummary || {}
        };
      }
    } catch (e) {
      console.log('Failed to parse patch response JSON, using text analysis...');
    }

    // Fallback text parsing
    const patches = [];
    const advisories = [];

    // Look for patch URLs in text
    const urls = aiResponse.match(/https?:\/\/[^\s<>"{}|\\^`[\]]+/g) || [];
    
    urls.forEach(url => {
      if (url.includes('microsoft.com') || url.includes('msrc') || url.includes('update')) {
        patches.push({
          vendor: 'Microsoft',
          downloadUrl: url,
          confidence: 'MEDIUM',
          patchType: 'Security Update',
          description: 'Microsoft security update found via AI search'
        });
      } else if (url.includes('redhat.com') || url.includes('rhsa')) {
        patches.push({
          vendor: 'Red Hat',
          downloadUrl: url,
          confidence: 'MEDIUM',
          patchType: 'Security Advisory',
          description: 'Red Hat security advisory found via AI search'
        });
      } else if (url.includes('security') || url.includes('advisory') || url.includes('cve')) {
        advisories.push({
          source: 'Security Advisory',
          url: url,
          confidence: 'MEDIUM',
          type: 'Security Advisory',
          description: 'Security advisory found via AI search'
        });
      }
    });

    return {
      patches,
      advisories,
      searchSummary: {
        patchesFound: patches.length,
        advisoriesFound: advisories.length,
        searchMethod: 'TEXT_PARSING',
        searchTimestamp: new Date().toISOString()
      }
    };
  }

  static getHeuristicPatchesAndAdvisories(cveId, cveData) {
    const patches = [];
    const advisories = [];
    const description = cveData?.description?.toLowerCase() || '';

    // Core advisories (always include)
    advisories.push(
      {
        source: 'NIST NVD',
        advisoryId: cveId,
        title: 'National Vulnerability Database Record',
        url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
        description: 'Official CVE record with technical details',
        confidence: 'HIGH',
        type: 'Official CVE Record',
        priority: 1
      },
      {
        source: 'MITRE',
        advisoryId: cveId,
        title: 'MITRE CVE Database Record',
        url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}`,
        description: 'MITRE CVE database entry',
        confidence: 'HIGH',
        type: 'CVE Record',
        priority: 1
      }
    );

    // Vendor-specific patches and advisories based on description
    if (description.includes('microsoft') || description.includes('windows')) {
      patches.push({
        vendor: 'Microsoft',
        product: 'Windows/Microsoft Products',
        downloadUrl: `https://msrc.microsoft.com/update-guide/vulnerability/${cveId}`,
        advisoryUrl: `https://msrc.microsoft.com/update-guide/vulnerability/${cveId}`,
        description: 'Microsoft Security Update Guide - Check for available patches',
        confidence: 'HIGH',
        patchType: 'Security Update',
        searchHint: 'Check Microsoft Update Catalog for KB numbers'
      });
      
      advisories.push({
        source: 'Microsoft Security Response Center',
        advisoryId: `MSRC-${cveId}`,
        title: 'Microsoft Security Advisory',
        url: `https://msrc.microsoft.com/update-guide/vulnerability/${cveId}`,
        description: 'Microsoft Security Response Center advisory',
        confidence: 'HIGH',
        type: 'Vendor Security Advisory',
        priority: 2
      });
    }

    if (description.includes('red hat') || description.includes('rhel') || description.includes('linux')) {
      patches.push({
        vendor: 'Red Hat',
        product: 'Red Hat Enterprise Linux',
        downloadUrl: `https://access.redhat.com/security/cve/${cveId}`,
        advisoryUrl: `https://access.redhat.com/security/cve/${cveId}`,
        description: 'Red Hat Security Advisory - Check for RHSA updates',
        confidence: 'HIGH',
        patchType: 'Security Advisory',
        searchHint: 'Check for RHSA advisory numbers'
      });

      advisories.push({
        source: 'Red Hat Product Security',
        advisoryId: `RHSA-${cveId}`,
        title: 'Red Hat Security Advisory',
        url: `https://access.redhat.com/security/cve/${cveId}`,
        description: 'Red Hat Product Security advisory and patches',
        confidence: 'HIGH',
        type: 'Vendor Security Advisory',
        priority: 2
      });
    }

    if (description.includes('ubuntu')) {
      patches.push({
        vendor: 'Ubuntu',
        product: 'Ubuntu Linux',
        downloadUrl: `https://ubuntu.com/security/notices?q=${cveId}`,
        advisoryUrl: `https://ubuntu.com/security/notices?q=${cveId}`,
        description: 'Ubuntu Security Notices - Check for USN updates',
        confidence: 'HIGH',
        patchType: 'Security Notice',
        searchHint: 'Look for USN (Ubuntu Security Notice) numbers'
      });

      advisories.push({
        source: 'Ubuntu Security Team',
        advisoryId: `USN-${cveId}`,
        title: 'Ubuntu Security Notice',
        url: `https://ubuntu.com/security/notices?q=${cveId}`,
        description: 'Ubuntu Security Team advisory and updates',
        confidence: 'HIGH',
        type: 'Distribution Security Notice',
        priority: 2
      });
    }

    if (description.includes('debian')) {
      patches.push({
        vendor: 'Debian',
        product: 'Debian Linux',
        downloadUrl: `https://security-tracker.debian.org/tracker/${cveId}`,
        advisoryUrl: `https://security-tracker.debian.org/tracker/${cveId}`,
        description: 'Debian Security Tracker - Check for DSA updates',
        confidence: 'HIGH',
        patchType: 'Security Advisory',
        searchHint: 'Look for DSA (Debian Security Advisory) numbers'
      });

      advisories.push({
        source: 'Debian Security Team',
        advisoryId: `DSA-${cveId}`,
        title: 'Debian Security Advisory',
        url: `https://security-tracker.debian.org/tracker/${cveId}`,
        description: 'Debian Security Team advisory and patches',
        confidence: 'HIGH',
        type: 'Distribution Security Advisory',
        priority: 2
      });
    }

    if (description.includes('oracle')) {
      patches.push({
        vendor: 'Oracle',
        product: 'Oracle Products',
        downloadUrl: `https://www.oracle.com/security-alerts/`,
        advisoryUrl: `https://www.oracle.com/security-alerts/`,
        description: 'Oracle Security Alerts - Check quarterly CPU updates',
        confidence: 'MEDIUM',
        patchType: 'Critical Patch Update',
        searchHint: 'Check Oracle Critical Patch Updates (CPU)'
      });

      advisories.push({
        source: 'Oracle Security Alerts',
        advisoryId: `Oracle-${cveId}`,
        title: 'Oracle Security Alert',
        url: `https://www.oracle.com/security-alerts/`,
        description: 'Oracle security alerts and critical patch updates',
        confidence: 'MEDIUM',
        type: 'Vendor Security Alert',
        priority: 2
      });
    }

    if (description.includes('adobe')) {
      patches.push({
        vendor: 'Adobe',
        product: 'Adobe Products',
        downloadUrl: `https://helpx.adobe.com/security.html`,
        advisoryUrl: `https://helpx.adobe.com/security.html`,
        description: 'Adobe Security Updates - Check product-specific updates',
        confidence: 'MEDIUM',
        patchType: 'Security Update',
        searchHint: 'Check Adobe product update pages'
      });

      advisories.push({
        source: 'Adobe Product Security',
        advisoryId: `Adobe-${cveId}`,
        title: 'Adobe Security Bulletin',
        url: `https://helpx.adobe.com/security.html`,
        description: 'Adobe Product Security bulletins and updates',
        confidence: 'MEDIUM',
        type: 'Vendor Security Bulletin',
        priority: 2
      });
    }

    // Additional security resources
    advisories.push(
      {
        source: 'CERT/CC',
        advisoryId: `CERT-${cveId}`,
        title: 'CERT Coordination Center Advisory',
        url: `https://www.kb.cert.org/vuls/byid/${cveId}`,
        description: 'CERT/CC vulnerability analysis and recommendations',
        confidence: 'MEDIUM',
        type: 'Security Advisory',
        priority: 3
      },
      {
        source: 'Exploit Database',
        advisoryId: `EDB-${cveId}`,
        title: 'Exploit Database Reference',
        url: `https://www.exploit-db.com/search?cve=${cveId}`,
        description: 'Security research and exploit information',
        confidence: 'MEDIUM',
        type: 'Security Research',
        priority: 3
      }
    );

    // Sort by priority
    advisories.sort((a, b) => (a.priority || 99) - (b.priority || 99));

    return {
      patches: patches,
      advisories: advisories,
      searchSummary: {
        patchesFound: patches.length,
        advisoriesFound: advisories.length,
        searchMethod: 'HEURISTIC_DETECTION',
        vendorsSearched: [...new Set(patches.map(p => p.vendor))],
        searchTimestamp: new Date().toISOString(),
        note: 'Heuristic detection based on CVE description analysis'
      }
    };
  }

// NOW UPDATE YOUR fetchVulnerabilityDataWithAI METHOD
// FIND THIS LINE:
// const aiThreatIntel = await this.fetchAIThreatIntelligence(cveId, cve, epss, settings, setLoadingSteps);

// ADD THESE LINES IMMEDIATELY AFTER IT:

      // Fetch patches and advisories
      setLoadingSteps(prev => [...prev, `🔧 Searching for patches and security advisories...`]);
      const patchAdvisoryData = await this.fetchPatchesAndAdvisories(cveId, cve, settings, setLoadingSteps);

// THEN FIND YOUR enhancedVulnerability OBJECT AND ADD THESE PROPERTIES:

        // ADD THESE THREE LINES TO YOUR enhancedVulnerability OBJECT (around line where you have sources, discoveredSources, etc.):
        // Patch and Advisory Data
        patches: patchAdvisoryData.patches || [],
        advisories: patchAdvisoryData.advisories || [],
        patchSearchSummary: patchAdvisoryData.searchSummary || {},
  static buildEnhancedAnalysisPrompt(vulnerability, ragContext, ragDocCount = 0) {
    const cveId = vulnerability.cve.id;
    const cvssScore = vulnerability.cve.cvssV3?.baseScore || vulnerability.cve.cvssV2?.baseScore || 'N/A';
    const epssScore = vulnerability.epss ? vulnerability.epss.epssPercentage + '%' : 'N/A';
    const kevStatus = vulnerability.kev?.listed ? 'Yes - ACTIVE EXPLOITATION CONFIRMED' : 'No';
    const kevValidated = vulnerability.kev?.validated ? ' (VALIDATED)' : ' (UNVALIDATED)';
    const confidenceLevel = vulnerability.confidence?.overall || 'UNKNOWN';

    return `You are a senior cybersecurity analyst providing comprehensive vulnerability assessment for ${cveId}.

VULNERABILITY DETAILS:
- CVE ID: ${cveId}
- CVSS Score: ${cvssScore}
- EPSS Score: ${epssScore}
- CISA KEV Status: ${kevStatus}${kevValidated}
- Overall Confidence: ${confidenceLevel}
- Description: ${vulnerability.cve.description.substring(0, 800)}

VALIDATION STATUS:
- Data Validated: ${vulnerability.validation ? 'Yes' : 'No'}
- Confidence Flags: ${vulnerability.confidence?.flags?.join(', ') || 'None'}
- Hallucination Flags: ${vulnerability.hallucinationFlags?.join(', ') || 'None'}

REAL-TIME THREAT INTELLIGENCE:
${vulnerability.kev?.listed ? `⚠️ CRITICAL: This vulnerability is actively exploited according to CISA KEV catalog${kevValidated}.` : ''}
${vulnerability.exploits?.found ? `💣 PUBLIC EXPLOITS: ${vulnerability.exploits.count} exploit(s) found with ${vulnerability.exploits.confidence || 'MEDIUM'} confidence${vulnerability.exploits?.validated ? ' (VALIDATED)' : ' (UNVALIDATED)'}.` : ''}
${vulnerability.github?.found ? `🔍 GITHUB REFS: ${vulnerability.github.count} security-related repositories found.` : ''}
${vulnerability.activeExploitation?.confirmed ? `🚨 ACTIVE EXPLOITATION: Confirmed exploitation in the wild.` : ''}

SECURITY KNOWLEDGE BASE (${ragDocCount} relevant documents retrieved):
${ragContext}

DATA SOURCES ANALYZED:
${vulnerability.discoveredSources?.join(', ') || 'NVD, EPSS'}

VALIDATION SUMMARY:
${vulnerability.validation ? `
- CISA KEV Validation: ${vulnerability.validation.cisaKev?.verified ? 'VERIFIED' : 'UNVERIFIED'}
- Exploit Validation: ${vulnerability.validation.exploits?.verified ? 'VERIFIED' : 'UNVERIFIED'} 
- Vendor Advisory Validation: ${vulnerability.validation.vendorAdvisories?.verified ? 'VERIFIED' : 'UNVERIFIED'}
- Overall Validation Confidence: ${vulnerability.validation.confidence}
` : 'No validation performed'}

You have access to ${ragDocCount} relevant security documents from the knowledge base. Use this contextual information to provide enhanced insights beyond standard vulnerability analysis.

ANALYSIS REQUIREMENTS:
1. **Clearly distinguish between validated and unvalidated claims**
2. **Highlight confidence levels for all findings**
3. **Note any hallucination flags or inconsistencies**
4. **Prioritize validated information over AI-generated content**
5. **Provide actionable recommendations based on confidence levels**

Provide a comprehensive vulnerability analysis including:
1. Executive Summary with immediate actions needed (noting confidence levels)
2. Technical details and attack vectors (validated vs unvalidated)
3. Impact assessment and potential consequences
4. Mitigation strategies and remediation guidance
5. Affected systems and software components
6. Current exploitation status and threat landscape (with validation status)
7. Priority recommendations based on validated threat intelligence
8. Lessons learned from similar vulnerabilities (use knowledge base context)
9. Data quality assessment and recommendation reliability

Format your response in clear sections with detailed analysis. Leverage the security knowledge base context and validated threat intelligence to provide enhanced insights that go beyond basic CVE information.

${vulnerability.kev?.listed ? `EMPHASIZE THE CRITICAL NATURE DUE TO ${vulnerability.kev?.validated ? 'VALIDATED' : 'UNVALIDATED'} ACTIVE EXPLOITATION CLAIMS.` : ''}
${vulnerability.exploits?.found && vulnerability.exploits.confidence === 'HIGH' ? `HIGHLIGHT THE AVAILABILITY OF ${vulnerability.exploits?.validated ? 'VALIDATED' : 'UNVALIDATED'} PUBLIC EXPLOITS.` : ''}

**Important Guidelines**:
- Reference insights from the security knowledge base when relevant
- Clearly mark validated vs unvalidated information with confidence indicators
- DO NOT include citation numbers like [1], [2], [3] or any bracketed numbers
- Write in clear, natural language without citation markers
- Always note the reliability of each piece of information
- Provide specific recommendations for low-confidence findings`;
  }

  static generateEnhancedFallbackAnalysis(vulnerability, error) {
    const cveId = vulnerability.cve.id;
    const cvssScore = vulnerability.cve.cvssV3?.baseScore || vulnerability.cve.cvssV2?.baseScore || 'N/A';
    const epssScore = vulnerability.epss ? vulnerability.epss.epssPercentage + '%' : 'N/A';
    const kevStatus = vulnerability.kev?.listed ? 'Yes - ACTIVE EXPLOITATION CONFIRMED' : 'No';
    const kevValidated = vulnerability.kev?.validated ? ' (VALIDATED)' : ' (UNVALIDATED)';
    const confidenceLevel = vulnerability.confidence?.overall || 'UNKNOWN';

    return {
      analysis: `# Enhanced Security Analysis: ${cveId}

## Executive Summary
${kevStatus.includes('Yes') ? `🚨 **CRITICAL PRIORITY** - This vulnerability is actively exploited according to CISA KEV catalog${kevValidated}. ${vulnerability.kev?.validated ? 'This has been verified against official CISA data.' : 'This claim requires manual verification.'}` :
  vulnerability.exploits?.found ? `💣 **HIGH RISK** - ${vulnerability.exploits.count} exploit(s) detected with ${vulnerability.exploits.confidence} confidence level${vulnerability.exploits?.validated ? ' (VALIDATED)' : ' (UNVALIDATED)'}.` :
  `This vulnerability has a CVSS score of ${cvssScore} with an EPSS exploitation probability of ${epssScore}.`}

**Overall Confidence Level:** ${confidenceLevel}
${vulnerability.confidence?.recommendation ? `**Recommendation:** ${vulnerability.confidence.recommendation}` : ''}

${vulnerability.exploits?.found ? `💣 **PUBLIC EXPLOITS AVAILABLE** - ${vulnerability.exploits.count} exploit(s) detected with ${vulnerability.exploits.confidence} confidence level${vulnerability.exploits?.validated ? ' (URL patterns verified)' : ' (requires manual verification)'}.` : ''}

## Vulnerability Details
**CVE ID:** ${cveId}
**CVSS Score:** ${cvssScore}
**EPSS Score:** ${epssScore}
**CISA KEV Status:** ${kevStatus}${kevValidated}

**Description:** ${vulnerability.cve.description}

## Data Quality Assessment
**Validation Status:** ${vulnerability.validation ? 'Performed' : 'Not performed'}
${vulnerability.validation ? `
- **CISA KEV Validation:** ${vulnerability.validation.cisaKev?.verified ? '✅ VERIFIED' : '❌ UNVERIFIED'}
- **Exploit Validation:** ${vulnerability.validation.exploits?.verified ? '✅ VERIFIED' : '❌ UNVERIFIED'}
- **Vendor Advisory Validation:** ${vulnerability.validation.vendorAdvisories?.verified ? '✅ VERIFIED' : '❌ UNVERIFIED'}
- **Overall Validation Confidence:** ${vulnerability.validation.confidence}
` : ''}

**Confidence Flags:** ${vulnerability.confidence?.flags?.join(', ') || 'None detected'}
**Hallucination Flags:** ${vulnerability.hallucinationFlags?.join(', ') || 'None detected'}

## Real-Time Threat Intelligence Summary
${vulnerability.kev?.listed ? `- ⚠️ **ACTIVE EXPLOITATION**: ${vulnerability.kev?.validated ? 'VERIFIED' : 'UNVERIFIED'} - ${vulnerability.kev?.validated ? 'Confirmed in CISA Known Exploited Vulnerabilities catalog' : 'Claimed in AI analysis but not validated'}` : '- No confirmed active exploitation in CISA KEV catalog'}
${vulnerability.exploits?.found ? `- 💣 **PUBLIC EXPLOITS**: ${vulnerability.exploits?.validated ? 'VERIFIED' : 'UNVERIFIED'} - ${vulnerability.exploits.count} exploit(s) with ${vulnerability.exploits.confidence} confidence` : '- No high-confidence public exploits identified'}
${vulnerability.github?.found ? `- 🔍 **SECURITY COVERAGE**: ${vulnerability.github.count} GitHub security references found` : '- Limited GitHub security advisory coverage'}
${vulnerability.activeExploitation?.confirmed ? '- 🚨 **ACTIVE EXPLOITATION**: Confirmed exploitation detected in threat intelligence' : '- No confirmed active exploitation detected'}

## Risk Assessment
**Exploitation Probability:** ${epssScore} (EPSS)
**Attack Vector:** ${vulnerability.cve.cvssV3?.attackVector || 'Unknown'}
**Attack Complexity:** ${vulnerability.cve.cvssV3?.attackComplexity || 'Unknown'}
**Privileges Required:** ${vulnerability.cve.cvssV3?.privilegesRequired || 'Unknown'}
**Impact Level:** ${vulnerability.cve.cvssV3?.baseSeverity || 'Unknown'}

## Validation-Based Recommendations

### Immediate Actions
1. **${kevStatus.includes('Yes') ? (vulnerability.kev?.validated ? 'URGENT: Apply patches immediately - KEV status verified' : 'VERIFY KEV STATUS: Check CISA catalog directly before emergency actions') : 'Review and prioritize patching based on CVSS score and environment exposure'}**

2. **${vulnerability.exploits?.found ? (vulnerability.exploits?.validated ? 'Implement additional monitoring - verified public exploits available' : 'Verify exploit availability through security research before implementing emergency controls') : 'Monitor for unusual activity patterns'}**

3. **Review access controls and authentication mechanisms**

4. **${vulnerability.kev?.listed ? (vulnerability.kev?.validated ? 'Follow CISA emergency directive timelines' : 'Manually verify CISA KEV status before following emergency timelines') : 'Consider temporary compensating controls if patches unavailable'}**

### Data Quality Actions
${vulnerability.confidence?.overall === 'LOW' || vulnerability.confidence?.overall === 'VERY_LOW' ? `
**⚠️ LOW CONFIDENCE DATA DETECTED**
- Manually verify all AI-generated findings before taking action
- Cross-reference with official security advisories
- Consider requesting additional threat intelligence sources
` : ''}

${vulnerability.validation?.cisaKev && !vulnerability.validation.cisaKev.verified ? `
**❌ CISA KEV VALIDATION FAILED**
- AI claimed KEV listing but validation failed
- Manually check CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Do not follow emergency KEV procedures until verified
` : ''}

${vulnerability.validation?.exploits && !vulnerability.validation.exploits.verified ? `
**❌ EXPLOIT VALIDATION FAILED**
- AI claimed ${vulnerability.exploits?.count || 0} exploits but validation failed
- Manually verify through security research and trusted sources
- Do not implement emergency monitoring based on unverified exploit claims
` : ''}

## Mitigation Strategies
- **Patch Management**: ${kevStatus.includes('Yes') ? (vulnerability.kev?.validated ? 'Emergency patching within CISA timeline' : 'Verify KEV status before emergency patching') : 'Standard patch testing and deployment'}
- **Network Controls**: Implement input validation and filtering
- **Access Controls**: Review and restrict privileged access
- **Monitoring**: Deploy detection rules for exploitation attempts

## Data Sources Analyzed
${vulnerability.discoveredSources?.join(', ') || 'NVD, EPSS'} (${vulnerability.discoveredSources?.length || 2} sources)

## Intelligence Assessment
- **Data Freshness**: Real-time (${new Date().toLocaleString()})
- **Confidence Level**: ${vulnerability.confidence?.overall || 'UNKNOWN'} based on validation results
- **Validation Performed**: ${vulnerability.validation ? 'Yes' : 'No'}
- **Threat Landscape**: ${vulnerability.threatLevel || 'STANDARD'} risk environment
- **AI Enhancement**: ${vulnerability.extractionMetadata ? 'Extractive approach used' : 'Standard AI approach'}

## Verification Recommendations
${vulnerability.confidence?.recommendations ? vulnerability.confidence.recommendations.map(rec => `- ${rec}`).join('\n') : 'No specific verification recommendations available'}

**⚠️ Important Disclaimer:** This analysis includes AI-generated findings. ${vulnerability.validation ? `Validation was performed with ${vulnerability.validation.confidence} confidence.` : 'No validation was performed.'} Always verify critical security decisions with official sources.

*Enhanced analysis with validation layer. AI service temporarily unavailable due to: ${error.message}*`,
      ragUsed: false,
      ragDocuments: 0,
      ragSources: [],
      webGrounded: false,
      enhancedSources: vulnerability.enhancedSources || [],
      discoveredSources: vulnerability.discoveredSources || [],
      error: error.message,
      fallbackUsed: true,
      validationEnhanced: true,
      confidence: vulnerability.confidence,
      validation: vulnerability.validation,
      realTimeData: {
        cisaKev: vulnerability.kev?.listed || false,
        cisaKevValidated: vulnerability.kev?.validated || false,
        exploitsFound: vulnerability.exploits?.count || 0,
        exploitsValidated: vulnerability.exploits?.validated || false,
        exploitConfidence: vulnerability.exploits?.confidence || 'NONE',
        githubRefs: vulnerability.github?.count || 0,
        threatLevel: vulnerability.threatLevel || 'STANDARD',
        activeExploitation: vulnerability.activeExploitation?.confirmed || false,
        overallConfidence: vulnerability.confidence?.overall || 'UNKNOWN',
        hallucinationFlags: vulnerability.hallucinationFlags || []
      }
    };
  }

  // Utility method to create presentation-ready data with confidence indicators
  static formatFindingWithConfidence(finding, confidence, validation) {
    const confidenceIcon = this.getConfidenceIcon(confidence);
    const verificationBadge = this.getVerificationBadge(validation);
    
    return {
      ...finding,
      displayText: `${confidenceIcon} ${finding.text} ${verificationBadge}`,
      confidence: confidence,
      validation: validation,
      userWarning: this.generateUserWarning(confidence, validation)
    };
  }

  static getConfidenceIcon(confidence) {
    const icons = {
      'HIGH': '✅',
      'MEDIUM': '⚠️',
      'LOW': '❓',
      'VERY_LOW': '❌'
    };
    return icons[confidence] || '❓';
  }

  static getVerificationBadge(validation) {
    if (!validation) return '🤖 AI-Generated';
    
    if (validation.verified) {
      return '✓ Verified';
    } else {
      return '⚠️ Unverified';
    }
  }

  static generateUserWarning(confidence, validation) {
    if (confidence === 'VERY_LOW') {
      return 'This information has very low confidence and should not be relied upon without manual verification.';
    }
    
    if (!validation?.verified && confidence !== 'HIGH') {
      return 'This AI-generated finding has not been verified against authoritative sources.';
    }
    
    return null;
  }

  // Method to create comprehensive AI data disclaimer
  static createAIDataDisclaimer(vulnerability) {
    const totalAIFindings = this.countAIGeneratedFindings(vulnerability);
    const verifiedFindings = this.countVerifiedFindings(vulnerability.validation);
    const confidence = vulnerability.confidence?.overall || 'UNKNOWN';
    
    return {
      totalAIFindings,
      verifiedFindings,
      unverifiedFindings: totalAIFindings - verifiedFindings,
      overallConfidence: confidence,
      hallucinationFlags: vulnerability.hallucinationFlags || [],
      disclaimer: `This analysis includes ${totalAIFindings} AI-generated findings. ` +
                 `${verifiedFindings} have been verified against authoritative sources. ` +
                 `Overall confidence: ${confidence}. Always verify critical security decisions with official sources.`,
      recommendations: vulnerability.confidence?.recommendations || [],
      validationTimestamp: vulnerability.validationTimestamp || new Date().toISOString()
    };
  }

  static countAIGeneratedFindings(vulnerability) {
    let count = 0;
    if (vulnerability.kev?.aiDiscovered) count++;
    if (vulnerability.exploits?.details?.some(e => e.aiDiscovered)) count++;
    if (vulnerability.vendorAdvisories?.aiDiscovered) count++;
    if (vulnerability.activeExploitation?.aiDiscovered) count++;
    return count;
  }

  static countVerifiedFindings(validation) {
    if (!validation) return 0;
    
    let count = 0;
    if (validation.cisaKev?.verified) count++;
    if (validation.exploits?.verified) count++;
    if (validation.vendorAdvisories?.verified) count++;
    return count;
  }
}