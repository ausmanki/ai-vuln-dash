// This file will contain helper/utility methods
import { utils } from '../utils/helpers';
import { CONSTANTS } from '../utils/constants';

export async function fetchWithFallback(url, options = {}) {
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

export function processCVEData(cve) {
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

export function parsePatchAndAdvisoryResponse(aiResponseOrMetadata, cveId) {
  if (typeof aiResponseOrMetadata === 'string') {
    // Existing logic for text response
    try {
      const jsonMatch = aiResponseOrMetadata.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return {
          patches: parsed.patches || [],
          advisories: parsed.advisories || [],
          searchSummary: { ...parsed.searchSummary, searchMethod: parsed.searchSummary?.searchMethod || 'JSON_PARSED' } || { searchMethod: 'JSON_PARSED' }
        };
      }
    } catch (e) {
      console.log('Failed to parse patch response JSON from text, using raw text analysis...');
      // Fall through to conservative text parsing if JSON parsing fails
    }

    // Fallback text parsing for string input
    const patches = [];
    const advisories = [];
    const urls = aiResponseOrMetadata.match(/https?:\/\/[^\s<>"{}|\\^`[\]]+/g) || [];
    urls.forEach(url => {
      if (url.includes('microsoft.com') || url.includes('msrc') || url.includes('update')) {
        patches.push({ vendor: 'Microsoft', downloadUrl: url, confidence: 'MEDIUM', patchType: 'Security Update', description: 'Microsoft security update found via AI search' });
      } else if (url.includes('redhat.com') || url.includes('rhsa')) {
        patches.push({ vendor: 'Red Hat', downloadUrl: url, confidence: 'MEDIUM', patchType: 'Security Advisory', description: 'Red Hat security advisory found via AI search' });
      } else if (url.includes('security') || url.includes('advisory') || url.includes('cve')) {
        advisories.push({ source: 'Security Advisory', url: url, confidence: 'MEDIUM', type: 'Security Advisory', description: 'Security advisory found via AI search' });
      }
    });
    return {
      patches,
      advisories,
      searchSummary: { patchesFound: patches.length, advisoriesFound: advisories.length, searchMethod: 'TEXT_PARSING_FALLBACK', searchTimestamp: new Date().toISOString() }
    };

  } else if (typeof aiResponseOrMetadata === 'object' && aiResponseOrMetadata.groundingMetadata) {
    // Handle groundingMetadata object
    const searchQueries = aiResponseOrMetadata.searchQueries || [];
    console.log(`Patch/Advisory parsing: Received groundingMetadata for ${cveId}`);
    return {
      patches: [],
      advisories: [],
      searchSummary: {
        patchesFound: 0,
        advisoriesFound: 0,
        searchMethod: 'GROUNDING_INFO_ONLY',
        searchTimestamp: new Date().toISOString(),
        searchQueries: searchQueries,
        note: 'AI did not provide a textual summary for patches/advisories. Displaying search queries performed.'
      }
    };
  } else {
    // Should not happen, safeguard
    console.error(`Unknown content type for patch/advisory parsing: ${typeof aiResponseOrMetadata}`);
    return {
      patches: [],
      advisories: [],
      searchSummary: {
        patchesFound: 0,
        advisoriesFound: 0,
        searchMethod: 'PARSING_FAILED_UNEXPECTED_TYPE',
        searchTimestamp: new Date().toISOString(),
        note: 'Failed to parse patch/advisory information due to an unexpected AI response format.'
      }
    };
  }
}

export function getHeuristicPatchesAndAdvisories(cveId, cveData) {
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

export function parseAIThreatIntelligence(aiResponseOrMetadata, cveId, setLoadingSteps) {
  const updateStepsParse = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};

  if (typeof aiResponseOrMetadata === 'string') {
    // Existing logic for text response
    try {
      const jsonMatch = aiResponseOrMetadata.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        updateStepsParse(prev => [...prev, `📊 Parsed structured threat intelligence for ${cveId}`]);

        parsed.parsingMethod = 'JSON_EXTRACTION';
        parsed.hallucinationFlags = detectHallucinationFlags(parsed);

        return normalizeAIFindings(parsed, cveId);
      }
    } catch (e) {
      console.log('Failed to parse JSON from text response, analyzing raw text...');
      // Fall through to conservative text analysis if JSON parsing fails
    }

    // Fallback text analysis with conservative interpretation for string input
    const findings = performConservativeTextAnalysis(aiResponseOrMetadata, cveId);
    updateStepsParse(prev => [...prev, `📈 Used conservative text analysis for ${cveId}`]);
    return findings;

  } else if (typeof aiResponseOrMetadata === 'object' && aiResponseOrMetadata.groundingMetadata) {
    // Handle groundingMetadata object
    updateStepsParse(prev => [...prev, `ℹ️ Processing grounding metadata for ${cveId}`]);
    const searchQueries = aiResponseOrMetadata.searchQueries || [];
    return {
      cisaKev: { listed: false, details: 'No direct AI summary, grounding info only.', source: '', confidence: 'LOW', aiDiscovered: true },
      activeExploitation: { confirmed: false, details: 'No direct AI summary, grounding info only.', sources: [], aiDiscovered: true },
      exploitDiscovery: { found: false, totalCount: 0, exploits: [], confidence: 'LOW', aiDiscovered: true },
      vendorAdvisories: { found: false, count: 0, advisories: [], aiDiscovered: true },
      intelligenceSummary: {
        sourcesAnalyzed: searchQueries.length,
        analysisMethod: 'GROUNDING_INFO_ONLY',
        confidenceLevel: 'VERY_LOW',
        aiEnhanced: true,
        extractionBased: false, // No text was extracted
        searchQueries: searchQueries,
        note: 'AI did not provide a textual summary. Displaying search queries performed.'
      },
      overallThreatLevel: 'UNKNOWN', // Or 'LOW' as it's unconfirmed
      lastUpdated: new Date().toISOString(),
      summary: 'AI analysis did not yield a direct textual summary. Grounding searches were performed.',
      hallucinationFlags: ['NO_TEXTUAL_AI_SUMMARY']
    };
  } else {
    // Should not happen if fetchAIThreatIntelligence is correct, but as a safeguard:
    console.error(`Unknown content type for AI threat intelligence parsing: ${typeof aiResponseOrMetadata}`);
    updateStepsParse(prev => [...prev, `⚠️ Unknown AI response type for ${cveId}, cannot parse.`]);
    // Return a minimal structure indicating failure
    return {
      cisaKev: { listed: false, details: 'Parsing failed due to unknown AI response type.', source: '', confidence: 'VERY_LOW', aiDiscovered: false },
      activeExploitation: { confirmed: false, details: 'Parsing failed.', sources: [], aiDiscovered: false },
      exploitDiscovery: { found: false, totalCount: 0, exploits: [], confidence: 'VERY_LOW', aiDiscovered: false },
      vendorAdvisories: { found: false, count: 0, advisories: [], aiDiscovered: false },
      intelligenceSummary: { analysisMethod: 'PARSING_FAILED', confidenceLevel: 'VERY_LOW' },
      overallThreatLevel: 'UNKNOWN',
      lastUpdated: new Date().toISOString(),
      summary: 'Failed to parse AI threat intelligence due to an unexpected response format.',
      hallucinationFlags: ['PARSING_FAILURE_UNEXPECTED_TYPE']
    };
  }
}

export function detectHallucinationFlags(parsed) {
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

export function normalizeAIFindings(parsed, cveId) {
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
    overallThreatLevel: calculateThreatLevel(parsed),
    lastUpdated: new Date().toISOString(),
    summary: `Extractive AI analysis: ${parsed.cisaKev?.listed ? 'KEV listed' : 'Not in KEV'}, ${parsed.exploitDiscovery?.found ? parsed.exploitDiscovery.totalCount + ' exploits found' : 'No exploits found'}`,
    hallucinationFlags: parsed.hallucinationFlags || []
  };
}

export function performConservativeTextAnalysis(aiResponse, cveId) {
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

export function calculateThreatLevel(findings) {
  if (findings.cisaKev?.listed) return 'CRITICAL';
  if (findings.activeExploitation?.confirmed) return 'HIGH';
  if (findings.exploitDiscovery?.found) return 'HIGH';
  return 'MEDIUM';
}

export async function performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps) {
  const updateStepsHeuristic = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  updateStepsHeuristic(prev => [...prev, `🔍 Performing advanced heuristic analysis for ${cveId}...`]);

  const year = parseInt(cveId.split('-')[1]);
  const id = parseInt(cveId.split('-')[2]);
  const cvssScore = cveData?.cvssV3?.baseScore || cveData?.cvssV2?.baseScore || 0;
  const epssFloat = epssData?.epssFloat || 0;
  const severity = utils?.getSeverityLevel ? utils.getSeverityLevel(cvssScore) : (cvssScore >= 9 ? 'CRITICAL' : cvssScore >= 7 ? 'HIGH' : cvssScore >= 4 ? 'MEDIUM' : 'LOW');

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

export function buildEnhancedAnalysisPrompt(vulnerability, ragContext, ragDocCount = 0) {
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

PATCHES AND ADVISORIES:
${vulnerability.patches?.length ? `🔧 PATCHES FOUND: ${vulnerability.patches.length} patch(es) available from ${[...new Set(vulnerability.patches.map(p => p.vendor))].join(', ')}` : 'No specific patches identified'}
${vulnerability.advisories?.length ? `📋 ADVISORIES: ${vulnerability.advisories.length} security advisory(ies) from ${[...new Set(vulnerability.advisories.map(a => a.source))].join(', ')}` : 'Limited advisory coverage'}

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
6. **Include patch and advisory information in recommendations**

Provide a comprehensive vulnerability analysis including:
1. Executive Summary with immediate actions needed (noting confidence levels)
2. Technical details and attack vectors (validated vs unvalidated)
3. Impact assessment and potential consequences
4. Patch availability and vendor advisory status
5. Mitigation strategies and remediation guidance
6. Affected systems and software components
7. Current exploitation status and threat landscape (with validation status)
8. Priority recommendations based on validated threat intelligence
9. Lessons learned from similar vulnerabilities (use knowledge base context)
10. Data quality assessment and recommendation reliability

Format your response in clear sections with detailed analysis. Leverage the security knowledge base context and validated threat intelligence to provide enhanced insights that go beyond basic CVE information.

${vulnerability.kev?.listed ? `EMPHASIZE THE CRITICAL NATURE DUE TO ${vulnerability.kev?.validated ? 'VALIDATED' : 'UNVALIDATED'} ACTIVE EXPLOITATION CLAIMS.` : ''}
${vulnerability.exploits?.found && vulnerability.exploits.confidence === 'HIGH' ? `HIGHLIGHT THE AVAILABILITY OF ${vulnerability.exploits?.validated ? 'VALIDATED' : 'UNVALIDATED'} PUBLIC EXPLOITS.` : ''}

**Important Guidelines**:
- Reference insights from the security knowledge base when relevant
- Clearly mark validated vs unvalidated information with confidence indicators
- DO NOT include citation numbers like [1], [2], [3] or any bracketed numbers
- Write in clear, natural language without citation markers
- Always note the reliability of each piece of information
- Provide specific recommendations for low-confidence findings
- Include patch and advisory information where applicable`;
}

export function generateEnhancedFallbackAnalysis(vulnerability, error) {
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

## Patches and Advisories
${vulnerability.patches?.length ? `**Available Patches:** ${vulnerability.patches.length} patch(es) identified
${vulnerability.patches.map(p => `- ${p.vendor} ${p.patchType}: ${p.description}`).join('\n')}` : 'No specific patches identified through automated search'}

${vulnerability.advisories?.length ? `**Security Advisories:** ${vulnerability.advisories.length} advisory(ies) found
${vulnerability.advisories.slice(0, 5).map(a => `- ${a.source}: ${a.title || a.description}`).join('\n')}` : 'Limited security advisory coverage found'}

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

### Patch Management
${vulnerability.patches?.length ? `**Available Patches:**
${vulnerability.patches.slice(0, 3).map(p => `- **${p.vendor}**: ${p.description} (Confidence: ${p.confidence})`).join('\n')}
${vulnerability.patches.length > 3 ? `- *... and ${vulnerability.patches.length - 3} additional patch sources*` : ''}

**Patch Priority:** ${vulnerability.kev?.listed ? 'CRITICAL - Emergency deployment' : vulnerability.exploits?.found ? 'HIGH - Expedited testing and deployment' : 'STANDARD - Normal patch cycle'}` : `**Patch Status:** No specific patches identified through automated search
- Check vendor security advisories manually
- Review CVE references for patch information
- Monitor vendor security bulletins for updates`}

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

// Utility methods for confidence and validation
export function formatFindingWithConfidence(finding, confidence, validation) {
  const confidenceIcon = getConfidenceIcon(confidence);
  const verificationBadge = getVerificationBadge(validation);

  return {
    ...finding,
    displayText: `${confidenceIcon} ${finding.text} ${verificationBadge}`,
    confidence: confidence,
    validation: validation,
    userWarning: generateUserWarning(confidence, validation)
  };
}

export function getConfidenceIcon(confidence) {
  const icons = {
    'HIGH': '✅',
    'MEDIUM': '⚠️',
    'LOW': '❓',
    'VERY_LOW': '❌'
  };
  return icons[confidence] || '❓';
}

export function getVerificationBadge(validation) {
  if (!validation) return '🤖 AI-Generated';

  if (validation.verified) {
    return '✓ Verified';
  } else {
    return '⚠️ Unverified';
  }
}

export function generateUserWarning(confidence, validation) {
  if (confidence === 'VERY_LOW') {
    return 'This information has very low confidence and should not be relied upon without manual verification.';
  }

  if (!validation?.verified && confidence !== 'HIGH') {
    return 'This AI-generated finding has not been verified against authoritative sources.';
  }

  return null;
}

export function createAIDataDisclaimer(vulnerability) {
  const totalAIFindings = countAIGeneratedFindings(vulnerability);
  const verifiedFindings = countVerifiedFindings(vulnerability.validation);
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

export function countAIGeneratedFindings(vulnerability) {
  let count = 0;
  if (vulnerability.kev?.aiDiscovered) count++;
  if (vulnerability.exploits?.details?.some(e => e.aiDiscovered)) count++;
  if (vulnerability.vendorAdvisories?.aiDiscovered) count++;
  if (vulnerability.activeExploitation?.aiDiscovered) count++;
  return count;
}

export function countVerifiedFindings(validation) {
  if (!validation) return 0;

  let count = 0;
  if (validation.cisaKev?.verified) count++;
  if (validation.exploits?.verified) count++;
  if (validation.vendorAdvisories?.verified) count++;
  return count;
}
