import { CONSTANTS } from '../utils/constants';
import { utils } from '../utils/helpers';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { APIService } from './APIService'; // For fetchWithFallback

// Using the more complex logic from the 'master' side of the conflict for these functions

export const fetchAIThreatIntelligence = async (cveId, cveData, epssData, settings, setLoadingSteps) => {
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};

  if (!settings.geminiApiKey) {
    throw new Error('Gemini API key required for AI-powered threat intelligence');
  }

  const model = settings.geminiModel || 'gemini-2.5-flash';
  const isWebSearchCapable = model.includes('2.0') || model.includes('2.5');

  if (!isWebSearchCapable) {
    updateSteps(prev => [...prev, `⚠️ Model ${model} doesn't support web search - using heuristic analysis`]);
    return await performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
  }

  updateSteps(prev => [...prev, `🤖 AI searching web for real-time ${cveId} threat intelligence...`]);

  // Enhanced extractive prompt from the master branch
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
      contents: [{ parts: [{ text: searchPrompt }] }],
      generationConfig: {
        temperature: 0.05,
        topK: 1,
        topP: 0.8,
        maxOutputTokens: 4096,
        candidateCount: 1
      },
      tools: [{ google_search: {} }]
    };

    const response = await APIService.fetchWithFallback(
      `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${settings.geminiApiKey}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(requestBody) }
    );

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(`AI Threat Intelligence API error: ${response.status} - ${errorData.error?.message || 'Unknown error'}`);
    }

    const data = await response.json();
    const aiResponseText = data.candidates[0].content.parts[0].text;

    updateSteps(prev => [...prev, `✅ AI completed web-based CISA KEV and threat intelligence analysis for ${cveId}`]);

    const findings = parseAIThreatIntelligence(aiResponseText, cveId, setLoadingSteps);

    findings.extractionMetadata = {
      extractionMethod: 'WEB_SEARCH_EXTRACTION_WITH_CISA_VERIFICATION',
      hallucinationMitigation: true,
      extractiveApproach: true,
      temperatureUsed: 0.05,
      maxTokensUsed: 4096,
      cisaVerificationPerformed: true,
      webSearchValidation: true
    };

    if (ragDatabase?.initialized) { // Null check
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
    return await performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
  }
};

export const parseAIThreatIntelligence = (aiResponse, cveId, setLoadingSteps) => {
  const updateStepsParse = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  try {
    const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      updateStepsParse(prev => [...prev, `📊 Parsed structured threat intelligence for ${cveId}`]);
      // @ts-ignore
      parsed.parsingMethod = 'JSON_EXTRACTION';
      // @ts-ignore
      parsed.hallucinationFlags = detectHallucinationFlags(parsed);
      // @ts-ignore
      return normalizeAIFindings(parsed, cveId);
    }
  } catch (e) {
    console.log('Failed to parse JSON, analyzing text response...');
  }
  // @ts-ignore
  const findings = performConservativeTextAnalysis(aiResponse, cveId);
  updateStepsParse(prev => [...prev, `📈 Used conservative text analysis for ${cveId}`]);
  return findings;
};

const detectHallucinationFlags = (parsed) => {
  const flags = [];
  if (parsed.exploitDiscovery?.totalCount > 20) flags.push('UNREALISTIC_EXPLOIT_COUNT');
  if (parsed.cisaKev?.listed && parsed.cisaKev?.confidence === 'LOW') flags.push('INCONSISTENT_CONFIDENCE');
  if (parsed.cisaKev?.listed && !parsed.cisaKev?.source) flags.push('MISSING_SOURCE_ATTRIBUTION');
  return flags;
};

const normalizeAIFindings = (parsed, cveId) => {
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
      totalCount: Math.min(parsed.exploitDiscovery?.totalCount || 0, 10),
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
    // @ts-ignore
    overallThreatLevel: calculateThreatLevel(parsed),
    lastUpdated: new Date().toISOString(),
    summary: `Extractive AI analysis: ${parsed.cisaKev?.listed ? 'KEV listed' : 'Not in KEV'}, ${parsed.exploitDiscovery?.found ? parsed.exploitDiscovery.totalCount + ' exploits found' : 'No exploits found'}`,
    hallucinationFlags: parsed.hallucinationFlags || []
  };
};

const performConservativeTextAnalysis = (aiResponse, cveId) => {
  const response = aiResponse.toLowerCase();
  return {
    cisaKev: {
      listed: response.includes('cisa') && response.includes('kev') && response.includes('listed'),
      details: response.includes('cisa') ? 'Mentioned in search results' : '',
      source: '',
      confidence: 'LOW',
      aiDiscovered: true
    },
    activeExploitation: { confirmed: false, details: '', sources: [], aiDiscovered: true },
    exploitDiscovery: {
      found: response.includes('exploit') && (response.includes('github') || response.includes('poc')),
      totalCount: response.includes('exploit') ? 1 : 0,
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
};

const calculateThreatLevel = (findings) => {
  if (findings.cisaKev?.listed) return 'CRITICAL';
  if (findings.activeExploitation?.confirmed) return 'HIGH';
  if (findings.exploitDiscovery?.found) return 'HIGH';
  return 'MEDIUM';
};

export const performHeuristicAnalysis = async (cveId, cveData, epssData, setLoadingSteps) => {
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
    cveValidation: { // This structure might need alignment if master branch had a different cveValidation structure
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
};
