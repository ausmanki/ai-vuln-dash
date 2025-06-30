import { CONSTANTS } from '../utils/constants';
import { utils } from '../utils/helpers';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { APIService } from './APIService'; // For fetchWithFallback

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

  const searchPrompt = `You are a cybersecurity analyst researching ${cveId}. Use web search to find current information.

SEARCH FOR AND ANALYZE:
1. CISA KEV Status: Search "CISA Known Exploited Vulnerabilities ${cveId}" - Is this CVE listed in the CISA KEV catalog? If yes, get exact details including due date and required actions.
2. Active Exploitation: Search "${cveId} active exploitation in the wild ransomware APT" - Are there confirmed reports of this vulnerability being actively exploited by threat actors?
3. Public Exploits Discovery:
   - Search "${cveId} exploit proof of concept github metasploit"
   - Search "${cveId} working exploit code demonstration"
   - Search "${cveId} exploit-db vulnerability scanner modules"
   - Find evidence of exploits but DO NOT include URLs unless you can verify they are real GitHub repos or exploit-db entries
4. Vendor Security Advisories:
   - Search "${cveId} security advisory Microsoft Adobe Oracle"
   - Search "${cveId} vendor patch security bulletin"
   - Find vendor names and patch status but DO NOT generate advisory URLs
5. Threat Intelligence & IOCs: Search "${cveId} threat intelligence IOCs indicators compromise" - Any IOCs, attack patterns, or threat actor usage?
6. CVE Validation & False Positive Analysis:
   - Search "${cveId} false positive disputed invalid vulnerability"
   - Search "${cveId} vendor dispute CVE rejection withdrawn"
   - Search "${cveId} security researcher validation confirmation"
   - Analyze if this is a legitimate vulnerability or false positive
7. Technical Analysis:
   - Search "${cveId} technical analysis root cause impact"
   - Search "${cveId} vulnerability details exploitation method"

**CRITICAL URL HANDLING RULES**:
1. DO NOT generate or guess any URLs
2. DO NOT include URLs in the response unless you found them in actual search results
3. For vendor advisories: Only provide the vendor name (e.g., "Microsoft", "Oracle", "Red Hat")
4. For exploits: Only include GitHub URLs if you found actual repositories, otherwise just mention the source name
5. For patches: Only include download URLs if explicitly found in search results
6. For validation sources: Only list source names like "NVD", "Mitre", "SecurityFocus", blog names, etc.
7. If you mention a blog or news site, just use its name without any URL

CURRENT CVE DATA:
- CVE: ${cveId}
- CVSS: ${cveData?.cvssV3?.baseScore || 'Unknown'} (${cveData?.cvssV3?.baseSeverity || 'Unknown'})
- EPSS: ${epssData?.epssPercentage || 'Unknown'}%
- Attack Vector: ${cveData?.cvssV3?.attackVector || 'Unknown'}
- Attack Complexity: ${cveData?.cvssV3?.attackComplexity || 'Unknown'}
- Description: ${cveData?.description?.substring(0, 300) || 'No description'}

For each search result, provide:
- Source credibility (CISA, vendor, security researcher, etc.)
- Specific findings with dates and URLs
- Exploitation status (confirmed/suspected/none)
- Available exploits with specific URLs and types
- Vendor advisories and patch information with URLs
- Validation status and any disputes
- Recommended actions

**IMPORTANT**: Actively search for and discover:
- Specific exploit repositories and POC code
- Vendor security advisories and patches
- Technical analysis and validation studies
- Any CVE disputes or false positive claims
- Real-world exploitation evidence

**CRITICAL URL HANDLING RULES**:
- For "sources" arrays, only provide source/vendor names, NOT URLs (e.g., "Microsoft", "Red Hat", "CISA")
- For specific advisory URLs, only include them if you can verify they are real and working
- Do NOT generate or guess URLs - if you don't have a real URL, leave the url field empty or use ""
- For exploit URLs, only include actual GitHub repos or exploit-db links you found
- For vendor advisory URLs, only include if you found the actual advisory page

Return your findings in this enhanced JSON structure:
{
  "cisaKev": { "listed": boolean, "details": "string", "dueDate": "string", "source": "string", "emergencyDirective": boolean, "aiDiscovered": true },
  "activeExploitation": { "confirmed": boolean, "details": "string", "sources": ["string"], "threatActors": ["string"], "campaigns": ["string"], "aiDiscovered": true },
  "exploitDiscovery": { "found": boolean, "totalCount": number, "exploits": [{ "type": "string", "url": "string", "source": "string", "description": "string", "reliability": "string", "dateFound": "string" }], "githubRepos": number, "exploitDbEntries": number, "metasploitModules": number, "confidence": "string", "aiDiscovered": true },
  "vendorAdvisories": { "found": boolean, "count": number, "advisories": [{ "vendor": "string", "title": "string", "url": "", "patchAvailable": boolean, "patchUrl": "", "severity": "string", "publishDate": "string" }], "patchStatus": "string", "aiDiscovered": true },
  "cveValidation": { "isValid": boolean, "confidence": "string", "validationSources": ["string"], "disputes": [{ "source": "string", "reason": "string", "url": "", "date": "string" }], "falsePositiveIndicators": ["string"], "legitimacyEvidence": ["string"], "recommendation": "string", "aiDiscovered": true },
  "technicalAnalysis": { "rootCause": "string", "exploitMethod": "string", "impactAnalysis": "string", "mitigations": ["string"], "sources": ["string"], "aiDiscovered": true },
  "threatIntelligence": { "iocs": ["string"], "threatActors": ["string"], "campaignDetails": "string", "ransomwareUsage": boolean, "aptGroups": ["string"], "aiDiscovered": true },
  "intelligenceSummary": { "sourcesAnalyzed": number, "exploitsFound": number, "vendorAdvisoriesFound": number, "activeExploitation": boolean, "cisaKevListed": boolean, "cveValid": boolean, "threatLevel": "string", "dataFreshness": "string", "analysisMethod": "string", "confidenceLevel": "string", "aiEnhanced": true },
  "overallThreatLevel": "string", "lastUpdated": "string", "summary": "string"
}

IMPORTANT:
- Do NOT include citation numbers like [1], [2], [3] or any bracketed numbers in your responses
- Write all text in natural language without any citation markers
- Focus on clear, actionable intelligence without reference numbers
- CRITICAL: Do NOT generate any URLs. Only include URLs if you found them in actual search results and can verify they are real
- For all sources, advisories, and validation sources, provide NAMES ONLY (no URLs)
- The frontend will map source names to appropriate URLs to avoid 404 errors`;

  try {
    const requestBody = {
      contents: [{ parts: [{ text: searchPrompt }] }],
      generationConfig: { temperature: 0.1, topK: 1, topP: 0.95, maxOutputTokens: 8192, candidateCount: 1 },
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
    const aiResponse = data.candidates[0].content.parts[0].text;

    updateSteps(prev => [...prev, `✅ AI completed web-based threat intelligence analysis for ${cveId}`]);

    const findings = parseAIThreatIntelligence(aiResponse, cveId, setLoadingSteps);

    if (ragDatabase.initialized) {
      await ragDatabase.addDocument(
        `AI Web-Based Threat Intelligence for ${cveId}: CISA KEV: ${findings.cisaKev.listed ? 'LISTED' : 'Not Listed'}, Active Exploitation: ${findings.activeExploitation.confirmed ? 'CONFIRMED' : 'None'}, Public Exploits: ${findings.exploitDiscovery?.totalCount || 0}, Threat Level: ${findings.overallThreatLevel}. ${findings.summary}`,
        { title: `AI Web Threat Intelligence - ${cveId}`, category: 'ai-web-intelligence', tags: ['ai-web-search', 'threat-intelligence', cveId.toLowerCase()], source: 'gemini-web-search' }
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
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  try {
    const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      updateSteps(prev => [...prev, `📊 Parsed structured threat intelligence for ${cveId}`]);
      return parsed;
    }
  } catch (e) {
    console.log('Failed to parse JSON, analyzing text response...');
  }

  const findings = { /* Default/fallback structure */ };
  // Fallback text parsing logic (simplified for brevity)
  updateSteps(prev => [...prev, `📈 AI analysis: ${findings.overallThreatLevel || 'UNKNOWN'} threat level determined`]);
  return findings;
};

export const performHeuristicAnalysis = async (cveId, cveData, epssData, setLoadingSteps) => {
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  updateSteps(prev => [...prev, `🔍 Performing advanced heuristic analysis for ${cveId}...`]);

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

  // Simplified additional heuristic logic
  const threatLevel = riskScore >= 8 ? 'CRITICAL' : riskScore >= 6 ? 'HIGH' : 'MEDIUM';
  updateSteps(prev => [...prev, `📊 Heuristic analysis complete: ${threatLevel} threat level (score: ${riskScore})`]);

  return { /* Default/fallback structure based on heuristics */ };
};
