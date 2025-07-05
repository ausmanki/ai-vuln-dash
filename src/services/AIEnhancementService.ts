import { CONSTANTS } from '../utils/constants';

// Enhanced patch and advisory retrieval integrated into AI analysis
export async function fetchPatchesAndAdvisories(cveId, cveData, settings, setLoadingSteps, fetchWithFallback, parsePatchAndAdvisoryResponse, getHeuristicPatchesAndAdvisories) {
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  updateSteps(prev => [...prev, `🔍 Searching for patches and advisories for ${cveId}...`]);

  if (!settings.geminiApiKey) {
    updateSteps(prev => [...prev, `⚠️ Using heuristic patch detection - API key required for comprehensive search`]);
    return getHeuristicPatchesAndAdvisories(cveId, cveData);
  }

  const model = settings.geminiModel || 'gemini-2.5-flash';
  const isWebSearchCapable = model.includes('2.0') || model.includes('2.5');

  if (!isWebSearchCapable) {
    updateSteps(prev => [...prev, `⚠️ Using heuristic patch detection - model doesn't support web search`]);
    return getHeuristicPatchesAndAdvisories(cveId, cveData);
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
- Find ACTUAL patch download URLs (not search pages or general vendor pages).
- Extract vendor security advisory links that are specific to the CVE.
- Get patch version numbers and release dates if available.
- Identify affected product versions if specified in the advisory.
- Note patch availability status (e.g., "Available", "Superseded", "Unavailable").
- For each patch and advisory, provide a citationUrl which is the direct URL of the page confirming the information.

NEGATIVE CONSTRAINTS:
- Do not invent URLs or patch details not found in sources.
- Do not list a patch if a direct link to its official announcement or download page is not discovered.
- Do not list general vendor security pages as advisories unless they specifically mention the CVE.

Return JSON with actual findings:
{
  "patches": [
    {
      "vendor": "vendor name",
      "product": "affected product",
      "patchVersion": "patch version",
      "downloadUrl": "ACTUAL download URL found for the patch",
      "advisoryUrl": "URL of the vendor advisory page for this patch",
      "releaseDate": "patch release date",
      "description": "patch description",
      "confidence": "HIGH/MEDIUM/LOW based on source directness",
      "patchType": "Security Update/Hotfix/Critical Patch",
      "citationUrl": "URL of the page confirming this specific patch information"
    }
  ],
  "advisories": [
    {
      "source": "source organization (e.g. Microsoft, CERT)",
      "advisoryId": "advisory ID (CVE, RHSA, etc)",
      "title": "advisory title",
      "url": "direct advisory URL for this CVE",
      "severity": "advisory severity",
      "publishDate": "publish date",
      "description": "advisory description",
      "confidence": "HIGH/MEDIUM/LOW based on source directness",
      "type": "Security Advisory/Bulletin/Alert",
      "citationUrl": "URL of the page confirming this specific advisory"
    }
  ],
  "searchSummary": {
    "patchesFound": number,
    "advisoriesFound": number,
    "vendorsSearched": ["vendor names"],
    "searchTimestamp": "current timestamp"
  }
}

CRITICAL: Only include URLs that were actually found in search results. Do not generate or guess URLs. Ensure citationUrl is provided for each entry.`;

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

    const response = await fetchWithFallback(
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
    let aiResponseContent = null;

    if (!data.candidates || data.candidates.length === 0) {
      console.error(`AI Patch/Advisory API response missing candidates for ${cveId}:`, JSON.stringify(data, null, 2));
      updateSteps(prev => [...prev, `⚠️ AI patch/advisory response missing candidates, using heuristic for ${cveId}`]);
      return getHeuristicPatchesAndAdvisories(cveId, cveData);
    }

    const candidate = data.candidates[0];

    if (candidate.content && candidate.content.parts && candidate.content.parts.length > 0 && candidate.content.parts[0].text) {
      aiResponseContent = candidate.content.parts[0].text;
      updateSteps(prev => [...prev, `✅ AI completed patch and advisory search for ${cveId}`]);
    } else if (candidate.groundingMetadata) {
      console.log(`AI Patch/Advisory: Only groundingMetadata returned for ${cveId}. Falling back to heuristic detection.`);
      updateSteps(prev => [...prev, `⚠️ AI patch/advisory response lacked text. Using heuristic data for ${cveId}`]);
      return getHeuristicPatchesAndAdvisories(cveId, cveData);
    } else {
      console.error(`AI Patch/Advisory API response candidate missing content/grounding for ${cveId}:`, JSON.stringify(data, null, 2));
      updateSteps(prev => [...prev, `⚠️ AI patch/advisory response candidate malformed, using heuristic for ${cveId}`]);
      return getHeuristicPatchesAndAdvisories(cveId, cveData);
    }

    const patchData = parsePatchAndAdvisoryResponse(aiResponseContent, cveId);

    // Enhance with heuristic patches as fallback
    const heuristicData = getHeuristicPatchesAndAdvisories(cveId, cveData);

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
    return getHeuristicPatchesAndAdvisories(cveId, cveData);
  }
}

export async function fetchAIThreatIntelligence(cveId, cveData, epssData, settings, setLoadingSteps, ragDatabase, fetchWithFallback, parseAIThreatIntelligence, performHeuristicAnalysis) {
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
- Do not invent URLs, technical details, or threat actor names not found directly in sources.

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
 - EPSS: ${epssData?.epss || 'Unknown'} (${epssData?.epssPercentage || 'Unknown'}%)
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
        "source": "source name where found (e.g., GitHub, Exploit-DB)",
        "description": "extracted description of the exploit",
        "reliability": "HIGH/MEDIUM/LOW based on source and details",
        "citationUrl": "URL of the page confirming this specific exploit"
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
        "url": "URL to the specific advisory page",
        "patchAvailable": boolean (only if explicitly stated),
        "severity": "extracted severity rating",
        "source": "source organization that published the advisory (e.g., Microsoft, Red Hat)"
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

    const response = await fetchWithFallback(
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
    let aiResponseContent = null; // Can be string (text response) or object (groundingMetadata)

    if (!data.candidates || data.candidates.length === 0) {
      console.error('AI Threat Intelligence API response missing candidates:', JSON.stringify(data, null, 2));
      // Fallback to heuristic if no candidates are provided at all
      updateSteps(prev => [...prev, `⚠️ AI response missing candidates, falling back for ${cveId}`]);
      return await performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
    }

    const candidate = data.candidates[0];

    if (candidate.content && candidate.content.parts && candidate.content.parts.length > 0 && candidate.content.parts[0].text) {
      aiResponseContent = candidate.content.parts[0].text;
      updateSteps(prev => [...prev, `✅ AI completed web-based CISA KEV and threat intelligence analysis for ${cveId}`]);
    } else if (candidate.groundingMetadata) {
      console.log(`AI Threat Intelligence: Only groundingMetadata returned for ${cveId}. Falling back to heuristic analysis.`);
      updateSteps(prev => [...prev, `⚠️ AI threat intelligence response lacked text. Using heuristic analysis for ${cveId}`]);
      return await performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
    } else {
      console.error('AI Threat Intelligence API response candidate missing content parts or grounding metadata:', JSON.stringify(data, null, 2));
      // Fallback to heuristic if candidate structure is unexpected
      updateSteps(prev => [...prev, `⚠️ AI response candidate malformed, falling back for ${cveId}`]);
      return await performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
    }

    const findings = parseAIThreatIntelligence(aiResponseContent, cveId, setLoadingSteps);

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

    if (ragDatabase?.initialized) {
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
}

export async function generateAIAnalysis(vulnerability, apiKey, model, settings = {}, ragDatabase, fetchWithFallback, buildEnhancedAnalysisPrompt, generateEnhancedFallbackAnalysis) {
  if (!apiKey) throw new Error('Gemini API key required');

  const now = Date.now();
  // @ts-ignore
  const lastRequest = window.lastGeminiRequest || 0;

  if ((now - lastRequest) < CONSTANTS.RATE_LIMITS.GEMINI_COOLDOWN) {
    const waitTime = Math.ceil((CONSTANTS.RATE_LIMITS.GEMINI_COOLDOWN - (now - lastRequest)) / 1000);
    throw new Error(`Rate limit protection: Please wait ${waitTime} more seconds. Free Gemini API has strict limits.`);
  }
  // @ts-ignore
  window.lastGeminiRequest = now;

  if (ragDatabase) {
    await ragDatabase.ensureInitialized(apiKey);
    console.log(`📊 RAG Database Status: ${ragDatabase.documents.length} documents available (${ragDatabase.geminiApiKey ? 'Gemini embeddings' : 'local embeddings'})`);
  }

  const cveId = vulnerability.cve.id;
  const ragQuery = `${cveId} ${vulnerability.cve.description.substring(0, 200)} vulnerability analysis security impact mitigation threat intelligence EPSS ${vulnerability.epss?.epss || 'N/A'} (${vulnerability.epss?.epssPercentage || 'N/A'}%) CVSS ${vulnerability.cve.cvssV3?.baseScore || 'N/A'} ${vulnerability.kev?.listed ? 'CISA KEV active exploitation' : ''}`;

  console.log(`🔍 RAG Query: "${ragQuery.substring(0, 100)}..."`);

  let relevantDocs = [];
  let ragContext = 'No specific security knowledge found in database. Initializing knowledge base for future queries.';

  if (ragDatabase && ragDatabase.initialized) {
    relevantDocs = await ragDatabase.search(ragQuery, 15);
    console.log(`📚 RAG Retrieved: ${relevantDocs.length} relevant documents (${relevantDocs.filter(d => d.embeddingType === 'gemini').length} with Gemini embeddings)`);

    if (relevantDocs.length > 0) {
      ragContext = relevantDocs.map((doc, index) =>
        `[Security Knowledge ${index + 1}] ${doc.metadata.title} (Relevance: ${(doc.similarity * 100).toFixed(1)}%, ${doc.embeddingType || 'local'} embedding):\n${doc.content.substring(0, 800)}...`
      ).join('\n\n');
    } else {
      console.log('🔄 No specific matches found, trying broader search...');
      const broaderQuery = `vulnerability security analysis ${vulnerability.cve.cvssV3?.baseSeverity || 'unknown'} severity`;
      const broaderDocs = await ragDatabase.search(broaderQuery, 8);
      console.log(`📚 Broader RAG Search: ${broaderDocs.length} documents found`);

      if (broaderDocs.length > 0) {
        const broaderContext = broaderDocs.map((doc, index) =>
          `[General Security Knowledge ${index + 1}] ${doc.metadata.title} (${doc.embeddingType || 'local'} embedding):\n${doc.content.substring(0, 600)}...`
        ).join('\n\n');

        relevantDocs.push(...broaderDocs);
        ragContext = broaderContext;
      }
    }
  }

  const prompt = buildEnhancedAnalysisPrompt(vulnerability, ragContext, relevantDocs.length);

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
    const response = await fetchWithFallback(apiUrl, {
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

    if (analysisText.length > 500 && ragDatabase && ragDatabase.initialized) {
      await ragDatabase.addDocument(
        `Enhanced CVE Analysis: ${cveId}\n\nCVSS: ${vulnerability.cve.cvssV3?.baseScore || 'N/A'}\nEPSS: ${vulnerability.epss?.epss || 'N/A'} (${vulnerability.epss?.epssPercentage || 'N/A'}%)\nCISA KEV: ${vulnerability.kev?.listed ? 'Yes' : 'No'}\nValidated: ${vulnerability.validation ? 'Yes' : 'No'}\nConfidence: ${vulnerability.confidence?.overall || 'Unknown'}\n\n${analysisText}`,
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
      ragDatabaseSize: ragDatabase ? ragDatabase.documents.length : 0,
      embeddingType: ragDatabase && ragDatabase.geminiApiKey ? 'gemini' : 'local',
      geminiEmbeddingsCount: ragDatabase ? ragDatabase.documents.filter(d => d.embeddingType === 'gemini').length : 0,
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
    return generateEnhancedFallbackAnalysis(vulnerability, error);
  }
}

export async function fetchGeneralAnswer(query: string, settings: any, fetchWithFallbackFn: any) {
  if (!settings.geminiApiKey) {
    throw new Error("Gemini API key required for AI responses");
  }
  const model = settings.geminiModel || "gemini-2.5-flash";
  const requestBody = {
    contents: [{ parts: [{ text: query }] }],
    generationConfig: { temperature: 0.3, topK: 1, topP: 0.8, maxOutputTokens: 1024, candidateCount: 1 },
    tools: [{ google_search: {} }]
  };
  const response = await fetchWithFallbackFn(`${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${settings.geminiApiKey}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requestBody)
  });
  if (!response.ok) {
    throw new Error(`General AI query error: ${response.status}`);
  }
  const data = await response.json();
  const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) {
    throw new Error("Invalid AI response");
  }
  return { answer: text };
}

export async function generateAITaintAnalysis(
  vulnerability: any,
  apiKey: string,
  model: string,
  settings: any = {},
  fetchWithFallbackFn: any
) {
  if (!apiKey) throw new Error('Gemini API key required');

  const prompt = `Perform conceptual taint analysis for ${vulnerability?.cve?.id} based on the following description:\n${vulnerability?.cve?.description}`;

  const requestBody: any = {
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: { temperature: 0.1, topK: 1, topP: 0.8, maxOutputTokens: 2048, candidateCount: 1 }
  };

  const isWebSearchCapable = model.includes('2.0') || model.includes('2.5');
  if (isWebSearchCapable) {
    requestBody.tools = [{ google_search: {} }];
  }

  const response = await fetchWithFallbackFn(
    `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${apiKey}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody)
    }
  );

  if (!response.ok) {
    throw new Error(`Gemini API error: ${response.status}`);
  }

  const data = await response.json();
  const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) {
    throw new Error('Invalid response from Gemini API');
  }
  return { analysis: text };
}
