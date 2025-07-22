import { CONSTANTS } from '../utils/constants';

interface GroundingMetadata {
  groundingChunks?: Array<{
    web?: {
      uri: string;
      title?: string;
    };
    retrievalQueries?: string[];
  }>;
  webSearchQueries?: string[];
  searchEntryPoint?: {
    renderedContent?: string;
  };
  groundingSupports?: Array<{
    segment?: {
      text?: string;
      startIndex?: number;
      endIndex?: number;
    };
    groundingChunkIndices?: number[];
    confidenceScores?: number[];
  }>;
}

interface ExtractedGroundingInfo {
  sources: Array<{
    url: string;
    title: string;
    queries?: string[];
  }>;
  extractedText: string[];
  searchQueries: string[];
  confidence: number;
}

/**
 * Extract useful information from grounding metadata when text response is missing
 */
function extractFromGroundingMetadata(groundingMetadata: GroundingMetadata): ExtractedGroundingInfo {
  const info: ExtractedGroundingInfo = {
    sources: [],
    extractedText: [],
    searchQueries: [],
    confidence: 0
  };

  // Extract web search queries
  if (groundingMetadata.webSearchQueries) {
    info.searchQueries = groundingMetadata.webSearchQueries;
  }

  // Extract sources from grounding chunks
  if (groundingMetadata.groundingChunks) {
    for (const chunk of groundingMetadata.groundingChunks) {
      if (chunk.web?.uri) {
        info.sources.push({
          url: chunk.web.uri,
          title: chunk.web.title || 'Unknown',
          queries: chunk.retrievalQueries || []
        });
      }
    }
  }

  // Extract text from search entry point
  if (groundingMetadata.searchEntryPoint?.renderedContent) {
    info.extractedText.push(groundingMetadata.searchEntryPoint.renderedContent);
  }

  // Extract supported text segments
  if (groundingMetadata.groundingSupports) {
    for (const support of groundingMetadata.groundingSupports) {
      if (support.segment?.text) {
        info.extractedText.push(support.segment.text);
      }
      // Calculate confidence from scores
      if (support.confidenceScores?.length) {
        const avgScore = support.confidenceScores.reduce((a, b) => a + b, 0) / support.confidenceScores.length;
        info.confidence = Math.max(info.confidence, avgScore);
      }
    }
  }

  return info;
}

/**
 * Enhanced patch search that reads description first and extracts vendor information
 */
export async function fetchPatchesAndAdvisories(
  cveId: string,
  cveData: any,
  settings: any,
  setLoadingSteps: any,
  fetchWithFallback: any,
  parsePatchAndAdvisoryResponse: any,
  getHeuristicPatchesAndAdvisories: any
) {
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  updateSteps(prev => [...prev, `📖 Reading ${cveId} description to extract vendor information...`]);

  if (!settings.geminiApiKey && !settings.openAiApiKey) {
    updateSteps(prev => [...prev, `⚠️ API key required for intelligent analysis`]);
    return getHeuristicPatchesAndAdvisories(cveId, cveData);
  }

  const useGemini = !settings.openAiApiKey && !!settings.geminiApiKey;
  const model = useGemini ? (settings.geminiModel || 'gemini-2.5-flash') : (settings.openAiModel || 'gpt-4o');
  const isWebSearchCapable = useGemini && (model.includes('2.0') || model.includes('2.5'));

  if (useGemini && !isWebSearchCapable) {
    updateSteps(prev => [...prev, `⚠️ Web search not supported by model`]);
    return getHeuristicPatchesAndAdvisories(cveId, cveData);
  }

  const description = cveData?.description || 'No description available';

  // Clear, step-by-step prompt that forces description reading
  const analysisPrompt = `IMPORTANT: You MUST analyze the CVE description to extract vendor and product information BEFORE searching.

CVE: ${cveId}
DESCRIPTION: "${description}"

MANDATORY EXTRACTION TASK:
Carefully read the description above and extract ALL of the following that you can find:

1. VENDOR - The company that makes the product (e.g., ASUS, Cisco, Microsoft, Apache)
2. PRODUCT - The specific product name (e.g., RT-AX55, Windows Server, Tomcat)  
3. VERSION/FIRMWARE - Any version numbers (e.g., 3.0.0.4.386.51598, 2019, 9.0.45)
4. MODEL - Hardware model if mentioned (e.g., RT-AX55, DIR-850L)
5. COMPONENT - Specific component if mentioned (e.g., authentication module)
6. PACKAGE - Software package if mentioned (e.g., openssh-server)

EXTRACTION PATTERNS TO LOOK FOR:
- "On [VENDOR] [PRODUCT] [VERSION] devices" → Extract vendor, product, version
- "[VENDOR] [MODEL] firmware [VERSION]" → Extract vendor, model, firmware version  
- "[PACKAGE] before [VERSION]" → Extract package and version
- "vulnerability in [COMPONENT]" → Extract component

EXAMPLE EXTRACTION:
Description: "On ASUS RT-AX55 3.0.0.4.386.51598 devices, authenticated attackers can perform OS command injection"
You MUST extract: vendor=ASUS, product=RT-AX55, model=RT-AX55, version=3.0.0.4.386.51598

YOUR EXTRACTION FROM THE DESCRIPTION ABOVE:
{
  "extracted": {
    "vendor": "[WHAT YOU FOUND or null]",
    "product": "[WHAT YOU FOUND or null]", 
    "version": "[WHAT YOU FOUND or null]",
    "model": "[WHAT YOU FOUND or null]",
    "component": "[WHAT YOU FOUND or null]",
    "package": "[WHAT YOU FOUND or null]"
  }
}

AFTER EXTRACTION, CREATE TARGETED SEARCHES:
Based on what you extracted above, search for:

If vendor="ASUS" and product="RT-AX55":
- "ASUS RT-AX55 ${cveId} security advisory"
- "ASUS RT-AX55 firmware update security"
- "site:asus.com RT-AX55 security patch"

If vendor="Microsoft" and product found:
- "Microsoft [product] ${cveId} security update"
- "site:microsoft.com ${cveId} patch"

SEARCH AND RETURN:
{
  "analysisSteps": {
    "descriptionRead": true,
    "extracted": {
      "vendor": "[extracted vendor]",
      "product": "[extracted product]",
      "version": "[extracted version]",
      "model": "[extracted model]",
      "component": "[extracted component]",
      "package": "[extracted package]"
    },
    "searchQueriesUsed": [
      "[actual search queries you used based on extraction]"
    ]
  },
  "patches": [
    {
      "vendor": "[vendor from extraction]",
      "product": "[product from extraction]",
      "patchVersion": "[version found]",
      "downloadUrl": "[actual URL found]",
      "advisoryUrl": "[advisory URL]",
      "releaseDate": "[date]",
      "description": "[description]",
      "patchType": "Firmware Update/Security Patch",
      "confidence": "HIGH/MEDIUM/LOW",
      "citationUrl": "[source URL]"
    }
  ],
  "advisories": [
    {
      "source": "[vendor name]",
      "advisoryId": "${cveId}",
      "title": "[advisory title]",
      "url": "[advisory URL]",
      "severity": "[severity]",
      "description": "[description]",
      "confidence": "HIGH/MEDIUM/LOW",
      "type": "Security Advisory",
      "citationUrl": "[source URL]"
    }
  ],
  "searchSummary": {
    "patchesFound": [number],
    "advisoriesFound": [number],
    "vendorsSearched": ["list of vendors searched"]
  }
}

CRITICAL: You MUST show the extraction results in your response. Do NOT skip the extraction step.`;

  try {
    const requestBody: any = useGemini
      ? {
          contents: [{ parts: [{ text: analysisPrompt }] }],
          generationConfig: {
            temperature: 0.1,
            topK: 1,
            topP: 0.9,
            maxOutputTokens: 8192,
            candidateCount: 1
          },
          tools: [{ google_search: {} }]
        }
      : {
          model,
          messages: [{ role: 'user', content: analysisPrompt }]
        };

    updateSteps(prev => [...prev, `🔍 AI analyzing description and extracting vendor details...`]);

    const apiUrl = useGemini
      ? `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${settings.geminiApiKey}`
      : `${CONSTANTS.API_ENDPOINTS.OPENAI}/chat/completions`;
    const headers: any = { 'Content-Type': 'application/json' };
    if (!useGemini) headers['Authorization'] = `Bearer ${settings.openAiApiKey}`;

    const response = await fetchWithFallback(apiUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();
    let result = { patches: [], advisories: [], analysisSteps: {} };

    if (useGemini) {
      if (data.candidates?.[0]?.content?.parts?.[0]?.text) {
        const aiResponse = data.candidates[0].content.parts[0].text;
        result = parseDescriptionBasedResponse(aiResponse, cveId);

        // Show what was extracted
        if (result.analysisSteps?.extracted) {
          const extracted = Object.entries(result.analysisSteps.extracted)
            .filter(([_, value]) => value && value !== 'null')
            .map(([key, value]) => `${key}: ${value}`)
            .join(', ');

          if (extracted) {
            updateSteps(prev => [...prev, `✅ Extracted from description: ${extracted}`]);
          } else {
            updateSteps(prev => [...prev, `⚠️ No vendor information found in description`]);
          }
        }

        // Show search queries used
        if (result.analysisSteps?.searchQueriesUsed?.length > 0) {
          updateSteps(prev => [...prev, `🔎 Performed ${result.analysisSteps.searchQueriesUsed.length} targeted searches`]);
        }

      } else if (data.candidates?.[0]?.groundingMetadata) {
        updateSteps(prev => [...prev, `📊 Extracting from search metadata...`]);
        result = extractFromGroundingWithContext(data.candidates[0].groundingMetadata, cveId, description);
      } else {
        updateSteps(prev => [...prev, `⚠️ No usable response - using heuristics`]);
        return getHeuristicPatchesAndAdvisories(cveId, cveData);
      }
    } else {
      const text = data.choices?.[0]?.message?.content;
      if (!text) {
        updateSteps(prev => [...prev, `⚠️ No usable response - using heuristics`]);
        return getHeuristicPatchesAndAdvisories(cveId, cveData);
      }
      result = parseDescriptionBasedResponse(text, cveId);
    
    }

    // Always enhance with heuristics
    const heuristicData = getHeuristicPatchesAndAdvisories(cveId, cveData);
    
    // Merge patches and advisories
    const mergedPatches = [...(result.patches || []), ...(heuristicData.patches || [])];
    const mergedAdvisories = [...(result.advisories || []), ...(heuristicData.advisories || [])];
    
    return {
      patches: mergedPatches,
      advisories: mergedAdvisories,
      searchSummary: {
        ...(result.searchSummary || {}),
        enhancedWithHeuristics: true,
        descriptionAnalyzed: true,
        extractionSuccessful: !!(result.analysisSteps?.extracted?.vendor),
        targetedSearchPerformed: !!(result.analysisSteps?.searchQueriesUsed?.length > 0),
        totalPatchesFound: mergedPatches.length,
        totalAdvisoriesFound: mergedAdvisories.length,
        patchesFound: mergedPatches.length,
        advisoriesFound: mergedAdvisories.length
      }
    };

  } catch (error) {
    console.error('Description analysis error:', error);
    updateSteps(prev => [...prev, `⚠️ Analysis failed: ${error.message}`]);
    return getHeuristicPatchesAndAdvisories(cveId, cveData);
  }
}

/**
 * Enhanced threat intelligence that extracts from grounding metadata
 */
export async function fetchAIThreatIntelligence(
  cveId: string,
  cveData: any,
  epssData: any,
  settings: any,
  setLoadingSteps: any,
  ragDatabase: any,
  fetchWithFallback: any,
  parseAIThreatIntelligence: any,
  performHeuristicAnalysis: any
) {
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};

  if (!settings.geminiApiKey && !settings.openAiApiKey) {
    throw new Error('Gemini or OpenAI API key required');
  }

  const useGemini = !!settings.geminiApiKey;
  const model = useGemini ? (settings.geminiModel || 'gemini-2.5-flash') : (settings.openAiModel || 'gpt-4o');
  const isWebSearchCapable = useGemini && (model.includes('2.0') || model.includes('2.5'));

  if (useGemini && !isWebSearchCapable) {
    updateSteps(prev => [...prev, `⚠️ Model doesn't support web search`]);
    return await performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
  }

  updateSteps(prev => [...prev, `🤖 Searching for ${cveId} threat intelligence...`]);

  const searchPrompt = createEnhancedThreatSearchPrompt(cveId, cveData, epssData);

  try {
    const requestBody = useGemini
      ? {
          contents: [{ parts: [{ text: searchPrompt }] }],
          generationConfig: {
            temperature: 0.05,
            topK: 1,
            topP: 0.8,
            maxOutputTokens: 4096,
            candidateCount: 1
          },
          tools: [{ google_search: {} }]
        }
      : {
          model,
          messages: [{ role: 'user', content: searchPrompt }]
        };

    const apiUrl = useGemini
      ? `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${settings.geminiApiKey}`
      : `${CONSTANTS.API_ENDPOINTS.OPENAI}/chat/completions`;
    const headers: any = { 'Content-Type': 'application/json' };
    if (!useGemini) headers['Authorization'] = `Bearer ${settings.openAiApiKey}`;

    const response = await fetchWithFallback(apiUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();

    let findings = null;

    if (useGemini) {
      if (!data.candidates || data.candidates.length === 0) {
        updateSteps(prev => [...prev, `⚠️ No response candidates`]);
        return await performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
      }

      const candidate = data.candidates[0];

      if (candidate.content?.parts?.[0]?.text) {
        const aiResponseContent = candidate.content.parts[0].text;
        updateSteps(prev => [...prev, `✅ AI completed threat intelligence analysis`]);
        findings = parseAIThreatIntelligence(aiResponseContent, cveId, setLoadingSteps);
      } else if (candidate.groundingMetadata) {
        updateSteps(prev => [...prev, `📊 Extracting threat data from search results...`]);

        findings = extractThreatIntelFromGrounding(
          candidate.groundingMetadata,
          cveId,
          cveData,
          epssData
        );

        findings.extractedFromGrounding = true;
      } else {
        updateSteps(prev => [...prev, `⚠️ No usable response`]);
        return await performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
      }

      findings.extractionMetadata = {
        extractionMethod: candidate.content?.parts?.[0]?.text
          ? 'TEXT_RESPONSE_EXTRACTION'
          : 'GROUNDING_METADATA_EXTRACTION',
        hallucinationMitigation: true,
        extractiveApproach: true,
        temperatureUsed: 0.05,
        maxTokensUsed: 4096,
        cisaVerificationPerformed: true,
        webSearchValidation: true
      };
    } else {
      const text = data.choices?.[0]?.message?.content;
      if (!text) {
        updateSteps(prev => [...prev, `⚠️ No usable response`]);
        return await performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
      }
      updateSteps(prev => [...prev, `✅ AI completed threat intelligence analysis`]);
      findings = parseAIThreatIntelligence(text, cveId, setLoadingSteps);
      findings.extractionMetadata = {
        extractionMethod: 'TEXT_RESPONSE_ONLY',
        hallucinationMitigation: true,
        extractiveApproach: true,
        temperatureUsed: 0.05,
        maxTokensUsed: 4096,
        cisaVerificationPerformed: false,
        webSearchValidation: false
      };
    }

    // Store in RAG if available
    if (ragDatabase?.initialized) {
      await ragDatabase.addDocument(
        `AI Threat Intelligence for ${cveId}: CISA KEV: ${findings.cisaKev?.listed ? 'LISTED' : 'Not Listed'}, Active Exploitation: ${findings.activeExploitation?.confirmed ? 'CONFIRMED' : 'None'}, Public Exploits: ${findings.exploitDiscovery?.totalCount || 0}`,
        {
          title: `AI Threat Intelligence - ${cveId}`,
          category: 'ai-threat-intelligence',
          tags: ['ai-search', 'threat-intel', cveId.toLowerCase()],
          source: useGemini ? 'gemini-web-search' : 'openai'
        }
      );
    }

    return findings;

  } catch (error) {
    console.error('Threat intelligence error:', error);
    updateSteps(prev => [...prev, `⚠️ Search failed: ${error.message}`]);
    return await performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
  }
}

/**
 * Create enhanced threat search prompt
 */
function createEnhancedThreatSearchPrompt(cveId: string, cveData: any, epssData: any): string {
  return `Search for ${cveId} threat intelligence. Extract ONLY factual information from search results.

REQUIRED SEARCHES:
1. "site:cisa.gov Known Exploited Vulnerabilities ${cveId}" - Check CISA KEV listing
2. "${cveId} active exploitation ransomware" - Find exploitation evidence
3. "${cveId} exploit github poc" - Search for public exploits
4. "${cveId} security advisory patch" - Find vendor advisories

CVE Context:
- CVE: ${cveId}
- CVSS: ${cveData?.cvssV3?.baseScore || 'Unknown'}
- EPSS: ${epssData?.epss || 'Unknown'}%
- Description: ${cveData?.description?.substring(0, 300) || 'Unknown'}

Extract and return in JSON format:
{
  "cisaKev": {
    "listed": boolean (true ONLY if found on official CISA site),
    "details": "extracted CISA details or empty",
    "source": "CISA URL or empty",
    "dueDate": "date or empty",
    "confidence": "HIGH if found on CISA, else LOW"
  },
  "activeExploitation": {
    "confirmed": boolean,
    "details": "extracted details",
    "sources": ["source URLs"],
    "threatActors": ["actor names if found"],
    "confidence": "HIGH/MEDIUM/LOW"
  },
  "exploitDiscovery": {
    "found": boolean,
    "totalCount": number,
    "exploits": [{
      "type": "type",
      "url": "actual URL or empty",
      "source": "GitHub/ExploitDB/etc",
      "description": "description"
    }],
    "confidence": "HIGH/MEDIUM/LOW"
  }
}

Include ONLY information found in search results. Do not generate URLs or details.`;
}

/**
 * Extract threat intelligence from grounding metadata
 */
function extractThreatIntelFromGrounding(
  groundingMetadata: GroundingMetadata,
  cveId: string,
  cveData: any,
  epssData: any
): any {
  const groundingInfo = extractFromGroundingMetadata(groundingMetadata);
  
  const findings = {
    cisaKev: {
      listed: false,
      details: '',
      source: '',
      dueDate: '',
      confidence: 'LOW',
      searchQueries: [],
      aiDiscovered: true
    },
    activeExploitation: {
      confirmed: false,
      details: '',
      sources: [],
      threatActors: [],
      confidence: 'LOW',
      aiDiscovered: true
    },
    exploitDiscovery: {
      found: false,
      totalCount: 0,
      exploits: [],
      githubRepos: 0,
      exploitDbEntries: 0,
      confidence: 'LOW',
      aiDiscovered: true
    },
    vendorAdvisories: {
      found: false,
      count: 0,
      advisories: [],
      confidence: 'LOW',
      aiDiscovered: true
    },
    extractionSummary: {
      sourcesSearched: groundingInfo.sources.length,
      officialSourcesFound: 0,
      cisaSourcesChecked: false,
      extractionMethod: 'GROUNDING_METADATA_EXTRACTION',
      confidenceLevel: 'MEDIUM',
      searchTimestamp: new Date().toISOString()
    }
  };

  // Analyze sources for threat intelligence
  for (const source of groundingInfo.sources) {
    const url = source.url.toLowerCase();
    
    // Check for CISA KEV
    if (url.includes('cisa.gov') && url.includes('known-exploited')) {
      findings.cisaKev.listed = true;
      findings.cisaKev.source = source.url;
      findings.cisaKev.confidence = 'HIGH';
      findings.cisaKev.details = `Found in CISA KEV catalog`;
      findings.extractionSummary.cisaSourcesChecked = true;
      findings.extractionSummary.officialSourcesFound++;
    }
    
    // Check for exploitation evidence
    if (url.includes('exploit') || url.includes('ransomware') || url.includes('attack')) {
      findings.activeExploitation.confirmed = true;
      findings.activeExploitation.sources.push(source.url);
      findings.activeExploitation.details = source.title || 'Active exploitation reported';
      findings.activeExploitation.confidence = 'MEDIUM';
    }
    
    // Check for exploit code
    if (url.includes('github.com') && (url.includes('exploit') || url.includes('poc'))) {
      findings.exploitDiscovery.found = true;
      findings.exploitDiscovery.totalCount++;
      findings.exploitDiscovery.githubRepos++;
      findings.exploitDiscovery.exploits.push({
        type: 'GitHub PoC',
        url: source.url,
        source: 'GitHub',
        description: source.title || 'Exploit code repository',
        reliability: 'MEDIUM',
        citationUrl: source.url
      });
    }
    
    // Check for vendor advisories
    if (url.includes('security') && (url.includes('advisory') || url.includes('bulletin'))) {
      findings.vendorAdvisories.found = true;
      findings.vendorAdvisories.count++;
      findings.vendorAdvisories.advisories.push({
        vendor: extractVendorFromUrl(url),
        title: source.title || 'Security Advisory',
        url: source.url,
        patchAvailable: url.includes('patch') || url.includes('update'),
        severity: 'Unknown',
        source: extractVendorFromUrl(url)
      });
    }
  }

  // Set confidence levels based on findings
  if (findings.cisaKev.listed || findings.activeExploitation.confirmed) {
    findings.extractionSummary.confidenceLevel = 'HIGH';
  }

  return findings;
}

/**
 * Extract vendor name from URL
 */
function extractVendorFromUrl(url: string): string {
  const vendorPatterns = {
    'microsoft.com': 'Microsoft',
    'redhat.com': 'Red Hat',
    'oracle.com': 'Oracle',
    'adobe.com': 'Adobe',
    'cisco.com': 'Cisco',
    'ubuntu.com': 'Ubuntu',
    'debian.org': 'Debian',
    'apache.org': 'Apache',
    'github.com': 'GitHub',
    'cisa.gov': 'CISA',
    'asus.com': 'ASUS',
    'd-link.com': 'D-Link',
    'dlink.com': 'D-Link',
    'tp-link.com': 'TP-Link',
    'netgear.com': 'Netgear',
    'fortinet.com': 'Fortinet',
    'vmware.com': 'VMware',
    'juniper.net': 'Juniper'
  };
  
  for (const [pattern, vendor] of Object.entries(vendorPatterns)) {
    if (url.includes(pattern)) {
      return vendor;
    }
  }
  
  try {
    const urlObj = new URL(url);
    return urlObj.hostname.split('.')[0];
  } catch {
    return 'Unknown';
  }
}

/**
 * Extract version from URL
 */
function extractVersionFromUrl(url: string): string | null {
  // Common version patterns in URLs
  const patterns = [
    /v?(\d+\.\d+\.\d+(?:\.\d+)*)/,
    /version[_-]?(\d+\.\d+(?:\.\d+)*)/,
    /firmware[_-]?v?(\d+\.\d+(?:\.\d+)*)/i,
    /-(\d+\.\d+\.\d+)\./,
    /\/(\d+\.\d+)\//
  ];
  
  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match) {
      return match[1];
    }
  }
  
  return null;
}

/**
 * Parse response that includes description analysis
 */
export function parseDescriptionBasedResponse(response: string, cveId: string): any {
  try {
    // Remove common code block markers and trim
    let cleaned = response.replace(/```(?:json)?/gi, '').trim();

    // Isolate the first JSON object in the response
    const first = cleaned.indexOf('{');
    const last = cleaned.lastIndexOf('}');
    if (first !== -1 && last !== -1 && last > first) {
      const jsonString = cleaned.slice(first, last + 1);
      const data = JSON.parse(jsonString);
      
      // Extract the core patch/advisory data while preserving analysis steps
      const result = {
        patches: data.patches || [],
        advisories: data.advisories || [],
        searchSummary: data.searchSummary || {
          patchesFound: data.patches?.length || 0,
          advisoriesFound: data.advisories?.length || 0,
          enhancedWithAnalysis: true
        }
      };
      
      // Store analysis steps separately if available
      if (data.analysisSteps) {
        result.analysisSteps = data.analysisSteps;
      }
      
      return result;
    }
  } catch (error) {
    console.error('Failed to parse description-based response:', error);
  }
  
  return { 
    patches: [], 
    advisories: [], 
    searchSummary: { patchesFound: 0, advisoriesFound: 0 } 
  };
}

/**
 * Extract from grounding with description context
 */
function extractFromGroundingWithContext(groundingMetadata: any, cveId: string, description: string): any {
  // First, manually extract from description
  const extracted = extractInfoFromDescription(description);
  
  const groundingInfo = extractFromGroundingMetadata(groundingMetadata);
  const patches = [];
  const advisories = [];

  for (const source of groundingInfo.sources) {
    const url = source.url;
    const title = source.title || '';
    const urlLower = url.toLowerCase();
    
    // Match against extracted vendor
    if (extracted.vendor && urlLower.includes(extracted.vendor.toLowerCase())) {
      if (urlLower.includes('download') || urlLower.includes('firmware') || urlLower.includes('update')) {
        patches.push({
          vendor: extracted.vendor,
          product: extracted.product || extracted.model || 'Unknown',
          patchVersion: extractVersionFromUrl(url) || 'Latest',
          downloadUrl: url,
          advisoryUrl: url,
          description: title || 'Security patch',
          confidence: 'HIGH',
          patchType: extracted.model ? 'Firmware Update' : 'Security Patch',
          basedOnExtraction: true,
          citationUrl: url
        });
      } else {
        advisories.push({
          source: extracted.vendor,
          advisoryId: cveId,
          title: title || `Security Advisory for ${cveId}`,
          url: url,
          severity: 'Unknown',
          description: `${extracted.vendor} security advisory`,
          confidence: 'HIGH',
          type: 'Vendor Advisory',
          affectedProduct: extracted.product || extracted.model || 'Unknown',
          basedOnExtraction: true,
          citationUrl: url
        });
      }
    }
  }

  return {
    patches: patches,
    advisories: advisories,
    searchSummary: {
      descriptionAnalyzed: true,
      extractionSuccessful: !!(extracted.vendor),
      searchQueries: groundingInfo.searchQueries,
      sourcesFound: groundingInfo.sources.length,
      extractedFromGrounding: true,
      confidence: groundingInfo.confidence,
      patchesFound: patches.length,
      advisoriesFound: advisories.length
    },
    analysisSteps: {
      descriptionRead: true,
      extracted: extracted,
      searchQueriesUsed: groundingMetadata.webSearchQueries || []
    }
  };
}

/**
 * Manual extraction from description as fallback
 */
function extractInfoFromDescription(description: string): any {
  const extracted = {
    vendor: null,
    product: null,
    component: null,
    version: null,
    model: null,
    package: null,
    os: null
  };

  // Pattern matching for common formats
  const patterns = {
    // "On VENDOR PRODUCT VERSION devices"
    devicePattern: /On\s+(\w+)\s+([\w\-]+)\s+([\d.]+(?:\.\d+)*)\s+devices/i,
    // "VENDOR MODEL firmware VERSION"
    firmwarePattern: /(\w+)\s+([\w\-]+)\s+firmware\s+([\d.]+(?:\.\d+)*)/i,
    // "PACKAGE before VERSION"
    packagePattern: /([\w\-]+)\s+(?:package\s+)?before\s+([\d.]+(?:\.\d+)*)/i,
    // "VENDOR PRODUCT version VERSION"
    versionPattern: /(\w+)\s+([\w\s\-]+)\s+version\s+([\d.]+(?:\.\d+)*)/i,
    // Component pattern
    componentPattern: /vulnerability\s+in\s+(?:the\s+)?([\w\s\-]+)\s+(?:component|module|function)/i
  };

  // Try device pattern first (like ASUS example)
  const deviceMatch = description.match(patterns.devicePattern);
  if (deviceMatch) {
    extracted.vendor = deviceMatch[1];
    extracted.product = deviceMatch[2];
    extracted.model = deviceMatch[2];
    extracted.version = deviceMatch[3];
    return extracted;
  }

  // Try other patterns
  for (const [key, pattern] of Object.entries(patterns)) {
    const match = description.match(pattern);
    if (match) {
      switch (key) {
        case 'firmwarePattern':
          extracted.vendor = match[1];
          extracted.model = match[2];
          extracted.version = match[3];
          break;
        case 'packagePattern':
          extracted.package = match[1];
          extracted.version = match[2];
          break;
        case 'versionPattern':
          extracted.vendor = match[1];
          extracted.product = match[2].trim();
          extracted.version = match[3];
          break;
        case 'componentPattern':
          extracted.component = match[1].trim();
          break;
      }
    }
  }

  // Known vendor detection
  const knownVendors = [
    'ASUS', 'Cisco', 'Microsoft', 'Oracle', 'Apache', 'Adobe',
    'D-Link', 'TP-Link', 'Netgear', 'VMware', 'Fortinet', 'Juniper',
    'Huawei', 'Sophos', 'Palo Alto', 'F5', 'Citrix', 'IBM'
  ];

  if (!extracted.vendor) {
    for (const vendor of knownVendors) {
      if (description.includes(vendor)) {
        extracted.vendor = vendor;
        break;
      }
    }
  }

  return extracted;
}

// Include the other functions directly
export async function generateAIAnalysis(vulnerability, apiKey, model, settings = {}, ragDatabase, fetchWithFallback, buildEnhancedAnalysisPrompt, generateEnhancedFallbackAnalysis) {
  if (!apiKey && !settings.openAiApiKey) throw new Error('Gemini or OpenAI API key required');

  const useGemini = !!apiKey;

  const now = Date.now();
  // @ts-ignore
  const lastRequest = window.lastGeminiRequest || 0;

  if (useGemini && (now - lastRequest) < CONSTANTS.RATE_LIMITS.GEMINI_COOLDOWN) {
    const waitTime = Math.ceil((CONSTANTS.RATE_LIMITS.GEMINI_COOLDOWN - (now - lastRequest)) / 1000);
    throw new Error(`Rate limit protection: Please wait ${waitTime} more seconds. Free Gemini API has strict limits.`);
  }
  // @ts-ignore
  if (useGemini) window.lastGeminiRequest = now;

  if (ragDatabase) {
    await ragDatabase.ensureInitialized(useGemini ? apiKey : null);
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

  const requestBody: any = useGemini
    ? {
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.1,
          topK: 1,
          topP: 0.8,
          maxOutputTokens: 8192,
          candidateCount: 1,
        },
      }
    : {
        model,
        messages: [{ role: 'user', content: prompt }],
      };

  const isWebSearchCapable = useGemini && (model.includes('2.0') || model.includes('2.5'));
  if (useGemini && isWebSearchCapable) {
    requestBody.tools = [{ google_search: {} }];
  }

  const apiUrl = useGemini
    ? `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${apiKey}`
    : `${CONSTANTS.API_ENDPOINTS.OPENAI}/chat/completions`;

  try {
    const headers: any = { 'Content-Type': 'application/json' };
    if (!useGemini) headers['Authorization'] = `Bearer ${settings.openAiApiKey}`;
    const response = await fetchWithFallback(apiUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));

      if (useGemini) {
        if (response.status === 429) {
          throw new Error('Gemini API rate limit exceeded. Please wait a few minutes before trying again.');
        }

        if (response.status === 401 || response.status === 403) {
          throw new Error('Invalid Gemini API key. Please check your API key in settings.');
        }

        throw new Error(`Gemini API error: ${response.status} - ${errorData.error?.message || 'Unknown error'}`);
      } else {
        throw new Error(`OpenAI API error: ${response.status} - ${errorData.error?.message || 'Unknown error'}`);
      }
    }

    const data = await response.json();
    let analysisText;
    if (useGemini) {
      const content = data.candidates?.[0]?.content;
      if (!content?.parts?.[0]?.text) {
        throw new Error('Invalid response from Gemini API');
      }
      analysisText = content.parts[0].text;
      if (!analysisText || analysisText.trim().length === 0) {
        throw new Error('Empty analysis received from Gemini API');
      }
    } else {
      analysisText = data.choices?.[0]?.message?.content;
      if (!analysisText) {
        throw new Error('Invalid response from OpenAI API');
      }
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
  if (!settings.geminiApiKey && !settings.openAiApiKey) {
    throw new Error("Gemini or OpenAI API key required for AI responses");
  }
  const useGemini = !!settings.geminiApiKey;
  const model = useGemini ? (settings.geminiModel || "gemini-2.5-flash") : (settings.openAiModel || 'gpt-4o');
  const requestBody = useGemini
    ? {
        contents: [{ parts: [{ text: query }] }],
        generationConfig: { temperature: 0.3, topK: 1, topP: 0.8, maxOutputTokens: 1024, candidateCount: 1 },
        tools: [{ google_search: {} }]
      }
      : {
          model,
          messages: [{ role: 'user', content: query }]
        };
  const apiUrl = useGemini
    ? `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${settings.geminiApiKey}`
    : `${CONSTANTS.API_ENDPOINTS.OPENAI}/chat/completions`;
  const headers: any = { "Content-Type": "application/json" };
  if (!useGemini) headers["Authorization"] = `Bearer ${settings.openAiApiKey}`;
  const response = await fetchWithFallbackFn(apiUrl, {
    method: "POST",
    headers,
    body: JSON.stringify(requestBody)
  });
  if (!response.ok) {
    throw new Error(`General AI query error: ${response.status}`);
  }
  const data = await response.json();
  const text = useGemini ? data.candidates?.[0]?.content?.parts?.[0]?.text : data.choices?.[0]?.message?.content;
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
  if (!apiKey && !settings.openAiApiKey) throw new Error('Gemini or OpenAI API key required');

  const useGemini = !!apiKey;

  const prompt = `Perform conceptual taint analysis for ${vulnerability?.cve?.id} based on the following description:\n${vulnerability?.cve?.description}`;

  const requestBody: any = useGemini
    ? {
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.1, topK: 1, topP: 0.8, maxOutputTokens: 2048, candidateCount: 1 }
      }
    : {
        model: settings.openAiModel || 'gpt-4o',
        messages: [{ role: 'user', content: prompt }]
      };

  const isWebSearchCapable = useGemini && (model.includes('2.0') || model.includes('2.5'));
  if (useGemini && isWebSearchCapable) {
    requestBody.tools = [{ google_search: {} }];
  }

  const apiUrl = useGemini
    ? `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${apiKey}`
    : `${CONSTANTS.API_ENDPOINTS.OPENAI}/chat/completions`;
  const headers: any = { 'Content-Type': 'application/json' };
  if (!useGemini) headers['Authorization'] = `Bearer ${settings.openAiApiKey}`;

  const response = await fetchWithFallbackFn(apiUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify(requestBody)
  });

  if (!response.ok) {
    throw new Error(useGemini ? `Gemini API error: ${response.status}` : `OpenAI API error: ${response.status}`);
  }

  const data = await response.json();
  const text = useGemini ? data.candidates?.[0]?.content?.parts?.[0]?.text : data.choices?.[0]?.message?.content;
  if (!text) {
    throw new Error(useGemini ? 'Invalid response from Gemini API' : 'Invalid response from OpenAI API');
  }
  return { analysis: text };
}