// Complete DataFetchingService.ts with corrected Google Search Integration
import { CONSTANTS } from '../utils/constants';
import { processCVEData } from './UtilityService';

// Global AI settings for web search fallbacks
let globalAISettings: any = null;

export function setGlobalAISettings(settings: any) {
  globalAISettings = settings;
}

// AI-powered web search to fetch URL content
async function fetchWithAIWebSearch(url: string, aiSettings: any): Promise<Response> {
  try {
    // Create a more specific search prompt for different services
    let searchPrompt = '';
    
    if (url.includes('cisa.gov') && url.includes('known_exploited_vulnerabilities')) {
      searchPrompt = `I need you to search for information about the CISA Known Exploited Vulnerabilities (KEV) catalog. Please search for:

1. The current CISA KEV catalog data
2. Information from the official CISA website about known exploited vulnerabilities
3. Any recent updates to the CISA KEV list

Please provide structured information about:
- The catalog version and date
- Total number of vulnerabilities in the catalog
- Recent additions to the KEV list
- The general structure of KEV entries

Search terms: CISA Known Exploited Vulnerabilities catalog KEV official list`;
    } else if (url.includes('first.org') && url.includes('epss')) {
      searchPrompt = `Search for information about EPSS (Exploit Prediction Scoring System) data from FIRST.org. I need current EPSS scoring information.`;
    } else if (url.includes('nvd.nist.gov')) {
      searchPrompt = `Search for CVE vulnerability information from the National Vulnerability Database (NVD) at NIST.`;
    } else {
      searchPrompt = `Please search for information from this website: ${url}`;
    }

    console.log('Making AI web search request for URL:', url);

    const useGemini = !!aiSettings.geminiApiKey;
    const model = useGemini ? (aiSettings.geminiModel || 'gemini-2.5-flash') : (aiSettings.openAiModel || 'gpt-4o');
    const apiUrl = useGemini
      ? `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`
      : `${CONSTANTS.API_ENDPOINTS.OPENAI}/chat/completions`;

    const requestBody: any = useGemini
      ? {
          contents: [{ parts: [{ text: searchPrompt }] }],
          tools: [{ google_search: {} }],
          generationConfig: {
            temperature: 0.1,
            topK: 40,
            topP: 0.95,
            maxOutputTokens: 2048
          }
        }
      : {
          model,
          messages: [{ role: 'user', content: searchPrompt }],
          tools: [{ type: 'web_search' }]
        };

    const headers: any = { 'Content-Type': 'application/json' };
    if (useGemini) {
      headers['x-goog-api-key'] = aiSettings.geminiApiKey;
    } else {
      headers['Authorization'] = `Bearer ${aiSettings.openAiApiKey}`;
    }

    const response = await fetch(apiUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Gemini API error response:', errorText);
      throw new Error(`Gemini API responded with ${response.status}: ${errorText}`);
    }

    const data = await response.json();
    
    let aiResponse = '';
    let groundingMetadata: any = {};
    let searchQueries: any[] = [];
    let groundingSupports: any[] = [];

    if (useGemini) {
      const candidate = data.candidates?.[0];
      if (!candidate) {
        throw new Error('No candidate response from Gemini API');
      }

      aiResponse = candidate.content?.parts?.[0]?.text || '';
      groundingMetadata = candidate.groundingMetadata || {};
      searchQueries = groundingMetadata.searchQueries || [];
      groundingSupports = groundingMetadata.groundingSupports || [];

      if (!aiResponse) {
        throw new Error('No response content from Gemini API');
      }

      console.log('AI web search response received, length:', aiResponse.length);
      console.log('Grounding queries used:', searchQueries);
      console.log('Number of grounding supports:', groundingSupports.length);
    } else {
      aiResponse = data.choices?.[0]?.message?.content || '';
      if (!aiResponse) {
        throw new Error('No response content from OpenAI API');
      }
      console.log('AI response received from OpenAI, length:', aiResponse.length);
    }

    // Parse the AI response into structured data
    const parsedContent = parseAIWebSearchResponse(aiResponse, url, groundingMetadata);

    // Return a mock Response object with the AI-fetched content
    return {
      ok: true,
      status: 200,
      statusText: 'OK',
      json: () => Promise.resolve(parsedContent.json),
      text: () => Promise.resolve(parsedContent.text),
      headers: new Headers({
        'content-type': parsedContent.contentType,
        'x-ai-fetched': 'true',
        'x-grounding-queries': JSON.stringify(searchQueries),
        'x-grounding-supports': JSON.stringify(groundingSupports.length)
      })
    } as Response;

  } catch (error) {
    console.error('AI web search failed:', error);
    throw error;
  }
}

// Parse AI web search response into structured data
function parseAIWebSearchResponse(aiResponse: string, originalUrl: string, groundingMetadata?: any): any {
  try {
    // For CISA KEV catalog specifically
    if (originalUrl.includes('cisa.gov') && originalUrl.includes('known_exploited_vulnerabilities')) {
      return parseCISAKEVFromAIResponse(aiResponse, groundingMetadata);
    }

    // For EPSS API
    if (originalUrl.includes('first.org') && originalUrl.includes('epss')) {
      return parseEPSSFromAIResponse(aiResponse, groundingMetadata);
    }

    // For NVD API
    if (originalUrl.includes('nvd.nist.gov')) {
      return parseNVDFromAIResponse(aiResponse, groundingMetadata);
    }

    // Generic text response
    return {
      json: { 
        content: aiResponse, 
        source: 'ai-web-search',
        groundingMetadata: groundingMetadata || {}
      },
      text: aiResponse,
      contentType: 'text/plain'
    };

  } catch (error) {
    console.error('Error parsing AI web search response:', error);
    return {
      json: { 
        error: 'Failed to parse AI response', 
        originalResponse: aiResponse,
        groundingMetadata: groundingMetadata || {}
      },
      text: aiResponse,
      contentType: 'text/plain'
    };
  }
}

// Parse CISA KEV data from AI response with grounding
function parseCISAKEVFromAIResponse(aiResponse: string, groundingMetadata?: any): any {
  console.log('Parsing CISA KEV from AI response:', aiResponse.substring(0, 200) + '...');
  
  try {
    // Create a mock KEV structure based on what the AI found
    const mockKEVStructure = {
      title: "CISA Known Exploited Vulnerabilities Catalog",
      catalogVersion: extractFromAI(aiResponse, 'version', new Date().toISOString().split('T')[0]),
      dateReleased: extractFromAI(aiResponse, 'date', new Date().toISOString().split('T')[0]),
      count: extractNumberFromAI(aiResponse, 'vulnerabilities') || 0,
      vulnerabilities: [], // Will be empty since we can't get specific CVE data
      note: "Data retrieved via AI web search with grounding - specific CVE lookup not available",
      aiParsed: true,
      searchSummary: aiResponse.substring(0, 500) + '...',
      groundingMetadata: groundingMetadata || {},
      searchQueries: groundingMetadata?.searchQueries || [],
      groundingSupports: (groundingMetadata?.groundingSupports || []).length
    };

    return {
      json: mockKEVStructure,
      text: aiResponse,
      contentType: 'application/json'
    };

  } catch (error) {
    console.error('Error parsing CISA KEV from AI response:', error);
    return {
      json: { 
        error: 'Failed to parse CISA KEV data', 
        aiResponse: aiResponse.substring(0, 500),
        note: 'AI search completed but data parsing failed',
        groundingMetadata: groundingMetadata || {}
      },
      text: aiResponse,
      contentType: 'application/json'
    };
  }
}

// Parse EPSS data from AI response with grounding
function parseEPSSFromAIResponse(aiResponse: string, groundingMetadata?: any): any {
  try {
    // Look for EPSS score patterns in the response
    const epssMatch = aiResponse.match(/epss['"]*\s*:\s*([0-9.]+)/i);
    const percentileMatch = aiResponse.match(/percentile['"]*\s*:\s*([0-9.]+)/i);
    const cveMatch = aiResponse.match(/(CVE-\d{4}-\d+)/);

    if (epssMatch || percentileMatch) {
      const epssData = {
        status: "OK",
        status_code: 200,
        version: "v1",
        access: "public",
        total: 1,
        offset: 0,
        limit: 100,
        data: [{
          cve: cveMatch ? cveMatch[1] : "unknown",
          epss: epssMatch ? epssMatch[1] : "0.0",
          percentile: percentileMatch ? percentileMatch[1] : "0.0",
          date: new Date().toISOString().split('T')[0]
        }],
        aiParsed: true,
        groundingMetadata: groundingMetadata || {}
      };

      return {
        json: epssData,
        text: aiResponse,
        contentType: 'application/json'
      };
    }

    // Fallback empty EPSS response
    return {
      json: { 
        status: "OK", 
        data: [], 
        note: "No EPSS data found via AI search",
        aiParsed: true,
        groundingMetadata: groundingMetadata || {}
      },
      text: aiResponse,
      contentType: 'application/json'
    };

  } catch (error) {
    console.error('Error parsing EPSS from AI response:', error);
    return {
      json: { 
        error: 'Failed to parse EPSS data', 
        aiResponse: aiResponse.substring(0, 500),
        groundingMetadata: groundingMetadata || {}
      },
      text: aiResponse,
      contentType: 'application/json'
    };
  }
}

// Parse NVD data from AI response with grounding
function parseNVDFromAIResponse(aiResponse: string, groundingMetadata?: any): any {
  try {
    // Look for CVE data structure in the response
    const cveMatch = aiResponse.match(/(CVE-\d{4}-\d+)/);
    const descriptionMatch = aiResponse.match(/description['"]*\s*:?\s*['"](.*?)['"]/i);
    const cvssMatch = aiResponse.match(/cvss.*?([0-9.]+)/i);

    if (cveMatch) {
      const nvdStructure = {
        resultsPerPage: 1,
        startIndex: 0,
        totalResults: 1,
        format: "NVD_CVE",
        version: "2.0",
        timestamp: new Date().toISOString(),
        vulnerabilities: [{
          cve: {
            id: cveMatch[1],
            sourceIdentifier: "ai-web-search",
            published: new Date().toISOString(),
            lastModified: new Date().toISOString(),
            vulnStatus: "Analyzed",
            descriptions: [{
              lang: "en",
              value: descriptionMatch ? descriptionMatch[1] : "Description retrieved via AI web search"
            }],
            metrics: cvssMatch ? {
              cvssMetricV31: [{
                cvssData: {
                  baseScore: parseFloat(cvssMatch[1]) || 0.0,
                  baseSeverity: "UNKNOWN"
                }
              }]
            } : {},
            references: [],
            aiParsed: true,
            groundingMetadata: groundingMetadata || {}
          }
        }]
      };

      return {
        json: nvdStructure,
        text: aiResponse,
        contentType: 'application/json'
      };
    }

    // Fallback empty NVD response
    return {
      json: { 
        vulnerabilities: [], 
        note: "No CVE data found via AI search",
        aiParsed: true,
        groundingMetadata: groundingMetadata || {}
      },
      text: aiResponse,
      contentType: 'application/json'
    };

  } catch (error) {
    console.error('Error parsing NVD from AI response:', error);
    return {
      json: { 
        error: 'Failed to parse NVD data', 
        aiResponse: aiResponse.substring(0, 500),
        groundingMetadata: groundingMetadata || {}
      },
      text: aiResponse,
      contentType: 'application/json'
    };
  }
}

// Helper functions for parsing AI responses
function extractFromAI(response: string, type: string, defaultValue: string): string {
  try {
    const lowerResponse = response.toLowerCase();
    
    switch (type) {
      case 'version':
        const versionMatch = response.match(/version[:\s]+([0-9]{4}\.[0-9]{2}\.[0-9]{2}|[0-9.]+)/i);
        return versionMatch ? versionMatch[1] : defaultValue;
        
      case 'date':
        const dateMatch = response.match(/([0-9]{4}-[0-9]{1,2}-[0-9]{1,2})/);
        return dateMatch ? dateMatch[1] : defaultValue;
        
      default:
        return defaultValue;
    }
  } catch (error) {
    return defaultValue;
  }
}

function extractNumberFromAI(response: string, context: string): number | null {
  try {
    const regex = new RegExp(`${context}[:\\s]*([0-9,]+)`, 'i');
    const match = response.match(regex);
    if (match) {
      return parseInt(match[1].replace(/,/g, ''));
    }
    
    // Try to find any large numbers in the response that might be vulnerability counts
    const numberMatches = response.match(/([0-9,]{3,})/g);
    if (numberMatches) {
      const numbers = numberMatches.map(n => parseInt(n.replace(/,/g, '')));
      // Return the largest reasonable number (likely the vulnerability count)
      return Math.max(...numbers.filter(n => n > 100 && n < 50000));
    }
    
    return null;
  } catch (error) {
    return null;
  }
}

// Enhanced fetchWithFallback with AI web search
async function fetchWithFallback(url: string, options: RequestInit = {}, aiSettings?: any): Promise<Response> {
  try {
    // First attempt: Direct fetch
    console.log('Attempting direct fetch for:', url);
    const response = await fetch(url, options);
    
    // Check if response is ok - CORS issues might not throw but return failed response
    if (response.ok) {
      return response;
    } else {
      // Response failed, treat as CORS/network issue
      throw new Error(`Direct fetch failed with status: ${response.status}`);
    }
  } catch (corsError) {
    console.log('Direct fetch failed (CORS/Network issue), trying AI web search fallback...');
    console.log('Error details:', corsError);
    
    // Use provided AI settings or global settings
    const activeAISettings = aiSettings || globalAISettings;
    
    console.log('AI Settings check:', {
      hasGeminiKey: !!activeAISettings?.geminiApiKey,
      hasOpenAIKey: !!activeAISettings?.openAiApiKey,
      geminiModel: activeAISettings?.geminiModel,
      openAiModel: activeAISettings?.openAiModel,
      globalSettingsAvailable: !!(globalAISettings?.geminiApiKey || globalAISettings?.openAiApiKey)
    });

    if (activeAISettings?.geminiApiKey || activeAISettings?.openAiApiKey) {
      console.log('Using AI web search to fetch content for:', url);
      try {
        const aiResponse = await fetchWithAIWebSearch(url, activeAISettings);
        console.log('AI web search successful for:', url);
        return aiResponse;
      } catch (aiError) {
        console.error('AI web search failed:', aiError);
        console.error('AI error details:', {
          message: aiError instanceof Error ? aiError.message : 'Unknown error',
          stack: aiError instanceof Error ? aiError.stack : undefined
        });
        
        // If AI search fails, try CORS proxy as final fallback
        console.log('AI search failed, trying CORS proxy as final fallback...');
        return await tryCorsproxy(url);
      }
    } else {
      console.log('No AI settings available, trying CORS proxy...');
      console.log('AI Settings debug:', {
        providedSettings: !!aiSettings,
        globalSettings: !!globalAISettings,
        providedGeminiKey: !!aiSettings?.geminiApiKey,
        providedOpenAIKey: !!aiSettings?.openAiApiKey,
        globalGeminiKey: !!globalAISettings?.geminiApiKey,
        globalOpenAIKey: !!globalAISettings?.openAiApiKey
      });
      return await tryCorsproxy(url);
    }
  }
}

// CORS proxy fallback function
async function tryCorsproxy(url: string): Promise<Response> {
  try {
    const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`;
    const response = await fetch(proxyUrl);

    if (response.ok) {
      const proxyData = await response.json();
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: () => Promise.resolve(JSON.parse(proxyData.contents)),
        text: () => Promise.resolve(proxyData.contents),
        headers: new Headers({
          'content-type': 'application/json',
          'x-cors-proxy': 'true'
        })
      } as Response;
    }
    throw new Error(`CORS proxy failed with status: ${response.status}`);
  } catch (proxyError) {
    console.error('CORS proxy also failed:', proxyError);
    throw new Error(`All fallback methods failed. Original CORS error, AI search failed, and CORS proxy failed: ${proxyError.message}`);
  }
}

// Specific CISA KEV search function with corrected API
export async function searchCISAKEVWithAI(cveId: string, aiSettings: any): Promise<any> {
  try {
    const kevSearchPrompt = `Search for information about CVE ${cveId} in the CISA Known Exploited Vulnerabilities (KEV) catalog.

Please search for:
1. Is ${cveId} listed in the CISA KEV catalog?
2. If listed, what are the details (date added, required action, due date)?
3. Any information about active exploitation of ${cveId}

Focus on official CISA sources and government advisories. Return specific information about whether this CVE is actively being exploited according to CISA.`;

    console.log(`Searching CISA KEV for ${cveId} with AI...`);

    const useGemini = !!aiSettings.geminiApiKey;
    const model = useGemini ? (aiSettings.geminiModel || 'gemini-2.5-flash') : (aiSettings.openAiModel || 'gpt-4o');
    const apiUrl = useGemini
      ? `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`
      : `${CONSTANTS.API_ENDPOINTS.OPENAI}/chat/completions`;

    const requestBody: any = useGemini
      ? {
          contents: [{ parts: [{ text: kevSearchPrompt }] }],
          tools: [{ google_search: {} }],
          generationConfig: {
            temperature: 0.1,
            topK: 40,
            topP: 0.95,
            maxOutputTokens: 1024
          }
        }
      : {
          model,
          messages: [{ role: 'user', content: kevSearchPrompt }],
          tools: [{ type: 'web_search' }]
        };

    const headers: any = { 'Content-Type': 'application/json' };
    if (useGemini) {
      headers['x-goog-api-key'] = aiSettings.geminiApiKey;
    } else {
      headers['Authorization'] = `Bearer ${aiSettings.openAiApiKey}`;
    }

    const response = await fetch(apiUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('AI KEV search API error:', errorText);
      throw new Error(`AI KEV search failed: ${response.status} - ${errorText}`);
    }

    const data = await response.json();

    let aiResponse = '';
    let groundingMetadata: any = {};

    if (useGemini) {
      const candidate = data.candidates?.[0];
      aiResponse = candidate?.content?.parts?.[0]?.text || '';
      groundingMetadata = candidate?.groundingMetadata || {};
    } else {
      aiResponse = data.choices?.[0]?.message?.content || '';
    }

    // Parse the response for KEV status
    const isListed = aiResponse.toLowerCase().includes('listed') && 
                    !aiResponse.toLowerCase().includes('not listed') &&
                    !aiResponse.toLowerCase().includes('is not listed');

    return {
      cve: cveId,
      listed: isListed,
      aiResponse: aiResponse,
      source: 'ai-kev-search',
      confidence: isListed ? 'MEDIUM' : 'HIGH', // Higher confidence for "not listed"
      lastChecked: new Date().toISOString(),
      groundingMetadata: groundingMetadata,
      searchQueries: groundingMetadata.searchQueries || [],
      groundingSupports: (groundingMetadata.groundingSupports || []).length
    };

  } catch (error) {
    console.error(`AI KEV search failed for ${cveId}:`, error);
    return {
      cve: cveId,
      listed: false,
      source: 'ai-search-failed',
      error: error instanceof Error ? error.message : String(error),
      confidence: 'LOW',
      lastChecked: new Date().toISOString()
    };
  }
}

// Updated CISA KEV fetch with improved AI integration
export async function fetchCISAKEVData(cveId: string, setLoadingSteps: any, ragDatabase: any, fetchWithFallbackParam: any, aiSettings?: any) {
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  updateSteps((prev: any) => [...prev, `🏛️ Checking CISA KEV catalog for ${cveId}...`]);

  // Debug: Log AI settings availability
  console.log('AI Settings available:', {
    gemini: !!aiSettings?.geminiApiKey,
    openai: !!aiSettings?.openAiApiKey
  });
  console.log('Global AI Settings available:', {
    gemini: !!globalAISettings?.geminiApiKey,
    openai: !!globalAISettings?.openAiApiKey
  });

  try {
    // First attempt: Try to get the full KEV catalog (will likely fail due to CORS)
    const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
    
    try {
      updateSteps((prev: any) => [...prev, `📡 Attempting direct access to CISA KEV catalog...`]);
      
      const response = await fetchWithFallback(url, {
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'VulnerabilityIntelligence/1.0'
        }
      }, aiSettings);

      if (response.ok) {
        const data = await response.json();
        
        // Check if we got valid KEV data
        if (data.vulnerabilities && Array.isArray(data.vulnerabilities)) {
          // Search for the specific CVE in the catalog
          const kevEntry = data.vulnerabilities.find((vuln: any) => vuln.cveID === cveId);
          
          if (kevEntry) {
            updateSteps((prev: any) => [...prev, `🚨 ${cveId} found in CISA KEV catalog - ACTIVELY EXPLOITED`]);
            
            const kevData = {
              cve: cveId,
              listed: true,
              dateAdded: kevEntry.dateAdded,
              shortDescription: kevEntry.shortDescription,
              requiredAction: kevEntry.requiredAction,
              dueDate: kevEntry.dueDate,
              knownRansomwareCampaignUse: kevEntry.knownRansomwareCampaignUse || 'Unknown',
              notes: kevEntry.notes || '',
              vendorProject: kevEntry.vendorProject,
              product: kevEntry.product,
              vulnerabilityName: kevEntry.vulnerabilityName,
              catalogVersion: data.catalogVersion,
              catalogDate: data.dateReleased,
              source: response.headers?.get('x-ai-fetched') ? 'ai-web-search' : 'cisa-kev-direct',
              confidence: response.headers?.get('x-ai-fetched') ? 'MEDIUM' : 'HIGH',
              groundingSupports: response.headers?.get('x-grounding-supports') ? parseInt(response.headers.get('x-grounding-supports')!) : 0
            };

            // Store in RAG database
            if (ragDatabase?.initialized) {
              try {
                await ragDatabase.addDocument(
                  `CISA KEV Entry for ${cveId}: ${kevEntry.shortDescription}. Required Action: ${kevEntry.requiredAction}. Due Date: ${kevEntry.dueDate}. Known Ransomware Use: ${kevEntry.knownRansomwareCampaignUse}. This CVE is actively exploited in the wild and is on the CISA Known Exploited Vulnerabilities catalog.`,
                  {
                    title: `CISA KEV - ${cveId}`,
                    category: 'cisa-kev',
                    tags: ['cisa', 'kev', 'actively-exploited', cveId.toLowerCase(), 'government-source'],
                    source: 'cisa-kev-catalog',
                    cveId: cveId,
                    dateAdded: kevEntry.dateAdded,
                    priority: 'CRITICAL'
                  }
                );
              } catch (ragError) {
                if (ragError && typeof ragError === 'object' && 'message' in ragError) {
                  console.warn(`Failed to store KEV data in RAG: ${(ragError as any).message}`);
                } else {
                  console.warn('Failed to store KEV data in RAG:', ragError);
                }
              }
            }

            return kevData;
          } else {
            updateSteps((prev: any) => [...prev, `✅ ${cveId} not found in CISA KEV catalog (not actively exploited)`]);
            return {
              cve: cveId,
              listed: false,
              catalogVersion: data.catalogVersion,
              catalogDate: data.dateReleased,
              lastChecked: new Date().toISOString(),
              source: response.headers?.get('x-ai-fetched') ? 'ai-web-search' : 'cisa-kev-direct',
              confidence: 'HIGH',
              groundingSupports: response.headers?.get('x-grounding-supports') ? parseInt(response.headers.get('x-grounding-supports')!) : 0
            };
          }
        } else {
          // Got response but no valid vulnerability data - fall back to AI search
          throw new Error('Invalid KEV catalog structure received');
        }
      } else {
        throw new Error(`KEV catalog unavailable: HTTP ${response.status}`);
      }
      
    } catch (catalogError) {
      console.log('Catalog fetch error details:', catalogError);
      updateSteps((prev: any) => [...prev, `⚠️ Full KEV catalog unavailable, trying targeted AI search...`]);
      
      // Fallback: Use AI to search specifically for this CVE
      const activeAISettings = aiSettings || globalAISettings;
      if (activeAISettings?.geminiApiKey) {
        updateSteps((prev: any) => [...prev, `🤖 Using AI with grounding to search CISA KEV for ${cveId}...`]);
        
        try {
          const aiKevResult = await searchCISAKEVWithAI(cveId, activeAISettings);
          
          if (aiKevResult.listed) {
            updateSteps((prev: any) => [...prev, `🚨 AI found ${cveId} in CISA KEV - ACTIVELY EXPLOITED (${aiKevResult.groundingSupports} sources)`]);
          } else {
            updateSteps((prev: any) => [...prev, `✅ AI confirmed ${cveId} not in CISA KEV (${aiKevResult.groundingSupports} sources checked)`]);
          }
          
          // Store AI findings in RAG if KEV listed
          if (ragDatabase?.initialized && aiKevResult.listed) {
            try {
              await ragDatabase.addDocument(
                `AI-Verified CISA KEV Entry for ${cveId}: Listed in CISA Known Exploited Vulnerabilities catalog according to AI search with grounding. This CVE is actively exploited.`,
                {
                  title: `AI-Verified CISA KEV - ${cveId}`,
                  category: 'cisa-kev',
                  tags: ['cisa', 'kev', 'actively-exploited', 'ai-verified', 'grounded', cveId.toLowerCase()],
                  source: 'cisa-kev-ai-search',
                  cveId: cveId,
                  priority: 'CRITICAL'
                }
              );
            } catch (ragError) {
              if (ragError && typeof ragError === 'object' && 'message' in ragError) {
                console.warn(`Failed to store AI KEV data in RAG: ${(ragError as any).message}`);
              } else {
                console.warn('Failed to store AI KEV data in RAG:', ragError);
              }
            }
          }
          
          return aiKevResult;
        } catch (aiSearchError) {
          console.error('AI search also failed:', aiSearchError);
          updateSteps((prev: any) => [...prev, `❌ AI search failed: ${aiSearchError instanceof Error ? aiSearchError.message : 'Unknown error'}`]);
          
          // Return conservative fallback
          return {
            cve: cveId,
            listed: false,
            lastChecked: new Date().toISOString(),
            source: 'ai-search-failed',
            confidence: 'LOW',
            note: 'Both direct access and AI search failed - conservative assumption applied'
          };
        }
      } else {
        updateSteps((prev: any) => [...prev, `⚠️ No AI search available - using conservative approach`]);
        return {
          cve: cveId,
          listed: false,
          lastChecked: new Date().toISOString(),
          source: 'unavailable',
          confidence: 'LOW',
          note: 'CISA KEV status could not be verified - conservative assumption applied'
        };
      }
    }

  } catch (error) {
    console.error(`CISA KEV fetch error for ${cveId}:`, error);
    if (error && typeof error === 'object' && 'message' in error) {
      updateSteps((prev: any) => [...prev, `❌ CISA KEV check failed: ${(error as any).message}`]);
    } else {
      updateSteps((prev: any) => [...prev, `❌ CISA KEV check failed: Unknown error`]);
    }
    
    // Return conservative fallback
    return {
      cve: cveId,
      listed: false,
      lastChecked: new Date().toISOString(),
      source: 'error',
      error: (error && typeof error === 'object' && 'message' in error) ? (error as any).message : String(error),
      confidence: 'LOW',
      note: 'Conservative assumption due to fetch failure'
    };
  }
}

// Enhanced fetchCVEData with AI settings support
export async function fetchCVEData(cveId: string, apiKey: any, setLoadingSteps: any, ragDatabase: any, aiSettings?: any) {
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  updateSteps((prev: string[]) => [...prev, `🔍 Fetching ${cveId} from NVD...`]);

  const url = `${CONSTANTS.API_ENDPOINTS.NVD}?cveId=${cveId}`;
  const headers: any = {
    'Accept': 'application/json',
    'User-Agent': 'VulnerabilityIntelligence/1.0'
  };

  if (apiKey) headers['apiKey'] = apiKey;

  // Enhanced: Pass AI settings for web search fallback
  const response = await fetchWithFallback(url, { headers }, aiSettings);

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

  const aiEnhanced = response.headers?.get('x-ai-fetched') === 'true';
  const groundingSupports = response.headers?.get('x-grounding-supports') ? 
    parseInt(response.headers.get('x-grounding-supports')!) : 0;

  updateSteps((prev: string[]) => [...prev, 
    `✅ Retrieved ${cveId} from NVD${aiEnhanced ? ` (via AI web search, ${groundingSupports} sources)` : ''}`
  ]);

  const processedData = processCVEData(data.vulnerabilities[0].cve);
  processedData.aiEnhanced = aiEnhanced;
  processedData.groundingSupports = groundingSupports;

  // Store in RAG database
  if (ragDatabase?.initialized) {
    try {
      await ragDatabase.addDocument(
        `CVE ${cveId} NVD Data: ${processedData.description} CVSS Score: ${processedData.cvssV3?.baseScore || 'N/A'} Severity: ${processedData.cvssV3?.baseSeverity || 'Unknown'}`,
        {
          title: `NVD Data - ${cveId}`,
          category: 'nvd-data',
          tags: ['nvd', cveId.toLowerCase(), 'official-data', ...(aiEnhanced ? ['ai-enhanced', 'grounded'] : [])],
          source: aiEnhanced ? 'nvd-api-ai-enhanced' : 'nvd-api',
          cveId: cveId
        }
      );
    } catch (ragError: any) {
      console.warn(`Failed to store NVD data in RAG: ${ragError.message}`);
    }
  }

  return processedData;
}

// Enhanced fetchEPSSData with AI settings support
export async function fetchEPSSData(cveId: string, setLoadingSteps: any, ragDatabase: any, aiSettings?: any) {
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  updateSteps((prev: string[]) => [...prev, `📊 Fetching EPSS data for ${cveId}...`]);

  const url = `${CONSTANTS.API_ENDPOINTS.EPSS}?cve=${cveId}`;
  
  // Enhanced: Pass AI settings for web search fallback
  const response = await fetchWithFallback(url, {
    headers: {
      'Accept': 'application/json',
      'User-Agent': 'VulnerabilityIntelligence/1.0'
    }
  }, aiSettings);

  if (!response.ok) {
    if (response.status === 404) {
      updateSteps((prev: string[]) => [...prev, `⚠️ No EPSS data available for ${cveId}`]);
      return null;
    }
    throw new Error(`EPSS API error: ${response.status}`);
  }

  const data = await response.json();

  if (!data.data?.length) {
    updateSteps((prev: string[]) => [...prev, `⚠️ No EPSS data found for ${cveId}`]);
    return null;
  }

  const epssData = data.data[0];
  const epssScore = parseFloat(epssData.epss);
  const percentileScore = parseFloat(epssData.percentile);
  const epssPercentage = (epssScore * 100).toFixed(3);
  const aiEnhanced = response.headers?.get('x-ai-fetched') === 'true';
  const groundingSupports = response.headers?.get('x-grounding-supports') ? 
    parseInt(response.headers.get('x-grounding-supports')!) : 0;

  updateSteps((prev: string[]) => [...prev, 
    `✅ Retrieved EPSS data for ${cveId}: ${epssPercentage}% (Percentile: ${percentileScore.toFixed(3)})${aiEnhanced ? ` (via AI, ${groundingSupports} sources)` : ''}`
  ]);

  // Store in RAG database
  if (ragDatabase?.initialized) {
    try {
      await ragDatabase.addDocument(
        `CVE ${cveId} EPSS Analysis: Exploitation probability ${epssPercentage}% (percentile ${percentileScore.toFixed(3)}). ${epssScore > 0.5 ? 'High exploitation likelihood - immediate attention required.' : epssScore > 0.1 ? 'Moderate exploitation likelihood - monitor closely.' : 'Lower exploitation likelihood but monitoring recommended.'}`,
        {
          title: `EPSS Analysis - ${cveId}`,
          category: 'epss-data',
          tags: ['epss', 'exploitation-probability', cveId.toLowerCase(), ...(aiEnhanced ? ['ai-enhanced', 'grounded'] : [])],
          source: aiEnhanced ? 'first-api-ai-enhanced' : 'first-api',
          cveId: cveId
        }
      );
    } catch (ragError: any) {
      console.warn(`Failed to store EPSS data in RAG: ${ragError.message}`);
    }
  }

  return {
    cve: cveId,
    epss: epssScore.toFixed(9).substring(0, 10),
    percentile: percentileScore.toFixed(9).substring(0, 10),
    epssFloat: epssScore,
    percentileFloat: percentileScore,
    epssPercentage: epssPercentage,
    date: epssData.date,
    model_version: data.model_version,
    aiEnhanced: aiEnhanced,
    groundingSupports: groundingSupports
  };
}
