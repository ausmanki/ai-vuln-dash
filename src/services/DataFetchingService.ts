// DataFetchingService.ts - Fixed with OpenAI /responses endpoint for web search
import { CONSTANTS } from '../utils/constants';
import { processCVEData } from './UtilityService';

export class AIApiRateLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AIApiRateLimitError';
  }
}

// Global AI settings
let globalAISettings: any = null;

export function setGlobalAISettings(settings: any) {
  globalAISettings = settings;
}

// FIXED: Use AI native web search with proper OpenAI /responses endpoint
async function fetchWithAIWebSearch(url: string, aiSettings: any, specificQuery?: string): Promise<Response> {
  console.log('🤖 Using AI native web search for:', url);
  console.log('🔧 AI Settings debug:', {
    hasGeminiKey: !!aiSettings?.geminiApiKey,
    hasOpenAIKey: !!aiSettings?.openAiApiKey,
    geminiModel: aiSettings?.geminiModel,
    openAiModel: aiSettings?.openAiModel,
    globalSettingsAvailable: !!globalAISettings
  });
  
  // FIXED: Better AI settings validation and fallback
  const activeSettings = aiSettings || globalAISettings;
  
  if (!activeSettings) {
    throw new Error('No AI settings provided');
  }
  
  if (!activeSettings.geminiApiKey && !activeSettings.openAiApiKey) {
    throw new Error('Neither Gemini nor OpenAI API key found in settings');
  }
  
  const useGemini = !!activeSettings.geminiApiKey;
  const model = useGemini ? (activeSettings.geminiModel || 'gemini-2.5-flash') : (activeSettings.openAiModel || 'gpt-4o');
  
  // FORCE OpenAI web search for all OpenAI requests
  const openAiSearchCapable = !useGemini; // Always true for OpenAI
  
  console.log('🎯 Using:', useGemini ? 'Gemini' : 'OpenAI', 'with model:', model);
  console.log('🔍 OpenAI search capable:', openAiSearchCapable);
  console.log('🔍 FORCING WEB SEARCH for OpenAI');
  
  // Create targeted search queries based on the URL and purpose
  let searchPrompt = specificQuery || createSearchPrompt(url);
  
  console.log('🔍 Search prompt:', searchPrompt);

  try {
    let apiUrl: string;
    let requestBody: any;
    
    if (useGemini) {
      apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${activeSettings.geminiApiKey}`;
      requestBody = {
        contents: [{ parts: [{ text: searchPrompt }] }],
        tools: [{ google_search_retrieval: {} }],
        generationConfig: {
          temperature: 0.1,
          topK: 40,
          topP: 0.95,
          maxOutputTokens: 4096
        }
      };
    } else if (openAiSearchCapable) {
      // FORCE /responses endpoint for web search
      apiUrl = 'https://api.openai.com/v1/responses';
      console.log('🚀 FORCING /responses endpoint:', apiUrl);
      
      requestBody = {
        model: 'gpt-4.1', // Must use gpt-4.1 for /responses
        tools: [{"type": "web_search_preview"}],
        input: searchPrompt
        // No max_tokens for /responses endpoint
      };
      
      console.log('🚀 Request body for /responses:', JSON.stringify(requestBody, null, 2));
    } else {
      // Fallback to chat completions without web search
      apiUrl = 'https://api.openai.com/v1/chat/completions';
      requestBody = {
        model,
        messages: [{ 
          role: 'user', 
          content: searchPrompt 
        }],
        max_tokens: 4096,
        temperature: 0.1
      };
    }

    const headers: any = { 'Content-Type': 'application/json' };
    if (!useGemini) {
      if (!activeSettings.openAiApiKey) {
        throw new Error('OpenAI API key is missing or undefined');
      }
      headers['Authorization'] = `Bearer ${activeSettings.openAiApiKey}`;
      console.log('🔑 OpenAI key length:', activeSettings.openAiApiKey.length);
    }

    console.log('🌐 Making request to:', apiUrl);
    console.log('🌐 Using web search:', useGemini || openAiSearchCapable);
    console.log('🌐 Request body preview:', JSON.stringify(requestBody).substring(0, 200));

    const response = await fetch(apiUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(requestBody)
    });

    console.log('📡 Response status:', response.status);
    console.log('📡 Response headers:', Object.fromEntries(response.headers.entries()));

    if (!response.ok) {
      const errorText = await response.text();
      console.error('❌ API Error Response:', errorText);
      if (response.status === 429) {
        throw new AIApiRateLimitError(`AI API Error: ${response.status} - ${errorText}`);
      }
      throw new Error(`AI API Error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();
    console.log('📦 Raw response structure keys:', Object.keys(data));
    console.log('📦 Response preview:', JSON.stringify(data).substring(0, 500));
    
    let aiResponse = '';
    let groundingMetadata: any = {};

    if (useGemini) {
      const candidate = data.candidates?.[0];
      if (!candidate?.content?.parts?.[0]?.text) {
        throw new Error('No valid response from Gemini');
      }
      aiResponse = candidate.content.parts[0].text;
      groundingMetadata = candidate.groundingMetadata || {};
      
      console.log('✅ Gemini web search completed');
      console.log('📊 Grounding sources:', groundingMetadata.groundingSupports?.length || 0);
    } else if (openAiSearchCapable) {
      // Handle OpenAI /responses format
      console.log('🔍 Parsing /responses format...');
      console.log('🔍 data.output exists:', !!data.output);
      console.log('🔍 data.output is array:', Array.isArray(data.output));
      
      if (Array.isArray(data.output)) {
        console.log('🔍 Output array length:', data.output.length);
        const messageObj = data.output.find(item => item.type === 'message' && item.content);
        console.log('🔍 Found message object:', !!messageObj);
        
        if (messageObj && Array.isArray(messageObj.content)) {
          console.log('🔍 Message content length:', messageObj.content.length);
          const textObj = messageObj.content.find(item => item.type === 'output_text' && item.text);
          console.log('🔍 Found text object:', !!textObj);
          
          if (textObj && textObj.text) {
            aiResponse = textObj.text;
            console.log('✅ OpenAI web search completed (/responses)');
            console.log('✅ Response length:', aiResponse.length);
          }
        }
      } else if (data.output) {
        aiResponse = data.output;
        console.log('✅ OpenAI web search completed (/responses) - direct output');
      } else if (data.text) {
        // Alternative format
        aiResponse = data.text;
        console.log('✅ OpenAI web search completed (/responses) - text field');
      }
      
      if (!aiResponse) {
        console.error('❌ Failed to extract response from /responses format');
        console.error('❌ Full data structure:', JSON.stringify(data, null, 2));
        throw new Error('No valid response from OpenAI /responses endpoint');
      }
    } else {
      // Handle standard chat completions response
      const choice = data.choices?.[0];
      if (!choice?.message?.content) {
        throw new Error('No valid response from OpenAI');
      }
      aiResponse = choice.message.content;
      
      console.log('✅ OpenAI completed (no web search)');
    }

    // Parse the AI response based on what we're looking for
    const parsedContent = parseAIWebSearchResponse(aiResponse, url, groundingMetadata);

    return {
      ok: true,
      status: 200,
      statusText: 'OK',
      json: () => Promise.resolve(parsedContent.json),
      text: () => Promise.resolve(parsedContent.text),
      headers: new Headers({
        'content-type': parsedContent.contentType,
        'x-ai-fetched': 'true',
        'x-ai-provider': useGemini ? 'gemini' : 'openai',
        'x-web-search-used': String(useGemini || openAiSearchCapable),
        'x-grounding-sources': String(groundingMetadata.groundingSupports?.length || 0)
      })
    } as Response;

  } catch (error) {
    console.error('❌ AI web search failed:', error);
    throw error;
  }
}

// Create targeted search prompts for different data sources
function createSearchPrompt(url: string): string {
  if (url.includes('cisa.gov') && url.includes('known_exploited_vulnerabilities')) {
    return `Search for the current CISA Known Exploited Vulnerabilities (KEV) catalog. I need:
1. The latest catalog information from cisa.gov
2. Total number of vulnerabilities in the catalog
3. Recent updates and catalog version
4. The structure and format of KEV entries

Please provide detailed information about the CISA KEV catalog structure and current statistics.`;
  }
  
  if (url.includes('first.org') && url.includes('epss')) {
    return `Search for information about EPSS (Exploit Prediction Scoring System) from FIRST.org:
1. Current EPSS API endpoints and data structure
2. How EPSS scores are calculated and interpreted
3. Recent updates to the EPSS system
4. Example EPSS data format

Focus on official FIRST.org sources for EPSS information.`;
  }
  
  if (url.includes('nvd.nist.gov')) {
    return `Search for information about the National Vulnerability Database (NVD) from NIST:
1. Current NVD API structure and endpoints
2. CVE data format and available fields
3. Recent updates to NVD services
4. How to access CVE information from NVD

Focus on official NIST/NVD sources.`;
  }
  
  return `Search for current information from this website: ${url}. Provide detailed and up-to-date information about the content and services available.`;
}

// ENHANCED: Parse AI responses into structured data
function parseAIWebSearchResponse(aiResponse: string, originalUrl: string, groundingMetadata?: any): any {
  console.log('🔍 Parsing AI response for:', originalUrl);
  
  if (originalUrl.includes('cisa.gov') && originalUrl.includes('known_exploited_vulnerabilities')) {
    return parseCISAKEVFromAI(aiResponse, groundingMetadata);
  }
  
  if (originalUrl.includes('first.org') && originalUrl.includes('epss')) {
    return parseEPSSFromAI(aiResponse, groundingMetadata);
  }
  
  if (originalUrl.includes('nvd.nist.gov')) {
    return parseNVDFromAI(aiResponse, groundingMetadata);
  }
  
  // Generic response
  return {
    json: {
      content: aiResponse,
      source: 'ai-web-search',
      groundingMetadata: groundingMetadata || {}
    },
    text: aiResponse,
    contentType: 'application/json'
  };
}

// ENHANCED CISA KEV parser
function parseCISAKEVFromAI(aiResponse: string, groundingMetadata?: any): any {
  console.log('📋 Parsing CISA KEV information from AI response');
  
  // Extract key information from the AI response
  const catalogVersionMatch = aiResponse.match(/version[:\s]+([0-9]{4}\.[0-9]{2}\.[0-9]{2}|[0-9.]+)/i);
  const dateMatch = aiResponse.match(/([0-9]{4}-[0-9]{1,2}-[0-9]{1,2})/);
  const countMatch = aiResponse.match(/(\d{1,5})\s*(?:vulnerabilities|CVEs|entries)/i);
  
  const mockKEVStructure = {
    title: "CISA Known Exploited Vulnerabilities Catalog",
    catalogVersion: catalogVersionMatch ? catalogVersionMatch[1] : new Date().toISOString().split('T')[0],
    dateReleased: dateMatch ? dateMatch[1] : new Date().toISOString().split('T')[0],
    count: countMatch ? parseInt(countMatch[1]) : 0,
    vulnerabilities: [], // This will be populated by specific CVE searches
    note: "Data retrieved via AI web search - use searchCISAKEVForCVE for specific CVE lookups",
    aiParsed: true,
    aiResponse: aiResponse,
    groundingMetadata: groundingMetadata || {},
    searchCapability: true
  };

  return {
    json: mockKEVStructure,
    text: aiResponse,
    contentType: 'application/json'
  };
}

// ENHANCED EPSS parser
function parseEPSSFromAI(aiResponse: string, groundingMetadata?: any): any {
  console.log('📊 Parsing EPSS information from AI response');
  
  const epssData = {
    status: "OK",
    status_code: 200,
    version: "v1",
    access: "public",
    note: "EPSS data structure from AI search - use searchEPSSForCVE for specific CVE scores",
    data: [], // Will be populated by specific CVE searches
    aiParsed: true,
    aiResponse: aiResponse,
    groundingMetadata: groundingMetadata || {},
    searchCapability: true
  };

  return {
    json: epssData,
    text: aiResponse,
    contentType: 'application/json'
  };
}

// ENHANCED NVD parser  
function parseNVDFromAI(aiResponse: string, groundingMetadata?: any): any {
  console.log('🗃️ Parsing NVD information from AI response');
  
  const nvdStructure = {
    resultsPerPage: 0,
    startIndex: 0,
    totalResults: 0,
    format: "NVD_CVE",
    version: "2.0",
    timestamp: new Date().toISOString(),
    note: "NVD structure from AI search - use searchNVDForCVE for specific CVE data",
    vulnerabilities: [], // Will be populated by specific CVE searches
    aiParsed: true,
    aiResponse: aiResponse,
    groundingMetadata: groundingMetadata || {},
    searchCapability: true
  };

  return {
    json: nvdStructure,
    text: aiResponse,
    contentType: 'application/json'
  };
}

// SMART: CVE-specific search functions using AI web search
export async function searchCISAKEVForCVE(cveId: string, aiSettings: any): Promise<any> {
  console.log(`🔍 Searching CISA KEV for ${cveId} using AI web search`);
  
  const searchPrompt = `Search the official CISA Known Exploited Vulnerabilities (KEV) catalog for CVE ${cveId}.

Please check:
1. Is ${cveId} listed in the current CISA KEV catalog?
2. If listed, what are the specific details:
   - Date added to catalog
   - Short description
   - Required action
   - Due date for patching
   - Known ransomware campaign use
   - Vendor/Project name
   - Product name

Search specifically on cisa.gov for the KEV catalog and ${cveId}. Be very precise about whether this CVE is actually listed or not.

Respond in this exact format:
LISTED: [YES/NO]
DATE_ADDED: [date if listed]
DESCRIPTION: [description if listed]
REQUIRED_ACTION: [action if listed]
DUE_DATE: [due date if listed]
RANSOMWARE_USE: [yes/no/unknown if listed]
VENDOR: [vendor if listed]
PRODUCT: [product if listed]`;

  try {
    const response = await fetchWithAIWebSearch('https://www.cisa.gov/known-exploited-vulnerabilities', aiSettings, searchPrompt);
    const data = await response.json();
    
    const aiResponse = data.aiResponse || data.content || '';
    const isListed = aiResponse.toLowerCase().includes('listed: yes') || 
                    (aiResponse.toLowerCase().includes('listed') && 
                     !aiResponse.toLowerCase().includes('listed: no') &&
                     aiResponse.toLowerCase().includes(cveId.toLowerCase()));

    // Extract details if listed
    let details: any = {
      cve: cveId,
      listed: isListed,
      source: 'ai-kev-search',
      confidence: isListed ? 'HIGH' : 'HIGH',
      lastChecked: new Date().toISOString(),
      aiResponse: aiResponse.substring(0, 1000),
      groundingMetadata: data.groundingMetadata || {}
    };

    if (isListed) {
      // Extract specific details from the response
      details.dateAdded = extractField(aiResponse, 'DATE_ADDED');
      details.shortDescription = extractField(aiResponse, 'DESCRIPTION');
      details.requiredAction = extractField(aiResponse, 'REQUIRED_ACTION');
      details.dueDate = extractField(aiResponse, 'DUE_DATE');
      details.knownRansomwareCampaignUse = extractField(aiResponse, 'RANSOMWARE_USE');
      details.vendorProject = extractField(aiResponse, 'VENDOR');
      details.product = extractField(aiResponse, 'PRODUCT');
    }

    return details;

  } catch (error) {
    console.error(`❌ AI KEV search failed for ${cveId}:`, error);
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

// Fallback: Directly check the CISA KEV catalog if AI search fails or is unavailable
async function fetchCisaKevFromCatalog(cveId: string): Promise<any> {
  const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch CISA KEV catalog: ${response.status}`);
  }

  const catalog = await response.json();
  const entry = (catalog.vulnerabilities || []).find((v: any) => v.cveID === cveId);

  if (entry) {
    return {
      cve: cveId,
      listed: true,
      source: 'cisa-kev-catalog',
      confidence: 'HIGH',
      lastChecked: new Date().toISOString(),
      dateAdded: entry.dateAdded,
      shortDescription: entry.shortDescription,
      requiredAction: entry.requiredAction,
      dueDate: entry.dueDate,
      knownRansomwareCampaignUse: entry.knownRansomwareCampaignUse,
      vendorProject: entry.vendorProject,
      product: entry.product
    };
  }

  return {
    cve: cveId,
    listed: false,
    source: 'cisa-kev-catalog',
    confidence: 'MEDIUM',
    lastChecked: new Date().toISOString()
  };
}

export async function searchEPSSForCVE(cveId: string, aiSettings: any): Promise<any> {
  console.log(`📊 Searching EPSS data for ${cveId} using AI web search`);
  
  const searchPrompt = `Search for EPSS (Exploit Prediction Scoring System) data for CVE ${cveId} from FIRST.org.

Please find:
1. The current EPSS score for ${cveId}
2. The percentile ranking
3. The date of the score
4. Any recent changes to the score

Search specifically on first.org for EPSS data and ${cveId}.

Respond in this exact format:
CVE: ${cveId}
EPSS_SCORE: [decimal score 0.0-1.0]
PERCENTILE: [decimal percentile 0.0-1.0] 
DATE: [YYYY-MM-DD]
FOUND: [YES/NO]`;

  try {
    const response = await fetchWithAIWebSearch('https://api.first.org/data/v1/epss', aiSettings, searchPrompt);
    const data = await response.json();
    
    const aiResponse = data.aiResponse || data.content || '';
    const epssMatch = aiResponse.match(/EPSS_SCORE:\s*([0-9.]+)/i);
    const percentileMatch = aiResponse.match(/PERCENTILE:\s*([0-9.]+)/i);
    const dateMatch = aiResponse.match(/DATE:\s*([0-9]{4}-[0-9]{1,2}-[0-9]{1,2})/i);
    const foundMatch = aiResponse.match(/FOUND:\s*(YES|NO)/i);

    if (foundMatch && foundMatch[1].toUpperCase() === 'YES' && epssMatch && percentileMatch) {
      const epssScore = parseFloat(epssMatch[1]);
      const percentileScore = parseFloat(percentileMatch[1]);
      
      return {
        cve: cveId,
        epss: epssScore.toFixed(9).substring(0, 10),
        percentile: percentileScore.toFixed(9).substring(0, 10),
        epssFloat: epssScore,
        percentileFloat: percentileScore,
        epssPercentage: (epssScore * 100).toFixed(3),
        date: dateMatch ? dateMatch[1] : new Date().toISOString().split('T')[0],
        aiEnhanced: true,
        source: 'ai-epss-search',
        aiResponse: aiResponse.substring(0, 500)
      };
    }

    return null; // No EPSS data found

  } catch (error) {
    console.error(`❌ AI EPSS search failed for ${cveId}:`, error);
    return null;
  }
}

export async function searchNVDForCVE(cveId: string, aiSettings: any): Promise<any> {
  console.log(`🗃️ Searching NVD for ${cveId} using AI web search`);
  
  const searchPrompt = `Search for CVE ${cveId} in the National Vulnerability Database (NVD) from NIST.

Please find:
1. The complete CVE description
2. CVSS v3.1 base score and severity
3. Publication date
4. Last modified date
5. Vulnerability status
6. Any CWE (weakness) classifications
7. Reference links

Search specifically on nvd.nist.gov for ${cveId}.

Respond with detailed CVE information if found, or indicate if not found.`;

  try {
    const response = await fetchWithAIWebSearch('https://nvd.nist.gov/', aiSettings, searchPrompt);
    const data = await response.json();
    
    const aiResponse = data.aiResponse || data.content || '';
    
    // Enhanced parsing for better results
    const cveMatch = aiResponse.match(new RegExp(cveId, 'i'));
    if (!cveMatch && !aiResponse.toLowerCase().includes('not found')) {
      console.log('🔍 CVE found in response, parsing details...');
    }

    // Extract description - look for various patterns
    let description = 'No description available';
    const descPatterns = [
      /description[:\s]*"([^"]+)"/i,
      /description[:\s]*([^.]+\.)/i,
      /vulnerability[:\s]*([^.]+\.)/i,
      /summary[:\s]*([^.]+\.)/i,
      /(.*vulnerability.*)/i
    ];
    
    for (const pattern of descPatterns) {
      const match = aiResponse.match(pattern);
      if (match && match[1] && match[1].length > 20) {
        description = match[1].trim();
        break;
      }
    }

    // Extract CVSS score - look for various patterns
    let cvssScore = null;
    let severity = 'UNKNOWN';
    const cvssPatterns = [
      /cvss.*?([0-9]\.[0-9])/i,
      /score[:\s]*([0-9]\.[0-9])/i,
      /base\s*score[:\s]*([0-9]\.[0-9])/i,
      /([0-9]\.[0-9])\s*\((critical|high|medium|low)\)/i
    ];
    
    for (const pattern of cvssPatterns) {
      const match = aiResponse.match(pattern);
      if (match && match[1]) {
        cvssScore = parseFloat(match[1]);
        break;
      }
    }
    
    // Extract severity
    const severityMatch = aiResponse.match(/severity[:\s]*(\w+)/i) || 
                         aiResponse.match(/\((critical|high|medium|low)\)/i);
    if (severityMatch) {
      severity = severityMatch[1].toUpperCase();
    } else if (cvssScore) {
      // Derive severity from score
      if (cvssScore >= 9.0) severity = 'CRITICAL';
      else if (cvssScore >= 7.0) severity = 'HIGH';
      else if (cvssScore >= 4.0) severity = 'MEDIUM';
      else severity = 'LOW';
    }

    // Extract dates
    const datePattern = /(\d{4}-\d{2}-\d{2})/g;
    const dates = aiResponse.match(datePattern) || [];
    const published = dates[0] || new Date().toISOString();
    const lastModified = dates[1] || dates[0] || new Date().toISOString();

    const processedData = {
      id: cveId,
      description: description,
      published: published,
      lastModified: lastModified,
      vulnStatus: 'Analyzed',
      cvssV3: cvssScore ? {
        baseScore: cvssScore,
        baseSeverity: severity,
        vectorString: 'N/A'
      } : null,
      references: [],
      configurations: [],
      weaknesses: [],
      aiEnhanced: true,
      source: 'ai-nvd-search',
      webSearchUsed: true,
      aiResponse: aiResponse.substring(0, 1000)
    };

    console.log(`✅ Parsed NVD data - Score: ${cvssScore}, Severity: ${severity}`);
    return processedData;

  } catch (error) {
    console.error(`❌ AI NVD search failed for ${cveId}:`, error);
    throw error;
  }
}

// Utility function to extract fields from structured AI responses
function extractField(response: string, fieldName: string): string {
  const regex = new RegExp(`${fieldName}:\\s*([^\\n]+)`, 'i');
  const match = response.match(regex);
  return match ? match[1].trim() : '';
}

// MAIN API FUNCTIONS - Updated to use AI web search with better error handling
export async function fetchCVEData(cveId: string, apiKey: any, setLoadingSteps: any, ragDatabase: any, aiSettings?: any) {
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  const activeAISettings = aiSettings || globalAISettings;
  
  // FIXED: Check for AI settings before proceeding
  if (!activeAISettings?.geminiApiKey && !activeAISettings?.openAiApiKey) {
    updateSteps((prev: string[]) => [...prev, `⚠️ No AI settings available - falling back to direct API`]);
    
    // Try direct NVD API call without AI
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    try {
      const response = await fetch(url);
      if (response.ok) {
        const data = await response.json();
        if (data.vulnerabilities?.length > 0) {
          updateSteps((prev: string[]) => [...prev, `✅ Retrieved ${cveId} from NVD directly`]);
          return processCVEData(data.vulnerabilities[0].cve);
        }
      }
    } catch (directError) {
      console.log('Direct NVD fetch failed:', directError);
    }
    
    throw new Error(`No AI settings configured and direct API failed for ${cveId}`);
  }
  
  updateSteps((prev: string[]) => [...prev, `🔍 Searching for ${cveId} using AI web search...`]);

  try {
    const processedData = await searchNVDForCVE(cveId, activeAISettings);
    
    updateSteps((prev: string[]) => [...prev, `✅ Retrieved ${cveId} from NVD via AI web search`]);

    // Store in RAG database
    if (ragDatabase?.initialized) {
      await ragDatabase.addDocument(
        `CVE ${cveId} NVD Data: ${processedData.description} CVSS Score: ${processedData.cvssV3?.baseScore || 'N/A'} Severity: ${processedData.cvssV3?.baseSeverity || 'Unknown'}`,
        {
          title: `NVD Data - ${cveId}`,
          category: 'nvd-data',
          tags: ['nvd', cveId.toLowerCase(), 'ai-enhanced', 'web-search'],
          source: 'nvd-ai-search',
          cveId: cveId
        }
      );
    }

    return processedData;
  } catch (error) {
    updateSteps((prev: string[]) => [...prev, `❌ AI search failed for ${cveId}: ${error.message}`]);
    throw error;
  }
}

export async function fetchEPSSData(cveId: string, setLoadingSteps: any, ragDatabase: any, aiSettings?: any) {
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  const activeAISettings = aiSettings || globalAISettings;
  
  // FIXED: Check for AI settings before proceeding
  if (!activeAISettings?.geminiApiKey && !activeAISettings?.openAiApiKey) {
    updateSteps((prev: string[]) => [...prev, `⚠️ No AI settings available - trying direct EPSS API`]);
    
    // Try direct EPSS API call
    const url = `https://api.first.org/data/v1/epss?cve=${cveId}`;
    try {
      const response = await fetch(url);
      if (response.ok) {
        const data = await response.json();
        if (data.data?.length > 0) {
          const epssData = data.data[0];
          const epssScore = parseFloat(epssData.epss);
          const percentileScore = parseFloat(epssData.percentile);
          
          updateSteps((prev: string[]) => [...prev, `✅ Retrieved EPSS data for ${cveId} directly`]);
          
          return {
            cve: cveId,
            epss: epssScore.toFixed(9).substring(0, 10),
            percentile: percentileScore.toFixed(9).substring(0, 10),
            epssFloat: epssScore,
            percentileFloat: percentileScore,
            epssPercentage: (epssScore * 100).toFixed(3),
            date: epssData.date,
            model_version: data.model_version,
            aiEnhanced: false
          };
        }
      }
    } catch (directError) {
      console.log('Direct EPSS fetch failed:', directError);
    }
    
    updateSteps((prev: string[]) => [...prev, `⚠️ No EPSS data available for ${cveId}`]);
    return null;
  }
  
  updateSteps((prev: string[]) => [...prev, `📊 Searching for EPSS data for ${cveId}...`]);

  try {
    const epssData = await searchEPSSForCVE(cveId, activeAISettings);
    
    if (epssData) {
      updateSteps((prev: string[]) => [...prev, `✅ Retrieved EPSS data for ${cveId}: ${epssData.epssPercentage}%`]);
      
      // Store in RAG database
      if (ragDatabase?.initialized) {
        await ragDatabase.addDocument(
          `CVE ${cveId} EPSS Analysis: Exploitation probability ${epssData.epssPercentage}% (percentile ${epssData.percentileFloat.toFixed(3)}). ${epssData.epssFloat > 0.5 ? 'High exploitation likelihood' : epssData.epssFloat > 0.1 ? 'Moderate exploitation likelihood' : 'Lower exploitation likelihood'}.`,
          {
            title: `EPSS Analysis - ${cveId}`,
            category: 'epss-data',
            tags: ['epss', 'exploitation-probability', cveId.toLowerCase(), 'ai-enhanced'],
            source: 'epss-ai-search',
            cveId: cveId
          }
        );
      }
      
      return epssData;
    } else {
      updateSteps((prev: string[]) => [...prev, `⚠️ No EPSS data available for ${cveId}`]);
      return null;
    }
  } catch (error) {
    updateSteps((prev: string[]) => [...prev, `❌ EPSS search failed for ${cveId}`]);
    return null;
  }
}

export async function fetchCISAKEVData(cveId: string, setLoadingSteps: any, ragDatabase: any, fetchWithFallbackParam: any, aiSettings?: any) {
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  const activeAISettings = aiSettings || globalAISettings;
  
  // FIXED: Check for AI settings before proceeding
  if (!activeAISettings?.geminiApiKey && !activeAISettings?.openAiApiKey) {
    updateSteps((prev: any) => [...prev, `⚠️ No AI settings available - using direct CISA KEV catalog`]);

    try {
      return await fetchCisaKevFromCatalog(cveId);
    } catch (catalogErr) {
      return {
        cve: cveId,
        listed: false,
        source: 'kev-catalog-failed',
        error: catalogErr instanceof Error ? catalogErr.message : String(catalogErr),
        confidence: 'LOW',
        lastChecked: new Date().toISOString()
      };
    }
  }
  
  updateSteps((prev: any) => [...prev, `🏛️ Searching CISA KEV for ${cveId}...`]);

  try {
    const kevData = await searchCISAKEVForCVE(cveId, activeAISettings);
    
    if (kevData.listed) {
      updateSteps((prev: any) => [...prev, `🚨 ${cveId} found in CISA KEV - ACTIVELY EXPLOITED`]);
      
      // Store in RAG database
      if (ragDatabase?.initialized) {
        await ragDatabase.addDocument(
          `CISA KEV Entry for ${cveId}: ${kevData.shortDescription || 'Listed in Known Exploited Vulnerabilities'}. This CVE is actively exploited in the wild according to CISA.`,
          {
            title: `CISA KEV - ${cveId}`,
            category: 'cisa-kev',
            tags: ['cisa', 'kev', 'actively-exploited', cveId.toLowerCase(), 'ai-verified'],
            source: 'cisa-kev-ai-search',
            cveId: cveId,
            priority: 'CRITICAL'
          }
        );
      }
    } else {
      updateSteps((prev: any) => [...prev, `✅ ${cveId} not found in CISA KEV (not actively exploited)`]);
    }

    return kevData;
  } catch (error) {
    updateSteps((prev: any) => [...prev, `❌ CISA KEV search failed for ${cveId} - falling back to catalog`]);
    try {
      return await fetchCisaKevFromCatalog(cveId);
    } catch (catalogErr) {
      return {
        cve: cveId,
        listed: false,
        source: 'kev-catalog-failed',
        error: catalogErr instanceof Error ? catalogErr.message : String(catalogErr),
        confidence: 'LOW',
        lastChecked: new Date().toISOString()
      };
    }
  }
}

// COMPATIBILITY: Export alias for backward compatibility
export const searchCISAKEVWithAI = searchCISAKEVForCVE;
