// AIEnhancementService.ts - FIXED VERSION with proper OpenAI /responses endpoint support
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
 * FIXED: Enhanced patch search with proper OpenAI /responses endpoint support
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
  updateSteps(prev => [...prev, `🔍 Searching for patches and advisories for ${cveId}...`]);

  if (!settings.geminiApiKey && !settings.openAiApiKey) {
    updateSteps(prev => [...prev, `⚠️ API key required for patch search`]);
    return getHeuristicPatchesAndAdvisories(cveId, cveData);
  }

  const useGemini = !settings.openAiApiKey && !!settings.geminiApiKey;
  const model = useGemini ? (settings.geminiModel || 'gemini-2.5-flash') : (settings.openAiModel || 'gpt-4o');
  const geminiSearchCapable = useGemini && (model.includes('2.0') || model.includes('2.5'));
  
  // OpenAI /responses endpoint DOES exist and supports web search
  // Force gpt-4.1 for web search regardless of selected model
  const openAiSearchCapable = !useGemini && model === 'gpt-4.1';
  
  // Always use gpt-4.1 for /responses endpoint
  const openAiModelForSearch = openAiSearchCapable ? 'gpt-4.1' : model;
  
  console.log('🚨 EMERGENCY DEBUG:');
  console.log('- useGemini:', useGemini);
  console.log('- model:', model);
  console.log('- settings.openAiModel:', settings.openAiModel);
  console.log('- openAiSearchCapable:', openAiSearchCapable, '(/responses endpoint available)');

  if (useGemini && !geminiSearchCapable) {
    updateSteps(prev => [...prev, `⚠️ Web search not supported by Gemini model`]);
    return getHeuristicPatchesAndAdvisories(cveId, cveData);
  }

  if (!useGemini && !openAiSearchCapable) {
    updateSteps(prev => [...prev, `⚠️ Web search not supported by OpenAI model - use gpt-4.1 or gpt-4o`]);
    return getHeuristicPatchesAndAdvisories(cveId, cveData);
  }

  const description = cveData?.description || 'No description available';

  // Enhanced prompt for web search
  const analysisPrompt = `Search for security patches and advisories for ${cveId}.

CVE Description: "${description}"

Search for:
1. Official vendor security patches for ${cveId}. Provide version numbers.
2. Security advisories mentioning ${cveId}.
3. Firmware updates that fix ${cveId}.
4. Software updates addressing ${cveId}.

Focus on official vendor sources and security advisory sites.

Please provide information about any patches, updates, or advisories you find for ${cveId}. Include download links and version numbers where available.`;

  try {
    const requestBody: any = useGemini
    ? {
        contents: [{ parts: [{ text: analysisPrompt }] }],
        generationConfig: {
          temperature: 0.1,
          topK: 40,
          topP: 0.95,
          maxOutputTokens: 8192,
          candidateCount: 1
        },
        tools: [{ google_search: {} }]
      }
    : openAiSearchCapable
      ? {
          // FIXED: OpenAI /responses endpoint format with correct model and tool type
          model: "gpt-4.1", // ALWAYS use "gpt-4.1" for /responses endpoint
          tools: [{"type": "web_search_preview"}], // Use "web_search_preview" as per docs
          input: analysisPrompt, // /responses uses 'input' not 'messages'
          // NO max_tokens for /responses endpoint
        }
      : {
          // Standard chat completions format (fallback)
          model,
          messages: [{ 
            role: 'user', 
            content: analysisPrompt 
          }],
          max_tokens: 4096,
          temperature: 0.1
        };

  console.log('🔧 DEBUG: OpenAI search capable:', openAiSearchCapable);
  console.log('🔧 DEBUG: Using model:', openAiSearchCapable ? "gpt-4.1" : model);
  console.log('🔧 DEBUG: Request body format:', useGemini ? 'Gemini with web search' : openAiSearchCapable ? 'OpenAI /responses with web search' : 'OpenAI chat completions');

  updateSteps(prev => [...prev, `🤖 AI searching for patches and advisories ${(useGemini && geminiSearchCapable) || (!useGemini && openAiSearchCapable) ? 'with web search' : 'without web search'}...`]);

  const apiUrl = useGemini
    ? `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${settings.geminiApiKey}`
    : openAiSearchCapable
      ? 'https://api.openai.com/v1/responses' // Use /responses for web search
      : 'https://api.openai.com/v1/chat/completions'; // Use chat completions as fallback

  console.log('🔧 DEBUG: API URL being used:', apiUrl);
  console.log('🔧 DEBUG: Using web search endpoint:', openAiSearchCapable);

    const headers: any = { 'Content-Type': 'application/json' };
    
    if (!useGemini) {
      console.log('🔧 DEBUG: Setting OpenAI auth header');
      headers['Authorization'] = `Bearer ${settings.openAiApiKey}`;
    }

    const response = await fetchWithFallback(apiUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => 'Unknown error');
      console.error('API Error Response:', errorText);
      
      // Try to parse error for more details
      try {
        const errorData = JSON.parse(errorText);
        console.error('Parsed error:', errorData);
      } catch (e) {
        // Ignore parsing errors
      }
      
      throw new Error(`API error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();
    let aiResponse = '';
    let groundingMetadata: any = {};

    if (useGemini) {
      // FIXED: Handle chunked/multi-part Gemini responses to fix truncation
      if (data.candidates && data.candidates.length > 0) {
        aiResponse = data.candidates
          .map(candidate =>
            candidate.content?.parts?.map(part => part.text).join('') || ''
          )
          .join('\n');

        groundingMetadata = data.candidates[0].groundingMetadata || {};
        
        if (aiResponse.trim()) {
          updateSteps(prev => [...prev, `✅ Found patch information via Gemini web search`]);
        } else if (groundingMetadata.webSearchQueries) {
          updateSteps(prev => [...prev, `📊 Extracting from Gemini search metadata...`]);
          aiResponse = 'Search completed - extracting from metadata';
        } else {
          throw new Error('No usable text or metadata in Gemini response');
        }
      } else {
        throw new Error('No candidates in Gemini API response');
      }
    } else {
      // Handle OpenAI response (both /responses and /chat/completions)
      let responseText = '';
      
      if (openAiSearchCapable) {
        // FIXED: OpenAI /responses endpoint returns output as an array
        console.log('📥 OpenAI /responses response structure:', Object.keys(data));
        console.log('📥 data.output exists:', !!data.output);
        console.log('📥 data.output type:', typeof data.output);
        console.log('📥 Is data.output an array?:', Array.isArray(data.output));
        
        // Extract text from the output array structure
        if (Array.isArray(data.output)) {
          const messageObj = data.output.find(item => item.type === 'message' && item.content);
          
          if (messageObj && Array.isArray(messageObj.content)) {
            const textObj = messageObj.content.find(item => item.type === 'output_text' && item.text);
            
            if (textObj && textObj.text) {
              responseText = textObj.text;
              console.log('📥 Found text in output array structure');
            }
          }
        } else if (typeof data.output === 'string') {
          responseText = data.output;
        } else if (typeof data.text === 'string') {
          responseText = data.text;
        } else if (data.output && typeof data.output === 'object') {
          responseText = data.output.text || data.output.content || data.output.message || JSON.stringify(data.output);
        } else if (data.text && typeof data.text === 'object') {
          responseText = data.text.content || data.text.text || JSON.stringify(data.text);
        } else {
          responseText = '';
        }
        
        // Ensure responseText is a string
        if (typeof responseText !== 'string') {
          console.error('📥 responseText is not a string:', typeof responseText, responseText);
          responseText = String(responseText);
        }
        
        // Extract search metadata if available from /responses
        if (data.search_results || data.web_results || data.sources) {
          groundingMetadata = {
            searchResults: data.search_results || data.web_results || [],
            webSearchQueries: data.search_queries || [],
            sources: data.sources || []
          };
        }
        
        console.log('📥 Final responseText length:', responseText?.length || 0);
        updateSteps(prev => [...prev, `✅ Found patch information via OpenAI web search (/responses)`]);
      } else {
        // Standard chat completions response format
        responseText = data.choices?.[0]?.message?.content || '';
        updateSteps(prev => [...prev, `✅ Found patch information via OpenAI (standard completion)`]);
      }
      
      if (!responseText) {
        console.error('No text in response. Full response:', JSON.stringify(data, null, 2));
        throw new Error(`No usable response from OpenAI ${openAiSearchCapable ? '/responses' : 'chat completions'} API`);
      }
      
      aiResponse = responseText;
    }

    // Parse response more reliably
    const result = parseTextResponseForPatches(aiResponse, cveId, groundingMetadata);

    // Always enhance with heuristics
    const heuristicData = getHeuristicPatchesAndAdvisories(cveId, cveData);
    
    // Merge patches and advisories
    const mergedPatches = [...(result.patches || []), ...(heuristicData.patches || [])];
    const mergedAdvisories = [...(result.advisories || []), ...(heuristicData.advisories || [])];
    
    updateSteps(prev => [...prev, `📋 Found ${mergedPatches.length} patches and ${mergedAdvisories.length} advisories`]);
    
    return {
      patches: mergedPatches,
      advisories: mergedAdvisories,
      searchSummary: {
        patchesFound: mergedPatches.length,
        advisoriesFound: mergedAdvisories.length,
        enhancedWithHeuristics: true,
        aiSearchPerformed: true,
        webSearchUsed: useGemini ? geminiSearchCapable : openAiSearchCapable,
        confidence: result.confidence || 'MEDIUM'
      }
    };

  } catch (error) {
    console.error('Patch search error:', error);
    updateSteps(prev => [...prev, `⚠️ AI search failed: ${error.message}`]);
    return getHeuristicPatchesAndAdvisories(cveId, cveData);
  }
}

/**
 * FIXED: Enhanced threat intelligence with proper OpenAI /responses endpoint support
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
  const geminiSearchCapable = useGemini && (model.includes('2.0') || model.includes('2.5'));
  // Re-enable OpenAI web search - /responses endpoint is available
  const openAiSearchCapable = !useGemini && model === 'gpt-4.1';

  console.log('🚨 Threat Intel DEBUG:');
  console.log('- useGemini:', useGemini);
  console.log('- model:', model);
  console.log('- geminiSearchCapable:', geminiSearchCapable);
  console.log('- openAiSearchCapable:', openAiSearchCapable, '(/responses endpoint available)');

  if (useGemini && !geminiSearchCapable) {
    updateSteps(prev => [...prev, `⚠️ Gemini model doesn't support web search`]);
    return await performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
  }

  if (!useGemini && !openAiSearchCapable) {
    updateSteps(prev => [...prev, `⚠️ OpenAI model doesn't support web search - use gpt-4.1`]);
    return await performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
  }

  updateSteps(prev => [...prev, `🔍 Searching for threat intelligence on ${cveId}...`]);

  // Enhanced threat intelligence prompt
  const searchPrompt = `Search for threat intelligence information about ${cveId}.

Look for:
1. Is ${cveId} in the CISA Known Exploited Vulnerabilities catalog?
2. Evidence of active exploitation of ${cveId}.
3. Public exploit code or proof-of-concept for ${cveId}. Provide links to the code.
4. Security vendor reports about ${cveId}.
5. Threat actor usage of ${cveId}. Name specific threat actors.

CVE Details:
- CVE: ${cveId}
- Description: ${cveData?.description?.substring(0, 200) || 'Unknown'}
- CVSS Score: ${cveData?.cvssV3?.baseScore || 'Unknown'}
- EPSS Score: ${epssData?.epss || 'Unknown'}%

Provide specific information about any threats, exploits, or active usage you find.`;

  try {
    const requestBody = useGemini
      ? {
          contents: [{ parts: [{ text: searchPrompt }] }],
          generationConfig: {
            temperature: 0.05,
            topK: 1,
            topP: 0.8,
            maxOutputTokens: 8192,
            candidateCount: 1
          },
          tools: [{ google_search: {} }]
        } 
      : {
          // FIXED: OpenAI /responses endpoint format
          model: "gpt-4.1", // MUST be "gpt-4.1"
          tools: [{"type": "web_search_preview"}], // Correct tool type
          input: searchPrompt // 'input' not 'messages'
          // NO max_tokens for /responses
        };

    const apiUrl = useGemini
      ? `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${settings.geminiApiKey}`
      : openAiSearchCapable
        ? 'https://api.openai.com/v1/responses'
        : 'https://api.openai.com/v1/chat/completions';

    const headers: any = { 'Content-Type': 'application/json' };
    if (!useGemini) {
      console.log('🔧 DEBUG: Setting OpenAI auth header for threat intel');
      headers['Authorization'] = `Bearer ${settings.openAiApiKey}`;
    }

    const response = await fetchWithFallback(apiUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => 'Unknown error');
      throw new Error(`API error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();
    let aiResponse = '';
    let groundingMetadata: any = {};

    if (useGemini) {
      // FIXED: Handle chunked/multi-part Gemini responses to fix truncation
      if (data.candidates && data.candidates.length > 0) {
        aiResponse = data.candidates
          .map(candidate =>
            candidate.content?.parts?.map(part => part.text).join('') || ''
          )
          .join('\n');

        groundingMetadata = data.candidates[0].groundingMetadata || {};

        if (aiResponse.trim()) {
          updateSteps(prev => [...prev, `✅ Found threat intelligence via Gemini web search`]);
        } else if (groundingMetadata.webSearchQueries) {
          updateSteps(prev => [...prev, `📊 Extracting from Gemini search metadata...`]);
          aiResponse = 'Threat intelligence search completed - extracting from metadata';
        } else {
          throw new Error('No usable text or metadata in Gemini response');
        }
      } else {
        throw new Error('No candidates in Gemini API response');
      }
    } else {
      // FIXED: Handle OpenAI /responses endpoint response format
      let text = '';
      
      // The /responses endpoint returns output as an array of objects
      if (Array.isArray(data.output)) {
        // Find the message object in the output array
        const messageObj = data.output.find(item => item.type === 'message' && item.content);
        
        if (messageObj && Array.isArray(messageObj.content)) {
          // Find the output_text object in the content array
          const textObj = messageObj.content.find(item => item.type === 'output_text' && item.text);
          
          if (textObj && textObj.text) {
            text = textObj.text;
            console.log('Found text in output array structure');
          }
        }
      } else if (typeof data.output === 'string') {
        text = data.output;
      } else if (typeof data.text === 'string') {
        text = data.text;
      } else if (data.output && typeof data.output === 'object') {
        text = data.output.text || data.output.content || data.output.message || '';
      } else if (data.text && typeof data.text === 'object') {
        text = data.text.content || data.text.text || '';
      }
      
      if (!text) {
        console.error('No output in response. Full response:', JSON.stringify(data, null, 2));
        console.error('Available fields:', Object.keys(data));
        console.error('data.output:', data.output);
        console.error('data.text:', data.text);
        throw new Error('No usable response from OpenAI /responses endpoint');
      }
      aiResponse = text;
      
      // Extract search metadata if available
      if (data.search_results || data.web_results) {
        groundingMetadata = {
          searchResults: data.search_results || data.web_results,
          webSearchQueries: data.search_queries || [],
          sources: data.sources || []
        };
      }
      
      updateSteps(prev => [...prev, `✅ Found threat intelligence via OpenAI web search`]);
    }

    // Parse threat intelligence more reliably
    const findings = parseTextResponseForThreatIntel(aiResponse, cveId, groundingMetadata);

    // Store in RAG if available
    if (ragDatabase?.initialized) {
      await ragDatabase.addDocument(
        `Threat Intelligence for ${cveId}: CISA KEV: ${findings.cisaKev?.listed ? 'LISTED' : 'Not Listed'}, Active Exploitation: ${findings.activeExploitation?.confirmed ? 'CONFIRMED' : 'None'}, Public Exploits: ${findings.exploitDiscovery?.totalCount || 0}`,
        {
          title: `AI Threat Intelligence - ${cveId}`,
          category: 'ai-threat-intelligence',
          tags: ['ai-search', 'threat-intel', cveId.toLowerCase()],
          source: useGemini ? 'gemini-web-search' : 'openai-web-search'
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
 * FIXED: Enhanced AI analysis with proper OpenAI /responses endpoint support
 */
export async function generateAIAnalysis(
  vulnerability: any, 
  apiKey: string, 
  model: string, 
  settings: any = {}, 
  ragDatabase: any, 
  fetchWithFallback: any, 
  buildEnhancedAnalysisPrompt: any, 
  generateEnhancedFallbackAnalysis: any
) {
  if (!apiKey && !settings.openAiApiKey) {
    throw new Error('Gemini or OpenAI API key required');
  }

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
    console.log(`📊 RAG Database Status: ${ragDatabase.documents.length} documents available`);
  }

  const cveId = vulnerability.cve.id;
  const ragQuery = `${cveId} ${vulnerability.cve.description.substring(0, 200)} vulnerability analysis security impact mitigation threat intelligence EPSS ${vulnerability.epss?.epss || 'N/A'} CVSS ${vulnerability.cve.cvssV3?.baseScore || 'N/A'}`;

  let relevantDocs = [];
  let ragContext = 'No specific security knowledge found in database.';

  if (ragDatabase && ragDatabase.initialized) {
    relevantDocs = await ragDatabase.search(ragQuery, 15);
    console.log(`📚 RAG Retrieved: ${relevantDocs.length} relevant documents`);

    if (relevantDocs.length > 0) {
      ragContext = relevantDocs.map((doc, index) =>
        `[Security Knowledge ${index + 1}] ${doc.metadata.title} (Relevance: ${(doc.similarity * 100).toFixed(1)}%):\n${doc.content.substring(0, 800)}...`
      ).join('\n\n');
    }
  }

  const prompt = buildEnhancedAnalysisPrompt(vulnerability, ragContext, relevantDocs.length);

  const geminiSearchCapable = useGemini && (model.includes('2.0') || model.includes('2.5'));
  const openAiSearchCapable = !useGemini && model === 'gpt-4.1';

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
    : openAiSearchCapable
      ? {
          // FIXED: OpenAI /responses endpoint format
          model: 'gpt-4.1', // MUST be gpt-4.1
          tools: [{"type": "web_search_preview"}], // Correct tool type
          input: prompt, // /responses uses 'input' not 'messages'
          // NO max_tokens for /responses
        }
      : {
          // Fallback to standard chat completions without web search
          model,
          messages: [{ 
            role: 'user', 
            content: prompt 
          }],
          max_tokens: 8192,
          temperature: 0.1
        };

  if (useGemini && geminiSearchCapable) {
    requestBody.tools = [{ google_search: {} }];
  }

  const apiUrl = useGemini
    ? `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${apiKey}`
    : openAiSearchCapable
      ? 'https://api.openai.com/v1/responses' // Use /responses for web search
      : 'https://api.openai.com/v1/chat/completions'; // Use chat completions as fallback
  
  console.log('🚨 generateAIAnalysis REQUEST DEBUG:');
  console.log('- apiUrl:', apiUrl);
  console.log('- openAiSearchCapable:', openAiSearchCapable);
  console.log('- useGemini:', useGemini);

  try {
    const headers: any = { 'Content-Type': 'application/json' };
    if (!useGemini) {
      console.log('🔧 DEBUG: Setting OpenAI auth header for AI analysis');
      headers['Authorization'] = `Bearer ${settings.openAiApiKey}`;
    }

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
    
    console.log('🔍 DEBUG: Full OpenAI response structure:', Object.keys(data));
    
    if (useGemini) {
      // FIXED: Handle chunked/multi-part Gemini responses to fix truncation
      if (data.candidates && data.candidates.length > 0) {
        analysisText = data.candidates
          .map(candidate =>
            candidate.content?.parts?.map(part => part.text).join('') || ''
          )
          .join('\n');

        if (!analysisText.trim()) {
          // Check for grounding metadata as a fallback
          if (data.candidates[0].groundingMetadata?.webSearchQueries) {
            analysisText = 'Analysis complete - extracted from metadata';
          } else {
            throw new Error('No usable text or metadata in Gemini response');
          }
        }
      } else {
        throw new Error('No candidates in Gemini API response');
      }
    } else {
      // FIXED: Handle OpenAI /responses endpoint response format
      if (openAiSearchCapable) {
        console.log('🔍 DEBUG: Checking /responses fields:');
        console.log('- data.output:', !!data.output);
        console.log('- data.output type:', typeof data.output);
        console.log('- Is data.output an array?:', Array.isArray(data.output));
        console.log('- Full response keys:', Object.keys(data));
        
        // Extract text from the output array structure
        if (Array.isArray(data.output)) {
          const messageObj = data.output.find(item => item.type === 'message' && item.content);
          
          if (messageObj && Array.isArray(messageObj.content)) {
            const textObj = messageObj.content.find(item => item.type === 'output_text' && item.text);
            
            if (textObj && textObj.text) {
              analysisText = textObj.text;
              console.log('🔍 Found text in output array structure');
            }
          }
        } else if (typeof data.output === 'string') {
          analysisText = data.output;
        } else if (typeof data.text === 'string') {
          analysisText = data.text;
        } else if (data.output && typeof data.output === 'object') {
          // If output is an object, try to extract text from it
          if (data.output.text) {
            analysisText = data.output.text;
          } else if (data.output.content) {
            analysisText = data.output.content;
          } else if (data.output.message) {
            analysisText = data.output.message;
          } else {
            console.error('❌ data.output is object:', data.output);
            analysisText = JSON.stringify(data.output);
          }
        } else if (data.text && typeof data.text === 'object') {
          // If text is an object, try to extract content from it
          if (data.text.content) {
            analysisText = data.text.content;
          } else if (data.text.text) {
            analysisText = data.text.text;
          } else {
            console.error('❌ data.text is object:', data.text);
            analysisText = JSON.stringify(data.text);
          }
        } else {
          analysisText = '';
        }
        
        console.log('🔍 DEBUG: Final analysisText type:', typeof analysisText);
        console.log('🔍 DEBUG: Final analysisText length:', analysisText?.length || 0);
        if (typeof analysisText === 'string' && analysisText.length > 0) {
          console.log('🔍 DEBUG: First 200 chars of analysisText:', analysisText.substring(0, 200));
        }
      } else {
        // Standard chat completions response format
        analysisText = data.choices?.[0]?.message?.content || '';
      }
      
      if (!analysisText) {
        console.error('❌ DEBUG: No text found in response');
        console.error('❌ DEBUG: Available fields:', Object.keys(data));
        throw new Error('Invalid response from OpenAI API - no text content found');
      }
    }

    if (analysisText.length > 500 && ragDatabase && ragDatabase.initialized) {
      await ragDatabase.addDocument(
        `Enhanced CVE Analysis: ${cveId}\n\n${analysisText}`,
        {
          title: `Enhanced Analysis - ${cveId}`,
          category: 'enhanced-analysis',
          tags: ['ai-analysis', 'validated', cveId.toLowerCase()],
          source: 'ai-analysis-rag',
          model: model,
          cveId: cveId
        }
      );
    }

    return {
      analysis: analysisText,
      ragUsed: true,
      ragDocuments: relevantDocs.length,
      ragSources: relevantDocs.map(doc => doc.metadata?.title || 'Unknown').filter(Boolean),
      webGrounded: useGemini ? geminiSearchCapable : openAiSearchCapable,
      model: model,
      analysisTimestamp: new Date().toISOString(),
      ragDatabaseSize: ragDatabase ? ragDatabase.documents.length : 0,
      webSearchUsed: (useGemini && geminiSearchCapable) || (!useGemini && openAiSearchCapable)
    };

  } catch (error) {
    console.error('Enhanced Analysis Error:', error);
    return generateEnhancedFallbackAnalysis(vulnerability, error);
  }
}

/**
 * FIXED: General answer with proper OpenAI /responses endpoint support
 */
export async function fetchGeneralAnswer(query: string, settings: any, fetchWithFallbackFn: any) {
  if (!settings.geminiApiKey && !settings.openAiApiKey) {
    throw new Error("Gemini or OpenAI API key required for AI responses");
  }
  
  const useGemini = !!settings.geminiApiKey;
  const model = useGemini ? (settings.geminiModel || "gemini-2.5-flash") : (settings.openAiModel || 'gpt-4o');
  const geminiSearchCapable = useGemini && (model.includes('2.0') || model.includes('2.5'));
  // Re-enable OpenAI web search
  const openAiSearchCapable = !useGemini && model === 'gpt-4.1';
  
  const requestBody = useGemini
    ? {
        contents: [{ parts: [{ text: query }] }],
        generationConfig: { 
          temperature: 0.3, 
          topK: 1, 
          topP: 0.8, 
          maxOutputTokens: 8192,
          candidateCount: 1 
        },
        tools: geminiSearchCapable ? [{ google_search: {} }] : undefined
      }
    : openAiSearchCapable
      ? {
          // FIXED: OpenAI /responses endpoint format
          model: "gpt-4.1", // MUST be "gpt-4.1"
          tools: [{"type": "web_search_preview"}], // Correct tool type
          input: query // 'input' not 'messages'
          // NO max_tokens for /responses
        }
      : {
          // Standard chat completions format
          model,
          messages: [{
            role: 'user',
            content: query
          }],
          max_tokens: 1024,
          temperature: 0.3,
          tools: [{ type: 'function', function: { name: 'web_search' } }]
        };

  const apiUrl = useGemini
    ? `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${settings.geminiApiKey}`
    : openAiSearchCapable
      ? 'https://api.openai.com/v1/responses'
      : 'https://api.openai.com/v1/chat/completions';

  const headers: any = { "Content-Type": "application/json" };
  if (!useGemini) {
    headers["Authorization"] = `Bearer ${settings.openAiApiKey}`;
  }

  const response = await fetchWithFallbackFn(apiUrl, {
    method: "POST",
    headers,
    body: JSON.stringify(requestBody)
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => 'Unknown error');
    throw new Error(`General AI query error: ${response.status} - ${errorText}`);
  }

  const data = await response.json();
  
  let text = '';
  if (useGemini) {
    // FIXED: Handle chunked/multi-part Gemini responses to fix truncation
    if (data.candidates && data.candidates.length > 0) {
      text = data.candidates
        .map(candidate =>
          candidate.content?.parts?.map(part => part.text).join('') || ''
        )
        .join('\n');
    }
  } else if (openAiSearchCapable) {
    // FIXED: /responses endpoint returns output as an array
    if (Array.isArray(data.output)) {
      const messageObj = data.output.find(item => item.type === 'message' && item.content);
      
      if (messageObj && Array.isArray(messageObj.content)) {
        const textObj = messageObj.content.find(item => item.type === 'output_text' && item.text);
        
        if (textObj && textObj.text) {
          text = textObj.text;
        }
      }
    } else if (typeof data.output === 'string') {
      text = data.output;
    } else if (typeof data.text === 'string') {
      text = data.text;
    } else if (data.output && typeof data.output === 'object') {
      text = data.output.text || data.output.content || data.output.message || '';
    } else if (data.text && typeof data.text === 'object') {
      text = data.text.content || data.text.text || '';
    }
  } else {
    text = data.choices?.[0]?.message?.content || '';
  }

  if (!text) {
    throw new Error("Invalid AI response");
  }

  return { answer: text };
}

/**
 * FIXED: AI Taint Analysis with proper OpenAI /responses endpoint support
 */
export async function generateAITaintAnalysis(
  vulnerability: any,
  apiKey: string,
  model: string,
  settings: any = {},
  fetchWithFallbackFn: any
) {
  if (!apiKey && !settings.openAiApiKey) {
    throw new Error('Gemini or OpenAI API key required');
  }

  const useGemini = !!apiKey;
  const geminiSearchCapable = useGemini && (model.includes('2.0') || model.includes('2.5'));
  // Re-enable OpenAI web search for taint analysis
  const openAiSearchCapable = !useGemini && model === 'gpt-4.1';

  const prompt = `Perform conceptual taint analysis for ${vulnerability?.cve?.id} based on the following description:\n${vulnerability?.cve?.description}\n\nIdentify potential sources, sinks, and sanitizers.`;

  const requestBody: any = useGemini
    ? {
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { 
          temperature: 0.1, 
          topK: 1, 
          topP: 0.8, 
          maxOutputTokens: 2048, 
          candidateCount: 1 
        },
        tools: geminiSearchCapable ? [{ google_search: {} }] : undefined
      }
    : openAiSearchCapable
      ? {
          // FIXED: OpenAI /responses endpoint format
          model: 'gpt-4.1', // MUST be gpt-4.1
          tools: [{"type": "web_search_preview"}], // Correct tool type
          input: prompt, // /responses uses 'input' not 'messages'
          // NO max_tokens for /responses
        }
      : {
          // Standard chat completions format (fallback)
          model: settings.openAiModel || 'gpt-4o',
          messages: [{ 
            role: 'user', 
            content: prompt 
          }],
          max_tokens: 2048,
          temperature: 0.1
        };

  const apiUrl = useGemini
    ? `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${apiKey}`
    : openAiSearchCapable
      ? 'https://api.openai.com/v1/responses' // Use /responses for web search
      : 'https://api.openai.com/v1/chat/completions'; // Use chat completions as fallback

  console.log('🔧 TAINT ANALYSIS DEBUG:');
  console.log('- useGemini:', useGemini);
  console.log('- openAiSearchCapable:', openAiSearchCapable);
  console.log('- apiUrl:', apiUrl);

  const headers: any = { 'Content-Type': 'application/json' };
  if (!useGemini) {
    console.log('🔧 DEBUG: Setting OpenAI auth header for taint analysis');
    headers['Authorization'] = `Bearer ${settings.openAiApiKey}`;
  }

  const response = await fetchWithFallbackFn(apiUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify(requestBody)
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => 'Unknown error');
    throw new Error(useGemini ? `Gemini API error: ${response.status} - ${errorText}` : `OpenAI API error: ${response.status} - ${errorText}`);
  }

  const data = await response.json();
  
  let responseText = '';
  
  if (useGemini) {
    // FIXED: Handle chunked/multi-part Gemini responses to fix truncation
    if (data.candidates && data.candidates.length > 0) {
      responseText = data.candidates
        .map(candidate =>
          candidate.content?.parts?.map(part => part.text).join('') || ''
        )
        .join('\n');
    }
  } else if (openAiSearchCapable) {
    // FIXED: /responses endpoint returns output as an array
    if (Array.isArray(data.output)) {
      const messageObj = data.output.find(item => item.type === 'message' && item.content);
      
      if (messageObj && Array.isArray(messageObj.content)) {
        const textObj = messageObj.content.find(item => item.type === 'output_text' && item.text);
        
        if (textObj && textObj.text) {
          responseText = textObj.text;
        }
      }
    } else if (typeof data.output === 'string') {
      responseText = data.output;
    } else if (typeof data.text === 'string') {
      responseText = data.text;
    } else if (data.output && typeof data.output === 'object') {
      responseText = data.output.text || data.output.content || data.output.message || '';
    } else if (data.text && typeof data.text === 'object') {
      responseText = data.text.content || data.text.text || '';
    }
  } else {
    // Handle standard chat completions response
    responseText = data.choices?.[0]?.message?.content || '';
  }

  if (!responseText) {
    throw new Error(useGemini ? 'Invalid response from Gemini API' : 'Invalid response from OpenAI API');
  }

  return { 
    analysis: responseText,
    webSearchUsed: (useGemini && geminiSearchCapable) || (!useGemini && openAiSearchCapable)
  };
}

// Keep the existing helper functions unchanged...
function parseTextResponseForPatches(response: string, cveId: string, groundingMetadata?: any): any {
  console.log('Parsing patch response for', cveId, '- Length:', response.length);
  
  const patches: any[] = [];
  const advisories: any[] = [];
  let confidence = 'LOW';

  const lowerResponse = response.toLowerCase();
  const patchKeywords = ['patch', 'update', 'fix', 'firmware', 'security update', 'hotfix'];
  const advisoryKeywords = ['advisory', 'bulletin', 'security notice', 'alert'];

  if (patchKeywords.some(k => lowerResponse.includes(k)) || advisoryKeywords.some(k => lowerResponse.includes(k))) {
    confidence = 'MEDIUM';
  }

  // Generic URL extraction from the main text body
  const urls = extractUrlsFromText(response);
  for (const url of urls) {
    const lowerUrl = url.toLowerCase();
    const vendor = extractVendorFromUrl(lowerUrl) || 'Unknown';

    if (patchKeywords.some(k => lowerUrl.includes(k))) {
      patches.push({
        vendor: vendor,
        product: 'Unknown',
        patchVersion: 'Latest',
        downloadUrl: url,
        advisoryUrl: url,
        description: `Security patch for ${cveId}`,
        confidence: 'MEDIUM',
        patchType: 'Security Update',
        citationUrl: url
      });
    } else if (advisoryKeywords.some(k => lowerUrl.includes(k))) {
      advisories.push({
        source: vendor,
        advisoryId: cveId,
        title: `Security advisory for ${cveId}`,
        url: url,
        severity: 'Unknown',
        description: `Security advisory related to ${cveId}`,
        confidence: 'MEDIUM',
        type: 'Security Advisory',
        citationUrl: url
      });
    }
  }

  // Handle grounding metadata from both Gemini and OpenAI
  if (groundingMetadata) {
    confidence = 'HIGH';
    let sources: any[] = [];

    // Gemini format
    if (groundingMetadata.groundingChunks) {
      const groundingInfo = extractFromGroundingMetadata(groundingMetadata);
      sources = groundingInfo.sources.map(s => ({
        url: s.url,
        title: s.title,
        snippet: s.queries?.join(' ') || ''
      }));
    }
    // OpenAI /responses format
    else if (groundingMetadata.searchResults || groundingMetadata.sources) {
      sources = (groundingMetadata.searchResults || groundingMetadata.sources || []).map((s: any) => ({
        url: s.url || s.link,
        title: s.title || s.snippet,
        snippet: s.snippet || ''
      }));
    }

    for (const source of sources) {
      if (!source.url) continue;
      
      const lowerUrl = source.url.toLowerCase();
      const vendor = extractVendorFromUrl(lowerUrl);
      const title = source.title || 'Security Information';

      const isPatch = patchKeywords.some(k => lowerUrl.includes(k) || title.toLowerCase().includes(k));
      const isAdvisory = advisoryKeywords.some(k => lowerUrl.includes(k) || title.toLowerCase().includes(k));

      if (isPatch) {
        patches.push({
          vendor: vendor,
          product: 'Unknown',
          patchVersion: 'Latest',
          downloadUrl: source.url,
          advisoryUrl: source.url,
          description: title,
          confidence: 'HIGH',
          patchType: 'Security Update',
          citationUrl: source.url
        });
      } else if (isAdvisory) {
        advisories.push({
          source: vendor,
          advisoryId: cveId,
          title: title,
          url: source.url,
          severity: 'Unknown',
          description: title,
          confidence: 'HIGH',
          type: 'Security Advisory',
          citationUrl: source.url
        });
      }
    }
  }

  return {
    patches: removeDuplicates(patches, 'downloadUrl'),
    advisories: removeDuplicates(advisories, 'url'),
    confidence: confidence,
    extractionMethod: 'text-and-metadata-parsing'
  };
}

function parseTextResponseForThreatIntel(response: string, cveId: string, groundingMetadata?: any): any {
  console.log('Parsing threat intel response for', cveId, '- Length:', response.length);
  
  const findings = {
    cisaKev: { listed: false, details: '', source: '', confidence: 'LOW', aiDiscovered: true },
    activeExploitation: { confirmed: false, details: '', sources: [], confidence: 'LOW', aiDiscovered: true },
    exploitDiscovery: { found: false, totalCount: 0, exploits: [], confidence: 'LOW', aiDiscovered: true },
    vendorAdvisories: { found: false, count: 0, advisories: [], confidence: 'LOW', aiDiscovered: true },
    intelligenceSummary: {
      sourcesAnalyzed: 0, exploitsFound: 0, vendorAdvisoriesFound: 0,
      activeExploitation: false, cisaKevListed: false, threatLevel: 'MEDIUM',
      dataFreshness: 'AI_SEARCH', analysisMethod: 'AI_WEB_SEARCH',
      confidenceLevel: 'MEDIUM', aiEnhanced: true, validated: false
    },
    summary: '', overallThreatLevel: 'MEDIUM',
    extractionMetadata: { extractionMethod: 'TEXT_PARSING', timestamp: new Date().toISOString() }
  };

  const lowerResponse = response.toLowerCase();
  
  // Check for CISA KEV
  if (lowerResponse.includes('cisa') && (lowerResponse.includes('kev') || lowerResponse.includes('known exploited'))) {
    if (lowerResponse.includes('listed') || lowerResponse.includes('included')) {
      findings.cisaKev.listed = true;
      findings.cisaKev.confidence = 'HIGH';
      findings.cisaKev.details = 'Found in CISA KEV catalog according to AI search';
      findings.intelligenceSummary.cisaKevListed = true;
    }
  }

  // Check for active exploitation
  if (lowerResponse.includes('active') && lowerResponse.includes('exploit')) {
    findings.activeExploitation.confirmed = true;
    findings.activeExploitation.confidence = 'MEDIUM';
    findings.activeExploitation.details = 'Active exploitation reported';
    findings.intelligenceSummary.activeExploitation = true;
  }

  // Check for exploit code
  if (lowerResponse.includes('exploit') || lowerResponse.includes('poc')) {
    findings.exploitDiscovery.found = true;
    findings.exploitDiscovery.totalCount = 1;
    findings.exploitDiscovery.confidence = 'MEDIUM';
    findings.intelligenceSummary.exploitsFound = 1;
  }

  // Calculate threat level
  if (findings.cisaKev.listed || findings.activeExploitation.confirmed) {
    findings.overallThreatLevel = 'HIGH';
    findings.intelligenceSummary.threatLevel = 'HIGH';
  } else if (findings.exploitDiscovery.found) {
    findings.overallThreatLevel = 'MEDIUM';
  } else {
    findings.overallThreatLevel = 'LOW';
    findings.intelligenceSummary.threatLevel = 'LOW';
  }

  findings.summary = createThreatIntelSummary(findings, cveId);
  return findings;
}

function createThreatIntelSummary(findings: any, cveId: string): string {
  const threats = [];
  
  if (findings.cisaKev.listed) threats.push('listed in CISA KEV catalog (actively exploited)');
  if (findings.activeExploitation.confirmed) threats.push('active exploitation reported');
  if (findings.exploitDiscovery.found) threats.push(`${findings.exploitDiscovery.totalCount} public exploit(s) found`);
  if (findings.vendorAdvisories.found) threats.push(`${findings.vendorAdvisories.count} vendor advisory(ies) found`);

  return threats.length === 0 
    ? `No immediate threat indicators found for ${cveId} via AI search.`
    : `${cveId} threat intelligence: ${threats.join(', ')}.`;
}

function extractVendorsFromText(text: string): string[] {
  const knownVendors = ['ASUS', 'Cisco', 'Microsoft', 'Oracle', 'Apache', 'Adobe', 'D-Link', 'TP-Link', 'Netgear', 'VMware', 'Fortinet', 'Juniper', 'Huawei', 'Sophos', 'Palo Alto', 'F5', 'Citrix', 'IBM', 'Google', 'Amazon', 'Mozilla', 'Red Hat', 'Ubuntu', 'Debian', 'SUSE'];
  return [...new Set(knownVendors.filter(vendor => text.toLowerCase().includes(vendor.toLowerCase())))];
}

function extractUrlsFromText(text: string): string[] {
  const urlRegex = /https?:\/\/[^\s<>"]{4,}/gi;
  const matches = text.match(urlRegex) || [];
  return [...new Set(matches)];
}

function extractVendorFromUrl(url: string): string {
  const vendorPatterns = {
    'microsoft.com': 'Microsoft', 'redhat.com': 'Red Hat', 'oracle.com': 'Oracle',
    'adobe.com': 'Adobe', 'cisco.com': 'Cisco', 'ubuntu.com': 'Ubuntu'
  };
  
  for (const [pattern, vendor] of Object.entries(vendorPatterns)) {
    if (url.includes(pattern)) return vendor;
  }
  
  try {
    return new URL(url).hostname.split('.')[0];
  } catch {
    return 'Unknown';
  }
}

function removeDuplicates(array: any[], property: string): any[] {
  const seen = new Set();
  return array.filter(item => {
    const value = item[property];
    if (seen.has(value)) return false;
    seen.add(value);
    return true;
  });
}

// Simple utility to parse JSON embedded in description-style responses
export function parseDescriptionBasedResponse(text: string, _cveId: string) {
  const match = text.match(/```json\n([\s\S]*?)\n```/i);
  let data: any = {};
  if (match) {
    try {
      data = JSON.parse(match[1]);
    } catch {
      data = {};
    }
  }
  return {
    patches: data.patches || [],
    advisories: data.advisories || [],
    searchSummary: { patchesFound: (data.patches || []).length }
  };
}
