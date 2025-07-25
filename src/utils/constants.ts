
// constants.ts - CORRECTED VERSION with OpenAI Responses API
export const CONSTANTS = {
  API_ENDPOINTS: {
    NVD: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    EPSS: 'https://api.first.org/data/v1/epss',
    GEMINI: 'https://generativelanguage.googleapis.com/v1beta/models',
    OPENAI: 'https://api.openai.com/v1',
    
    // OpenAI has two different endpoints:
    OPENAI_CHAT: 'https://api.openai.com/v1/chat/completions',  // Standard chat
    OPENAI_RESPONSES: 'https://api.openai.com/v1/responses'     // Web search capable (gpt-4.1 only)
  },
  RATE_LIMITS: {
    GEMINI_COOLDOWN: 60000, // 1 minute
    MAX_RETRIES: 3
  },
  CVSS_THRESHOLDS: {
    CRITICAL: 9.0,
    HIGH: 7.0,
    MEDIUM: 4.0,
    LOW: 0.1
  },
  EPSS_THRESHOLDS: {
    HIGH: 0.5,
    MEDIUM: 0.1
  }
};

export const COLORS = {
  blue: '#3b82f6',
  purple: '#8b5cf6',
  green: '#22c55e',
  red: '#ef4444',
  yellow: '#f59e0b',
  dark: {
    background: '#0f172a',
    surface: '#1e293b',
    primaryText: '#f1f5f9',
    secondaryText: '#94a3b8',
    tertiaryText: '#64748b',
    border: '#334155',
    shadow: 'rgba(0, 0, 0, 0.2)'
  },
  light: {
    background: '#f8fafc',
    surface: '#ffffff',
    primaryText: '#0f172a',
    secondaryText: '#64748b',
    tertiaryText: '#94a3b8',
    border: '#e2e8f0',
    shadow: 'rgba(0, 0, 0, 0.07)'
  }
};

// Updated AIEnhancementService functions to properly use OpenAI Responses API

/**
 * CORRECTED: OpenAI does have a /responses endpoint for web search with gpt-4.1
 */
export async function fetchWithOpenAIResponses(
  prompt: string,
  settings: any,
  fetchWithFallback: any,
  forceWebSearch: boolean = false
) {
  const model = 'gpt-4.1'; // Only gpt-4.1 supports the responses API
  
  const requestBody = {
    model: model,
    tools: [{ type: 'web_search_preview' }],
    input: prompt
  };
  
  // Optionally force web search
  if (forceWebSearch) {
    requestBody['tool_choice'] = { type: 'web_search_preview' };
  }

  const apiUrl = CONSTANTS.API_ENDPOINTS.OPENAI_RESPONSES;

  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${settings.openAiApiKey}`
  };

  console.log('📡 Using OpenAI Responses API with web search');
  console.log('🔍 Model:', model);
  console.log('🌐 Web search:', forceWebSearch ? 'forced' : 'optional');

  try {
    const response = await fetchWithFallback(apiUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('OpenAI Responses API error:', errorText);
      throw new Error(`OpenAI Responses API error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();
    
    // The responses API returns a different format than chat completions
    // Based on OpenAI docs, it should return the response directly
    let content = '';
    
    if (data.output) {
      content = data.output;
    } else if (data.response) {
      content = data.response;
    } else if (data.text) {
      content = data.text;
    } else {
      console.warn('Unexpected response format from OpenAI Responses API:', data);
      content = JSON.stringify(data);
    }

    return {
      answer: content,
      webSearchUsed: true,
      model: model,
      sources: data.sources || data.references || []
    };
    
  } catch (error) {
    console.error('OpenAI Responses API error:', error);
    throw error;
  }
}

/**
 * Updated function to check if OpenAI web search is available
 */
export function checkOpenAIWebSearchCapability(model: string): boolean {
  // Only gpt-4.1 supports the Responses API with web search
  return model === 'gpt-4.1';
}

/**
 * Updated generateAIAnalysis to properly use OpenAI Responses API
 */
export async function generateAIAnalysisFixed(
  vulnerability: any, 
  apiKey: string, 
  model: string, 
  settings: any = {}, 
  ragDatabase: any, 
  fetchWithFallback: any, 
  buildEnhancedAnalysisPrompt: any, 
  generateEnhancedFallbackAnalysis: any
) {
  const useGemini = !!apiKey;
  
  // Check if we can use web search
  const geminiSearchCapable = useGemini && (model.includes('2.0') || model.includes('2.5'));
  const openAiSearchCapable = !useGemini && checkOpenAIWebSearchCapability(model);
  
  console.log('🔧 AI Analysis Configuration:', {
    useGemini,
    model,
    geminiSearchCapable,
    openAiSearchCapable,
    endpoint: useGemini ? 'Gemini' : (openAiSearchCapable ? 'OpenAI Responses' : 'OpenAI Chat')
  });
  
  // Build the analysis prompt
  const prompt = buildEnhancedAnalysisPrompt(vulnerability, '', 0);
  
  let requestBody: any;
  let apiUrl: string;
  
  if (useGemini) {
    // Gemini configuration with google_search tool
    requestBody = {
      contents: [{
        parts: [{
          text: prompt
        }]
      }],
      generationConfig: {
        temperature: 0.1,
        topK: 1,
        topP: 0.8,
        maxOutputTokens: 8192,
        candidateCount: 1
      }
    };
    
    // Add search tool for supported models
    if (geminiSearchCapable) {
      requestBody.tools = [{ google_search: {} }];
    }
    
    apiUrl = `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${apiKey}`;
  } else if (openAiSearchCapable) {
    // OpenAI Responses API with web search
    requestBody = {
      model: 'gpt-4.1',
      tools: [{ type: 'web_search_preview' }],
      input: prompt,
      // Optionally force web search for CVE analysis
      tool_choice: { type: 'web_search_preview' }
    };
    
    apiUrl = CONSTANTS.API_ENDPOINTS.OPENAI_RESPONSES;
  } else {
    // Standard OpenAI chat completions (no web search)
    requestBody = {
      model: settings.openAiModel || 'gpt-4.1',
      messages: [{ 
        role: 'user', 
        content: prompt 
      }],
      max_tokens: 8192,
      temperature: 0.1
    };
    
    apiUrl = CONSTANTS.API_ENDPOINTS.OPENAI_CHAT;
  }
  
  try {
    const headers: any = { 'Content-Type': 'application/json' };
    if (!useGemini) {
      headers['Authorization'] = `Bearer ${settings.openAiApiKey}`;
    }

    const response = await fetchWithFallback(apiUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('API Error:', errorText);
      throw new Error(`API error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();
    
    let analysisText = '';
    let sources = [];
    
    if (useGemini) {
      analysisText = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    } else if (openAiSearchCapable) {
      // Handle OpenAI Responses API format
      if (data.output) {
        analysisText = data.output;
      } else if (data.response) {
        analysisText = data.response;
      } else if (data.text) {
        analysisText = data.text;
      }
      sources = data.sources || data.references || [];
    } else {
      // Standard chat completions format
      analysisText = data.choices?.[0]?.message?.content || '';
    }
    
    if (!analysisText) {
      throw new Error('No analysis text in response');
    }

    return {
      analysis: analysisText,
      ragUsed: false,
      ragDocuments: 0,
      ragSources: [],
      webGrounded: useGemini ? geminiSearchCapable : openAiSearchCapable,
      model: model,
      analysisTimestamp: new Date().toISOString(),
      ragDatabaseSize: 0,
      webSearchUsed: useGemini ? geminiSearchCapable : openAiSearchCapable,
      webSearchSources: sources
    };

  } catch (error) {
    console.error('AI Analysis Error:', error);
    return generateEnhancedFallbackAnalysis(vulnerability, error);
  }
}

/**
 * Updated patch discovery to use OpenAI Responses API when available
 */
export async function fetchPatchesWithWebSearch(
  cveId: string,
  cveData: any,
  settings: any,
  setLoadingSteps: any,
  fetchWithFallback: any
) {
  const useGemini = !settings.openAiApiKey && !!settings.geminiApiKey;
  const model = useGemini ? (settings.geminiModel || 'gemini-2.5-flash') : (settings.openAiModel || 'gpt-4');
  
  // Check web search capability
  const geminiSearchCapable = useGemini && (model.includes('2.0') || model.includes('2.5'));
  const openAiSearchCapable = !useGemini && model === 'gpt-4.1';
  
  if (!geminiSearchCapable && !openAiSearchCapable) {
    console.log('⚠️ Web search not available with current model');
    return { patches: [], advisories: [] };
  }
  
  const searchPrompt = `Search for security patches and advisories for ${cveId}.

CVE Description: "${cveData?.description || 'No description'}"

Search for:
1. Official vendor security patches for ${cveId}
2. Security advisories mentioning ${cveId}
3. Firmware updates that fix ${cveId}
4. Software updates addressing ${cveId}

Focus on official vendor sources and security advisory sites.`;

  try {
    let result;
    
    if (useGemini) {
      // Use Gemini with google_search
      const requestBody = {
        contents: [{ parts: [{ text: searchPrompt }] }],
        generationConfig: {
          temperature: 0.1,
          topK: 40,
          topP: 0.95,
          maxOutputTokens: 4096
        },
        tools: [{ google_search: {} }]
      };
      
      const response = await fetchWithFallback(
        `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${settings.geminiApiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(requestBody)
        }
      );
      
      const data = await response.json();
      result = {
        answer: data.candidates?.[0]?.content?.parts?.[0]?.text || '',
        groundingMetadata: data.candidates?.[0]?.groundingMetadata
      };
    } else {
      // Use OpenAI Responses API with web search
      result = await fetchWithOpenAIResponses(
        searchPrompt,
        settings,
        fetchWithFallback,
        true // Force web search for patch discovery
      );
    }
    
    // Parse the results
    return parsePatchAndAdvisoryResponse(result.answer, cveId);
    
  } catch (error) {
    console.error('Patch search error:', error);
    return { patches: [], advisories: [] };
  }
}
