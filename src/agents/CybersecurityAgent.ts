import { APIService } from '../services/APIService';
import { fetchCISAKEVData } from '../services/DataFetchingService';
import { RiskAssessmentAgent } from './RiskAssessmentAgent';
import {
  AgentSettings,
  ChatResponse,
  EPSSData,
  PatchData,
  RemediationStep,
  EnhancedVulnerabilityData,
  CVEValidationData,
  BaseCVEInfo,
  CisaKevDetails,
  ActiveExploitationData,
  ExploitDiscoveryData,
  AISummaryData,
  PatchInfo,
  AdvisoryInfo,
  BulkAnalysisResult
} from '../types/cveData';
import { generateRemediationPlan } from '../utils/remediation';
import { extractComponentNames } from '../utils/componentUtils';
import { CONSTANTS } from '../utils/constants';
import { CVE_REGEX } from '../utils/cveRegex';
import { ragDatabase } from '../db/EnhancedVectorDatabase';

// Utility to map CVSS score to severity label
export const getCVSSSeverity = (score: number): string => {
  if (score === 0) return 'NONE';
  if (score < 4.0) return 'LOW';
  if (score < 7.0) return 'MEDIUM';
  if (score < 9.0) return 'HIGH';
  return 'CRITICAL';
};

// ===== Types for AI grounding engine =====
export interface GroundedSearchResult {
  content: string;
  sources: string[];
  confidence: number;
}

export interface AIGroundingConfig {
  enableWebGrounding?: boolean;
  autoLearn?: boolean;
  crossValidate?: boolean;
  updateFrequency?: string;
  confidenceThreshold?: number;
  maxSearchDepth?: number;
}

// Simple grounding engine using Gemini and OpenAI
export class AIGroundingEngine {
  constructor(
    private config: AIGroundingConfig = {},
    private keys: { gemini?: string; openai?: string } = {}
  ) {}

  async search(query: string): Promise<GroundedSearchResult> {
    const result: GroundedSearchResult = { content: '', sources: [], confidence: 0 };

    if (!this.config.enableWebGrounding) {
      return result;
    }

    // Gemini search
    if (this.keys.gemini) {
      try {
        const res = await fetch(
          `/api/gemini?model=gemini-2.5-flash`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ parts: [{ text: query }] }],
              generationConfig: { temperature: 0.1, maxOutputTokens: 8192 }
            })
          }
        );
        if (res.ok) {
          const data = await res.json();
          const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
          result.content += text;
          result.confidence = Math.max(result.confidence, 0.6);
        }
      } catch (e) {
        console.error('Gemini grounding failed', e);
      }
    }

    // OpenAI search
    if (this.keys.openai) {
      try {
        const res = await fetch('/api/openai?endpoint=chat/completions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            model: 'gpt-4.1',
            messages: [{ role: 'user', content: query }],
            tools: [{ type: 'web_search_preview' }],
            max_tokens: 8192
          })
        });
        if (res.ok) {
          const data = await res.json();
          const text = data.choices?.[0]?.message?.content || '';
          result.content += `\n${text}`;
          result.confidence = Math.max(result.confidence, 0.8);
        }
      } catch (e) {
        console.error('OpenAI grounding failed', e);
      }
    }

    return result;
  }

  async learn(result: GroundedSearchResult): Promise<void> {
    if (!ragDatabase?.initialized || !result.content) {
      return;
    }
    try {
      await ragDatabase.addDocument(result.content, {
        title: 'Grounded Search Result',
        category: 'grounded-info',
        tags: ['grounding', 'auto-learn'],
        source: result.sources?.join(', ') || 'web-search'
      });
    } catch (e) {
      console.error('Grounding learn failed', e);
    }
  }
}

export class CybersecurityAgent {
  private settings: AgentSettings;
  private currentCveIdForSession: string | null = null;
  private cache: Map<string, { data: any; timestamp: number }> = new Map();
  private readonly DEFAULT_CACHE_TTL = 300000; // 5 minutes
  private cacheTTL: number;
  private groundingEngine?: AIGroundingEngine;
  private groundingConfig?: AIGroundingConfig;
  private bulkAnalysisResults: BulkAnalysisResult[] | null = null;

  constructor(settings?: AgentSettings) {
    this.settings = settings || {};
    this.cacheTTL = this.settings.cacheTTL ?? this.DEFAULT_CACHE_TTL;

    if (this.settings.aiProvider) {
      this.groundingConfig = { enableWebGrounding: true, autoLearn: true };
      this.groundingEngine = new AIGroundingEngine(this.groundingConfig, {});
    }
  }

  private isCybersecurityRelated(query: string): boolean {
    const keywords = [
      'cve',
      'vulnerability',
      'exploit',
      'patch',
      'malware',
      'cyber',
      'security',
      'kev',
      'epss',
      'threat'
    ];
    const lower = query.toLowerCase();
    return keywords.some(k => lower.includes(k));
  }

  public async handleQuery(query: string): Promise<ChatResponse> {
    try {
      // Extract CVE ID from query
      const cveMatches = Array.from(query.matchAll(CVE_REGEX));
      let operationalCveId: string | null = null;

      if (cveMatches.length > 0) {
        operationalCveId = cveMatches[0][0].toUpperCase();
        this.currentCveIdForSession = operationalCveId;
      }

      if (operationalCveId) {
        const res = await this.handleCVEQuery(query, operationalCveId);
        try {
          const verification = await this.verifyResponse(
            operationalCveId,
            res.text
          );
          res.data = { ...(res.data || {}), confidence: verification };
        } catch (e) {
          console.error('Verification failed', e);
        }
        return res;
      }

      if (this.groundingEngine && this.isCybersecurityRelated(query)) {
        const grounded = await this.getGroundedInfo(query);
        if (grounded.content) {
          return {
            text: grounded.content,
            sender: 'bot',
            id: Date.now().toString(),
            confidence: grounded.confidence,
          };
        }
      }

      let response = `I understand you're asking about cybersecurity. `;
      response += `To provide you with the most helpful information, could you please specify your question?`;

      return {
        text: response,
        sender: 'bot',
        id: Date.now().toString(),
      };
    } catch (error: any) {
      console.error('Error in handleQuery:', error);
      return {
        text: `I ran into an issue processing your request. Please try again in a moment or rephrase your question. If the problem persists, let our team know.`,
        sender: 'bot',
        id: Date.now().toString(),
        error: error.message
      };
    }
  }

  private async handleCVEQuery(query: string, cveId: string): Promise<ChatResponse> {
    try {
      // Future CVE warning
      const yearMatch = cveId.match(/CVE-(\d{4})-/);
      if (yearMatch) {
        const year = parseInt(yearMatch[1]);
        const currentYear = new Date().getFullYear();
        if (year > currentYear) {
          return {
            text: `⚠️ ${cveId} appears to reference a future year. Please verify the CVE ID.`,
            sender: 'bot',
            id: Date.now().toString(),
          };
        }
      }

      // All CVE queries now go through the comprehensive report generator
      return await this.generateComprehensiveCVEReport(query, cveId);

    } catch (error: any) {
      console.error('CVE Query Error:', error);
      return {
        text: `I had trouble analyzing ${cveId}. Here are a few direct links that might help while I investigate:\n\n🔗 **Direct Links:**\n• [NVD Entry](https://nvd.nist.gov/vuln/detail/${cveId})\n• [MITRE Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId})\n• [ExploitDB Search](https://www.exploit-db.com/search?cve=${cveId})`,
        sender: 'bot',
        id: Date.now().toString(),
        error: error.message
      };
    }
  }

  private async getGroundedInfo(query: string): Promise<GroundedSearchResult> {
    if (!this.groundingEngine) {
      return { content: '', sources: [], confidence: 0 };
    }
    const result = await this.groundingEngine.search(query);
    if (this.groundingConfig?.autoLearn) {
      await this.groundingEngine.learn(result);
    }
    return result;
  }

  private async generateNaturalLanguageReport(
    query: string,
    cveId: string,
    context: {
      cveData: any;
      epssData: any;
      webIntel: any;
      errors: string[];
    }
  ): Promise<string> {
    const { cveData, epssData, webIntel, errors } = context;

    const prompt = `
      You are a helpful, expert cybersecurity analyst. Your user has asked the following query: "${query}".
      Analyze the user's query and the provided data to give a comprehensive, yet easy-to-understand, natural language response.
      Do not just list the data. Synthesize it into a coherent answer. Use Markdown for formatting if it helps clarity (e.g., bolding, lists).

      Here is the data I have gathered for ${cveId}:

      **NVD Data:**
      ${cveData ? JSON.stringify(cveData, null, 2) : 'Not available.'}

      **EPSS (Exploit Prediction Scoring System) Data:**
      ${epssData ? JSON.stringify(epssData, null, 2) : 'Not available.'}

      **Live Web Intelligence & Analysis:**
      ${webIntel?.summary ? webIntel.summary : 'Not available.'}

      **Data Fetching Errors:**
      ${errors.length > 0 ? errors.join(', ') : 'None'}

      Based on all of this information, please provide a response to the user's query: "${query}".
      If the user is asking a general question, provide a summary. If they are asking a specific question (e.g., about patches or exploits), focus on that.
      If data is missing, mention it, but try to provide a useful answer with the information you do have.
      Conclude your response with a clear, actionable summary or recommendation.
    `;

    // Re-use the performWebSearch logic to call the LLM
    const result = await this.performWebSearch(prompt);
    return result.summary || 'I was unable to generate a response based on the available information.';
  }

  private async generateComprehensiveCVEReport(query: string, cveId: string): Promise<ChatResponse> {
    try {
      const errors: string[] = [];
      const [cveData, epssData, webIntel] = await Promise.all([
        this.getCachedOrFetch(`cve_${cveId}`, () => APIService.fetchCVEData(cveId, this.settings?.nvdApiKey, () => {})).catch(err => {
          console.log('CVE data fetch failed:', err);
          errors.push('Official CVE data unavailable');
          return null;
        }),
        this.getCachedOrFetch(`epss_${cveId}`, () => APIService.fetchEPSSData(cveId, () => {})).catch(err => {
          console.log('EPSS data fetch failed:', err);
          errors.push('EPSS score unavailable');
          return null;
        }),
        this.performWebSearch(`${cveId} vulnerability analysis patches advisories exploits`).catch(err => {
          console.log('Web intelligence failed:', err);
          errors.push('Web intelligence limited');
          return null;
        })
      ]);

      const reportText = await this.generateNaturalLanguageReport(query, cveId, {
        cveData,
        epssData,
        webIntel,
        errors,
      });

      return {
        text: reportText,
        sender: 'bot',
        id: Date.now().toString(),
      };

    } catch (error: any) {
      console.error('CVE Report Error:', error);
      return {
        text: `**${cveId} Analysis**\n\nI encountered some technical issues during comprehensive analysis, but here's what I can provide:\n\n🔍 **${cveId}** is a vulnerability that requires analysis.\n\n🔗 **Quick Links:**\n• [NVD Entry](https://nvd.nist.gov/vuln/detail/${cveId})\n• [MITRE Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId})\n• [ExploitDB Search](https://www.exploit-db.com/search?cve=${cveId})\n\n💡 **Recommendation:**\n• Check the official NVD entry for detailed information\n• Verify if your systems are affected\n• Look for vendor security advisories\n\nWould you like me to focus on a specific aspect using available data?`,
        sender: 'bot',
        id: Date.now().toString(),
        error: error.message
      };
    }
  }

  private async performWebSearch(query: string): Promise<any> {
    try {
      if (!this.settings.openAiApiKey && !this.settings.geminiApiKey) {
        return { summary: 'Web search unavailable: no AI key configured' };
      }

      // The `query` is now the full prompt for the LLM
      const searchPrompt = query;
      let generatedText = '';

      // Prefer OpenAI if available, as it might handle complex prompts better
      if (this.settings.openAiApiKey) {
        try {
          const openaiRes = await fetch('/api/openai?endpoint=chat/completions', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              model: 'gpt-4.1', // Using a powerful model for synthesis
              messages: [{ role: 'user', content: searchPrompt }],
              max_tokens: 4096,
              temperature: 0.2, // Lower temperature for more factual responses
            })
          });
          if (openaiRes.ok) {
            const openData = await openaiRes.json();
            generatedText = openData.choices?.[0]?.message?.content || '';
          }
        } catch (e) {
          console.error('OpenAI web search failed', e);
        }
      }

      // Fallback to Gemini
      if (!generatedText && this.settings.geminiApiKey) {
        const response = await fetch(`/api/gemini?model=gemini-2.5-flash`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [{ text: searchPrompt }] }],
            generationConfig: {
              temperature: 0.2,
              maxOutputTokens: 4096,
            }
          })
        });

        if (response.ok) {
          const data = await response.json();
          generatedText = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
        } else {
          console.error('Gemini web search failed', response.status);
        }
      }

      return {
        summary: generatedText
      };

    } catch (error) {
      console.error('Web search failed:', error);
      return { summary: `Web search failed: ${error.message}` };
    }
  }

  private async getCachedOrFetch<T>(
    key: string,
    fetcher: () => Promise<T>,
    ttl: number = this.cacheTTL
  ): Promise<T> {
    const cached = this.cache.get(key);
    if (cached && Date.now() - cached.timestamp < ttl) {
      return cached.data;
    }

    const data = await fetcher();
    this.cache.set(key, { data, timestamp: Date.now() });
    return data;
  }

  private async verifyResponse(
    cveId: string,
    responseText: string
  ): Promise<{ overall: number; flags: string[] }> {
    const flags: string[] = [];
    let confidence = 1;
    try {
      const [nvdData, kev] = await Promise.all([
        APIService.fetchCVEData(cveId, this.settings?.nvdApiKey, () => {}),
        fetchCISAKEVData(cveId, () => {}, ragDatabase, null, this.settings),
      ]);

      if (!nvdData) {
        flags.push('NO_NVD_DATA');
        confidence -= 0.3;
      }

      if (/cisa kev|actively exploited/i.test(responseText)) {
        if (!kev?.listed) {
          flags.push('CLAIMED_ACTIVE_NOT_IN_KEV');
          confidence -= 0.3;
        }
      }
    } catch (err) {
      flags.push('VERIFICATION_FAILED');
      confidence -= 0.2;
    }

    confidence = Math.max(0, Math.min(1, confidence));
    return { overall: parseFloat(confidence.toFixed(2)), flags };
  }

  public setBulkAnalysisResults(results: BulkAnalysisResult[]): void {
    this.bulkAnalysisResults = results;
  }

  public setContextualCVE(cveId: string): ChatResponse | null {
    if (cveId && CVE_REGEX.test(cveId) && cveId !== this.currentCveIdForSession) {
      this.currentCveIdForSession = cveId.toUpperCase();

      const text = `Perfect! I'm now focused on ${this.currentCveIdForSession}. What would you like to know about it?`;
      return {
        text,
        sender: 'system',
        id: Date.now().toString(),
      };
    }
    return null;
  }
}
