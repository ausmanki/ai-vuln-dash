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
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${this.keys.gemini}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ parts: [{ text: query }] }],
              generationConfig: { temperature: 0.1, maxOutputTokens: 4096 }
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
        const res = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${this.keys.openai}`
          },
          body: JSON.stringify({
            model: 'gpt-4o',
            messages: [{ role: 'user', content: query }],
            max_tokens: 4096
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

  async learn(_result: GroundedSearchResult): Promise<void> {
    // Placeholder for automatic learning storage
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

  constructor(settings?: AgentSettings) {
    this.settings = settings || {};
    this.cacheTTL = this.settings.cacheTTL ?? this.DEFAULT_CACHE_TTL;

    if (this.settings.openAiApiKey || this.settings.geminiApiKey) {
      this.groundingConfig = { enableWebGrounding: true };
      this.groundingEngine = new AIGroundingEngine(this.groundingConfig, {
        gemini: this.settings.geminiApiKey,
        openai: this.settings.openAiApiKey,
      });
    }
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
        return this.handleCVEQuery(query, operationalCveId);
      }

      if (this.groundingEngine) {
        const grounded = await this.groundingEngine.search(query);
        if (grounded.content) {
          return { text: grounded.content, sender: 'bot', id: Date.now().toString(), confidence: grounded.confidence };
        }
      }

      if (this.settings.openAiApiKey) {
        const model = this.settings.openAiModel || 'gpt-4o';
        const res = await fetch(`${CONSTANTS.API_ENDPOINTS.OPENAI_RESPONSES}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.settings.openAiApiKey}`
          },
          body: JSON.stringify({
            model,
            messages: [{ role: 'user', content: query }],
            tools: [{ type: 'function', function: { name: 'web_search' } }]
          })
        });
        if (!res.ok) {
          throw new Error(`OpenAI error: ${res.status}`);
        }
        const data = await res.json();
        const text = data.choices?.[0]?.message?.content || 'No response';
        return { text, sender: 'bot', id: Date.now().toString() };
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
      const lowerQuery = query.toLowerCase();

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

      // Use grounded info for specific intents
      if (this.groundingEngine && (lowerQuery.includes('exploit') || lowerQuery.includes('patch') || lowerQuery.includes('validate') || lowerQuery.includes('risk'))) {
        const grounded = await this.getGroundedInfo(`${cveId} ${query}`);
        if (grounded.content && grounded.confidence >= (this.groundingConfig?.confidenceThreshold ?? 0)) {
          return { text: grounded.content, sender: 'bot', id: Date.now().toString(), confidence: grounded.confidence };
        }
      }

      // Determine intent based on keywords
      if (lowerQuery.includes('validate') || lowerQuery.includes('verify') || lowerQuery.includes('legitimate')) {
        return await this.getValidationInfo(cveId);
      } else if (lowerQuery.includes('epss') || lowerQuery.includes('exploit') && lowerQuery.includes('score')) {
        return await this.getEPSSScore(cveId);
      } else if (lowerQuery.includes('patch') || lowerQuery.includes('fix') || lowerQuery.includes('update')) {
        return await this.getPatchAndAdvisoryInfo(cveId);
      } else if (lowerQuery.includes('exploit') || lowerQuery.includes('poc')) {
        return await this.getExploitInfo(cveId);
      } else if (lowerQuery.includes('risk') || lowerQuery.includes('assessment')) {
        return await this.getRiskAssessment(cveId);
      } else {
        // Default comprehensive report
        return await this.generateComprehensiveCVEReport(cveId);
      }

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
    return result;
  }

  private async getValidationInfo(cveId: string): Promise<ChatResponse> {
    return this.generateComprehensiveCVEReport(cveId);
  }

  private async getEPSSScore(cveId: string): Promise<ChatResponse> {
    return this.generateComprehensiveCVEReport(cveId);
  }

  private async getPatchAndAdvisoryInfo(cveId: string): Promise<ChatResponse> {
    return this.generateComprehensiveCVEReport(cveId);
  }

  private async getExploitInfo(cveId: string): Promise<ChatResponse> {
    return this.generateComprehensiveCVEReport(cveId);
  }

  private async getRiskAssessment(cveId: string): Promise<ChatResponse> {
    return this.generateComprehensiveCVEReport(cveId);
  }

  private async generateComprehensiveCVEReport(cveId: string): Promise<ChatResponse> {
    try {
      let cveData = null;
      let epssData = null;
      let webIntel = null;
      const errors: string[] = [];

      try {
        cveData = await this.getCachedOrFetch(
          `cve_${cveId}`,
          () => APIService.fetchCVEData(cveId, this.settings?.nvdApiKey, () => {})
        );
      } catch (error) {
        console.log('CVE data fetch failed:', error);
        errors.push('Official CVE data unavailable');
      }

      try {
        epssData = await this.getCachedOrFetch(
          `epss_${cveId}`,
          () => APIService.fetchEPSSData(cveId, () => {})
        );
      } catch (error) {
        console.log('EPSS data fetch failed:', error);
        errors.push('EPSS score unavailable');
      }

      try {
        webIntel = await this.performWebSearch(
          `${cveId} vulnerability analysis patches advisories exploits`
        );
      } catch (error) {
        console.log('Web intelligence failed:', error);
        errors.push('Web intelligence limited');
      }

      let report = `**${cveId} Comprehensive Analysis**\n\n`;

      if (errors.length > 0) {
        report += `⚠️ **Analysis Limitations**: ${errors.join(', ')}\n\n`;
      }

      if (cveData?.description) {
        report += `🔍 **Key Finding:** ${cveData.description}\n\n`;
      }

      if (cveData?.cvssV3) {
        report += `📊 **Technical Details:**\n`;
        report += `• **CVSS v3 Score:** ${cveData.cvssV3.baseScore}/10 (${getCVSSSeverity(cveData.cvssV3.baseScore)})\n`;
      }

      if (epssData?.epss) {
        report += `• **EPSS Score:** ${epssData.epss} (${epssData.epssPercentage}%)\n`;
      }

      report += `\n🔗 **Official Sources:**\n`;
      report += `• [NVD Entry](https://nvd.nist.gov/vuln/detail/${cveId})\n`;
      report += `• [MITRE CVE Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId})\n`;

      if (webIntel?.summary) {
        report += `\n**Web Intelligence Summary:**\n${webIntel.summary.substring(0, 400)}...\n\n`;
      }

      return {
        text: report,
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
      if (!this.settings.geminiApiKey) {
        return { summary: 'Web search unavailable: Gemini API key not configured' };
      }

      const searchPrompt = `Search for information about: ${query}. Provide a comprehensive analysis including current threat status, patches, advisories, and any dispute information.`;

      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${this.settings.geminiApiKey}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          contents: [{
            parts: [{
              text: searchPrompt
            }]
          }],
          generationConfig: {
            temperature: 0.1,
            maxOutputTokens: 4096,
          }
        })
      });

      if (!response.ok) {
        throw new Error(`Gemini API error: ${response.status}`);
      }

      const data = await response.json();
      let generatedText = data.candidates?.[0]?.content?.parts?.[0]?.text || '';

      if (this.settings.openAiApiKey) {
        try {
          const openaiRes = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${this.settings.openAiApiKey}`
            },
            body: JSON.stringify({
              model: 'gpt-4o',
              messages: [{ role: 'user', content: query }],
              max_tokens: 4096
            })
          });
          if (openaiRes.ok) {
            const openData = await openaiRes.json();
            const openText = openData.choices?.[0]?.message?.content || '';
            generatedText += `\n${openText}`;
          }
        } catch (e) {
          console.error('OpenAI web search failed', e);
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
}
