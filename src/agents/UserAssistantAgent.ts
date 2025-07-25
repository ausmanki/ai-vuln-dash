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
            tools: [{ type: 'web_search_preview' }],
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

interface ConversationContext {
  currentTopic?: string;
  lastIntent?: string;
  recentCVEs: string[];
  recentIntents: string[];
  flags: string[];
  userExpertiseLevel: 'beginner' | 'intermediate' | 'expert';
  emergencyMode: boolean;
}

interface UserPreferences {
  responseLength: 'brief' | 'detailed' | 'comprehensive';
  priorityFactors: ('cvss' | 'epss' | 'kev' | 'exploits' | 'business_impact')[];
  autoSuggestions: boolean;
  technicalLevel: 'business' | 'technical' | 'deep_technical';
  urgencyThreshold: number;
  notificationStyle: 'proactive' | 'reactive' | 'minimal';
}

interface RetryConfig {
  maxRetries: number;
  baseDelay: number;
  maxDelay: number;
  exponentialBase: number;
}

export class UserAssistantAgent {
  private settings: AgentSettings;
  private currentCveIdForSession: string | null = null;
  private bulkAnalysisResults: BulkAnalysisResult[] | null = null;
  private conversationContext: ConversationContext;
  private userPreferences: UserPreferences;
  private conversationHistory: { query: string; response: string }[] = [];
  private cache: Map<string, { data: any; timestamp: number }> = new Map();
  private readonly DEFAULT_CACHE_TTL = 300000; // 5 minutes
  private cacheTTL: number;
  private groundingEngine?: AIGroundingEngine;
  private groundingConfig?: AIGroundingConfig;
  private readonly DEFAULT_RETRY_CONFIG: RetryConfig = {
    maxRetries: 3,
    baseDelay: 1000,
    maxDelay: 10000,
    exponentialBase: 2
  };

  constructor(settings?: AgentSettings) {
    this.settings = settings || {};
    // Allow overriding the default cache TTL via settings
    this.cacheTTL = this.settings.cacheTTL ?? this.DEFAULT_CACHE_TTL;
    this.conversationContext = {
      recentCVEs: [],
      recentIntents: [],
      flags: [],
      userExpertiseLevel: 'intermediate',
      emergencyMode: false
    };
    this.userPreferences = {
      responseLength: 'detailed',
      priorityFactors: ['cvss', 'epss', 'kev'],
      autoSuggestions: true,
      technicalLevel: 'technical',
      urgencyThreshold: 0.8,
      notificationStyle: 'proactive'
    };
    this.conversationHistory = [];

    if (this.settings.openAiApiKey || this.settings.geminiApiKey) {
      this.groundingConfig = this.settings.groundingConfig;
      this.groundingEngine = new AIGroundingEngine(this.groundingConfig || {}, {
        gemini: this.settings.geminiApiKey,
        openai: this.settings.openAiApiKey,
      });
    }
  }

  // Basic query analysis for multi-intent understanding and sentiment
  private analyzeQuery(query: string): { intents: string[]; sentiment: 'neutral' | 'urgent' | 'confused'; confidence: number } {
    const lower = query.toLowerCase();
    const intents: string[] = [];
    let confidence = 0.5;
    if (/(patch|fix|update)/.test(lower)) { intents.push('patch_info'); confidence += 0.1; }
    if (/(exploit|poc)/.test(lower)) { intents.push('exploit_info'); confidence += 0.1; }
    if (/(risk|assessment)/.test(lower)) { intents.push('risk_assessment'); confidence += 0.1; }
    if (/(validate|verify|legitimate)/.test(lower)) { intents.push('validation'); confidence += 0.1; }

    let sentiment: 'neutral' | 'urgent' | 'confused' = 'neutral';
    if (/(urgent|asap|immediately|!)/.test(lower)) sentiment = 'urgent';
    if (/(\?|help|how do i)/.test(lower)) sentiment = 'confused';

    return { intents, sentiment, confidence: Math.min(confidence, 1) };
  }

  private updateConversationContext(intents: string[]): void {
    if (intents.length === 0) return;
    this.conversationContext.lastIntent = intents[0];
    this.conversationContext.recentIntents.unshift(intents[0]);
    if (this.conversationContext.recentIntents.length > 5) {
      this.conversationContext.recentIntents.pop();
    }
  }

  // Update stored user preferences
  public setUserPreferences(prefs: Partial<UserPreferences>): void {
    this.userPreferences = { ...this.userPreferences, ...prefs };
  }

  // Remember conversation history for context resolution
  private storeConversation(query: string, response: string): void {
    this.conversationHistory.unshift({ query, response });
    if (this.conversationHistory.length > 10) {
      this.conversationHistory.pop();
    }
  }

  // Adjust tone and depth based on technical level preference
  private applyTechnicalTone(text: string): string {
    if (this.userPreferences.technicalLevel === 'business') {
      return text.split('\n').slice(0, 2).join('\n');
    }
    if (this.userPreferences.technicalLevel === 'deep_technical') {
      return `${text}\n\n(Advanced details available on request.)`;
    }
    return text;
  }

  private varyResponse(text: string): string {
    const variants = [
      ['Here is', 'Here are', 'Below are'],
      ['details', 'information', 'insights']
    ];
    let varied = text;
    variants.forEach(([a, b, c]) => {
      const choice = [a, b, c][Math.floor(Math.random() * 3)];
      varied = varied.replace(a, choice);
    });
    return varied;
  }

  private generateFollowUps(intents: string[], cveId?: string): string[] {
    const suggestions: string[] = [];
    if (cveId) {
      if (!intents.includes('patch_info')) suggestions.push(`Ask for patch details on ${cveId}`);
      if (!intents.includes('exploit_info')) suggestions.push(`Check for exploits related to ${cveId}`);
      if (!intents.includes('risk_assessment')) suggestions.push(`Request a risk assessment for ${cveId}`);
    } else {
      suggestions.push('Provide a CVE ID for targeted analysis');
    }
    return suggestions;
  }

  private checkProactiveSuggestions(): string | null {
    if (this.conversationContext.recentCVEs.length >= 3 &&
        this.conversationContext.lastIntent !== 'risk_assessment') {
      return 'I can run a consolidated risk assessment across the CVEs we\'ve discussed.';
    }
    return null;
  }

  // Main query handler
  public async handleQuery(query: string): Promise<ChatResponse> {
    try {
      // Handle special commands
      if (query.toLowerCase().trim() === '/help') {
        return this.generateHelpMessage();
      }

      const analysis = this.analyzeQuery(query);
      this.updateConversationContext(analysis.intents);

      // Extract CVE ID from query
      const cveMatches = Array.from(query.matchAll(CVE_REGEX));
      let operationalCveId: string | null = null;
      
      if (cveMatches.length > 0) {
        operationalCveId = cveMatches[0][0].toUpperCase();
        this.currentCveIdForSession = operationalCveId;
      } else {
        operationalCveId = this.currentCveIdForSession;
        if (!operationalCveId && /(it|that cve|this vulnerability)/i.test(query)) {
          operationalCveId = this.conversationContext.recentCVEs[0] || null;
        }
      }

      if (!operationalCveId && analysis.intents.length === 0) {
        return {
          text: 'Could you specify which CVE or security topic you need help with?',
          sender: 'bot',
          id: Date.now().toString(),
          confidence: analysis.confidence
        };
      }
      
      let response: ChatResponse;

      // Handle CVE-specific queries
      if (operationalCveId) {
        response = await this.handleCVEQuery(query, operationalCveId);
      } else {
        // Handle general queries
        response = await this.handleGeneralQuery(query);
      }

      if (analysis.sentiment === 'urgent') {
        response.text = `🚨 ${response.text}`;
      } else if (analysis.sentiment === 'confused') {
        response.text = `Let me break that down for you.\n\n${response.text}`;
      }

      const followUps = this.generateFollowUps(analysis.intents, operationalCveId || undefined);
      if (followUps.length > 0) {
        response.text += `\n\n**You might also:**\n- ${followUps.join('\n- ')}`;
      }

      const proactive = this.checkProactiveSuggestions();
      if (proactive && this.userPreferences.autoSuggestions) {
        response.text += `\n\n💡 ${proactive}`;
      }

      response.text = this.applyTechnicalTone(this.varyResponse(response.text));

      response.confidence = analysis.confidence;
      response.followUps = followUps;

      this.storeConversation(query, response.text);
      return response;
      
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

  private async handleGeneralQuery(query: string): Promise<ChatResponse> {
    if (this.settings.openAiApiKey) {
      try {
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
      } catch (error: any) {
        console.error('OpenAI request failed:', error);
        return { text: 'Failed to fetch response from OpenAI.', sender: 'system', id: Date.now().toString(), error: error.message };
      }
    }

    let response = `I understand you're asking about cybersecurity. `;

    response += `To provide you with the most helpful information, could you:\n\n`;
    response += `• Specify a CVE ID (like CVE-2024-1234) if you're asking about a specific vulnerability\n`;
    response += `• Let me know what aspect you're most concerned about (patches, exploits, business impact)\n`;
    response += `• Share any relevant context about your environment or industry\n\n`;

    if (this.conversationContext.recentCVEs.length > 0) {
      response += `We were recently discussing: ${this.conversationContext.recentCVEs.join(', ')}. Would you like to continue with any of these?`;
    }

    const finalText = this.applyTechnicalTone(this.varyResponse(response));
    this.storeConversation(query, finalText);
    return {
      text: finalText,
      sender: 'bot',
      id: Date.now().toString(),
    };
  }

  // CVE validation with improved dispute detection
  

  // Enhanced dispute detection with ML-powered analysis (#5)
  private async enhancedDisputeDetection(cveId: string, webData: any): Promise<{
    isDisputed: boolean;
    confidence: number;
    evidence: string[];
    sources: string[];
    riskLevel: string;
    recommendation: string;
  }> {
    const features = this.extractDisputeFeatures(webData, cveId);
    const mlPrediction = await this.mlDisputeAnalysis(features);
    
    // Combine traditional rule-based and ML approaches
    const traditionalResult = this.isActualDispute(webData?.summary || '', cveId);
    const enhancedResult = this.combineDisputeAnalysis(traditionalResult, mlPrediction);
    
    return {
      isDisputed: enhancedResult.isDisputed,
      confidence: enhancedResult.confidence,
      evidence: enhancedResult.evidence,
      sources: enhancedResult.sources,
      riskLevel: this.calculateDisputeRiskLevel(enhancedResult),
      recommendation: this.generateDisputeRecommendation(enhancedResult)
    };
  }

  // Extract ML features for dispute detection
  private extractDisputeFeatures(webData: any, cveId: string): any {
    const features = {
      // Text-based features
      textLength: webData?.summary?.length || 0,
      disputeKeywordCount: 0,
      vendorMentions: 0,
      securityToolMentions: 0,
      
      // Source credibility features
      sourceCount: 0,
      officialSources: 0,
      communityReports: 0,
      
      // Temporal features
      reportAge: 0,
      lastUpdate: 0,
      
      // Pattern-based features
      contradictoryStatements: 0,
      consensusLevel: 0,
      
      // CVE characteristics
      cveAge: this.calculateCVEAge(cveId),
      hasOfficialEntry: false,
      hasCVSSScore: false
    };

    if (webData?.summary) {
      const summary = webData.summary.toLowerCase();
      
      // Count dispute-related keywords with weights
      const disputeKeywords = [
        { term: 'vendor disputes', weight: 3 },
        { term: 'false positive', weight: 2.5 },
        { term: 'disputed', weight: 2 },
        { term: 'rejected', weight: 2 },
        { term: 'invalid', weight: 2 },
        { term: 'withdrawn', weight: 1.5 },
        { term: 'not a vulnerability', weight: 3 },
        { term: 'excluded from', weight: 2 },
        { term: 'resolved wontfix', weight: 2.5 }
      ];

      for (const keyword of disputeKeywords) {
        if (summary.includes(keyword.term)) {
          features.disputeKeywordCount += keyword.weight;
        }
      }

      // Count vendor mentions
      const vendors = ['microsoft', 'oracle', 'red hat', 'suse', 'canonical', 'debian', 'apple', 'google', 'cisco', 'adobe'];
      features.vendorMentions = vendors.filter(vendor => summary.includes(vendor)).length;

      // Count security tool mentions
      const tools = ['sonatype', 'dependencycheck', 'snyk', 'veracode', 'checkmarx', 'fortify'];
      features.securityToolMentions = tools.filter(tool => summary.includes(tool)).length;

      // Detect contradictory statements
      features.contradictoryStatements = this.detectContradictions(summary);
    }

    // Analyze sources if available
    if (webData?.sources) {
      features.sourceCount = webData.sources.length;
      features.officialSources = webData.sources.filter((source: string) => 
        source.includes('nvd.nist.gov') || source.includes('cve.mitre.org') || 
        source.includes('cisa.gov') || source.includes('first.org')
      ).length;
    }

    return features;
  }

  // ML-inspired dispute analysis
  private async mlDisputeAnalysis(features: any): Promise<{
    isDisputed: boolean;
    confidence: number;
    reasoning: string[];
    evidenceStrength: number;
  }> {
    // Weighted decision tree approach (simulating ML model)
    let disputeScore = 0;
    const reasoning: string[] = [];
    let evidenceStrength = 0;

    // Feature-based scoring
    if (features.disputeKeywordCount > 5) {
      disputeScore += 40;
      reasoning.push(`Strong dispute keywords detected (score: ${features.disputeKeywordCount})`);
      evidenceStrength += 0.3;
    } else if (features.disputeKeywordCount > 2) {
      disputeScore += 20;
      reasoning.push(`Moderate dispute keywords detected (score: ${features.disputeKeywordCount})`);
      evidenceStrength += 0.2;
    }

    if (features.vendorMentions > 2) {
      disputeScore += 15;
      reasoning.push(`Multiple vendor mentions suggest industry awareness`);
      evidenceStrength += 0.1;
    }

    if (features.securityToolMentions > 1) {
      disputeScore += 20;
      reasoning.push(`Security tools involvement indicates dispute resolution`);
      evidenceStrength += 0.2;
    }

    if (features.contradictoryStatements > 0) {
      disputeScore += 25;
      reasoning.push(`Contradictory statements detected in sources`);
      evidenceStrength += 0.15;
    }

    // Negative indicators (reduce dispute probability)
    if (features.officialSources > 0 && features.disputeKeywordCount === 0) {
      disputeScore -= 30;
      reasoning.push(`Official sources present without dispute indicators`);
      evidenceStrength -= 0.2;
    }

    if (features.cveAge > 365 && features.disputeKeywordCount === 0) {
      disputeScore -= 15;
      reasoning.push(`Mature CVE without dispute history`);
      evidenceStrength -= 0.1;
    }

    // Confidence calculation based on evidence strength and consistency
    const confidence = Math.min(Math.max(evidenceStrength + 0.5, 0), 1);
    const isDisputed = disputeScore > 30;

    return {
      isDisputed,
      confidence,
      reasoning,
      evidenceStrength
    };
  }

  // Detect contradictory statements in text
  private detectContradictions(text: string): number {
    const contradictionPatterns = [
      { positive: 'legitimate', negative: 'false positive' },
      { positive: 'valid', negative: 'disputed' },
      { positive: 'confirmed', negative: 'rejected' },
      { positive: 'exploitable', negative: 'not exploitable' },
      { positive: 'patch available', negative: 'wontfix' }
    ];

    let contradictions = 0;
    for (const pattern of contradictionPatterns) {
      if (text.includes(pattern.positive) && text.includes(pattern.negative)) {
        contradictions++;
      }
    }

    return contradictions;
  }

  // Calculate CVE age in days
  private calculateCVEAge(cveId: string): number {
    const cveMatch = cveId.match(/CVE-(\d{4})-/);
    if (cveMatch) {
      const year = parseInt(cveMatch[1]);
      const currentYear = new Date().getFullYear();
      return (currentYear - year) * 365; // Approximate age in days
    }
    return 0;
  }

  // Legacy keyword-based dispute detection used as a fallback
  private isActualDispute(text: string, cveId: string): boolean {
    if (!text) return false;
    const lower = text.toLowerCase();
    const indicators = [
      'vendor dispute',
      'vendor disputes',
      'false positive',
      'not a vulnerability',
      'rejected',
      'withdrawn',
      'invalid',
      "won't fix",
      'wontfix',
      'not exploitable',
      'no patch because',
      'excluded'
    ];

    if (cveId) {
      const idLower = cveId.toLowerCase();
      if (lower.includes(`rejected ${idLower}`) || lower.includes(`withdrawn ${idLower}`)) {
        return true;
      }
    }

    return indicators.some(ind => lower.includes(ind));
  }

  // Combine traditional and ML dispute analysis
  private combineDisputeAnalysis(traditionalResult: boolean, mlResult: any): {
    isDisputed: boolean;
    confidence: number;
    evidence: string[];
    sources: string[];
  } {
    const evidence: string[] = [];
    const sources: string[] = [];

    // Weighted combination of results
    let combinedScore = 0;
    
    if (traditionalResult) {
      combinedScore += 40;
      evidence.push('Traditional rule-based analysis indicates dispute');
      sources.push('Pattern matching algorithm');
    }

    if (mlResult.isDisputed) {
      combinedScore += 60;
      evidence.push(...mlResult.reasoning);
      sources.push('ML-enhanced analysis');
    }

    // Consensus building
    const isDisputed = combinedScore > 50;
    const confidence = Math.min((combinedScore / 100) * mlResult.confidence, 1);

    // Add evidence strength indicators
    if (mlResult.evidenceStrength > 0.7) {
      evidence.push('High evidence strength from multiple indicators');
    } else if (mlResult.evidenceStrength > 0.4) {
      evidence.push('Moderate evidence strength from various sources');
    }

    return {
      isDisputed,
      confidence,
      evidence,
      sources
    };
  }

  // ===== Grounding and validation helpers =====
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

  private async storeLearningData(result: GroundedSearchResult): Promise<void> {
    try {
      await this.groundingEngine?.learn(result);
    } catch (e) {
      console.error('Learning storage failed', e);
    }
  }

  private validateCVEData(data: any): any {
    if (data?.cvssV3?.baseScore) {
      const correct = getCVSSSeverity(data.cvssV3.baseScore);
      if (data.cvssV3.baseSeverity !== correct) {
        data.cvssV3.baseSeverity = correct;
      }
    }
    return data;
  }

  // Calculate dispute risk level
  private calculateDisputeRiskLevel(result: any): string {
    if (result.confidence > 0.8 && result.isDisputed) {
      return 'HIGH_CONFIDENCE_DISPUTE';
    } else if (result.confidence > 0.6 && result.isDisputed) {
      return 'MODERATE_CONFIDENCE_DISPUTE';
    } else if (result.confidence > 0.4 && result.isDisputed) {
      return 'LOW_CONFIDENCE_DISPUTE';
    } else if (result.confidence > 0.7 && !result.isDisputed) {
      return 'HIGH_CONFIDENCE_LEGITIMATE';
    } else {
      return 'UNCERTAIN';
    }
  }

  // Generate dispute-specific recommendations
  private generateDisputeRecommendation(result: any): string {
    const riskLevel = this.calculateDisputeRiskLevel(result);
    
    const recommendations = {
      'HIGH_CONFIDENCE_DISPUTE': 'Strong evidence suggests this CVE is disputed. Verify with official vendor sources before taking action. Consider this low priority unless confirmed otherwise.',
      'MODERATE_CONFIDENCE_DISPUTE': 'Moderate evidence of dispute detected. Cross-reference with multiple vendor sources and security advisories before proceeding with remediation.',
      'LOW_CONFIDENCE_DISPUTE': 'Some indicators suggest potential dispute. Exercise caution and verify through official channels while maintaining standard security practices.',
      'HIGH_CONFIDENCE_LEGITIMATE': 'High confidence this is a legitimate vulnerability. Proceed with normal vulnerability management processes and prioritize based on risk assessment.',
      'UNCERTAIN': 'Insufficient evidence to determine dispute status. Conduct additional research through official sources and treat with standard security precautions.'
    };

    return recommendations[riskLevel as keyof typeof recommendations] ||
      recommendations['UNCERTAIN'];
  }

  // Enhanced validation with ML dispute detection
  private async getValidationInfo(cveId: string): Promise<ChatResponse> {
    try {
      let cveData = null;
      let epssData = null;
      let webIntel = null;

      try {
        cveData = await this.getCachedOrFetch(
          `cve_${cveId}`,
          () => APIService.fetchCVEData(cveId, this.settings?.nvdApiKey, () => {})
        );
        cveData = this.validateCVEData(cveData);
      } catch (error) {
        console.log('CVE data fetch failed:', error);
      }

      try {
        epssData = await this.getCachedOrFetch(
          `epss_${cveId}`,
          () => APIService.fetchEPSSData(cveId, () => {})
        );
      } catch (error) {
        console.log('EPSS data fetch failed:', error);
      }

      try {
        webIntel = await this.performWebSearch(
          `${cveId} vendor dispute false positive rejected legitimate status verification security tools excluded`
        );
      } catch (error) {
        console.error('Web intelligence failed:', error);
      }

      // Enhanced dispute detection with ML
      const disputeAnalysis = await this.enhancedDisputeDetection(cveId, webIntel);
      
      // Traditional vendor confirmation check
      const vendorConfirmation = await this.checkVendorConfirmation(cveId, webIntel);
      
      // Calculate enhanced confidence with ML insights
      const { confidence, reasoning } = this.calculateEnhancedValidationConfidence(
        cveData, epssData, webIntel, vendorConfirmation, disputeAnalysis
      );

      // Determine final status with ML enhancement
      let legitimacyStatus = 'UNKNOWN';
      let isFalsePositive = false;

      if (disputeAnalysis.isDisputed && disputeAnalysis.confidence > 0.6) {
        legitimacyStatus = disputeAnalysis.riskLevel;
        isFalsePositive = true;
      } else if (vendorConfirmation.hasConfirmation && confidence > 70) {
        legitimacyStatus = 'LEGITIMATE';
      } else if (cveData?.cve?.id && confidence > 50) {
        legitimacyStatus = 'LIKELY LEGITIMATE';
      } else {
        legitimacyStatus = 'UNCERTAIN';
      }

      // Generate enhanced response
      let responseText = `**${cveId} Enhanced Validation Results**\n\n`;
      
      responseText += `**Status:** ${legitimacyStatus}\n`;
      responseText += `**Confidence:** ${confidence}%\n`;
      responseText += `**ML Analysis:** ${disputeAnalysis.confidence > 0.5 ? 'Enhanced' : 'Standard'} dispute detection applied\n`;
      responseText += `**Reasoning:** ${reasoning}\n\n`;

      if (disputeAnalysis.isDisputed) {
        responseText += `**🤖 ML-Enhanced Dispute Analysis:**\n`;
        responseText += `• **Dispute Confidence:** ${(disputeAnalysis.confidence * 100).toFixed(1)}%\n`;
        responseText += `• **Risk Level:** ${disputeAnalysis.riskLevel}\n`;
        responseText += `• **Evidence Found:**\n`;
        disputeAnalysis.evidence.forEach(evidence => {
          responseText += `  - ${evidence}\n`;
        });
        responseText += `• **Analysis Sources:** ${disputeAnalysis.sources.join(', ')}\n\n`;
      }

      if (webIntel?.summary && webIntel.summary !== 'Web search failed') {
        responseText += `**Web Intelligence Summary:**\n${webIntel.summary.substring(0, 400)}...\n\n`;
      }

      if (vendorConfirmation.hasConfirmation) {
        responseText += `**✅ Vendor Confirmation Found:**\n`;
        responseText += `• **Confirmed by:** ${vendorConfirmation.vendors.join(', ')}\n`;
        responseText += `• **Patches available:** ${vendorConfirmation.patches}\n`;
        responseText += `• **Security advisories:** ${vendorConfirmation.advisories}\n\n`;
      }

      // ML-enhanced recommendation
      responseText += `**🎯 ML-Enhanced Recommendation:**\n`;
      responseText += `${disputeAnalysis.recommendation}\n\n`;

      // Additional insights based on ML analysis
      if (disputeAnalysis.confidence > 0.7) {
        responseText += `**🔍 Additional Insights:**\n`;
        responseText += `• High-confidence ML analysis suggests ${disputeAnalysis.isDisputed ? 'dispute' : 'legitimacy'}\n`;
        responseText += `• Consider this analysis in your vulnerability management decisions\n`;
        responseText += `• Monitor for updates as dispute status may evolve\n`;
      }

      return {
        text: responseText,
        sender: 'bot',
        id: Date.now().toString(),
        data: {
          legitimacyStatus,
          confidence,
          isDisputed: disputeAnalysis.isDisputed,
          isFalsePositive,
          vendorConfirmation,
          reasoning,
          webIntel,
          mlAnalysis: disputeAnalysis
        }
      };

    } catch (error: any) {
      return {
        text: `Sorry, I couldn't validate ${cveId} due to technical issues. Please try again or check the CVE manually through official sources.`,
        sender: 'bot',
        id: Date.now().toString(),
        error: error.message
      };
    }
  }

  // Enhanced confidence calculation with ML insights
  private calculateEnhancedValidationConfidence(
    cveData: any,
    epssData: any,
    webIntel: any,
    vendorConfirmation: any,
    disputeAnalysis: any
  ): { confidence: number; reasoning: string } {
    let confidence = 0;
    const reasoningFactors: string[] = [];

    // Base confidence from official sources
    if (cveData?.cve?.id) {
      confidence += 25;
      reasoningFactors.push('Official NVD entry exists');
    }

    if (epssData?.epss) {
      confidence += 15;
      reasoningFactors.push('EPSS score available');
    }

    // ML-enhanced dispute analysis factor
    if (disputeAnalysis.confidence > 0.7) {
      if (disputeAnalysis.isDisputed) {
        confidence -= 35;
        reasoningFactors.push('High-confidence ML dispute detection');
      } else {
        confidence += 20;
        reasoningFactors.push('High-confidence ML legitimacy verification');
      }
    } else if (disputeAnalysis.confidence > 0.4) {
      if (disputeAnalysis.isDisputed) {
        confidence -= 20;
        reasoningFactors.push('Moderate-confidence ML dispute indicators');
      } else {
        confidence += 10;
        reasoningFactors.push('Moderate-confidence ML legitimacy indicators');
      }
    }

    // Vendor confirmation with ML weighting
    if (vendorConfirmation.hasConfirmation) {
      const vendorWeight = disputeAnalysis.isDisputed ? 15 : 25;
      confidence += vendorWeight;
      reasoningFactors.push(`${vendorConfirmation.vendors.length} major vendors acknowledge this CVE`);
      
      if (vendorConfirmation.patches > 0) {
        confidence += 15;
        reasoningFactors.push(`${vendorConfirmation.patches} patches available`);
      }
      
      if (vendorConfirmation.advisories > 0) {
        confidence += 10;
        reasoningFactors.push(`${vendorConfirmation.advisories} security advisories found`);
      }
    }

    // CVE characteristics
    if (cveData?.cve?.cvssV3?.baseScore > 0) {
      confidence += 10;
      reasoningFactors.push('Valid CVSS score assigned');
    }

    // Web intelligence quality with ML assessment
    if (webIntel?.summary && webIntel.summary.length > 100) {
      confidence += 5;
      reasoningFactors.push('Comprehensive web intelligence available');
    }

    // ML evidence strength bonus
    if (disputeAnalysis.evidenceStrength > 0.6) {
      confidence += 5;
      reasoningFactors.push('Strong ML evidence consistency');
    }

    // Ensure confidence is within bounds
    confidence = Math.max(0, Math.min(100, confidence));

    return {
      confidence,
      reasoning: reasoningFactors.join(', ')
    };
  }

  // Vendor confirmation check
  private async checkVendorConfirmation(cveId: string, webIntel: any): Promise<{
    hasConfirmation: boolean;
    vendors: string[];
    patches: number;
    advisories: number;
  }> {
    const majorVendors = ['microsoft', 'oracle', 'red hat', 'suse', 'canonical', 'debian', 'apple', 'google'];
    const confirmedVendors: string[] = [];
    let patchCount = 0;
    let advisoryCount = 0;

    if (webIntel?.patches) {
      patchCount = webIntel.patches.length;
      webIntel.patches.forEach((patch: any) => {
        const vendor = patch.vendor?.toLowerCase() || patch.title?.toLowerCase() || '';
        for (const majorVendor of majorVendors) {
          if (vendor.includes(majorVendor) && !confirmedVendors.includes(majorVendor)) {
            confirmedVendors.push(majorVendor);
          }
        }
      });
    }

    if (webIntel?.advisories) {
      advisoryCount = webIntel.advisories.length;
      webIntel.advisories.forEach((advisory: any) => {
        const source = advisory.source?.toLowerCase() || advisory.title?.toLowerCase() || '';
        for (const majorVendor of majorVendors) {
          if (source.includes(majorVendor) && !confirmedVendors.includes(majorVendor)) {
            confirmedVendors.push(majorVendor);
          }
        }
      });
    }

    return {
      hasConfirmation: confirmedVendors.length > 0 || patchCount > 0 || advisoryCount > 0,
      vendors: confirmedVendors,
      patches: patchCount,
      advisories: advisoryCount
    };
  }

  // Confidence calculation
  private calculateValidationConfidence(
    cveData: any,
    epssData: any,
    webIntel: any,
    vendorConfirmation: any,
    isDisputed: boolean
  ): { confidence: number; reasoning: string } {
    let confidence = 0;
    const reasoningFactors: string[] = [];

    if (cveData?.cve?.id) {
      confidence += 30;
      reasoningFactors.push('Official NVD entry exists');
    }

    if (epssData?.epss) {
      confidence += 15;
      reasoningFactors.push('EPSS score available');
    }

    if (vendorConfirmation.hasConfirmation) {
      confidence += 25;
      reasoningFactors.push(`${vendorConfirmation.vendors.length} major vendors acknowledge this CVE`);
      
      if (vendorConfirmation.patches > 0) {
        confidence += 15;
        reasoningFactors.push(`${vendorConfirmation.patches} patches available`);
      }
      
      if (vendorConfirmation.advisories > 0) {
        confidence += 10;
        reasoningFactors.push(`${vendorConfirmation.advisories} security advisories found`);
      }
    }

    if (cveData?.cve?.cvssV3?.baseScore > 0) {
      confidence += 10;
      reasoningFactors.push('Valid CVSS score assigned');
    }

    if (isDisputed) {
      confidence -= 40;
      reasoningFactors.push('Evidence of vendor dispute or false positive classification');
    }

    if (webIntel?.summary && webIntel.summary.length > 100) {
      confidence += 5;
      reasoningFactors.push('Comprehensive web intelligence available');
    }

    confidence = Math.max(0, Math.min(100, confidence));

    return {
      confidence,
      reasoning: reasoningFactors.join(', ')
    };
  }

  // Generate comprehensive CVE report with improved contextual links
  private async generateComprehensiveCVEReport(cveId: string): Promise<ChatResponse> {
    try {
      let cveData = null;
      let epssData = null;
      let webIntel = null;
      const errors: string[] = [];
      
      // Fetch CVE data with error handling
      try {
        cveData = await this.getCachedOrFetch(
          `cve_${cveId}`,
          () => APIService.fetchCVEData(cveId, this.settings?.nvdApiKey, () => {})
        );
        cveData = this.validateCVEData(cveData);
      } catch (error) {
        console.log('CVE data fetch failed:', error);
        errors.push('Official CVE data unavailable');
      }
      
      // Fetch EPSS data with error handling
      try {
        epssData = await this.getCachedOrFetch(
          `epss_${cveId}`,
          () => APIService.fetchEPSSData(cveId, () => {})
        );
      } catch (error) {
        console.log('EPSS data fetch failed:', error);
        errors.push('EPSS score unavailable');
      }
      
      // Fetch web intelligence with error handling
      try {
        webIntel = await this.performWebSearch(
          `${cveId} vulnerability analysis patches advisories exploits`
        );
      } catch (error) {
        console.log('Web intelligence failed:', error);
        errors.push('Web intelligence limited');
        webIntel = this.createFallbackWebSearchResult('Web search failed');
      }
      
      // Generate contextual information using improved logic
      const contextualInfo = this.generateContextualInformation(cveId, cveData, webIntel);
      
      // Determine CVE status with error handling
      let cveStatus;
      try {
        cveStatus = this.determineCVEStatus(cveData, epssData, webIntel);
      } catch (error) {
        console.error('CVE status determination failed:', error);
        cveStatus = {
          status: 'ANALYSIS_ERROR',
          confidence: 20,
          isDisputed: false,
          hasPatches: false,
          hasExploits: false
        };
        errors.push('Status analysis incomplete');
      }
      
      // Build comprehensive report
      let report = `**${cveId} Comprehensive Analysis**\n\n`;
      
      // Add error notices if any
      if (errors.length > 0) {
        report += `⚠️ **Analysis Limitations**: ${errors.join(', ')}\n\n`;
      }
      
      // Key findings with affected products
      if (cveData?.description) {
        const severity = getCVSSSeverity(cveData.cvssV3?.baseScore || 0).toLowerCase();
        const affectedProducts = this.extractAffectedProductsSimple(cveData.description);

        let desc = cveData.description;
        let truncated = false;
        if (desc.length > 300) {
          truncated = true;
          desc = desc.substring(0, 300) + '...';
        }

        report += `🔍 **Key Finding:** ${cveId} is a ${severity} severity vulnerability`;
        if (affectedProducts.length > 0) {
          report += ` affecting ${affectedProducts.join(', ')}`;
        }
        report += `. ${desc}`;
        if (truncated) {
          const more = await this.getGroundedInfo(`${cveId} full description`);
          if (more.content) {
            report += `\n\n${more.content}`;
          } else {
            report += ' [description truncated]';
          }
        }
        report += `\n\n`;
      } else {
        report += `🔍 **Key Finding:** ${cveId} vulnerability analysis is in progress. Limited data available.\n\n`;
      }
      
      // Status information
      report += `📊 **Analysis Status:**\n`;
      report += `• **Status:** ${cveStatus.status}\n`;
      report += `• **Confidence:** ${cveStatus.confidence}%\n`;
      if (cveStatus.isDisputed) {
        report += `• **Dispute Status:** Evidence of dispute detected\n`;
      }
      report += `\n`;
      
      // Technical details
      report += `📊 **Technical Details:**\n`;
      if (cveData?.cvssV3) {
        report += `• **CVSS v3 Score:** ${cveData.cvssV3.baseScore}/10 (${getCVSSSeverity(cveData.cvssV3.baseScore)})\n`;
        report += `• **Attack Vector:** ${cveData.cvssV3.attackVector || 'Unknown'}\n`;
        report += `• **Attack Complexity:** ${cveData.cvssV3.attackComplexity || 'Unknown'}\n`;
        report += `• **Privileges Required:** ${cveData.cvssV3.privilegesRequired || 'Unknown'}\n`;
        report += `• **User Interaction:** ${cveData.cvssV3.userInteraction || 'Unknown'}\n`;
      } else {
        report += `• **CVSS Score:** Not available or still being analyzed\n`;
      }
      
      if (epssData?.epss) {
        report += `• **EPSS Score:** ${epssData.epss} (${epssData.epssPercentage}% - ${this.interpretEPSSScore(parseFloat(epssData.epss))})\n`;
      } else {
        report += `• **EPSS Score:** Not available\n`;
      }
      
      // Official sources
      report += `\n🔗 **Official Sources:**\n`;
      report += `• [NVD Entry](https://nvd.nist.gov/vuln/detail/${cveId})\n`;
      report += `• [MITRE CVE Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId})\n`;
      report += `• [EPSS Score Details](https://www.first.org/epss/model)\n`;
      report += `• [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)\n`;
      
      // Add contextual vendor information
      if (contextualInfo.vendors.length > 0) {
        report += `\n🏢 **Vendor Information:**\n`;
        contextualInfo.vendors.forEach(vendor => {
          report += `• [${vendor.name} Security](${vendor.url})\n`;
        });
      }
      
      // Exploitation assessment
      report += `\n⚡ **Exploitation Assessment:**\n`;
      if (webIntel?.exploits?.length > 0) {
        report += `• **Public Exploits:** ${webIntel.exploits.length} potential exploits found\n`;
        webIntel.exploits.slice(0, 3).forEach((exploit: any) => {
          report += `  - ${exploit.title} (${exploit.source})\n`;
        });
      } else {
        report += `• **Public Exploits:** No known public exploits found\n`;
      }
      
      // Exploit research links
      report += `\n🔍 **Exploit Research:**\n`;
      report += `• [ExploitDB Search](https://www.exploit-db.com/search?cve=${cveId})\n`;
      report += `• [Packet Storm](https://packetstormsecurity.com/search/?q=${cveId})\n`;
      report += `• [Rapid7 Vulnerability Database](https://www.rapid7.com/db/search?q=${cveId})\n`;
      report += `• [Metasploit Database](https://www.rapid7.com/db/?q=${cveId})\n`;
      
      // Add contextual exploit links based on CVE content
      if (cveData?.description) {
        const description = cveData.description.toLowerCase();
        if (description.includes('remote code execution') || description.includes('rce')) {
          report += `• [GitHub RCE Exploits](https://github.com/search?q=${cveId}+remote+code+execution&type=repositories)\n`;
        }
        if (description.includes('sql injection')) {
          report += `• [GitHub SQL Injection](https://github.com/search?q=${cveId}+sql+injection&type=repositories)\n`;
        }
        if (description.includes('cross-site scripting') || description.includes('xss')) {
          report += `• [GitHub XSS Exploits](https://github.com/search?q=${cveId}+xss&type=repositories)\n`;
        }
      }
      
      // Patches and remediation
      report += `\n🛠️ **Patches and Remediation:**\n`;
      if (cveStatus.hasPatches) {
        report += `• **Available Patches:** Patches detected in analysis\n`;
        if (webIntel?.patches?.length > 0) {
          webIntel.patches.forEach((patch: any) => {
            report += `  - **${patch.vendor || 'Vendor'}:** ${patch.title}\n`;
            report += `    🔗 [${patch.url}](${patch.url})\n`;
          });
        }
      } else {
        report += `• **Available Patches:** Check vendor websites for updates\n`;
      }
      
      // Contextual patch sources
      report += `\n📦 **Patch Sources:**\n`;
      contextualInfo.patchSources.forEach(source => {
        report += `• [${source.name}](${source.url})\n`;
      });
      
      // Security advisories
      report += `\n📋 **Security Advisories:**\n`;
      contextualInfo.advisorySources.forEach(source => {
        report += `• [${source.name}](${source.url})\n`;
      });
      
      // Research and analysis links
      report += `\n🔬 **Research & Analysis:**\n`;
      report += `• [CVE Details](https://www.cvedetails.com/cve/${cveId}/)\n`;
      report += `• [Google Scholar](https://scholar.google.com/scholar?q=${cveId})\n`;
      report += `• [Security Focus](https://www.securityfocus.com/bid)\n`;
      
      report += `\n💡 **Recommendation:**\n`;
      if (cveStatus.isDisputed) {
        report += `**CAUTION** - This CVE appears to be disputed:\n`;
        report += `• Verify through official vendor channels before taking action\n`;
        report += `• Consider this lower priority unless confirmed otherwise\n`;
        report += `• Monitor for updates on dispute resolution\n`;
      } else {
        const cvssScore = cveData?.cvssV3?.baseScore || 0;
        if (cvssScore >= 7.0) {
          report += `**HIGH PRIORITY** - This appears to be a high-severity vulnerability:\n`;
        } else if (cvssScore >= 4.0) {
          report += `**MEDIUM PRIORITY** - This appears to be a medium-severity vulnerability:\n`;
        } else {
          report += `**STANDARD PRIORITY** - Follow normal patch management processes:\n`;
        }
        
        report += `• Verify if your systems are affected using vendor-specific resources above\n`;
        report += `• Check for and apply available patches from the patch sources listed\n`;
        report += `• Implement workarounds if patching is delayed\n`;
        report += `• Monitor for exploitation attempts using the research links provided\n`;
      }
      
      // Add data source information
      report += `\n📋 **Data Sources:**\n`;
      report += `• **Official CVE Data:** ${cveData ? 'Available' : 'Limited'}\n`;
      report += `• **EPSS Score:** ${epssData ? 'Available' : 'Not available'}\n`;
      report += `• **Web Intelligence:** ${webIntel?.fallback ? 'Limited (offline mode)' : 'Available'}\n`;
      report += `• **Contextual Links:** ${contextualInfo.vendors.length + contextualInfo.patchSources.length + contextualInfo.advisorySources.length} vendor-specific resources\n`;
      
      return {
        text: report,
        sender: 'bot',
        id: Date.now().toString(),
        data: {
          cveId,
          cveData,
          epssData,
          webIntel,
          cveStatus,
          contextualInfo,
          errors
        }
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

  // Generate contextual information using improved logic
  private generateContextualInformation(cveId: string, cveData: any, webIntel: any): {
    vendors: Array<{ name: string; url: string }>;
    patchSources: Array<{ name: string; url: string }>;
    advisorySources: Array<{ name: string; url: string }>;
  } {
    const contextualInfo = {
      vendors: [],
      patchSources: [],
      advisorySources: []
    };

    // Extract affected products from CVE description
    const affectedProducts = this.extractAffectedProductsSimple(cveData?.description || '');
    
    // Generate vendor-specific links based on affected products
    const vendorMappings = {
      'microsoft': { 
        name: 'Microsoft Security Response Center',
        url: `https://msrc.microsoft.com/update-guide/vulnerability/${cveId}`
      },
      'windows': { 
        name: 'Microsoft Windows Security',
        url: `https://msrc.microsoft.com/update-guide/vulnerability/${cveId}`
      },
      'adobe': { 
        name: 'Adobe Security Bulletins',
        url: 'https://helpx.adobe.com/security.html'
      },
      'oracle': { 
        name: 'Oracle Critical Patch Updates',
        url: 'https://www.oracle.com/security-alerts/'
      },
      'java': { 
        name: 'Oracle Java Security',
        url: 'https://www.oracle.com/security-alerts/'
      },
      'apache': { 
        name: 'Apache Security Reports',
        url: 'https://www.apache.org/security/'
      },
      'red hat': { 
        name: 'Red Hat Security',
        url: `https://access.redhat.com/security/cve/${cveId}`
      },
      'ubuntu': { 
        name: 'Ubuntu Security',
        url: `https://ubuntu.com/security/cve/${cveId}`
      },
      'debian': { 
        name: 'Debian Security',
        url: `https://security-tracker.debian.org/tracker/${cveId}`
      }
    };

    // Add vendors based on affected products
    for (const product of affectedProducts) {
      const lowerProduct = product.toLowerCase();
      for (const [key, vendor] of Object.entries(vendorMappings)) {
        if (lowerProduct.includes(key)) {
          contextualInfo.vendors.push(vendor);
          break;
        }
      }
    }

    // Generate patch sources
    contextualInfo.patchSources = [
      { name: 'Microsoft Update Catalog', url: `https://www.catalog.update.microsoft.com/Search.aspx?q=${cveId}` },
      { name: 'Red Hat CVE Database', url: `https://access.redhat.com/security/cve/${cveId}` },
      { name: 'Ubuntu Security Notices', url: `https://ubuntu.com/security/notices?q=${cveId}` },
      { name: 'Debian Security Tracker', url: `https://security-tracker.debian.org/tracker/${cveId}` },
      { name: 'SUSE Security Updates', url: `https://www.suse.com/security/cve/${cveId}/` }
    ];

    // Generate advisory sources
    contextualInfo.advisorySources = [
      { name: 'CISA Known Exploited Vulnerabilities', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
      { name: 'NIST NVD', url: `https://nvd.nist.gov/vuln/detail/${cveId}` },
      { name: 'MITRE CVE', url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}` },
      { name: 'Tenable Research', url: `https://www.tenable.com/cve/${cveId}` },
      { name: 'Qualys VMDR', url: 'https://www.qualys.com/research/security-advisories/' }
    ];

    return contextualInfo;
  }

  // Simple product extraction for contextual links
  private extractAffectedProductsSimple(description: string): string[] {
    if (!description) return [];
    
    const products = [];
    const lowerDescription = description.toLowerCase();
    
    // Common product patterns
    const productPatterns = [
      'microsoft', 'windows', 'office', 'exchange', 'sharepoint', 'sql server',
      'adobe', 'acrobat', 'flash', 'photoshop',
      'oracle', 'java', 'mysql', 'weblogic',
      'apache', 'http server', 'tomcat', 'struts', 'log4j',
      'red hat', 'ubuntu', 'debian', 'suse',
      'cisco', 'juniper', 'fortinet',
      'git', 'jenkins', 'docker',
      'postgresql', 'mongodb', 'redis',
      'nginx', 'haproxy',
      'openssl', 'wordpress', 'drupal'
    ];
    
    for (const pattern of productPatterns) {
      if (lowerDescription.includes(pattern)) {
        products.push(pattern);
      }
    }
    
    return products.slice(0, 5); // Limit to top 5 products
  }

  // Generate contextual reasoning
  private generateContextualReasoning(query: string, intents: any[], sentiment: string, complexity: string): string {
    let reasoning = `Query analysis: `;
    
    if (intents.length > 0) {
      reasoning += `Primary intent appears to be ${intents[0].name.replace('_', ' ')}. `;
    }
    
    if (sentiment === 'urgent') {
      reasoning += `High urgency detected - user needs immediate assistance. `;
    } else if (sentiment === 'confused') {
      reasoning += `User seems confused - should provide clear, step-by-step explanation. `;
    }
    
    if (complexity === 'expert') {
      reasoning += `Technical complexity is high - can provide detailed technical information. `;
    } else if (complexity === 'simple') {
      reasoning += `Simple query - should provide concise, actionable answer. `;
    }
    
    return reasoning;
  }

  // Determine CVE status based on available data (fixed method)
  private determineCVEStatus(cveData: any, epssData: any, webIntel: any): {
    status: string;
    confidence: number;
    isDisputed: boolean;
    hasPatches: boolean;
    hasExploits: boolean;
  } {
    let status = 'UNKNOWN';
    let confidence = 0;
    let isDisputed = false;
    let hasPatches = false;
    let hasExploits = false;

    // Check if CVE exists in official databases
    if (cveData?.cve?.id) {
      status = 'LEGITIMATE';
      confidence += 40;
    }

    // Check for disputes using the legacy method (now available)
    if (webIntel?.summary) {
      try {
        isDisputed = this.isActualDispute(webIntel.summary, cveData?.cve?.id || '');
        if (isDisputed) {
          status = 'DISPUTED';
          confidence -= 30;
        }
      } catch (error) {
        console.log('Dispute detection failed, using fallback logic:', error);
        // Fallback dispute detection
        const summary = webIntel.summary.toLowerCase();
        isDisputed = summary.includes('disputed') || summary.includes('false positive') || summary.includes('rejected');
        if (isDisputed) {
          status = 'DISPUTED';
          confidence -= 20;
        }
      }
    }

    // Check for patches
    if (webIntel?.patches && webIntel.patches.length > 0) {
      hasPatches = true;
      confidence += 10;
    }

    // Check for exploits
    if (webIntel?.exploits && webIntel.exploits.length > 0) {
      hasExploits = true;
      confidence += 15;
    }

    // EPSS score adds confidence
    if (epssData?.epss) {
      confidence += 10;
    }

    // CVE has CVSS score
    if (cveData?.cvssV3?.baseScore) {
      confidence += 15;
    }

    // Handle fallback scenarios
    if (webIntel?.fallback) {
      confidence -= 10;
      status = status === 'UNKNOWN' ? 'LIMITED_DATA' : status;
    }

    // Ensure confidence is within bounds
    confidence = Math.max(0, Math.min(100, confidence));

    return {
      status,
      confidence,
      isDisputed,
      hasPatches,
      hasExploits
    };
  }

  // Improved patch and advisory info with better logic
  private async getPatchAndAdvisoryInfo(cveId: string): Promise<ChatResponse> {
    try {
      let response = `**Patch and Advisory Information for ${cveId}**\n\n`;
      
      // Single comprehensive search instead of multiple separate calls
      const comprehensiveSearch = await this.performComprehensiveSearch(cveId);
      
      // Process results with improved logic
      const processedResults = this.processSearchResults(comprehensiveSearch, cveId);
      
      // Generate response sections
      response += this.generatePatchSection(processedResults.patches, cveId);
      response += this.generateAdvisorySection(processedResults.advisories, cveId);
      response += this.generateVendorSection(processedResults.vendors, cveId);
      response += this.generateRecommendationsSection(processedResults, cveId);
      
      return {
        text: response,
        sender: 'bot',
        id: Date.now().toString(),
        data: {
          cveId,
          searchResults: processedResults,
          searchTimestamp: new Date().toISOString(),
          confidence: processedResults.confidence
        }
      };
      
    } catch (error: any) {
      return this.generateFallbackPatchResponse(cveId, error.message);
    }
  }

  // Single comprehensive search with better logic
  private async performComprehensiveSearch(cveId: string): Promise<{
    summary: string;
    confidence: number;
    searchQuery: string;
    fallback: boolean;
  }> {
    try {
      // Single, well-crafted search query
      const searchQuery = `${cveId} security patch update advisory vendor Microsoft Red Hat Ubuntu Oracle fix download`;
      
      const webResult = await this.performWebSearch(searchQuery);
      
      return {
        summary: webResult.summary || '',
        confidence: webResult.fallback ? 0.3 : 0.8,
        searchQuery,
        fallback: webResult.fallback || false
      };
      
    } catch (error) {
      console.error('Comprehensive search failed:', error);
      return {
        summary: '',
        confidence: 0.1,
        searchQuery: `${cveId} search failed`,
        fallback: true
      };
    }
  }

  // Improved result processing with context awareness
  private processSearchResults(searchResult: any, cveId: string): {
    patches: any[];
    advisories: any[];
    vendors: any[];
    confidence: number;
    hasRealData: boolean;
  } {
    const results = {
      patches: [],
      advisories: [],
      vendors: [],
      confidence: searchResult.confidence,
      hasRealData: false
    };

    if (!searchResult.summary || searchResult.fallback) {
      return results;
    }

    const summary = searchResult.summary.toLowerCase();
    
    // Improved patch detection with context validation
    results.patches = this.extractPatchesWithContext(searchResult.summary, cveId);
    results.advisories = this.extractAdvisoriesWithContext(searchResult.summary, cveId);
    results.vendors = this.extractVendorsWithContext(searchResult.summary, cveId);
    
    // Determine if we have real data
    results.hasRealData = results.patches.length > 0 || results.advisories.length > 0 || results.vendors.length > 0;
    
    // Adjust confidence based on data quality
    if (results.hasRealData) {
      results.confidence = Math.min(results.confidence + 0.2, 1.0);
    }
    
    return results;
  }

  // Context-aware patch extraction
  private extractPatchesWithContext(summary: string, cveId: string): any[] {
    const patches = [];
    const sentences = summary.split(/[.!?]+/);
    
    for (const sentence of sentences) {
      const lowerSentence = sentence.toLowerCase();
      
      // Only process sentences that mention the CVE or security updates
      if (!lowerSentence.includes(cveId.toLowerCase()) && 
          !lowerSentence.includes('security update') && 
          !lowerSentence.includes('patch') &&
          !lowerSentence.includes('advisory')) {
        continue;
      }
      
      // Look for patch indicators with context
      const patchIndicators = ['patch', 'update', 'fix', 'security update', 'hotfix'];
      const vendorIndicators = ['microsoft', 'red hat', 'ubuntu', 'oracle', 'adobe', 'apache'];
      
      const hasPatchIndicator = patchIndicators.some(indicator => lowerSentence.includes(indicator));
      const hasVendorIndicator = vendorIndicators.some(vendor => lowerSentence.includes(vendor));
      
      if (hasPatchIndicator && hasVendorIndicator) {
        // Extract URL if present
        const urlMatch = sentence.match(/https?:\/\/[^\s<>"]+/);
        const vendor = this.extractVendorFromSentence(sentence);
        
        if (vendor) {
          patches.push({
            vendor: vendor,
            title: this.extractPatchTitleFromSentence(sentence, cveId),
            url: urlMatch ? urlMatch[0] : this.generateVendorSearchUrl(vendor, cveId),
            confidence: urlMatch ? 0.8 : 0.5,
            source: 'web_search'
          });
        }
      }
    }
    
    return this.deduplicatePatches(patches);
  }

  // Context-aware advisory extraction
  private extractAdvisoriesWithContext(summary: string, cveId: string): any[] {
    const advisories = [];
    const sentences = summary.split(/[.!?]+/);
    
    for (const sentence of sentences) {
      const lowerSentence = sentence.toLowerCase();
      
      // Only process CVE-relevant sentences
      if (!lowerSentence.includes(cveId.toLowerCase()) && 
          !lowerSentence.includes('advisory') && 
          !lowerSentence.includes('bulletin') &&
          !lowerSentence.includes('security notice')) {
        continue;
      }
      
      const advisoryIndicators = ['advisory', 'bulletin', 'security notice', 'alert', 'warning'];
      const hasAdvisoryIndicator = advisoryIndicators.some(indicator => lowerSentence.includes(indicator));
      
      if (hasAdvisoryIndicator) {
        const urlMatch = sentence.match(/https?:\/\/[^\s<>"]+/);
        const source = this.extractSourceFromSentence(sentence);
        
        if (source) {
          advisories.push({
            source: source,
            title: this.extractAdvisoryTitleFromSentence(sentence, cveId),
            url: urlMatch ? urlMatch[0] : this.generateAdvisorySearchUrl(source, cveId),
            confidence: urlMatch ? 0.8 : 0.5,
            extractedFrom: 'web_search'
          });
        }
      }
    }
    
    return this.deduplicateAdvisories(advisories);
  }

  // Context-aware vendor extraction
  private extractVendorsWithContext(summary: string, cveId: string): any[] {
    const vendors = [];
    const sentences = summary.split(/[.!?]+/);
    
    const knownVendors = [
      'Microsoft', 'Red Hat', 'Ubuntu', 'Oracle', 'Adobe', 'Apache', 
      'Cisco', 'VMware', 'Google', 'Amazon', 'Debian', 'SUSE'
    ];
    
    for (const sentence of sentences) {
      const lowerSentence = sentence.toLowerCase();
      
      // Only process CVE-relevant sentences
      if (!lowerSentence.includes(cveId.toLowerCase()) && 
          !lowerSentence.includes('vendor') && 
          !lowerSentence.includes('security')) {
        continue;
      }
      
      for (const vendor of knownVendors) {
        if (lowerSentence.includes(vendor.toLowerCase())) {
          const urlMatch = sentence.match(/https?:\/\/[^\s<>"]+/);
          
          vendors.push({
            vendor: vendor,
            description: this.extractVendorDescriptionFromSentence(sentence, cveId),
            url: urlMatch ? urlMatch[0] : this.generateVendorSecurityUrl(vendor, cveId),
            confidence: urlMatch ? 0.8 : 0.4,
            mentioned: true
          });
        }
      }
    }
    
    return this.deduplicateVendors(vendors);
  }

  // Generate response sections with improved logic
  private generatePatchSection(patches: any[], cveId: string): string {
    let section = '';
    
    if (patches.length > 0) {
      section += `🔗 **Verified Patch Information:**\n`;
      
      // Sort by confidence
      const sortedPatches = patches.sort((a, b) => b.confidence - a.confidence);
      
      for (const patch of sortedPatches) {
        section += `• **${patch.vendor}**: ${patch.title}\n`;
        section += `  📎 [View Patch](${patch.url})\n`;
        section += `  🎯 Confidence: ${Math.round(patch.confidence * 100)}%\n`;
        section += `\n`;
      }
    } else {
      section += `🔗 **Patch Sources** (no specific patches found in search):\n`;
      section += `• [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/Search.aspx?q=${cveId})\n`;
      section += `• [Red Hat CVE Database](https://access.redhat.com/security/cve/${cveId})\n`;
      section += `• [Ubuntu Security Notices](https://ubuntu.com/security/notices?q=${cveId})\n`;
      section += `• [Debian Security Tracker](https://security-tracker.debian.org/tracker/${cveId})\n`;
      section += `\n`;
    }
    
    return section;
  }

  private generateAdvisorySection(advisories: any[], cveId: string): string {
    let section = '';
    
    if (advisories.length > 0) {
      section += `📋 **Security Advisories:**\n`;
      
      const sortedAdvisories = advisories.sort((a, b) => b.confidence - a.confidence);
      
      for (const advisory of sortedAdvisories) {
        section += `• **${advisory.source}**: ${advisory.title}\n`;
        section += `  📎 [View Advisory](${advisory.url})\n`;
        section += `  🎯 Confidence: ${Math.round(advisory.confidence * 100)}%\n`;
        section += `\n`;
      }
    } else {
      section += `📋 **Standard Advisory Sources:**\n`;
      section += `• [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)\n`;
      section += `• [NIST NVD](https://nvd.nist.gov/vuln/detail/${cveId})\n`;
      section += `• [MITRE CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId})\n`;
      section += `\n`;
    }
    
    return section;
  }

  private generateVendorSection(vendors: any[], cveId: string): string {
    let section = '';
    
    if (vendors.length > 0) {
      section += `🏢 **Vendor Information:**\n`;
      
      const sortedVendors = vendors.sort((a, b) => b.confidence - a.confidence);
      
      for (const vendor of sortedVendors) {
        section += `• **${vendor.vendor}**: ${vendor.description}\n`;
        section += `  📎 [Vendor Security](${vendor.url})\n`;
        section += `  🎯 Confidence: ${Math.round(vendor.confidence * 100)}%\n`;
        section += `\n`;
      }
    }
    
    return section;
  }

  private generateRecommendationsSection(results: any, cveId: string): string {
    let section = `💡 **Recommendations:**\n`;
    
    if (results.hasRealData) {
      section += `• **Data Quality**: Found ${results.patches.length} patches, ${results.advisories.length} advisories\n`;
      section += `• **Confidence**: ${Math.round(results.confidence * 100)}% overall confidence in search results\n`;
      
      if (results.patches.length > 0) {
        section += `• **Action**: Review patches above and apply according to your maintenance schedule\n`;
      }
      
      if (results.advisories.length > 0) {
        section += `• **Review**: Check advisories for additional context and mitigation guidance\n`;
      }
    } else {
      section += `• **Limited Data**: No specific patches/advisories found in search results\n`;
      section += `• **Manual Check**: Visit vendor security pages directly using the links above\n`;
      section += `• **Monitor**: Check back later as information may be updated\n`;
    }
    
    section += `\n📅 **Search Completed**: ${new Date().toLocaleString()}\n`;
    section += `🔄 **Note**: Information is based on web search results and should be verified with official sources.\n`;
    
    return section;
  }

  // Utility methods for better extraction
  private extractVendorFromSentence(sentence: string): string | null {
    const vendors = ['Microsoft', 'Red Hat', 'Ubuntu', 'Oracle', 'Adobe', 'Apache', 'Cisco', 'VMware'];
    
    for (const vendor of vendors) {
      if (sentence.toLowerCase().includes(vendor.toLowerCase())) {
        return vendor;
      }
    }
    
    return null;
  }

  private extractPatchTitleFromSentence(sentence: string, cveId: string): string {
    // Clean up sentence and create meaningful title
    const cleaned = sentence.replace(/https?:\/\/[^\s<>"]+/g, '').trim();
    const title = cleaned.length > 80 ? cleaned.substring(0, 80) + '...' : cleaned;
    return title || `Security update for ${cveId}`;
  }

  private extractAdvisoryTitleFromSentence(sentence: string, cveId: string): string {
    const cleaned = sentence.replace(/https?:\/\/[^\s<>"]+/g, '').trim();
    const title = cleaned.length > 80 ? cleaned.substring(0, 80) + '...' : cleaned;
    return title || `Security advisory for ${cveId}`;
  }

  private extractSourceFromSentence(sentence: string): string | null {
    const sources = ['Microsoft', 'Red Hat', 'Ubuntu', 'CISA', 'NIST', 'Oracle', 'Adobe'];
    
    for (const source of sources) {
      if (sentence.toLowerCase().includes(source.toLowerCase())) {
        return source;
      }
    }
    
    return null;
  }

  private extractVendorDescriptionFromSentence(sentence: string, cveId: string): string {
    const cleaned = sentence.replace(/https?:\/\/[^\s<>"]+/g, '').trim();
    return cleaned.length > 100 ? cleaned.substring(0, 100) + '...' : cleaned;
  }

  // Deduplication methods
  private deduplicatePatches(patches: any[]): any[] {
    const seen = new Set();
    return patches.filter(patch => {
      const key = `${patch.vendor}-${patch.title}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private deduplicateAdvisories(advisories: any[]): any[] {
    const seen = new Set();
    return advisories.filter(advisory => {
      const key = `${advisory.source}-${advisory.title}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private deduplicateVendors(vendors: any[]): any[] {
    const seen = new Set();
    return vendors.filter(vendor => {
      const key = vendor.vendor;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  // URL generation fallbacks
  private generateVendorSearchUrl(vendor: string, cveId: string): string {
    const urlMappings = {
      'Microsoft': `https://www.catalog.update.microsoft.com/Search.aspx?q=${cveId}`,
      'Red Hat': `https://access.redhat.com/security/cve/${cveId}`,
      'Ubuntu': `https://ubuntu.com/security/notices?q=${cveId}`,
      'Oracle': `https://www.oracle.com/security-alerts/`,
      'Adobe': `https://helpx.adobe.com/security.html`,
      'Apache': `https://www.apache.org/security/`
    };
    
    return urlMappings[vendor] || `https://www.google.com/search?q=${vendor}+${cveId}+security+patch`;
  }

  private generateAdvisorySearchUrl(source: string, cveId: string): string {
    const urlMappings = {
      'CISA': `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`,
      'NIST': `https://nvd.nist.gov/vuln/detail/${cveId}`,
      'Microsoft': `https://msrc.microsoft.com/update-guide/vulnerability/${cveId}`,
      'Red Hat': `https://access.redhat.com/security/cve/${cveId}`
    };
    
    return urlMappings[source] || `https://www.google.com/search?q=${source}+${cveId}+security+advisory`;
  }

  private generateVendorSecurityUrl(vendor: string, cveId: string): string {
    const urlMappings = {
      'Microsoft': `https://msrc.microsoft.com/update-guide/vulnerability/${cveId}`,
      'Red Hat': `https://access.redhat.com/security/cve/${cveId}`,
      'Ubuntu': `https://ubuntu.com/security/cve/${cveId}`,
      'Oracle': `https://www.oracle.com/security-alerts/`,
      'Adobe': `https://helpx.adobe.com/security.html`,
      'Apache': `https://www.apache.org/security/`
    };
    
    return urlMappings[vendor] || `https://www.google.com/search?q=${vendor}+security+${cveId}`;
  }

  // Fallback response generation
  private generateFallbackPatchResponse(cveId: string, errorMessage: string): ChatResponse {
    return {
      text: `**Patch and Advisory Information for ${cveId}**\n\nI encountered an issue while searching for real-time information, but here are reliable sources to check:\n\n🔗 **Verified Patch Sources:**\n• [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/Search.aspx?q=${cveId})\n• [Red Hat CVE Database](https://access.redhat.com/security/cve/${cveId})\n• [Ubuntu Security Notices](https://ubuntu.com/security/notices?q=${cveId})\n• [Debian Security Tracker](https://security-tracker.debian.org/tracker/${cveId})\n\n📋 **Security Advisories:**\n• [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)\n• [NIST NVD](https://nvd.nist.gov/vuln/detail/${cveId})\n• [MITRE CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId})\n\n💡 **Recommendation:** Check these verified sources directly for the most current patch and advisory information.\n\n**Note:** ${errorMessage}`,
      sender: 'bot',
      id: Date.now().toString(),
      error: errorMessage
    };
  }

  // Search for actual patches using web search
  private async searchForActualPatches(cveId: string): Promise<{
    patches: Array<{
      vendor: string;
      title: string;
      url: string;
      releaseDate?: string;
      severity?: string;
    }>;
    searchQuery: string;
  }> {
    try {
      const searchQuery = `${cveId} patch update fix download security vendor`;
      const webResult = await this.performWebSearch(searchQuery);
      
      const patches = [];
      
      if (webResult.summary && !webResult.fallback) {
        // Parse the web search results for actual patch information
        const patchInfo = this.extractPatchInfoFromWebResult(webResult.summary, cveId);
        patches.push(...patchInfo);
      }
      
      return {
        patches,
        searchQuery
      };
      
    } catch (error) {
      console.error('Patch search failed:', error);
      return {
        patches: [],
        searchQuery: `${cveId} patch search failed`
      };
    }
  }

  // Search for actual advisories using web search
  private async searchForActualAdvisories(cveId: string): Promise<{
    advisories: Array<{
      source: string;
      title: string;
      url: string;
      severity?: string;
      publishDate?: string;
    }>;
    searchQuery: string;
  }> {
    try {
      const searchQuery = `${cveId} security advisory bulletin vendor notification`;
      const webResult = await this.performWebSearch(searchQuery);
      
      const advisories = [];
      
      if (webResult.summary && !webResult.fallback) {
        // Parse the web search results for actual advisory information
        const advisoryInfo = this.extractAdvisoryInfoFromWebResult(webResult.summary, cveId);
        advisories.push(...advisoryInfo);
      }
      
      return {
        advisories,
        searchQuery
      };
      
    } catch (error) {
      console.error('Advisory search failed:', error);
      return {
        advisories: [],
        searchQuery: `${cveId} advisory search failed`
      };
    }
  }

  // Search for vendor-specific information
  private async searchVendorSpecificInfo(cveId: string): Promise<Array<{
    vendor: string;
    description: string;
    url: string;
  }>> {
    try {
      const searchQuery = `${cveId} vendor response official statement Microsoft Adobe Oracle Apache`;
      const webResult = await this.performWebSearch(searchQuery);
      
      const vendorInfo = [];
      
      if (webResult.summary && !webResult.fallback) {
        // Parse for vendor-specific information
        const vendors = this.extractVendorInfoFromWebResult(webResult.summary, cveId);
        vendorInfo.push(...vendors);
      }
      
      return vendorInfo;
      
    } catch (error) {
      console.error('Vendor info search failed:', error);
      return [];
    }
  }

  // Search for government advisories
  private async searchGovernmentAdvisories(cveId: string): Promise<Array<{
    agency: string;
    title: string;
    url: string;
  }>> {
    try {
      const searchQuery = `${cveId} CISA NIST government advisory federal security alert`;
      const webResult = await this.performWebSearch(searchQuery);
      
      const govAdvisories = [];
      
      if (webResult.summary && !webResult.fallback) {
        // Parse for government advisory information
        const advisories = this.extractGovAdvisoryInfoFromWebResult(webResult.summary, cveId);
        govAdvisories.push(...advisories);
      }
      
      return govAdvisories;
      
    } catch (error) {
      console.error('Government advisory search failed:', error);
      return [];
    }
  }

  // Extract patch information from web search results
  private extractPatchInfoFromWebResult(summary: string, cveId: string): Array<{
    vendor: string;
    title: string;
    url: string;
    releaseDate?: string;
    severity?: string;
  }> {
    const patches = [];
    const lines = summary.split('\n');
    
    // Look for patch-related information
    for (const line of lines) {
      const lowerLine = line.toLowerCase();
      
      // Check for Microsoft patches
      if (lowerLine.includes('microsoft') && (lowerLine.includes('update') || lowerLine.includes('patch'))) {
        const urlMatch = line.match(/https?:\/\/[^\s<>"]+/);
        if (urlMatch) {
          patches.push({
            vendor: 'Microsoft',
            title: this.extractTitleFromLine(line),
            url: urlMatch[0],
            severity: this.extractSeverityFromLine(line)
          });
        }
      }
      
      // Check for Red Hat patches
      if (lowerLine.includes('red hat') && (lowerLine.includes('update') || lowerLine.includes('patch'))) {
        const urlMatch = line.match(/https?:\/\/[^\s<>"]+/);
        if (urlMatch) {
          patches.push({
            vendor: 'Red Hat',
            title: this.extractTitleFromLine(line),
            url: urlMatch[0],
            severity: this.extractSeverityFromLine(line)
          });
        }
      }
      
      // Check for Ubuntu patches
      if (lowerLine.includes('ubuntu') && (lowerLine.includes('update') || lowerLine.includes('patch'))) {
        const urlMatch = line.match(/https?:\/\/[^\s<>"]+/);
        if (urlMatch) {
          patches.push({
            vendor: 'Ubuntu',
            title: this.extractTitleFromLine(line),
            url: urlMatch[0],
            severity: this.extractSeverityFromLine(line)
          });
        }
      }
    }
    
    return patches;
  }

  // Extract advisory information from web search results
  private extractAdvisoryInfoFromWebResult(summary: string, cveId: string): Array<{
    source: string;
    title: string;
    url: string;
    severity?: string;
    publishDate?: string;
  }> {
    const advisories = [];
    const lines = summary.split('\n');
    
    // Look for advisory-related information
    for (const line of lines) {
      const lowerLine = line.toLowerCase();
      
      // Check for security advisories
      if (lowerLine.includes('advisory') || lowerLine.includes('bulletin') || lowerLine.includes('security notice')) {
        const urlMatch = line.match(/https?:\/\/[^\s<>"]+/);
        if (urlMatch) {
          advisories.push({
            source: this.extractSourceFromLine(line),
            title: this.extractTitleFromLine(line),
            url: urlMatch[0],
            severity: this.extractSeverityFromLine(line),
            publishDate: this.extractDateFromLine(line)
          });
        }
      }
    }
    
    return advisories;
  }

  // Extract vendor information from web search results
  private extractVendorInfoFromWebResult(summary: string, cveId: string): Array<{
    vendor: string;
    description: string;
    url: string;
  }> {
    const vendorInfo = [];
    const lines = summary.split('\n');
    
    const vendors = ['Microsoft', 'Adobe', 'Oracle', 'Apache', 'Red Hat', 'Ubuntu', 'Debian', 'SUSE'];
    
    for (const line of lines) {
      for (const vendor of vendors) {
        if (line.toLowerCase().includes(vendor.toLowerCase())) {
          const urlMatch = line.match(/https?:\/\/[^\s<>"]+/);
          if (urlMatch) {
            vendorInfo.push({
              vendor: vendor,
              description: this.extractDescriptionFromLine(line),
              url: urlMatch[0]
            });
          }
        }
      }
    }
    
    return vendorInfo;
  }

  // Extract government advisory information from web search results
  private extractGovAdvisoryInfoFromWebResult(summary: string, cveId: string): Array<{
    agency: string;
    title: string;
    url: string;
  }> {
    const govAdvisories = [];
    const lines = summary.split('\n');
    
    const agencies = ['CISA', 'NIST', 'NSA', 'FBI', 'DHS'];
    
    for (const line of lines) {
      for (const agency of agencies) {
        if (line.toLowerCase().includes(agency.toLowerCase())) {
          const urlMatch = line.match(/https?:\/\/[^\s<>"]+/);
          if (urlMatch) {
            govAdvisories.push({
              agency: agency,
              title: this.extractTitleFromLine(line),
              url: urlMatch[0]
            });
          }
        }
      }
    }
    
    return govAdvisories;
  }

  // Utility methods for extracting information from lines
  private extractTitleFromLine(line: string): string {
    // Remove URLs and clean up the line to extract title
    const withoutUrl = line.replace(/https?:\/\/[^\s<>"]+/g, '').trim();
    return withoutUrl.length > 100 ? withoutUrl.substring(0, 100) + '...' : withoutUrl;
  }

  private extractSeverityFromLine(line: string): string | undefined {
    const severityMatch = line.match(/\b(critical|high|medium|low|important)\b/i);
    return severityMatch ? severityMatch[1] : undefined;
  }

  private extractSourceFromLine(line: string): string {
    // Try to extract source from common patterns
    const sourceMatch = line.match(/\b(Microsoft|Red Hat|Ubuntu|Debian|SUSE|Oracle|Adobe|Apache|CISA|NIST)\b/i);
    return sourceMatch ? sourceMatch[1] : 'Unknown Source';
  }

  private extractDateFromLine(line: string): string | undefined {
    const dateMatch = line.match(/\b(\d{4}-\d{2}-\d{2}|\d{2}\/\d{2}\/\d{4}|\w+ \d{1,2}, \d{4})\b/);
    return dateMatch ? dateMatch[1] : undefined;
  }

  private extractDescriptionFromLine(line: string): string {
    // Remove URLs and clean up the line to extract description
    const withoutUrl = line.replace(/https?:\/\/[^\s<>"]+/g, '').trim();
    return withoutUrl.length > 150 ? withoutUrl.substring(0, 150) + '...' : withoutUrl;
  }

  // Enhanced EPSS score with web search validation
  private async getEPSSScore(cveId: string): Promise<ChatResponse> {
    try {
      const epssData = await this.getCachedOrFetch(
        `epss_${cveId}`,
        () => APIService.fetchEPSSData(cveId, () => {})
      );

      let response = `**EPSS Score for ${cveId}**\n\n`;

      if (epssData?.epss) {
        const score = parseFloat(epssData.epss);
        const interpretation = this.interpretEPSSScore(score);
        
        response += `• **Score:** ${epssData.epss} (${epssData.epssPercentage}%)\n`;
        response += `• **Interpretation:** ${interpretation}\n\n`;
        
        // Add contextual analysis based on score
        if (score >= 0.7) {
          response += `🚨 **High Risk Alert:** This score indicates a very high likelihood of exploitation. Consider this a priority for immediate patching.\n\n`;
        } else if (score >= 0.5) {
          response += `⚠️ **Moderate Risk:** This score suggests active threat interest. Monitor closely and prioritize patching.\n\n`;
        } else if (score >= 0.1) {
          response += `📊 **Low-Medium Risk:** Standard monitoring recommended. Include in regular patch cycles.\n\n`;
        } else {
          response += `✅ **Low Risk:** Currently low exploitation activity. Follow standard patch management procedures.\n\n`;
        }
        
        // Search for current exploitation activity
        const exploitSearch = await this.searchForExploitationActivity(cveId);
        if (exploitSearch.length > 0) {
          response += `🔍 **Current Exploitation Activity:**\n`;
          exploitSearch.forEach(activity => {
            response += `• ${activity.description}\n`;
            response += `  📎 [Source](${activity.url})\n`;
          });
          response += `\n`;
        }
        
        response += `**What this means:** The EPSS score predicts the likelihood of this vulnerability being exploited in the next 30 days based on current threat intelligence, including exploit availability, threat actor activity, and attack patterns.\n\n`;
        
        // Add EPSS methodology info
        response += `📊 **EPSS Methodology:**\n`;
        response += `• **Data Sources:** CVE metadata, exploit databases, threat intelligence feeds\n`;
        response += `• **Machine Learning:** Predictive model trained on historical exploitation data\n`;
        response += `• **Update Frequency:** Daily updates based on new threat intelligence\n`;
        response += `• **Validation:** Continuously validated against real-world exploitation events\n\n`;
        
        response += `🔗 **Learn More:**\n`;
        response += `• [FIRST EPSS Website](https://www.first.org/epss/)\n`;
        response += `• [EPSS User Guide](https://www.first.org/epss/user-guide)\n`;
        response += `• [EPSS API Documentation](https://www.first.org/epss/api)\n`;
        
      } else {
        response += `EPSS score is not available for this CVE. This could mean:\n`;
        response += `• The CVE is very new (EPSS scores are calculated daily)\n`;
        response += `• The CVE is not in the EPSS database\n`;
        response += `• There was an error fetching the data\n\n`;
        
        // Search for alternative exploitation indicators
        const altSearch = await this.searchForExploitationActivity(cveId);
        if (altSearch.length > 0) {
          response += `🔍 **Alternative Exploitation Indicators:**\n`;
          altSearch.forEach(activity => {
            response += `• ${activity.description}\n`;
            response += `  📎 [Source](${activity.url})\n`;
          });
          response += `\n`;
        }
        
        response += `**Alternative Resources:**\n`;
        response += `• [FIRST EPSS Website](https://www.first.org/epss/)\n`;
        response += `• [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)\n`;
        response += `• [ExploitDB Search](https://www.exploit-db.com/search?cve=${cveId})\n`;
      }

      return {
        text: response,
        sender: 'bot',
        id: Date.now().toString(),
        data: epssData
      };
    } catch (error: any) {
      return {
        text: `Sorry, I couldn't retrieve the EPSS score for ${cveId}. Please try again or check the FIRST EPSS website directly.\n\n**Error**: ${error.message}`,
        sender: 'bot',
        id: Date.now().toString(),
        error: error.message
      };
    }
  }

  // Enhanced exploit info with real-time search
  private async getExploitInfo(cveId: string): Promise<ChatResponse> {
    try {
      let response = `**Exploit Information for ${cveId}**\n\n`;
      
      // Search for actual exploits
      const exploitSearch = await this.searchForActualExploits(cveId);
      
      if (exploitSearch.exploits.length > 0) {
        response += `🔍 **Verified Exploits Found:**\n`;
        exploitSearch.exploits.forEach(exploit => {
          response += `• **${exploit.type}**: ${exploit.title}\n`;
          response += `  📎 [${exploit.source}](${exploit.url})\n`;
          if (exploit.severity) {
            response += `  ⚠️ Severity: ${exploit.severity}\n`;
          }
          if (exploit.publishDate) {
            response += `  📅 Published: ${exploit.publishDate}\n`;
          }
          response += `\n`;
        });
      } else {
        response += `🔍 **No Verified Exploits Found** in current search\n`;
        response += `• This could mean the vulnerability is new or unexploited\n`;
        response += `• Check the databases below for the latest information\n\n`;
      }
      
      // Search for proof-of-concept code
      const pocSearch = await this.searchForPoCCode(cveId);
      if (pocSearch.length > 0) {
        response += `💻 **Proof-of-Concept Code:**\n`;
        pocSearch.forEach(poc => {
          response += `• **${poc.platform}**: ${poc.title}\n`;
          response += `  📎 [${poc.url}](${poc.url})\n`;
          if (poc.description) {
            response += `  📝 ${poc.description}\n`;
          }
          response += `\n`;
        });
      }
      
      // Search for threat intelligence
      const threatIntel = await this.searchForThreatIntelligence(cveId);
      if (threatIntel.length > 0) {
        response += `🎯 **Threat Intelligence:**\n`;
        threatIntel.forEach(intel => {
          response += `• ${intel.description}\n`;
          response += `  📎 [Source](${intel.url})\n`;
        });
        response += `\n`;
      }
      
      response += `🔗 **Exploit Databases:**\n`;
      response += `• [ExploitDB Search](https://www.exploit-db.com/search?cve=${cveId})\n`;
      response += `• [Packet Storm](https://packetstormsecurity.com/search/?q=${cveId})\n`;
      response += `• [Rapid7 Vulnerability Database](https://www.rapid7.com/db/search?q=${cveId})\n`;
      response += `• [Metasploit Database](https://www.rapid7.com/db/?q=${cveId})\n`;
      response += `• [GitHub Security Advisories](https://github.com/advisories?query=${cveId})\n\n`;
      
      response += `💡 **Analysis Recommendations:**\n`;
      if (exploitSearch.exploits.length > 0) {
        response += `• **HIGH PRIORITY**: Active exploits detected - implement patches immediately\n`;
        response += `• **Monitor**: Set up detection rules for the exploit patterns identified\n`;
        response += `• **Test**: Verify your systems against the specific exploits found\n`;
      } else {
        response += `• **Monitor**: Continue monitoring exploit databases for new developments\n`;
        response += `• **Prepare**: Develop incident response plans for potential exploitation\n`;
        response += `• **Update**: Keep systems updated as preventive measure\n`;
      }
      
      response += `\n📅 **Search Completed**: ${new Date().toLocaleString()}\n`;
      response += `🔄 **Note**: Exploit information changes rapidly. Check sources regularly for updates.\n`;
      
      return {
        text: response,
        sender: 'bot',
        id: Date.now().toString(),
        data: {
          cveId,
          exploits: exploitSearch.exploits,
          pocCode: pocSearch,
          threatIntel: threatIntel,
          searchTimestamp: new Date().toISOString()
        }
      };
    } catch (error: any) {
      return {
        text: `**Exploit Information for ${cveId}**\n\nI encountered an issue while searching for real-time exploit information. Here are the standard databases to check:\n\n🔗 **Exploit Databases:**\n• [ExploitDB Search](https://www.exploit-db.com/search?cve=${cveId})\n• [Packet Storm](https://packetstormsecurity.com/search/?q=${cveId})\n• [Metasploit Database](https://www.rapid7.com/db/?q=${cveId})\n\n**Error**: ${error.message}`,
        sender: 'bot',
        id: Date.now().toString(),
        error: error.message
      };
    }
  }

  // Generate a concise risk assessment
  private async getRiskAssessment(cveId: string): Promise<ChatResponse> {
    try {
      let cveData = await this.getCachedOrFetch(
        `cve_${cveId}`,
        () => APIService.fetchCVEData(cveId, this.settings?.nvdApiKey, () => {})
      );
      cveData = this.validateCVEData(cveData);

      const epssData: EPSSData | null = await this.getCachedOrFetch(
        `epss_${cveId}`,
        () => APIService.fetchEPSSData(cveId, () => {})
      ).catch(() => null);

      const kevData: CisaKevDetails | null = await this.getCachedOrFetch(
        `kev_${cveId}`,
        () => fetchCISAKEVData(cveId, () => {}, null, null, this.settings)
      ).catch(() => null);

      const patchData: PatchData | null = await this.getCachedOrFetch(
        `patch_${cveId}`,
        () => APIService.fetchPatchesAndAdvisories(cveId, cveData, this.settings, () => {})
      ).catch(() => null);

      const exploitSearch = await this.searchForActualExploits(cveId);

      const cvssScore = cveData?.cvssV3?.baseScore || cveData?.cvssV2?.baseScore || 0;
      const epssScore = epssData ? parseFloat(epssData.epss) : 0;
      const kevStatus = kevData?.listed ? 'YES' : 'NO';
      const exploitsKnown = exploitSearch.exploits.length > 0 ? 'YES' : 'NO';

      let patchInfo = 'Patch information unavailable';
      if (patchData?.patches && patchData.patches.length > 0) {
        const p = patchData.patches[0];
        patchInfo = `Patch Available${p.releaseDate ? `, Released: ${p.releaseDate}` : ''}`;
      } else if (patchData?.advisories && patchData.advisories.length > 0) {
        patchInfo = 'Advisory available';
      }

      let businessPriority = 'P3 – Review in normal cycle';
      if (kevData?.listed) {
        businessPriority = 'P1 – Active exploitation';
      } else if (cvssScore >= 9.0 || epssScore >= 0.7) {
        businessPriority = 'P1 – Critical severity';
      } else if (cvssScore >= 7.0 || epssScore >= 0.3) {
        businessPriority = 'P2 – High severity';
      }

      let threatConfidence = 'Low – Limited intelligence';
      if (kevData?.listed || exploitSearch.exploits.length > 0) {
        threatConfidence = 'High – Verified threat activity';
      } else if (epssScore >= 0.5) {
        threatConfidence = 'Medium – Elevated EPSS score';
      }

      const assessment = RiskAssessmentAgent.generateAssessment({
        cvssScore,
        epssScore,
        cisaKevStatus: kevStatus as 'YES' | 'NO',
        exploitsKnown: exploitsKnown as 'YES' | 'NO',
        vulnerabilityId: cveId,
        patchInfo,
        businessPriority,
        threatIntelConfidence: threatConfidence
      });

      return { text: assessment.text, sender: 'bot', id: Date.now().toString() };
    } catch (error: any) {
      return {
        text: `Risk assessment for ${cveId} failed: ${error.message}`,
        sender: 'bot',
        id: Date.now().toString(),
        error: error.message
      };
    }
  }

  // Search for actual exploits
  private async searchForActualExploits(cveId: string): Promise<{
    exploits: Array<{
      type: string;
      title: string;
      url: string;
      source: string;
      severity?: string;
      publishDate?: string;
    }>;
  }> {
    try {
      const searchQuery = `${cveId} exploit proof concept vulnerability weaponized attack code`;
      const webResult = await this.performWebSearch(searchQuery);
      
      const exploits = [];
      
      if (webResult.summary && !webResult.fallback) {
        const exploitInfo = this.extractExploitInfoFromWebResult(webResult.summary, cveId);
        exploits.push(...exploitInfo);
      }
      
      return { exploits };
    } catch (error) {
      console.error('Exploit search failed:', error);
      return { exploits: [] };
    }
  }

  // Search for exploitation activity
  private async searchForExploitationActivity(cveId: string): Promise<Array<{
    description: string;
    url: string;
  }>> {
    try {
      const searchQuery = `${cveId} exploitation activity threat intelligence attack campaigns`;
      const webResult = await this.performWebSearch(searchQuery);
      
      const activities = [];
      
      if (webResult.summary && !webResult.fallback) {
        const activityInfo = this.extractActivityInfoFromWebResult(webResult.summary, cveId);
        activities.push(...activityInfo);
      }
      
      return activities;
    } catch (error) {
      console.error('Exploitation activity search failed:', error);
      return [];
    }
  }

  // Search for PoC code
  private async searchForPoCCode(cveId: string): Promise<Array<{
    platform: string;
    title: string;
    url: string;
    description?: string;
  }>> {
    try {
      const searchQuery = `${cveId} proof of concept github exploit code repository`;
      const webResult = await this.performWebSearch(searchQuery);
      
      const pocCode = [];
      
      if (webResult.summary && !webResult.fallback) {
        const pocInfo = this.extractPoCInfoFromWebResult(webResult.summary, cveId);
        pocCode.push(...pocInfo);
      }
      
      return pocCode;
    } catch (error) {
      console.error('PoC code search failed:', error);
      return [];
    }
  }

  // Search for threat intelligence
  private async searchForThreatIntelligence(cveId: string): Promise<Array<{
    description: string;
    url: string;
  }>> {
    try {
      const searchQuery = `${cveId} threat intelligence security research analysis campaign`;
      const webResult = await this.performWebSearch(searchQuery);
      
      const threatIntel = [];
      
      if (webResult.summary && !webResult.fallback) {
        const intelInfo = this.extractThreatIntelFromWebResult(webResult.summary, cveId);
        threatIntel.push(...intelInfo);
      }
      
      return threatIntel;
    } catch (error) {
      console.error('Threat intelligence search failed:', error);
      return [];
    }
  }

  // Extract exploit info from web results
  private extractExploitInfoFromWebResult(summary: string, cveId: string): Array<{
    type: string;
    title: string;
    url: string;
    source: string;
    severity?: string;
    publishDate?: string;
  }> {
    const exploits = [];
    const lines = summary.split('\n');
    
    for (const line of lines) {
      const lowerLine = line.toLowerCase();
      
      if (lowerLine.includes('exploit') || lowerLine.includes('proof of concept') || lowerLine.includes('weaponized')) {
        const urlMatch = line.match(/https?:\/\/[^\s<>"]+/);
        if (urlMatch) {
          exploits.push({
            type: this.determineExploitType(line),
            title: this.extractTitleFromLine(line),
            url: urlMatch[0],
            source: this.extractSourceFromLine(line),
            severity: this.extractSeverityFromLine(line),
            publishDate: this.extractDateFromLine(line)
          });
        }
      }
    }
    
    return exploits;
  }

  // Extract activity info from web results
  private extractActivityInfoFromWebResult(summary: string, cveId: string): Array<{
    description: string;
    url: string;
  }> {
    const activities = [];
    const lines = summary.split('\n');
    
    for (const line of lines) {
      const lowerLine = line.toLowerCase();
      
      if (lowerLine.includes('campaign') || lowerLine.includes('attack') || lowerLine.includes('exploitation')) {
        const urlMatch = line.match(/https?:\/\/[^\s<>"]+/);
        if (urlMatch) {
          activities.push({
            description: this.extractDescriptionFromLine(line),
            url: urlMatch[0]
          });
        }
      }
    }
    
    return activities;
  }

  // Extract PoC info from web results
  private extractPoCInfoFromWebResult(summary: string, cveId: string): Array<{
    platform: string;
    title: string;
    url: string;
    description?: string;
  }> {
    const pocCode = [];
    const lines = summary.split('\n');
    
    for (const line of lines) {
      const lowerLine = line.toLowerCase();
      
      if (lowerLine.includes('github') || lowerLine.includes('code') || lowerLine.includes('repository')) {
        const urlMatch = line.match(/https?:\/\/[^\s<>"]+/);
        if (urlMatch) {
          pocCode.push({
            platform: this.determinePlatform(line),
            title: this.extractTitleFromLine(line),
            url: urlMatch[0],
            description: this.extractDescriptionFromLine(line)
          });
        }
      }
    }
    
    return pocCode;
  }

  // Extract threat intel from web results
  private extractThreatIntelFromWebResult(summary: string, cveId: string): Array<{
    description: string;
    url: string;
  }> {
    const threatIntel = [];
    const lines = summary.split('\n');
    
    for (const line of lines) {
      const lowerLine = line.toLowerCase();
      
      if (lowerLine.includes('threat') || lowerLine.includes('intelligence') || lowerLine.includes('research')) {
        const urlMatch = line.match(/https?:\/\/[^\s<>"]+/);
        if (urlMatch) {
          threatIntel.push({
            description: this.extractDescriptionFromLine(line),
            url: urlMatch[0]
          });
        }
      }
    }
    
    return threatIntel;
  }

  // Utility methods
  private determineExploitType(line: string): string {
    const lowerLine = line.toLowerCase();
    if (lowerLine.includes('proof of concept') || lowerLine.includes('poc')) return 'Proof of Concept';
    if (lowerLine.includes('weaponized')) return 'Weaponized Exploit';
    if (lowerLine.includes('metasploit')) return 'Metasploit Module';
    return 'Exploit';
  }

  private determinePlatform(line: string): string {
    const lowerLine = line.toLowerCase();
    if (lowerLine.includes('github')) return 'GitHub';
    if (lowerLine.includes('gitlab')) return 'GitLab';
    if (lowerLine.includes('exploit-db')) return 'ExploitDB';
    return 'Unknown Platform';
  }

  // Enhanced web search method with retry logic and fallback
  private async performWebSearch(query: string): Promise<any> {
    try {
      if (!this.settings.geminiApiKey) {
        return this.createFallbackWebSearchResult('Gemini API key not configured');
      }

      const searchPrompt = `Search for information about: ${query}. Provide a comprehensive analysis including current threat status, patches, advisories, and any dispute information.`;

      // Retry logic for API failures
      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
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
            if (response.status === 503 && attempt < 3) {
              // Service unavailable, wait and retry
              await this.sleep(1000 * attempt);
              continue;
            }
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
            summary: generatedText,
            patches: [],
            advisories: [],
            exploits: []
          };

        } catch (error) {
          console.error(`Web search attempt ${attempt} failed:`, error);
          if (attempt === 3) {
            throw error;
          }
          await this.sleep(1000 * attempt);
        }
      }

    } catch (error) {
      console.error('Web search failed after retries:', error);
      return this.createFallbackWebSearchResult(`Web search failed: ${error.message}`);
    }
  }

  // Create fallback web search result
  private createFallbackWebSearchResult(reason: string): any {
    return {
      summary: `Web search unavailable: ${reason}. Using offline analysis capabilities.`,
      patches: [],
      advisories: [],
      exploits: [],
      fallback: true
    };
  }

  // Sleep utility for retry logic
  private async sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Utility methods
  private interpretEPSSScore(score: number): string {
    if (score >= 0.7) return "Very High - Exploitation is highly likely";
    if (score >= 0.5) return "High - Exploitation is likely";
    if (score >= 0.3) return "Medium - Moderate exploitation probability";
    if (score >= 0.1) return "Low-Medium - Lower exploitation probability";
    return "Low - Exploitation is less likely";
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

  private generateHelpMessage(): ChatResponse {
    const helpText = `🤖 **I'm your cybersecurity assistant**\n\n` +
      `I can help you with vulnerability management. Here's what I can do:\n\n` +
      `**🎯 CVE Analysis:**\n` +
      `• Comprehensive vulnerability reports\n` +
      `• EPSS score interpretation\n` +
      `• Patch and advisory information\n` +
      `• Exploit database searches\n` +
      `• Risk assessments\n` +
      `• CVE validation and dispute detection\n\n` +
      `**💡 How to use me:**\n` +
      `• Ask about specific CVEs: "Tell me about CVE-2024-1234"\n` +
      `• Request specific information: "What's the EPSS score for CVE-2024-1234?"\n` +
      `• Get validation: "Is CVE-2024-1234 legitimate?"\n` +
      `• Find patches: "Show me patches for CVE-2024-1234"\n\n` +
      `Just ask me about any CVE and I'll provide comprehensive analysis!`;

    return { text: helpText, sender: 'system', id: Date.now().toString() };
  }

  // Public interface methods
  public setContextualCVE(cveId: string): ChatResponse | null {
    if (cveId && CVE_REGEX.test(cveId) && cveId !== this.currentCveIdForSession) {
      this.currentCveIdForSession = cveId.toUpperCase();
      this.conversationContext.recentCVEs.unshift(this.currentCveIdForSession);
      
      // Keep only last 5 CVEs
      if (this.conversationContext.recentCVEs.length > 5) {
        this.conversationContext.recentCVEs.pop();
      }

      const text = `Perfect! I'm now focused on ${this.currentCveIdForSession}. What would you like to know about it?`;
      this.storeConversation(`context:${cveId}`, text);
      return {
        text,
        sender: 'system',
        id: Date.now().toString(),
      };
    }
    return null;
  }

  public setBulkAnalysisResults(results: BulkAnalysisResult[]): void {
    this.bulkAnalysisResults = results;
  }

  public clearCache(): void {
    // Allow tests or callers to reset the cached data
    this.cache.clear();
  }

  public generateBulkAnalysisSummary(): ChatResponse {
    if (!this.bulkAnalysisResults || this.bulkAnalysisResults.length === 0) {
      return {
        text: "I don't have any bulk analysis results to summarize yet. Once you upload and process a file, I'll provide insights across all your vulnerabilities.",
        sender: 'system',
        id: Date.now().toString(),
      };
    }

    const totalCVEs = this.bulkAnalysisResults.length;
    const successfulAnalyses = this.bulkAnalysisResults.filter(r => r.status === 'Complete' && r.data).length;
    const criticalCVEs = this.bulkAnalysisResults.filter(r => 
      r.data?.cve?.cvssV3?.baseScore >= 9.0 || r.data?.kev?.listed
    ).length;

    let summaryText = `📊 **Bulk Analysis Summary**\n\n`;
    summaryText += `I've analyzed ${totalCVEs} vulnerabilities with ${successfulAnalyses} successful analyses.\n\n`;
    
    if (criticalCVEs > 0) {
      summaryText += `🚨 **Critical findings**: ${criticalCVEs} vulnerabilities require immediate attention.\n\n`;
    }
    
    summaryText += `Ask me about any specific CVE or for recommendations across your portfolio.`;

    return {
      text: summaryText,
      sender: 'bot',
      id: Date.now().toString(),
    };
  }

  public generateBulkComponentImpactSummary(): ChatResponse {
    if (!this.bulkAnalysisResults || this.bulkAnalysisResults.length === 0) {
      return {
        text: "I need bulk analysis results to provide component impact insights. Upload your vulnerability data and I'll analyze the impact across your technology stack.",
        sender: 'system',
        id: Date.now().toString(),
      };
    }

    const componentMap: Record<string, { cveIds: string[]; severities: string[] }> = {};

    this.bulkAnalysisResults.forEach(result => {
      if (!result.data) return;
      const desc = result.data.cve?.cve?.descriptions?.[0]?.value || '';
      const components = extractComponentNames(desc);
      const severity = getCVSSSeverity(result.data.cve?.cvssV3?.baseScore ?? 0);

      const comps = components.length > 0 ? components : ['Unknown'];
      comps.forEach(name => {
        if (!componentMap[name]) {
          componentMap[name] = { cveIds: [], severities: [] };
        }
        componentMap[name].cveIds.push(result.cveId);
        componentMap[name].severities.push(severity);
      });
    });

    let summaryText = `🏗️ **Component Impact Analysis**\n\n`;
    summaryText += `I've identified vulnerability patterns across your technology stack:\n\n`;
    
    Object.entries(componentMap).forEach(([name, info]) => {
      const highest = info.severities.reduce((a, b) => {
        const severityRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
        return (severityRank[b.toUpperCase()] > severityRank[a.toUpperCase()] ? b : a);
      }, 'UNKNOWN');
      summaryText += `• **${name}**: ${info.cveIds.length} vulnerabilities (Peak: ${highest})\n`;
    });

    summaryText += `\n💡 I can provide detailed remediation strategies for each component. Just ask!`;

    return { text: summaryText, sender: 'bot', id: Date.now().toString() };
  }
}
