import { APIService } from '../services/APIService';
import { AgentSettings, ChatResponse, BulkAnalysisResult } from '../types/cveData';
import { CVE_REGEX } from '../utils/cveRegex';
import { ragDatabase } from '../db/EnhancedVectorDatabase';

export class CybersecurityAgent {
  private settings: AgentSettings;
  private currentCveIdForSession: string | null = null;
  private bulkAnalysisResults: BulkAnalysisResult[] | null = null;

  constructor(settings?: AgentSettings) {
    this.settings = settings || {};
  }

  public async handleQuery(query: string): Promise<ChatResponse> {
    const cveMatch = query.match(CVE_REGEX);
    const cveId = cveMatch ? cveMatch[0].toUpperCase() : this.currentCveIdForSession;

    if (cveId) {
      this.currentCveIdForSession = cveId;
      return this.handleCveQuery(query, cveId);
    }

    return this.handleGeneralQuery(query);
  }

  private async handleCveQuery(query: string, cveId: string): Promise<ChatResponse> {
    const intent = this.getIntent(query);

    switch (intent) {
      case 'remediation':
        return this.getRemediation(cveId);
      case 'threat_intelligence':
        return this.getThreatIntelligence(cveId);
      case 'related_vulnerabilities':
        return this.getRelatedVulnerabilities(cveId);
      default:
        return this.getComprehensiveReport(cveId);
    }
  }

  private async handleGeneralQuery(query: string): Promise<ChatResponse> {
    try {
      const response = await APIService.fetchGeneralAnswer(query, this.settings);
      return {
        id: Date.now().toString(),
        sender: 'bot',
        text: response.answer,
      };
    } catch (error) {
      return {
        id: Date.now().toString(),
        sender: 'bot',
        text: "I'm sorry, I couldn't process your request. Please try again later.",
        error: true,
      };
    }
  }

  private getIntent(query: string): string {
    const lowerQuery = query.toLowerCase();
    if (lowerQuery.includes('remediate') || lowerQuery.includes('fix') || lowerQuery.includes('patch')) {
      return 'remediation';
    }
    if (lowerQuery.includes('threat') || lowerQuery.includes('exploit')) {
      return 'threat_intelligence';
    }
    if (lowerQuery.includes('related') || lowerQuery.includes('similar')) {
      return 'related_vulnerabilities';
    }
    return 'comprehensive_report';
  }

  private async getRemediation(cveId: string): Promise<ChatResponse> {
    try {
      const vulnerability = await APIService.fetchVulnerabilityDataWithAI(cveId, () => {}, {}, this.settings);
      const response = await APIService.generateRemediationSuggestions(vulnerability, this.settings);
      return {
        id: Date.now().toString(),
        sender: 'bot',
        text: response.suggestions,
      };
    } catch (error) {
      return this.getErrorResponse(error);
    }
  }

  private async getThreatIntelligence(cveId: string): Promise<ChatResponse> {
    try {
      const vulnerability = await APIService.fetchVulnerabilityDataWithAI(cveId, () => {}, {}, this.settings);
      const response = await APIService.fetchAIThreatIntelligence(cveId, vulnerability.cve, vulnerability.epss, this.settings, () => {});
      return {
        id: Date.now().toString(),
        sender: 'bot',
        text: response.summary,
      };
    } catch (error) {
      return this.getErrorResponse(error);
    }
  }

  private async getRelatedVulnerabilities(cveId: string): Promise<ChatResponse> {
    try {
      const vulnerability = await APIService.fetchVulnerabilityDataWithAI(cveId, () => {}, {}, this.settings);
      const response = await APIService.findRelatedVulnerabilities(vulnerability, this.settings);
      return {
        id: Date.now().toString(),
        sender: 'bot',
        text: response.related,
      };
    } catch (error) {
      return this.getErrorResponse(error);
    }
  }

  private async getComprehensiveReport(cveId: string): Promise<ChatResponse> {
    try {
      const vulnerability = await APIService.fetchVulnerabilityDataWithAI(cveId, () => {}, {}, this.settings);
      const response = await APIService.generateAIAnalysis(vulnerability, this.settings.geminiApiKey, this.settings.geminiModel, this.settings);
      return {
        id: Date.now().toString(),
        sender: 'bot',
        text: response.analysis,
      };
    } catch (error) {
      return this.getErrorResponse(error);
    }
  }

  private getErrorResponse(error: any): ChatResponse {
    console.error('CybersecurityAgent Error:', error);
    return {
      id: Date.now().toString(),
      sender: 'bot',
      text: "I'm sorry, I encountered an error while processing your request. Please try again.",
      error: true,
    };
  }

  public setBulkAnalysisResults(results: BulkAnalysisResult[]): void {
    this.bulkAnalysisResults = results;
  }

  public setContextualCVE(cveId: string): ChatResponse | null {
    if (cveId && CVE_REGEX.test(cveId) && cveId !== this.currentCveIdForSession) {
      this.currentCveIdForSession = cveId.toUpperCase();
      return {
        id: Date.now().toString(),
        sender: 'system',
        text: `Now focusing on ${this.currentCveIdForSession}. How can I help?`,
      };
    }
    return null;
  }
}
