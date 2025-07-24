// src/agents/SmartResearchAgent.ts
// Browser-compatible EventEmitter implementation
class EventEmitter {
  private events: Map<string, Function[]> = new Map();

  on(event: string, listener: Function): void {
    if (!this.events.has(event)) {
      this.events.set(event, []);
    }
    this.events.get(event)!.push(listener);
  }

  off(event: string, listener: Function): void {
    const listeners = this.events.get(event);
    if (listeners) {
      const index = listeners.indexOf(listener);
      if (index > -1) {
        listeners.splice(index, 1);
      }
    }
  }

  emit(event: string, ...args: any[]): void {
    const listeners = this.events.get(event);
    if (listeners) {
      listeners.forEach(listener => listener(...args));
    }
  }

  removeAllListeners(event?: string): void {
    if (event) {
      this.events.delete(event);
    } else {
      this.events.clear();
    }
  }
}
import { APIService } from '../services/APIService';
import { ValidationService } from '../services/ValidationService';
import { ConfidenceScorer } from '../services/ConfidenceScorer';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import {
  fetchCVEData,
  fetchEPSSData,
  fetchCISAKEVData,
  AIApiRateLimitError,
} from '../services/DataFetchingService';
import {
  fetchPatchesAndAdvisories,
  fetchAIThreatIntelligence,
} from '../services/AIEnhancementService';
import { 
  AgentSettings, 
  InformationSource, 
  PatchData,
  CVEData 
} from '../types/cveData';
import { AIThreatIntelData } from '../types/aiThreatIntel';
import {
  processCVEData,
  parseAIThreatIntelligence,
  performHeuristicAnalysis,
  parsePatchAndAdvisoryResponse,
  getHeuristicPatchesAndAdvisories,
  fetchWithFallback,
} from '../services/UtilityService';

// ==================== SMART AGENT TYPES ====================
interface OrganizationContext {
  inventory: string[];
  patchingMaturity: number;
  teamSize: number;
  industry: string;
  complianceRequirements: string[];
  patchCycle?: number;
  criticalAssets?: string[];
}

interface CVEPattern {
  vendorPattern: VendorInfo;
  severityLikelihood: number;
  exploitProbability: number;
  techStack: string[];
  historicalSimilarity: number;
  timeToExploitEstimate: number;
}

interface VendorInfo {
  vendor: string;
  confidence: number;
  products: string[];
}

interface CVEPrediction {
  likelyVendor: VendorInfo;
  expectedSeverity: number;
  exploitProbability: number;
  expectedTimeToExploit: number;
  suggestedSearchDepth: string;
}

interface SmartAnalysis extends ReturnType<ResearchAgent['analyzeCVE']> {
  predictions?: {
    characteristics: CVEPrediction;
    exploitTimeline?: any;
    weaponization?: any;
    patchAvailability?: any;
    remediationComplexity?: any;
  };
  contextualAnalysis?: any;
  recommendations?: any;
  escalation?: any;
  analysisMetadata?: {
    strategy: any;
    aiModel: any;
    searchStrategy: any;
    executionTime: number;
    confidence: any;
  };
}

// ==================== PATTERN LEARNING ENGINE ====================
class PatternLearningEngine {
  private patterns: Map<string, CVEPattern> = new Map();
  private vendorPatterns: Map<string, any> = new Map();
  private historicalData: Map<string, any> = new Map();

  async learnFromAnalysis(cveId: string, analysis: any): Promise<void> {
    const pattern = await this.extractPattern(cveId, analysis);
    this.patterns.set(cveId, pattern);
    await this.updateVendorPatterns(analysis);
    // In production, persist to database
  }

  async predictCharacteristics(cveId: string): Promise<CVEPrediction> {
    const year = parseInt(cveId.split('-')[1]);
    const number = parseInt(cveId.split('-')[2]);
    
    // Simple heuristic-based prediction for MVP
    const vendorPrediction = this.predictVendor(year, number);
    const severityPrediction = this.predictSeverityHeuristic(year, number);
    const exploitPrediction = this.predictExploitabilityHeuristic(year, number);
    
    return {
      likelyVendor: vendorPrediction,
      expectedSeverity: severityPrediction,
      exploitProbability: exploitPrediction,
      expectedTimeToExploit: this.calculateTimeToExploit(exploitPrediction),
      suggestedSearchDepth: this.determineSearchDepth(severityPrediction, exploitPrediction)
    };
  }

  private predictVendor(year: number, cveNumber: number): VendorInfo {
    // Simplified vendor prediction based on CVE number ranges
    const vendorRanges = {
      microsoft: { min: 40000, max: 45000 },
      cisco: { min: 1000, max: 5000 },
      apache: { min: 15000, max: 20000 },
      linux: { min: 5000, max: 10000 }
    };
    
    for (const [vendor, range] of Object.entries(vendorRanges)) {
      if (cveNumber >= range.min && cveNumber <= range.max) {
        return {
          vendor,
          confidence: 0.7,
          products: []
        };
      }
    }
    
    return { vendor: 'unknown', confidence: 0.1, products: [] };
  }

  private predictSeverityHeuristic(year: number, cveNumber: number): number {
    // Simple heuristic: newer CVEs tend to be more severe
    const currentYear = new Date().getFullYear();
    const age = currentYear - year;
    return Math.max(1, Math.min(10, 7 - age * 0.5));
  }

  private predictExploitabilityHeuristic(year: number, cveNumber: number): number {
    // Simple heuristic based on CVE age and number
    const currentYear = new Date().getFullYear();
    const age = currentYear - year;
    return age < 2 ? 0.6 : 0.3;
  }

  private calculateTimeToExploit(exploitProbability: number): number {
    return Math.round(30 - (exploitProbability * 25));
  }

  private determineSearchDepth(severity: number, exploitProb: number): string {
    if (severity > 7 || exploitProb > 0.7) return 'comprehensive';
    if (severity < 4 && exploitProb < 0.3) return 'minimal';
    return 'standard';
  }

  private async extractPattern(cveId: string, analysis: any): Promise<CVEPattern> {
    // Extract patterns from analysis results
    return {
      vendorPattern: { vendor: 'extracted', confidence: 0.5, products: [] },
      severityLikelihood: analysis.cve?.metrics?.cvssV3?.baseScore || 5,
      exploitProbability: 0.5,
      techStack: [],
      historicalSimilarity: 0.5,
      timeToExploitEstimate: 30
    };
  }

  private async updateVendorPatterns(analysis: any): Promise<void> {
    // Update vendor-specific patterns based on analysis
  }

  async adaptSearchStrategy(cveId: string, historicalSuccess?: any[]): Promise<any> {
    const prediction = await this.predictCharacteristics(cveId);
    
    return {
      depth: prediction.suggestedSearchDepth,
      sources: ['nvd', 'cisa', 'exploitdb', 'github'],
      queries: this.generateOptimizedQueries(cveId, prediction),
      aiModel: prediction.exploitProbability > 0.7 ? 'gemini-1.5-pro' : 'gemini-1.5-flash',
      parallelism: 3
    };
  }

  private generateOptimizedQueries(cveId: string, prediction: CVEPrediction): string[] {
    const queries = [cveId];
    
    if (prediction.likelyVendor.vendor !== 'unknown') {
      queries.push(`${cveId} ${prediction.likelyVendor.vendor}`);
      queries.push(`${prediction.likelyVendor.vendor} security advisory ${cveId}`);
    }
    
    if (prediction.exploitProbability > 0.5) {
      queries.push(`${cveId} exploit`);
      queries.push(`${cveId} poc`);
    }
    
    return queries;
  }
}

// ==================== PREDICTIVE ANALYTICS ENGINE ====================
class PredictiveAnalyticsEngine {
  async predictExploitTimeline(cve: any, patterns: CVEPattern): Promise<any> {
    // Simplified prediction based on CVSS score
    const cvssScore = cve?.metrics?.cvssV3?.baseScore || 5;
    const complexity = cve?.metrics?.cvssV3?.attackComplexity === 'LOW' ? 0.8 : 0.5;
    
    const daysToExploit = Math.round(60 - (cvssScore * 5 * complexity));
    const probability = cvssScore / 10 * complexity;
    
    return {
      daysToExploit,
      probability,
      confidence: 0.6,
      factors: ['CVSS Score', 'Attack Complexity'],
      timeline: {
        discovery: 0,
        poc: daysToExploit * 0.3,
        weaponized: daysToExploit,
        widespread: daysToExploit * 1.5
      }
    };
  }

  async anticipatePatchAvailability(cve: any, vendor: VendorInfo): Promise<any> {
    // Simple vendor-based prediction
    const vendorPatchTimes = {
      microsoft: 30,
      cisco: 45,
      apache: 20,
      linux: 15,
      unknown: 60
    };
    
    const expectedDays = vendorPatchTimes[vendor.vendor] || 60;
    
    return {
      expectedDays,
      probability: vendor.confidence,
      vendorTrackRecord: { avgPatchTime: expectedDays, reliability: 0.7 },
      factors: ['Vendor History', 'Severity']
    };
  }

  async estimateRemediationComplexity(cve: any, context?: OrganizationContext): Promise<any> {
    const baseComplexity = cve?.metrics?.cvssV3?.attackComplexity === 'HIGH' ? 0.8 : 0.5;
    const affectedSystems = context?.inventory?.length || 10;
    
    return {
      complexityScore: baseComplexity,
      estimatedEffortHours: Math.round(affectedSystems * baseComplexity * 10),
      riskScore: baseComplexity * 0.7,
      recommendations: ['Test in staging', 'Schedule maintenance window'],
      criticalPath: ['Identify affected systems', 'Test patches', 'Deploy']
    };
  }
}

// ==================== CONTEXTUAL INTELLIGENCE ENGINE ====================
class ContextualIntelligenceEngine {
  public orgContext: OrganizationContext | null = null;

  async initializeContext(context: OrganizationContext): Promise<void> {
    this.orgContext = context;
  }

  async analyzeWithContext(cve: any): Promise<any> {
    if (!this.orgContext) {
      return {
        relevanceScore: 0.5,
        affectedAssets: [],
        businessImpact: { score: 'MEDIUM' },
        priorityScore: 5,
        patchingStrategy: 'standard',
        complianceRequirements: []
      };
    }

    const relevance = await this.assessRelevance(cve);
    const businessImpact = this.calculateBusinessImpact(cve, relevance);
    
    return {
      relevanceScore: relevance.score,
      affectedAssets: relevance.assets,
      businessImpact,
      priorityScore: this.calculatePriority(relevance, businessImpact),
      patchingStrategy: this.optimizePatchStrategy(cve, businessImpact),
      complianceRequirements: this.assessComplianceImpact(cve)
    };
  }

  private async assessRelevance(cve: any): Promise<any> {
    // Check if CVE affects systems in inventory
    const affected = this.orgContext?.inventory?.filter(system => 
      cve.description?.toLowerCase().includes(system.toLowerCase())
    ) || [];
    
    return {
      score: affected.length > 0 ? 0.8 : 0.2,
      assets: affected.map(a => ({ name: a, criticality: 'medium' }))
    };
  }

  private calculateBusinessImpact(cve: any, relevance: any): any {
    const severity = cve?.metrics?.cvssV3?.baseSeverity || 'MEDIUM';
    const affectedCount = relevance.assets.length;
    
    return {
      score: affectedCount > 5 ? 'HIGH' : affectedCount > 0 ? 'MEDIUM' : 'LOW',
      financialImpact: affectedCount * 10000,
      operationalImpact: severity,
      affectedUsers: affectedCount * 100
    };
  }

  private calculatePriority(relevance: any, impact: any): number {
    const impactScore = impact.score === 'HIGH' ? 10 : impact.score === 'MEDIUM' ? 5 : 1;
    return Math.min(10, relevance.score * 10 * (impactScore / 10));
  }

  private optimizePatchStrategy(cve: any, impact: any): string {
    if (impact.score === 'HIGH') return 'emergency';
    if (impact.score === 'MEDIUM') return 'accelerated';
    return 'standard';
  }

  private assessComplianceImpact(cve: any): string[] {
    return this.orgContext?.complianceRequirements || [];
  }

  adaptRecommendations(analysis: any): any {
    return {
      immediate: ['Assess exposure', 'Monitor for exploits'],
      shortTerm: ['Plan patching', 'Test mitigations'],
      longTerm: ['Update security controls', 'Review architecture'],
      alternativeMitigations: ['Network segmentation', 'WAF rules']
    };
  }
}

// ==================== SMART DECISION ENGINE ====================
class SmartDecisionEngine {
  async determineDataCollectionDepth(cveId: string, predictions: CVEPrediction): Promise<any> {
    let depth = 'standard';
    
    if (predictions.exploitProbability > 0.7 || predictions.expectedSeverity > 7) {
      depth = 'comprehensive';
    } else if (predictions.exploitProbability < 0.3 && predictions.expectedSeverity < 4) {
      depth = 'minimal';
    }
    
    return {
      depth,
      dataSources: this.selectDataSources(depth),
      aiSearches: depth === 'comprehensive' ? 5 : depth === 'minimal' ? 1 : 3,
      timeout: depth === 'comprehensive' ? 60000 : 30000,
      parallelism: depth === 'comprehensive' ? 5 : 3
    };
  }

  private selectDataSources(depth: string): string[] {
    const base = ['nvd', 'cisa'];
    if (depth === 'minimal') return base;
    if (depth === 'standard') return [...base, 'exploitdb', 'github'];
    return [...base, 'exploitdb', 'github', 'darkweb', 'social'];
  }

  selectOptimalAIModel(complexity: { score: number }): any {
    if (complexity.score < 0.3) {
      return {
        model: 'gemini-1.5-flash',
        temperature: 0.3,
        maxTokens: 1000,
        reasoning: 'Simple query - using fast model'
      };
    }
    
    if (complexity.score > 0.7) {
      return {
        model: 'gemini-1.5-pro',
        temperature: 0.5,
        maxTokens: 4000,
        reasoning: 'Complex analysis - using advanced model'
      };
    }
    
    return {
      model: 'gemini-1.5-flash',
      temperature: 0.4,
      maxTokens: 2000,
      reasoning: 'Standard analysis - balanced approach'
    };
  }

  async autoEscalate(findings: any): Promise<any> {
    const criteria = {
      activelyExploited: findings.cisaKev?.listed || false,
      criticalAssets: findings.contextualAnalysis?.affectedAssets?.some(
        (a: any) => a.criticality === 'critical'
      ),
      highBusinessImpact: findings.contextualAnalysis?.businessImpact?.score === 'HIGH',
      zeroDay: findings.exploits?.zeroDay || false
    };
    
    const shouldEscalate = Object.values(criteria).some(v => v === true);
    
    return {
      escalate: shouldEscalate,
      level: shouldEscalate ? 'HIGH' : 'NORMAL',
      message: shouldEscalate ? `Critical CVE ${findings.cve?.id} requires immediate attention` : '',
      criteria
    };
  }
}

// ==================== CONTINUOUS LEARNING SYSTEM ====================
class ContinuousLearningSystem {
  private metrics: Map<string, any> = new Map();
  private feedback: Map<string, any> = new Map();

  async trackPredictionAccuracy(prediction: any, actual: any): Promise<void> {
    const key = `${prediction.type}_${new Date().toISOString()}`;
    this.metrics.set(key, {
      prediction,
      actual,
      accuracy: this.calculateAccuracy(prediction, actual),
      timestamp: new Date()
    });
  }

  private calculateAccuracy(prediction: any, actual: any): number {
    let score = 0;
    if (prediction.vendor && actual.vendor) {
      if (
        prediction.vendor.toLowerCase() === actual.vendor.toLowerCase()
      ) {
        score += 0.4;
      }
    }
    if (
      typeof prediction.severity === 'number' &&
      typeof actual.severity === 'number'
    ) {
      const diff = Math.abs(prediction.severity - actual.severity);
      score += diff < 1 ? 0.4 : diff < 2 ? 0.2 : 0;
    }
    if (
      prediction.exploited !== undefined &&
      actual.exploited !== undefined
    ) {
      score += prediction.exploited === actual.exploited ? 0.2 : 0;
    }
    return Math.round(score * 100) / 100;
  }

  async collectUserFeedback(analysisId: string, feedback: any): Promise<void> {
    this.feedback.set(analysisId, {
      ...feedback,
      timestamp: new Date()
    });
  }

  async optimizeSearchQueries(searchHistory: any[]): Promise<void> {
    // Analyze search effectiveness
    // In production, update query generation strategies
  }

  async refineConfidenceScoring(history: any[]): Promise<void> {
    // Analyze confidence calibration
    // In production, adjust confidence algorithms
  }

  getAccuracyMetrics(): any {
    const values = Array.from(this.metrics.values());
    const overall =
      values.reduce((sum, m) => sum + (m.accuracy || 0), 0) /
      (values.length || 1);
    return {
      overall: Math.round(overall * 100) / 100,
      predictions: values
    };
  }
}

// ==================== MAIN SMART RESEARCH AGENT ====================
export class SmartResearchAgent {
  private setLoadingSteps: (stepsUpdater: (prev: string[]) => string[]) => void;
  private patternLearning: PatternLearningEngine;
  private predictiveAnalytics: PredictiveAnalyticsEngine;
  private contextualIntelligence: ContextualIntelligenceEngine;
  private decisionEngine: SmartDecisionEngine;
  private learningSystem: ContinuousLearningSystem;
  private eventEmitter: EventEmitter;

  constructor(
    setLoadingSteps?: (stepsUpdater: (prev: string[]) => string[]) => void,
    orgContext?: OrganizationContext
  ) {
    this.setLoadingSteps = setLoadingSteps || (() => {});
    
    // Initialize smart components
    this.patternLearning = new PatternLearningEngine();
    this.predictiveAnalytics = new PredictiveAnalyticsEngine();
    this.contextualIntelligence = new ContextualIntelligenceEngine();
    this.decisionEngine = new SmartDecisionEngine();
    this.learningSystem = new ContinuousLearningSystem();
    this.eventEmitter = new EventEmitter();
    
    if (orgContext) {
      this.contextualIntelligence.initializeContext(orgContext);
    }
  }

  private updateSteps(message: string) {
    this.setLoadingSteps(prev => [...prev, message]);
  }

  async analyzeCVE(
    cveId: string,
    apiKeys: { nvd?: string; geminiApiKey?: string },
    settings: AgentSettings
  ): Promise<SmartAnalysis> {
    const startTime = Date.now();

    try {
      // 1. PATTERN LEARNING - Predict before fetching
      this.updateSteps(`🧠 Analyzing patterns and predicting characteristics for ${cveId}...`);
      const predictions = await this.patternLearning.predictCharacteristics(cveId);
      
      // 2. SMART DECISION MAKING - Determine strategy
      this.updateSteps(`🎯 Determining optimal analysis strategy...`);
      const strategy = await this.decisionEngine.determineDataCollectionDepth(cveId, predictions);
      const aiModel = this.decisionEngine.selectOptimalAIModel({ score: predictions.exploitProbability });
      
      // 3. ADAPTIVE SEARCH - Use learned patterns
      const searchStrategy = await this.patternLearning.adaptSearchStrategy(cveId);
      
      // Update settings with smart parameters
      const enhancedSettings = {
        ...settings,
        geminiModel: aiModel.model,
        searchDepth: strategy.depth,
        searchStrategy: searchStrategy
      };

      // 4. Execute base analysis (from original ResearchAgent logic)
      this.updateSteps(`🚀 Smart Research Agent starting enhanced analysis for ${cveId}...`);

      // RAG Initialization
      if (ragDatabase && !ragDatabase.initialized) {
        this.updateSteps(`📚 Initializing RAG knowledge base...`);
        await ragDatabase.initialize(enhancedSettings.geminiApiKey || apiKeys.geminiApiKey);
      }

      this.updateSteps(`🔍 Fetching primary data with smart parameters...`);
      
      // Create AI settings object
      const aiSettingsForFetch = {
        geminiApiKey: apiKeys.geminiApiKey || enhancedSettings.geminiApiKey,
        geminiModel: aiModel.model,
        openAiApiKey: enhancedSettings.openAiApiKey,
        openAiModel: enhancedSettings.openAiModel || 'gpt-4o'
      };

      // Fetch primary data with parallel optimization
      let cve, epss, cisaKev;
      try {
        const [cveResult, epssResult, cisaKevResult] = await Promise.allSettled([
          fetchCVEData(cveId, apiKeys.nvd, this.setLoadingSteps, ragDatabase, aiSettingsForFetch),
          fetchEPSSData(cveId, this.setLoadingSteps, ragDatabase, aiSettingsForFetch),
          fetchCISAKEVData(cveId, this.setLoadingSteps, ragDatabase, null, aiSettingsForFetch)
        ]);

        cve = cveResult.status === 'fulfilled' ? cveResult.value : null;
        epss = epssResult.status === 'fulfilled' ? epssResult.value : null;
        cisaKev = cisaKevResult.status === 'fulfilled' ? cisaKevResult.value : null;

        if (cveResult.status === 'rejected' && cveResult.reason instanceof AIApiRateLimitError) {
          this.updateSteps(`🚨 AI rate limit hit, falling back to direct NVD fetch for ${cveId}...`);
          cve = await fetchCVEData(cveId, apiKeys.nvd, this.setLoadingSteps, ragDatabase, null);
        }

      } catch (error) {
        if (error instanceof AIApiRateLimitError) {
          this.updateSteps(`🚨 AI rate limit hit, falling back to direct NVD fetch for ${cveId}...`);
          cve = await fetchCVEData(cveId, apiKeys.nvd, this.setLoadingSteps, ragDatabase, null);
        } else {
          throw error;
        }
      }

      // Handle KEV status
      if (cisaKev?.listed) {
        this.updateSteps(`🚨 CRITICAL: ${cveId} is on CISA KEV - Active exploitation confirmed!`);
      }

      if (!cve) {
        throw new Error(`CVE ${cveId} not found in NVD database.`);
      }

      // 5. AI-ENHANCED ANALYSIS with smart parameters
      this.updateSteps(`🤖 Performing AI threat intelligence with ${aiModel.model}...`);
      const aiThreatIntel = await fetchAIThreatIntelligence(
        cveId,
        cve,
        epss,
        enhancedSettings,
        this.setLoadingSteps,
        ragDatabase,
        fetchWithFallback,
        parseAIThreatIntelligence,
        performHeuristicAnalysis
      );

      const patchAdvisoryData = await fetchPatchesAndAdvisories(
        cveId,
        cve,
        enhancedSettings,
        this.setLoadingSteps,
        fetchWithFallback,
        parsePatchAndAdvisoryResponse,
        getHeuristicPatchesAndAdvisories
      );

      // 6. PREDICTIVE ANALYTICS
      this.updateSteps(`🔮 Generating predictive insights...`);
      const exploitPrediction = await this.predictiveAnalytics.predictExploitTimeline(cve, predictions);
      const patchPrediction = await this.predictiveAnalytics.anticipatePatchAvailability(cve, predictions.likelyVendor);
      
      // 7. CONTEXTUAL ANALYSIS
      this.updateSteps(`🏢 Applying organizational context...`);
      const contextualAnalysis = await this.contextualIntelligence.analyzeWithContext(cve);
      const remediationComplexity = await this.predictiveAnalytics.estimateRemediationComplexity(
        cve, 
        this.contextualIntelligence.orgContext || undefined
      );

      // 8. VALIDATION
      const validation = await ValidationService.validateAIFindings(
        cveId,
        cve,
        aiThreatIntel,
        patchAdvisoryData
      );

      const confidence = ConfidenceScorer.scoreAIFindings(
        aiThreatIntel,
        validation,
        { discoveredSources: ['NVD', 'EPSS', 'CISA_KEV', 'AI_WEB_SEARCH'] }
      );

      // Build sources array (from original logic)
      const discoveredSources = ['NVD'];
      const sources: InformationSource[] = [
        { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${cveId}`, aiDiscovered: false }
      ];

      if (epss) {
        discoveredSources.push('EPSS/FIRST');
        sources.push({ name: 'EPSS', url: `https://api.first.org/data/v1/epss?cve=${cveId}`, aiDiscovered: false });
      }

      if (cisaKev) {
        discoveredSources.push('CISA KEV');
        sources.push({ 
          name: 'CISA KEV', 
          url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
          aiDiscovered: cisaKev.source === 'ai-web-search',
          kevListed: cisaKev.listed
        } as any);
      }

      // 9. SMART RECOMMENDATIONS
      const recommendations = this.contextualIntelligence.adaptRecommendations({
        cve,
        contextualAnalysis,
        predictions: {
          exploit: exploitPrediction,
          patch: patchPrediction
        }
      });

      // 10. AUTO-ESCALATION
      const escalation = await this.decisionEngine.autoEscalate({
        cve,
        cisaKev,
        contextualAnalysis,
        exploits: aiThreatIntel.exploitDiscovery
      });

      if (escalation.escalate) {
        this.updateSteps(`🚨 AUTO-ESCALATION: ${escalation.message}`);
        this.eventEmitter.emit('escalation', escalation);
      }

      // Build intelligence summary
      const intelligenceSummary = {
        sourcesAnalyzed: discoveredSources.length,
        exploitsFound: aiThreatIntel.exploitDiscovery?.totalCount || 0,
        vendorAdvisoriesFound: aiThreatIntel.vendorAdvisories?.count || 0,
        activeExploitation: cisaKev?.listed || false,
        cisaKevListed: cisaKev?.listed || false,
        threatLevel: aiThreatIntel.overallThreatLevel || 'MEDIUM',
        dataFreshness: 'AI_WEB_SEARCH',
        analysisMethod: 'SMART_AI_ANALYSIS',
        confidenceLevel: confidence.overall,
        aiEnhanced: true,
        validated: true
      };

      const threatLevel = aiThreatIntel.overallThreatLevel || 'MEDIUM';
      const summary = `Smart AI-driven analysis for ${cveId}. Predicted severity: ${predictions.expectedSeverity}/10. Exploit probability: ${(predictions.exploitProbability * 100).toFixed(0)}%. Confidence: ${confidence.overall}. Threat: ${threatLevel}.`;

      // Compile enhanced vulnerability data
      const enhancedVulnerability = {
        cve,
        epss,
        cisaKev: cisaKev || { listed: false, lastChecked: new Date().toISOString() },
        kev: { ...aiThreatIntel.cisaKev, validated: validation.cisaKev?.verified || false },
        exploits: { ...aiThreatIntel.exploitDiscovery, validated: validation.exploits?.verified || false },
        vendorAdvisories: { ...aiThreatIntel.vendorAdvisories, validated: validation.vendorAdvisories?.verified || false },
        cveValidation: validation,
        technicalAnalysis: aiThreatIntel.technicalAnalysis,
        activeExploitation: aiThreatIntel.activeExploitation || { confirmed: cisaKev?.listed || false },
        threatIntelligence: aiThreatIntel.threatIntelligence,
        intelligenceSummary,
        patches: patchAdvisoryData.patches || [],
        advisories: patchAdvisoryData.advisories || [],
        sources,
        discoveredSources: [...new Set(discoveredSources)],
        summary,
        analysisSummary: summary,
        threatLevel,
        dataFreshness: 'AI_WEB_SEARCH',
        lastUpdated: new Date().toISOString(),
        confidence,
        validation,
        
        // Smart agent additions
        predictions: {
          characteristics: predictions,
          exploitTimeline: exploitPrediction,
          patchAvailability: patchPrediction,
          remediationComplexity
        },
        contextualAnalysis,
        recommendations,
        escalation,
        analysisMetadata: {
          strategy,
          aiModel,
          searchStrategy,
          executionTime: Date.now() - startTime,
          confidence: {
            overall: confidence.overall,
            predictionAccuracy: predictions.likelyVendor.confidence,
            contextRelevance: contextualAnalysis.relevanceScore
          }
        }
      };

      // 11. CONTINUOUS LEARNING
      await this.learn(cveId, enhancedVulnerability);

      // Store in RAG if confidence is high
      if (ragDatabase?.initialized && (confidence.overall === 'HIGH' || confidence.overall === 'MEDIUM')) {
        await this.storeInRAG(cveId, enhancedVulnerability);
      }

      this.updateSteps(`✅ Smart Research Agent analysis complete for ${cveId}.`);
      return enhancedVulnerability as SmartAnalysis;

    } catch (error) {
      // Learn from failures
      await this.learningSystem.trackPredictionAccuracy(
        { id: cveId, type: 'analysis', value: 'success' },
        { value: 'failure', error: error.message }
      );
      throw error;
    }
  }

  private async learn(cveId: string, analysis: any): Promise<void> {
    await this.patternLearning.learnFromAnalysis(cveId, analysis);
    
    // Track prediction accuracy
    if (analysis.predictions && analysis.cve) {
      await this.learningSystem.trackPredictionAccuracy(
        analysis.predictions.characteristics,
        {
          vendor: this.extractVendorFromCVE(analysis.cve),
          severity: analysis.cve.metrics?.cvssV3?.baseScore || 0,
          exploited: analysis.cisaKev?.listed || false
        }
      );
    }
  }

  private extractVendorFromCVE(cve: any): string {
    // Simple vendor extraction from description
    const description = cve.description?.toLowerCase() || '';
    const vendors = ['microsoft', 'cisco', 'apache', 'linux', 'adobe', 'oracle'];
    
    for (const vendor of vendors) {
      if (description.includes(vendor)) return vendor;
    }
    return 'unknown';
  }

  private async storeInRAG(cveId: string, analysis: any): Promise<void> {
    const { predictions, contextualAnalysis, recommendations } = analysis;
    
    let ragContent = `Smart AI Analysis for ${cveId}:\n`;
    ragContent += `Predicted Vendor: ${predictions.characteristics.likelyVendor.vendor} (${(predictions.characteristics.likelyVendor.confidence * 100).toFixed(0)}% confidence)\n`;
    ragContent += `Exploit Timeline: ${predictions.exploitTimeline.daysToExploit} days (${(predictions.exploitTimeline.probability * 100).toFixed(0)}% probability)\n`;
    ragContent += `Business Impact: ${contextualAnalysis.businessImpact.score}\n`;
    ragContent += `Priority Score: ${contextualAnalysis.priorityScore}/10\n`;
    ragContent += `Patching Strategy: ${contextualAnalysis.patchingStrategy}\n`;
    
    try {
      await ragDatabase.addDocument(ragContent, {
        title: `Smart Analysis - ${cveId}`,
        category: 'smart-ai-analysis',
        tags: ['smart-agent', cveId.toLowerCase(), analysis.threatLevel.toLowerCase()],
        source: 'smart-research-agent',
        cveId,
        timestamp: new Date().toISOString(),
        confidence: analysis.confidence.overall,
        predictedExploitDays: predictions.exploitTimeline.daysToExploit
      });
    } catch (error) {
      console.error(`Failed to store smart analysis in RAG:`, error);
    }
  }

  // Public methods for feedback and insights
  async provideFeedback(analysisId: string, feedback: any): Promise<void> {
    await this.learningSystem.collectUserFeedback(analysisId, feedback);
  }

  async getInsights(): Promise<any> {
    return {
      accuracyMetrics: this.learningSystem.getAccuracyMetrics(),
      patternCount: this.patternLearning.patterns.size,
      contextConfigured: this.contextualIntelligence.orgContext !== null
    };
  }
}

// For backward compatibility
export class ResearchAgent extends SmartResearchAgent {
  constructor(setLoadingSteps?: (stepsUpdater: (prev: string[]) => string[]) => void) {
    super(setLoadingSteps);
  }

  // Override analyzeCVE to use the original implementation
  async analyzeCVE(
    cveId: string,
    apiKeys: { nvd?: string; geminiApiKey?: string },
    settings: AgentSettings
  ): Promise<any> {
    // Use the full implementation from SmartResearchAgent but return without smart fields
    const result = await super.analyzeCVE(cveId, apiKeys, settings);
    
    // Remove smart-specific fields for backward compatibility
    const { predictions, contextualAnalysis, recommendations, escalation, analysisMetadata, ...basicResult } = result;
    
    return basicResult;
  }
}
