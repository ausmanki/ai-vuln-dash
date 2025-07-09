import { ValidationService } from '../services/ValidationService';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { BaseCVEInfo, PatchData, CVEValidationData } from '../types/cveData';
import { AIThreatIntelData } from '../types/aiThreatIntel';

interface ValidationConfig {
  maxRetries?: number;
  retryDelay?: number;
  timeoutMs?: number;
  enableCaching?: boolean;
  batchSize?: number;
  priorityThreshold?: number;
  enableMLEnhancement?: boolean;
  enableCrossValidation?: boolean;
}

interface ValidationMetrics {
  processingTime: number;
  retryCount: number;
  validationScore: number;
  confidenceLevel: number;
  riskScore: number;
  severityLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  falsePositiveScore: number;
  mlEnhancementScore?: number;
}

interface ValidationRule {
  id: string;
  name: string;
  weight: number;
  validator: (data: any) => boolean | Promise<boolean>;
  errorMessage: string;
}

interface ValidationResult extends CVEValidationData {
  metrics: ValidationMetrics;
  cacheHit: boolean;
  processingSteps: string[];
  ruleResults: Array<{ ruleId: string; passed: boolean; message: string }>;
  recommendations: string[];
  relatedCVEs: string[];
  threatActor?: string;
  exploitProbability: number;
  businessImpact: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  patches: PatchRecommendation[];
}

interface PatchRecommendation {
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  estimatedTime: string;
  complexity: 'SIMPLE' | 'MODERATE' | 'COMPLEX';
  dependencies: string[];
  rollbackPlan: string;
}

interface ValidationPipeline {
  stages: ValidationStage[];
  parallel?: boolean;
}

interface ValidationStage {
  name: string;
  validator: (data: any) => Promise<any>;
  required: boolean;
  timeout?: number;
}

interface AlertConfig {
  webhookUrl?: string;
  emailRecipients?: string[];
  slackChannel?: string;
  severityThreshold: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

interface ValidationEvent {
  type: 'started' | 'completed' | 'failed' | 'alert';
  cveId: string;
  timestamp: Date;
  data: any;
}

export class ValidationAgent {
  private setLoadingSteps: (stepsUpdater: (prev: string[]) => string[]) => void;
  private config: ValidationConfig;
  private validationCache = new Map<string, { result: ValidationResult; timestamp: number }>();
  private processingSteps: string[] = [];
  private validationRules: ValidationRule[] = [];
  private validationPipeline: ValidationPipeline | null = null;
  private alertConfig: AlertConfig | null = null;
  private eventListeners: Map<string, ((event: ValidationEvent) => void)[]> = new Map();
  private knownVulnerabilities = new Set<string>();
  private threatIntelHistory: Map<string, AIThreatIntelData[]> = new Map();
  private validationHistory: Map<string, ValidationResult[]> = new Map();

  constructor(
    setLoadingSteps?: (stepsUpdater: (prev: string[]) => string[]) => void,
    config: ValidationConfig = {}
  ) {
    this.setLoadingSteps = setLoadingSteps || (() => {});
    this.config = {
      maxRetries: 3,
      retryDelay: 1000,
      timeoutMs: 30000,
      enableCaching: true,
      batchSize: 5,
      priorityThreshold: 7.0,
      enableMLEnhancement: true,
      enableCrossValidation: true,
      ...config
    };
    
    this.initializeDefaultRules();
  }

  // Event System
  public addEventListener(event: string, listener: (event: ValidationEvent) => void): void {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, []);
    }
    this.eventListeners.get(event)!.push(listener);
  }

  private emitEvent(event: ValidationEvent): void {
    const listeners = this.eventListeners.get(event.type) || [];
    listeners.forEach(listener => listener(event));
  }

  // Rule Engine
  public addValidationRule(rule: ValidationRule): void {
    this.validationRules.push(rule);
  }

  public removeValidationRule(ruleId: string): void {
    this.validationRules = this.validationRules.filter(rule => rule.id !== ruleId);
  }

  private initializeDefaultRules(): void {
    this.addValidationRule({
      id: 'cvss-score-check',
      name: 'CVSS Score Validation',
      weight: 0.3,
      validator: (data) => data.nvdData?.baseScore >= 0 && data.nvdData?.baseScore <= 10,
      errorMessage: 'Invalid CVSS score range'
    });

    this.addValidationRule({
      id: 'exploit-availability',
      name: 'Exploit Availability Check',
      weight: 0.4,
      validator: (data) => this.checkExploitAvailability(data.cveId),
      errorMessage: 'Failed to verify exploit availability'
    });

    this.addValidationRule({
      id: 'patch-availability',
      name: 'Patch Availability Check',
      weight: 0.3,
      validator: (data) => data.patchData !== null,
      errorMessage: 'No patch data available'
    });
  }

  // AI/ML Enhancement
  private async enhanceWithML(
    cveId: string,
    result: CVEValidationData,
    nvdData: BaseCVEInfo | null
  ): Promise<number> {
    if (!this.config.enableMLEnhancement) return 0;

    try {
      this.updateSteps(`🤖 Applying ML enhancement for ${cveId}...`);
      
      // Simulated ML enhancement - replace with actual ML service
      const features = this.extractFeatures(cveId, result, nvdData);
      const mlScore = await this.callMLService(features);
      
      this.updateSteps(`🎯 ML enhancement score: ${mlScore.toFixed(2)}`);
      return mlScore;
    } catch (error) {
      console.warn('ML enhancement failed:', error);
      return 0;
    }
  }

  private extractFeatures(cveId: string, result: CVEValidationData, nvdData: BaseCVEInfo | null): any {
    return {
      cveYear: parseInt(cveId.split('-')[1]),
      hasNVDData: !!nvdData,
      descriptionLength: result.legitimacySummary?.length || 0,
      confidenceScore: result.confidence || 0,
      // Add more features as needed
    };
  }

  private async callMLService(features: any): Promise<number> {
    // Mock ML service call - replace with actual implementation
    return Math.random() * 100;
  }

  // Cross-Validation
  private async performCrossValidation(
    cveId: string,
    result: ValidationResult
  ): Promise<ValidationResult> {
    if (!this.config.enableCrossValidation) return result;

    this.updateSteps(`🔍 Performing cross-validation for ${cveId}...`);

    try {
      // Check against known vulnerability databases
      const crossValidationResults = await Promise.allSettled([
        this.validateAgainstNIST(cveId),
        this.validateAgainstMITRE(cveId),
        this.validateAgainstVulnDB(cveId),
        this.checkThreatIntelFeeds(cveId)
      ]);

      const validationCount = crossValidationResults.filter(r => r.status === 'fulfilled').length;
      const crossValidationScore = (validationCount / crossValidationResults.length) * 100;

      result.metrics.validationScore = (result.metrics.validationScore + crossValidationScore) / 2;
      this.updateSteps(`✅ Cross-validation complete: ${crossValidationScore.toFixed(1)}% confidence`);

      return result;
    } catch (error) {
      console.warn('Cross-validation failed:', error);
      return result;
    }
  }

  private async validateAgainstNIST(cveId: string): Promise<boolean> {
    // Mock implementation - replace with actual NIST API call
    return Math.random() > 0.3;
  }

  private async validateAgainstMITRE(cveId: string): Promise<boolean> {
    // Mock implementation - replace with actual MITRE API call
    return Math.random() > 0.2;
  }

  private async validateAgainstVulnDB(cveId: string): Promise<boolean> {
    // Mock implementation - replace with actual vulnerability database query
    return Math.random() > 0.4;
  }

  private async checkThreatIntelFeeds(cveId: string): Promise<boolean> {
    // Mock implementation - replace with actual threat intelligence feeds
    return Math.random() > 0.25;
  }

  // Smart Prioritization
  private calculatePriority(result: ValidationResult): number {
    const weights = {
      cvssScore: 0.3,
      exploitAvailability: 0.25,
      threatIntel: 0.2,
      patchAvailability: 0.15,
      businessImpact: 0.1
    };

    let priority = 0;
    priority += (result.metrics.riskScore / 10) * weights.cvssScore;
    priority += (result.exploitProbability / 100) * weights.exploitAvailability;
    priority += (result.metrics.confidenceLevel) * weights.threatIntel;
    priority += (result.patches.length > 0 ? 0.5 : 1) * weights.patchAvailability;
    priority += this.getBusinessImpactScore(result.businessImpact) * weights.businessImpact;

    return Math.min(priority * 10, 10);
  }

  private getBusinessImpactScore(impact: string): number {
    switch (impact) {
      case 'CRITICAL': return 1.0;
      case 'HIGH': return 0.8;
      case 'MEDIUM': return 0.5;
      case 'LOW': return 0.2;
      default: return 0.1;
    }
  }

  // Automated Alerting
  public configureAlerts(config: AlertConfig): void {
    this.alertConfig = config;
  }

  private async sendAlert(result: ValidationResult): Promise<void> {
    if (!this.alertConfig || !this.shouldAlert(result)) return;

    const alert = {
      cveId: result.cveId || 'Unknown',
      severity: result.metrics.severityLevel,
      riskScore: result.metrics.riskScore,
      exploitProbability: result.exploitProbability,
      businessImpact: result.businessImpact,
      recommendations: result.recommendations,
      timestamp: new Date().toISOString()
    };

    try {
      await Promise.allSettled([
        this.sendWebhookAlert(alert),
        this.sendEmailAlert(alert),
        this.sendSlackAlert(alert)
      ]);
    } catch (error) {
      console.error('Failed to send alerts:', error);
    }
  }

  private shouldAlert(result: ValidationResult): boolean {
    if (!this.alertConfig) return false;
    
    const severityLevels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const thresholdIndex = severityLevels.indexOf(this.alertConfig.severityThreshold);
    const currentIndex = severityLevels.indexOf(result.metrics.severityLevel);
    
    return currentIndex >= thresholdIndex;
  }

  private async sendWebhookAlert(alert: any): Promise<void> {
    if (!this.alertConfig?.webhookUrl) return;
    // Implement webhook sending logic
  }

  private async sendEmailAlert(alert: any): Promise<void> {
    if (!this.alertConfig?.emailRecipients?.length) return;
    // Implement email sending logic
  }

  private async sendSlackAlert(alert: any): Promise<void> {
    if (!this.alertConfig?.slackChannel) return;
    // Implement Slack notification logic
  }

  // Threat Intelligence Integration
  private async enrichWithThreatIntel(cveId: string, result: ValidationResult): Promise<ValidationResult> {
    try {
      this.updateSteps(`🕵️ Enriching with threat intelligence for ${cveId}...`);
      
      const threatData = await this.fetchThreatIntelligence(cveId);
      if (threatData) {
        result.threatActor = threatData.actor;
        result.exploitProbability = threatData.exploitProbability;
        result.relatedCVEs = threatData.relatedCVEs;
        
        // Store threat intel history
        if (!this.threatIntelHistory.has(cveId)) {
          this.threatIntelHistory.set(cveId, []);
        }
        this.threatIntelHistory.get(cveId)!.push(threatData);
      }
      
      return result;
    } catch (error) {
      console.warn('Threat intelligence enrichment failed:', error);
      return result;
    }
  }

  private async fetchThreatIntelligence(cveId: string): Promise<any> {
    // Mock implementation - replace with actual threat intelligence API
    return {
      actor: 'APT29',
      exploitProbability: Math.random() * 100,
      relatedCVEs: [`CVE-2023-${Math.floor(Math.random() * 10000)}`],
      campaigns: ['Operation CloudHopper']
    };
  }

  // Advanced Analytics
  public async generateTrendAnalysis(timeRange: string = '30d'): Promise<any> {
    const analysis = {
      totalValidations: this.validationHistory.size,
      averageProcessingTime: 0,
      severityDistribution: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
      topThreatActors: new Map<string, number>(),
      exploitTrends: [],
      recommendationPatterns: new Map<string, number>()
    };

    // Analyze historical data
    for (const [cveId, history] of this.validationHistory.entries()) {
      const latest = history[history.length - 1];
      analysis.averageProcessingTime += latest.metrics.processingTime;
      analysis.severityDistribution[latest.metrics.severityLevel]++;
      
      if (latest.threatActor) {
        analysis.topThreatActors.set(
          latest.threatActor,
          (analysis.topThreatActors.get(latest.threatActor) || 0) + 1
        );
      }
    }

    analysis.averageProcessingTime /= this.validationHistory.size || 1;
    return analysis;
  }

  // Pipeline Configuration
  public configurePipeline(pipeline: ValidationPipeline): void {
    this.validationPipeline = pipeline;
  }

  private async executeValidationPipeline(
    cveId: string,
    nvdData: BaseCVEInfo | null,
    aiIntel: AIThreatIntelData | null,
    patchData: PatchData | null
  ): Promise<ValidationResult> {
    if (!this.validationPipeline) {
      throw new Error('No validation pipeline configured');
    }

    const pipelineData = { cveId, nvdData, aiIntel, patchData };
    
    if (this.validationPipeline.parallel) {
      return await this.executeParallelPipeline(pipelineData);
    } else {
      return await this.executeSequentialPipeline(pipelineData);
    }
  }

  private async executeParallelPipeline(data: any): Promise<ValidationResult> {
    const stagePromises = this.validationPipeline!.stages.map(stage => 
      this.executeStage(stage, data)
    );
    
    const results = await Promise.allSettled(stagePromises);
    return this.mergePipelineResults(results, data);
  }

  private async executeSequentialPipeline(data: any): Promise<ValidationResult> {
    let currentData = data;
    
    for (const stage of this.validationPipeline!.stages) {
      try {
        currentData = await this.executeStage(stage, currentData);
      } catch (error) {
        if (stage.required) {
          throw error;
        }
        console.warn(`Optional stage ${stage.name} failed:`, error);
      }
    }
    
    return currentData;
  }

  private async executeStage(stage: ValidationStage, data: any): Promise<any> {
    const timeout = stage.timeout || this.config.timeoutMs;
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error(`Stage ${stage.name} timeout`)), timeout);
    });
    
    return Promise.race([stage.validator(data), timeoutPromise]);
  }

  private mergePipelineResults(results: PromiseSettledResult<any>[], originalData: any): ValidationResult {
    // Implement result merging logic
    return {} as ValidationResult;
  }

  // Utility Methods
  private async checkExploitAvailability(cveId: string): Promise<boolean> {
    // Mock implementation - replace with actual exploit database check
    return Math.random() > 0.6;
  }

  private generateRecommendations(result: ValidationResult): string[] {
    const recommendations: string[] = [];
    
    if (result.metrics.riskScore > 8) {
      recommendations.push('Immediate patching required - High risk vulnerability');
    }
    
    if (result.exploitProbability > 70) {
      recommendations.push('Active exploits detected - Prioritize remediation');
    }
    
    if (result.patches.length === 0) {
      recommendations.push('No patches available - Implement compensating controls');
    }
    
    return recommendations;
  }

  private generatePatchRecommendations(patchData: PatchData | null): PatchRecommendation[] {
    if (!patchData) return [];
    
    return [{
      priority: 'HIGH',
      description: 'Apply security patch immediately',
      estimatedTime: '2-4 hours',
      complexity: 'MODERATE',
      dependencies: ['System maintenance window'],
      rollbackPlan: 'Restore from backup if issues occur'
    }];
  }

  // Enhanced main validation method
  public async validateCVE(
    cveId: string,
    nvdData: BaseCVEInfo | null,
    aiIntel: AIThreatIntelData | null,
    patchData: PatchData | null
  ): Promise<ValidationResult> {
    const startTime = Date.now();
    this.processingSteps = [];
    
    this.emitEvent({
      type: 'started',
      cveId,
      timestamp: new Date(),
      data: { nvdData, aiIntel, patchData }
    });

    try {
      // Input validation
      if (!cveId || !cveId.match(/^CVE-\d{4}-\d{4,}$/)) {
        throw new Error(`Invalid CVE ID format: ${cveId}`);
      }

      this.updateSteps(`🛡️ Validation Agent processing ${cveId}...`);

      // Check cache
      if (this.config.enableCaching) {
        const cacheKey = this.getCacheKey(cveId, nvdData, aiIntel);
        const cached = this.validationCache.get(cacheKey);
        
        if (cached && this.isCacheValid(cached.timestamp)) {
          this.updateSteps(`💨 Using cached validation result for ${cveId}`);
          return { ...cached.result, cacheHit: true };
        }
      }

      // Execute validation pipeline or default validation
      let result: ValidationResult;
      if (this.validationPipeline) {
        result = await this.executeValidationPipeline(cveId, nvdData, aiIntel, patchData);
      } else {
        // Default validation logic
        const baseResult = await this.withRetry(
          () => ValidationService.validateAIFindings(cveId, nvdData, aiIntel, patchData),
          `Validating ${cveId}`
        );
        
        result = await this.enhanceValidationResult(cveId, baseResult, nvdData, aiIntel, patchData);
      }

      // Post-processing enhancements
      result = await this.performCrossValidation(cveId, result);
      result = await this.enrichWithThreatIntel(cveId, result);
      
      // Calculate final metrics
      const processingTime = Date.now() - startTime;
      result.metrics.processingTime = processingTime;
      result.recommendations = this.generateRecommendations(result);
      result.patches = this.generatePatchRecommendations(patchData);

      // Store in history
      if (!this.validationHistory.has(cveId)) {
        this.validationHistory.set(cveId, []);
      }
      this.validationHistory.get(cveId)!.push(result);

      // Cache result
      if (this.config.enableCaching) {
        const cacheKey = this.getCacheKey(cveId, nvdData, aiIntel);
        this.validationCache.set(cacheKey, {
          result,
          timestamp: Date.now()
        });
      }

      // Send alerts if necessary
      await this.sendAlert(result);

      // Store in RAG database
      await this.storeInRAG(cveId, result);

      this.updateSteps(`✅ Validation complete for ${cveId} (${processingTime}ms)`);
      
      this.emitEvent({
        type: 'completed',
        cveId,
        timestamp: new Date(),
        data: result
      });

      return result;

    } catch (error) {
      this.emitEvent({
        type: 'failed',
        cveId,
        timestamp: new Date(),
        data: { error: error.message }
      });
      
      throw error;
    }
  }

  private async enhanceValidationResult(
    cveId: string,
    baseResult: CVEValidationData,
    nvdData: BaseCVEInfo | null,
    aiIntel: AIThreatIntelData | null,
    patchData: PatchData | null
  ): Promise<ValidationResult> {
    const mlScore = await this.enhanceWithML(cveId, baseResult, nvdData);
    
    const result: ValidationResult = {
      ...baseResult,
      cveId,
      metrics: {
        processingTime: 0,
        retryCount: 0,
        validationScore: this.calculateValidationScore(baseResult),
        confidenceLevel: this.calculateConfidenceLevel(nvdData, aiIntel, patchData),
        riskScore: this.calculateRiskScore(nvdData, aiIntel),
        severityLevel: this.calculateSeverityLevel(nvdData),
        falsePositiveScore: this.calculateFalsePositiveScore(baseResult, aiIntel),
        mlEnhancementScore: mlScore
      },
      cacheHit: false,
      processingSteps: [...this.processingSteps],
      ruleResults: [],
      recommendations: [],
      relatedCVEs: [],
      exploitProbability: 0,
      businessImpact: 'LOW',
      patches: []
    };

    return result;
  }

  // Additional utility methods
  private getCacheKey(cveId: string, nvdData: BaseCVEInfo | null, aiIntel: AIThreatIntelData | null): string {
    const nvdHash = nvdData ? JSON.stringify(nvdData).slice(0, 50) : 'null';
    const aiHash = aiIntel ? JSON.stringify(aiIntel).slice(0, 50) : 'null';
    return `${cveId}-${btoa(nvdHash + aiHash)}`;
  }

  private isCacheValid(timestamp: number): boolean {
    const CACHE_TTL = 1000 * 60 * 60; // 1 hour
    return Date.now() - timestamp < CACHE_TTL;
  }

  private async delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private async withRetry<T>(operation: () => Promise<T>, context: string): Promise<T> {
    let lastError: Error;
    
    for (let attempt = 1; attempt <= this.config.maxRetries!; attempt++) {
      try {
        this.updateSteps(`🔄 ${context} (attempt ${attempt}/${this.config.maxRetries})`);
        
        const timeoutPromise = new Promise<never>((_, reject) => {
          setTimeout(() => reject(new Error('Operation timeout')), this.config.timeoutMs);
        });

        return await Promise.race([operation(), timeoutPromise]);
      } catch (error) {
        lastError = error as Error;
        
        if (attempt === this.config.maxRetries) {
          this.updateSteps(`❌ ${context} failed after ${this.config.maxRetries} attempts`);
          throw lastError;
        }

        this.updateSteps(`⚠️ ${context} failed, retrying in ${this.config.retryDelay}ms...`);
        await this.delay(this.config.retryDelay!);
      }
    }

    throw lastError!;
  }

  private updateSteps(message: string) {
    this.processingSteps.push(message);
    this.setLoadingSteps(prev => [...prev, message]);
  }

  private calculateValidationScore(result: CVEValidationData): number {
    let score = 0;
    
    if (result.status === 'validated') score += 50;
    if (result.legitimacySummary?.length > 0) score += 30;
    if (result.confidence && result.confidence > 0.7) score += 20;
    
    return Math.min(score, 100);
  }

  private calculateConfidenceLevel(
    nvdData: BaseCVEInfo | null,
    aiIntel: AIThreatIntelData | null,
    patchData: PatchData | null
  ): number {
    let confidence = 0;
    let factors = 0;

    if (nvdData) {
      confidence += 0.4;
      factors++;
    }
    if (aiIntel) {
      confidence += 0.3;
      factors++;
    }
    if (patchData) {
      confidence += 0.3;
      factors++;
    }

    return factors > 0 ? confidence : 0;
  }

  private calculateRiskScore(nvdData: BaseCVEInfo | null, aiIntel: AIThreatIntelData | null): number {
    let score = 0;
    
    if (nvdData?.baseScore) {
      score += nvdData.baseScore;
    }
    
    if (aiIntel?.riskLevel) {
      score += aiIntel.riskLevel * 2;
    }
    
    return Math.min(score, 10);
  }

  private calculateSeverityLevel(nvdData: BaseCVEInfo | null): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const score = nvdData?.baseScore || 0;
    
    if (score >= 9) return 'CRITICAL';
    if (score >= 7) return 'HIGH';
    if (score >= 4) return 'MEDIUM';
    return 'LOW';
  }

  private calculateFalsePositiveScore(result: CVEValidationData, aiIntel: AIThreatIntelData | null): number {
    // Mock implementation - replace with actual false positive detection logic
    return Math.random() * 100;
  }

  private async storeInRAG(cveId: string, result: ValidationResult): Promise<void> {
    if (!ragDatabase?.initialized) {
      this.updateSteps(`⚠️ RAG database not initialized, skipping storage`);
      return;
    }

    try {
      const document = {
        content: `Validation for ${cveId}: ${result.legitimacySummary || result.status}`,
        metadata: {
          title: `Validation - ${cveId}`,
          category: 'validation-result',
          cveId,
          source: 'validation-agent',
          timestamp: new Date().toISOString(),
          processingTime: result.metrics.processingTime,
          validationScore: result.metrics.validationScore,
          confidenceLevel: result.metrics.confidenceLevel,
          riskScore: result.metrics.riskScore,
          severityLevel: result.metrics.severityLevel,
          businessImpact: result.businessImpact,
          threatActor: result.threatActor,
          exploitProbability: result.exploitProbability
        }
      };

      await ragDatabase.addDocument(document.content, document.metadata);
      this.updateSteps(`💾 Stored validation result in RAG database`);
    } catch (err) {
      console.warn('ValidationAgent failed to store result in RAG DB:', err);
      this.updateSteps(`❌ Failed to store in RAG database: ${err}`);
    }
  }

  // Public utility methods
  public clearCache(): void {
    this.validationCache.clear();
    this.updateSteps(`🗑️ Validation cache cleared`);
  }

  public getCacheStats(): { size: number; hitRate: number } {
    return {
      size: this.validationCache.size,
      hitRate: 0 // Would need proper tracking
    };
  }

  public getValidationHistory(cveId: string): ValidationResult[] {
    return this.validationHistory.get(cveId) || [];
  }

  public async validateBatch(
    cveRequests: Array<{
      cveId: string;
      nvdData: BaseCVEInfo | null;
      aiIntel: AIThreatIntelData | null;
      patchData: PatchData | null;
    }>
  ): Promise<ValidationResult[]> {
    this.updateSteps(`🔄 Processing batch of ${cveRequests.length} CVEs...`);
    
    const results: ValidationResult[] = [];
    
    for (let i = 0; i < cveRequests.length; i += this.config.batchSize!) {
      const batch = cveRequests.slice(i, i + this.config.batchSize!);
      
      const batchPromises = batch.map(req => 
        this.validateCVE(req.cveId, req.nvdData, req.aiIntel, req.patchData)
      );
      
      const batchResults = await Promise.allSettled(batchPromises);
      
      for (const result of batchResults) {
        if (result.status === 'fulfilled') {
          results.push(result.value);
        } else {
          console.error('Batch validation failed:', result.reason);
        }
      }
    }

    this.updateSteps(`✅ Batch processing complete: ${results.length} validations`);
    return results;
  }
}
