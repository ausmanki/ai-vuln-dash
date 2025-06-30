import { CONSTANTS } from '../utils/constants';
import { utils } from '../utils/helpers';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { ResearchAgent } from '../agents/ResearchAgent';
import { ValidationService } from './ValidationService';
import { ConfidenceScorer } from './ConfidenceScorer';
import {
  fetchWithFallback,
  processCVEData,
  parsePatchAndAdvisoryResponse,
  getHeuristicPatchesAndAdvisories,
  parseAIThreatIntelligence,
  performHeuristicAnalysis,
  buildEnhancedAnalysisPrompt,
  generateEnhancedFallbackAnalysis,
  formatFindingWithConfidence,
  getConfidenceIcon,
  getVerificationBadge,
  generateUserWarning,
  createAIDataDisclaimer,
  countAIGeneratedFindings,
  countVerifiedFindings,
  // calculateThreatLevel, // This is used internally by normalizeAIFindings and performHeuristicAnalysis, not directly by APIService
  // normalizeAIFindings, // Used by parseAIThreatIntelligence
  // detectHallucinationFlags, // Used by parseAIThreatIntelligence
  // performConservativeTextAnalysis // Used by parseAIThreatIntelligence
} from './UtilityService';
import {
  fetchCVEData as fetchCVEDataInternal,
  fetchEPSSData as fetchEPSSDataInternal,
} from './DataFetchingService';
import {
  fetchPatchesAndAdvisories as fetchPatchesAndAdvisoriesInternal,
  fetchAIThreatIntelligence as fetchAIThreatIntelligenceInternal,
  generateAIAnalysis as generateAIAnalysisInternal,
} from './AIEnhancementService';


// Enhanced API Service Layer with Multi-Source Intelligence and Validation
export class APIService {
  // Utility methods are now imported from UtilityService, so they are removed from here.
  // Data fetching methods are moved to DataFetchingService
  static async fetchCVEData(cveId, apiKey, setLoadingSteps) {
    return fetchCVEDataInternal(cveId, apiKey, setLoadingSteps, ragDatabase, fetchWithFallback, processCVEData);
  }

  static async fetchEPSSData(cveId, setLoadingSteps) {
    return fetchEPSSDataInternal(cveId, setLoadingSteps, ragDatabase, fetchWithFallback);
  }

  // AI enhancement methods are moved to AIEnhancementService
  static async fetchPatchesAndAdvisories(cveId, cveData, settings, setLoadingSteps) {
    return fetchPatchesAndAdvisoriesInternal(cveId, cveData, settings, setLoadingSteps, fetchWithFallback, parsePatchAndAdvisoryResponse, getHeuristicPatchesAndAdvisories);
  }

  static async fetchAIThreatIntelligence(cveId, cveData, epssData, settings, setLoadingSteps) {
    return fetchAIThreatIntelligenceInternal(cveId, cveData, epssData, settings, setLoadingSteps, ragDatabase, fetchWithFallback, parseAIThreatIntelligence, performHeuristicAnalysis);
  }

  static async generateAIAnalysis(vulnerability, apiKey, model, settings = {}) {
    return generateAIAnalysisInternal(vulnerability, apiKey, model, settings, ragDatabase, fetchWithFallback, buildEnhancedAnalysisPrompt, generateEnhancedFallbackAnalysis);
  }




// Enhanced main function with validation
  static async fetchVulnerabilityDataWithAI(cveId, setLoadingSteps, apiKeys, settings) {
    try {
      // All previous logic is now encapsulated within ResearchAgent
      const agent = new ResearchAgent(setLoadingSteps);
      const enhancedVulnerability = await agent.analyzeCVE(cveId, apiKeys, settings);

      // The setLoadingSteps updates are now handled by the agent itself.
      // The final "Enhanced analysis complete" message from APIService might be redundant
      // if the agent has its own final step message.
      // For consistency, we can rely on the agent's last message or add a specific one here.
      // For now, let's assume agent's logging is sufficient.
      // setLoadingSteps(prev => [...prev,
      //   `✅ APIService: Orchestration complete via ResearchAgent for ${cveId}`
      // ]);

      return enhancedVulnerability;
    } catch (error) {
      console.error(`APIService: Error processing ${cveId} via ResearchAgent:`, error);
      // It's important to re-throw the error so the UI can catch it and display an appropriate message.
      // Or, APIService could return a structured error object. For now, re-throwing.
      throw error;
    }
  }

  // Utility methods previously here are now in UtilityService.ts or handled by the ResearchAgent
  // They are kept here for now to avoid breaking existing calls from other parts of the APIService class,
  // but they should be removed once all internal calls are updated to use the imported versions.
  static formatFindingWithConfidence(finding, confidence, validation) {
    return formatFindingWithConfidence(finding, confidence, validation);
  }

  static getConfidenceIcon(confidence) {
    return getConfidenceIcon(confidence);
  }

  static getVerificationBadge(validation) {
    return getVerificationBadge(validation);
  }

  static generateUserWarning(confidence, validation) {
    return generateUserWarning(confidence, validation);
  }

  static createAIDataDisclaimer(vulnerability) {
    return createAIDataDisclaimer(vulnerability);
  }

  static countAIGeneratedFindings(vulnerability) {
    return countAIGeneratedFindings(vulnerability);
  }

  static countVerifiedFindings(validation) {
    return countVerifiedFindings(validation);
  }
}
