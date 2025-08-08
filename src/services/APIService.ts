import { CONSTANTS } from '../utils/constants';
import { utils } from '../utils/helpers';
import { logger } from '../utils/logger';

const cache = new Map();

async function fetchWithCache(key, fetcher) {
  if (cache.has(key)) {
    return cache.get(key);
  }
  const result = await fetcher();
  cache.set(key, result);
  return result;
}
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { ResearchAgent } from '../agents/ResearchAgent';
import { NaturalLanguageSearchAgent } from '../agents/NaturalLanguageSearchAgent';
import { ValidationService } from './ValidationService';
import { ConfidenceScorer } from './ConfidenceScorer';
import {
  fetchWithFallback, // Now properly exported from UtilityService
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
} from './UtilityService';
import {
  fetchCVEData as fetchCVEDataInternal,
  fetchEPSSData as fetchEPSSDataInternal,
} from './DataFetchingService';
import {
  fetchPatchesAndAdvisories as fetchPatchesAndAdvisoriesInternal,
  fetchAIThreatIntelligence as fetchAIThreatIntelligenceInternal,
  generateAIAnalysis as generateAIAnalysisInternal,
  generateAITaintAnalysis as generateAITaintAnalysisInternal,
  fetchGeneralAnswer as fetchGeneralAnswerInternal,
} from './AIEnhancementService';

// Enhanced API Service Layer with Multi-Source Intelligence and Validation
export class APIService {
  // Data fetching methods are moved to DataFetchingService
  static async fetchCVEData(cveId, apiKey, setLoadingSteps) {
    return fetchWithCache(`cve-${cveId}`, () => fetchCVEDataInternal(cveId, apiKey, setLoadingSteps, ragDatabase, fetchWithFallback, processCVEData));
  }

  static async fetchEPSSData(cveId, setLoadingSteps) {
    return fetchWithCache(`epss-${cveId}`, () => fetchEPSSDataInternal(cveId, setLoadingSteps, ragDatabase, fetchWithFallback));
  }

  // AI enhancement methods are moved to AIEnhancementService
  static async fetchPatchesAndAdvisories(cveId, cveData, settings, setLoadingSteps) {
    return fetchWithCache(`patches-${cveId}`, () => fetchPatchesAndAdvisoriesInternal(cveId, cveData, settings, setLoadingSteps, ragDatabase, fetchWithFallback, parsePatchAndAdvisoryResponse, getHeuristicPatchesAndAdvisories));
  }

  static async fetchAIThreatIntelligence(cveId, cveData, epssData, settings, setLoadingSteps) {
    return fetchWithCache(`threat-intel-${cveId}`, () => fetchAIThreatIntelligenceInternal(cveId, cveData, epssData, settings, setLoadingSteps, ragDatabase, fetchWithFallback, parseAIThreatIntelligence, performHeuristicAnalysis));
  }

  static async generateAIAnalysis(vulnerability, model, settings = {}) {
    return fetchWithCache(`analysis-${vulnerability.cve.id}`, () => generateAIAnalysisInternal(vulnerability, model, settings, ragDatabase, fetchWithFallback, buildEnhancedAnalysisPrompt, generateEnhancedFallbackAnalysis));
  }

  static async generateAITaintAnalysis(vulnerability, model, settings = {}) {
    return fetchWithCache(`taint-analysis-${vulnerability.cve.id}`, () => generateAITaintAnalysisInternal(vulnerability, model, settings, fetchWithFallback));
  }

  static async fetchGeneralAnswer(query, settings = {}) {
    return fetchWithCache(`general-answer-${query}`, () => fetchGeneralAnswerInternal(query, settings, fetchWithFallback));
  }

  // Enhanced main function with validation
  static async fetchVulnerabilityDataWithAI(cveId, setLoadingSteps, apiKeys, settings) {
    try {
      // All previous logic is now encapsulated within ResearchAgent
      const agent = new ResearchAgent(setLoadingSteps);
      const enhancedVulnerability = await agent.analyzeCVE(cveId, apiKeys, settings);

      return enhancedVulnerability;
    } catch (error) {
      logger.error(`APIService: Error processing ${cveId} via ResearchAgent:`, error);
      throw error;
    }
  }

  static async performNaturalLanguageSearch(query: string) {
    try {
      const agent = new NaturalLanguageSearchAgent();
      const results = await agent.search(query);
      return results;
    } catch (error) {
      logger.error(`APIService: Error performing natural language search for query "${query}":`, error);
      throw error;
    }
  }

  // Utility methods for backward compatibility
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
