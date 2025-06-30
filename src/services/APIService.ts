import { CONSTANTS } from '../utils/constants';
import { utils } from '../utils/helpers';
import { ragDatabase } from '../db/EnhancedVectorDatabase';

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
      setLoadingSteps(prev => [...prev, `🚀 Starting AI-powered real-time analysis for ${cveId}...`]);

      if (ragDatabase && !ragDatabase.initialized) {
        setLoadingSteps(prev => [...prev, `📚 Initializing RAG knowledge base...`]);
        await ragDatabase.initialize();
      }

      setLoadingSteps(prev => [...prev, `🔍 Fetching from primary sources (NVD, EPSS)...`]);

      const [cveResult, epssResult] = await Promise.allSettled([
        APIService.fetchCVEData(cveId, apiKeys.nvd, setLoadingSteps), // Use APIService.fetchCVEData
        APIService.fetchEPSSData(cveId, setLoadingSteps) // Use APIService.fetchEPSSData
      ]);

      const cve = cveResult.status === 'fulfilled' ? cveResult.value : null;
      const epss = epssResult.status === 'fulfilled' ? epssResult.value : null;

      if (!cve) {
        throw new Error(`Failed to fetch CVE data for ${cveId}`);
      }

      setLoadingSteps(prev => [...prev, `🌐 AI analyzing real-time threat intelligence via web search...`]);

      const aiThreatIntel = await APIService.fetchAIThreatIntelligence(cveId, cve, epss, settings, setLoadingSteps); // Use APIService.fetchAIThreatIntelligence

      // Fetch patches and advisories
      setLoadingSteps(prev => [...prev, `🔧 Searching for patches and security advisories...`]);
      const patchAdvisoryData = await APIService.fetchPatchesAndAdvisories(cveId, cve, settings, setLoadingSteps); // Use APIService.fetchPatchesAndAdvisories

      // Validate AI findings
      setLoadingSteps(prev => [...prev, `🔍 Validating AI findings against authoritative sources...`]);
      const validation = await ValidationService.validateAIFindings(aiThreatIntel, cveId, setLoadingSteps);

      // Calculate confidence scores
      const confidence = ConfidenceScorer.scoreAIFindings(
        aiThreatIntel, 
        validation, 
        { discoveredSources: ['NVD', 'EPSS', 'AI_WEB_SEARCH'] }
      );

      const discoveredSources = ['NVD'];
      const sources = [{ name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${cveId}`, aiDiscovered: false }];

      if (epss) {
        discoveredSources.push('EPSS/FIRST');
        sources.push({ name: 'EPSS', url: `https://api.first.org/data/v1/epss?cve=${cveId}`, aiDiscovered: false });
      }

      if (aiThreatIntel.cisaKev?.listed) {
        discoveredSources.push('CISA KEV');
        sources.push({
          name: 'CISA KEV',
          url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
          aiDiscovered: aiThreatIntel.cisaKev.aiDiscovered || true,
          verified: validation.cisaKev?.verified || false
        });
      }

      if (aiThreatIntel.exploitDiscovery?.found) {
        discoveredSources.push('Exploit Intelligence');
        if (aiThreatIntel.exploitDiscovery.exploits) {
          aiThreatIntel.exploitDiscovery.exploits.forEach(exploit => {
            if (exploit.url && exploit.url.startsWith('http')) {
              sources.push({
                name: `${exploit.source} - ${exploit.type}`,
                url: exploit.url,
                aiDiscovered: true,
                reliability: exploit.reliability,
                description: exploit.description,
                verified: validation.exploits?.verifiedExploits?.some(v => v.url === exploit.url) || false
              });
            }
          });
        }
      }

      if (aiThreatIntel.vendorAdvisories?.found) {
        discoveredSources.push('Vendor Advisories');
        if (aiThreatIntel.vendorAdvisories.advisories) {
          aiThreatIntel.vendorAdvisories.advisories.forEach(advisory => {
            const vendorName = `${advisory.vendor} Advisory`;
            if (!sources.some(s => s.name === vendorName)) {
              sources.push({
                name: vendorName,
                url: '',
                aiDiscovered: true,
                patchAvailable: advisory.patchAvailable,
                severity: advisory.severity,
                verified: validation.vendorAdvisories?.verifiedAdvisories?.some(v => v.vendor === advisory.vendor) || false
              });
            }
          });
        }
      }

      if (aiThreatIntel.intelligenceSummary?.analysisMethod === 'GROUNDING_INFO_ONLY' && aiThreatIntel.intelligenceSummary.searchQueries?.length > 0) {
        discoveredSources.push('AI Performed Searches');
        sources.push({
          name: 'AI Search Queries Performed',
          type: 'ai-search-queries', // New type for UI to potentially handle differently
          queries: aiThreatIntel.intelligenceSummary.searchQueries,
          aiDiscovered: true,
          description: 'The AI performed these web searches but did not provide a textual summary based on them.'
        });
      }

      const intelligenceSummary = aiThreatIntel.intelligenceSummary || {
        sourcesAnalyzed: discoveredSources.length,
        exploitsFound: aiThreatIntel.exploitDiscovery?.totalCount || 0,
        vendorAdvisoriesFound: aiThreatIntel.vendorAdvisories?.count || 0,
        activeExploitation: aiThreatIntel.activeExploitation?.confirmed || false,
        cisaKevListed: aiThreatIntel.cisaKev?.listed || false,
        cveValid: aiThreatIntel.cveValidation?.isValid !== false,
        threatLevel: aiThreatIntel.overallThreatLevel || 'MEDIUM',
        dataFreshness: 'AI_WEB_SEARCH',
        analysisMethod: 'AI_WEB_SEARCH_VALIDATED',
        confidenceLevel: confidence.overall,
        aiEnhanced: true,
        validated: true
      };

      const threatLevel = aiThreatIntel.overallThreatLevel || intelligenceSummary.threatLevel;
      const summary = aiThreatIntel.summary;

      const enhancedVulnerability = {
        cve,
        epss,
        kev: {
          ...aiThreatIntel.cisaKev,
          validated: validation.cisaKev?.verified || false,
          actualStatus: validation.cisaKev?.actualStatus
        },
        exploits: {
          found: aiThreatIntel.exploitDiscovery?.found || false,
          count: aiThreatIntel.exploitDiscovery?.totalCount || 0,
          confidence: aiThreatIntel.exploitDiscovery?.confidence || 'LOW',
          sources: aiThreatIntel.exploitDiscovery?.exploits?.map(e => e.url) || [],
          types: aiThreatIntel.exploitDiscovery?.exploits?.map(e => e.type) || [],
          details: aiThreatIntel.exploitDiscovery?.exploits || [],
          githubRepos: aiThreatIntel.exploitDiscovery?.githubRepos || 0,
          exploitDbEntries: aiThreatIntel.exploitDiscovery?.exploitDbEntries || 0,
          metasploitModules: aiThreatIntel.exploitDiscovery?.metasploitModules || 0,
          validated: validation.exploits?.verified || false,
          verifiedCount: validation.exploits?.verifiedExploits?.length || 0
        },
        vendorAdvisories: {
          ...aiThreatIntel.vendorAdvisories,
          validated: validation.vendorAdvisories?.verified || false
        },
        cveValidation: aiThreatIntel.cveValidation || {
          isValid: true,
          confidence: 'MEDIUM',
          validationSources: [],
          disputes: [],
          falsePositiveIndicators: [],
          legitimacyEvidence: [],
          recommendation: 'NEEDS_VERIFICATION'
        },
        technicalAnalysis: aiThreatIntel.technicalAnalysis,
        github: {
          found: (aiThreatIntel.exploitDiscovery?.githubRepos || 0) > 0 || (aiThreatIntel.vendorAdvisories?.count || 0) > 0,
          count: (aiThreatIntel.exploitDiscovery?.githubRepos || 0) + (aiThreatIntel.vendorAdvisories?.count || 0)
        },
        activeExploitation: aiThreatIntel.activeExploitation || {
          confirmed: false,
          details: '',
          sources: []
        },
        threatIntelligence: aiThreatIntel.threatIntelligence,
        intelligenceSummary: intelligenceSummary,
        
        // Patch and Advisory Data
        patches: patchAdvisoryData.patches || [],
        advisories: patchAdvisoryData.advisories || [],
        patchSearchSummary: patchAdvisoryData.searchSummary || {},
        
        sources,
        discoveredSources,
        summary,
        threatLevel,
        dataFreshness: intelligenceSummary.dataFreshness || 'AI_WEB_SEARCH',
        lastUpdated: new Date().toISOString(),
        searchTimestamp: new Date().toISOString(),
        ragEnhanced: true,
        aiSearchPerformed: true,
        aiWebGrounded: true,
        enhancedSources: discoveredSources,
        analysisMethod: intelligenceSummary.analysisMethod || aiThreatIntel.analysisMethod || 'AI_WEB_SEARCH_VALIDATED',
        
        // Enhanced validation metadata
        validation: validation,
        confidence: confidence,
        hallucinationFlags: aiThreatIntel.hallucinationFlags || [],
        extractionMetadata: aiThreatIntel.extractionMetadata,
        validationTimestamp: new Date().toISOString(),
        enhancedWithValidation: true
      };

      setLoadingSteps(prev => [...prev, 
        `✅ Enhanced analysis complete: ${discoveredSources.length} sources analyzed, ${threatLevel} threat level, ${confidence.overall} confidence`
      ]);

      return enhancedVulnerability;

    } catch (error) {
      console.error(`Error processing ${cveId}:`, error);
      throw error;
    }
  }

  // These static methods are now part of UtilityService.ts and are imported.
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