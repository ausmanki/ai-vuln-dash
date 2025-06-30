// src/agents/ResearchAgent.ts
import { APIService } from '../services/APIService'; // Will be used to call specific static methods if needed, or refactored further
import { ValidationService } from '../services/ValidationService';
import { ConfidenceScorer } from '../services/ConfidenceScorer';
import { ragDatabase } from '../db/EnhancedVectorDatabase'; // Direct import for now
import {
  fetchCVEDataInternal,
  fetchEPSSDataInternal,
} from '../services/DataFetchingService';
import {
  fetchPatchesAndAdvisories,
  fetchAIThreatIntelligence,
  // generateAIAnalysis, // generateAIAnalysis is typically user-triggered, might not be part of this agent's primary flow initially
} from '../services/AIEnhancementService';
import {
    fetchWithFallback,
    processCVEData,
    parsePatchAndAdvisoryResponse,
    getHeuristicPatchesAndAdvisories,
    parseAIThreatIntelligence,
    performHeuristicAnalysis,
} from '../services/UtilityService';


export class ResearchAgent {
  private setLoadingSteps: (stepsUpdater: (prev: string[]) => string[]) => void;

  constructor(setLoadingSteps?: (stepsUpdater: (prev: string[]) => string[]) => void) {
    this.setLoadingSteps = setLoadingSteps || (() => {});
  }

  private updateSteps(message: string) {
    this.setLoadingSteps(prev => [...prev, message]);
  }

  async analyzeCVE(cveId: string, apiKeys: { nvd?: string; geminiApiKey?: string }, settings: any) {
    this.updateSteps(`🚀 Research Agent starting analysis for ${cveId}...`);

    // RAG Initialization (moved from APIService)
    if (ragDatabase && !ragDatabase.initialized) {
        this.updateSteps(`📚 Initializing RAG knowledge base (agent)...`);
        // Use the geminiApiKey from settings if available, as it's passed for AI calls
        await ragDatabase.initialize(settings.geminiApiKey);
    }

    this.updateSteps(`🔍 Agent fetching primary data (NVD, EPSS) for ${cveId}...`);
    const [cveResult, epssResult] = await Promise.allSettled([
        fetchCVEDataInternal(cveId, apiKeys.nvd, this.setLoadingSteps, ragDatabase, fetchWithFallback, processCVEData),
        fetchEPSSDataInternal(cveId, this.setLoadingSteps, ragDatabase, fetchWithFallback)
    ]);

    const cve = cveResult.status === 'fulfilled' ? cveResult.value : null;
    const epss = epssResult.status === 'fulfilled' ? epssResult.value : null;

    if (!cve) {
        this.updateSteps(`❌ Agent failed to fetch critical CVE data for ${cveId}. Aborting further analysis.`);
        throw new Error(`Agent: Failed to fetch CVE data for ${cveId}`);
    }

    this.updateSteps(`🤖 Agent fetching AI threat intelligence for ${cveId}...`);
    const aiThreatIntel = await fetchAIThreatIntelligence(
        cveId, cve, epss, settings, this.setLoadingSteps,
        ragDatabase, fetchWithFallback, parseAIThreatIntelligence, performHeuristicAnalysis
    );

    this.updateSteps(`🔧 Agent fetching patches and advisories for ${cveId}...`);
    const patchAdvisoryData = await fetchPatchesAndAdvisories(
        cveId, cve, settings, this.setLoadingSteps,
        fetchWithFallback, parsePatchAndAdvisoryResponse, getHeuristicPatchesAndAdvisories
    );

    this.updateSteps(`🛡️ Agent validating AI findings for ${cveId}...`);
    const validation = await ValidationService.validateAIFindings(aiThreatIntel, cveId, this.setLoadingSteps);

    this.updateSteps(`💯 Agent scoring confidence for ${cveId}...`);
    const confidence = ConfidenceScorer.scoreAIFindings(
        aiThreatIntel,
        validation,
        { discoveredSources: ['NVD', 'EPSS', 'AI_WEB_SEARCH'] } // This might need dynamic update based on actual sources found
    );

    // Constructing discoveredSources and sources (logic from APIService)
    // This part might need refinement if the agent is to be more autonomous in source discovery reporting
    const discoveredSources = ['NVD'];
    const sources: any[] = [{ name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${cveId}`, aiDiscovered: false }];

    if (epss) {
        discoveredSources.push('EPSS/FIRST');
        sources.push({ name: 'EPSS', url: `https://api.first.org/data/v1/epss?cve=${cveId}`, aiDiscovered: false });
    }
    if (aiThreatIntel.intelligenceSummary?.analysisMethod === 'GROUNDING_INFO_ONLY' && aiThreatIntel.intelligenceSummary.searchQueries?.length > 0) {
        discoveredSources.push('AI Performed Searches');
        sources.push({
          name: 'AI Search Queries Performed',
          type: 'ai-search-queries',
          queries: aiThreatIntel.intelligenceSummary.searchQueries,
          aiDiscovered: true,
          description: 'The AI performed these web searches but did not provide a textual summary based on them.'
        });
    }
    // ... (add other source population logic for KEV, Exploits, Vendor Advisories as in APIService) ...
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
                verified: validation.exploits?.verifiedExploits?.some(v => v.url === exploit.url) || false,
                citationUrl: exploit.citationUrl
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
                url: advisory.url || '', // Ensure URL is present from prompt update
                aiDiscovered: true,
                patchAvailable: advisory.patchAvailable,
                severity: advisory.severity,
                verified: validation.vendorAdvisories?.verifiedAdvisories?.some(v => v.vendor === advisory.vendor) || false,
                citationUrl: advisory.citationUrl
              });
            }
          });
        }
      }


    const intelligenceSummary = aiThreatIntel.intelligenceSummary || {
        sourcesAnalyzed: discoveredSources.length,
        exploitsFound: aiThreatIntel.exploitDiscovery?.totalCount || 0,
        vendorAdvisoriesFound: aiThreatIntel.vendorAdvisories?.count || 0,
        activeExploitation: aiThreatIntel.activeExploitation?.confirmed || false,
        cisaKevListed: aiThreatIntel.cisaKev?.listed || false,
        threatLevel: aiThreatIntel.overallThreatLevel || 'MEDIUM', // Default
        dataFreshness: 'AI_WEB_SEARCH', // Default
        analysisMethod: 'AI_WEB_SEARCH_VALIDATED', // Default
        confidenceLevel: confidence.overall,
        aiEnhanced: true,
        validated: true
    };
    intelligenceSummary.sourcesAnalyzed = discoveredSources.length; // Ensure this is updated

    const threatLevel = aiThreatIntel.overallThreatLevel || intelligenceSummary.threatLevel;
    const summary = aiThreatIntel.summary || `AI-driven analysis for ${cveId}. Confidence: ${confidence.overall}. Threat: ${threatLevel}.`;

    const enhancedVulnerability = {
        cve,
        epss,
        kev: { ...aiThreatIntel.cisaKev, validated: validation.cisaKev?.verified || false, actualStatus: validation.cisaKev?.actualStatus },
        exploits: { ...aiThreatIntel.exploitDiscovery, validated: validation.exploits?.verified || false, verifiedCount: validation.exploits?.verifiedExploits?.length || 0 },
        vendorAdvisories: { ...aiThreatIntel.vendorAdvisories, validated: validation.vendorAdvisories?.verified || false },
        cveValidation: aiThreatIntel.cveValidation, // Assuming this comes from aiThreatIntel or a dedicated step
        technicalAnalysis: aiThreatIntel.technicalAnalysis,
        github: {
            found: (aiThreatIntel.exploitDiscovery?.githubRepos || 0) > 0 || (aiThreatIntel.vendorAdvisories?.count || 0) > 0,
            count: (aiThreatIntel.exploitDiscovery?.githubRepos || 0) + (aiThreatIntel.vendorAdvisories?.count || 0)
        },
        activeExploitation: aiThreatIntel.activeExploitation,
        threatIntelligence: aiThreatIntel.threatIntelligence,
        intelligenceSummary: intelligenceSummary,
        patches: patchAdvisoryData.patches || [],
        advisories: patchAdvisoryData.advisories || [],
        patchSearchSummary: patchAdvisoryData.searchSummary || {},
        sources,
        discoveredSources: [...new Set(discoveredSources)], // Deduplicate
        summary,
        threatLevel,
        dataFreshness: intelligenceSummary.dataFreshness,
        lastUpdated: new Date().toISOString(),
        searchTimestamp: new Date().toISOString(), // Or from a more specific part of the process
        ragEnhanced: true, // Assuming RAG is used
        aiSearchPerformed: true, // By definition of this agent
        aiWebGrounded: true, // If AI searches were done
        enhancedSources: [...new Set(discoveredSources)],
        analysisMethod: intelligenceSummary.analysisMethod,
        validation: validation,
        confidence: confidence,
        hallucinationFlags: aiThreatIntel.hallucinationFlags || [],
        extractionMetadata: aiThreatIntel.extractionMetadata,
        validationTimestamp: new Date().toISOString(),
        enhancedWithValidation: true
    };

    this.updateSteps(`💾 Agent potentially storing refined summary for ${cveId} in RAG DB...`);
    if (ragDatabase?.initialized && (confidence.overall === 'HIGH' || confidence.overall === 'MEDIUM')) {
        let ragDocContent = `Refined AI Summary for ${cveId}:\nOverall Threat: ${threatLevel}\nSummary: ${summary}\n`;
        if (aiThreatIntel.cisaKev?.listed) ragDocContent += `CISA KEV: Listed. Details: ${aiThreatIntel.cisaKev.details || 'Not specified'}\n`;
        if (aiThreatIntel.activeExploitation?.confirmed) ragDocContent += `Active Exploitation: Confirmed. Details: ${aiThreatIntel.activeExploitation.details || 'Not specified'}\n`;
        if (aiThreatIntel.exploitDiscovery?.found && aiThreatIntel.exploitDiscovery.exploits && aiThreatIntel.exploitDiscovery.exploits.length > 0) {
          ragDocContent += `Public Exploits (${aiThreatIntel.exploitDiscovery.totalCount}):\n`;
          aiThreatIntel.exploitDiscovery.exploits.slice(0, 2).forEach(ex => {
            ragDocContent += `- Type: ${ex.type || 'N/A'}, Source: ${ex.source || 'N/A'}, Reliability: ${ex.reliability || 'N/A'}, URL: ${ex.url || 'N/A'}\n Description: ${(ex.description || 'N/A').substring(0,100)}...\n Citation: ${ex.citationUrl || 'N/A'}\n`;
          });
        }
        if (patchAdvisoryData.patches && patchAdvisoryData.patches.length > 0) {
            ragDocContent += `Patches (${patchAdvisoryData.patches.length}):\n`;
            patchAdvisoryData.patches.slice(0,1).forEach(p => {
                 ragDocContent += `- Vendor: ${p.vendor || 'N/A'}, Product: ${p.product || 'N/A'}, Version: ${p.patchVersion || 'N/A'}, URL: ${p.downloadUrl || 'N/A'}\n Advisory: ${p.advisoryUrl || 'N/A'}, Citation: ${p.citationUrl || 'N/A'}\n`;
            });
        }
        if (patchAdvisoryData.advisories && patchAdvisoryData.advisories.length > 0) {
            ragDocContent += `Advisories (${patchAdvisoryData.advisories.length}):\n`;
            patchAdvisoryData.advisories.slice(0,1).forEach(a => {
                ragDocContent += `- Source: ${a.source || 'N/A'}, Title: ${a.title || 'N/A'}, URL: ${a.url || 'N/A'}, Citation: ${a.citationUrl || 'N/A'}\n`;
            });
        }

        const existingDocs = await ragDatabase.search(`Refined AI Summary for ${cveId}`, 1, { cveId: cveId, source: 'self-ai-refined-summary-agent' }); // Search for agent's own summaries
        let shouldAdd = true;
        if (existingDocs.length > 0 && existingDocs[0].metadata?.timestamp) {
            const lastAddedTime = new Date(existingDocs[0].metadata.timestamp).getTime();
            if ((new Date().getTime() - lastAddedTime) < 24 * 60 * 60 * 1000) { // 24 hours
                 console.log(`Agent: Skipping RAG update for ${cveId}, recent agent summary exists.`);
                 shouldAdd = false;
            }
        }
        if (shouldAdd) {
            try {
                await ragDatabase.addDocument(
                    ragDocContent,
                    {
                        title: `Refined AI Analysis - ${cveId} (${confidence.overall} Confidence) - Agent`,
                        category: 'ai-refined-summary', // Consistent category
                        tags: ['ai-refined', 'agent-generated', cveId.toLowerCase(), threatLevel.toLowerCase(), confidence.overall.toLowerCase()],
                        source: 'self-ai-refined-summary-agent', // Specific source for agent summaries
                        cveId: cveId,
                        timestamp: new Date().toISOString(),
                        confidence: confidence.overall,
                        threatLevel: threatLevel
                    }
                );
                this.updateSteps(`💾 Agent: Stored refined AI summary for ${cveId} in RAG DB.`);
            } catch (ragError) {
                console.error(`Agent: Failed to store refined AI summary for ${cveId} in RAG:`, ragError);
            }
        }
    }

    this.updateSteps(`✅ Research Agent analysis complete for ${cveId}.`);
    return enhancedVulnerability;
  }
}
