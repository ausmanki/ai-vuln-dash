// src/agents/ResearchAgent.ts
import { APIService } from '../services/APIService'; // Will be used to call specific static methods if needed, or refactored further
import { ValidationService } from '../services/ValidationService';
import { ConfidenceScorer } from '../services/ConfidenceScorer';
import { ragDatabase } from '../db/EnhancedVectorDatabase'; // Direct import for now
import {
  fetchCVEData,
  fetchEPSSData,
  fetchCISAKEVData,
} from '../services/DataFetchingService';
import {
  fetchPatchesAndAdvisories,
  fetchAIThreatIntelligence,
  // generateAIAnalysis, // generateAIAnalysis is typically user-triggered, might not be part of this agent's primary flow initially
} from '../services/AIEnhancementService';
import { AgentSettings, InformationSource, PatchData } from '../types/cveData';
import { AIThreatIntelData } from '../types/aiThreatIntel';
import {
    processCVEData,
    parseAIThreatIntelligence,
    performHeuristicAnalysis,
    parsePatchAndAdvisoryResponse,
    getHeuristicPatchesAndAdvisories,
    fetchWithFallback, // Add this import
} from '../services/UtilityService';


export class ResearchAgent {
  private setLoadingSteps: (stepsUpdater: (prev: string[]) => string[]) => void;

  constructor(setLoadingSteps?: (stepsUpdater: (prev: string[]) => string[]) => void) {
    this.setLoadingSteps = setLoadingSteps || (() => {});
  }

  private updateSteps(message: string) {
    this.setLoadingSteps(prev => [...prev, message]);
  }

  async analyzeCVE(
    cveId: string,
    apiKeys: { nvd?: string; geminiApiKey?: string },
    settings: AgentSettings
  ) {
    this.updateSteps(`🚀 Research Agent starting analysis for ${cveId}...`);

    // RAG Initialization (moved from APIService)
    if (ragDatabase && !ragDatabase.initialized) {
        this.updateSteps(`📚 Initializing RAG knowledge base (agent)...`);
        // Use the geminiApiKey from settings if available, as it's passed for AI calls
        await ragDatabase.initialize(settings.geminiApiKey || apiKeys.geminiApiKey);
    }

    this.updateSteps(`🔍 Agent fetching primary data (NVD, EPSS, CISA KEV) for ${cveId}...`);
    
    // Create AI settings object for all data fetching operations
    const aiSettingsForFetch = {
        geminiApiKey: apiKeys.geminiApiKey || settings.geminiApiKey,
        geminiModel: settings.geminiModel || 'gemini-1.5-flash'
    };

    this.updateSteps(`🤖 AI fallback configured with model: ${aiSettingsForFetch.geminiModel}`);

    // Enhanced: Pass AI settings to ALL data fetching functions for web search fallback
    const [cveResult, epssResult, cisaKevResult] = await Promise.allSettled([
        fetchCVEData(cveId, apiKeys.nvd, this.setLoadingSteps, ragDatabase, aiSettingsForFetch).catch(error => {
            console.error(`CVE fetch error for ${cveId}:`, error);
            this.updateSteps(`❌ CVE fetch failed: ${error.message}`);
            throw error;
        }),
        fetchEPSSData(cveId, this.setLoadingSteps, ragDatabase, aiSettingsForFetch).catch(error => {
            console.error(`EPSS fetch error for ${cveId}:`, error);
            this.updateSteps(`⚠️ EPSS fetch failed: ${error.message}`);
            return null; // EPSS is not critical, allow to continue
        }),
        // Enhanced: Pass AI settings for web search fallback when direct API fails
        fetchCISAKEVData(cveId, this.setLoadingSteps, ragDatabase, null, aiSettingsForFetch).catch(error => {
            console.error(`CISA KEV fetch error for ${cveId}:`, error);
            this.updateSteps(`⚠️ CISA KEV fetch failed: ${error.message}`);
            return { 
                listed: false, 
                details: null, 
                source: 'error', 
                error: error.message,
                lastChecked: new Date().toISOString()
            }; // CISA KEV is not critical, allow to continue
        })
    ]);

    console.log(`CVE Result:`, cveResult);
    console.log(`EPSS Result:`, epssResult);
    console.log(`CISA KEV Result:`, cisaKevResult);
    
    const cve = cveResult.status === 'fulfilled' ? cveResult.value : null;
    const epss = epssResult.status === 'fulfilled' ? epssResult.value : null;
    const cisaKev = cisaKevResult.status === 'fulfilled' ? cisaKevResult.value : null;

    // Enhanced KEV status reporting
    if (cisaKev?.listed) {
        this.updateSteps(`🚨 CRITICAL: ${cveId} is on CISA KEV - Active exploitation confirmed!`);
        if (cisaKev.source === 'ai-web-search') {
            this.updateSteps(`🤖 KEV status verified via AI web search of CISA catalog`);
        }
    } else if (cisaKev?.source === 'ai-web-search') {
        this.updateSteps(`✅ AI search confirmed ${cveId} not in CISA KEV catalog`);
    } else if (cisaKev?.source === 'error') {
        this.updateSteps(`⚠️ Could not verify CISA KEV status for ${cveId} - ${cisaKev.error}`);
    } else if (cisaKev && !cisaKev.listed) {
        this.updateSteps(`✅ ${cveId} not found in CISA KEV catalog (not actively exploited)`);
    }

    if (!cve) {
        const errorDetails = cveResult.status === 'rejected' ? cveResult.reason : 'Unknown error';
        this.updateSteps(`❌ Agent failed to fetch critical CVE data for ${cveId}. Error: ${errorDetails?.message || errorDetails}`);
        
        // Check if CVE format is valid
        const cvePattern = /^CVE-\d{4}-\d{4,}$/;
        if (!cvePattern.test(cveId)) {
            throw new Error(`Agent: Invalid CVE format for ${cveId}. Expected format: CVE-YYYY-NNNN`);
        }
        
        // Check if CVE number is reasonable
        const match = cveId.match(/^CVE-(\d{4})-(\d+)$/);
        if (match) {
            const year = parseInt(match[1]);
            const number = parseInt(match[2]);
            if (number > 50000) {
                throw new Error(`Agent: CVE number ${number} seems unusually high for ${year}. Please verify this CVE exists.`);
            }
        }
        
        throw new Error(`Agent: CVE ${cveId} not found in NVD database. This CVE may not exist or may not be publicly available yet. Please verify the CVE ID.`);
    }

    this.updateSteps(`🤖 Agent fetching AI threat intelligence for ${cveId}...`);
    const aiThreatIntel: AIThreatIntelData = await fetchAIThreatIntelligence(
        cveId,
        cve,
        epss,
        settings,
        this.setLoadingSteps,
        ragDatabase,
        fetchWithFallback,
        parseAIThreatIntelligence,
        performHeuristicAnalysis
    );

    this.updateSteps(`🔧 Agent fetching patches and advisories for ${cveId}...`);
    const patchAdvisoryData: PatchData = await fetchPatchesAndAdvisories(
        cveId,
        cve,
        settings,
        this.setLoadingSteps,
        fetchWithFallback,
        parsePatchAndAdvisoryResponse,
        getHeuristicPatchesAndAdvisories
    );

    this.updateSteps(`🛡️ Agent validating AI findings for ${cveId}...`);
    const validation = await ValidationService.validateAIFindings(
        cveId,
        cve,
        aiThreatIntel,
        patchAdvisoryData
    );

    this.updateSteps(`💯 Agent scoring confidence for ${cveId}...`);
    const confidence = ConfidenceScorer.scoreAIFindings(
        aiThreatIntel,
        validation,
        { discoveredSources: ['NVD', 'EPSS', 'CISA_KEV', 'AI_WEB_SEARCH'] } // Enhanced with CISA KEV
    );

    // Constructing discoveredSources and sources (enhanced logic from APIService)
    const discoveredSources = ['NVD'];
    const sources: InformationSource[] = [
      { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${cveId}`, aiDiscovered: false }
    ];

    if (epss) {
        discoveredSources.push('EPSS/FIRST');
        sources.push({ name: 'EPSS', url: `https://api.first.org/data/v1/epss?cve=${cveId}`, aiDiscovered: false });
    }
    
    // Enhanced CISA KEV source handling
    if (cisaKev) {
        discoveredSources.push('CISA KEV');
        sources.push({ 
          name: 'CISA KEV', 
          url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 
          aiDiscovered: cisaKev.source === 'ai-web-search',
          kevListed: cisaKev.listed,
          dateAdded: cisaKev.dateAdded,
          priority: cisaKev.listed ? 'CRITICAL' : 'INFO',
          source: cisaKev.source,
          confidence: cisaKev.confidence || 'MEDIUM',
          verified: cisaKev.source === 'cisa-kev-direct' ? true : false
        });
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
    
    // Add other source population logic for KEV, Exploits, Vendor Advisories
    if (aiThreatIntel.cisaKev?.listed) {
        // Avoid duplicate CISA KEV entries
        if (!sources.some(s => s.name === 'CISA KEV' && s.aiDiscovered === true)) {
            discoveredSources.push('AI-Discovered CISA KEV');
            sources.push({
              name: 'AI-Discovered CISA KEV',
              url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
              aiDiscovered: aiThreatIntel.cisaKev?.aiDiscovered ?? true,
              verified: validation.cisaKev?.verified || false
            });
        }
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

    if (patchAdvisoryData.patches && patchAdvisoryData.patches.length > 0) {
        discoveredSources.push('Vendor Patches');
        patchAdvisoryData.patches.forEach(patch => {
          const patchName = `${patch.vendor} Patch${patch.patchVersion ? ' ' + patch.patchVersion : ''}`.trim();
          sources.push({
            name: patchName,
            url: patch.downloadUrl || patch.advisoryUrl || '',
            aiDiscovered: true,
            vendor: patch.vendor,
            product: patch.product,
            patchVersion: patch.patchVersion,
            verified: validation.vendorConfirmation?.patches?.some(p => (p.downloadUrl && patch.downloadUrl && p.downloadUrl === patch.downloadUrl) || (p.advisoryUrl && patch.advisoryUrl && p.advisoryUrl === patch.advisoryUrl)) || false,
            citationUrl: patch.citationUrl
          });
        });
    }

    if (patchAdvisoryData.advisories && patchAdvisoryData.advisories.length > 0) {
        discoveredSources.push('Vendor Patch Advisories');
        patchAdvisoryData.advisories.forEach(advisory => {
          const advName = advisory.title || `${advisory.vendor} Advisory`;
          if (!sources.some(s => s.name === advName)) {
            sources.push({
              name: advName,
              url: advisory.url || '',
              aiDiscovered: true,
              vendor: advisory.vendor,
              severity: advisory.severity,
              patchAvailable: advisory.patchAvailable,
              verified: validation.vendorConfirmation?.advisories?.some(a => a.url === advisory.url) || false,
              citationUrl: advisory.citationUrl
            });
          }
        });
    }

    // Enhanced intelligence summary with CISA KEV information
    const intelligenceSummary = aiThreatIntel.intelligenceSummary || {
        sourcesAnalyzed: discoveredSources.length,
        exploitsFound: aiThreatIntel.exploitDiscovery?.totalCount || 0,
        vendorAdvisoriesFound: aiThreatIntel.vendorAdvisories?.count || 0,
        activeExploitation: aiThreatIntel.activeExploitation?.confirmed || cisaKev?.listed || false,
        cisaKevListed: aiThreatIntel.cisaKev?.listed || cisaKev?.listed || false,
        threatLevel: aiThreatIntel.overallThreatLevel || 'MEDIUM', // Default
        dataFreshness: 'AI_WEB_SEARCH', // Default
        analysisMethod: 'AI_WEB_SEARCH_VALIDATED', // Default
        confidenceLevel: confidence.overall,
        aiEnhanced: true,
        validated: true
    };
    intelligenceSummary.sourcesAnalyzed = discoveredSources.length; // Ensure this is updated
    
    // Override CISA KEV status with official data if available
    if (cisaKev?.source === 'cisa-kev-direct' || cisaKev?.source === 'ai-web-search') {
        intelligenceSummary.cisaKevListed = cisaKev.listed;
        intelligenceSummary.activeExploitation = intelligenceSummary.activeExploitation || cisaKev.listed;
    }

    const threatLevel = aiThreatIntel.overallThreatLevel || intelligenceSummary.threatLevel;
    const summary = aiThreatIntel.summary || `AI-driven analysis for ${cveId}. Confidence: ${confidence.overall}. Threat: ${threatLevel}.`;

    const enhancedVulnerability = {
        cve,
        epss,
        cisaKev: cisaKev || { listed: false, lastChecked: new Date().toISOString() },
        kev: { ...aiThreatIntel.cisaKev, validated: validation.cisaKev?.verified || false, actualStatus: validation.cisaKev?.actualStatus, officialKev: cisaKev },
        exploits: { ...aiThreatIntel.exploitDiscovery, validated: validation.exploits?.verified || false, verifiedCount: validation.exploits?.verifiedExploits?.length || 0 },
        vendorAdvisories: { ...aiThreatIntel.vendorAdvisories, validated: validation.vendorAdvisories?.verified || false },
        cveValidation: validation,
        technicalAnalysis: aiThreatIntel.technicalAnalysis,
        github: {
            found: (aiThreatIntel.exploitDiscovery?.githubRepos || 0) > 0 || (aiThreatIntel.vendorAdvisories?.count || 0) > 0,
            count: (aiThreatIntel.exploitDiscovery?.githubRepos || 0) + (aiThreatIntel.vendorAdvisories?.count || 0)
        },
        activeExploitation: aiThreatIntel.activeExploitation || { confirmed: cisaKev?.listed || false, details: cisaKev?.listed ? 'Listed in CISA KEV catalog' : null },
        threatIntelligence: aiThreatIntel.threatIntelligence,
        intelligenceSummary: intelligenceSummary,
        patches: patchAdvisoryData.patches || [],
        advisories: patchAdvisoryData.advisories || [],
        patchSearchSummary: patchAdvisoryData.searchSummary || {},
        sources,
        discoveredSources: [...new Set(discoveredSources)], // Deduplicate
        summary,
        analysisSummary: summary,
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
        
        // Enhanced RAG content with CISA KEV information
        if (cisaKev?.listed) {
            ragDocContent += `CISA KEV: ACTIVELY EXPLOITED - Listed in CISA Known Exploited Vulnerabilities catalog.\n`;
            if (cisaKev.dateAdded) ragDocContent += `Date Added to KEV: ${cisaKev.dateAdded}\n`;
            if (cisaKev.shortDescription) ragDocContent += `KEV Description: ${cisaKev.shortDescription}\n`;
            if (cisaKev.requiredAction) ragDocContent += `Required Action: ${cisaKev.requiredAction}\n`;
            if (cisaKev.dueDate) ragDocContent += `Due Date: ${cisaKev.dueDate}\n`;
            ragDocContent += `KEV Verification Method: ${cisaKev.source}\n`;
        }
        
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
                        threatLevel: threatLevel,
                        cisaKevListed: cisaKev?.listed || false,
                        kevVerificationMethod: cisaKev?.source || 'unknown'
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
