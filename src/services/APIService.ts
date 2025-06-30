import { CONSTANTS } from '../utils/constants';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { fetchCVEData } from './nvdService'; // processCVEData is internal to nvdService
import { fetchEPSSData } from './epssService';
import { fetchAIThreatIntelligence } from './aiThreatIntelService'; // performHeuristicAnalysis is internal to aiThreatIntelService
import { generateAIAnalysis as generateGeminiAIAnalysis } from './geminiService'; // Renamed import

// Enhanced API Service Layer with Multi-Source Intelligence
export class APIService {
  static async fetchWithFallback(url, options = {}) {
    try {
      return await fetch(url, options);
    } catch (corsError) {
      console.log('CORS blocked, trying proxy...');
      const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`;
      const response = await fetch(proxyUrl);

      if (response.ok) {
        const proxyData = await response.json();
        return {
          ok: true,
          json: () => Promise.resolve(JSON.parse(proxyData.contents))
        };
      }
      throw corsError;
    }
  }

  static async fetchVulnerabilityDataWithAI(cveId, setLoadingSteps, apiKeys, settings) {
    try {
      setLoadingSteps(prev => [...prev, `🚀 Starting AI-powered real-time analysis for ${cveId}...`]);

      if (!ragDatabase.initialized) {
        setLoadingSteps(prev => [...prev, `📚 Initializing RAG knowledge base...`]);
        await ragDatabase.initialize(settings.geminiApiKey);
      }

      setLoadingSteps(prev => [...prev, `🔍 Fetching from primary sources (NVD, EPSS)...`]);

      const [cveResult, epssResult] = await Promise.allSettled([
        fetchCVEData(cveId, apiKeys.nvd, setLoadingSteps),
        fetchEPSSData(cveId, setLoadingSteps)
      ]);

      const cve = cveResult.status === 'fulfilled' ? cveResult.value : null;
      const epss = epssResult.status === 'fulfilled' ? epssResult.value : null;

      if (!cve) {
        throw new Error(`Failed to fetch CVE data for ${cveId}`);
      }

      setLoadingSteps(prev => [...prev, `🌐 AI analyzing real-time threat intelligence via web search...`]);

      const aiThreatIntel = await fetchAIThreatIntelligence(cveId, cve, epss, settings, setLoadingSteps);

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
          aiDiscovered: aiThreatIntel.cisaKev.aiDiscovered || true
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
                // @ts-ignore
                reliability: exploit.reliability,
                // @ts-ignore
                description: exploit.description
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
                // @ts-ignore
                patchAvailable: advisory.patchAvailable,
                // @ts-ignore
                severity: advisory.severity
              });
            }
          });
        }
      }

      if (aiThreatIntel.activeExploitation?.confirmed) {
        discoveredSources.push('Threat Intelligence');
        if (!sources.some(s => s.name === 'Threat Intelligence')) {
          sources.push({
            name: 'Threat Intelligence',
            url: '',
            aiDiscovered: true
          });
        }
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
        analysisMethod: 'AI_WEB_SEARCH',
        confidenceLevel: aiThreatIntel.exploitDiscovery?.confidence || 'MEDIUM',
        aiEnhanced: true
      };

      const threatLevel = aiThreatIntel.overallThreatLevel || intelligenceSummary.threatLevel;
      const summary = aiThreatIntel.summary;

      const enhancedVulnerability = {
        cve,
        epss,
        kev: aiThreatIntel.cisaKev,
        exploits: {
          found: aiThreatIntel.exploitDiscovery?.found || false,
          count: aiThreatIntel.exploitDiscovery?.totalCount || 0,
          confidence: aiThreatIntel.exploitDiscovery?.confidence || 'LOW',
          sources: aiThreatIntel.exploitDiscovery?.exploits?.map(e => e.url) || [],
          types: aiThreatIntel.exploitDiscovery?.exploits?.map(e => e.type) || [],
          details: aiThreatIntel.exploitDiscovery?.exploits || [],
          githubRepos: aiThreatIntel.exploitDiscovery?.githubRepos || 0,
          exploitDbEntries: aiThreatIntel.exploitDiscovery?.exploitDbEntries || 0,
          metasploitModules: aiThreatIntel.exploitDiscovery?.metasploitModules || 0
        },
        vendorAdvisories: aiThreatIntel.vendorAdvisories || {
          found: false,
          count: 0,
          advisories: [],
          patchStatus: 'unknown'
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
        analysisMethod: intelligenceSummary.analysisMethod || aiThreatIntel.analysisMethod || 'AI_WEB_SEARCH',
        // @ts-ignore
        patches: aiThreatIntel.patches, // Added from master version
        // @ts-ignore
        advisories: aiThreatIntel.advisories, // Added from master version
        // @ts-ignore
        validation: aiThreatIntel.validation, // Added from master version
        // @ts-ignore
        confidence: aiThreatIntel.confidence, // Added from master version
        // @ts-ignore
        hallucinationFlags: aiThreatIntel.hallucinationFlags, // Added from master version
        // @ts-ignore
        extractionMetadata: aiThreatIntel.extractionMetadata // Added from master version
      };

      setLoadingSteps(prev => [...prev, `✅ AI web-based analysis complete: ${discoveredSources.length} sources analyzed, ${threatLevel} threat level`]);

      return enhancedVulnerability;

    } catch (error) {
      console.error(`Error processing ${cveId}:`, error);
      throw error;
    }
  }

  static async generateAIAnalysis(vulnerability, apiKey, model, settings = {}) {
    return generateGeminiAIAnalysis(vulnerability, apiKey, model, settings);
  }
}
