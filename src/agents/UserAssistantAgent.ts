import { APIService } from '../services/APIService';
import { AppContext } // Assuming settings might come from AppContext
// We might need to import specific types for vulnerability data if we strongly type responses.
// For now, we'll keep it simple and return strings or simple objects.

// Define a simple structure for responses, can be expanded later
interface ChatResponse {
  text: string;
  data?: any; // Optional structured data
  error?: string;
}

export class UserAssistantAgent {
  private settings: any; // To store settings if needed

  constructor(settings?: any) {
    this.settings = settings || {};
    // Initialize any services if they require instantiation and settings
    // For now, APIService uses static methods, so no instantiation needed here.
  }

  public async handleQuery(query: string, cveId: string): Promise<ChatResponse> {
    if (!cveId || !/CVE-\d{4}-\d{4,7}/i.test(cveId)) {
      return { text: "Please provide a valid CVE ID to ask questions about.", error: "Invalid CVE ID" };
    }

    const lowerQuery = query.toLowerCase();

    try {
      if (lowerQuery.includes("epss score")) {
        return this.getEPSSScore(cveId);
      } else if (lowerQuery.includes("exploit") || lowerQuery.includes("exploited")) {
        return this.getExploitInfo(cveId);
      } else if (lowerQuery.includes("summarize") || lowerQuery.includes("summary") || lowerQuery.includes("overview") || lowerQuery.includes("tell me about")) {
        return this.getSummary(cveId);
      } else if (lowerQuery.includes("patch") || lowerQuery.includes("patches") || lowerQuery.includes("advisory") || lowerQuery.includes("advisories")) {
        return this.getPatchAndAdvisoryInfo(cveId);
      }
      else {
        return { text: "I'm not sure how to answer that. You can ask about EPSS scores, exploits, summaries, or patches for a CVE." };
      }
    } catch (error) {
      console.error("Error handling query:", error);
      return { text: `Sorry, I encountered an error trying to answer that: ${error.message}`, error: error.message };
    }
  }

  private async getEPSSScore(cveId: string): Promise<ChatResponse> {
    try {
      // Assuming APIService.fetchEPSSData might need setLoadingSteps, but for agent, we might omit or use a dummy.
      // Also, it interacts with ragDatabase, which APIService handles.
      const epssData = await APIService.fetchEPSSData(cveId, () => {}); // Passing a dummy setLoadingSteps
      if (epssData && epssData.epss) {
        return {
          text: `The EPSS score for ${cveId} is ${epssData.epssPercentage}% (Percentile: ${epssData.percentile}). This data was last updated on ${epssData.date}.`,
          data: epssData
        };
      } else {
        return { text: `I couldn't find EPSS data for ${cveId}. It might not be available.` };
      }
    } catch (error) {
      console.error(`Error fetching EPSS for ${cveId}:`, error);
      return { text: `Sorry, I couldn't fetch the EPSS score for ${cveId}. Error: ${error.message}`, error: error.message };
    }
  }

  private async getExploitInfo(cveId: string): Promise<ChatResponse> {
    try {
      // We need CVE data and EPSS data to pass to fetchAIThreatIntelligence
      // Let's fetch minimal CVE data first.
      // The NVD API key and Gemini API key would ideally come from settings.
      // For now, assuming APIService or its underlying services can access them if configured globally,
      // or they are passed via `this.settings` if the agent is instantiated with them.

      const cveData = await APIService.fetchCVEData(cveId, this.settings?.nvdApiKey, () => {});
      if (!cveData) {
        return { text: `Could not retrieve basic data for ${cveId} to check for exploits.`, error: "CVE data fetch failed" };
      }
      const epssData = await APIService.fetchEPSSData(cveId, () => {}); // epssData can be null, that's okay

      // fetchAIThreatIntelligence requires settings for Gemini API key and model
      const aiThreatIntel = await APIService.fetchAIThreatIntelligence(cveId, cveData, epssData, this.settings, () => {});

      let responseText = `Regarding exploits for ${cveId}:\n`;
      let foundExploitInfo = false;

      if (aiThreatIntel.cisaKev?.listed) {
        responseText += `- This CVE is listed in the CISA Known Exploited Vulnerabilities (KEV) catalog. Details: ${aiThreatIntel.cisaKev.details || 'See CISA KEV for more.'}\n`;
        foundExploitInfo = true;
      } else {
        responseText += `- Not currently listed in CISA KEV.\n`;
      }

      if (aiThreatIntel.activeExploitation?.confirmed) {
        responseText += `- There is evidence of active exploitation in the wild. Details: ${aiThreatIntel.activeExploitation.details || 'Monitoring suggested.'}\n`;
        foundExploitInfo = true;
      } else {
        responseText += `- No confirmed reports of widespread active exploitation found by AI at this time.\n`;
      }

      if (aiThreatIntel.exploitDiscovery?.found && aiThreatIntel.exploitDiscovery.exploits && aiThreatIntel.exploitDiscovery.exploits.length > 0) {
        responseText += `- Public exploits found: ${aiThreatIntel.exploitDiscovery.totalCount}. Examples:\n`;
        aiThreatIntel.exploitDiscovery.exploits.slice(0, 2).forEach(ex => {
          responseText += `  - Type: ${ex.type || 'N/A'}, Source: ${ex.source || 'N/A'}${ex.url ? `, URL: ${ex.url}` : ''}\n`;
        });
        foundExploitInfo = true;
      } else {
        responseText += `- No public proof-of-concept exploits were immediately found by AI.\n`;
      }

      if (!foundExploitInfo) {
        responseText = `I checked for exploits for ${cveId}. It's not listed in CISA KEV, no widespread active exploitation was confirmed, and no public PoCs were immediately found by the AI search. However, this doesn't mean it's not exploitable.`;
      }

      return { text: responseText, data: aiThreatIntel };
    } catch (error) {
      console.error(`Error fetching exploit info for ${cveId}:`, error);
      return { text: `Sorry, I couldn't fetch exploit information for ${cveId}. Error: ${error.message}`, error: error.message };
    }
  }

  private async getPatchAndAdvisoryInfo(cveId: string): Promise<ChatResponse> {
    try {
      const cveData = await APIService.fetchCVEData(cveId, this.settings?.nvdApiKey, () => {});
      if (!cveData) {
        return { text: `Could not retrieve basic data for ${cveId} to check for patches/advisories.`, error: "CVE data fetch failed" };
      }

      const patchAdvisoryData = await APIService.fetchPatchesAndAdvisories(cveId, cveData, this.settings, () => {});

      let responseText = `For patches and advisories regarding ${cveId}:\n`;
      let foundInfo = false;

      if (patchAdvisoryData.patches && patchAdvisoryData.patches.length > 0) {
        responseText += `- Found ${patchAdvisoryData.patches.length} potential patch(es):\n`;
        patchAdvisoryData.patches.slice(0,2).forEach(p => {
          responseText += `  - Vendor: ${p.vendor || 'N/A'}, Product: ${p.product || 'N/A'}${p.downloadUrl ? `, Download: ${p.downloadUrl}` : ''}\n`;
        });
        foundInfo = true;
      } else {
        responseText += `- No direct patch download links were immediately found by AI.\n`;
      }

      if (patchAdvisoryData.advisories && patchAdvisoryData.advisories.length > 0) {
        responseText += `- Found ${patchAdvisoryData.advisories.length} advisory(s):\n`;
        patchAdvisoryData.advisories.slice(0,2).forEach(a => {
          responseText += `  - Source: ${a.source || 'N/A'}, Title: ${a.title || 'N/A'}${a.url ? `, URL: ${a.url}` : ''}\n`;
        });
        foundInfo = true;
      } else {
        responseText += `- No specific advisories were immediately found by AI.\n`;
      }

      if (!foundInfo) {
        responseText = `I searched for patches and advisories for ${cveId} but did not immediately find specific download links or advisories through the AI search. It's recommended to check vendor websites directly.`;
      }

      if (patchAdvisoryData.searchSummary) {
          responseText += `\n(AI search summary: ${patchAdvisoryData.searchSummary.patchesFound} patches, ${patchAdvisoryData.searchSummary.advisoriesFound} advisories from searched vendors).`;
      }

      return { text: responseText, data: patchAdvisoryData };
    } catch (error) {
      console.error(`Error fetching patch/advisory info for ${cveId}:`, error);
      return { text: `Sorry, I couldn't fetch patch and advisory information for ${cveId}. Error: ${error.message}`, error: error.message };
    }
  }

  private async getSummary(cveId: string): Promise<ChatResponse> {
    try {
      // For a summary, we probably want the full enhanced vulnerability data.
      // This means using the ResearchAgent or a similar comprehensive fetch.
      // APIService.fetchVulnerabilityDataWithAI uses ResearchAgent.
      // It needs API keys and settings.
      const vulnerability = await APIService.fetchVulnerabilityDataWithAI(cveId, () => {}, { nvd: this.settings?.nvdApiKey }, this.settings);

      if (!vulnerability || !vulnerability.cve) {
        return { text: `I couldn't retrieve a summary for ${cveId}. Essential data might be missing.` };
      }

      // Now, construct a summary. The `vulnerability.summary` might already be good.
      // Or we can call generateAIAnalysis for a more narrative summary.
      // Let's try using the existing vulnerability.summary and add key details.

      let summaryText = `Here's a summary for ${vulnerability.cve.id}:\n`;
      summaryText += `- Description: ${vulnerability.cve.description?.substring(0, 200) + "..." || 'Not available.'}\n`;
      if (vulnerability.cve.cvssV3) {
        summaryText += `- CVSS v3 Score: ${vulnerability.cve.cvssV3.baseScore} (${vulnerability.cve.cvssV3.baseSeverity})\n`;
      } else if (vulnerability.cve.cvssV2) {
        summaryText += `- CVSS v2 Score: ${vulnerability.cve.cvssV2.baseScore} (${vulnerability.cve.cvssV2.severity})\n`;
      }

      if (vulnerability.epss) {
        summaryText += `- EPSS Score: ${vulnerability.epss.epssPercentage}% (Exploitability percentile: ${vulnerability.epss.percentile})\n`;
      }

      if (vulnerability.kev?.listed) {
        summaryText += `- CISA KEV: LISTED (Known to be exploited)\n`;
      }

      if (vulnerability.exploits?.found) {
        summaryText += `- Public Exploits: ${vulnerability.exploits.count} found.\n`;
      }

      if (vulnerability.activeExploitation?.confirmed) {
        summaryText += `- Active Exploitation: Confirmed in the wild.\n`;
      }

      if (vulnerability.summary) { // This is the AI-generated summary from ResearchAgent
        summaryText += `\nAI-Generated Summary Overview:\n${vulnerability.summary}\n`;
      }

      // Alternative: Call generateAIAnalysis for a fresh summary
      // const aiAnalysis = await APIService.generateAIAnalysis(vulnerability, this.settings.geminiApiKey, this.settings.geminiModel, this.settings);
      // if (aiAnalysis && aiAnalysis.analysis) {
      //   summaryText += `\nAI Detailed Analysis:\n${aiAnalysis.analysis.substring(0, 300)}...\n`;
      // }


      return { text: summaryText, data: vulnerability };
    } catch (error) {
      console.error(`Error fetching summary for ${cveId}:`, error);
      return { text: `Sorry, I couldn't generate a summary for ${cveId}. Error: ${error.message}`, error: error.message };
    }
  }
}
