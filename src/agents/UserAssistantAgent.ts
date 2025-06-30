import { APIService } from '../services/APIService';
import {
  AgentSettings,
  ChatResponse,
  EPSSData,
  PatchData,
  EnhancedVulnerabilityData,
  CVEValidationData,
  BaseCVEInfo,
  CisaKevDetails,
  ActiveExploitationData,
  ExploitDiscoveryData,
  AISummaryData
} from '../types/cveData';

const CVE_REGEX = /CVE-\d{4}-\d{4,7}/i;

// Helper type for the expected structure from APIService.fetchAIThreatIntelligence
// This should ideally be replaced by a strong type returned by APIService itself.
interface InternalAIThreatIntelData {
  cisaKev?: Partial<CisaKevDetails>;
  activeExploitation?: Partial<ActiveExploitationData>;
  exploitDiscovery?: Partial<ExploitDiscoveryData>;
  // Potentially other fields like cveValidation, technicalAnalysis, etc.
}

export class UserAssistantAgent {
  private settings: AgentSettings;
  private currentCveIdForSession: string | null = null;

  constructor(settings?: AgentSettings) {
    this.settings = settings || {};
  }

  public setContextualCVE(cveId: string): ChatResponse | null {
    if (cveId && CVE_REGEX.test(cveId) && cveId !== this.currentCveIdForSession) {
      this.currentCveIdForSession = cveId.toUpperCase();
      return {
        text: `Okay, I'm now focused on ${this.currentCveIdForSession} from your main view. How can I help with it?`,
        sender: 'system',
        id: Date.now().toString(),
      };
    }
    return null;
  }

  public async handleQuery(query: string): Promise<ChatResponse> {
    const lowerQuery = query.toLowerCase();
    const cveMatch = query.match(CVE_REGEX);
    let operationalCveId: string | null = null;

    if (cveMatch) {
      operationalCveId = cveMatch[0].toUpperCase();
      this.currentCveIdForSession = operationalCveId;
    } else {
      operationalCveId = this.currentCveIdForSession;
    }

    if (!operationalCveId) {
      return { text: "Please specify a CVE ID in your query (e.g., 'What about CVE-2023-1234?') or ask me to focus on one first." };
    }

    if (cveMatch && query.trim().toUpperCase() === operationalCveId) {
        return { text: `Okay, I'm now focused on ${operationalCveId}. What would you like to know about it? (e.g., summary, EPSS score, patches)` };
    }

    // Define intents
    const intents = [
      {
        name: 'getEPSSScore',
        keywords: ['epss score', 'epss value', 'exploit prediction'],
        handler: this.getEPSSScore
      },
      {
        name: 'getExploitInfo',
        keywords: ['exploit', 'exploited', 'exploitation details'], // "exploit" is broad, ensure it's desired
        handler: this.getExploitInfo
      },
      {
        name: 'getValidationInfo',
        keywords: ['validate', 'validity', 'legitimacy', 'is valid', 'is it real'],
        handler: this.getValidationInfo
      },
      {
        name: 'getPatchAndAdvisoryInfo',
        keywords: ['patch', 'patches', 'advisory', 'advisories', 'fix', 'remediation', 'mitigation'],
        handler: this.getPatchAndAdvisoryInfo
      },
      {
        name: 'getSummary', // Should generally be less specific or a fallback if other keywords for summary are used
        keywords: ['summarize', 'summary', 'overview', 'tell me about', 'details for'],
        handler: this.getSummary
      },
      // Add more intents here. Order might matter if keywords overlap.
      // More specific intents should generally come before broader ones.
    ];

    try {
      for (const intent of intents) {
        if (intent.keywords.some(keyword => lowerQuery.includes(keyword))) {
          return await intent.handler.call(this, operationalCveId);
        }
      }
      // Fallback if no intent is matched but a CVE context exists
      return { text: `I have context for ${operationalCveId}, but I'm not sure what you're asking. You can ask for EPSS score, summary, patches, validation, etc.` };

    } catch (error: any) {
      console.error(`Error handling query for CVE ${operationalCveId}:`, error);
      return { text: `Sorry, I encountered an error trying to answer that: ${error.message}`, error: error.message };
    }
  }

  private async getEPSSScore(cveId: string): Promise<ChatResponse<EPSSData | null>> {
    try {
      const epssData = await APIService.fetchEPSSData(cveId, () => {}) as EPSSData | null;
      if (epssData && epssData.epss) {
        return {
          text: `The EPSS score for ${cveId} is ${epssData.epssPercentage}% (Percentile: ${epssData.percentile}). This data was last updated on ${epssData.date}.`,
          data: epssData
        };
      } else {
        return { text: `I couldn't find EPSS data for ${cveId}. It might not be available.`, data: null };
      }
    } catch (error: any) {
      console.error(`Error fetching EPSS for ${cveId}:`, error);
      return { text: `Sorry, I couldn't fetch the EPSS score for ${cveId}. Error: ${error.message}`, error: error.message, data: null };
    }
  }

  private async getExploitInfo(cveId: string): Promise<ChatResponse<Partial<InternalAIThreatIntelData>>> {
    try {
      const cveData = await APIService.fetchCVEData(cveId, this.settings?.nvdApiKey, () => {}) as BaseCVEInfo | null;
      if (!cveData) {
        return { text: `Could not retrieve basic data for ${cveId} to check for exploits.`, error: "CVE data fetch failed" };
      }
      const epssData = await APIService.fetchEPSSData(cveId, () => {}) as EPSSData | null;
      const aiThreatIntel = await APIService.fetchAIThreatIntelligence(cveId, cveData, epssData, this.settings, () => {}) as InternalAIThreatIntelData;

      let responseText = `For ${cveId}, my focus is on providing vendor advisories and patch information to help you mitigate risks.\n`;
      let keyInfoFound = false;
      const returnedData: Partial<InternalAIThreatIntelData> = {};

      if (aiThreatIntel.cisaKev?.listed) {
        responseText += `- **CISA KEV:** This CVE IS LISTED in the CISA Known Exploited Vulnerabilities (KEV) catalog, indicating active exploitation. Details: ${aiThreatIntel.cisaKev.details || 'Refer to CISA for specifics.'}\n`;
        keyInfoFound = true;
        returnedData.cisaKev = aiThreatIntel.cisaKev;
      } else {
        responseText += `- **CISA KEV:** This CVE is NOT listed in the CISA KEV catalog at this time.\n`;
      }

      if (aiThreatIntel.activeExploitation?.confirmed) {
        responseText += `- **Active Exploitation:** AI threat intelligence suggests evidence of active exploitation in the wild. Details: ${aiThreatIntel.activeExploitation.details || 'General reports suggest activity.'}\n`;
        keyInfoFound = true;
        returnedData.activeExploitation = aiThreatIntel.activeExploitation;
      } else {
        responseText += `- **Active Exploitation:** No specific widespread active exploitation was confirmed by AI threat intelligence beyond potential KEV listing.\n`;
      }

      if (aiThreatIntel.exploitDiscovery?.found) {
        responseText += `- **Public Exploit Code:** Publicly available exploit information or PoCs may exist for this vulnerability (AI found ${aiThreatIntel.exploitDiscovery.totalCount} potential indicators).\n`;
        keyInfoFound = true;
        returnedData.exploitDiscovery = { found: true, totalCount: aiThreatIntel.exploitDiscovery.totalCount };
      } else {
         responseText += `- **Public Exploit Code:** AI threat intelligence did not immediately find specific public exploit PoCs.\n`;
      }

      responseText += "\nFor remediation, please check for vendor patches and advisories. You can ask me 'tell me about patches for this CVE'.";

      if (!keyInfoFound && !aiThreatIntel.cisaKev?.listed && !aiThreatIntel.activeExploitation?.confirmed && !aiThreatIntel.exploitDiscovery?.found) {
         responseText = `I've checked for high-level exploit information for ${cveId}. It's not listed in CISA KEV, and AI threat intelligence didn't confirm widespread active exploitation or readily available public PoCs. For security details, please refer to vendor advisories. You can ask 'patches for ${cveId}'.`;
      }

      return { text: responseText, data: returnedData };
    } catch (error: any) {
      console.error(`Error fetching exploit info for ${cveId}:`, error);
      return { text: `Sorry, I couldn't fetch exploit information for ${cveId}. Error: ${error.message}`, error: error.message };
    }
  }

  private async getPatchAndAdvisoryInfo(cveId: string): Promise<ChatResponse<PatchData | null>> {
    try {
      const cveData = await APIService.fetchCVEData(cveId, this.settings?.nvdApiKey, () => {}) as BaseCVEInfo | null;
      if (!cveData) {
        return { text: `Could not retrieve basic data for ${cveId} to check for patches/advisories.`, error: "CVE data fetch failed", data: null };
      }

      const patchAdvisoryData = await APIService.fetchPatchesAndAdvisories(cveId, cveData, this.settings, () => {}) as PatchData | null;

      if (!patchAdvisoryData) {
        return { text: `Could not retrieve patch and advisory data for ${cveId}.`, error: "Patch/Advisory data fetch failed", data: null };
      }

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
    } catch (error: any) {
      console.error(`Error fetching patch/advisory info for ${cveId}:`, error);
      return { text: `Sorry, I couldn't fetch patch and advisory information for ${cveId}. Error: ${error.message}`, error: error.message, data: null };
    }
  }

  private async getSummary(cveId: string): Promise<ChatResponse<AISummaryData | EnhancedVulnerabilityData | null>> {
    try {
      const vulnerabilityDataForAISummary = await APIService.fetchVulnerabilityDataWithAI(cveId, () => {}, { nvd: this.settings?.nvdApiKey }, this.settings) as EnhancedVulnerabilityData | null;

      if (!vulnerabilityDataForAISummary || !vulnerabilityDataForAISummary.cve) {
        return { text: `I couldn't retrieve enough information for ${cveId} to generate an AI summary.`, error: "Comprehensive CVE data fetch failed", data: null };
      }

      const aiAnalysis = await APIService.generateAIAnalysis(
        vulnerabilityDataForAISummary,
        this.settings.geminiApiKey,
        this.settings.geminiModel,
        this.settings
      ) as AISummaryData | null; // Assuming generateAIAnalysis returns this or similar

      if (aiAnalysis && aiAnalysis.analysis) {
        let responseText = `Here's an AI-generated summary for ${cveId}:\n\n`;
        if (vulnerabilityDataForAISummary.cve.cvssV3) {
          responseText += `CVSS v3: ${vulnerabilityDataForAISummary.cve.cvssV3.baseScore} (${vulnerabilityDataForAISummary.cve.cvssV3.baseSeverity})\n`;
        } else if (vulnerabilityDataForAISummary.cve.cvssV2) {
          responseText += `CVSS v2: ${vulnerabilityDataForAISummary.cve.cvssV2.baseScore} (${vulnerabilityDataForAISummary.cve.cvssV2.severity})\n`;
        }
        if (vulnerabilityDataForAISummary.epss) {
          responseText += `EPSS: ${vulnerabilityDataForAISummary.epss.epssPercentage}% (Percentile: ${vulnerabilityDataForAISummary.epss.percentile})\n`;
        }
        if (vulnerabilityDataForAISummary.kev?.listed) {
            responseText += `CISA KEV: LISTED (Known Exploited)\n`;
        }
        responseText += "-----------------------------------\n";
        responseText += aiAnalysis.analysis;
        return { text: responseText, data: aiAnalysis };
      } else {
        let fallbackText = `I retrieved some information for ${cveId}, but couldn't generate a full AI summary.\n`;
        fallbackText += `- Description: ${vulnerabilityDataForAISummary.cve.description?.substring(0, 200) + "..." || 'Not available.'}\n`;
        if (vulnerabilityDataForAISummary.cve.cvssV3) {
            fallbackText += `- CVSS v3 Score: ${vulnerabilityDataForAISummary.cve.cvssV3.baseScore} (${vulnerabilityDataForAISummary.cve.cvssV3.baseSeverity})\n`;
        }
        if (vulnerabilityDataForAISummary.epss) {
            fallbackText += `- EPSS Score: ${vulnerabilityDataForAISummary.epss.epssPercentage}%\n`;
        }
        return { text: fallbackText, data: vulnerabilityDataForAISummary };
      }
    } catch (error: any) {
      console.error(`Error fetching summary for ${cveId}:`, error);
      return { text: `Sorry, I couldn't generate a summary for ${cveId}. Error: ${error.message}`, error: error.message, data: null };
    }
  }

  private async getValidationInfo(cveId: string): Promise<ChatResponse<CVEValidationData | null>> {
    try {
      const vulnerability = await APIService.fetchVulnerabilityDataWithAI(cveId, () => {}, { nvd: this.settings?.nvdApiKey }, this.settings) as EnhancedVulnerabilityData | null;

      if (!vulnerability || !vulnerability.cveValidation) {
        return { text: `I couldn't retrieve detailed validation information for ${cveId}. Basic CVE data might be missing or validation could not be performed.`, error: "Validation data fetch failed or incomplete", data: null };
      }

      const validation = vulnerability.cveValidation;
      const overallConfidence = vulnerability.confidence?.overallValidation || validation.confidence || "Not available";

      let responseText = `Here's the validation analysis for ${cveId} (Confidence: ${overallConfidence}):\n\n`;

      responseText += `**Overall Assessment:** ${validation.recommendation || 'Unavailable'}\n`;
      responseText += `   - Meaning: ${this.getValidationRecommendationMeaning(validation.recommendation)}\n\n`;

      if (validation.summary) {
        responseText += `**AI Summary of Validation:**\n${validation.summary}\n\n`;
      }

      if (validation.legitimacyEvidence && validation.legitimacyEvidence.length > 0) {
        responseText += "**Evidence Supporting Validity:**\n";
        validation.legitimacyEvidence.forEach(e => responseText += `- ${e}\n`);
        responseText += "\n";
      }

      if (validation.falsePositiveIndicators && validation.falsePositiveIndicators.length > 0) {
        responseText += "**Potential False Positive Indicators:**\n";
        validation.falsePositiveIndicators.forEach(i => responseText += `- ${i}\n`);
        responseText += "\n";
      }

      if (validation.disputes && validation.disputes.length > 0) {
        responseText += "**Disputes or Challenges:**\n";
        validation.disputes.forEach(d => {
          responseText += `- Source: ${d.source} (${d.date || 'N/A'})\n   Reason: ${d.reason}\n`;
          if (d.url) responseText += `   More Info: ${d.url}\n`;
        });
        responseText += "\n";
      }

      if (!validation.legitimacyEvidence?.length && !validation.falsePositiveIndicators?.length && !validation.disputes?.length && !validation.summary) {
        responseText += "No specific evidence, indicators, or disputes were detailed in the AI validation process beyond the overall assessment.\n";
      }

      responseText += `\n*Validation Source(s): ${validation.validationSources?.join(', ') || 'AI analysis based on available data'}*`;

      return { text: responseText, data: validation };
    } catch (error: any) {
      console.error(`Error fetching validation info for ${cveId}:`, error);
      return { text: `Sorry, I couldn't fetch or process validation information for ${cveId}. Error: ${error.message}`, error: error.message, data: null };
    }
  }

  private getValidationRecommendationMeaning(recommendation: string | undefined): string {
    switch (recommendation) {
      case 'VALID':
        return "The CVE is considered legitimate and confirmed by various sources.";
      case 'FALSE_POSITIVE':
        return "The CVE is likely a false positive or has been disputed/withdrawn.";
      case 'DISPUTED':
        return "The CVE has been disputed by vendors or researchers; its legitimacy is questionable.";
      case 'NEEDS_VERIFICATION':
        return "The CVE is listed but requires further verification from vendors or researchers. Treat as potentially valid until confirmed otherwise.";
      case 'REJECTED':
        return "The CVE has been officially rejected or withdrawn.";
      default:
        return "The validation status is undetermined or not clearly specified.";
    }
  }
}
