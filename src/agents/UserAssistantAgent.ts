import { APIService } from '../services/APIService';
import {
  AgentSettings,
  ChatResponse,
  EPSSData,
  PatchData,
  EnhancedVulnerabilityData,
  CVEValidationData, // Make sure this is the new detailed structure
  BaseCVEInfo,
  CisaKevDetails,
  ActiveExploitationData,
  ExploitDiscoveryData,
  AISummaryData,
  PatchInfo, // For vendorConfirmation
  AdvisoryInfo // For vendorConfirmation
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
      // This call should now return EnhancedVulnerabilityData with the *new* CVEValidationData structure
      const vulnerabilityData = await APIService.fetchVulnerabilityDataWithAI(cveId, () => {}, { nvd: this.settings?.nvdApiKey }, this.settings) as EnhancedVulnerabilityData | null;

      if (!vulnerabilityData || !vulnerabilityData.cveValidation) {
        return {
          text: `I couldn't retrieve detailed validation and legitimacy information for ${cveId}. Basic CVE data might be missing or validation could not be performed.`,
          error: "Validation data fetch failed or incomplete",
          data: null
        };
      }

      const validation = vulnerabilityData.cveValidation; // This should be our new detailed CVEValidationData
      let responseText = `**Legitimacy Analysis for ${cveId}**:\n\n`;

      // Use the new legitimacySummary if available and informative
      if (validation.legitimacySummary) {
        responseText += `*Summary:* ${validation.legitimacySummary}\n\n`;
      } else {
        // Fallback if summary is not generated
        responseText += `*Overall Status:* ${validation.status || 'Unknown'}\n`;
        responseText += `*Recommendation:* ${validation.recommendation || 'N/A'}\n`;
      }

      if (validation.legitimacyScore !== null) {
        responseText += `*Legitimacy Score:* ${validation.legitimacyScore}/100\n`;
      }
      responseText += `*Confidence in this Assessment:* ${validation.confidence || 'N/A'}\n\n`;

      responseText += "**Key Legitimacy Factors:**\n";

      // 1. Vendor Confirmation
      if (validation.vendorConfirmation) {
        if (validation.vendorConfirmation.hasConfirmation) {
          responseText += `- **Vendor Confirmation:** Yes. ${validation.vendorConfirmation.details || ''}\n`;
          if (validation.vendorConfirmation.patches && validation.vendorConfirmation.patches.length > 0) {
            responseText += `  - Patches found: ${validation.vendorConfirmation.patches.length}\n`;
          }
          if (validation.vendorConfirmation.advisories && validation.vendorConfirmation.advisories.length > 0) {
            responseText += `  - Advisories found: ${validation.vendorConfirmation.advisories.length}\n`;
          }
        } else {
          responseText += `- **Vendor Confirmation:** No direct confirmation via patches/advisories found by automated search.\n`;
        }
      } else {
        responseText += `- **Vendor Confirmation:** Information not available.\n`;
      }

      // 2. Vendor Dispute
      if (validation.vendorDispute) {
        if (validation.vendorDispute.hasDispute) {
          responseText += `- **Vendor Dispute:** Yes. Source: ${validation.vendorDispute.source || 'N/A'}. Details: ${validation.vendorDispute.details || 'A vendor has disputed this CVE.'}\n`;
        } else {
          responseText += `- **Vendor Dispute:** No specific vendor dispute found by automated search.\n`;
        }
      } else {
        responseText += `- **Vendor Dispute:** Information not available.\n`;
      }

      // 3. False Positive Status
      if (validation.falsePositive) {
        if (validation.falsePositive.isFalsePositive) {
          responseText += `- **False Positive Status:** Likely a False Positive or Rejected. Reason: ${validation.falsePositive.reason || 'N/A'}. Source: ${validation.falsePositive.source || 'N/A'}.\n`;
        } else {
          responseText += `- **False Positive Status:** Not identified as a false positive by automated search.\n`;
        }
      } else {
        responseText += `- **False Positive Status:** Information not available.\n`;
      }

      // 4. Researcher Validation
      if (validation.researcherValidation) {
        responseText += `- **Researcher Validation:** Consensus: ${validation.researcherValidation.consensus || 'Unknown'}.\n`;
        if (validation.researcherValidation.summary) {
          responseText += `  - Summary: ${validation.researcherValidation.summary}\n`;
        }
        if (validation.researcherValidation.evidence && validation.researcherValidation.evidence.length > 0) {
          responseText += `  - Supporting Evidence/Mentions: ${validation.researcherValidation.evidence.length}\n`;
          // Optionally list some evidence URLs or sources if not too verbose
          // For example, list the first 1-2 pieces of evidence:
          validation.researcherValidation.evidence.slice(0, 1).forEach(ev => {
            responseText += `    - Source: ${ev.source || (ev.url ? new URL(ev.url).hostname : 'N/A')}\n`; // Show domain if URL exists
          });
        }
      } else {
        responseText += `- **Researcher Validation:** Information not available.\n`;
      }

      responseText += `\n*Validation Sources Consulted:* ${validation.validationSources?.join(', ') || 'N/A'}\n`;
      responseText += `*Last Assessed:* ${validation.lastUpdated ? new Date(validation.lastUpdated).toLocaleString() : 'N/A'}\n`;

      // Retain original raw disputes if they exist and provide more detail
      if (validation.disputes && validation.disputes.length > 0 && !validation.vendorDispute?.hasDispute) {
          responseText += `\n*Additional Dispute Information (from original data structure):*\n`;
          validation.disputes.forEach(d => {
            responseText += `  - Source: ${d.source}, Reason: ${d.reason}\n`;
          });
      }


      return { text: responseText, data: validation };
    } catch (error: any) {
      console.error(`Error fetching validation info for ${cveId}:`, error);
      return {
        text: `Sorry, I couldn't fetch or process legitimacy and validation information for ${cveId}. Error: ${error.message}`,
        error: error.message,
        data: null
      };
    }
  }

  // getValidationRecommendationMeaning is no longer needed as the new structure provides more direct info.
  // If any part of the old logic for meaning is required, it should be integrated into the response generation above.
}
