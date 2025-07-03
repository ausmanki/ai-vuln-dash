import { APIService } from '../services/APIService';
import { ValidationAgent } from './ValidationAgent';
import {
  AgentSettings,
  ChatResponse,
  EPSSData,
  PatchData,
  RemediationStep,
  EnhancedVulnerabilityData,
  CVEValidationData, // Make sure this is the new detailed structure
  BaseCVEInfo,
  CisaKevDetails,
  ActiveExploitationData,
  ExploitDiscoveryData,
  AISummaryData,
  PatchInfo, // For vendorConfirmation
  AdvisoryInfo, // For vendorConfirmation
  BulkAnalysisResult // Added for bulk analysis
} from '../types/cveData';
import { AIThreatIntelData } from '../types/aiThreatIntel';
import { generateRemediationPlan } from '../utils/remediation';

const CVE_REGEX = /CVE-\d{4}-\d{4,7}/i;

// Helper type for the expected structure from APIService.fetchAIThreatIntelligence
// This should ideally be replaced by a strong type returned by APIService itself.

export class UserAssistantAgent {
  private settings: AgentSettings;
  private currentCveIdForSession: string | null = null;
  private bulkAnalysisResults: BulkAnalysisResult[] | null = null; // Added for bulk analysis

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
    const lowerQuery = query.toLowerCase().trim();
    const cveMatch = query.match(CVE_REGEX);
    let operationalCveId: string | null = null;

    // Prioritize /bulk_summary command
    if (lowerQuery === '/bulk_summary') {
      return this.generateBulkAnalysisSummary();
    }

    // Determine operational CVE ID
    if (cveMatch) {
      operationalCveId = cveMatch[0].toUpperCase();
      // If the query *only* contains a CVE ID, set it as context and respond.
      if (operationalCveId === query.trim().toUpperCase()) {
        this.currentCveIdForSession = operationalCveId;
        return {
          text: `Okay, I'm now focused on ${operationalCveId}. What would you like to know about it? (e.g., summary, EPSS score, patches, or type /bulk_summary for an overview of all analyzed CVEs).`,
          sender: 'bot',
          id: Date.now().toString(),
        };
      }
      // If CVE is part of a larger query, use it for this query and also update session context.
      this.currentCveIdForSession = operationalCveId;
    } else {
      operationalCveId = this.currentCveIdForSession;
    }

    // If no operational CVE ID is active, attempt a general AI answer
    if (!operationalCveId) {
      try {
        const aiResult = await APIService.fetchGeneralAnswer(query, this.settings);
        return { text: aiResult.answer, sender: 'bot', id: Date.now().toString() };
      } catch (err: any) {
        return {
          text: "I don't have a specific CVE in context. Please specify a CVE ID (e.g., 'What about CVE-2023-1234?'), ask me to focus on one, or type `/bulk_summary` for an overview of analyzed CVEs.",
          sender: 'bot',
          id: Date.now().toString(),
        };
      }
    }

    // Define intents - these are processed ONLY if an operationalCveId is active.
    const intents = [
      {
        name: 'getEPSSScore',
        keywords: ['epss score', 'epss value', 'exploit prediction'],
        handler: this.getEPSSScore
      },
      {
        name: 'getExploitInfo',
        keywords: ['exploit', 'exploited', 'exploitation details'],
        handler: this.getExploitInfo
      },
      {
        name: 'getValidationInfo',
        keywords: ['validate', 'validity', 'legitimacy', 'is valid', 'is it real'],
        handler: this.getValidationInfo
      },
      {
        name: 'getRemediationPlan',
        keywords: ['remediation plan', 'remediation steps', 'mitigation plan', 'mitigation steps', 'fix plan'],
        handler: this.getRemediationPlan
      },
      {
        name: 'getPatchAndAdvisoryInfo',
        keywords: ['patch', 'patches', 'advisory', 'advisories', 'fix'],
        handler: this.getPatchAndAdvisoryInfo
      },
      {
        name: 'getSummary',
        keywords: ['summarize', 'summary', 'overview', 'tell me about', 'details for'],
        handler: this.getSummary
      },
      // Add more intents here.
    ];

    try {
      for (const intent of intents) {
        if (intent.keywords.some(keyword => lowerQuery.includes(keyword))) {
          // Pass the operationalCveId, which is confirmed to be non-null here.
          return await intent.handler.call(this, operationalCveId as string);
        }
      }
      // Use AI search as a smart fallback if no intent is matched
      try {
        const aiResult = await APIService.fetchGeneralAnswer(query, this.settings);
        return {
          text: aiResult.answer,
          sender: 'bot',
          id: Date.now().toString(),
        };
      } catch (err: any) {
        // If AI search fails, return a basic help message
        return {
          text: `I'm focused on ${operationalCveId}, but I'm not sure what you're asking. You can ask for its EPSS score, summary, patches, validation, etc. Type '/bulk_summary' for an overview of all analyzed CVEs.`,
          sender: 'bot',
          id: Date.now().toString(),
        };
      }

    } catch (error: any) {
      console.error(`Error handling query for CVE ${operationalCveId}:`, error);
      return {
        text: `Sorry, I encountered an error trying to process your request for ${operationalCveId}: ${error.message}`,
        sender: 'bot',
        id: Date.now().toString(),
        error: error.message
      };
    }
  }

  private async getEPSSScore(cveId: string): Promise<ChatResponse<EPSSData | null>> {
    try {
      const epssData = await APIService.fetchEPSSData(cveId, () => {}) as EPSSData | null;
      if (epssData && epssData.epss) {
        return {
          text: `The EPSS score for ${cveId} is ${epssData.epssPercentage} (Percentile: ${epssData.percentile}). This data was last updated on ${epssData.date}.`,
          sender: 'bot',
          id: Date.now().toString(),
          data: epssData
        };
      } else {
        return {
          text: `I couldn't find EPSS data for ${cveId}. It might not be available.`,
          sender: 'bot',
          id: Date.now().toString(),
          data: null
        };
      }
    } catch (error: any) {
      console.error(`Error fetching EPSS for ${cveId}:`, error);
      return {
        text: `Sorry, I couldn't fetch the EPSS score for ${cveId}. Error: ${error.message}`,
        sender: 'bot',
        id: Date.now().toString(),
        error: error.message,
        data: null
      };
    }
  }

  private async getExploitInfo(cveId: string): Promise<ChatResponse<AIThreatIntelData | null>> {
    try {
      const cveData = await APIService.fetchCVEData(cveId, this.settings?.nvdApiKey, () => {}) as BaseCVEInfo | null;
      if (!cveData) {
        return {
          text: `Could not retrieve basic data for ${cveId} to check for exploits.`,
          sender: 'bot',
          id: Date.now().toString(),
          error: "CVE data fetch failed",
          data: null
        };
      }
      const epssData = await APIService.fetchEPSSData(cveId, () => {}) as EPSSData | null;
      const aiThreatIntel = await APIService.fetchAIThreatIntelligence(
        cveId,
        cveData,
        epssData,
        this.settings,
        () => {}
      ) as AIThreatIntelData | null;

      if (!aiThreatIntel || (!aiThreatIntel.cisaKev && !aiThreatIntel.activeExploitation && !aiThreatIntel.exploitDiscovery)) {
        return {
          text: `I've checked for high-level exploit information for ${cveId}. It's not listed in CISA KEV, and AI threat intelligence didn't confirm widespread active exploitation or readily available public PoCs. For security details, please refer to vendor advisories. You can ask 'patches for ${cveId}'.`,
          sender: 'bot',
          id: Date.now().toString(),
          data: null
        };
      }

      let responseText = `For ${cveId}, my focus is on providing vendor advisories and patch information to help you mitigate risks.\n`;
      const returnedData: AIThreatIntelData = {}; // Initialize as potentially empty
      let keyInfoFound = false;

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
        returnedData.exploitDiscovery = aiThreatIntel.exploitDiscovery;
      } else {
         responseText += `- **Public Exploit Code:** AI threat intelligence did not immediately find specific public exploit PoCs.\n`;
      }

      responseText += "\nFor remediation, please check for vendor patches and advisories. You can ask me 'tell me about patches for this CVE'.";

      if (!keyInfoFound) {
         // This case should ideally be caught by the check at the beginning of the function if aiThreatIntel is effectively empty.
         // However, if some fields exist but are all negative (e.g. cisaKev: {listed: false}), this text might still be relevant.
         responseText = `I've checked for high-level exploit information for ${cveId}. It's not listed in CISA KEV, and AI threat intelligence didn't confirm widespread active exploitation or readily available public PoCs. For security details, please refer to vendor advisories. You can ask 'patches for ${cveId}'.`;
         return { text: responseText, sender: 'bot', id: Date.now().toString(), data: null };
      }

      return {
        text: responseText,
        sender: 'bot',
        id: Date.now().toString(),
        data: Object.keys(returnedData).length > 0 ? returnedData : null
      };
    } catch (error: any) {
      console.error(`Error fetching exploit info for ${cveId}:`, error);
      return {
        text: `Sorry, I couldn't fetch exploit information for ${cveId}. Error: ${error.message}`,
        sender: 'bot',
        id: Date.now().toString(),
        error: error.message,
        data: null
      };
    }
  }

  private async getPatchAndAdvisoryInfo(cveId: string): Promise<ChatResponse<PatchData | null>> {
    try {
      const cveData = await APIService.fetchCVEData(cveId, this.settings?.nvdApiKey, () => {}) as BaseCVEInfo | null;
      if (!cveData) {
        return {
          text: `Could not retrieve basic data for ${cveId} to check for patches/advisories.`,
          sender: 'bot',
          id: Date.now().toString(),
          error: "CVE data fetch failed",
          data: null
        };
      }

      const patchAdvisoryData = await APIService.fetchPatchesAndAdvisories(cveId, cveData, this.settings, () => {}) as PatchData | null;

      if (!patchAdvisoryData || ((!patchAdvisoryData.patches || patchAdvisoryData.patches.length === 0) && (!patchAdvisoryData.advisories || patchAdvisoryData.advisories.length === 0))) {
        let responseText = `I searched for patches and advisories for ${cveId} but did not immediately find specific download links or advisories through the AI search. It's recommended to check vendor websites directly.`;
        if (patchAdvisoryData?.searchSummary) {
             responseText += `\n(AI search summary: ${patchAdvisoryData.searchSummary.patchesFound} patches, ${patchAdvisoryData.searchSummary.advisoriesFound} advisories from searched vendors).`;
        }
        return {
          text: responseText,
          sender: 'bot',
          id: Date.now().toString(),
          data: patchAdvisoryData // can still return searchSummary even if no patches/advisories found
        };
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

      return {
        text: responseText,
        sender: 'bot',
        id: Date.now().toString(),
        data: patchAdvisoryData
      };
    } catch (error: any) {
      console.error(`Error fetching patch/advisory info for ${cveId}:`, error);
      return {
        text: `Sorry, I couldn't fetch patch and advisory information for ${cveId}. Error: ${error.message}`,
        sender: 'bot',
        id: Date.now().toString(),
        error: error.message,
        data: null
      };
    }
  }

  private async getRemediationPlan(cveId: string): Promise<ChatResponse<RemediationStep[]>> {
    try {
      const steps = generateRemediationPlan();
      let responseText = `**Remediation Plan for ${cveId}**\n\n`;
      steps.forEach((step, idx) => {
        responseText += `**${idx + 1}. ${step.phase}: ${step.title}**\n`;
        responseText += `${step.description}\n`;
        step.actions.forEach(action => {
          responseText += `- ${action}\n`;
        });
        responseText += `Estimated time: ${step.estimatedTime}. Priority: ${step.priority.toUpperCase()}\n\n`;
      });
      return { text: responseText, sender: 'bot', id: Date.now().toString(), data: steps };
    } catch (error: any) {
      console.error(`Error generating remediation plan for ${cveId}:`, error);
      return { text: `Sorry, I couldn't generate a remediation plan for ${cveId}. Error: ${error.message}`, sender: 'bot', id: Date.now().toString(), error: error.message };
    }
  }

  private async getSummary(cveId: string): Promise<ChatResponse<AISummaryData | EnhancedVulnerabilityData | null>> {
    try {
      const vulnerabilityDataForAISummary = await APIService.fetchVulnerabilityDataWithAI(cveId, () => {}, { nvd: this.settings?.nvdApiKey }, this.settings) as EnhancedVulnerabilityData | null;

      if (!vulnerabilityDataForAISummary || !vulnerabilityDataForAISummary.cve) {
        return {
          text: `I couldn't retrieve enough information for ${cveId} to generate an AI summary.`,
          sender: 'bot',
          id: Date.now().toString(),
          error: "Comprehensive CVE data fetch failed",
          data: null
        };
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
          responseText += `EPSS: ${vulnerabilityDataForAISummary.epss.epssPercentage} (Percentile: ${vulnerabilityDataForAISummary.epss.percentile})\n`;
        }
        if (vulnerabilityDataForAISummary.kev?.listed) {
            responseText += `CISA KEV: LISTED (Known Exploited)\n`;
        }
        responseText += "-----------------------------------\n";
        responseText += aiAnalysis.analysis;
        return {
          text: responseText,
          sender: 'bot',
          id: Date.now().toString(),
          data: aiAnalysis
        };
      } else {
        let fallbackText = `I retrieved some information for ${cveId}, but couldn't generate a full AI summary.\n`;
        fallbackText += `- Description: ${vulnerabilityDataForAISummary.cve.description?.substring(0, 200) + "..." || 'Not available.'}\n`;
        if (vulnerabilityDataForAISummary.cve.cvssV3) {
            fallbackText += `- CVSS v3 Score: ${vulnerabilityDataForAISummary.cve.cvssV3.baseScore} (${vulnerabilityDataForAISummary.cve.cvssV3.baseSeverity})\n`;
        }
        if (vulnerabilityDataForAISummary.epss) {
            fallbackText += `- EPSS Score: ${vulnerabilityDataForAISummary.epss.epssPercentage}\n`;
        }
        return {
          text: fallbackText,
          sender: 'bot',
          id: Date.now().toString(),
          data: vulnerabilityDataForAISummary // Return the partial data if AI summary failed
        };
      }
    } catch (error: any) {
      console.error(`Error fetching summary for ${cveId}:`, error);
      return {
        text: `Sorry, I couldn't generate a summary for ${cveId}. Error: ${error.message}`,
        sender: 'bot',
        id: Date.now().toString(),
        error: error.message,
        data: null
      };
    }
  }

  private async getValidationInfo(cveId: string): Promise<ChatResponse<CVEValidationData | null>> {
    try {
      // Retrieve vulnerability data to supply context for validation
      const vulnerabilityData = await APIService.fetchVulnerabilityDataWithAI(
        cveId,
        () => {},
        { nvd: this.settings?.nvdApiKey },
        this.settings
      ) as EnhancedVulnerabilityData | null;

      if (!vulnerabilityData) {
        return {
          text: `I couldn't retrieve detailed validation and legitimacy information for ${cveId}. Basic CVE data might be missing or validation could not be performed.`,
          sender: 'bot',
          id: Date.now().toString(),
          error: "Validation data fetch failed or incomplete",
          data: null
        };
      }

      const validationAgent = new ValidationAgent();
      const validation = await validationAgent.validateCVE(
        cveId,
        vulnerabilityData.cve,
        {
          cisaKev: vulnerabilityData.kev as CisaKevDetails,
          activeExploitation: vulnerabilityData.activeExploitation as ActiveExploitationData,
          exploitDiscovery: vulnerabilityData.exploits as ExploitDiscoveryData,
          vendorAdvisories: vulnerabilityData.vendorAdvisories,
          technicalAnalysis: vulnerabilityData.technicalAnalysis,
          threatIntelligence: vulnerabilityData.threatIntelligence,
          intelligenceSummary: vulnerabilityData.intelligenceSummary,
          overallThreatLevel: vulnerabilityData.threatLevel,
          hallucinationFlags: vulnerabilityData.hallucinationFlags,
          extractionMetadata: vulnerabilityData.extractionMetadata,
        } as AIThreatIntelData,
        {
          patches: vulnerabilityData.patches,
          advisories: vulnerabilityData.advisories,
        } as PatchData
      );
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


      return {
        text: responseText,
        sender: 'bot',
        id: Date.now().toString(),
        data: validation
      };
    } catch (error: any) {
      console.error(`Error fetching validation info for ${cveId}:`, error);
      return {
        text: `Sorry, I couldn't fetch or process legitimacy and validation information for ${cveId}. Error: ${error.message}`,
        sender: 'bot',
        id: Date.now().toString(),
        error: error.message,
        data: null
      };
    }
  }

  // getValidationRecommendationMeaning is no longer needed as the new structure provides more direct info.
  // If any part of the old logic for meaning is required, it should be integrated into the response generation above.

  public setBulkAnalysisResults(results: BulkAnalysisResult[]): void {
    this.bulkAnalysisResults = results;
  }

  public generateBulkAnalysisSummary(): ChatResponse {
    if (!this.bulkAnalysisResults || this.bulkAnalysisResults.length === 0) {
      return {
        text: "No bulk analysis results available to summarize. Please upload and process a file first.",
        sender: 'system',
        id: Date.now().toString(),
      };
    }

    const totalCVEs = this.bulkAnalysisResults.length;
    const successfulAnalyses = this.bulkAnalysisResults.filter(r => r.status === 'Complete' && r.data).length;
    const errors = this.bulkAnalysisResults.filter(r => r.status === 'Error').length;
    const pending = this.bulkAnalysisResults.filter(r => r.status === 'Pending').length;
    const processing = this.bulkAnalysisResults.filter(r => r.status === 'Processing').length;

    let summaryText = `**Bulk Analysis Summary:**\n\n`;
    summaryText += `- Total CVEs Processed: ${totalCVEs}\n`;
    summaryText += `- Successful Analyses: ${successfulAnalyses}\n`;
    summaryText += `- Analyses with Errors: ${errors}\n`;
    if (pending > 0) summaryText += `- Analyses Pending: ${pending}\n`;
    if (processing > 0) summaryText += `- Analyses Still Processing: ${processing}\n\n`;

    // Highlight critical vulnerabilities (example: CVSS > 9 or KEV listed)
    const criticalCVEs: string[] = [];
    this.bulkAnalysisResults.forEach(result => {
      if (result.data) {
        const cveData = result.data.cve?.cve;
        const kevListed = result.data.kev?.listed;
        let isCritical = false;

        if (kevListed) {
          isCritical = true;
        } else if (cveData?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore >= 9.0) {
          isCritical = true;
        } else if (cveData?.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore >= 9.0) {
          isCritical = true;
        } else if (!cveData?.metrics?.cvssMetricV31 && !cveData?.metrics?.cvssMetricV30 && cveData?.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore >= 9.0) {
          isCritical = true; // Fallback to CVSS v2 if v3 is not available
        }
        if (isCritical) {
          criticalCVEs.push(result.cveId);
        }
      }
    });

    if (criticalCVEs.length > 0) {
      summaryText += `**Potentially Critical CVEs Identified (${criticalCVEs.length}):**\n${criticalCVEs.join(', ')}\n (Based on KEV listing or CVSS score >= 9.0)\n\n`;
    } else if (successfulAnalyses > 0) {
      summaryText += `No CVEs found in CISA KEV or with CVSS score >= 9.0 among the successfully analyzed items.\n\n`;
    }

    summaryText += "You can ask for details on any specific CVE by typing its ID (e.g., 'CVE-2023-1234').";

    return {
      text: summaryText,
      sender: 'bot',
      id: Date.now().toString(),
    };
  }
}
