import { APIService } from '../services/APIService';
import { AppContext } from '../contexts/AppContext'; // Assuming settings might come from AppContext
// We might need to import specific types for vulnerability data if we strongly type responses.
// For now, we'll keep it simple and return strings or simple objects.

// Define a simple structure for responses, can be expanded later
interface ChatResponse {
  text: string;
  data?: any; // Optional structured data
  error?: string;
}

const CVE_REGEX = /CVE-\d{4}-\d{4,7}/i;

export class UserAssistantAgent {
  private settings: any; // To store settings if needed
  private currentCveIdForSession: string | null = null;

  constructor(settings?: any) {
    this.settings = settings || {};
    // Initialize any services if they require instantiation and settings
    // For now, APIService uses static methods, so no instantiation needed here.
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
    return null; // No change or invalid CVE
  }

  public async generateBulkAnalysisSummary(
    bulkResults: Array<{cveId: string, data?: any, error?: string}>
  ): Promise<ChatResponse> {
    if (!bulkResults || bulkResults.length === 0) {
      return { text: "There are no bulk analysis results to summarize. Please perform a bulk analysis first." };
    }

    let totalCVEs = bulkResults.length;
    let successfullyAnalyzed = 0;
    let failedAnalysis = 0;

    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
    const kevListedCVEs: string[] = [];
    const highEpssCVEs: { cveId: string, score: string }[] = [];

    for (const result of bulkResults) {
      if (result.error || !result.data) {
        failedAnalysis++;
        continue;
      }
      successfullyAnalyzed++;
      const cveData = result.data.cve;
      const epssData = result.data.epss;
      const kevData = result.data.kev;

      // Severity
      let severity = "UNKNOWN";
      if (cveData?.cvssV3?.baseSeverity) {
        severity = cveData.cvssV3.baseSeverity.toUpperCase();
      } else if (cveData?.cvssV2?.severity) {
        severity = cveData.cvssV2.severity.toUpperCase();
      }
      severityCounts[severity]++;

      // KEV
      if (kevData?.listed) {
        kevListedCVEs.push(result.cveId);
      }

      // EPSS
      if (epssData?.epssFloat && epssData.epssFloat > 0.75) { // Threshold for "high" EPSS, adjust as needed
        highEpssCVEs.push({ cveId: result.cveId, score: epssData.epssPercentage });
      }
    }

    let summaryText = `**Bulk Analysis Report Summary**\n\n`;
    summaryText += `Total CVEs Processed: ${totalCVEs}\n`;
    summaryText += `Successfully Analyzed: ${successfullyAnalyzed}\n`;
    summaryText += `Failed to Analyze: ${failedAnalysis}\n\n`;

    summaryText += `**Severity Distribution:**\n`;
    summaryText += `- Critical: ${severityCounts.CRITICAL}\n`;
    summaryText += `- High: ${severityCounts.HIGH}\n`;
    summaryText += `- Medium: ${severityCounts.MEDIUM}\n`;
    summaryText += `- Low: ${severityCounts.LOW}\n`;
    summaryText += `- Unknown: ${severityCounts.UNKNOWN}\n\n`;

    if (kevListedCVEs.length > 0) {
      summaryText += `**CISA KEV (Known Exploited Vulnerabilities):**\n`;
      summaryText += `- ${kevListedCVEs.length} CVE(s) are listed: ${kevListedCVEs.join(', ')}\n\n`;
    } else {
      summaryText += `**CISA KEV:** No CVEs in this report are currently listed in the CISA KEV catalog.\n\n`;
    }

    if (highEpssCVEs.length > 0) {
      summaryText += `**High EPSS Scores (Predicted Exploitable > 75%):**\n`;
      highEpssCVEs.forEach(item => {
        summaryText += `- ${item.cveId} (EPSS: ${item.score}%)\n`;
      });
      summaryText += `\n`;
    } else {
      summaryText += `**High EPSS Scores:** No CVEs in this report have an EPSS score above 75%.\n\n`;
    }

    summaryText += `This summary provides a high-level overview. For detailed findings, please refer to the individual CVE results in the Bulk Analysis tab.`;

    return {
      text: summaryText,
      data: {
        totalCVEs,
        successfullyAnalyzed,
        failedAnalysis,
        severityCounts,
        kevListedCVEs,
        highEpssCVEs
      }
    };
  }

  public async handleQuery(query: string, bulkResults?: Array<{cveId: string, data?: any, error?: string}> ): Promise<ChatResponse> {
    const lowerQuery = query.toLowerCase();

    // Check for bulk summary command first
    if (lowerQuery.includes("/summarize_bulk") || lowerQuery.includes("/bulksummary") || lowerQuery.includes("/bulk_summary")) {
      if (bulkResults && bulkResults.length > 0) {
        return this.generateBulkAnalysisSummary(bulkResults);
      } else {
        return { text: "Bulk analysis data is not available or is empty. Please perform a bulk analysis first and ensure it has results."};
      }
    }

    const cveMatch = query.match(CVE_REGEX);
    let operationalCveId: string | null = null;

    if (cveMatch) {
      operationalCveId = cveMatch[0].toUpperCase();
      this.currentCveIdForSession = operationalCveId; // Update session CVE if one is in the query
    } else {
      operationalCveId = this.currentCveIdForSession;
    }

    // If the query is just the CVE ID (and it matched), or if it's a known command that requires a CVE context.
    // If no operationalCveId is set (neither from query nor session), then it's an ambiguous query.
    if (!operationalCveId) {
      // Check if it's a generic query that doesn't need a CVE context but isn't a bulk summary command
      const isGenericQueryNotRequiringCVE = intents.some(intent =>
        intent.keywords.some(keyword => lowerQuery.includes(keyword)) && !intent.requiresCveContext
      );
      if (!isGenericQueryNotRequiringCVE) {
         return { text: "Please specify a CVE ID in your query (e.g., 'What about CVE-2023-1234?'), ask me to focus on one, or use '/bulk_summary' for the latest bulk report." };
      }
      // If it IS a generic query that doesn't require CVE context, proceed (though current intents all seem to require it implicitly by using operationalCveId)
      // This part might need refinement if we add truly CVE-independent general queries.
    }

    // If CVE was just set by the query, and the query is *only* the CVE ID, ask for more details.
    if (cveMatch && query.trim().toUpperCase() === operationalCveId) {
        return { text: `Okay, I'm now focused on ${operationalCveId}. What would you like to know about it? (e.g., summary, EPSS score, patches)` };
    }

    // Define intents (assuming this might be expanded or moved)
    // For now, keeping structure from master, but all handlers implicitly use operationalCveId
    const intents = [
      { name: 'getEPSSScore', keywords: ['epss score', 'epss value', 'exploit prediction'], handler: this.getEPSSScore, requiresCveContext: true },
      { name: 'getExploitInfo', keywords: ['exploit', 'exploited', 'exploitation details'], handler: this.getExploitInfo, requiresCveContext: true },
      { name: 'getValidationInfo', keywords: ['validate', 'validity', 'legitimacy', 'is valid', 'is it real'], handler: this.getValidationInfo, requiresCveContext: true },
      { name: 'getPatchAndAdvisoryInfo', keywords: ['patch', 'patches', 'advisory', 'advisories', 'fix', 'remediation', 'mitigation'], handler: this.getPatchAndAdvisoryInfo, requiresCveContext: true },
      { name: 'getSummary', keywords: ['summarize', 'summary', 'overview', 'tell me about', 'details for'], handler: this.getSummary, requiresCveContext: true },
    ];

    try {
      if (operationalCveId) { // Ensure we have a CVE context for intent processing
        for (const intent of intents) {
          if (intent.keywords.some(keyword => lowerQuery.includes(keyword))) {
            return await intent.handler.call(this, operationalCveId);
          }
        }
      }
      // Fallback if no intent is matched OR if operationalCveId was not set but we passed the initial check (e.g. for a future general query type)
      // If operationalCveId exists, it means we didn't match an intent for it.
      if (operationalCveId) {
        return { text: `I have context for ${operationalCveId}, but I'm not sure how to answer your query about it. You can ask for EPSS score, summary, patches, validation, etc., or use '/bulk_summary' for the bulk report.` };
      }
      // If no operationalCveId and it wasn't a bulk command (already handled) or a recognized general query.
      return { text: "I'm not sure how to help with that. Please specify a CVE ID, ask me to focus on one, or use '/bulk_summary' for the latest report." };

    } catch (error: any) {
      console.error(`Error handling query. CVE context: ${operationalCveId || 'None'}. Query: "${query}". Error:`, error);
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

      let responseText = `For ${cveId}, my focus is on providing vendor advisories and patch information to help you mitigate risks.\n`;
      let keyInfoFound = false;

      if (aiThreatIntel.cisaKev?.listed) {
        responseText += `- **CISA KEV:** This CVE IS LISTED in the CISA Known Exploited Vulnerabilities (KEV) catalog, indicating active exploitation. Details: ${aiThreatIntel.cisaKev.details || 'Refer to CISA for specifics.'}\n`;
        keyInfoFound = true;
      } else {
        responseText += `- **CISA KEV:** This CVE is NOT listed in the CISA KEV catalog at this time.\n`;
      }

      if (aiThreatIntel.activeExploitation?.confirmed) {
        responseText += `- **Active Exploitation:** AI threat intelligence suggests evidence of active exploitation in the wild. Details: ${aiThreatIntel.activeExploitation.details || 'General reports suggest activity.'}\n`;
        keyInfoFound = true;
      } else {
        responseText += `- **Active Exploitation:** No specific widespread active exploitation was confirmed by AI threat intelligence beyond potential KEV listing.\n`;
      }

      if (aiThreatIntel.exploitDiscovery?.found) {
        responseText += `- **Public Exploit Code:** Publicly available exploit information or PoCs may exist for this vulnerability (AI found ${aiThreatIntel.exploitDiscovery.totalCount} potential indicators).\n`;
        keyInfoFound = true;
      } else {
         responseText += `- **Public Exploit Code:** AI threat intelligence did not immediately find specific public exploit PoCs.\n`;
      }

      responseText += "\nFor remediation, please check for vendor patches and advisories. You can ask me 'tell me about patches for this CVE'.";

      if (!keyInfoFound && !aiThreatIntel.cisaKev?.listed && !aiThreatIntel.activeExploitation?.confirmed && !aiThreatIntel.exploitDiscovery?.found) {
         responseText = `I've checked for high-level exploit information for ${cveId}. It's not listed in CISA KEV, and AI threat intelligence didn't confirm widespread active exploitation or readily available public PoCs. For security details, please refer to vendor advisories. You can ask 'patches for ${cveId}'.`;
      }

      // We are deliberately not returning detailed exploit links here.
      // The 'data' can still contain the full aiThreatIntel for internal use or future structured display if policies change.
      return { text: responseText, data: { cisaKev: aiThreatIntel.cisaKev, activeExploitation: aiThreatIntel.activeExploitation, exploitDiscoverySummary: { found: aiThreatIntel.exploitDiscovery?.found, count: aiThreatIntel.exploitDiscovery?.totalCount } } };
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
      // Fetch necessary base data first
      const cveData = await APIService.fetchCVEData(cveId, this.settings?.nvdApiKey, () => {});
      if (!cveData) {
        return { text: `I couldn't retrieve basic data for ${cveId} to generate a summary.`, error: "CVE data fetch failed" };
      }
      const epssData = await APIService.fetchEPSSData(cveId, () => {}); // Can be null

      // Construct a partial vulnerability object for generateAIAnalysis
      // The generateAIAnalysis function expects a richer object, often the output of ResearchAgent.
      // We need to ensure it can handle a more minimal input or adapt.
      // For now, we pass what we have. The service might also re-fetch if needed or work with partial data.
      // A more robust solution might involve enhancing generateAIAnalysis or having a dedicated "summarizeThisData" type of method.

      // Let's use the more comprehensive fetchVulnerabilityDataWithAI to get a richer object
      // as generateAIAnalysis is designed to work with its output.
      const vulnerabilityDataForAISummary = await APIService.fetchVulnerabilityDataWithAI(cveId, () => {}, { nvd: this.settings?.nvdApiKey }, this.settings);

      if (!vulnerabilityDataForAISummary || !vulnerabilityDataForAISummary.cve) {
        return { text: `I couldn't retrieve enough information for ${cveId} to generate an AI summary.`, error: "Comprehensive CVE data fetch failed" };
      }

      // Now call generateAIAnalysis with the richer vulnerability data
      const aiAnalysis = await APIService.generateAIAnalysis(
        vulnerabilityDataForAISummary,
        this.settings.geminiApiKey,
        this.settings.geminiModel,
        this.settings
      );

      if (aiAnalysis && aiAnalysis.analysis) {
        let responseText = `Here's an AI-generated summary for ${cveId}:\n\n`;
        // Prepend some key facts for clarity before the narrative
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
        // Fallback if AI analysis fails but we have some data
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
    } catch (error) {
      console.error(`Error fetching summary for ${cveId}:`, error);
      return { text: `Sorry, I couldn't generate a summary for ${cveId}. Error: ${error.message}`, error: error.message };
    }
  }

  private async getValidationInfo(cveId: string): Promise<ChatResponse> {
    try {
      const vulnerability = await APIService.fetchVulnerabilityDataWithAI(cveId, () => {}, { nvd: this.settings?.nvdApiKey }, this.settings);

      if (!vulnerability || !vulnerability.cveValidation) {
        return { text: `I couldn't retrieve detailed validation information for ${cveId}. Basic CVE data might be missing or validation could not be performed.`, error: "Validation data fetch failed or incomplete" };
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
    } catch (error) {
      console.error(`Error fetching validation info for ${cveId}:`, error);
      return { text: `Sorry, I couldn't fetch or process validation information for ${cveId}. Error: ${error.message}`, error: error.message };
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
