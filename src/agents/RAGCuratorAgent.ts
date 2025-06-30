// src/agents/RAGCuratorAgent.ts
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { ResearchAgent } from './ResearchAgent'; // To trigger re-analysis
import { APIService } from '../services/APIService'; // Or use APIService to trigger ResearchAgent indirectly

export class RAGCuratorAgent {
  private researchAgent: ResearchAgent; // For triggering re-analysis

  constructor(researchAgent?: ResearchAgent) {
    // If a researchAgent instance is provided, use it. Otherwise, create a new one.
    // This allows for sharing the same ResearchAgent instance if desired, or if it has specific configurations.
    this.researchAgent = researchAgent || new ResearchAgent();
  }

  /**
   * Identifies AI-refined summaries in the RAG database older than a specified number of days.
   * @param maxAgeDays Threshold for how old summaries can be before being considered outdated.
   * @returns Array of CVE IDs that have outdated summaries.
   */
  async identifyOutdatedSummaries(maxAgeDays: number = 30): Promise<string[]> {
    console.log(`RAG Curator: Identifying outdated AI summaries older than ${maxAgeDays} days...`);
    if (!ragDatabase || !ragDatabase.initialized) {
      console.warn('RAG Curator: RAG Database not initialized. Cannot identify outdated summaries.');
      return [];
    }

    const outdatedCVEs: string[] = [];
    try {
      // Assuming RAG DB search can filter by category/source and return all, or we paginate
      // For simplicity, let's assume we can get all relevant docs or a representative sample
      // A more robust search might involve specific metadata queries if supported by ragDatabase.search
      const allRefinedSummaries = await ragDatabase.search('', 1000, { // Search for many docs
        category: 'ai-refined-summary',
        source: 'self-ai-refined-summary-agent' // Check summaries created by ResearchAgent
      });

      const cutoffTime = new Date().getTime() - (maxAgeDays * 24 * 60 * 60 * 1000);

      for (const doc of allRefinedSummaries) {
        if (doc.metadata && doc.metadata.cveId && doc.metadata.timestamp) {
          const docTimestamp = new Date(doc.metadata.timestamp).getTime();
          if (docTimestamp < cutoffTime) {
            if (!outdatedCVEs.includes(doc.metadata.cveId)) {
              outdatedCVEs.push(doc.metadata.cveId);
            }
          }
        }
      }
      console.log(`RAG Curator: Found ${outdatedCVEs.length} CVEs with potentially outdated summaries.`);
    } catch (error) {
      console.error('RAG Curator: Error identifying outdated summaries:', error);
    }
    return outdatedCVEs;
  }

  /**
   * Triggers a re-analysis for a given CVE ID using the ResearchAgent.
   * @param cveId The CVE ID to re-analyze.
   * @param apiKeys API keys needed for the ResearchAgent.
   * @param settings Settings needed for the ResearchAgent.
   */
  async triggerReanalysis(cveId: string, apiKeys: { nvd?: string; geminiApiKey?: string }, settings: any): Promise<boolean> {
    console.log(`RAG Curator: Triggering re-analysis for ${cveId}...`);
    try {
      // Option 1: Directly use the researchAgent instance
      // The ResearchAgent's analyzeCVE method already handles RAG updates.
      await this.researchAgent.analyzeCVE(cveId, apiKeys, settings);

      // Option 2: Use APIService, which then uses ResearchAgent.
      // This might be cleaner if APIService has other pre/post processing or state management.
      // For now, direct agent call is simpler if ResearchAgent is self-contained for analysis.
      // await APIService.fetchVulnerabilityDataWithAI(cveId, () => {}, apiKeys, settings);

      console.log(`RAG Curator: Re-analysis successfully triggered for ${cveId}. RAG DB should be updated by the ResearchAgent.`);
      return true;
    } catch (error) {
      console.error(`RAG Curator: Error triggering re-analysis for ${cveId}:`, error);
      return false;
    }
  }

  // Placeholder for future task: Identify conflicting information
  async identifyConflictingInfo(cveId: string): Promise<any[]> {
    console.log(`RAG Curator: Identifying conflicting info for ${cveId} (Not Implemented Yet)...`);
    // 1. Search RAG for all documents related to cveId.
    // 2. Analyze content of these documents (e.g., looking for contradictory statements on severity, KEV status, patch availability).
    //    This might involve simpler keyword/pattern matching or even another AI call for summarization/comparison.
    // 3. Return a list of identified conflicts or a summary.
    return [];
  }

  // Main method to run curation tasks (can be expanded)
  async runCurationCycle(apiKeys: { nvd?: string; geminiApiKey?: string }, settings: any, maxAgeDays: number = 30) {
    console.log("RAG Curator: Starting curation cycle...");
    const outdated = await this.identifyOutdatedSummaries(maxAgeDays);
    for (const cveId of outdated) {
      console.log(`RAG Curator: Found outdated summary for ${cveId}. Attempting re-analysis.`);
      await this.triggerReanalysis(cveId, apiKeys, settings);
      // Optional: Add a delay here if running many re-analyses to avoid rate limiting.
    }
    // Future: Call identifyConflictingInfo for high-priority CVEs, etc.
    console.log("RAG Curator: Curation cycle finished.");
  }
}
