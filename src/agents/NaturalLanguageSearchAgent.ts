// src/agents/NaturalLanguageSearchAgent.ts
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { SearchResult } from '../types/search';
import { AgentSettings } from '../types/cveData';
import { fetchGeneralAnswer } from '../services/AIEnhancementService';
import { fetchWithFallback } from '../services/UtilityService';
import { logger } from '../utils/logger';
import { CVE_REGEX } from '../utils/cveRegex';

export class NaturalLanguageSearchAgent {
  constructor() {
    // This constructor can be expanded later to accept settings or context.
  }

  /**
   * Performs a natural language search using the RAG database, with a fallback to web search.
   * @param query The user's natural language query.
   * @param settings The application settings, including AI provider and model info.
   * @returns A promise that resolves to an array of formatted search results.
   */
  async search(query: string, settings: AgentSettings): Promise<SearchResult[]> {
    logger.info(`Executing RAG search for: "${query}"`);

    if (!ragDatabase.initialized) {
      logger.info('RAG database not initialized. Initializing now...');
      await ragDatabase.initialize();
    }

    const searchResults = await ragDatabase.search(query);

    if (searchResults.length > 0) {
      logger.info(`RAG search found ${searchResults.length} relevant documents.`);
      // Format the raw search results into a structure suitable for the UI
      return searchResults.map(result => ({
        cveId: result.metadata.cveId || null,
        title: result.metadata.title || 'Untitled Document',
        snippet: result.content.substring(0, 250) + (result.content.length > 250 ? '...' : ''),
        source: result.metadata.source || 'Unknown Source',
        similarity: result.similarity,
      }));
    }

    logger.warn(`RAG search found no documents for "${query}". Falling back to AI web search.`);

    // Fallback to web search if RAG returns no results
    try {
      const webResult = await this.performWebSearch(query, settings);
      return [webResult];
    } catch (error) {
      logger.error('AI web search fallback failed:', error);
      // Return empty array if web search also fails
      return [];
    }
  }

  /**
   * Performs a web search using the configured AI provider.
   * @param query The user's query.
   * @param settings The application settings.
   * @returns A promise that resolves to a single SearchResult.
   */
  private async performWebSearch(query: string, settings: AgentSettings): Promise<SearchResult> {
    if (!settings.aiProvider) {
      throw new Error('AI provider not configured. Cannot perform web search.');
    }

    logger.info(`Performing AI web search with ${settings.aiProvider} for: "${query}"`);

    const result = await fetchGeneralAnswer(query, settings, fetchWithFallback);

    // Reset regex state
    CVE_REGEX.lastIndex = 0;
    const match = CVE_REGEX.exec(result.answer);
    const detectedCveId = match ? match[0].toUpperCase() : undefined;

    if (detectedCveId) {
      logger.info(`Detected CVE ID in web search result: ${detectedCveId}`);
    }

    return {
      cveId: null,
      title: `AI Web Search Results for "${query}"`,
      snippet: result.answer,
      source: `AI (${settings.aiProvider})`,
      similarity: null, // No similarity score for web search results
      detectedCveId,
    };
  }
}
