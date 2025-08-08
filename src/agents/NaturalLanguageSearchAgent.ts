// src/agents/NaturalLanguageSearchAgent.ts
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { SearchResult } from '../types/search';
import { AgentSettings } from '../types/cveData';
import { fetchGeneralAnswer } from '../services/AIEnhancementService';
import { fetchWithFallback } from '../services/UtilityService';
import { logger } from '../utils/logger';

export class NaturalLanguageSearchAgent {
  constructor() {
    // This constructor can be expanded later to accept settings or context.
  }

  /**
   * Performs a natural language search using the RAG database and blends the
   * results with an AI-powered web search. If either source is unavailable or
   * returns no data, the method gracefully returns whatever results are
   * available.
   *
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

    // Run RAG search and AI web search in parallel (web search only if configured)
    const ragPromise = ragDatabase.search(query);
    const webPromise = settings.aiProvider
      ? this.performWebSearch(query, settings).catch(error => {
          logger.error('AI web search failed:', error);
          return null; // Gracefully handle web search failures
        })
      : Promise.resolve(null);

    const [ragResults, webResult] = await Promise.all([ragPromise, webPromise]);

    const formattedRagResults = ragResults.map(result => ({
      cveId: result.metadata.cveId || null,
      title: result.metadata.title || 'Untitled Document',
      snippet: result.content.substring(0, 250) + (result.content.length > 250 ? '...' : ''),
      source: result.metadata.source || 'Unknown Source',
      similarity: result.similarity,
    }));

    if (!formattedRagResults.length) {
      logger.warn(`RAG search found no documents for "${query}".`);
    }

    if (webResult) {
      formattedRagResults.push(webResult);
    }

    return formattedRagResults;
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

    return {
      cveId: null,
      title: `AI Web Search Results for "${query}"`,
      snippet: result.answer,
      source: `AI (${settings.aiProvider})`,
      similarity: null, // No similarity score for web search results
    };
  }
}
