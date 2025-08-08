// src/agents/NaturalLanguageSearchAgent.ts
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { SearchResult } from '../types/search';

export class NaturalLanguageSearchAgent {
  constructor() {
    // This constructor can be expanded later to accept settings or context.
  }

  /**
   * Performs a natural language search using the RAG database.
   * @param query The user's natural language query.
   * @returns A promise that resolves to an array of formatted search results.
   */
  async search(query: string): Promise<SearchResult[]> {
    console.log(`Executing RAG search for: "${query}"`);

    if (!ragDatabase.initialized) {
      console.log('RAG database not initialized. Initializing now...');
      await ragDatabase.initialize();
    }

    const searchResults = await ragDatabase.search(query);

    // Format the raw search results into a structure suitable for the UI
    const formattedResults = searchResults.map(result => ({
      cveId: result.metadata.cveId || null,
      title: result.metadata.title || 'Untitled Document',
      snippet: result.content.substring(0, 250) + (result.content.length > 250 ? '...' : ''),
      source: result.metadata.source || 'Unknown Source',
      similarity: result.similarity,
    }));

    console.log(`RAG search found ${formattedResults.length} relevant documents.`);
    return formattedResults;
  }
}
