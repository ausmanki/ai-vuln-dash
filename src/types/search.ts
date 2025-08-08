// src/types/search.ts

/**
 * Represents a single search result from a natural language query.
 */
export interface SearchResult {
  cveId: string | null;
  title: string;
  snippet: string;
  source: string;
  similarity: number;
}
