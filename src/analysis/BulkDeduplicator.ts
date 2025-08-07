import { EnhancedVectorDatabase, ragDatabase } from '../db/EnhancedVectorDatabase';

export interface BulkAnalysisResult {
  cveId: string;
  data?: any;
  error?: string;
  duplicates?: BulkAnalysisResult[];
}

/**
 * Deduplicate analysis results by grouping CVEs with similar descriptions.
 * Descriptions are embedded using EnhancedVectorDatabase.embedText and
 * entries are grouped when cosine similarity exceeds the provided threshold.
 */
export async function dedupeResults(
  results: BulkAnalysisResult[],
  threshold = 0.9,
  embedFn: (text: string) => Promise<number[]> = (EnhancedVectorDatabase as any).embedText
    ? (EnhancedVectorDatabase as any).embedText.bind(EnhancedVectorDatabase)
    : (text: string) => ragDatabase.createEmbedding(text)
): Promise<BulkAnalysisResult[]> {
  if (results.length === 0) return [];

  const descriptions = results.map(r => r.data?.cve?.description || '');
  const embeddings = await Promise.all(descriptions.map(d => embedFn(d)));

  const n = results.length;
  const parent = Array.from({ length: n }, (_, i) => i);

  const find = (x: number): number => {
    while (parent[x] !== x) {
      parent[x] = parent[parent[x]];
      x = parent[x];
    }
    return x;
  };

  const union = (a: number, b: number) => {
    const pa = find(a);
    const pb = find(b);
    if (pa !== pb) parent[pa] = pb;
  };

  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const sim = ragDatabase.cosineSimilarity(embeddings[i], embeddings[j]);
      if (sim >= threshold) union(i, j);
    }
  }

  const groups = new Map<number, number[]>();
  for (let i = 0; i < n; i++) {
    const root = find(i);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root)!.push(i);
  }

  const deduped: BulkAnalysisResult[] = [];
  for (const indices of groups.values()) {
    const [first, ...rest] = indices;
    const representative: BulkAnalysisResult = { ...results[first], duplicates: [] };
    rest.forEach(idx => representative.duplicates!.push(results[idx]));
    deduped.push(representative);
  }

  return deduped;
}

export default { dedupeResults };
