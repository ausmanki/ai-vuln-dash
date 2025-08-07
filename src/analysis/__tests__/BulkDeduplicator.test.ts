import { describe, it, expect, vi } from 'vitest';
import { dedupeResults, BulkAnalysisResult } from '../BulkDeduplicator';

const makeResult = (id: string, desc: string): BulkAnalysisResult => ({
  cveId: id,
  data: { cve: { description: desc } }
});

describe('BulkDeduplicator', () => {
  it('groups results exceeding similarity threshold', async () => {
    const results = [
      makeResult('CVE-1', 'same'),
      makeResult('CVE-2', 'same'),
      makeResult('CVE-3', 'different')
    ];

    const embed = vi.fn()
      .mockResolvedValueOnce([1, 0])
      .mockResolvedValueOnce([1, 0])
      .mockResolvedValueOnce([0, 1]);

    const deduped = await dedupeResults(results, 0.9, embed);
    expect(deduped.length).toBe(2);
    const group = deduped.find(r => r.cveId === 'CVE-1');
    expect(group?.duplicates?.length).toBe(1);
    expect(group?.duplicates?.[0].cveId).toBe('CVE-2');
  });

  it('respects similarity threshold', async () => {
    const results = [
      makeResult('CVE-1', 'alpha'),
      makeResult('CVE-2', 'beta')
    ];

    const embed = vi.fn()
      .mockResolvedValueOnce([1, 0])
      .mockResolvedValueOnce([0.86, 0.5]); // similarity ~0.86

    const deduped = await dedupeResults(results, 0.9, embed);
    expect(deduped.length).toBe(2);
    expect(deduped[0].duplicates?.length).toBe(0);
    expect(deduped[1].duplicates?.length).toBe(0);
  });

  it('deduplicates using explicit CVE aliases', async () => {
    const results: BulkAnalysisResult[] = [
      {
        cveId: 'CVE-1',
        data: { cve: { description: 'alpha', aliases: ['CVE-2'] } }
      },
      {
        cveId: 'CVE-2',
        data: { cve: { description: 'beta', aliases: [] } }
      }
    ];

    const embed = vi.fn()
      .mockResolvedValueOnce([1, 0])
      .mockResolvedValueOnce([0, 1]);

    const deduped = await dedupeResults(results, 0.9, embed);
    expect(deduped.length).toBe(1);
    expect(deduped[0].duplicates?.[0].cveId).toBe('CVE-2');
  });
});
