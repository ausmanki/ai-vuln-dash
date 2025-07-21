import { describe, it, expect, vi } from 'vitest';
import { UserAssistantAgent } from '../agents/UserAssistantAgent';
import type { BulkAnalysisResult, EnhancedVulnerabilityData } from '../types/cveData';

describe('UserAssistantAgent', () => {
  it('handleQuery returns help message for /help', async () => {
    const agent = new UserAssistantAgent();
    const result = await agent.handleQuery('/help');
    expect(result.text).toContain('cybersecurity assistant');
  });

  it('handleQuery delegates to handleCVEQuery when CVE present', async () => {
    const agent = new UserAssistantAgent();
    const spy = vi
      .spyOn(agent as any, 'handleCVEQuery')
      .mockResolvedValue({ text: 'ok', sender: 'bot', id: '1' });
    await agent.handleQuery('Check CVE-2024-9999 details');
    expect(spy).toHaveBeenCalledWith('Check CVE-2024-9999 details', 'CVE-2024-9999');
    spy.mockRestore();
  });

  it('setContextualCVE updates current CVE and recent list', () => {
    const agent = new UserAssistantAgent();
    const res = agent.setContextualCVE('CVE-2024-1111');
    expect(res?.text).toContain('CVE-2024-1111');
    expect((agent as any).currentCveIdForSession).toBe('CVE-2024-1111');
    expect((agent as any).conversationContext.recentCVEs[0]).toBe('CVE-2024-1111');
  });

  it('generateBulkAnalysisSummary summarizes results', () => {
    const agent = new UserAssistantAgent();
    const results: BulkAnalysisResult[] = [
      {
        cveId: 'CVE-1',
        status: 'Complete',
        data: {
          cve: { cvssV3: { baseScore: 9.1 } } as any,
          kev: { listed: false } as any,
        } as EnhancedVulnerabilityData,
      },
      {
        cveId: 'CVE-2',
        status: 'Complete',
        data: {
          cve: { cvssV3: { baseScore: 5.0 } } as any,
          kev: { listed: true } as any,
        } as EnhancedVulnerabilityData,
      },
      {
        cveId: 'CVE-3',
        status: 'Error',
      },
    ];
    agent.setBulkAnalysisResults(results);
    const summary = agent.generateBulkAnalysisSummary();
    expect(summary.text).toContain('Bulk Analysis Summary');
    expect(summary.text).toContain('3 vulnerabilities');
    expect(summary.text).toContain('2 successful analyses');
    expect(summary.text).toContain('2 vulnerabilities require immediate attention');
  });

  it('generateBulkAnalysisSummary handles empty results', () => {
    const agent = new UserAssistantAgent();
    const summary = agent.generateBulkAnalysisSummary();
    expect(summary.text).toContain("don't have any bulk analysis results");
  });

  it('respects custom cache TTL', async () => {
    const agent = new UserAssistantAgent({ cacheTTL: 0 });
    const fetcher = vi.fn().mockResolvedValueOnce('a').mockResolvedValueOnce('b');
    const res1 = await (agent as any).getCachedOrFetch('k', fetcher);
    const res2 = await (agent as any).getCachedOrFetch('k', fetcher);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(res1).toBe('a');
    expect(res2).toBe('b');
  });

  it('clearCache forces refetch', async () => {
    const agent = new UserAssistantAgent({ cacheTTL: 10000 });
    const fetcher = vi.fn().mockResolvedValueOnce('a').mockResolvedValueOnce('b');
    await (agent as any).getCachedOrFetch('k', fetcher);
    agent.clearCache();
    const res = await (agent as any).getCachedOrFetch('k', fetcher);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(res).toBe('b');
  });
});
