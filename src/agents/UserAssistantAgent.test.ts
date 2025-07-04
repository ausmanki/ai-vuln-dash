import { describe, it, expect, vi } from 'vitest';

vi.mock('../services/APIService', () => ({
  APIService: {
    fetchVulnerabilityDataWithAI: vi.fn().mockResolvedValue({
      cve: { id: 'CVE-1234-0001' },
      patches: [],
      advisories: [],
    })
  }
}));

const mockValidation = { cveId: 'CVE-1234-0001', status: 'VALID' };
const validateSpy = vi.fn().mockResolvedValue(mockValidation);
vi.mock('./ValidationAgent', () => ({
  ValidationAgent: vi.fn().mockImplementation(() => ({ validateCVE: validateSpy }))
}));

import { UserAssistantAgent } from './UserAssistantAgent';

describe('UserAssistantAgent validation integration', () => {
  it('uses ValidationAgent when handling validation queries', async () => {
    const agent = new UserAssistantAgent({});
    const res = await agent.handleQuery('validate CVE-1234-0001');
    expect(validateSpy).toHaveBeenCalled();
    expect(res.data).toEqual(mockValidation);
  });

  it('returns remediation plan when asked', async () => {
    const agent = new UserAssistantAgent({});
    const res = await agent.handleQuery('remediation plan for CVE-1234-0001');
    expect(res.text).toContain('Remediation Plan');
    expect(Array.isArray(res.data)).toBe(true);
    expect(res.data.length).toBeGreaterThan(0);
  });

  it('summarizes components for bulk results', async () => {
    const agent = new UserAssistantAgent({});
    agent.setBulkAnalysisResults([
      {
        cveId: 'CVE-0001',
        status: 'Complete',
        data: {
          cve: {
            cve: { descriptions: [{ lang: 'en', value: 'Vulnerability in Apache HTTP Server' }] },
            cvssV3: { baseSeverity: 'HIGH' }
          }
        } as any
      },
      {
        cveId: 'CVE-0002',
        status: 'Complete',
        data: {
          cve: {
            cve: { descriptions: [{ lang: 'en', value: 'Issue in Apache HTTP Server module' }] },
            cvssV3: { baseSeverity: 'MEDIUM' }
          }
        } as any
      }
    ]);

    const res = await agent.handleQuery('/component_summary');
    expect(res.text).toContain('Component Impact Summary');
    expect(res.text).toContain('Apache HTTP Server');
    expect(res.text).toContain('CVE-0001, CVE-0002');
  });
});
