import { describe, it, expect, vi, afterEach } from 'vitest';
import { UserAssistantAgent } from './UserAssistantAgent';
import { APIService } from '../services/APIService';
import { ValidationService } from '../services/ValidationService';

// Unit test with mocked dependencies to avoid real network calls.

describe('UserAssistantAgent.getValidationInfo', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns validation info using service results', async () => {
    vi.spyOn(APIService, 'fetchCVEData').mockResolvedValue({} as any);
    vi.spyOn(APIService, 'fetchEPSSData').mockResolvedValue({} as any);
    vi.spyOn(APIService, 'fetchAIThreatIntelligence').mockResolvedValue(null);
    vi.spyOn(APIService, 'fetchPatchesAndAdvisories').mockResolvedValue(null);

    const validationResult = { cveId: 'CVE-2021-1234', status: 'VALID' } as any;
    vi.spyOn(ValidationService, 'validateAIFindings').mockResolvedValue(validationResult);

    const agent = new UserAssistantAgent({});
    const resp = await (agent as any).getValidationInfo('CVE-2021-1234');

    expect(resp.data).toEqual(validationResult);
  });
});
