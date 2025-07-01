import { describe, it, expect, vi } from 'vitest';
import { UserAssistantAgent } from './UserAssistantAgent';
import { ValidationAgent } from './ValidationAgent';
import { APIService } from '../services/APIService';

const validationResult = { cveId: 'CVE-2024-1234', status: 'VALID' } as any;

describe('UserAssistantAgent.getValidationInfo', () => {
  it('uses ValidationAgent to obtain validation data', async () => {
    vi.spyOn(APIService, 'fetchCVEData').mockResolvedValue({ id: 'CVE-2024-1234' } as any);
    vi.spyOn(APIService, 'fetchEPSSData').mockResolvedValue(null as any);
    vi.spyOn(APIService, 'fetchAIThreatIntelligence').mockResolvedValue(null as any);
    vi.spyOn(APIService, 'fetchPatchesAndAdvisories').mockResolvedValue(null as any);

    const validateSpy = vi.spyOn(ValidationAgent.prototype, 'validateCVE').mockResolvedValue(validationResult);

    const agent = new UserAssistantAgent({});
    const resp = await (agent as any).getValidationInfo('CVE-2024-1234');

    expect(validateSpy).toHaveBeenCalled();
    expect(resp.data).toEqual(validationResult);

    validateSpy.mockRestore();
  });
});
