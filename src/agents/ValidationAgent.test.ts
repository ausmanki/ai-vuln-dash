import { describe, it, expect, vi } from 'vitest';
import { ValidationAgent } from './ValidationAgent';
import { ValidationService } from '../services/ValidationService';
import type { CVEValidationData } from '../types/cveData';

describe('ValidationAgent', () => {
  it('returns validation data from ValidationService', async () => {
    const sample: CVEValidationData = { cveId: 'CVE-0000-0000' } as CVEValidationData;
    const spy = vi.spyOn(ValidationService, 'validateAIFindings').mockResolvedValue(sample);
    const agent = new ValidationAgent();
    const result = await agent.validateCVE('CVE-0000-0000', null, null, null);
    expect(result.cveId).toBe(sample.cveId);
    expect(spy).toHaveBeenCalledWith('CVE-0000-0000', null, null, null);
    spy.mockRestore();
  });
});
