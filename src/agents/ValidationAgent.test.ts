import { describe, it, expect, vi } from 'vitest';
import { ValidationAgent } from './ValidationAgent';
import { ValidationService } from '../services/ValidationService';

const sampleResult = {
  cveId: 'CVE-2024-1234',
  status: 'VALID'
};

describe('ValidationAgent.validateCVE', () => {
  it('calls ValidationService and returns result', async () => {
    const spy = vi.spyOn(ValidationService, 'validateAIFindings').mockResolvedValue(sampleResult as any);
    const agent = new ValidationAgent();
    const res = await agent.validateCVE('CVE-2024-1234', null, null, null);
    expect(spy).toHaveBeenCalledWith('CVE-2024-1234', null, null, null);
    expect(res).toEqual(sampleResult);
    spy.mockRestore();
  });
});
