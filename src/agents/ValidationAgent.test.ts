import { describe, it, expect, vi, afterEach } from 'vitest';
import { ValidationAgent } from './ValidationAgent';
import { ValidationService } from '../services/ValidationService';

describe('ValidationAgent.validateCVE', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('delegates to ValidationService and returns its result', async () => {
    const mockResult = { cveId: 'CVE-1234-5678', status: 'VALID' } as any;
    const spy = vi
      .spyOn(ValidationService, 'validateAIFindings')
      .mockResolvedValue(mockResult);

    const agent = new ValidationAgent();
    const result = await agent.validateCVE('CVE-1234-5678', null, null, null);

    expect(spy).toHaveBeenCalled();
    expect(result).toBe(mockResult);
  });
});
