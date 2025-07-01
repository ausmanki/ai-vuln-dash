import { describe, it, expect } from 'vitest';
import { ValidationAgent } from './ValidationAgent';
import { APIService } from '../services/APIService';

// This integration test performs real API requests to validate a known CVE.
// It does not mock the ValidationService so that the agent uses the actual
// network responses from the APIService helpers.

describe('ValidationAgent.validateCVE (integration)', () => {
  it(
    'fetches real vulnerability data and returns a validation result',
    async () => {
      const cveId = 'CVE-2021-34527';
      const nvdData = await APIService.fetchCVEData(cveId, undefined, () => {});
      const patchData = await APIService.fetchPatchesAndAdvisories(
        cveId,
        nvdData,
        {},
        () => {},
      );

      const agent = new ValidationAgent();
      const result = await agent.validateCVE(cveId, nvdData, null, patchData);

      expect(result.cveId).toBe(cveId);
      expect(result.status).toBeDefined();
    },
    30000,
  );
});
