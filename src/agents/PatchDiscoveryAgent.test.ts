import { describe, it, expect, vi } from 'vitest';
import { PatchDiscoveryAgent } from './PatchDiscoveryAgent';
import { fetchPatchesAndAdvisories } from '../services/AIEnhancementService';

vi.mock('../services/AIEnhancementService', () => ({
  fetchPatchesAndAdvisories: vi.fn().mockResolvedValue({
    patches: [],
    advisories: [],
    searchSummary: { patchesFound: 0, advisoriesFound: 0 }
  })
}));

describe('PatchDiscoveryAgent', () => {
  it('identifies vendor portals and calls patch search', async () => {
    const agent = new PatchDiscoveryAgent();
    const res = await agent.discover(
      'CVE-0000-0000',
      'This vulnerability affects the Apache HTTP Server and allows remote code execution.',
      {}
    );
    expect(res.components[0].name).toBe('Apache HTTP Server');
    expect(res.vendorPortals.length).toBeGreaterThan(0);
    expect(fetchPatchesAndAdvisories).toHaveBeenCalled();
  });
});
