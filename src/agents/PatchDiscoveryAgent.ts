import { fetchPatchesAndAdvisories } from '../services/AIEnhancementService';
import { extractAffectedComponents, DetectedComponent } from '../utils/componentUtils';
import { vendorPortalMap } from '../utils/vendorPortals';
import type { AgentSettings, PatchData } from '../types/cveData';

export interface PatchDiscoveryResult {
  components: DetectedComponent[];
  vendorPortals: any[];
  patchData: PatchData;
}

export class PatchDiscoveryAgent {
  private setLoadingSteps: (stepsUpdater: (prev: string[]) => string[]) => void;

  constructor(setLoadingSteps?: (stepsUpdater: (prev: string[]) => string[]) => void) {
    this.setLoadingSteps = setLoadingSteps || (() => {});
  }

  private updateSteps(message: string) {
    this.setLoadingSteps(prev => [...prev, message]);
  }

  async discover(
    cveId: string,
    description: string,
    settings: AgentSettings
  ): Promise<PatchDiscoveryResult> {
    this.updateSteps(`🔍 PatchDiscoveryAgent analyzing ${cveId}...`);

    const components = extractAffectedComponents(description);
    const vendorPortals = components
      .map(c => vendorPortalMap[c.ecosystem])
      .filter(Boolean)
      .map(portal => ({ ...portal }));

    if (vendorPortals.length > 0) {
      this.updateSteps(
        `🌐 Vendor portals identified: ${vendorPortals.map(p => p.name).join(', ')}`
      );
    } else {
      this.updateSteps('ℹ️ No specific vendor portals found');
    }

    const cveData = { description } as any;
    const patchData = await fetchPatchesAndAdvisories(
      cveId,
      cveData,
      settings,
      this.setLoadingSteps
    );

    this.updateSteps(`✅ Patch discovery complete for ${cveId}`);
    return { components, vendorPortals, patchData };
  }
}
