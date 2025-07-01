import { ValidationService } from '../services/ValidationService';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { BaseCVEInfo, PatchData, CVEValidationData } from '../types/cveData';
import { AIThreatIntelData } from '../types/aiThreatIntel';

export class ValidationAgent {
  private setLoadingSteps: (stepsUpdater: (prev: string[]) => string[]) => void;

  constructor(setLoadingSteps?: (stepsUpdater: (prev: string[]) => string[]) => void) {
    this.setLoadingSteps = setLoadingSteps || (() => {});
  }

  private updateSteps(message: string) {
    this.setLoadingSteps(prev => [...prev, message]);
  }

  public async validateCVE(
    cveId: string,
    nvdData: BaseCVEInfo | null,
    aiIntel: AIThreatIntelData | null,
    patchData: PatchData | null
  ): Promise<CVEValidationData> {
    this.updateSteps(`🛡️ Validation Agent processing ${cveId}...`);
    const result = await ValidationService.validateAIFindings(
      cveId,
      nvdData,
      aiIntel,
      patchData
    );
    this.updateSteps(`✅ Validation complete for ${cveId}`);

    if (ragDatabase?.initialized) {
      try {
        await ragDatabase.addDocument(
          `Validation for ${cveId}: ${result.legitimacySummary || result.status}`,
          {
            title: `Validation - ${cveId}`,
            category: 'validation-result',
            cveId,
            source: 'validation-agent',
            timestamp: new Date().toISOString(),
          }
        );
      } catch (err) {
        console.warn('ValidationAgent failed to store result in RAG DB:', err);
      }
    }
    return result;
  }
}
