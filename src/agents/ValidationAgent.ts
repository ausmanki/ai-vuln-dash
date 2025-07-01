import { ValidationService } from '../services/ValidationService';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { AgentSettings, PatchData, BaseCVEInfo, CVEValidationData } from '../types/cveData';
import { AIThreatIntelData } from '../types/aiThreatIntel';

export class ValidationAgent {
  private settings: AgentSettings;

  constructor(settings: AgentSettings = {}) {
    this.settings = settings;
  }

  async validateCVE(
    cveId: string,
    nvdData: BaseCVEInfo | null,
    aiIntel: AIThreatIntelData | null,
    patchData: PatchData | null,
  ): Promise<CVEValidationData> {
    const result = await ValidationService.validateAIFindings(cveId, nvdData, aiIntel, patchData);

    if (ragDatabase?.initialized) {
      try {
        const summary = result.legitimacySummary || result.recommendation || '';
        await ragDatabase.addDocument(
          `Validation summary for ${cveId}: ${summary}`,
          {
            title: `Validation - ${cveId}`,
            category: 'validation-summary',
            tags: ['validation', cveId.toLowerCase()],
            source: 'validation-agent',
            cveId,
            timestamp: new Date().toISOString(),
            status: result.status,
          },
        );
      } catch (err) {
        console.warn('ValidationAgent: failed to store result in RAG DB:', err);
      }
    }

    return result;
  }
}
