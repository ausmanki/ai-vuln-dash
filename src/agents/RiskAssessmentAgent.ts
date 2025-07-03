export interface RiskAssessmentInput {
  cvssScore: number;
  epssScore: number;
  cisaKevStatus: 'YES' | 'NO';
  exploitsKnown: 'YES' | 'NO';
  vulnerabilityId: string;
  patchInfo: string;
  businessPriority: string;
  threatIntelConfidence: string;
}

export interface RiskAssessmentResult {
  text: string;
}

export class RiskAssessmentAgent {
  static generateAssessment(input: RiskAssessmentInput): RiskAssessmentResult {
    const timestamp = new Date().toLocaleString();
    const lines = [
      '🛡️ **AI Risk Assessment Results**',
      `- **CVSS Score**: ${input.cvssScore}`,
      `- **EPSS Score**: ${input.epssScore}`,
      `- **CISA KEV**: ${input.cisaKevStatus}`,
      `- **Exploits Known**: ${input.exploitsKnown}`,
      `Generated ${timestamp}`,
      '',
      '📘 **Risk Assessment Analysis**',
      `# ${input.vulnerabilityId} Technical Brief`,
      `**Status**: ${input.patchInfo}`,
      `**Priority**: ${input.businessPriority}`,
      `**Confidence**: ${input.threatIntelConfidence}`
    ];
    return { text: lines.join('\n') };
  }
}
