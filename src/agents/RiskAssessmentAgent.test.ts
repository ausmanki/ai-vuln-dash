import { describe, it, expect } from 'vitest';
import { RiskAssessmentAgent, RiskAssessmentInput } from './RiskAssessmentAgent';

describe('RiskAssessmentAgent', () => {
  it('formats risk assessment output', () => {
    const input: RiskAssessmentInput = {
      cvssScore: 8.0,
      epssScore: 0.75,
      cisaKevStatus: 'YES',
      exploitsKnown: 'YES',
      vulnerabilityId: 'CVE-2017-1000251',
      patchInfo: 'Patch Available, Released: 2017-09-30',
      businessPriority: 'P2 – Next sprint priority for engineering',
      threatIntelConfidence: 'High – Multiple authoritative sources: CERT, vendor, GitHub'
    };

    const result = RiskAssessmentAgent.generateAssessment(input);
    expect(result.text).toContain('AI Risk Assessment Results');
    expect(result.text).toContain('# CVE-2017-1000251 Technical Brief');
    expect(result.text).toContain('Patch Available');
  });
});
