import { describe, it, expect } from 'vitest'
import { buildConversationalAnalysisPrompt } from './UtilityService'

// This test ensures severity is derived from CVSS score when not provided

describe('buildConversationalAnalysisPrompt', () => {
  it('derives severity from CVSS score', () => {
    const vuln = {
      cve: {
        id: 'CVE-TEST-0001',
        description: 'Test vuln',
        cvssV3: {
          baseScore: 8.2
          // intentionally omit baseSeverity
        }
      },
      epss: { epss: '0.1' }
    } as any

    const prompt = buildConversationalAnalysisPrompt(vuln)
    expect(prompt).toContain('8.2 CVSS (HIGH)')
  })
})
