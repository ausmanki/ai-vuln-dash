import { describe, it, expect } from 'vitest'
import { buildConversationalAnalysisPrompt, fetchWithFallback } from './UtilityService'

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

describe('fetchWithFallback', () => {
  it('uses error message from JSON response', async () => {
    const originalFetch = global.fetch
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      text: () => Promise.resolve(JSON.stringify({ error: { message: 'Invalid key' } }))
    }) as any

    await expect(fetchWithFallback('http://test', {}, 1)).rejects.toThrow('Invalid key')

    global.fetch = originalFetch
  })
})
