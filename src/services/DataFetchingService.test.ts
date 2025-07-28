import { describe, it, expect, vi, afterEach } from 'vitest'
import * as DFS from './DataFetchingService'

const sampleNvd = {
  vulnerabilities: [
    {
      cve: {
        id: 'CVE-TEST',
        descriptions: [{ lang: 'en', value: 'desc' }],
        published: '2024-01-01',
        lastModified: '2024-01-02',
        metrics: {
          cvssMetricV31: [
            { cvssData: { baseScore: 7.2, baseSeverity: 'HIGH', vectorString: 'V' } }
          ]
        },
        references: [],
        configurations: [],
        weaknesses: []
      }
    }
  ]
}

describe('fetchCVEData', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('uses direct API when no AI settings', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(sampleNvd) })
    global.fetch = fetchMock as any

    const res = await DFS.fetchCVEData('CVE-TEST', null, () => {}, null)
    expect(fetchMock).toHaveBeenCalled()
    expect(res.id).toBe('CVE-TEST')
  })

  it('handles AI search path', async () => {
    const aiResponse = {
      output: [
        {
          type: 'message',
          content: [
            {
              type: 'output_text',
              text:
                'Description: Something. CVSS 7.3 (HIGH). 2024-01-01 2024-02-01'
            }
          ]
        }
      ]
    }
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers(),
      json: () => Promise.resolve(aiResponse),
      text: () => Promise.resolve(JSON.stringify(aiResponse))
    })
    global.fetch = fetchMock as any

    const rag = { initialized: true, addDocument: vi.fn() }
    const res = await DFS.fetchCVEData('CVE-XYZ', null, () => {}, rag, {
      aiProvider: 'openai'
    })

    expect(fetchMock).toHaveBeenCalled()
    expect(res.aiEnhanced).toBe(true)
    expect(res.id).toBe('CVE-XYZ')
    expect(rag.addDocument).toHaveBeenCalled()
  })

  it('throws when direct API fails and no AI', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 })
    await expect(DFS.fetchCVEData('CVE-BAD', null, () => {}, null)).rejects.toThrow()
  })
})
