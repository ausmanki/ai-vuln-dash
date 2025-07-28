import { describe, it, expect, vi, afterEach } from 'vitest'

vi.mock('./AIEnhancementService', () => ({
  fetchPatchesAndAdvisories: vi.fn(),
  fetchAIThreatIntelligence: vi.fn(),
  generateAIAnalysis: vi.fn(),
  generateAITaintAnalysis: vi.fn(),
  fetchGeneralAnswer: vi.fn()
}))

import { APIService } from './APIService'
import * as AI from './AIEnhancementService'

const dummySettings = { aiProvider: 'openai', openAiModel: 'gpt-4.1' }

describe('APIService.fetchPatchesAndAdvisories', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('caches successful responses', async () => {
    const mock = vi
      .spyOn(AI, 'fetchPatchesAndAdvisories')
      .mockResolvedValue({ patches: ['p1'], advisories: ['a1'], searchSummary: {} })

    const res1 = await APIService.fetchPatchesAndAdvisories('CVE-1111', {}, dummySettings, () => {})
    const res2 = await APIService.fetchPatchesAndAdvisories('CVE-1111', {}, dummySettings, () => {})

    expect(mock).toHaveBeenCalledTimes(1)
    expect(res1).toEqual(res2)
  })

  it('does not cache failed requests', async () => {
    const mock = vi
      .spyOn(AI, 'fetchPatchesAndAdvisories')
      .mockRejectedValueOnce(new Error('fail'))
      .mockResolvedValueOnce({ patches: [], advisories: [], searchSummary: {} })

    await expect(
      APIService.fetchPatchesAndAdvisories('CVE-2222', {}, dummySettings, () => {})
    ).rejects.toThrow('fail')

    const res = await APIService.fetchPatchesAndAdvisories('CVE-2222', {}, dummySettings, () => {})
    expect(mock).toHaveBeenCalledTimes(2)
    expect(res.patches).toEqual([])
  })
})
