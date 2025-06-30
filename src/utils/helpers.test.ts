import { describe, it, expect } from 'vitest'
import { utils } from './helpers'

describe('utils.validateCVE', () => {
  it('accepts valid CVE identifiers', () => {
    expect(utils.validateCVE('CVE-2024-1234')).toBe(true)
    expect(utils.validateCVE('cve-1999-9999')).toBe(true)
    expect(utils.validateCVE('BDSA-2024-0001')).toBe(true)
  })

  it('rejects invalid CVE identifiers', () => {
    expect(utils.validateCVE('CVE-20-1234')).toBe(false)
    expect(utils.validateCVE('invalid')).toBe(false)
  })
})

describe('utils.getVulnerabilityUrl', () => {
  it('returns correct URL for CVE and BDSA', () => {
    expect(utils.getVulnerabilityUrl('CVE-2024-1234')).toBe('https://nvd.nist.gov/vuln/detail/CVE-2024-1234')
    expect(utils.getVulnerabilityUrl('bdsa-2024-0001')).toBe('https://openhub.net/vulnerabilities/bdsa/BDSA-2024-0001')
  })
})

describe('utils.getSeverityLevel', () => {
  it('maps numeric scores to severity strings', () => {
    expect(utils.getSeverityLevel(9.1)).toBe('CRITICAL')
    expect(utils.getSeverityLevel(8.0)).toBe('HIGH')
    expect(utils.getSeverityLevel(5.5)).toBe('MEDIUM')
    expect(utils.getSeverityLevel(1.0)).toBe('LOW')
  })
})
