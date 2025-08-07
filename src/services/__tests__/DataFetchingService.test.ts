import { describe, it, expect, vi, afterEach } from 'vitest';
import { resolveAliases } from '../DataFetchingService';
import { readFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ghsaResponse = JSON.parse(
  readFileSync(path.join(__dirname, 'fixtures/ghsa_response.json'), 'utf-8')
);
const cveResponse = JSON.parse(
  readFileSync(path.join(__dirname, 'fixtures/cve_response.json'), 'utf-8')
);

describe('resolveAliases', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('maps non-CVE identifiers to canonical CVE and collects aliases', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(ghsaResponse)
    }) as any;

    const result = await resolveAliases('GHSA-xxxx-yyyy');
    expect(global.fetch).toHaveBeenCalled();
    expect(result.canonical).toBe('CVE-2024-1234');
    expect(result.aliases).toEqual(expect.arrayContaining(['GHSA-xxxx-yyyy', 'CVE-2024-1234']));
  });

  it('returns aliases when starting from CVE id', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(cveResponse)
    }) as any;

    const result = await resolveAliases('CVE-2024-1234');
    expect(result.canonical).toBe('CVE-2024-1234');
    expect(result.aliases).toEqual(expect.arrayContaining(['GHSA-xxxx-yyyy', 'CVE-2024-1234']));
  });
});
