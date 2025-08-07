import { describe, it, expect, beforeEach } from 'vitest';
import { DedupCache } from '../DedupCache';

class LocalStorageMock {
  private store: Record<string, string> = {};
  getItem(key: string) { return this.store[key] || null; }
  setItem(key: string, value: string) { this.store[key] = value; }
  removeItem(key: string) { delete this.store[key]; }
  clear() { this.store = {}; }
}

describe('DedupCache', () => {
  beforeEach(() => {
    (global as any).localStorage = new LocalStorageMock();
    DedupCache.reset();
  });

  it('stores hash for new descriptions', () => {
    const unique = DedupCache.shouldProcess('Example CVE description');
    expect(unique).toBe(true);
    const stored = JSON.parse(localStorage.getItem('dedupHashes') || '[]');
    expect(stored.length).toBe(1);
  });

  it('skips similar descriptions once cached', () => {
    const desc = 'Buffer overflow in component X allows remote execution.';
    expect(DedupCache.shouldProcess(desc)).toBe(true);
    expect(DedupCache.shouldProcess(desc)).toBe(false);
  });
});
