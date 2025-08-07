export class DedupCache {
  private static readonly CACHE_KEY = 'dedupHashes';
  private static readonly HASH_BITS = 64; // use 64-bit simhash

  // Retrieve stored hashes from localStorage
  private static getHashes(): string[] {
    if (typeof localStorage === 'undefined') return [];
    try {
      const raw = localStorage.getItem(this.CACHE_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch {
      return [];
    }
  }

  // Persist hashes to localStorage
  private static saveHashes(hashes: string[]): void {
    if (typeof localStorage === 'undefined') return;
    try {
      localStorage.setItem(this.CACHE_KEY, JSON.stringify(hashes));
    } catch {
      // ignore storage errors
    }
  }

  // Simple string hash function (32-bit)
  private static stringHash(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = (hash * 31 + str.charCodeAt(i)) >>> 0;
    }
    return hash;
  }

  // Generate a 64-bit simhash for given text
  private static simHash(text: string): string {
    const tokens = text.toLowerCase().split(/\W+/).filter(Boolean);
    const bits = new Array(this.HASH_BITS).fill(0);

    tokens.forEach(token => {
      let hash = this.stringHash(token);
      for (let i = 0; i < this.HASH_BITS; i++) {
        bits[i] += (hash & 1) ? 1 : -1;
        hash = hash >>> 1;
      }
    });

    let result = BigInt(0);
    for (let i = 0; i < this.HASH_BITS; i++) {
      if (bits[i] > 0) {
        result |= BigInt(1) << BigInt(i);
      }
    }
    return result.toString(16);
  }

  private static hammingDistance(a: string, b: string): number {
    const x = BigInt('0x' + a) ^ BigInt('0x' + b);
    let dist = 0;
    let y = x;
    while (y) {
      dist += Number(y & BigInt(1));
      y >>= BigInt(1);
    }
    return dist;
  }

  private static similarity(a: string, b: string): number {
    const dist = this.hammingDistance(a, b);
    return 1 - dist / this.HASH_BITS;
  }

  /**
   * Determines whether the provided text should be processed. Returns true if
   * the text is unique enough (no stored hash exceeds the threshold), in which
   * case the new hash is stored. Returns false if the text is considered a
   * duplicate and should be skipped.
   */
  static shouldProcess(text: string, threshold = 0.9): boolean {
    const newHash = this.simHash(text);
    const hashes = this.getHashes();

    for (const hash of hashes) {
      if (this.similarity(newHash, hash) >= threshold) {
        return false;
      }
    }

    hashes.push(newHash);
    this.saveHashes(hashes);
    return true;
  }

  // Clears stored hashes
  static reset(): void {
    if (typeof localStorage === 'undefined') return;
    try {
      localStorage.removeItem(this.CACHE_KEY);
    } catch {
      // ignore
    }
  }
}
