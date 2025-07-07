export interface CVEEntry {
  id: string;
  functions: string[];
  library?: string;
  description: string;
  severity: string;
}

export function buildCVEMap(entries: CVEEntry[]): Map<string, CVEEntry[]> {
  const map = new Map<string, CVEEntry[]>();
  for (const entry of entries) {
    for (const fn of entry.functions) {
      const list = map.get(fn) || [];
      list.push(entry);
      map.set(fn, list);
    }
  }
  return map;
}
