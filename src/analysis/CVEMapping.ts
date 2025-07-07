export interface CVEEntry {
  id: string;
  functions: string[];
  library?: string;
  description: string;
  severity: string;
  module?: string;
  version?: string;
}

export interface CVEModuleInfo {
  name: string;
  version: string;
}

export interface CVERecord {
  description: string;
  modules: CVEModuleInfo[];
  cvss?: number;
  fix_version?: string;
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

export function parseCVEText(text: string): Record<string, CVERecord> {
  const records: Record<string, CVERecord> = {};
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  for (const line of lines) {
    const [idPart, modulePart] = line.split(' - ');
    if (!idPart || !modulePart) continue;
    const idx = modulePart.lastIndexOf(':');
    const name = modulePart.substring(0, idx);
    const version = modulePart.substring(idx + 1);
    const id = idPart.trim();
    const module: CVEModuleInfo = { name: name.trim(), version: version.trim() };
    if (!records[id]) {
      records[id] = { description: '', modules: [module] };
    } else {
      records[id].modules.push(module);
    }
  }
  return records;
}
