import { EnhancedVulnerabilityData } from '../types/cveData';
import { generateAIAnalysis } from '../services/AIEnhancementService';

export interface DedupedVulnerability {
  cveId: string;
  data: EnhancedVulnerabilityData;
  duplicates: EnhancedVulnerabilityData[];
  conflictNote?: string;
}

/**
 * BulkDeduplicator groups vulnerability entries by CVE ID and detects
 * conflicts in key fields between duplicates. When significant
 * differences are found it calls AIEnhancementService.generateAIAnalysis
 * to produce a short conflict note describing the discrepancy.
 */
export class BulkDeduplicator {
  static CVSS_DIFF_THRESHOLD = 1; // points

  /**
   * Deduplicate vulnerabilities and generate conflict notes when
   * duplicates disagree on important fields.
   */
  static async deduplicate(
    vulns: EnhancedVulnerabilityData[],
    aiSettings: any = {}
  ): Promise<DedupedVulnerability[]> {
    const groups = new Map<string, EnhancedVulnerabilityData[]>();

    for (const v of vulns) {
      const id = this.getId(v);
      if (!id) continue;
      if (!groups.has(id)) groups.set(id, []);
      groups.get(id)!.push(v);
    }

    const result: DedupedVulnerability[] = [];

    for (const [cveId, entries] of groups.entries()) {
      const primary = entries[0];
      let conflictNote: string | undefined;

      for (let i = 1; i < entries.length; i++) {
        const other = entries[i];
        const cvssA = this.getCvssScore(primary);
        const cvssB = this.getCvssScore(other);
        const exploitA = this.getExploitStatus(primary);
        const exploitB = this.getExploitStatus(other);
        const cvssDiff = Math.abs((cvssA ?? 0) - (cvssB ?? 0));
        const exploitMismatch =
          exploitA != null && exploitB != null && exploitA !== exploitB;

        if (
          (cvssA != null && cvssB != null && cvssDiff > this.CVSS_DIFF_THRESHOLD) ||
          exploitMismatch
        ) {
          try {
            conflictNote = await (generateAIAnalysis as any)(
              {
                primary,
                duplicate: other,
                prompt:
                  'Provide a short note describing the differences between the two vulnerability entries.'
              },
              'conflict-note',
              { aiProvider: 'mock' },
              null,
              async () => ({}),
              () => '',
              () => ''
            );
          } catch {
            conflictNote = 'Conflict detected between data sources.';
          }
          break; // one note per group
        }
      }

      result.push({ cveId, data: primary, duplicates: entries, conflictNote });
    }

    return result;
  }

  private static getId(v: any): string | undefined {
    return v?.cve?.id || v?.cve?.cve?.id || v?.cveId || v?.id;
  }

  private static getCvssScore(v: any): number | null {
    return (
      v?.cve?.cvssV3?.baseScore ??
      v?.cve?.cvssV2?.baseScore ??
      null
    );
  }

  private static getExploitStatus(v: any): boolean | null {
    return v?.exploits?.found ?? null;
  }
}

export default BulkDeduplicator;
