import { fetchWithFallback } from '../UtilityService';

export interface VendorAdvisory {
  vendor: string;
  title: string;
  url: string;
  severity?: string;
  patchAvailable?: boolean;
  description?: string;
}

/**
 * Fetch advisories from Microsoft's Security Update Guide.
 * Uses the public API which returns details for a given CVE ID.
 */
export async function fetchMicrosoftAdvisories(cveId: string): Promise<VendorAdvisory[]> {
  const url = `https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/${cveId}`;
  try {
    const res = await fetchWithFallback(url, {
      headers: { 'Accept': 'application/json' }
    });
    const data = await res.json();

    const advisories: VendorAdvisory[] = [];
    if (data) {
      advisories.push({
        vendor: 'Microsoft',
        title: data.cveTitle || data.title || `Microsoft advisory for ${cveId}`,
        url: `https://msrc.microsoft.com/update-guide/vulnerability/${cveId}`,
        severity: data.severity || data.cvssSeverity || 'Unknown',
        patchAvailable: true,
        description: data.description || ''
      });
    }
    return advisories;
  } catch (err) {
    console.warn('Microsoft advisory fetch failed', err);
    return [];
  }
}
