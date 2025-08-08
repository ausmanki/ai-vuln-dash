import { fetchWithFallback } from '../UtilityService';
import type { VendorAdvisory } from './MicrosoftScraper';

/**
 * Fetch advisories from Cisco's security advisory feed.
 * Cisco provides a public endpoint which lists advisories by CVE.
 */
export async function fetchCiscoAdvisories(cveId: string): Promise<VendorAdvisory[]> {
  const url = `https://api.cisco.com/security/advisories/v2/CVE/${cveId}`;
  try {
    const res = await fetchWithFallback(url, {
      headers: { 'Accept': 'application/json' }
    });
    const data = await res.json();
    const advisories: VendorAdvisory[] = [];
    if (data && Array.isArray(data.advisories)) {
      for (const adv of data.advisories) {
        advisories.push({
          vendor: 'Cisco',
          title: adv.advisoryTitle || adv.title || `Cisco advisory for ${cveId}`,
          url: adv.advisoryURL || adv.url || '',
          severity: adv.severity || 'Unknown',
          patchAvailable: !!adv.firstFixed,
          description: adv.description || ''
        });
      }
    }
    return advisories;
  } catch (err) {
    console.warn('Cisco advisory fetch failed', err);
    return [];
  }
}
