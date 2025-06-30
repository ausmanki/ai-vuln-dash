import { CONSTANTS } from '../utils/constants';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { APIService } from './APIService'; // For fetchWithFallback

// Using the more complex logic from the 'master' side of the conflict
export const fetchEPSSData = async (cveId, setLoadingSteps) => {
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  updateSteps(prev => [...prev, `📊 Fetching EPSS data for ${cveId}...`]);

  const url = `${CONSTANTS.API_ENDPOINTS.EPSS}?cve=${cveId}`;
  const response = await APIService.fetchWithFallback(url, {
    headers: {
      'Accept': 'application/json',
      'User-Agent': 'VulnerabilityIntelligence/1.0'
    }
  });

  if (!response.ok) {
    if (response.status === 404) {
      updateSteps(prev => [...prev, `⚠️ No EPSS data available for ${cveId}`]);
      return null;
    }
    throw new Error(`EPSS API error: ${response.status}`);
  }

  const data = await response.json();

  if (!data.data?.length) {
    updateSteps(prev => [...prev, `⚠️ No EPSS data found for ${cveId}`]);
    return null;
  }

  const epssData = data.data[0];
  const epssScore = parseFloat(epssData.epss);
  const percentileScore = parseFloat(epssData.percentile);
  const epssPercentage = (epssScore * 100).toFixed(3);

  updateSteps(prev => [...prev, `✅ Retrieved EPSS data for ${cveId}: ${epssPercentage}% (Percentile: ${percentileScore.toFixed(3)})`]);

  if (ragDatabase?.initialized) { // Added null check
    await ragDatabase.addDocument(
      `CVE ${cveId} EPSS Analysis: Exploitation probability ${epssPercentage}% (percentile ${percentileScore.toFixed(3)}). ${epssScore > 0.5 ? 'High exploitation likelihood - immediate attention required.' : epssScore > 0.1 ? 'Moderate exploitation likelihood - monitor closely.' : 'Lower exploitation likelihood but monitoring recommended.'}`,
      {
        title: `EPSS Analysis - ${cveId}`,
        category: 'epss-data',
        tags: ['epss', 'exploitation-probability', cveId.toLowerCase()],
        source: 'first-api',
        cveId: cveId
      }
    );
  }

  return {
    cve: cveId,
    epss: epssScore.toFixed(9).substring(0, 10),
    percentile: percentileScore.toFixed(9).substring(0, 10),
    epssFloat: epssScore,
    percentileFloat: percentileScore,
    epssPercentage: epssPercentage,
    date: epssData.date,
    model_version: data.model_version
  };
};
