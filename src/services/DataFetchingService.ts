import { CONSTANTS } from '../utils/constants';

export async function fetchCVEData(cveId, apiKey, setLoadingSteps, ragDatabase, fetchWithFallback, processCVEData) {
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  updateSteps(prev => [...prev, `🔍 Fetching ${cveId} from NVD...`]);

  const url = `${CONSTANTS.API_ENDPOINTS.NVD}?cveId=${cveId}`;
  const headers = {
    'Accept': 'application/json',
    'User-Agent': 'VulnerabilityIntelligence/1.0'
  };

  if (apiKey) headers['apiKey'] = apiKey;

  const response = await fetchWithFallback(url, { headers });

  if (!response.ok) {
    if (response.status === 403) {
      throw new Error('NVD API rate limit exceeded. Consider adding an API key.');
    }
    throw new Error(`NVD API error: ${response.status}`);
  }

  const data = await response.json();

  if (!data.vulnerabilities?.length) {
    throw new Error(`CVE ${cveId} not found in NVD database`);
  }

  updateSteps(prev => [...prev, `✅ Retrieved ${cveId} from NVD`]);

  const processedData = processCVEData(data.vulnerabilities[0].cve);

  // Store in RAG database
  if (ragDatabase?.initialized) {
    await ragDatabase.addDocument(
      `CVE ${cveId} NVD Data: ${processedData.description} CVSS Score: ${processedData.cvssV3?.baseScore || 'N/A'} Severity: ${processedData.cvssV3?.baseSeverity || 'Unknown'}`,
      {
        title: `NVD Data - ${cveId}`,
        category: 'nvd-data',
        tags: ['nvd', cveId.toLowerCase(), 'official-data'],
        source: 'nvd-api',
        cveId: cveId
      }
    );
  }

  return processedData;
}

export async function fetchEPSSData(cveId, setLoadingSteps, ragDatabase, fetchWithFallback) {
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  updateSteps(prev => [...prev, `📊 Fetching EPSS data for ${cveId}...`]);

  const url = `${CONSTANTS.API_ENDPOINTS.EPSS}?cve=${cveId}`;
  const response = await fetchWithFallback(url, {
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

  // Store in RAG database
  if (ragDatabase?.initialized) {
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
}
