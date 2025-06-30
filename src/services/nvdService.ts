import { CONSTANTS } from '../utils/constants';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { APIService } from './APIService'; // For fetchWithFallback

export const fetchCVEData = async (cveId, apiKey, setLoadingSteps) => {
  const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  updateSteps(prev => [...prev, `🔍 Fetching ${cveId} from NVD...`]);

  const url = `${CONSTANTS.API_ENDPOINTS.NVD}?cveId=${cveId}`;
  const headers = {
    'Accept': 'application/json',
    'User-Agent': 'VulnerabilityIntelligence/1.0'
  };

  if (apiKey) headers['apiKey'] = apiKey;

  // Assuming APIService.fetchWithFallback is accessible or moved to a shared util
  const response = await APIService.fetchWithFallback(url, { headers });

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

  if (ragDatabase.initialized) {
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
};

export const processCVEData = (cve) => {
  const description = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description available';
  const cvssV31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
  const cvssV30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
  const cvssV2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData;
  const cvssV3 = cvssV31 || cvssV30;

  return {
    id: cve.id,
    description,
    publishedDate: cve.published,
    lastModifiedDate: cve.lastModified,
    cvssV3: cvssV3 ? {
      baseScore: cvssV3.baseScore,
      baseSeverity: cvssV3.baseSeverity,
      vectorString: cvssV3.vectorString,
      exploitabilityScore: cvssV3.exploitabilityScore,
      impactScore: cvssV3.impactScore,
      attackVector: cvssV3.attackVector,
      attackComplexity: cvssV3.attackComplexity,
      privilegesRequired: cvssV3.privilegesRequired,
      userInteraction: cvssV3.userInteraction,
      scope: cvssV3.scope,
      confidentialityImpact: cvssV3.confidentialityImpact,
      integrityImpact: cvssV3.integrityImpact,
      availabilityImpact: cvssV3.availabilityImpact
    } : null,
    cvssV2: cvssV2 ? {
      baseScore: cvssV2.baseScore,
      vectorString: cvssV2.vectorString,
      accessVector: cvssV2.accessVector,
      accessComplexity: cvssV2.accessComplexity,
      authentication: cvssV2.authentication
    } : null,
    references: cve.references?.map(ref => ({
      url: ref.url,
      source: ref.source || 'Unknown',
      tags: ref.tags || []
    })) || []
  };
};
