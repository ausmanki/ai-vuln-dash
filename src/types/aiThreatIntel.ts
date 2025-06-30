import {
  CisaKevDetails,
  ActiveExploitationData,
  ExploitDiscoveryData,
  VendorAdvisoryData,
  TechnicalAnalysisData,
  ThreatIntelligenceData,
  IntelligenceSummary,
  HallucinationFlag,
  ExtractionMetadata,
} from './cveData';

export interface AIThreatIntelData {
  cisaKev?: CisaKevDetails;
  activeExploitation?: ActiveExploitationData;
  exploitDiscovery?: ExploitDiscoveryData;
  vendorAdvisories?: VendorAdvisoryData;
  technicalAnalysis?: TechnicalAnalysisData;
  threatIntelligence?: ThreatIntelligenceData;
  searchResults?: Array<{ snippet?: string; title?: string; url?: string }>;
  intelligenceSummary?: IntelligenceSummary;
  overallThreatLevel?: string;
  lastUpdated?: string;
  summary?: string;
  hallucinationFlags?: Array<HallucinationFlag | string>;
  extractionMetadata?: ExtractionMetadata | Record<string, unknown>;
}
