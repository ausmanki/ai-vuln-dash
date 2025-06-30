// src/types/cveData.ts

// Settings for agents
export interface AgentSettings {
  nvdApiKey?: string;
  geminiApiKey?: string;
  geminiModel?: string;
  darkMode?: boolean;
  // Add any other settings that agents might need
}

// Data structure for EPSS information
export interface EPSSData {
  cve: string;
  epss: string; // Consider making this number if it's always numeric
  percentile: string; // Consider making this number
  epssFloat?: number; // Already number in some uses
  percentileFloat?: number; // Already number in some uses
  epssPercentage: string; // e.g., "X.XXX%"
  date: string;
  model_version?: string;
}

// Details for CISA KEV catalog entries
export interface CisaKevDetails {
  listed: boolean;
  details?: string;
  source?: string;
  dueDate?: string;
  vendorProject?: string;
  confidence?: string;
  aiDiscovered?: boolean;
  validated?: boolean;
  actualStatus?: string;
}

// Details for individual exploits
export interface ExploitDetails {
  type?: string;
  url?: string;
  source?: string;
  description?: string;
  reliability?: string;
  citationUrl?: string;
}

// Data structure for discovered exploits
export interface ExploitDiscoveryData {
  found: boolean;
  totalCount?: number;
  exploits?: ExploitDetails[];
  githubRepos?: number;
  exploitDbEntries?: number;
  metasploitModules?: number;
  validated?: boolean;
  verifiedCount?: number;
  // Summary fields that might be part of the raw AI response
  confidence?: string;
}


// Details for vendor advisories or patches
export interface VendorAdvisoryDetails {
  vendor?: string;
  product?: string; // Affected product
  patchVersion?: string;
  downloadUrl?: string; // Actual download URL for a patch
  advisoryUrl?: string; // URL of the vendor advisory page
  releaseDate?: string;
  description?: string;
  confidence?: string; // AI's confidence in this finding
  patchType?: string; // e.g., Security Update, Hotfix
  citationUrl?: string; // Source URL confirming this specific info
  title?: string; // Advisory title
  patchAvailable?: boolean; // Explicitly stated patch availability
  severity?: string; // Advisory severity
  source?: string; // Publishing organization (for advisories)
  type?: string; // Type of advisory (e.g., Security Advisory, Bulletin)
  advisoryId?: string; // e.g. RHSA-XXXX:XXXX
  publishDate?: string; // for advisories
}

// Data structure for patches and advisories search results
export interface PatchData {
  patches?: VendorAdvisoryDetails[];
  advisories?: VendorAdvisoryDetails[];
  searchSummary?: {
    patchesFound?: number;
    advisoriesFound?: number;
    vendorsSearched?: string[];
    searchTimestamp?: string;
    enhancedWithHeuristics?: boolean;
    totalPatchesFound?: number;
    totalAdvisoriesFound?: number;
  };
}

// Data structure for active exploitation information
export interface ActiveExploitationData {
  confirmed: boolean;
  details?: string;
  sources?: string[]; // List of credible sources confirming exploitation
  threatActors?: string[];
  confidence?: string;
  aiDiscovered?: boolean;
}

// Data structure for AI-generated analysis/summary
export interface AISummaryData {
  analysis: string;
  ragUsed?: boolean;
  ragDocuments?: number;
  ragSources?: string[];
  webGrounded?: boolean;
  model?: string;
  analysisTimestamp?: string;
  // Include other relevant fields from the actual generateAIAnalysis response
}

// Details for a single dispute in CVE validation
export interface CVEValidationDispute {
  source: string;
  date?: string;
  reason: string;
  url?: string;
}

// Data structure for CVE validation results
export interface CVEValidationData {
  recommendation?: 'VALID' | 'FALSE_POSITIVE' | 'DISPUTED' | 'NEEDS_VERIFICATION' | 'REJECTED' | string; // string for flexibility if new values appear
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW' | string;
  summary?: string; // AI-generated summary of the validation process
  legitimacyEvidence?: string[];
  falsePositiveIndicators?: string[];
  disputes?: CVEValidationDispute[];
  validationSources?: string[]; // e.g., ['NVD', 'Vendor X', 'Researcher Y']
  isValid?: boolean; // Simplified boolean, true if recommendation is 'VALID'
  // other fields from ValidationService output
}

// Basic NVD CVE Information
export interface CVSSV2Data {
  baseScore: number;
  severity: string;
  vectorString?: string;
  // ... other CVSSv2 fields
}
export interface CVSSV3Data {
  baseScore: number;
  baseSeverity: string;
  vectorString?: string;
  // ... other CVSSv3 fields
}
export interface BaseCVEInfo {
  id: string;
  description?: string; // Often from NVD description
  cvssV2?: CVSSV2Data;
  cvssV3?: CVSSV3Data;
  publishedDate?: string;
  lastModifiedDate?: string;
  // Potentially more fields from NVD's CVE structure
}

// Comprehensive Vulnerability Data Object (like the one from ResearchAgent)
export interface EnhancedVulnerabilityData {
  cve: BaseCVEInfo; // Core NVD data
  epss?: EPSSData;
  kev?: CisaKevDetails; // CISA KEV status
  exploits?: ExploitDiscoveryData; // Public exploit info (summary, not links)
  patchesAndAdvisories?: PatchData; // Renamed from vendorAdvisories to be more encompassing
  cveValidation?: CVEValidationData; // Legitimacy analysis
  activeExploitation?: ActiveExploitationData; // Active exploitation in the wild

  // AI generated summaries / threat levels
  summary?: string; // Overall AI-generated summary of the CVE
  threatLevel?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | string;
  aiAnalysis?: AISummaryData; // Detailed narrative AI analysis

  // Metadata
  sources?: Array<{name: string, url?: string, type?: string, [key: string]: any}>; // List of information sources used
  discoveredSources?: string[];
  lastUpdated?: string;
  confidence?: any; // TODO: Define a proper confidence score object structure
  validation?: any; // TODO: Define a proper overall validation object from ValidationService more fully
  // ... any other fields that ResearchAgent aggregates
}

// Generic Chat Response interface, can be typed with specific data
export interface ChatResponse<T = any> {
  text: string;
  data?: T;
  error?: string;
  // Fields below are more for ChatHistory's Message interface, but can be here for flexibility
  sender?: 'user' | 'bot' | 'system';
  id?: string;
}
