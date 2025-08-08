// src/types/cveData.ts

export interface CVSSV2 {
  source: string;
  type: string;
  cvssData: {
    version: string;
    vectorString: string;
    accessVector: string;
    accessComplexity: string;
    authentication: string;
    confidentialityImpact: string;
    integrityImpact: string;
    availabilityImpact: string;
    baseScore: number;
  };
  baseSeverity: string;
  exploitabilityScore: number;
  impactScore: number;
  acInsufInfo: boolean;
  obtainAllPrivilege: boolean;
  obtainUserPrivilege: boolean;
  obtainOtherPrivilege: boolean;
  userInteractionRequired: boolean;
}

export interface CVSSV3 {
  source: string;
  type: string;
  cvssData: {
    version: string;
    vectorString: string;
    attackVector: string;
    attackComplexity: string;
    privilegesRequired: string;
    userInteraction: string;
    scope: string;
    confidentialityImpact: string;
    integrityImpact: string;
    availabilityImpact: string;
    baseScore: number;
    baseSeverity: string;
  };
  exploitabilityScore: number;
  impactScore: number;
}

export interface Reference {
  url: string;
  source: string;
  tags?: string[];
}

export interface Weakness {
  source: string;
  type: string;
  description: Array<{
    lang: string;
    value: string;
  }>;
}

export interface ConfigurationNode {
  operator: string;
  negate: boolean;
  cpeMatch: Array<{
    vulnerable: boolean;
    criteria: string;
    matchCriteriaId: string;
    versionStartIncluding?: string;
    versionEndExcluding?: string;
    versionEndIncluding?: string;
  }>;
}

export interface CVE {
  id: string;
  sourceIdentifier: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  aliases?: string[]; // Additional identifiers referring to this CVE
  descriptions: Array<{
    lang: string;
    value: string;
  }>;
  metrics: {
    cvssMetricV2?: CVSSV2[];
    cvssMetricV31?: CVSSV3[];
    cvssMetricV30?: CVSSV3[];
  };
  weaknesses?: Weakness[];
  configurations?: Array<{
    nodes: ConfigurationNode[];
  }>;
  references: Reference[];
  evaluatorComment?: string;
  evaluatorImpact?: string;
  evaluatorSolution?: string;
  cisaExploitAdd?: string;
  cisaActionDue?: string;
  cisaRequiredAction?: string;
  cisaVulnerabilityName?: string;
}

export interface BaseCVEInfo {
  cve: CVE;
  cvssV2?: CVSSV2['cvssData'] & { baseSeverity?: string };
  cvssV3?: CVSSV3['cvssData'] & { baseSeverity?: string };
}


export interface EPSSData {
  cve: string;
  epss: string; // Store as string, convert to number when needed
  percentile: string; // Store as string, convert to number when needed
  date: string;
  epssPercentage?: number; // Calculated field
  percentilePercentage?: number; // Calculated field
}

export interface CisaKevDetails {
  catalogVersion?: string;
  dateAdded?: string;
  dueDate?: string;
  notes?: string;
  requiredAction?: string;
  vulnerabilityName?: string;
  [key: string]: any; // Allow other properties from KEV data
  listed?: boolean; // Custom field: is it listed in KEV?
  details?: string; // Summary of KEV details
  aiDiscovered?: boolean;
  verified?: boolean;
  actualStatus?: string; // From validation
}

export interface Exploit {
  source: string; // e.g., 'Metasploit', 'ExploitDB', 'GitHub'
  type: string; // e.g., 'PoC', 'Exploit Module', 'Tool'
  url?: string;
  description?: string;
  date?: string; // Date exploit was published or found
  reliability?: 'High' | 'Medium' | 'Low' | 'Unknown'; // Assessed reliability
  verified?: boolean; // Has the exploit been verified to work?
  tags?: string[]; // e.g., ['RCE', 'DoS', 'Privilege Escalation']
  codeAvailable?: boolean; // Is the exploit code directly available?
  githubRepo?: string; // If from GitHub
  citationUrl?: string; // URL of the AI's source for this info
}


export interface ExploitDiscoveryData {
  found: boolean;
  totalCount: number;
  exploits?: Exploit[];
  sourcesChecked?: string[]; // Which sources were actively checked
  summary?: string; // AI-generated summary of exploit availability
  githubRepos?: number;
  metasploitModules?: number;
  exploitDBEntries?: number;
  validated?: boolean;
  verifiedCount?: number;
}


export interface VendorAdvisory {
  vendor: string;
  product?: string; // Specific product if mentioned
  url: string;
  title?: string;
  date?: string; // Advisory publication date
  severity?: string; // Severity as rated by vendor
  patchAvailable?: boolean;
  cwe?: string; // CWE if mentioned in advisory
  summary?: string; // Brief summary of the advisory content
  source?: string; // Where this advisory was found (e.g., 'AI Web Search', 'Vendor X Security Page')
  citationUrl?: string; // URL of the AI's source for this info
}

export interface VendorAdvisoryData {
  found: boolean;
  count: number;
  advisories?: VendorAdvisory[];
  sourcesChecked?: string[];
  summary?: string; // AI-generated summary
  validated?: boolean;
}

export interface PatchInfo {
  vendor: string;
  product?: string;
  patchVersion?: string; // Version that includes the fix
  downloadUrl?: string;
  advisoryUrl?: string; // Link to advisory detailing the patch
  releaseDate?: string;
  description?: string;
  source?: string; // e.g., 'AI Web Search', 'Vendor X Patch Notes'
  citationUrl?: string; // URL of the AI's source for this info
}

export interface PatchSearchSummary {
  patchesFound: number;
  advisoriesFound: number;
  vendorsSearched: string[]; // List of vendors AI attempted to search for
  directDownloads: number; // Number of direct patch download links found
  requiresLogin: number; // Number of patches that require login to download
}

export interface PatchData {
  patches?: PatchInfo[];
  advisories?: VendorAdvisory[]; // Advisories specifically about patches or fixes
  searchSummary?: PatchSearchSummary;
  summary?: string; // Overall summary of patch availability
}

export interface RemediationStep {
  phase: string;
  title: string;
  description: string;
  actions: string[];
  tools: string[];
  estimatedTime: string;
  priority: string;
}

export interface TechnicalAnalysisData {
  text?: string; // In-depth technical explanation of the vulnerability
  attackVector?: string; // How the vulnerability is exploited
  impact?: string; // Potential impact of exploitation
  mitigationSteps?: string[]; // Suggested mitigation steps
  codeSnippets?: Array<{ language: string; code: string; description?: string }>; // Relevant code examples
  source?: string; // Where this analysis came from (e.g., 'AI Generated', 'Researcher Blog URL')
}

export interface ThreatActorActivity {
  actorName?: string; // Name of the threat actor/group
  description?: string; // Description of their activity related to this CVE
  targets?: string[]; // Industries or regions targeted
  ttps?: string[]; // Tactics, Techniques, and Procedures used
  source?: string; // Source of this information (e.g., 'Threat Intel Report URL', 'AI Web Search')
  firstSeen?: string; // Date first seen
  lastSeen?: string; // Date last seen
}

export interface ActiveExploitationData {
  confirmed: boolean; // Is active exploitation confirmed?
  details?: string; // Summary of exploitation activity
  sources?: string[]; // Sources confirming exploitation (e.g., 'CISA KEV', 'News Article URL')
  threatActors?: ThreatActorActivity[];
  firstSeen?: string;
  lastSeen?: string;
  validated?: boolean;
}

export interface ThreatIntelligenceData {
  summary?: string; // Overall threat intelligence summary
  activeExploitation?: ActiveExploitationData;
  exploitAvailability?: ExploitDiscoveryData; // Could be part of this or separate
  targetedSectors?: string[];
  threatActors?: ThreatActorActivity[];
  malwareUsed?: string[];
  potentialImpact?: string;
  confidence?: 'High' | 'Medium' | 'Low';
  source?: string; // e.g., AI-generated, specific feed
}

export interface GithubData {
  found: boolean;
  count: number; // Total relevant repos/commits/etc.
  repositories?: Array<{
    name: string;
    url: string;
    description?: string;
    stars?: number;
    forks?: number;
    lastPush?: string;
    type?: 'PoC' | 'Exploit' | 'VulnerableCode' | 'Discussion' | 'Patch';
  }>;
  summary?: string;
}

export interface IntelligenceSummary {
  sourcesAnalyzed: number;
  exploitsFound: number;
  vendorAdvisoriesFound: number;
  activeExploitation: boolean;
  cisaKevListed: boolean;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  dataFreshness: 'REAL_TIME' | 'HOURLY' | 'DAILY' | 'AI_WEB_SEARCH' | 'STATIC';
  analysisMethod: 'AUTOMATED_CORRELATION' | 'AI_ENHANCED' | 'AI_WEB_SEARCH' | 'MANUAL_REVIEW' | 'GROUNDING_INFO_ONLY' | 'AI_WEB_SEARCH_VALIDATED';
  confidenceLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  aiEnhanced: boolean;
  validated: boolean; // New field: overall validation status of the AI findings
  searchQueries?: string[]; // Queries AI used for web search
}

export interface HallucinationFlag {
  field: string; // Which field might be a hallucination
  suspectedReason: string; // Why it's suspected (e.g., "contradicts NVD", "unlikely claim")
  confidence: 'High' | 'Medium' | 'Low'; // Confidence in it being a hallucination
  details?: string; // More details
}

export interface ExtractionMetadata {
  sourceType: 'NVD' | 'EPSS' | 'AI_WEB_SEARCH' | 'VENDOR_API';
  query?: string; // Query used if applicable (e.g., for AI web search)
  timestamp: string;
  confidence?: number; // 0-1, confidence in the extraction from this source
  errors?: string[]; // Any errors during extraction from this source
}

export interface InformationSource {
  name: string;
  url?: string;
  type?: string;
  aiDiscovered?: boolean;
  [key: string]: any;
}

export interface ConflictingInfo {
  field: string;
  details: string;
  sources?: string[];
}


// --- CVEValidationData for Legitimacy Analysis ---
export interface AdvisoryInfo { // Duplicated for now, consider moving to a shared types location if not already
  source: string;
  url?: string;
  title?: string;
}

export interface CVEValidationData {
  cveId: string;
  status?: 'VALID' | 'INVALID' | 'DISPUTED' | 'NEEDS_VERIFICATION' | 'REJECTED' | 'UNKNOWN';
  recommendation?: string;
  summary?: string; // This can be the AI-generated summary of validation points.
  confidence?: string; // e.g., "High", "Medium", "Low" for the overall validation assessment.
  validationSources?: string[]; // List of sources used for this validation (e.g., NVD, AI Web Search, Vendor X)
  lastUpdated?: string;

  // New structured fields for Legitimacy Analysis
  vendorDispute?: {
    hasDispute: boolean;
    source?: string;
    details?: string;
  } | null;

  falsePositive?: {
    isFalsePositive: boolean;
    reason?: string;
    source?: string;
  } | null;

  vendorConfirmation?: {
    hasConfirmation: boolean;
    patches?: PatchInfo[]; // Using existing PatchInfo
    advisories?: AdvisoryInfo[]; // Using existing AdvisoryInfo (or a refined version)
    details?: string; // Summary of confirmations
  } | null;

  researcherValidation?: {
    consensus?: 'Positive' | 'Negative' | 'Mixed' | 'Unknown';
    evidence?: Array<{
      text?: string;
      url?: string;
      source?: string; // Name of researcher or organization
    }>;
    summary?: string;
  } | null;

  legitimacySummary?: string; // Overall textual summary from ValidationService addressing the four points.
  legitimacyScore?: number | null; // Optional: 0-100 score.

  // Retaining for detailed evidence or backward compatibility
  legitimacyEvidence?: string[];
  falsePositiveIndicators?: string[];
  disputes?: Array<{
      source: string;
      reason: string;
      date?: string;
      url?: string;
  }>;
}


export interface EnhancedVulnerabilityData {
  cve: BaseCVEInfo | null;
  epss?: EPSSData | null;
  kev?: CisaKevDetails | null;
  exploits?: ExploitDiscoveryData | null;
  vendorAdvisories?: VendorAdvisoryData | null;
  cveValidation?: CVEValidationData | null; // Updated to new structure
  technicalAnalysis?: TechnicalAnalysisData | null;
  github?: GithubData | null; // Info from GitHub (PoCs, discussions)
  activeExploitation?: ActiveExploitationData | null; // More focused than full ThreatIntel
  threatIntelligence?: ThreatIntelligenceData | null; // Broader threat context

  intelligenceSummary?: IntelligenceSummary | null; // Summary of how this data was gathered/analyzed

  patches?: PatchInfo[]; // Direct patch info
  advisories?: VendorAdvisory[]; // Direct advisory info (might be duplicated if also in vendorAdvisories)
  patchSearchSummary?: PatchSearchSummary;

  sources?: InformationSource[]; // List of all information sources used
  discoveredSources?: string[]; // Names of sources AI found data in

  summary?: string; // Overall AI-generated summary of the CVE
  analysisSummary?: string; // Alias for summary used by some UI components
  groupSummary?: string; // Summary for grouped/merged CVE descriptions
  threatLevel?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  dataFreshness?: string; // e.g., 'Real-time', 'Daily', 'As of YYYY-MM-DD'
  lastUpdated: string; // When this enhanced record was created/updated
  searchTimestamp?: string; // When the AI search was performed for this CVE

  ragEnhanced?: boolean; // Was this data enhanced by RAG?
  aiSearchPerformed?: boolean; // Was an AI web search performed?
  aiWebGrounded?: boolean; // Were AI results grounded with web search?

  // Fields for advanced validation and confidence scoring
  enhancedSources?: string[];
  analysisMethod?: string;
  validation?: any; // Placeholder for a more structured validation object if needed beyond cveValidation
  confidence?: { // Overall confidence in this entire enhanced record
      overall: 'HIGH' | 'MEDIUM' | 'LOW';
      score?: number; // 0-100
      factors?: Record<string, 'HIGH' | 'MEDIUM' | 'LOW' | number>; // Confidence in specific parts
      [key: string]: any;
  };
  hallucinationFlags?: HallucinationFlag[];
  extractionMetadata?: ExtractionMetadata[];
  validationTimestamp?: string;
  enhancedWithValidation?: boolean;
}


export interface AISummaryData {
  cveId: string;
  summary: string;
  technicalSummary?: string;
  exploitStatus?: string;
  patchStatus?: string;
  threatContext?: string;
  recommendations?: string[];
  confidenceScore?: number; // 0-1
  sourcesConsidered?: string[];
  error?: string;
  analysis?: string; // General purpose field for AI analysis text
}


export interface EnvironmentProfile {
  os: string;
  softwareVersions: Record<string, string>;
  criticalAssets: string[];
}

export interface AgentSettings {
  nvdApiKey?: string;
  geminiModel?: string;
  openAiModel?: string;
  aiProvider?: 'gemini' | 'openai';
  cacheTTL?: number; // TTL for caching in milliseconds
  intentRecognitionMode?: 'regex' | 'ml';
  alertFrequencyMinutes?: number; // How often to poll for updates
  environmentProfile?: EnvironmentProfile;
  [key: string]: any; // Allow other settings
}


export interface ChatResponse<T = any> {
  text: string;
  data?: T; // Optional structured data
  error?: string; // Optional error message
  // For UserAssistantAgent
  id?: string;
  sender?: 'user' | 'bot' | 'system';
  confidence?: number;
  followUps?: string[];
  sources?: string[]; // Source URLs for citations
}

export interface BulkAnalysisResult {
  cveId: string;
  data?: EnhancedVulnerabilityData;
  error?: string;
  status: 'Pending' | 'Processing' | 'Complete' | 'Error';
  group?: string[]; // All CVE IDs represented in this deduplicated group
}
