// Updated UtilityService.ts - Remove duplicate fetchWithFallback and focus on other utilities
import { utils } from '../utils/helpers';
import { CONSTANTS } from '../utils/constants';

// Enhanced fetch with retry and fallback mechanisms
export async function fetchWithFallback(url: string, options: RequestInit = {}, retries: number = 3): Promise<Response> {
  let lastError: Error;
  
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const response = await fetch(url, {
        ...options,
        // Note: timeout is not a standard fetch option in browsers
        // You might want to implement timeout using AbortController
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      return response;
    } catch (error) {
      lastError = error as Error;
      console.warn(`Fetch attempt ${attempt}/${retries} failed for ${url}:`, error);
      
      if (attempt === retries) {
        break;
      }
      
      // Exponential backoff: wait longer between retries
      const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  
  throw new Error(`Failed to fetch ${url} after ${retries} attempts. Last error: ${lastError.message}`);
}

// Enhanced fetch with timeout using AbortController (more robust)
export async function fetchWithTimeout(url: string, options: RequestInit = {}, timeoutMs: number = 30000): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error(`Request timeout after ${timeoutMs}ms`);
    }
    throw error;
  }
}

// Unified prompt used for CVE analysis requests
export const TECHNICAL_BRIEF_PROMPT = String.raw`# CVE Technical Brief Generation Prompt – Multi-Audience Engineering Focus

You are a senior cybersecurity analyst with 20 years of experience. Your task is to generate a concise, accurate, and actionable technical brief for a single CVE ID. This brief serves **product teams, engineering leads, BU security champions, and product security engineers** with tailored information for each audience.

## Target Audiences & Their Needs
- **Product Teams**: Business impact, user-facing risks, deployment timeline implications
- **Engineering Leads**: Technical implementation, resource requirements, testing priorities  
- **BU Security Champions**: Risk communication, stakeholder messaging, compliance implications
- **Product Security Engineers**: Deep technical analysis, validation, tooling integration

## Core Guidelines
- Communicate as a technical peer, not a vendor
- Balance technical depth with business clarity
- Avoid filler, hype, or generalized language  
- Focus on decision-making, not speculation
- Confidence levels must be justified
- Only use information explicitly found in the provided context
- **NEVER fabricate or infer information not explicitly stated in context**
- If data is missing, write "Not specified" - do not estimate or assume

## Priority Definitions (Multi-Audience Context)
- **P0**: Active exploitation + high business impact → **All Teams**: Patch within 24h, halt deployments, emergency response
- **P1**: Public exploit available + medium-high impact → **Engineering**: Patch within 72h, **BU**: Customer communication plan, **Product**: Release planning impact
- **P2**: PoC exists + moderate impact → **Engineering**: Next sprint priority, **BU**: Monitor threat landscape, **Product**: Include in roadmap
- **P3**: Theoretical risk + low impact → **All Teams**: Standard maintenance cycle, monitor for changes

## Business Context Integration
Each section should consider:
- **Customer Impact**: How does this affect end users?
- **Business Risk**: Revenue, compliance, reputation implications
- **Resource Requirements**: Engineering effort, timeline impact
- **Communication Needs**: What do BU champions tell stakeholders?

## Language Standards
### ❌ Security Theater Language
- "Critical vulnerability could allow attackers to completely compromise systems"
- "Sophisticated threat actors are actively exploiting this flaw"
- "Immediate patching is essential across all environments"
- "Could lead to devastating business impact"

### ✅ Multi-Audience Engineering Language
- **Technical**: "Remote code execution via malformed HTTP headers, no auth required"
- **Business**: "Allows attackers to execute code on servers, potentially accessing customer data"
- **Operational**: "Update to version 2.1.3 within 72h for internet-facing systems"
- **Risk Communication**: "High severity with proof-of-concept available, customers should be notified of patching timeline"

## Required Output Format

# CVE-YYYY-NNNNN Technical Brief

<!-- SCHEMA_VALIDATION_START -->
**Status**: [ENUM: Patch Available|In Progress|No Fix] (Released: [DATE: YYYY-MM-DD|Not specified])  
**Priority**: [ENUM: P0|P1|P2|P3] – [STRING: Specific remediation timeframe + business context]  
**Confidence**: [ENUM: High|Medium|Low] – [STRING: # sources, agreement level, vendor confirmation Y/N]

## Executive Summary (For BU Security Champions & Product Teams)
- **Business Risk**: [STRING: Customer impact, revenue risk, compliance implications]
- **Customer Communication**: [ENUM: Immediate notification required|Proactive communication recommended|Standard update cycle|No customer communication needed]
- **Timeline Impact**: [STRING: Effect on product releases, deployment schedules]

## Core Facts (Technical Foundation)
- **Component**: [STRING: Exact affected software/version ranges or "Not specified"]
- **Attack Vector**: [ENUM: Network|Local|Physical] + [Auth Required: ENUM: Y|N|Not specified]
- **Exploitation**: [ENUM: Confirmed in wild|PoC available|Theoretical only|Not specified]
- **Exploit Published**: [DATE: YYYY-MM-DD|Not published|Not specified]
- **Real-world Usage**: [Active attacks: ENUM: Y|N|Not specified] | [CISA KEV: ENUM: Y|N]
- **Complexity**: [ENUM: Trivial|Moderate|High|Not specified] skill required

## Business Impact Analysis
- **Technical Effect**: [STRING: Specific consequence - RCE, DoS, privilege escalation, data access]
- **Customer Impact**: [STRING: How end users are affected - service disruption, data exposure risk]
- **Business Risk Level**: [ENUM: Critical|High|Medium|Low] – [STRING: Revenue/reputation/compliance implications]
- **Scope**: [STRING: Number/percentage of affected systems or customer installations]

## Actions Required (By Team)

### Immediate Actions (Product Security Engineers)
1. **Technical Assessment** ([STRING: timeframe]): [STRING: Vulnerability validation, exploit analysis]
2. **System Inventory** ([STRING: timeframe]): [STRING: Identify affected systems, versions]

### Engineering Actions (Engineering Leads)
1. **Patch Implementation** ([STRING: timeframe]): [STRING: Exact patch version or config change]
2. **Testing Strategy** ([STRING: timeframe]): [STRING: Validation approach, rollback plan]
3. **Detection**: [STRING: Specific command or method to identify vulnerable systems]
4. **Verification**: [STRING: Exact steps to confirm patch/config was applied successfully]

### Business Actions (BU Security Champions & Product Teams)
1. **Stakeholder Communication** ([STRING: timeframe]): [STRING: Who to notify, key messages]
2. **Customer Impact Assessment** ([STRING: timeframe]): [STRING: Affected customers, communication plan]
3. **Release Planning** ([STRING: timeframe]): [STRING: Timeline adjustments, resource allocation]

## Patch Information (Engineering Focus)
- **Patch Status**: [ENUM: Available|In Development|No Fix Planned|Not specified]
- **Fixed Version(s)**: [STRING: Specific version numbers that resolve the issue or "Not specified"]
- **Patch Source**: [STRING: Direct URL to patch/update or vendor advisory or "Not specified"]
- **Release Notes**: [STRING: Link to changelog/release notes or "Not specified"]
- **Backport Status**: [STRING: Whether fixes are available for older supported versions or "Not specified"]
- **Deployment Complexity**: [ENUM: Simple update|Requires downtime|Complex migration|Not specified]

## Technical Details (Product Security Engineers)
- **Root Cause**: [STRING: Buffer overflow, logic flaw, injection, etc. or "Not specified"]
- **Trigger**: [STRING: How the vulnerability is activated or "Not specified"]
- **Prerequisites**: [STRING: Specific conditions needed to exploit or "Not specified"]
- **Exploit Reliability**: [ENUM: Consistent|Intermittent|PoC only|Not specified]
- **Mitigation Options**: [STRING: Workarounds if patch not immediately available]

## Risk Communication (BU Security Champions)
- **Customer Messaging**: [STRING: Key points for customer communication]
- **Stakeholder Summary**: [STRING: Executive-level risk explanation]
- **Compliance Considerations**: [STRING: Regulatory implications, audit requirements]
- **Media/Public Response**: [ENUM: Proactive statement needed|Reactive only|No public response needed]

## Missing Information & Impact
- [ARRAY: List of key unknowns that impact remediation decisions]
- **Business Impact of Gaps**: [STRING: How missing info affects business decisions]
- **Recommended Next Steps**: [STRING: Additional research, vendor engagement needed]

## Source Assessment (All Teams)
- **Quality**: [ENUM: High|Medium|Low] – [STRING: # authoritative sources vs community sources]
- **Agreement**: [ENUM: Complete|Partial conflicts|Major disputes]
- **Recency**: [DATE: Most recent source date YYYY-MM-DD or "Stale data"]
- **Vendor Response**: [ENUM: Official advisory issued|Vendor acknowledges|No vendor response|Not applicable]
- **Source Links Used**:
  - [STRING: URL or name of Source 1]
  - [STRING: URL or name of Source 2]
<!-- SCHEMA_VALIDATION_END -->

## Field Validation Rules

**All sections are REQUIRED** and must serve multiple audiences:

**Executive Summary** (NEW - for BU Champions/Product Teams):
- Business Risk: Must include customer/revenue/compliance impact
- Customer Communication: Must specify communication urgency
- Timeline Impact: Must address product/release implications

**Actions Required**: 
- Must be organized by team responsibility
- Each action must include specific timeframe and clear ownership
- Business actions must address communication and planning needs

**Risk Communication** (NEW - for BU Champions):
- Customer Messaging: Key points for external communication
- Stakeholder Summary: Executive-level explanation
- Compliance/Media considerations

**Multi-Audience Language Requirements**:
- Technical sections: Precise, actionable for engineers
- Business sections: Risk-focused, decision-enabling for BU champions
- All sections: Clear ownership and timelines for different teams

## Critical Constraints
🚫 **NEVER**:
- Fabricate CVSS scores, dates, version numbers, or technical details
- Use marketing language or threat vendor terminology
- Provide generic advice that doesn't help specific team decisions
- Skip audience-specific sections
- Make business risk assessments without technical foundation

✅ **ALWAYS**:
- Write "Not specified" for any missing data points
- Include specific business context for BU security champions
- Provide actionable technical details for engineering teams
- Address product timeline and customer impact concerns
- Balance technical accuracy with business clarity
- Specify which team owns each action item

## Confidence Calibration Guide
- **High**: 3+ authoritative sources in complete agreement + vendor confirmation
- **Medium**: 2+ sources with minor conflicts OR single authoritative source  
- **Low**: Single community source OR major conflicts between sources OR incomplete data

## Final Validation Before Submission
**Your output will be automatically validated against the schema. Ensure**:
1. Every required section serves its target audience
2. Business risk and customer impact are clearly articulated
3. Actions are organized by team with clear ownership
4. Technical details support business decision-making
5. BU security champions have stakeholder communication guidance
6. Product teams understand timeline and customer implications
7. Engineering teams have specific technical remediation steps
8. All audience needs are balanced without duplication

**Multi-audience success criteria**: Each team should be able to extract their specific action items and context without reading the entire brief.`;

// Prompt for conceptual taint analysis
export const CONCEPTUAL_TAINT_ANALYSIS_PROMPT = String.raw`**Prompt for RAG-Powered CVE Conceptual Taint Analysis**

"Perform a comprehensive conceptual taint analysis for the following CVE, as if you were an expert security analyst explaining it without direct code access. Focus on the *principles* of taint analysis rather than specific code lines, unless used for illustrative conceptual examples.  

**CVE ID:** [CVE_ID]

Please structure your analysis as follows:

**1. What is this potential vulnerability, conceptually?**
* Provide a high-level, easy-to-understand explanation of the vulnerability.
* Describe the core flaw and its potential impact.

**2. AI Taint Analysis**  
* Outline how AI-driven methods (e.g., retrieval-augmented generation) can help trace tainted data flow from sources through propagators to sinks.
* Explain how AI can highlight patterns or indicators that might not be obvious through manual inspection.

**3. Mapping to Relevant CVEs (Primary & Related):**
* Identify the primary CVE ID.
* List any directly related CVEs (such as subsequent fixes, bypasses, or similar vulnerabilities in the same component) and briefly explain their connection.

**4. Conceptual Taint Analysis Breakdown:**
* **Sources (Where Taint Begins):** Identify common conceptual entry points for attacker-controlled data that could lead to this vulnerability.
* **Propagators (How Taint Spreads):** Describe how tainted data can move through the system.
* **Sinks (Where Taint Becomes Dangerous):** Explain the points or functions where untrusted data can trigger the vulnerability, and why these are considered sinks.
* Provide a simple conceptual taint flow example using the identified sources, propagators, and sinks.

**5. Specific Remediation Suggestions (Conceptual & Actionable):**
* Detail the most effective mitigation steps at a conceptual level.
* Include any common strategies if a full patch isn’t immediately feasible, and the rationale behind them.

**6. Conceptual Code Example for Fix (Focus on Principle):**
* Describe in principle how a developer would prevent the taint from reaching the sink or how to neutralize it (e.g., input validation, parameterized functions, or disabling certain features).`;

export function buildConceptualTaintAnalysisPrompt(cveId: string): string {
  return CONCEPTUAL_TAINT_ANALYSIS_PROMPT.replace('[CVE_ID]', cveId);
}

// CVE Data Processing Functions
export function processCVEData(cveData: any) {
  console.log('processCVEData received:', JSON.stringify(cveData, null, 2));
  
  if (!cveData) {
    throw new Error('No CVE data provided');
  }
  
  // Handle both direct CVE object and nested structure
  const cve = cveData.cve || cveData;
  
  if (!cve || !cve.id) {
    console.error('Invalid CVE structure:', cve);
    throw new Error('Invalid CVE data structure - missing CVE ID');
  }
  
  // Extract description
  const descriptions = cve.descriptions || [];
  const description = descriptions.find((d: any) => d.lang === 'en')?.value || 'No description available';
  
  console.log(`Extracted description for ${cve.id}:`, description);
  
  // Extract CVSS scores
  const metrics = cve.metrics || {};
  const cvssV31 = metrics.cvssMetricV31?.[0]?.cvssData;
  const cvssV30 = metrics.cvssMetricV30?.[0]?.cvssData;
  const cvssV2 = metrics.cvssMetricV2?.[0]?.cvssData;
  
  // Use the most recent CVSS version available
  const cvssV3 = cvssV31 || cvssV30;
  
  const processedData = {
    id: cve.id,
    description,
    published: cve.published,
    lastModified: cve.lastModified,
    cvssV3: cvssV3 ? {
      baseScore: cvssV3.baseScore,
      baseSeverity: cvssV3.baseSeverity,
      vectorString: cvssV3.vectorString,
      version: cvssV3.version
    } : null,
    cvssV2: cvssV2 ? {
      baseScore: cvssV2.baseScore,
      baseSeverity: cvssV2.baseSeverity,
      vectorString: cvssV2.vectorString
    } : null,
    references: cve.references || [],
    configurations: cve.configurations || [],
    weaknesses: cve.weaknesses || [],
    sourceIdentifier: cve.sourceIdentifier,
    vulnStatus: cve.vulnStatus,
    evaluatorComment: cve.evaluatorComment,
    evaluatorSolution: cve.evaluatorSolution,
    evaluatorImpact: cve.evaluatorImpact,
    cisaExploitAdd: cve.cisaExploitAdd,
    cisaActionDue: cve.cisaActionDue,
    cisaRequiredAction: cve.cisaRequiredAction,
    cisaVulnerabilityName: cve.cisaVulnerabilityName,
    aiEnhanced: cve.aiParsed || false
  };
  
  console.log('Processed CVE data:', processedData);
  return processedData;
}

// Patch and Advisory Response Parsing
export function parsePatchAndAdvisoryResponse(response: any) {
  try {
    const patches = response.patches || [];
    const advisories = response.advisories || [];
    const searchSummary = response.searchSummary || {};
    
    return {
      patches: patches.map((patch: any) => ({
        vendor: patch.vendor || 'Unknown',
        product: patch.product || 'Unknown',
        patchVersion: patch.patchVersion || 'Not specified',
        downloadUrl: patch.downloadUrl || '',
        advisoryUrl: patch.advisoryUrl || '',
        citationUrl: patch.citationUrl || ''
      })),
      advisories: advisories.map((advisory: any) => ({
        source: advisory.source || 'Unknown',
        title: advisory.title || 'Unknown',
        url: advisory.url || '',
        vendor: advisory.vendor || 'Unknown',
        severity: advisory.severity || 'Unknown',
        patchAvailable: advisory.patchAvailable || false,
        citationUrl: advisory.citationUrl || ''
      })),
      searchSummary
    };
  } catch (error) {
    console.error('Error parsing patch and advisory response:', error);
    return { patches: [], advisories: [], searchSummary: {} };
  }
}

// Heuristic Patches and Advisories
export function getHeuristicPatchesAndAdvisories(cveId: string, cveData: any) {
  const heuristicData = {
    patches: [],
    advisories: [],
    searchSummary: {
      method: 'heuristic',
      confidence: 'low',
      note: 'Generated from CVE metadata when AI search fails'
    }
  };

  // Extract vendor information from CVE data if available
  if (cveData && cveData.descriptions) {
    const description = cveData.descriptions.find((d: any) => d.lang === 'en')?.value || '';
    
    // Simple heuristics to extract potential vendor/product information
    const vendorPatterns = [
      /\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+(?:version|v\.?\s*[\d.]+)/gi,
      /\b(Apache|Microsoft|Oracle|Google|Mozilla|Adobe|Cisco|VMware)\b/gi
    ];
    
    vendorPatterns.forEach(pattern => {
      const matches = description.match(pattern);
      if (matches) {
        matches.forEach(match => {
          heuristicData.advisories.push({
            source: 'heuristic',
            title: `${match} Security Advisory`,
            url: '',
            vendor: match,
            severity: 'Unknown',
            patchAvailable: false,
            citationUrl: ''
          });
        });
      }
    });
  }

  return heuristicData;
}

// AI Threat Intelligence Parsing
export function parseAIThreatIntelligence(response: any, cveId: string) {
  try {
    return {
      cisaKev: response.cisaKev || { listed: false },
      exploitDiscovery: response.exploitDiscovery || { found: false, exploits: [], totalCount: 0 },
      vendorAdvisories: response.vendorAdvisories || { found: false, advisories: [], count: 0 },
      activeExploitation: response.activeExploitation || { confirmed: false },
      technicalAnalysis: response.technicalAnalysis || {},
      threatIntelligence: response.threatIntelligence || {},
      intelligenceSummary: response.intelligenceSummary || {},
      summary: response.summary || `AI analysis for ${cveId}`,
      overallThreatLevel: response.overallThreatLevel || 'MEDIUM',
      hallucinationFlags: response.hallucinationFlags || [],
      extractionMetadata: response.extractionMetadata || {}
    };
  } catch (error) {
    console.error('Error parsing AI threat intelligence:', error);
    return {
      cisaKev: { listed: false },
      exploitDiscovery: { found: false, exploits: [], totalCount: 0 },
      vendorAdvisories: { found: false, advisories: [], count: 0 },
      activeExploitation: { confirmed: false },
      technicalAnalysis: {},
      threatIntelligence: {},
      intelligenceSummary: {},
      summary: `Failed to parse AI analysis for ${cveId}`,
      overallThreatLevel: 'MEDIUM',
      hallucinationFlags: ['parsing_error'],
      extractionMetadata: { error: 'Failed to parse response' }
    };
  }
}

// Heuristic Analysis
export function performHeuristicAnalysis(cveId: string, cveData: any, epssData: any) {
  const heuristicFindings = {
    cisaKev: { listed: false, aiDiscovered: false },
    exploitDiscovery: { found: false, exploits: [], totalCount: 0, githubRepos: 0 },
    vendorAdvisories: { found: false, advisories: [], count: 0 },
    activeExploitation: { confirmed: false },
    technicalAnalysis: {
      attackVector: 'Unknown',
      complexity: 'Unknown',
      impact: 'Unknown'
    },
    threatIntelligence: {},
    intelligenceSummary: {
      sourcesAnalyzed: 1,
      exploitsFound: 0,
      vendorAdvisoriesFound: 0,
      activeExploitation: false,
      cisaKevListed: false,
      threatLevel: 'MEDIUM',
      dataFreshness: 'HEURISTIC_FALLBACK',
      analysisMethod: 'HEURISTIC_FALLBACK',
      confidenceLevel: 'LOW',
      aiEnhanced: false,
      validated: false
    },
    summary: `Heuristic analysis for ${cveId} - limited data available`,
    overallThreatLevel: 'MEDIUM',
    hallucinationFlags: [],
    extractionMetadata: {
      method: 'heuristic',
      timestamp: new Date().toISOString(),
      note: 'Fallback analysis when AI services are unavailable'
    }
  };

  // Use EPSS score to influence threat level if available
  if (epssData && epssData.epss) {
    const epssScore = parseFloat(epssData.epss);
    if (epssScore > 0.7) {
      heuristicFindings.overallThreatLevel = 'HIGH';
      heuristicFindings.intelligenceSummary.threatLevel = 'HIGH';
    } else if (epssScore > 0.3) {
      heuristicFindings.overallThreatLevel = 'MEDIUM';
    } else {
      heuristicFindings.overallThreatLevel = 'LOW';
      heuristicFindings.intelligenceSummary.threatLevel = 'LOW';
    }
  }

  return heuristicFindings;
}

// Enhanced Analysis Prompt Builder
export function buildEnhancedAnalysisPrompt(vulnerability: any, settings: any = {}) {
  console.log('buildEnhancedAnalysisPrompt called with vulnerability:', vulnerability);
  
  // Handle both nested structure (vulnerability.cve) and flat structure
  const cveData = vulnerability.cve || vulnerability;
  const cveId = cveData.id || 'Unknown';
  
  // Extract description
  const descriptions = cveData.descriptions || [];
  const description = descriptions.find((d: any) => d.lang === 'en')?.value || 'No description available';
  
  // Extract CVSS data
  const metrics = cveData.metrics || {};
  const cvssV31 = metrics.cvssMetricV31?.[0]?.cvssData;
  const cvssData = cvssV31 || {};
  
  console.log('Extracted CVE data for prompt:');
  console.log('- CVE ID:', cveId);
  console.log('- Description:', description);
  console.log('- CVSS Score:', cvssData.baseScore);
  console.log('- Attack Vector:', cvssData.attackVector);
  console.log('- Base Severity:', cvssData.baseSeverity);
  
  const prompt = `${TECHNICAL_BRIEF_PROMPT}

## Analysis Request

CVE ID: ${cveId}
Context Sources:
<context_chunk_1>
CVE Description: ${description}
CVSS Score: ${cvssData.baseScore || 'Not available'}
Base Severity: ${cvssData.baseSeverity || 'Not available'}
Attack Vector: ${cvssData.attackVector || 'Not available'}
Attack Complexity: ${cvssData.attackComplexity || 'Not available'}
Privileges Required: ${cvssData.privilegesRequired || 'Not available'}
User Interaction: ${cvssData.userInteraction || 'Not available'}
Scope: ${cvssData.scope || 'Not available'}
Confidentiality Impact: ${cvssData.confidentialityImpact || 'Not available'}
Integrity Impact: ${cvssData.integrityImpact || 'Not available'}
Availability Impact: ${cvssData.availabilityImpact || 'Not available'}
Published Date: ${cveData.published || 'Not available'}
Last Modified: ${cveData.lastModified || 'Not available'}
Vulnerability Status: ${cveData.vulnStatus || 'Not available'}
References: ${JSON.stringify(cveData.references || [])}
Weaknesses (CWE): ${JSON.stringify(cveData.weaknesses || [])}
${cveData.aiEnhanced ? 'Data Source: AI-Enhanced via Web Search' : 'Data Source: Direct API'}
</context_chunk_1>

${vulnerability.epss ? `<context_chunk_2>
EPSS Data:
Exploitation Probability Score: ${vulnerability.epss.epss || 'Not available'}
Percentile: ${vulnerability.epss.percentile || 'Not available'}
Date: ${vulnerability.epss.date || 'Not available'}
${vulnerability.epss.aiParsed ? 'EPSS Source: AI-Enhanced via Web Search' : 'EPSS Source: Direct API'}
</context_chunk_2>` : ''}

${vulnerability.cisaKev ? `<context_chunk_3>
CISA KEV (Known Exploited Vulnerabilities) Data:
Listed in CISA KEV: ${vulnerability.cisaKev.listed ? 'YES - ACTIVELY EXPLOITED' : 'NO'}
${vulnerability.cisaKev.listed ? `Date Added to KEV: ${vulnerability.cisaKev.dateAdded || 'Not available'}
Short Description: ${vulnerability.cisaKev.shortDescription || 'Not available'}
Required Action: ${vulnerability.cisaKev.requiredAction || 'Not available'}
Due Date: ${vulnerability.cisaKev.dueDate || 'Not available'}
Known Ransomware Campaign Use: ${vulnerability.cisaKev.knownRansomwareCampaignUse || 'Unknown'}
Vendor/Project: ${vulnerability.cisaKev.vendorProject || 'Not available'}
Product: ${vulnerability.cisaKev.product || 'Not available'}
Vulnerability Name: ${vulnerability.cisaKev.vulnerabilityName || 'Not available'}` : `Last Checked: ${vulnerability.cisaKev.lastChecked || 'Not available'}`}
KEV Catalog Version: ${vulnerability.cisaKev.catalogVersion || 'Not available'}
KEV Catalog Date: ${vulnerability.cisaKev.catalogDate || 'Not available'}
${vulnerability.cisaKev.source === 'ai-web-search' ? 'KEV Source: AI-Enhanced via Web Search' : 'KEV Source: Direct API/Cache'}
</context_chunk_3>` : ''}

Please generate a comprehensive technical brief following the exact schema requirements. Use ONLY the information provided above - do not fabricate any details not explicitly stated.

IMPORTANT: If this CVE is listed in CISA KEV, this indicates ACTIVE EXPLOITATION in the wild and should significantly impact priority and business risk assessment.

NOTE: Some data may have been enhanced via AI web search when direct APIs were unavailable. This is indicated in the source annotations above.`;

  console.log('Generated AI prompt length:', prompt.length);
  console.log('AI prompt preview (first 500 chars):', prompt.substring(0, 500) + '...');
  return prompt;
}

// Enhanced Fallback Analysis
export function generateEnhancedFallbackAnalysis(vulnerability: any) {
  const cveId = vulnerability.cve?.id || 'Unknown';
  const baseScore = vulnerability.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore;
  const epssScore = vulnerability.epss?.epss;
  
  let priority = 'P3';
  let threatLevel = 'LOW';
  
  if (baseScore >= 9.0 || epssScore >= 0.7) {
    priority = 'P1';
    threatLevel = 'HIGH';
  } else if (baseScore >= 7.0 || epssScore >= 0.3) {
    priority = 'P2';
    threatLevel = 'MEDIUM';
  }
  
  return `# ${cveId} Technical Brief

**Status**: Not specified (Released: Not specified)
**Priority**: ${priority} – Review and assess within standard cycle
**Confidence**: Low – Limited automated analysis, manual review required

## Core Facts
- **Component**: Not specified
- **Attack Vector**: Not specified + Auth Required: Not specified
- **Exploitation**: Not specified
- **Exploit Published**: Not specified
- **Real-world Usage**: Active attacks: Not specified | CISA KEV: N
- **Complexity**: Not specified skill required

## Business Impact
- **Technical Effect**: Not specified
- **Realistic Scenario**: Manual analysis required to determine impact
- **Scope**: Not specified

## Actions Required
1. **Immediate** (Within 24h): Manual review of CVE details and affected systems
2. **Short-term** (Within 1 week): Determine applicability and remediation strategy
3. **Detection**: Review system inventory for affected components
4. **Verification**: Confirm remediation steps after manual analysis

## Patch Information
- **Patch Status**: Not specified
- **Fixed Version(s)**: Not specified
- **Patch Source**: Not specified
- **Release Notes**: Not specified
- **Backport Status**: Not specified

## Technical Details
- **Root Cause**: Not specified
- **Trigger**: Not specified
- **Prerequisites**: Not specified
- **Exploit Reliability**: Not specified

## Missing Information
- All technical details require manual analysis
- Impact assessment needed
- Patch availability unknown

## Source Assessment
- **Quality**: Low – Automated analysis only
- **Agreement**: Not applicable
- **Recency**: ${new Date().toISOString().split('T')[0]}
- **Source Links Used**:
  - Basic CVE metadata only`;
}

// Finding Formatting with Confidence
export function formatFindingWithConfidence(finding: any, confidence: string, validation: any) {
  const confidenceIcon = getConfidenceIcon(confidence);
  const verificationBadge = getVerificationBadge(validation);
  
  return `${confidenceIcon} ${finding} ${verificationBadge}`;
}

// Confidence Icon Helper
export function getConfidenceIcon(confidence: string): string {
  switch (confidence?.toUpperCase()) {
    case 'HIGH': return '🟢';
    case 'MEDIUM': return '🟡';
    case 'LOW': return '🟠';
    default: return '⚪';
  }
}

// Verification Badge Helper
export function getVerificationBadge(validation: any): string {
  if (validation?.verified === true) {
    return '✅ Verified';
  } else if (validation?.verified === false) {
    return '❌ Unverified';
  }
  return '⏳ Pending';
}

// User Warning Generator
export function generateUserWarning(confidence: string, validation: any): string {
  if (confidence === 'LOW' || validation?.verified === false) {
    return '⚠️ This information has low confidence or failed verification. Manual review recommended.';
  }
  return '';
}

// AI Data Disclaimer
export function createAIDataDisclaimer(vulnerability: any): string {
  const aiGeneratedCount = countAIGeneratedFindings(vulnerability);
  const verifiedCount = countVerifiedFindings(vulnerability.validation || {});

  return `📊 Analysis Summary: ${aiGeneratedCount} AI-generated findings, ${verifiedCount} verified. AI is prone to mistakes, so validate the evidence before taking action.`;
}

// Count AI Generated Findings
export function countAIGeneratedFindings(vulnerability: any): number {
  let count = 0;
  
  if (vulnerability.exploits?.found) count++;
  if (vulnerability.vendorAdvisories?.found) count++;
  if (vulnerability.kev?.listed && vulnerability.kev?.aiDiscovered) count++;
  if (vulnerability.patches?.length > 0) count += vulnerability.patches.length;
  if (vulnerability.advisories?.length > 0) count += vulnerability.advisories.length;
  
  return count;
}

// Count Verified Findings
export function countVerifiedFindings(validation: any): number {
  let count = 0;
  
  if (validation.cisaKev?.verified) count++;
  if (validation.exploits?.verified) count++;
  if (validation.vendorAdvisories?.verified) count++;
  if (validation.vendorConfirmation?.patches?.length > 0) count += validation.vendorConfirmation.patches.length;
  if (validation.vendorConfirmation?.advisories?.length > 0) count += validation.vendorConfirmation.advisories.length;
  
  return count;
}

// Re-export functions from DataFetchingService for backward compatibility
export { searchCISAKEVWithAI } from './DataFetchingService';
