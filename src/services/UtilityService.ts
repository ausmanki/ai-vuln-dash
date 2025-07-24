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
        let errorDetail = response.statusText;
        try {
          const text = await response.text();
          if (text) {
            try {
              const data = JSON.parse(text);
              if (data.error?.message) {
                errorDetail = data.error.message;
              } else {
                errorDetail = text;
              }
            } catch {
              errorDetail = text;
            }
          }
        } catch {
          // ignore
        }
        throw new Error(`HTTP ${response.status}: ${errorDetail}`);
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

// Enhanced Analysis Prompt Builder - More Informative and Comprehensive
export function buildEnhancedAnalysisPrompt(vulnerability: any, settings: any = {}) {
  console.log('buildEnhancedAnalysisPrompt called with vulnerability:', vulnerability);
  
  // Handle both nested structure (vulnerability.cve) and flat structure
  const cveData = vulnerability.cve || vulnerability;
  const cveId = cveData.id || 'Unknown';
  
  // Extract all available data
  const description = extractDescription(cveData);
  const cvssInfo = extractCVSSInfo(cveData);
  const epssInfo = extractEPSSInfo(vulnerability);
  const kevInfo = extractKEVInfo(vulnerability);
  const exploitInfo = extractExploitInfo(vulnerability);
  const patchInfo = extractPatchInfo(vulnerability);
  const referenceInfo = extractReferenceInfo(cveData);
  const weaknessInfo = extractWeaknessInfo(cveData);
  const vendorInfo = extractVendorProductInfo(description);
  
  // Calculate risk context
  const riskContext = calculateRiskContext(cvssInfo, epssInfo, kevInfo, exploitInfo);
  
  // Extract detailed patch and advisory information
  const detailedPatches = vulnerability.patches?.map((p: any) => ({
    vendor: p.vendor,
    product: p.product,
    version: p.patchVersion,
    downloadUrl: p.downloadUrl,
    advisoryUrl: p.advisoryUrl
  })) || [];
  
  const detailedAdvisories = vulnerability.advisories?.map((a: any) => ({
    source: a.source,
    title: a.title,
    url: a.url,
    severity: a.severity,
    patchAvailable: a.patchAvailable
  })) || [];
  
  // Determine priority based on available data
  const suggestedPriority = determinePriority(kevInfo, cvssInfo, epssInfo, exploitInfo);
  const suggestedStatus = determineStatus(detailedPatches, detailedAdvisories);
  const suggestedConfidence = determineConfidence(vulnerability);
  
  // Build comprehensive prompt
  const prompt = `You are a senior security engineer preparing a comprehensive technical brief for ${cveId}. 

## CRITICAL DATA SUMMARY
- **CVE**: ${cveId}
- **CVSS Score**: ${cvssInfo.score} (${cvssInfo.severity})
- **EPSS**: ${epssInfo.score} (${epssInfo.percentile} percentile)
- **CISA KEV**: ${kevInfo.listed ? 'YES - ACTIVELY EXPLOITED' : 'No'}
- **Public Exploits**: ${exploitInfo.found ? 'YES' : 'No'}
- **Patches Available**: ${detailedPatches.length > 0 ? 'YES' : 'No'}

## 📊 VULNERABILITY OVERVIEW

**CVE ID**: ${cveId}
**Description**: ${description}
**Affected Component**: ${vendorInfo.vendor} ${vendorInfo.product} ${vendorInfo.versions}

## 🎯 THREAT INTELLIGENCE

**CVSS v3 Metrics**:
- Base Score: ${cvssInfo.score} (${cvssInfo.severity})
- Vector: ${cvssInfo.vectorString || 'Not available'}
- Attack Vector: ${cvssInfo.attackVector} | Complexity: ${cvssInfo.attackComplexity}
- Privileges: ${cvssInfo.privilegesRequired} | User Interaction: ${cvssInfo.userInteraction}
- Impact: C:${cvssInfo.confidentialityImpact}/I:${cvssInfo.integrityImpact}/A:${cvssInfo.availabilityImpact}

**Exploitation Probability (EPSS)**:
- Score: ${epssInfo.score} (${epssInfo.percentile} percentile)
- Risk Level: ${epssInfo.riskLevel}
- Context: ${epssInfo.context}

**Active Exploitation Status**:
${kevInfo.summary}
${exploitInfo.summary}

**Weakness Classification**:
${weaknessInfo}

## 🔧 PATCHES AND FIXES

**Available Patches**:
${patchInfo.summary}

${detailedPatches.length > 0 ? `**Detailed Patch Information**:
${detailedPatches.map((p: any) => `
- **${p.vendor} ${p.product}**
  - Fixed Version: ${p.version}
  - Download: ${p.downloadUrl}
  - Advisory: ${p.advisoryUrl}`).join('\n')}` : 'No specific patch information available'}

## 📢 SECURITY ADVISORIES

**Published Advisories**:
${patchInfo.advisories}

${detailedAdvisories.length > 0 ? `**Detailed Advisory Information**:
${detailedAdvisories.map((a: any) => `
- **${a.source}**: ${a.title}
  - URL: ${a.url}
  - Severity: ${a.severity}
  - Patch Available: ${a.patchAvailable ? 'Yes' : 'No'}`).join('\n')}` : 'No advisory information available'}

## 🔗 ADDITIONAL REFERENCES

**Official Resources**:
- [NVD Entry](https://nvd.nist.gov/vuln/detail/${cveId})
- [MITRE CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId})
${kevInfo.listed ? `- [CISA KEV Entry](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)` : ''}

**Additional References**:
${referenceInfo}

## 📋 YOUR TECHNICAL BRIEF REQUIREMENTS

Create a comprehensive technical brief following this EXACT format:

### CVE Analysis - Quick Summary

**Status**: ${suggestedStatus}
**Priority**: ${suggestedPriority}  
**Confidence**: ${suggestedConfidence}

### 1. Executive Summary
${kevInfo.listed ? '🚨 **CRITICAL: This vulnerability is actively exploited in the wild and listed in CISA KEV.**\n\n' : ''}
- Start with the most critical finding
- Explain the business impact of ${cveId} in plain language
- State the recommended action and timeline clearly
- Mention patch availability: ${detailedPatches.length > 0 ? 'Patches are available from ' + detailedPatches.map(p => p.vendor).join(', ') : 'No patches available yet'}
- Include customer impact assessment

### 2. Technical Analysis
Provide deep technical insights for ${cveId}:
- **Attack Scenario**: Step-by-step how THIS SPECIFIC vulnerability (${cveId}) could be exploited based on the description
- **Attack Surface**: What specific ${vendorInfo.product} systems/configurations are vulnerable
- **Indicators of Compromise (IoCs)**: What to look for in logs/systems for ${cveId}
- **Attack Complexity Analysis**: Real-world difficulty of exploiting ${cveId}

### 3. CVE-Specific Remediation

**PATCHES AND UPDATES for ${cveId}**:
${detailedPatches.length > 0 ? `Apply these specific patches:
${detailedPatches.map((p: any) => `
- For ${p.vendor} ${p.product}: Upgrade to version ${p.version}
  - Download from: [${p.vendor} Patch](${p.downloadUrl})
  - Review advisory: [Security Advisory](${p.advisoryUrl})`).join('\n')}` : 'No patches available yet - implement workarounds below'}

**VENDOR ADVISORIES for ${cveId}**:
${detailedAdvisories.length > 0 ? `Follow guidance from these advisories:
${detailedAdvisories.map((a: any) => `
- [${a.source} Advisory: ${a.title}](${a.url})
  - Severity: ${a.severity}
  - Extract specific recommendations from this advisory`).join('\n')}` : 'Monitor vendor security pages for updates'}

**Immediate Actions for ${cveId}**:
- Affected versions: ${vendorInfo.versions}
- Fixed versions: ${detailedPatches.length > 0 ? detailedPatches.map(p => p.version).join(', ') : 'Not yet available'}
- Specific configuration changes for ${cveId}
- Vendor-specific guidance

**Detection Commands** (specific to ${cveId}):
\`\`\`bash
# Commands to detect ${cveId} vulnerability in ${vendorInfo.product}
# Version detection commands
# Configuration checks
\`\`\`

**Patch Verification** (for ${cveId}):
\`\`\`bash
# Commands to verify ${cveId} patches are applied
# Version verification for ${vendorInfo.product}
\`\`\`

### 4. Actionable Recommendations

**For Security Teams**:
- Implement detection for ${cveId} using the IoCs above
- Review security advisories: ${detailedAdvisories.map(a => `[${a.source}](${a.url})`).join(', ')}
- Monitor for ${cveId} exploitation attempts

**For Engineering Teams**:
- ${vendorInfo.product} versions affected: ${vendorInfo.versions}
- Patch to: ${detailedPatches.length > 0 ? detailedPatches.map(p => `${p.product} ${p.version}`).join(', ') : 'Awaiting vendor patch'}
- Testing recommendations for ${cveId} fixes

**For Leadership**:
- ${kevInfo.listed ? 'URGENT: Active exploitation confirmed by CISA' : 'No active exploitation reported'}
- Customer communication needed: ${kevInfo.listed || cvssInfo.score >= 7.0 ? 'Yes - proactive notification' : 'Standard update cycle'}
- Patch status: ${detailedPatches.length > 0 ? 'Available now' : 'Pending vendor release'}

### 5. Detailed Mitigation Guidance

Based on ${cveId} specifics:
- **Primary Mitigation**: ${detailedPatches.length > 0 ? 'Apply patches: ' + detailedPatches.map(p => `${p.product} ${p.version}`).join(', ') : 'Patches pending - use workarounds'}
- **Temporary Workarounds**: [Extract from advisories or description]
- **Compensating Controls**: Based on ${cvssInfo.attackVector} attack vector
- **Verification Steps**: Confirm ${cveId} is remediated

### 6. Advisory-Based Timeline
${kevInfo.listed ? '- 🚨 **CISA KEV LISTED**: Remediate within 24-48 hours per CISA directive' : ''}
${cvssInfo.score >= 9.0 ? '- ⚠️ **CRITICAL SEVERITY**: Remediate within 72 hours' : ''}
${cvssInfo.score >= 7.0 && cvssInfo.score < 9.0 ? '- ⚠️ **HIGH SEVERITY**: Remediate within 1 week' : ''}
${epssInfo.score > 0.5 ? '- 📊 **HIGH EXPLOITATION PROBABILITY**: Prioritize in current cycle' : ''}
${detailedPatches.length > 0 ? '- ✅ **PATCHES AVAILABLE**: Apply immediately' : '- ⏳ **NO PATCHES YET**: Implement workarounds now'}

### 7. Knowledge Gaps & Next Steps
- ${detailedPatches.length === 0 ? 'Awaiting patches from: ' + vendorInfo.vendor : 'Verify all systems patched'}
- ${detailedAdvisories.length === 0 ? 'No vendor advisories yet published' : 'Review all advisories for updates'}
- Additional research needed for ${cveId}

## 📝 CRITICAL INSTRUCTIONS

- **Make all recommendations specific to ${cveId}**
- Use the exact version numbers from patches: ${detailedPatches.map(p => p.version).join(', ')}
- Reference the specific advisories provided
- Include the actual vulnerability behavior from the description
- Format all URLs as clickable markdown links
- Don't use generic security advice - tie everything to ${cveId}

Remember: This is about ${cveId} specifically. Use the CVE ID throughout your response.`;

  console.log('Generated enhanced prompt with CVE-specific focus and proper status determination');
  return prompt;
}

// Helper function to determine priority based on risk factors
function determinePriority(kevInfo: any, cvssInfo: any, epssInfo: any, exploitInfo: any): string {
  if (kevInfo.listed) {
    return 'P0 – Emergency response required (24-48 hours)';
  }
  if (cvssInfo.score >= 9.0 || (exploitInfo.found && cvssInfo.score >= 7.0)) {
    return 'P1 – Critical priority (72 hours)';
  }
  if (cvssInfo.score >= 7.0 || epssInfo.score > 0.5) {
    return 'P2 – High priority (1 week)';
  }
  return 'P3 – Standard priority (30 days)';
}

// Helper function to determine status based on patches
function determineStatus(patches: any[], advisories: any[]): string {
  if (patches.length > 0) {
    return 'Patch Available';
  }
  if (advisories.some((a: any) => a.patchAvailable)) {
    return 'Patch Available';
  }
  if (advisories.length > 0) {
    return 'In Progress';
  }
  return 'No Fix';
}

// Helper function to determine confidence level
function determineConfidence(vulnerability: any): string {
  let confidenceFactors = 0;
  
  if (vulnerability.cve?.id) confidenceFactors++;
  if (vulnerability.cve?.metrics?.cvssMetricV31?.[0]) confidenceFactors++;
  if (vulnerability.epss) confidenceFactors++;
  if (vulnerability.patches?.length > 0) confidenceFactors++;
  if (vulnerability.advisories?.length > 0) confidenceFactors++;
  if (vulnerability.kev || vulnerability.cisaKev) confidenceFactors++;
  
  if (confidenceFactors >= 5) {
    return 'High – Multiple authoritative sources';
  } else if (confidenceFactors >= 3) {
    return 'Medium – Good source coverage';
  } else {
    return 'Low – Limited data available';
  }
}

// Helper function to extract comprehensive CVSS information
function extractCVSSInfo(cveData: any): any {
  let cvssData: any = {};
  let cvssScore = 'Not available';
  let baseSeverity = 'Not available';
  let vectorString = 'Not available';
  
  if (cveData.cvssV3) {
    cvssData = cveData.cvssV3;
  } else if (cveData.metrics) {
    const metrics = cveData.metrics || {};
    const cvssV31 = metrics.cvssMetricV31?.[0]?.cvssData;
    const cvssV30 = metrics.cvssMetricV30?.[0]?.cvssData;
    cvssData = cvssV31 || cvssV30 || {};
  }
  
  cvssScore = cvssData.baseScore || 'Not available';
  baseSeverity = cvssData.baseSeverity || 'Not available';

  if (baseSeverity === 'Not available' && cvssScore !== 'Not available') {
    const scoreNum = parseFloat(cvssScore);
    if (!isNaN(scoreNum)) {
      if (scoreNum >= 9.0) baseSeverity = 'CRITICAL';
      else if (scoreNum >= 7.0) baseSeverity = 'HIGH';
      else if (scoreNum >= 4.0) baseSeverity = 'MEDIUM';
      else baseSeverity = 'LOW';
    }
  }

  return {
    score: cvssScore,
    severity: baseSeverity,
    vectorString: cvssData.vectorString || 'Not available',
    attackVector: cvssData.attackVector || 'Unknown',
    attackComplexity: cvssData.attackComplexity || 'Unknown',
    privilegesRequired: cvssData.privilegesRequired || 'Unknown',
    userInteraction: cvssData.userInteraction || 'Unknown',
    scope: cvssData.scope || 'Unknown',
    confidentialityImpact: cvssData.confidentialityImpact || 'Unknown',
    integrityImpact: cvssData.integrityImpact || 'Unknown',
    availabilityImpact: cvssData.availabilityImpact || 'Unknown'
  };
}

// Helper function to extract EPSS information with context
function extractEPSSInfo(vulnerability: any): any {
  if (!vulnerability.epss) {
    return {
      score: 'Not available',
      percentile: 'Not available',
      riskLevel: 'Unknown',
      context: 'No EPSS data available'
    };
  }
  
  const score = parseFloat(vulnerability.epss.epss) || 0;
  let riskLevel = 'Very Low';
  let context = '';
  
  if (score >= 0.7) {
    riskLevel = 'Very High';
    context = 'This vulnerability is in the top tier for exploitation probability. Immediate action recommended.';
  } else if (score >= 0.5) {
    riskLevel = 'High';
    context = 'Significantly elevated risk of exploitation. Prioritize patching within days.';
  } else if (score >= 0.3) {
    riskLevel = 'Moderate';
    context = 'Above average exploitation probability. Include in next patching cycle.';
  } else if (score >= 0.1) {
    riskLevel = 'Low';
    context = 'Below average exploitation probability. Standard patching timeline appropriate.';
  } else {
    riskLevel = 'Very Low';
    context = 'Minimal exploitation probability based on current threat landscape.';
  }
  
  return {
    score: vulnerability.epss.epss || 'Not available',
    percentile: vulnerability.epss.percentile || 'Not available',
    riskLevel,
    context
  };
}

// Helper function to extract KEV information
function extractKEVInfo(vulnerability: any): any {
  const isListed = vulnerability.kev?.listed || vulnerability.cisaKev?.listed;
  
  if (!isListed) {
    return {
      listed: false,
      summary: '✅ Not in CISA KEV - No confirmed active exploitation'
    };
  }
  
  return {
    listed: true,
    summary: `🚨 **CRITICAL: Active Exploitation Confirmed**
- Listed in CISA Known Exploited Vulnerabilities catalog
- Required Action: ${vulnerability.kev?.requiredAction || vulnerability.cisaKev?.requiredAction || 'Patch immediately'}
- Due Date: ${vulnerability.kev?.dueDate || vulnerability.cisaKev?.dueDate || 'ASAP'}
- ${vulnerability.kev?.shortDescription || vulnerability.cisaKev?.shortDescription || ''}`
  };
}

// Helper function to extract exploit information
function extractExploitInfo(vulnerability: any): any {
  if (!vulnerability.exploits?.found) {
    return {
      found: false,
      summary: '✅ No public exploits found'
    };
  }
  
  const count = vulnerability.exploits.totalCount || vulnerability.exploits.count || 0;
  const verified = vulnerability.exploits.verifiedCount || 0;
  
  return {
    found: true,
    summary: `⚠️ **Public Exploits Available**
- Total exploits found: ${count}
- Verified exploits: ${verified}
- Source: ${vulnerability.exploits.aiDiscovered ? 'AI-Enhanced Discovery' : 'Direct Search'}
- Implication: Weaponized exploits may be in circulation`
  };
}

// Helper function to extract patch information
function extractPatchInfo(vulnerability: any): any {
  const patches = vulnerability.patches || [];
  const advisories = vulnerability.advisories || [];
  
  let patchSummary = 'No patches found';
  let advisorySummary = 'No advisories found';
  
  if (patches.length > 0) {
    patchSummary = patches.map((p: any) => 
      `- ${p.vendor || 'Unknown'} ${p.product || ''}: [${p.patchVersion || 'Patch Available'}](${p.downloadUrl || p.advisoryUrl || '#'})`
    ).join('\n');
  }
  
  if (advisories.length > 0) {
    advisorySummary = advisories.map((a: any) => 
      `- [${a.title || a.source || 'Advisory'}](${a.url || '#'}) - ${a.severity || 'Severity unknown'}`
    ).join('\n');
  }
  
  return {
    summary: patchSummary,
    advisories: advisorySummary
  };
}

// Helper function to extract reference information
function extractReferenceInfo(cveData: any): string {
  const references = cveData.references || [];
  
  if (references.length === 0) {
    return 'No additional references available';
  }
  
  // Group references by type/source
  const grouped = references.reduce((acc: any, ref: any) => {
    const source = ref.source || 'Other';
    if (!acc[source]) acc[source] = [];
    acc[source].push(ref);
    return acc;
  }, {});
  
  return Object.entries(grouped).map(([source, refs]: [string, any]) => {
    const refList = refs.map((ref: any) => `  - [${source} Reference](${ref.url})`).join('\n');
    return `**${source}**:\n${refList}`;
  }).join('\n\n');
}

// Helper function to extract weakness information
function extractWeaknessInfo(cveData: any): string {
  const weaknesses = cveData.weaknesses || [];
  
  if (weaknesses.length === 0) {
    return 'No CWE classification available';
  }
  
  return weaknesses.map((w: any) => {
    const cweId = w.source?.find((s: any) => s.type === 'Primary')?.cweId || 'Unknown';
    const description = w.description?.find((d: any) => d.lang === 'en')?.value || '';
    return `- ${cweId}: ${description}`;
  }).join('\n');
}

// Helper function to extract vendor/product information
function extractVendorProductInfo(description: string): any {
  let vendor = 'Unknown';
  let product = 'Unknown';
  let versions = 'Unknown';
  
  // Common patterns to extract vendor/product
  const patterns = [
    { pattern: /Apache\s+Tomcat\s+([\d.]+(?:\s*(?:through|to|-)\s*[\d.]+)?)/i, vendor: 'Apache', product: 'Tomcat' },
    { pattern: /Apache\s+HTTP\s+Server\s+([\d.]+(?:\s*(?:through|to|-)\s*[\d.]+)?)/i, vendor: 'Apache', product: 'HTTP Server' },
    { pattern: /Microsoft\s+Windows\s+([\w\s]+)/i, vendor: 'Microsoft', product: 'Windows' },
    { pattern: /Oracle\s+Java\s+([\d.]+)/i, vendor: 'Oracle', product: 'Java' },
    { pattern: /Google\s+Chrome\s+([\d.]+)/i, vendor: 'Google', product: 'Chrome' },
    { pattern: /Mozilla\s+Firefox\s+([\d.]+)/i, vendor: 'Mozilla', product: 'Firefox' }
  ];
  
  for (const { pattern, vendor: v, product: p } of patterns) {
    const match = description.match(pattern);
    if (match) {
      vendor = v;
      product = p;
      versions = match[1] || 'Unknown';
      break;
    }
  }
  
  return { vendor, product, versions };
}

// Helper function to calculate risk context
function calculateRiskContext(cvssInfo: any, epssInfo: any, kevInfo: any, exploitInfo: any): string {
  const factors = [];
  
  if (kevInfo.listed) {
    factors.push('🚨 **ACTIVE EXPLOITATION CONFIRMED** (CISA KEV)');
  }
  
  if (cvssInfo.score >= 9.0) {
    factors.push('⚠️ **CRITICAL SEVERITY** (CVSS 9.0+)');
  } else if (cvssInfo.score >= 7.0) {
    factors.push('⚠️ **HIGH SEVERITY** (CVSS 7.0+)');
  }
  
  if (epssInfo.score >= 0.5) {
    factors.push('📊 **HIGH EXPLOITATION PROBABILITY** (EPSS 50%+)');
  }
  
  if (exploitInfo.found) {
    factors.push('💣 **PUBLIC EXPLOITS AVAILABLE**');
  }
  
  if (cvssInfo.attackVector === 'NETWORK' && cvssInfo.privilegesRequired === 'NONE') {
    factors.push('🌐 **REMOTELY EXPLOITABLE WITHOUT AUTH**');
  }
  
  return factors.length > 0 ? 
    `**Risk Factors**:\n${factors.join('\n')}\n` : 
    'Standard risk profile - no exceptional risk factors identified';
}

// Alternative: Even more conversational prompt
export function buildConversationalAnalysisPrompt(vulnerability: any, settings: any = {}) {
  const cveData = vulnerability.cve || vulnerability;
  const cveId = cveData.id || 'Unknown';
  
  // Extract key data
  let description = extractDescription(cveData);
  let cvssScore = extractCVSSScore(cveData);
  let isActivelyExploited = (vulnerability.kev?.listed || vulnerability.cisaKev?.listed);
  let epssScore = vulnerability.epss?.epss;
  
  // Extract references and patches
  const references = cveData.references || [];
  const hasReferences = references.length > 0;
  const hasPatches = vulnerability.patches?.length > 0;
  const hasAdvisories = vulnerability.advisories?.length > 0;
  
  const prompt = `Hey, I need your help analyzing ${cveId} for our teams.

Here's the situation:
${description}

Key facts:
- Severity: ${cvssScore.score} CVSS (${cvssScore.severity})
- Exploitation probability: ${epssScore || 'unknown'} EPSS
${isActivelyExploited ? '- ⚠️ ACTIVELY EXPLOITED (in CISA KEV)' : '- Not currently in CISA KEV'}
${hasReferences ? `- We have ${references.length} reference links available` : ''}
${hasPatches ? `- Patches are available` : ''}
${hasAdvisories ? `- Security advisories exist` : ''}

Can you break this down for me? I need to brief:
1. Leadership (business impact, customer risk)
2. Engineering (what to patch, how urgent)
3. Security team (detection, verification)

Just talk me through it like we're having a conversation. What matters most here? What should each team do first?

**Important**: Please format all URLs as clickable markdown links [like this](url) so people can easily access them. Include links to:
- The NVD page: https://nvd.nist.gov/vuln/detail/${cveId}
- Any patches or advisories mentioned
- Reference URLs if they're helpful

If anything's unclear from the data, just tell me what we're missing. Keep it real and practical.`;

  return prompt;
}

// Helper function to extract description
function extractDescription(cveData: any): string {
  let description = 'No description available';
  
  if (cveData.aiResponse) {
    const aiResponseMatch = cveData.aiResponse.match(/Complete CVE Description:\*?\*?\s*([^*\n]+(?:\n(?!\d\.|##)[^\n]+)*)/i);
    if (aiResponseMatch && aiResponseMatch[1]) {
      description = aiResponseMatch[1].trim();
    } else if (cveData.aiResponse.includes('vulnerability')) {
      description = cveData.aiResponse;
    }
  } else if (cveData.description && typeof cveData.description === 'string') {
    description = cveData.description;
  } else if (cveData.descriptions) {
    const descriptions = cveData.descriptions || [];
    description = descriptions.find((d: any) => d.lang === 'en')?.value || 'No description available';
  }
  
  return description.replace(/\*\*/g, '').replace(/^\s*-\s*/, '').trim();
}

// Helper function to extract CVSS score
function extractCVSSScore(cveData: any): { score: string, severity: string } {
  let cvssData: any = {};
  let cvssScore = 'Not available';
  let baseSeverity = 'Not available';
  
  if (cveData.cvssV3) {
    cvssData = cveData.cvssV3;
    cvssScore = cvssData.baseScore?.toString() || 'Not available';
    baseSeverity = cvssData.baseSeverity || 'Not available';
  } else if (cveData.metrics) {
    const metrics = cveData.metrics || {};
    const cvssV31 = metrics.cvssMetricV31?.[0]?.cvssData;
    const cvssV30 = metrics.cvssMetricV30?.[0]?.cvssData;
    cvssData = cvssV31 || cvssV30 || {};
    cvssScore = cvssData.baseScore?.toString() || 'Not available';
    baseSeverity = cvssData.baseSeverity || 'Not available';
  }

  if (baseSeverity === 'Not available' && cvssScore !== 'Not available') {
    const scoreNum = parseFloat(cvssScore);
    if (!isNaN(scoreNum)) {
      if (scoreNum >= 9.0) baseSeverity = 'CRITICAL';
      else if (scoreNum >= 7.0) baseSeverity = 'HIGH';
      else if (scoreNum >= 4.0) baseSeverity = 'MEDIUM';
      else baseSeverity = 'LOW';
    }
  }

  return { score: cvssScore, severity: baseSeverity };
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
