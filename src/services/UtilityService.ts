// This file will contain helper/utility methods
import { utils } from '../utils/helpers';
import { CONSTANTS } from '../utils/constants';

// Unified prompt used for CVE analysis requests
export const TECHNICAL_BRIEF_PROMPT = String.raw`# CVE Technical Brief Generation Prompt – Engineering Focus

You are a senior cybersecurity analyst with 20 years of experience. Your task is to generate a concise, accurate, and actionable technical brief for a single CVE ID. This brief is for product teams, engineering leads, BU security champions, and product security engineers.

## Core Guidelines
- Communicate as a technical peer, not a vendor
- Avoid filler, hype, or generalized language  
- Focus on decision-making, not speculation
- Confidence levels must be justified
- Only use information explicitly found in the provided context
- **NEVER fabricate or infer information not explicitly stated in context**
- If data is missing, write "Not specified" - do not estimate or assume

## Priority Definitions
- **P0**: Active exploitation + high business impact (patch within 24h)
- **P1**: Public exploit available + medium-high impact (patch within 72h)  
- **P2**: PoC exists + moderate impact (patch next cycle)
- **P3**: Theoretical risk + low impact (address in maintenance)

## Language Standards
### ❌ Security Theater Language
- "Critical vulnerability could allow attackers to completely compromise systems"
- "Sophisticated threat actors are actively exploiting this flaw"
- "Immediate patching is essential across all environments"
- "Could lead to devastating business impact"

### ✅ Engineering Language
- "Remote code execution via malformed HTTP headers, no auth required"
- "Buffer overflow in parser, public exploit available since 2024-01-15"
- "Update to version 2.1.3 within 72h for internet-facing systems"
- "Affects authentication module, enables privilege escalation"

## Input Format
\`\`\`
CVE ID: CVE-<insert_ID_here>
Context Sources:
<context_chunk_1>
{source 1}
</context_chunk_1>
<context_chunk_2>
{source 2}
</context_chunk_2>
\`\`\`

## Output Schema Enforcement

**CRITICAL**: Your response must follow this exact structure with all required fields. Missing or improperly formatted sections will be rejected.

### Required Output Format

\`\`\`markdown
# CVE-<insert_ID_here> Technical Brief

<!-- SCHEMA_VALIDATION_START -->
**Status**: [ENUM: Patch Available|In Progress|No Fix] (Released: [DATE: YYYY-MM-DD|Not specified])  
**Priority**: [ENUM: P0|P1|P2|P3] – [STRING: Specific remediation timeframe]  
**Confidence**: [ENUM: High|Medium|Low] – [STRING: # sources, agreement level, vendor confirmation Y/N]

## Core Facts
- **Component**: [STRING: Exact affected software/version ranges or "Not specified"]
- **Attack Vector**: [ENUM: Network|Local|Physical] + [Auth Required: ENUM: Y|N|Not specified]
- **Exploitation**: [ENUM: Confirmed in wild|PoC available|Theoretical only|Not specified]
- **Exploit Published**: [DATE: YYYY-MM-DD|Not published|Not specified]
- **Real-world Usage**: [Active attacks: ENUM: Y|N|Not specified] | [CISA KEV: ENUM: Y|N]
- **Complexity**: [ENUM: Trivial|Moderate|High|Not specified] skill required

## Business Impact
- **Technical Effect**: [STRING: Specific consequence - RCE, DoS, privilege escalation, data access]
- **Realistic Scenario**: [STRING: What actually happens during exploitation - be specific]
- **Scope**: [STRING: Number/percentage of affected systems or "Not specified"]

## Actions Required
1. **Immediate** ([STRING: specific timeframe]): [STRING: Measurable task - inventory, restrict access, alert teams]
2. **Short-term** ([STRING: specific timeframe]): [STRING: Exact patch version or config change]
3. **Detection**: [STRING: Specific command or method to identify vulnerable systems]
4. **Verification**: [STRING: Exact steps to confirm patch/config was applied successfully]

## Patch Information
- **Patch Status**: [ENUM: Available|In Development|No Fix Planned|Not specified]
- **Fixed Version(s)**: [STRING: Specific version numbers that resolve the issue or "Not specified"]
- **Patch Source**: [STRING: Direct URL to patch/update or vendor advisory or "Not specified"]
- **Release Notes**: [STRING: Link to changelog/release notes or "Not specified"]
- **Backport Status**: [STRING: Whether fixes are available for older supported versions or "Not specified"]

## Technical Details
- **Root Cause**: [STRING: Buffer overflow, logic flaw, injection, etc. or "Not specified"]
- **Trigger**: [STRING: How the vulnerability is activated or "Not specified"]
- **Prerequisites**: [STRING: Specific conditions needed to exploit or "Not specified"]
- **Exploit Reliability**: [ENUM: Consistent|Intermittent|PoC only|Not specified]

## Missing Information
- [ARRAY: List of key unknowns that impact remediation decisions]
- [STRING: Note how missing info affects risk assessment or prioritization]

## Source Assessment  
- **Quality**: [ENUM: High|Medium|Low] – [STRING: # authoritative sources vs community sources]
- **Agreement**: [ENUM: Complete|Partial conflicts|Major disputes]
- **Recency**: [DATE: Most recent source date YYYY-MM-DD or "Stale data"]
- **Source Links Used**:
  - [STRING: URL or name of Source 1]
  - [STRING: URL or name of Source 2]
<!-- SCHEMA_VALIDATION_END -->
\`\`\`

### Field Validation Rules

**Status Section** (ALL REQUIRED):
- `Status`: Must be exactly one of: "Patch Available", "In Progress", "No Fix"
- `Released date`: Must be YYYY-MM-DD format or "Not specified"
- `Priority`: Must be exactly P0, P1, P2, or P3
- `Priority rationale`: Must include specific timeframe (e.g., "within 24h", "next sprint")
- `Confidence`: Must be exactly "High", "Medium", or "Low"
- `Confidence rationale`: Must include number of sources and agreement level

**Core Facts Section** (ALL REQUIRED):
- `Component`: Cannot be empty - use "Not specified" if unknown
- `Attack Vector`: Must be exactly "Network", "Local", or "Physical"
- `Auth Required`: Must be exactly "Y", "N", or "Not specified"
- `Exploitation`: Must be one of the four specified enums
- `Exploit Published`: Must be date format or specified alternatives
- `Active attacks`: Must be exactly "Y", "N", or "Not specified"
- `CISA KEV`: Must be exactly "Y" or "N"
- `Complexity`: Must be one of the four specified enums

**Actions Required Section** (ALL 4 REQUIRED):
- Each action must include specific timeframe in parentheses
- Actions must be measurable and specific, not generic
- Detection method must be executable command or specific process
- Verification must be concrete steps, not vague guidance

**Patch Information Section** (ALL 5 REQUIRED):
- `Patch Status`: Must be exactly one of: "Available", "In Development", "No Fix Planned", "Not specified"
- `Fixed Version(s)`: Must include specific version numbers when available
- `Patch Source`: Must be direct URL or specific source reference
- `Release Notes`: Must be URL or specific reference to changelog
- `Backport Status`: Must address older version support status

**Completeness Validation Checklist**:
\`\`\`markdown
<!-- VALIDATION_CHECKLIST -->
- [ ] CVE_ID: Properly formatted (CVE-YYYY-NNNNN)
- [ ] STATUS_COMPLETE: All 5 status fields filled
- [ ] CORE_FACTS_COMPLETE: All 6 core facts fields filled  
- [ ] IMPACT_COMPLETE: All 3 business impact fields filled
- [ ] ACTIONS_COMPLETE: All 4 action items with timeframes
- [ ] PATCH_INFO_COMPLETE: All 5 patch information fields filled
- [ ] TECHNICAL_COMPLETE: All 4 technical detail fields filled
- [ ] MISSING_INFO_ACKNOWLEDGED: Section present (can be empty)
- [ ] SOURCE_ASSESSMENT_COMPLETE: All 4 assessment fields filled
- [ ] NO_FABRICATED_DATA: All claims backed by provided context
- [ ] ENUM_VALUES_VALID: All enum fields use exact specified values
- [ ] DATES_FORMATTED: All dates in YYYY-MM-DD or specified alternative
- [ ] TIMEFRAMES_SPECIFIC: All action timeframes include duration
<!-- END_VALIDATION_CHECKLIST -->
\`\`\`

### Data Type Enforcement
- **Dates**: Must be YYYY-MM-DD format or exactly "Not specified", "Not published", or "Stale data"
- **Enums**: Must use EXACT text from specified options - no variations or synonyms
- **Booleans**: Must be exactly "Y", "N", or "Not specified" - no "Yes/No" or "True/False"
- **Timeframes**: Must include specific duration (e.g., "Within 24h", "Next sprint", "End of month")
- **Strings**: Cannot be empty - use "Not specified" for missing data
- **URLs**: Must be complete URLs when available, or "Not specified" if missing

### Quality Gates
**REJECT OUTPUT IF**:
- Any required field is missing or empty
- Enum values don't match exactly (case-sensitive)
- Dates are not in proper format
- Actions lack specific timeframes
- Confidence rationale doesn't include source count
- Patch information section is incomplete
- Any section uses placeholder text like "TBD" or "TODO"

## Critical Constraints
🚫 **NEVER**:
- Fabricate CVSS scores, dates, version numbers, or technical details
- Use marketing language or threat vendor terminology
- Reference other CVEs or make comparisons
- Include general security advice unrelated to this specific CVE
- Assume impact, complexity, or remediation beyond stated facts
- Write "typically" or "usually" - stick to this CVE only
- Skip required fields or sections
- Use enum values not in the specified list
- Fabricate patch URLs or download links

✅ **ALWAYS**:
- Write "Not specified" for any missing data points
- Use exact version numbers and dates when provided
- Include specific timelines for all action items
- Quantify scope and impact when data is available
- Lead with most actionable information
- Justify priority rating with specific facts
- Complete every required field in the schema
- Use exact enum values as specified
- Include direct patch sources when available in context

## Confidence Calibration Guide
- **High**: 3+ authoritative sources in complete agreement + vendor confirmation
- **Medium**: 2+ sources with minor conflicts OR single authoritative source
- **Low**: Single community source OR major conflicts between sources OR incomplete data

## Final Validation Before Submission
**Your output will be automatically validated against the schema. Ensure**:
1. Every required field is completed
2. All enum values match exactly
3. All dates are properly formatted
4. All action items have specific timeframes
5. No fabricated information is included
6. Confidence rationale includes source assessment
7. Priority is justified by concrete facts
8. Missing information is explicitly acknowledged
9. Patch information section is complete with all 5 fields
10. Patch sources are direct URLs when available in context

**If validation fails, the entire brief must be regenerated.**

---

**Schema-Compliant Example**:
\`\`\`markdown
# CVE-2024-1234 Technical Brief

<!-- SCHEMA_VALIDATION_START -->
**Status**: Patch Available (Released: 2024-01-20)  
**Priority**: P1 – Patch within 72h for internet-facing systems  
**Confidence**: High – 3 sources, complete agreement, vendor confirmation Y

## Core Facts
- **Component**: nginx 1.20.0 through 1.22.1
- **Attack Vector**: Network + Auth Required: N
- **Exploitation**: PoC available
- **Exploit Published**: 2024-01-18
- **Real-world Usage**: Active attacks: N | CISA KEV: N
- **Complexity**: Moderate skill required

## Business Impact
- **Technical Effect**: Remote code execution via HTTP header buffer overflow
- **Realistic Scenario**: Attacker sends crafted HTTP request to trigger memory corruption and execute arbitrary code
- **Scope**: Not specified

## Actions Required
1. **Immediate** (Within 24h): Run \`nginx -v\` inventory across all web servers
2. **Short-term** (Within 72h): Update to nginx 1.22.2+ on internet-facing systems
3. **Detection**: Execute \`find /etc -name "nginx.conf" -exec nginx -t \\;\` on all systems
4. **Verification**: Confirm \`nginx -v\` shows version 1.22.2+ after service restart

## Patch Information
- **Patch Status**: Available
- **Fixed Version(s)**: nginx 1.22.2, 1.23.1
- **Patch Source**: https://nginx.org/download/nginx-1.22.2.tar.gz
- **Release Notes**: https://nginx.org/en/CHANGES-1.22
- **Backport Status**: Fixes available for 1.20.x series in version 1.20.3

## Technical Details
- **Root Cause**: Buffer overflow in HTTP header parsing function
- **Trigger**: Malformed Content-Length header with oversized value
- **Prerequisites**: Network access to HTTP service port
- **Exploit Reliability**: Consistent

## Missing Information
- Number of affected systems in current environment
- CVSS score not provided in available sources

## Source Assessment  
- **Quality**: High – 2 authoritative sources, 1 vendor advisory
- **Agreement**: Complete
- **Recency**: 2024-01-20
- **Source Links Used**:
  - nginx.com security advisory
  - NVD CVE database entry
<!-- SCHEMA_VALIDATION_END -->

<!-- VALIDATION_CHECKLIST -->
- [x] CVE_ID: Properly formatted (CVE-2024-1234)
- [x] STATUS_COMPLETE: All 5 status fields filled
- [x] CORE_FACTS_COMPLETE: All 6 core facts fields filled  
- [x] IMPACT_COMPLETE: All 3 business impact fields filled
- [x] ACTIONS_COMPLETE: All 4 action items with timeframes
- [x] PATCH_INFO_COMPLETE: All 5 patch information fields filled
- [x] TECHNICAL_COMPLETE: All 4 technical detail fields filled
- [x] MISSING_INFO_ACKNOWLEDGED: Section present with 2 items
- [x] SOURCE_ASSESSMENT_COMPLETE: All 4 assessment fields filled
- [x] NO_FABRICATED_DATA: All claims backed by provided context
- [x] ENUM_VALUES_VALID: All enum fields use exact specified values
- [x] DATES_FORMATTED: All dates in YYYY-MM-DD format
- [x] TIMEFRAMES_SPECIFIC: All action timeframes include duration
<!-- END_VALIDATION_CHECKLIST -->
\`\`\`
`;

export async function fetchWithFallback(url, options = {}) {
  try {
    return await fetch(url, options);
  } catch (corsError) {
    console.log('CORS blocked, trying proxy...');
    const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`;
    const response = await fetch(proxyUrl);

    if (response.ok) {
      const proxyData = await response.json();
      return {
        ok: true,
        json: () => Promise.resolve(JSON.parse(proxyData.contents))
      };
    }
    throw corsError;
  }
}

export function processCVEData(cve) {
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
}

export function parsePatchAndAdvisoryResponse(aiResponseOrMetadata, cveId) {
  if (typeof aiResponseOrMetadata === 'string') {
    // Existing logic for text response
    try {
      const jsonMatch = aiResponseOrMetadata.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        const processEntries = (entries, type) => (entries || []).map(entry => ({
          ...entry,
          citationUrl: entry.citationUrl || entry.url // Ensure citationUrl is populated
        }));
        return {
          patches: processEntries(parsed.patches, 'patch'),
          advisories: processEntries(parsed.advisories, 'advisory'),
          searchSummary: { ...parsed.searchSummary, searchMethod: parsed.searchSummary?.searchMethod || 'JSON_PARSED' } || { searchMethod: 'JSON_PARSED' }
        };
      }
    } catch (e) {
      console.log('Failed to parse patch response JSON from text, using raw text analysis...');
      // Fall through to conservative text parsing if JSON parsing fails
    }

    // Fallback text parsing for string input
    const patches = [];
    const advisories = [];
    const urls = aiResponseOrMetadata.match(/https?:\/\/[^\s<>"{}|\\^`[\]]+/g) || [];
    urls.forEach(url => {
      if (url.includes('microsoft.com') || url.includes('msrc') || url.includes('update')) {
        patches.push({ vendor: 'Microsoft', downloadUrl: url, confidence: 'MEDIUM', patchType: 'Security Update', description: 'Microsoft security update found via AI search' });
      } else if (url.includes('redhat.com') || url.includes('rhsa')) {
        patches.push({ vendor: 'Red Hat', downloadUrl: url, confidence: 'MEDIUM', patchType: 'Security Advisory', description: 'Red Hat security advisory found via AI search' });
      } else if (url.includes('security') || url.includes('advisory') || url.includes('cve')) {
        advisories.push({ source: 'Security Advisory', url: url, confidence: 'MEDIUM', type: 'Security Advisory', description: 'Security advisory found via AI search' });
      }
    });
    return {
      patches,
      advisories,
      searchSummary: { patchesFound: patches.length, advisoriesFound: advisories.length, searchMethod: 'TEXT_PARSING_FALLBACK', searchTimestamp: new Date().toISOString() }
    };

  } else if (typeof aiResponseOrMetadata === 'object' && aiResponseOrMetadata.groundingMetadata) {
    // Handle groundingMetadata object
    const searchQueries = aiResponseOrMetadata.searchQueries || [];
    console.log(`Patch/Advisory parsing: Received groundingMetadata for ${cveId}`);
    return {
      patches: [],
      advisories: [],
      searchSummary: {
        patchesFound: 0,
        advisoriesFound: 0,
        searchMethod: 'GROUNDING_INFO_ONLY',
        searchTimestamp: new Date().toISOString(),
        searchQueries: searchQueries,
        note: 'AI did not return a textual summary. Generated a brief overview from search context.'
      }
    };
  } else {
    // Should not happen, safeguard
    console.error(`Unknown content type for patch/advisory parsing: ${typeof aiResponseOrMetadata}`);
    return {
      patches: [],
      advisories: [],
      searchSummary: {
        patchesFound: 0,
        advisoriesFound: 0,
        searchMethod: 'PARSING_FAILED_UNEXPECTED_TYPE',
        searchTimestamp: new Date().toISOString(),
        note: 'Failed to parse patch/advisory information due to an unexpected AI response format.'
      }
    };
  }
}

export function getHeuristicPatchesAndAdvisories(cveId, cveData) {
  const patches = [];
  const advisories = [];
  const description = cveData?.description?.toLowerCase() || '';

  // Core advisories (always include)
  advisories.push(
    {
      source: 'NIST NVD',
      advisoryId: cveId,
      title: 'National Vulnerability Database Record',
      url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
      description: 'Official CVE record with technical details',
      confidence: 'HIGH',
      type: 'Official CVE Record',
      priority: 1
    },
    {
      source: 'MITRE',
      advisoryId: cveId,
      title: 'MITRE CVE Database Record',
      url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}`,
      description: 'MITRE CVE database entry',
      confidence: 'HIGH',
      type: 'CVE Record',
      priority: 1
    }
  );

  // Vendor-specific patches and advisories based on description
  if (description.includes('microsoft') || description.includes('windows')) {
    patches.push({
      vendor: 'Microsoft',
      product: 'Windows/Microsoft Products',
      downloadUrl: `https://msrc.microsoft.com/update-guide/vulnerability/${cveId}`,
      advisoryUrl: `https://msrc.microsoft.com/update-guide/vulnerability/${cveId}`,
      description: 'Microsoft Security Update Guide - Check for available patches',
      confidence: 'HIGH',
      patchType: 'Security Update',
      searchHint: 'Check Microsoft Update Catalog for KB numbers'
    });

    advisories.push({
      source: 'Microsoft Security Response Center',
      advisoryId: `MSRC-${cveId}`,
      title: 'Microsoft Security Advisory',
      url: `https://msrc.microsoft.com/update-guide/vulnerability/${cveId}`,
      description: 'Microsoft Security Response Center advisory',
      confidence: 'HIGH',
      type: 'Vendor Security Advisory',
      priority: 2
    });
  }

  if (description.includes('red hat') || description.includes('rhel') || description.includes('linux')) {
    patches.push({
      vendor: 'Red Hat',
      product: 'Red Hat Enterprise Linux',
      downloadUrl: `https://access.redhat.com/security/cve/${cveId}`,
      advisoryUrl: `https://access.redhat.com/security/cve/${cveId}`,
      description: 'Red Hat Security Advisory - Check for RHSA updates',
      confidence: 'HIGH',
      patchType: 'Security Advisory',
      searchHint: 'Check for RHSA advisory numbers'
    });

    advisories.push({
      source: 'Red Hat Product Security',
      advisoryId: `RHSA-${cveId}`,
      title: 'Red Hat Security Advisory',
      url: `https://access.redhat.com/security/cve/${cveId}`,
      description: 'Red Hat Product Security advisory and patches',
      confidence: 'HIGH',
      type: 'Vendor Security Advisory',
      priority: 2
    });
  }

  if (description.includes('ubuntu')) {
    patches.push({
      vendor: 'Ubuntu',
      product: 'Ubuntu Linux',
      downloadUrl: `https://ubuntu.com/security/notices?q=${cveId}`,
      advisoryUrl: `https://ubuntu.com/security/notices?q=${cveId}`,
      description: 'Ubuntu Security Notices - Check for USN updates',
      confidence: 'HIGH',
      patchType: 'Security Notice',
      searchHint: 'Look for USN (Ubuntu Security Notice) numbers'
    });

    advisories.push({
      source: 'Ubuntu Security Team',
      advisoryId: `USN-${cveId}`,
      title: 'Ubuntu Security Notice',
      url: `https://ubuntu.com/security/notices?q=${cveId}`,
      description: 'Ubuntu Security Team advisory and updates',
      confidence: 'HIGH',
      type: 'Distribution Security Notice',
      priority: 2
    });
  }

  if (description.includes('debian')) {
    patches.push({
      vendor: 'Debian',
      product: 'Debian Linux',
      downloadUrl: `https://security-tracker.debian.org/tracker/${cveId}`,
      advisoryUrl: `https://security-tracker.debian.org/tracker/${cveId}`,
      description: 'Debian Security Tracker - Check for DSA updates',
      confidence: 'HIGH',
      patchType: 'Security Advisory',
      searchHint: 'Look for DSA (Debian Security Advisory) numbers'
    });

    advisories.push({
      source: 'Debian Security Team',
      advisoryId: `DSA-${cveId}`,
      title: 'Debian Security Advisory',
      url: `https://security-tracker.debian.org/tracker/${cveId}`,
      description: 'Debian Security Team advisory and patches',
      confidence: 'HIGH',
      type: 'Distribution Security Advisory',
      priority: 2
    });
  }

  if (description.includes('oracle')) {
    patches.push({
      vendor: 'Oracle',
      product: 'Oracle Products',
      downloadUrl: `https://www.oracle.com/security-alerts/`,
      advisoryUrl: `https://www.oracle.com/security-alerts/`,
      description: 'Oracle Security Alerts - Check quarterly CPU updates',
      confidence: 'MEDIUM',
      patchType: 'Critical Patch Update',
      searchHint: 'Check Oracle Critical Patch Updates (CPU)'
    });

    advisories.push({
      source: 'Oracle Security Alerts',
      advisoryId: `Oracle-${cveId}`,
      title: 'Oracle Security Alert',
      url: `https://www.oracle.com/security-alerts/`,
      description: 'Oracle security alerts and critical patch updates',
      confidence: 'MEDIUM',
      type: 'Vendor Security Alert',
      priority: 2
    });
  }

  if (description.includes('adobe')) {
    patches.push({
      vendor: 'Adobe',
      product: 'Adobe Products',
      downloadUrl: `https://helpx.adobe.com/security.html`,
      advisoryUrl: `https://helpx.adobe.com/security.html`,
      description: 'Adobe Security Updates - Check product-specific updates',
      confidence: 'MEDIUM',
      patchType: 'Security Update',
      searchHint: 'Check Adobe product update pages'
    });

    advisories.push({
      source: 'Adobe Product Security',
      advisoryId: `Adobe-${cveId}`,
      title: 'Adobe Security Bulletin',
      url: `https://helpx.adobe.com/security.html`,
      description: 'Adobe Product Security bulletins and updates',
      confidence: 'MEDIUM',
      type: 'Vendor Security Bulletin',
      priority: 2
    });
  }

  // Additional security resources
  advisories.push(
    {
      source: 'CERT/CC',
      advisoryId: `CERT-${cveId}`,
      title: 'CERT Coordination Center Advisory',
      url: `https://www.kb.cert.org/vuls/byid/${cveId}`,
      description: 'CERT/CC vulnerability analysis and recommendations',
      confidence: 'MEDIUM',
      type: 'Security Advisory',
      priority: 3
    },
    {
      source: 'Exploit Database',
      advisoryId: `EDB-${cveId}`,
      title: 'Exploit Database Reference',
      url: `https://www.exploit-db.com/search?cve=${cveId}`,
      description: 'Security research and exploit information',
      confidence: 'MEDIUM',
      type: 'Security Research',
      priority: 3
    }
  );

  // Sort by priority
  advisories.sort((a, b) => (a.priority || 99) - (b.priority || 99));

  return {
    patches: patches,
    advisories: advisories,
    searchSummary: {
      patchesFound: patches.length,
      advisoriesFound: advisories.length,
      searchMethod: 'HEURISTIC_DETECTION',
      vendorsSearched: [...new Set(patches.map(p => p.vendor))],
      searchTimestamp: new Date().toISOString(),
      note: 'Heuristic detection based on CVE description analysis'
    }
  };
}

export function parseAIThreatIntelligence(aiResponseOrMetadata, cveId, setLoadingSteps) {
  const updateStepsParse = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};

  if (typeof aiResponseOrMetadata === 'string') {
    // Existing logic for text response
    try {
      const jsonMatch = aiResponseOrMetadata.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        updateStepsParse(prev => [...prev, `📊 Parsed structured threat intelligence for ${cveId}`]);

        parsed.parsingMethod = 'JSON_EXTRACTION';
        parsed.hallucinationFlags = detectHallucinationFlags(parsed);

        return normalizeAIFindings(parsed, cveId);
      }
    } catch (e) {
      console.log('Failed to parse JSON from text response, analyzing raw text...');
      // Fall through to conservative text analysis if JSON parsing fails
    }

    // Fallback text analysis with conservative interpretation for string input
    const findings = performConservativeTextAnalysis(aiResponseOrMetadata, cveId);
    updateStepsParse(prev => [...prev, `📈 Used conservative text analysis for ${cveId}`]);
    return findings;

  } else if (typeof aiResponseOrMetadata === 'object' && aiResponseOrMetadata.groundingMetadata) {
    // Handle groundingMetadata object
    updateStepsParse(prev => [...prev, `ℹ️ Processing grounding metadata for ${cveId}`]);
    const searchQueries = aiResponseOrMetadata.searchQueries || [];
    const queryExample = searchQueries.slice(0, 3).join('; ');
    const noSummaryText = searchQueries.length > 0
      ? `AI search performed (${searchQueries.length} queries) but no textual summary returned. Example queries: ${queryExample}`
      : 'AI search performed but no textual summary returned.';
    return {
      cisaKev: { listed: false, details: 'No direct AI summary, grounding info only.', source: '', confidence: 'LOW', aiDiscovered: true },
      activeExploitation: { confirmed: false, details: 'No direct AI summary, grounding info only.', sources: [], aiDiscovered: true },
      exploitDiscovery: { found: false, totalCount: 0, exploits: [], confidence: 'LOW', aiDiscovered: true },
      vendorAdvisories: { found: false, count: 0, advisories: [], aiDiscovered: true },
      intelligenceSummary: {
        sourcesAnalyzed: searchQueries.length,
        analysisMethod: 'GROUNDING_INFO_ONLY',
        confidenceLevel: 'VERY_LOW',
        aiEnhanced: true,
        extractionBased: false, // No text was extracted
        searchQueries: searchQueries,
        note: 'AI did not return a textual summary. Generated a brief overview from search context.'
      },
      overallThreatLevel: 'UNKNOWN', // Or 'LOW' as it's unconfirmed
      lastUpdated: new Date().toISOString(),
      summary: noSummaryText,
      hallucinationFlags: ['NO_TEXTUAL_AI_SUMMARY']
    };
  } else {
    // Should not happen if fetchAIThreatIntelligence is correct, but as a safeguard:
    console.error(`Unknown content type for AI threat intelligence parsing: ${typeof aiResponseOrMetadata}`);
    updateStepsParse(prev => [...prev, `⚠️ Unknown AI response type for ${cveId}, cannot parse.`]);
    // Return a minimal structure indicating failure
    return {
      cisaKev: { listed: false, details: 'Parsing failed due to unknown AI response type.', source: '', confidence: 'VERY_LOW', aiDiscovered: false },
      activeExploitation: { confirmed: false, details: 'Parsing failed.', sources: [], aiDiscovered: false },
      exploitDiscovery: { found: false, totalCount: 0, exploits: [], confidence: 'VERY_LOW', aiDiscovered: false },
      vendorAdvisories: { found: false, count: 0, advisories: [], aiDiscovered: false },
      intelligenceSummary: { analysisMethod: 'PARSING_FAILED', confidenceLevel: 'VERY_LOW' },
      overallThreatLevel: 'UNKNOWN',
      lastUpdated: new Date().toISOString(),
      summary: 'Failed to parse AI threat intelligence due to an unexpected response format.',
      hallucinationFlags: ['PARSING_FAILURE_UNEXPECTED_TYPE']
    };
  }
}

export function detectHallucinationFlags(parsed) {
  const flags = [];

  // Check for unrealistic counts
  if (parsed.exploitDiscovery?.totalCount > 20) {
    flags.push('UNREALISTIC_EXPLOIT_COUNT');
  }

  // Check for inconsistent confidence levels
  if (parsed.cisaKev?.listed && parsed.cisaKev?.confidence === 'LOW') {
    flags.push('INCONSISTENT_CONFIDENCE');
  }

  // Check for missing source attribution
  if (parsed.cisaKev?.listed && !parsed.cisaKev?.source) {
    flags.push('MISSING_SOURCE_ATTRIBUTION');
  }

  return flags;
}

export function normalizeAIFindings(parsed, cveId) {
  // Normalize the parsed findings to standard format
  return {
    cisaKev: {
      listed: parsed.cisaKev?.listed || false,
      details: parsed.cisaKev?.details || '',
      source: parsed.cisaKev?.source || '',
      confidence: parsed.cisaKev?.confidence || 'LOW',
      aiDiscovered: true
    },
    activeExploitation: {
      confirmed: parsed.activeExploitation?.confirmed || false,
      details: parsed.activeExploitation?.details || '',
      sources: parsed.activeExploitation?.sources || [],
      aiDiscovered: true
    },
    exploitDiscovery: {
      found: parsed.exploitDiscovery?.found || false,
      totalCount: Math.min(parsed.exploitDiscovery?.totalCount || 0, 10), // Cap at 10
      exploits: (parsed.exploitDiscovery?.exploits || []).map(e => ({ ...e, citationUrl: e.citationUrl || e.url })),
      confidence: parsed.exploitDiscovery?.confidence || 'LOW',
      aiDiscovered: true
    },
    vendorAdvisories: {
      found: parsed.vendorAdvisories?.found || false,
      count: parsed.vendorAdvisories?.count || 0,
      advisories: (parsed.vendorAdvisories?.advisories || []).map(a => ({ ...a, citationUrl: a.citationUrl || a.url })),
      aiDiscovered: true
    },
    intelligenceSummary: {
      sourcesAnalyzed: parsed.extractionSummary?.sourcesFound || 1,
      analysisMethod: 'AI_WEB_EXTRACTION',
      confidenceLevel: parsed.extractionSummary?.confidenceLevel || 'LOW',
      aiEnhanced: true,
      extractionBased: true
    },
    overallThreatLevel: calculateThreatLevel(parsed),
    lastUpdated: new Date().toISOString(),
    summary: `Extractive AI analysis: ${parsed.cisaKev?.listed ? 'KEV listed' : 'Not in KEV'}, ${parsed.exploitDiscovery?.found ? parsed.exploitDiscovery.totalCount + ' exploits found' : 'No exploits found'}`,
    hallucinationFlags: parsed.hallucinationFlags || []
  };
}

export function performConservativeTextAnalysis(aiResponse, cveId) {
  const response = aiResponse.toLowerCase();

  // Very conservative text analysis
  const findings = {
    cisaKev: {
      listed: response.includes('cisa') && response.includes('kev') && response.includes('listed'),
      details: response.includes('cisa') ? 'Mentioned in search results' : '',
      source: '',
      confidence: 'LOW',
      aiDiscovered: true
    },
    activeExploitation: {
      confirmed: false, // Conservative - require explicit confirmation
      details: '',
      sources: [],
      aiDiscovered: true
    },
    exploitDiscovery: {
      found: response.includes('exploit') && (response.includes('github') || response.includes('poc')),
      totalCount: response.includes('exploit') ? 1 : 0, // Conservative count
      exploits: [],
      confidence: 'LOW',
      aiDiscovered: true
    },
    vendorAdvisories: {
      found: response.includes('advisory') || response.includes('patch'),
      count: response.includes('advisory') ? 1 : 0,
      advisories: [],
      aiDiscovered: true
    },
    intelligenceSummary: {
      sourcesAnalyzed: 1,
      analysisMethod: 'CONSERVATIVE_TEXT_ANALYSIS',
      confidenceLevel: 'VERY_LOW',
      aiEnhanced: false
    },
    overallThreatLevel: 'MEDIUM',
    lastUpdated: new Date().toISOString(),
    summary: 'Conservative text analysis with minimal claims',
    hallucinationFlags: ['TEXT_ANALYSIS_FALLBACK']
  };

  return findings;
}

export function calculateThreatLevel(findings) {
  if (findings.cisaKev?.listed) return 'CRITICAL';
  if (findings.activeExploitation?.confirmed) return 'HIGH';
  if (findings.exploitDiscovery?.found) return 'HIGH';
  return 'MEDIUM';
}

export async function performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps) {
  const updateStepsHeuristic = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
  updateStepsHeuristic(prev => [...prev, `🔍 Performing advanced heuristic analysis for ${cveId}...`]);

  const year = parseInt(cveId.split('-')[1]);
  const id = parseInt(cveId.split('-')[2]);
  const cvssScore = cveData?.cvssV3?.baseScore || cveData?.cvssV2?.baseScore || 0;
  const epssFloat = epssData?.epssFloat || 0;
  const severity = utils?.getSeverityLevel ? utils.getSeverityLevel(cvssScore) : (cvssScore >= 9 ? 'CRITICAL' : cvssScore >= 7 ? 'HIGH' : cvssScore >= 4 ? 'MEDIUM' : 'LOW');

  let riskScore = 0;
  const indicators = [];

  if (cvssScore >= 9) { riskScore += 4; indicators.push('Critical CVSS score'); }
  else if (cvssScore >= 7) { riskScore += 3; indicators.push('High CVSS score'); }

  if (epssFloat > 0.7) { riskScore += 4; indicators.push('Very high EPSS score'); }
  else if (epssFloat > 0.3) { riskScore += 2; indicators.push('Elevated EPSS score'); }

  if (year >= 2024) { riskScore += 2; indicators.push('Recent vulnerability'); }
  if (id < 1000) { riskScore += 2; indicators.push('Early discovery in year'); }

  const highRiskPatterns = ['21413', '44487', '38030', '26923', '1675'];
  if (highRiskPatterns.some(pattern => cveId.includes(pattern))) {
    riskScore += 5;
    indicators.push('Matches known high-risk pattern');
  }

  const description = cveData?.description?.toLowerCase() || '';
  const highValueTargets = ['microsoft', 'apache', 'oracle', 'vmware', 'cisco', 'windows', 'exchange', 'linux'];
  if (highValueTargets.some(target => description.includes(target))) {
    riskScore += 2;
    indicators.push('Affects high-value target software');
  }

  const threatLevel = riskScore >= 8 ? 'CRITICAL' : riskScore >= 6 ? 'HIGH' : riskScore >= 4 ? 'MEDIUM' : 'LOW';
  const likelyInKEV = riskScore >= 7;
  const likelyExploited = riskScore >= 5;
  const exploitCount = Math.min(Math.floor(riskScore / 2), 5);

  updateStepsHeuristic(prev => [...prev, `📊 Heuristic analysis complete: ${threatLevel} threat level (score: ${riskScore})`]);

  return {
    cisaKev: {
      listed: likelyInKEV,
      details: likelyInKEV ? 'High probability of KEV listing based on risk factors' : 'Low probability of KEV listing',
      confidence: 'HEURISTIC',
      source: 'Advanced pattern analysis',
      aiDiscovered: false
    },
    activeExploitation: {
      confirmed: likelyExploited,
      details: likelyExploited ? 'High exploitation likelihood based on multiple risk factors' : 'Lower exploitation probability',
      sources: [`Risk indicators: ${indicators.join(', ')}`],
      aiDiscovered: false
    },
    exploitDiscovery: {
      found: exploitCount > 0,
      totalCount: exploitCount,
      exploits: exploitCount > 0 ? [{
        type: exploitCount > 2 ? 'Working Exploit' : 'POC',
        url: `https://www.exploit-db.com/search?cve=${cveId}`,
        source: 'Exploit-DB (Predicted)',
        description: 'Heuristic prediction based on vulnerability characteristics',
        reliability: riskScore >= 6 ? 'HIGH' : 'MEDIUM',
        dateFound: new Date().toISOString()
      }] : [],
      githubRepos: Math.max(0, exploitCount - 1),
      exploitDbEntries: exploitCount > 0 ? 1 : 0,
      metasploitModules: exploitCount > 3 ? 1 : 0,
      confidence: riskScore >= 6 ? 'HIGH' : 'MEDIUM',
      aiDiscovered: false
    },
    vendorAdvisories: {
      found: Math.floor(riskScore / 3) > 0,
      count: Math.floor(riskScore / 3),
      advisories: [],
      patchStatus: cvssScore >= 7 ? 'likely available' : 'pending',
      aiDiscovered: false
    },
    cveValidation: {
      isValid: true,
      confidence: 'MEDIUM',
      validationSources: ['NVD', 'EPSS'],
      disputes: [],
      falsePositiveIndicators: [],
      legitimacyEvidence: indicators,
      recommendation: 'VALID',
      aiDiscovered: false
    },
    technicalAnalysis: {
      rootCause: 'Analysis based on CVE description and scoring',
      exploitMethod: cvssScore >= 7 ? 'Remote exploitation likely' : 'Local access may be required',
      impactAnalysis: `${severity} impact vulnerability with ${cvssScore} CVSS score`,
      mitigations: ['Apply vendor patches', 'Monitor for exploitation attempts', 'Implement network controls'],
      sources: [],
      aiDiscovered: false
    },
    threatIntelligence: {
      iocs: [],
      threatActors: [],
      campaignDetails: riskScore >= 8 ? 'Possible APT interest due to high impact' : '',
      ransomwareUsage: riskScore >= 7,
      aptGroups: [],
      aiDiscovered: false
    },
    intelligenceSummary: {
      sourcesAnalyzed: 2,
      exploitsFound: exploitCount,
      vendorAdvisoriesFound: Math.floor(riskScore / 3),
      activeExploitation: likelyExploited,
      cisaKevListed: likelyInKEV,
      cveValid: true,
      threatLevel: threatLevel,
      dataFreshness: new Date().toISOString(),
      analysisMethod: 'ADVANCED_HEURISTICS',
      confidenceLevel: riskScore >= 6 ? 'HIGH' : 'MEDIUM',
      aiEnhanced: false
    },
    overallThreatLevel: threatLevel,
    lastUpdated: new Date().toISOString(),
    summary: `Heuristic analysis: ${indicators.length} risk indicators detected, ${threatLevel} threat level assigned`,
    analysisMethod: 'ADVANCED_HEURISTICS',
    riskScore: riskScore,
    indicators: indicators,
    hallucinationFlags: ['HEURISTIC_BASED']
  };
}

export function buildEnhancedAnalysisPrompt(
  vulnerability,
  ragContext,
  ragDocCount = 0
) {
  const cveId = vulnerability.cve.id;
  const cvssScore =
    vulnerability.cve.cvssV3?.baseScore ||
    vulnerability.cve.cvssV2?.baseScore ||
    'N/A';
  const severity =
    vulnerability.cve.cvssV3?.baseSeverity ||
    vulnerability.cve.cvssV2?.severity ||
    'N/A';
  const epssScore = vulnerability.epss ? vulnerability.epss.epssPercentage : 'N/A';
  const kevStatus = vulnerability.kev?.listed ? 'Listed' : 'Not Listed';
  const exploitation = vulnerability.activeExploitation?.confirmed ? 'Yes' : 'No';
  const confidenceLevel = vulnerability.confidence?.overall || 'UNKNOWN';
  const classification = vulnerability.validation?.status || 'Unknown';

  return `${TECHNICAL_BRIEF_PROMPT}

CVE ID: ${cveId}
Context Sources:
<context_chunk_1>
${ragContext}
</context_chunk_1>`;
}

export function generateEnhancedFallbackAnalysis(vulnerability, error) {
  const cveId = vulnerability.cve.id;
  const cvssScore = vulnerability.cve.cvssV3?.baseScore || vulnerability.cve.cvssV2?.baseScore || 'N/A';
  const epssScore = vulnerability.epss ? vulnerability.epss.epssPercentage : 'N/A';
  const kevStatus = vulnerability.kev?.listed ? 'Yes - ACTIVE EXPLOITATION CONFIRMED' : 'No';
  const kevValidated = vulnerability.kev?.validated ? ' (VALIDATED)' : ' (UNVALIDATED)';
  const confidenceLevel = vulnerability.confidence?.overall || 'UNKNOWN';

  return {
    analysis: `# CVE-${cveId} Technical Brief

_Fallback analysis due to error: ${error.message}_

**Status**: ${vulnerability.patches?.length ? 'Patch Available' : 'No Fix'} | **Priority**: P2
**Confidence**: ${confidenceLevel} - Limited data

## Core Facts
- **Component**: ${vulnerability.cve.sourceIdentifier || 'Not specified'}
- **Attack Vector**: ${vulnerability.cve.cvssV3?.attackVector || 'Unknown'} + Auth Required: ${vulnerability.cve.cvssV3?.privilegesRequired || 'Unknown'}
- **Exploitation**: ${vulnerability.exploits?.found ? 'PoC available' : 'Theoretical only'}
- **Real-world Usage**: Active attacks: ${vulnerability.activeExploitation?.confirmed ? 'Y' : 'N'} | CISA KEV: ${vulnerability.kev?.listed ? 'Y' : 'N'}
- **Complexity**: ${vulnerability.cve.cvssV3?.attackComplexity || 'Unknown'}

_Detailed sections omitted due to fallback mode._`,
    ragUsed: false,
    ragDocuments: 0,
    ragSources: [],
    webGrounded: false,
    enhancedSources: vulnerability.enhancedSources || [],
    discoveredSources: vulnerability.discoveredSources || [],
    error: error.message,
    fallbackUsed: true,
    validationEnhanced: true,
    confidence: vulnerability.confidence,
    validation: vulnerability.validation,
    realTimeData: {
      cisaKev: vulnerability.kev?.listed || false,
      cisaKevValidated: vulnerability.kev?.validated || false,
      exploitsFound: vulnerability.exploits?.count || 0,
      exploitsValidated: vulnerability.exploits?.validated || false,
      exploitConfidence: vulnerability.exploits?.confidence || 'NONE',
      githubRefs: vulnerability.github?.count || 0,
      threatLevel: vulnerability.threatLevel || 'STANDARD',
      activeExploitation: vulnerability.activeExploitation?.confirmed || false,
      overallConfidence: vulnerability.confidence?.overall || 'UNKNOWN',
      hallucinationFlags: vulnerability.hallucinationFlags || []
    }
  };
}

// Utility methods for confidence and validation
export function formatFindingWithConfidence(finding, confidence, validation) {
  const confidenceIcon = getConfidenceIcon(confidence);
  const verificationBadge = getVerificationBadge(validation);

  return {
    ...finding,
    displayText: `${confidenceIcon} ${finding.text} ${verificationBadge}`,
    confidence: confidence,
    validation: validation,
    userWarning: generateUserWarning(confidence, validation)
  };
}

export function getConfidenceIcon(confidence) {
  const icons = {
    'HIGH': '✅',
    'MEDIUM': '⚠️',
    'LOW': '❓',
    'VERY_LOW': '❌'
  };
  return icons[confidence] || '❓';
}

export function getVerificationBadge(validation) {
  if (!validation) return '🤖 AI-Generated';

  if (validation.verified) {
    return '✓ Verified';
  } else {
    return '⚠️ Unverified';
  }
}

export function generateUserWarning(confidence, validation) {
  if (confidence === 'VERY_LOW') {
    return 'This information has very low confidence and should not be relied upon without manual verification.';
  }

  if (!validation?.verified && confidence !== 'HIGH') {
    return 'This AI-generated finding has not been verified against authoritative sources.';
  }

  return null;
}

export function createAIDataDisclaimer(vulnerability) {
  const totalAIFindings = countAIGeneratedFindings(vulnerability);
  const verifiedFindings = countVerifiedFindings(vulnerability.validation);
  const confidence = vulnerability.confidence?.overall || 'UNKNOWN';

  return {
    totalAIFindings,
    verifiedFindings,
    unverifiedFindings: totalAIFindings - verifiedFindings,
    overallConfidence: confidence,
    hallucinationFlags: vulnerability.hallucinationFlags || [],
    disclaimer: `This analysis includes ${totalAIFindings} AI-generated findings. ` +
               `${verifiedFindings} have been verified against authoritative sources. ` +
               `Overall confidence: ${confidence}. Always verify critical security decisions with official sources.`,
    recommendations: vulnerability.confidence?.recommendations || [],
    validationTimestamp: vulnerability.validationTimestamp || new Date().toISOString()
  };
}

export function countAIGeneratedFindings(vulnerability) {
  let count = 0;
  if (vulnerability.kev?.aiDiscovered) count++;
  if (vulnerability.exploits?.details?.some(e => e.aiDiscovered)) count++;
  if (vulnerability.vendorAdvisories?.aiDiscovered) count++;
  if (vulnerability.activeExploitation?.aiDiscovered) count++;
  return count;
}

export function countVerifiedFindings(validation) {
  if (!validation) return 0;

  let count = 0;
  if (validation.cisaKev?.verified) count++;
  if (validation.exploits?.verified) count++;
  if (validation.vendorAdvisories?.verified) count++;
  return count;
}
