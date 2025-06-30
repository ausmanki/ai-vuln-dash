import { CONSTANTS } from '../utils/constants';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { APIService } from './APIService'; // For fetchWithFallback

// Using the more complex logic from the 'master' side of the conflict for these functions

export const generateAIAnalysis = async (vulnerability, apiKey, model, settings = {}) => {
  if (!apiKey) throw new Error('Gemini API key required');

  const now = Date.now();
  // @ts-ignore
  const lastRequest = window.lastGeminiRequest || 0;

  if ((now - lastRequest) < CONSTANTS.RATE_LIMITS.GEMINI_COOLDOWN) {
    const waitTime = Math.ceil((CONSTANTS.RATE_LIMITS.GEMINI_COOLDOWN - (now - lastRequest)) / 1000);
    throw new Error(`Rate limit protection: Please wait ${waitTime} more seconds. Free Gemini API has strict limits.`);
  }
  // @ts-ignore
  window.lastGeminiRequest = now;

  if (ragDatabase) {
    await ragDatabase.ensureInitialized(apiKey);
    console.log(`📊 RAG Database Status: ${ragDatabase.documents.length} documents available (${ragDatabase.geminiApiKey ? 'Gemini embeddings' : 'local embeddings'})`);
  }

  const cveId = vulnerability.cve.id;
  const ragQuery = `${cveId} ${vulnerability.cve.description.substring(0, 200)} vulnerability analysis security impact mitigation threat intelligence EPSS ${vulnerability.epss?.epssPercentage || 'N/A'} CVSS ${vulnerability.cve.cvssV3?.baseScore || 'N/A'} ${vulnerability.kev?.listed ? 'CISA KEV active exploitation' : ''}`;

  console.log(`🔍 RAG Query: "${ragQuery.substring(0, 100)}..."`);

  let relevantDocs = [];
  let ragContext = 'No specific security knowledge found in database. Initializing knowledge base for future queries.';

  if (ragDatabase && ragDatabase.initialized) {
    relevantDocs = await ragDatabase.search(ragQuery, 15);
    console.log(`📚 RAG Retrieved: ${relevantDocs.length} relevant documents (${relevantDocs.filter(d => d.embeddingType === 'gemini').length} with Gemini embeddings)`);

    if (relevantDocs.length > 0) {
      ragContext = relevantDocs.map((doc, index) =>
        `[Security Knowledge ${index + 1}] ${doc.metadata.title} (Relevance: ${(doc.similarity * 100).toFixed(1)}%, ${doc.embeddingType || 'local'} embedding):\n${doc.content.substring(0, 800)}...`
      ).join('\n\n');
    } else {
      console.log('🔄 No specific matches found, trying broader search...');
      const broaderQuery = `vulnerability security analysis ${vulnerability.cve.cvssV3?.baseSeverity || 'unknown'} severity`;
      const broaderDocs = await ragDatabase.search(broaderQuery, 8);
      console.log(`📚 Broader RAG Search: ${broaderDocs.length} documents found`);

      if (broaderDocs.length > 0) {
        const broaderContextText = broaderDocs.map((doc, index) =>
          `[General Security Knowledge ${index + 1}] ${doc.metadata.title} (${doc.embeddingType || 'local'} embedding):\n${doc.content.substring(0, 600)}...`
        ).join('\n\n');
        // @ts-ignore
        relevantDocs.push(...broaderDocs);
        ragContext = ragContext === 'No specific security knowledge found in database. Initializing knowledge base for future queries.' ? broaderContextText : ragContext + "\n\n" + broaderContextText;
      }
    }
  }

  const prompt = buildEnhancedAnalysisPrompt(vulnerability, ragContext, relevantDocs.length);

  const requestBody = {
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: {
      temperature: 0.1,
      topK: 1,
      topP: 0.8,
      maxOutputTokens: 8192,
      candidateCount: 1
    }
  };

  const isWebSearchCapable = model.includes('2.0') || model.includes('2.5');
  if (isWebSearchCapable) {
    // @ts-ignore
    requestBody.tools = [{ google_search: {} }];
  }

  const apiUrl = `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${apiKey}`;

  try {
    const response = await APIService.fetchWithFallback(apiUrl, { // APIService.fetchWithFallback might need to be made available if not already
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));

      if (response.status === 429) {
        throw new Error('Gemini API rate limit exceeded. Please wait a few minutes before trying again.');
      }

      if (response.status === 401 || response.status === 403) {
        throw new Error('Invalid Gemini API key. Please check your API key in settings.');
      }

      throw new Error(`Gemini API error: ${response.status} - ${errorData.error?.message || 'Unknown error'}`);
    }

    const data = await response.json();
    const content = data.candidates?.[0]?.content;

    if (!content?.parts?.[0]?.text) {
      throw new Error('Invalid response from Gemini API');
    }

    const analysisText = content.parts[0].text;

    if (!analysisText || analysisText.trim().length === 0) {
      throw new Error('Empty analysis received from Gemini API');
    }

    if (analysisText.length > 500 && ragDatabase && ragDatabase.initialized) {
      await ragDatabase.addDocument(
        `Enhanced CVE Analysis: ${cveId}\n\nCVSS: ${vulnerability.cve.cvssV3?.baseScore || 'N/A'}\nEPSS: ${vulnerability.epss?.epssPercentage || 'N/A'}%\nCISA KEV: ${vulnerability.kev?.listed ? 'Yes' : 'No'}\nValidated: ${vulnerability.validation ? 'Yes' : 'No'}\nConfidence: ${vulnerability.confidence?.overall || 'Unknown'}\n\n${analysisText}`,
        {
          title: `Enhanced RAG Security Analysis - ${cveId}`,
          category: 'enhanced-analysis',
          tags: ['rag-enhanced', 'ai-analysis', 'validated', cveId.toLowerCase(), vulnerability.cve.cvssV3?.baseSeverity?.toLowerCase() || 'unknown'],
          source: 'ai-analysis-rag',
          model: model,
          cveId: cveId
        }
      );
      console.log(`💾 Stored validated analysis for ${cveId} in RAG database for future reference`);
    }

    return {
      analysis: analysisText,
      ragUsed: true,
      ragDocuments: relevantDocs.length,
      ragSources: relevantDocs.map(doc => doc.metadata?.title || 'Unknown').filter(Boolean),
      webGrounded: isWebSearchCapable,
      enhancedSources: vulnerability.enhancedSources || [],
      discoveredSources: vulnerability.discoveredSources || [],
      model: model,
      analysisTimestamp: new Date().toISOString(),
      ragDatabaseSize: ragDatabase ? ragDatabase.documents.length : 0,
      embeddingType: ragDatabase && ragDatabase.geminiApiKey ? 'gemini' : 'local',
      // @ts-ignore
      geminiEmbeddingsCount: ragDatabase ? ragDatabase.documents.filter(d => d.embeddingType === 'gemini').length : 0,
      realTimeData: {
        cisaKev: vulnerability.kev?.listed || false,
        cisaKevValidated: vulnerability.kev?.validated || false,
        exploitsFound: vulnerability.exploits?.count || 0,
        exploitsValidated: vulnerability.exploits?.validated || false,
        exploitConfidence: vulnerability.exploits?.confidence || 'NONE',
        githubRefs: vulnerability.github?.count || 0,
        threatLevel: vulnerability.threatLevel || 'STANDARD',
        overallConfidence: vulnerability.confidence?.overall || 'UNKNOWN',
        hallucinationFlags: vulnerability.hallucinationFlags || []
      },
      validationEnhanced: true,
      confidence: vulnerability.confidence,
      validation: vulnerability.validation
    };

  } catch (error) {
    console.error('Enhanced RAG Analysis Error:', error);
    return generateEnhancedFallbackAnalysis(vulnerability, error);
  }
};

export const buildEnhancedAnalysisPrompt = (vulnerability, ragContext, ragDocCount = 0) => {
  const cveId = vulnerability.cve.id;
  const cvssScore = vulnerability.cve.cvssV3?.baseScore || vulnerability.cve.cvssV2?.baseScore || 'N/A';
  const epssScore = vulnerability.epss ? vulnerability.epss.epssPercentage + '%' : 'N/A';
  const kevStatus = vulnerability.kev?.listed ? 'Yes - ACTIVE EXPLOITATION CONFIRMED' : 'No';
  const kevValidated = vulnerability.kev?.validated ? ' (VALIDATED)' : ' (UNVALIDATED)';
  const confidenceLevel = vulnerability.confidence?.overall || 'UNKNOWN';

  return `You are a senior cybersecurity analyst providing comprehensive vulnerability assessment for ${cveId}.

VULNERABILITY DETAILS:
- CVE ID: ${cveId}
- CVSS Score: ${cvssScore}
- EPSS Score: ${epssScore}
- CISA KEV Status: ${kevStatus}${kevValidated}
- Overall Confidence: ${confidenceLevel}
- Description: ${vulnerability.cve.description.substring(0, 800)}

VALIDATION STATUS:
- Data Validated: ${vulnerability.validation ? 'Yes' : 'No'}
- Confidence Flags: ${vulnerability.confidence?.flags?.join(', ') || 'None'}
- Hallucination Flags: ${vulnerability.hallucinationFlags?.join(', ') || 'None'}

REAL-TIME THREAT INTELLIGENCE:
${vulnerability.kev?.listed ? `⚠️ CRITICAL: This vulnerability is actively exploited according to CISA KEV catalog${kevValidated}.` : ''}
${vulnerability.exploits?.found ? `💣 PUBLIC EXPLOITS: ${vulnerability.exploits.count} exploit(s) found with ${vulnerability.exploits.confidence || 'MEDIUM'} confidence${vulnerability.exploits?.validated ? ' (VALIDATED)' : ' (UNVALIDATED)'}.` : ''}
${vulnerability.github?.found ? `🔍 GITHUB REFS: ${vulnerability.github.count} security-related repositories found.` : ''}
${vulnerability.activeExploitation?.confirmed ? `🚨 ACTIVE EXPLOITATION: Confirmed exploitation in the wild.` : ''}

PATCHES AND ADVISORIES:
${vulnerability.patches?.length ? `🔧 PATCHES FOUND: ${vulnerability.patches.length} patch(es) available from ${[...new Set(vulnerability.patches.map(p => p.vendor))].join(', ')}` : 'No specific patches identified'}
${vulnerability.advisories?.length ? `📋 ADVISORIES: ${vulnerability.advisories.length} security advisory(ies) from ${[...new Set(vulnerability.advisories.map(a => a.source))].join(', ')}` : 'Limited advisory coverage'}

SECURITY KNOWLEDGE BASE (${ragDocCount} relevant documents retrieved):
${ragContext}

DATA SOURCES ANALYZED:
${vulnerability.discoveredSources?.join(', ') || 'NVD, EPSS'}

VALIDATION SUMMARY:
${vulnerability.validation ? `
- CISA KEV Validation: ${vulnerability.validation.cisaKev?.verified ? 'VERIFIED' : 'UNVERIFIED'}
- Exploit Validation: ${vulnerability.validation.exploits?.verified ? 'VERIFIED' : 'UNVERIFIED'}
- Vendor Advisory Validation: ${vulnerability.validation.vendorAdvisories?.verified ? 'VERIFIED' : 'UNVERIFIED'}
- Overall Validation Confidence: ${vulnerability.validation.confidence}
` : 'No validation performed'}

You have access to ${ragDocCount} relevant security documents from the knowledge base. Use this contextual information to provide enhanced insights beyond standard vulnerability analysis.

ANALYSIS REQUIREMENTS:
1. **Clearly distinguish between validated and unvalidated claims**
2. **Highlight confidence levels for all findings**
3. **Note any hallucination flags or inconsistencies**
4. **Prioritize validated information over AI-generated content**
5. **Provide actionable recommendations based on confidence levels**
6. **Include patch and advisory information in recommendations**

Provide a comprehensive vulnerability analysis including:
1. Executive Summary with immediate actions needed (noting confidence levels)
2. Technical details and attack vectors (validated vs unvalidated)
3. Impact assessment and potential consequences
4. Patch availability and vendor advisory status
5. Mitigation strategies and remediation guidance
6. Affected systems and software components
7. Current exploitation status and threat landscape (with validation status)
8. Priority recommendations based on validated threat intelligence
9. Lessons learned from similar vulnerabilities (use knowledge base context)
10. Data quality assessment and recommendation reliability

Format your response in clear sections with detailed analysis. Leverage the security knowledge base context and validated threat intelligence to provide enhanced insights that go beyond basic CVE information.

${vulnerability.kev?.listed ? `EMPHASIZE THE CRITICAL NATURE DUE TO ${vulnerability.kev?.validated ? 'VALIDATED' : 'UNVALIDATED'} ACTIVE EXPLOITATION CLAIMS.` : ''}
${vulnerability.exploits?.found && vulnerability.exploits.confidence === 'HIGH' ? `HIGHLIGHT THE AVAILABILITY OF ${vulnerability.exploits?.validated ? 'VALIDATED' : 'UNVALIDATED'} PUBLIC EXPLOITS.` : ''}

**Important Guidelines**:
- Reference insights from the security knowledge base when relevant
- Clearly mark validated vs unvalidated information with confidence indicators
- DO NOT include citation numbers like [1], [2], [3] or any bracketed numbers
- Write in clear, natural language without citation markers
- Always note the reliability of each piece of information
- Provide specific recommendations for low-confidence findings
- Include patch and advisory information where applicable`;
};

export const generateEnhancedFallbackAnalysis = (vulnerability, error) => {
  const cveId = vulnerability.cve.id;
  const cvssScore = vulnerability.cve.cvssV3?.baseScore || vulnerability.cve.cvssV2?.baseScore || 'N/A';
  const epssScore = vulnerability.epss ? vulnerability.epss.epssPercentage + '%' : 'N/A';
  const kevStatus = vulnerability.kev?.listed ? 'Yes - ACTIVE EXPLOITATION CONFIRMED' : 'No';
  const kevValidated = vulnerability.kev?.validated ? ' (VALIDATED)' : ' (UNVALIDATED)';
  const confidenceLevel = vulnerability.confidence?.overall || 'UNKNOWN';

  return {
    analysis: `# Enhanced Security Analysis: ${cveId}

## Executive Summary
${kevStatus.includes('Yes') ? `🚨 **CRITICAL PRIORITY** - This vulnerability is actively exploited according to CISA KEV catalog${kevValidated}. ${vulnerability.kev?.validated ? 'This has been verified against official CISA data.' : 'This claim requires manual verification.'}` :
vulnerability.exploits?.found ? `💣 **HIGH RISK** - ${vulnerability.exploits.count} exploit(s) detected with ${vulnerability.exploits.confidence} confidence level${vulnerability.exploits?.validated ? ' (VALIDATED)' : ' (UNVALIDATED)'}.` :
`This vulnerability has a CVSS score of ${cvssScore} with an EPSS exploitation probability of ${epssScore}.`}

**Overall Confidence Level:** ${confidenceLevel}
${vulnerability.confidence?.recommendation ? `**Recommendation:** ${vulnerability.confidence.recommendation}` : ''}

${vulnerability.exploits?.found ? `💣 **PUBLIC EXPLOITS AVAILABLE** - ${vulnerability.exploits.count} exploit(s) detected with ${vulnerability.exploits.confidence} confidence level${vulnerability.exploits?.validated ? ' (URL patterns verified)' : ' (requires manual verification)'}.` : ''}

## Vulnerability Details
**CVE ID:** ${cveId}
**CVSS Score:** ${cvssScore}
**EPSS Score:** ${epssScore}
**CISA KEV Status:** ${kevStatus}${kevValidated}

**Description:** ${vulnerability.cve.description}

## Patches and Advisories
${vulnerability.patches?.length ? `**Available Patches:** ${vulnerability.patches.length} patch(es) identified
${vulnerability.patches.map(p => `- ${p.vendor} ${p.patchType}: ${p.description}`).join('\n')}` : 'No specific patches identified through automated search'}

${vulnerability.advisories?.length ? `**Security Advisories:** ${vulnerability.advisories.length} advisory(ies) found
${vulnerability.advisories.slice(0, 5).map(a => `- ${a.source}: ${a.title || a.description}`).join('\n')}` : 'Limited security advisory coverage found'}

## Data Quality Assessment
**Validation Status:** ${vulnerability.validation ? 'Performed' : 'Not performed'}
${vulnerability.validation ? `
- **CISA KEV Validation:** ${vulnerability.validation.cisaKev?.verified ? '✅ VERIFIED' : '❌ UNVERIFIED'}
- **Exploit Validation:** ${vulnerability.validation.exploits?.verified ? '✅ VERIFIED' : '❌ UNVERIFIED'}
- **Vendor Advisory Validation:** ${vulnerability.validation.vendorAdvisories?.verified ? '✅ VERIFIED' : '❌ UNVERIFIED'}
- **Overall Validation Confidence:** ${vulnerability.validation.confidence}
` : ''}

**Confidence Flags:** ${vulnerability.confidence?.flags?.join(', ') || 'None detected'}
**Hallucination Flags:** ${vulnerability.hallucinationFlags?.join(', ') || 'None detected'}

## Real-Time Threat Intelligence Summary
${vulnerability.kev?.listed ? `- ⚠️ **ACTIVE EXPLOITATION**: ${vulnerability.kev?.validated ? 'VERIFIED' : 'UNVERIFIED'} - ${vulnerability.kev?.validated ? 'Confirmed in CISA Known Exploited Vulnerabilities catalog' : 'Claimed in AI analysis but not validated'}` : '- No confirmed active exploitation in CISA KEV catalog'}
${vulnerability.exploits?.found ? `- 💣 **PUBLIC EXPLOITS**: ${vulnerability.exploits?.validated ? 'VERIFIED' : 'UNVERIFIED'} - ${vulnerability.exploits.count} exploit(s) with ${vulnerability.exploits.confidence} confidence` : '- No high-confidence public exploits identified'}
${vulnerability.github?.found ? `- 🔍 **SECURITY COVERAGE**: ${vulnerability.github.count} GitHub security references found` : '- Limited GitHub security advisory coverage'}
${vulnerability.activeExploitation?.confirmed ? '- 🚨 **ACTIVE EXPLOITATION**: Confirmed exploitation detected in threat intelligence' : '- No confirmed active exploitation detected'}

## Risk Assessment
**Exploitation Probability:** ${epssScore} (EPSS)
**Attack Vector:** ${vulnerability.cve.cvssV3?.attackVector || 'Unknown'}
**Attack Complexity:** ${vulnerability.cve.cvssV3?.attackComplexity || 'Unknown'}
**Privileges Required:** ${vulnerability.cve.cvssV3?.privilegesRequired || 'Unknown'}
**Impact Level:** ${vulnerability.cve.cvssV3?.baseSeverity || 'Unknown'}

## Validation-Based Recommendations

### Immediate Actions
1. **${kevStatus.includes('Yes') ? (vulnerability.kev?.validated ? 'URGENT: Apply patches immediately - KEV status verified' : 'VERIFY KEV STATUS: Check CISA catalog directly before emergency actions') : 'Review and prioritize patching based on CVSS score and environment exposure'}**

2. **${vulnerability.exploits?.found ? (vulnerability.exploits?.validated ? 'Implement additional monitoring - verified public exploits available' : 'Verify exploit availability through security research before implementing emergency controls') : 'Monitor for unusual activity patterns'}**

3. **Review access controls and authentication mechanisms**

4. **${vulnerability.kev?.listed ? (vulnerability.kev?.validated ? 'Follow CISA emergency directive timelines' : 'Manually verify CISA KEV status before following emergency timelines') : 'Consider temporary compensating controls if patches unavailable'}**

### Patch Management
${vulnerability.patches?.length ? `**Available Patches:**
${vulnerability.patches.slice(0, 3).map(p => `- **${p.vendor}**: ${p.description} (Confidence: ${p.confidence})`).join('\n')}
${vulnerability.patches.length > 3 ? `- *... and ${vulnerability.patches.length - 3} additional patch sources*` : ''}

**Patch Priority:** ${vulnerability.kev?.listed ? 'CRITICAL - Emergency deployment' : vulnerability.exploits?.found ? 'HIGH - Expedited testing and deployment' : 'STANDARD - Normal patch cycle'}` : `**Patch Status:** No specific patches identified through automated search
- Check vendor security advisories manually
- Review CVE references for patch information
- Monitor vendor security bulletins for updates`}

### Data Quality Actions
${vulnerability.confidence?.overall === 'LOW' || vulnerability.confidence?.overall === 'VERY_LOW' ? `
**⚠️ LOW CONFIDENCE DATA DETECTED**
- Manually verify all AI-generated findings before taking action
- Cross-reference with official security advisories
- Consider requesting additional threat intelligence sources
` : ''}

${vulnerability.validation?.cisaKev && !vulnerability.validation.cisaKev.verified ? `
**❌ CISA KEV VALIDATION FAILED**
- AI claimed KEV listing but validation failed
- Manually check CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Do not follow emergency KEV procedures until verified
` : ''}

${vulnerability.validation?.exploits && !vulnerability.validation.exploits.verified ? `
**❌ EXPLOIT VALIDATION FAILED**
- AI claimed ${vulnerability.exploits?.count || 0} exploits but validation failed
- Manually verify through security research and trusted sources
- Do not implement emergency monitoring based on unverified exploit claims
` : ''}

## Mitigation Strategies
- **Patch Management**: ${kevStatus.includes('Yes') ? (vulnerability.kev?.validated ? 'Emergency patching within CISA timeline' : 'Verify KEV status before emergency patching') : 'Standard patch testing and deployment'}
- **Network Controls**: Implement input validation and filtering
- **Access Controls**: Review and restrict privileged access
- **Monitoring**: Deploy detection rules for exploitation attempts

## Data Sources Analyzed
${vulnerability.discoveredSources?.join(', ') || 'NVD, EPSS'} (${vulnerability.discoveredSources?.length || 2} sources)

## Intelligence Assessment
- **Data Freshness**: Real-time (${new Date().toLocaleString()})
- **Confidence Level**: ${vulnerability.confidence?.overall || 'UNKNOWN'} based on validation results
- **Validation Performed**: ${vulnerability.validation ? 'Yes' : 'No'}
- **Threat Landscape**: ${vulnerability.threatLevel || 'STANDARD'} risk environment
- **AI Enhancement**: ${vulnerability.extractionMetadata ? 'Extractive approach used' : 'Standard AI approach'}

## Verification Recommendations
${vulnerability.confidence?.recommendations ? vulnerability.confidence.recommendations.map(rec => `- ${rec}`).join('\n') : 'No specific verification recommendations available'}

**⚠️ Important Disclaimer:** This analysis includes AI-generated findings. ${vulnerability.validation ? `Validation was performed with ${vulnerability.validation.confidence} confidence.` : 'No validation was performed.'} Always verify critical security decisions with official sources.

*Enhanced analysis with validation layer. AI service temporarily unavailable due to: ${error.message}*`,
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
};
