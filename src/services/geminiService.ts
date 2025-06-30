import { CONSTANTS } from '../utils/constants';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { APIService } from './APIService'; // For fetchWithFallback

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

  await ragDatabase.ensureInitialized(apiKey);
  console.log(`📊 RAG Database Status: ${ragDatabase.documents.length} documents available (${ragDatabase.geminiApiKey ? 'Gemini embeddings' : 'local embeddings'})`);

  const cveId = vulnerability.cve.id;
  const ragQuery = `${cveId} ${vulnerability.cve.description.substring(0, 200)} vulnerability analysis security impact mitigation threat intelligence EPSS ${vulnerability.epss?.epssPercentage || 'N/A'} CVSS ${vulnerability.cve.cvssV3?.baseScore || 'N/A'} ${vulnerability.kev?.listed ? 'CISA KEV active exploitation' : ''}`;

  console.log(`🔍 RAG Query: "${ragQuery.substring(0, 100)}..."`);
  const relevantDocs = await ragDatabase.search(ragQuery, 15);
  console.log(`📚 RAG Retrieved: ${relevantDocs.length} relevant documents (${relevantDocs.filter(d => d.embeddingType === 'gemini').length} with Gemini embeddings)`);

  let ragContext = relevantDocs.length > 0 ?
    relevantDocs.map((doc, index) =>
      `[Security Knowledge ${index + 1}] ${doc.metadata.title} (Relevance: ${(doc.similarity * 100).toFixed(1)}%, ${doc.embeddingType || 'local'} embedding):\n${doc.content.substring(0, 800)}...`
    ).join('\n\n') :
    'No specific security knowledge found in database. Initializing knowledge base for future queries.';

  if (relevantDocs.length === 0) {
    console.log('🔄 No specific matches found, trying broader search...');
    const broaderQuery = `vulnerability security analysis ${vulnerability.cve.cvssV3?.baseSeverity || 'unknown'} severity`;
    const broaderDocs = await ragDatabase.search(broaderQuery, 8);
    console.log(`📚 Broader RAG Search: ${broaderDocs.length} documents found`);

    if (broaderDocs.length > 0) {
      const broaderContext = broaderDocs.map((doc, index) =>
        `[General Security Knowledge ${index + 1}] ${doc.metadata.title} (${doc.embeddingType || 'local'} embedding):\n${doc.content.substring(0, 600)}...`
      ).join('\n\n');
      // @ts-ignore
      relevantDocs.push(...broaderDocs); // Add to existing relevantDocs for metadata
      ragContext += "\n\n" + broaderContext; // Append to ragContext
    }
  }

  const prompt = buildEnhancedAnalysisPrompt(vulnerability, ragContext, relevantDocs.length);

  const requestBody = {
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: { temperature: 0.1, topK: 1, topP: 0.8, maxOutputTokens: 8192, candidateCount: 1 }
  };

  const isWebSearchCapable = model.includes('2.0') || model.includes('2.5');
  if (isWebSearchCapable) {
    // @ts-ignore
    requestBody.tools = [{ google_search: {} }];
  }

  const apiUrl = `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${apiKey}`;

  try {
    const response = await APIService.fetchWithFallback(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      if (response.status === 429) throw new Error('Gemini API rate limit exceeded. Please wait a few minutes before trying again.');
      if (response.status === 401 || response.status === 403) throw new Error('Invalid Gemini API key. Please check your API key in settings.');
      throw new Error(`Gemini API error: ${response.status} - ${errorData.error?.message || 'Unknown error'}`);
    }

    const data = await response.json();
    const content = data.candidates?.[0]?.content;
    if (!content?.parts?.[0]?.text) throw new Error('Invalid response from Gemini API');

    const analysisText = content.parts[0].text;
    if (!analysisText || analysisText.trim().length === 0) throw new Error('Empty analysis received from Gemini API');

    if (analysisText.length > 500) {
      await ragDatabase.addDocument(
        `Enhanced CVE Analysis: ${cveId}\n\nCVSS: ${vulnerability.cve.cvssV3?.baseScore || 'N/A'}\nEPSS: ${vulnerability.epss?.epssPercentage || 'N/A'}%\nCISA KEV: ${vulnerability.kev?.listed ? 'Yes' : 'No'}\n\n${analysisText}`,
        { title: `Enhanced RAG Security Analysis - ${cveId}`, category: 'enhanced-analysis', tags: ['rag-enhanced', 'ai-analysis', cveId.toLowerCase(), vulnerability.cve.cvssV3?.baseSeverity?.toLowerCase() || 'unknown'], source: 'ai-analysis-rag', model: model, cveId: cveId }
      );
      console.log(`💾 Stored analysis for ${cveId} in RAG database for future reference`);
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
      ragDatabaseSize: ragDatabase.documents.length,
      embeddingType: ragDatabase.geminiApiKey ? 'gemini' : 'local',
      geminiEmbeddingsCount: ragDatabase.documents.filter(d => d.embeddingType === 'gemini').length,
      realTimeData: {
        cisaKev: vulnerability.kev?.listed || false,
        exploitsFound: vulnerability.exploits?.count || 0,
        exploitConfidence: vulnerability.exploits?.confidence || 'NONE',
        githubRefs: vulnerability.github?.count || 0,
        threatLevel: vulnerability.threatLevel || 'STANDARD',
        // @ts-ignore
        heuristicRisk: vulnerability.kev?.heuristicHighRisk || false
      }
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

  return `You are a senior cybersecurity analyst providing comprehensive vulnerability assessment for ${cveId}.

VULNERABILITY DETAILS:
- CVE ID: ${cveId}
- CVSS Score: ${cvssScore}
- EPSS Score: ${epssScore}
- CISA KEV Status: ${kevStatus}
- Description: ${vulnerability.cve.description.substring(0, 800)}

REAL-TIME THREAT INTELLIGENCE:
${vulnerability.kev?.listed ? `⚠️ CRITICAL: This vulnerability is actively exploited according to CISA KEV catalog.` : ''}
${vulnerability.exploits?.found ? `💣 PUBLIC EXPLOITS: ${vulnerability.exploits.count} exploit(s) found with ${vulnerability.exploits.confidence || 'MEDIUM'} confidence.` : ''}
${vulnerability.github?.found ? `🔍 GITHUB REFS: ${vulnerability.github.count} security-related repositories found.` : ''}
${vulnerability.activeExploitation?.confirmed ? `🚨 ACTIVE EXPLOITATION: Confirmed exploitation in the wild.` : ''}

SECURITY KNOWLEDGE BASE (${ragDocCount} relevant documents retrieved):
${ragContext}

DATA SOURCES ANALYZED:
${vulnerability.discoveredSources?.join(', ') || 'NVD, EPSS'}

You have access to ${ragDocCount} relevant security documents from the knowledge base. Use this contextual information to provide enhanced insights beyond standard vulnerability analysis.

Provide a comprehensive vulnerability analysis including:
1. Executive Summary with immediate actions needed
2. Technical details and attack vectors
3. Impact assessment and potential consequences
4. Mitigation strategies and remediation guidance
5. Affected systems and software components
6. Current exploitation status and threat landscape
7. Priority recommendations based on real-time threat intelligence
8. Lessons learned from similar vulnerabilities (use knowledge base context)

Format your response in clear sections with detailed analysis. Leverage the security knowledge base context and real-time threat intelligence to provide enhanced insights that go beyond basic CVE information.

${vulnerability.kev?.listed ? 'EMPHASIZE THE CRITICAL NATURE DUE TO CONFIRMED ACTIVE EXPLOITATION.' : ''}
${vulnerability.exploits?.found && vulnerability.exploits.confidence === 'HIGH' ? 'HIGHLIGHT THE AVAILABILITY OF PUBLIC EXPLOITS.' : ''}

**Important**:
- Reference insights from the security knowledge base when relevant to demonstrate enhanced RAG-powered analysis.
- DO NOT include citation numbers like [1], [2], [3] or any bracketed numbers in your response.
- Write in clear, natural language without any citation markers.`;
};

export const generateEnhancedFallbackAnalysis = (vulnerability, error) => {
  const cveId = vulnerability.cve.id;
  const cvssScore = vulnerability.cve.cvssV3?.baseScore || vulnerability.cve.cvssV2?.baseScore || 'N/A';
  const epssScore = vulnerability.epss ? vulnerability.epss.epssPercentage + '%' : 'N/A';
  const kevStatus = vulnerability.kev?.listed ? 'Yes - ACTIVE EXPLOITATION CONFIRMED' : 'No';

  return {
    analysis: `# Security Analysis: ${cveId}

## Executive Summary
${kevStatus.includes('Yes') ? '🚨 **CRITICAL PRIORITY** - This vulnerability is actively exploited according to CISA KEV catalog. Immediate patching required.' :
vulnerability.exploits?.found ? `💣 **HIGH RISK** - ${vulnerability.exploits.count} exploit(s) detected with ${vulnerability.exploits.confidence} confidence level.` :
`This vulnerability has a CVSS score of ${cvssScore} with an EPSS exploitation probability of ${epssScore}.`}

${vulnerability.exploits?.found ? `💣 **PUBLIC EXPLOITS AVAILABLE** - ${vulnerability.exploits.count} exploit(s) detected with ${vulnerability.exploits.confidence} confidence level.` : ''}

## Vulnerability Details
**CVE ID:** ${cveId}
**CVSS Score:** ${cvssScore}
**EPSS Score:** ${epssScore}
**CISA KEV Status:** ${kevStatus}

**Description:** ${vulnerability.cve.description}

## Real-Time Threat Intelligence Summary
${vulnerability.kev?.listed ? '- ⚠️ **ACTIVE EXPLOITATION**: Confirmed in CISA Known Exploited Vulnerabilities catalog' : '- No confirmed active exploitation in CISA KEV catalog'}
${vulnerability.exploits?.found ? `- 💣 **PUBLIC EXPLOITS**: ${vulnerability.exploits.count} exploit(s) with ${vulnerability.exploits.confidence} confidence` : '- No high-confidence public exploits identified'}
${vulnerability.github?.found ? `- 🔍 **SECURITY COVERAGE**: ${vulnerability.github.count} GitHub security references found` : '- Limited GitHub security advisory coverage'}
${vulnerability.activeExploitation?.confirmed ? '- 🚨 **ACTIVE EXPLOITATION**: Confirmed exploitation detected in threat intelligence' : '- No confirmed active exploitation detected'}

## Risk Assessment
**Exploitation Probability:** ${epssScore} (EPSS)
**Attack Vector:** ${vulnerability.cve.cvssV3?.attackVector || 'Unknown'}
**Attack Complexity:** ${vulnerability.cve.cvssV3?.attackComplexity || 'Unknown'}
**Privileges Required:** ${vulnerability.cve.cvssV3?.privilegesRequired || 'Unknown'}
**Impact Level:** ${vulnerability.cve.cvssV3?.baseSeverity || 'Unknown'}

## Immediate Actions Required
1. ${kevStatus.includes('Yes') || vulnerability.exploits?.found ?
 'URGENT: Apply patches immediately - high exploitation risk confirmed' :
 'Review and prioritize patching based on CVSS score and environment exposure'}
2. ${vulnerability.exploits?.found ? 'Implement additional monitoring - public exploits available' : 'Monitor for unusual activity patterns'}
3. Review access controls and authentication mechanisms
4. ${vulnerability.kev?.listed ? 'Follow CISA emergency directive timelines' : 'Consider temporary compensating controls if patches unavailable'}

## Mitigation Strategies
- **Patch Management**: ${kevStatus.includes('Yes') ? 'Emergency patching within CISA timeline' : 'Standard patch testing and deployment'}
- **Network Controls**: Implement input validation and filtering
- **Access Controls**: Review and restrict privileged access
- **Monitoring**: Deploy detection rules for exploitation attempts

## Data Sources Analyzed
${vulnerability.discoveredSources?.join(', ') || 'NVD, EPSS'} (${vulnerability.discoveredSources?.length || 2} sources)

## Intelligence Assessment
- **Data Freshness**: Real-time (${new Date().toLocaleString()})
- **Confidence Level**: ${vulnerability.exploits?.confidence || 'MEDIUM'} based on multiple source correlation
- **Threat Landscape**: ${vulnerability.threatLevel || 'STANDARD'} risk environment

*Analysis generated using real-time threat intelligence. Enhanced AI service temporarily unavailable due to: ${error.message}*`,
    ragUsed: false,
    ragDocuments: 0,
    ragSources: [],
    webGrounded: false,
    enhancedSources: vulnerability.enhancedSources || [],
    discoveredSources: vulnerability.discoveredSources || [],
    error: error.message,
    fallbackUsed: true,
    realTimeData: {
      cisaKev: vulnerability.kev?.listed || false,
      exploitsFound: vulnerability.exploits?.count || 0,
      exploitConfidence: vulnerability.exploits?.confidence || 'NONE',
      githubRefs: vulnerability.github?.count || 0,
      threatLevel: vulnerability.threatLevel || 'STANDARD',
      activeExploitation: vulnerability.activeExploitation?.confirmed || false
    }
  };
};
