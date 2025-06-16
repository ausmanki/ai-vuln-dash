import React, { useState, createContext, useContext, useEffect } from 'react';
import { Search, Shield, AlertTriangle, Loader2, ExternalLink, Brain, Settings, Target, Clock, Database, Activity, CheckCircle, XCircle, X, Upload, Filter, PieChart, Sun, Moon, Eye, EyeOff, Save, FileText, Wifi, WifiOff } from 'lucide-react';
import { PieChart as RechartsPieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

// RAG Vector Database Implementation
class VectorDatabase {
  constructor() {
    this.documents = [];
    this.embeddings = [];
    this.initialized = false;
  }

  async createEmbedding(text) {
    const words = text.toLowerCase().split(/\W+/).filter(w => w.length > 2);
    const wordFreq = {};
    words.forEach(word => {
      wordFreq[word] = (wordFreq[word] || 0) + 1;
    });
    
    const vocabulary = Object.keys(wordFreq);
    const vector = vocabulary.slice(0, 50).map(word => wordFreq[word] || 0);
    
    const magnitude = Math.sqrt(vector.reduce((sum, val) => sum + val * val, 0));
    return magnitude > 0 ? vector.map(val => val / magnitude) : vector;
  }

  cosineSimilarity(vec1, vec2) {
    if (vec1.length !== vec2.length) return 0;
    
    let dotProduct = 0;
    let norm1 = 0;
    let norm2 = 0;
    
    for (let i = 0; i < vec1.length; i++) {
      dotProduct += vec1[i] * vec2[i];
      norm1 += vec1[i] * vec1[i];
      norm2 += vec2[i] * vec2[i];
    }
    
    return dotProduct / (Math.sqrt(norm1) * Math.sqrt(norm2));
  }

  async addDocument(content, metadata = {}) {
    const embedding = await this.createEmbedding(content);
    const doc = {
      id: Date.now() + Math.random(),
      content,
      metadata,
      embedding,
      timestamp: new Date().toISOString()
    };
    
    this.documents.push(doc);
    console.log('📚 Added document to RAG database:', metadata.title || 'Untitled');
    return doc.id;
  }

  async search(query, k = 5) {
    if (this.documents.length === 0) {
      console.warn('⚠️ RAG database is empty');
      return [];
    }

    const queryEmbedding = await this.createEmbedding(query);
    
    const similarities = this.documents.map(doc => ({
      ...doc,
      similarity: this.cosineSimilarity(queryEmbedding, doc.embedding)
    }));
    
    const results = similarities
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, k)
      .filter(doc => doc.similarity > 0.1);
    
    console.log(`🔍 RAG search for "${query}" found ${results.length} relevant documents`);
    return results;
  }

  async initialize() {
    if (this.initialized) return;

    console.log('🚀 Initializing RAG Vector Database...');
    await this.addSecurityKnowledgeBase();
    this.initialized = true;
    console.log(`✅ RAG database initialized with ${this.documents.length} documents`);
  }

  async addSecurityKnowledgeBase() {
    const knowledgeBase = [
      {
        title: "CVSS Scoring Guidelines",
        content: `CVSS (Common Vulnerability Scoring System) provides a standardized method for rating IT vulnerabilities:
        
        CVSS v3.1 Base Score Ranges:
        - Critical (9.0-10.0): Vulnerabilities with severe impact, easy exploitation, widespread applicability
        - High (7.0-8.9): Significant security impact, exploitation may be difficult but possible
        - Medium (4.0-6.9): Moderate impact, may require specific conditions for exploitation
        - Low (0.1-3.9): Minimal impact, exploitation is difficult or has limited effect
        
        Key Metrics:
        - Attack Vector: Network, Adjacent, Local, Physical
        - Attack Complexity: Low, High
        - Privileges Required: None, Low, High
        - User Interaction: None, Required
        - Scope: Unchanged, Changed
        - Impact: Confidentiality, Integrity, Availability`,
        category: "scoring",
        tags: ["cvss", "scoring", "risk-assessment"]
      },
      {
        title: "EPSS Interpretation Guide",
        content: `EPSS (Exploit Prediction Scoring System) predicts the probability of exploitation:
        
        EPSS Score Interpretation:
        - >70%: Very High probability of exploitation within 30 days
        - 50-70%: High probability, prioritize for immediate patching
        - 20-50%: Moderate probability, patch within normal cycle
        - 10-20%: Low probability, monitor and plan patching
        - <10%: Very low probability, standard patching timeline
        
        EPSS considers:
        - Known exploits in the wild
        - Proof-of-concept availability
        - Vulnerability age and disclosure
        - Technical characteristics
        - Social media discussions`,
        category: "threat-intelligence",
        tags: ["epss", "exploitation", "probability"]
      }
    ];

    for (const item of knowledgeBase) {
      await this.addDocument(item.content, {
        title: item.title,
        category: item.category,
        tags: item.tags,
        source: 'knowledge-base'
      });
    }
  }

  getStats() {
    const categories = {};
    this.documents.forEach(doc => {
      const category = doc.metadata.category || 'uncategorized';
      categories[category] = (categories[category] || 0) + 1;
    });

    return {
      totalDocuments: this.documents.length,
      categories,
      initialized: this.initialized
    };
  }
}

// Global RAG instance
const ragDatabase = new VectorDatabase();

const getStyles = (darkMode) => ({
  appContainer: { minHeight: '100vh', backgroundColor: darkMode ? '#0f172a' : '#f8fafc' },
  header: { 
    background: darkMode 
      ? 'linear-gradient(135deg, #1e293b 0%, #334155 100%)' 
      : 'linear-gradient(135deg, #1e40af 0%, #3730a3 100%)', 
    color: 'white', 
    boxShadow: '0 4px 20px rgba(0, 0, 0, 0.1)'
  },
  headerContent: { maxWidth: '1440px', margin: '0 auto', padding: '24px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' },
  headerTitle: { display: 'flex', alignItems: 'center', gap: '16px' },
  title: { fontSize: '1.5rem', fontWeight: '600', margin: 0 },
  subtitle: { fontSize: '0.8rem', opacity: 0.8, margin: 0 },
  headerActions: { display: 'flex', alignItems: 'center', gap: '16px' },
  statusIndicator: { 
    display: 'flex', 
    alignItems: 'center', 
    gap: '6px', 
    fontSize: '0.75rem', 
    padding: '6px 12px', 
    background: 'rgba(255, 255, 255, 0.2)', 
    borderRadius: '6px', 
    border: '1px solid rgba(255, 255, 255, 0.3)' 
  },
  mainContent: { maxWidth: '1440px', margin: '0 auto', padding: '32px 16px' },
  card: { 
    background: darkMode ? '#1e293b' : '#ffffff', 
    borderRadius: '12px', 
    boxShadow: '0 4px 20px rgba(0, 0, 0, 0.08)', 
    border: darkMode ? '1px solid #334155' : '1px solid #e2e8f0', 
    padding: '24px', 
    marginBottom: '16px', 
    color: darkMode ? '#e2e8f0' : '#1e293b' 
  },
  button: { display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 16px', borderRadius: '8px', fontWeight: '500', cursor: 'pointer', border: '1px solid', fontSize: '0.875rem' },
  buttonPrimary: { 
    background: '#2563eb', 
    color: 'white', 
    borderColor: '#2563eb' 
  },
  buttonSecondary: { 
    background: darkMode ? '#475569' : '#ffffff', 
    color: darkMode ? '#f1f5f9' : '#374151', 
    borderColor: darkMode ? '#64748b' : '#d1d5db' 
  },
  searchContainer: { 
    marginBottom: '32px', 
    background: darkMode ? '#1e293b' : '#ffffff', 
    borderRadius: '12px', 
    padding: '24px', 
    boxShadow: '0 4px 20px rgba(0, 0, 0, 0.08)', 
    border: darkMode ? '1px solid #334155' : '1px solid #e2e8f0' 
  },
  searchWrapper: { position: 'relative', marginBottom: '16px' },
  searchInput: { 
    width: '100%', 
    padding: '12px 12px 12px 40px', 
    border: darkMode ? '1px solid #64748b' : '1px solid #d1d5db', 
    borderRadius: '8px', 
    fontSize: '1rem', 
    outline: 'none', 
    boxSizing: 'border-box', 
    background: darkMode ? '#1e293b' : '#ffffff', 
    color: darkMode ? '#f1f5f9' : '#1f2937'
  },
  searchIcon: { position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: darkMode ? '#cbd5e1' : '#6b7280' },
  searchButton: { position: 'absolute', right: '8px', top: '50%', transform: 'translateY(-50%)' },
  filterPanel: { 
    display: 'grid', 
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
    gap: '16px', 
    marginTop: '16px', 
    padding: '16px', 
    background: darkMode ? '#0f172a' : '#f9fafb', 
    borderRadius: '8px', 
    border: darkMode ? '1px solid #334155' : '1px solid #e5e7eb' 
  },
  filterGroup: { display: 'flex', flexDirection: 'column', gap: '4px' },
  dashboardGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '24px', marginBottom: '32px' },
  chartContainer: { 
    background: darkMode ? '#1e293b' : '#ffffff', 
    borderRadius: '12px', 
    padding: '24px', 
    boxShadow: '0 4px 20px rgba(0, 0, 0, 0.08)',
    border: darkMode ? '1px solid #334155' : '1px solid #e2e8f0'
  },
  notification: { 
    position: 'fixed', 
    top: '24px', 
    right: '24px', 
    background: darkMode ? '#1e293b' : '#ffffff', 
    borderRadius: '8px', 
    padding: '16px', 
    boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)', 
    zIndex: 1000, 
    maxWidth: '400px', 
    border: darkMode ? '1px solid #334155' : '1px solid #e5e7eb' 
  },
  notificationSuccess: { borderLeft: '4px solid #10b981' },
  notificationError: { borderLeft: '4px solid #ef4444' },
  notificationWarning: { borderLeft: '4px solid #f59e0b' },
  badge: { padding: '4px 12px', borderRadius: '9999px', fontSize: '0.75rem', fontWeight: '500', border: '1px solid', display: 'inline-block' },
  badgeCritical: { background: '#fef2f2', color: '#991b1b', borderColor: '#fecaca' },
  badgeHigh: { background: '#fff7ed', color: '#c2410c', borderColor: '#fed7aa' },
  badgeMedium: { background: '#fefce8', color: '#a16207', borderColor: '#fde68a' },
  badgeLow: { background: '#f0fdf4', color: '#166534', borderColor: '#bbf7d0' },
  loadingContainer: { display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '48px 0' },
  emptyState: { textAlign: 'center', padding: '48px 0', color: darkMode ? '#94a3b8' : '#6b7280' },
  modal: { position: 'fixed', inset: 0, background: 'rgba(0, 0, 0, 0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50 },
  modalContent: { 
    background: darkMode ? '#1e293b' : '#ffffff', 
    borderRadius: '12px', 
    padding: '24px', 
    width: '100%', 
    maxWidth: '800px', 
    maxHeight: '90vh', 
    overflowY: 'auto', 
    margin: '16px',
    border: darkMode ? '1px solid #334155' : 'none'
  },
  modalHeader: { 
    display: 'flex', 
    alignItems: 'center', 
    justifyContent: 'space-between', 
    marginBottom: '24px', 
    paddingBottom: '16px', 
    borderBottom: darkMode ? '1px solid #334155' : '1px solid #e5e7eb' 
  },
  modalTitle: { fontSize: '1.25rem', fontWeight: '700', margin: 0, color: darkMode ? '#e2e8f0' : '#1f2937' },
  formGroup: { marginBottom: '16px' },
  label: { 
    display: 'block', 
    fontSize: '0.875rem', 
    fontWeight: '500', 
    color: darkMode ? '#e2e8f0' : '#374151', 
    marginBottom: '4px' 
  },
  input: { 
    width: '100%', 
    padding: '8px 12px', 
    border: darkMode ? '1px solid #64748b' : '1px solid #d1d5db', 
    borderRadius: '6px', 
    fontSize: '0.875rem', 
    outline: 'none', 
    boxSizing: 'border-box',
    background: darkMode ? '#1e293b' : '#ffffff',
    color: darkMode ? '#f1f5f9' : '#1f2937'
  },
  select: { 
    width: '100%', 
    padding: '8px 12px', 
    border: darkMode ? '1px solid #64748b' : '1px solid #d1d5db', 
    borderRadius: '6px', 
    fontSize: '0.875rem', 
    outline: 'none', 
    background: darkMode ? '#1e293b' : '#ffffff', 
    boxSizing: 'border-box',
    color: darkMode ? '#f1f5f9' : '#1f2937'
  },
  linkButton: { display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '4px 8px', background: '#3b82f6', color: 'white', textDecoration: 'none', borderRadius: '4px', fontSize: '0.75rem', fontWeight: '500', border: 'none', cursor: 'pointer' }
});

const AppContext = createContext({});

// Utility functions
const calculateOverallRiskScore = (cveData, epssData, kevData) => {
  let score = 0;
  if (cveData.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore) {
    score += cveData.metrics.cvssMetricV31[0].cvssData.baseScore;
  } else if (cveData.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore) {
    score += cveData.metrics.cvssMetricV30[0].cvssData.baseScore;
  } else if (cveData.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore) {
    score += cveData.metrics.cvssMetricV2[0].cvssData.baseScore;
  }
  if (epssData?.epss) {
    score += epssData.epss * 10;
  }
  if (kevData) {
    score += 3;
  }
  return Math.min(score / 2, 10);
};

const calculatePriority = (cveData, epssData, kevData) => {
  if (kevData) return 'CRITICAL';
  const cvssScore = cveData.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                   cveData.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || 
                   cveData.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || 0;
  if (cvssScore >= 9 || (epssData?.epss && epssData.epss > 0.5)) return 'HIGH';
  if (cvssScore >= 7) return 'MEDIUM';
  return 'LOW';
};

const calculateReleaseRecommendation = (cveData, epssData, kevData) => {
  const cvssScore = cveData.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                   cveData.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || 
                   cveData.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || 0;
  const epssScore = epssData?.epss || 0;
  
  if (kevData) {
    return {
      recommendation: 'FIX_THIS_RELEASE',
      reasoning: 'CISA Known Exploited Vulnerability - Federal compliance requires immediate patching',
      urgency: 'CRITICAL',
      timeframe: 'Immediate',
      dueDate: kevData.dueDate || 'ASAP',
      source: 'RULE_BASED'
    };
  }
  
  if (cvssScore >= 9.0 || epssScore > 0.5) {
    return {
      recommendation: 'FIX_THIS_RELEASE',
      reasoning: 'High severity and/or high exploitation probability',
      urgency: 'HIGH',
      timeframe: 'Current Release Cycle',
      dueDate: 'Next deployment window',
      source: 'RULE_BASED'
    };
  }
  
  if (cvssScore >= 7.0 || epssScore >= 0.2) {
    return {
      recommendation: 'FIX_NEXT_RELEASE',
      reasoning: 'Moderate severity with elevated exploitation risk',
      urgency: 'MEDIUM',
      timeframe: 'Next Release Cycle',
      dueDate: 'Within 30-60 days',
      source: 'RULE_BASED'
    };
  }
  
  return {
    recommendation: 'PLAN_FOR_FUTURE',
    reasoning: 'Lower severity and low exploitation probability',
    urgency: 'LOW',
    timeframe: 'Future Release',
    dueDate: 'Within 90 days or next major release',
    source: 'RULE_BASED'
  };
};

const extractTags = (description) => {
  const tags = [];
  if (description.toLowerCase().includes('remote code execution')) tags.push('RCE');
  if (description.toLowerCase().includes('privilege escalation')) tags.push('Privilege Escalation');
  if (description.toLowerCase().includes('denial of service')) tags.push('DoS');
  if (description.toLowerCase().includes('sql injection')) tags.push('SQLi');
  if (description.toLowerCase().includes('cross-site scripting')) tags.push('XSS');
  if (description.toLowerCase().includes('buffer overflow')) tags.push('Buffer Overflow');
  if (description.toLowerCase().includes('authentication bypass')) tags.push('Auth Bypass');
  if (description.toLowerCase().includes('directory traversal')) tags.push('Path Traversal');
  if (description.toLowerCase().includes('information disclosure')) tags.push('Info Disclosure');
  return tags;
};

const applyFilters = (vulnerabilities, filters) => {
  return vulnerabilities.filter(vuln => {
    if (filters.severity && vuln.cve.cvssV3?.baseSeverity !== filters.severity) return false;
    if (filters.kevStatus !== undefined && (vuln.kev ? 'true' : 'false') !== filters.kevStatus) return false;
    if (filters.cvssMin && vuln.cve.cvssV3?.baseScore < parseFloat(filters.cvssMin)) return false;
    if (filters.cvssMax && vuln.cve.cvssV3?.baseScore > parseFloat(filters.cvssMax)) return false;
    if (filters.vendor && !vuln.cve.description.toLowerCase().includes(filters.vendor.toLowerCase())) return false;
    return true;
  });
};

// Enhanced AI Analysis with RAG + Web Grounding
const generateEnhancedAIAnalysis = async (vulnerability, apiKey, model) => {
  const cveId = vulnerability.cve.id;
  const description = vulnerability.cve.description;
  const cvssScore = vulnerability.cve.cvssV3?.baseScore || 'N/A';
  const epssScore = vulnerability.epss ? (vulnerability.epss.epss * 100).toFixed(2) + '%' : 'N/A';
  const kevStatus = vulnerability.kev ? 'Yes' : 'No';
  const isGemini2 = model.includes('2.0');

  const modelName = isGemini2 ? 'gemini-2.0-flash' : model;

  const createAnalysisResult = (analysisText, ragDocs = [], webGrounded = false) => {
    return {
      analysis: analysisText || '',
      ragUsed: ragDocs.length > 0,
      webGrounded: webGrounded,
      ragDocs: ragDocs.length,
      ragSources: ragDocs.map(doc => doc.metadata?.title || 'Unknown').filter(Boolean)
    };
  };

  try {
    console.log('🚀 Starting AI Analysis for', cveId);
    
    if (!ragDatabase.initialized) {
      console.log('🚀 Initializing RAG database...');
      await ragDatabase.initialize();
    }

    console.log('📚 Performing RAG retrieval for', cveId);
    const ragQuery = `${cveId} ${description.substring(0, 200)} vulnerability analysis security impact mitigation`;
    const relevantDocs = await ragDatabase.search(ragQuery, 5);
    
    const ragContext = relevantDocs.length > 0 ? 
      relevantDocs.map((doc, index) => 
        `[Security Knowledge ${index + 1}] ${doc.metadata.title}:\n${doc.content.substring(0, 800)}...`
      ).join('\n\n') : 
      'No specific security knowledge found in database.';

    console.log(`📖 Retrieved ${relevantDocs.length} relevant documents from RAG database`);

    const prompt = `You are a senior cybersecurity analyst providing a comprehensive vulnerability assessment for ${cveId}.

VULNERABILITY DETAILS:
- CVE ID: ${cveId}
- CVSS Score: ${cvssScore}
- EPSS Score: ${epssScore}
- KEV Listed: ${kevStatus}
- Description: ${description.substring(0, 500)}

RELEVANT SECURITY KNOWLEDGE BASE:
${ragContext}

${isGemini2 ? 'Search the web for the latest threat intelligence and current exploitation status for this vulnerability.' : ''}

CRITICAL REQUIREMENTS:
- You MUST provide a detailed analysis of at least 3000 words
- Do NOT provide brief summaries or incomplete analysis
- Write comprehensive paragraphs with specific technical details
- Include actionable recommendations that security professionals can implement
- Structure the response with clear sections but write in full paragraphs

Write a comprehensive security assessment following this structure:
Write a comprehensive security assessment following this structure:

# EXECUTIVE CONCLUSION

Based on comprehensive analysis of CVE ${cveId}, CVSS ${cvssScore}, EPSS ${epssScore}, KEV status "${kevStatus}", and vulnerability description analysis, provide a critical 4-line executive conclusion:

Line 1: State the fundamental nature and primary threat classification of ${cveId} based on the technical description and attack vectors identified.
Line 2: Severity Assessment - Analyze if the current CVSS score of ${cvssScore} accurately reflects real-world risk or should be adjusted higher/lower considering the vulnerability description, affected systems, and exploitation complexity.
Line 3: Exploitation Probability - Evaluate if the EPSS score of ${epssScore} correctly represents exploitation likelihood, or if threat intelligence, proof-of-concepts, and ${kevStatus === 'Yes' ? 'active KEV exploitation' : 'current threat landscape'} suggest higher/lower probability.
Line 4: Critical Action - Provide definitive guidance on whether to patch immediately, adjust timelines, or modify organizational risk rating based on the integrated analysis of all factors.

# EXECUTIVE SUMMARY

Provide a thorough strategic overview (minimum 500 words) covering:
# EXECUTIVE SUMMARY

Provide a thorough strategic overview (minimum 500 words) covering:

Begin with a detailed explanation of what ${cveId} represents and why it poses a significant threat to modern organizations. Explain the fundamental nature of this vulnerability, including the specific software components it affects and the underlying technical mechanisms that make exploitation possible. Discuss how this vulnerability fits into the current threat landscape and what makes it particularly concerning for security professionals.

Analyze the overall risk posture this vulnerability creates for organizations, considering factors such as the ease of exploitation, the potential for widespread impact, and the availability of exploit code or proof-of-concept demonstrations. Explain how the CVSS score of ${cvssScore} and EPSS score of ${epssScore} should be interpreted in the context of real-world risk assessment and prioritization decisions.

Present strategic recommendations for security leadership, including immediate actions required, resource allocation considerations, and communication strategies for briefing executive stakeholders. Discuss the urgency classification and explain the reasoning behind prioritization decisions, considering factors such as ${kevStatus === 'Yes' ? 'the CISA KEV listing which indicates active exploitation' : 'the current threat intelligence and exploitation probability'}.

Conclude with a clear call to action that synthesizes the key points and provides security leaders with the essential information needed to make informed decisions about resource allocation and response priorities.

# TECHNICAL ANALYSIS

Deliver an in-depth technical assessment (minimum 700 words) including:

Provide a detailed explanation of the vulnerability mechanism, starting with the specific technical flaw or design weakness that enables exploitation. Explain the root cause of the vulnerability, whether it stems from coding errors, architectural design flaws, configuration weaknesses, or protocol vulnerabilities. Detail the specific conditions under which the vulnerability can be triggered and the technical prerequisites that must be met for successful exploitation.

Identify and enumerate all affected systems, components, and software versions, providing specific version numbers, configuration requirements, and deployment scenarios where the vulnerability is exploitable. Explain how different deployment configurations might affect the exploitability and impact of the vulnerability, and identify any environmental factors that could increase or decrease the risk.

Describe the complete attack chain and exploitation methodology, providing step-by-step details of how an attacker would identify vulnerable systems, craft exploit payloads, and execute successful attacks. Explain the technical skills and resources required for exploitation, including any specialized tools, network access requirements, or authentication credentials needed.

Analyze the potential for privilege escalation and lateral movement following initial exploitation, explaining how attackers might leverage this vulnerability as part of a broader attack campaign. Discuss the network and application layer security implications, including how the vulnerability might interact with other security controls and defensive measures.

Examine the technical indicators that would reveal ongoing exploitation attempts, including network traffic patterns, system behavior changes, and log file entries that security teams should monitor for signs of compromise.

# THREAT INTELLIGENCE ASSESSMENT

${isGemini2 ? 'Based on current web intelligence and real-time threat data' : 'Using available threat intelligence and security research'} (minimum 600 words):

Provide a comprehensive breakdown of the CVSS v3.1 scoring methodology, explaining each component score and how it contributes to the overall risk assessment. Detail the Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, and Impact scores, explaining what each metric means in practical terms and how they should influence security decision-making.

Analyze the EPSS probability score in detail, explaining the statistical model behind the prediction and what factors contribute to the exploitation probability calculation. Discuss how the EPSS score should be interpreted alongside other risk factors and explain any limitations or considerations security teams should keep in mind when using EPSS data for prioritization decisions.

${kevStatus === 'Yes' ? 
  'Examine the implications of the CISA KEV listing, including the federal compliance requirements for government agencies and the recommended timelines for remediation. Discuss what the KEV listing reveals about the current threat landscape and active exploitation campaigns targeting this vulnerability.' : 
  'Assess the current KEV status and monitoring requirements, explaining the criteria that would trigger a KEV listing and the ongoing threat intelligence monitoring necessary to detect changes in exploitation activity.'
}

Research and document known exploitation patterns, including any publicly available proof-of-concept code, exploit frameworks that include modules for this vulnerability, and documented attack campaigns that have leveraged this specific weakness. Analyze current threat actor interest and targeting methodologies, identifying which threat groups are most likely to exploit this vulnerability and their typical attack patterns.

Compare this vulnerability with similar security flaws that have been exploited in the past, drawing lessons from historical attack campaigns and explaining how those insights should inform current response strategies.

# BUSINESS IMPACT ASSESSMENT

Analyze comprehensive organizational consequences (minimum 700 words):

Detail specific operational disruption scenarios that could result from successful exploitation of this vulnerability, including system downtime, service interruptions, and cascading effects on dependent business processes. Explain how different types of organizations might be affected differently based on their technology stack, business model, and operational dependencies.

Conduct a thorough financial impact analysis covering both direct costs such as incident response, system remediation, and recovery efforts, as well as indirect costs including lost productivity, customer compensation, regulatory fines, and long-term business disruption. Provide frameworks for organizations to estimate their specific financial exposure based on their size, industry, and technology environment.

Examine regulatory compliance implications across different industries and jurisdictions, explaining specific requirements that might be triggered by a security incident involving this vulnerability. Discuss potential legal liabilities, reporting obligations, and compliance enforcement actions that organizations should anticipate.

Assess the potential impact on brand reputation and customer trust, explaining how security incidents involving this vulnerability might affect customer relationships, market position, and competitive standing. Discuss strategies for reputation management and customer communication during incident response activities.

Analyze supply chain vulnerabilities and third-party vendor risks, explaining how exploitation of this vulnerability in partner organizations or service providers could create indirect business impact. Discuss vendor risk management strategies and contractual considerations for managing third-party security exposures.

Consider industry-specific impact factors, explaining how different sectors such as healthcare, financial services, critical infrastructure, or retail might face unique risks and challenges related to this vulnerability.

# COMPREHENSIVE REMEDIATION STRATEGY

Provide a detailed action plan (minimum 800 words):

## Immediate Emergency Response (0-24 hours)

Outline step-by-step emergency response procedures that security teams should execute immediately upon discovering vulnerable systems in their environment. Detail the specific actions required for rapid threat assessment, including vulnerability scanning procedures, asset inventory verification, and initial risk evaluation.

Explain critical system isolation and network segmentation strategies, providing specific technical guidance for implementing emergency containment measures without disrupting essential business operations. Include decision trees for determining which systems require immediate isolation versus those that can remain operational with enhanced monitoring.

Describe comprehensive stakeholder notification protocols and communication plans, including templates for executive briefings, customer communications, and regulatory notifications. Explain escalation procedures and decision-making frameworks for determining when different types of communications are required.

Detail the implementation of initial risk mitigation and temporary security controls, including compensating controls that can provide immediate protection while permanent remediation is being planned and executed.

## Short-term Tactical Actions (1-7 days)

Provide detailed patch deployment strategy and testing procedures, including guidance for establishing test environments, validating patch compatibility, and rolling out updates across different system types and criticality levels. Explain rollback procedures and contingency planning for patch deployment failures.

Describe comprehensive system hardening recommendations and configuration updates that can reduce the attack surface and improve overall security posture beyond just addressing the specific vulnerability. Include specific configuration parameters, security settings, and architectural changes that provide defense-in-depth protection.

Outline access control reviews and privilege management audits, explaining how to identify and remediate excessive privileges that could compound the impact of this vulnerability. Provide frameworks for ongoing access management and least-privilege enforcement.

Detail enhanced monitoring implementation and detection rules, including specific SIEM configurations, network monitoring parameters, and endpoint detection capabilities that can identify exploitation attempts and successful compromises.

## Long-term Strategic Improvements (1-30 days)

Describe infrastructure architecture security enhancements that address the underlying conditions that make organizations vulnerable to this type of attack. Explain design principles and architectural patterns that provide resilience against similar vulnerabilities in the future.

Outline security process improvements and policy updates required to prevent similar vulnerabilities from going undetected or unpatched in the future. Include governance frameworks, change management procedures, and security testing requirements.

Detail staff training programs and security awareness initiatives that address the human factors contributing to vulnerability management challenges. Explain competency development requirements and ongoing education programs.

Describe the implementation of continuous monitoring and threat hunting capabilities that provide ongoing assurance and early detection of emerging threats and attack campaigns.

# DETECTION AND MONITORING FRAMEWORK

Detail a comprehensive monitoring approach (minimum 600 words):

Specify detailed indicators of compromise and attack signatures that security teams should monitor for, including network traffic patterns, system behavior anomalies, and application-level indicators that could reveal exploitation attempts. Provide specific IOCs in standard formats that can be imported into security tools.

Identify comprehensive log sources and event correlation requirements, explaining which systems generate relevant security events and how those events should be collected, normalized, and analyzed. Include specific log parsing requirements and data retention recommendations.

Provide detailed SIEM rules, queries, and detection logic that can identify both successful exploitation and attempted attacks. Include correlation rules that can detect multi-stage attack campaigns and lateral movement activities.

Describe network monitoring strategies and traffic analysis methods, including specific network signatures, protocol analysis techniques, and traffic flow analysis procedures that can detect exploitation network activity.

Explain behavioral analytics and anomaly detection implementations, including baseline establishment procedures, anomaly threshold tuning, and false positive reduction strategies.

Detail incident response triggers and escalation procedures, explaining the specific conditions that should trigger different levels of incident response and the decision-making frameworks for escalation to senior management and external stakeholders.

# STRATEGIC RECOMMENDATIONS AND NEXT STEPS

Summarize key findings and provide clear next steps (minimum 400 words):

Present prioritized action items with detailed timelines, explaining the sequencing of remediation activities and the dependencies between different action items. Provide specific milestone dates and deliverable requirements for tracking progress.

Describe resource allocation and responsibility assignments, including specific role definitions, skill requirements, and organizational coordination mechanisms needed for successful remediation.

Define success metrics and validation criteria that organizations can use to measure the effectiveness of their remediation efforts and ensure that risk reduction objectives are achieved.

Establish ongoing monitoring and reassessment schedules, explaining the frequency and scope of follow-up activities needed to maintain security posture and detect emerging threats related to this vulnerability.

Ensure each section provides specific, actionable intelligence that security professionals can implement immediately. Include technical details, step-by-step procedures, and reference relevant industry standards and best practices throughout the analysis.`;

    const requestBody = {
      contents: [
        {
          parts: [
            { text: prompt }
          ]
        }
      ],
      generationConfig: {
        temperature: 0.1,
        topK: 1,
        topP: 0.8,
        maxOutputTokens: 8192,
        stopSequences: [],
        candidateCount: 1
      },
      safetySettings: [
        {
          category: "HARM_CATEGORY_HARASSMENT",
          threshold: "BLOCK_NONE"
        },
        {
          category: "HARM_CATEGORY_HATE_SPEECH", 
          threshold: "BLOCK_NONE"
        },
        {
          category: "HARM_CATEGORY_SEXUALLY_EXPLICIT",
          threshold: "BLOCK_NONE"
        },
        {
          category: "HARM_CATEGORY_DANGEROUS_CONTENT",
          threshold: "BLOCK_NONE"
        }
      ]
    };

    if (isGemini2) {
      requestBody.tools = [
        {
          google_search: {}
        }
      ];
    }

    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`;
    
    console.log('🔗 Making API Request:', {
      url: apiUrl,
      model: modelName,
      hasRAG: relevantDocs.length > 0,
      hasWebGrounding: isGemini2,
      promptLength: prompt.length,
      ragDocsUsed: relevantDocs.length
    });
    
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      console.error('❌ Gemini API Error:', response.status, errorData);
      throw new Error(`AI API error: ${response.status} - ${JSON.stringify(errorData)}`);
    }

    const data = await response.json();
    console.log('✅ AI analysis response received');
    console.log('📄 Full response data:', JSON.stringify(data, null, 2));
    
    if (!data.candidates || !data.candidates[0] || !data.candidates[0].content) {
      console.error('❌ Invalid response structure:', data);
      throw new Error('Invalid API response format - no content generated');
    }
    
    // CRITICAL FIX: Handle multiple parts in the response
    const content = data.candidates[0].content;
    let analysisText = '';
    
    if (content.parts && Array.isArray(content.parts)) {
      // Combine all parts of the response
      analysisText = content.parts.map(part => part.text || '').join('');
      console.log(`📝 Combined ${content.parts.length} response parts`);
      console.log('📝 Individual part lengths:', content.parts.map((part, i) => `Part ${i+1}: ${part.text?.length || 0} chars`));
    } else if (content.parts && content.parts[0] && content.parts[0].text) {
      // Single part response
      analysisText = content.parts[0].text;
    } else {
      throw new Error('No valid content parts found in response');
    }
    
    console.log('📝 Complete analysis text length:', analysisText?.length);
    console.log('📝 First 300 chars:', analysisText?.substring(0, 300));
    console.log('📝 Last 300 chars:', analysisText?.substring(Math.max(0, analysisText.length - 300)));
    
    if (!analysisText || typeof analysisText !== 'string' || analysisText.trim().length === 0) {
      throw new Error('Empty or invalid analysis text in response');
    }
    
    // Log the complete analysis to console for debugging
    console.log('🔍 COMPLETE AI ANALYSIS TEXT:');
    console.log('='.repeat(80));
    console.log(analysisText);
    console.log('='.repeat(80));
    console.log('📊 Total analysis length:', analysisText.length, 'characters');
    
    // Log final analysis length and warn if still short
    console.log('📊 Final analysis statistics:', {
      length: analysisText.length,
      preview: analysisText.substring(0, 200) + '...',
      ragDocsUsed: relevantDocs.length,
      hasWebGrounding: isGemini2,
      isAcceptableLength: analysisText.length >= 1000
    });
    
    if (analysisText.length < 1000) {
      console.warn(`⚠️ WARNING: Analysis is still short (${analysisText.length} chars). This may indicate API limitations or model constraints.`);
    }
    
    if (analysisText.length > 500) {
      await ragDatabase.addDocument(
        `CVE Analysis: ${cveId}\n\n${analysisText}`,
        {
          title: `Security Analysis - ${cveId}`,
          category: 'analysis',
          tags: ['cve-analysis', cveId.toLowerCase(), 'ai-generated'],
          source: 'ai-analysis',
          cvss: cvssScore,
          epss: epssScore,
          kev: kevStatus
        }
      );
      console.log('💾 Stored analysis in RAG database for future retrieval');
    }
    
    return createAnalysisResult(analysisText, relevantDocs, isGemini2);
    
  } catch (error) {
    console.error('💥 Enhanced AI Analysis Error:', error);
    
    return createAnalysisResult(
      `**AI Analysis Error**

An error occurred while generating the security analysis for ${cveId}:

**Error Details:**
${error.message}

**Troubleshooting Steps:**
1. **Check API Key**: Ensure your Gemini API key is valid and has sufficient quota
2. **Network Issues**: Verify your internet connection and try again
3. **Rate Limits**: Wait a few moments before retrying if you've made many requests
4. **Model Availability**: Try switching to a different Gemini model in settings

**Manual Analysis Recommendation:**
While the AI analysis failed, you can still perform manual analysis using:
- Official NVD details: https://nvd.nist.gov/vuln/detail/${cveId}
- MITRE CVE database: https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}
- Security advisories from the vendor
- Community discussions and proof-of-concept research

Please check the browser console for detailed error information and try configuring your API settings.`,
      [],
      false
    );
  }
};

// API functions
const fetchCVEDataFromNVD = async (cveId, setLoadingSteps, apiKey) => {
  setLoadingSteps(prev => [...prev, `🔍 Fetching ${cveId} from NVD...`]);
  
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    const headers = { 
      'Accept': 'application/json',
      'User-Agent': 'VulnerabilityManagementConsole/1.0'
    };
    
    if (apiKey) {
      headers['apiKey'] = apiKey;
    }
    
    const response = await fetch(url, { headers, method: 'GET' });
    
    if (!response.ok) {
      if (response.status === 403) {
        throw new Error('NVD API rate limit exceeded. Consider adding an API key.');
      }
      throw new Error(`NVD API error: ${response.status} ${response.statusText}`);
    }
    
    const data = await response.json();
    
    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
      throw new Error(`CVE ${cveId} not found in NVD database`);
    }
    
    const cve = data.vulnerabilities[0].cve;
    const description = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description available';
    
    const cvssV31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
    const cvssV30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
    const cvssV2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData;
    
    const cvssV3 = cvssV31 || cvssV30;
    
    setLoadingSteps(prev => [...prev, `✅ Retrieved ${cveId} from NVD`]);
    
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
        impactScore: cvssV3.impactScore
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
      })) || [],
      metrics: cve.metrics,
      configurations: cve.configurations,
      weaknesses: cve.weaknesses?.map(w => ({
        source: w.source,
        type: w.type,
        description: w.description
      })) || []
    };
    
  } catch (error) {
    console.error(`NVD API Error for ${cveId}:`, error);
    setLoadingSteps(prev => [...prev, `❌ Failed to fetch ${cveId} from NVD: ${error.message}`]);
    throw error;
  }
};

const fetchEPSSData = async (cveId, setLoadingSteps) => {
  setLoadingSteps(prev => [...prev, `📊 Fetching EPSS data for ${cveId}...`]);
  
  try {
    const response = await fetch(`https://api.first.org/data/v1/epss?cve=${cveId}`, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'VulnerabilityManagementConsole/1.0'
      }
    });
    
    if (!response.ok) {
      if (response.status === 404) {
        setLoadingSteps(prev => [...prev, `⚠️ No EPSS data available for ${cveId}`]);
        return null;
      }
      throw new Error(`EPSS API error: ${response.status} ${response.statusText}`);
    }
    
    const data = await response.json();
    
    if (!data.data || data.data.length === 0) {
      setLoadingSteps(prev => [...prev, `⚠️ No EPSS data found for ${cveId}`]);
      return null;
    }
    
    const epssData = data.data[0];
    setLoadingSteps(prev => [...prev, `✅ Retrieved EPSS data for ${cveId}: ${(parseFloat(epssData.epss) * 100).toFixed(2)}%`]);
    
    return {
      cve: cveId,
      epss: parseFloat(epssData.epss),
      percentile: parseFloat(epssData.percentile),
      date: epssData.date,
      model_version: data.model_version
    };
    
  } catch (error) {
    console.error(`EPSS API Error for ${cveId}:`, error);
    setLoadingSteps(prev => [...prev, `⚠️ EPSS data unavailable for ${cveId}: ${error.message}`]);
    return null;
  }
};

const fetchKEVData = async (cveId, setLoadingSteps) => {
  setLoadingSteps(prev => [...prev, `🎯 Checking CISA KEV catalog for ${cveId}...`]);
  
  try {
    const response = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'VulnerabilityManagementConsole/1.0'
      }
    });
    
    if (!response.ok) {
      throw new Error(`KEV API error: ${response.status} ${response.statusText}`);
    }
    
    const data = await response.json();
    
    if (!data.vulnerabilities) {
      throw new Error('Invalid KEV data format');
    }
    
    const kevEntry = data.vulnerabilities.find(v => v.cveID === cveId);
    
    if (!kevEntry) {
      setLoadingSteps(prev => [...prev, `ℹ️ ${cveId} not in CISA KEV catalog`]);
      return null;
    }
    
    setLoadingSteps(prev => [...prev, `🚨 ${cveId} found in CISA KEV catalog - CRITICAL!`]);
    
    return {
      cveID: kevEntry.cveID,
      vendorProject: kevEntry.vendorProject,
      product: kevEntry.product,
      vulnerabilityName: kevEntry.vulnerabilityName,
      dateAdded: kevEntry.dateAdded,
      shortDescription: kevEntry.shortDescription,
      requiredAction: kevEntry.requiredAction,
      dueDate: kevEntry.dueDate,
      knownRansomwareCampaignUse: kevEntry.knownRansomwareCampaignUse,
      notes: kevEntry.notes || ''
    };
    
  } catch (error) {
    console.error(`KEV API Error for ${cveId}:`, error);
    setLoadingSteps(prev => [...prev, `⚠️ KEV data unavailable for ${cveId}: ${error.message}`]);
    return null;
  }
};

const fetchVulnerabilityWithThreatData = async (cveId, setLoadingSteps, apiKey, settings = {}) => {
  try {
    const [cveData, epssData, kevData] = await Promise.allSettled([
      fetchCVEDataFromNVD(cveId, setLoadingSteps, apiKey),
      fetchEPSSData(cveId, setLoadingSteps),
      fetchKEVData(cveId, setLoadingSteps)
    ]);
    
    const cve = cveData.status === 'fulfilled' ? cveData.value : null;
    const epss = epssData.status === 'fulfilled' ? epssData.value : null;
    const kev = kevData.status === 'fulfilled' ? kevData.value : null;
    
    if (!cve) {
      throw new Error(`Failed to fetch CVE data for ${cveId}`);
    }
const fetchAIEnhancedSecurityAdvisories = async (cve, setLoadingSteps, geminiApiKey, geminiModel) => {
  setLoadingSteps(prev => [...prev, `🤖 AI-generating security advisories for ${cve.id}...`]);
  
  try {
    const isGemini2 = geminiModel.includes('2.0');
    const modelName = isGemini2 ? 'gemini-2.0-flash' : geminiModel;
    
    const prompt = `Find current security advisories and vendor fixes for ${cve.id}. ${isGemini2 ? 'Search the web for the latest vendor advisories, patches, and security bulletins.' : 'Provide known security advisories and fix information.'}
    
    CVE: ${cve.id}
    Description: ${cve.description}
    
    Return a JSON array of security advisories with this exact format:
    [
      {
        "title": "Advisory title",
        "url": "https://vendor.com/advisory",
        "vendor": "Vendor name",
        "priority": "CRITICAL|HIGH|MEDIUM|LOW",
        "type": "Security Advisory|Patch|Update|Bulletin",
        "icon": "🛡️"
      }
    ]`;

    const requestBody = {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.1,
        topK: 1,
        topP: 0.8,
        maxOutputTokens: 2048
      }
    };

    if (isGemini2) {
      requestBody.tools = [{ google_search: {} }];
    }

    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${geminiApiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      throw new Error(`AI API error: ${response.status}`);
    }

    const data = await response.json();
    const content = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    
    try {
      const jsonMatch = content.match(/\[[\s\S]*\]/);
      const advisories = jsonMatch ? JSON.parse(jsonMatch[0]) : [];
      
      setLoadingSteps(prev => [...prev, `✅ AI generated ${advisories.length} security advisories`]);
      
      return advisories.map(advisory => ({
        ...advisory,
        aiGenerated: true
      }));
    } catch (parseError) {
      console.warn('Failed to parse AI advisories response:', parseError);
      return [
        {
          title: "AI-Generated Security Advisory Analysis",
          url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
          vendor: "NVD",
          priority: "MEDIUM",
          type: "Analysis",
          icon: "🤖",
          aiGenerated: true
        }
      ];
    }
  } catch (error) {
    console.error('AI Enhanced Advisories Error:', error);
    setLoadingSteps(prev => [...prev, `⚠️ AI advisories failed, using fallback`]);
    return [
      {
        title: "Standard Security Advisory",
        url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
        vendor: "NVD",
        priority: "MEDIUM",
        type: "Reference",
        icon: "🔗",
        aiGenerated: false
      }
    ];
  }
};
const fetchSecurityAdvisoriesAndFixes = async (cve, setLoadingSteps) => {
  setLoadingSteps(prev => [...prev, `📋 Generating standard advisories for ${cve.id}...`]);
  
  const advisories = [
    {
      title: "NVD Official Entry",
      url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      vendor: "NIST",
      priority: "HIGH",
      type: "Official Database",
      icon: "🏛️"
    },
    {
      title: "MITRE CVE Database",
      url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id}`,
      vendor: "MITRE",
      priority: "MEDIUM",
      type: "CVE Reference",
      icon: "🔍"
    }
  ];

  // Add vendor-specific advisories based on CVE description
  const description = cve.description.toLowerCase();
  if (description.includes('microsoft') || description.includes('windows')) {
    advisories.push({
      title: "Microsoft Security Response Center",
      url: `https://msrc.microsoft.com/search?query=${cve.id}`,
      vendor: "Microsoft",
      priority: "HIGH",
      type: "Vendor Advisory",
      icon: "🖥️"
    });
  }
  
  if (description.includes('apache')) {
    advisories.push({
      title: "Apache Security Advisories",
      url: `https://httpd.apache.org/security/vulnerabilities_24.html`,
      vendor: "Apache",
      priority: "HIGH",
      type: "Vendor Advisory",
      icon: "🪶"
    });
  }

  setLoadingSteps(prev => [...prev, `✅ Generated ${advisories.length} standard advisories`]);
  return advisories;
};
    // CRITICAL: Use AI-enhanced security advisories if Gemini API key is available
    const securityAdvisories = settings.geminiApiKey ? 
      await fetchAIEnhancedSecurityAdvisories(cve, setLoadingSteps, settings.geminiApiKey, settings.geminiModel || 'gemini-1.5-flash') :
      await fetchSecurityAdvisoriesAndFixes(cve, setLoadingSteps);
    
    const riskScore = calculateOverallRiskScore(cve, epss, kev);
    const priority = calculatePriority(cve, epss, kev);
    const tags = extractTags(cve.description);
    
    const releaseRecommendation = calculateReleaseRecommendation(cve, epss, kev);
    
    return {
      cve,
      epss,
      kev,
      securityAdvisories, // This now contains AI-discovered vendor advisories
      riskScore,
      priority,
      tags,
      releaseRecommendation,
      dataFreshness: 'REAL_TIME',
      lastUpdated: new Date().toISOString(),
      searchTimestamp: new Date().toISOString(),
      aiEnhanced: settings.geminiApiKey ? true : false
    };
    
  } catch (error) {
    console.error(`Error processing ${cveId}:`, error);
    throw error;
  }
};

// Components
const NotificationManager = () => {
  const { notifications, settings } = useContext(AppContext);
  const styles = getStyles(settings.darkMode);
  
  return (
    <div style={{ position: 'fixed', top: '24px', right: '24px', zIndex: 1000 }}>
      {notifications.map((notification) => (
        <div
          key={notification.id}
          style={{
            ...styles.notification,
            ...(notification.type === 'success' ? styles.notificationSuccess : 
               notification.type === 'error' ? styles.notificationError : 
               styles.notificationWarning),
            marginBottom: '8px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {notification.type === 'success' && <CheckCircle size={16} color="#10b981" />}
            {notification.type === 'error' && <XCircle size={16} color="#ef4444" />}
            {notification.type === 'warning' && <AlertTriangle size={16} color="#f59e0b" />}
            <div>
              <div style={{ fontWeight: '500', fontSize: '0.875rem', color: settings.darkMode ? '#e2e8f0' : '#1f2937' }}>{notification.title}</div>
              <div style={{ fontSize: '0.75rem', color: settings.darkMode ? '#94a3b8' : '#6b7280' }}>{notification.message}</div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

const SettingsModal = ({ isOpen, onClose, settings, setSettings }) => {
  const [localSettings, setLocalSettings] = useState(settings);
  const [showApiKey, setShowApiKey] = useState(false);
  const [showGeminiKey, setShowGeminiKey] = useState(false);
  const [testingConnection, setTestingConnection] = useState(false);
  const styles = getStyles(settings.darkMode);

  useEffect(() => {
    setLocalSettings(settings);
  }, [settings]);

  const testGeminiConnection = async () => {
    if (!localSettings.geminiApiKey) {
      alert('Please enter a Gemini API key first');
      return;
    }

    setTestingConnection(true);
    try {
      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${localSettings.geminiModel}:generateContent?key=${localSettings.geminiApiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{
            parts: [{
              text: 'Test connection - respond with "Connection successful"'
            }]
          }],
          generationConfig: {
            temperature: 0.1,
            maxOutputTokens: 10
          }
        })
      });

      if (response.ok) {
        alert('✅ Gemini API connection successful!');
      } else {
        const errorText = await response.text();
        alert(`❌ Connection failed: ${response.status} - ${errorText}`);
      }
    } catch (error) {
      alert(`❌ Connection failed: ${error.message}`);
    } finally {
      setTestingConnection(false);
    }
  };

  const handleSave = () => {
    setSettings(localSettings);
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div style={styles.modal}>
      <div style={styles.modalContent}>
        <div style={styles.modalHeader}>
          <h3 style={styles.modalTitle}>Settings</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer' }}>
            <X size={20} color={settings.darkMode ? '#e2e8f0' : '#1f2937'} />
          </button>
        </div>

        <div style={{ display: 'grid', gap: '24px' }}>
          <div>
            <h4 style={{ margin: '0 0 16px 0', color: settings.darkMode ? '#e2e8f0' : '#1f2937' }}>General Settings</h4>
            
            <div style={styles.formGroup}>
              <label style={{ ...styles.label, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <input
                  type="checkbox"
                  checked={localSettings.aiAnalysisEnabled}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, aiAnalysisEnabled: e.target.checked }))}
                />
                Enable AI Analysis
              </label>
            </div>

            <div style={styles.formGroup}>
              <label style={{ ...styles.label, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <input
                  type="checkbox"
                  checked={localSettings.autoRefresh}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, autoRefresh: e.target.checked }))}
                />
                Auto-refresh data (every 5 minutes)
              </label>
            </div>
          </div>

          <div>
            <h4 style={{ margin: '0 0 16px 0', color: settings.darkMode ? '#e2e8f0' : '#1f2937' }}>API Configuration</h4>
            
            <div style={styles.formGroup}>
              <label style={styles.label}>NVD API Key (Recommended for higher rate limits)</label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showApiKey ? 'text' : 'password'}
                  style={styles.input}
                  placeholder="Enter your NVD API key"
                  value={localSettings.nvdApiKey || ''}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, nvdApiKey: e.target.value }))}
                />
                <button
                  style={{ 
                    position: 'absolute', 
                    right: '8px', 
                    top: '50%', 
                    transform: 'translateY(-50%)',
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    padding: '4px'
                  }}
                  onClick={() => setShowApiKey(!showApiKey)}
                >
                  {showApiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <div style={styles.formGroup}>
              <label style={styles.label}>Gemini API Key (For AI Analysis & Enhanced Advisories)</label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showGeminiKey ? 'text' : 'password'}
                  style={styles.input}
                  placeholder="Enter your Gemini API key for AI analysis"
                  value={localSettings.geminiApiKey || ''}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiApiKey: e.target.value }))}
                />
                <button
                  style={{ 
                    position: 'absolute', 
                    right: '8px', 
                    top: '50%', 
                    transform: 'translateY(-50%)',
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    padding: '4px'
                  }}
                  onClick={() => setShowGeminiKey(!showGeminiKey)}
                >
                  {showGeminiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              <div style={{ marginTop: '8px' }}>
                <button
                  style={{
                    ...styles.button,
                    ...styles.buttonSecondary,
                    fontSize: '0.8rem',
                    padding: '6px 12px'
                  }}
                  onClick={testGeminiConnection}
                  disabled={testingConnection || !localSettings.geminiApiKey}
                >
                  {testingConnection ? (
                    <>
                      <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} />
                      Testing...
                    </>
                  ) : (
                    <>
                      <Wifi size={14} />
                      Test Connection
                    </>
                  )}
                </button>
              </div>
            </div>

            <div style={styles.formGroup}>
              <label style={styles.label}>Gemini Model</label>
              <select
                style={styles.select}
                value={localSettings.geminiModel || 'gemini-1.5-flash'}
                onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiModel: e.target.value }))}
              >
                <option value="gemini-2.0-flash">Gemini 2.0 Flash - 🌐 Internet Grounding (Recommended)</option>
                <option value="gemini-1.5-flash">Gemini 1.5 Flash (Fast & Efficient)</option>
                <option value="gemini-1.5-pro">Gemini 1.5 Pro (Advanced Analysis)</option>
                <option value="gemini-1.0-pro">Gemini 1.0 Pro (Stable)</option>
              </select>
              {localSettings.geminiModel?.includes('2.0') && (
                <div style={{
                  marginTop: '8px',
                  padding: '8px',
                  background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                  borderRadius: '4px',
                  fontSize: '0.75rem',
                  color: 'white'
                }}>
                  🌐 <strong>Gemini 2.0 Features:</strong> Real-time web search, current threat intelligence, live security advisory search
                </div>
              )}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', paddingTop: '16px', borderTop: settings.darkMode ? '1px solid #334155' : '1px solid #e5e7eb' }}>
          <button
            style={{ ...styles.button, ...styles.buttonSecondary }}
            onClick={onClose}
          >
            Cancel
          </button>
          <button
            style={{ ...styles.button, ...styles.buttonPrimary }}
            onClick={handleSave}
          >
            <Save size={16} />
            Save Settings
          </button>
        </div>
      </div>
    </div>
  );
};

const EnhancedSearchComponent = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [showFilters, setShowFilters] = useState(false);
  const [bulkFile, setBulkFile] = useState(null);
  const [searchHistory, setSearchHistory] = useState([]);
  const { 
    setVulnerabilities, 
    setLoading, 
    loading, 
    setLoadingSteps, 
    filters, 
    setFilters,
    addNotification,
    settings
  } = useContext(AppContext);

  const styles = getStyles(settings.darkMode);

  const validateCVEFormat = (cveId) => {
    return /^CVE-\d{4}-\d{4,}$/i.test(cveId.trim());
  };

  const handleSearch = async () => {
    if (!searchTerm.trim() && !bulkFile) return;

    setLoading(true);
    setLoadingSteps([]);
    
    try {
      let cveIds = [];

      if (bulkFile) {
        setLoadingSteps(prev => [...prev, `📁 Processing bulk file: ${bulkFile.name}`]);
        
        const fileContent = await bulkFile.text();
        const extractedIds = fileContent
          .split(/[\,\n\r\t\s]+/)
          .map(id => id.trim().toUpperCase())
          .filter(id => id && validateCVEFormat(id));
        
        cveIds = [...new Set(extractedIds)];
        setLoadingSteps(prev => [...prev, `✅ Extracted ${cveIds.length} valid CVE IDs from file`]);
        
        if (cveIds.length === 0) {
          throw new Error('No valid CVE IDs found in file. Expected format: CVE-YYYY-NNNN');
        }
      } else {
        const inputIds = searchTerm
          .split(/[\,\n\r\t\s]+/)
          .map(id => id.trim().toUpperCase())
          .filter(id => id);
        
        const validIds = inputIds.filter(id => validateCVEFormat(id));
        const invalidIds = inputIds.filter(id => !validateCVEFormat(id));
        
        if (invalidIds.length > 0) {
          addNotification({
            type: 'warning',
            title: 'Invalid CVE IDs',
            message: `Skipping invalid IDs: ${invalidIds.join(', ')}`
          });
        }
        
        if (validIds.length === 0) {
          throw new Error('No valid CVE IDs provided. Expected format: CVE-YYYY-NNNN');
        }
        
        cveIds = [...new Set(validIds)];
        setSearchHistory(prev => [...new Set([...cveIds, ...prev])].slice(0, 10));
      }
      
      setLoadingSteps(prev => [...prev, `🎯 Starting real-time analysis of ${cveIds.length} CVE${cveIds.length > 1 ? 's' : ''}`]);
      
      const vulnerabilityResults = [];
      const failedCves = [];
      
      const batchSize = settings.nvdApiKey ? 10 : 3;
      
      for (let i = 0; i < cveIds.length; i += batchSize) {
        const batch = cveIds.slice(i, i + batchSize);
        setLoadingSteps(prev => [...prev, `📋 Processing batch ${Math.floor(i / batchSize) + 1} of ${Math.ceil(cveIds.length / batchSize)}...`]);
        
        const batchPromises = batch.map(async (cveId) => {
          try {
            const vulnerability = await fetchVulnerabilityWithThreatData(cveId, setLoadingSteps, settings.nvdApiKey, settings);
            vulnerabilityResults.push(vulnerability);
            setLoadingSteps(prev => [...prev, `✅ Successfully processed ${cveId}`]);
          } catch (error) {
            failedCves.push(cveId);
            setLoadingSteps(prev => [...prev, `❌ Failed to process ${cveId}: ${error.message}`]);
            console.error(`Error processing ${cveId}:`, error);
          }
        });
        
        await Promise.allSettled(batchPromises);
        
        if (i + batchSize < cveIds.length) {
          const delay = settings.nvdApiKey ? 500 : 2000;
          setLoadingSteps(prev => [...prev, `⏱️ Rate limiting delay (${delay}ms)...`]);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
      
      if (failedCves.length > 0) {
        addNotification({
          type: 'warning',
          title: `${failedCves.length} CVE(s) Failed`,
          message: `Could not process: ${failedCves.slice(0, 3).join(', ')}${failedCves.length > 3 ? '...' : ''}`
        });
      }
      
      if (vulnerabilityResults.length === 0) {
        throw new Error('No vulnerabilities could be processed successfully');
      }
      
      const filteredResults = applyFilters(vulnerabilityResults, filters);
      setVulnerabilities(filteredResults, cveIds);
      
      const criticalCount = vulnerabilityResults.filter(v => v.priority === 'CRITICAL').length;
      const kevCount = vulnerabilityResults.filter(v => v.kev).length;
      const highEpssCount = vulnerabilityResults.filter(v => v.epss && v.epss.epss > 0.5).length;
      const aiEnhancedCount = vulnerabilityResults.filter(v => v.aiEnhanced).length;
      
      let message = `Processed ${vulnerabilityResults.length}/${cveIds.length} CVEs successfully`;
      if (criticalCount > 0) message += ` • ${criticalCount} Critical`;
      if (kevCount > 0) message += ` • ${kevCount} KEV Listed`;
      if (highEpssCount > 0) message += ` • ${highEpssCount} High EPSS`;
      if (aiEnhancedCount > 0) message += ` • ${aiEnhancedCount} AI Enhanced`;
      
      addNotification({
        type: 'success',
        title: 'Real-time Analysis Complete',
        message
      });
      
    } catch (error) {
      console.error('Error in vulnerability search:', error);
      setLoadingSteps(prev => [...prev, `❌ Search Error: ${error.message}`]);
      addNotification({
        type: 'error',
        title: 'Search Failed',
        message: error.message
      });
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (event) => {
    const file = event.target.files?.[0];
    if (file) {
      const allowedTypes = ['text/plain', 'text/csv', 'application/json'];
      const maxSize = 5 * 1024 * 1024;
      
      if (!allowedTypes.includes(file.type) && !file.name.match(/\.(txt|csv|json)$/i)) {
        addNotification({
          type: 'error',
          title: 'Invalid File Type',
          message: 'Please upload a .txt, .csv, or .json file'
        });
        return;
      }
      
      if (file.size > maxSize) {
        addNotification({
          type: 'error',
          title: 'File Too Large',
          message: 'File size must be less than 5MB'
        });
        return;
      }
      
      setBulkFile(file);
      addNotification({
        type: 'success',
        title: 'File Uploaded',
        message: `Ready to process ${file.name} (${(file.size / 1024).toFixed(1)} KB)`
      });
    }
  };

  return (
    <div style={styles.searchContainer}>
      <h2 style={{ margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Search size={24} color="#3b82f6" />
        Real-time Vulnerability Intelligence
        <span style={{
          ...styles.badge,
          background: '#10b981',
          color: 'white',
          borderColor: '#10b981'
        }}>
          LIVE APIs
        </span>
        {settings.geminiApiKey && (
          <span style={{
            ...styles.badge,
            background: settings.geminiModel?.includes('2.0') ? 
              'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' : '#8b5cf6',
            color: 'white',
            borderColor: settings.geminiModel?.includes('2.0') ? '#667eea' : '#8b5cf6'
          }}>
            {settings.geminiModel?.includes('2.0') ? '🌐 AI + WEB' : 'AI ENHANCED'}
          </span>
        )}
      </h2>
      
      <div style={styles.searchWrapper}>
        <Search style={styles.searchIcon} size={20} />
        <input
          type="text"
          placeholder="Enter CVE IDs (e.g., CVE-2024-12345, CVE-2023-98765) or upload bulk file"
          style={{
            ...styles.searchInput,
            borderColor: searchTerm ? '#3b82f6' : (settings.darkMode ? '#475569' : '#d1d5db')
          }}
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && !loading && handleSearch()}
          disabled={loading}
        />
        <button
          style={{ ...styles.button, ...styles.buttonPrimary, ...styles.searchButton }}
          onClick={handleSearch}
          disabled={loading || (!searchTerm.trim() && !bulkFile)}
        >
          {loading ? <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> : <Search size={16} />}
          {loading ? 'Analyzing...' : 'Analyze'}
        </button>
      </div>

      <div style={{ display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap' }}>
        <label style={{ ...styles.button, ...styles.buttonSecondary, cursor: 'pointer' }}>
          <Upload size={16} />
          Upload CVE List
          <input
            type="file"
            accept=".txt,.csv,.json"
            onChange={handleFileUpload}
            style={{ display: 'none' }}
            disabled={loading}
          />
        </label>
        
        {bulkFile && (
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '8px', 
            padding: '8px 12px', 
            background: settings.darkMode ? '#065f46' : '#f0fdf4', 
            borderRadius: '6px', 
            border: settings.darkMode ? '1px solid #10b981' : '1px solid #bbf7d0' 
          }}>
            <FileText size={16} color="#10b981" />
            <span style={{ fontSize: '0.875rem', color: settings.darkMode ? '#86efac' : '#10b981' }}>
              {bulkFile.name} ({(bulkFile.size / 1024).toFixed(1)} KB)
            </span>
            <button 
              onClick={() => setBulkFile(null)} 
              style={{ background: 'none', border: 'none', cursor: 'pointer' }}
              disabled={loading}
            >
              <X size={14} color="#10b981" />
            </button>
          </div>
        )}
        
        <button
          style={{ ...styles.button, ...styles.buttonSecondary }}
          onClick={() => setShowFilters(!showFilters)}
          disabled={loading}
        >
          <Filter size={16} />
          Filters {Object.values(filters).filter(v => v).length > 0 && `(${Object.values(filters).filter(v => v).length})`}
        </button>
      </div>

      {searchHistory.length > 0 && (
        <div style={{ 
          marginBottom: '16px', 
          padding: '12px', 
          background: settings.darkMode ? '#1e293b' : '#f8fafc', 
          borderRadius: '8px',
          border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0'
        }}>
          <div style={{ fontSize: '0.875rem', fontWeight: '500', marginBottom: '8px', color: settings.darkMode ? '#f1f5f9' : '#1f2937' }}>
            Recent Searches:
          </div>
          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
            {searchHistory.slice(0, 8).map((cve, index) => (
              <button
                key={index}
                style={{
                  ...styles.badge,
                  background: settings.darkMode ? '#475569' : '#e5e7eb',
                  color: settings.darkMode ? '#f1f5f9' : '#374151',
                  borderColor: settings.darkMode ? '#64748b' : '#d1d5db',
                  cursor: 'pointer',
                  fontSize: '0.75rem',
                  padding: '4px 8px',
                  border: '1px solid'
                }}
                onClick={() => {
                  setSearchTerm(cve);
                }}
                disabled={loading}
              >
                {cve}
              </button>
            ))}
          </div>
        </div>
      )}

      {showFilters && (
        <div style={styles.filterPanel}>
          <div style={styles.filterGroup}>
            <label style={styles.label}>Severity</label>
            <select
              style={styles.select}
              value={filters.severity || ''}
              onChange={(e) => setFilters(prev => ({ ...prev, severity: e.target.value }))}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
          
          <div style={styles.filterGroup}>
            <label style={styles.label}>KEV Status</label>
            <select
              style={styles.select}
              value={filters.kevStatus || ''}
              onChange={(e) => setFilters(prev => ({ ...prev, kevStatus: e.target.value }))}
            >
              <option value="">All</option>
              <option value="true">KEV Listed</option>
              <option value="false">Not KEV Listed</option>
            </select>
          </div>
          
          <div style={styles.filterGroup}>
            <label style={styles.label}>Vendor</label>
            <input
              type="text"
              style={styles.input}
              placeholder="e.g., Microsoft, Apache"
              value={filters.vendor || ''}
              onChange={(e) => setFilters(prev => ({ ...prev, vendor: e.target.value }))}
            />
          </div>
          
          <div style={{ display: 'flex', gap: '8px', alignItems: 'end' }}>
            <button
              style={{ ...styles.button, ...styles.buttonSecondary }}
              onClick={() => setFilters({})}
            >
              Clear Filters
            </button>
          </div>
        </div>
      )}

      <div style={{ 
        fontSize: '0.75rem', 
        color: settings.darkMode ? '#cbd5e1' : '#6b7280', 
        marginTop: '12px',
        padding: '12px',
        background: settings.darkMode ? '#1e293b' : '#f9fafb',
        borderRadius: '6px',
        border: settings.darkMode ? '1px solid #475569' : '1px solid #e5e7eb'
      }}>
        <strong style={{ color: settings.darkMode ? '#f1f5f9' : '#1f2937' }}>Live Data Sources:</strong> NIST NVD • FIRST.org EPSS • CISA KEV Catalog
        {settings.geminiApiKey && (
          <span style={{ marginLeft: '8px' }}>
            <strong style={{ color: '#8b5cf6' }}>AI Enhanced:</strong> Gemini {settings.geminiModel}
            {settings.geminiModel?.includes('2.0') && (
              <span style={{ 
                marginLeft: '4px',
                padding: '2px 6px',
                background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                color: 'white',
                borderRadius: '4px',
                fontSize: '0.7rem'
              }}>
                🌐 WEB GROUNDED
              </span>
            )}
          </span>
        )}
      </div>
    </div>
  );
};

const EnhancedDashboard = ({ vulnerabilities }) => {
  const { settings } = useContext(AppContext);
  const styles = getStyles(settings.darkMode);

  const severityData = [
    { name: 'Critical', value: vulnerabilities.filter(v => v.priority === 'CRITICAL').length, color: '#ef4444' },
    { name: 'High', value: vulnerabilities.filter(v => v.priority === 'HIGH').length, color: '#f59e0b' },
    { name: 'Medium', value: vulnerabilities.filter(v => v.priority === 'MEDIUM').length, color: '#3b82f6' },
    { name: 'Low', value: vulnerabilities.filter(v => v.priority === 'LOW').length, color: '#10b981' }
  ].filter(item => item.value > 0);

  const epssDistribution = [
    { name: 'Very High (>70%)', value: vulnerabilities.filter(v => v.epss && v.epss.epss > 0.7).length, color: '#dc2626' },
    { name: 'High (50-70%)', value: vulnerabilities.filter(v => v.epss && v.epss.epss > 0.5 && v.epss.epss <= 0.7).length, color: '#ea580c' },
    { name: 'Medium (20-50%)', value: vulnerabilities.filter(v => v.epss && v.epss.epss > 0.2 && v.epss.epss <= 0.5).length, color: '#d97706' },
    { name: 'Low (<20%)', value: vulnerabilities.filter(v => v.epss && v.epss.epss <= 0.2).length, color: '#65a30d' },
    { name: 'No EPSS Data', value: vulnerabilities.filter(v => !v.epss).length, color: '#6b7280' }
  ].filter(item => item.value > 0);

  const avgCvssScore = vulnerabilities.reduce((acc, v) => {
    const score = v.cve.cvssV3?.baseScore || 0;
    return acc + score;
  }, 0) / vulnerabilities.length;

  const avgEpssScore = vulnerabilities.reduce((acc, v) => {
    const score = v.epss?.epss || 0;
    return acc + score;
  }, 0) / vulnerabilities.length;

  return (
    <div style={styles.dashboardGrid}>
      <div style={styles.chartContainer}>
        <h3 style={{ margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <PieChart size={20} />
          Priority Distribution
        </h3>
        <ResponsiveContainer width="100%" height={200}>
          <RechartsPieChart>
            <Pie
              data={severityData}
              cx="50%"
              cy="50%"
              outerRadius={80}
              fill="#8884d8"
              dataKey="value"
              label={(entry) => `${entry.name}: ${entry.value}`}
            >
              {severityData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip />
          </RechartsPieChart>
        </ResponsiveContainer>
      </div>

      <div style={styles.chartContainer}>
        <h3 style={{ margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Target size={20} />
          EPSS Exploitation Probability
        </h3>
        <ResponsiveContainer width="100%" height={200}>
          <RechartsPieChart>
            <Pie
              data={epssDistribution}
              cx="50%"
              cy="50%"
              outerRadius={80}
              fill="#8884d8"
              dataKey="value"
              label={(entry) => `${entry.value}`}
            >
              {epssDistribution.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip formatter={(value, name) => [value, name]} />
            <Legend />
          </RechartsPieChart>
        </ResponsiveContainer>
      </div>

      <div style={styles.chartContainer}>
        <h3 style={{ margin: '0 0 16px 0' }}>Risk Overview</h3>
        <div style={{ display: 'grid', gap: '12px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>Total CVEs</span>
            <span style={{ fontWeight: 'bold', fontSize: '1.25rem' }}>{vulnerabilities.length}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>KEV Listed</span>
            <span style={{ fontWeight: 'bold', fontSize: '1.25rem', color: '#ef4444' }}>
              {vulnerabilities.filter(v => v.kev).length}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>High EPSS (&gt;50%)</span>
            <span style={{ fontWeight: 'bold', fontSize: '1.25rem', color: '#f59e0b' }}>
              {vulnerabilities.filter(v => v.epss && v.epss.epss > 0.5).length}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>Fix This Release</span>
            <span style={{ fontWeight: 'bold', fontSize: '1.25rem', color: '#dc2626' }}>
              {vulnerabilities.filter(v => {
                const rec = v.releaseRecommendation;
                return (typeof rec === 'string' && rec === 'FIX_THIS_RELEASE') || 
                       (typeof rec === 'object' && rec?.recommendation === 'FIX_THIS_RELEASE');
              }).length}
            </span>
          </div>
          {settings.geminiApiKey && (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>AI Enhanced</span>
              <span style={{ fontWeight: 'bold', fontSize: '1.25rem', color: '#8b5cf6' }}>
                {vulnerabilities.filter(v => v.aiEnhanced).length}
              </span>
            </div>
          )}
        </div>
      </div>

      <div style={styles.chartContainer}>
        <h3 style={{ margin: '0 0 16px 0' }}>Average Scores</h3>
        <div style={{ display: 'grid', gap: '16px' }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#3b82f6' }}>
              {avgCvssScore.toFixed(1)}
            </div>
            <div style={{ fontSize: '0.875rem', color: settings.darkMode ? '#94a3b8' : '#6b7280' }}>
              Average CVSS Score
            </div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#f59e0b' }}>
              {(avgEpssScore * 100).toFixed(1)}%
            </div>
            <div style={{ fontSize: '0.875rem', color: settings.darkMode ? '#94a3b8' : '#6b7280' }}>
              Average EPSS Score
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const AIAnalysisButton = ({ vulnerability }) => {
  const [showAnalysis, setShowAnalysis] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [debugInfo, setDebugInfo] = useState(null);
  const { settings, addNotification } = useContext(AppContext);
  
  const styles = getStyles(settings.darkMode);

  const generateAIAnalysis = async () => {
    setAnalysis(null);
    setDebugInfo(null);
    setShowAnalysis(false);
    
    if (!settings.geminiApiKey) {
      const error = 'No Gemini API key configured';
      setDebugInfo({ error, step: 'API_KEY_CHECK' });
      addNotification({
        type: 'error',
        title: 'API Key Required',
        message: 'Please configure your Gemini API key in settings'
      });
      return;
    }

    if (!settings.geminiApiKey.trim() || settings.geminiApiKey.length < 10) {
      const error = 'Invalid Gemini API key format';
      setDebugInfo({ error, step: 'API_KEY_VALIDATION' });
      addNotification({
        type: 'error',
        title: 'Invalid API Key',
        message: 'Please check your Gemini API key format'
      });
      return;
    }

    setLoading(true);
    setDebugInfo({ step: 'STARTING', timestamp: new Date().toISOString() });
    
    try {
      console.log('🚀 Starting AI Analysis for', vulnerability.cve.id);
      console.log('🔑 Using API Key:', settings.geminiApiKey.substring(0, 10) + '...');
      console.log('🤖 Using Model:', settings.geminiModel);
      
      setDebugInfo(prev => ({ ...prev, step: 'CALLING_API', apiKey: settings.geminiApiKey.substring(0, 10) + '...', model: settings.geminiModel }));
      
      const enhancedAnalysis = await generateEnhancedAIAnalysis(
        vulnerability,
        settings.geminiApiKey,
        settings.geminiModel
      );
      
      console.log('🔍 Raw AI Analysis Response:', enhancedAnalysis);
      console.log('🔍 Response Type:', typeof enhancedAnalysis);
      console.log('🔍 Response Keys:', enhancedAnalysis ? Object.keys(enhancedAnalysis) : 'null');
      
      setDebugInfo(prev => ({ 
        ...prev, 
        step: 'RESPONSE_RECEIVED', 
        responseType: typeof enhancedAnalysis,
        responseKeys: enhancedAnalysis ? Object.keys(enhancedAnalysis) : null,
        hasAnalysis: enhancedAnalysis?.analysis ? 'yes' : 'no',
        analysisLength: enhancedAnalysis?.analysis?.length || 0,
        analysisPreview: enhancedAnalysis?.analysis?.substring(0, 100) || '',
        analysisSuffix: enhancedAnalysis?.analysis?.substring(Math.max(0, (enhancedAnalysis?.analysis?.length || 0) - 100)) || ''
      }));
      
      let normalizedAnalysis;
      
      if (typeof enhancedAnalysis === 'string') {
        console.log('📝 Handling string response');
        normalizedAnalysis = {
          analysis: enhancedAnalysis,
          ragUsed: false,
          webGrounded: false,
          ragDocs: 0,
          ragSources: []
        };
      } else if (enhancedAnalysis && typeof enhancedAnalysis === 'object') {
        console.log('📝 Handling object response');
        if (enhancedAnalysis.analysis && typeof enhancedAnalysis.analysis === 'string') {
          normalizedAnalysis = {
            analysis: enhancedAnalysis.analysis,
            ragUsed: Boolean(enhancedAnalysis.ragUsed),
            webGrounded: Boolean(enhancedAnalysis.webGrounded),
            ragDocs: Number(enhancedAnalysis.ragDocs) || 0,
            ragSources: Array.isArray(enhancedAnalysis.ragSources) ? enhancedAnalysis.ragSources : []
          };
        } else {
          throw new Error(`Invalid object response: missing or invalid analysis property. Keys: ${Object.keys(enhancedAnalysis)}`);
        }
      } else {
        throw new Error(`Invalid response format: expected string or object, got ${typeof enhancedAnalysis}`);
      }
      
      if (!normalizedAnalysis.analysis || normalizedAnalysis.analysis.trim().length === 0) {
        throw new Error('Empty analysis content received');
      }
      
      console.log('✅ Normalized Analysis:', normalizedAnalysis);
      console.log('✅ Analysis Preview:', normalizedAnalysis.analysis.substring(0, 200) + '...');
      
      setDebugInfo(prev => ({ 
        ...prev, 
        step: 'ANALYSIS_NORMALIZED',
        normalized: true,
        finalAnalysisLength: normalizedAnalysis.analysis.length
      }));
      
      setAnalysis(normalizedAnalysis);
      
      console.log('📱 Analysis state set, showing UI...');
      setDebugInfo(prev => ({ ...prev, step: 'STATE_SET' }));
      
      setShowAnalysis(true);
      
      setDebugInfo(prev => ({ ...prev, step: 'UI_SHOWN', success: true }));
      
      const ragInfo = normalizedAnalysis.ragUsed ? ` with ${normalizedAnalysis.ragDocs} RAG docs` : '';
      const webInfo = normalizedAnalysis.webGrounded ? ' and web grounding' : '';
      
      addNotification({
        type: 'success',
        title: 'Complete AI Analysis Generated',
        message: `Full threat intelligence analysis generated successfully${ragInfo}${webInfo} (${normalizedAnalysis.analysis.length} chars) - Complete display confirmed`
      });
      
    } catch (error) {
      console.error('💥 AI Analysis Error:', error);
      console.error('💥 Error Stack:', error.stack);
      
      setDebugInfo(prev => ({ 
        ...prev, 
        step: 'ERROR', 
        error: error.message,
        errorType: error.constructor.name,
        timestamp: new Date().toISOString()
      }));
      
      setAnalysis(null);
      setShowAnalysis(false);
      
      addNotification({
        type: 'error',
        title: 'AI Analysis Failed',
        message: `Error: ${error.message}`
      });
    } finally {
      setLoading(false);
      setDebugInfo(prev => ({ ...prev, loadingComplete: new Date().toISOString() }));
    }
  };

  const renderAnalysisContent = () => {
    if (!analysis) {
      return (
        <div style={{ color: '#ef4444', fontStyle: 'italic' }}>
          No analysis available
          {debugInfo && (
            <div style={{ fontSize: '0.7rem', marginTop: '4px', opacity: 0.7 }}>
              Debug: {debugInfo.step} {debugInfo.error && `- ${debugInfo.error}`}
            </div>
          )}
        </div>
      );
    }
    
    if (typeof analysis !== 'object' || !analysis.analysis) {
      console.error('Invalid analysis object:', analysis);
      return (
        <div style={{ color: '#ef4444', fontStyle: 'italic' }}>
          Invalid analysis format
          <div style={{ fontSize: '0.7rem', marginTop: '4px', opacity: 0.7 }}>
            Type: {typeof analysis}, Has analysis prop: {analysis?.analysis ? 'yes' : 'no'}
          </div>
        </div>
      );
    }
    
    if (typeof analysis.analysis !== 'string' || analysis.analysis.trim().length === 0) {
      console.error('Invalid analysis content:', analysis.analysis);
      return (
        <div style={{ color: '#ef4444', fontStyle: 'italic' }}>
          Empty analysis content
          <div style={{ fontSize: '0.7rem', marginTop: '4px', opacity: 0.7 }}>
            Content type: {typeof analysis.analysis}, Length: {analysis.analysis?.length || 0}
          </div>
        </div>
      );
    }
    
    // Return the complete analysis content without any truncation or modification
    return (
      <div style={{ 
        width: '100%',
        display: 'block',
        whiteSpace: 'pre-wrap',
        wordWrap: 'break-word',
        overflowWrap: 'break-word'
      }}>
        {/* Display the COMPLETE analysis text exactly as received */}
        {analysis.analysis}
      </div>
    );
  };

  const renderMetadata = () => {
    if (!analysis || typeof analysis !== 'object') {
      return null;
    }
    
    const parts = [`🤖 Generated by ${settings.geminiModel || 'Gemini'}`];
    
    if (settings.geminiModel?.includes('2.0')) {
      parts.push('🌐 Enhanced with real-time web search and current threat intelligence');
    } else {
      parts.push('Enhanced security intelligence');
    }
    
    if (analysis.ragUsed && analysis.ragDocs > 0) {
      parts.push(`📚 Enhanced with security knowledge base (${analysis.ragDocs} docs)`);
    }
    
    if (analysis.webGrounded) {
      parts.push('🌐 Web-grounded analysis');
    }
    
    return parts.join(' • ');
  };

  const renderDebugInfo = () => {
    if (!debugInfo) return null;
    
    return (
      <details style={{ marginTop: '8px', fontSize: '0.7rem', opacity: 0.7 }}>
        <summary style={{ cursor: 'pointer' }}>🔧 Debug Info</summary>
        <pre style={{ 
          background: settings.darkMode ? '#1e293b' : '#f8fafc', 
          padding: '8px', 
          borderRadius: '4px', 
          marginTop: '4px',
          overflow: 'auto',
          maxHeight: '100px'
        }}>
          {JSON.stringify(debugInfo, null, 2)}
        </pre>
      </details>
    );
  };

  return (
    <>
      <button
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '4px',
          padding: '2px 8px',
          background: settings.geminiApiKey ? (loading ? '#6b7280' : '#8b5cf6') : '#6b7280',
          color: 'white',
          border: 'none',
          borderRadius: '4px',
          fontSize: '0.7rem',
          fontWeight: '500',
          cursor: settings.geminiApiKey && !loading ? 'pointer' : 'not-allowed',
          opacity: settings.geminiApiKey ? 1 : 0.7
        }}
        onClick={generateAIAnalysis}
        disabled={!settings.geminiApiKey || loading}
        title={
          !settings.geminiApiKey ? 'Configure Gemini API key in settings' :
          loading ? 'Generating analysis...' :
          'AI Security Analysis'
        }
      >
        {loading ? <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> : <Brain size={12} />}
        {loading ? 'Analyzing...' : 'AI Analysis'}
        {settings.geminiModel?.includes('2.0') && !loading && (
          <span style={{
            fontSize: '0.6rem',
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            color: 'white',
            padding: '1px 4px',
            borderRadius: '3px',
            marginLeft: '4px'
          }}>
            WEB
          </span>
        )}
      </button>

      {debugInfo && (
        <span style={{
          marginLeft: '8px',
          fontSize: '0.6rem',
          padding: '2px 6px',
          borderRadius: '3px',
          background: debugInfo.error ? '#ef4444' : 
                     debugInfo.success ? '#10b981' : '#f59e0b',
          color: 'white'
        }}>
          {debugInfo.step}
        </span>
      )}

      {(showAnalysis || debugInfo?.error) && (
        <div style={{
          marginTop: '12px',
          padding: '12px',
          background: settings.darkMode ? '#312e81' : '#f3e8ff',
          borderRadius: '6px',
          border: settings.darkMode ? '1px solid #4338ca' : '1px solid #c084fc',
          width: '100%',
          boxSizing: 'border-box'
        }}>
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center',
            marginBottom: '8px' 
          }}>
            <span style={{ 
              fontWeight: '600', 
              fontSize: '0.8rem',
              color: settings.darkMode ? '#a5b4fc' : '#7c3aed',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}>
              🤖 AI Security Analysis
              <span style={{
                fontSize: '0.6rem',
                background: settings.geminiModel?.includes('2.0') ? 
                  'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' : 
                  'linear-gradient(135deg, #8b5cf6 0%, #a855f7 100%)',
                color: 'white',
                padding: '2px 6px',
                borderRadius: '4px'
              }}>
                {settings.geminiModel?.includes('2.0') ? '🌐 WEB GROUNDED' : settings.geminiModel?.toUpperCase() || 'GEMINI'}
              </span>
              {analysis && (
                <span style={{
                  fontSize: '0.6rem',
                  background: '#10b981',
                  color: 'white',
                  padding: '2px 6px',
                  borderRadius: '4px'
                }}>
                  {analysis.analysis?.length || 0} chars
                </span>
              )}
            </span>
            <button
              onClick={() => {
                setShowAnalysis(false);
                setDebugInfo(null);
              }}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                color: settings.darkMode ? '#a5b4fc' : '#7c3aed'
              }}
            >
              <X size={14} />
            </button>
          </div>
          
          <div style={{
            fontSize: '0.9rem',
            lineHeight: '1.7',
            color: settings.darkMode ? '#e2e8f0' : '#1f2937',
            whiteSpace: 'pre-wrap', // CRITICAL: Preserves all formatting and line breaks
            wordWrap: 'break-word', // Handles long words
            overflowWrap: 'break-word', // Additional word wrapping
            wordBreak: 'break-word', // Ensures proper word breaking
            maxHeight: 'none', // NO height restrictions
            height: 'auto', // Auto-size to content
            overflow: 'visible', // Show ALL content
            overflowY: 'visible', // No vertical scrolling
            overflowX: 'visible', // No horizontal scrolling
            padding: '20px',
            background: settings.darkMode ? 'rgba(15, 23, 42, 0.5)' : 'rgba(248, 250, 252, 0.8)',
            borderRadius: '8px',
            border: settings.darkMode ? '1px solid rgba(71, 85, 105, 0.3)' : '1px solid rgba(226, 232, 240, 0.5)',
            fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
            width: '100%',
            boxSizing: 'border-box',
            display: 'block',
            minHeight: 'auto',
            position: 'relative'
          }}>
            {/* Display COMPLETE analysis with enhanced debug info */}
            {renderAnalysisContent()}
            
            {/* Enhanced debug display for analysis completeness */}
            {analysis && (
              <div style={{
                marginTop: '16px',
                padding: '8px',
                background: settings.darkMode ? 'rgba(59, 130, 246, 0.1)' : 'rgba(59, 130, 246, 0.05)',
                borderRadius: '4px',
                fontSize: '0.7rem',
                color: settings.darkMode ? '#93c5fd' : '#1d4ed8',
                borderLeft: '3px solid #3b82f6'
              }}>
                📊 <strong>Complete Analysis Display Confirmed:</strong> {analysis.analysis?.length || 0} characters fully rendered
                {analysis.analysis && ` • ${analysis.analysis.split('\n').length} lines displayed`}
                {analysis.analysis && ` • ${analysis.analysis.split(' ').length} words shown`}
                {analysis.analysis && ` • ${Math.ceil(analysis.analysis.length / 80)} text rows`}
                {analysis.analysis && analysis.analysis.length > 2000 && ' • ✅ COMPREHENSIVE ANALYSIS'}
              </div>
            )}
          </div>
          
          {analysis && (
            <div style={{
              marginTop: '12px',
              padding: '8px 12px',
              background: settings.darkMode ? 'rgba(139, 92, 246, 0.15)' : 'rgba(139, 92, 246, 0.08)',
              borderRadius: '6px',
              fontSize: '0.75rem',
              color: settings.darkMode ? '#a78bfa' : '#7c3aed',
              borderLeft: '3px solid #8b5cf6'
            }}>
              {renderMetadata()}
            </div>
          )}
          
          {/* Always show action buttons for any analysis with content */}
          {analysis && analysis.analysis && analysis.analysis.length > 100 && (
            <div style={{
              marginTop: '12px',
              display: 'flex',
              gap: '8px',
              flexWrap: 'wrap'
            }}>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(analysis.analysis).then(() => {
                    addNotification({
                      type: 'success',
                      title: 'Copied to Clipboard',
                      message: 'Complete AI analysis copied to clipboard'
                    });
                  }).catch(() => {
                    addNotification({
                      type: 'error',
                      title: 'Copy Failed',
                      message: 'Could not copy to clipboard'
                    });
                  });
                }}
                style={{
                  ...styles.button,
                  ...styles.buttonSecondary,
                  fontSize: '0.75rem',
                  padding: '6px 12px'
                }}
              >
                📋 Copy Full Analysis
              </button>
              
              <button
                onClick={() => {
                  const blob = new Blob([analysis.analysis], { type: 'text/plain' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `${vulnerability.cve.id}_Complete_AI_Analysis.txt`;
                  document.body.appendChild(a);
                  a.click();
                  document.body.removeChild(a);
                  URL.revokeObjectURL(url);
                  
                  addNotification({
                    type: 'success',
                    title: 'Download Started',
                    message: 'Complete AI analysis download started'
                  });
                }}
                style={{
                  ...styles.button,
                  ...styles.buttonSecondary,
                  fontSize: '0.75rem',
                  padding: '6px 12px'
                }}
              >
                💾 Download Complete Analysis
              </button>
              
              <button
                onClick={() => {
                  const printWindow = window.open('', '_blank');
                  printWindow.document.write(`
                    <html>
                      <head>
                        <title>Complete AI Security Analysis - ${vulnerability.cve.id}</title>
                        <style>
                          body { 
                            font-family: 'Inter', Arial, sans-serif; 
                            line-height: 1.6; 
                            margin: 40px; 
                            max-width: 800px;
                            color: #1f2937;
                          }
                          h1 { 
                            color: #2563eb; 
                            border-bottom: 2px solid #2563eb; 
                            padding-bottom: 10px; 
                            margin-bottom: 20px;
                          }
                          pre { 
                            white-space: pre-wrap; 
                            word-wrap: break-word; 
                            font-family: inherit;
                            background: #f8fafc;
                            padding: 20px;
                            border-radius: 8px;
                            border-left: 4px solid #2563eb;
                          }
                          .meta { 
                            background: #f3f4f6; 
                            padding: 15px; 
                            border-radius: 8px; 
                            margin: 20px 0; 
                            border-left: 4px solid #8b5cf6;
                          }
                          .footer {
                            margin-top: 30px;
                            padding-top: 20px;
                            border-top: 1px solid #e5e7eb;
                            font-size: 0.875rem;
                            color: #6b7280;
                          }
                        </style>
                      </head>
                      <body>
                        <h1>Complete AI Security Analysis - ${vulnerability.cve.id}</h1>
                        <div class="meta">
                          <strong>Generated:</strong> ${new Date().toLocaleString()}<br>
                          <strong>Model:</strong> ${settings.geminiModel}<br>
                          <strong>RAG Enhanced:</strong> ${analysis.ragUsed ? 'Yes' : 'No'}<br>
                          <strong>Web Grounded:</strong> ${analysis.webGrounded ? 'Yes' : 'No'}<br>
                          <strong>Analysis Length:</strong> ${analysis.analysis.length} characters
                        </div>
                        <pre>${analysis.analysis}</pre>
                        <div class="footer">
                          <p><strong>Vulnerability Intelligence Platform</strong><br>
                          Real-time Security Intelligence • NIST NVD • FIRST EPSS • CISA KEV • AI Analysis</p>
                        </div>
                      </body>
                    </html>
                  `);
                  printWindow.document.close();
                  printWindow.print();
                }}
                style={{
                  ...styles.button,
                  ...styles.buttonSecondary,
                  fontSize: '0.75rem',
                  padding: '6px 12px'
                }}
              >
                🖨️ Print Full Analysis
              </button>
              
              {/* Show analysis statistics */}
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '6px 12px',
                background: settings.darkMode ? 'rgba(16, 185, 129, 0.1)' : 'rgba(16, 185, 129, 0.05)',
                borderRadius: '4px',
                fontSize: '0.75rem',
                color: settings.darkMode ? '#6ee7b7' : '#059669',
                border: settings.darkMode ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(16, 185, 129, 0.2)'
              }}>
                📊 Analysis: {analysis.analysis.length} chars • {analysis.analysis.split('\n').length} lines
                {analysis.ragUsed && ` • RAG: ${analysis.ragDocs} docs`}
                {analysis.webGrounded && ' • Web Enhanced'}
              </div>
            </div>
          )}
          
          {renderDebugInfo()}
        </div>
      )}
    </>
  );
};

const VulnerabilityList = ({ vulnerabilities }) => {
  const { settings } = useContext(AppContext);
  const styles = getStyles(settings.darkMode);

  const getSeverityStyle = (severity) => {
    switch (severity) {
      case 'CRITICAL': return styles.badgeCritical;
      case 'HIGH': return styles.badgeHigh;
      case 'MEDIUM': return styles.badgeMedium;
      case 'LOW': return styles.badgeLow;
      default: return styles.badge;
    }
  };

  const getReleaseRecommendationStyle = (releaseRec) => {
    if (!releaseRec || typeof releaseRec === 'string') {
      const recommendation = releaseRec || 'PLAN_FOR_FUTURE';
      switch (recommendation) {
        case 'FIX_THIS_RELEASE':
          return { 
            background: settings.darkMode ? '#7f1d1d' : '#fef2f2', 
            color: settings.darkMode ? '#fca5a5' : '#dc2626', 
            borderColor: settings.darkMode ? '#991b1b' : '#fecaca',
            label: 'Fix This Release',
            urgency: 'CRITICAL'
          };
        case 'FIX_NEXT_RELEASE':
          return { 
            background: settings.darkMode ? '#92400e' : '#fff7ed', 
            color: settings.darkMode ? '#fed7aa' : '#ea580c', 
            borderColor: settings.darkMode ? '#c2410c' : '#fed7aa',
            label: 'Fix Next Release',
            urgency: 'MEDIUM'
          };
        default:
          return { 
            background: settings.darkMode ? '#1e40af' : '#f0f9ff', 
            color: settings.darkMode ? '#93c5fd' : '#0284c7', 
            borderColor: settings.darkMode ? '#2563eb' : '#bae6fd',
            label: 'Plan for Future',
            urgency: 'LOW'
          };
      }
    }
    
    switch (releaseRec.recommendation) {
      case 'FIX_THIS_RELEASE':
        return { 
          background: settings.darkMode ? '#7f1d1d' : '#fef2f2', 
          color: settings.darkMode ? '#fca5a5' : '#dc2626', 
          borderColor: settings.darkMode ? '#991b1b' : '#fecaca',
          label: 'Fix This Release',
          urgency: releaseRec.urgency || 'CRITICAL',
          reasoning: releaseRec.reasoning,
          timeframe: releaseRec.timeframe,
          dueDate: releaseRec.dueDate
        };
      case 'FIX_NEXT_RELEASE':
        return { 
          background: settings.darkMode ? '#92400e' : '#fff7ed', 
          color: settings.darkMode ? '#fed7aa' : '#ea580c', 
          borderColor: settings.darkMode ? '#c2410c' : '#fed7aa',
          label: 'Fix Next Release',
          urgency: releaseRec.urgency || 'MEDIUM',
          reasoning: releaseRec.reasoning,
          timeframe: releaseRec.timeframe,
          dueDate: releaseRec.dueDate
        };
      default:
        return { 
          background: settings.darkMode ? '#1e40af' : '#f0f9ff', 
          color: settings.darkMode ? '#93c5fd' : '#0284c7', 
          borderColor: settings.darkMode ? '#2563eb' : '#bae6fd',
          label: 'Plan for Future',
          urgency: releaseRec.urgency || 'LOW',
          reasoning: releaseRec.reasoning,
          timeframe: releaseRec.timeframe,
          dueDate: releaseRec.dueDate
        };
    }
  };

  return (
    <div style={{ marginTop: '32px' }}>
      <h2 style={{ margin: '0 0 24px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Shield size={24} />
        Vulnerability Analysis ({vulnerabilities.length})
        <span style={{
          ...styles.badge,
          background: '#10b981',
          color: 'white',
          borderColor: '#10b981'
        }}>
          REAL-TIME DATA
        </span>
        {settings.geminiApiKey && (
          <span style={{
            ...styles.badge,
            background: settings.geminiModel?.includes('2.0') ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' : '#8b5cf6',
            color: 'white',
            borderColor: settings.geminiModel?.includes('2.0') ? '#667eea' : '#8b5cf6'
          }}>
            {settings.geminiModel?.includes('2.0') ? '🌐 AI + WEB' : 'AI ENHANCED'}
          </span>
        )}
      </h2>
      
      <div style={{ display: 'grid', gap: '16px' }}>
        {vulnerabilities.map((vuln, index) => {
          const releaseStyle = getReleaseRecommendationStyle(vuln.releaseRecommendation);
          
          return (
            <div key={vuln.cve.id || index} style={{
              ...styles.card,
              borderLeft: vuln.kev ? '4px solid #ef4444' : 
                         vuln.priority === 'CRITICAL' ? '4px solid #dc2626' :
                         vuln.priority === 'HIGH' ? '4px solid #ea580c' : 'none'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '16px' }}>
                <div style={{ flex: 1 }}>
                  <h3 style={{ margin: '0 0 8px 0', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <a 
                      href={`https://nvd.nist.gov/vuln/detail/${vuln.cve.id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ 
                        textDecoration: 'none', 
                        color: settings.darkMode ? '#60a5fa' : '#2563eb',
                        fontWeight: '600'
                      }}
                    >
                      {vuln.cve.id}
                    </a>
                    <span style={{ ...styles.badge, ...getSeverityStyle(vuln.priority) }}>
                      {vuln.priority}
                    </span>
                    {vuln.kev && (
                      <span style={{ ...styles.badge, ...styles.badgeCritical }}>
                        🚨 KEV
                      </span>
                    )}
                    <span style={{ 
                      ...styles.badge, 
                      ...releaseStyle,
                      fontSize: '0.7rem',
                      cursor: 'help'
                    }}
                    title={releaseStyle.reasoning || `${releaseStyle.label} - ${releaseStyle.dueDate || 'No specific deadline'}`}>
                      {releaseStyle.label}
                    </span>
                    {vuln.aiEnhanced && (
                      <span style={{
                        ...styles.badge,
                        background: '#8b5cf6',
                        color: 'white',
                        borderColor: '#8b5cf6',
                        fontSize: '0.7rem'
                      }}>
                        🤖 AI
                      </span>
                    )}
                  </h3>
                  <p style={{ margin: '0 0 12px 0', color: settings.darkMode ? '#cbd5e1' : '#4b5563', lineHeight: '1.5' }}>
                    {vuln.cve.description.length > 300 ? 
                      vuln.cve.description.substring(0, 300) + '...' : 
                      vuln.cve.description
                    }
                  </p>
                </div>
                
                <div style={{ textAlign: 'right', fontSize: '0.875rem', minWidth: '120px', marginLeft: '16px' }}>
                  <div style={{ marginBottom: '4px' }}>
                    <strong>Risk Score:</strong> {vuln.riskScore?.toFixed(1)}/10
                  </div>
                  {vuln.cve.cvssV3 && (
                    <div style={{ marginBottom: '4px' }}>
                      <strong>CVSS v3:</strong> {vuln.cve.cvssV3.baseScore?.toFixed(1)}
                    </div>
                  )}
                  {vuln.epss && (
                    <div style={{ marginBottom: '4px' }}>
                      <strong>EPSS:</strong> {(vuln.epss.epss * 100).toFixed(1)}%
                    </div>
                  )}
                  <div style={{ fontSize: '0.75rem', color: settings.darkMode ? '#94a3b8' : '#6b7280' }}>
                    Updated: {new Date(vuln.lastUpdated).toLocaleDateString()}
                  </div>
                </div>
              </div>

              {vuln.kev && (
                <div style={{
                  background: settings.darkMode ? '#7f1d1d' : '#fef2f2',
                  border: settings.darkMode ? '1px solid #991b1b' : '1px solid #fecaca',
                  borderRadius: '6px',
                  padding: '12px',
                  marginBottom: '12px'
                }}>
                  <div style={{ fontWeight: '600', color: settings.darkMode ? '#fca5a5' : '#dc2626', marginBottom: '4px' }}>
                    🚨 CISA Known Exploited Vulnerability
                  </div>
                  <div style={{ fontSize: '0.875rem', color: settings.darkMode ? '#fca5a5' : '#991b1b' }}>
                    <strong>Required Action:</strong> {vuln.kev.requiredAction}
                  </div>
                  <div style={{ fontSize: '0.875rem', color: settings.darkMode ? '#fca5a5' : '#991b1b' }}>
                    <strong>Due Date:</strong> {vuln.kev.dueDate}
                  </div>
                </div>
              )}
              
              {vuln.tags && vuln.tags.length > 0 && (
                <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginBottom: '12px' }}>
                  {vuln.tags.map((tag, i) => (
                    <span key={i} style={{
                      ...styles.badge,
                      background: settings.darkMode ? '#374151' : '#f3f4f6',
                      color: settings.darkMode ? '#d1d5db' : '#374151',
                      borderColor: settings.darkMode ? '#4b5563' : '#d1d5db',
                      fontSize: '0.7rem'
                    }}>
                      {tag}
                    </span>
                  ))}
                </div>
              )}

              {vuln.securityAdvisories && vuln.securityAdvisories.length > 0 && (
                <div style={{
                  background: settings.darkMode ? '#1e40af' : '#eff6ff',
                  border: settings.darkMode ? '1px solid #3b82f6' : '1px solid #93c5fd',
                  borderRadius: '6px',
                  padding: '12px',
                  marginBottom: '12px'
                }}>
                  <div style={{ fontWeight: '600', color: settings.darkMode ? '#93c5fd' : '#1d4ed8', marginBottom: '8px' }}>
                    🛡️ Security Advisories & Resources ({vuln.securityAdvisories.length})
                  </div>
                  <div style={{ display: 'grid', gap: '6px', maxHeight: '140px', overflowY: 'auto' }}>
                    {vuln.securityAdvisories.slice(0, 8).map((advisory, i) => (
                      <div key={i} style={{ 
                        display: 'flex', 
                        justifyContent: 'space-between', 
                        alignItems: 'center',
                        padding: '6px 0',
                        borderBottom: i < Math.min(vuln.securityAdvisories.length, 8) - 1 ? (settings.darkMode ? '1px solid #374151' : '1px solid #e5e7eb') : 'none'
                      }}>
                        <div style={{ fontSize: '0.8rem', color: settings.darkMode ? '#cbd5e1' : '#374151', flex: 1 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span>{advisory.icon}</span>
                            <span>{advisory.title}</span>
                            {advisory.aiGenerated && (
                              <span style={{
                                fontSize: '0.6rem',
                                background: '#8b5cf6',
                                color: 'white',
                                padding: '1px 4px',
                                borderRadius: '3px'
                              }}>
                                AI
                              </span>
                            )}
                          </div>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <span style={{
                            ...styles.badge,
                            background: advisory.priority === 'CRITICAL' ? '#dc2626' : 
                                       advisory.priority === 'HIGH' ? '#ea580c' : 
                                       advisory.priority === 'MEDIUM' ? '#d97706' : '#65a30d',
                            color: 'white',
                            fontSize: '0.6rem',
                            padding: '2px 6px'
                          }}>
                            {advisory.priority}
                          </span>
                          <a 
                            href={advisory.url} 
                            target="_blank" 
                            rel="noopener noreferrer" 
                            style={{
                              ...styles.linkButton,
                              fontSize: '0.7rem',
                              padding: '2px 6px'
                            }}
                          >
                            <ExternalLink size={10} />
                            View
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              
              <div style={{ display: 'flex', gap: '8px', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                  <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cve.id}`} target="_blank" rel="noopener noreferrer" style={styles.linkButton}>
                    <ExternalLink size={12} />
                    NVD
                  </a>
                  {vuln.epss && (
                    <a href={`https://api.first.org/data/v1/epss?cve=${vuln.cve.id}`} target="_blank" rel="noopener noreferrer" style={styles.linkButton}>
                      <Target size={12} />
                      EPSS
                    </a>
                  )}
                  {vuln.kev && (
                    <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" style={{...styles.linkButton, background: '#dc2626'}}>
                      <AlertTriangle size={12} />
                      KEV
                    </a>
                  )}
                </div>
              </div>
              
              <AIAnalysisButton vulnerability={vuln} />
            </div>
          );
        })}
      </div>
    </div>
  );
};

const EnterpriseVulnerabilityApp = () => {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadingSteps, setLoadingSteps] = useState([]);
  const [filters, setFilters] = useState({});
  const [notifications, setNotifications] = useState([]);
  const [showSettings, setShowSettings] = useState(false);
  const [settings, setSettings] = useState({
    aiAnalysisEnabled: true,
    autoRefresh: false,
    notificationsEnabled: true,
    darkMode: true,
    defaultView: 'detailed',
    resultsPerPage: '10',
    geminiModel: 'gemini-1.5-flash',
    ragEnabled: true,
    realTimeScrapingEnabled: true
  });

  const styles = getStyles(settings.darkMode);

  const addNotification = (notification) => {
      const id = Date.now() + Math.random(); // Add randomness to ensure uniqueness

    setNotifications(prev => [...prev, { ...notification, id }]);
    
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 5000);
  };

  const handleVulnerabilitiesUpdate = (newVulns, searchTerms) => {
    setVulnerabilities(newVulns);
  };

  return (
    <AppContext.Provider
      value={{
        vulnerabilities,
        setVulnerabilities: handleVulnerabilitiesUpdate,
        loading,
        setLoading,
        loadingSteps,
        setLoadingSteps,
        filters,
        setFilters,
        notifications,
        addNotification,
        settings,
        setSettings
      }}
    >
      <div style={styles.appContainer}>
        <NotificationManager />
        <SettingsModal 
          isOpen={showSettings} 
          onClose={() => setShowSettings(false)} 
          settings={settings}
          setSettings={setSettings}
        />
        
        <header style={styles.header}>
          <div style={styles.headerContent}>
            <div style={styles.headerTitle}>
              <Brain size={40} color="white" />
              <div>
                <h1 style={styles.title}>Vulnerability Intelligence Platform</h1>
                <p style={styles.subtitle}>Real-time Security Intelligence • NIST NVD • FIRST EPSS • CISA KEV • AI Analysis</p>
              </div>
            </div>
            <div style={styles.headerActions}>
              <div style={styles.statusIndicator}>
                <Activity size={14} />
                <span>LIVE</span>
              </div>
              <div style={styles.statusIndicator}>
                {settings.geminiApiKey ? (
                  <>
                    {settings.geminiModel?.includes('2.0') ? <Wifi size={14} /> : <Brain size={14} />}
                    <span>{settings.geminiModel?.includes('2.0') ? 'AI + WEB' : 'AI READY'}</span>
                  </>
                ) : (
                  <>
                    <Shield size={14} />
                    <span>SECURE</span>
                  </>
                )}
              </div>
              <button 
                style={{ 
                  ...styles.button, 
                  background: 'rgba(255,255,255,0.2)', 
                  border: '1px solid rgba(255,255,255,0.3)', 
                  color: '#e2e8f0', 
                  fontSize: '0.75rem', 
                  padding: '6px 8px',
                  minWidth: 'auto'
                }}
                onClick={() => setSettings(prev => ({ ...prev, darkMode: !prev.darkMode }))}
                title={settings.darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              >
                {settings.darkMode ? <Sun size={14} /> : <Moon size={14} />}
              </button>
              <button 
                style={{ 
                  ...styles.button, 
                  background: 'rgba(255,255,255,0.2)', 
                  border: '1px solid rgba(255,255,255,0.3)', 
                  color: '#e2e8f0', 
                  fontSize: '0.75rem', 
                  padding: '6px 12px' 
                }}
                onClick={() => setShowSettings(true)}
              >
                <Settings size={14} />
                Settings
              </button>
            </div>
          </div>
        </header>

        <main style={styles.mainContent}>
          <EnhancedSearchComponent />
          
          {vulnerabilities.length > 0 && <EnhancedDashboard vulnerabilities={vulnerabilities} />}

          {loading && (
            <div style={styles.loadingContainer}>
              <div style={{
                background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                color: 'white',
                padding: '32px',
                borderRadius: '12px',
                textAlign: 'center',
                maxWidth: '600px'
              }}>
                <Loader2 size={48} style={{ marginBottom: '16px', animation: 'spin 1s linear infinite' }} />
                <h3 style={{ margin: '0 0 8px 0' }}>Processing Real-time Vulnerability Data</h3>
                <p style={{ margin: '0 0 24px 0', fontSize: '1.1rem' }}>
                  Fetching live data from NIST NVD, FIRST.org EPSS, and CISA KEV databases...
                  {settings.geminiApiKey && ' • AI analysis enabled'}
                </p>
                
                {loadingSteps.length > 0 && (
                  <div style={{ 
                    background: 'rgba(255,255,255,0.1)', 
                    borderRadius: '8px', 
                    padding: '16px',
                    textAlign: 'left',
                    maxHeight: '200px',
                    overflowY: 'auto'
                  }}>
                    {loadingSteps.slice(-8).map((step, index) => (
                      <div key={index} style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: '8px', 
                        marginBottom: '8px',
                        fontSize: '0.875rem'
                      }}>
                        {step.startsWith('✅') ? (
                          <CheckCircle size={16} color="#10b981" />
                        ) : step.startsWith('❌') ? (
                          <XCircle size={16} color="#ef4444" />
                        ) : step.startsWith('⚠️') ? (
                          <AlertTriangle size={16} color="#f59e0b" />
                        ) : step.startsWith('🤖') ? (
                          <Brain size={16} color="#8b5cf6" />
                        ) : (
                          <div style={{ 
                            width: '12px', 
                            height: '12px', 
                            borderRadius: '50%', 
                            background: 'white',
                            opacity: 0.7
                          }} />
                        )}
                        <span>{step}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {!loading && vulnerabilities.length === 0 && (
            <div style={styles.emptyState}>
              <div style={{
                background: settings.darkMode ? '#1e293b' : '#ffffff',
                borderRadius: '12px',
                padding: '48px',
                boxShadow: '0 4px 20px rgba(0, 0, 0, 0.08)',
                border: settings.darkMode ? '1px solid #334155' : '1px solid #e2e8f0',
                maxWidth: '800px',
                margin: '0 auto'
              }}>
                <Shield size={64} style={{ marginBottom: '24px', color: '#3b82f6' }} />
                <h2 style={{ margin: '0 0 12px 0', fontSize: '1.75rem', color: settings.darkMode ? '#e2e8f0' : '#1e293b' }}>Real-time Vulnerability Intelligence</h2>
                <p style={{ margin: '0 0 24px 0', fontSize: '1.1rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                  Advanced vulnerability management platform with live API integrations and AI-powered analysis
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', marginTop: '32px' }}>
                  <div style={{ textAlign: 'center', padding: '16px' }}>
                    <Database size={32} style={{ color: '#3b82f6', marginBottom: '8px' }} />
                    <div style={{ fontWeight: '600', marginBottom: '4px', color: settings.darkMode ? '#e2e8f0' : '#1f2937' }}>Live Data Sources</div>
                    <div style={{ fontSize: '0.875rem', color: settings.darkMode ? '#94a3b8' : '#6b7280' }}>NIST NVD, FIRST EPSS, CISA KEV</div>
                  </div>
                  <div style={{ textAlign: 'center', padding: '16px' }}>
                    <Brain size={32} style={{ color: '#8b5cf6', marginBottom: '8px' }} />
                    <div style={{ fontWeight: '600', marginBottom: '4px', color: settings.darkMode ? '#e2e8f0' : '#1f2937' }}>AI-Powered Analysis</div>
                    <div style={{ fontSize: '0.875rem', color: settings.darkMode ? '#94a3b8' : '#6b7280' }}>
                      {settings.geminiApiKey ? 
                        `${settings.geminiModel}${settings.geminiModel?.includes('2.0') ? ' + Web Grounding' : ''} Ready` : 
                        'Configure in Settings'
                      }
                    </div>
                  </div>
                  <div style={{ textAlign: 'center', padding: '16px' }}>
                    <Target size={32} style={{ color: '#f59e0b', marginBottom: '8px' }} />
                    <div style={{ fontWeight: '600', marginBottom: '4px', color: settings.darkMode ? '#e2e8f0' : '#1f2937' }}>Threat Intelligence</div>
                    <div style={{ fontSize: '0.875rem', color: settings.darkMode ? '#94a3b8' : '#6b7280' }}>Real-time exploitation probability</div>
                  </div>
                </div>
                
                {!settings.geminiApiKey && (
                  <div style={{
                    marginTop: '24px',
                    padding: '16px',
                    background: settings.geminiModel?.includes('2.0') ?
                      'linear-gradient(135deg, rgba(102, 126, 234, 0.1) 0%, rgba(118, 75, 162, 0.1) 100%)' :
                      (settings.darkMode ? '#312e81' : '#f3e8ff'),
                    borderRadius: '8px',
                    border: settings.geminiModel?.includes('2.0') ?
                      '1px solid rgba(102, 126, 234, 0.3)' :
                      (settings.darkMode ? '1px solid #4338ca' : '1px solid #c084fc')
                  }}>
                    <p style={{ margin: 0, fontSize: '0.875rem', color: settings.darkMode ? '#a5b4fc' : '#7c3aed' }}>
                      💡 <strong>Pro Tip:</strong> {settings.geminiModel?.includes('2.0') ? 
                        'Gemini 2.0 with web grounding provides real-time threat intelligence and current security advisories!' :
                        'Add your Gemini API key in Settings to unlock AI-powered security analysis and enhanced advisory search!'
                      }
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {vulnerabilities.length > 0 && <VulnerabilityList vulnerabilities={vulnerabilities} />}
        </main>
      </div>
    </AppContext.Provider>
  );
};

export default EnterpriseVulnerabilityApp;
