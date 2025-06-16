import React, { useState, createContext, useContext, useEffect } from 'react';
import { Search, Shield, AlertTriangle, Loader2, ExternalLink, Brain, Settings, Target, Clock, Database, Activity, CheckCircle, XCircle, X, Upload, Filter, PieChart, Sun, Moon, Eye, EyeOff, Save, FileText, Wifi, WifiOff, GitBranch, Code, Server, Cloud, Zap } from 'lucide-react';
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
        title: "VEX Processing Guidelines",
        content: "VEX (Vulnerability Exploitability eXchange) provides machine-readable information about vulnerability status. VEX Status Values: Not Affected (Product not vulnerable), Affected (Product is vulnerable), Fixed (Product was vulnerable but remediated), Under Investigation (Vendor assessing impact). Key VEX Fields include Product Identification, Vulnerability ID, Status, Action Statement, Impact Statement, and Timestamp.",
        category: "vex",
        tags: ["vex", "vulnerability-exchange", "automation"]
      },
      {
        title: "GitHub Security Advisory Processing",
        content: "GitHub Security Advisories provide vulnerability information for open source projects. Types include GHSA (GitHub-originated), CVE-mapped (Links CVEs to repositories), and Malware identification. Key data points: Affected Packages, Severity Assessment, Vulnerable Versions, Patched Versions, and References.",
        category: "github",
        tags: ["github", "open-source", "packages"]
      },
      {
        title: "EPSS Scoring Methodology",
        content: "EPSS (Exploit Prediction Scoring System) estimates probability of exploitation. Scores range 0-1 with higher values indicating greater exploitation likelihood. EPSS considers CVE characteristics, threat intelligence, and known exploit activity. Updates daily with new threat data.",
        category: "epss",
        tags: ["epss", "exploit-prediction", "scoring"]
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

// Real API functions (no mock data)
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

// GitHub Security Advisories (real API call)
const fetchGitHubSecurityAdvisories = async (cveId, setLoadingSteps, githubToken) => {
  setLoadingSteps(prev => [...prev, `🐙 Fetching GitHub Security Advisories for ${cveId}...`]);
  
  if (!githubToken) {
    setLoadingSteps(prev => [...prev, `⚠️ GitHub token not configured - skipping GitHub advisories`]);
    return [];
  }
  
  try {
    const query = `
      query {
        securityAdvisories(first: 10, identifier: {type: CVE, value: "${cveId}"}) {
          nodes {
            ghsaId
            summary
            description
            severity
            publishedAt
            updatedAt
            withdrawnAt
            vulnerabilities(first: 5) {
              nodes {
                package {
                  ecosystem
                  name
                }
                vulnerableVersionRange
                firstPatchedVersion {
                  identifier
                }
              }
            }
            references {
              url
            }
          }
        }
      }
    `;

    const response = await fetch('https://api.github.com/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${githubToken}`
      },
      body: JSON.stringify({ query })
    });

    if (!response.ok) {
      throw new Error(`GitHub API error: ${response.status}`);
    }

    const data = await response.json();
    
    if (data.data && data.data.securityAdvisories && data.data.securityAdvisories.nodes && data.data.securityAdvisories.nodes.length > 0) {
      setLoadingSteps(prev => [...prev, `✅ Found ${data.data.securityAdvisories.nodes.length} GitHub advisories for ${cveId}`]);
      return data.data.securityAdvisories.nodes;
    } else {
      setLoadingSteps(prev => [...prev, `ℹ️ No GitHub advisories found for ${cveId}`]);
      return [];
    }
    
  } catch (error) {
    console.error(`GitHub API Error for ${cveId}:`, error);
    setLoadingSteps(prev => [...prev, `⚠️ GitHub advisories unavailable for ${cveId}: ${error.message}`]);
    return [];
  }
};

// Utility functions
const calculateOverallRiskScore = (cveData, epssData, kevData) => {
  let score = 0;
  
  // Base CVSS score
  if (cveData.cvssV3?.baseScore) {
    score += cveData.cvssV3.baseScore;
  } else if (cveData.cvssV2?.baseScore) {
    score += cveData.cvssV2.baseScore;
  }
  
  // EPSS contribution
  if (epssData?.epss) {
    score += epssData.epss * 10;
  }
  
  // KEV listing adds significant weight
  if (kevData) {
    score += 3;
  }
  
  return Math.min(score / 2, 10);
};

const calculatePriority = (cveData, epssData, kevData) => {
  if (kevData) return 'CRITICAL';
  
  const cvssScore = cveData.cvssV3?.baseScore || cveData.cvssV2?.baseScore || 0;
  
  if (cvssScore >= 9 || (epssData?.epss && epssData.epss > 0.5)) return 'HIGH';
  if (cvssScore >= 7) return 'MEDIUM';
  return 'LOW';
};

// Enhanced AI Analysis
const generateEnhancedAIAnalysis = async (vulnerability, apiKey, model, settings = {}) => {
  const cveId = vulnerability.cve.id;
  const description = vulnerability.cve.description;
  const cvssScore = vulnerability.cve.cvssV3?.baseScore || vulnerability.cve.cvssV2?.baseScore || 'N/A';
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
      ragSources: ragDocs.map(doc => doc.metadata?.title || 'Unknown').filter(Boolean),
      enhancedSources: vulnerability.enhancedSources || []
    };
  };

  try {
    console.log('🚀 Starting Enhanced AI Analysis for', cveId);
    
    if (!ragDatabase.initialized) {
      console.log('🚀 Initializing RAG database...');
      await ragDatabase.initialize();
    }

    console.log('📚 Performing RAG retrieval for', cveId);
    const ragQuery = `${cveId} ${description.substring(0, 200)} vulnerability analysis security impact mitigation`;
    const relevantDocs = await ragDatabase.search(ragQuery, 5);
    
    const ragContext = relevantDocs.length > 0 ? 
      relevantDocs.map((doc, index) => 
        `[Security Knowledge ${index + 1}] ${doc.metadata.title}:\n${doc.content.substring(0, 400)}...`
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
- Enhanced Risk Score: ${vulnerability.riskScore?.toFixed(1) || 'N/A'}/10

SECURITY KNOWLEDGE BASE:
${ragContext}

${isGemini2 ? 'Search the web for the latest threat intelligence, current exploitation campaigns, and vendor security bulletins for this vulnerability.' : ''}

REQUIREMENTS:
- Provide a detailed analysis of at least 2000 words
- Structure the response with clear sections
- Provide specific actionable recommendations
- Include threat landscape context
- Assess business impact and remediation priorities

Write a comprehensive security assessment following this structure:

# EXECUTIVE SUMMARY

Provide a strategic overview of ${cveId} including severity assessment, exploitation likelihood, and immediate concerns.

# TECHNICAL ANALYSIS

Detail the technical vulnerability, attack vectors, and exploitation mechanisms.

# THREAT INTELLIGENCE ASSESSMENT

Analyze current threat landscape, known exploitation, and threat actor interest.

# BUSINESS IMPACT ASSESSMENT

Evaluate potential organizational impact and risk factors.

# REMEDIATION STRATEGY

Provide detailed action plan with prioritized steps and timelines.

# DETECTION AND MONITORING

Recommend specific detection signatures and monitoring approaches.

# STRATEGIC RECOMMENDATIONS

Summarize key findings and provide executive-level guidance.

Ensure each section provides specific, actionable intelligence based on the vulnerability data and security knowledge base.`;

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
    
    console.log('🔗 Making Enhanced AI API Request:', {
      url: apiUrl,
      model: modelName,
      hasRAG: relevantDocs.length > 0,
      hasWebGrounding: isGemini2
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
      console.error('❌ Enhanced Gemini API Error:', response.status, errorData);
      throw new Error(`Enhanced AI API error: ${response.status} - ${JSON.stringify(errorData)}`);
    }

    const data = await response.json();
    console.log('✅ Enhanced AI analysis response received');
    
    if (!data.candidates || !data.candidates[0] || !data.candidates[0].content) {
      console.error('❌ Invalid enhanced response structure:', data);
      throw new Error('Invalid enhanced API response format - no content generated');
    }
    
    const content = data.candidates[0].content;
    let analysisText = '';
    
    if (content.parts && Array.isArray(content.parts)) {
      analysisText = content.parts.map(part => part.text || '').join('');
      console.log(`📝 Combined ${content.parts.length} enhanced response parts`);
    } else if (content.parts && content.parts[0] && content.parts[0].text) {
      analysisText = content.parts[0].text;
    } else {
      throw new Error('No valid content parts found in enhanced response');
    }
    
    console.log('📝 Enhanced analysis text length:', analysisText?.length);
    
    if (!analysisText || typeof analysisText !== 'string' || analysisText.trim().length === 0) {
      throw new Error('Empty or invalid enhanced analysis text in response');
    }
    
    if (analysisText.length > 500) {
      await ragDatabase.addDocument(
        `Enhanced CVE Analysis: ${cveId}\n\n${analysisText}`,
        {
          title: `Enhanced Security Analysis - ${cveId}`,
          category: 'enhanced-analysis',
          tags: ['cve-analysis', cveId.toLowerCase(), 'ai-enhanced'],
          source: 'enhanced-ai-analysis',
          cvss: cvssScore,
          epss: epssScore,
          kev: kevStatus
        }
      );
      console.log('💾 Stored enhanced analysis in RAG database for future retrieval');
    }
    
    return createAnalysisResult(analysisText, relevantDocs, isGemini2);
    
  } catch (error) {
    console.error('💥 Enhanced AI Analysis Error:', error);
    
    return createAnalysisResult(
      `**Enhanced AI Analysis Error**

An error occurred while generating the enhanced security analysis for ${cveId}:

**Error Details:**
${error.message}

**Manual Analysis Recommendation:**
- Official NVD details: https://nvd.nist.gov/vuln/detail/${cveId}
- MITRE CVE database: https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}
- FIRST EPSS: https://api.first.org/data/v1/epss?cve=${cveId}
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Consider reviewing vendor-specific advisories and threat intelligence feeds for additional context.`,
      [],
      false
    );
  }
};

// Enhanced fetch function
const fetchEnhancedVulnerabilityData = async (cveId, setLoadingSteps, apiKey, githubToken) => {
  try {
    setLoadingSteps(prev => [...prev, `🚀 Starting enhanced analysis for ${cveId}...`]);
    
    // Fetch all data sources in parallel
    const [
      cveResult,
      epssResult,
      kevResult,
      githubResult
    ] = await Promise.allSettled([
      fetchCVEDataFromNVD(cveId, setLoadingSteps, apiKey),
      fetchEPSSData(cveId, setLoadingSteps),
      fetchKEVData(cveId, setLoadingSteps),
      fetchGitHubSecurityAdvisories(cveId, setLoadingSteps, githubToken)
    ]);
    
    const cve = cveResult.status === 'fulfilled' ? cveResult.value : null;
    const epss = epssResult.status === 'fulfilled' ? epssResult.value : null;
    const kev = kevResult.status === 'fulfilled' ? kevResult.value : null;
    const github = githubResult.status === 'fulfilled' ? githubResult.value : null;
    
    if (!cve) {
      throw new Error(`Failed to fetch CVE data for ${cveId}`);
    }
    
    const riskScore = calculateOverallRiskScore(cve, epss, kev);
    const priority = calculatePriority(cve, epss, kev);
    
    setLoadingSteps(prev => [...prev, `✅ Enhanced analysis complete for ${cveId} - Risk Score: ${riskScore.toFixed(1)}`]);
    
    const enhancedSources = ['NVD'];
    if (epss) enhancedSources.push('EPSS');
    if (kev) enhancedSources.push('KEV');
    if (github && github.length > 0) enhancedSources.push('GitHub');
    
    setLoadingSteps(prev => [...prev, `📊 Data sources integrated: ${enhancedSources.join(', ')}`]);
    
    return {
      cve,
      epss,
      kev,
      github,
      riskScore,
      priority,
      dataFreshness: 'REAL_TIME',
      lastUpdated: new Date().toISOString(),
      searchTimestamp: new Date().toISOString(),
      enhancedSources
    };
    
  } catch (error) {
    console.error(`Error processing ${cveId}:`, error);
    throw error;
  }
};

const renderThreatIntelligence = (threatIntel) => {
  if (!threatIntel) return null;
  
  const hasThreats = threatIntel.misp_events?.length > 0 || 
                   threatIntel.stix_indicators?.length > 0 || 
                   Object.values(threatIntel.exploit_availability || {}).some(v => v);
  
  if (!hasThreats) return null;
  
  return (
    <div style={{
      background: 'rgba(239, 68, 68, 0.1)',
      border: '1px solid rgba(239, 68, 68, 0.3)',
      borderRadius: '6px',
      padding: '12px',
      marginBottom: '12px'
    }}>
      <div style={{ fontWeight: '600', color: '#dc2626', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
        <Zap size={16} />
        Active Threat Intelligence
      </div>
      <div style={{ display: 'grid', gap: '6px' }}>
        {threatIntel.misp_events?.length > 0 && (
          <div style={{ fontSize: '0.875rem', color: '#dc2626' }}>
            🎯 <strong>{threatIntel.misp_events.length} MISP event(s)</strong> - Active threat campaigns detected
          </div>
        )}
        {threatIntel.exploit_availability?.metasploit && (
          <div style={{ fontSize: '0.875rem', color: '#dc2626' }}>
            💥 <strong>Metasploit module available</strong> - Exploitation framework ready
          </div>
        )}
        {threatIntel.exploit_availability?.github_pocs > 0 && (
          <div style={{ fontSize: '0.875rem', color: '#dc2626' }}>
            🔬 <strong>{threatIntel.exploit_availability.github_pocs} PoC(s) on GitHub</strong> - Public exploits available
          </div>
        )}
      </div>
    </div>
  );
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
  const [showGitHubKey, setShowGitHubKey] = useState(false);
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
            <h4 style={{ margin: '0 0 16px 0', color: settings.darkMode ? '#e2e8f0' : '#1f2937' }}>API Configuration</h4>
            
            <div style={styles.formGroup}>
              <label style={styles.label}>NVD API Key (Optional - Higher rate limits)</label>
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
              <label style={styles.label}>Gemini API Key (For AI Analysis)</label>
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
              <label style={styles.label}>GitHub Personal Access Token (For Security Advisories)</label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showGitHubKey ? 'text' : 'password'}
                  style={styles.input}
                  placeholder="Enter GitHub PAT for security advisory access"
                  value={localSettings.githubToken || ''}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, githubToken: e.target.value }))}
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
                  onClick={() => setShowGitHubKey(!showGitHubKey)}
                >
                  {showGitHubKey ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>
          </div>

          <div>
            <h4 style={{ margin: '0 0 16px 0', color: settings.darkMode ? '#e2e8f0' : '#1f2937' }}>AI Configuration</h4>
            
            <div style={styles.formGroup}>
              <label style={styles.label}>Gemini Model</label>
              <select
                style={styles.select}
                value={localSettings.geminiModel || 'gemini-2.0-flash'}
                onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiModel: e.target.value }))}
              >
                <option value="gemini-2.0-flash">Gemini 2.0 Flash - 🌐 Web Search + Enhanced Analysis</option>
                <option value="gemini-1.5-flash">Gemini 1.5 Flash (Fast & Efficient)</option>
                <option value="gemini-1.5-pro">Gemini 1.5 Pro (Advanced Analysis)</option>
                <option value="gemini-1.0-pro">Gemini 1.0 Pro (Stable)</option>
              </select>
            </div>

            <div style={styles.formGroup}>
              <label style={{ ...styles.label, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <input
                  type="checkbox"
                  checked={localSettings.aiAnalysisEnabled || false}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, aiAnalysisEnabled: e.target.checked }))}
                />
                Enable AI-Powered Security Analysis
              </label>
            </div>
          </div>

          <div>
            <h4 style={{ margin: '0 0 16px 0', color: settings.darkMode ? '#e2e8f0' : '#1f2937' }}>Display Options</h4>
            
            <div style={styles.formGroup}>
              <label style={{ ...styles.label, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <input
                  type="checkbox"
                  checked={localSettings.darkMode || false}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, darkMode: e.target.checked }))}
                />
                Dark Mode
              </label>
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

const SearchComponent = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [bulkFile, setBulkFile] = useState(null);
  const [searchHistory, setSearchHistory] = useState([]);
  const { 
    setVulnerabilities, 
    setLoading, 
    loading, 
    setLoadingSteps, 
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
      
      setLoadingSteps(prev => [...prev, `🎯 Starting analysis of ${cveIds.length} CVE${cveIds.length > 1 ? 's' : ''}`]);
      
      const vulnerabilityResults = [];
      const failedCves = [];
      
      const batchSize = settings.nvdApiKey ? 10 : 3;
      
      for (let i = 0; i < cveIds.length; i += batchSize) {
        const batch = cveIds.slice(i, i + batchSize);
        setLoadingSteps(prev => [...prev, `📋 Processing batch ${Math.floor(i / batchSize) + 1} of ${Math.ceil(cveIds.length / batchSize)}...`]);
        
        const batchPromises = batch.map(async (cveId) => {
          try {
            const vulnerability = await fetchEnhancedVulnerabilityData(cveId, setLoadingSteps, settings.nvdApiKey, settings.githubToken);
            vulnerabilityResults.push(vulnerability);
            setLoadingSteps(prev => [...prev, `✅ Processing complete for ${cveId}`]);
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
      
      setVulnerabilities(vulnerabilityResults, cveIds);
      
      const criticalCount = vulnerabilityResults.filter(v => v.priority === 'CRITICAL').length;
      const kevCount = vulnerabilityResults.filter(v => v.kev).length;
      const githubCount = vulnerabilityResults.filter(v => v.github && v.github.length > 0).length;
      
      let message = `Analysis complete: ${vulnerabilityResults.length}/${cveIds.length} CVEs`;
      if (criticalCount > 0) message += ` • ${criticalCount} Critical`;
      if (kevCount > 0) message += ` • ${kevCount} KEV`;
      if (githubCount > 0) message += ` • ${githubCount} GitHub`;
      
      addNotification({
        type: 'success',
        title: 'Analysis Complete',
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

  const getEnabledSources = () => {
    const sources = ['NIST NVD', 'FIRST EPSS', 'CISA KEV'];
    if (settings.githubToken) sources.push('GitHub');
    return sources;
  };

  return (
    <div style={styles.searchContainer}>
      <h2 style={{ margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
        <Search size={24} color="#3b82f6" />
        Vulnerability Intelligence Platform
        <span style={{
          ...styles.badge,
          background: '#10b981',
          color: 'white',
          borderColor: '#10b981'
        }}>
          LIVE APIs
        </span>
        {settings.githubToken && (
          <span style={{
            ...styles.badge,
            background: '#6b7280',
            color: 'white',
            borderColor: '#6b7280'
          }}>
            <GitBranch size={12} style={{ marginRight: '4px' }} />
            GITHUB
          </span>
        )}
        {settings.geminiApiKey && (
          <span style={{
            ...styles.badge,
            background: settings.geminiModel?.includes('2.0') ? 
              'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' : '#8b5cf6',
            color: 'white',
            borderColor: settings.geminiModel?.includes('2.0') ? '#667eea' : '#8b5cf6'
          }}>
            {settings.geminiModel?.includes('2.0') ? '🌐 AI + WEB' : 'AI ENABLED'}
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

      <div style={{ 
        fontSize: '0.75rem', 
        color: settings.darkMode ? '#cbd5e1' : '#6b7280', 
        marginTop: '12px',
        padding: '12px',
        background: settings.darkMode ? '#1e293b' : '#f9fafb',
        borderRadius: '6px',
        border: settings.darkMode ? '1px solid #475569' : '1px solid #e5e7eb'
      }}>
        <strong style={{ color: settings.darkMode ? '#f1f5f9' : '#1f2937' }}>Data Sources:</strong> {getEnabledSources().join(' • ')}
        {settings.geminiApiKey && (
          <span style={{ marginLeft: '8px' }}>
            <strong style={{ color: '#8b5cf6' }}>AI Enhanced:</strong> {settings.geminiModel}
            {settings.geminiModel?.includes('2.0') && (
              <span style={{ 
                marginLeft: '4px',
                padding: '2px 6px',
                background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                color: 'white',
                borderRadius: '4px',
                fontSize: '0.7rem'
              }}>
                🌐 WEB SEARCH
              </span>
            )}
          </span>
        )}
      </div>
    </div>
  );
};

const Dashboard = ({ vulnerabilities }) => {
  const { settings } = useContext(AppContext);
  const styles = getStyles(settings.darkMode);

  const severityData = [
    { name: 'Critical', value: vulnerabilities.filter(v => v.priority === 'CRITICAL').length, color: '#ef4444' },
    { name: 'High', value: vulnerabilities.filter(v => v.priority === 'HIGH').length, color: '#f59e0b' },
    { name: 'Medium', value: vulnerabilities.filter(v => v.priority === 'MEDIUM').length, color: '#3b82f6' },
    { name: 'Low', value: vulnerabilities.filter(v => v.priority === 'LOW').length, color: '#10b981' }
  ].filter(item => item.value > 0);

  const dataSourcesData = [
    { name: 'NVD Only', value: vulnerabilities.filter(v => v.enhancedSources?.length === 1).length, color: '#6b7280' },
    { name: '2-3 Sources', value: vulnerabilities.filter(v => v.enhancedSources?.length >= 2 && v.enhancedSources?.length <= 3).length, color: '#3b82f6' },
    { name: '4+ Sources', value: vulnerabilities.filter(v => v.enhancedSources?.length >= 4).length, color: '#10b981' }
  ].filter(item => item.value > 0);

  const avgRiskScore = vulnerabilities.reduce((acc, v) => acc + (v.riskScore || 0), 0) / vulnerabilities.length;

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
          <Database size={20} />
          Data Source Coverage
        </h3>
        <ResponsiveContainer width="100%" height={200}>
          <RechartsPieChart>
            <Pie
              data={dataSourcesData}
              cx="50%"
              cy="50%"
              outerRadius={80}
              fill="#8884d8"
              dataKey="value"
              label={(entry) => `${entry.value}`}
            >
              {dataSourcesData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip formatter={(value, name) => [value, name]} />
            <Legend />
          </RechartsPieChart>
        </ResponsiveContainer>
      </div>

      <div style={styles.chartContainer}>
        <h3 style={{ margin: '0 0 16px 0' }}>Summary Statistics</h3>
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
            <span>GitHub Advisories</span>
            <span style={{ fontWeight: 'bold', fontSize: '1.25rem', color: '#6b7280' }}>
              {vulnerabilities.filter(v => v.github && v.github.length > 0).length}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>Avg Risk Score</span>
            <span style={{ fontWeight: 'bold', fontSize: '1.25rem', color: '#8b5cf6' }}>
              {avgRiskScore.toFixed(1)}/10
            </span>
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
  const { settings, addNotification } = useContext(AppContext);
  
  const styles = getStyles(settings.darkMode);

  const generateAIAnalysis = async () => {
    setAnalysis(null);
    setShowAnalysis(false);
    
    if (!settings.geminiApiKey) {
      addNotification({
        type: 'error',
        title: 'API Key Required',
        message: 'Please configure your Gemini API key in settings'
      });
      return;
    }

    setLoading(true);
    
    try {
      console.log('🚀 Starting AI Analysis for', vulnerability.cve.id);
      
      const enhancedAnalysis = await generateEnhancedAIAnalysis(
        vulnerability,
        settings.geminiApiKey,
        settings.geminiModel,
        settings
      );
      
      console.log('🔍 AI Analysis Response:', enhancedAnalysis);
      
      let normalizedAnalysis;
      
      if (typeof enhancedAnalysis === 'string') {
        normalizedAnalysis = {
          analysis: enhancedAnalysis,
          ragUsed: false,
          webGrounded: false,
          ragDocs: 0,
          ragSources: [],
          enhancedSources: vulnerability.enhancedSources || []
        };
      } else if (enhancedAnalysis && typeof enhancedAnalysis === 'object') {
        if (enhancedAnalysis.analysis && typeof enhancedAnalysis.analysis === 'string') {
          normalizedAnalysis = {
            analysis: enhancedAnalysis.analysis,
            ragUsed: Boolean(enhancedAnalysis.ragUsed),
            webGrounded: Boolean(enhancedAnalysis.webGrounded),
            ragDocs: Number(enhancedAnalysis.ragDocs) || 0,
            ragSources: Array.isArray(enhancedAnalysis.ragSources) ? enhancedAnalysis.ragSources : [],
            enhancedSources: enhancedAnalysis.enhancedSources || vulnerability.enhancedSources || []
          };
        } else {
          throw new Error(`Invalid analysis object response: missing analysis property`);
        }
      } else {
        throw new Error(`Invalid response format: expected string or object, got ${typeof enhancedAnalysis}`);
      }
      
      if (!normalizedAnalysis.analysis || normalizedAnalysis.analysis.trim().length === 0) {
        throw new Error('Empty analysis content received');
      }
      
      console.log('✅ Analysis Normalized:', normalizedAnalysis);
      
      setAnalysis(normalizedAnalysis);
      setShowAnalysis(true);
      
      const enhancedInfo = [];
      if (normalizedAnalysis.ragUsed) enhancedInfo.push(`${normalizedAnalysis.ragDocs} RAG docs`);
      if (normalizedAnalysis.webGrounded) enhancedInfo.push('web search');
      if (normalizedAnalysis.enhancedSources?.length > 1) enhancedInfo.push(`${normalizedAnalysis.enhancedSources.length} data sources`);
      
      addNotification({
        type: 'success',
        title: 'AI Analysis Complete',
        message: `Analysis generated (${normalizedAnalysis.analysis.length} chars)${enhancedInfo.length > 0 ? ` with ${enhancedInfo.join(', ')}` : ''}`
      });
      
    } catch (error) {
      console.error('💥 AI Analysis Error:', error);
      
      setAnalysis(null);
      setShowAnalysis(false);
      
      addNotification({
        type: 'error',
        title: 'AI Analysis Failed',
        message: `Error: ${error.message}`
      });
    } finally {
      setLoading(false);
    }
  };

  const renderAnalysisContent = () => {
    if (!analysis) {
      return (
        <div style={{ color: '#ef4444', fontStyle: 'italic' }}>
          No analysis available
        </div>
      );
    }
    
    if (typeof analysis !== 'object' || !analysis.analysis) {
      console.error('Invalid analysis object:', analysis);
      return (
        <div style={{ color: '#ef4444', fontStyle: 'italic' }}>
          Invalid analysis format
        </div>
      );
    }
    
    if (typeof analysis.analysis !== 'string' || analysis.analysis.trim().length === 0) {
      return (
        <div style={{ color: '#ef4444', fontStyle: 'italic' }}>
          Empty analysis content
        </div>
      );
    }
    
    return (
      <div style={{ 
        width: '100%',
        display: 'block',
        whiteSpace: 'pre-wrap',
        wordWrap: 'break-word',
        overflowWrap: 'break-word'
      }}>
        {analysis.analysis}
      </div>
    );
  };

  const renderMetadata = () => {
    if (!analysis || typeof analysis !== 'object') {
      return null;
    }
    
    const parts = [`🤖 AI Analysis by ${settings.geminiModel || 'Gemini'}`];
    
    if (settings.geminiModel?.includes('2.0')) {
      parts.push('🌐 Web-enhanced with real-time search');
    }
    
    if (analysis.enhancedSources?.length > 1) {
      parts.push(`📊 ${analysis.enhancedSources.length} Data Sources: ${analysis.enhancedSources.join(', ')}`);
    }
    
    if (analysis.ragUsed && analysis.ragDocs > 0) {
      parts.push(`📚 Enhanced with security knowledge base (${analysis.ragDocs} docs)`);
    }
    
    return parts.join(' • ');
  };

  return (
    <>
      <button
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '4px',
          padding: '4px 12px',
          background: settings.geminiApiKey ? 
            (loading ? '#6b7280' : 
             vulnerability.enhancedSources?.length > 1 ? 
               'linear-gradient(135deg, #8b5cf6 0%, #3b82f6 100%)' : '#8b5cf6'
            ) : '#6b7280',
          color: 'white',
          border: 'none',
          borderRadius: '6px',
          fontSize: '0.8rem',
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
        {loading ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Brain size={14} />}
        {loading ? 'Analyzing...' : 'AI Analysis'}
        {vulnerability.enhancedSources?.length > 1 && !loading && (
          <span style={{
            fontSize: '0.7rem',
            background: 'rgba(255, 255, 255, 0.3)',
            color: 'white',
            padding: '2px 6px',
            borderRadius: '4px',
            marginLeft: '4px'
          }}>
            {vulnerability.enhancedSources.length} SOURCES
          </span>
        )}
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

      {showAnalysis && (
        <div style={{
          marginTop: '16px',
          padding: '16px',
          background: settings.darkMode ? '#312e81' : '#f3e8ff',
          borderRadius: '8px',
          border: settings.darkMode ? '1px solid #4338ca' : '1px solid #c084fc',
          width: '100%',
          boxSizing: 'border-box'
        }}>
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center',
            marginBottom: '12px' 
          }}>
            <span style={{ 
              fontWeight: '600', 
              fontSize: '0.9rem',
              color: settings.darkMode ? '#a5b4fc' : '#7c3aed',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}>
              🤖 AI Security Analysis
              {vulnerability.enhancedSources?.length > 1 && (
                <span style={{
                  fontSize: '0.7rem',
                  background: 'linear-gradient(135deg, #8b5cf6 0%, #3b82f6 100%)',
                  color: 'white',
                  padding: '3px 8px',
                  borderRadius: '4px'
                }}>
                  {vulnerability.enhancedSources.length} SOURCES
                </span>
              )}
              {settings.geminiModel?.includes('2.0') && (
                <span style={{
                  fontSize: '0.7rem',
                  background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                  color: 'white',
                  padding: '3px 8px',
                  borderRadius: '4px'
                }}>
                  🌐 WEB ENHANCED
                </span>
              )}
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
              onClick={() => setShowAnalysis(false)}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                color: settings.darkMode ? '#a5b4fc' : '#7c3aed'
              }}
            >
              <X size={16} />
            </button>
          </div>
          
          <div style={{
            fontSize: '0.9rem',
            lineHeight: '1.7',
            color: settings.darkMode ? '#e2e8f0' : '#1f2937',
            whiteSpace: 'pre-wrap',
            wordWrap: 'break-word',
            overflowWrap: 'break-word',
            wordBreak: 'break-word',
            maxHeight: 'none',
            height: 'auto',
            overflow: 'visible',
            padding: '20px',
            background: settings.darkMode ? 'rgba(15, 23, 42, 0.5)' : 'rgba(248, 250, 252, 0.8)',
            borderRadius: '8px',
            border: settings.darkMode ? '1px solid rgba(71, 85, 105, 0.3)' : '1px solid rgba(226, 232, 240, 0.5)',
            fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
            width: '100%',
            boxSizing: 'border-box',
            display: 'block'
          }}>
            {renderAnalysisContent()}
          </div>
          
          {analysis && (
            <div style={{
              marginTop: '12px',
              padding: '12px',
              background: settings.darkMode ? 'rgba(139, 92, 246, 0.15)' : 'rgba(139, 92, 246, 0.08)',
              borderRadius: '6px',
              fontSize: '0.75rem',
              color: settings.darkMode ? '#a78bfa' : '#7c3aed',
              borderLeft: '3px solid #8b5cf6'
            }}>
              {renderMetadata()}
            </div>
          )}
          
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
                      message: 'AI analysis copied to clipboard'
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
                📋 Copy Analysis
              </button>
            </div>
          )}
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

  const renderGitHubAdvisories = (githubData) => {
    if (!githubData || githubData.length === 0) return null;
    
    return (
      <div style={{
        background: settings.darkMode ? '#374151' : '#f9fafb',
        border: settings.darkMode ? '1px solid #6b7280' : '1px solid #d1d5db',
        borderRadius: '6px',
        padding: '12px',
        marginBottom: '12px'
      }}>
        <div style={{ fontWeight: '600', color: settings.darkMode ? '#f3f4f6' : '#1f2937', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <GitBranch size={16} />
          GitHub Security Advisories ({githubData.length})
        </div>
        {githubData.slice(0, 2).map((advisory, i) => (
          <div key={i} style={{ fontSize: '0.875rem', marginBottom: '8px', padding: '8px', background: settings.darkMode ? '#1f2937' : '#ffffff', borderRadius: '4px' }}>
            <div style={{ fontWeight: '500', marginBottom: '4px' }}>
              {advisory.ghsaId} - {advisory.severity?.toUpperCase()}
            </div>
            <div style={{ color: settings.darkMode ? '#d1d5db' : '#4b5563' }}>
              {advisory.summary}
            </div>
            {advisory.vulnerabilities?.nodes?.map((vuln, j) => (
              <div key={j} style={{ fontSize: '0.75rem', marginTop: '4px', color: settings.darkMode ? '#9ca3af' : '#6b7280' }}>
                📦 {vuln.package.ecosystem}/{vuln.package.name} - {vuln.vulnerableVersionRange}
              </div>
            ))}
          </div>
        ))}
      </div>
    );
  };

  return (
    <div style={{ marginTop: '32px' }}>
      <h2 style={{ margin: '0 0 24px 0', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
        <Shield size={24} />
        Vulnerability Intelligence ({vulnerabilities.length})
        <span style={{
          ...styles.badge,
          background: '#10b981',
          color: 'white',
          borderColor: '#10b981'
        }}>
          MULTI-SOURCE
        </span>
      </h2>
      
      <div style={{ display: 'grid', gap: '16px' }}>
        {vulnerabilities.map((vuln, index) => (
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
                  {vuln.enhancedSources && (
                    <span style={{
                      ...styles.badge,
                      background: '#3b82f6',
                      color: 'white',
                      borderColor: '#3b82f6',
                      fontSize: '0.7rem'
                    }}>
                      {vuln.enhancedSources.length} SOURCES
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
                {vuln.enhancedSources && (
                  <div style={{ fontSize: '0.75rem', color: settings.darkMode ? '#94a3b8' : '#6b7280' }}>
                    Sources: {vuln.enhancedSources.join(', ')}
                  </div>
                )}
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
            
            {renderGitHubAdvisories(vuln.github)}
            
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
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
                {vuln.github && vuln.github.length > 0 && (
                  <a href={`https://github.com/advisories?query=${vuln.cve.id}`} target="_blank" rel="noopener noreferrer" style={{...styles.linkButton, background: '#6b7280'}}>
                    <GitBranch size={12} />
                    GitHub
                  </a>
                )}
              </div>
            </div>

            {/* Data Sources Summary */}
            <div style={{
              padding: '12px',
              background: settings.darkMode ? '#0f172a' : '#f8fafc',
              borderRadius: '6px',
              border: settings.darkMode ? '1px solid #334155' : '1px solid #e2e8f0',
              marginBottom: '12px'
            }}>
              <div style={{ fontSize: '0.75rem', color: settings.darkMode ? '#94a3b8' : '#6b7280', marginBottom: '4px' }}>
                <strong>Intelligence Sources ({vuln.enhancedSources?.length || 1}):</strong>
              </div>
              <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                {vuln.enhancedSources?.map((source, idx) => (
                  <span key={idx} style={{
                    ...styles.badge,
                    background: source === 'NVD' ? '#3b82f6' : 
                               source === 'EPSS' ? '#10b981' :
                               source === 'KEV' ? '#ef4444' :
                               source === 'GitHub' ? '#6b7280' : '#8b5cf6',
                    color: 'white',
                    fontSize: '0.65rem',
                    padding: '2px 6px'
                  }}>
                    {source}
                  </span>
                )) || (
                  <span style={{
                    ...styles.badge,
                    background: '#3b82f6',
                    color: 'white',
                    fontSize: '0.65rem',
                    padding: '2px 6px'
                  }}>
                    NVD
                  </span>
                )}
              </div>
            </div>
            
            {/* AI Analysis Button */}
            <div style={{ 
              display: 'flex', 
              justifyContent: 'flex-start', 
              alignItems: 'center',
              gap: '12px',
              paddingTop: '12px',
              borderTop: settings.darkMode ? '1px solid #334155' : '1px solid #e5e7eb'
            }}>
              <AIAnalysisButton vulnerability={vuln} />
              <div style={{ fontSize: '0.75rem', color: settings.darkMode ? '#94a3b8' : '#6b7280' }}>
                {settings.geminiApiKey ? 
                  'AI analysis available with enhanced intelligence sources' : 
                  'Configure Gemini API key in settings for AI analysis'
                }
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

const VulnerabilityApp = () => {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadingSteps, setLoadingSteps] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const [showSettings, setShowSettings] = useState(false);
  const [settings, setSettings] = useState({
    aiAnalysisEnabled: true,
    darkMode: true,
    geminiModel: 'gemini-2.0-flash'
  });

  const styles = getStyles(settings.darkMode);

  const addNotification = (notification) => {
    const id = Date.now() + Math.random();
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
                <p style={styles.subtitle}>Real-time vulnerability data with AI-powered analysis</p>
              </div>
            </div>
            <div style={styles.headerActions}>
              <div style={styles.statusIndicator}>
                <Activity size={14} />
                <span>LIVE</span>
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
          <SearchComponent />
          
          {vulnerabilities.length > 0 && <Dashboard vulnerabilities={vulnerabilities} />}

          {loading && (
            <div style={styles.loadingContainer}>
              <div style={{
                background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                color: 'white',
                padding: '32px',
                borderRadius: '12px',
                textAlign: 'center',
                maxWidth: '700px'
              }}>
                <Loader2 size={48} style={{ marginBottom: '16px', animation: 'spin 1s linear infinite' }} />
                <h3 style={{ margin: '0 0 8px 0' }}>Processing Vulnerability Data</h3>
                <p style={{ margin: '0 0 24px 0', fontSize: '1.1rem' }}>
                  Fetching real-time data from multiple intelligence sources...
                </p>
                
                {loadingSteps.length > 0 && (
                  <div style={{ 
                    background: 'rgba(255,255,255,0.1)', 
                    borderRadius: '8px', 
                    padding: '16px',
                    textAlign: 'left',
                    maxHeight: '250px',
                    overflowY: 'auto'
                  }}>
                    {loadingSteps.slice(-10).map((step, index) => (
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
                        ) : step.startsWith('🐙') ? (
                          <GitBranch size={16} color="#6b7280" />
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
                maxWidth: '900px',
                margin: '0 auto'
              }}>
                <Shield size={64} style={{ marginBottom: '24px', color: '#3b82f6' }} />
                <h2 style={{ margin: '0 0 12px 0', fontSize: '1.75rem', color: settings.darkMode ? '#e2e8f0' : '#1e293b' }}>Vulnerability Intelligence Platform</h2>
                <p style={{ margin: '0 0 24px 0', fontSize: '1.1rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                  Comprehensive vulnerability analysis with real-time data from authoritative sources
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '16px', marginTop: '32px' }}>
                  <div style={{ textAlign: 'center', padding: '16px' }}>
                    <Database size={32} style={{ color: '#3b82f6', marginBottom: '8px' }} />
                    <div style={{ fontWeight: '600', marginBottom: '4px', color: settings.darkMode ? '#e2e8f0' : '#1f2937' }}>Real-time Data</div>
                    <div style={{ fontSize: '0.875rem', color: settings.darkMode ? '#94a3b8' : '#6b7280' }}>NVD, EPSS, KEV</div>
                  </div>
                  <div style={{ textAlign: 'center', padding: '16px' }}>
                    <GitBranch size={32} style={{ color: '#6b7280', marginBottom: '8px' }} />
                    <div style={{ fontWeight: '600', marginBottom: '4px', color: settings.darkMode ? '#e2e8f0' : '#1f2937' }}>GitHub Integration</div>
                    <div style={{ fontSize: '0.875rem', color: settings.darkMode ? '#94a3b8' : '#6b7280' }}>
                      {settings.githubToken ? 'Enabled' : 'Configure Token'}
                    </div>
                  </div>
                  <div style={{ textAlign: 'center', padding: '16px' }}>
                    <Brain size={32} style={{ color: '#8b5cf6', marginBottom: '8px' }} />
                    <div style={{ fontWeight: '600', marginBottom: '4px', color: settings.darkMode ? '#e2e8f0' : '#1f2937' }}>AI Analysis</div>
                    <div style={{ fontSize: '0.875rem', color: settings.darkMode ? '#94a3b8' : '#6b7280' }}>
                      {settings.geminiApiKey ? 
                        `${settings.geminiModel}${settings.geminiModel?.includes('2.0') ? ' + Web' : ''}` : 
                        'Configure API Key'
                      }
                    </div>
                  </div>
                </div>
                
                <div style={{
                  marginTop: '24px',
                  padding: '16px',
                  background: settings.darkMode ? '#312e81' : '#f3e8ff',
                  borderRadius: '8px',
                  border: settings.darkMode ? '1px solid #4338ca' : '1px solid #c084fc'
                }}>
                  <p style={{ margin: 0, fontSize: '0.875rem', color: settings.darkMode ? '#a5b4fc' : '#7c3aed' }}>
                    💡 <strong>Real Data Only:</strong> This platform uses only live API endpoints and official sources. No mock or simulated data is used, ensuring accurate and up-to-date vulnerability intelligence.
                  </p>
                </div>
              </div>
            </div>
          )}

          {vulnerabilities.length > 0 && <VulnerabilityList vulnerabilities={vulnerabilities} />}
        </main>
      </div>
    </AppContext.Provider>
  );
};

export default VulnerabilityApp;
