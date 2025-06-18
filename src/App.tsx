import React, { useState, createContext, useContext, useEffect } from 'react';
import { Search, Shield, AlertTriangle, Loader2, ExternalLink, Brain, Settings, Target, Clock, Database, Activity, CheckCircle, XCircle, X, Upload, Filter, PieChart, Sun, Moon, Eye, EyeOff, Save, FileText, Wifi, WifiOff, GitBranch, Code, Server, Cloud, Zap, TrendingUp, Users, Globe, Award, Bug, Layers, Info, Calendar, Package, AlertCircle, MapPin, TrendingDown, BarChart3, RefreshCw, Download, Share2 } from 'lucide-react';

// Enhanced RAG Vector Database Implementation
class EnhancedVectorDatabase {
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
    const vector = vocabulary.slice(0, 150).map(word => wordFreq[word] || 0);
    
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

  async search(query, k = 8) {
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

    console.log('🚀 Initializing Enhanced RAG Vector Database...');
    await this.addSecurityKnowledgeBase();
    this.initialized = true;
    console.log(`✅ RAG database initialized with ${this.documents.length} documents`);
  }

  async addSecurityKnowledgeBase() {
    const knowledgeBase = [
      {
        title: "CVE Severity Classification",
        content: "CVE severity classification considers CVSS scores, exploitability, asset exposure, and business impact. Critical vulnerabilities (9.0-10.0 CVSS) with known exploits and high exposure get immediate priority. High severity (7.0-8.9) with active exploitation or wide exposure requires rapid remediation. Medium (4.0-6.9) and Low (0.1-3.9) are prioritized based on context and exposure metrics.",
        category: "severity",
        tags: ["severity", "classification", "priority"]
      },
      {
        title: "Cloud Asset Context Intelligence",
        content: "Modern vulnerability assessment emphasizes cloud asset context - understanding where vulnerabilities exist in relation to critical business assets, data sensitivity, and network exposure. Vulnerabilities in internet-facing assets, those with access to sensitive data, or in critical business applications receive elevated priority regardless of base CVSS score.",
        category: "context",
        tags: ["cloud", "assets", "context", "business-impact"]
      },
      {
        title: "Active Exploitation Intelligence",
        content: "Integration of multiple threat intelligence sources helps identify vulnerabilities under active exploitation. This includes CISA KEV catalog, commercial threat feeds, proof-of-concept availability, and ransomware campaign usage. Active exploitation significantly elevates vulnerability priority and triggers immediate response protocols.",
        category: "exploitation",
        tags: ["exploitation", "threat-intelligence", "ransomware", "kev"]
      },
      {
        title: "Supply Chain Vulnerability Assessment",
        content: "Modern vulnerability management tracks vulnerabilities across the entire software supply chain, including container images, third-party libraries, and dependencies. Supply chain vulnerabilities are assessed based on usage prevalence, update availability, and potential for widespread impact across customer environments.",
        category: "supply-chain",
        tags: ["supply-chain", "containers", "dependencies", "libraries"]
      },
      {
        title: "Zero-Day Vulnerability Response",
        content: "Zero-day vulnerabilities require immediate assessment of exposure, temporary mitigations, and rapid deployment of patches when available. Response includes asset inventory review, network segmentation analysis, and emergency patching procedures. Risk assessment considers attack surface exposure and criticality of affected systems.",
        category: "zero-day",
        tags: ["zero-day", "emergency-response", "mitigation", "patching"]
      },
      {
        title: "EPSS Exploitation Prediction Analysis",
        content: "EPSS (Exploit Prediction Scoring System) provides probability scores for vulnerability exploitation within 30 days. Scores above 0.5 (50%) indicate high exploitation likelihood and warrant immediate attention. EPSS combines multiple factors including proof-of-concept availability, exploit code maturity, and threat actor interest patterns.",
        category: "epss",
        tags: ["epss", "exploitation-probability", "prediction", "first"]
      },
      {
        title: "CISA KEV Catalog Intelligence",
        content: "CISA Known Exploited Vulnerabilities catalog lists CVEs with confirmed active exploitation. KEV inclusion triggers mandatory remediation deadlines for federal agencies and serves as authoritative source for private sector prioritization. KEV entries include vendor/product details, required actions, and due dates for remediation.",
        category: "kev",
        tags: ["cisa", "kev", "known-exploited", "mandatory"]
      },
      {
        title: "Ransomware Campaign Vulnerability Analysis",
        content: "Ransomware groups actively exploit vulnerabilities for initial access and lateral movement. Historical analysis shows preference for remote code execution, authentication bypass, and privilege escalation vulnerabilities. Tracking ransomware exploitation patterns helps predict future targeting and prioritize defensive measures.",
        category: "ransomware",
        tags: ["ransomware", "campaigns", "targeting", "tactics"]
      },
      {
        title: "GitHub Security Advisory Intelligence",
        content: "GitHub Security Advisories provide crucial supply chain vulnerability information including affected package versions, patched releases, and workaround procedures. Advisory data enables precise identification of vulnerable dependencies and supports automated vulnerability scanning in development workflows.",
        category: "github",
        tags: ["github", "supply-chain", "advisories", "packages"]
      },
      {
        title: "OSV Database Ecosystem Mapping",
        content: "Open Source Vulnerabilities database aggregates vulnerability information across multiple ecosystems including npm, PyPI, Maven, NuGet, and others. OSV provides standardized vulnerability identifiers and enables comprehensive dependency vulnerability tracking across heterogeneous software environments.",
        category: "osv",
        tags: ["osv", "ecosystems", "dependencies", "open-source"]
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

// Global enhanced RAG instance
const enhancedRAGDatabase = new EnhancedVectorDatabase();

const getStyles = (darkMode) => ({
  appContainer: { minHeight: '100vh', backgroundColor: darkMode ? '#0f172a' : '#f8fafc' },
  header: { 
    background: darkMode 
      ? 'linear-gradient(135deg, #1e293b 0%, #334155 100%)' 
      : 'linear-gradient(135deg, #ffffff 0%, #f8fafc 100%)', 
    color: darkMode ? 'white' : '#1f2937', 
    boxShadow: '0 4px 6px rgba(0, 0, 0, 0.07)',
    borderBottom: darkMode ? '1px solid #334155' : '1px solid #e2e8f0'
  },
  headerContent: { 
    maxWidth: '1400px', 
    margin: '0 auto', 
    padding: '20px 32px', 
    display: 'flex', 
    alignItems: 'center', 
    justifyContent: 'space-between'
  },
  headerTitle: { display: 'flex', alignItems: 'center', gap: '16px' },
  title: { fontSize: '1.5rem', fontWeight: '700', margin: 0, background: 'linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' },
  subtitle: { fontSize: '0.875rem', opacity: 0.8, margin: 0, fontWeight: '500' },
  headerActions: { display: 'flex', alignItems: 'center', gap: '16px' },
  statusIndicator: { 
    display: 'flex', 
    alignItems: 'center', 
    gap: '8px', 
    fontSize: '0.75rem', 
    padding: '6px 12px', 
    background: darkMode ? 'rgba(34, 197, 94, 0.15)' : 'rgba(34, 197, 94, 0.1)', 
    borderRadius: '16px', 
    border: '1px solid rgba(34, 197, 94, 0.3)',
    color: '#22c55e',
    fontWeight: '600'
  },
  mainContent: { maxWidth: '1400px', margin: '0 auto', padding: '32px' },
  searchSection: {
    background: darkMode ? 'linear-gradient(135deg, #1e293b 0%, #334155 100%)' : 'linear-gradient(135deg, #ffffff 0%, #f8fafc 100%)',
    padding: '60px 0 80px 0',
    borderBottom: darkMode ? '1px solid #334155' : '1px solid #e2e8f0'
  },
  searchContainer: {
    maxWidth: '900px',
    margin: '0 auto',
    textAlign: 'center'
  },
  searchTitle: {
    fontSize: '3rem',
    fontWeight: '800',
    background: 'linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%)',
    WebkitBackgroundClip: 'text',
    WebkitTextFillColor: 'transparent',
    marginBottom: '16px'
  },
  searchSubtitle: {
    fontSize: '1.25rem',
    color: darkMode ? '#94a3b8' : '#64748b',
    marginBottom: '48px',
    fontWeight: '500'
  },
  searchWrapper: { 
    position: 'relative', 
    maxWidth: '700px', 
    margin: '0 auto',
    marginBottom: '32px' 
  },
  searchInput: { 
    width: '100%', 
    padding: '20px 24px 20px 56px', 
    border: darkMode ? '2px solid #334155' : '2px solid #e2e8f0', 
    borderRadius: '16px', 
    fontSize: '1.1rem', 
    outline: 'none', 
    boxSizing: 'border-box', 
    background: darkMode ? '#1e293b' : '#ffffff', 
    color: darkMode ? '#f1f5f9' : '#0f172a',
    transition: 'all 0.3s ease',
    boxShadow: darkMode ? '0 4px 6px rgba(0, 0, 0, 0.1)' : '0 1px 3px rgba(0, 0, 0, 0.1)'
  },
  searchIcon: { position: 'absolute', left: '20px', top: '50%', transform: 'translateY(-50%)', color: darkMode ? '#64748b' : '#94a3b8' },
  searchButton: { 
    position: 'absolute', 
    right: '6px', 
    top: '50%', 
    transform: 'translateY(-50%)',
    padding: '12px 24px',
    background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
    color: 'white',
    border: 'none',
    borderRadius: '12px',
    cursor: 'pointer',
    fontWeight: '600',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '1rem',
    boxShadow: '0 4px 12px rgba(59, 130, 246, 0.4)'
  },
  button: { 
    display: 'flex', 
    alignItems: 'center', 
    gap: '8px', 
    padding: '10px 20px', 
    borderRadius: '12px', 
    fontWeight: '600', 
    cursor: 'pointer', 
    border: '2px solid', 
    fontSize: '0.9rem',
    transition: 'all 0.3s ease'
  },
  buttonPrimary: { 
    background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)', 
    color: 'white', 
    borderColor: 'transparent',
    boxShadow: '0 4px 12px rgba(59, 130, 246, 0.4)'
  },
  buttonSecondary: { 
    background: darkMode ? '#334155' : '#f1f5f9', 
    color: darkMode ? '#f1f5f9' : '#334155', 
    borderColor: darkMode ? '#475569' : '#cbd5e1'
  },
  badge: { 
    padding: '6px 12px', 
    borderRadius: '16px', 
    fontSize: '0.75rem', 
    fontWeight: '700', 
    display: 'inline-block',
    textTransform: 'uppercase',
    letterSpacing: '0.5px'
  },
  badgeCritical: { background: 'rgba(239, 68, 68, 0.15)', color: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.3)' },
  badgeHigh: { background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', border: '1px solid rgba(245, 158, 11, 0.3)' },
  badgeMedium: { background: 'rgba(59, 130, 246, 0.15)', color: '#3b82f6', border: '1px solid rgba(59, 130, 246, 0.3)' },
  badgeLow: { background: 'rgba(34, 197, 94, 0.15)', color: '#22c55e', border: '1px solid rgba(34, 197, 94, 0.3)' },
  notification: { 
    position: 'fixed', 
    top: '24px', 
    right: '24px', 
    background: darkMode ? '#1e293b' : '#ffffff', 
    borderRadius: '12px', 
    padding: '20px', 
    boxShadow: '0 20px 40px rgba(0, 0, 0, 0.15)', 
    zIndex: 1000, 
    maxWidth: '420px', 
    border: darkMode ? '1px solid #334155' : '1px solid #e2e8f0'
  },
  notificationSuccess: { borderLeft: '4px solid #22c55e' },
  notificationError: { borderLeft: '4px solid #ef4444' },
  notificationWarning: { borderLeft: '4px solid #f59e0b' },
  loadingContainer: { 
    display: 'flex', 
    flexDirection: 'column', 
    alignItems: 'center', 
    justifyContent: 'center', 
    padding: '80px 0',
    textAlign: 'center'
  },
  emptyState: { 
    textAlign: 'center', 
    padding: '80px 0', 
    color: darkMode ? '#94a3b8' : '#64748b' 
  },
  modal: { 
    position: 'fixed', 
    inset: 0, 
    background: 'rgba(0, 0, 0, 0.7)', 
    display: 'flex', 
    alignItems: 'center', 
    justifyContent: 'center', 
    zIndex: 50,
    backdropFilter: 'blur(8px)'
  },
  modalContent: { 
    background: darkMode ? '#1e293b' : '#ffffff', 
    borderRadius: '20px', 
    padding: '32px', 
    width: '100%', 
    maxWidth: '700px', 
    maxHeight: '90vh', 
    overflowY: 'auto', 
    margin: '20px',
    border: darkMode ? '1px solid #334155' : 'none',
    boxShadow: '0 20px 40px rgba(0, 0, 0, 0.3)'
  },
  modalHeader: { 
    display: 'flex', 
    alignItems: 'center', 
    justifyContent: 'space-between', 
    marginBottom: '32px', 
    paddingBottom: '20px', 
    borderBottom: darkMode ? '2px solid #334155' : '2px solid #e2e8f0' 
  },
  modalTitle: { fontSize: '1.5rem', fontWeight: '700', margin: 0, color: darkMode ? '#f1f5f9' : '#0f172a' },
  formGroup: { marginBottom: '20px' },
  label: { 
    display: 'block', 
    fontSize: '0.9rem', 
    fontWeight: '600', 
    color: darkMode ? '#cbd5e1' : '#475569', 
    marginBottom: '8px' 
  },
  input: { 
    width: '100%', 
    padding: '12px 16px', 
    border: darkMode ? '2px solid #475569' : '2px solid #cbd5e1', 
    borderRadius: '12px', 
    fontSize: '0.9rem', 
    outline: 'none', 
    boxSizing: 'border-box',
    background: darkMode ? '#334155' : '#ffffff',
    color: darkMode ? '#f1f5f9' : '#0f172a',
    transition: 'border-color 0.3s ease'
  },
  select: { 
    width: '100%', 
    padding: '12px 16px', 
    border: darkMode ? '2px solid #475569' : '2px solid #cbd5e1', 
    borderRadius: '12px', 
    fontSize: '0.9rem', 
    outline: 'none', 
    background: darkMode ? '#334155' : '#ffffff', 
    boxSizing: 'border-box',
    color: darkMode ? '#f1f5f9' : '#0f172a',
    transition: 'border-color 0.3s ease'
  }
});

const AppContext = createContext({});

// Enhanced CVE data fetching functions with real-time RAG integration
const fetchCVEDataFromNVD = async (cveId, setLoadingSteps, apiKey) => {
  setLoadingSteps(prev => [...prev, `🔍 Fetching ${cveId} from NVD...`]);
  
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    const headers = { 
      'Accept': 'application/json',
      'User-Agent': 'VulnerabilityIntelligence/4.0'
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
    
    // Add NVD data to RAG database for future context
    if (enhancedRAGDatabase.initialized) {
      await enhancedRAGDatabase.addDocument(
        `CVE ${cveId} NVD Data: ${description} CVSS Score: ${cvssV3?.baseScore || 'N/A'} Severity: ${cvssV3?.baseSeverity || 'Unknown'}`,
        {
          title: `NVD Data - ${cveId}`,
          category: 'nvd-data',
          tags: ['nvd', cveId.toLowerCase(), 'official-data'],
          source: 'nvd-api',
          cveId: cveId
        }
      );
    }
    
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
        'User-Agent': 'VulnerabilityIntelligence/4.0'
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
    
    // Add EPSS data to RAG database
    if (enhancedRAGDatabase.initialized) {
      await enhancedRAGDatabase.addDocument(
        `CVE ${cveId} EPSS Analysis: Exploitation probability ${(parseFloat(epssData.epss) * 100).toFixed(2)}% (percentile ${parseFloat(epssData.percentile).toFixed(1)}). ${parseFloat(epssData.epss) > 0.5 ? 'High exploitation likelihood - immediate attention required.' : 'Lower exploitation likelihood but monitoring recommended.'}`,
        {
          title: `EPSS Analysis - ${cveId}`,
          category: 'epss-data',
          tags: ['epss', 'exploitation-probability', cveId.toLowerCase()],
          source: 'first-api',
          cveId: cveId
        }
      );
    }
    
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
        'User-Agent': 'VulnerabilityIntelligence/4.0'
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
    
    // Add KEV data to RAG database
    if (enhancedRAGDatabase.initialized) {
      await enhancedRAGDatabase.addDocument(
        `CVE ${cveId} CISA KEV Entry: CONFIRMED ACTIVE EXPLOITATION. Vendor: ${kevEntry.vendorProject}, Product: ${kevEntry.product}. Required Action: ${kevEntry.requiredAction}. Due Date: ${kevEntry.dueDate}. ${kevEntry.knownRansomwareCampaignUse === 'Known' ? 'KNOWN RANSOMWARE USAGE - CRITICAL PRIORITY' : 'Government mandate for immediate remediation.'}`,
        {
          title: `CISA KEV Alert - ${cveId}`,
          category: 'kev-data',
          tags: ['cisa', 'kev', 'active-exploitation', 'critical', cveId.toLowerCase()],
          source: 'cisa-api',
          cveId: cveId
        }
      );
    }
    
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
            vulnerabilities(first: 10) {
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
      
      // Add GitHub advisory data to RAG database
      if (enhancedRAGDatabase.initialized) {
        const advisories = data.data.securityAdvisories.nodes;
        const packageInfo = advisories.flatMap(advisory => 
          advisory.vulnerabilities?.nodes?.map(vuln => 
            `${vuln.package.ecosystem}/${vuln.package.name} (${vuln.vulnerableVersionRange})`
          ) || []
        );
        
        await enhancedRAGDatabase.addDocument(
          `CVE ${cveId} GitHub Security Advisory: ${advisories.length} advisories found. Affected packages: ${packageInfo.join(', ')}. Supply chain impact across multiple ecosystems. ${advisories[0]?.summary || 'Detailed advisory information available.'}`,
          {
            title: `GitHub Advisory - ${cveId}`,
            category: 'github-advisory',
            tags: ['github', 'supply-chain', 'packages', cveId.toLowerCase()],
            source: 'github-api',
            cveId: cveId
          }
        );
      }
      
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

const fetchOSVData = async (cveId, setLoadingSteps) => {
  setLoadingSteps(prev => [...prev, `📦 Fetching OSV database for ${cveId}...`]);
  
  try {
    const response = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        version: '1.0',
        query: cveId
      })
    });

    if (!response.ok) {
      throw new Error(`OSV API error: ${response.status}`);
    }

    const data = await response.json();
    
    if (data.vulns && data.vulns.length > 0) {
      setLoadingSteps(prev => [...prev, `✅ Found ${data.vulns.length} OSV entries for ${cveId}`]);
      
      // Add OSV data to RAG database
      if (enhancedRAGDatabase.initialized) {
        const ecosystems = new Set(data.vulns.flatMap(entry => 
          entry.affected?.map(a => a.package?.ecosystem) || []
        ));
        
        await enhancedRAGDatabase.addDocument(
          `CVE ${cveId} OSV Database: ${data.vulns.length} vulnerability entries across ${ecosystems.size} ecosystems (${Array.from(ecosystems).join(', ')}). Open source vulnerability tracking with comprehensive package version information and affected ranges.`,
          {
            title: `OSV Database - ${cveId}`,
            category: 'osv-data',
            tags: ['osv', 'open-source', 'ecosystems', cveId.toLowerCase()],
            source: 'osv-api',
            cveId: cveId
          }
        );
      }
      
      return data.vulns;
    } else {
      setLoadingSteps(prev => [...prev, `ℹ️ No OSV data found for ${cveId}`]);
      return [];
    }
    
  } catch (error) {
    console.error(`OSV API Error for ${cveId}:`, error);
    setLoadingSteps(prev => [...prev, `⚠️ OSV data unavailable for ${cveId}: ${error.message}`]);
    return [];
  }
};

// Enhanced RAG-powered AI Analysis
const generateEnhancedRAGAnalysis = async (vulnerability, apiKey, model, settings = {}) => {
  const cveId = vulnerability.cve.id;
  const description = vulnerability.cve.description;
  const cvssScore = vulnerability.cve.cvssV3?.baseScore || vulnerability.cve.cvssV2?.baseScore || 'N/A';
  const epssScore = vulnerability.epss ? (vulnerability.epss.epss * 100).toFixed(2) + '%' : 'N/A';
  const kevStatus = vulnerability.kev ? 'Yes' : 'No';
  const isGemini2 = model.includes('2.0');

  try {
    console.log('🚀 Starting Enhanced RAG Analysis for', cveId);
    
    // Initialize RAG database if needed
    if (!enhancedRAGDatabase.initialized) {
      console.log('🚀 Initializing RAG database...');
      await enhancedRAGDatabase.initialize();
    }

    // Perform RAG retrieval for vulnerability context
    console.log('📚 Performing RAG retrieval for', cveId);
    const ragQuery = `${cveId} ${description.substring(0, 200)} vulnerability analysis security impact mitigation threat intelligence EPSS ${epssScore} CVSS ${cvssScore} ${kevStatus === 'Yes' ? 'CISA KEV active exploitation' : ''}`;
    const relevantDocs = await enhancedRAGDatabase.search(ragQuery, 10);
    
    const ragContext = relevantDocs.length > 0 ? 
      relevantDocs.map((doc, index) => 
        `[Security Knowledge ${index + 1}] ${doc.metadata.title}:\n${doc.content.substring(0, 600)}...`
      ).join('\n\n') : 
      'No specific security knowledge found in database.';

    console.log(`📖 Retrieved ${relevantDocs.length} relevant documents from RAG database`);

    // Build comprehensive context from all data sources
    const githubPackages = vulnerability.github?.flatMap(advisory => 
      advisory.vulnerabilities?.nodes?.map(vuln => ({
        ecosystem: vuln.package.ecosystem,
        name: vuln.package.name,
        vulnerable: vuln.vulnerableVersionRange,
        patched: vuln.firstPatchedVersion?.identifier
      })) || []
    ) || [];

    const osvPackages = vulnerability.osv?.flatMap(entry => 
      entry.affected?.map(affected => ({
        ecosystem: affected.package?.ecosystem,
        name: affected.package?.name,
        versions: affected.ranges?.map(range => range.events).flat() || []
      })) || []
    ) || [];

    const packageContext = [...githubPackages, ...osvPackages].length > 0 ? 
      `\n\nAFFECTED PACKAGES:\n${[...githubPackages, ...osvPackages].map(pkg => 
        `- ${pkg.ecosystem || 'Unknown'}/${pkg.name || 'Unknown'} (${pkg.vulnerable || pkg.versions || 'Version info unavailable'})`
      ).join('\n')}` : '';

    // Enhanced prompt with RAG context
    const prompt = `You are a senior cybersecurity analyst providing a comprehensive vulnerability assessment for ${cveId}.

VULNERABILITY DETAILS:
- CVE ID: ${cveId}
- CVSS Score: ${cvssScore}
- EPSS Score: ${epssScore}
- KEV Listed: ${kevStatus}
- Description: ${description.substring(0, 800)}${packageContext}

RELEVANT SECURITY KNOWLEDGE BASE:
${ragContext}

DATA SOURCES ANALYZED:
- NVD: ${vulnerability.cve ? 'Available' : 'Not Available'}
- EPSS: ${vulnerability.epss ? 'Available' : 'Not Available'}
- CISA KEV: ${vulnerability.kev ? 'CONFIRMED ACTIVE EXPLOITATION' : 'Not Listed'}
- GitHub Advisories: ${vulnerability.github?.length || 0} found
- OSV Database: ${vulnerability.osv?.length || 0} entries

${isGemini2 ? 'Search the web for the latest threat intelligence, current exploitation campaigns, vendor security bulletins, and real-world attacks involving this vulnerability.' : ''}

Provide a detailed technical analysis including:

1. **Executive Summary** (2-3 sentences)
   - Key risk level and immediate actions required
   - Business impact assessment

2. **Technical Analysis**
   - Root cause and attack vectors
   - Exploitation complexity and requirements
   - CVSS and EPSS interpretation with context

3. **Threat Landscape Assessment**
   - Current exploitation status and evidence
   - Threat actor activity and campaigns
   - Ransomware usage patterns

4. **Supply Chain Impact**
   - Affected packages and ecosystems
   - Dependency risk assessment
   - Update availability and constraints

5. **Business Risk Analysis**
   - Potential consequences and affected systems
   - Regulatory and compliance implications
   - Financial and operational impact

6. **Remediation Strategy**
   - Immediate actions and emergency procedures
   - Patch management and deployment timeline
   - Compensating controls and mitigations

7. **Detection and Monitoring**
   - IOCs and behavioral indicators
   - Security control recommendations
   - Monitoring and alerting strategies

8. **Risk Prioritization**
   - Context-based risk scoring
   - Urgency assessment and timeline
   - Resource allocation recommendations

Write a comprehensive security assessment of at least 2500 words with actionable intelligence and specific recommendations.`;

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

    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
    
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(`AI API error: ${response.status} - ${JSON.stringify(errorData)}`);
    }

    const data = await response.json();
    
    if (!data.candidates || !data.candidates[0] || !data.candidates[0].content) {
      throw new Error('Invalid API response format - no content generated');
    }
    
    const content = data.candidates[0].content;
    let analysisText = '';
    
    if (content.parts && Array.isArray(content.parts)) {
      analysisText = content.parts.map(part => part.text || '').join('');
    } else if (content.parts && content.parts[0] && content.parts[0].text) {
      analysisText = content.parts[0].text;
    } else {
      throw new Error('No valid content parts found in response');
    }
    
    if (!analysisText || typeof analysisText !== 'string' || analysisText.trim().length === 0) {
      throw new Error('Empty or invalid analysis text in response');
    }
    
    // Store the enhanced analysis in RAG database for future context
    if (analysisText.length > 500) {
      await enhancedRAGDatabase.addDocument(
        `Enhanced CVE Analysis: ${cveId}\n\n${analysisText}`,
        {
          title: `Enhanced RAG Security Analysis - ${cveId}`,
          category: 'enhanced-analysis',
          tags: ['rag-enhanced', 'ai-analysis', cveId.toLowerCase(), 'comprehensive-threat-intelligence'],
          source: 'ai-analysis-rag',
          cvss: cvssScore,
          epss: epssScore,
          kev: kevStatus,
          model: model
        }
      );
    }
    
    return {
      analysis: analysisText,
      ragUsed: true,
      ragDocuments: relevantDocs.length,
      ragSources: relevantDocs.map(doc => doc.metadata?.title || 'Unknown').filter(Boolean),
      webGrounded: isGemini2,
      enhancedSources: vulnerability.enhancedSources || [],
      model: model,
      analysisTimestamp: new Date().toISOString()
    };
    
  } catch (error) {
    console.error('Enhanced RAG Analysis Error:', error);
    
    return {
      analysis: `**Enhanced RAG Analysis Error**

An error occurred while generating the comprehensive security analysis for ${cveId}:

**Error Details:**
${error.message}

**Manual Analysis Recommendation:**
- Official NVD details: https://nvd.nist.gov/vuln/detail/${cveId}
- MITRE CVE database: https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}
- FIRST EPSS: https://api.first.org/data/v1/epss?cve=${cveId}
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- OSV Database: https://osv.dev/vulnerability/${cveId}

Consider reviewing vendor-specific advisories and threat intelligence feeds for additional context.`,
      ragUsed: false,
      ragDocuments: 0,
      ragSources: [],
      webGrounded: false,
      enhancedSources: vulnerability.enhancedSources || [],
      error: error.message
    };
  }
};

// Enhanced fetch function with RAG integration
const fetchVulnerabilityData = async (cveId, setLoadingSteps, apiKeys) => {
  try {
    setLoadingSteps(prev => [...prev, `🚀 Starting comprehensive RAG-enhanced analysis for ${cveId}...`]);
    
    // Initialize RAG database early in the process
    if (!enhancedRAGDatabase.initialized) {
      setLoadingSteps(prev => [...prev, `📚 Initializing RAG knowledge base...`]);
      await enhancedRAGDatabase.initialize();
    }
    
    const [
      cveResult,
      epssResult,
      kevResult,
      githubResult,
      osvResult
    ] = await Promise.allSettled([
      fetchCVEDataFromNVD(cveId, setLoadingSteps, apiKeys.nvd),
      fetchEPSSData(cveId, setLoadingSteps),
      fetchKEVData(cveId, setLoadingSteps),
      fetchGitHubSecurityAdvisories(cveId, setLoadingSteps, apiKeys.github),
      fetchOSVData(cveId, setLoadingSteps)
    ]);
    
    const cve = cveResult.status === 'fulfilled' ? cveResult.value : null;
    const epss = epssResult.status === 'fulfilled' ? epssResult.value : null;
    const kev = kevResult.status === 'fulfilled' ? kevResult.value : null;
    const github = githubResult.status === 'fulfilled' ? githubResult.value : null;
    const osv = osvResult.status === 'fulfilled' ? osvResult.value : null;
    
    if (!cve) {
      throw new Error(`Failed to fetch CVE data for ${cveId}`);
    }
    
    setLoadingSteps(prev => [...prev, `✅ Comprehensive RAG-enhanced analysis complete for ${cveId}`]);
    
    const enhancedSources = ['NVD'];
    if (epss) enhancedSources.push('EPSS');
    if (kev) enhancedSources.push('KEV');
    if (github && github.length > 0) enhancedSources.push('GitHub');
    if (osv && osv.length > 0) enhancedSources.push('OSV');
    
    return {
      cve,
      epss,
      kev,
      github,
      osv,
      dataFreshness: 'REAL_TIME',
      lastUpdated: new Date().toISOString(),
      searchTimestamp: new Date().toISOString(),
      enhancedSources,
      ragEnhanced: true
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
            marginBottom: '12px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {notification.type === 'success' && <CheckCircle size={20} color="#22c55e" />}
            {notification.type === 'error' && <XCircle size={20} color="#ef4444" />}
            {notification.type === 'warning' && <AlertTriangle size={20} color="#f59e0b" />}
            <div>
              <div style={{ fontWeight: '600', fontSize: '0.95rem', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>{notification.title}</div>
              <div style={{ fontSize: '0.8rem', color: settings.darkMode ? '#64748b' : '#94a3b8' }}>{notification.message}</div>
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

  const handleSave = () => {
    setSettings(localSettings);
    onClose();
  };

  const testGeminiConnection = async () => {
    if (!localSettings.geminiApiKey) {
      alert('Please enter a Gemini API key first');
      return;
    }

    setTestingConnection(true);
    try {
      const testPrompt = 'Test connection - respond with "Connection successful"';
      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${localSettings.geminiApiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: testPrompt }] }]
        })
      });
      
      if (response.ok) {
        alert('✅ Gemini AI connection successful!');
      } else {
        throw new Error(`HTTP ${response.status}`);
      }
    } catch (error) {
      alert(`❌ Connection failed: ${error.message}`);
    } finally {
      setTestingConnection(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div style={styles.modal}>
      <div style={styles.modalContent}>
        <div style={styles.modalHeader}>
          <h3 style={styles.modalTitle}>RAG-Enhanced Platform Settings</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer' }}>
            <X size={24} color={settings.darkMode ? '#f1f5f9' : '#0f172a'} />
          </button>
        </div>

        <div style={{ display: 'grid', gap: '32px' }}>
          <div>
            <h4 style={{ margin: '0 0 20px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a', fontSize: '1.2rem', fontWeight: '700' }}>
              🤖 AI & RAG Configuration
            </h4>
            
            <div style={styles.formGroup}>
              <label style={styles.label}>Gemini API Key (Required for AI Analysis)</label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showGeminiKey ? 'text' : 'password'}
                  style={styles.input}
                  placeholder="Enter your Gemini API key for RAG-enhanced analysis"
                  value={localSettings.geminiApiKey || ''}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiApiKey: e.target.value }))}
                />
                <button
                  style={{ 
                    position: 'absolute', 
                    right: '12px', 
                    top: '50%', 
                    transform: 'translateY(-50%)',
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer'
                  }}
                  onClick={() => setShowGeminiKey(!showGeminiKey)}
                >
                  {showGeminiKey ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
              <div style={{ fontSize: '0.8rem', color: settings.darkMode ? '#64748b' : '#94a3b8', marginTop: '8px' }}>
                Get your free API key from{' '}
                <a 
                  href="https://aistudio.google.com/app/apikey" 
                  target="_blank" 
                  rel="noopener noreferrer" 
                  style={{ color: '#3b82f6', textDecoration: 'none' }}
                >
                  Google AI Studio
                </a>
              </div>
            </div>

            <div style={styles.formGroup}>
              <label style={styles.label}>Gemini Model Selection</label>
              <select
                style={styles.select}
                value={localSettings.geminiModel || 'gemini-2.0-flash-exp'}
                onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiModel: e.target.value }))}
              >
                <option value="gemini-2.0-flash-exp">Gemini 2.0 Flash (Real-time Web Search + RAG)</option>
                <option value="gemini-1.5-flash">Gemini 1.5 Flash (Fast RAG Analysis)</option>
                <option value="gemini-1.5-pro">Gemini 1.5 Pro (Deep RAG Analysis)</option>
                <option value="gemini-pro">Gemini Pro (Standard RAG)</option>
              </select>
            </div>

            <button
              onClick={testGeminiConnection}
              disabled={testingConnection || !localSettings.geminiApiKey}
              style={{
                ...styles.button,
                ...styles.buttonSecondary,
                opacity: testingConnection || !localSettings.geminiApiKey ? 0.6 : 1,
                marginBottom: '24px'
              }}
            >
              {testingConnection ? <Loader2 size={18} className="animate-spin" /> : <Brain size={18} />}
              Test AI + RAG Connection
            </button>

            <div style={{
              background: settings.darkMode ? 'rgba(59, 130, 246, 0.1)' : 'rgba(59, 130, 246, 0.05)',
              border: '1px solid rgba(59, 130, 246, 0.3)',
              borderRadius: '12px',
              padding: '20px'
            }}>
              <h5 style={{ margin: '0 0 12px 0', color: '#3b82f6', fontSize: '1rem', fontWeight: '600' }}>
                🧠 RAG-Enhanced Intelligence Features
              </h5>
              <div style={{ fontSize: '0.85rem', color: settings.darkMode ? '#cbd5e1' : '#475569' }}>
                <div style={{ marginBottom: '8px' }}>✓ Vector database with security knowledge base</div>
                <div style={{ marginBottom: '8px' }}>✓ Semantic search for relevant context retrieval</div>
                <div style={{ marginBottom: '8px' }}>✓ Real-time knowledge base updates from analysis</div>
                <div style={{ marginBottom: '8px' }}>✓ Multi-source data integration and augmentation</div>
                <div>✓ Context-aware AI analysis with domain expertise</div>
              </div>
            </div>
          </div>

          <div>
            <h4 style={{ margin: '0 0 20px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a', fontSize: '1.2rem', fontWeight: '700' }}>
              🌐 Data Source Configuration
            </h4>
            
            <div style={styles.formGroup}>
              <label style={styles.label}>NVD API Key (Optional - Higher Rate Limits)</label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showApiKey ? 'text' : 'password'}
                  style={styles.input}
                  placeholder="Enter your NVD API key for increased rate limits"
                  value={localSettings.nvdApiKey || ''}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, nvdApiKey: e.target.value }))}
                />
                <button
                  style={{ 
                    position: 'absolute', 
                    right: '12px', 
                    top: '50%', 
                    transform: 'translateY(-50%)',
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer'
                  }}
                  onClick={() => setShowApiKey(!showApiKey)}
                >
                  {showApiKey ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            <div style={styles.formGroup}>
              <label style={styles.label}>GitHub Personal Access Token</label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showGitHubKey ? 'text' : 'password'}
                  style={styles.input}
                  placeholder="Enter GitHub PAT for supply chain intelligence"
                  value={localSettings.githubToken || ''}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, githubToken: e.target.value }))}
                />
                <button
                  style={{ 
                    position: 'absolute', 
                    right: '12px', 
                    top: '50%', 
                    transform: 'translateY(-50%)',
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer'
                  }}
                  onClick={() => setShowGitHubKey(!showGitHubKey)}
                >
                  {showGitHubKey ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
              <div style={{ fontSize: '0.8rem', color: settings.darkMode ? '#64748b' : '#94a3b8', marginTop: '4px' }}>
                Required for GitHub Security Advisory data and package intelligence
              </div>
            </div>
          </div>

          <div>
            <h4 style={{ margin: '0 0 20px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a', fontSize: '1.2rem', fontWeight: '700' }}>
              ⚙️ Analysis Preferences
            </h4>
            
            <div style={styles.formGroup}>
              <label style={{ ...styles.label, display: 'flex', alignItems: 'center', gap: '12px' }}>
                <input
                  type="checkbox"
                  checked={localSettings.includeExploits !== false}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, includeExploits: e.target.checked }))}
                  style={{ width: 'auto' }}
                />
                Deep Exploit Analysis
              </label>
              <div style={{ fontSize: '0.8rem', color: settings.darkMode ? '#64748b' : '#94a3b8', marginTop: '4px', marginLeft: '24px' }}>
                Search ExploitDB, GitHub, and other sources for public exploits
              </div>
            </div>

            <div style={styles.formGroup}>
              <label style={{ ...styles.label, display: 'flex', alignItems: 'center', gap: '12px' }}>
                <input
                  type="checkbox"
                  checked={localSettings.includeThreatIntel !== false}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, includeThreatIntel: e.target.checked }))}
                  style={{ width: 'auto' }}
                />
                Threat Intelligence Enrichment
              </label>
              <div style={{ fontSize: '0.8rem', color: settings.darkMode ? '#64748b' : '#94a3b8', marginTop: '4px', marginLeft: '24px' }}>
                Include active threat campaigns and malware families
              </div>
            </div>

            <div style={styles.formGroup}>
              <label style={{ ...styles.label, display: 'flex', alignItems: 'center', gap: '12px' }}>
                <input
                  type="checkbox"
                  checked={localSettings.darkMode || false}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, darkMode: e.target.checked }))}
                  style={{ width: 'auto' }}
                />
                Dark Mode Interface
              </label>
            </div>

            <div style={styles.formGroup}>
              <label style={{ ...styles.label, display: 'flex', alignItems: 'center', gap: '12px' }}>
                <input
                  type="checkbox"
                  checked={localSettings.enableRAG !== false}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, enableRAG: e.target.checked }))}
                  style={{ width: 'auto' }}
                />
                Enable RAG-Enhanced Analysis
              </label>
              <div style={{ fontSize: '0.8rem', color: settings.darkMode ? '#64748b' : '#94a3b8', marginTop: '4px', marginLeft: '24px' }}>
                Use vector database and semantic search for contextual analysis
              </div>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '16px', justifyContent: 'flex-end', paddingTop: '24px', borderTop: settings.darkMode ? '2px solid #334155' : '2px solid #e2e8f0' }}>
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
            <Save size={18} />
            Save Configuration
          </button>
        </div>
      </div>
    </div>
  );
};

const CVEDetailView = ({ vulnerability, onRefresh, onExport }) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const { settings, addNotification } = useContext(AppContext);
  const styles = getStyles(settings.darkMode);

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getSeverityStyle = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return styles.badgeCritical;
      case 'HIGH': return styles.badgeHigh;
      case 'MEDIUM': return styles.badgeMedium;
      case 'LOW': return styles.badgeLow;
      default: return styles.badge;
    }
  };

  const getSeverityColor = (score) => {
    if (score >= 9) return '#ef4444';
    if (score >= 7) return '#f59e0b';
    if (score >= 4) return '#3b82f6';
    return '#22c55e';
  };

  const cvssScore = vulnerability.cve?.cvssV3?.baseScore || vulnerability.cve?.cvssV2?.baseScore || 0;
  const severity = vulnerability.cve?.cvssV3?.baseSeverity || 
                  (cvssScore >= 9 ? 'CRITICAL' : 
                   cvssScore >= 7 ? 'HIGH' : 
                   cvssScore >= 4 ? 'MEDIUM' : 'LOW');

  const generateRAGAnalysis = async () => {
    if (!settings.geminiApiKey) {
      addNotification({
        type: 'error',
        title: 'API Key Required',
        message: 'Please configure your Gemini API key in settings'
      });
      return;
    }

    setAiLoading(true);
    try {
      const result = await generateEnhancedRAGAnalysis(
        vulnerability,
        settings.geminiApiKey,
        settings.geminiModel || 'gemini-2.0-flash-exp',
        settings
      );
      setAiAnalysis(result);
      setActiveTab('ai-analysis');
      
      addNotification({
        type: 'success',
        title: 'RAG Analysis Complete',
        message: `Enhanced analysis generated using ${result.ragDocuments} knowledge sources and real-time intelligence`
      });
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'AI Analysis Failed',
        message: error.message
      });
    } finally {
      setAiLoading(false);
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 400px', gap: '40px', marginTop: '40px' }}>
      {/* Main Content */}
      <div style={{
        background: settings.darkMode ? 'linear-gradient(135deg, #1e293b 0%, #334155 100%)' : '#ffffff',
        borderRadius: '20px',
        padding: '40px',
        boxShadow: settings.darkMode ? '0 8px 32px rgba(0, 0, 0, 0.3)' : '0 4px 20px rgba(0, 0, 0, 0.08)',
        border: settings.darkMode ? '1px solid #334155' : '1px solid #e2e8f0'
      }}>
        {/* Header */}
        <div style={{
          marginBottom: '32px',
          paddingBottom: '20px',
          borderBottom: settings.darkMode ? '2px solid #334155' : '2px solid #e2e8f0'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
            <h1 style={{
              fontSize: '2.25rem',
              fontWeight: '800',
              background: 'linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              margin: 0
            }}>
              {vulnerability.cve?.id || 'Unknown CVE'}
            </h1>
            
            <div style={{ display: 'flex', gap: '12px' }}>
              <button
                onClick={onRefresh}
                style={{
                  ...styles.button,
                  ...styles.buttonSecondary,
                  padding: '8px 16px'
                }}
              >
                <RefreshCw size={16} />
                Refresh
              </button>
              <button
                onClick={onExport}
                style={{
                  ...styles.button,
                  ...styles.buttonPrimary,
                  padding: '8px 16px'
                }}
              >
                <Download size={16} />
                Export
              </button>
            </div>
          </div>

          <p style={{
            fontSize: '1.2rem',
            color: settings.darkMode ? '#94a3b8' : '#64748b',
            marginBottom: '20px',
            fontWeight: '500'
          }}>
            RAG-Enhanced Vulnerability Intelligence with Real-time Analysis
          </p>

          <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{
              ...styles.badge,
              ...getSeverityStyle(severity),
              fontSize: '0.9rem',
              padding: '8px 16px'
            }}>
              {severity} - {cvssScore?.toFixed(1) || 'N/A'}
            </span>
            
            {vulnerability.kev && (
              <span style={{
                ...styles.badge,
                ...styles.badgeCritical,
                fontSize: '0.8rem',
                padding: '6px 12px'
              }}>
                CISA KEV
              </span>
            )}
            
            {vulnerability.epss?.epss > 0.5 && (
              <span style={{
                ...styles.badge,
                background: 'rgba(245, 158, 11, 0.15)',
                color: '#f59e0b',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                fontSize: '0.8rem',
                padding: '6px 12px'
              }}>
                HIGH EPSS: {(vulnerability.epss.epss * 100).toFixed(1)}%
              </span>
            )}

            {vulnerability.ragEnhanced && (
              <span style={{
                ...styles.badge,
                background: 'rgba(139, 92, 246, 0.15)',
                color: '#8b5cf6',
                border: '1px solid rgba(139, 92, 246, 0.3)',
                fontSize: '0.8rem',
                padding: '6px 12px'
              }}>
                <Database size={12} style={{ marginRight: '4px' }} />
                RAG ENHANCED
              </span>
            )}
          </div>
        </div>

        {/* Tabs */}
        <div style={{
          display: 'flex',
          borderBottom: settings.darkMode ? '2px solid #334155' : '2px solid #e2e8f0',
          marginBottom: '32px',
          gap: '8px',
          flexWrap: 'wrap'
        }}>
          {['overview', 'packages', 'technical', 'ai-analysis'].map((tab) => (
            <div 
              key={tab}
              style={{
                padding: '16px 20px',
                cursor: 'pointer',
                borderBottom: activeTab === tab ? '3px solid #3b82f6' : '3px solid transparent',
                fontSize: '0.95rem',
                fontWeight: '600',
                color: activeTab === tab ? '#3b82f6' : (settings.darkMode ? '#64748b' : '#94a3b8'),
                transition: 'all 0.3s ease',
                borderRadius: '12px 12px 0 0',
                background: activeTab === tab ? (settings.darkMode ? 'rgba(59, 130, 246, 0.1)' : 'rgba(59, 130, 246, 0.05)') : 'transparent'
              }}
              onClick={() => setActiveTab(tab)}
            >
              {tab === 'overview' && <Info size={16} style={{ marginRight: '6px', display: 'inline' }} />}
              {tab === 'packages' && <Package size={16} style={{ marginRight: '6px', display: 'inline' }} />}
              {tab === 'technical' && <BarChart3 size={16} style={{ marginRight: '6px', display: 'inline' }} />}
              {tab === 'ai-analysis' && <Brain size={16} style={{ marginRight: '6px', display: 'inline' }} />}
              {tab === 'ai-analysis' ? 'RAG Analysis' : tab.charAt(0).toUpperCase() + tab.slice(1)}
            </div>
          ))}
        </div>

        {/* Tab Content */}
        <div>
          {activeTab === 'overview' && (
            <div>
              <h2 style={{
                fontSize: '1.5rem',
                fontWeight: '700',
                color: settings.darkMode ? '#f1f5f9' : '#0f172a',
                marginBottom: '20px'
              }}>
                Vulnerability Overview
              </h2>
              
              <div style={{
                fontSize: '1rem',
                lineHeight: '1.7',
                color: settings.darkMode ? '#cbd5e1' : '#475569',
                marginBottom: '32px'
              }}>
                <p style={{ fontSize: '1.05rem', lineHeight: '1.7' }}>
                  {vulnerability.cve?.description || 'No description available'}
                </p>
              </div>

              {vulnerability.epss && (
                <div style={{ marginBottom: '32px' }}>
                  <h3 style={{ fontSize: '1.2rem', fontWeight: '600', marginBottom: '16px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                    Exploitation Probability (EPSS)
                  </h3>
                  <div style={{
                    background: vulnerability.epss.epss > 0.5 ? 'rgba(245, 158, 11, 0.1)' : 'rgba(34, 197, 94, 0.1)',
                    border: `1px solid ${vulnerability.epss.epss > 0.5 ? 'rgba(245, 158, 11, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`,
                    borderRadius: '12px',
                    padding: '20px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                      <Target size={24} color={vulnerability.epss.epss > 0.5 ? '#f59e0b' : '#22c55e'} />
                      <div>
                        <div style={{ fontWeight: '700', fontSize: '1.1rem' }}>
                          EPSS Score: {(vulnerability.epss.epss * 100).toFixed(2)}%
                        </div>
                        <div style={{ fontSize: '0.9rem', opacity: 0.8 }}>
                          Percentile: {vulnerability.epss.percentile?.toFixed(1) || 'N/A'}
                        </div>
                      </div>
                    </div>
                    <p style={{ margin: 0, fontSize: '0.95rem' }}>
                      {vulnerability.epss.epss > 0.5 
                        ? 'This vulnerability has a HIGH probability of exploitation in the wild. Immediate patching recommended.'
                        : vulnerability.epss.epss > 0.1 
                          ? 'This vulnerability has a MODERATE probability of exploitation. Monitor for patches and updates.'
                          : 'This vulnerability has a LOW probability of exploitation, but still requires attention.'}
                    </p>
                  </div>
                </div>
              )}

              {vulnerability.kev && (
                <div style={{ marginBottom: '32px' }}>
                  <h3 style={{ fontSize: '1.2rem', fontWeight: '600', marginBottom: '16px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                    CISA Known Exploited Vulnerability
                  </h3>
                  <div style={{
                    background: 'rgba(239, 68, 68, 0.1)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    borderRadius: '12px',
                    padding: '20px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                      <AlertTriangle size={24} color="#ef4444" />
                      <span style={{ fontWeight: '700', fontSize: '1.1rem', color: '#ef4444' }}>
                        ACTIVE EXPLOITATION CONFIRMED
                      </span>
                    </div>
                    <div style={{ display: 'grid', gap: '12px' }}>
                      <div><strong>Vendor/Product:</strong> {vulnerability.kev.vendorProject} / {vulnerability.kev.product}</div>
                      <div><strong>Vulnerability Name:</strong> {vulnerability.kev.vulnerabilityName}</div>
                      <div><strong>Required Action:</strong> {vulnerability.kev.requiredAction}</div>
                      <div><strong>Due Date:</strong> {vulnerability.kev.dueDate}</div>
                      {vulnerability.kev.knownRansomwareCampaignUse === 'Known' && (
                        <div style={{ color: '#ef4444', fontWeight: '700' }}>
                          ⚠️ Known to be used in ransomware campaigns
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* RAG Analysis Button */}
              <div style={{ 
                marginTop: '40px', 
                paddingTop: '32px', 
                borderTop: settings.darkMode ? '2px solid #334155' : '2px solid #e2e8f0',
                textAlign: 'center'
              }}>
                <button
                  style={{
                    ...styles.button,
                    ...styles.buttonPrimary,
                    opacity: aiLoading ? 0.7 : 1,
                    fontSize: '1rem',
                    padding: '16px 32px'
                  }}
                  onClick={generateRAGAnalysis}
                  disabled={aiLoading || !settings.geminiApiKey}
                >
                  {aiLoading ? (
                    <>
                      <Loader2 size={20} style={{ animation: 'spin 1s linear infinite' }} />
                      Generating RAG-Enhanced Analysis...
                    </>
                  ) : (
                    <>
                      <Brain size={20} />
                      <Database size={16} style={{ marginLeft: '4px' }} />
                      Generate RAG-Powered Analysis
                    </>
                  )}
                </button>
                {!settings.geminiApiKey && (
                  <p style={{ fontSize: '0.9rem', color: settings.darkMode ? '#64748b' : '#94a3b8', marginTop: '12px' }}>
                    Configure Gemini API key in settings to enable RAG-enhanced threat intelligence
                  </p>
                )}
              </div>
            </div>
          )}

          {activeTab === 'packages' && (
            <div>
              <h2 style={{
                fontSize: '1.5rem',
                fontWeight: '700',
                color: settings.darkMode ? '#f1f5f9' : '#0f172a',
                marginBottom: '20px'
              }}>
                Affected Packages & Supply Chain
              </h2>
              
              {/* GitHub Advisories */}
              {vulnerability.github && vulnerability.github.length > 0 && (
                <div style={{ marginBottom: '32px' }}>
                  <h3 style={{ fontSize: '1.2rem', fontWeight: '600', marginBottom: '16px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                    GitHub Security Advisories
                  </h3>
                  {vulnerability.github.map((advisory, index) => (
                    <div key={index} style={{
                      background: settings.darkMode ? '#334155' : '#f8fafc',
                      border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0',
                      borderRadius: '12px',
                      padding: '20px',
                      marginBottom: '16px'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                        <span style={{
                          ...styles.badge,
                          background: 'rgba(139, 92, 246, 0.15)',
                          color: '#8b5cf6',
                          border: '1px solid rgba(139, 92, 246, 0.3)'
                        }}>
                          {advisory.ghsaId}
                        </span>
                        <span style={{
                          ...styles.badge,
                          ...getSeverityStyle(advisory.severity)
                        }}>
                          {advisory.severity}
                        </span>
                      </div>
                      <h4 style={{ margin: '0 0 8px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                        {advisory.summary}
                      </h4>
                      <p style={{ margin: '0 0 12px 0', fontSize: '0.9rem', color: settings.darkMode ? '#cbd5e1' : '#475569' }}>
                        {advisory.description}
                      </p>
                      {advisory.vulnerabilities?.nodes && advisory.vulnerabilities.nodes.length > 0 && (
                        <div>
                          <strong>Affected Packages:</strong>
                          <div style={{ marginTop: '8px' }}>
                            {advisory.vulnerabilities.nodes.map((vuln, vIndex) => (
                              <div key={vIndex} style={{
                                background: settings.darkMode ? '#1e293b' : '#ffffff',
                                border: settings.darkMode ? '1px solid #334155' : '1px solid #e2e8f0',
                                borderRadius: '8px',
                                padding: '12px',
                                marginBottom: '8px',
                                fontSize: '0.85rem'
                              }}>
                                <div><strong>Ecosystem:</strong> {vuln.package.ecosystem}</div>
                                <div><strong>Package:</strong> {vuln.package.name}</div>
                                <div><strong>Vulnerable Range:</strong> {vuln.vulnerableVersionRange}</div>
                                {vuln.firstPatchedVersion && (
                                  <div><strong>First Patched:</strong> {vuln.firstPatchedVersion.identifier}</div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* OSV Data */}
              {vulnerability.osv && vulnerability.osv.length > 0 && (
                <div style={{ marginBottom: '32px' }}>
                  <h3 style={{ fontSize: '1.2rem', fontWeight: '600', marginBottom: '16px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                    OSV Database Entries
                  </h3>
                  {vulnerability.osv.map((entry, index) => (
                    <div key={index} style={{
                      background: settings.darkMode ? '#334155' : '#f8fafc',
                      border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0',
                      borderRadius: '12px',
                      padding: '20px',
                      marginBottom: '16px'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                        <span style={{
                          ...styles.badge,
                          background: 'rgba(34, 197, 94, 0.15)',
                          color: '#22c55e',
                          border: '1px solid rgba(34, 197, 94, 0.3)'
                        }}>
                          {entry.id}
                        </span>
                      </div>
                      <h4 style={{ margin: '0 0 8px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                        {entry.summary || 'OSV Entry'}
                      </h4>
                      {entry.affected && entry.affected.length > 0 && (
                        <div>
                          <strong>Affected Packages:</strong>
                          <div style={{ marginTop: '8px' }}>
                            {entry.affected.map((affected, aIndex) => (
                              <div key={aIndex} style={{
                                background: settings.darkMode ? '#1e293b' : '#ffffff',
                                border: settings.darkMode ? '1px solid #334155' : '1px solid #e2e8f0',
                                borderRadius: '8px',
                                padding: '12px',
                                marginBottom: '8px',
                                fontSize: '0.85rem'
                              }}>
                                <div><strong>Ecosystem:</strong> {affected.package?.ecosystem || 'Unknown'}</div>
                                <div><strong>Package:</strong> {affected.package?.name || 'Unknown'}</div>
                                {affected.ranges && affected.ranges.length > 0 && (
                                  <div><strong>Affected Ranges:</strong> {affected.ranges.length} range(s)</div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {(!vulnerability.github || vulnerability.github.length === 0) && 
               (!vulnerability.osv || vulnerability.osv.length === 0) && (
                <div style={{
                  textAlign: 'center',
                  padding: '60px',
                  background: settings.darkMode ? '#334155' : '#f8fafc',
                  borderRadius: '12px',
                  border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0'
                }}>
                  <Package size={48} style={{ marginBottom: '16px', opacity: 0.5 }} />
                  <p>No package information available from GitHub Security Advisories or OSV database for this CVE.</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'technical' && (
            <div>
              <h2 style={{
                fontSize: '1.5rem',
                fontWeight: '700',
                color: settings.darkMode ? '#f1f5f9' : '#0f172a',
                marginBottom: '20px'
              }}>
                Technical Details
              </h2>
              
              {vulnerability.cve?.cvssV3 && (
                <div style={{ marginBottom: '32px' }}>
                  <h3 style={{ fontSize: '1.2rem', fontWeight: '600', marginBottom: '16px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                    CVSS v3.1 Metrics
                  </h3>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '20px' }}>
                    <div style={{
                      background: settings.darkMode ? '#334155' : '#f8fafc',
                      borderRadius: '12px',
                      padding: '20px',
                      border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0'
                    }}>
                      <h4 style={{ margin: '0 0 16px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>Base Metrics</h4>
                      <div style={{ display: 'grid', gap: '8px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Base Score:</span>
                          <span style={{ fontSize: '0.85rem', fontWeight: '600' }}>{vulnerability.cve.cvssV3.baseScore}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Attack Vector:</span>
                          <span style={{ fontSize: '0.85rem', fontWeight: '600' }}>{vulnerability.cve.cvssV3.attackVector}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Complexity:</span>
                          <span style={{ fontSize: '0.85rem', fontWeight: '600' }}>{vulnerability.cve.cvssV3.attackComplexity}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Privileges Required:</span>
                          <span style={{ fontSize: '0.85rem', fontWeight: '600' }}>{vulnerability.cve.cvssV3.privilegesRequired}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>User Interaction:</span>
                          <span style={{ fontSize: '0.85rem', fontWeight: '600' }}>{vulnerability.cve.cvssV3.userInteraction}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Scope:</span>
                          <span style={{ fontSize: '0.85rem', fontWeight: '600' }}>{vulnerability.cve.cvssV3.scope}</span>
                        </div>
                      </div>
                    </div>

                    <div style={{
                      background: settings.darkMode ? '#334155' : '#f8fafc',
                      borderRadius: '12px',
                      padding: '20px',
                      border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0'
                    }}>
                      <h4 style={{ margin: '0 0 16px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>Impact Metrics</h4>
                      <div style={{ display: 'grid', gap: '8px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Confidentiality:</span>
                          <span style={{ fontSize: '0.85rem', fontWeight: '600' }}>{vulnerability.cve.cvssV3.confidentialityImpact}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Integrity:</span>
                          <span style={{ fontSize: '0.85rem', fontWeight: '600' }}>{vulnerability.cve.cvssV3.integrityImpact}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Availability:</span>
                          <span style={{ fontSize: '0.85rem', fontWeight: '600' }}>{vulnerability.cve.cvssV3.availabilityImpact}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Exploitability Score:</span>
                          <span style={{ fontSize: '0.85rem', fontWeight: '600' }}>{vulnerability.cve.cvssV3.exploitabilityScore}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Impact Score:</span>
                          <span style={{ fontSize: '0.85rem', fontWeight: '600' }}>{vulnerability.cve.cvssV3.impactScore}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div style={{ marginTop: '20px' }}>
                    <h4 style={{ margin: '0 0 12px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>Vector String</h4>
                    <div style={{
                      background: settings.darkMode ? '#1e293b' : '#ffffff',
                      border: settings.darkMode ? '1px solid #334155' : '1px solid #e2e8f0',
                      borderRadius: '8px',
                      padding: '12px',
                      fontFamily: 'monospace',
                      fontSize: '0.9rem',
                      wordBreak: 'break-all'
                    }}>
                      {vulnerability.cve.cvssV3.vectorString}
                    </div>
                  </div>
                </div>
              )}

              {vulnerability.cve?.cvssV2 && (
                <div style={{ marginBottom: '32px' }}>
                  <h3 style={{ fontSize: '1.2rem', fontWeight: '600', marginBottom: '16px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                    CVSS v2.0 Metrics
                  </h3>
                  <div style={{
                    background: settings.darkMode ? '#334155' : '#f8fafc',
                    borderRadius: '12px',
                    padding: '20px',
                    border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0'
                  }}>
                    <div style={{ display: 'grid', gap: '8px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Base Score:</span>
                        <span style={{ fontSize: '0.85rem', fontWeight: '600' }}>{vulnerability.cve.cvssV2.baseScore}</span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Access Vector:</span>
                        <span style={{ fontSize: '0.85rem', fontWeight: '600' }}>{vulnerability.cve.cvssV2.accessVector}</span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Access Complexity:</span>
                        <span style={{ fontSize: '0.85rem', fontWeight: '600' }}>{vulnerability.cve.cvssV2.accessComplexity}</span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Authentication:</span>
                        <span style={{ fontSize: '0.85rem', fontWeight: '600' }}>{vulnerability.cve.cvssV2.authentication}</span>
                      </div>
                    </div>
                    <div style={{ marginTop: '16px' }}>
                      <h5 style={{ margin: '0 0 8px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>Vector String</h5>
                      <div style={{
                        background: settings.darkMode ? '#1e293b' : '#ffffff',
                        border: settings.darkMode ? '1px solid #334155' : '1px solid #e2e8f0',
                        borderRadius: '8px',
                        padding: '12px',
                        fontFamily: 'monospace',
                        fontSize: '0.9rem',
                        wordBreak: 'break-all'
                      }}>
                        {vulnerability.cve.cvssV2.vectorString}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {vulnerability.cve?.references && vulnerability.cve.references.length > 0 && (
                <div style={{ marginBottom: '32px' }}>
                  <h3 style={{ fontSize: '1.2rem', fontWeight: '600', marginBottom: '16px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                    References
                  </h3>
                  <div style={{ display: 'grid', gap: '12px' }}>
                    {vulnerability.cve.references.slice(0, 10).map((ref, index) => (
                      <div key={index} style={{
                        background: settings.darkMode ? '#334155' : '#f8fafc',
                        border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0',
                        borderRadius: '8px',
                        padding: '16px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '12px'
                      }}>
                        <ExternalLink size={16} color={settings.darkMode ? '#94a3b8' : '#64748b'} />
                        <div style={{ flex: 1 }}>
                          <a 
                            href={ref.url} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            style={{ 
                              color: '#3b82f6', 
                              textDecoration: 'none',
                              fontSize: '0.9rem',
                              fontWeight: '500'
                            }}
                          >
                            {ref.url}
                          </a>
                          {ref.source && (
                            <div style={{ 
                              fontSize: '0.8rem', 
                              color: settings.darkMode ? '#64748b' : '#94a3b8',
                              marginTop: '4px'
                            }}>
                              Source: {ref.source}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                    {vulnerability.cve.references.length > 10 && (
                      <div style={{ 
                        textAlign: 'center', 
                        padding: '12px',
                        fontSize: '0.9rem', 
                        color: settings.darkMode ? '#64748b' : '#94a3b8'
                      }}>
                        And {vulnerability.cve.references.length - 10} more references...
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'ai-analysis' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
                <h2 style={{
                  fontSize: '1.5rem',
                  fontWeight: '700',
                  color: settings.darkMode ? '#f1f5f9' : '#0f172a',
                  margin: 0
                }}>
                  RAG-Enhanced Security Analysis
                </h2>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  {aiAnalysis?.webGrounded && (
                    <span style={{
                      ...styles.badge,
                      background: 'rgba(34, 197, 94, 0.15)',
                      color: '#22c55e',
                      border: '1px solid rgba(34, 197, 94, 0.3)'
                    }}>
                      <Globe size={12} style={{ marginRight: '4px' }} />
                      REAL-TIME
                    </span>
                  )}
                  {aiAnalysis?.ragUsed && (
                    <span style={{
                      ...styles.badge,
                      background: 'rgba(139, 92, 246, 0.15)',
                      color: '#8b5cf6',
                      border: '1px solid rgba(139, 92, 246, 0.3)'
                    }}>
                      <Database size={12} style={{ marginRight: '4px' }} />
                      RAG ENHANCED
                    </span>
                  )}
                </div>
              </div>

              {aiAnalysis ? (
                <div>
                  <div style={{
                    whiteSpace: 'pre-wrap',
                    lineHeight: '1.7',
                    fontSize: '1rem',
                    color: settings.darkMode ? '#cbd5e1' : '#475569'
                  }}>
                    {aiAnalysis.analysis}
                  </div>
                  <div style={{
                    background: settings.darkMode ? '#334155' : '#f8fafc',
                    border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0',
                    borderRadius: '12px',
                    padding: '16px',
                    marginTop: '24px',
                    fontSize: '0.85rem'
                  }}>
                    <div style={{ fontWeight: '600', marginBottom: '8px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                      Enhanced Analysis Metadata:
                    </div>
                    <div style={{ color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                      • Data Sources: {aiAnalysis.enhancedSources?.join(', ') || 'Unknown'}
                      {aiAnalysis.ragUsed && (
                        <>
                          <br />• Knowledge Base: {aiAnalysis.ragDocuments} relevant security documents
                          <br />• RAG Sources: {aiAnalysis.ragSources?.join(', ') || 'Multiple knowledge sources'}
                        </>
                      )}
                      {aiAnalysis.webGrounded && (
                        <>
                          <br />• Real-time Intelligence: Current threat landscape data via web search
                        </>
                      )}
                      <br />• Model: {aiAnalysis.model || 'Gemini Pro'}
                      <br />• Generated: {aiAnalysis.analysisTimestamp ? new Date(aiAnalysis.analysisTimestamp).toLocaleString() : 'Unknown'}
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{
                  textAlign: 'center',
                  padding: '60px',
                  background: settings.darkMode ? '#334155' : '#f8fafc',
                  borderRadius: '12px',
                  border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0'
                }}>
                  <Brain size={48} style={{ marginBottom: '16px', opacity: 0.5 }} />
                  <Database size={32} style={{ marginBottom: '20px', opacity: 0.5, marginLeft: '20px' }} />
                  <h3 style={{ margin: '0 0 12px 0' }}>RAG-Enhanced Analysis Not Generated</h3>
                  <p style={{ margin: '0 0 24px 0' }}>
                    Generate comprehensive security analysis using RAG-enhanced AI with contextual knowledge retrieval.
                  </p>
                  <button
                    style={{
                      ...styles.button,
                      ...styles.buttonPrimary,
                      opacity: aiLoading ? 0.7 : 1
                    }}
                    onClick={generateRAGAnalysis}
                    disabled={aiLoading || !settings.geminiApiKey}
                  >
                    {aiLoading ? (
                      <>
                        <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} />
                        Generating...
                      </>
                    ) : (
                      <>
                        <Brain size={18} />
                        Generate RAG Analysis
                      </>
                    )}
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Enhanced Sidebar */}
      <div style={{
        background: settings.darkMode ? 'linear-gradient(135deg, #1e293b 0%, #334155 100%)' : '#ffffff',
        borderRadius: '20px',
        padding: '32px',
        boxShadow: settings.darkMode ? '0 8px 32px rgba(0, 0, 0, 0.3)' : '0 4px 20px rgba(0, 0, 0, 0.08)',
        border: settings.darkMode ? '1px solid #334155' : '1px solid #e2e8f0',
        height: 'fit-content'
      }}>
        {/* CVSS Score Circle */}
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <div 
            style={{
              width: '140px',
              height: '140px',
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 20px',
              background: `conic-gradient(from 0deg, ${getSeverityColor(cvssScore)} 0%, ${getSeverityColor(cvssScore)} ${(cvssScore / 10) * 100}%, ${settings.darkMode ? '#334155' : '#e5e7eb'} ${(cvssScore / 10) * 100}%, ${settings.darkMode ? '#334155' : '#e5e7eb'} 100%)`
            }}
          >
            <div style={{
              width: '110px',
              height: '110px',
              borderRadius: '50%',
              background: settings.darkMode ? '#1e293b' : '#ffffff',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <div style={{
                fontSize: '1.75rem',
                fontWeight: '800',
                color: settings.darkMode ? '#f1f5f9' : '#0f172a'
              }}>
                {cvssScore?.toFixed(1) || 'N/A'}
              </div>
              <div style={{
                fontSize: '0.8rem',
                color: settings.darkMode ? '#64748b' : '#94a3b8',
                fontWeight: '600'
              }}>
                CVSS Score
              </div>
            </div>
          </div>
        </div>

        {/* Quick Stats */}
        <div style={{
          borderBottom: settings.darkMode ? '1px solid #334155' : '1px solid #e5e7eb',
          paddingBottom: '20px',
          marginBottom: '20px'
        }}>
          <div style={{ display: 'grid', gap: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b', fontWeight: '500' }}>
                Published
              </span>
              <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#f1f5f9' : '#0f172a', fontWeight: '600' }}>
                {vulnerability.cve?.publishedDate ? formatDate(vulnerability.cve.publishedDate) : 'Unknown'}
              </span>
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b', fontWeight: '500' }}>
                Last Updated
              </span>
              <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#f1f5f9' : '#0f172a', fontWeight: '600' }}>
                {vulnerability.lastUpdated ? formatDate(vulnerability.lastUpdated) : 'Unknown'}
              </span>
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b', fontWeight: '500' }}>
                Data Sources
              </span>
              <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#f1f5f9' : '#0f172a', fontWeight: '600' }}>
                {vulnerability.enhancedSources?.length || 0}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b', fontWeight: '500' }}>
                RAG Enhanced
              </span>
              <span style={{ fontSize: '0.85rem', color: vulnerability.ragEnhanced ? '#8b5cf6' : (settings.darkMode ? '#f1f5f9' : '#0f172a'), fontWeight: '600' }}>
                {vulnerability.ragEnhanced ? 'Yes' : 'No'}
              </span>
            </div>
          </div>
        </div>

        {/* Intelligence Sources */}
        <div>
          <h3 style={{
            fontSize: '0.9rem',
            fontWeight: '600',
            marginBottom: '16px',
            color: settings.darkMode ? '#94a3b8' : '#64748b'
          }}>
            🧠 RAG Intelligence Sources
          </h3>
          
          <div style={{ display: 'grid', gap: '8px' }}>
            {vulnerability.enhancedSources?.map((source, index) => (
              <div key={index} style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '6px 10px',
                background: settings.darkMode ? '#334155' : '#f8fafc',
                borderRadius: '6px',
                border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0'
              }}>
                <div style={{
                  width: '16px',
                  height: '16px',
                  background: '#22c55e',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <CheckCircle size={8} color="white" />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '0.75rem', fontWeight: '600' }}>
                    {source}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
        
        <div style={{ 
          marginTop: '24px', 
          fontSize: '0.75rem', 
          color: settings.darkMode ? '#64748b' : '#94a3b8', 
          textAlign: 'center',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '6px'
        }}>
          <Brain size={12} />
          <Database size={12} />
          Powered by RAG + AI
        </div>
      </div>
    </div>
  );
};

const SearchComponent = () => {
  const [searchTerm, setSearchTerm] = useState('');
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
    if (!searchTerm.trim()) {
      addNotification({
        type: 'warning',
        title: 'Search Required',
        message: 'Please enter a CVE ID to analyze'
      });
      return;
    }

    const cveId = searchTerm.trim().toUpperCase();
    
    if (!validateCVEFormat(cveId)) {
      addNotification({
        type: 'error',
        title: 'Invalid CVE Format',
        message: 'Please enter a valid CVE ID (e.g., CVE-2024-12345)'
      });
      return;
    }

    setLoading(true);
    setLoadingSteps([]);
    
    try {
      const vulnerability = await fetchVulnerabilityData(cveId, setLoadingSteps, {
        nvd: settings.nvdApiKey,
        github: settings.githubToken
      });
      
      setVulnerabilities([vulnerability]);
      setSearchHistory(prev => [...new Set([cveId, ...prev])].slice(0, 5));
      
      addNotification({
        type: 'success',
        title: 'RAG Analysis Complete',
        message: `Successfully analyzed ${cveId} with ${vulnerability.enhancedSources.length} data sources and RAG enhancement`
      });
      
    } catch (error) {
      console.error('Error in vulnerability search:', error);
      addNotification({
        type: 'error',
        title: 'Search Failed',
        message: error.message
      });
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
  };

  return (
    <div style={styles.searchSection}>
      <div style={styles.searchContainer}>
        <h1 style={styles.searchTitle}>RAG-Enhanced Vulnerability Intelligence</h1>
        <p style={styles.searchSubtitle}>
          AI-powered analysis with contextual knowledge retrieval and real-time threat intelligence
        </p>
        
        <div style={styles.searchWrapper}>
          <Search size={24} style={styles.searchIcon} />
          <input
            type="text"
            placeholder="Enter CVE ID (e.g., CVE-2024-12345)"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            onKeyPress={handleKeyPress}
            style={styles.searchInput}
            disabled={loading}
          />
          <button
            onClick={handleSearch}
            disabled={loading || !searchTerm.trim()}
            style={{
              ...styles.searchButton,
              opacity: loading || !searchTerm.trim() ? 0.6 : 1
            }}
          >
            {loading ? <Loader2 size={18} className="animate-spin" /> : <Brain size={18} />}
            {loading ? 'Analyzing...' : 'RAG Analyze'}
          </button>
        </div>

        <div style={{ 
          display: 'flex', 
          gap: '16px', 
          justifyContent: 'center', 
          alignItems: 'center',
          flexWrap: 'wrap',
          marginTop: '24px',
          fontSize: '0.85rem',
          color: settings.darkMode ? '#94a3b8' : '#64748b'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Brain size={16} color="#3b82f6" />
            <span>RAG-Enhanced AI</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Database size={16} color="#8b5cf6" />
            <span>Knowledge Retrieval</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Globe size={16} color="#22c55e" />
            <span>Real-time Intelligence</span>
          </div>
        </div>

        {searchHistory.length > 0 && (
          <div style={{ display: 'flex', gap: '8px', justifyContent: 'center', flexWrap: 'wrap', marginTop: '20px' }}>
            <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#64748b' : '#94a3b8', marginRight: '8px' }}>
              Recent:
            </span>
            {searchHistory.map((cve, index) => (
              <button
                key={index}
                onClick={() => setSearchTerm(cve)}
                style={{
                  padding: '4px 8px',
                  background: settings.darkMode ? 'rgba(59, 130, 246, 0.1)' : 'rgba(59, 130, 246, 0.05)',
                  border: '1px solid rgba(59, 130, 246, 0.3)',
                  borderRadius: '12px',
                  fontSize: '0.7rem',
                  color: '#3b82f6',
                  cursor: 'pointer',
                  fontWeight: '500'
                }}
              >
                {cve}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

const LoadingComponent = () => {
  const { loadingSteps, settings } = useContext(AppContext);
  const styles = getStyles(settings.darkMode);

  return (
    <div style={styles.loadingContainer}>
      <div style={{ marginBottom: '32px' }}>
        <div style={{ 
          width: '64px', 
          height: '64px', 
          border: '4px solid transparent',
          borderTop: '4px solid #3b82f6',
          borderRadius: '50%',
          animation: 'spin 1s linear infinite',
          margin: '0 auto'
        }} />
      </div>
      <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '16px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
        RAG-Enhanced Vulnerability Analysis
      </h2>
      <p style={{ fontSize: '1rem', color: settings.darkMode ? '#94a3b8' : '#64748b', marginBottom: '32px' }}>
        AI is analyzing vulnerability intelligence with contextual knowledge retrieval...
      </p>
      
      <div style={{ 
        background: settings.darkMode ? '#1e293b' : '#ffffff',
        borderRadius: '12px',
        padding: '24px',
        maxWidth: '700px',
        textAlign: 'left',
        border: settings.darkMode ? '1px solid #334155' : '1px solid #e2e8f0'
      }}>
        <div style={{ marginBottom: '16px', fontSize: '0.9rem', fontWeight: '600', color: settings.darkMode ? '#f1f5f9' : '#0f172a', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Brain size={18} color="#3b82f6" />
          <Database size={16} color="#8b5cf6" />
          RAG Analysis Progress:
        </div>
        {loadingSteps.map((step, index) => (
          <div key={index} style={{ 
            marginBottom: '8px', 
            fontSize: '0.85rem',
            color: settings.darkMode ? '#cbd5e1' : '#475569',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <div style={{
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              background: '#3b82f6',
              flexShrink: 0
            }} />
            {step}
          </div>
        ))}
      </div>
    </div>
  );
};

const VulnerabilityIntelligence = () => {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadingSteps, setLoadingSteps] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const [showSettings, setShowSettings] = useState(false);
  const [settings, setSettings] = useState({
    darkMode: false,
    geminiApiKey: '',
    geminiModel: 'gemini-2.5-flash',
    nvdApiKey: '',
    githubToken: '',
    enableRAG: true,
    includeExploits: true,
    includeThreatIntel: true
  });

  const styles = getStyles(settings.darkMode);

  const addNotification = (notification) => {
    const id = Date.now() + Math.random();
    setNotifications(prev => [...prev, { ...notification, id }]);
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 5000);
  };

  const handleRefreshAnalysis = async () => {
    if (vulnerabilities.length === 0) return;
    
    const cveId = vulnerabilities[0].cve?.id;
    if (!cveId) return;

    setLoading(true);
    setLoadingSteps([]);
    
    try {
      const vulnerability = await fetchVulnerabilityData(cveId, setLoadingSteps, {
        nvd: settings.nvdApiKey,
        github: settings.githubToken
      });
      
      setVulnerabilities([vulnerability]);
      
      addNotification({
        type: 'success',
        title: 'Analysis Refreshed',
        message: `Updated RAG-enhanced analysis for ${cveId}`
      });
      
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Refresh Failed',
        message: error.message
      });
    } finally {
      setLoading(false);
    }
  };

  const handleExportAnalysis = async () => {
    if (vulnerabilities.length === 0) return;
    
    try {
      const vulnerability = vulnerabilities[0];
      const exportData = {
        ...vulnerability,
        exportedAt: new Date().toISOString(),
        exportedBy: 'VulnIntel RAG Platform'
      };
      
      // Create and download file
      const blob = new Blob([JSON.stringify(exportData, null, 2)], {
        type: 'application/json'
      });
      
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${vulnerability.cve?.id || 'vulnerability'}_rag_analysis.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      
      addNotification({
        type: 'success',
        title: 'Export Complete',
        message: 'RAG-enhanced analysis exported successfully'
      });
      
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Export Failed',
        message: error.message
      });
    }
  };

  const contextValue = {
    vulnerabilities,
    setVulnerabilities,
    loading,
    setLoading,
    loadingSteps,
    setLoadingSteps,
    notifications,
    addNotification,
    settings,
    setSettings
  };

  return (
    <AppContext.Provider value={contextValue}>
      <div style={styles.appContainer}>
        <style>
          {`
            @keyframes spin {
              0% { transform: rotate(0deg); }
              100% { transform: rotate(360deg); }
            }
            .animate-spin {
              animation: spin 1s linear infinite;
            }
          `}
        </style>
        
        <NotificationManager />
        
        <header style={styles.header}>
          <div style={styles.headerContent}>
            <div style={styles.headerTitle}>
              <div style={{ position: 'relative' }}>
                <Brain size={32} color="#3b82f6" />
                <Database size={20} color="#8b5cf6" style={{ position: 'absolute', top: '16px', left: '20px' }} />
              </div>
              <div>
                <h1 style={styles.title}>VulnIntel RAG</h1>
                <p style={styles.subtitle}>AI-Powered Vulnerability Intelligence with Knowledge Retrieval</p>
              </div>
            </div>
            
            <div style={styles.headerActions}>
              <div style={{
                ...styles.statusIndicator,
                background: settings.geminiApiKey 
                  ? (settings.darkMode ? 'rgba(34, 197, 94, 0.15)' : 'rgba(34, 197, 94, 0.1)')
                  : (settings.darkMode ? 'rgba(245, 158, 11, 0.15)' : 'rgba(245, 158, 11, 0.1)'),
                borderColor: settings.geminiApiKey ? 'rgba(34, 197, 94, 0.3)' : 'rgba(245, 158, 11, 0.3)',
                color: settings.geminiApiKey ? '#22c55e' : '#f59e0b'
              }}>
                <Brain size={16} />
                {settings.geminiApiKey ? 'RAG Ready' : 'RAG Offline'}
              </div>
              
              <button
                onClick={() => setShowSettings(true)}
                style={{ ...styles.button, ...styles.buttonSecondary }}
              >
                <Settings size={18} />
                Configure RAG
              </button>
            </div>
          </div>
        </header>

        <main>
          <SearchComponent />
          
          <div style={styles.mainContent}>
            {loading && <LoadingComponent />}
            
            {!loading && vulnerabilities.length === 0 && (
              <div style={styles.emptyState}>
                <div style={{ marginBottom: '24px' }}>
                  <Brain size={64} color={settings.darkMode ? '#64748b' : '#94a3b8'} style={{ marginBottom: '8px' }} />
                  <Database size={48} color={settings.darkMode ? '#64748b' : '#94a3b8'} style={{ marginLeft: '32px', marginTop: '-16px' }} />
                </div>
                <h3 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '12px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                  RAG-Enhanced Intelligence Platform Ready
                </h3>
                <p style={{ fontSize: '1rem', marginBottom: '8px' }}>
                  Enter a CVE ID to begin comprehensive AI-powered vulnerability analysis with contextual knowledge retrieval
                </p>
                <p style={{ fontSize: '0.9rem', opacity: 0.7, marginBottom: '24px' }}>
                  Real-time intelligence enhanced with semantic search and domain expertise
                </p>
                
                {!settings.geminiApiKey && (
                  <div style={{
                    marginTop: '32px',
                    padding: '20px',
                    background: settings.darkMode ? 'rgba(245, 158, 11, 0.1)' : 'rgba(245, 158, 11, 0.05)',
                    border: '1px solid rgba(245, 158, 11, 0.3)',
                    borderRadius: '12px',
                    maxWidth: '500px',
                    margin: '32px auto 0'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                      <AlertTriangle size={20} color="#f59e0b" />
                      <span style={{ fontWeight: '600', color: '#f59e0b' }}>RAG Configuration Required</span>
                    </div>
                    <p style={{ fontSize: '0.9rem', margin: 0, color: settings.darkMode ? '#cbd5e1' : '#475569' }}>
                      Configure your Gemini API key to enable RAG-enhanced vulnerability analysis with contextual intelligence.
                    </p>
                  </div>
                )}
              </div>
            )}
            
            {!loading && vulnerabilities.length > 0 && (
              <CVEDetailView 
                vulnerability={vulnerabilities[0]} 
                onRefresh={handleRefreshAnalysis}
                onExport={handleExportAnalysis}
              />
            )}
          </div>
        </main>

        <SettingsModal
          isOpen={showSettings}
          onClose={() => setShowSettings(false)}
          settings={settings}
          setSettings={setSettings}
        />
      </div>
    </AppContext.Provider>
  );
};

export default VulnerabilityIntelligence;
