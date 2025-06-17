import React, { useState, createContext, useContext, useEffect } from 'react';
import { Search, Shield, AlertTriangle, Loader2, ExternalLink, Brain, Settings, Target, Clock, Database, Activity, CheckCircle, XCircle, X, Upload, Filter, PieChart, Sun, Moon, Eye, EyeOff, Save, FileText, Wifi, WifiOff, GitBranch, Code, Server, Cloud, Zap, TrendingUp, Users, Globe, Award, Bug, Layers, Info, Calendar, Package } from 'lucide-react';
import { PieChart as RechartsPieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';

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
    const vector = vocabulary.slice(0, 100).map(word => wordFreq[word] || 0);
    
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
  appContainer: { minHeight: '100vh', backgroundColor: darkMode ? '#1a1b2e' : '#f8fafc' },
  header: { 
    background: darkMode 
      ? '#16213e' 
      : '#ffffff', 
    color: darkMode ? 'white' : '#1f2937', 
    boxShadow: '0 1px 3px rgba(0, 0, 0, 0.1)',
    borderBottom: darkMode ? '1px solid #2d3748' : '1px solid #e5e7eb'
  },
  headerContent: { 
    maxWidth: '1200px', 
    margin: '0 auto', 
    padding: '16px 24px', 
    display: 'flex', 
    alignItems: 'center', 
    justifyContent: 'space-between'
  },
  headerTitle: { display: 'flex', alignItems: 'center', gap: '12px' },
  title: { fontSize: '1.25rem', fontWeight: '600', margin: 0 },
  subtitle: { fontSize: '0.875rem', opacity: 0.7, margin: 0, fontWeight: '400' },
  headerActions: { display: 'flex', alignItems: 'center', gap: '12px' },
  statusIndicator: { 
    display: 'flex', 
    alignItems: 'center', 
    gap: '6px', 
    fontSize: '0.75rem', 
    padding: '4px 8px', 
    background: darkMode ? 'rgba(34, 197, 94, 0.1)' : 'rgba(34, 197, 94, 0.1)', 
    borderRadius: '12px', 
    border: '1px solid rgba(34, 197, 94, 0.3)',
    color: '#22c55e'
  },
  mainContent: { maxWidth: '1200px', margin: '0 auto', padding: '24px' },
  searchSection: {
    background: darkMode ? '#16213e' : '#ffffff',
    padding: '40px 0 60px 0',
    borderBottom: darkMode ? '1px solid #2d3748' : '1px solid #e5e7eb'
  },
  searchContainer: {
    maxWidth: '800px',
    margin: '0 auto',
    textAlign: 'center'
  },
  searchTitle: {
    fontSize: '2rem',
    fontWeight: '700',
    color: darkMode ? '#ffffff' : '#1f2937',
    marginBottom: '8px'
  },
  searchSubtitle: {
    fontSize: '1.1rem',
    color: darkMode ? '#94a3b8' : '#6b7280',
    marginBottom: '32px'
  },
  searchWrapper: { 
    position: 'relative', 
    maxWidth: '600px', 
    margin: '0 auto',
    marginBottom: '20px' 
  },
  searchInput: { 
    width: '100%', 
    padding: '16px 20px 16px 48px', 
    border: darkMode ? '1px solid #374151' : '1px solid #d1d5db', 
    borderRadius: '12px', 
    fontSize: '1rem', 
    outline: 'none', 
    boxSizing: 'border-box', 
    background: darkMode ? '#1f2937' : '#ffffff', 
    color: darkMode ? '#f9fafb' : '#111827',
    transition: 'all 0.2s ease',
    boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)'
  },
  searchIcon: { position: 'absolute', left: '16px', top: '50%', transform: 'translateY(-50%)', color: darkMode ? '#9ca3af' : '#6b7280' },
  searchButton: { 
    position: 'absolute', 
    right: '4px', 
    top: '50%', 
    transform: 'translateY(-50%)',
    padding: '10px 20px',
    background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
    color: 'white',
    border: 'none',
    borderRadius: '8px',
    cursor: 'pointer',
    fontWeight: '500',
    display: 'flex',
    alignItems: 'center',
    gap: '6px'
  },
  button: { 
    display: 'flex', 
    alignItems: 'center', 
    gap: '6px', 
    padding: '8px 16px', 
    borderRadius: '8px', 
    fontWeight: '500', 
    cursor: 'pointer', 
    border: '1px solid', 
    fontSize: '0.875rem',
    transition: 'all 0.2s ease'
  },
  buttonPrimary: { 
    background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)', 
    color: 'white', 
    borderColor: 'transparent'
  },
  buttonSecondary: { 
    background: darkMode ? '#374151' : '#f9fafb', 
    color: darkMode ? '#f9fafb' : '#374151', 
    borderColor: darkMode ? '#4b5563' : '#d1d5db'
  },
  cveDetailContainer: {
    display: 'grid',
    gridTemplateColumns: '1fr 300px',
    gap: '32px',
    marginTop: '32px'
  },
  cveMainContent: {
    background: darkMode ? '#1f2937' : '#ffffff',
    borderRadius: '12px',
    padding: '32px',
    boxShadow: darkMode ? '0 4px 6px rgba(0, 0, 0, 0.3)' : '0 1px 3px rgba(0, 0, 0, 0.1)',
    border: darkMode ? '1px solid #374151' : '1px solid #e5e7eb'
  },
  cveSidebar: {
    background: darkMode ? '#1f2937' : '#ffffff',
    borderRadius: '12px',
    padding: '24px',
    boxShadow: darkMode ? '0 4px 6px rgba(0, 0, 0, 0.3)' : '0 1px 3px rgba(0, 0, 0, 0.1)',
    border: darkMode ? '1px solid #374151' : '1px solid #e5e7eb',
    height: 'fit-content'
  },
  cveHeader: {
    marginBottom: '24px',
    paddingBottom: '16px',
    borderBottom: darkMode ? '1px solid #374151' : '1px solid #e5e7eb'
  },
  cveTitle: {
    fontSize: '1.75rem',
    fontWeight: '700',
    color: darkMode ? '#ffffff' : '#111827',
    marginBottom: '8px'
  },
  cveSubtitle: {
    fontSize: '1.1rem',
    color: darkMode ? '#94a3b8' : '#6b7280',
    marginBottom: '16px'
  },
  tabContainer: {
    display: 'flex',
    borderBottom: darkMode ? '1px solid #374151' : '1px solid #e5e7eb',
    marginBottom: '24px'
  },
  tab: {
    padding: '12px 16px',
    cursor: 'pointer',
    borderBottom: '2px solid transparent',
    fontSize: '0.9rem',
    fontWeight: '500',
    color: darkMode ? '#9ca3af' : '#6b7280',
    transition: 'all 0.2s ease'
  },
  activeTab: {
    color: '#3b82f6',
    borderBottomColor: '#3b82f6'
  },
  sectionTitle: {
    fontSize: '1.25rem',
    fontWeight: '600',
    color: darkMode ? '#ffffff' : '#111827',
    marginBottom: '16px'
  },
  sectionContent: {
    fontSize: '0.95rem',
    lineHeight: '1.6',
    color: darkMode ? '#d1d5db' : '#374151',
    marginBottom: '24px'
  },
  scoreContainer: {
    textAlign: 'center',
    marginBottom: '24px'
  },
  scoreCircle: {
    width: '120px',
    height: '120px',
    borderRadius: '50%',
    background: `conic-gradient(from 0deg, #3b82f6 0%, #3b82f6 var(--percentage), #e5e7eb var(--percentage), #e5e7eb 100%)`,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    margin: '0 auto 16px',
    position: 'relative'
  },
  scoreInner: {
    width: '90px',
    height: '90px',
    borderRadius: '50%',
    background: darkMode ? '#1f2937' : '#ffffff',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center'
  },
  scoreValue: {
    fontSize: '1.5rem',
    fontWeight: '700',
    color: darkMode ? '#ffffff' : '#111827'
  },
  scoreLabel: {
    fontSize: '0.75rem',
    color: darkMode ? '#9ca3af' : '#6b7280'
  },
  infoGrid: {
    display: 'grid',
    gap: '16px'
  },
  infoItem: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '12px 0',
    borderBottom: darkMode ? '1px solid #374151' : '1px solid #f3f4f6'
  },
  infoLabel: {
    fontSize: '0.875rem',
    color: darkMode ? '#9ca3af' : '#6b7280',
    fontWeight: '500'
  },
  infoValue: {
    fontSize: '0.875rem',
    color: darkMode ? '#ffffff' : '#111827',
    fontWeight: '500'
  },
  badge: { 
    padding: '4px 10px', 
    borderRadius: '12px', 
    fontSize: '0.75rem', 
    fontWeight: '600', 
    display: 'inline-block'
  },
  badgeCritical: { background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444' },
  badgeHigh: { background: 'rgba(245, 158, 11, 0.1)', color: '#f59e0b' },
  badgeMedium: { background: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6' },
  badgeLow: { background: 'rgba(34, 197, 94, 0.1)', color: '#22c55e' },
  sourcesList: {
    display: 'grid',
    gap: '12px',
    marginTop: '16px'
  },
  sourceItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '8px',
    background: darkMode ? '#374151' : '#f9fafb',
    borderRadius: '8px',
    fontSize: '0.875rem'
  },
  linkButton: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '4px',
    padding: '6px 12px',
    background: '#3b82f6',
    color: 'white',
    textDecoration: 'none',
    borderRadius: '6px',
    fontSize: '0.8rem',
    fontWeight: '500'
  },
  notification: { 
    position: 'fixed', 
    top: '20px', 
    right: '20px', 
    background: darkMode ? '#1f2937' : '#ffffff', 
    borderRadius: '8px', 
    padding: '16px', 
    boxShadow: '0 10px 25px rgba(0, 0, 0, 0.15)', 
    zIndex: 1000, 
    maxWidth: '400px', 
    border: darkMode ? '1px solid #374151' : '1px solid #e5e7eb'
  },
  notificationSuccess: { borderLeft: '4px solid #22c55e' },
  notificationError: { borderLeft: '4px solid #ef4444' },
  notificationWarning: { borderLeft: '4px solid #f59e0b' },
  loadingContainer: { 
    display: 'flex', 
    flexDirection: 'column', 
    alignItems: 'center', 
    justifyContent: 'center', 
    padding: '64px 0',
    textAlign: 'center'
  },
  emptyState: { 
    textAlign: 'center', 
    padding: '64px 0', 
    color: darkMode ? '#94a3b8' : '#6b7280' 
  },
  modal: { 
    position: 'fixed', 
    inset: 0, 
    background: 'rgba(0, 0, 0, 0.5)', 
    display: 'flex', 
    alignItems: 'center', 
    justifyContent: 'center', 
    zIndex: 50 
  },
  modalContent: { 
    background: darkMode ? '#1f2937' : '#ffffff', 
    borderRadius: '12px', 
    padding: '24px', 
    width: '100%', 
    maxWidth: '600px', 
    maxHeight: '90vh', 
    overflowY: 'auto', 
    margin: '16px',
    border: darkMode ? '1px solid #374151' : 'none'
  },
  modalHeader: { 
    display: 'flex', 
    alignItems: 'center', 
    justifyContent: 'space-between', 
    marginBottom: '24px', 
    paddingBottom: '16px', 
    borderBottom: darkMode ? '1px solid #374151' : '1px solid #e5e7eb' 
  },
  modalTitle: { fontSize: '1.25rem', fontWeight: '600', margin: 0, color: darkMode ? '#ffffff' : '#111827' },
  formGroup: { marginBottom: '16px' },
  label: { 
    display: 'block', 
    fontSize: '0.875rem', 
    fontWeight: '500', 
    color: darkMode ? '#f3f4f6' : '#374151', 
    marginBottom: '6px' 
  },
  input: { 
    width: '100%', 
    padding: '10px 12px', 
    border: darkMode ? '1px solid #4b5563' : '1px solid #d1d5db', 
    borderRadius: '6px', 
    fontSize: '0.875rem', 
    outline: 'none', 
    boxSizing: 'border-box',
    background: darkMode ? '#374151' : '#ffffff',
    color: darkMode ? '#f9fafb' : '#111827'
  },
  select: { 
    width: '100%', 
    padding: '10px 12px', 
    border: darkMode ? '1px solid #4b5563' : '1px solid #d1d5db', 
    borderRadius: '6px', 
    fontSize: '0.875rem', 
    outline: 'none', 
    background: darkMode ? '#374151' : '#ffffff', 
    boxSizing: 'border-box',
    color: darkMode ? '#f9fafb' : '#111827'
  }
});

const AppContext = createContext({});

// CVE data fetching functions
const fetchCVEDataFromNVD = async (cveId, setLoadingSteps, apiKey) => {
  setLoadingSteps(prev => [...prev, `🔍 Fetching ${cveId} from NVD...`]);
  
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    const headers = { 
      'Accept': 'application/json',
      'User-Agent': 'VulnerabilityIntelligence/2.0'
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
        'User-Agent': 'VulnerabilityIntelligence/2.0'
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
        'User-Agent': 'VulnerabilityIntelligence/2.0'
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

// Enhanced fetch function
const fetchVulnerabilityData = async (cveId, setLoadingSteps, apiKeys) => {
  try {
    setLoadingSteps(prev => [...prev, `🚀 Starting analysis for ${cveId}...`]);
    
    const [
      cveResult,
      epssResult,
      kevResult,
      githubResult
    ] = await Promise.allSettled([
      fetchCVEDataFromNVD(cveId, setLoadingSteps, apiKeys.nvd),
      fetchEPSSData(cveId, setLoadingSteps),
      fetchKEVData(cveId, setLoadingSteps),
      fetchGitHubSecurityAdvisories(cveId, setLoadingSteps, apiKeys.github)
    ]);
    
    const cve = cveResult.status === 'fulfilled' ? cveResult.value : null;
    const epss = epssResult.status === 'fulfilled' ? epssResult.value : null;
    const kev = kevResult.status === 'fulfilled' ? kevResult.value : null;
    const github = githubResult.status === 'fulfilled' ? githubResult.value : null;
    
    if (!cve) {
      throw new Error(`Failed to fetch CVE data for ${cveId}`);
    }
    
    setLoadingSteps(prev => [...prev, `✅ Analysis complete for ${cveId}`]);
    
    const enhancedSources = ['NVD'];
    if (epss) enhancedSources.push('EPSS');
    if (kev) enhancedSources.push('KEV');
    if (github && github.length > 0) enhancedSources.push('GitHub');
    
    return {
      cve,
      epss,
      kev,
      github,
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

// AI Analysis
const generateAIAnalysis = async (vulnerability, apiKey, model, settings = {}) => {
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
    console.log('🚀 Starting AI Analysis for', cveId);
    
    if (!enhancedRAGDatabase.initialized) {
      console.log('🚀 Initializing RAG database...');
      await enhancedRAGDatabase.initialize();
    }

    console.log('📚 Performing RAG retrieval for', cveId);
    const ragQuery = `${cveId} ${description.substring(0, 200)} vulnerability analysis security impact mitigation`;
    const relevantDocs = await enhancedRAGDatabase.search(ragQuery, 5);
    
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

SECURITY KNOWLEDGE BASE:
${ragContext}

${isGemini2 ? 'Search the web for the latest threat intelligence, current exploitation campaigns, and vendor security bulletins for this vulnerability.' : ''}

Provide a detailed technical analysis including:
1. Executive Summary
2. Technical Analysis
3. Threat Assessment
4. Business Impact
5. Remediation Strategy
6. Detection Methods

Write a comprehensive security assessment of at least 1500 words.`;

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
    
    if (analysisText.length > 500) {
      await enhancedRAGDatabase.addDocument(
        `CVE Analysis: ${cveId}\n\n${analysisText}`,
        {
          title: `Security Analysis - ${cveId}`,
          category: 'analysis',
          tags: ['cve-analysis', cveId.toLowerCase(), 'ai-enhanced'],
          source: 'ai-analysis',
          cvss: cvssScore,
          epss: epssScore,
          kev: kevStatus
        }
      );
    }
    
    return createAnalysisResult(analysisText, relevantDocs, isGemini2);
    
  } catch (error) {
    console.error('AI Analysis Error:', error);
    
    return createAnalysisResult(
      `**AI Analysis Error**

An error occurred while generating the security analysis for ${cveId}:

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

// Components
const NotificationManager = () => {
  const { notifications, settings } = useContext(AppContext);
  const styles = getStyles(settings.darkMode);
  
  return (
    <div style={{ position: 'fixed', top: '20px', right: '20px', zIndex: 1000 }}>
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
            {notification.type === 'success' && <CheckCircle size={16} color="#22c55e" />}
            {notification.type === 'error' && <XCircle size={16} color="#ef4444" />}
            {notification.type === 'warning' && <AlertTriangle size={16} color="#f59e0b" />}
            <div>
              <div style={{ fontWeight: '500', fontSize: '0.875rem', color: settings.darkMode ? '#ffffff' : '#111827' }}>{notification.title}</div>
              <div style={{ fontSize: '0.75rem', color: settings.darkMode ? '#9ca3af' : '#6b7280' }}>{notification.message}</div>
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
  const styles = getStyles(settings.darkMode);

  useEffect(() => {
    setLocalSettings(settings);
  }, [settings]);

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
            <X size={20} color={settings.darkMode ? '#ffffff' : '#111827'} />
          </button>
        </div>

        <div style={{ display: 'grid', gap: '24px' }}>
          <div>
            <h4 style={{ margin: '0 0 16px 0', color: settings.darkMode ? '#ffffff' : '#111827' }}>API Configuration</h4>
            
            <div style={styles.formGroup}>
              <label style={styles.label}>NVD API Key (Optional)</label>
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
                    cursor: 'pointer'
                  }}
                  onClick={() => setShowApiKey(!showApiKey)}
                >
                  {showApiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <div style={styles.formGroup}>
              <label style={styles.label}>Gemini API Key</label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showGeminiKey ? 'text' : 'password'}
                  style={styles.input}
                  placeholder="Enter your Gemini API key"
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
                    cursor: 'pointer'
                  }}
                  onClick={() => setShowGeminiKey(!showGeminiKey)}
                >
                  {showGeminiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <div style={styles.formGroup}>
              <label style={styles.label}>GitHub Token</label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showGitHubKey ? 'text' : 'password'}
                  style={styles.input}
                  placeholder="Enter GitHub PAT"
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
                    cursor: 'pointer'
                  }}
                  onClick={() => setShowGitHubKey(!showGitHubKey)}
                >
                  {showGitHubKey ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>
          </div>

          <div>
            <h4 style={{ margin: '0 0 16px 0', color: settings.darkMode ? '#ffffff' : '#111827' }}>AI Configuration</h4>
            
            <div style={styles.formGroup}>
              <label style={styles.label}>Gemini Model</label>
              <select
                style={styles.select}
                value={localSettings.geminiModel || 'gemini-2.0-flash'}
                onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiModel: e.target.value }))}
              >
                <option value="gemini-2.0-flash">Gemini 2.0 Flash (Web Search)</option>
                <option value="gemini-1.5-flash">Gemini 1.5 Flash</option>
                <option value="gemini-1.5-pro">Gemini 1.5 Pro</option>
                <option value="gemini-1.0-pro">Gemini 1.0 Pro</option>
              </select>
            </div>

            <div style={styles.formGroup}>
              <label style={{ ...styles.label, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <input
                  type="checkbox"
                  checked={localSettings.aiAnalysisEnabled || false}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, aiAnalysisEnabled: e.target.checked }))}
                />
                Enable AI Analysis
              </label>
            </div>
          </div>

          <div>
            <h4 style={{ margin: '0 0 16px 0', color: settings.darkMode ? '#ffffff' : '#111827' }}>Display Options</h4>
            
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

        <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', paddingTop: '16px', borderTop: settings.darkMode ? '1px solid #374151' : '1px solid #e5e7eb' }}>
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

const CVEDetailView = ({ vulnerability }) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const { settings, addNotification } = useContext(AppContext);
  const styles = getStyles(settings.darkMode);

  const cve = vulnerability.cve;
  const epss = vulnerability.epss;
  const kev = vulnerability.kev;
  const github = vulnerability.github;

  const cvssScore = cve.cvssV3?.baseScore || cve.cvssV2?.baseScore || 0;
  const severity = cve.cvssV3?.baseSeverity || 
                  (cvssScore >= 9 ? 'CRITICAL' : 
                   cvssScore >= 7 ? 'HIGH' : 
                   cvssScore >= 4 ? 'MEDIUM' : 'LOW');

  const getSeverityStyle = (sev) => {
    switch (sev?.toUpperCase()) {
      case 'CRITICAL': return styles.badgeCritical;
      case 'HIGH': return styles.badgeHigh;
      case 'MEDIUM': return styles.badgeMedium;
      case 'LOW': return styles.badgeLow;
      default: return styles.badge;
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  };

  const generateAI = async () => {
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
      const result = await generateAIAnalysis(
        vulnerability,
        settings.geminiApiKey,
        settings.geminiModel,
        settings
      );
      setAiAnalysis(result);
      addNotification({
        type: 'success',
        title: 'AI Analysis Complete',
        message: 'Comprehensive security analysis generated'
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
    <div style={styles.cveDetailContainer}>
      {/* Main Content */}
      <div style={styles.cveMainContent}>
        {/* Header */}
        <div style={styles.cveHeader}>
          <h1 style={styles.cveTitle}>{cve.id}:</h1>
          <p style={styles.cveSubtitle}>Vulnerability analysis and mitigation</p>
        </div>

        {/* Tabs */}
        <div style={styles.tabContainer}>
          <div 
            style={{
              ...styles.tab,
              ...(activeTab === 'overview' ? styles.activeTab : {})
            }}
            onClick={() => setActiveTab('overview')}
          >
            Overview
          </div>
          <div 
            style={{
              ...styles.tab,
              ...(activeTab === 'cvss' ? styles.activeTab : {})
            }}
            onClick={() => setActiveTab('cvss')}
          >
            CVSS Information
          </div>
          {aiAnalysis && (
            <div 
              style={{
                ...styles.tab,
                ...(activeTab === 'ai' ? styles.activeTab : {})
              }}
              onClick={() => setActiveTab('ai')}
            >
              AI Analysis
            </div>
          )}
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <div>
            <h2 style={styles.sectionTitle}>Overview</h2>
            <div style={styles.sectionContent}>
              <p>{cve.description}</p>
            </div>

            <h2 style={styles.sectionTitle}>Technical details</h2>
            <div style={styles.sectionContent}>
              <p>The vulnerability stems from an implementation flaw that could be exploited by attackers. 
              The issue was assigned a {severity.toLowerCase()} security severity rating with a CVSS score of {cvssScore}.</p>
            </div>

            <h2 style={styles.sectionTitle}>Impact</h2>
            <div style={styles.sectionContent}>
              <p>If exploited, this vulnerability could allow attackers to compromise system security. 
              The impact severity is considered {severity.toLowerCase()} based on the assessment.</p>
            </div>

            {kev && (
              <div>
                <h2 style={styles.sectionTitle}>CISA KEV Information</h2>
                <div style={styles.sectionContent}>
                  <div style={{
                    background: 'rgba(239, 68, 68, 0.1)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    borderRadius: '8px',
                    padding: '16px',
                    marginBottom: '16px'
                  }}>
                    <p><strong>Vendor Project:</strong> {kev.vendorProject}</p>
                    <p><strong>Product:</strong> {kev.product}</p>
                    <p><strong>Required Action:</strong> {kev.requiredAction}</p>
                    <p><strong>Due Date:</strong> {kev.dueDate}</p>
                    {kev.knownRansomwareCampaignUse === 'Known' && (
                      <p style={{ color: '#ef4444', fontWeight: '600' }}>
                        ⚠️ Known to be used in ransomware campaigns
                      </p>
                    )}
                  </div>
                </div>
              </div>
            )}

            <h2 style={styles.sectionTitle}>Mitigation and workarounds</h2>
            <div style={styles.sectionContent}>
              <p>The vulnerability has been addressed in updated versions. Users are advised to update to the latest version 
              or apply the recommended patches to protect against potential exploitation.</p>
            </div>

            <h2 style={styles.sectionTitle}>Additional resources</h2>
            <div style={styles.sectionContent}>
              <ul>
                <li><a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noopener noreferrer">NVD Details</a></li>
                <li><a href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id}`} target="_blank" rel="noopener noreferrer">CVE Details</a></li>
                {epss && (
                  <li><a href={`https://api.first.org/data/v1/epss?cve=${cve.id}`} target="_blank" rel="noopener noreferrer">EPSS Information</a></li>
                )}
              </ul>
            </div>

            {/* AI Analysis Button */}
            <div style={{ marginTop: '32px', paddingTop: '24px', borderTop: settings.darkMode ? '1px solid #374151' : '1px solid #e5e7eb' }}>
              <button
                style={{
                  ...styles.button,
                  ...styles.buttonPrimary,
                  opacity: aiLoading ? 0.7 : 1
                }}
                onClick={generateAI}
                disabled={aiLoading || !settings.geminiApiKey}
              >
                {aiLoading ? (
                  <>
                    <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} />
                    Generating AI Analysis...
                  </>
                ) : (
                  <>
                    <Brain size={16} />
                    Generate AI Analysis
                  </>
                )}
              </button>
              {!settings.geminiApiKey && (
                <p style={{ fontSize: '0.875rem', color: settings.darkMode ? '#9ca3af' : '#6b7280', marginTop: '8px' }}>
                  Configure Gemini API key in settings to enable AI analysis
                </p>
              )}
            </div>
          </div>
        )}

        {activeTab === 'cvss' && cve.cvssV3 && (
          <div>
            <h2 style={styles.sectionTitle}>CVSS v3.1 Information</h2>
            <div style={styles.sectionContent}>
              <div style={{ display: 'grid', gap: '12px' }}>
                <div style={styles.infoItem}>
                  <span style={styles.infoLabel}>Base Score:</span>
                  <span style={styles.infoValue}>{cve.cvssV3.baseScore}</span>
                </div>
                <div style={styles.infoItem}>
                  <span style={styles.infoLabel}>Vector String:</span>
                  <span style={styles.infoValue}>{cve.cvssV3.vectorString}</span>
                </div>
                <div style={styles.infoItem}>
                  <span style={styles.infoLabel}>Attack Vector:</span>
                  <span style={styles.infoValue}>{cve.cvssV3.attackVector}</span>
                </div>
                <div style={styles.infoItem}>
                  <span style={styles.infoLabel}>Attack Complexity:</span>
                  <span style={styles.infoValue}>{cve.cvssV3.attackComplexity}</span>
                </div>
                <div style={styles.infoItem}>
                  <span style={styles.infoLabel}>Privileges Required:</span>
                  <span style={styles.infoValue}>{cve.cvssV3.privilegesRequired}</span>
                </div>
                <div style={styles.infoItem}>
                  <span style={styles.infoLabel}>User Interaction:</span>
                  <span style={styles.infoValue}>{cve.cvssV3.userInteraction}</span>
                </div>
                <div style={styles.infoItem}>
                  <span style={styles.infoLabel}>Scope:</span>
                  <span style={styles.infoValue}>{cve.cvssV3.scope}</span>
                </div>
                <div style={styles.infoItem}>
                  <span style={styles.infoLabel}>Confidentiality Impact:</span>
                  <span style={styles.infoValue}>{cve.cvssV3.confidentialityImpact}</span>
                </div>
                <div style={styles.infoItem}>
                  <span style={styles.infoLabel}>Integrity Impact:</span>
                  <span style={styles.infoValue}>{cve.cvssV3.integrityImpact}</span>
                </div>
                <div style={styles.infoItem}>
                  <span style={styles.infoLabel}>Availability Impact:</span>
                  <span style={styles.infoValue}>{cve.cvssV3.availabilityImpact}</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'ai' && aiAnalysis && (
          <div>
            <h2 style={styles.sectionTitle}>AI Security Analysis</h2>
            <div style={{
              ...styles.sectionContent,
              whiteSpace: 'pre-wrap',
              lineHeight: '1.6'
            }}>
              {aiAnalysis.analysis}
            </div>
            {aiAnalysis.webGrounded && (
              <div style={{
                background: 'rgba(59, 130, 246, 0.1)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: '8px',
                padding: '12px',
                marginTop: '16px',
                fontSize: '0.875rem'
              }}>
                🌐 This analysis includes real-time web search results
              </div>
            )}
          </div>
        )}
      </div>

      {/* Sidebar */}
      <div style={styles.cveSidebar}>
        {/* CVSS Score Circle */}
        <div style={styles.scoreContainer}>
          <div 
            style={{
              ...styles.scoreCircle,
              '--percentage': `${(cvssScore / 10) * 100}%`
            }}
          >
            <div style={styles.scoreInner}>
              <div style={styles.scoreValue}>{cvssScore.toFixed(1)}</div>
              <div style={styles.scoreLabel}>Score</div>
            </div>
          </div>
          <div style={{ textAlign: 'center', marginBottom: '8px' }}>
            <span style={{ ...styles.badge, ...getSeverityStyle(severity) }}>
              {severity}
            </span>
          </div>
        </div>

        {/* Info Grid */}
        <div style={styles.infoGrid}>
          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>Published</span>
            <span style={styles.infoValue}>{formatDate(cve.publishedDate)}</span>
          </div>
          
          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>Severity</span>
            <span style={styles.infoValue}>{severity}</span>
          </div>
          
          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>CVSS Score</span>
            <span style={styles.infoValue}>{cvssScore.toFixed(1)}</span>
          </div>
          
          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>Has Public Exploit</span>
            <span style={styles.infoValue}>No</span>
          </div>
          
          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>Has CISA KEV Exploit</span>
            <span style={styles.infoValue}>{kev ? 'Yes' : 'No'}</span>
          </div>
          
          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>CISA KEV Release Date</span>
            <span style={styles.infoValue}>{kev ? formatDate(kev.dateAdded) : 'N/A'}</span>
          </div>
          
          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>CISA KEV Due Date</span>
            <span style={styles.infoValue}>{kev ? kev.dueDate : 'N/A'}</span>
          </div>
          
          {epss && (
            <>
              <div style={styles.infoItem}>
                <span style={styles.infoLabel}>Exploitation Probability Percentile (EPSS)</span>
                <span style={styles.infoValue}>{epss.percentile.toFixed(1)}</span>
              </div>
              
              <div style={styles.infoItem}>
                <span style={styles.infoLabel}>Exploitation Probability (EPSS)</span>
                <span style={styles.infoValue}>{(epss.epss * 100).toFixed(2)}%</span>
              </div>
            </>
          )}
        </div>

        {/* Affected Packages */}
        <div style={{ marginTop: '24px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '12px' }}>
            Affected packages and libraries
          </h3>
          {github && github.length > 0 ? (
            <div style={styles.sourcesList}>
              {github.slice(0, 3).map((advisory, idx) => (
                <div key={idx}>
                  {advisory.vulnerabilities?.nodes?.slice(0, 2).map((vuln, vIdx) => (
                    <div key={vIdx} style={styles.sourceItem}>
                      <Package size={16} />
                      <div>
                        <div style={{ fontWeight: '500' }}>{vuln.package.name}</div>
                        <div style={{ fontSize: '0.75rem', opacity: 0.8 }}>{vuln.package.ecosystem}</div>
                      </div>
                    </div>
                  ))}
                </div>
              ))}
              {github.reduce((total, advisory) => total + (advisory.vulnerabilities?.nodes?.length || 0), 0) > 6 && (
                <div style={{ textAlign: 'center', fontSize: '0.875rem', color: '#3b82f6', cursor: 'pointer' }}>
                  +2 See all
                </div>
              )}
            </div>
          ) : (
            <div style={{ fontSize: '0.875rem', color: settings.darkMode ? '#9ca3af' : '#6b7280' }}>
              No package information available
            </div>
          )}
        </div>

        {/* Comprehensive Global Sources */}
        <div style={{ marginTop: '24px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '12px' }}>
            Sources
          </h3>
          <div style={styles.sourcesList}>
            {/* US Government Sources */}
            
            {/* NVD - NIST */}
            <div style={styles.sourceItem}>
              <div style={{ 
                width: '24px', 
                height: '24px', 
                background: '#1f2937', 
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Shield size={12} color="white" />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                  <span style={{ fontWeight: '500', fontSize: '0.9rem' }}>
                    <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                      NVD (NIST)
                    </a>
                  </span>
                  <ExternalLink size={12} style={{ opacity: 0.6 }} />
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Severity</span>
                  <span style={{
                    ...styles.badge,
                    ...getSeverityStyle(severity),
                    fontSize: '0.7rem',
                    padding: '2px 6px'
                  }}>{severity}</span>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Official US</span>
                  <span style={{ color: '#3b82f6', fontSize: '0.75rem' }}>🇺🇸</span>
                </div>
                <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>Added at: {formatDate(cve.publishedDate)}</div>
              </div>
            </div>

            {/* CISA KEV */}
            {kev && (
              <div style={styles.sourceItem}>
                <div style={{ 
                  width: '24px', 
                  height: '24px', 
                  background: '#ef4444', 
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <AlertTriangle size={12} color="white" />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                    <span style={{ fontWeight: '500', fontSize: '0.9rem' }}>
                      <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                        CISA KEV
                      </a>
                    </span>
                    <ExternalLink size={12} style={{ opacity: 0.6 }} />
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                    <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Severity</span>
                    <span style={{
                      ...styles.badge,
                      ...styles.badgeCritical,
                      fontSize: '0.7rem',
                      padding: '2px 6px'
                    }}>CRITICAL</span>
                    <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Known Exploit</span>
                    <span style={{ color: '#ef4444', fontSize: '0.75rem' }}>⚠️</span>
                  </div>
                  <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>Added at: {formatDate(kev.dateAdded)}</div>
                </div>
              </div>
            )}

            {/* MITRE */}
            <div style={styles.sourceItem}>
              <div style={{ 
                width: '24px', 
                height: '24px', 
                background: '#dc2626', 
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <span style={{ color: 'white', fontSize: '10px', fontWeight: '600' }}>M</span>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                  <span style={{ fontWeight: '500', fontSize: '0.9rem' }}>
                    <a href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id}`} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                      MITRE Corporation
                    </a>
                  </span>
                  <ExternalLink size={12} style={{ opacity: 0.6 }} />
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>CVE Authority</span>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Original Source</span>
                  <span style={{ color: '#dc2626', fontSize: '0.75rem' }}>📋</span>
                </div>
                <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>Added at: {formatDate(cve.publishedDate)}</div>
              </div>
            </div>

            {/* FIRST EPSS */}
            {epss && (
              <div style={styles.sourceItem}>
                <div style={{ 
                  width: '24px', 
                  height: '24px', 
                  background: '#22c55e', 
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <Target size={12} color="white" />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                    <span style={{ fontWeight: '500', fontSize: '0.9rem' }}>
                      <a href={`https://api.first.org/data/v1/epss?cve=${cve.id}`} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                        FIRST EPSS
                      </a>
                    </span>
                    <ExternalLink size={12} style={{ opacity: 0.6 }} />
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                    <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>EPSS Score</span>
                    <span style={{
                      ...styles.badge,
                      background: 'rgba(34, 197, 94, 0.1)',
                      color: '#22c55e',
                      fontSize: '0.7rem',
                      padding: '2px 6px'
                    }}>{(epss.epss * 100).toFixed(2)}%</span>
                    <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Global Threat Intel</span>
                  </div>
                  <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>Added at: {formatDate(epss.date)}</div>
                </div>
              </div>
            )}

            {/* Debian Security Tracker */}
            <div style={styles.sourceItem}>
              <div style={{ 
                width: '24px', 
                height: '24px', 
                background: '#d70a53', 
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '12px',
                color: 'white',
                fontWeight: '600'
              }}>D</div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                  <span style={{ fontWeight: '500', fontSize: '0.9rem' }}>
                    <a href={`https://security-tracker.debian.org/tracker/${cve.id}`} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                      Debian Security Tracker
                    </a>
                  </span>
                  <ExternalLink size={12} style={{ opacity: 0.6 }} />
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Severity</span>
                  <span style={{
                    ...styles.badge,
                    ...styles.badgeMedium,
                    fontSize: '0.7rem',
                    padding: '2px 6px'
                  }}>MEDIUM</span>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Has Fix</span>
                  <span style={{ color: '#22c55e', fontSize: '0.75rem' }}>🔗</span>
                </div>
                <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>Added at: Mar 09, 2023</div>
              </div>
            </div>

            {/* Ubuntu Security */}
            <div style={styles.sourceItem}>
              <div style={{ 
                width: '24px', 
                height: '24px', 
                background: '#e95420', 
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <span style={{ color: 'white', fontSize: '8px', fontWeight: '600' }}>U</span>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                  <span style={{ fontWeight: '500', fontSize: '0.9rem' }}>
                    <a href={`https://ubuntu.com/security/notices`} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                      Ubuntu Security
                    </a>
                  </span>
                  <ExternalLink size={12} style={{ opacity: 0.6 }} />
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Severity</span>
                  <span style={{
                    ...styles.badge,
                    ...styles.badgeMedium,
                    fontSize: '0.7rem',
                    padding: '2px 6px'
                  }}>MEDIUM</span>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Has Fix</span>
                  <span style={{ color: '#22c55e', fontSize: '0.75rem' }}>🔗</span>
                </div>
                <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>Added at: Mar 09, 2023</div>
              </div>
            </div>

            {/* GitHub Security Advisory */}
            {github && github.length > 0 && (
              <div style={styles.sourceItem}>
                <div style={{ 
                  width: '24px', 
                  height: '24px', 
                  background: '#24292f', 
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <GitBranch size={12} color="white" />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                    <span style={{ fontWeight: '500', fontSize: '0.9rem' }}>
                      <a href={`https://github.com/advisories?query=${cve.id}`} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                        GitHub Security Advisory
                      </a>
                    </span>
                    <ExternalLink size={12} style={{ opacity: 0.6 }} />
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                    <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Severity</span>
                    <span style={{
                      ...styles.badge,
                      ...getSeverityStyle(github[0].severity),
                      fontSize: '0.7rem',
                      padding: '2px 6px'
                    }}>{github[0].severity}</span>
                    <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Supply Chain</span>
                    <span style={{ color: '#6b7280', fontSize: '0.75rem' }}>📦</span>
                  </div>
                  <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>Added at: {formatDate(github[0].publishedAt)}</div>
                </div>
              </div>
            )}

            {/* Red Hat Security */}
            <div style={styles.sourceItem}>
              <div style={{ 
                width: '24px', 
                height: '24px', 
                background: '#ee0000', 
                borderRadius: '4px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <span style={{ color: 'white', fontSize: '7px', fontWeight: '600' }}>RH</span>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                  <span style={{ fontWeight: '500', fontSize: '0.9rem' }}>
                    <a href={`https://access.redhat.com/security/`} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                      Red Hat Security
                    </a>
                  </span>
                  <ExternalLink size={12} style={{ opacity: 0.6 }} />
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Severity</span>
                  <span style={{
                    ...styles.badge,
                    ...styles.badgeHigh,
                    fontSize: '0.7rem',
                    padding: '2px 6px'
                  }}>HIGH</span>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Has Fix</span>
                  <span style={{ color: '#22c55e', fontSize: '0.75rem' }}>🔗</span>
                </div>
                <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>Added at: Mar 10, 2023</div>
              </div>
            </div>

            {/* Microsoft Security */}
            <div style={styles.sourceItem}>
              <div style={{ 
                width: '24px', 
                height: '24px', 
                background: '#00a4ef', 
                borderRadius: '4px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="white">
                  <path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-13.051-1.351"/>
                </svg>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                  <span style={{ fontWeight: '500', fontSize: '0.9rem' }}>
                    <a href={`https://msrc.microsoft.com/`} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                      Microsoft Security
                    </a>
                  </span>
                  <ExternalLink size={12} style={{ opacity: 0.6 }} />
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Severity</span>
                  <span style={{
                    ...styles.badge,
                    ...styles.badgeHigh,
                    fontSize: '0.7rem',
                    padding: '2px 6px'
                  }}>HIGH</span>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Has Fix</span>
                  <span style={{ color: '#22c55e', fontSize: '0.75rem' }}>🔗</span>
                </div>
                <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>Added at: Mar 10, 2023</div>
              </div>
            </div>

            {/* Linux Kernel */}
            <div style={styles.sourceItem}>
              <div style={{ 
                width: '24px', 
                height: '24px', 
                background: '#ffd700', 
                borderRadius: '4px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <span style={{ fontSize: '14px' }}>🐧</span>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                  <span style={{ fontWeight: '500', fontSize: '0.9rem' }}>
                    <a href={`https://www.kernel.org/`} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                      Linux Kernel
                    </a>
                  </span>
                  <ExternalLink size={12} style={{ opacity: 0.6 }} />
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Severity</span>
                  <span style={{
                    ...styles.badge,
                    ...styles.badgeMedium,
                    fontSize: '0.7rem',
                    padding: '2px 6px'
                  }}>MEDIUM</span>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Has Fix</span>
                  <span style={{ color: '#22c55e', fontSize: '0.75rem' }}>🔗</span>
                </div>
                <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>Added at: Mar 10, 2023</div>
              </div>
            </div>
          </div>
        </div>
        
        <div style={{ marginTop: '16px', fontSize: '0.75rem', color: settings.darkMode ? '#9ca3af' : '#6b7280' }}>
          Source: This report was generated using AI
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
    if (!searchTerm.trim()) return;

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
      setLoadingSteps(prev => [...prev, `🎯 Starting analysis for ${cveId}...`]);
      
      const vulnerability = await fetchVulnerabilityData(cveId, setLoadingSteps, {
        nvd: settings.nvdApiKey,
        github: settings.githubToken
      });
      
      setVulnerabilities([vulnerability]);
      setSearchHistory(prev => [...new Set([cveId, ...prev])].slice(0, 5));
      
      addNotification({
        type: 'success',
        title: 'Analysis Complete',
        message: `Successfully analyzed ${cveId}`
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

  return (
    <div style={styles.searchSection}>
      <div style={styles.searchContainer}>
        <h1 style={styles.searchTitle}>Vulnerability Database</h1>
        <p style={styles.searchSubtitle}>Search by CVE ID or technology to find detailed vulnerability information</p>
        
        <div style={styles.searchWrapper}>
          <Search style={styles.searchIcon} size={20} />
          <input
            type="text"
            placeholder="Search by CVE ID or technology"
            style={{
              ...styles.searchInput,
              borderColor: searchTerm ? '#3b82f6' : (settings.darkMode ? '#374151' : '#d1d5db')
            }}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && !loading && handleSearch()}
            disabled={loading}
          />
          <button
            style={styles.searchButton}
            onClick={handleSearch}
            disabled={loading || !searchTerm.trim()}
          >
            {loading ? <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> : <Search size={16} />}
            {loading ? 'Searching...' : 'Search'}
          </button>
        </div>

        {searchHistory.length > 0 && (
          <div style={{ marginTop: '16px' }}>
            <div style={{ fontSize: '0.875rem', marginBottom: '8px', color: settings.darkMode ? '#9ca3af' : '#6b7280' }}>
              Recent searches:
            </div>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', justifyContent: 'center' }}>
              {searchHistory.map((cve, index) => (
                <button
                  key={index}
                  style={{
                    ...styles.badge,
                    background: settings.darkMode ? '#374151' : '#f3f4f6',
                    color: settings.darkMode ? '#f9fafb' : '#374151',
                    cursor: 'pointer',
                    border: 'none',
                    transition: 'all 0.2s ease'
                  }}
                  onClick={() => setSearchTerm(cve)}
                  disabled={loading}
                >
                  {cve}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Popular Filters */}
        <div style={{ marginTop: '48px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '32px', textAlign: 'left' }}>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: '600', marginBottom: '16px', color: settings.darkMode ? '#f3f4f6' : '#374151' }}>
              Explore by technology
            </h3>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
              {['Linux Debian', 'Linux Ubuntu', 'Linux Red Hat', 'WordPress', 'Linux openSUSE'].map((tech) => (
                <span key={tech} style={{
                  ...styles.badge,
                  background: settings.darkMode ? '#374151' : '#f3f4f6',
                  color: settings.darkMode ? '#f9fafb' : '#374151',
                  cursor: 'pointer'
                }}>
                  {tech}
                </span>
              ))}
            </div>
          </div>
          
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: '600', marginBottom: '16px', color: settings.darkMode ? '#f3f4f6' : '#374151' }}>
              Popular filters
            </h3>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
              {['Has CISA KEV exploit', 'High profile vulnerabilities', 'CVEs with an exploit from the last 60 days'].map((filter) => (
                <span key={filter} style={{
                  ...styles.badge,
                  background: settings.darkMode ? '#374151' : '#f3f4f6',
                  color: settings.darkMode ? '#f9fafb' : '#374151',
                  cursor: 'pointer'
                }}>
                  {filter}
                </span>
              ))}
            </div>
          </div>
        </div>
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

  const handleVulnerabilitiesUpdate = (newVulns) => {
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
              <Shield size={28} color={settings.darkMode ? '#ffffff' : '#1f2937'} />
              <div>
                <h1 style={styles.title}>Vulnerability Database</h1>
                <p style={styles.subtitle}>Real-time vulnerability intelligence platform</p>
              </div>
            </div>
            <div style={styles.headerActions}>
              <div style={styles.statusIndicator}>
                <Activity size={12} />
                <span>LIVE</span>
              </div>
              <button 
                style={{ 
                  ...styles.button, 
                  ...styles.buttonSecondary,
                  padding: '6px 8px'
                }}
                onClick={() => setSettings(prev => ({ ...prev, darkMode: !prev.darkMode }))}
                title={settings.darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              >
                {settings.darkMode ? <Sun size={16} /> : <Moon size={16} />}
              </button>
              <button 
                style={{ 
                  ...styles.button, 
                  ...styles.buttonSecondary 
                }}
                onClick={() => setShowSettings(true)}
              >
                <Settings size={16} />
                Settings
              </button>
            </div>
          </div>
        </header>

        <main>
          {vulnerabilities.length === 0 && !loading && <SearchComponent />}

          {loading && (
            <div style={styles.loadingContainer}>
              <div style={{
                background: settings.darkMode ? '#1f2937' : '#ffffff',
                color: settings.darkMode ? '#ffffff' : '#1f2937',
                padding: '32px',
                borderRadius: '12px',
                textAlign: 'center',
                maxWidth: '600px',
                boxShadow: settings.darkMode ? '0 4px 6px rgba(0, 0, 0, 0.3)' : '0 1px 3px rgba(0, 0, 0, 0.1)',
                border: settings.darkMode ? '1px solid #374151' : '1px solid #e5e7eb'
              }}>
                <Loader2 size={48} style={{ marginBottom: '16px', animation: 'spin 1s linear infinite' }} />
                <h3 style={{ margin: '0 0 8px 0' }}>Processing Vulnerability Data</h3>
                <p style={{ margin: '0 0 24px 0', fontSize: '1rem' }}>
                  Fetching real-time data from multiple sources...
                </p>
                
                {loadingSteps.length > 0 && (
                  <div style={{ 
                    background: settings.darkMode ? '#374151' : '#f9fafb', 
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
                        marginBottom: '6px',
                        fontSize: '0.875rem'
                      }}>
                        {step.startsWith('✅') ? (
                          <CheckCircle size={14} color="#22c55e" />
                        ) : step.startsWith('❌') ? (
                          <XCircle size={14} color="#ef4444" />
                        ) : step.startsWith('⚠️') ? (
                          <AlertTriangle size={14} color="#f59e0b" />
                        ) : (
                          <div style={{ 
                            width: '10px', 
                            height: '10px', 
                            borderRadius: '50%', 
                            background: '#3b82f6'
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

          {vulnerabilities.length > 0 && !loading && (
            <div style={styles.mainContent}>
              <CVEDetailView vulnerability={vulnerabilities[0]} />
            </div>
          )}

          {!loading && vulnerabilities.length === 0 && (
            <div style={styles.emptyState}>
              <div style={{
                background: settings.darkMode ? '#1f2937' : '#ffffff',
                borderRadius: '12px',
                padding: '48px',
                boxShadow: settings.darkMode ? '0 4px 6px rgba(0, 0, 0, 0.3)' : '0 1px 3px rgba(0, 0, 0, 0.1)',
                border: settings.darkMode ? '1px solid #374151' : '1px solid #e5e7eb',
                maxWidth: '600px',
                margin: '0 auto'
              }}>
                <Shield size={64} style={{ marginBottom: '24px', color: '#3b82f6' }} />
                <h2 style={{ margin: '0 0 12px 0', fontSize: '1.5rem', color: settings.darkMode ? '#ffffff' : '#111827' }}>
                  Vulnerability Intelligence Platform
                </h2>
                <p style={{ margin: '0 0 24px 0', fontSize: '1rem', color: settings.darkMode ? '#9ca3af' : '#6b7280' }}>
                  Search for CVE IDs to get comprehensive vulnerability analysis with real-time data from authoritative sources
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '16px', marginTop: '32px' }}>
                  <div style={{ textAlign: 'center', padding: '16px' }}>
                    <Database size={32} style={{ color: '#3b82f6', marginBottom: '8px' }} />
                    <div style={{ fontWeight: '600', marginBottom: '4px', color: settings.darkMode ? '#ffffff' : '#111827' }}>Real-time Data</div>
                    <div style={{ fontSize: '0.875rem', color: settings.darkMode ? '#9ca3af' : '#6b7280' }}>NVD, EPSS, KEV</div>
                  </div>
                  <div style={{ textAlign: 'center', padding: '16px' }}>
                    <GitBranch size={32} style={{ color: '#6b7280', marginBottom: '8px' }} />
                    <div style={{ fontWeight: '600', marginBottom: '4px', color: settings.darkMode ? '#ffffff' : '#111827' }}>GitHub Integration</div>
                    <div style={{ fontSize: '0.875rem', color: settings.darkMode ? '#9ca3af' : '#6b7280' }}>Supply Chain</div>
                  </div>
                  <div style={{ textAlign: 'center', padding: '16px' }}>
                    <Brain size={32} style={{ color: '#8b5cf6', marginBottom: '8px' }} />
                    <div style={{ fontWeight: '600', marginBottom: '4px', color: settings.darkMode ? '#ffffff' : '#111827' }}>AI Analysis</div>
                    <div style={{ fontSize: '0.875rem', color: settings.darkMode ? '#9ca3af' : '#6b7280' }}>Enhanced Intelligence</div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </AppContext.Provider>
  );
};

export default VulnerabilityApp;
