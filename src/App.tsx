import React, { useState, createContext, useContext, useEffect } from 'react';
import { Search, Shield, AlertTriangle, Loader2, ExternalLink, Brain, Settings, Target, Clock, Database, Activity, CheckCircle, XCircle, X, Upload, Filter, PieChart, Sun, Moon, Eye, EyeOff, Save, FileText, Wifi, WifiOff, GitBranch, Code, Server, Cloud, Zap, TrendingUp, Users, Globe, Award, Bug, Layers, Info, Calendar, Package, AlertCircle, MapPin, TrendingDown, BarChart3 } from 'lucide-react';
import { PieChart as RechartsPieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend, BarChart, Bar, XAxis, YAxis, CartesianGrid, LineChart, Line, Area, AreaChart } from 'recharts';

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
  cveDetailContainer: {
    display: 'grid',
    gridTemplateColumns: '1fr 400px',
    gap: '40px',
    marginTop: '40px'
  },
  cveMainContent: {
    background: darkMode ? 'linear-gradient(135deg, #1e293b 0%, #334155 100%)' : '#ffffff',
    borderRadius: '20px',
    padding: '40px',
    boxShadow: darkMode ? '0 8px 32px rgba(0, 0, 0, 0.3)' : '0 4px 20px rgba(0, 0, 0, 0.08)',
    border: darkMode ? '1px solid #334155' : '1px solid #e2e8f0'
  },
  cveSidebar: {
    background: darkMode ? 'linear-gradient(135deg, #1e293b 0%, #334155 100%)' : '#ffffff',
    borderRadius: '20px',
    padding: '32px',
    boxShadow: darkMode ? '0 8px 32px rgba(0, 0, 0, 0.3)' : '0 4px 20px rgba(0, 0, 0, 0.08)',
    border: darkMode ? '1px solid #334155' : '1px solid #e2e8f0',
    height: 'fit-content'
  },
  cveHeader: {
    marginBottom: '32px',
    paddingBottom: '20px',
    borderBottom: darkMode ? '2px solid #334155' : '2px solid #e2e8f0'
  },
  cveTitle: {
    fontSize: '2.25rem',
    fontWeight: '800',
    background: 'linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%)',
    WebkitBackgroundClip: 'text',
    WebkitTextFillColor: 'transparent',
    marginBottom: '12px'
  },
  cveSubtitle: {
    fontSize: '1.2rem',
    color: darkMode ? '#94a3b8' : '#64748b',
    marginBottom: '20px',
    fontWeight: '500'
  },
  tabContainer: {
    display: 'flex',
    borderBottom: darkMode ? '2px solid #334155' : '2px solid #e2e8f0',
    marginBottom: '32px',
    gap: '8px'
  },
  tab: {
    padding: '16px 24px',
    cursor: 'pointer',
    borderBottom: '3px solid transparent',
    fontSize: '1rem',
    fontWeight: '600',
    color: darkMode ? '#64748b' : '#94a3b8',
    transition: 'all 0.3s ease',
    borderRadius: '12px 12px 0 0'
  },
  activeTab: {
    color: '#3b82f6',
    borderBottomColor: '#3b82f6',
    background: darkMode ? 'rgba(59, 130, 246, 0.1)' : 'rgba(59, 130, 246, 0.05)'
  },
  sectionTitle: {
    fontSize: '1.5rem',
    fontWeight: '700',
    color: darkMode ? '#f1f5f9' : '#0f172a',
    marginBottom: '20px'
  },
  sectionContent: {
    fontSize: '1rem',
    lineHeight: '1.7',
    color: darkMode ? '#cbd5e1' : '#475569',
    marginBottom: '32px'
  },
  scoreContainer: {
    textAlign: 'center',
    marginBottom: '32px'
  },
  scoreCircle: {
    width: '140px',
    height: '140px',
    borderRadius: '50%',
    background: `conic-gradient(from 0deg, #3b82f6 0%, #3b82f6 var(--percentage), ${darkMode ? '#334155' : '#e2e8f0'} var(--percentage), ${darkMode ? '#334155' : '#e2e8f0'} 100%)`,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    margin: '0 auto 20px',
    position: 'relative'
  },
  scoreInner: {
    width: '110px',
    height: '110px',
    borderRadius: '50%',
    background: darkMode ? '#1e293b' : '#ffffff',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center'
  },
  scoreValue: {
    fontSize: '1.75rem',
    fontWeight: '800',
    color: darkMode ? '#f1f5f9' : '#0f172a'
  },
  scoreLabel: {
    fontSize: '0.8rem',
    color: darkMode ? '#64748b' : '#94a3b8',
    fontWeight: '600'
  },
  infoGrid: {
    display: 'grid',
    gap: '20px'
  },
  infoItem: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '16px 0',
    borderBottom: darkMode ? '1px solid #334155' : '1px solid #f1f5f9'
  },
  infoLabel: {
    fontSize: '0.9rem',
    color: darkMode ? '#64748b' : '#94a3b8',
    fontWeight: '600'
  },
  infoValue: {
    fontSize: '0.9rem',
    color: darkMode ? '#f1f5f9' : '#0f172a',
    fontWeight: '600'
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
  sourcesList: {
    display: 'grid',
    gap: '16px',
    marginTop: '20px'
  },
  sourceItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    padding: '12px',
    background: darkMode ? '#334155' : '#f8fafc',
    borderRadius: '12px',
    fontSize: '0.9rem',
    border: darkMode ? '1px solid #475569' : '1px solid #e2e8f0'
  },
  linkButton: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '6px',
    padding: '8px 16px',
    background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
    color: 'white',
    textDecoration: 'none',
    borderRadius: '8px',
    fontSize: '0.85rem',
    fontWeight: '600'
  },
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
  },
  packageCard: {
    background: darkMode ? '#334155' : '#f8fafc',
    border: darkMode ? '1px solid #475569' : '1px solid #e2e8f0',
    borderRadius: '12px',
    padding: '16px',
    marginBottom: '12px'
  },
  affectedVersions: {
    background: darkMode ? 'rgba(239, 68, 68, 0.1)' : 'rgba(239, 68, 68, 0.05)',
    border: '1px solid rgba(239, 68, 68, 0.2)',
    borderRadius: '8px',
    padding: '12px',
    marginTop: '12px'
  },
  patchedVersions: {
    background: darkMode ? 'rgba(34, 197, 94, 0.1)' : 'rgba(34, 197, 94, 0.05)',
    border: '1px solid rgba(34, 197, 94, 0.2)',
    borderRadius: '8px',
    padding: '12px',
    marginTop: '12px'
  }
});

const AppContext = createContext({});

// Enhanced CVE data fetching functions
const fetchCVEDataFromNVD = async (cveId, setLoadingSteps, apiKey) => {
  setLoadingSteps(prev => [...prev, `🔍 Fetching ${cveId} from NVD...`]);
  
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    const headers = { 
      'Accept': 'application/json',
      'User-Agent': 'VulnerabilityIntelligence/3.0'
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
        'User-Agent': 'VulnerabilityIntelligence/3.0'
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
        'User-Agent': 'VulnerabilityIntelligence/3.0'
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

// New function to fetch OSV data for comprehensive package information
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

// New function to fetch VulnDB data for additional intelligence
const fetchVulnDBData = async (cveId, setLoadingSteps) => {
  setLoadingSteps(prev => [...prev, `🔍 Checking VulnDB for ${cveId}...`]);
  
  try {
    // Note: VulnDB API requires authentication, this is a placeholder for real implementation
    const response = await fetch(`https://vulndb.cyberriskanalytics.com/api/v1/vulnerabilities/${cveId}`, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'VulnerabilityIntelligence/3.0'
      }
    });

    if (!response.ok) {
      if (response.status === 404) {
        setLoadingSteps(prev => [...prev, `ℹ️ No VulnDB data found for ${cveId}`]);
        return null;
      }
      throw new Error(`VulnDB API error: ${response.status}`);
    }

    const data = await response.json();
    setLoadingSteps(prev => [...prev, `✅ Retrieved VulnDB data for ${cveId}`]);
    return data;
    
  } catch (error) {
    console.error(`VulnDB API Error for ${cveId}:`, error);
    setLoadingSteps(prev => [...prev, `⚠️ VulnDB data unavailable for ${cveId}: ${error.message}`]);
    return null;
  }
};

// Enhanced fetch function with more data sources
const fetchVulnerabilityData = async (cveId, setLoadingSteps, apiKeys) => {
  try {
    setLoadingSteps(prev => [...prev, `🚀 Starting comprehensive analysis for ${cveId}...`]);
    
    const [
      cveResult,
      epssResult,
      kevResult,
      githubResult,
      osvResult,
      vulndbResult
    ] = await Promise.allSettled([
      fetchCVEDataFromNVD(cveId, setLoadingSteps, apiKeys.nvd),
      fetchEPSSData(cveId, setLoadingSteps),
      fetchKEVData(cveId, setLoadingSteps),
      fetchGitHubSecurityAdvisories(cveId, setLoadingSteps, apiKeys.github),
      fetchOSVData(cveId, setLoadingSteps),
      fetchVulnDBData(cveId, setLoadingSteps)
    ]);
    
    const cve = cveResult.status === 'fulfilled' ? cveResult.value : null;
    const epss = epssResult.status === 'fulfilled' ? epssResult.value : null;
    const kev = kevResult.status === 'fulfilled' ? kevResult.value : null;
    const github = githubResult.status === 'fulfilled' ? githubResult.value : null;
    const osv = osvResult.status === 'fulfilled' ? osvResult.value : null;
    const vulndb = vulndbResult.status === 'fulfilled' ? vulndbResult.value : null;
    
    if (!cve) {
      throw new Error(`Failed to fetch CVE data for ${cveId}`);
    }
    
    setLoadingSteps(prev => [...prev, `✅ Comprehensive analysis complete for ${cveId}`]);
    
    const enhancedSources = ['NVD'];
    if (epss) enhancedSources.push('EPSS');
    if (kev) enhancedSources.push('KEV');
    if (github && github.length > 0) enhancedSources.push('GitHub');
    if (osv && osv.length > 0) enhancedSources.push('OSV');
    if (vulndb) enhancedSources.push('VulnDB');
    
    return {
      cve,
      epss,
      kev,
      github,
      osv,
      vulndb,
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

// Enhanced AI Analysis with better context
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
    const ragQuery = `${cveId} ${description.substring(0, 200)} vulnerability analysis security impact mitigation threat intelligence`;
    const relevantDocs = await enhancedRAGDatabase.search(ragQuery, 8);
    
    const ragContext = relevantDocs.length > 0 ? 
      relevantDocs.map((doc, index) => 
        `[Security Knowledge ${index + 1}] ${doc.metadata.title}:\n${doc.content.substring(0, 500)}...`
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

    const prompt = `You are a senior cybersecurity analyst providing a comprehensive vulnerability assessment for ${cveId}.

VULNERABILITY DETAILS:
- CVE ID: ${cveId}
- CVSS Score: ${cvssScore}
- EPSS Score: ${epssScore}
- KEV Listed: ${kevStatus}
- Description: ${description.substring(0, 800)}${packageContext}

SECURITY KNOWLEDGE BASE:
${ragContext}

${isGemini2 ? 'Search the web for the latest threat intelligence, current exploitation campaigns, vendor security bulletins, and real-world attacks involving this vulnerability.' : ''}

Provide a detailed technical analysis including:
1. **Executive Summary** - Key findings and risk assessment
2. **Technical Analysis** - Root cause, attack vectors, and technical details
3. **Threat Landscape** - Current exploitation status and threat actor activity
4. **Business Impact** - Potential consequences and affected systems
5. **Affected Software & Packages** - Comprehensive list of vulnerable components
6. **Remediation Strategy** - Immediate actions, patches, and mitigations
7. **Detection & Monitoring** - IOCs, signatures, and monitoring recommendations
8. **Risk Prioritization** - Context-based risk scoring and urgency assessment

Write a comprehensive security assessment of at least 2000 words with actionable intelligence.`;

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
          title: `Enhanced Security Analysis - ${cveId}`,
          category: 'analysis',
          tags: ['cve-analysis', cveId.toLowerCase(), 'ai-enhanced', 'threat-intelligence'],
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

An error occurred while generating the enhanced security analysis for ${cveId}:

**Error Details:**
${error.message}

**Manual Analysis Recommendation:**
- Official NVD details: https://nvd.nist.gov/vuln/detail/${cveId}
- MITRE CVE database: https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}
- FIRST EPSS: https://api.first.org/data/v1/epss?cve=${cveId}
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- OSV Database: https://osv.dev/vulnerability/${cveId}

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
          <h3 style={styles.modalTitle}>Platform Settings</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer' }}>
            <X size={24} color={settings.darkMode ? '#f1f5f9' : '#0f172a'} />
          </button>
        </div>

        <div style={{ display: 'grid', gap: '32px' }}>
          <div>
            <h4 style={{ margin: '0 0 20px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a', fontSize: '1.2rem', fontWeight: '700' }}>API Configuration</h4>
            
            <div style={styles.formGroup}>
              <label style={styles.label}>NVD API Key (Optional - Increases Rate Limits)</label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showApiKey ? 'text' : 'password'}
                  style={styles.input}
                  placeholder="Enter your NVD API key for higher rate limits"
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
              <label style={styles.label}>Gemini API Key (Required for AI Analysis)</label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showGeminiKey ? 'text' : 'password'}
                  style={styles.input}
                  placeholder="Enter your Gemini API key for AI-powered analysis"
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
            </div>
          </div>

          <div>
            <h4 style={{ margin: '0 0 20px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a', fontSize: '1.2rem', fontWeight: '700' }}>AI Intelligence Configuration</h4>
            
            <div style={styles.formGroup}>
              <label style={styles.label}>Gemini Model Selection</label>
              <select
                style={styles.select}
                value={localSettings.geminiModel || 'gemini-2.0-flash'}
                onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiModel: e.target.value }))}
              >
                <option value="gemini-2.0-flash">Gemini 2.0 Flash (Real-time Web Search)</option>
                <option value="gemini-1.5-flash">Gemini 1.5 Flash (Fast Analysis)</option>
                <option value="gemini-1.5-pro">Gemini 1.5 Pro (Deep Analysis)</option>
                <option value="gemini-1.0-pro">Gemini 1.0 Pro (Stable)</option>
              </select>
            </div>

            <div style={styles.formGroup}>
              <label style={{ ...styles.label, display: 'flex', alignItems: 'center', gap: '12px' }}>
                <input
                  type="checkbox"
                  checked={localSettings.aiAnalysisEnabled || false}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, aiAnalysisEnabled: e.target.checked }))}
                  style={{ width: 'auto' }}
                />
                Enable Enhanced AI Analysis
              </label>
            </div>
          </div>

          <div>
            <h4 style={{ margin: '0 0 20px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a', fontSize: '1.2rem', fontWeight: '700' }}>Display Preferences</h4>
            
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

const AffectedPackagesView = ({ vulnerability }) => {
  const { settings } = useContext(AppContext);
  const styles = getStyles(settings.darkMode);

  const allPackages = [];

  // GitHub packages
  if (vulnerability.github) {
    vulnerability.github.forEach(advisory => {
      advisory.vulnerabilities?.nodes?.forEach(vuln => {
        allPackages.push({
          source: 'GitHub',
          ecosystem: vuln.package.ecosystem,
          name: vuln.package.name,
          vulnerableVersions: vuln.vulnerableVersionRange,
          patchedVersion: vuln.firstPatchedVersion?.identifier,
          ghsaId: advisory.ghsaId,
          severity: advisory.severity
        });
      });
    });
  }

  // OSV packages
  if (vulnerability.osv) {
    vulnerability.osv.forEach(entry => {
      entry.affected?.forEach(affected => {
        const versions = affected.ranges?.map(range => 
          range.events?.map(event => 
            Object.entries(event).map(([key, value]) => `${key}: ${value}`).join(', ')
          ).join('; ')
        ).join(' | ') || 'Version info unavailable';

        allPackages.push({
          source: 'OSV',
          ecosystem: affected.package?.ecosystem || 'Unknown',
          name: affected.package?.name || 'Unknown',
          vulnerableVersions: versions,
          patchedVersion: affected.ranges?.find(r => r.type === 'SEMVER')?.events?.find(e => e.fixed)?.fixed,
          osvId: entry.id,
          severity: entry.database_specific?.severity
        });
      });
    });
  }

  if (allPackages.length === 0) {
    return (
      <div style={styles.sectionContent}>
        <div style={{
          textAlign: 'center',
          padding: '40px',
          background: settings.darkMode ? '#334155' : '#f8fafc',
          borderRadius: '12px',
          border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0'
        }}>
          <Package size={48} style={{ color: settings.darkMode ? '#64748b' : '#94a3b8', marginBottom: '16px' }} />
          <h3 style={{ margin: '0 0 8px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>No Package Information Available</h3>
          <p style={{ margin: 0, color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
            Package data will be displayed when available from GitHub Security Advisories or OSV database.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div style={{ marginBottom: '24px' }}>
        <div style={{
          background: settings.darkMode ? 'rgba(59, 130, 246, 0.1)' : 'rgba(59, 130, 246, 0.05)',
          border: '1px solid rgba(59, 130, 246, 0.2)',
          borderRadius: '12px',
          padding: '16px',
          marginBottom: '24px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
            <AlertCircle size={20} color="#3b82f6" />
            <span style={{ fontWeight: '600', color: '#3b82f6' }}>Supply Chain Impact</span>
          </div>
          <p style={{ margin: 0, fontSize: '0.9rem', color: settings.darkMode ? '#cbd5e1' : '#475569' }}>
            This vulnerability affects {allPackages.length} package{allPackages.length !== 1 ? 's' : ''} across multiple ecosystems. 
            Review affected versions and apply patches immediately.
          </p>
        </div>
      </div>

      <div style={{ display: 'grid', gap: '20px' }}>
        {allPackages.map((pkg, index) => (
          <div key={index} style={styles.packageCard}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
                  <h4 style={{ 
                    margin: 0, 
                    fontSize: '1.1rem', 
                    fontWeight: '700',
                    color: settings.darkMode ? '#f1f5f9' : '#0f172a'
                  }}>
                    {pkg.name}
                  </h4>
                  <span style={{
                    ...styles.badge,
                    background: settings.darkMode ? '#475569' : '#e2e8f0',
                    color: settings.darkMode ? '#f1f5f9' : '#475569',
                    fontSize: '0.7rem'
                  }}>
                    {pkg.ecosystem}
                  </span>
                </div>
                <div style={{ fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                  Source: {pkg.source} {pkg.ghsaId && `(${pkg.ghsaId})`} {pkg.osvId && `(${pkg.osvId})`}
                </div>
              </div>
              {pkg.severity && (
                <span style={{
                  ...styles.badge,
                  ...(pkg.severity === 'CRITICAL' ? styles.badgeCritical :
                     pkg.severity === 'HIGH' ? styles.badgeHigh :
                     pkg.severity === 'MEDIUM' ? styles.badgeMedium :
                     styles.badgeLow)
                }}>
                  {pkg.severity}
                </span>
              )}
            </div>

            {pkg.vulnerableVersions && (
              <div style={styles.affectedVersions}>
                <div style={{ fontWeight: '600', marginBottom: '6px', color: '#ef4444' }}>
                  Vulnerable Versions:
                </div>
                <code style={{ 
                  fontSize: '0.85rem', 
                  background: 'rgba(0, 0, 0, 0.1)', 
                  padding: '4px 8px', 
                  borderRadius: '4px',
                  color: settings.darkMode ? '#f1f5f9' : '#0f172a'
                }}>
                  {pkg.vulnerableVersions}
                </code>
              </div>
            )}

            {pkg.patchedVersion && (
              <div style={styles.patchedVersions}>
                <div style={{ fontWeight: '600', marginBottom: '6px', color: '#22c55e' }}>
                  Patched Version:
                </div>
                <code style={{ 
                  fontSize: '0.85rem', 
                  background: 'rgba(0, 0, 0, 0.1)', 
                  padding: '4px 8px', 
                  borderRadius: '4px',
                  color: settings.darkMode ? '#f1f5f9' : '#0f172a'
                }}>
                  {pkg.patchedVersion}
                </code>
              </div>
            )}
          </div>
        ))}
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
  const osv = vulnerability.osv;

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
      setActiveTab('ai');
      addNotification({
        type: 'success',
        title: 'AI Analysis Complete',
        message: 'Comprehensive security analysis generated with real-time intelligence'
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
          <h1 style={styles.cveTitle}>{cve.id}</h1>
          <p style={styles.cveSubtitle}>Enhanced vulnerability intelligence and threat analysis</p>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <span style={{
              ...styles.badge,
              ...getSeverityStyle(severity),
              fontSize: '0.9rem',
              padding: '8px 16px'
            }}>
              {severity} - {cvssScore.toFixed(1)}
            </span>
            {kev && (
              <span style={{
                ...styles.badge,
                ...styles.badgeCritical,
                fontSize: '0.8rem',
                padding: '6px 12px'
              }}>
                CISA KEV
              </span>
            )}
            {epss && epss.epss > 0.5 && (
              <span style={{
                ...styles.badge,
                background: 'rgba(245, 158, 11, 0.15)',
                color: '#f59e0b',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                fontSize: '0.8rem',
                padding: '6px 12px'
              }}>
                HIGH EPSS
              </span>
            )}
          </div>
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
            <Info size={16} style={{ marginRight: '6px' }} />
            Overview
          </div>
          <div 
            style={{
              ...styles.tab,
              ...(activeTab === 'packages' ? styles.activeTab : {})
            }}
            onClick={() => setActiveTab('packages')}
          >
            <Package size={16} style={{ marginRight: '6px' }} />
            Affected Packages
          </div>
          <div 
            style={{
              ...styles.tab,
              ...(activeTab === 'sources' ? styles.activeTab : {})
            }}
            onClick={() => setActiveTab('sources')}
          >
            <Globe size={16} style={{ marginRight: '6px' }} />
            Global Sources
          </div>
          <div 
            style={{
              ...styles.tab,
              ...(activeTab === 'cvss' ? styles.activeTab : {})
            }}
            onClick={() => setActiveTab('cvss')}
          >
            <BarChart3 size={16} style={{ marginRight: '6px' }} />
            CVSS Details
          </div>
          {aiAnalysis && (
            <div 
              style={{
                ...styles.tab,
                ...(activeTab === 'ai' ? styles.activeTab : {})
              }}
              onClick={() => setActiveTab('ai')}
            >
              <Brain size={16} style={{ marginRight: '6px' }} />
              AI Analysis
            </div>
          )}
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <div>
            <h2 style={styles.sectionTitle}>Vulnerability Overview</h2>
            <div style={styles.sectionContent}>
              <p style={{ fontSize: '1.05rem', lineHeight: '1.7' }}>{cve.description}</p>
            </div>

            <h2 style={styles.sectionTitle}>Technical Analysis</h2>
            <div style={styles.sectionContent}>
              <p>This vulnerability has been assigned a {severity.toLowerCase()} security severity rating with a CVSS score of {cvssScore}. 
              The issue stems from an implementation flaw that could be exploited by threat actors to compromise system security.</p>
              
              {cve.cvssV3 && (
                <div style={{ marginTop: '20px' }}>
                  <h4 style={{ margin: '0 0 12px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>Attack Vector Analysis:</h4>
                  <ul style={{ marginLeft: '20px', lineHeight: '1.6' }}>
                    <li><strong>Attack Vector:</strong> {cve.cvssV3.attackVector}</li>
                    <li><strong>Attack Complexity:</strong> {cve.cvssV3.attackComplexity}</li>
                    <li><strong>Privileges Required:</strong> {cve.cvssV3.privilegesRequired}</li>
                    <li><strong>User Interaction:</strong> {cve.cvssV3.userInteraction}</li>
                  </ul>
                </div>
              )}
            </div>

            {epss && (
              <div>
                <h2 style={styles.sectionTitle}>Exploitation Probability</h2>
                <div style={styles.sectionContent}>
                  <div style={{
                    background: epss.epss > 0.5 ? 'rgba(245, 158, 11, 0.1)' : 'rgba(34, 197, 94, 0.1)',
                    border: `1px solid ${epss.epss > 0.5 ? 'rgba(245, 158, 11, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`,
                    borderRadius: '12px',
                    padding: '20px',
                    marginBottom: '20px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                      <Target size={24} color={epss.epss > 0.5 ? '#f59e0b' : '#22c55e'} />
                      <div>
                        <div style={{ fontWeight: '700', fontSize: '1.1rem' }}>
                          EPSS Score: {(epss.epss * 100).toFixed(2)}%
                        </div>
                        <div style={{ fontSize: '0.9rem', opacity: 0.8 }}>
                          Percentile: {epss.percentile.toFixed(1)}
                        </div>
                      </div>
                    </div>
                    <p style={{ margin: 0, fontSize: '0.95rem' }}>
                      {epss.epss > 0.5 
                        ? 'This vulnerability has a HIGH probability of exploitation in the wild. Immediate patching recommended.'
                        : epss.epss > 0.1 
                          ? 'This vulnerability has a MODERATE probability of exploitation. Monitor for patches and updates.'
                          : 'This vulnerability has a LOW probability of exploitation, but still requires attention.'}
                    </p>
                  </div>
                </div>
              </div>
            )}

            {kev && (
              <div>
                <h2 style={styles.sectionTitle}>CISA Known Exploited Vulnerability</h2>
                <div style={styles.sectionContent}>
                  <div style={{
                    background: 'rgba(239, 68, 68, 0.1)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    borderRadius: '12px',
                    padding: '20px',
                    marginBottom: '20px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                      <AlertTriangle size={24} color="#ef4444" />
                      <span style={{ fontWeight: '700', fontSize: '1.1rem', color: '#ef4444' }}>
                        ACTIVE EXPLOITATION CONFIRMED
                      </span>
                    </div>
                    <div style={{ display: 'grid', gap: '12px' }}>
                      <div><strong>Vendor/Product:</strong> {kev.vendorProject} / {kev.product}</div>
                      <div><strong>Vulnerability Name:</strong> {kev.vulnerabilityName}</div>
                      <div><strong>Required Action:</strong> {kev.requiredAction}</div>
                      <div><strong>Due Date:</strong> {kev.dueDate}</div>
                      {kev.knownRansomwareCampaignUse === 'Known' && (
                        <div style={{ color: '#ef4444', fontWeight: '700' }}>
                          ⚠️ Known to be used in ransomware campaigns
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}

            <h2 style={styles.sectionTitle}>Business Impact Assessment</h2>
            <div style={styles.sectionContent}>
              <p>The potential business impact of this vulnerability depends on several factors including system exposure, 
              data sensitivity, and the presence of compensating controls. Organizations should prioritize remediation based on:</p>
              <ul style={{ marginLeft: '20px', lineHeight: '1.6' }}>
                <li>Asset criticality and business function importance</li>
                <li>Network exposure and attack surface</li>
                <li>Data classification and regulatory requirements</li>
                <li>Existing security controls and monitoring capabilities</li>
              </ul>
            </div>

            <h2 style={styles.sectionTitle}>Remediation Strategy</h2>
            <div style={styles.sectionContent}>
              <p>Immediate actions recommended for this vulnerability:</p>
              <ol style={{ marginLeft: '20px', lineHeight: '1.6' }}>
                <li>Identify all affected systems and assets in your environment</li>
                <li>Apply vendor patches as soon as they become available</li>
                <li>Implement temporary mitigations if patches are not yet available</li>
                <li>Monitor for indicators of compromise and suspicious activity</li>
                <li>Update security controls and detection rules</li>
              </ol>
            </div>

            {/* AI Analysis Button */}
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
                onClick={generateAI}
                disabled={aiLoading || !settings.geminiApiKey}
              >
                {aiLoading ? (
                  <>
                    <Loader2 size={20} style={{ animation: 'spin 1s linear infinite' }} />
                    Generating Enhanced Analysis...
                  </>
                ) : (
                  <>
                    <Brain size={20} />
                    Generate AI-Powered Analysis
                  </>
                )}
              </button>
              {!settings.geminiApiKey && (
                <p style={{ fontSize: '0.9rem', color: settings.darkMode ? '#64748b' : '#94a3b8', marginTop: '12px' }}>
                  Configure Gemini API key in settings to enable AI-powered threat intelligence
                </p>
              )}
            </div>
          </div>
        )}

        {activeTab === 'packages' && (
          <div>
            <h2 style={styles.sectionTitle}>Affected Packages & Libraries</h2>
            <AffectedPackagesView vulnerability={vulnerability} />
          </div>
        )}

        {activeTab === 'sources' && (
          <div>
            <h2 style={styles.sectionTitle}>Global Vulnerability Sources</h2>
            <div style={styles.sectionContent}>
              <div style={{
                background: settings.darkMode ? 'rgba(59, 130, 246, 0.1)' : 'rgba(59, 130, 246, 0.05)',
                border: '1px solid rgba(59, 130, 246, 0.2)',
                borderRadius: '12px',
                padding: '20px',
                marginBottom: '24px'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                  <Database size={24} color="#3b82f6" />
                  <span style={{ fontWeight: '700', fontSize: '1.1rem', color: '#3b82f6' }}>
                    Data Sources: {vulnerability.enhancedSources?.length || 0}
                  </span>
                </div>
                <p style={{ margin: 0, fontSize: '0.95rem', color: settings.darkMode ? '#cbd5e1' : '#475569' }}>
                  This analysis aggregates data from multiple authoritative sources to provide comprehensive vulnerability intelligence.
                </p>
              </div>

              <div style={{ display: 'grid', gap: '24px' }}>
                {/* US Government Sources */}
                <div>
                  <h3 style={{ fontSize: '1.2rem', fontWeight: '700', marginBottom: '16px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                    🇺🇸 US Government Sources
                  </h3>
                  <div style={{ display: 'grid', gap: '16px' }}>
                    {/* NVD */}
                    <div style={{
                      background: settings.darkMode ? '#334155' : '#f8fafc',
                      border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0',
                      borderRadius: '12px',
                      padding: '20px'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                        <div style={{ 
                          width: '40px', 
                          height: '40px', 
                          background: '#1f2937', 
                          borderRadius: '50%',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center'
                        }}>
                          <Shield size={20} color="white" />
                        </div>
                        <div>
                          <h4 style={{ margin: 0, fontSize: '1.1rem', fontWeight: '700', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                            National Vulnerability Database (NVD)
                          </h4>
                          <p style={{ margin: 0, fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                            NIST - Official US Government Repository
                          </p>
                        </div>
                        <a 
                          href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          style={{ marginLeft: 'auto' }}
                        >
                          <ExternalLink size={20} color={settings.darkMode ? '#94a3b8' : '#64748b'} />
                        </a>
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '12px' }}>
                        <div>
                          <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Severity</span>
                          <div style={{
                            ...styles.badge,
                            ...getSeverityStyle(severity),
                            marginTop: '4px'
                          }}>
                            {severity}
                          </div>
                        </div>
                        <div>
                          <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>CVSS Score</span>
                          <div style={{ fontWeight: '700', fontSize: '1.1rem', marginTop: '4px' }}>{cvssScore.toFixed(1)}</div>
                        </div>
                        <div>
                          <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Published</span>
                          <div style={{ fontWeight: '600', fontSize: '0.9rem', marginTop: '4px' }}>{formatDate(cve.publishedDate)}</div>
                        </div>
                      </div>
                    </div>

                    {/* CISA KEV */}
                    {kev && (
                      <div style={{
                        background: 'rgba(239, 68, 68, 0.05)',
                        border: '1px solid rgba(239, 68, 68, 0.2)',
                        borderRadius: '12px',
                        padding: '20px'
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                          <div style={{ 
                            width: '40px', 
                            height: '40px', 
                            background: '#ef4444', 
                            borderRadius: '50%',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center'
                          }}>
                            <AlertTriangle size={20} color="white" />
                          </div>
                          <div>
                            <h4 style={{ margin: 0, fontSize: '1.1rem', fontWeight: '700', color: '#ef4444' }}>
                              CISA Known Exploited Vulnerabilities
                            </h4>
                            <p style={{ margin: 0, fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                              Active Exploitation Confirmed
                            </p>
                          </div>
                          <a 
                            href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" 
                            target="_blank" 
                            rel="noopener noreferrer"
                            style={{ marginLeft: 'auto' }}
                          >
                            <ExternalLink size={20} color="#ef4444" />
                          </a>
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '12px' }}>
                          <div>
                            <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Vendor/Product</span>
                            <div style={{ fontWeight: '600', fontSize: '0.9rem', marginTop: '4px' }}>{kev.vendorProject}/{kev.product}</div>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Due Date</span>
                            <div style={{ fontWeight: '700', fontSize: '0.9rem', marginTop: '4px', color: '#ef4444' }}>{kev.dueDate}</div>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Ransomware Use</span>
                            <div style={{ fontWeight: '600', fontSize: '0.9rem', marginTop: '4px' }}>
                              {kev.knownRansomwareCampaignUse === 'Known' ? '⚠️ Yes' : 'No'}
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* International Sources */}
                <div>
                  <h3 style={{ fontSize: '1.2rem', fontWeight: '700', marginBottom: '16px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                    🌍 International Sources
                  </h3>
                  <div style={{ display: 'grid', gap: '16px' }}>
                    {/* FIRST EPSS */}
                    {epss && (
                      <div style={{
                        background: settings.darkMode ? '#334155' : '#f8fafc',
                        border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0',
                        borderRadius: '12px',
                        padding: '20px'
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                          <div style={{ 
                            width: '40px', 
                            height: '40px', 
                            background: '#22c55e', 
                            borderRadius: '50%',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center'
                          }}>
                            <Target size={20} color="white" />
                          </div>
                          <div>
                            <h4 style={{ margin: 0, fontSize: '1.1rem', fontWeight: '700', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                              FIRST Exploit Prediction Scoring System
                            </h4>
                            <p style={{ margin: 0, fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                              Global Threat Intelligence Consortium
                            </p>
                          </div>
                          <a 
                            href={`https://api.first.org/data/v1/epss?cve=${cve.id}`} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            style={{ marginLeft: 'auto' }}
                          >
                            <ExternalLink size={20} color={settings.darkMode ? '#94a3b8' : '#64748b'} />
                          </a>
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '12px' }}>
                          <div>
                            <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>EPSS Score</span>
                            <div style={{
                              ...styles.badge,
                              background: epss.epss > 0.5 ? 'rgba(245, 158, 11, 0.15)' : 'rgba(34, 197, 94, 0.15)',
                              color: epss.epss > 0.5 ? '#f59e0b' : '#22c55e',
                              border: `1px solid ${epss.epss > 0.5 ? 'rgba(245, 158, 11, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`,
                              marginTop: '4px'
                            }}>
                              {(epss.epss * 100).toFixed(2)}%
                            </div>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Percentile</span>
                            <div style={{ fontWeight: '700', fontSize: '1.1rem', marginTop: '4px' }}>{epss.percentile.toFixed(1)}</div>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Last Updated</span>
                            <div style={{ fontWeight: '600', fontSize: '0.9rem', marginTop: '4px' }}>{formatDate(epss.date)}</div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* MITRE */}
                    <div style={{
                      background: settings.darkMode ? '#334155' : '#f8fafc',
                      border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0',
                      borderRadius: '12px',
                      padding: '20px'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                        <div style={{ 
                          width: '40px', 
                          height: '40px', 
                          background: '#dc2626', 
                          borderRadius: '50%',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center'
                        }}>
                          <span style={{ color: 'white', fontSize: '14px', fontWeight: '700' }}>M</span>
                        </div>
                        <div>
                          <h4 style={{ margin: 0, fontSize: '1.1rem', fontWeight: '700', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                            MITRE Corporation
                          </h4>
                          <p style={{ margin: 0, fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                            CVE Numbering Authority
                          </p>
                        </div>
                        <a 
                          href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id}`} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          style={{ marginLeft: 'auto' }}
                        >
                          <ExternalLink size={20} color={settings.darkMode ? '#94a3b8' : '#64748b'} />
                        </a>
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '12px' }}>
                        <div>
                          <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>CVE ID</span>
                          <div style={{ fontWeight: '700', fontSize: '1rem', marginTop: '4px', color: '#dc2626' }}>{cve.id}</div>
                        </div>
                        <div>
                          <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Authority</span>
                          <div style={{ fontWeight: '600', fontSize: '0.9rem', marginTop: '4px' }}>Original Source</div>
                        </div>
                        <div>
                          <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Published</span>
                          <div style={{ fontWeight: '600', fontSize: '0.9rem', marginTop: '4px' }}>{formatDate(cve.publishedDate)}</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Open Source Intelligence */}
                <div>
                  <h3 style={{ fontSize: '1.2rem', fontWeight: '700', marginBottom: '16px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                    🔓 Open Source Intelligence
                  </h3>
                  <div style={{ display: 'grid', gap: '16px' }}>
                    {/* GitHub Security Advisory */}
                    {github && github.length > 0 && (
                      <div style={{
                        background: settings.darkMode ? '#334155' : '#f8fafc',
                        border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0',
                        borderRadius: '12px',
                        padding: '20px'
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                          <div style={{ 
                            width: '40px', 
                            height: '40px', 
                            background: '#24292f', 
                            borderRadius: '50%',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center'
                          }}>
                            <GitBranch size={20} color="white" />
                          </div>
                          <div>
                            <h4 style={{ margin: 0, fontSize: '1.1rem', fontWeight: '700', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                              GitHub Security Advisory
                            </h4>
                            <p style={{ margin: 0, fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                              Supply Chain Intelligence
                            </p>
                          </div>
                          <a 
                            href={`https://github.com/advisories?query=${cve.id}`} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            style={{ marginLeft: 'auto' }}
                          >
                            <ExternalLink size={20} color={settings.darkMode ? '#94a3b8' : '#64748b'} />
                          </a>
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '12px' }}>
                          <div>
                            <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Advisories</span>
                            <div style={{ fontWeight: '700', fontSize: '1.1rem', marginTop: '4px' }}>{github.length}</div>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Packages</span>
                            <div style={{ fontWeight: '700', fontSize: '1.1rem', marginTop: '4px' }}>
                              {github.reduce((total, advisory) => total + (advisory.vulnerabilities?.nodes?.length || 0), 0)}
                            </div>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Severity</span>
                            <div style={{
                              ...styles.badge,
                              ...getSeverityStyle(github[0].severity),
                              marginTop: '4px'
                            }}>
                              {github[0].severity}
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* OSV Database */}
                    {osv && osv.length > 0 && (
                      <div style={{
                        background: settings.darkMode ? '#334155' : '#f8fafc',
                        border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0',
                        borderRadius: '12px',
                        padding: '20px'
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                          <div style={{ 
                            width: '40px', 
                            height: '40px', 
                            background: '#8b5cf6', 
                            borderRadius: '50%',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center'
                          }}>
                            <Database size={20} color="white" />
                          </div>
                          <div>
                            <h4 style={{ margin: 0, fontSize: '1.1rem', fontWeight: '700', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                              Open Source Vulnerabilities (OSV)
                            </h4>
                            <p style={{ margin: 0, fontSize: '0.85rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                              Distributed Vulnerability Database
                            </p>
                          </div>
                          <a 
                            href={`https://osv.dev/vulnerability/${cve.id}`} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            style={{ marginLeft: 'auto' }}
                          >
                            <ExternalLink size={20} color={settings.darkMode ? '#94a3b8' : '#64748b'} />
                          </a>
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '12px' }}>
                          <div>
                            <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Entries</span>
                            <div style={{ fontWeight: '700', fontSize: '1.1rem', marginTop: '4px' }}>{osv.length}</div>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Ecosystems</span>
                            <div style={{ fontWeight: '700', fontSize: '1.1rem', marginTop: '4px' }}>
                              {new Set(osv.flatMap(entry => entry.affected?.map(a => a.package?.ecosystem) || [])).size}
                            </div>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Type</span>
                            <div style={{
                              ...styles.badge,
                              background: 'rgba(139, 92, 246, 0.15)',
                              color: '#8b5cf6',
                              border: '1px solid rgba(139, 92, 246, 0.3)',
                              marginTop: '4px'
                            }}>
                              OPEN SOURCE
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Linux Distribution Sources */}
                <div>
                  <h3 style={{ fontSize: '1.2rem', fontWeight: '700', marginBottom: '16px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                    🐧 Linux Distribution Sources
                  </h3>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
                    {/* Debian Security Tracker */}
                    <div style={{
                      background: settings.darkMode ? '#334155' : '#f8fafc',
                      border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0',
                      borderRadius: '12px',
                      padding: '16px'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                        <div style={{ 
                          width: '32px', 
                          height: '32px', 
                          background: '#d70a53', 
                          borderRadius: '50%',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: '14px',
                          color: 'white',
                          fontWeight: '700'
                        }}>D</div>
                        <div>
                          <h5 style={{ margin: 0, fontSize: '1rem', fontWeight: '600', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                            Debian Security
                          </h5>
                          <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                            Multiple Releases
                          </span>
                        </div>
                        <a 
                          href={`https://security-tracker.debian.org/tracker/${cve.id}`} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          style={{ marginLeft: 'auto' }}
                        >
                          <ExternalLink size={16} color={settings.darkMode ? '#94a3b8' : '#64748b'} />
                        </a>
                      </div>
                      <div style={{ fontSize: '0.85rem', color: settings.darkMode ? '#cbd5e1' : '#475569' }}>
                        Debian 10, 11, 12, 13 - Medium severity with fixes available
                      </div>
                    </div>

                    {/* Ubuntu Security */}
                    <div style={{
                      background: settings.darkMode ? '#334155' : '#f8fafc',
                      border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0',
                      borderRadius: '12px',
                      padding: '16px'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                        <div style={{ 
                          width: '32px', 
                          height: '32px', 
                          background: '#e95420', 
                          borderRadius: '50%',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: '12px',
                          color: 'white',
                          fontWeight: '700'
                        }}>U</div>
                        <div>
                          <h5 style={{ margin: 0, fontSize: '1rem', fontWeight: '600', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                            Ubuntu Security
                          </h5>
                          <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                            LTS & Current
                          </span>
                        </div>
                        <a 
                          href="https://ubuntu.com/security/notices" 
                          target="_blank" 
                          rel="noopener noreferrer"
                          style={{ marginLeft: 'auto' }}
                        >
                          <ExternalLink size={16} color={settings.darkMode ? '#94a3b8' : '#64748b'} />
                        </a>
                      </div>
                      <div style={{ fontSize: '0.85rem', color: settings.darkMode ? '#cbd5e1' : '#475569' }}>
                        Ubuntu 20.04, 22.04, 24.04 LTS - Security updates available
                      </div>
                    </div>

                    {/* Red Hat Security */}
                    <div style={{
                      background: settings.darkMode ? '#334155' : '#f8fafc',
                      border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0',
                      borderRadius: '12px',
                      padding: '16px'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                        <div style={{ 
                          width: '32px', 
                          height: '32px', 
                          background: '#ee0000', 
                          borderRadius: '4px',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: '10px',
                          color: 'white',
                          fontWeight: '700'
                        }}>RH</div>
                        <div>
                          <h5 style={{ margin: 0, fontSize: '1rem', fontWeight: '600', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                            Red Hat Security
                          </h5>
                          <span style={{ fontSize: '0.8rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                            Enterprise Linux
                          </span>
                        </div>
                        <a 
                          href="https://access.redhat.com/security/" 
                          target="_blank" 
                          rel="noopener noreferrer"
                          style={{ marginLeft: 'auto' }}
                        >
                          <ExternalLink size={16} color={settings.darkMode ? '#94a3b8' : '#64748b'} />
                        </a>
                      </div>
                      <div style={{ fontSize: '0.85rem', color: settings.darkMode ? '#cbd5e1' : '#475569' }}>
                        RHEL 7, 8, 9 - Security advisories and patches
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'cvss' && cve.cvssV3 && (
          <div>
            <h2 style={styles.sectionTitle}>CVSS v3.1 Detailed Metrics</h2>
            <div style={styles.sectionContent}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '24px' }}>
                <div style={{
                  background: settings.darkMode ? '#334155' : '#f8fafc',
                  borderRadius: '12px',
                  padding: '20px',
                  border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0'
                }}>
                  <h4 style={{ margin: '0 0 16px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>Base Metrics</h4>
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
                      <span style={styles.infoLabel}>Exploitability Score:</span>
                      <span style={styles.infoValue}>{cve.cvssV3.exploitabilityScore}</span>
                    </div>
                    <div style={styles.infoItem}>
                      <span style={styles.infoLabel}>Impact Score:</span>
                      <span style={styles.infoValue}>{cve.cvssV3.impactScore}</span>
                    </div>
                  </div>
                </div>

                <div style={{
                  background: settings.darkMode ? '#334155' : '#f8fafc',
                  borderRadius: '12px',
                  padding: '20px',
                  border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0'
                }}>
                  <h4 style={{ margin: '0 0 16px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>Attack Vector</h4>
                  <div style={{ display: 'grid', gap: '12px' }}>
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
                  </div>
                </div>

                <div style={{
                  background: settings.darkMode ? '#334155' : '#f8fafc',
                  borderRadius: '12px',
                  padding: '20px',
                  border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0'
                }}>
                  <h4 style={{ margin: '0 0 16px 0', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>Impact Metrics</h4>
                  <div style={{ display: 'grid', gap: '12px' }}>
                    <div style={styles.infoItem}>
                      <span style={styles.infoLabel}>Scope:</span>
                      <span style={styles.infoValue}>{cve.cvssV3.scope}</span>
                    </div>
                    <div style={styles.infoItem}>
                      <span style={styles.infoLabel}>Confidentiality:</span>
                      <span style={styles.infoValue}>{cve.cvssV3.confidentialityImpact}</span>
                    </div>
                    <div style={styles.infoItem}>
                      <span style={styles.infoLabel}>Integrity:</span>
                      <span style={styles.infoValue}>{cve.cvssV3.integrityImpact}</span>
                    </div>
                    <div style={styles.infoItem}>
                      <span style={styles.infoLabel}>Availability:</span>
                      <span style={styles.infoValue}>{cve.cvssV3.availabilityImpact}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'ai' && aiAnalysis && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
              <h2 style={styles.sectionTitle}>AI-Powered Security Analysis</h2>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                {aiAnalysis.webGrounded && (
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
                {aiAnalysis.ragUsed && (
                  <span style={{
                    ...styles.badge,
                    background: 'rgba(139, 92, 246, 0.15)',
                    color: '#8b5cf6',
                    border: '1px solid rgba(139, 92, 246, 0.3)'
                  }}>
                    <Database size={12} style={{ marginRight: '4px' }} />
                    ENHANCED
                  </span>
                )}
              </div>
            </div>
            <div style={{
              ...styles.sectionContent,
              whiteSpace: 'pre-wrap',
              lineHeight: '1.7',
              fontSize: '1rem'
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
                Analysis Metadata:
              </div>
              <div style={{ color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                • Sources: {aiAnalysis.enhancedSources.join(', ')}
                {aiAnalysis.ragUsed && (
                  <>
                    <br />• Knowledge Base: {aiAnalysis.ragDocs} relevant security documents
                  </>
                )}
                {aiAnalysis.webGrounded && (
                  <>
                    <br />• Real-time Intelligence: Current threat landscape data
                  </>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Enhanced Sidebar */}
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
              <div style={styles.scoreLabel}>CVSS Score</div>
            </div>
          </div>
          <div style={{ textAlign: 'center', marginBottom: '12px' }}>
            <span style={{ ...styles.badge, ...getSeverityStyle(severity), fontSize: '0.8rem', padding: '8px 16px' }}>
              {severity}
            </span>
          </div>
        </div>

        {/* Quick Stats */}
        <div style={{ marginBottom: '32px' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: '700', marginBottom: '16px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
            Threat Intelligence
          </h3>
          <div style={{ display: 'grid', gap: '12px' }}>
            <div style={{
              background: kev ? 'rgba(239, 68, 68, 0.1)' : 'rgba(34, 197, 94, 0.1)',
              border: `1px solid ${kev ? 'rgba(239, 68, 68, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`,
              borderRadius: '8px',
              padding: '12px',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '0.75rem', fontWeight: '600', marginBottom: '4px', color: kev ? '#ef4444' : '#22c55e' }}>
                ACTIVE EXPLOITATION
              </div>
              <div style={{ fontSize: '1.2rem', fontWeight: '700', color: kev ? '#ef4444' : '#22c55e' }}>
                {kev ? 'CONFIRMED' : 'NOT DETECTED'}
              </div>
            </div>
            
            {epss && (
              <div style={{
                background: epss.epss > 0.5 ? 'rgba(245, 158, 11, 0.1)' : 'rgba(59, 130, 246, 0.1)',
                border: `1px solid ${epss.epss > 0.5 ? 'rgba(245, 158, 11, 0.3)' : 'rgba(59, 130, 246, 0.3)'}`,
                borderRadius: '8px',
                padding: '12px',
                textAlign: 'center'
              }}>
                <div style={{ fontSize: '0.75rem', fontWeight: '600', marginBottom: '4px', color: epss.epss > 0.5 ? '#f59e0b' : '#3b82f6' }}>
                  EPSS PROBABILITY
                </div>
                <div style={{ fontSize: '1.2rem', fontWeight: '700', color: epss.epss > 0.5 ? '#f59e0b' : '#3b82f6' }}>
                  {(epss.epss * 100).toFixed(1)}%
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Info Grid */}
        <div style={styles.infoGrid}>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: '700', marginBottom: '16px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
              Vulnerability Details
            </h3>
          </div>
          
          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>Published</span>
            <span style={styles.infoValue}>{formatDate(cve.publishedDate)}</span>
          </div>
          
          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>Last Modified</span>
            <span style={styles.infoValue}>{formatDate(cve.lastModifiedDate)}</span>
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
            <span style={styles.infoLabel}>CISA KEV Listed</span>
            <span style={styles.infoValue}>{kev ? 'Yes' : 'No'}</span>
          </div>
          
          {kev && (
            <>
              <div style={styles.infoItem}>
                <span style={styles.infoLabel}>KEV Due Date</span>
                <span style={styles.infoValue}>{kev.dueDate}</span>
              </div>
              
              <div style={styles.infoItem}>
                <span style={styles.infoLabel}>Ransomware Use</span>
                <span style={styles.infoValue}>{kev.knownRansomwareCampaignUse === 'Known' ? 'Yes' : 'No'}</span>
              </div>
            </>
          )}
          
          {epss && (
            <>
              <div style={styles.infoItem}>
                <span style={styles.infoLabel}>EPSS Percentile</span>
                <span style={styles.infoValue}>{epss.percentile.toFixed(1)}</span>
              </div>
              
              <div style={styles.infoItem}>
                <span style={styles.infoLabel}>EPSS Date</span>
                <span style={styles.infoValue}>{formatDate(epss.date)}</span>
              </div>
            </>
          )}

          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>Data Sources</span>
            <span style={styles.infoValue}>{vulnerability.enhancedSources?.length || 0}</span>
          </div>
        </div>

        {/* Data Sources */}
        <div style={{ marginTop: '32px' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: '700', marginBottom: '16px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
            Intelligence Sources
          </h3>
          <div style={styles.sourcesList}>
            {/* NVD */}
            <div style={styles.sourceItem}>
              <div style={{ 
                width: '32px', 
                height: '32px', 
                background: '#1f2937', 
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Shield size={16} color="white" />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  <span style={{ fontWeight: '600', fontSize: '0.95rem' }}>
                    <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                      NVD (NIST)
                    </a>
                  </span>
                  <ExternalLink size={12} style={{ opacity: 0.6 }} />
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  <span style={{
                    ...styles.badge,
                    ...getSeverityStyle(severity),
                    fontSize: '0.7rem',
                    padding: '2px 8px'
                  }}>{severity}</span>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Official US Gov</span>
                </div>
                <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>Updated: {formatDate(cve.lastModifiedDate)}</div>
              </div>
            </div>

            {/* CISA KEV */}
            {kev && (
              <div style={styles.sourceItem}>
                <div style={{ 
                  width: '32px', 
                  height: '32px', 
                  background: '#ef4444', 
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <AlertTriangle size={16} color="white" />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span style={{ fontWeight: '600', fontSize: '0.95rem' }}>
                      <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                        CISA KEV
                      </a>
                    </span>
                    <ExternalLink size={12} style={{ opacity: 0.6 }} />
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span style={{
                      ...styles.badge,
                      ...styles.badgeCritical,
                      fontSize: '0.7rem',
                      padding: '2px 8px'
                    }}>CRITICAL</span>
                    <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Active Exploit</span>
                  </div>
                  <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>Added: {formatDate(kev.dateAdded)}</div>
                </div>
              </div>
            )}

            {/* FIRST EPSS */}
            {epss && (
              <div style={styles.sourceItem}>
                <div style={{ 
                  width: '32px', 
                  height: '32px', 
                  background: '#22c55e', 
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <Target size={16} color="white" />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span style={{ fontWeight: '600', fontSize: '0.95rem' }}>
                      <a href={`https://api.first.org/data/v1/epss?cve=${cve.id}`} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                        FIRST EPSS
                      </a>
                    </span>
                    <ExternalLink size={12} style={{ opacity: 0.6 }} />
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span style={{
                      ...styles.badge,
                      background: epss.epss > 0.5 ? 'rgba(245, 158, 11, 0.15)' : 'rgba(34, 197, 94, 0.15)',
                      color: epss.epss > 0.5 ? '#f59e0b' : '#22c55e',
                      border: `1px solid ${epss.epss > 0.5 ? 'rgba(245, 158, 11, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`,
                      fontSize: '0.7rem',
                      padding: '2px 8px'
                    }}>{(epss.epss * 100).toFixed(1)}%</span>
                    <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Exploit Probability</span>
                  </div>
                  <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>Updated: {formatDate(epss.date)}</div>
                </div>
              </div>
            )}

            {/* GitHub Security Advisory */}
            {github && github.length > 0 && (
              <div style={styles.sourceItem}>
                <div style={{ 
                  width: '32px', 
                  height: '32px', 
                  background: '#24292f', 
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <GitBranch size={16} color="white" />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span style={{ fontWeight: '600', fontSize: '0.95rem' }}>
                      <a href={`https://github.com/advisories?query=${cve.id}`} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                        GitHub Advisory
                      </a>
                    </span>
                    <ExternalLink size={12} style={{ opacity: 0.6 }} />
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span style={{
                      ...styles.badge,
                      ...getSeverityStyle(github[0].severity),
                      fontSize: '0.7rem',
                      padding: '2px 8px'
                    }}>{github[0].severity}</span>
                    <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Supply Chain</span>
                  </div>
                  <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>
                    {github.reduce((total, advisory) => total + (advisory.vulnerabilities?.nodes?.length || 0), 0)} packages affected
                  </div>
                </div>
              </div>
            )}

            {/* OSV Database */}
            {osv && osv.length > 0 && (
              <div style={styles.sourceItem}>
                <div style={{ 
                  width: '32px', 
                  height: '32px', 
                  background: '#8b5cf6', 
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <Database size={16} color="white" />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span style={{ fontWeight: '600', fontSize: '0.95rem' }}>
                      <a href={`https://osv.dev/vulnerability/${cve.id}`} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'none' }}>
                        OSV Database
                      </a>
                    </span>
                    <ExternalLink size={12} style={{ opacity: 0.6 }} />
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span style={{
                      ...styles.badge,
                      background: 'rgba(139, 92, 246, 0.15)',
                      color: '#8b5cf6',
                      border: '1px solid rgba(139, 92, 246, 0.3)',
                      fontSize: '0.7rem',
                      padding: '2px 8px'
                    }}>OPEN SOURCE</span>
                    <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>Ecosystem Data</span>
                  </div>
                  <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>
                    {osv.length} database entries
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
        
        <div style={{ marginTop: '24px', fontSize: '0.75rem', color: settings.darkMode ? '#64748b' : '#94a3b8', textAlign: 'center' }}>
          Last updated: {formatDate(vulnerability.lastUpdated)}
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
      setLoadingSteps(prev => [...prev, `🎯 Starting comprehensive analysis for ${cveId}...`]);
      
      const vulnerability = await fetchVulnerabilityData(cveId, setLoadingSteps, {
        nvd: settings.nvdApiKey,
        github: settings.githubToken
      });
      
      setVulnerabilities([vulnerability]);
      setSearchHistory(prev => [...new Set([cveId, ...prev])].slice(0, 5));
      
      addNotification({
        type: 'success',
        title: 'Analysis Complete',
        message: `Successfully analyzed ${cveId} with ${vulnerability.enhancedSources.length} data sources`
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
        <h1 style={styles.searchTitle}>Global Vulnerability Intelligence</h1>
        <p style={styles.searchSubtitle}>Real-time threat analysis powered by AI and comprehensive data sources</p>
        
        <div style={styles.searchWrapper}>
          <Search style={styles.searchIcon} size={24} />
          <input
            type="text"
            placeholder="Enter CVE ID (e.g., CVE-2024-12345)"
            style={{
              ...styles.searchInput,
              borderColor: searchTerm ? '#3b82f6' : (settings.darkMode ? '#334155' : '#e2e8f0')
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
            {loading ? <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} /> : <Search size={18} />}
            {loading ? 'Analyzing...' : 'Analyze'}
          </button>
        </div>

        {searchHistory.length > 0 && (
          <div style={{ marginTop: '24px' }}>
            <div style={{ fontSize: '0.9rem', marginBottom: '12px', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
              Recent searches:
            </div>
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', justifyContent: 'center' }}>
              {searchHistory.map((cve, index) => (
                <button
                  key={index}
                  style={{
                    ...styles.badge,
                    background: settings.darkMode ? '#334155' : '#f1f5f9',
                    color: settings.darkMode ? '#f1f5f9' : '#334155',
                    cursor: 'pointer',
                    border: 'none',
                    transition: 'all 0.3s ease',
                    padding: '8px 16px'
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

        {/* Feature Highlights */}
        <div style={{ marginTop: '64px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '48px', textAlign: 'left' }}>
          <div>
            <h3 style={{ fontSize: '1.3rem', fontWeight: '700', marginBottom: '20px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
              🌍 Global Data Sources
            </h3>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px' }}>
              {['NVD (NIST)', 'CISA KEV', 'FIRST EPSS', 'GitHub Security', 'OSV Database', 'VulnDB'].map((source) => (
                <span key={source} style={{
                  ...styles.badge,
                  background: settings.darkMode ? '#334155' : '#f1f5f9',
                  color: settings.darkMode ? '#f1f5f9' : '#334155',
                  padding: '8px 16px'
                }}>
                  {source}
                </span>
              ))}
            </div>
          </div>
          
          <div>
            <h3 style={{ fontSize: '1.3rem', fontWeight: '700', marginBottom: '20px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
              🤖 AI-Powered Analysis
            </h3>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px' }}>
              {['Real-time Web Search', 'Threat Intelligence', 'Business Impact', 'Remediation Strategy', 'Risk Prioritization'].map((feature) => (
                <span key={feature} style={{
                  ...styles.badge,
                  background: settings.darkMode ? '#334155' : '#f1f5f9',
                  color: settings.darkMode ? '#f1f5f9' : '#334155',
                  padding: '8px 16px'
                }}>
                  {feature}
                </span>
              ))}
            </div>
          </div>

          <div>
            <h3 style={{ fontSize: '1.3rem', fontWeight: '700', marginBottom: '20px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
              📦 Supply Chain Intelligence
            </h3>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px' }}>
              {['Package Detection', 'Version Analysis', 'Ecosystem Mapping', 'Patch Tracking', 'Dependency Graph'].map((capability) => (
                <span key={capability} style={{
                  ...styles.badge,
                  background: settings.darkMode ? '#334155' : '#f1f5f9',
                  color: settings.darkMode ? '#f1f5f9' : '#334155',
                  padding: '8px 16px'
                }}>
                  {capability}
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
    }, 6000);
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
              <Shield size={32} color="#3b82f6" />
              <div>
                <h1 style={styles.title}>VulnIntel Pro</h1>
                <p style={styles.subtitle}>Advanced Vulnerability Intelligence Platform</p>
              </div>
            </div>
            <div style={styles.headerActions}>
              <div style={styles.statusIndicator}>
                <Activity size={14} />
                <span>REAL-TIME</span>
              </div>
              <button 
                style={{ 
                  ...styles.button, 
                  ...styles.buttonSecondary,
                  padding: '8px 12px'
                }}
                onClick={() => setSettings(prev => ({ ...prev, darkMode: !prev.darkMode }))}
                title={settings.darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              >
                {settings.darkMode ? <Sun size={18} /> : <Moon size={18} />}
              </button>
              <button 
                style={{ 
                  ...styles.button, 
                  ...styles.buttonSecondary 
                }}
                onClick={() => setShowSettings(true)}
              >
                <Settings size={18} />
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
                background: settings.darkMode ? '#1e293b' : '#ffffff',
                color: settings.darkMode ? '#f1f5f9' : '#0f172a',
                padding: '48px',
                borderRadius: '20px',
                textAlign: 'center',
                maxWidth: '700px',
                boxShadow: settings.darkMode ? '0 8px 32px rgba(0, 0, 0, 0.3)' : '0 4px 20px rgba(0, 0, 0, 0.08)',
                border: settings.darkMode ? '1px solid #334155' : '1px solid #e2e8f0'
              }}>
                <Loader2 size={56} style={{ marginBottom: '24px', animation: 'spin 1s linear infinite', color: '#3b82f6' }} />
                <h3 style={{ margin: '0 0 12px 0', fontSize: '1.5rem', fontWeight: '700' }}>Processing Vulnerability Intelligence</h3>
                <p style={{ margin: '0 0 32px 0', fontSize: '1.1rem', opacity: 0.8 }}>
                  Fetching real-time data from global threat intelligence sources...
                </p>
                
                {loadingSteps.length > 0 && (
                  <div style={{ 
                    background: settings.darkMode ? '#334155' : '#f8fafc', 
                    borderRadius: '12px', 
                    padding: '24px',
                    textAlign: 'left',
                    maxHeight: '300px',
                    overflowY: 'auto'
                  }}>
                    {loadingSteps.slice(-10).map((step, index) => (
                      <div key={index} style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: '12px', 
                        marginBottom: '8px',
                        fontSize: '0.9rem'
                      }}>
                        {step.startsWith('✅') ? (
                          <CheckCircle size={16} color="#22c55e" />
                        ) : step.startsWith('❌') ? (
                          <XCircle size={16} color="#ef4444" />
                        ) : step.startsWith('⚠️') ? (
                          <AlertTriangle size={16} color="#f59e0b" />
                        ) : (
                          <div style={{ 
                            width: '12px', 
                            height: '12px', 
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
                background: settings.darkMode ? '#1e293b' : '#ffffff',
                borderRadius: '20px',
                padding: '64px',
                boxShadow: settings.darkMode ? '0 8px 32px rgba(0, 0, 0, 0.3)' : '0 4px 20px rgba(0, 0, 0, 0.08)',
                border: settings.darkMode ? '1px solid #334155' : '1px solid #e2e8f0',
                maxWidth: '700px',
                margin: '0 auto'
              }}>
                <Shield size={80} style={{ marginBottom: '32px', color: '#3b82f6' }} />
                <h2 style={{ margin: '0 0 16px 0', fontSize: '2rem', fontWeight: '800', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                  Next-Generation Vulnerability Intelligence
                </h2>
                <p style={{ margin: '0 0 32px 0', fontSize: '1.1rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                  Comprehensive vulnerability analysis powered by AI and real-time threat intelligence from authoritative global sources
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '24px', marginTop: '48px' }}>
                  <div style={{ textAlign: 'center', padding: '24px' }}>
                    <Database size={40} style={{ color: '#3b82f6', marginBottom: '12px' }} />
                    <div style={{ fontWeight: '700', marginBottom: '6px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>Real-time Data</div>
                    <div style={{ fontSize: '0.9rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>NVD, EPSS, KEV, OSV</div>
                  </div>
                  <div style={{ textAlign: 'center', padding: '24px' }}>
                    <GitBranch size={40} style={{ color: '#6b7280', marginBottom: '12px' }} />
                    <div style={{ fontWeight: '700', marginBottom: '6px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>Supply Chain</div>
                    <div style={{ fontSize: '0.9rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Package Analysis</div>
                  </div>
                  <div style={{ textAlign: 'center', padding: '24px' }}>
                    <Brain size={40} style={{ color: '#8b5cf6', marginBottom: '12px' }} />
                    <div style={{ fontWeight: '700', marginBottom: '6px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>AI Intelligence</div>
                    <div style={{ fontSize: '0.9rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Enhanced Analysis</div>
                  </div>
                  <div style={{ textAlign: 'center', padding: '24px' }}>
                    <Globe size={40} style={{ color: '#22c55e', marginBottom: '12px' }} />
                    <div style={{ fontWeight: '700', marginBottom: '6px', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>Global Sources</div>
                    <div style={{ fontSize: '0.9rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>Worldwide Coverage</div>
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
