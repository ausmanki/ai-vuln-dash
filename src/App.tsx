import React, { useState, createContext, useContext, useEffect } from 'react';
import { Search, Brain, Settings, Target, Database, Activity, CheckCircle, XCircle, X, Eye, EyeOff, Save, Globe, AlertTriangle, Loader2, ExternalLink, RefreshCw, Download, Info, Package, BarChart3 } from 'lucide-react';

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
        title: "Active Exploitation Intelligence",
        content: "Integration of multiple threat intelligence sources helps identify vulnerabilities under active exploitation. This includes CISA KEV catalog, commercial threat feeds, proof-of-concept availability, and ransomware campaign usage. Active exploitation significantly elevates vulnerability priority and triggers immediate response protocols.",
        category: "exploitation",
        tags: ["exploitation", "threat-intelligence", "ransomware", "kev"]
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

// Helper function to convert hex to RGB (used for rgba backgrounds with theme colors)
const hexToRgb = (hex) => {
  let r = 0, g = 0, b = 0;
  if (hex.length === 4) { // #RGB format
    r = parseInt(hex[1] + hex[1], 16);
    g = parseInt(hex[2] + hex[2], 16);
    b = parseInt(hex[3] + hex[3], 16);
  } else if (hex.length === 7) { // #RRGGBB format
    r = parseInt(hex[1] + hex[2], 16);
    g = parseInt(hex[3] + hex[4], 16);
    b = parseInt(hex[5] + hex[6], 16);
  }
  return `${r}, ${g}, ${b}`;
};

// Consistent color palette
const colors = {
  blue: '#3b82f6',
  purple: '#8b5cf6',
  green: '#22c55e',
  red: '#ef4444',
  yellow: '#f59e0b',

  dark: {
    background: '#0f172a', // Slate 900
    surface: '#1e293b',   // Slate 800
    primaryText: '#f1f5f9', // Slate 100
    secondaryText: '#94a3b8', // Slate 400
    tertiaryText: '#64748b', // Slate 500
    border: '#334155',     // Slate 700
    interactive: '#475569', // Slate 600
    gradientStart: '#1e293b',
    gradientEnd: '#334155',
    shadow: 'rgba(0, 0, 0, 0.2)',
  },
  light: {
    background: '#f8fafc', // Slate 50
    surface: '#ffffff',   // White
    primaryText: '#0f172a', // Slate 900
    secondaryText: '#64748b', // Slate 500
    tertiaryText: '#94a3b8', // Slate 400
    border: '#e2e8f0',     // Slate 200
    interactive: '#cbd5e1', // Slate 300
    gradientStart: '#ffffff',
    gradientEnd: '#f8fafc',
    shadow: 'rgba(0, 0, 0, 0.07)',
  }
};

const getStyles = (darkMode) => {
  const currentTheme = darkMode ? colors.dark : colors.light;
  const commonShadow = `0 4px 6px -1px ${currentTheme.shadow}, 0 2px 4px -1px ${currentTheme.shadow}`;
  const strongShadow = `0 10px 15px -3px ${currentTheme.shadow}, 0 4px 6px -2px ${currentTheme.shadow}`;

  return {
    appContainer: {
      minHeight: '100vh',
      backgroundColor: currentTheme.background,
      fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol"', // Modern font stack
      color: currentTheme.primaryText, // Default text color
    },
    header: {
      background: `linear-gradient(135deg, ${currentTheme.gradientStart} 0%, ${currentTheme.gradientEnd} 100%)`,
      color: currentTheme.primaryText,
      boxShadow: commonShadow,
      borderBottom: `1px solid ${currentTheme.border}`
    },
    headerContent: {
      maxWidth: '1536px', // Wider max width for larger screens
      margin: '0 auto',
      padding: '16px 32px', // Slightly reduced padding
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between'
    },
    headerTitle: { display: 'flex', alignItems: 'center', gap: '16px' },
    title: {
      fontSize: '1.375rem', // Slightly adjusted size
      fontWeight: '700',
      margin: 0,
      background: `linear-gradient(135deg, ${colors.blue} 0%, ${colors.purple} 100%)`,
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent'
    },
    subtitle: {
      fontSize: '0.8125rem', // Slightly adjusted size
      color: currentTheme.secondaryText, // Use theme color
      margin: 0,
      fontWeight: '500'
    },
    headerActions: { display: 'flex', alignItems: 'center', gap: '16px' },
    statusIndicator: {
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      fontSize: '0.8rem', // Standardized font size
      padding: '6px 12px',
      borderRadius: '9999px', // Pill shape
      border: `1px solid`, // Border color set dynamically
      fontWeight: '600'
      // Background and color set dynamically based on status in component
    },
    mainContent: {
      maxWidth: '1536px', // Wider max width
      margin: '0 auto',
      padding: '24px 32px' // Consistent padding
    },
    searchSection: {
      background: `linear-gradient(135deg, ${currentTheme.gradientStart} 0%, ${currentTheme.gradientEnd} 100%)`,
      padding: '48px 32px 64px 32px', // Adjusted padding
      borderBottom: `1px solid ${currentTheme.border}`
    },
    searchContainer: {
      maxWidth: '960px', // Increased max width
      margin: '0 auto',
      textAlign: 'center'
    },
    searchTitle: {
      fontSize: '2.5rem', // Adjusted size
      fontWeight: '800',
      background: `linear-gradient(135deg, ${colors.blue} 0%, ${colors.purple} 100%)`,
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      marginBottom: '12px'
    },
    searchSubtitle: {
      fontSize: '1.125rem', // Adjusted size
      color: currentTheme.secondaryText,
      marginBottom: '40px',
      fontWeight: '500',
      maxWidth: '700px',
      margin: '0 auto 32px auto', // Center subtitle
    },
    searchWrapper: {
      position: 'relative',
      maxWidth: '768px', // Increased max width
      margin: '0 auto 24px auto', // Centered
    },
    searchInput: {
      width: '100%',
      padding: '18px 20px 18px 52px', // Adjusted padding
      border: `2px solid ${currentTheme.border}`,
      borderRadius: '12px', // Softer radius
      fontSize: '1rem',
      outline: 'none',
      boxSizing: 'border-box',
      background: currentTheme.surface,
      color: currentTheme.primaryText,
      transition: 'all 0.2s ease-in-out', // Faster transition
      boxShadow: `0 2px 4px ${currentTheme.shadow}`,
      '&:focus': { // Add focus style
        borderColor: colors.blue,
        boxShadow: `0 0 0 3px rgba(59, 130, 246, 0.3)`,
      }
    },
    searchIcon: {
      position: 'absolute',
      left: '18px', // Adjusted position
      top: '50%',
      transform: 'translateY(-50%)',
      color: currentTheme.secondaryText
    },
    searchButton: {
      position: 'absolute',
      right: '8px',
      top: '50%',
      transform: 'translateY(-50%)',
      padding: '10px 20px', // Adjusted padding
      background: `linear-gradient(135deg, ${colors.blue} 0%, #1d4ed8 100%)`, // Kept gradient for primary action
      color: 'white',
      border: 'none',
      borderRadius: '8px', // Softer radius
      cursor: 'pointer',
      fontWeight: '600',
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      fontSize: '0.95rem', // Adjusted size
          boxShadow: `0 2px 8px rgba(${hexToRgb(colors.blue)}, 0.3)`, // Use themed blue
      transition: 'all 0.2s ease-in-out',
      '&:hover': { // Add hover style
            boxShadow: `0 4px 12px rgba(${hexToRgb(colors.blue)}, 0.4)`, // Use themed blue
        transform: 'translateY(-50%) scale(1.02)',
          },
          '&:disabled': { // Added disabled style
            opacity: 0.6,
            cursor: 'not-allowed',
            boxShadow: 'none',
      }
    },
    button: {
      display: 'inline-flex', // Use inline-flex for better alignment
      alignItems: 'center',
      justifyContent: 'center', // Center content
      gap: '8px',
      padding: '10px 18px', // Adjusted padding
      borderRadius: '8px', // Softer radius
      fontWeight: '600',
      cursor: 'pointer',
      border: '1px solid', // Thinner border
      fontSize: '0.9rem',
      transition: 'all 0.2s ease-in-out',
      textDecoration: 'none', // Remove underline from potential <a> tags
      whiteSpace: 'nowrap', // Prevent wrapping
          '&:disabled': { // Added disabled style for general buttons
            opacity: 0.6,
            cursor: 'not-allowed',
            boxShadow: 'none',
            transform: 'none',
          }
    },
    buttonPrimary: {
      background: `linear-gradient(135deg, ${colors.blue} 0%, #1d4ed8 100%)`,
      color: 'white',
      borderColor: 'transparent',
          boxShadow: `0 2px 8px rgba(${hexToRgb(colors.blue)}, 0.3)`, // Use themed blue
      '&:hover': {
            boxShadow: `0 4px 12px rgba(${hexToRgb(colors.blue)}, 0.4)`, // Use themed blue
        transform: 'scale(1.02)',
          },
          // Disabled state will be inherited from .button
    },
    buttonSecondary: {
      background: currentTheme.surface,
      color: currentTheme.primaryText,
      borderColor: currentTheme.interactive,
      '&:hover': {
            background: darkMode ? colors.dark.interactive : colors.light.background, // Use theme background for light hover
            borderColor: darkMode ? colors.dark.border : colors.light.interactive, // Use theme interactive for light border hover
          },
          // Disabled state will be inherited from .button
    },
    badge: {
      padding: '5px 10px', // Adjusted padding
      borderRadius: '6px', // Softer radius
      fontSize: '0.7rem',
      fontWeight: '700',
      display: 'inline-flex', // Use inline-flex
      alignItems: 'center',
      textTransform: 'uppercase',
      letterSpacing: '0.05em', // Slightly reduced letter spacing
      lineHeight: 1.2,
    },
    // Specific badge colors can remain as they are, but ensure good contrast with new text colors
    badgeCritical: { background: 'rgba(239, 68, 68, 0.15)', color: colors.red, border: `1px solid ${colors.red}4D` }, // Added alpha to border
    badgeHigh: { background: 'rgba(245, 158, 11, 0.15)', color: colors.yellow, border: `1px solid ${colors.yellow}4D` },
    badgeMedium: { background: 'rgba(59, 130, 246, 0.15)', color: colors.blue, border: `1px solid ${colors.blue}4D` },
    badgeLow: { background: 'rgba(34, 197, 94, 0.15)', color: colors.green, border: `1px solid ${colors.green}4D` },

    notification: {
      // position: 'fixed', // Keep position fixed
      // top: '24px',
      // right: '24px',
      background: currentTheme.surface,
      borderRadius: '8px', // Softer radius
      padding: '16px', // Adjusted padding
      boxShadow: strongShadow,
      // zIndex: 1000,
      maxWidth: '400px', // Adjusted width
      border: `1px solid ${currentTheme.border}`,
      display: 'flex', // Added for icon alignment
      alignItems: 'flex-start', // Align icon to top
      gap: '12px',
    },
    notificationSuccess: { borderLeft: `4px solid ${colors.green}` },
    notificationError: { borderLeft: `4px solid ${colors.red}` },
    notificationWarning: { borderLeft: `4px solid ${colors.yellow}` },

    loadingContainer: {
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '64px 32px', // Adjusted padding
      textAlign: 'center',
      color: currentTheme.secondaryText,
    },
    emptyState: {
      textAlign: 'center',
      padding: '64px 32px',
      color: currentTheme.secondaryText,
    },
    modal: {
      position: 'fixed',
      inset: 0,
      background: darkMode ? 'rgba(0, 0, 0, 0.8)' : 'rgba(0, 0, 0, 0.6)', // Adjusted backdrop opacity
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1050, // Ensure modal is above other content
      backdropFilter: 'blur(5px)' // Slightly softer blur
    },
    modalContent: {
      background: currentTheme.surface,
      borderRadius: '16px', // Softer radius
      padding: '24px 32px', // Adjusted padding
      width: '100%',
      maxWidth: '700px',
      maxHeight: '90vh',
      overflowY: 'auto',
      margin: '20px',
      border: `1px solid ${currentTheme.border}`,
      boxShadow: `0 25px 50px -12px ${currentTheme.shadow}`, // More pronounced shadow
    },
    modalHeader: {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      marginBottom: '24px',
      paddingBottom: '16px',
      borderBottom: `1px solid ${currentTheme.border}`
    },
    modalTitle: {
      fontSize: '1.25rem', // Adjusted size
      fontWeight: '700',
      margin: 0,
      color: currentTheme.primaryText
    },
    formGroup: { marginBottom: '24px' }, // Increased spacing
    label: {
      display: 'block',
      fontSize: '0.875rem', // Standardized size
      fontWeight: '600',
      color: currentTheme.secondaryText,
      marginBottom: '8px'
    },
    input: {
      width: '100%',
      padding: '10px 14px', // Adjusted padding
      border: `1px solid ${currentTheme.interactive}`,
      borderRadius: '8px', // Softer radius
      fontSize: '0.9rem',
      outline: 'none',
      boxSizing: 'border-box',
      background: currentTheme.surface, // Use surface for inputs
      color: currentTheme.primaryText,
      transition: 'border-color 0.2s ease-in-out, box-shadow 0.2s ease-in-out',
      '&:focus': {
        borderColor: colors.blue,
        boxShadow: `0 0 0 3px rgba(59, 130, 246, 0.3)`,
      }
    },
    select: {
      width: '100%',
      padding: '10px 14px',
      border: `1px solid ${currentTheme.interactive}`,
      borderRadius: '8px',
      fontSize: '0.9rem',
      outline: 'none',
      background: currentTheme.surface,
      boxSizing: 'border-box',
      color: currentTheme.primaryText,
      transition: 'border-color 0.2s ease-in-out, box-shadow 0.2s ease-in-out',
      appearance: 'none', // Remove default arrow
      backgroundImage: darkMode
        ? `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' fill='${currentTheme.secondaryText.replace('#', '%23')}' viewBox='0 0 16 16'%3E%3Cpath fill-rule='evenodd' d='M1.646 4.646a.5.5 0 0 1 .708 0L8 10.293l5.646-5.647a.5.5 0 0 1 .708.708l-6 6a.5.5 0 0 1-.708 0l-6-6a.5.5 0 0 1 0-.708z'/%3E%3C/svg%3E")`
        : `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' fill='${currentTheme.secondaryText.replace('#', '%23')}' viewBox='0 0 16 16'%3E%3Cpath fill-rule='evenodd' d='M1.646 4.646a.5.5 0 0 1 .708 0L8 10.293l5.646-5.647a.5.5 0 0 1 .708.708l-6 6a.5.5 0 0 1-.708 0l-6-6a.5.5 0 0 1 0-.708z'/%3E%3C/svg%3E")`,
      backgroundRepeat: 'no-repeat',
      backgroundPosition: 'right 14px center',
      paddingRight: '36px', // Make space for custom arrow
      '&:focus': {
        borderColor: colors.blue,
        boxShadow: `0 0 0 3px rgba(59, 130, 246, 0.3)`,
      }
    }
  };
};

const AppContext = createContext({});

// Real API functions for vulnerability data
const fetchCVEDataFromNVD = async (cveId, setLoadingSteps, apiKey) => {
  setLoadingSteps(prev => [...prev, `🔍 Fetching ${cveId} from NVD...`]);
  
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    const headers = { 
      'Accept': 'application/json',
      'User-Agent': 'VulnerabilityIntelligence/1.0'
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
    
    // Add NVD data to RAG database
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
        'User-Agent': 'VulnerabilityIntelligence/1.0'
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
        'User-Agent': 'VulnerabilityIntelligence/1.0'
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

// Enhanced RAG-powered AI Analysis with source fetching
const generateEnhancedRAGAnalysis = async (vulnerability, apiKey, model, settings = {}) => {
  const cveId = vulnerability.cve.id;
  const description = vulnerability.cve.description;
  const cvssScore = vulnerability.cve.cvssV3?.baseScore || vulnerability.cve.cvssV2?.baseScore || 'N/A';
  const epssScore = vulnerability.epss ? (vulnerability.epss.epss * 100).toFixed(2) + '%' : 'N/A';
  const kevStatus = vulnerability.kev ? 'Yes' : 'No';
  const isGemini2Plus = model.includes('2.0') || model.includes('2.5');

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

    // Enhanced prompt with structured format matching the layout
    const prompt = `You are a senior cybersecurity analyst providing a comprehensive vulnerability assessment for ${cveId}.

VULNERABILITY DETAILS:
- CVE ID: ${cveId}
- CVSS Score: ${cvssScore}
- EPSS Score: ${epssScore}
- KEV Listed: ${kevStatus}
- Description: ${description.substring(0, 800)}

RELEVANT SECURITY KNOWLEDGE BASE:
${ragContext}

DATA SOURCES ANALYZED:
- NVD: ${vulnerability.cve ? 'Available' : 'Not Available'}
- EPSS: ${vulnerability.epss ? 'Available' : 'Not Available'}
- CISA KEV: ${vulnerability.kev ? 'CONFIRMED ACTIVE EXPLOITATION' : 'Not Listed'}

${isGemini2Plus ? 'IMPORTANT: Search the web extensively for the latest information about this vulnerability. Find and include specific URLs for vendor advisories, security bulletins, patch releases, affected package repositories, and official fixes. DO NOT include social media links.' : ''}

CRITICAL REQUIREMENTS:
1. Based on the CVE description, identify and search for official vendor advisories, security bulletins, and patch information
2. Find affected packages, libraries, and software components with specific version information
3. Locate official fix releases, updates, and workarounds from vendors
4. Search package repositories (npm, PyPI, Maven Central, NuGet, etc.) for affected packages
5. Find official security advisories from vendors like Microsoft, Adobe, Oracle, etc.
6. Include direct links to patches, updates, and security bulletins
7. EXCLUDE social media links, forums, and unofficial sources

OUTPUT FORMAT - GENERATE IN THIS EXACT STRUCTURE:

# ${cveId} vulnerability analysis and mitigation

## Overview
[Write a comprehensive paragraph describing the vulnerability. Include: what software/versions are affected, the type of vulnerability, when it was discovered, severity assessment, and key technical details. Reference official sources with links where found.]

## Technical details
[Provide detailed technical analysis of the vulnerability mechanism. Explain: the root cause, how the vulnerability works, attack vectors, exploitation techniques, technical implementation flaws, and specific code-level details. Include CVSS vector information and technical specifications.]

## Impact
[Describe the potential consequences if this vulnerability is exploited. Cover: what attackers can achieve, data exposure risks, system compromise possibilities, business impact, and real-world implications. Reference severity assessments and impact ratings.]

## Mitigation and workarounds
[Provide specific remediation guidance. Include: official patches and updates, version numbers to upgrade to, configuration changes, temporary workarounds, vendor recommendations, and step-by-step mitigation instructions. Include direct links to patches.]

## Affected packages and libraries
[List specific software components affected. Include: package names, version ranges (vulnerable and fixed), package manager ecosystems (npm, PyPI, Maven, etc.), dependency information, and repository links. Organize by ecosystem/platform.]

## Exploitation and threat landscape
[Analyze current threat activity. Cover: exploitation status in the wild, proof-of-concept availability, threat actor activity, active campaigns, EPSS probability context, and real-world attack observations.]

## References and discovered sources
[List all authoritative sources found during analysis. Organize into categories:
- **Official Vendor Advisories:** [URL] - [Description]
- **Security Patches:** [URL] - [Product/Version info]  
- **Package Advisories:** [URL] - [Package manager/ecosystem]
- **Security Bulletins:** [URL] - [Organization/Advisory ID]
- **Technical Analysis:** [URL] - [Analysis source]]

METADATA TO EXTRACT AND INCLUDE:
During your analysis, identify and extract these specific data points:
- Severity Level: [HIGH/MEDIUM/LOW based on CVSS]
- CNA Score: [CVSS score]
- High-profile Vulnerability: [Yes/No based on severity and exploitation]
- Affected Technologies: [Primary affected software/platform]
- Has Public Exploit: [Yes/No if exploit code available]
- Has CISA KEV Exploit: [Yes/No if in CISA KEV catalog]
- CISA KEV Release Date: [Date if applicable]
- CISA KEV Due Date: [Date if applicable]
- Exploitation Probability Percentile (EPSS): [Percentage]
- Exploitation Probability (EPSS): [Score/Rating]
- Affected packages and libraries: [Primary package/software name]

FORMATTING REQUIREMENTS:
- Use markdown headers (# for title, ## for sections)
- Write in clear, professional prose paragraphs
- Include specific version numbers, package names, and technical details
- Provide actionable recommendations with direct links
- Make each section comprehensive and focused
- Extract metadata accurately from available sources
- Write minimum 2500 words with detailed technical analysis
- Include real URLs when discovered through web search`;

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

    // Add Google Search tool for Gemini 2.0+ models
    if (isGemini2Plus) {
      requestBody.tools = [
        {
          google_search: {}
        }
      ];
    }

    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
    let response;
    let attempts = 0;
    const maxAttempts = 3; // Maximum number of retries

    while (attempts < maxAttempts) {
      try {
        response = await fetch(apiUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(requestBody)
        });

        if (response.ok) {
          break; // Successful response, exit loop
        }

        const errorData = await response.json().catch(() => ({}));

        if (response.status === 429) {
          attempts++;
          const retryDelayInfo = errorData.error?.details?.find(d => d['@type']?.includes('RetryInfo'))?.retryDelay;
          let waitTime = retryDelayInfo ? parseInt(retryDelayInfo.replace('s', '')) : 60;

          // Ensure waitTime is a reasonable number, default to 60 if parsing fails or is too short
          if (isNaN(waitTime) || waitTime <= 0) {
            waitTime = 60;
          }

          // Cap wait time to avoid excessively long waits, e.g., 5 minutes
          waitTime = Math.min(waitTime, 300);


          if (attempts >= maxAttempts) {
            throw new Error(`Rate limit exceeded after ${maxAttempts} attempts. Last error: ${errorData.error?.message || 'Too Many Requests'}. Please wait or upgrade your Gemini API plan.`);
          }

          console.warn(`Rate limit hit (attempt ${attempts}/${maxAttempts}). Waiting ${waitTime}s before retry...`);
          // Optionally, notify the user about the delay
          // addNotification({ type: 'warning', title: 'Rate Limit Hit', message: `Experiencing high load. Retrying in ${waitTime}s... (Attempt ${attempts}/${maxAttempts})` });

          await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
          continue; // Retry the fetch
        }

        // Handle other non-retryable errors
        if (response.status === 503) {
          throw new Error(`Model is currently overloaded. This is temporary - please try again in 30-60 seconds. Consider switching to a different model in settings.`);
        }
        if (response.status === 400) {
          throw new Error(`Invalid request. Please check your API key and model selection in settings.`);
        }
        if (response.status === 401 || response.status === 403) {
          throw new Error(`Authentication failed. Please verify your Gemini API key in settings.`);
        }
        throw new Error(`AI API error: ${response.status} - ${errorData.error?.message || 'Unknown error'}`);

      } catch (error) {
        // Network errors or errors from throw new Error()
        if (attempts >= maxAttempts -1) { // If it's a network error on the last attempt, or any thrown error
            throw error; // Re-throw the caught error if max attempts reached or it's not a 429
        }
        // For network errors before max attempts, could implement a shorter, fixed retry delay
        console.error(`Fetch error (attempt ${attempts + 1}/${maxAttempts}):`, error);
        attempts++;
        await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5s for general network issues
      }
    }

    if (!response || !response.ok) {
      // This should ideally be caught by the loop's error handling, but as a fallback:
      throw new Error('Failed to fetch AI analysis after multiple retries.');
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

    // Extract discovered sources from the analysis
    const discoveredSources = extractSourcesFromAnalysis(analysisText);
    
    // Store the enhanced analysis in RAG database
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
      webGrounded: isGemini2Plus,
      enhancedSources: vulnerability.enhancedSources || [],
      discoveredSources: discoveredSources,
      model: model,
      analysisTimestamp: new Date().toISOString()
    };
    
  } catch (error) {
    console.error('Enhanced RAG Analysis Error:', error);
    
    return {
      analysis: `**${error.message.includes('Rate limit') ? 'Rate Limit Exceeded' : error.message.includes('overloaded') ? 'Model Overloaded' : 'API Error'} - Gemini AI**

${error.message.includes('overloaded') ? `The Gemini model is currently experiencing high demand and is temporarily overloaded.

**Quick Solutions:**

**1. Wait and Retry (Recommended)**
- Wait 30-60 seconds and try again
- Model capacity usually recovers quickly
- This is a temporary issue, not a quota problem

**2. Switch Models**
- Try "Gemini 1.5 Flash" (usually less congested)
- Or "Gemini Pro" for basic analysis
- Change model in settings and retry

**3. Try Different Times**
- Peak usage hours can cause overloading
- Early morning or late evening often work better
- Weekends typically have less traffic` : error.message.includes('Rate limit') ? `You have exceeded your current quota for the Gemini API.

**Rate Limit Details:**
${error.message}

**Solutions:**

**1. Wait and Retry (Free Option)**
- Wait 1-2 minutes and try again
- The free tier resets quotas periodically
- Consider using shorter prompts to reduce token usage

**2. Upgrade API Plan (Recommended)**
- Visit: https://ai.google.dev/pricing
- Pay-as-you-go plans offer much higher quotas
- Starting at $0.000125 per 1K input tokens
- No daily limits on paid plans

**3. Alternative Models**
- Try switching to "Gemini 1.5 Flash" in settings (uses fewer tokens)
- Gemini Pro has lower quotas than Gemini 2.5 Flash` : `An error occurred while connecting to the Gemini AI service.

**Error Details:**
${error.message}

**Troubleshooting Steps:**

**1. Check API Key**
- Verify your Gemini API key in settings
- Ensure the key is valid and active
- Get a new key at: https://aistudio.google.com/app/apikey

**2. Try Different Model**
- Switch to "Gemini 1.5 Flash" or "Gemini Pro"
- Some models may be more available than others

**3. Check Network Connection**
- Ensure stable internet connection
- Try refreshing the page`}

**Manual Analysis Resources:**
- Official NVD details: https://nvd.nist.gov/vuln/detail/${cveId}
- MITRE CVE database: https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}
- FIRST EPSS: https://api.first.org/data/v1/epss?cve=${cveId}
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

**Status:** ${error.message.includes('overloaded') ? 'Model temporarily overloaded - retry in 1 minute' : error.message.includes('Rate limit') ? 'Quota exceeded - wait or upgrade plan' : 'API connection issue'}`,
      ragUsed: false,
      ragDocuments: 0,
      ragSources: [],
      webGrounded: false,
      enhancedSources: vulnerability.enhancedSources || [],
      discoveredSources: [],
      error: error.message.includes('overloaded') ? 'Model overloaded' : error.message.includes('Rate limit') ? 'Rate limit exceeded' : 'API error',
      isTemporary: error.message.includes('overloaded') || error.message.includes('Rate limit')
    };
  }
};

// Function to extract sources from AI analysis
const extractSourcesFromAnalysis = (analysisText) => {
  const sources = [];
  
  // Look for URLs in the analysis text
  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/g;
  const urls = analysisText.match(urlRegex) || [];
  
  // Filter out social media and extract relevant sources
  const relevantSources = urls.filter(url => {
    const domain = url.toLowerCase();
    return !domain.includes('twitter.com') && 
           !domain.includes('facebook.com') && 
           !domain.includes('linkedin.com') && 
           !domain.includes('instagram.com') && 
           !domain.includes('youtube.com') &&
           !domain.includes('reddit.com');
  });

  // Parse sources from the analysis sections
  const lines = analysisText.split('\n');
  let currentSection = '';
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    
    if (line.includes('Official Vendor Advisories:') || 
        line.includes('Patches and Fixes:') || 
        line.includes('Affected Packages:') || 
        line.includes('Security Bulletins:')) {
      currentSection = line;
      continue;
    }
    
    // Extract structured source information
    if (line.startsWith('- ') && line.includes('http')) {
      const urlMatch = line.match(/https?:\/\/[^\s<>"{}|\\^`[\]]+/);
      if (urlMatch) {
        const url = urlMatch[0];
        const description = line.replace(/- /, '').replace(url, '').replace(/[:\-]/g, '').trim();
        
        sources.push({
          url: url,
          description: description || 'Security Advisory',
          category: currentSection.replace(':', '').trim() || 'General',
          source: extractDomainFromUrl(url)
        });
      }
    }
  }
  
  // Add remaining URLs as general references
  relevantSources.forEach(url => {
    if (!sources.some(s => s.url === url)) {
      sources.push({
        url: url,
        description: 'Security Reference',
        category: 'General',
        source: extractDomainFromUrl(url)
      });
    }
  });
  
  return sources;
};

// Helper function to extract domain from URL
const extractDomainFromUrl = (url) => {
  try {
    const domain = new URL(url).hostname;
    return domain.replace('www.', '');
  } catch {
    return 'Unknown';
  }
};

// Main vulnerability data fetching function
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
      kevResult
    ] = await Promise.allSettled([
      fetchCVEDataFromNVD(cveId, setLoadingSteps, apiKeys.nvd),
      fetchEPSSData(cveId, setLoadingSteps),
      fetchKEVData(cveId, setLoadingSteps)
    ]);
    
    const cve = cveResult.status === 'fulfilled' ? cveResult.value : null;
    const epss = epssResult.status === 'fulfilled' ? epssResult.value : null;
    const kev = kevResult.status === 'fulfilled' ? kevResult.value : null;
    
    if (!cve) {
      throw new Error(`Failed to fetch CVE data for ${cveId}`);
    }
    
    setLoadingSteps(prev => [...prev, `✅ Comprehensive RAG-enhanced analysis complete for ${cveId}`]);
    
    const enhancedSources = ['NVD'];
    if (epss) enhancedSources.push('EPSS');
    if (kev) enhancedSources.push('KEV');
    
    return {
      cve,
      epss,
      kev,
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
  const { addNotification } = useContext(AppContext); // Get addNotification from context
  const [localSettings, setLocalSettings] = useState(settings);
  const [showGeminiKey, setShowGeminiKey] = useState(false);
  const [showNvdKey, setShowNvdKey] = useState(false);
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
      addNotification({ type: 'error', title: 'API Key Missing', message: 'Please enter a Gemini API key to test connection.' });
      return;
    }

    setTestingConnection(true);
    try {
      const testPrompt = 'Test connection - respond with "Connection successful"';
      // Using a generally available model for connection testing to avoid issues with specific model access
      const testModel = 'gemini-pro';
      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${testModel}:generateContent?key=${localSettings.geminiApiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: testPrompt }] }],
          generationConfig: { candidateCount: 1 } // Ensure candidateCount is set
        })
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.candidates && data.candidates[0].content.parts[0].text.includes("Connection successful")) {
          addNotification({ type: 'success', title: 'Connection Test', message: 'Gemini AI connection successful!' });
        } else {
           throw new Error('Unexpected response from API.');
        }
      } else {
         const errorData = await response.json().catch(() => ({}));
        throw new Error(`HTTP ${response.status}: ${errorData.error?.message || 'Failed to connect'}`);
      }
    } catch (error) {
      addNotification({ type: 'error', title: 'Connection Test Failed', message: error.message });
    } finally {
      setTestingConnection(false);
    }
  };

  if (!isOpen) return null;

  const inputGroupStyle = {
    background: settings.darkMode ? colors.dark.background : colors.light.background, // Slightly different background for input groups
    padding: '20px',
    borderRadius: '12px', // Consistent radius
    border: `1px solid ${styles.appContainer.border}`,
    marginBottom: '24px' // Space between groups
  };

  const sectionTitleStyle = {
    margin: '0 0 16px 0', // Adjusted margin
    color: styles.appContainer.primaryText, // Themed color
    fontSize: '1.1rem', // Adjusted size
    fontWeight: '600', // Adjusted weight
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    paddingBottom: '10px',
    borderBottom: `1px solid ${styles.appContainer.border}`
  };

  const eyeButtonStyle = {
    position: 'absolute',
    right: '12px',
    top: '50%',
    transform: 'translateY(-50%)',
    background: 'transparent', // Transparent background
    border: 'none',
    cursor: 'pointer',
    color: styles.appContainer.secondaryText, // Themed color for icon
    padding: '4px' // Add some padding for easier click
  };

  const checkboxLabelStyle = {
    ...styles.label,
    display: 'flex',
    alignItems: 'center',
    gap: '10px', // Consistent gap
    cursor: 'pointer', // Make label clickable for checkbox
  };

  const checkboxStyle = {
    width: '16px', // Custom size
    height: '16px', // Custom size
    accentColor: colors.blue, // Themed accent color
    margin: 0, // Remove default margin
  };


  return (
    <div style={styles.modal}>
      <div style={styles.modalContent}>
        <div style={styles.modalHeader}>
          <h3 style={styles.modalTitle}>RAG-Enhanced Platform Settings</h3>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 0 }}>
            <X size={24} color={styles.appContainer.primaryText} />
          </button>
        </div>

        <div style={{ display: 'grid', gap: '24px' }}> {/* Overall container for sections */}
          {/* AI & RAG Configuration Section */}
          <div style={inputGroupStyle}>
            <h4 style={sectionTitleStyle}>
              <Brain size={20} /> AI & RAG Configuration
            </h4>
            
            <div style={styles.formGroup}>
              <label htmlFor="geminiApiKey" style={styles.label}>Gemini API Key (Required for AI Analysis)</label>
              <div style={{ position: 'relative' }}>
                <input
                  id="geminiApiKey"
                  type={showGeminiKey ? 'text' : 'password'}
                  style={styles.input} // Uses themed input style
                  placeholder="Enter your Gemini API key"
                  value={localSettings.geminiApiKey || ''}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiApiKey: e.target.value }))}
                />
                <button style={eyeButtonStyle} onClick={() => setShowGeminiKey(!showGeminiKey)} aria-label={showGeminiKey ? "Hide API key" : "Show API key"}>
                  {showGeminiKey ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
              <div style={{ fontSize: '0.8rem', color: styles.appContainer.tertiaryText, marginTop: '8px' }}>
                Get your free API key from{' '}
                <a 
                  href="https://aistudio.google.com/app/apikey" 
                  target="_blank" 
                  rel="noopener noreferrer" 
                  style={{ color: colors.blue, textDecoration: 'underline' }} // Themed link
                >
                  Google AI Studio
                </a>.
              </div>
            </div>

            <div style={styles.formGroup}>
              <label htmlFor="geminiModel" style={styles.label}>Gemini Model Selection</label>
              <select
                id="geminiModel"
                style={styles.select} // Uses themed select style
                value={localSettings.geminiModel || 'gemini-2.5-flash'}
                onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiModel: e.target.value }))}
              >
                <option value="gemini-2.5-flash">Gemini 2.5 Flash (Latest, Web Search + RAG)</option>
                <option value="gemini-2.0-flash-exp">Gemini 2.0 Flash Exp (Web Search + RAG)</option>
                <option value="gemini-1.5-flash">Gemini 1.5 Flash (Fast RAG)</option>
                <option value="gemini-1.5-pro">Gemini 1.5 Pro (Deep RAG)</option>
                <option value="gemini-pro">Gemini Pro (Standard RAG)</option>
              </select>
            </div>

            <button
              onClick={testGeminiConnection}
              disabled={testingConnection || !localSettings.geminiApiKey}
              style={{
                ...styles.button,
                ...styles.buttonSecondary, // Themed secondary button
                // opacity inherited from disabled state in styles.button
              }}
            >
              {testingConnection ? <Loader2 size={18} className="animate-spin" /> : <Settings size={18} />} {/* Changed icon */}
              Test AI Connection
            </button>
          </div>

          {/* Data Source & Interface Configuration Section */}
          <div style={inputGroupStyle}>
            <h4 style={sectionTitleStyle}>
              <Database size={20} /> Data Source & Interface
            </h4>
            
            <div style={styles.formGroup}>
              <label htmlFor="nvdApiKey" style={styles.label}>NVD API Key (Optional - Higher Rate Limits)</label>
              <div style={{ position: 'relative' }}>
                <input
                  id="nvdApiKey"
                  type={showNvdKey ? 'text' : 'password'}
                  style={styles.input} // Uses themed input style
                  placeholder="Enter your NVD API key"
                  value={localSettings.nvdApiKey || ''}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, nvdApiKey: e.target.value }))}
                />
                <button style={eyeButtonStyle} onClick={() => setShowNvdKey(!showNvdKey)} aria-label={showNvdKey ? "Hide API key" : "Show API key"}>
                  {showNvdKey ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            <div style={styles.formGroup}>
              <label htmlFor="darkModeToggle" style={checkboxLabelStyle}>
                <input
                  id="darkModeToggle"
                  type="checkbox"
                  checked={localSettings.darkMode || false}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, darkMode: e.target.checked }))}
                  style={checkboxStyle}
                />
                Dark Mode Interface
              </label>
            </div>

            <div style={styles.formGroup}>
              <label htmlFor="enableRagToggle" style={checkboxLabelStyle}>
                <input
                  id="enableRagToggle"
                  type="checkbox"
                  checked={localSettings.enableRAG !== false} // Handles undefined case
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, enableRAG: e.target.checked }))}
                  style={checkboxStyle}
                />
                Enable RAG-Enhanced Analysis
              </label>
              <div style={{ fontSize: '0.8rem', color: styles.appContainer.tertiaryText, marginTop: '6px', marginLeft: '26px' }}> {/* Adjusted margin */}
                Use vector database and semantic search for contextual analysis.
              </div>
            </div>
          </div>
        </div>

        {/* Modal Actions Footer */}
        <div style={{
            display: 'flex',
            gap: '12px', // Reduced gap
            justifyContent: 'flex-end',
            paddingTop: '24px',
            marginTop: '16px', // Added margin top
            borderTop: `1px solid ${styles.appContainer.border}` // Themed border
        }}>
          <button
            style={{ ...styles.button, ...styles.buttonSecondary }} // Themed secondary button
            onClick={onClose}
          >
            Cancel
          </button>
          <button
            style={{ ...styles.button, ...styles.buttonPrimary }} // Themed primary button
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

  // useEffect to apply body styles based on dark mode
  useEffect(() => {
    document.body.style.backgroundColor = styles.appContainer.backgroundColor;
    document.body.style.color = styles.appContainer.color;
    document.body.style.fontFamily = styles.appContainer.fontFamily;
  }, [settings.darkMode, styles.appContainer]);

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
        nvd: settings.nvdApiKey
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
          marginTop: '32px', // Increased margin
          fontSize: '0.875rem', // Slightly larger
          color: styles.appContainer.color // Use themed text color
        }}>
          {[
            { icon: <Brain size={16} color={colors.blue} />, text: 'RAG-Enhanced AI' },
            { icon: <Database size={16} color={colors.purple} />, text: 'Knowledge Retrieval' },
            { icon: <Globe size={16} color={colors.green} />, text: 'Real-time Intelligence' }
          ].map((item, index) => (
            <div key={index} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 12px', background: settings.darkMode ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.02)', borderRadius: '8px', margin: '4px' }}>
              {item.icon}
              <span style={{ fontWeight: '500' }}>{item.text}</span>
            </div>
          ))}
        </div>

        {searchHistory.length > 0 && (
          <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', flexWrap: 'wrap', marginTop: '28px' }}>
            <span style={{ fontSize: '0.875rem', color: styles.appContainer.color, fontWeight: '500', alignSelf: 'center' }}>
              Recent:
            </span>
            {searchHistory.map((cve, index) => (
              <button
                key={index}
                onClick={() => setSearchTerm(cve)}
                style={{
                  ...styles.button, // Inherit base button styles
                  padding: '6px 12px', // Slightly larger padding
                  background: settings.darkMode ? `rgba(${hexToRgb(colors.blue)}, 0.15)` : `rgba(${hexToRgb(colors.blue)}, 0.1)`,
                  border: `1px solid rgba(${hexToRgb(colors.blue)}, 0.3)`,
                  borderRadius: '8px', // Consistent radius
                  fontSize: '0.8rem', // Standardized size
                  color: colors.blue,
                  fontWeight: '500',
                  transition: 'all 0.2s ease',
                  '&:hover': {
                    background: settings.darkMode ? `rgba(${hexToRgb(colors.blue)}, 0.25)` : `rgba(${hexToRgb(colors.blue)}, 0.2)`,
                    borderColor: `rgba(${hexToRgb(colors.blue)}, 0.5)`,
                  }
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
            marginBottom: '10px', // Increased margin
            fontSize: '0.875rem', // Slightly larger font
            color: styles.appContainer.secondaryText, // Use themed secondary text
            display: 'flex',
            alignItems: 'center',
            gap: '10px' // Increased gap
          }}>
            <div style={{ // Custom animated check or pulse icon could go here
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: colors.blue, // Use themed blue
              flexShrink: 0,
              opacity: 0.7 + (index / loadingSteps.length) * 0.3 // Subtle opacity animation based on step
            }} />
            <span>{step}</span> {/* Wrapped step in span for potential future styling */}
          </div>
        ))}
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
        settings.geminiModel || 'gemini-2.5-flash',
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
        padding: '32px', // Adjusted padding
        boxShadow: settings.darkMode ? `0 8px 32px ${colors.dark.shadow}` : `0 4px 20px ${colors.light.shadow}`,
        border: `1px solid ${styles.appContainer.border}` // Use themed border
      }}>
        {/* Header Section */}
        <div style={{
          marginBottom: '24px', // Reduced margin
          paddingBottom: '24px', // Reduced padding
          borderBottom: `1px solid ${styles.appContainer.border}` // Use themed border
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h1 style={{
              fontSize: '2rem', // Slightly reduced size
              fontWeight: '700', // Adjusted weight
              background: `linear-gradient(135deg, ${colors.blue} 0%, ${colors.purple} 100%)`,
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              margin: 0,
              lineHeight: 1.2,
            }}>
              {vulnerability.cve?.id || 'Unknown CVE'}
            </h1>
            
            <div style={{ display: 'flex', gap: '12px' }}>
              <button
                onClick={onRefresh}
                style={{
                  ...styles.button,
                  ...styles.buttonSecondary,
                  // padding: '8px 16px' // Padding from base button is fine
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
                  // padding: '8px 16px' // Padding from base button is fine
                }}
              >
                <Download size={16} />
                Export
              </button>
            </div>
          </div>

          {/* Badges Row */}
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{
              ...styles.badge,
              ...getSeverityStyle(severity),
              fontSize: '0.85rem', // Adjusted size
              padding: '6px 12px' // Adjusted padding
            }}>
              {severity} - {cvssScore?.toFixed(1) || 'N/A'}
            </span>
            
            {vulnerability.kev && (
              <span style={{
                ...styles.badge,
                ...styles.badgeCritical, // Uses themed critical color
                // fontSize: '0.8rem', // Inherits from styles.badge
                // padding: '6px 12px' // Inherits from styles.badge
              }}>
                CISA KEV
              </span>
            )}
            
            {vulnerability.epss?.epss > 0.5 && (
              <span style={{
                ...styles.badge,
                background: `rgba(${hexToRgb(colors.yellow)}, 0.15)`,
                color: colors.yellow,
                border: `1px solid rgba(${hexToRgb(colors.yellow)}, 0.3)`,
                // fontSize: '0.8rem',
                // padding: '6px 12px'
              }}>
                HIGH EPSS: {(vulnerability.epss.epss * 100).toFixed(1)}%
              </span>
            )}

            {vulnerability.ragEnhanced && (
              <span style={{
                ...styles.badge,
                background: `rgba(${hexToRgb(colors.purple)}, 0.15)`, // Use purple for RAG
                color: colors.purple,
                border: `1px solid rgba(${hexToRgb(colors.purple)}, 0.3)`,
                // fontSize: '0.8rem',
                // padding: '6px 12px'
              }}>
                <Database size={12} style={{ marginRight: '6px' }} /> {/* Increased margin */}
                RAG ENHANCED
              </span>
            )}
          </div>
        </div>

        {/* Tabs */}
        <div style={{
          display: 'flex',
          borderBottom: `1px solid ${styles.appContainer.border}`, // Thinner border
          marginBottom: '24px', // Reduced margin
          gap: '4px', // Reduced gap for tighter tabs
          flexWrap: 'wrap'
        }}>
          {['overview', 'technical', 'ai-analysis'].map((tab) => (
            <button // Changed div to button for better accessibility
              key={tab}
              style={{
                padding: '12px 18px', // Adjusted padding
                cursor: 'pointer',
                border: 'none', // Remove button default border
                borderBottom: activeTab === tab ? `3px solid ${colors.blue}` : '3px solid transparent',
                fontSize: '0.9rem', // Adjusted size
                fontWeight: '600',
                color: activeTab === tab ? colors.blue : styles.appContainer.secondaryText, // Use themed colors
                transition: 'all 0.2s ease-in-out',
                borderRadius: '6px 6px 0 0', // Softer radius for top corners
                background: activeTab === tab
                  ? (settings.darkMode ? `rgba(${hexToRgb(colors.blue)}, 0.1)` : `rgba(${hexToRgb(colors.blue)}, 0.05)`)
                  : 'transparent',
                display: 'inline-flex', // For icon alignment
                alignItems: 'center',
                gap: '8px',
                outline: 'none', // Remove focus outline if not desired, or style it
                ':hover': { // Add hover effect
                   color: colors.blue,
                   background: settings.darkMode ? `rgba(${hexToRgb(colors.blue)}, 0.15)` : `rgba(${hexToRgb(colors.blue)}, 0.1)`,
                }
              }}
              onClick={() => setActiveTab(tab)}
              role="tab" // ARIA role
              aria-selected={activeTab === tab} // ARIA selected state
            >
              {tab === 'overview' && <Info size={16} />}
              {tab === 'technical' && <BarChart3 size={16} />}
              {tab === 'ai-analysis' && <Brain size={16} />}
              {tab === 'ai-analysis' ? 'RAG Analysis' : tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div style={{ paddingTop: '8px' }}> {/* Added small padding top */}
          {activeTab === 'overview' && (
            <div>
              <h2 style={{
                fontSize: '1.375rem', // Adjusted size
                fontWeight: '700',
                color: styles.appContainer.primaryText, // Use themed color
                marginBottom: '16px' // Reduced margin
              }}>
                Vulnerability Overview
              </h2>
              
              <div style={{
                fontSize: '0.95rem', // Adjusted size
                lineHeight: '1.65', // Adjusted line height
                color: styles.appContainer.secondaryText, // Use themed color
                marginBottom: '24px' // Reduced margin
              }}>
                <p style={{ margin: 0 }}> {/* Removed nested p and font size override */}
                  {vulnerability.cve?.description || 'No description available.'}
                </p>
              </div>

              {/* EPSS and KEV sections - using a card-like structure */}
              {[
                vulnerability.epss && {
                  title: 'Exploitation Probability (EPSS)',
                  icon: <Target size={24} color={vulnerability.epss.epss > 0.5 ? colors.yellow : colors.green} />,
                  bgColor: vulnerability.epss.epss > 0.5 ? `rgba(${hexToRgb(colors.yellow)}, 0.1)` : `rgba(${hexToRgb(colors.green)}, 0.1)`,
                  borderColor: vulnerability.epss.epss > 0.5 ? `rgba(${hexToRgb(colors.yellow)}, 0.3)` : `rgba(${hexToRgb(colors.green)}, 0.3)`,
                  content: (
                    <>
                      <div style={{ fontWeight: '700', fontSize: '1.05rem', color: styles.appContainer.primaryText }}>
                        EPSS Score: {(vulnerability.epss.epss * 100).toFixed(2)}%
                      </div>
                      <div style={{ fontSize: '0.85rem', color: styles.appContainer.tertiaryText }}>
                        Percentile: {vulnerability.epss.percentile?.toFixed(1) || 'N/A'}
                      </div>
                      <p style={{ margin: '12px 0 0 0', fontSize: '0.9rem', color: styles.appContainer.secondaryText }}>
                        {vulnerability.epss.epss > 0.5
                          ? 'This vulnerability has a HIGH probability of exploitation. Immediate patching recommended.'
                          : vulnerability.epss.epss > 0.1
                            ? 'This vulnerability has a MODERATE probability of exploitation. Monitor for patches and updates.'
                            : 'This vulnerability has a LOW probability of exploitation, but still requires attention.'}
                      </p>
                    </>
                  )
                },
                vulnerability.kev && {
                  title: 'CISA Known Exploited Vulnerability',
                  icon: <AlertTriangle size={24} color={colors.red} />,
                  bgColor: `rgba(${hexToRgb(colors.red)}, 0.1)`,
                  borderColor: `rgba(${hexToRgb(colors.red)}, 0.3)`,
                  content: (
                    <>
                      <span style={{ fontWeight: '700', fontSize: '1.05rem', color: colors.red }}>
                        ACTIVE EXPLOITATION CONFIRMED
                      </span>
                      <div style={{ display: 'grid', gap: '8px', marginTop: '12px', fontSize: '0.9rem', color: styles.appContainer.secondaryText }}>
                        <div><strong>Vendor/Product:</strong> {vulnerability.kev.vendorProject} / {vulnerability.kev.product}</div>
                        <div><strong>Vulnerability Name:</strong> {vulnerability.kev.vulnerabilityName}</div>
                        <div><strong>Required Action:</strong> {vulnerability.kev.requiredAction}</div>
                        <div><strong>Due Date:</strong> {vulnerability.kev.dueDate}</div>
                        {vulnerability.kev.knownRansomwareCampaignUse === 'Known' && (
                          <div style={{ color: colors.red, fontWeight: '600' }}>
                            ⚠️ Known to be used in ransomware campaigns
                          </div>
                        )}
                      </div>
                    </>
                  )
                }
              ].filter(Boolean).map((item, index) => (
                <div key={index} style={{ marginBottom: '24px' }}>
                  <h3 style={{ fontSize: '1.125rem', fontWeight: '600', marginBottom: '12px', color: styles.appContainer.primaryText }}>
                    {item.title}
                  </h3>
                  <div style={{
                    background: item.bgColor,
                    border: `1px solid ${item.borderColor}`,
                    borderRadius: '12px', // Consistent radius
                    padding: '20px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: item.title.includes('EPSS') ? '12px' : '16px' }}>
                      {item.icon}
                      {item.title.includes('EPSS') ? <div>{item.content}</div> : item.content}
                    </div>
                    {item.title.includes('EPSS') ? null : null /* Content moved inside for KEV */}
                  </div>
                </div>
              ))}

              {/* RAG Analysis Button */}
              <div style={{ 
                marginTop: '32px', // Adjusted margin
                paddingTop: '24px', // Adjusted padding
                borderTop: `1px solid ${styles.appContainer.border}`, // Use themed border
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
              
              {/* AI-Generated Technical Analysis Section */}
              <div style={{ marginBottom: '32px' }}>
                <div style={{
                  background: settings.darkMode ? '#334155' : '#f8fafc',
                  border: settings.darkMode ? '1px solid #475569' : '1px solid #e2e8f0',
                  borderRadius: '12px',
                  padding: '20px'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                    <Brain size={24} color="#3b82f6" />
                    <div>
                      <div style={{ fontWeight: '600', fontSize: '1rem', color: settings.darkMode ? '#f1f5f9' : '#0f172a' }}>
                        AI Technical Analysis Required
                      </div>
                      <div style={{ fontSize: '0.85rem', color: settings.darkMode ? '#cbd5e1' : '#475569' }}>
                        Generate comprehensive technical analysis with RAG-enhanced intelligence
                      </div>
                    </div>
                  </div>
                  <div style={{ fontSize: '0.9rem', color: settings.darkMode ? '#94a3b8' : '#64748b' }}>
                    The AI will provide detailed technical analysis including:
                    <ul style={{ margin: '8px 0 0 20px', paddingLeft: 0 }}>
                      <li>Attack vectors and exploitation techniques</li>
                      <li>Affected packages and version ranges</li>
                      <li>Proof-of-concept availability</li>
                      <li>Patch analysis and remediation steps</li>
                      <li>Technical countermeasures</li>
                      <li>Code examples and technical indicators</li>
                    </ul>
                  </div>
                  
                  <button
                    style={{
                      ...styles.button,
                      ...styles.buttonPrimary,
                      opacity: aiLoading ? 0.7 : 1,
                      marginTop: '16px'
                    }}
                    onClick={generateRAGAnalysis}
                    disabled={aiLoading || !settings.geminiApiKey}
                  >
                    {aiLoading ? (
                      <>
                        <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} />
                        Generating Technical Analysis...
                      </>
                    ) : (
                      <>
                        <Brain size={18} />
                        Generate Technical Analysis
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Display AI Technical Analysis if available */}
              {aiAnalysis && (
                <div style={{ marginBottom: '24px' }}>
                  <h3 style={{ fontSize: '1.125rem', fontWeight: '600', marginBottom: '12px', color: styles.appContainer.primaryText }}>
                    AI-Generated Technical Analysis
                  </h3>
                  <div style={{
                    background: styles.appContainer.surface, // Use themed surface
                    border: `1px solid ${styles.appContainer.border}`, // Use themed border
                    borderRadius: '12px', // Consistent radius
                    padding: '20px', // Adjusted padding
                    whiteSpace: 'pre-wrap', // Keep for markdown-like text
                    lineHeight: '1.65', // Adjusted line height
                    fontSize: '0.9rem', // Adjusted size
                    color: styles.appContainer.secondaryText, // Use themed text color
                    maxHeight: '500px', // Add max height for long content
                    overflowY: 'auto', // Add scroll for overflow
                  }}>
                    {aiAnalysis.analysis}
                  </div>
                </div>
              )}

              {/* CVSS Metrics Section - Unified Card Structure */}
              {[
                vulnerability.cve?.cvssV3 && {
                  version: 'v3.1',
                  metrics: vulnerability.cve.cvssV3,
                  baseKeys: ['baseScore', 'attackVector', 'attackComplexity', 'privilegesRequired', 'userInteraction', 'scope'],
                  impactKeys: ['confidentialityImpact', 'integrityImpact', 'availabilityImpact', 'exploitabilityScore', 'impactScore']
                },
                vulnerability.cve?.cvssV2 && {
                  version: 'v2.0',
                  metrics: vulnerability.cve.cvssV2,
                  baseKeys: ['baseScore', 'accessVector', 'accessComplexity', 'authentication'],
                  impactKeys: [] // CVSSv2 does not separate impact like v3
                }
              ].filter(Boolean).map((cvssInfo, index) => (
                <div key={index} style={{ marginBottom: '24px' }}>
                  <h3 style={{ fontSize: '1.125rem', fontWeight: '600', marginBottom: '12px', color: styles.appContainer.primaryText }}>
                    CVSS {cvssInfo.version} Metrics
                  </h3>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
                    {/* Base Metrics Card */}
                    <div style={{
                      background: styles.appContainer.surface,
                      borderRadius: '12px',
                      padding: '20px',
                      border: `1px solid ${styles.appContainer.border}`
                    }}>
                      <h4 style={{ margin: '0 0 16px 0', fontSize: '1rem', fontWeight: '600', color: styles.appContainer.primaryText }}>Base Metrics</h4>
                      <div style={{ display: 'grid', gap: '10px' }}>
                        {cvssInfo.baseKeys.map(key => (
                          <div key={key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: '0.8rem', color: styles.appContainer.tertiaryText, textTransform: 'capitalize' }}>{key.replace(/([A-Z])/g, ' $1')}:</span>
                            <span style={{ fontSize: '0.8rem', fontWeight: '600', color: styles.appContainer.secondaryText }}>{cvssInfo.metrics[key]}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Impact Metrics Card (Only for CVSSv3) */}
                    {cvssInfo.impactKeys.length > 0 && (
                       <div style={{
                        background: styles.appContainer.surface,
                        borderRadius: '12px',
                        padding: '20px',
                        border: `1px solid ${styles.appContainer.border}`
                      }}>
                        <h4 style={{ margin: '0 0 16px 0', fontSize: '1rem', fontWeight: '600', color: styles.appContainer.primaryText }}>Impact Metrics</h4>
                        <div style={{ display: 'grid', gap: '10px' }}>
                          {cvssInfo.impactKeys.map(key => (
                            <div key={key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <span style={{ fontSize: '0.8rem', color: styles.appContainer.tertiaryText, textTransform: 'capitalize' }}>{key.replace(/([A-Z])/g, ' $1')}:</span>
                              <span style={{ fontSize: '0.8rem', fontWeight: '600', color: styles.appContainer.secondaryText }}>{cvssInfo.metrics[key]}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Vector String */}
                  {cvssInfo.metrics.vectorString && (
                    <div style={{ marginTop: '20px' }}>
                      <h4 style={{ margin: '0 0 10px 0', fontSize: '1rem', fontWeight: '600', color: styles.appContainer.primaryText }}>Vector String</h4>
                      <div style={{
                        background: settings.darkMode ? colors.dark.background : colors.light.background, // Slightly different background
                        border: `1px solid ${styles.appContainer.border}`,
                        borderRadius: '8px',
                        padding: '12px 16px',
                        fontFamily: 'monospace',
                        fontSize: '0.85rem', // Adjusted size
                        color: styles.appContainer.secondaryText,
                        wordBreak: 'break-all',
                        lineHeight: 1.5,
                      }}>
                        {cvssInfo.metrics.vectorString}
                      </div>
                    </div>
                  )}
                </div>
              ))}
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
                <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}> {/* Increased gap */}
                  {aiAnalysis?.webGrounded && (
                    <span style={{
                      ...styles.badge, // Inherit base badge style
                      background: `rgba(${hexToRgb(colors.green)}, 0.15)`,
                      color: colors.green,
                      border: `1px solid rgba(${hexToRgb(colors.green)}, 0.3)`,
                    }}>
                      <Globe size={12} style={{ marginRight: '6px' }} /> {/* Increased margin */}
                      REAL-TIME
                    </span>
                  )}
                  {aiAnalysis?.ragUsed && (
                    <span style={{
                      ...styles.badge, // Inherit base badge style
                      background: `rgba(${hexToRgb(colors.purple)}, 0.15)`,
                      color: colors.purple,
                      border: `1px solid rgba(${hexToRgb(colors.purple)}, 0.3)`,
                    }}>
                      <Database size={12} style={{ marginRight: '6px' }} /> {/* Increased margin */}
                      RAG ENHANCED
                    </span>
                  )}
                </div>
              </div>

              {/* Temporary Error/Rate Limit Message Styling */}
              {aiAnalysis?.isTemporary && (
                <div style={{
                  background: aiAnalysis.error === 'Model overloaded'
                    ? `rgba(${hexToRgb(colors.blue)}, 0.1)`
                    : `rgba(${hexToRgb(colors.yellow)}, 0.1)`,
                  border: `1px solid ${aiAnalysis.error === 'Model overloaded'
                    ? `rgba(${hexToRgb(colors.blue)}, 0.3)`
                    : `rgba(${hexToRgb(colors.yellow)}, 0.3)`}`,
                  borderRadius: '12px', // Consistent radius
                  padding: '16px 20px', // Adjusted padding
                  marginBottom: '20px' // Adjusted margin
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '10px' }}> {/* Reduced margin */}
                    {aiAnalysis.error === 'Model overloaded' ? (
                      <Activity size={20} color={colors.blue} />
                    ) : (
                      <AlertTriangle size={20} color={colors.yellow} />
                    )}
                    <span style={{ 
                      fontWeight: '600', 
                      fontSize: '0.95rem', // Adjusted size
                      color: aiAnalysis.error === 'Model overloaded' ? colors.blue : colors.yellow
                    }}>
                      {aiAnalysis.error === 'Model overloaded' ? 'Model Temporarily Overloaded' : 'API Rate Limit Exceeded'}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.875rem', color: styles.appContainer.secondaryText, lineHeight: 1.5 }}> {/* Themed color */}
                    {aiAnalysis.error === 'Model overloaded' 
                      ? 'High demand detected. Wait 30-60 seconds and retry, or switch to a different model in settings.'
                      : 'You\'ve hit API quota limits for the selected model. Wait and retry, or upgrade to a paid plan.'
                    }
                  </div>
                </div>
              )}
              
              {/* AI Analysis Content Display */}
              {aiAnalysis && !aiAnalysis.isTemporary ? ( // Only show if not a temporary error message
                <div>
                  <div style={{
                    background: styles.appContainer.surface, // Themed surface
                    border: `1px solid ${styles.appContainer.border}`, // Themed border
                    borderRadius: '12px', // Consistent radius
                    padding: '20px 24px', // Adjusted padding
                    whiteSpace: 'pre-wrap', // Keep for markdown-like text
                    lineHeight: '1.65', // Adjusted line height
                    fontSize: '0.9rem', // Adjusted size
                    color: styles.appContainer.secondaryText, // Themed text color
                    maxHeight: '600px', // Increased max height
                    overflowY: 'auto', // Scroll for overflow
                  }}>
                    {/* This is where more sophisticated Markdown rendering could go if the output format changes */}
                    {aiAnalysis.analysis}
                  </div>

                  {/* Metadata Section */}
                  <div style={{
                    background: settings.darkMode ? colors.dark.background : colors.light.background, // Slightly different background for contrast
                    border: `1px solid ${styles.appContainer.border}`,
                    borderRadius: '12px',
                    padding: '16px 20px',
                    marginTop: '20px', // Adjusted margin
                    fontSize: '0.8rem', // Adjusted size
                    color: styles.appContainer.tertiaryText, // Themed tertiary text
                    lineHeight: 1.6,
                  }}>
                    <div style={{ fontWeight: '600', marginBottom: '10px', color: styles.appContainer.secondaryText }}>
                      Enhanced Analysis Metadata:
                    </div>
                    <ul style={{ margin: 0, paddingLeft: '20px', listStyleType: "'• ' வெளியே" }}> {/* Custom bullet */}
                      <li>Data Sources: {aiAnalysis.enhancedSources?.join(', ') || 'Unknown'}</li>
                      {aiAnalysis.ragUsed && (
                        <>
                          <li>Knowledge Base: {aiAnalysis.ragDocuments} relevant security documents retrieved</li>
                          <li>RAG Sources: {aiAnalysis.ragSources?.slice(0,3).join(', ') || 'Multiple knowledge sources'}{aiAnalysis.ragSources?.length > 3 ? '...' : ''}</li>
                        </>
                      )}
                      {aiAnalysis.webGrounded && (
                        <li>Real-time Intelligence: Current threat landscape data via web search</li>
                      )}
                      <li>Model Used: {aiAnalysis.model || 'Gemini Pro'}</li>
                      <li>Generated On: {aiAnalysis.analysisTimestamp ? new Date(aiAnalysis.analysisTimestamp).toLocaleString() : 'Unknown'}</li>
                      {aiAnalysis.rateLimited && ( // This state might be part of 'isTemporary' now
                        <li>Status: <span style={{ color: colors.yellow, fontWeight: '600' }}>Rate Limited - Consider upgrading API plan</span></li>
                      )}
                    </ul>
                  </div>
                </div>
              ) : !aiAnalysis ? ( // Placeholder if no analysis and no temporary error
                <div style={{
                  textAlign: 'center',
                  padding: '48px 32px', // Adjusted padding
                  background: styles.appContainer.surface, // Themed surface
                  borderRadius: '12px', // Consistent radius
                  border: `1px solid ${styles.appContainer.border}` // Themed border
                }}>
                  <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
                    <Brain size={40} color={styles.appContainer.tertiaryText} />
                    <Database size={32} color={styles.appContainer.tertiaryText} />
                  </div>
                  <h3 style={{ margin: '0 0 10px 0', fontSize: '1.125rem', fontWeight: '600', color: styles.appContainer.primaryText }}>
                    RAG-Enhanced Analysis Not Generated
                  </h3>
                  <p style={{ margin: '0 0 20px 0', fontSize: '0.9rem', color: styles.appContainer.secondaryText, lineHeight: 1.5 }}>
                    Generate comprehensive security analysis using RAG-enhanced AI with contextual knowledge retrieval and real-time web intelligence.
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
        borderRadius: '16px', // Softer radius
        padding: '24px', // Adjusted padding
        boxShadow: settings.darkMode ? `0 8px 32px ${colors.dark.shadow}` : `0 4px 20px ${colors.light.shadow}`,
        border: `1px solid ${styles.appContainer.border}`, // Use themed border
        height: 'fit-content',
        position: 'sticky', // Make sidebar sticky
        top: '24px', // Add some top offset
      }}>
        {/* CVSS Score Circle */}
        <div style={{ textAlign: 'center', marginBottom: '28px' }}> {/* Adjusted margin */}
          <div 
            style={{
              width: '120px', // Slightly smaller
              height: '120px', // Slightly smaller
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 16px', // Adjusted margin
              background: `conic-gradient(from 0deg, ${getSeverityColor(cvssScore)} 0%, ${getSeverityColor(cvssScore)} ${(cvssScore / 10) * 100}%, ${settings.darkMode ? colors.dark.border : colors.light.border} ${(cvssScore / 10) * 100}%, ${settings.darkMode ? colors.dark.border : colors.light.border} 100%)`,
              boxShadow: `0 0 15px ${getSeverityColor(cvssScore)}33` // Added a subtle glow
            }}
          >
            <div style={{
              width: '90px', // Slightly smaller inner circle
              height: '90px', // Slightly smaller inner circle
              borderRadius: '50%',
              background: styles.appContainer.surface, // Use themed surface
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              border: `2px solid ${styles.appContainer.border}` // Inner border for definition
            }}>
              <div style={{
                fontSize: '1.625rem', // Adjusted size
                fontWeight: '700', // Bold
                color: styles.appContainer.primaryText // Themed text
              }}>
                {cvssScore?.toFixed(1) || 'N/A'}
              </div>
              <div style={{
                fontSize: '0.75rem', // Adjusted size
                color: styles.appContainer.secondaryText, // Themed text
                fontWeight: '500' // Medium weight
              }}>
                CVSS Score
              </div>
            </div>
          </div>
        </div>

        {/* Quick Stats */}
        <div style={{
          borderBottom: `1px solid ${styles.appContainer.border}`, // Themed border
          paddingBottom: '16px', // Adjusted padding
          marginBottom: '16px' // Adjusted margin
        }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: '600', marginBottom: '12px', color: styles.appContainer.secondaryText }}>
            Key Information
          </h3>
          <div style={{ display: 'grid', gap: '10px' }}> {/* Adjusted gap */}
            {[
              { label: 'Published', value: vulnerability.cve?.publishedDate ? formatDate(vulnerability.cve.publishedDate) : 'Unknown' },
              { label: 'Last Updated', value: vulnerability.lastUpdated ? formatDate(vulnerability.lastUpdated) : 'Unknown' },
              { label: 'Data Sources', value: vulnerability.enhancedSources?.length || 0 },
              { label: 'RAG Enhanced', value: vulnerability.ragEnhanced ? 'Yes' : 'No', color: vulnerability.ragEnhanced ? colors.purple : undefined }
            ].map(item => (
              <div key={item.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.8rem', color: styles.appContainer.tertiaryText, fontWeight: '500' }}>
                  {item.label}
                </span>
                <span style={{ fontSize: '0.8rem', color: item.color || styles.appContainer.secondaryText, fontWeight: '600' }}>
                  {item.value}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Sources */}
        <div style={{ marginBottom: '20px' }}> {/* Adjusted margin */}
          <h3 style={{
            fontSize: '0.95rem', // Consistent heading size
            fontWeight: '600',
            marginBottom: '12px', // Adjusted margin
            color: styles.appContainer.secondaryText // Themed color
          }}>
            <Activity size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} /> Data Sources
          </h3>
          
          <div style={{ display: 'grid', gap: '8px' }}>
            {vulnerability.enhancedSources?.map((source, index) => (
              <div key={index} style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px', // Adjusted gap
                padding: '8px 12px', // Adjusted padding
                background: styles.appContainer.surface, // Themed surface
                borderRadius: '8px', // Consistent radius
                border: `1px solid ${styles.appContainer.border}` // Themed border
              }}>
                <div style={{
                  minWidth: '20px', // Ensure consistent icon space
                  height: '20px', // Ensure consistent icon space
                  background: `rgba(${hexToRgb(colors.green)}, 0.15)`, // Themed green background
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <CheckCircle size={10} color={colors.green} /> {/* Themed green icon */}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '0.8rem', fontWeight: '600', color: styles.appContainer.secondaryText }}> {/* Themed text */}
                    {source}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* References */}
        {(vulnerability.cve?.references?.length > 0 || aiAnalysis?.discoveredSources?.length > 0) && (
          <div style={{ marginBottom: '20px' }}> {/* Adjusted margin */}
            <h3 style={{
              fontSize: '0.95rem', // Consistent heading size
              fontWeight: '600',
              marginBottom: '12px', // Adjusted margin
              color: styles.appContainer.secondaryText // Themed color
            }}>
              <ExternalLink size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} /> References
            </h3>
            
            <div style={{ display: 'grid', gap: '10px', maxHeight: '280px', overflowY: 'auto', paddingRight: '8px' }}> {/* Adjusted padding for scrollbar */}
              {/* AI Discovered Sources */}
              {aiAnalysis?.discoveredSources?.map((ref, index) => (
                <div key={`ai-${index}`} style={{
                  display: 'flex',
                  alignItems: 'flex-start', // Align icon with first line of text
                  gap: '10px', // Adjusted gap
                  padding: '10px 12px', // Adjusted padding
                  background: `rgba(${hexToRgb(colors.blue)}, ${settings.darkMode ? '0.15' : '0.1'})`, // Themed blue background
                  borderRadius: '8px', // Consistent radius
                  border: `1px solid rgba(${hexToRgb(colors.blue)}, 0.3)` // Themed blue border
                }}>
                  <div style={{
                    minWidth: '10px', // Ensure consistent icon space
                    height: '10px', // Ensure consistent icon space
                    background: colors.blue, // Solid blue for AI discovered
                    borderRadius: '50%',
                    marginTop: '4px', // Align with text
                    flexShrink: 0
                  }} />
                  <div style={{ flex: 1, overflow: 'hidden' }}> {/* Prevent long URLs from breaking layout */}
                    <a 
                      href={ref.url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      title={ref.url} // Add title for full URL on hover
                      style={{ 
                        color: colors.blue,
                        textDecoration: 'underline', // Explicitly underline links
                        fontSize: '0.75rem', // Adjusted size
                        fontWeight: '500',
                        lineHeight: '1.3', // Adjusted line height
                        display: 'block',
                        wordBreak: 'break-all', // Break long URLs
                        '&:hover': {
                          textDecoration: 'none', // Remove underline on hover if desired
                        }
                      }}
                    >
                      {ref.url.length > 45 ? `${ref.url.substring(0, 45)}...` : ref.url}
                    </a>
                    <div style={{ 
                      fontSize: '0.7rem', // Adjusted size
                      color: styles.appContainer.tertiaryText, // Themed tertiary text
                      marginTop: '3px', // Adjusted margin
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}>
                      {ref.category} - {ref.description}
                    </div>
                  </div>
                </div>
              ))}
              
              {/* Original CVE References */}
              {vulnerability.cve?.references?.slice(0, 8).map((ref, index) => (
                <div key={`cve-${index}`} style={{
                  display: 'flex',
                  alignItems: 'flex-start', // Align icon with first line of text
                  gap: '10px', // Adjusted gap
                  padding: '10px 12px', // Adjusted padding
                  background: styles.appContainer.surface, // Themed surface
                  borderRadius: '8px', // Consistent radius
                  border: `1px solid ${styles.appContainer.border}` // Themed border
                }}>
                  <ExternalLink size={14} color={styles.appContainer.tertiaryText} style={{ marginTop: '3px', flexShrink: 0 }} /> {/* Align icon */}
                  <div style={{ flex: 1, overflow: 'hidden' }}> {/* Prevent long URLs from breaking layout */}
                    <a 
                      href={ref.url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      title={ref.url} // Add title for full URL on hover
                      style={{ 
                        color: colors.blue, // Themed blue for links
                        textDecoration: 'underline', // Explicitly underline
                        fontSize: '0.75rem', // Adjusted size
                        fontWeight: '500',
                        lineHeight: '1.3', // Adjusted line height
                        display: 'block',
                        wordBreak: 'break-all', // Break long URLs
                         '&:hover': {
                          textDecoration: 'none',
                        }
                      }}
                    >
                      {ref.url.length > 45 ? `${ref.url.substring(0, 45)}...` : ref.url}
                    </a>
                    {ref.source && (
                      <div style={{ 
                        fontSize: '0.7rem', // Adjusted size
                        color: styles.appContainer.tertiaryText, // Themed tertiary text
                        marginTop: '3px', // Adjusted margin
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                      }}>
                        Source: {ref.source}
                      </div>
                    )}
                  </div>
                </div>
              ))}
              
              {/* Show count if there are more references */}
              {(vulnerability.cve?.references?.length > 8 || (aiAnalysis?.discoveredSources?.length > 0)) && (
                <div style={{ 
                  textAlign: 'center', 
                  padding: '10px 0', // Adjusted padding
                  fontSize: '0.75rem', // Adjusted size
                  color: styles.appContainer.tertiaryText // Themed tertiary text
                }}>
                  {aiAnalysis?.discoveredSources?.length > 0 && (
                    <div style={{ color: colors.blue, fontWeight: '600', marginBottom: '4px' }}>
                      {aiAnalysis.discoveredSources.length} AI-discovered source{aiAnalysis.discoveredSources.length === 1 ? '' : 's'}
                    </div>
                  )}
                  {vulnerability.cve?.references?.length > 8 && (
                    <div>+{vulnerability.cve.references.length - 8} more official reference{vulnerability.cve.references.length - 8 === 1 ? '' : 's'}</div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
        
        {/* Footer branding */}
        <div style={{ 
          marginTop: 'auto', // Pushes to bottom if sidebar has space
          paddingTop: '16px', // Space above
          borderTop: `1px solid ${styles.appContainer.border}`, // Separator line
          fontSize: '0.8rem', // Adjusted size
          color: styles.appContainer.tertiaryText, // Themed tertiary text
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
    enableRAG: true
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
        nvd: settings.nvdApiKey
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
              <div
                style={{
                  ...styles.statusIndicator,
                  background: settings.geminiApiKey
                    ? (settings.darkMode ? `rgba(${hexToRgb(colors.green)}, 0.15)` : `rgba(${hexToRgb(colors.green)}, 0.1)`)
                    : (settings.darkMode ? `rgba(${hexToRgb(colors.yellow)}, 0.15)` : `rgba(${hexToRgb(colors.yellow)}, 0.1)`),
                  borderColor: settings.geminiApiKey
                    ? `rgba(${hexToRgb(colors.green)}, 0.3)`
                    : `rgba(${hexToRgb(colors.yellow)}, 0.3)`,
                  color: settings.geminiApiKey ? colors.green : colors.yellow,
                }}
              >
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
              <div style={{...styles.emptyState, paddingTop: '48px', paddingBottom: '48px' }}> {/* Adjusted padding */}
                <div style={{ marginBottom: '28px', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '16px' }}> {/* Centered icons */}
                  <Brain size={56} color={styles.appContainer.tertiaryText} /> {/* Themed color */}
                  <Database size={40} color={styles.appContainer.tertiaryText} /> {/* Themed color */}
                </div>
                <h3 style={{
                  fontSize: '1.375rem', // Adjusted size
                  fontWeight: '600', // Adjusted weight
                  marginBottom: '16px', // Adjusted margin
                  color: styles.appContainer.primaryText // Themed color
                }}>
                  RAG-Enhanced Intelligence Platform Ready
                </h3>
                <p style={{
                  fontSize: '0.95rem', // Adjusted size
                  marginBottom: '12px', // Adjusted margin
                  color: styles.appContainer.secondaryText, // Themed color
                  lineHeight: 1.6,
                  maxWidth: '600px', // Limit width for readability
                  margin: '0 auto 12px auto'
                }}>
                  Enter a CVE ID to begin comprehensive AI-powered vulnerability analysis with contextual knowledge retrieval.
                </p>
                <p style={{
                  fontSize: '0.875rem', // Adjusted size
                  color: styles.appContainer.tertiaryText, // Themed color
                  marginBottom: '28px', // Adjusted margin
                  maxWidth: '600px',
                  margin: '0 auto 28px auto'
                }}>
                  Real-time intelligence enhanced with semantic search and domain expertise.
                </p>
                
                {/* API Key Configuration Notice */}
                {!settings.geminiApiKey && (
                  <div style={{
                    marginTop: '32px',
                    padding: '16px 20px', // Adjusted padding
                    background: settings.darkMode
                      ? `rgba(${hexToRgb(colors.yellow)}, 0.1)`
                      : `rgba(${hexToRgb(colors.yellow)}, 0.07)`, // Lighter yellow for light mode
                    border: `1px solid rgba(${hexToRgb(colors.yellow)}, 0.3)`,
                    borderRadius: '12px', // Consistent radius
                    maxWidth: '550px', // Adjusted width
                    margin: '32px auto 0'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '10px' }}> {/* Adjusted margin */}
                      <AlertTriangle size={20} color={colors.yellow} /> {/* Themed yellow */}
                      <span style={{ fontWeight: '600', color: colors.yellow, fontSize: '0.95rem' }}>RAG Configuration Required</span>
                    </div>
                    <p style={{
                      fontSize: '0.875rem', // Adjusted size
                      margin: 0,
                      color: styles.appContainer.secondaryText, // Themed color
                      lineHeight: 1.5
                    }}>
                      Configure your Gemini API key in settings to enable RAG-enhanced vulnerability analysis.
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
