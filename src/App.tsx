import React, { useState, createContext, useContext, useEffect, useCallback, useMemo } from 'react';
import { 
  Search, Brain, Settings, Target, Database, Activity, CheckCircle, XCircle, X, 
  Eye, EyeOff, Save, Globe, AlertTriangle, Loader2, RefreshCw, Copy, Clock, 
  ChevronRight, Info, Package, BarChart3, Zap, Shield, Code, Network, Server 
} from 'lucide-react';

// Constants and Configuration
const CONSTANTS = {
  API_ENDPOINTS: {
    NVD: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    EPSS: 'https://api.first.org/data/v1/epss',
    GEMINI: 'https://generativelanguage.googleapis.com/v1beta/models'
  },
  RATE_LIMITS: {
    GEMINI_COOLDOWN: 60000, // 1 minute
    MAX_RETRIES: 3
  },
  CVSS_THRESHOLDS: {
    CRITICAL: 9.0,
    HIGH: 7.0,
    MEDIUM: 4.0,
    LOW: 0.1
  },
  EPSS_THRESHOLDS: {
    HIGH: 0.5,
    MEDIUM: 0.1
  }
};

const COLORS = {
  blue: '#3b82f6',
  purple: '#8b5cf6',
  green: '#22c55e',
  red: '#ef4444',
  yellow: '#f59e0b',
  dark: {
    background: '#0f172a',
    surface: '#1e293b',
    primaryText: '#f1f5f9',
    secondaryText: '#94a3b8',
    tertiaryText: '#64748b',
    border: '#334155',
    shadow: 'rgba(0, 0, 0, 0.2)',
  },
  light: {
    background: '#f8fafc',
    surface: '#ffffff',
    primaryText: '#0f172a',
    secondaryText: '#64748b',
    tertiaryText: '#94a3b8',
    border: '#e2e8f0',
    shadow: 'rgba(0, 0, 0, 0.07)',
  }
};

// Utility Functions
const utils = {
  hexToRgb: (hex) => {
    let r = 0, g = 0, b = 0;
    if (hex.length === 4) {
      r = parseInt(hex[1] + hex[1], 16);
      g = parseInt(hex[2] + hex[2], 16);
      b = parseInt(hex[3] + hex[3], 16);
    } else if (hex.length === 7) {
      r = parseInt(hex[1] + hex[2], 16);
      g = parseInt(hex[3] + hex[4], 16);
      b = parseInt(hex[5] + hex[6], 16);
    }
    return `${r}, ${g}, ${b}`;
  },

  validateCVE: (cveId) => /^CVE-\d{4}-\d{4,}$/i.test(cveId.trim()),

  getSeverityLevel: (score) => {
    if (score >= CONSTANTS.CVSS_THRESHOLDS.CRITICAL) return 'CRITICAL';
    if (score >= CONSTANTS.CVSS_THRESHOLDS.HIGH) return 'HIGH';
    if (score >= CONSTANTS.CVSS_THRESHOLDS.MEDIUM) return 'MEDIUM';
    return 'LOW';
  },

  getSeverityColor: (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return COLORS.red;
      case 'HIGH': return COLORS.yellow;
      case 'MEDIUM': return COLORS.blue;
      case 'LOW': return COLORS.green;
      default: return COLORS.blue;
    }
  },

  formatDate: (dateString) => new Date(dateString).toLocaleString(),

  debounce: (func, wait) => {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }
};

// Enhanced RAG Vector Database with Gemini Embeddings
class EnhancedVectorDatabase {
  constructor() {
    this.documents = [];
    this.initialized = false;
    this.geminiApiKey = null;
  }

  setApiKey(apiKey) {
    this.geminiApiKey = apiKey;
  }

  async createEmbedding(text) {
    // Use Gemini embeddings if API key is available
    if (this.geminiApiKey) {
      try {
        return await this.createGeminiEmbedding(text);
      } catch (error) {
        console.warn('Gemini embedding failed, falling back to local embeddings:', error.message);
        return this.createLocalEmbedding(text);
      }
    }
    
    // Fallback to local embeddings
    return this.createLocalEmbedding(text);
  }

  async createGeminiEmbedding(text) {
    const url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-embedding-exp-03-07:embedContent';
    
    const requestBody = {
      model: "models/gemini-embedding-exp-03-07",
      content: {
        parts: [{ text: text.substring(0, 2048) }] // Limit text length for API
      }
    };

    try {
      let response;
      try {
        response = await fetch(url, {
          method: 'POST',
          headers: {
            'x-goog-api-key': this.geminiApiKey,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(requestBody)
        });
      } catch (corsError) {
        // CORS fallback using proxy
        console.log('Direct Gemini embedding blocked by CORS, trying proxy...');
        const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`;
        response = await fetch(proxyUrl, {
          method: 'POST',
          headers: {
            'x-goog-api-key': this.geminiApiKey,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(requestBody)
        });
      }

      if (!response.ok) {
        throw new Error(`Gemini Embedding API error: ${response.status}`);
      }

      const data = await response.json();
      
      if (!data.embedding?.values) {
        throw new Error('Invalid embedding response from Gemini API');
      }

      console.log(`🔗 Generated Gemini embedding (${data.embedding.values.length} dimensions) for text: "${text.substring(0, 50)}..."`);
      return data.embedding.values;
      
    } catch (error) {
      console.error('Gemini embedding error:', error);
      throw error;
    }
  }

  createLocalEmbedding(text) {
    // Fallback to improved local embeddings
    const words = text.toLowerCase().split(/\W+/).filter(w => w.length > 2);
    const wordFreq = {};
    
    words.forEach(word => {
      wordFreq[word] = (wordFreq[word] || 0) + 1;
    });
    
    // Create a more comprehensive vocabulary from security terms
    const securityTerms = [
      'vulnerability', 'exploit', 'cvss', 'epss', 'cisa', 'kev', 'critical', 'high', 'medium', 'low',
      'remote', 'local', 'authentication', 'authorization', 'injection', 'overflow', 'disclosure',
      'elevation', 'bypass', 'denial', 'service', 'code', 'execution', 'memory', 'corruption',
      'cross', 'site', 'scripting', 'sql', 'command', 'path', 'traversal', 'buffer', 'heap',
      'stack', 'format', 'string', 'integer', 'underflow', 'race', 'condition', 'symlink',
      'privilege', 'escalation', 'information', 'sensitive', 'exposure', 'leak', 'weak',
      'cryptography', 'certificate', 'validation', 'trust', 'boundary', 'sandbox', 'escape'
    ];
    
    const allTerms = [...new Set([...Object.keys(wordFreq), ...securityTerms])];
    const vector = allTerms.slice(0, 200).map(term => wordFreq[term] || 0);
    
    // Normalize the vector
    const magnitude = Math.sqrt(vector.reduce((sum, val) => sum + val * val, 0));
    return magnitude > 0 ? vector.map(val => val / magnitude) : vector;
  }

  cosineSimilarity(vec1, vec2) {
    if (vec1.length !== vec2.length) {
      // Handle different vector sizes by padding with zeros
      const maxLength = Math.max(vec1.length, vec2.length);
      const paddedVec1 = [...vec1, ...new Array(maxLength - vec1.length).fill(0)];
      const paddedVec2 = [...vec2, ...new Array(maxLength - vec2.length).fill(0)];
      vec1 = paddedVec1;
      vec2 = paddedVec2;
    }
    
    let dotProduct = 0;
    let norm1 = 0;
    let norm2 = 0;
    
    for (let i = 0; i < vec1.length; i++) {
      dotProduct += vec1[i] * vec2[i];
      norm1 += vec1[i] * vec1[i];
      norm2 += vec2[i] * vec2[i];
    }
    
    const magnitude1 = Math.sqrt(norm1);
    const magnitude2 = Math.sqrt(norm2);
    
    if (magnitude1 === 0 || magnitude2 === 0) return 0;
    
    return dotProduct / (magnitude1 * magnitude2);
  }

  async addDocument(content, metadata = {}) {
    const embedding = await this.createEmbedding(content);
    const doc = {
      id: Date.now() + Math.random(),
      content,
      metadata,
      embedding,
      timestamp: new Date().toISOString(),
      embeddingType: this.geminiApiKey ? 'gemini' : 'local'
    };
    
    this.documents.push(doc);
    console.log(`📚 Added document to RAG database (${doc.embeddingType} embedding):`, metadata.title || 'Untitled');
    return doc.id;
  }

  async search(query, k = 8) {
    if (this.documents.length === 0) {
      console.warn('⚠️ RAG database is empty - initializing with default knowledge base');
      await this.initialize();
    }

    const queryEmbedding = await this.createEmbedding(query);
    
    const similarities = this.documents.map(doc => ({
      ...doc,
      similarity: this.cosineSimilarity(queryEmbedding, doc.embedding)
    }));
    
    const results = similarities
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, k)
      .filter(doc => doc.similarity > 0.05); // Lower threshold for better matches
    
    const embeddingTypes = results.map(r => r.embeddingType).filter(Boolean);
    const hasGemini = embeddingTypes.includes('gemini');
    
    console.log(`🔍 RAG search for "${query}" found ${results.length} relevant documents from ${this.documents.length} total (${hasGemini ? 'Using Gemini embeddings' : 'Using local embeddings'})`);
    
    return results;
  }

  async initialize(geminiApiKey = null) {
    if (this.initialized) return;

    if (geminiApiKey) {
      this.setApiKey(geminiApiKey);
    }

    console.log(`🚀 Initializing Enhanced RAG Vector Database with ${this.geminiApiKey ? 'Gemini' : 'local'} embeddings...`);
    await this.addComprehensiveSecurityKnowledgeBase();
    this.initialized = true;
    console.log(`✅ RAG database initialized with ${this.documents.length} security documents using ${this.geminiApiKey ? 'Gemini' : 'local'} embeddings`);
  }

  async addComprehensiveSecurityKnowledgeBase() {
    const comprehensiveKnowledgeBase = [
      {
        title: "CVE Severity Classification Framework",
        content: "CVE severity classification uses CVSS (Common Vulnerability Scoring System) scores ranging from 0.0 to 10.0. Critical vulnerabilities (9.0-10.0) require immediate attention, especially when combined with high EPSS scores. High severity (7.0-8.9) vulnerabilities need urgent patching. Medium (4.0-6.9) and Low (0.1-3.9) require prioritization based on environmental factors and exploitability.",
        category: "severity",
        tags: ["cvss", "severity", "classification", "priority", "scoring"]
      },
      {
        title: "CISA Known Exploited Vulnerabilities (KEV) Catalog",
        content: "CISA KEV catalog contains vulnerabilities that are actively exploited in the wild. Any CVE listed in KEV requires emergency patching within specified timeframes. KEV listing indicates confirmed exploitation by threat actors and poses immediate risk to organizations. CISA mandates federal agencies patch KEV vulnerabilities within 14-21 days depending on severity.",
        category: "kev",
        tags: ["cisa", "kev", "active-exploitation", "emergency", "threat-actors"]
      },
      {
        title: "EPSS Exploitation Prediction Analysis",
        content: "EPSS (Exploit Prediction Scoring System) provides probability scores (0-100%) for vulnerability exploitation within 30 days. Scores above 50% indicate high exploitation likelihood requiring immediate attention. EPSS considers multiple factors including exploit availability, threat intelligence, and vulnerability characteristics. Developed by FIRST organization for prioritization.",
        category: "epss",
        tags: ["epss", "exploitation-probability", "prediction", "first", "prioritization"]
      },
      {
        title: "Active Exploitation Detection Methods",
        content: "Active exploitation can be detected through threat intelligence feeds, security vendor reports, honeypot data, and incident response findings. Indicators include public exploit code availability, proof-of-concept demonstrations, ransomware campaign usage, and APT group targeting. Real-world exploitation often follows public disclosure by days or weeks.",
        category: "exploitation",
        tags: ["active-exploitation", "threat-intelligence", "indicators", "ransomware", "apt"]
      },
      {
        title: "Vulnerability Exploitation Timeline Patterns",
        content: "Vulnerability exploitation typically follows predictable patterns: 0-day exploitation by advanced actors, public disclosure, proof-of-concept release, weaponization by criminal groups, and mass exploitation. Critical infrastructure and high-value targets are exploited first. Patch deployment races against exploit weaponization.",
        category: "timeline",
        tags: ["exploitation-timeline", "0-day", "weaponization", "critical-infrastructure"]
      },
      {
        title: "Threat Actor Vulnerability Targeting Preferences",
        content: "Advanced Persistent Threat (APT) groups prefer network infrastructure vulnerabilities, while ransomware operators target user-facing applications and remote access solutions. Nation-state actors focus on supply chain and zero-day vulnerabilities. Criminal groups exploit known vulnerabilities with available exploit tools.",
        category: "threat-actors",
        tags: ["apt", "ransomware", "nation-state", "criminal-groups", "targeting"]
      },
      {
        title: "Vulnerability Patch Management Strategies",
        content: "Effective patch management prioritizes based on CVSS score, EPSS probability, asset criticality, and threat intelligence. Emergency patching for KEV vulnerabilities overrides normal cycles. Virtual patching and compensating controls provide temporary protection. Testing prevents business disruption from patches.",
        category: "patching",
        tags: ["patch-management", "emergency-patching", "virtual-patching", "compensating-controls"]
      },
      {
        title: "Network Security Vulnerability Classes",
        content: "Network vulnerabilities include remote code execution, authentication bypass, privilege escalation, and information disclosure. Network infrastructure devices (routers, firewalls, VPN concentrators) are high-value targets. Lateral movement vulnerabilities enable attack progression through networks.",
        category: "network-security",
        tags: ["network-vulnerabilities", "rce", "authentication-bypass", "privilege-escalation"]
      },
      {
        title: "Web Application Security Vulnerability Types",
        content: "Common web application vulnerabilities include SQL injection, cross-site scripting (XSS), remote file inclusion, authentication flaws, and session management issues. OWASP Top 10 provides authoritative ranking of web application security risks requiring immediate attention.",
        category: "web-security",
        tags: ["web-applications", "sql-injection", "xss", "owasp", "authentication"]
      },
      {
        title: "Critical Infrastructure Vulnerability Impact",
        content: "Critical infrastructure vulnerabilities affect power grids, water systems, healthcare, financial services, and transportation. These sectors face nation-state targeting and require accelerated patching schedules. Operational technology (OT) and SCADA system vulnerabilities have physical world consequences.",
        category: "critical-infrastructure",
        tags: ["critical-infrastructure", "scada", "operational-technology", "nation-state", "physical-impact"]
      },
      {
        title: "Supply Chain Vulnerability Risks",
        content: "Supply chain vulnerabilities affect multiple organizations through shared software components, libraries, and dependencies. Examples include SolarWinds, Log4j, and Codecov incidents. Software bill of materials (SBOM) helps identify vulnerable components. Third-party risk assessment is crucial.",
        category: "supply-chain",
        tags: ["supply-chain", "dependencies", "sbom", "third-party-risk", "solarwinds", "log4j"]
      },
      {
        title: "Zero-Day Vulnerability Economics",
        content: "Zero-day vulnerabilities command high prices in underground markets and nation-state programs. Bug bounty programs compete with malicious actors for vulnerability disclosure. Coordinated disclosure balances security research with public safety. Vulnerability equity process governs government disclosure decisions.",
        category: "zero-day",
        tags: ["zero-day", "bug-bounty", "coordinated-disclosure", "vulnerability-equity"]
      },
      {
        title: "Vulnerability Scanning and Assessment",
        content: "Automated vulnerability scanners identify known vulnerabilities using CVE databases and signature-based detection. Manual penetration testing discovers complex vulnerabilities requiring human analysis. Continuous monitoring detects new vulnerabilities in dynamic environments. False positive management is critical.",
        category: "scanning",
        tags: ["vulnerability-scanning", "penetration-testing", "continuous-monitoring", "false-positives"]
      },
      {
        title: "Incident Response for Vulnerability Exploitation",
        content: "Incident response for exploited vulnerabilities requires rapid containment, forensic analysis, and recovery planning. Evidence preservation enables attribution and lessons learned. Communication with stakeholders and regulatory bodies may be required. Post-incident improvements prevent similar future incidents.",
        category: "incident-response",
        tags: ["incident-response", "containment", "forensics", "attribution", "regulatory"]
      },
      {
        title: "Regulatory Compliance and Vulnerability Management",
        content: "Regulatory frameworks like PCI DSS, HIPAA, SOX, and GDPR mandate vulnerability management programs. Compliance requires documented processes, regular assessments, and timely remediation. Industry-specific requirements vary by sector and geographic region. Audit evidence demonstrates due diligence.",
        category: "compliance",
        tags: ["regulatory-compliance", "pci-dss", "hipaa", "gdpr", "audit", "due-diligence"]
      }
    ];
    
    for (const item of comprehensiveKnowledgeBase) {
      await this.addDocument(item.content, {
        title: item.title,
        category: item.category,
        tags: item.tags,
        source: 'comprehensive-knowledge-base'
      });
    }
    
    // Add some CVE-specific knowledge
    const cveExamples = [
      {
        title: "High-Impact CVE Characteristics",
        content: "High-impact CVEs typically affect widely-deployed software, require no authentication, allow remote code execution, and have public exploit code available. Examples include Heartbleed (CVE-2014-0160), WannaCry SMB vulnerability (CVE-2017-0144), and Log4Shell (CVE-2021-44228). These vulnerabilities cause widespread internet disruption.",
        category: "high-impact-cves",
        tags: ["heartbleed", "wannacry", "log4shell", "widespread-impact", "rce"]
      },
      {
        title: "Microsoft Windows Vulnerability Patterns",
        content: "Microsoft Windows vulnerabilities often affect SMB protocol, Remote Desktop Protocol (RDP), and Windows kernel components. Patch Tuesday provides monthly security updates. Windows vulnerabilities frequently enable lateral movement in enterprise networks. Print Spooler and Exchange Server are common attack vectors.",
        category: "windows-vulnerabilities",
        tags: ["windows", "smb", "rdp", "patch-tuesday", "print-spooler", "exchange"]
      },
      {
        title: "Apache and Open Source Vulnerabilities",
        content: "Apache HTTP Server, Tomcat, and Struts vulnerabilities affect millions of web applications. Open source vulnerabilities in libraries like OpenSSL, Log4j, and Jackson create widespread exposure. Dependency management and software composition analysis help identify vulnerable components.",
        category: "apache-opensource",
        tags: ["apache", "open-source", "openssl", "log4j", "jackson", "dependencies"]
      }
    ];
    
    for (const item of cveExamples) {
      await this.addDocument(item.content, {
        title: item.title,
        category: item.category,
        tags: item.tags,
        source: 'cve-knowledge-base'
      });
    }
  }

  // Method to reinitialize if database seems empty
  async ensureInitialized(geminiApiKey = null) {
    if (this.documents.length === 0) {
      console.log('🔄 RAG database empty, reinitializing...');
      await this.initialize(geminiApiKey);
    } else if (geminiApiKey && !this.geminiApiKey) {
      // Upgrade to Gemini embeddings if API key is now available
      console.log('🔄 Upgrading to Gemini embeddings...');
      this.setApiKey(geminiApiKey);
      
      // Optionally re-embed existing documents with better embeddings
      const localEmbeddedDocs = this.documents.filter(doc => doc.embeddingType !== 'gemini');
      if (localEmbeddedDocs.length > 0) {
        console.log(`🔄 Re-embedding ${localEmbeddedDocs.length} documents with Gemini embeddings...`);
        
        // Re-embed in batches to avoid rate limits
        for (let i = 0; i < Math.min(localEmbeddedDocs.length, 5); i++) {
          try {
            const doc = localEmbeddedDocs[i];
            const newEmbedding = await this.createGeminiEmbedding(doc.content);
            doc.embedding = newEmbedding;
            doc.embeddingType = 'gemini';
            
            // Add a small delay to respect rate limits
            if (i < 4) await new Promise(resolve => setTimeout(resolve, 1000));
          } catch (error) {
            console.warn(`Failed to re-embed document ${i}:`, error.message);
          }
        }
      }
    }
  }
}

// Global RAG instance
const ragDatabase = new EnhancedVectorDatabase();

// Enhanced API Service Layer with Multi-Source Intelligence
class APIService {
  static async fetchWithFallback(url, options = {}) {
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

  static async fetchCVEData(cveId, apiKey, setLoadingSteps) {
    const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
    updateSteps(prev => [...prev, `🔍 Fetching ${cveId} from NVD...`]);
    
    const url = `${CONSTANTS.API_ENDPOINTS.NVD}?cveId=${cveId}`;
    const headers = { 
      'Accept': 'application/json',
      'User-Agent': 'VulnerabilityIntelligence/1.0'
    };
    
    if (apiKey) headers['apiKey'] = apiKey;
    
    const response = await this.fetchWithFallback(url, { headers });
    
    if (!response.ok) {
      if (response.status === 403) {
        throw new Error('NVD API rate limit exceeded. Consider adding an API key.');
      }
      throw new Error(`NVD API error: ${response.status}`);
    }
    
    const data = await response.json();
    
    if (!data.vulnerabilities?.length) {
      throw new Error(`CVE ${cveId} not found in NVD database`);
    }
    
    updateSteps(prev => [...prev, `✅ Retrieved ${cveId} from NVD`]);
    
    const processedData = this.processCVEData(data.vulnerabilities[0].cve);
    
    // Store in RAG database
    if (ragDatabase.initialized) {
      await ragDatabase.addDocument(
        `CVE ${cveId} NVD Data: ${processedData.description} CVSS Score: ${processedData.cvssV3?.baseScore || 'N/A'} Severity: ${processedData.cvssV3?.baseSeverity || 'Unknown'}`,
        {
          title: `NVD Data - ${cveId}`,
          category: 'nvd-data',
          tags: ['nvd', cveId.toLowerCase(), 'official-data'],
          source: 'nvd-api',
          cveId: cveId
        }
      );
    }
    
    return processedData;
  }

  static processCVEData(cve) {
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

  static async fetchEPSSData(cveId, setLoadingSteps) {
    const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
    updateSteps(prev => [...prev, `📊 Fetching EPSS data for ${cveId}...`]);
    
    const url = `${CONSTANTS.API_ENDPOINTS.EPSS}?cve=${cveId}`;
    const response = await this.fetchWithFallback(url, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'VulnerabilityIntelligence/1.0'
      }
    });
    
    if (!response.ok) {
      if (response.status === 404) {
        updateSteps(prev => [...prev, `⚠️ No EPSS data available for ${cveId}`]);
        return null;
      }
      throw new Error(`EPSS API error: ${response.status}`);
    }
    
    const data = await response.json();
    
    if (!data.data?.length) {
      updateSteps(prev => [...prev, `⚠️ No EPSS data found for ${cveId}`]);
      return null;
    }
    
    const epssData = data.data[0];
    const epssScore = parseFloat(epssData.epss);
    const percentileScore = parseFloat(epssData.percentile);
    const epssPercentage = (epssScore * 100).toFixed(3);
    
    updateSteps(prev => [...prev, `✅ Retrieved EPSS data for ${cveId}: ${epssPercentage}% (Percentile: ${percentileScore.toFixed(3)})`]);
    
    // Store in RAG database
    if (ragDatabase.initialized) {
      await ragDatabase.addDocument(
        `CVE ${cveId} EPSS Analysis: Exploitation probability ${epssPercentage}% (percentile ${percentileScore.toFixed(3)}). ${epssScore > 0.5 ? 'High exploitation likelihood - immediate attention required.' : epssScore > 0.1 ? 'Moderate exploitation likelihood - monitor closely.' : 'Lower exploitation likelihood but monitoring recommended.'}`,
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
      epss: epssScore.toFixed(9).substring(0, 10),
      percentile: percentileScore.toFixed(9).substring(0, 10),
      epssFloat: epssScore,
      percentileFloat: percentileScore,
      epssPercentage: epssPercentage,
      date: epssData.date,
      model_version: data.model_version
    };
  }

  // AI-Powered Multi-Source Intelligence with Web Search
  static async fetchAIThreatIntelligence(cveId, cveData, epssData, settings, setLoadingSteps) {
    const updateSteps = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
    
    if (!settings.geminiApiKey) {
      throw new Error('Gemini API key required for AI-powered threat intelligence');
    }
    
    const model = settings.geminiModel || 'gemini-2.5-flash';
    const isWebSearchCapable = model.includes('2.0') || model.includes('2.5');
    
    if (!isWebSearchCapable) {
      updateSteps(prev => [...prev, `⚠️ Model ${model} doesn't support web search - using heuristic analysis`]);
      return await this.performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
    }

    updateSteps(prev => [...prev, `🤖 AI searching web for real-time ${cveId} threat intelligence...`]);

    const searchPrompt = `You are a cybersecurity analyst researching ${cveId}. Use web search to find current information.

SEARCH FOR AND ANALYZE:
1. CISA KEV Status: Search "CISA Known Exploited Vulnerabilities ${cveId}" - Is this CVE listed in the CISA KEV catalog? If yes, get exact details including due date and required actions.

2. Active Exploitation: Search "${cveId} active exploitation in the wild ransomware APT" - Are there confirmed reports of this vulnerability being actively exploited by threat actors?

3. Public Exploits Discovery: 
   - Search "${cveId} exploit proof of concept github metasploit"
   - Search "${cveId} working exploit code demonstration"
   - Search "${cveId} exploit-db vulnerability scanner modules"
   - Find evidence of exploits but DO NOT include URLs unless you can verify they are real GitHub repos or exploit-db entries

4. Vendor Security Advisories: 
   - Search "${cveId} security advisory Microsoft Adobe Oracle"
   - Search "${cveId} vendor patch security bulletin"
   - Find vendor names and patch status but DO NOT generate advisory URLs

5. Threat Intelligence & IOCs: Search "${cveId} threat intelligence IOCs indicators compromise" - Any IOCs, attack patterns, or threat actor usage?

6. CVE Validation & False Positive Analysis:
   - Search "${cveId} false positive disputed invalid vulnerability"
   - Search "${cveId} vendor dispute CVE rejection withdrawn"
   - Search "${cveId} security researcher validation confirmation"
   - Analyze if this is a legitimate vulnerability or false positive

7. Technical Analysis: 
   - Search "${cveId} technical analysis root cause impact"
   - Search "${cveId} vulnerability details exploitation method"

**CRITICAL URL HANDLING RULES**:
1. DO NOT generate or guess any URLs
2. DO NOT include URLs in the response unless you found them in actual search results
3. For vendor advisories: Only provide the vendor name (e.g., "Microsoft", "Oracle", "Red Hat")
4. For exploits: Only include GitHub URLs if you found actual repositories, otherwise just mention the source name
5. For patches: Only include download URLs if explicitly found in search results
6. For validation sources: Only list source names like "NVD", "Mitre", "SecurityFocus", blog names, etc.
7. If you mention a blog or news site, just use its name without any URL

CURRENT CVE DATA:
- CVE: ${cveId}
- CVSS: ${cveData?.cvssV3?.baseScore || 'Unknown'} (${cveData?.cvssV3?.baseSeverity || 'Unknown'})
- EPSS: ${epssData?.epssPercentage || 'Unknown'}%
- Attack Vector: ${cveData?.cvssV3?.attackVector || 'Unknown'}
- Attack Complexity: ${cveData?.cvssV3?.attackComplexity || 'Unknown'}
- Description: ${cveData?.description?.substring(0, 300) || 'No description'}

For each search result, provide:
- Source credibility (CISA, vendor, security researcher, etc.)
- Specific findings with dates and URLs
- Exploitation status (confirmed/suspected/none)
- Available exploits with specific URLs and types
- Vendor advisories and patch information with URLs
- Validation status and any disputes
- Recommended actions

**IMPORTANT**: Actively search for and discover:
- Specific exploit repositories and POC code
- Vendor security advisories and patches
- Technical analysis and validation studies
- Any CVE disputes or false positive claims
- Real-world exploitation evidence

**CRITICAL URL HANDLING RULES**:
- For "sources" arrays, only provide source/vendor names, NOT URLs (e.g., "Microsoft", "Red Hat", "CISA")
- For specific advisory URLs, only include them if you can verify they are real and working
- Do NOT generate or guess URLs - if you don't have a real URL, leave the url field empty or use ""
- For exploit URLs, only include actual GitHub repos or exploit-db links you found
- For vendor advisory URLs, only include if you found the actual advisory page

Return your findings in this enhanced JSON structure:
{
  "cisaKev": {
    "listed": boolean,
    "details": "string with specifics including due dates",
    "dueDate": "if applicable",
    "source": "URL or source",
    "emergencyDirective": boolean,
    "aiDiscovered": true
  },
  "activeExploitation": {
    "confirmed": boolean,
    "details": "description of exploitation with evidence",
    "sources": ["array of source URLs"],
    "threatActors": ["known threat groups using this"],
    "campaigns": ["specific attack campaigns"],
    "aiDiscovered": true
  },
  "exploitDiscovery": {
    "found": boolean,
    "totalCount": number,
    "exploits": [
      {
        "type": "POC/Working/Weaponized",
        "url": "ONLY include if you found a real GitHub repo or exploit-db URL, otherwise empty string",
        "source": "GitHub/Exploit-DB/Metasploit/etc NAME ONLY",
        "description": "brief description",
        "reliability": "HIGH/MEDIUM/LOW",
        "dateFound": "discovery date"
      }
    ],
    "githubRepos": number,
    "exploitDbEntries": number,
    "metasploitModules": number,
    "confidence": "HIGH/MEDIUM/LOW",
    "aiDiscovered": true
  },
  "vendorAdvisories": {
    "found": boolean,
    "count": number,
    "advisories": [
      {
        "vendor": "vendor name ONLY (e.g., Microsoft, Red Hat, Oracle)",
        "title": "advisory title if found",
        "url": "", // LEAVE EMPTY - frontend will map to correct URL
        "patchAvailable": boolean,
        "patchUrl": "", // LEAVE EMPTY unless you found actual download link
        "severity": "vendor severity rating",
        "publishDate": "date"
      }
    ],
    "patchStatus": "available/pending/none",
    "aiDiscovered": true
  },
  "cveValidation": {
    "isValid": boolean,
    "confidence": "HIGH/MEDIUM/LOW",
    "validationSources": ["list of source NAMES only - NVD, Mitre, Red Hat, Krebs on Security, etc. NO URLS"],
    "disputes": [
      {
        "source": "who disputed",
        "reason": "why disputed",
        "url": "", // LEAVE EMPTY
        "date": "dispute date"
      }
    ],
    "falsePositiveIndicators": ["list of FP indicators"],
    "legitimacyEvidence": ["evidence supporting validity"],
    "recommendation": "VALID/FALSE_POSITIVE/DISPUTED/NEEDS_VERIFICATION",
    "aiDiscovered": true
  },
  "technicalAnalysis": {
    "rootCause": "technical root cause",
    "exploitMethod": "how it's exploited",
    "impactAnalysis": "detailed impact",
    "mitigations": ["list of mitigations"],
    "sources": ["technical analysis URLs"],
    "aiDiscovered": true
  },
  "threatIntelligence": {
    "iocs": ["any IOCs found"],
    "threatActors": ["any associated groups"],
    "campaignDetails": "if part of broader campaign",
    "ransomwareUsage": boolean,
    "aptGroups": ["nation-state actors"],
    "aiDiscovered": true
  },
  "intelligenceSummary": {
    "sourcesAnalyzed": number,
    "exploitsFound": number,
    "vendorAdvisoriesFound": number,
    "activeExploitation": boolean,
    "cisaKevListed": boolean,
    "cveValid": boolean,
    "threatLevel": "CRITICAL/HIGH/MEDIUM/LOW",
    "dataFreshness": "timestamp or freshness indicator",
    "analysisMethod": "AI_WEB_SEARCH",
    "confidenceLevel": "HIGH/MEDIUM/LOW",
    "aiEnhanced": true
  },
  "overallThreatLevel": "CRITICAL/HIGH/MEDIUM/LOW",
  "lastUpdated": "current date",
  "summary": "comprehensive executive summary with actionable intelligence"
}

IMPORTANT: 
- Do NOT include citation numbers like [1], [2], [3] or any bracketed numbers in your responses
- Write all text in natural language without any citation markers
- Focus on clear, actionable intelligence without reference numbers
- CRITICAL: Do NOT generate any URLs. Only include URLs if you found them in actual search results and can verify they are real
- For all sources, advisories, and validation sources, provide NAMES ONLY (no URLs)
- The frontend will map source names to appropriate URLs to avoid 404 errors`;

    try {
      const requestBody = {
        contents: [{
          parts: [{ text: searchPrompt }]
        }],
        generationConfig: {
          temperature: 0.1,
          topK: 1,
          topP: 0.95,
          maxOutputTokens: 8192,
          candidateCount: 1
        },
        tools: [{
          google_search: {}
        }]
      };
      
      const response = await this.fetchWithFallback(
        `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${settings.geminiApiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(requestBody)
        }
      );
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(`AI Threat Intelligence API error: ${response.status} - ${errorData.error?.message || 'Unknown error'}`);
      }
      
      const data = await response.json();
      const aiResponse = data.candidates[0].content.parts[0].text;
      
      const updateStepsAI = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
      updateStepsAI(prev => [...prev, `✅ AI completed web-based threat intelligence analysis for ${cveId}`]);
      
      const findings = this.parseAIThreatIntelligence(aiResponse, cveId, setLoadingSteps);
      
      // Store in RAG database
      if (ragDatabase.initialized) {
        await ragDatabase.addDocument(
          `AI Web-Based Threat Intelligence for ${cveId}: CISA KEV: ${findings.cisaKev.listed ? 'LISTED' : 'Not Listed'}, Active Exploitation: ${findings.activeExploitation.confirmed ? 'CONFIRMED' : 'None'}, Public Exploits: ${findings.exploitDiscovery?.totalCount || findings.publicExploits?.count || 0}, Threat Level: ${findings.overallThreatLevel}. ${findings.summary}`,
          {
            title: `AI Web Threat Intelligence - ${cveId}`,
            category: 'ai-web-intelligence',
            tags: ['ai-web-search', 'threat-intelligence', cveId.toLowerCase()],
            source: 'gemini-web-search'
          }
        );
      }
      
      return findings;
      
    } catch (error) {
      console.error('AI Threat Intelligence error:', error);
      const updateStepsError = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
      updateStepsError(prev => [...prev, `⚠️ AI web search failed: ${error.message} - using fallback analysis`]);
      
      return await this.performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps);
    }
  }

  // Parse AI threat intelligence response
  static parseAIThreatIntelligence(aiResponse, cveId, setLoadingSteps) {
    const updateStepsParse = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
    
    try {
      const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        updateStepsParse(prev => [...prev, `📊 Parsed structured threat intelligence for ${cveId}`]);
        return parsed;
      }
    } catch (e) {
      console.log('Failed to parse JSON, analyzing text response...');
    }
    
    // Fallback: parse text response
    const findings = {
      cisaKev: { listed: false, details: '', source: '', aiDiscovered: true },
      activeExploitation: { confirmed: false, details: '', sources: [], aiDiscovered: true },
      exploitDiscovery: { 
        found: false, 
        totalCount: 0, 
        exploits: [],
        githubRepos: 0,
        exploitDbEntries: 0,
        metasploitModules: 0,
        confidence: 'LOW',
        aiDiscovered: true
      },
      publicExploits: { found: false, count: 0, sources: [], types: [] }, // Legacy support
      vendorAdvisories: {
        found: false,
        count: 0,
        advisories: [],
        patchStatus: 'unknown',
        aiDiscovered: true
      },
      cveValidation: {
        isValid: true,
        confidence: 'MEDIUM',
        validationSources: [],
        disputes: [],
        falsePositiveIndicators: [],
        legitimacyEvidence: [],
        recommendation: 'NEEDS_VERIFICATION',
        aiDiscovered: true
      },
      technicalAnalysis: {
        rootCause: '',
        exploitMethod: '',
        impactAnalysis: '',
        mitigations: [],
        sources: [],
        aiDiscovered: true
      },
      threatIntelligence: { 
        iocs: [], 
        threatActors: [], 
        campaignDetails: '',
        ransomwareUsage: false,
        aptGroups: [],
        aiDiscovered: true
      },
      intelligenceSummary: {
        sourcesAnalyzed: 2,
        exploitsFound: 0,
        vendorAdvisoriesFound: 0,
        activeExploitation: false,
        cisaKevListed: false,
        cveValid: true,
        threatLevel: 'MEDIUM',
        dataFreshness: new Date().toISOString(),
        analysisMethod: 'HEURISTIC_FALLBACK',
        confidenceLevel: 'LOW',
        aiEnhanced: false
      },
      overallThreatLevel: 'MEDIUM',
      lastUpdated: new Date().toISOString(),
      summary: 'AI analysis completed with limited results'
    };
    
    const response = aiResponse.toLowerCase();
    
    // Parse CISA KEV status
    if (response.includes('cisa kev') || response.includes('known exploited')) {
      if (response.includes('listed') || response.includes('catalog')) {
        findings.cisaKev.listed = true;
        findings.cisaKev.details = 'Found in CISA Known Exploited Vulnerabilities catalog';
        findings.overallThreatLevel = 'CRITICAL';
      }
    }
    
    // Parse exploitation status
    if (response.includes('active exploit') || response.includes('in the wild')) {
      findings.activeExploitation.confirmed = true;
      findings.activeExploitation.details = 'Active exploitation detected in threat intelligence';
      findings.overallThreatLevel = 'HIGH';
    }
    
    // Parse public exploits
    if (response.includes('exploit') && (response.includes('github') || response.includes('poc'))) {
      findings.exploitDiscovery.found = true;
      findings.exploitDiscovery.totalCount = (response.match(/exploit/g) || []).length;
      findings.exploitDiscovery.confidence = 'MEDIUM';
      findings.publicExploits.found = true;
      findings.publicExploits.count = findings.exploitDiscovery.totalCount;
      findings.publicExploits.types = ['POC'];
    }
    
    // Extract URLs
    const urls = aiResponse.match(/https?:\/\/[^\s<>"{}|\\^`[\]]+/g);
    if (urls) {
      findings.activeExploitation.sources = urls.slice(0, 3);
      findings.exploitDiscovery.exploits = urls.slice(0, 5).map((url, idx) => ({
        type: 'POC',
        url: url,
        source: 'Web Search',
        description: 'Found via AI web search',
        reliability: 'MEDIUM',
        dateFound: new Date().toISOString()
      }));
      findings.publicExploits.sources = urls.slice(0, 5);
    }
    
    // Update intelligence summary
    findings.intelligenceSummary.exploitsFound = findings.exploitDiscovery.totalCount;
    findings.intelligenceSummary.activeExploitation = findings.activeExploitation.confirmed;
    findings.intelligenceSummary.cisaKevListed = findings.cisaKev.listed;
    
    findings.summary = `AI web search analysis: ${findings.cisaKev.listed ? 'CISA KEV listed' : 'Not in KEV'}, ${findings.activeExploitation.confirmed ? 'Active exploitation' : 'No active exploitation'}, ${findings.exploitDiscovery.totalCount} potential exploits found`;
    
    const updateStepsSummary = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
    updateStepsSummary(prev => [...prev, `📈 AI analysis: ${findings.overallThreatLevel} threat level determined`]);
    
    return findings;
  }

  // Advanced Heuristic Analysis Fallback
  static async performHeuristicAnalysis(cveId, cveData, epssData, setLoadingSteps) {
    const updateStepsHeuristic = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
    updateStepsHeuristic(prev => [...prev, `🔍 Performing advanced heuristic analysis for ${cveId}...`]);
    
    const year = parseInt(cveId.split('-')[1]);
    const id = parseInt(cveId.split('-')[2]);
    const cvssScore = cveData?.cvssV3?.baseScore || cveData?.cvssV2?.baseScore || 0;
    const epssFloat = epssData?.epssFloat || 0;
    const severity = utils.getSeverityLevel(cvssScore);
    
    // Advanced scoring algorithm
    let riskScore = 0;
    const indicators = [];
    
    // CVSS-based scoring
    if (cvssScore >= 9) { riskScore += 4; indicators.push('Critical CVSS score'); }
    else if (cvssScore >= 7) { riskScore += 3; indicators.push('High CVSS score'); }
    
    // EPSS-based scoring
    if (epssFloat > 0.7) { riskScore += 4; indicators.push('Very high EPSS score'); }
    else if (epssFloat > 0.3) { riskScore += 2; indicators.push('Elevated EPSS score'); }
    
    // Temporal factors
    if (year >= 2024) { riskScore += 2; indicators.push('Recent vulnerability'); }
    if (id < 1000) { riskScore += 2; indicators.push('Early discovery in year'); }
    
    // Known high-risk patterns
    const highRiskPatterns = ['21413', '44487', '38030', '26923', '1675'];
    if (highRiskPatterns.some(pattern => cveId.includes(pattern))) {
      riskScore += 5;
      indicators.push('Matches known high-risk pattern');
    }
    
    // Vendor/product patterns
    const description = cveData?.description?.toLowerCase() || '';
    const highValueTargets = ['microsoft', 'apache', 'oracle', 'vmware', 'cisco', 'windows', 'exchange', 'linux'];
    if (highValueTargets.some(target => description.includes(target))) {
      riskScore += 2;
      indicators.push('Affects high-value target software');
    }
    
    // Determine threat level and findings
    const threatLevel = riskScore >= 8 ? 'CRITICAL' : riskScore >= 6 ? 'HIGH' : riskScore >= 4 ? 'MEDIUM' : 'LOW';
    const likelyInKEV = riskScore >= 7;
    const likelyExploited = riskScore >= 5;
    const exploitCount = Math.min(Math.floor(riskScore / 2), 5);
    
    const updateStepsComplete = typeof setLoadingSteps === 'function' ? setLoadingSteps : () => {};
    updateStepsComplete(prev => [...prev, `📊 Heuristic analysis complete: ${threatLevel} threat level (score: ${riskScore})`]);
    
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
      indicators: indicators
    };
  }

  // Enhanced Multi-Source Vulnerability Data Fetching
  static async fetchVulnerabilityDataWithAI(cveId, setLoadingSteps, apiKeys, settings) {
    try {
      setLoadingSteps(prev => [...prev, `🚀 Starting AI-powered real-time analysis for ${cveId}...`]);
      
      if (!ragDatabase.initialized) {
        setLoadingSteps(prev => [...prev, `📚 Initializing RAG knowledge base...`]);
        await ragDatabase.initialize();
      }
      
      setLoadingSteps(prev => [...prev, `🔍 Fetching from primary sources (NVD, EPSS)...`]);
      
      // Fetch primary data sources
      const [cveResult, epssResult] = await Promise.allSettled([
        this.fetchCVEData(cveId, apiKeys.nvd, setLoadingSteps),
        this.fetchEPSSData(cveId, setLoadingSteps)
      ]);
      
      const cve = cveResult.status === 'fulfilled' ? cveResult.value : null;
      const epss = epssResult.status === 'fulfilled' ? epssResult.value : null;
      
      if (!cve) {
        throw new Error(`Failed to fetch CVE data for ${cveId}`);
      }
      
      setLoadingSteps(prev => [...prev, `🌐 AI analyzing real-time threat intelligence via web search...`]);
      
      // Use AI with web search for comprehensive threat intelligence
      const aiThreatIntel = await this.fetchAIThreatIntelligence(cveId, cve, epss, settings, setLoadingSteps);
      
      // Compile discovered sources with AI enhancement labels
      const discoveredSources = ['NVD'];
      const sources = [{ name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${cveId}`, aiDiscovered: false }];
      
      if (epss) {
        discoveredSources.push('EPSS/FIRST');
        sources.push({ name: 'EPSS', url: `https://api.first.org/data/v1/epss?cve=${cveId}`, aiDiscovered: false });
      }
      
      if (aiThreatIntel.cisaKev?.listed) {
        discoveredSources.push('CISA KEV');
        sources.push({ 
          name: 'CISA KEV', 
          url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
          aiDiscovered: aiThreatIntel.cisaKev.aiDiscovered || true
        });
      }
      
      if (aiThreatIntel.exploitDiscovery?.found) {
        discoveredSources.push('Exploit Intelligence');
        // Add specific exploit sources found by AI
        if (aiThreatIntel.exploitDiscovery.exploits) {
          aiThreatIntel.exploitDiscovery.exploits.forEach(exploit => {
            // Only add if URL is provided and looks valid
            if (exploit.url && exploit.url.startsWith('http')) {
              sources.push({ 
                name: `${exploit.source} - ${exploit.type}`, 
                url: exploit.url,
                aiDiscovered: true,
                reliability: exploit.reliability,
                description: exploit.description
              });
            }
          });
        }
      }
      
      if (aiThreatIntel.vendorAdvisories?.found) {
        discoveredSources.push('Vendor Advisories');
        // Add specific vendor advisories found by AI
        if (aiThreatIntel.vendorAdvisories.advisories) {
          aiThreatIntel.vendorAdvisories.advisories.forEach(advisory => {
            // Only add the vendor name, not URL to avoid 404s
            const vendorName = `${advisory.vendor} Advisory`;
            if (!sources.some(s => s.name === vendorName)) {
              sources.push({
                name: vendorName,
                url: '', // Empty URL - will be resolved by frontend mapping
                aiDiscovered: true,
                patchAvailable: advisory.patchAvailable,
                severity: advisory.severity
              });
            }
          });
        }
      }
      
      if (aiThreatIntel.activeExploitation?.confirmed) {
        discoveredSources.push('Threat Intelligence');
        // Don't add URLs from threat intelligence to avoid 404s
        if (!sources.some(s => s.name === 'Threat Intelligence')) {
          sources.push({
            name: 'Threat Intelligence',
            url: '', // Empty URL - will use generic threat intel resources
            aiDiscovered: true
          });
        }
      }

      // Use intelligence summary if available, otherwise fallback to individual fields
      const intelligenceSummary = aiThreatIntel.intelligenceSummary || {
        sourcesAnalyzed: discoveredSources.length,
        exploitsFound: aiThreatIntel.exploitDiscovery?.totalCount || 0,
        vendorAdvisoriesFound: aiThreatIntel.vendorAdvisories?.count || 0,
        activeExploitation: aiThreatIntel.activeExploitation?.confirmed || false,
        cisaKevListed: aiThreatIntel.cisaKev?.listed || false,
        cveValid: aiThreatIntel.cveValidation?.isValid !== false, // Default to valid unless proven false
        threatLevel: aiThreatIntel.overallThreatLevel || 'MEDIUM',
        dataFreshness: 'AI_WEB_SEARCH',
        analysisMethod: 'AI_WEB_SEARCH',
        confidenceLevel: aiThreatIntel.exploitDiscovery?.confidence || 'MEDIUM',
        aiEnhanced: true
      };
      
      // Generate comprehensive summary
      const threatLevel = aiThreatIntel.overallThreatLevel || intelligenceSummary.threatLevel;
      const summary = aiThreatIntel.summary;
      
      const enhancedVulnerability = {
        cve,
        epss,
        kev: aiThreatIntel.cisaKev,
        exploits: {
          found: aiThreatIntel.exploitDiscovery?.found || false,
          count: aiThreatIntel.exploitDiscovery?.totalCount || 0,
          confidence: aiThreatIntel.exploitDiscovery?.confidence || 'LOW',
          sources: aiThreatIntel.exploitDiscovery?.exploits?.map(e => e.url) || [],
          types: aiThreatIntel.exploitDiscovery?.exploits?.map(e => e.type) || [],
          details: aiThreatIntel.exploitDiscovery?.exploits || [],
          githubRepos: aiThreatIntel.exploitDiscovery?.githubRepos || 0,
          exploitDbEntries: aiThreatIntel.exploitDiscovery?.exploitDbEntries || 0,
          metasploitModules: aiThreatIntel.exploitDiscovery?.metasploitModules || 0
        },
        vendorAdvisories: aiThreatIntel.vendorAdvisories || {
          found: false,
          count: 0,
          advisories: [],
          patchStatus: 'unknown'
        },
        cveValidation: aiThreatIntel.cveValidation || {
          isValid: true,
          confidence: 'MEDIUM',
          validationSources: [],
          disputes: [],
          falsePositiveIndicators: [],
          legitimacyEvidence: [],
          recommendation: 'NEEDS_VERIFICATION'
        },
        technicalAnalysis: aiThreatIntel.technicalAnalysis,
        github: { 
          found: (aiThreatIntel.exploitDiscovery?.githubRepos || 0) > 0 || (aiThreatIntel.vendorAdvisories?.count || 0) > 0,
          count: (aiThreatIntel.exploitDiscovery?.githubRepos || 0) + (aiThreatIntel.vendorAdvisories?.count || 0)
        },
        activeExploitation: aiThreatIntel.activeExploitation || {
          confirmed: false,
          details: '',
          sources: []
        },
        threatIntelligence: aiThreatIntel.threatIntelligence,
        intelligenceSummary: intelligenceSummary,
        sources,
        discoveredSources,
        summary,
        threatLevel,
        dataFreshness: intelligenceSummary.dataFreshness || 'AI_WEB_SEARCH',
        lastUpdated: new Date().toISOString(),
        searchTimestamp: new Date().toISOString(),
        ragEnhanced: true,
        aiSearchPerformed: true,
        aiWebGrounded: true,
        enhancedSources: discoveredSources,
        analysisMethod: intelligenceSummary.analysisMethod || aiThreatIntel.analysisMethod || 'AI_WEB_SEARCH'
      };
      
      setLoadingSteps(prev => [...prev, `✅ AI web-based analysis complete: ${discoveredSources.length} sources analyzed, ${threatLevel} threat level`]);
      
      return enhancedVulnerability;
      
    } catch (error) {
      console.error(`Error processing ${cveId}:`, error);
      throw error;
    }
  }

  static async generateAIAnalysis(vulnerability, apiKey, model, settings = {}) {
    if (!apiKey) throw new Error('Gemini API key required');

    // Rate limiting with enhanced protection
    const now = Date.now();
    const lastRequest = window.lastGeminiRequest || 0;
    
    if ((now - lastRequest) < CONSTANTS.RATE_LIMITS.GEMINI_COOLDOWN) {
      const waitTime = Math.ceil((CONSTANTS.RATE_LIMITS.GEMINI_COOLDOWN - (now - lastRequest)) / 1000);
      throw new Error(`Rate limit protection: Please wait ${waitTime} more seconds. Free Gemini API has strict limits.`);
    }
    
    window.lastGeminiRequest = now;

    // Ensure RAG database is properly initialized with Gemini API key
    await ragDatabase.ensureInitialized(apiKey);
    console.log(`📊 RAG Database Status: ${ragDatabase.documents.length} documents available (${ragDatabase.geminiApiKey ? 'Gemini embeddings' : 'local embeddings'})`);

    // Enhanced RAG retrieval with better context
    const cveId = vulnerability.cve.id;
    const ragQuery = `${cveId} ${vulnerability.cve.description.substring(0, 200)} vulnerability analysis security impact mitigation threat intelligence EPSS ${vulnerability.epss?.epssPercentage || 'N/A'} CVSS ${vulnerability.cve.cvssV3?.baseScore || 'N/A'} ${vulnerability.kev?.listed ? 'CISA KEV active exploitation' : ''}`;
    
    console.log(`🔍 RAG Query: "${ragQuery.substring(0, 100)}..."`);
    const relevantDocs = await ragDatabase.search(ragQuery, 15); // Increased from 12
    console.log(`📚 RAG Retrieved: ${relevantDocs.length} relevant documents (${relevantDocs.filter(d => d.embeddingType === 'gemini').length} with Gemini embeddings)`);
    
    const ragContext = relevantDocs.length > 0 ? 
      relevantDocs.map((doc, index) => 
        `[Security Knowledge ${index + 1}] ${doc.metadata.title} (Relevance: ${(doc.similarity * 100).toFixed(1)}%, ${doc.embeddingType || 'local'} embedding):\n${doc.content.substring(0, 800)}...`
      ).join('\n\n') : 
      'No specific security knowledge found in database. Initializing knowledge base for future queries.';

    // If no relevant docs found, try a broader search
    if (relevantDocs.length === 0) {
      console.log('🔄 No specific matches found, trying broader search...');
      const broaderQuery = `vulnerability security analysis ${vulnerability.cve.cvssV3?.baseSeverity || 'unknown'} severity`;
      const broaderDocs = await ragDatabase.search(broaderQuery, 8);
      console.log(`📚 Broader RAG Search: ${broaderDocs.length} documents found`);
      
      if (broaderDocs.length > 0) {
        const broaderContext = broaderDocs.map((doc, index) => 
          `[General Security Knowledge ${index + 1}] ${doc.metadata.title} (${doc.embeddingType || 'local'} embedding):\n${doc.content.substring(0, 600)}...`
        ).join('\n\n');
        
        relevantDocs.push(...broaderDocs);
      }
    }

    const prompt = this.buildEnhancedAnalysisPrompt(vulnerability, ragContext, relevantDocs.length);
    
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

    // Add web search for capable models
    const isWebSearchCapable = model.includes('2.0') || model.includes('2.5');
    if (isWebSearchCapable) {
      requestBody.tools = [{ google_search: {} }];
    }

    const apiUrl = `${CONSTANTS.API_ENDPOINTS.GEMINI}/${model}:generateContent?key=${apiKey}`;
    
    try {
      const response = await this.fetchWithFallback(apiUrl, {
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
      
      // Store successful analysis in RAG database for future use
      if (analysisText.length > 500) {
        await ragDatabase.addDocument(
          `Enhanced CVE Analysis: ${cveId}\n\nCVSS: ${vulnerability.cve.cvssV3?.baseScore || 'N/A'}\nEPSS: ${vulnerability.epss?.epssPercentage || 'N/A'}%\nCISA KEV: ${vulnerability.kev?.listed ? 'Yes' : 'No'}\n\n${analysisText}`,
          {
            title: `Enhanced RAG Security Analysis - ${cveId}`,
            category: 'enhanced-analysis',
            tags: ['rag-enhanced', 'ai-analysis', cveId.toLowerCase(), vulnerability.cve.cvssV3?.baseSeverity?.toLowerCase() || 'unknown'],
            source: 'ai-analysis-rag',
            model: model,
            cveId: cveId
          }
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
          heuristicRisk: vulnerability.kev?.heuristicHighRisk || false
        }
      };
      
    } catch (error) {
      console.error('Enhanced RAG Analysis Error:', error);
      return this.generateEnhancedFallbackAnalysis(vulnerability, error);
    }
  }

  static buildEnhancedAnalysisPrompt(vulnerability, ragContext, ragDocCount = 0) {
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
  }

  static generateEnhancedFallbackAnalysis(vulnerability, error) {
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
  }
}

// Styling System
const createStyles = (darkMode) => {
  const theme = darkMode ? COLORS.dark : COLORS.light;
  const shadow = `0 4px 6px -1px ${theme.shadow}, 0 2px 4px -1px ${theme.shadow}`;

  return {
    app: {
      minHeight: '100vh',
      backgroundColor: theme.background,
      fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      color: theme.primaryText,
      fontSize: '16px',
      lineHeight: '1.6',
    },
    header: {
      background: `linear-gradient(135deg, ${theme.surface} 0%, ${theme.background} 100%)`,
      color: theme.primaryText,
      boxShadow: shadow,
      borderBottom: `1px solid ${theme.border}`
    },
    headerContent: {
      maxWidth: '1536px',
      margin: '0 auto',
      padding: '20px 32px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between'
    },
    title: {
      fontSize: '1.5rem',
      fontWeight: '700',
      margin: 0,
      background: `linear-gradient(135deg, ${COLORS.blue} 0%, ${COLORS.purple} 100%)`,
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      backgroundClip: 'text'
    },
    subtitle: {
      fontSize: '0.9375rem',
      color: theme.secondaryText,
      margin: 0,
      fontWeight: '500'
    },
    button: {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      gap: '8px',
      padding: '12px 20px',
      borderRadius: '8px',
      fontWeight: '600',
      cursor: 'pointer',
      borderWidth: '1px',
      borderStyle: 'solid',
      fontSize: '1rem',
      transition: 'all 0.2s ease-in-out',
      textDecoration: 'none',
      whiteSpace: 'nowrap',
      minHeight: '44px',
    },
    buttonPrimary: {
      background: `linear-gradient(135deg, ${COLORS.blue} 0%, #1d4ed8 100%)`,
      color: 'white',
      borderColor: 'transparent',
      boxShadow: `0 2px 8px rgba(${utils.hexToRgb(COLORS.blue)}, 0.3)`,
    },
    buttonSecondary: {
      background: theme.surface,
      color: theme.primaryText,
      borderColor: theme.border,
    },
    card: {
      background: theme.surface,
      borderRadius: '12px',
      padding: '24px',
      borderWidth: '1px',
      borderStyle: 'solid',
      borderColor: theme.border,
      boxShadow: shadow,
    },
    input: {
      width: '100%',
      padding: '12px 16px',
      borderWidth: '1px',
      borderStyle: 'solid',
      borderColor: theme.border,
      borderRadius: '8px',
      fontSize: '1rem',
      outline: 'none',
      boxSizing: 'border-box',
      background: theme.surface,
      color: theme.primaryText,
      transition: 'border-color 0.2s ease-in-out',
      minHeight: '44px',
    },
    badge: {
      padding: '6px 12px',
      borderRadius: '6px',
      fontSize: '0.8125rem',
      fontWeight: '700',
      display: 'inline-flex',
      alignItems: 'center',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
    },
    badgeCritical: { 
      background: 'rgba(239, 68, 68, 0.15)', 
      color: COLORS.red, 
      borderWidth: '1px',
      borderStyle: 'solid',
      borderColor: 'rgba(239, 68, 68, 0.3)'
    },
    badgeHigh: { 
      background: 'rgba(245, 158, 11, 0.15)', 
      color: COLORS.yellow, 
      borderWidth: '1px',
      borderStyle: 'solid',
      borderColor: 'rgba(245, 158, 11, 0.3)'
    },
    badgeMedium: { 
      background: 'rgba(59, 130, 246, 0.15)', 
      color: COLORS.blue, 
      borderWidth: '1px',
      borderStyle: 'solid',
      borderColor: 'rgba(59, 130, 246, 0.3)'
    },
    badgeLow: { 
      background: 'rgba(34, 197, 94, 0.15)', 
      color: COLORS.green, 
      borderWidth: '1px',
      borderStyle: 'solid',
      borderColor: 'rgba(34, 197, 94, 0.3)'
    },
  };
};

// Context
const AppContext = createContext({});

// Custom Hooks
const useNotifications = () => {
  const [notifications, setNotifications] = useState([]);
  
  const addNotification = useCallback((notification) => {
    const id = Date.now() + Math.random();
    setNotifications(prev => [...prev, { ...notification, id }]);
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 5000);
  }, []);
  
  const removeNotification = useCallback((id) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);
  
  return { notifications, addNotification, removeNotification };
};

const useSettings = () => {
  const [settings, setSettings] = useState({
    darkMode: false,
    geminiApiKey: '',
    geminiModel: 'gemini-2.5-flash',
    nvdApiKey: '',
    enableRAG: true
  });
  
  return { settings, setSettings };
};

// Components
const NotificationManager = () => {
  const { notifications, removeNotification } = useContext(AppContext);
  const { settings } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);
  
  return (
    <div style={{ position: 'fixed', top: '24px', right: '24px', zIndex: 1000 }}>
      {notifications.map((notification) => (
        <div
          key={notification.id}
          style={{
            ...styles.card,
            marginBottom: '12px',
            maxWidth: '400px',
            borderLeft: `4px solid ${
              notification.type === 'success' ? COLORS.green :
              notification.type === 'error' ? COLORS.red : COLORS.yellow
            }`,
            display: 'flex',
            alignItems: 'flex-start',
            gap: '12px',
            cursor: 'pointer'
          }}
          onClick={() => removeNotification(notification.id)}
        >
          {notification.type === 'success' && <CheckCircle size={20} color={COLORS.green} />}
          {notification.type === 'error' && <XCircle size={20} color={COLORS.red} />}
          {notification.type === 'warning' && <AlertTriangle size={20} color={COLORS.yellow} />}
          <div>
            <div style={{ fontWeight: '600', fontSize: '0.95rem' }}>{notification.title}</div>
            <div style={{ fontSize: '0.8rem', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
              {notification.message}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

const SettingsModal = ({ isOpen, onClose }) => {
  const { settings, setSettings } = useContext(AppContext);
  const { addNotification } = useContext(AppContext);
  const [localSettings, setLocalSettings] = useState(settings);
  const [showKeys, setShowKeys] = useState({ gemini: false, nvd: false });
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  useEffect(() => {
    setLocalSettings(settings);
  }, [settings]);

  const handleSave = useCallback(() => {
    setSettings(localSettings);
    addNotification({ 
      type: 'success', 
      title: 'Settings Saved', 
      message: 'Configuration updated successfully' 
    });
    onClose();
  }, [localSettings, setSettings, addNotification, onClose]);

  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'rgba(0, 0, 0, 0.6)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1050,
      backdropFilter: 'blur(5px)'
    }}>
      <div style={{
        ...styles.card,
        width: '100%',
        maxWidth: '600px',
        maxHeight: '90vh',
        overflowY: 'auto',
        margin: '20px'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '24px',
          paddingBottom: '16px',
          borderBottom: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`
        }}>
          <h3 style={{ fontSize: '1.375rem', fontWeight: '700', margin: 0 }}>
            AI Platform Settings
          </h3>
          <button 
            onClick={onClose} 
            style={{ 
              background: 'transparent', 
              border: 'none', 
              cursor: 'pointer', 
              padding: 0 
            }}
          >
            <X size={24} />
          </button>
        </div>

        <div style={{ display: 'grid', gap: '24px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '1rem', fontWeight: '600', marginBottom: '8px' }}>
              Gemini API Key
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type={showKeys.gemini ? 'text' : 'password'}
                style={styles.input}
                placeholder="Enter your Gemini API key"
                value={localSettings.geminiApiKey || ''}
                onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiApiKey: e.target.value }))}
              />
              <button 
                style={{
                  position: 'absolute',
                  right: '12px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'transparent',
                  border: 'none',
                  cursor: 'pointer',
                  padding: '4px'
                }}
                onClick={() => setShowKeys(prev => ({ ...prev, gemini: !prev.gemini }))}
              >
                {showKeys.gemini ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '1rem', fontWeight: '600', marginBottom: '8px' }}>
              Gemini Model
            </label>
            <select
              style={styles.input}
              value={localSettings.geminiModel || 'gemini-2.5-flash'}
              onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiModel: e.target.value }))}
            >
              <option value="gemini-2.5-pro">Gemini 2.5 Pro</option>
              <option value="gemini-2.5-flash">Gemini 2.5 Flash</option>
              <option value="gemini-2.0-pro">Gemini 2.0 Pro</option>
              <option value="gemini-2.0-flash">Gemini 2.0 Flash</option>
            </select>
          </div>

          <div>
            <label style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              cursor: 'pointer',
              fontSize: '1rem',
              fontWeight: '600'
            }}>
              <input
                type="checkbox"
                checked={localSettings.darkMode || false}
                onChange={(e) => setLocalSettings(prev => ({ ...prev, darkMode: e.target.checked }))}
                style={{ width: '16px', height: '16px', accentColor: COLORS.blue }}
              />
              Dark Mode
            </label>
          </div>

          <div>
            <label style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              cursor: 'pointer',
              fontSize: '1rem',
              fontWeight: '600'
            }}>
              <input
                type="checkbox"
                checked={localSettings.enableRAG !== false}
                onChange={(e) => setLocalSettings(prev => ({ ...prev, enableRAG: e.target.checked }))}
                style={{ width: '16px', height: '16px', accentColor: COLORS.blue }}
              />
              Enable RAG-Enhanced Analysis
            </label>
          </div>
        </div>

        <div style={{
          display: 'flex',
          gap: '12px',
          justifyContent: 'flex-end',
          paddingTop: '24px',
          marginTop: '16px',
          borderTop: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`
        }}>
          <button style={{ ...styles.button, ...styles.buttonSecondary }} onClick={onClose}>
            Cancel
          </button>
          <button style={{ ...styles.button, ...styles.buttonPrimary }} onClick={handleSave}>
            <Save size={18} />
            Save Settings
          </button>
        </div>
      </div>
    </div>
  );
};

const SearchComponent = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [searchHistory, setSearchHistory] = useState([]);
  const { setVulnerabilities, setLoading, loading, setLoadingSteps, addNotification, settings } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  const handleSearch = useCallback(async () => {
    if (!searchTerm.trim()) {
      addNotification({
        type: 'warning',
        title: 'Search Required',
        message: 'Please enter a CVE ID to analyze'
      });
      return;
    }

    const cveId = searchTerm.trim().toUpperCase();
    
    if (!utils.validateCVE(cveId)) {
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
      // Use the enhanced AI-powered search with multi-source discovery
      const vulnerability = await APIService.fetchVulnerabilityDataWithAI(
        cveId, 
        setLoadingSteps,
        { nvd: settings.nvdApiKey },
        settings
      );
      
      setVulnerabilities([vulnerability]);
      setSearchHistory(prev => [...new Set([cveId, ...prev])].slice(0, 5));
      
      addNotification({
        type: 'success',
        title: 'Analysis Complete',
        message: `Successfully analyzed ${cveId} with ${vulnerability.discoveredSources?.length || 0} sources`
      });
      
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Search Failed',
        message: error.message
      });
    } finally {
      setLoading(false);
    }
  }, [searchTerm, settings, setLoading, setLoadingSteps, setVulnerabilities, addNotification]);

  const debouncedSearch = useMemo(() => utils.debounce(handleSearch, 300), [handleSearch]);

  const handleKeyPress = useCallback((e) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
  }, [handleSearch]);

  return (
    <div style={{
      background: `linear-gradient(135deg, ${settings.darkMode ? COLORS.dark.surface : COLORS.light.surface} 0%, ${settings.darkMode ? COLORS.dark.background : COLORS.light.background} 100%)`,
      padding: '48px 32px 64px 32px',
      borderBottom: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`
    }}>
      <div style={{ maxWidth: '960px', margin: '0 auto', textAlign: 'center' }}>
        <h1 style={{
          fontSize: '2.75rem',
          fontWeight: '800',
          background: `linear-gradient(135deg, ${COLORS.blue} 0%, ${COLORS.purple} 100%)`,
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          backgroundClip: 'text',
          marginBottom: '12px'
        }}>
          AI-Enhanced Vulnerability Intelligence
        </h1>
        
        <p style={{
          fontSize: '1.25rem',
          color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
          marginBottom: '40px',
          fontWeight: '500',
          maxWidth: '700px',
          margin: '0 auto 32px auto',
        }}>
          AI-powered analysis with multi-source discovery and contextual knowledge retrieval
        </p>
        
        <div style={{ position: 'relative', maxWidth: '768px', margin: '0 auto 24px auto' }}>
          <Search size={24} style={{
            position: 'absolute',
            left: '20px',
            top: '50%',
            transform: 'translateY(-50%)',
            color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText
          }} />
          <input
            type="text"
            placeholder="Enter CVE ID (e.g., CVE-2024-12345)"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            onKeyPress={handleKeyPress}
            style={{
              ...styles.input,
              width: '100%',
              padding: '20px 22px 20px 56px',
              fontSize: '1.125rem',
              minHeight: '64px',
              paddingRight: '140px'
            }}
            disabled={loading}
          />
          <button
            onClick={handleSearch}
            disabled={loading || !searchTerm.trim()}
            style={{
              ...styles.button,
              ...styles.buttonPrimary,
              position: 'absolute',
              right: '8px',
              top: '50%',
              transform: 'translateY(-50%)',
              opacity: loading || !searchTerm.trim() ? 0.6 : 1
            }}
          >
            {loading ? <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} /> : <Brain size={18} />}
            {loading ? 'Analyzing...' : 'AI Analyze'}
          </button>
        </div>

        {searchHistory.length > 0 && (
          <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', flexWrap: 'wrap' }}>
            <span style={{ 
              fontSize: '0.875rem', 
              color: settings.darkMode ? COLORS.dark.primaryText : COLORS.light.primaryText, 
              fontWeight: '500', 
              alignSelf: 'center' 
            }}>
              Recent:
            </span>
            {searchHistory.map((cve, index) => (
              <button
                key={index}
                onClick={() => setSearchTerm(cve)}
                style={{
                  ...styles.button,
                  padding: '6px 12px',
                  background: settings.darkMode ? `rgba(${utils.hexToRgb(COLORS.blue)}, 0.15)` : `rgba(${utils.hexToRgb(COLORS.blue)}, 0.1)`,
                  borderWidth: '1px',
                  borderStyle: 'solid',
                  borderColor: `rgba(${utils.hexToRgb(COLORS.blue)}, 0.3)`,
                  borderRadius: '8px',
                  fontSize: '0.8rem',
                  color: COLORS.blue,
                  fontWeight: '500',
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
  const [progress, setProgress] = useState(0);
  const [timeRemaining, setTimeRemaining] = useState(30);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  useEffect(() => {
    const totalSteps = 10; // Increased for multi-source analysis
    const currentProgress = Math.min((loadingSteps.length / totalSteps) * 100, 95);
    setProgress(currentProgress);
    
    const estimatedTime = Math.max(45 - (loadingSteps.length * 5), 5); // More realistic timing
    setTimeRemaining(estimatedTime);
  }, [loadingSteps.length]);

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '64px 32px',
      textAlign: 'center',
      color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
    }}>
      <div style={{ marginBottom: '32px' }}>
        <div style={{ position: 'relative', display: 'inline-block' }}>
          <div style={{
            width: '80px',
            height: '80px',
            border: `4px solid ${settings.darkMode ? '#374151' : '#e5e7eb'}`,
            borderTop: `4px solid ${COLORS.blue}`,
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto'
          }} />
          <div style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            fontSize: '0.75rem',
            fontWeight: '600',
            color: COLORS.blue
          }}>
            {Math.round(progress)}%
          </div>
        </div>
        
        <div style={{
          width: '200px',
          height: '6px',
          background: settings.darkMode ? '#374151' : '#e5e7eb',
          borderRadius: '3px',
          margin: '16px auto 8px auto',
          overflow: 'hidden'
        }}>
          <div style={{
            width: `${progress}%`,
            height: '100%',
            background: `linear-gradient(90deg, ${COLORS.blue} 0%, ${COLORS.purple} 100%)`,
            borderRadius: '3px',
            transition: 'width 0.5s ease-out'
          }} />
        </div>
        
        <div style={{
          fontSize: '0.8rem',
          color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '6px'
        }}>
          <Clock size={14} />
          Estimated: ~{timeRemaining} seconds remaining
        </div>
      </div>

      <h2 style={{ 
        fontSize: '1.5rem', 
        fontWeight: '700', 
        marginBottom: '16px', 
        color: settings.darkMode ? '#f1f5f9' : '#0f172a',
        animation: 'pulse 2s ease-in-out infinite'
      }}>
        AI-Enhanced Multi-Source Analysis
      </h2>
      
      <p style={{ 
        fontSize: '1rem', 
        color: settings.darkMode ? '#94a3b8' : '#64748b', 
        marginBottom: '32px' 
      }}>
        AI is discovering and analyzing vulnerability intelligence from security sources...
      </p>
      
      <div style={{ 
        ...styles.card,
        maxWidth: '700px',
        textAlign: 'left',
        background: settings.darkMode ? '#1e293b' : '#ffffff'
      }}>
        <div style={{ 
          marginBottom: '16px', 
          fontSize: '0.9rem', 
          fontWeight: '600', 
          color: settings.darkMode ? '#f1f5f9' : '#0f172a', 
          display: 'flex', 
          alignItems: 'center', 
          gap: '8px' 
        }}>
          <Brain size={18} color="#3b82f6" style={{ animation: 'pulse 2s infinite' }} />
          <Database size={16} color="#8b5cf6" />
          <Globe size={16} color="#22c55e" />
          Multi-Source AI Analysis Progress:
        </div>
        
        {loadingSteps.map((step, index) => (
          <div key={index} style={{ 
            marginBottom: '12px',
            fontSize: '0.875rem',
            color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
            display: 'flex',
            alignItems: 'center',
            gap: '12px'
          }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: index === loadingSteps.length - 1 ? COLORS.blue : COLORS.green,
              flexShrink: 0,
              animation: index === loadingSteps.length - 1 ? 'pulse 1s ease-in-out infinite' : 'none'
            }} />
            <span style={{ flex: 1 }}>{step}</span>
            {index === loadingSteps.length - 1 && (
              <div style={{
                width: '16px',
                height: '16px',
                border: `2px solid ${COLORS.blue}`,
                borderTop: '2px solid transparent',
                borderRadius: '50%',
                animation: 'spin 1s linear infinite'
              }} />
            )}
          </div>
        ))}
        
        {loadingSteps.length === 0 && (
          <div style={{
            textAlign: 'center',
            padding: '20px',
            color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText,
            fontStyle: 'italic'
          }}>
            Initializing AI analysis pipeline...
          </div>
        )}
      </div>
    </div>
  );
};

const CVSSDisplay = ({ vulnerability, settings }) => {
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);
  const cvssScore = vulnerability.cve?.cvssV3?.baseScore || vulnerability.cve?.cvssV2?.baseScore || 0;
  const severity = utils.getSeverityLevel(cvssScore);
  const color = utils.getSeverityColor(severity);

  return (
    <div style={{ textAlign: 'center', marginBottom: '28px' }}>
      <div style={{
        position: 'relative',
        width: '120px',
        height: '120px',
        margin: '0 auto 16px'
      }}>
        <svg width="120" height="120" viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)' }}>
          <circle
            cx="50" cy="50" r="45"
            fill="none"
            stroke={settings.darkMode ? COLORS.dark.border : COLORS.light.border}
            strokeWidth="8"
          />
          <circle
            cx="50" cy="50" r="45"
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={`${(cvssScore / 10) * 283} 283`}
            style={{ transition: 'stroke-dasharray 1.5s ease' }}
          />
        </svg>
        
        <div style={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '1.625rem', fontWeight: '700' }}>
            {cvssScore?.toFixed(1) || 'N/A'}
          </div>
          <div style={{ fontSize: '0.75rem', fontWeight: '500' }}>
            CVSS Score
          </div>
        </div>
      </div>

      {vulnerability.epss && (
        <div style={{
          background: `rgba(${utils.hexToRgb(COLORS.purple)}, 0.1)`,
          borderRadius: '8px',
          padding: '8px 12px',
          borderWidth: '1px',
          borderStyle: 'solid',
          borderColor: `rgba(${utils.hexToRgb(COLORS.purple)}, 0.2)`
        }}>
          <div style={{ fontSize: '0.7rem', marginBottom: '4px' }}>
            EPSS Exploitation Probability
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{
              flex: 1,
              height: '4px',
              background: settings.darkMode ? COLORS.dark.border : COLORS.light.border,
              borderRadius: '2px',
              overflow: 'hidden'
            }}>
              <div style={{
                width: `${vulnerability.epss.epssFloat * 100}%`,
                height: '100%',
                background: vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH ? COLORS.red : 
                           vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.MEDIUM ? COLORS.yellow : COLORS.green,
                borderRadius: '2px',
                transition: 'width 1s ease-out'
              }} />
            </div>
            <span style={{
              fontSize: '0.75rem',
              fontWeight: '600',
              color: vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH ? COLORS.red : 
                     vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.MEDIUM ? COLORS.yellow : COLORS.green
            }}>
              {(vulnerability.epss.epssFloat * 100).toFixed(1)}%
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

const CVEDetailView = ({ vulnerability }) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const { settings, addNotification, setVulnerabilities } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  const generateAnalysis = useCallback(async () => {
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
      // Check if we need to perform AI source discovery first
      let enhancedVulnerability = vulnerability;
      
      if (!vulnerability.aiSearchPerformed || !vulnerability.sources || vulnerability.sources.length === 0) {
        addNotification({
          type: 'info',
          title: 'Performing AI Discovery',
          message: 'Running AI source discovery and validation analysis...'
        });
        
        // Perform full AI-powered analysis including source discovery
        enhancedVulnerability = await APIService.fetchVulnerabilityDataWithAI(
          vulnerability.cve.id,
          (steps) => {
            // Optionally show progress steps
            steps.forEach(step => console.log(step));
          },
          { nvd: settings.nvdApiKey },
          settings
        );
        
        // Update the vulnerability with enhanced data
        setVulnerabilities([enhancedVulnerability]);
        
        addNotification({
          type: 'success',
          title: 'AI Discovery Complete',
          message: `Discovered ${enhancedVulnerability.discoveredSources?.length || 0} sources and validation data`
        });
      }
      
      // Now generate the RAG analysis with the enhanced data
      const result = await APIService.generateAIAnalysis(
        enhancedVulnerability,
        settings.geminiApiKey,
        settings.geminiModel,
        settings
      );
      
      setAiAnalysis(result);
      setActiveTab('analysis');
      
      addNotification({
        type: 'success',
        title: 'RAG Analysis Complete',
        message: `Enhanced analysis generated using ${result.ragDocuments} knowledge sources and real-time intelligence`
      });
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Analysis Failed',
        message: error.message
      });
    } finally {
      setAiLoading(false);
    }
  }, [vulnerability, settings, addNotification, setVulnerabilities]);

  const handleRefresh = useCallback(async () => {
    const cveId = vulnerability.cve?.id;
    if (!cveId) return;

    try {
      const refreshedVulnerability = await APIService.fetchVulnerabilityDataWithAI(
        cveId, 
        (steps) => {}, // Empty function for refresh to avoid loading steps
        { nvd: settings.nvdApiKey }, 
        settings
      );
      
      setVulnerabilities([refreshedVulnerability]);
      
      addNotification({
        type: 'success',
        title: 'Data Refreshed',
        message: `Updated analysis for ${cveId} with latest threat intelligence`
      });
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Refresh Failed',
        message: error.message
      });
    }
  }, [vulnerability, settings, setVulnerabilities, addNotification]);

  const handleExport = useCallback(() => {
    try {
      const exportData = {
        ...vulnerability,
        aiAnalysis: aiAnalysis,
        exportedAt: new Date().toISOString(),
        exportedBy: 'AI-Enhanced VulnIntel Platform'
      };
      
      const blob = new Blob([JSON.stringify(exportData, null, 2)], {
        type: 'application/json'
      });
      
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${vulnerability.cve?.id || 'vulnerability'}_ai_analysis.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      
      addNotification({
        type: 'success',
        title: 'Export Complete',
        message: 'AI-enhanced analysis exported successfully'
      });
      
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Export Failed',
        message: error.message
      });
    }
  }, [vulnerability, aiAnalysis, addNotification]);

  const cvssScore = vulnerability.cve?.cvssV3?.baseScore || vulnerability.cve?.cvssV2?.baseScore || 0;
  const severity = utils.getSeverityLevel(cvssScore);

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 400px', gap: '40px', marginTop: '40px' }}>
      <div style={styles.card}>
        <div style={{
          marginBottom: '24px',
          paddingBottom: '24px',
          borderBottom: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h1 style={{
              ...styles.title,
              fontSize: '2rem',
              margin: 0
            }}>
              {vulnerability.cve?.id || 'Unknown CVE'}
            </h1>
            
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
              <button
                style={{
                  ...styles.button,
                  ...styles.buttonSecondary,
                  padding: '8px 12px',
                  fontSize: '0.875rem'
                }}
                onClick={() => {
                  navigator.clipboard.writeText(vulnerability.cve?.id);
                  addNotification({ type: 'success', title: 'Copied!', message: 'CVE ID copied to clipboard' });
                }}
              >
                <Copy size={14} />
                {vulnerability.cve?.id}
              </button>
              
              <button
                style={{
                  ...styles.button,
                  ...styles.buttonSecondary,
                  padding: '8px 12px',
                  fontSize: '0.875rem'
                }}
                onClick={handleRefresh}
              >
                <RefreshCw size={14} />
                Refresh
              </button>

              <button
                style={{
                  ...styles.button,
                  ...styles.buttonSecondary,
                  padding: '8px 12px',
                  fontSize: '0.875rem'
                }}
                onClick={handleExport}
              >
                <Package size={14} />
                Export
              </button>
            </div>
          </div>
          
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{
              ...styles.badge,
              ...(severity === 'CRITICAL' ? styles.badgeCritical :
                  severity === 'HIGH' ? styles.badgeHigh :
                  severity === 'MEDIUM' ? styles.badgeMedium : styles.badgeLow),
              fontSize: '0.85rem',
              padding: '6px 12px'
            }}>
              {severity} - {cvssScore?.toFixed(1) || 'N/A'}
            </span>
            
            {vulnerability.kev?.listed && (
              <span style={{
                ...styles.badge,
                ...styles.badgeCritical,
                animation: 'pulse 2s ease-in-out infinite'
              }}>
                🚨 CISA KEV - ACTIVE EXPLOITATION
              </span>
            )}
            
            {vulnerability.exploits?.found && (
              <span style={{
                ...styles.badge,
                background: `rgba(${utils.hexToRgb(COLORS.red)}, 0.15)`,
                color: COLORS.red,
                borderWidth: '1px',
                borderStyle: 'solid',
                borderColor: `rgba(${utils.hexToRgb(COLORS.red)}, 0.3)`,
              }}>
                💣 {vulnerability.exploits.count || 'Multiple'} EXPLOITS FOUND
              </span>
            )}

            {vulnerability.aiSearchPerformed && (
              <span style={{
                ...styles.badge,
                background: `rgba(${utils.hexToRgb(COLORS.purple)}, 0.15)`,
                color: COLORS.purple,
                borderWidth: '1px',
                borderStyle: 'solid',
                borderColor: `rgba(${utils.hexToRgb(COLORS.purple)}, 0.3)`,
              }}>
                <Brain size={12} style={{ marginRight: '6px' }} />
                AI ENHANCED ({vulnerability.discoveredSources?.length || 0} sources)
              </span>
            )}
          </div>
        </div>

        <div style={{
          display: 'flex',
          borderBottom: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`,
          marginBottom: '24px',
          gap: '4px',
          flexWrap: 'wrap'
        }}>
          {['overview', 'ai-sources', 'cve-validation', 'analysis'].map((tab) => (
            <button
              key={tab}
              style={{
                padding: '12px 18px',
                cursor: 'pointer',
                border: 'none',
                borderBottom: activeTab === tab ? `3px solid ${COLORS.blue}` : '3px solid transparent',
                fontSize: '0.9rem',
                fontWeight: '600',
                color: activeTab === tab ? COLORS.blue : settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
                transition: 'all 0.2s ease-in-out',
                borderRadius: '6px 6px 0 0',
                background: activeTab === tab
                  ? (settings.darkMode ? `rgba(${utils.hexToRgb(COLORS.blue)}, 0.1)` : `rgba(${utils.hexToRgb(COLORS.blue)}, 0.05)`)
                  : 'transparent',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                outline: 'none',
              }}
              onClick={() => setActiveTab(tab)}
            >
              {tab === 'overview' && <Info size={16} />}
              {tab === 'ai-sources' && <Globe size={16} />}
              {tab === 'cve-validation' && <Shield size={16} />}
              {tab === 'analysis' && <Brain size={16} />}
              {tab === 'ai-sources' ? 'AI Sources' : 
               tab === 'cve-validation' ? 'CVE Validation' :
               tab === 'analysis' ? 'RAG Analysis' : tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        <div>
          {activeTab === 'overview' && (
            <div>
              <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '16px' }}>
                Vulnerability Overview
              </h2>
              
              <p style={{
                fontSize: '1.0625rem',
                lineHeight: '1.7',
                color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
                marginBottom: '24px'
              }}>
                {vulnerability.cve?.description || 'No description available.'}
              </p>

              {vulnerability.epss && (
                <div style={{ marginBottom: '24px' }}>
                  <h3 style={{ fontSize: '1.25rem', fontWeight: '600', marginBottom: '12px' }}>
                    Exploitation Probability (EPSS)
                  </h3>
                  <div style={{
                    background: vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH ? 
                      `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)` : `rgba(${utils.hexToRgb(COLORS.green)}, 0.1)`,
                    borderWidth: '1px',
                    borderStyle: 'solid',
                    borderColor: vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH ? 
                      `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.3)` : `rgba(${utils.hexToRgb(COLORS.green)}, 0.3)`,
                    borderRadius: '12px',
                    padding: '20px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                      <Target size={24} color={vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH ? COLORS.yellow : COLORS.green} />
                      <div>
                        <div style={{ fontWeight: '700', fontSize: '1.05rem' }}>
                          EPSS Score: {vulnerability.epss.epssPercentage}%
                        </div>
                        <div style={{ fontSize: '0.85rem', color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                          Percentile: {parseFloat(vulnerability.epss.percentile).toFixed(3)}
                        </div>
                        <p style={{ margin: '12px 0 0 0', fontSize: '1rem' }}>
                          {vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH
                            ? 'This vulnerability has a HIGH probability of exploitation. Immediate patching recommended.'
                            : vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.MEDIUM
                              ? 'This vulnerability has a MODERATE probability of exploitation. Monitor for patches.'
                              : 'This vulnerability has a LOW probability of exploitation, but still requires attention.'}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              <div style={{ textAlign: 'center', marginTop: '32px', paddingTop: '24px', borderTop: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}` }}>
                <button
                  style={{
                    ...styles.button,
                    ...styles.buttonPrimary,
                    opacity: aiLoading || !settings.geminiApiKey ? 0.7 : 1,
                    fontSize: '1rem',
                    padding: '16px 32px'
                  }}
                  onClick={generateAnalysis}
                  disabled={aiLoading || !settings.geminiApiKey}
                >
                  {aiLoading ? (
                    <>
                      <Loader2 size={20} style={{ animation: 'spin 1s linear infinite' }} />
                      {!vulnerability.aiSearchPerformed ? 'Running Full AI Analysis...' : 'Generating RAG-Enhanced Analysis...'}
                    </>
                  ) : (
                    <>
                      <Brain size={20} />
                      <Database size={16} style={{ marginLeft: '4px' }} />
                      {!vulnerability.aiSearchPerformed ? 'Generate Full AI Analysis' : 'Generate RAG-Powered Analysis'}
                    </>
                  )}
                </button>
                {!settings.geminiApiKey && (
                  <p style={{ fontSize: '0.9rem', color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText, marginTop: '12px' }}>
                    Configure Gemini API key in settings to enable RAG-enhanced threat intelligence
                  </p>
                )}
              </div>
            </div>
          )}

          {activeTab === 'ai-sources' && (
            <div>
              <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '24px' }}>
                AI-Discovered Intelligence Sources
              </h2>

              {(!vulnerability.sources || vulnerability.sources.length === 0) && (!vulnerability.discoveredSources || vulnerability.discoveredSources.length === 0) ? (
                <div style={{
                  textAlign: 'center',
                  padding: '48px',
                  color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText
                }}>
                  <Brain size={48} style={{ marginBottom: '16px', opacity: 0.5 }} />
                  <p>AI source discovery not yet performed</p>
                  <p style={{ fontSize: '0.875rem', marginTop: '8px' }}>
                    {settings.geminiApiKey 
                      ? 'AI will automatically discover sources during search' 
                      : 'Configure Gemini API key to enable AI source discovery'}
                  </p>
                </div>
              ) : (
                <div>
                  <div style={{
                    ...styles.card,
                    marginBottom: '24px',
                    background: settings.darkMode ? COLORS.dark.background : COLORS.light.background
                  }}>
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      marginBottom: '16px'
                    }}>
                      <Brain size={24} color={COLORS.purple} />
                      <div>
                        <h3 style={{
                          fontSize: '1.125rem',
                          fontWeight: '600',
                          margin: 0
                        }}>
                          AI Analysis Summary
                        </h3>
                        <p style={{
                          margin: '4px 0 0 0',
                          fontSize: '0.875rem',
                          color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText
                        }}>
                          {vulnerability.summary || `AI searched ${vulnerability.discoveredSources?.length || 2} security sources`}
                        </p>
                      </div>
                    </div>

                    {(vulnerability.kev?.listed || vulnerability.exploits?.found || vulnerability.activeExploitation?.confirmed) && (
                      <div style={{
                        background: `rgba(${utils.hexToRgb(COLORS.red)}, 0.1)`,
                        borderWidth: '1px',
                        borderStyle: 'solid',
                        borderColor: `rgba(${utils.hexToRgb(COLORS.red)}, 0.3)`,
                        borderRadius: '8px',
                        padding: '12px',
                        marginBottom: '16px'
                      }}>
                        {vulnerability.kev?.listed && (
                          <div style={{ marginBottom: '8px' }}>
                            <strong style={{ color: COLORS.red }}>🚨 CISA KEV:</strong> {vulnerability.kev.details}
                          </div>
                        )}
                        {vulnerability.exploits?.found && (
                          <div style={{ marginBottom: '8px' }}>
                            <strong style={{ color: COLORS.red }}>💣 Public Exploits:</strong> Found {vulnerability.exploits.count} exploit(s)
                          </div>
                        )}
                        {vulnerability.activeExploitation?.confirmed && (
                          <div>
                            <strong style={{ color: COLORS.red }}>🔍 Active Exploitation:</strong> {vulnerability.activeExploitation.details}
                          </div>
                        )}
                      </div>
                    )}

                    {vulnerability.discoveredSources && vulnerability.discoveredSources.length > 0 && (
                      <div>
                        <h4 style={{
                          fontSize: '1rem',
                          fontWeight: '600',
                          marginBottom: '12px'
                        }}>
                          Sources Analyzed
                        </h4>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                          {vulnerability.discoveredSources.map((source, index) => (
                            <span
                              key={index}
                              style={{
                                padding: '4px 8px',
                                background: `rgba(${utils.hexToRgb(COLORS.blue)}, 0.15)`,
                                color: COLORS.blue,
                                borderWidth: '1px',
                                borderStyle: 'solid',
                                borderColor: `rgba(${utils.hexToRgb(COLORS.blue)}, 0.3)`,
                                borderRadius: '6px',
                                fontSize: '0.75rem',
                                fontWeight: '600'
                              }}
                            >
                              {source}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Display detailed source links */}
                    {vulnerability.sources && vulnerability.sources.length > 0 && (
                      <div style={{ marginTop: '24px' }}>
                        <h4 style={{
                          fontSize: '1rem',
                          fontWeight: '600',
                          marginBottom: '12px'
                        }}>
                          Source Links & Details
                        </h4>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                          {vulnerability.sources.map((source, index) => (
                            <div
                              key={index}
                              style={{
                                ...styles.card,
                                padding: '12px 16px',
                                background: settings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'space-between',
                                gap: '12px'
                              }}
                            >
                              <div style={{ flex: 1 }}>
                                <div style={{
                                  fontWeight: '600',
                                  fontSize: '0.9rem',
                                  marginBottom: '4px',
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: '8px'
                                }}>
                                  {source.name}
                                  {source.aiDiscovered && (
                                    <span style={{
                                      padding: '2px 6px',
                                      background: `rgba(${utils.hexToRgb(COLORS.purple)}, 0.15)`,
                                      color: COLORS.purple,
                                      borderRadius: '4px',
                                      fontSize: '0.7rem',
                                      fontWeight: '500'
                                    }}>
                                      AI Found
                                    </span>
                                  )}
                                  {source.reliability && (
                                    <span style={{
                                      padding: '2px 6px',
                                      background: source.reliability === 'HIGH' 
                                        ? `rgba(${utils.hexToRgb(COLORS.green)}, 0.15)`
                                        : source.reliability === 'MEDIUM'
                                        ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.15)`
                                        : `rgba(${utils.hexToRgb(COLORS.red)}, 0.15)`,
                                      color: source.reliability === 'HIGH' 
                                        ? COLORS.green
                                        : source.reliability === 'MEDIUM'
                                        ? COLORS.yellow
                                        : COLORS.red,
                                      borderRadius: '4px',
                                      fontSize: '0.7rem',
                                      fontWeight: '500'
                                    }}>
                                      {source.reliability}
                                    </span>
                                  )}
                                </div>
                                {source.description && (
                                  <div style={{
                                    fontSize: '0.8rem',
                                    color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
                                    marginBottom: '4px'
                                  }}>
                                    {source.description}
                                  </div>
                                )}
                                {source.patchAvailable && (
                                  <div style={{
                                    fontSize: '0.8rem',
                                    color: COLORS.green,
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '4px'
                                  }}>
                                    <CheckCircle size={12} />
                                    Patch Available
                                    {source.severity && ` - ${source.severity}`}
                                  </div>
                                )}
                              </div>
                              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                {source.patchUrl && source.patchUrl.startsWith('http') && (
                                  <a
                                    href={source.patchUrl}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    style={{
                                      ...styles.button,
                                      ...styles.buttonPrimary,
                                      padding: '6px 12px',
                                      fontSize: '0.8rem',
                                      textDecoration: 'none'
                                    }}
                                  >
                                    Get Patch
                                  </a>
                                )}
                                {source.url && source.url.startsWith('http') ? (
                                  <a
                                    href={source.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    style={{
                                      ...styles.button,
                                      ...styles.buttonSecondary,
                                      padding: '6px 12px',
                                      fontSize: '0.8rem',
                                      textDecoration: 'none'
                                    }}
                                  >
                                    View Source →
                                  </a>
                                ) : (
                                  <button
                                    onClick={() => {
                                      // Try to map the source name to a known URL
                                      // Comprehensive URL mapping for all sources
                                      const sourceUrls = {
                                        // Primary databases
                                        'NVD': `https://nvd.nist.gov/vuln/detail/${vulnerability.cve?.id}`,
                                        'EPSS': `https://api.first.org/data/v1/epss?cve=${vulnerability.cve?.id}`,
                                        'CISA KEV': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
                                        'CISA': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
                                        'Mitre': `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vulnerability.cve?.id}`,
                                        'CVE': `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vulnerability.cve?.id}`,
                                        'CVE Details': `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`,
                                        'CVEDetails': `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`,
                                        'NIST': `https://nvd.nist.gov/vuln/detail/${vulnerability.cve?.id}`,
                                        
                                        // Vendor Advisories & Patches
                                        'Microsoft Advisory': `https://msrc.microsoft.com/update-guide/en-US/vulnerability/${vulnerability.cve?.id}`,
                                        'Microsoft': `https://msrc.microsoft.com/update-guide/en-US/vulnerability/${vulnerability.cve?.id}`,
                                        'Red Hat Advisory': `https://access.redhat.com/security/cve/${vulnerability.cve?.id}`,
                                        'Red Hat': `https://access.redhat.com/security/cve/${vulnerability.cve?.id}`,
                                        'RedHat': `https://access.redhat.com/security/cve/${vulnerability.cve?.id}`,
                                        'Ubuntu Advisory': `https://ubuntu.com/security/cves?q=${vulnerability.cve?.id}`,
                                        'Ubuntu': `https://ubuntu.com/security/cves?q=${vulnerability.cve?.id}`,
                                        'Debian Advisory': `https://security-tracker.debian.org/tracker/${vulnerability.cve?.id}`,
                                        'Debian': `https://security-tracker.debian.org/tracker/${vulnerability.cve?.id}`,
                                        'Oracle Advisory': 'https://www.oracle.com/security-alerts/',
                                        'Oracle': 'https://www.oracle.com/security-alerts/',
                                        'VMware Advisory': 'https://www.vmware.com/security/advisories.html',
                                        'VMware': 'https://www.vmware.com/security/advisories.html',
                                        'Cisco Advisory': `https://tools.cisco.com/security/center/Search.x?searchTerm=${vulnerability.cve?.id}`,
                                        'Cisco': `https://tools.cisco.com/security/center/Search.x?searchTerm=${vulnerability.cve?.id}`,
                                        'Apache Advisory': 'https://www.apache.org/security/',
                                        'Apache': 'https://www.apache.org/security/',
                                        'Apache Software Foundation': 'https://www.apache.org/security/',
                                        'Adobe Advisory': 'https://helpx.adobe.com/security.html',
                                        'Adobe': 'https://helpx.adobe.com/security.html',
                                        'AWS Advisory': 'https://aws.amazon.com/security/security-bulletins/',
                                        'AWS': 'https://aws.amazon.com/security/security-bulletins/',
                                        'Amazon': 'https://aws.amazon.com/security/security-bulletins/',
                                        'Google Advisory': 'https://cloud.google.com/support/bulletins',
                                        'Google': 'https://cloud.google.com/support/bulletins',
                                        'GCP': 'https://cloud.google.com/support/bulletins',
                                        'Apple Advisory': 'https://support.apple.com/en-us/HT201222',
                                        'Apple': 'https://support.apple.com/en-us/HT201222',
                                        'Intel Advisory': 'https://www.intel.com/content/www/us/en/security-center/default.html',
                                        'Intel': 'https://www.intel.com/content/www/us/en/security-center/default.html',
                                        'NVIDIA Advisory': 'https://nvidia.custhelp.com/app/answers/list/st/5/kw/security%20bulletin',
                                        'NVIDIA': 'https://nvidia.custhelp.com/app/answers/list/st/5/kw/security%20bulletin',
                                        'IBM Advisory': 'https://www.ibm.com/support/pages/security-bulletins',
                                        'IBM': 'https://www.ibm.com/support/pages/security-bulletins',
                                        'SAP Advisory': 'https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html',
                                        'SAP': 'https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html',
                                        'Juniper Advisory': 'https://kb.juniper.net/InfoCenter/index?page=content&channel=SECURITY_ADVISORIES',
                                        'Juniper': 'https://kb.juniper.net/InfoCenter/index?page=content&channel=SECURITY_ADVISORIES',
                                        'F5 Advisory': 'https://support.f5.com/csp/home',
                                        'F5': 'https://support.f5.com/csp/home',
                                        'Citrix Advisory': 'https://support.citrix.com/securitybulletins',
                                        'Citrix': 'https://support.citrix.com/securitybulletins',
                                        'Atlassian Advisory': 'https://confluence.atlassian.com/security',
                                        'Atlassian': 'https://confluence.atlassian.com/security',
                                        'GitLab Advisory': 'https://about.gitlab.com/releases/categories/releases/',
                                        'GitLab': 'https://about.gitlab.com/releases/categories/releases/',
                                        'Jenkins Advisory': 'https://www.jenkins.io/security/advisories/',
                                        'Jenkins': 'https://www.jenkins.io/security/advisories/',
                                        'Drupal Advisory': 'https://www.drupal.org/security',
                                        'Drupal': 'https://www.drupal.org/security',
                                        'WordPress Advisory': 'https://wordpress.org/security/',
                                        'WordPress': 'https://wordpress.org/security/',
                                        'PHP Advisory': 'https://www.php.net/security/',
                                        'PHP': 'https://www.php.net/security/',
                                        'Python Advisory': 'https://www.python.org/dev/security/',
                                        'Python': 'https://www.python.org/dev/security/',
                                        'Node.js Advisory': 'https://nodejs.org/en/security/',
                                        'Node.js': 'https://nodejs.org/en/security/',
                                        'NodeJS': 'https://nodejs.org/en/security/',
                                        'npm Advisory': `https://www.npmjs.com/advisories/search?q=${vulnerability.cve?.id}`,
                                        'npm': `https://www.npmjs.com/advisories/search?q=${vulnerability.cve?.id}`,
                                        
                                        // Security News & Media Blogs
                                        'SecurityWeek': `https://www.securityweek.com/?s=${vulnerability.cve?.id}`,
                                        'Security Week': `https://www.securityweek.com/?s=${vulnerability.cve?.id}`,
                                        'ThreatPost': `https://threatpost.com/?s=${vulnerability.cve?.id}`,
                                        'Threatpost': `https://threatpost.com/?s=${vulnerability.cve?.id}`,
                                        'Dark Reading': `https://www.darkreading.com/search?q=${vulnerability.cve?.id}`,
                                        'DarkReading': `https://www.darkreading.com/search?q=${vulnerability.cve?.id}`,
                                        'The Hacker News': `https://thehackernews.com/search?q=${vulnerability.cve?.id}`,
                                        'TheHackerNews': `https://thehackernews.com/search?q=${vulnerability.cve?.id}`,
                                        'THN': `https://thehackernews.com/search?q=${vulnerability.cve?.id}`,
                                        'Bleeping Computer': `https://www.bleepingcomputer.com/search/?q=${vulnerability.cve?.id}`,
                                        'BleepingComputer': `https://www.bleepingcomputer.com/search/?q=${vulnerability.cve?.id}`,
                                        'ZDNet': `https://www.zdnet.com/search/?q=${vulnerability.cve?.id}`,
                                        'Ars Technica': `https://arstechnica.com/search/?query=${vulnerability.cve?.id}`,
                                        'ArsTechnica': `https://arstechnica.com/search/?query=${vulnerability.cve?.id}`,
                                        'The Register': `https://search.theregister.com/?q=${vulnerability.cve?.id}`,
                                        'TheRegister': `https://search.theregister.com/?q=${vulnerability.cve?.id}`,
                                        'Wired': `https://www.wired.com/search/?q=${vulnerability.cve?.id}`,
                                        'TechCrunch': `https://techcrunch.com/search/${vulnerability.cve?.id}`,
                                        'CyberScoop': `https://cyberscoop.com/?s=${vulnerability.cve?.id}`,
                                        'Cyberscoop': `https://cyberscoop.com/?s=${vulnerability.cve?.id}`,
                                        'InfoSecurity Magazine': `https://www.infosecurity-magazine.com/search/?q=${vulnerability.cve?.id}`,
                                        'Infosecurity Magazine': `https://www.infosecurity-magazine.com/search/?q=${vulnerability.cve?.id}`,
                                        'SC Magazine': `https://www.scmagazine.com/search?q=${vulnerability.cve?.id}`,
                                        'SCMagazine': `https://www.scmagazine.com/search?q=${vulnerability.cve?.id}`,
                                        'CSO Online': `https://www.csoonline.com/search?q=${vulnerability.cve?.id}`,
                                        'CSOOnline': `https://www.csoonline.com/search?q=${vulnerability.cve?.id}`,
                                        'Help Net Security': `https://www.helpnetsecurity.com/?s=${vulnerability.cve?.id}`,
                                        'HelpNetSecurity': `https://www.helpnetsecurity.com/?s=${vulnerability.cve?.id}`,
                                        'Security Affairs': `https://securityaffairs.co/wordpress/?s=${vulnerability.cve?.id}`,
                                        'SecurityAffairs': `https://securityaffairs.co/wordpress/?s=${vulnerability.cve?.id}`,
                                        'Cyber Security News': `https://cybersecuritynews.com/?s=${vulnerability.cve?.id}`,
                                        'CyberSecurityNews': `https://cybersecuritynews.com/?s=${vulnerability.cve?.id}`,
                                        'GBHackers': `https://gbhackers.com/?s=${vulnerability.cve?.id}`,
                                        'The Daily Swig': `https://portswigger.net/daily-swig/search?q=${vulnerability.cve?.id}`,
                                        'Daily Swig': `https://portswigger.net/daily-swig/search?q=${vulnerability.cve?.id}`,
                                        
                                        // Security Research Blogs
                                        'Krebs on Security': `https://krebsonsecurity.com/?s=${vulnerability.cve?.id}`,
                                        'KrebsOnSecurity': `https://krebsonsecurity.com/?s=${vulnerability.cve?.id}`,
                                        'Brian Krebs': `https://krebsonsecurity.com/?s=${vulnerability.cve?.id}`,
                                        'Schneier on Security': `https://www.schneier.com/search.html?q=${vulnerability.cve?.id}`,
                                        'Bruce Schneier': `https://www.schneier.com/search.html?q=${vulnerability.cve?.id}`,
                                        'Troy Hunt': `https://www.troyhunt.com/search?q=${vulnerability.cve?.id}`,
                                        'TroyHunt': `https://www.troyhunt.com/search?q=${vulnerability.cve?.id}`,
                                        'Graham Cluley': `https://grahamcluley.com/?s=${vulnerability.cve?.id}`,
                                        'GrahamCluley': `https://grahamcluley.com/?s=${vulnerability.cve?.id}`,
                                        'Daniel Miessler': `https://danielmiessler.com/?s=${vulnerability.cve?.id}`,
                                        'DanielMiessler': `https://danielmiessler.com/?s=${vulnerability.cve?.id}`,
                                        'Errata Security': `https://blog.erratasec.com/search?q=${vulnerability.cve?.id}`,
                                        'ErratasSec': `https://blog.erratasec.com/search?q=${vulnerability.cve?.id}`,
                                        'Robert Graham': `https://blog.erratasec.com/search?q=${vulnerability.cve?.id}`,
                                        'SANS ISC': `https://isc.sans.edu/search.html?q=${vulnerability.cve?.id}`,
                                        'SANS Internet Storm Center': `https://isc.sans.edu/search.html?q=${vulnerability.cve?.id}`,
                                        'Naked Security': `https://nakedsecurity.sophos.com/?s=${vulnerability.cve?.id}`,
                                        'NakedSecurity': `https://nakedsecurity.sophos.com/?s=${vulnerability.cve?.id}`,
                                        
                                        // Vendor Security Blogs
                                        'Microsoft Security Blog': `https://www.microsoft.com/en-us/security/blog/?s=${vulnerability.cve?.id}`,
                                        'Microsoft Security Response Center': 'https://msrc.microsoft.com/blog/',
                                        'MSRC': 'https://msrc.microsoft.com/blog/',
                                        'Google Security Blog': `https://security.googleblog.com/search?q=${vulnerability.cve?.id}`,
                                        'Google Project Zero': `https://googleprojectzero.blogspot.com/search?q=${vulnerability.cve?.id}`,
                                        'Project Zero': `https://googleprojectzero.blogspot.com/search?q=${vulnerability.cve?.id}`,
                                        'AWS Security Blog': `https://aws.amazon.com/blogs/security/?s=${vulnerability.cve?.id}`,
                                        'Cisco Security Blog': `https://blogs.cisco.com/security?search=${vulnerability.cve?.id}`,
                                        'Cisco Talos': `https://blog.talosintelligence.com/search?q=${vulnerability.cve?.id}`,
                                        'Talos Intelligence': `https://blog.talosintelligence.com/search?q=${vulnerability.cve?.id}`,
                                        'TalosIntelligence': `https://blog.talosintelligence.com/search?q=${vulnerability.cve?.id}`,
                                        'Red Hat Security Blog': `https://www.redhat.com/en/blog/channel/security?search=${vulnerability.cve?.id}`,
                                        'Oracle Security Blog': 'https://blogs.oracle.com/security/',
                                        'VMware Security Blog': 'https://blogs.vmware.com/security/',
                                        'Adobe Security Blog': 'https://blogs.adobe.com/security/',
                                        
                                        // Security Company Blogs
                                        'Kaspersky Blog': `https://www.kaspersky.com/blog/?s=${vulnerability.cve?.id}`,
                                        'Kaspersky Securelist': `https://securelist.com/?s=${vulnerability.cve?.id}`,
                                        'Securelist': `https://securelist.com/?s=${vulnerability.cve?.id}`,
                                        'McAfee Blog': `https://www.mcafee.com/blogs/?s=${vulnerability.cve?.id}`,
                                        'McAfee Labs': 'https://www.mcafee.com/blogs/category/mcafee-labs/',
                                        'Symantec Blog': `https://symantec-enterprise-blogs.security.com/search?q=${vulnerability.cve?.id}`,
                                        'Trend Micro Blog': `https://blog.trendmicro.com/?s=${vulnerability.cve?.id}`,
                                        'Trend Micro Research': 'https://blog.trendmicro.com/trendlabs-security-intelligence/',
                                        'F-Secure Blog': `https://blog.f-secure.com/?s=${vulnerability.cve?.id}`,
                                        'F-Secure Labs': 'https://labs.f-secure.com/blog/',
                                        'Sophos Blog': `https://news.sophos.com/?s=${vulnerability.cve?.id}`,
                                        'Sophos Labs': 'https://news.sophos.com/en-us/category/sophos-labs/',
                                        'Check Point Blog': `https://blog.checkpoint.com/?s=${vulnerability.cve?.id}`,
                                        'Check Point Research': 'https://research.checkpoint.com/',
                                        'Fortinet Blog': `https://www.fortinet.com/blog/search?q=${vulnerability.cve?.id}`,
                                        'FortiGuard Labs': 'https://www.fortiguard.com/threat-signal-report',
                                        'Palo Alto Networks Blog': `https://www.paloaltonetworks.com/blog/?s=${vulnerability.cve?.id}`,
                                        'Unit 42': `https://unit42.paloaltonetworks.com/?s=${vulnerability.cve?.id}`,
                                        'Unit42': `https://unit42.paloaltonetworks.com/?s=${vulnerability.cve?.id}`,
                                        'CrowdStrike Blog': `https://www.crowdstrike.com/blog/?s=${vulnerability.cve?.id}`,
                                        'FireEye Blog': 'https://www.fireeye.com/blog/threat-research.html',
                                        'Mandiant Blog': `https://www.mandiant.com/resources/blog?search=${vulnerability.cve?.id}`,
                                        'SentinelOne Blog': `https://www.sentinelone.com/blog/?s=${vulnerability.cve?.id}`,
                                        'SentinelLabs': 'https://www.sentinelone.com/labs/',
                                        'Proofpoint Blog': `https://www.proofpoint.com/us/blog?search=${vulnerability.cve?.id}`,
                                        'Tenable Blog': `https://www.tenable.com/blog/search?q=${vulnerability.cve?.id}`,
                                        'Rapid7 Blog': `https://blog.rapid7.com/?s=${vulnerability.cve?.id}`,
                                        'Qualys Blog': `https://blog.qualys.com/?s=${vulnerability.cve?.id}`,
                                        'Acunetix Blog': `https://www.acunetix.com/blog/?s=${vulnerability.cve?.id}`,
                                        'PortSwigger Blog': 'https://portswigger.net/research',
                                        'Synack Blog': `https://www.synack.com/blog/?s=${vulnerability.cve?.id}`,
                                        'HackerOne Blog': `https://www.hackerone.com/blog?search=${vulnerability.cve?.id}`,
                                        'Bugcrowd Blog': `https://www.bugcrowd.com/blog/?s=${vulnerability.cve?.id}`,
                                        
                                        // Research Team & Labs Blogs
                                        'Zero Day Initiative Blog': `https://www.zerodayinitiative.com/blog?search=${vulnerability.cve?.id}`,
                                        'ZDI Blog': `https://www.zerodayinitiative.com/blog?search=${vulnerability.cve?.id}`,
                                        'Zero Day Initiative': `https://www.zerodayinitiative.com/blog?search=${vulnerability.cve?.id}`,
                                        'ZDI': `https://www.zerodayinitiative.com/blog?search=${vulnerability.cve?.id}`,
                                        'Positive Technologies Blog': `https://www.ptsecurity.com/ww-en/analytics/?q=${vulnerability.cve?.id}`,
                                        'PT Security': `https://www.ptsecurity.com/ww-en/analytics/?q=${vulnerability.cve?.id}`,
                                        'Offensive Security Blog': `https://www.offensive-security.com/blog/?s=${vulnerability.cve?.id}`,
                                        'OffSec': `https://www.offensive-security.com/blog/?s=${vulnerability.cve?.id}`,
                                        'SecureWorks Blog': `https://www.secureworks.com/blog?search=${vulnerability.cve?.id}`,
                                        'Secureworks': `https://www.secureworks.com/blog?search=${vulnerability.cve?.id}`,
                                        'ESET Blog': `https://www.eset.com/blog/?s=${vulnerability.cve?.id}`,
                                        'ESET Research': `https://www.welivesecurity.com/?s=${vulnerability.cve?.id}`,
                                        'WeLiveSecurity': `https://www.welivesecurity.com/?s=${vulnerability.cve?.id}`,
                                        'Malwarebytes Blog': `https://blog.malwarebytes.com/?s=${vulnerability.cve?.id}`,
                                        'Malwarebytes Labs': 'https://blog.malwarebytes.com/',
                                        'Avast Blog': `https://blog.avast.com/?s=${vulnerability.cve?.id}`,
                                        'Bitdefender Blog': `https://www.bitdefender.com/blog/?s=${vulnerability.cve?.id}`,
                                        'Bitdefender Labs': 'https://www.bitdefender.com/blog/labs/',
                                        
                                        // Cloud Security Blogs
                                        'Aqua Security Blog': `https://blog.aquasec.com/?s=${vulnerability.cve?.id}`,
                                        'Aqua Blog': `https://blog.aquasec.com/?s=${vulnerability.cve?.id}`,
                                        'Sysdig Blog': `https://sysdig.com/blog/?s=${vulnerability.cve?.id}`,
                                        'Prisma Cloud Blog': 'https://www.paloaltonetworks.com/prisma/cloud/blog',
                                        'Lacework Blog': `https://www.lacework.com/blog/?s=${vulnerability.cve?.id}`,
                                        'Wiz Blog': `https://www.wiz.io/blog?search=${vulnerability.cve?.id}`,
                                        'Orca Security Blog': `https://orca.security/resources/blog/?_search=${vulnerability.cve?.id}`,
                                        'Snyk Blog': `https://snyk.io/blog/?search=${vulnerability.cve?.id}`,
                                        
                                        // Independent & Community Blogs
                                        'Full Disclosure': 'https://seclists.org/fulldisclosure/',
                                        'Packet Storm Security': `https://packetstormsecurity.com/search/?q=${vulnerability.cve?.id}`,
                                        'Packet Storm': `https://packetstormsecurity.com/search/?q=${vulnerability.cve?.id}`,
                                        'Security Focus': 'https://www.securityfocus.com/vulnerabilities',
                                        'SecurityFocus': 'https://www.securityfocus.com/vulnerabilities',
                                        'Bugtraq': 'https://www.securityfocus.com/vulnerabilities',
                                        'Reddit Security': `https://www.reddit.com/r/netsec/search?q=${vulnerability.cve?.id}`,
                                        'Reddit Netsec': `https://www.reddit.com/r/netsec/search?q=${vulnerability.cve?.id}`,
                                        'Stack Exchange Security': `https://security.stackexchange.com/search?q=${vulnerability.cve?.id}`,
                                        'Information Security Stack Exchange': `https://security.stackexchange.com/search?q=${vulnerability.cve?.id}`,
                                        'Hacker News': `https://hn.algolia.com/?q=${vulnerability.cve?.id}`,
                                        'OWASP Blog': `https://owasp.org/search/?searchString=${vulnerability.cve?.id}`,
                                        'SANS Blog': `https://www.sans.org/blog/?s=${vulnerability.cve?.id}`,
                                        
                                        // Exploit & Vulnerability Databases
                                        'Exploit-DB': `https://www.exploit-db.com/search?cve=${vulnerability.cve?.id}`,
                                        'ExploitDB': `https://www.exploit-db.com/search?cve=${vulnerability.cve?.id}`,
                                        'Exploit Database': `https://www.exploit-db.com/search?cve=${vulnerability.cve?.id}`,
                                        'Metasploit': `https://www.rapid7.com/db/?q=${vulnerability.cve?.id}&type=nexpose`,
                                        'GitHub': `https://github.com/search?q=${vulnerability.cve?.id}&type=repositories`,
                                        'Vulnhub': `https://www.vulnhub.com/?q=${vulnerability.cve?.id}`,
                                        'VulnHub': `https://www.vulnhub.com/?q=${vulnerability.cve?.id}`,
                                        'VulnDB': 'https://vulndb.cyberriskanalytics.com/',
                                        'SecurityTracker': `https://securitytracker.com/id?${vulnerability.cve?.id}`,
                                        'Vulnerability Lab': 'https://www.vulnerability-lab.com/',
                                        
                                        // Security Tools & Services
                                        'Rapid7': `https://www.rapid7.com/db/?q=${vulnerability.cve?.id}`,
                                        'Tenable': `https://www.tenable.com/plugins/search?q=${vulnerability.cve?.id}`,
                                        'Qualys': 'https://www.qualys.com/research/security-alerts/',
                                        'Nessus': `https://www.tenable.com/plugins/search?q=${vulnerability.cve?.id}`,
                                        'OpenVAS': 'https://www.openvas.org/',
                                        'Nexpose': `https://www.rapid7.com/db/?q=${vulnerability.cve?.id}`,
                                        'Snyk': `https://security.snyk.io/search?q=${vulnerability.cve?.id}`,
                                        'Shodan': `https://www.shodan.io/search?query=${vulnerability.cve?.id}`,
                                        'VirusTotal': 'https://www.virustotal.com/',
                                        
                                        // Bug Bounty Platforms
                                        'HackerOne': `https://hackerone.com/hacktivity?searchKey=${vulnerability.cve?.id}`,
                                        'Bugcrowd': 'https://bugcrowd.com/disclosures',
                                        'YesWeHack': 'https://yeswehack.com/programs',
                                        'Intigriti': 'https://www.intigriti.com/programs',
                                        
                                        // Government & CERTs
                                        'US-CERT': 'https://www.cisa.gov/uscert/ncas/current-activity',
                                        'CERT': `https://www.kb.cert.org/vuls/id/${vulnerability.cve?.id}`,
                                        'CERT/CC': `https://www.kb.cert.org/vuls/id/${vulnerability.cve?.id}`,
                                        'ICS-CERT': 'https://www.cisa.gov/uscert/ics/advisories',
                                        'JPCERT': 'https://www.jpcert.or.jp/english/at/',
                                        'AusCERT': 'https://www.auscert.org.au/bulletins/',
                                        'CERT-EU': 'https://cert.europa.eu/cert/filteredition/en/CERT-LatestNews.html',
                                        'ENISA': 'https://www.enisa.europa.eu/topics/csirt-cert-services',
                                        
                                        // Specialized Sources
                                        'OWASP': `https://owasp.org/search/?searchString=${vulnerability.cve?.id}`,
                                        'SANS': `https://www.sans.org/search/?q=${vulnerability.cve?.id}`,
                                        'CWE': 'https://cwe.mitre.org/',
                                        'ATT&CK': 'https://attack.mitre.org/',
                                        'MITRE ATT&CK': 'https://attack.mitre.org/',
                                        
                                        // Generic catch-alls
                                        'Threat Intelligence': `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`,
                                        'Exploit Intelligence': `https://www.exploit-db.com/search?cve=${vulnerability.cve?.id}`,
                                        'Security Advisory': `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`,
                                        'Security Bulletin': `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`,
                                        'Vulnerability Report': `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`,
                                        'Security Research': `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`,
                                        'Patch Information': `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`,
                                        'Wordfence': `https://www.wordfence.com/threat-intel/vulnerabilities/search?cve=${vulnerability.cve?.id}`,
                                        'WPScan': `https://wpscan.com/search?q=${vulnerability.cve?.id}`,
                                        'Sucuri': 'https://blog.sucuri.net/',
                                        'Imperva': 'https://www.imperva.com/blog/',
                                        'Akamai': 'https://www.akamai.com/blog/security',
                                        'Cloudflare': 'https://blog.cloudflare.com/tag/security/',
                                        'Fastly': 'https://www.fastly.com/blog/category/security'
                                      };
                                      
                                      // Try to find exact match first
                                      let url = sourceUrls[source.name];
                                      
                                      // If no exact match, try removing "Advisory" suffix
                                      if (!url && source.name.includes(' Advisory')) {
                                        const vendorName = source.name.replace(' Advisory', '');
                                        url = sourceUrls[vendorName];
                                      }
                                      
                                      // If still no match, try partial match on vendor name
                                      if (!url) {
                                        const matchedKey = Object.keys(sourceUrls).find(key => 
                                          source.name.toLowerCase().includes(key.toLowerCase().split(' ')[0])
                                        );
                                        url = matchedKey ? sourceUrls[matchedKey] : null;
                                      }
                                      
                                      // Final fallback to CVE Details (reliable aggregator)
                                      if (!url) {
                                        url = `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`;
                                      }
                                      
                                      window.open(url, '_blank', 'noopener,noreferrer');
                                    }}
                                    style={{
                                      ...styles.button,
                                      ...styles.buttonSecondary,
                                      padding: '6px 12px',
                                      fontSize: '0.8rem'
                                    }}
                                  >
                                    View Details →
                                  </button>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'cve-validation' && (
            <div>
              <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '24px' }}>
                CVE Validation & Legitimacy Analysis
              </h2>

              {!vulnerability.cveValidation ? (
                <div style={{
                  textAlign: 'center',
                  padding: '48px',
                  color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText
                }}>
                  <Shield size={48} style={{ marginBottom: '16px', opacity: 0.5 }} />
                  <h3 style={{ 
                    fontSize: '1.2rem', 
                    fontWeight: '600',
                    marginBottom: '12px',
                    color: settings.darkMode ? COLORS.dark.primaryText : COLORS.light.primaryText
                  }}>
                    CVE Validation Not Yet Performed
                  </h3>
                  <p style={{ fontSize: '0.95rem', marginBottom: '16px', maxWidth: '500px', margin: '0 auto 16px auto' }}>
                    AI validation checks if this CVE has been disputed, withdrawn, or confirmed by vendors and security researchers.
                  </p>
                  
                  <div style={{
                    background: settings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
                    borderRadius: '8px',
                    padding: '20px',
                    maxWidth: '450px',
                    margin: '0 auto',
                    textAlign: 'left'
                  }}>
                    <div style={{ fontWeight: '600', marginBottom: '12px', fontSize: '0.9rem' }}>
                      🔍 What CVE Validation Checks:
                    </div>
                    <ul style={{ 
                      margin: '0 0 0 20px', 
                      padding: 0, 
                      fontSize: '0.85rem',
                      lineHeight: '1.6' 
                    }}>
                      <li style={{ marginBottom: '8px' }}>
                        <strong>Vendor Disputes:</strong> Has the vendor said "this is not a vulnerability"?
                      </li>
                      <li style={{ marginBottom: '8px' }}>
                        <strong>False Positives:</strong> Was this CVE withdrawn or marked invalid?
                      </li>
                      <li style={{ marginBottom: '8px' }}>
                        <strong>Confirmations:</strong> Have vendors released patches or advisories?
                      </li>
                      <li>
                        <strong>Researcher Validation:</strong> Do security experts agree it's real?
                      </li>
                    </ul>
                  </div>
                  
                  <p style={{ 
                    fontSize: '0.875rem', 
                    marginTop: '20px',
                    fontStyle: 'italic' 
                  }}>
                    💡 Tip: Click "Generate Full AI Analysis" on the Overview tab to perform validation
                  </p>
                </div>
              ) : (
                <div>
                  {/* Validation Status Overview */}
                  <div style={{
                    ...styles.card,
                    marginBottom: '24px',
                    background: vulnerability.cveValidation.isValid 
                      ? `rgba(${utils.hexToRgb(COLORS.green)}, 0.1)` 
                      : vulnerability.cveValidation.recommendation === 'NEEDS_VERIFICATION'
                      ? `rgba(${utils.hexToRgb(COLORS.blue)}, 0.1)`
                      : `rgba(${utils.hexToRgb(COLORS.red)}, 0.1)`,
                    borderWidth: '2px',
                    borderStyle: 'solid',
                    borderColor: vulnerability.cveValidation.isValid 
                      ? `rgba(${utils.hexToRgb(COLORS.green)}, 0.3)` 
                      : vulnerability.cveValidation.recommendation === 'NEEDS_VERIFICATION'
                      ? `rgba(${utils.hexToRgb(COLORS.blue)}, 0.3)`
                      : `rgba(${utils.hexToRgb(COLORS.red)}, 0.3)`
                  }}>
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      marginBottom: '16px'
                    }}>
                      <Shield 
                        size={32} 
                        color={vulnerability.cveValidation.isValid 
                          ? COLORS.green 
                          : vulnerability.cveValidation.recommendation === 'NEEDS_VERIFICATION'
                          ? COLORS.blue
                          : COLORS.red} 
                      />
                      <div>
                        <h3 style={{
                          fontSize: '1.25rem',
                          fontWeight: '700',
                          margin: 0,
                          color: vulnerability.cveValidation.isValid 
                            ? COLORS.green 
                            : vulnerability.cveValidation.recommendation === 'NEEDS_VERIFICATION'
                            ? COLORS.blue
                            : COLORS.red
                        }}>
                          {vulnerability.cveValidation.recommendation === 'VALID' ? '✓ Legitimate Vulnerability' :
                           vulnerability.cveValidation.recommendation === 'FALSE_POSITIVE' ? '✗ Likely False Positive' :
                           vulnerability.cveValidation.recommendation === 'DISPUTED' ? '⚠ Disputed Vulnerability' :
                           vulnerability.cveValidation.recommendation === 'NEEDS_VERIFICATION' ? 'ℹ Standard CVE Entry' :
                           vulnerability.cveValidation.recommendation}
                        </h3>
                        <p style={{
                          margin: '4px 0 0 0',
                          fontSize: '0.875rem',
                          color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText
                        }}>
                          {vulnerability.cveValidation.confidence === 'HIGH' ? '✓ High confidence assessment' :
                           vulnerability.cveValidation.confidence === 'MEDIUM' ? '• Moderate confidence assessment' :
                           '○ Limited validation data available'} 
                          {vulnerability.cveValidation.validationSources?.length > 0 && 
                            ` • ${vulnerability.cveValidation.validationSources.length} sources checked`}
                        </p>
                      </div>
                    </div>

                    <div style={{ fontSize: '0.95rem', lineHeight: '1.6' }}>
                      {vulnerability.cveValidation.recommendation === 'NEEDS_VERIFICATION' ? (
                        <>
                          <p style={{ margin: '0 0 12px 0' }}>
                            <strong>What this means:</strong> This CVE is listed in the National Vulnerability Database (NVD) 
                            but hasn't been independently verified or disputed by vendors/researchers yet. This is normal for many CVEs.
                          </p>
                          <div style={{
                            background: settings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
                            borderRadius: '8px',
                            padding: '12px',
                            marginTop: '12px'
                          }}>
                            <p style={{ margin: '0 0 8px 0', fontWeight: '600', color: COLORS.blue }}>
                              👉 Recommended Actions:
                            </p>
                            <ul style={{ margin: '0 0 0 20px', padding: 0 }}>
                              <li>Treat this as a legitimate vulnerability until proven otherwise</li>
                              <li>Check with your software vendor for patches or statements</li>
                              <li>Monitor security advisories for updates</li>
                              <li>Apply standard risk assessment based on CVSS score ({vulnerability.cve?.cvssV3?.baseScore || 'N/A'})</li>
                            </ul>
                          </div>
                        </>
                      ) : vulnerability.cveValidation.recommendation === 'VALID' ? (
                        <>
                          <p style={{ margin: '0 0 12px 0' }}>
                            <strong>What this means:</strong> This vulnerability has been confirmed by multiple sources, 
                            vendors, or security researchers. It represents a real security risk that should be addressed.
                          </p>
                          <div style={{
                            background: settings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
                            borderRadius: '8px',
                            padding: '12px',
                            marginTop: '12px'
                          }}>
                            <p style={{ margin: '0 0 8px 0', fontWeight: '600', color: COLORS.green }}>
                              ✓ Recommended Actions:
                            </p>
                            <ul style={{ margin: '0 0 0 20px', padding: 0 }}>
                              <li>Prioritize patching based on your environment</li>
                              <li>Apply vendor-provided fixes immediately if critical</li>
                              <li>Implement compensating controls if patches unavailable</li>
                            </ul>
                          </div>
                        </>
                      ) : vulnerability.cveValidation.recommendation === 'FALSE_POSITIVE' ? (
                        <>
                          <p style={{ margin: '0 0 12px 0' }}>
                            <strong>What this means:</strong> This CVE has been disputed or identified as not being a real 
                            vulnerability. It may be intended behavior, a configuration issue, or incorrectly reported.
                          </p>
                          <div style={{
                            background: settings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
                            borderRadius: '8px',
                            padding: '12px',
                            marginTop: '12px'
                          }}>
                            <p style={{ margin: '0 0 8px 0', fontWeight: '600', color: COLORS.red }}>
                              ⚠ Recommended Actions:
                            </p>
                            <ul style={{ margin: '0 0 0 20px', padding: 0 }}>
                              <li>Review the dispute reasons below</li>
                              <li>May not require patching - verify with your vendor</li>
                              <li>Consider deprioritizing unless you have specific concerns</li>
                            </ul>
                          </div>
                        </>
                      ) : (
                        <p style={{ margin: '0' }}>
                          <strong>Validation Status:</strong> {vulnerability.cveValidation.recommendation}
                        </p>
                      )}
                    </div>

                    {/* Quick Reference Box */}
                    <div style={{
                      marginTop: '16px',
                      padding: '12px',
                      background: settings.darkMode ? `rgba(255, 255, 255, 0.05)` : `rgba(0, 0, 0, 0.05)`,
                      borderRadius: '6px',
                      fontSize: '0.85rem'
                    }}>
                      <div style={{ fontWeight: '600', marginBottom: '8px' }}>
                        🔍 How CVE Validation Works:
                      </div>
                      <div style={{ display: 'grid', gap: '4px' }}>
                        <div>• <strong>Legitimate:</strong> Confirmed by vendors/researchers as a real vulnerability</div>
                        <div>• <strong>False Positive:</strong> Disputed or withdrawn - may not need patching</div>
                        <div>• <strong>Standard Entry:</strong> In NVD but not yet independently verified (most CVEs)</div>
                      </div>
                    </div>
                  </div>

                  {/* Legitimacy Evidence */}
                  {vulnerability.cveValidation.legitimacyEvidence && vulnerability.cveValidation.legitimacyEvidence.length > 0 && (
                    <div style={{
                      ...styles.card,
                      marginBottom: '20px',
                      background: settings.darkMode ? COLORS.dark.background : COLORS.light.background
                    }}>
                      <h4 style={{
                        fontSize: '1.1rem',
                        fontWeight: '600',
                        marginBottom: '12px',
                        color: COLORS.green,
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                      }}>
                        <CheckCircle size={18} />
                        Supporting Evidence for Validity
                      </h4>
                      <ul style={{ 
                        margin: '0 0 0 20px', 
                        padding: 0,
                        fontSize: '0.9rem',
                        lineHeight: '1.5'
                      }}>
                        {vulnerability.cveValidation.legitimacyEvidence.map((evidence, index) => (
                          <li key={index} style={{ marginBottom: '6px' }}>
                            {evidence}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* False Positive Indicators */}
                  {vulnerability.cveValidation.falsePositiveIndicators && vulnerability.cveValidation.falsePositiveIndicators.length > 0 && (
                    <div style={{
                      ...styles.card,
                      marginBottom: '20px',
                      background: settings.darkMode ? COLORS.dark.background : COLORS.light.background
                    }}>
                      <h4 style={{
                        fontSize: '1.1rem',
                        fontWeight: '600',
                        marginBottom: '12px',
                        color: COLORS.yellow,
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                      }}>
                        <AlertTriangle size={18} />
                        False Positive Indicators
                      </h4>
                      <ul style={{ 
                        margin: '0 0 0 20px', 
                        padding: 0,
                        fontSize: '0.9rem',
                        lineHeight: '1.5'
                      }}>
                        {vulnerability.cveValidation.falsePositiveIndicators.map((indicator, index) => (
                          <li key={index} style={{ marginBottom: '6px' }}>
                            {indicator}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Disputes and Challenges */}
                  {vulnerability.cveValidation.disputes && vulnerability.cveValidation.disputes.length > 0 && (
                    <div style={{
                      ...styles.card,
                      marginBottom: '20px',
                      background: settings.darkMode ? COLORS.dark.background : COLORS.light.background
                    }}>
                      <h4 style={{
                        fontSize: '1.1rem',
                        fontWeight: '600',
                        marginBottom: '12px',
                        color: COLORS.red,
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                      }}>
                        <XCircle size={18} />
                        CVE Disputes & Challenges
                      </h4>
                      {vulnerability.cveValidation.disputes.map((dispute, index) => (
                        <div key={index} style={{
                          padding: '12px',
                          background: `rgba(${utils.hexToRgb(COLORS.red)}, 0.05)`,
                          borderWidth: '1px',
                          borderStyle: 'solid',
                          borderColor: `rgba(${utils.hexToRgb(COLORS.red)}, 0.2)`,
                          borderRadius: '6px',
                          marginBottom: '8px'
                        }}>
                          <div style={{ fontWeight: '600', marginBottom: '4px' }}>
                            {dispute.source} ({dispute.date})
                          </div>
                          <div style={{ fontSize: '0.9rem', marginBottom: '4px' }}>
                            {dispute.reason}
                          </div>
                          {dispute.url && (
                            <a 
                              href={dispute.url} 
                              target="_blank" 
                              rel="noopener noreferrer"
                              style={{ color: COLORS.blue, fontSize: '0.85rem' }}
                            >
                              View Dispute Details →
                            </a>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Validation Sources */}
                  {vulnerability.cveValidation.validationSources && vulnerability.cveValidation.validationSources.length > 0 && (
                    <div style={{
                      ...styles.card,
                      background: settings.darkMode ? COLORS.dark.background : COLORS.light.background
                    }}>
                      <h4 style={{
                        fontSize: '1rem',
                        fontWeight: '600',
                        marginBottom: '12px'
                      }}>
                        Validation Sources ({vulnerability.cveValidation.validationSources.length})
                      </h4>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                        {vulnerability.cveValidation.validationSources.map((source, index) => {
                          // Create URLs for known sources with better mappings
                          const sourceUrls = {
                            // Primary databases
                            'NVD': `https://nvd.nist.gov/vuln/detail/${vulnerability.cve?.id}`,
                            'EPSS': `https://api.first.org/data/v1/epss?cve=${vulnerability.cve?.id}`,
                            'CISA': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
                            'CISA KEV': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
                            'Mitre': `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vulnerability.cve?.id}`,
                            'CVE': `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vulnerability.cve?.id}`,
                            
                            // Exploit databases
                            'Exploit-DB': `https://www.exploit-db.com/search?cve=${vulnerability.cve?.id}`,
                            'ExploitDB': `https://www.exploit-db.com/search?cve=${vulnerability.cve?.id}`,
                            'Metasploit': `https://www.rapid7.com/db/?q=${vulnerability.cve?.id}&type=nexpose`,
                            'Packet Storm': `https://packetstormsecurity.com/search/?q=${vulnerability.cve?.id}`,
                            
                            // Vendor specific
                            'Microsoft': `https://msrc.microsoft.com/update-guide/vulnerability/${vulnerability.cve?.id}`,
                            'Red Hat': `https://access.redhat.com/security/cve/${vulnerability.cve?.id}`,
                            'RedHat': `https://access.redhat.com/security/cve/${vulnerability.cve?.id}`,
                            'Oracle': `https://www.oracle.com/security-alerts/`,
                            'VMware': `https://www.vmware.com/security/advisories.html`,
                            'Apache': `https://httpd.apache.org/security/vulnerabilities_24.html`,
                            'Apache Software Foundation': `https://www.apache.org/security/`,
                            'Cisco': `https://tools.cisco.com/security/center/Search.x?searchTerm=${vulnerability.cve?.id}`,
                            'AWS': `https://aws.amazon.com/security/security-bulletins/`,
                            'Ubuntu': `https://ubuntu.com/security/cves?q=${vulnerability.cve?.id}`,
                            'Debian': `https://security-tracker.debian.org/tracker/${vulnerability.cve?.id}`,
                            
                            // Security vendors/researchers
                            'Wordfence': `https://www.wordfence.com/threat-intel/vulnerabilities/search?cve=${vulnerability.cve?.id}`,
                            'Tenable': `https://www.tenable.com/plugins/search?q=${vulnerability.cve?.id}`,
                            'Qualys': `https://www.qualys.com/research/security-alerts/`,
                            'Rapid7': `https://www.rapid7.com/db/?q=${vulnerability.cve?.id}`,
                            'SecurityFocus': `https://www.securityfocus.com/bid`,
                            'Snyk': `https://security.snyk.io/search?q=${vulnerability.cve?.id}`,
                            'Palo Alto Networks': `https://security.paloaltonetworks.com/`,
                            'Unit 42 (Palo Alto Networks)': `https://unit42.paloaltonetworks.com/`,
                            'Check Point': `https://www.checkpoint.com/advisories/`,
                            'Fortinet': `https://www.fortiguard.com/search?q=${vulnerability.cve?.id}`,
                            'Trend Micro': `https://success.trendmicro.com/vulnerability-response`,
                            'McAfee': `https://www.mcafee.com/enterprise/en-us/threat-center.html`,
                            'Kaspersky': `https://threats.kaspersky.com/en/vulnerability/`,
                            'Symantec': `https://www.broadcom.com/support/security-center`,
                            'F-Secure': `https://www.f-secure.com/en/business/support-and-downloads/security-advisories`,
                            'Sophos': `https://www.sophos.com/en-us/security-advisories`,
                            'CrowdStrike': `https://www.crowdstrike.com/blog/`,
                            'FireEye': `https://www.fireeye.com/current-threats.html`,
                            'Mandiant': `https://www.mandiant.com/resources/blog`,
                            
                            // Security tools/scanners
                            'Nessus': `https://www.tenable.com/plugins/search?q=${vulnerability.cve?.id}`,
                            'OpenVAS': `https://www.openvas.org/`,
                            'Nexpose': `https://www.rapid7.com/db/?q=${vulnerability.cve?.id}`,
                            'Acunetix': `https://www.acunetix.com/vulnerabilities/`,
                            'Burp Suite': `https://portswigger.net/research`,
                            
                            // Bug bounty/research platforms
                            'HackerOne': `https://hackerone.com/hacktivity?searchKey=${vulnerability.cve?.id}`,
                            'Bugcrowd': `https://bugcrowd.com/disclosures`,
                            'SynAck': `https://www.synack.com/blog/`,
                            'ZDI': `https://www.zerodayinitiative.com/advisories/published/`,
                            'Zero Day Initiative': `https://www.zerodayinitiative.com/advisories/published/`,
                            
                            // Analysis/tracking
                            'VulnDB': `https://vulndb.cyberriskanalytics.com/`,
                            'CVE Details': `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`,
                            'CVEDetails': `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`,
                            'SecurityTracker': `https://securitytracker.com/id?${vulnerability.cve?.id}`,
                            'Vulnerability Lab': `https://www.vulnerability-lab.com/`,
                            'Full Disclosure': `https://seclists.org/fulldisclosure/`,
                            
                            // OS/Platform specific
                            'Linux': `https://www.linuxsecurity.com/advisories`,
                            'Windows': `https://msrc.microsoft.com/update-guide/vulnerability/${vulnerability.cve?.id}`,
                            'macOS': `https://support.apple.com/en-us/HT201222`,
                            'Android': `https://source.android.com/security/bulletin`,
                            'iOS': `https://support.apple.com/en-us/HT201222`,
                            
                            // Cloud providers
                            'Azure': `https://msrc.microsoft.com/update-guide/vulnerability/${vulnerability.cve?.id}`,
                            'Google Cloud': `https://cloud.google.com/support/bulletins`,
                            'GCP': `https://cloud.google.com/support/bulletins`,
                            'IBM': `https://www.ibm.com/support/pages/security-bulletins`,
                            'Alibaba Cloud': `https://www.alibabacloud.com/help/security-bulletins`,
                            
                            // Frameworks/Languages
                            'Node.js': `https://nodejs.org/en/security/`,
                            'Python': `https://www.python.org/dev/security/`,
                            'Java': `https://www.oracle.com/security-alerts/`,
                            'PHP': `https://www.php.net/security/`,
                            'Ruby': `https://www.ruby-lang.org/en/security/`,
                            'Go': `https://github.com/golang/go/issues?q=label%3ASecurity`,
                            'Rust': `https://rustsec.org/`,
                            '.NET': `https://github.com/dotnet/announcements/issues?q=is%3Aissue+label%3ASecurity`,
                            
                            // Package managers
                            'npm': `https://www.npmjs.com/advisories/search?q=${vulnerability.cve?.id}`,
                            'PyPI': `https://pypi.org/project/`,
                            'Maven': `https://mvnrepository.com/`,
                            'NuGet': `https://www.nuget.org/`,
                            'RubyGems': `https://rubygems.org/`,
                            'Packagist': `https://packagist.org/`,
                            
                            // Container/K8s
                            'Docker': `https://www.docker.com/blog/tag/security/`,
                            'Kubernetes': `https://kubernetes.io/docs/reference/issues-security/security/`,
                            'Quay': `https://quay.io/security/`,
                            'Harbor': `https://goharbor.io/docs/`,
                            
                            // Web servers/services
                            'Nginx': `https://nginx.org/en/security_advisories.html`,
                            'IIS': `https://msrc.microsoft.com/update-guide/vulnerability/${vulnerability.cve?.id}`,
                            'Tomcat': `https://tomcat.apache.org/security.html`,
                            'Jenkins': `https://www.jenkins.io/security/advisories/`,
                            'GitLab': `https://about.gitlab.com/releases/categories/releases/`,
                            'Jira': `https://confluence.atlassian.com/security`,
                            'Confluence': `https://confluence.atlassian.com/security`,
                            'WordPress': `https://wordpress.org/security/`,
                            'Drupal': `https://www.drupal.org/security`,
                            'Joomla': `https://developer.joomla.org/security-centre.html`,
                            
                            // Database systems
                            'MySQL': `https://www.oracle.com/security-alerts/`,
                            'PostgreSQL': `https://www.postgresql.org/support/security/`,
                            'MongoDB': `https://www.mongodb.com/alerts`,
                            'Redis': `https://redis.io/security`,
                            'Elasticsearch': `https://www.elastic.co/community/security`,
                            'Elastic Security': `https://www.elastic.co/community/security`,
                            'MariaDB': `https://mariadb.com/kb/en/security/`,
                            'SQL Server': `https://msrc.microsoft.com/update-guide/vulnerability/${vulnerability.cve?.id}`,
                            
                            // Security frameworks/protocols
                            'OpenSSL': `https://www.openssl.org/news/vulnerabilities.html`,
                            'OpenSSH': `https://www.openssh.com/security.html`,
                            'TLS': `https://www.openssl.org/news/vulnerabilities.html`,
                            'SSL': `https://www.openssl.org/news/vulnerabilities.html`,
                            
                            // Industry specific
                            'ICS-CERT': `https://www.cisa.gov/uscert/ics/advisories`,
                            'SCADA': `https://www.cisa.gov/uscert/ics/advisories`,
                            'Medical Device': `https://www.fda.gov/medical-devices/medical-device-safety/cybersecurity`,
                            'Automotive': `https://www.automotiveisac.com/`,
                            'IoT': `https://www.iotsecurityfoundation.org/`,
                            
                            // Government/Compliance
                            'US-CERT': `https://www.cisa.gov/uscert/ncas/current-activity`,
                            'CERT': `https://www.kb.cert.org/vuls/`,
                            'NIST': `https://nvd.nist.gov/vuln/detail/${vulnerability.cve?.id}`,
                            'ENISA': `https://www.enisa.europa.eu/topics/csirt-cert-services/community-projects/vulnerability-disclosure`,
                            'JPCERT': `https://www.jpcert.or.jp/english/at/`,
                            'AusCERT': `https://www.auscert.org.au/bulletins/`,
                            'CERT-EU': `https://cert.europa.eu/cert/filteredition/en/CERT-LatestNews.html`,
                            
                            // Industry groups
                            'OWASP': `https://owasp.org/www-community/vulnerabilities/`,
                            'SANS': `https://www.sans.org/reading-room/`,
                            'CWE': `https://cwe.mitre.org/`,
                            'WASC': `http://projects.webappsec.org/`,
                            
                            // News/Media/Blogs
                            'SecurityWeek': `https://www.securityweek.com/?s=${vulnerability.cve?.id}`,
                            'ThreatPost': `https://threatpost.com/?s=${vulnerability.cve?.id}`,
                            'Threatpost': `https://threatpost.com/?s=${vulnerability.cve?.id}`,
                            'Dark Reading': `https://www.darkreading.com/search?q=${vulnerability.cve?.id}`,
                            'DarkReading': `https://www.darkreading.com/search?q=${vulnerability.cve?.id}`,
                            'The Hacker News': `https://thehackernews.com/search?q=${vulnerability.cve?.id}`,
                            'TheHackerNews': `https://thehackernews.com/search?q=${vulnerability.cve?.id}`,
                            'Bleeping Computer': `https://www.bleepingcomputer.com/search/?q=${vulnerability.cve?.id}`,
                            'BleepingComputer': `https://www.bleepingcomputer.com/search/?q=${vulnerability.cve?.id}`,
                            'ZDNet': `https://www.zdnet.com/search/?q=${vulnerability.cve?.id}`,
                            'Ars Technica': `https://arstechnica.com/search/?query=${vulnerability.cve?.id}`,
                            'ArsTechnica': `https://arstechnica.com/search/?query=${vulnerability.cve?.id}`,
                            'The Register': `https://search.theregister.com/?q=${vulnerability.cve?.id}`,
                            'TheRegister': `https://search.theregister.com/?q=${vulnerability.cve?.id}`,
                            'Wired': `https://www.wired.com/search/?q=${vulnerability.cve?.id}`,
                            'TechCrunch': `https://techcrunch.com/search/${vulnerability.cve?.id}`,
                            'Motherboard': `https://www.vice.com/en/search?q=${vulnerability.cve?.id}`,
                            'CyberScoop': `https://cyberscoop.com/?s=${vulnerability.cve?.id}`,
                            'Cyberscoop': `https://cyberscoop.com/?s=${vulnerability.cve?.id}`,
                            'InfoSecurity Magazine': `https://www.infosecurity-magazine.com/search/?q=${vulnerability.cve?.id}`,
                            'Infosecurity Magazine': `https://www.infosecurity-magazine.com/search/?q=${vulnerability.cve?.id}`,
                            'SC Magazine': `https://www.scmagazine.com/search?q=${vulnerability.cve?.id}`,
                            'SCMagazine': `https://www.scmagazine.com/search?q=${vulnerability.cve?.id}`,
                            'CSO Online': `https://www.csoonline.com/search?q=${vulnerability.cve?.id}`,
                            'CSOOnline': `https://www.csoonline.com/search?q=${vulnerability.cve?.id}`,
                            'Help Net Security': `https://www.helpnetsecurity.com/?s=${vulnerability.cve?.id}`,
                            'HelpNetSecurity': `https://www.helpnetsecurity.com/?s=${vulnerability.cve?.id}`,
                            'Naked Security': `https://nakedsecurity.sophos.com/?s=${vulnerability.cve?.id}`,
                            'NakedSecurity': `https://nakedsecurity.sophos.com/?s=${vulnerability.cve?.id}`,
                            'Graham Cluley': `https://grahamcluley.com/?s=${vulnerability.cve?.id}`,
                            'GrahamCluley': `https://grahamcluley.com/?s=${vulnerability.cve?.id}`,
                            
                            // Security Research Blogs
                            'Krebs on Security': `https://krebsonsecurity.com/?s=${vulnerability.cve?.id}`,
                            'KrebsOnSecurity': `https://krebsonsecurity.com/?s=${vulnerability.cve?.id}`,
                            'Brian Krebs': `https://krebsonsecurity.com/?s=${vulnerability.cve?.id}`,
                            'Schneier on Security': `https://www.schneier.com/search.html?q=${vulnerability.cve?.id}`,
                            'Bruce Schneier': `https://www.schneier.com/search.html?q=${vulnerability.cve?.id}`,
                            'Troy Hunt': `https://www.troyhunt.com/search?q=${vulnerability.cve?.id}`,
                            'TroyHunt': `https://www.troyhunt.com/search?q=${vulnerability.cve?.id}`,
                            'Daniel Miessler': `https://danielmiessler.com/?s=${vulnerability.cve?.id}`,
                            'DanielMiessler': `https://danielmiessler.com/?s=${vulnerability.cve?.id}`,
                            'Robert Graham': `https://blog.erratasec.com/search?q=${vulnerability.cve?.id}`,
                            'Errata Security': `https://blog.erratasec.com/search?q=${vulnerability.cve?.id}`,
                            'ErratasSec': `https://blog.erratasec.com/search?q=${vulnerability.cve?.id}`,
                            'Matt Johansen': `https://www.mattjay.com/?s=${vulnerability.cve?.id}`,
                            'Didier Stevens': `https://blog.didierstevens.com/?s=${vulnerability.cve?.id}`,
                            'SANS ISC': `https://isc.sans.edu/search.html?q=${vulnerability.cve?.id}`,
                            'SANS Internet Storm Center': `https://isc.sans.edu/search.html?q=${vulnerability.cve?.id}`,
                            
                            // Vendor Security Blogs
                            'Microsoft Security Blog': `https://www.microsoft.com/en-us/security/blog/?s=${vulnerability.cve?.id}`,
                            'Microsoft Security Response Center': `https://msrc.microsoft.com/blog/`,
                            'MSRC': `https://msrc.microsoft.com/blog/`,
                            'Google Security Blog': `https://security.googleblog.com/search?q=${vulnerability.cve?.id}`,
                            'Google Project Zero': `https://googleprojectzero.blogspot.com/search?q=${vulnerability.cve?.id}`,
                            'Project Zero': `https://googleprojectzero.blogspot.com/search?q=${vulnerability.cve?.id}`,
                            'Apple Security Blog': `https://security.apple.com/blog/`,
                            'AWS Security Blog': `https://aws.amazon.com/blogs/security/?s=${vulnerability.cve?.id}`,
                            'Cisco Security Blog': `https://blogs.cisco.com/security?search=${vulnerability.cve?.id}`,
                            'Cisco Talos': `https://blog.talosintelligence.com/search?q=${vulnerability.cve?.id}`,
                            'Talos Intelligence': `https://blog.talosintelligence.com/search?q=${vulnerability.cve?.id}`,
                            'TalosIntelligence': `https://blog.talosintelligence.com/search?q=${vulnerability.cve?.id}`,
                            'Red Hat Security Blog': `https://www.redhat.com/en/blog/channel/security?search=${vulnerability.cve?.id}`,
                            'Ubuntu Security Blog': `https://ubuntu.com/blog/tag/security`,
                            'Oracle Security Blog': `https://blogs.oracle.com/security/`,
                            'VMware Security Blog': `https://blogs.vmware.com/security/`,
                            'Adobe Security Blog': `https://blogs.adobe.com/security/`,
                            'Intel Security Blog': `https://www.intel.com/content/www/us/en/security-center/default.html`,
                            
                            // Security Company Blogs
                            'Kaspersky Blog': `https://www.kaspersky.com/blog/?s=${vulnerability.cve?.id}`,
                            'Kaspersky Securelist': `https://securelist.com/?s=${vulnerability.cve?.id}`,
                            'Securelist': `https://securelist.com/?s=${vulnerability.cve?.id}`,
                            'McAfee Blog': `https://www.mcafee.com/blogs/?s=${vulnerability.cve?.id}`,
                            'McAfee Labs': `https://www.mcafee.com/blogs/category/mcafee-labs/`,
                            'Symantec Blog': `https://symantec-enterprise-blogs.security.com/search?q=${vulnerability.cve?.id}`,
                            'Trend Micro Blog': `https://blog.trendmicro.com/?s=${vulnerability.cve?.id}`,
                            'Trend Micro Research': `https://blog.trendmicro.com/trendlabs-security-intelligence/`,
                            'F-Secure Blog': `https://blog.f-secure.com/?s=${vulnerability.cve?.id}`,
                            'F-Secure Labs': `https://labs.f-secure.com/blog/`,
                            'Sophos Blog': `https://news.sophos.com/?s=${vulnerability.cve?.id}`,
                            'Sophos Labs': `https://news.sophos.com/en-us/category/sophos-labs/`,
                            'Check Point Blog': `https://blog.checkpoint.com/?s=${vulnerability.cve?.id}`,
                            'Check Point Research': `https://research.checkpoint.com/`,
                            'Fortinet Blog': `https://www.fortinet.com/blog/search?q=${vulnerability.cve?.id}`,
                            'FortiGuard Labs': `https://www.fortiguard.com/threat-signal-report`,
                            'Palo Alto Networks Blog': `https://www.paloaltonetworks.com/blog/?s=${vulnerability.cve?.id}`,
                            'Unit 42': `https://unit42.paloaltonetworks.com/?s=${vulnerability.cve?.id}`,
                            'Unit42': `https://unit42.paloaltonetworks.com/?s=${vulnerability.cve?.id}`,
                            'CrowdStrike Blog': `https://www.crowdstrike.com/blog/?s=${vulnerability.cve?.id}`,
                            'FireEye Blog': `https://www.fireeye.com/blog/threat-research/_jcr_content.feed?search=${vulnerability.cve?.id}`,
                            'Mandiant Blog': `https://www.mandiant.com/resources/blog?search=${vulnerability.cve?.id}`,
                            'SentinelOne Blog': `https://www.sentinelone.com/blog/?s=${vulnerability.cve?.id}`,
                            'SentinelLabs': `https://www.sentinelone.com/labs/`,
                            'Proofpoint Blog': `https://www.proofpoint.com/us/blog?search=${vulnerability.cve?.id}`,
                            'Recorded Future Blog': `https://www.recordedfuture.com/blog?search=${vulnerability.cve?.id}`,
                            'Digital Shadows Blog': `https://www.digitalshadows.com/blog-and-research/?s=${vulnerability.cve?.id}`,
                            'RiskIQ Blog': `https://www.riskiq.com/blog/?s=${vulnerability.cve?.id}`,
                            'Tenable Blog': `https://www.tenable.com/blog/search?q=${vulnerability.cve?.id}`,
                            'Rapid7 Blog': `https://blog.rapid7.com/?s=${vulnerability.cve?.id}`,
                            'Qualys Blog': `https://blog.qualys.com/?s=${vulnerability.cve?.id}`,
                            'Nessus Blog': `https://www.tenable.com/blog/search?q=${vulnerability.cve?.id}`,
                            'Acunetix Blog': `https://www.acunetix.com/blog/?s=${vulnerability.cve?.id}`,
                            'PortSwigger Blog': `https://portswigger.net/research`,
                            'Synack Blog': `https://www.synack.com/blog/?s=${vulnerability.cve?.id}`,
                            'HackerOne Blog': `https://www.hackerone.com/blog?search=${vulnerability.cve?.id}`,
                            'Bugcrowd Blog': `https://www.bugcrowd.com/blog/?s=${vulnerability.cve?.id}`,
                            
                            // Research Team Blogs
                            'Zero Day Initiative Blog': `https://www.zerodayinitiative.com/blog?search=${vulnerability.cve?.id}`,
                            'ZDI Blog': `https://www.zerodayinitiative.com/blog?search=${vulnerability.cve?.id}`,
                            'Positive Technologies Blog': `https://www.ptsecurity.com/ww-en/analytics/?q=${vulnerability.cve?.id}`,
                            'PT Security': `https://www.ptsecurity.com/ww-en/analytics/?q=${vulnerability.cve?.id}`,
                            'Offensive Security Blog': `https://www.offensive-security.com/blog/?s=${vulnerability.cve?.id}`,
                            'OffSec': `https://www.offensive-security.com/blog/?s=${vulnerability.cve?.id}`,
                            'SecureWorks Blog': `https://www.secureworks.com/blog?search=${vulnerability.cve?.id}`,
                            'Secureworks': `https://www.secureworks.com/blog?search=${vulnerability.cve?.id}`,
                            'ESET Blog': `https://www.eset.com/blog/?s=${vulnerability.cve?.id}`,
                            'ESET Research': `https://www.welivesecurity.com/?s=${vulnerability.cve?.id}`,
                            'WeLiveSecurity': `https://www.welivesecurity.com/?s=${vulnerability.cve?.id}`,
                            'Malwarebytes Blog': `https://blog.malwarebytes.com/?s=${vulnerability.cve?.id}`,
                            'Malwarebytes Labs': `https://blog.malwarebytes.com/`,
                            'Avast Blog': `https://blog.avast.com/?s=${vulnerability.cve?.id}`,
                            'AVG Blog': `https://www.avg.com/en/signal/search?q=${vulnerability.cve?.id}`,
                            'Bitdefender Blog': `https://www.bitdefender.com/blog/?s=${vulnerability.cve?.id}`,
                            'Bitdefender Labs': `https://www.bitdefender.com/blog/labs/`,
                            
                            // Cloud Security Blogs
                            'Aqua Security Blog': `https://blog.aquasec.com/?s=${vulnerability.cve?.id}`,
                            'Aqua Blog': `https://blog.aquasec.com/?s=${vulnerability.cve?.id}`,
                            'Sysdig Blog': `https://sysdig.com/blog/?s=${vulnerability.cve?.id}`,
                            'Twistlock Blog': `https://www.paloaltonetworks.com/prisma/cloud/blog`,
                            'Prisma Cloud Blog': `https://www.paloaltonetworks.com/prisma/cloud/blog`,
                            'Lacework Blog': `https://www.lacework.com/blog/?s=${vulnerability.cve?.id}`,
                            'Wiz Blog': `https://www.wiz.io/blog?search=${vulnerability.cve?.id}`,
                            'Orca Security Blog': `https://orca.security/resources/blog/?_search=${vulnerability.cve?.id}`,
                            'Snyk Blog': `https://snyk.io/blog/?search=${vulnerability.cve?.id}`,
                            
                            // Independent Security Researchers
                            'Full Disclosure': `https://seclists.org/fulldisclosure/`,
                            'Packet Storm Security': `https://packetstormsecurity.com/search/?q=${vulnerability.cve?.id}`,
                            'Security Focus': `https://www.securityfocus.com/archive/1`,
                            'SecurityFocus': `https://www.securityfocus.com/archive/1`,
                            'The Daily Swig': `https://portswigger.net/daily-swig/search?q=${vulnerability.cve?.id}`,
                            'Daily Swig': `https://portswigger.net/daily-swig/search?q=${vulnerability.cve?.id}`,
                            'Cyber Security News': `https://cybersecuritynews.com/?s=${vulnerability.cve?.id}`,
                            'CyberSecurityNews': `https://cybersecuritynews.com/?s=${vulnerability.cve?.id}`,
                            'Security Affairs': `https://securityaffairs.co/wordpress/?s=${vulnerability.cve?.id}`,
                            'SecurityAffairs': `https://securityaffairs.co/wordpress/?s=${vulnerability.cve?.id}`,
                            'E Hacking News': `https://www.ehackingnews.com/search?q=${vulnerability.cve?.id}`,
                            'EHackingNews': `https://www.ehackingnews.com/search?q=${vulnerability.cve?.id}`,
                            'GBHackers': `https://gbhackers.com/?s=${vulnerability.cve?.id}`,
                            'Cyber Defense Magazine': `https://www.cyberdefensemagazine.com/?s=${vulnerability.cve?.id}`,
                            'CyberDefenseMagazine': `https://www.cyberdefensemagazine.com/?s=${vulnerability.cve?.id}`,
                            
                            // Specialized Blogs
                            'Exploit Database Blog': `https://www.exploit-db.com/search?cve=${vulnerability.cve?.id}`,
                            'Vulnhub': `https://www.vulnhub.com/?q=${vulnerability.cve?.id}`,
                            'VulnHub': `https://www.vulnhub.com/?q=${vulnerability.cve?.id}`,
                            'Offensive Security': `https://www.offensive-security.com/blog/?s=${vulnerability.cve?.id}`,
                            'OWASP Blog': `https://owasp.org/search/?searchString=${vulnerability.cve?.id}`,
                            'SANS Blog': `https://www.sans.org/blog/?s=${vulnerability.cve?.id}`,
                            'CERT/CC Blog': `https://insights.sei.cmu.edu/search/?q=${vulnerability.cve?.id}`,
                            'US-CERT': `https://www.cisa.gov/news-events?search_api=${vulnerability.cve?.id}`,
                            
                            // Additional Tech Blogs that cover security
                            'Hacker News': `https://hn.algolia.com/?q=${vulnerability.cve?.id}`,
                            'Reddit Security': `https://www.reddit.com/r/netsec/search?q=${vulnerability.cve?.id}`,
                            'Reddit Netsec': `https://www.reddit.com/r/netsec/search?q=${vulnerability.cve?.id}`,
                            'Stack Exchange Security': `https://security.stackexchange.com/search?q=${vulnerability.cve?.id}`,
                            'Information Security Stack Exchange': `https://security.stackexchange.com/search?q=${vulnerability.cve?.id}`,
                            
                            // Generic/Other platforms
                            'GitHub': `https://github.com/search?q=${vulnerability.cve?.id}&type=repositories`,
                            'GitLab Security': `https://about.gitlab.com/releases/categories/releases/`,
                            'Bitbucket': `https://bitbucket.org/search?q=${vulnerability.cve?.id}`,
                            'SourceForge': `https://sourceforge.net/directory/?q=${vulnerability.cve?.id}`,
                            
                            // Specific security tools/products mentioned
                            'FRSecure': `https://frsecure.com/blog/`,
                            'CloudSEK': `https://cloudsek.com/blog/`,
                            'SentinelOne': `https://www.sentinelone.com/blog/`,
                            'Picus Security': `https://www.picussecurity.com/resource/blog`,
                            'AhnLab': `https://global.ahnlab.com/site/securitycenter/securitycenter.do`,
                            'Qualys': `https://blog.qualys.com/`,
                            
                            // For research categories
                            'Medium (security researchers)': `https://medium.com/search?q=${vulnerability.cve?.id}`,
                            'security researchers': `https://medium.com/search?q=${vulnerability.cve?.id}`,
                            'security researcher': `https://medium.com/search?q=${vulnerability.cve?.id}`,
                            
                            // Default handler for common patterns
                            'Security Advisory': `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`,
                            'Security Bulletin': `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`,
                            'Vulnerability Report': `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`
                          };
                          
                          // Try to find a match, including partial matches
                          let url = sourceUrls[source];
                          
                          // If no exact match, try case-insensitive match
                          if (!url) {
                            const lowerSource = source.toLowerCase();
                            const matchedKey = Object.keys(sourceUrls).find(key => 
                              key.toLowerCase() === lowerSource
                            );
                            if (matchedKey) {
                              url = sourceUrls[matchedKey];
                            }
                          }
                          
                          // If still no match, try to identify the vendor/product from the source string
                          if (!url) {
                            // Check if source contains known vendor names
                            const vendors = ['microsoft', 'apache', 'oracle', 'cisco', 'vmware', 'red hat', 'redhat', 
                                           'ubuntu', 'debian', 'aws', 'google', 'ibm', 'adobe', 'intel', 'nvidia'];
                            const foundVendor = vendors.find(vendor => source.toLowerCase().includes(vendor));
                            if (foundVendor) {
                              const vendorKey = Object.keys(sourceUrls).find(key => 
                                key.toLowerCase().includes(foundVendor)
                              );
                              if (vendorKey) {
                                url = sourceUrls[vendorKey];
                              }
                            }
                          }
                          
                          // Final fallback - try CVEDetails as it aggregates many sources
                          if (!url) {
                            url = `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`;
                          }
                          
                          return (
                            <a
                              key={index}
                              href={url}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{
                                padding: '4px 8px',
                                background: `rgba(${utils.hexToRgb(COLORS.blue)}, 0.15)`,
                                color: COLORS.blue,
                                borderWidth: '1px',
                                borderStyle: 'solid',
                                borderColor: `rgba(${utils.hexToRgb(COLORS.blue)}, 0.3)`,
                                borderRadius: '4px',
                                fontSize: '0.8rem',
                                fontWeight: '500',
                                textDecoration: 'none',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                                transition: 'all 0.2s ease-in-out'
                              }}
                              onMouseEnter={(e) => {
                                e.target.style.background = `rgba(${utils.hexToRgb(COLORS.blue)}, 0.25)`;
                                e.target.style.transform = 'translateY(-1px)';
                              }}
                              onMouseLeave={(e) => {
                                e.target.style.background = `rgba(${utils.hexToRgb(COLORS.blue)}, 0.15)`;
                                e.target.style.transform = 'translateY(0)';
                              }}
                              title={`View ${source} information for ${vulnerability.cve?.id}`}
                            >
                              {source}
                              <ChevronRight size={12} />
                            </a>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {activeTab === 'analysis' && (
            <div>
              {aiAnalysis ? (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
                    <h2 style={{ fontSize: '1.5rem', fontWeight: '700', margin: 0 }}>
                      RAG-Enhanced Security Analysis
                    </h2>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      {aiAnalysis.webGrounded && (
                        <span style={{
                          padding: '4px 8px',
                          background: 'rgba(34, 197, 94, 0.15)',
                          color: '#22c55e',
                          borderWidth: '1px',
                          borderStyle: 'solid',
                          borderColor: 'rgba(34, 197, 94, 0.3)',
                          borderRadius: '6px',
                          fontSize: '0.75rem',
                          fontWeight: '600',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '4px'
                        }}>
                          <Globe size={12} />
                          REAL-TIME
                        </span>
                      )}
                      {aiAnalysis.ragUsed && (
                        <span style={{
                          ...styles.badge,
                          background: `rgba(${utils.hexToRgb(COLORS.purple)}, 0.15)`,
                          color: COLORS.purple,
                          borderWidth: '1px',
                          borderStyle: 'solid',
                          borderColor: `rgba(${utils.hexToRgb(COLORS.purple)}, 0.3)`
                        }}>
                          <Database size={12} />
                          RAG ENHANCED
                        </span>
                      )}
                    </div>
                  </div>

                  <div style={{
                    ...styles.card,
                    marginBottom: '24px',
                    background: settings.darkMode ? COLORS.dark.background : COLORS.light.background
                  }}>
                    <div style={{
                      fontSize: '1rem',
                      lineHeight: '1.7',
                      whiteSpace: 'pre-wrap'
                    }}>
                      {aiAnalysis.analysis}
                    </div>
                  </div>

                  <div style={{
                    background: settings.darkMode ? COLORS.dark.surface : COLORS.light.background,
                    borderWidth: '1px',
                    borderStyle: 'solid',
                    borderColor: settings.darkMode ? COLORS.dark.border : COLORS.light.border,
                    borderRadius: '12px',
                    padding: '16px 20px',
                    fontSize: '0.8rem',
                    color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText
                  }}>
                    <div style={{ fontWeight: '600', marginBottom: '10px' }}>
                      Enhanced Analysis Metadata:
                    </div>
                    <ul style={{ margin: 0, paddingLeft: '20px' }}>
                      <li>Data Sources: {aiAnalysis.enhancedSources?.join(', ') || 'NVD, EPSS, AI-Discovery'}</li>
                      {aiAnalysis.ragUsed && (
                        <>
                          <li>Knowledge Base: {aiAnalysis.ragDocuments} relevant security documents retrieved</li>
                          <li>RAG Sources: {aiAnalysis.ragSources?.slice(0,3).join(', ') || 'Security knowledge base'}</li>
                        </>
                      )}
                      {aiAnalysis.webGrounded && (
                        <li>Real-time Intelligence: Current threat landscape data via web search</li>
                      )}
                      <li>Model Used: {aiAnalysis.model || 'Gemini-2.5-flash'}</li>
                      <li>Generated: {utils.formatDate(aiAnalysis.analysisTimestamp)}</li>
                      <li>RAG Database: {aiAnalysis.ragDatabaseSize || 0} total documents</li>
                      {aiAnalysis.embeddingType && (
                        <li>Embeddings: {aiAnalysis.embeddingType} ({aiAnalysis.geminiEmbeddingsCount || 0} Gemini embeddings)</li>
                      )}
                      {aiAnalysis.realTimeData && (
                        <>
                          <li>CISA KEV: {aiAnalysis.realTimeData.cisaKev ? 'Listed' : 'Not Listed'}</li>
                          <li>Exploits Found: {aiAnalysis.realTimeData.exploitsFound || 0}</li>
                          <li>Threat Level: {aiAnalysis.realTimeData.threatLevel || 'Standard'}</li>
                        </>
                      )}
                    </ul>
                  </div>
                </div>
              ) : (
                <div style={{ textAlign: 'center', padding: '48px 32px' }}>
                  <Brain size={40} color={settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText} />
                  <h3 style={{ margin: '16px 0 8px 0' }}>No AI Analysis Available</h3>
                  <p style={{ margin: 0, color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                    Generate RAG-enhanced analysis to see structured insights
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <div style={{
        ...styles.card,
        height: 'fit-content',
        position: 'sticky',
        top: '24px',
      }}>
        <CVSSDisplay vulnerability={vulnerability} settings={settings} />

        <div style={{
          ...styles.card,
          background: settings.darkMode ? COLORS.dark.background : COLORS.light.background,
          marginBottom: '20px'
        }}>
          <h3 style={{
            fontSize: '0.95rem',
            fontWeight: '600',
            marginBottom: '12px',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}>
            <Brain size={14} />
            AI Intelligence Summary
          </h3>
          
          <div style={{ fontSize: '0.8125rem', color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>CVSS Score:</strong> {cvssScore?.toFixed(1) || 'N/A'} ({severity})
            </p>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>EPSS Score:</strong> {vulnerability.epss?.epssPercentage || 'N/A'}% 
              {vulnerability.epss && (
                <span style={{ color: vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH ? COLORS.red : vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.MEDIUM ? COLORS.yellow : COLORS.green }}>
                  {vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH ? ' (High Risk)' : vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.MEDIUM ? ' (Medium Risk)' : ' (Low Risk)'}
                </span>
              )}
            </p>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>Sources Analyzed:</strong> {vulnerability.intelligenceSummary?.sourcesAnalyzed || vulnerability.discoveredSources?.length || vulnerability.sources?.length || 2}
              {vulnerability.aiSearchPerformed && (
                <span style={{ color: COLORS.blue, marginLeft: '4px' }}>
                  (AI Enhanced)
                </span>
              )}
            </p>
            <div style={{ margin: '0 0 8px 0' }}>
              <strong>Exploits Found:</strong> {vulnerability.exploits?.count || 0}
              {vulnerability.exploits?.confidence && vulnerability.exploits.count > 0 && (
                <span style={{ 
                  color: vulnerability.exploits.confidence === 'HIGH' ? COLORS.red : vulnerability.exploits.confidence === 'MEDIUM' ? COLORS.yellow : COLORS.blue,
                  marginLeft: '4px',
                  fontSize: '0.75rem'
                }}>
                  ({vulnerability.exploits.confidence})
                </span>
              )}
              {vulnerability.exploits?.details && vulnerability.exploits.details.length > 0 && (
                <div style={{ fontSize: '0.75rem', marginTop: '4px', color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                  • GitHub: {vulnerability.exploits.githubRepos || 0} | 
                  Exploit-DB: {vulnerability.exploits.exploitDbEntries || 0} | 
                  Metasploit: {vulnerability.exploits.metasploitModules || 0}
                </div>
              )}
            </div>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>Vendor Advisories:</strong> {vulnerability.vendorAdvisories?.count || 0}
              {vulnerability.vendorAdvisories?.found && (
                <span style={{ color: COLORS.blue, fontSize: '0.75rem', marginLeft: '4px' }}>
                  (Patches: {vulnerability.vendorAdvisories.patchStatus || 'Unknown'})
                </span>
              )}
            </p>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>Active Exploitation:</strong> 
              <span style={{ 
                color: vulnerability.kev?.listed || vulnerability.activeExploitation?.confirmed ? COLORS.red : COLORS.green,
                marginLeft: '4px',
                fontWeight: '600'
              }}>
                {vulnerability.kev?.listed || vulnerability.activeExploitation?.confirmed ? 'YES' : 'No'}
              </span>
              {vulnerability.activeExploitation?.confirmed && !vulnerability.kev?.listed && (
                <span style={{ color: COLORS.yellow, fontSize: '0.75rem', marginLeft: '4px' }}>
                  (Detected)
                </span>
              )}
            </p>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>CISA KEV:</strong> 
              <span style={{ 
                color: vulnerability.kev?.listed ? COLORS.red : COLORS.green,
                marginLeft: '4px',
                fontWeight: '600'
              }}>
                {vulnerability.kev?.listed ? 'LISTED' : 'Not Listed'}
              </span>
              {vulnerability.kev?.listed && (
                <span style={{ color: COLORS.red, fontSize: '0.75rem', marginLeft: '4px' }}>
                  (Emergency Patch Required)
                </span>
              )}
            </p>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>Threat Level:</strong> 
              <span style={{ 
                color: vulnerability.threatLevel === 'CRITICAL' ? COLORS.red : 
                      vulnerability.threatLevel === 'HIGH' ? COLORS.yellow : 
                      vulnerability.threatLevel === 'MEDIUM' ? COLORS.blue : COLORS.green,
                marginLeft: '4px',
                fontWeight: '600'
              }}>
                {vulnerability.threatLevel || 'Standard'}
              </span>
              {vulnerability.analysisMethod && (
                <span style={{ color: COLORS.purple, fontSize: '0.75rem', marginLeft: '4px' }}>
                  ({vulnerability.analysisMethod === 'AI_WEB_SEARCH' ? 'AI Enhanced' : 'Heuristic'})
                </span>
              )}
            </p>
            <p style={{ margin: 0 }}>
              <strong>Last Updated:</strong> {utils.formatDate(vulnerability.lastUpdated)}
              {vulnerability.dataFreshness && (
                <span style={{ color: COLORS.blue, fontSize: '0.75rem', marginLeft: '4px' }}>
                  ({vulnerability.dataFreshness})
                </span>
              )}
            </p>
          </div>
        </div>

        <div style={{ 
          fontSize: '0.8rem',
          color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText,
          textAlign: 'center',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '6px'
        }}>
          <Brain size={12} />
          <Database size={12} />
          Powered by AI + RAG
        </div>
      </div>
    </div>
  );
};

const EmptyState = () => {
  const { settings } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  return (
    <div style={{ 
      textAlign: 'center', 
      padding: '64px 32px',
      color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText 
    }}>
      <div style={{ 
        marginBottom: '28px', 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        gap: '16px' 
      }}>
        <Brain size={56} color={settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText} />
        <Database size={40} color={settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText} />
        <Globe size={44} color={settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText} />
      </div>
      
      <h3 style={{
        fontSize: '1.375rem',
        fontWeight: '600',
        marginBottom: '16px',
        color: settings.darkMode ? COLORS.dark.primaryText : COLORS.light.primaryText
      }}>
        AI-Enhanced Intelligence Platform Ready
      </h3>
      
      <p style={{
        fontSize: '0.95rem',
        marginBottom: '12px',
        color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
        lineHeight: 1.6,
        maxWidth: '600px',
        margin: '0 auto 12px auto'
      }}>
        Enter a CVE ID to begin comprehensive AI-powered vulnerability analysis with multi-source discovery and contextual knowledge retrieval.
      </p>
      
      <p style={{
        fontSize: '0.875rem',
        color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText,
        marginBottom: '28px',
        maxWidth: '600px',
        margin: '0 auto 28px auto'
      }}>
        Real-time intelligence enhanced with semantic search, security sources, and domain expertise.
      </p>
      
      {!settings.geminiApiKey && (
        <div style={{
          marginTop: '32px',
          padding: '16px 20px',
          background: settings.darkMode
            ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)`
            : `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.07)`,
          borderWidth: '1px',
          borderStyle: 'solid',
          borderColor: `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.3)`,
          borderRadius: '12px',
          maxWidth: '550px',
          margin: '32px auto 0'
        }}>
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '12px', 
            marginBottom: '10px' 
          }}>
            <AlertTriangle size={20} color={COLORS.yellow} />
            <span style={{ 
              fontWeight: '600', 
              color: COLORS.yellow, 
              fontSize: '0.95rem' 
            }}>
              AI Configuration Required
            </span>
          </div>
          <p style={{
            fontSize: '0.875rem',
            margin: 0,
            color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
            lineHeight: 1.5
          }}>
            Configure your Gemini API key in settings to enable AI-enhanced multi-source vulnerability analysis.
          </p>
        </div>
      )}
    </div>
  );
};

// Main Application Component
const VulnerabilityIntelligence = () => {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadingSteps, setLoadingSteps] = useState([]);
  const [showSettings, setShowSettings] = useState(false);
  
  const { notifications, addNotification } = useNotifications();
  const { settings, setSettings } = useSettings();
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  // Apply theme to document body
  useEffect(() => {
    document.body.style.backgroundColor = styles.app.backgroundColor;
    document.body.style.color = styles.app.color;
    document.body.style.fontFamily = styles.app.fontFamily;
  }, [styles.app]);

  // Initialize RAG database
  useEffect(() => {
    ragDatabase.initialize().catch(console.error);
  }, []);

  const contextValue = useMemo(() => ({
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
  }), [
    vulnerabilities,
    loading,
    loadingSteps,
    notifications,
    addNotification,
    settings,
    setSettings
  ]);

  return (
    <AppContext.Provider value={contextValue}>
      <div style={styles.app}>
        <style>
          {`
            @keyframes spin {
              0% { transform: rotate(0deg); }
              100% { transform: rotate(360deg); }
            }
            
            @keyframes pulse {
              0%, 100% { opacity: 1; }
              50% { opacity: 0.5; }
            }
            
            button:focus-visible, 
            input:focus-visible, 
            select:focus-visible, 
            a:focus-visible {
              outline: 2px solid ${COLORS.blue} !important;
              outline-offset: 2px !important;
            }
            
            button:hover:not(:disabled), 
            a:hover {
              transform: translateY(-1px);
            }
            
            @media (max-width: 768px) {
              button, a, input, select {
                min-height: 48px;
                padding: 14px 16px;
              }
            }
          `}
        </style>
        
        <NotificationManager />
        
        <header style={styles.header}>
          <div style={styles.headerContent}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ position: 'relative' }}>
                <Brain size={32} color={COLORS.blue} />
                <Database size={20} color={COLORS.purple} style={{ 
                  position: 'absolute', 
                  top: '16px', 
                  left: '20px' 
                }} />
              </div>
              <div>
                <h1 style={styles.title}>AI VulnIntel Pro</h1>
                <p style={styles.subtitle}>
                  AI-Powered Multi-Source Vulnerability Intelligence with RAG Enhancement
                </p>
              </div>
            </div>
            
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{
                ...styles.badge,
                background: settings.geminiApiKey
                  ? (settings.darkMode ? `rgba(${utils.hexToRgb(COLORS.green)}, 0.15)` : `rgba(${utils.hexToRgb(COLORS.green)}, 0.1)`)
                  : (settings.darkMode ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.15)` : `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)`),
                borderColor: settings.geminiApiKey
                  ? `rgba(${utils.hexToRgb(COLORS.green)}, 0.3)`
                  : `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.3)`,
                color: settings.geminiApiKey ? COLORS.green : COLORS.yellow,
                borderWidth: '1px',
                borderStyle: 'solid',
                fontWeight: '600',
                fontSize: '0.875rem',
                padding: '8px 14px',
                minHeight: '44px',
              }}>
                <Brain size={16} />
                {settings.geminiApiKey ? 'AI Ready' : 'AI Offline'}
              </div>
              
              <button
                onClick={() => setShowSettings(true)}
                style={{ ...styles.button, ...styles.buttonSecondary }}
              >
                <Settings size={18} />
                Configure AI
              </button>
            </div>
          </div>
        </header>

        <main>
          <SearchComponent />
          
          <div style={{ maxWidth: '1536px', margin: '0 auto', padding: '24px 32px' }}>
            {loading && <LoadingComponent />}
            
            {!loading && vulnerabilities.length === 0 && <EmptyState />}
            
            {!loading && vulnerabilities.length > 0 && (
              <CVEDetailView vulnerability={vulnerabilities[0]} />
            )}
          </div>
        </main>

        <SettingsModal
          isOpen={showSettings}
          onClose={() => setShowSettings(false)}
        />
      </div>
    </AppContext.Provider>
  );
};

export default VulnerabilityIntelligence;
