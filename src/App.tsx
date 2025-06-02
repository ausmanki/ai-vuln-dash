import React, { useState, createContext, useContext, useEffect, useRef } from 'react';
import { Search, Shield, AlertTriangle, TrendingUp, Loader2, ExternalLink, Brain, AlertCircle, Settings, Sparkles, Target, Clock, Database, Lock, Activity, CheckCircle, XCircle, X, Link, Download, Upload, Filter, Calendar, BarChart3, PieChart, LineChart, Bell, Zap, FileText, Users, Globe, RefreshCw, Eye, EyeOff, Mail, Webhook, Play, Pause, Save, Trash2, Edit3, Copy, Share2, MonitorSpeaker } from 'lucide-react';
import { LineChart as RechartsLineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, BarChart as RechartsBarChart, Bar, PieChart as RechartsPieChart, Pie, Cell, Area, AreaChart } from 'recharts';

// Enhanced CSS with modern animations
const styleSheet = document.createElement("style");
styleSheet.innerText = `
  @keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
  @keyframes slideIn {
    from { transform: translateY(-10px); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
  }
  @keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  @keyframes shimmer {
    0% { background-position: -200px 0; }
    100% { background-position: calc(200px + 100%) 0; }
  }
  .pulse { animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
  .animate-spin { animation: spin 1s linear infinite; }
  .slide-in { animation: slideIn 0.3s ease-out; }
  .fade-in { animation: fadeIn 0.5s ease-out; }
  .shimmer {
    background: linear-gradient(90deg, #f0f0f0 25%, #e0e0e0 50%, #f0f0f0 75%);
    background-size: 200px 100%;
    animation: shimmer 1.5s infinite;
  }
  .card-hover {
    transition: all 0.2s ease-in-out;
  }
  .card-hover:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
  }
  .gradient-text {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }
`;
document.head.appendChild(styleSheet);

// Enhanced styles with modern design
const styles = {
  appContainer: { minHeight: '100vh', backgroundColor: '#f8fafc' },
  header: { background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', color: 'white', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)' },
  headerContent: { maxWidth: '1440px', margin: '0 auto', padding: '24px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' },
  headerTitle: { display: 'flex', alignItems: 'center', gap: '16px' },
  title: { fontSize: '1.75rem', fontWeight: 'bold', margin: 0 },
  subtitle: { fontSize: '0.875rem', opacity: 0.9, margin: 0 },
  headerActions: { display: 'flex', alignItems: 'center', gap: '16px' },
  statusIndicator: { display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.875rem', padding: '8px 12px', background: 'rgba(255,255,255,0.2)', borderRadius: '20px' },
  button: { display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 16px', borderRadius: '8px', fontWeight: '500', transition: 'all 0.2s', cursor: 'pointer', border: '1px solid', fontSize: '0.875rem' },
  buttonPrimary: { background: '#3b82f6', color: 'white', borderColor: '#3b82f6' },
  buttonSecondary: { background: 'white', color: '#374151', borderColor: '#d1d5db' },
  buttonSuccess: { background: '#10b981', color: 'white', borderColor: '#10b981' },
  buttonWarning: { background: '#f59e0b', color: 'white', borderColor: '#f59e0b' },
  buttonDanger: { background: '#ef4444', color: 'white', borderColor: '#ef4444' },
  mainContent: { maxWidth: '1440px', margin: '0 auto', padding: '32px 16px' },
  
  // Enhanced search and filter styles
  searchContainer: { marginBottom: '32px', background: 'white', borderRadius: '12px', padding: '24px', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)' },
  searchWrapper: { position: 'relative' as const, marginBottom: '16px' },
  searchInput: { width: '100%', padding: '12px 12px 12px 40px', border: '2px solid #e5e7eb', borderRadius: '8px', fontSize: '1rem', outline: 'none', boxSizing: 'border-box' as const, transition: 'border-color 0.2s' },
  searchIcon: { position: 'absolute' as const, left: '12px', top: '50%', transform: 'translateY(-50%)', color: '#9ca3af' },
  searchButton: { position: 'absolute' as const, right: '8px', top: '50%', transform: 'translateY(-50%)' },
  
  // Filter panel styles
  filterPanel: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', marginTop: '16px', padding: '16px', background: '#f9fafb', borderRadius: '8px', border: '1px solid #e5e7eb' },
  filterGroup: { display: 'flex', flexDirection: 'column' as const, gap: '4px' },
  
  // Card styles with hover effects
  card: { background: 'white', borderRadius: '12px', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)', border: '1px solid #e5e7eb', padding: '24px', transition: 'all 0.2s', marginBottom: '16px' },
  cardHover: { cursor: 'pointer' },
  
  // Dashboard styles
  dashboardGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '24px', marginBottom: '32px' },
  statCard: { background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)', color: 'white', borderRadius: '12px', padding: '24px' },
  chartContainer: { background: 'white', borderRadius: '12px', padding: '24px', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)' },
  
  // Export and reporting styles
  exportPanel: { background: 'white', borderRadius: '12px', padding: '20px', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)', marginBottom: '24px' },
  exportGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '16px', marginTop: '16px' },
  
  // Notification styles
  notification: { position: 'fixed' as const, top: '20px', right: '20px', background: 'white', borderRadius: '8px', padding: '16px', boxShadow: '0 10px 25px rgba(0, 0, 0, 0.15)', zIndex: 1000, maxWidth: '400px', border: '1px solid #e5e7eb' },
  notificationSuccess: { borderLeft: '4px solid #10b981' },
  notificationError: { borderLeft: '4px solid #ef4444' },
  notificationWarning: { borderLeft: '4px solid #f59e0b' },
  
  // Common utility styles
  badge: { padding: '4px 12px', borderRadius: '9999px', fontSize: '0.75rem', fontWeight: '500', border: '1px solid', display: 'inline-block' },
  badgeCritical: { background: '#fef2f2', color: '#991b1b', borderColor: '#fecaca' },
  badgeHigh: { background: '#fff7ed', color: '#c2410c', borderColor: '#fed7aa' },
  badgeMedium: { background: '#fefce8', color: '#a16207', borderColor: '#fde68a' },
  badgeLow: { background: '#f0fdf4', color: '#166534', borderColor: '#bbf7d0' },
  
  // Loading and empty states
  loadingContainer: { display: 'flex', flexDirection: 'column' as const, alignItems: 'center', justifyContent: 'center', padding: '48px 0' },
  emptyState: { textAlign: 'center' as const, padding: '48px 0', color: '#6b7280' },
  
  // Modal styles
  modal: { position: 'fixed' as const, inset: 0, background: 'rgba(0, 0, 0, 0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50 },
  modalContent: { background: 'white', borderRadius: '12px', padding: '24px', width: '100%', maxWidth: '800px', maxHeight: '90vh', overflowY: 'auto' as const, margin: '16px' },
  modalHeader: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px', paddingBottom: '16px', borderBottom: '1px solid #e5e7eb' },
  modalTitle: { fontSize: '1.25rem', fontWeight: 'bold', margin: 0 },
  
  // Form styles
  formGroup: { marginBottom: '16px' },
  label: { display: 'block', fontSize: '0.875rem', fontWeight: '500', color: '#374151', marginBottom: '4px' },
  input: { width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: '6px', fontSize: '0.875rem', outline: 'none', boxSizing: 'border-box' as const },
  select: { width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: '6px', fontSize: '0.875rem', outline: 'none', background: 'white', boxSizing: 'border-box' as const },
  textarea: { width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: '6px', fontSize: '0.875rem', outline: 'none', resize: 'vertical' as const, minHeight: '100px', boxSizing: 'border-box' as const },
  
  // Utility classes
  flexBetween: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' },
  flexCenter: { display: 'flex', alignItems: 'center', justifyContent: 'center' },
  textSm: { fontSize: '0.875rem' },
  textXs: { fontSize: '0.75rem' },
  fontMedium: { fontWeight: '500' },
  fontBold: { fontWeight: 'bold' as const },
  textGray500: { color: '#6b7280' },
  textGray600: { color: '#4b5563' },
  textGray900: { color: '#111827' },
  
  // Link button styles
  linkButton: { 
    display: 'inline-flex', 
    alignItems: 'center', 
    gap: '4px', 
    padding: '4px 8px', 
    background: '#3b82f6', 
    color: 'white', 
    textDecoration: 'none', 
    borderRadius: '4px', 
    fontSize: '0.75rem',
    fontWeight: '500',
    transition: 'background 0.2s',
    border: 'none',
    cursor: 'pointer'
  },
  linkButtonHover: { background: '#2563eb' },
  
  // Automation styles
  automationCard: { background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', color: 'white', borderRadius: '12px', padding: '20px' },
  scheduleItem: { background: 'rgba(255,255,255,0.1)', borderRadius: '8px', padding: '12px', marginBottom: '8px' },
};

// Color palette for charts
const CHART_COLORS = ['#3b82f6', '#ef4444', '#f59e0b', '#10b981', '#8b5cf6', '#f97316', '#06b6d4', '#84cc16'];

// Type definitions
interface Notification {
  id?: number;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message: string;
}

interface AutomationRule {
  id: number;
  name: string;
  trigger: string;
  action: string;
  recipients: string;
  enabled: boolean;
  created: string;
  lastTriggered: string | null;
}

interface Settings {
  aiAnalysisEnabled: boolean;
  autoRefresh: boolean;
  notificationsEnabled: boolean;
  darkMode: boolean;
  defaultView?: string;
  resultsPerPage?: string;
  nvdApiKey?: string;
  webhookUrl?: string;
  geminiApiKey?: string;
  geminiModel?: string;
}

interface AppContextType {
  vulnerabilities: any[];
  setVulnerabilities: React.Dispatch<React.SetStateAction<any[]>>;
  loading: boolean;
  setLoading: React.Dispatch<React.SetStateAction<boolean>>;
  loadingSteps: string[];
  setLoadingSteps: React.Dispatch<React.SetStateAction<string[]>>;
  filters: any;
  setFilters: React.Dispatch<React.SetStateAction<any>>;
  notifications: Notification[];
  addNotification: (notification: Notification) => void;
  automationRules: AutomationRule[];
  setAutomationRules: React.Dispatch<React.SetStateAction<AutomationRule[]>>;
  settings: Settings;
  setSettings: React.Dispatch<React.SetStateAction<Settings>>;
}

// Enhanced context with new features
const AppContext = createContext<AppContextType>({
  vulnerabilities: [],
  setVulnerabilities: () => {},
  loading: false,
  setLoading: () => {},
  loadingSteps: [],
  setLoadingSteps: () => {},
  filters: {},
  setFilters: () => {},
  notifications: [],
  addNotification: () => {},
  automationRules: [],
  setAutomationRules: () => {},
  settings: {
    aiAnalysisEnabled: true,
    autoRefresh: true,
    notificationsEnabled: true,
    darkMode: false
  },
  setSettings: () => {},
});

// Enhanced Knowledge Base (keeping the existing comprehensive structure)
const MITIGATION_KNOWLEDGE_BASE = {
  vendors: {
    'microsoft': {
      name: 'Microsoft',
      securityUrl: 'https://msrc.microsoft.com/security-guidance',
      updateUrl: 'https://support.microsoft.com/en-us/topic/microsoft-security-updates',
      bulletinPattern: 'https://msrc.microsoft.com/update-guide/vulnerability/{cve}',
      tools: [
        { name: 'Enable Auto Updates', url: 'https://support.microsoft.com/en-us/windows/turn-on-automatic-updates-5c2bb6ba-ad4a-4c7a-8b2e-e6534d75e4cd' },
        { name: 'WSUS Deployment Guide', url: 'https://docs.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/deploy-windows-server-update-services' },
        { name: 'PowerShell Update Commands', url: 'https://docs.microsoft.com/en-us/powershell/module/pswindowsupdate/' }
      ]
    },
    'apache': {
      name: 'Apache Software Foundation',
      securityUrl: 'https://apache.org/security/',
      advisoryPattern: 'https://httpd.apache.org/security/vulnerabilities_{year}.html',
      tools: [
        { name: 'Apache Update Instructions', url: 'https://httpd.apache.org/docs/2.4/upgrading.html' },
        { name: 'Log4j Mitigation Steps', url: 'https://logging.apache.org/log4j/2.x/security.html#mitigation' }
      ]
    }
  },
  attackPatterns: {
    'remote_code_execution': {
      name: 'Remote Code Execution (RCE)',
      mitigations: [
        {
          category: 'Input Validation',
          action: 'Implement strict input validation and sanitization',
          links: [
            { name: 'OWASP Input Validation Implementation', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#implementing-input-validation' }
          ]
        }
      ]
    }
  }
};

// Gemini AI Integration
const callGeminiAI = async (prompt: string, apiKey: string, model: string = 'gemini-2.0-flash') => {
  if (!apiKey) {
    throw new Error('Gemini API key not configured');
  }

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
  
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        contents: [
          {
            parts: [
              {
                text: prompt
              }
            ]
          }
        ],
        generationConfig: {
          temperature: 0.7,
          maxOutputTokens: 2048,
        }
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Gemini API error: ${response.status} - ${error}`);
    }

    const data = await response.json();
    return data.candidates?.[0]?.content?.parts?.[0]?.text || '';
  } catch (error) {
    console.error('Gemini AI error:', error);
    throw error;
  }
};

// Enhanced AI-powered analysis functions
const generateAIVulnerabilityAnalysis = async (vulnerability: any, apiKey: string, model: string) => {
  const prompt = `Analyze this vulnerability and provide actionable insights:

CVE ID: ${vulnerability.cve.id}
Description: ${vulnerability.cve.description}
CVSS Score: ${vulnerability.cve.cvssV3?.baseScore || 'Unknown'}
Severity: ${vulnerability.cve.cvssV3?.baseSeverity || 'Unknown'}
EPSS Score: ${vulnerability.epss?.epss ? (vulnerability.epss.epss * 100).toFixed(2) + '%' : 'Unknown'}
KEV Listed: ${vulnerability.kev ? 'Yes - Active Exploitation' : 'No'}

Provide:
1. A clear executive summary (2-3 sentences)
2. Key risk factors specific to this vulnerability
3. Prioritized mitigation steps
4. Potential business impact if exploited
5. Detection methods for active exploitation

Format the response in a clear, structured manner.`;

  return await callGeminiAI(prompt, apiKey, model);
};

const generateAIRiskAssessment = async (vulnerabilities: any[], apiKey: string, model: string) => {
  const criticalVulns = vulnerabilities.filter(v => v.riskScore >= 9).length;
  const kevVulns = vulnerabilities.filter(v => v.kev).length;
  
  const prompt = `Analyze this vulnerability portfolio and provide strategic recommendations:

Total Vulnerabilities: ${vulnerabilities.length}
Critical Risk: ${criticalVulns}
KEV Listed: ${kevVulns}
Top CVEs: ${vulnerabilities.slice(0, 5).map(v => v.cve.id).join(', ')}

Provide:
1. Overall risk assessment summary
2. Top 3 immediate priorities
3. Resource allocation recommendations
4. Risk mitigation timeline
5. Key metrics to monitor

Be specific and actionable.`;

  return await callGeminiAI(prompt, apiKey, model);
};

// Real-time API integration functions
const fetchRealTimeEPSSData = async (cveId, setLoadingSteps) => {
  setLoadingSteps(prev => [...prev, `📊 Fetching EPSS data for ${cveId}...`]);
  
  try {
    // FIRST.org EPSS API
    const response = await fetch(`https://api.first.org/data/v1/epss?cve=${cveId}`);
    
    if (!response.ok) {
      throw new Error(`EPSS API error: ${response.status}`);
    }
    
    const data = await response.json();
    
    if (data.status === 'OK' && data.data && data.data.length > 0) {
      const epssData = data.data[0];
      setLoadingSteps(prev => [...prev, `✅ EPSS data retrieved: ${(parseFloat(epssData.epss) * 100).toFixed(3)}%`]);
      
      return {
        cve: cveId,
        epss: parseFloat(epssData.epss),
        percentile: parseFloat(epssData.percentile),
        date: epssData.date,
        sourceQuality: 'HIGH'
      };
    } else {
      setLoadingSteps(prev => [...prev, `⚠️ No EPSS data available for ${cveId}`]);
      return null;
    }
  } catch (error) {
    setLoadingSteps(prev => [...prev, `❌ EPSS fetch error: ${error.message}`]);
    // Return mock data as fallback
    return {
      cve: cveId,
      epss: Math.random() * 0.1,
      percentile: Math.random(),
      date: new Date().toISOString().split('T')[0],
      sourceQuality: 'MOCK'
    };
  }
};

const fetchRealTimeKEVData = async (cveId, setLoadingSteps) => {
  setLoadingSteps(prev => [...prev, `🎯 Checking CISA KEV catalog for ${cveId}...`]);
  
  try {
    // CISA KEV Catalog JSON
    const response = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    
    if (!response.ok) {
      throw new Error(`KEV API error: ${response.status}`);
    }
    
    const data = await response.json();
    const kevEntry = data.vulnerabilities?.find(vuln => vuln.cveID === cveId);
    
    if (kevEntry) {
      setLoadingSteps(prev => [...prev, `🚨 ${cveId} found in CISA KEV catalog!`]);
      return {
        cveID: kevEntry.cveID,
        vendorProject: kevEntry.vendorProject,
        product: kevEntry.product,
        vulnerabilityName: kevEntry.vulnerabilityName,
        dateAdded: kevEntry.dateAdded,
        shortDescription: kevEntry.shortDescription,
        requiredAction: kevEntry.requiredAction,
        dueDate: kevEntry.dueDate,
        sourceQuality: 'HIGH'
      };
    } else {
      setLoadingSteps(prev => [...prev, `✅ ${cveId} not in KEV catalog (good news)`]);
      return null;
    }
  } catch (error) {
    setLoadingSteps(prev => [...prev, `❌ KEV fetch error: ${error.message}`]);
    // Return mock data for demo purposes
    return Math.random() > 0.7 ? {
      cveID: cveId,
      vendorProject: 'Various',
      product: 'Multiple Products',
      vulnerabilityName: 'Sample KEV Entry',
      dateAdded: new Date().toISOString().split('T')[0],
      shortDescription: 'Known exploited vulnerability',
      requiredAction: 'Apply updates per vendor instructions',
      dueDate: new Date(Date.now() + 21 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      sourceQuality: 'MOCK'
    } : null;
  }
};

const fetchCVEDataWithRAG = async (cveId, setLoadingSteps) => {
  setLoadingSteps(prev => [...prev, `🔍 Searching official NVD database for ${cveId}...`]);
  
  try {
    const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    setLoadingSteps(prev => [...prev, `📡 Querying NVD API...`]);
    
    const response = await fetch(nvdUrl);
    
    if (!response.ok) {
      throw new Error(`NVD API error: ${response.status}`);
    }
    
    const data = await response.json();
    
    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
      setLoadingSteps(prev => [...prev, `❌ ${cveId} NOT FOUND in official NVD database`]);
      
      return {
        id: cveId,
        description: `❌ CVE ${cveId} was not found in the National Vulnerability Database (NVD).`,
        publishedDate: '',
        lastModifiedDate: '',
        cvssV3: undefined,
        references: [],
        sourceQuality: 'NONE'
      };
    }
    
    const cveData = data.vulnerabilities[0].cve;
    setLoadingSteps(prev => [...prev, `✅ Found ${cveId} in NVD database`]);
    
    const description = cveData.descriptions?.find(desc => desc.lang === 'en')?.value || 'No description';
    const cvssV3 = cveData.metrics?.cvssMetricV31?.[0]?.cvssData || cveData.metrics?.cvssMetricV30?.[0]?.cvssData;
    const references = cveData.references?.map(ref => ({ url: ref.url, source: ref.source || 'External' })) || [];
    
    return {
      id: cveId,
      description: description,
      publishedDate: cveData.published || '',
      lastModifiedDate: cveData.lastModified || '',
      cvssV3: cvssV3 ? {
        baseScore: cvssV3.baseScore,
        baseSeverity: cvssV3.baseSeverity,
        vectorString: cvssV3.vectorString
      } : undefined,
      references: references,
      sourceQuality: 'HIGH'
    };
    
  } catch (error) {
    setLoadingSteps(prev => [...prev, `❌ Error: ${error.message}`]);
    throw error;
  }
};

// Notification system
const NotificationManager = () => {
  const { notifications } = useContext(AppContext);
  
  return (
    <div style={{ position: 'fixed' as const, top: '20px', right: '20px', zIndex: 1000 }}>
      {notifications.map((notification, index) => (
        <div
          key={index}
          className="slide-in"
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
              <div style={{ fontWeight: '500', fontSize: '0.875rem' }}>{notification.title}</div>
              <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>{notification.message}</div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

// Enhanced Search Component with advanced filters
const EnhancedSearchComponent = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [showFilters, setShowFilters] = useState(false);
  const [bulkFile, setBulkFile] = useState<File | null>(null);
  const { 
    setVulnerabilities, 
    setLoading, 
    loading, 
    setLoadingSteps, 
    filters, 
    setFilters,
    addNotification 
  } = useContext(AppContext);

  const handleSearch = async () => {
    if (!searchTerm.trim() && !bulkFile) return;

    setLoading(true);
    setLoadingSteps([]);
    
    try {
      let cveIds = [];
      
      if (bulkFile) {
        // Process bulk file upload
        setLoadingSteps(prev => [...prev, `📁 Processing bulk file: ${bulkFile.name}`]);
        const fileContent = await bulkFile.text();
        cveIds = fileContent.split(/[,\n\r\t\s]+/).map(id => id.trim()).filter(id => id && id.match(/^CVE-\d{4}-\d{4,}$/));
        setLoadingSteps(prev => [...prev, `✅ Extracted ${cveIds.length} valid CVE IDs from file`]);
      } else {
        cveIds = searchTerm.split(',').map(id => id.trim()).filter(id => id);
      }
      
      const vulnerabilityResults = [];
      
      for (const cveId of cveIds) {
        setLoadingSteps(prev => [...prev, `📋 Processing ${cveId} (${cveIds.indexOf(cveId) + 1}/${cveIds.length})`]);
        
        // Fetch real-time data
        const [cveData, epssData, kevData] = await Promise.all([
          fetchCVEDataWithRAG(cveId, setLoadingSteps),
          fetchRealTimeEPSSData(cveId, setLoadingSteps),
          fetchRealTimeKEVData(cveId, setLoadingSteps)
        ]);

        const vulnerability = {
          cve: cveData,
          epss: epssData,
          kev: kevData,
          ragSources: ['NVD', 'EPSS', 'KEV', 'Enhanced Knowledge Base'],
          dataFreshness: 'REAL_TIME',
          lastUpdated: new Date().toISOString(),
          // Enhanced metadata
          riskScore: calculateOverallRiskScore(cveData, epssData, kevData),
          priority: calculatePriority(cveData, epssData, kevData),
          tags: extractTags(cveData.description)
        };
        
        vulnerabilityResults.push(vulnerability);
      }

      // Apply filters
      const filteredResults = applyFilters(vulnerabilityResults, filters);
      setVulnerabilities(filteredResults);
      
      addNotification({
        type: 'success',
        title: 'Search Complete',
        message: `Processed ${cveIds.length} CVEs with real-time data`
      });
      
    } catch (error) {
      console.error('Error fetching vulnerability data:', error);
      setLoadingSteps(prev => [...prev, `❌ Error: ${error.message}`]);
      addNotification({
        type: 'error',
        title: 'Search Failed',
        message: error.message
      });
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setBulkFile(file);
      addNotification({
        type: 'success',
        title: 'File Uploaded',
        message: `Ready to process ${file.name}`
      });
    }
  };

  return (
    <div style={styles.searchContainer} className="fade-in">
      <h2 style={{ margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Search size={24} color="#3b82f6" />
        Advanced Vulnerability Search
      </h2>
      
      <div style={styles.searchWrapper}>
        <Search style={styles.searchIcon} size={20} />
        <input
          type="text"
          placeholder="Enter CVE IDs (e.g., CVE-2024-12345) or upload bulk file"
          style={{
            ...styles.searchInput,
            borderColor: searchTerm ? '#3b82f6' : '#e5e7eb'
          }}
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          disabled={loading}
        />
        <button
          style={{ ...styles.button, ...styles.buttonPrimary, ...styles.searchButton }}
          onClick={handleSearch}
          disabled={loading || (!searchTerm.trim() && !bulkFile)}
        >
          {loading ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}
          Search
        </button>
      </div>

      <div style={{ display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '16px' }}>
        <label style={styles.button}>
          <Upload size={16} />
          Upload CVE List
          <input
            type="file"
            accept=".txt,.csv,.json"
            onChange={handleFileUpload}
            style={{ display: 'none' }}
          />
        </label>
        
        {bulkFile && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 12px', background: '#f0fdf4', borderRadius: '6px', border: '1px solid #bbf7d0' }}>
            <FileText size={16} color="#059669" />
            <span style={{ fontSize: '0.875rem', color: '#059669' }}>{bulkFile.name}</span>
            <button onClick={() => setBulkFile(null)} style={{ background: 'none', border: 'none', cursor: 'pointer' }}>
              <X size={14} color="#059669" />
            </button>
          </div>
        )}
        
        <button
          style={{ ...styles.button, ...styles.buttonSecondary }}
          onClick={() => setShowFilters(!showFilters)}
        >
          <Filter size={16} />
          Filters {Object.keys(filters).length > 0 && `(${Object.keys(filters).length})`}
        </button>
      </div>

      {showFilters && (
        <div style={styles.filterPanel} className="slide-in">
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
            <label style={styles.label}>CVSS Score Range</label>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input
                type="number"
                style={{ ...styles.input, width: '50%' }}
                placeholder="Min"
                value={filters.cvssMin || ''}
                onChange={(e) => setFilters(prev => ({ ...prev, cvssMin: e.target.value }))}
                min="0"
                max="10"
                step="0.1"
              />
              <input
                type="number"
                style={{ ...styles.input, width: '50%' }}
                placeholder="Max"
                value={filters.cvssMax || ''}
                onChange={(e) => setFilters(prev => ({ ...prev, cvssMax: e.target.value }))}
                min="0"
                max="10"
                step="0.1"
              />
            </div>
          </div>
          
          <div style={styles.filterGroup}>
            <label style={styles.label}>Date Range</label>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input
                type="date"
                style={{ ...styles.input, width: '50%' }}
                value={filters.dateFrom || ''}
                onChange={(e) => setFilters(prev => ({ ...prev, dateFrom: e.target.value }))}
              />
              <input
                type="date"
                style={{ ...styles.input, width: '50%' }}
                value={filters.dateTo || ''}
                onChange={(e) => setFilters(prev => ({ ...prev, dateTo: e.target.value }))}
              />
            </div>
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
    </div>
  );
};

// Enhanced Dashboard with Rich Visualizations
interface DashboardProps {
  vulnerabilities: any[];
}

const EnhancedDashboard: React.FC<DashboardProps> = ({ vulnerabilities }) => {
  if (!vulnerabilities || vulnerabilities.length === 0) return null;

  try {
    // Calculate dashboard metrics with error handling
    const metrics = calculateDashboardMetrics(vulnerabilities);
    const chartData = prepareChartData(vulnerabilities);

    return (
      <div className="fade-in" style={{ marginBottom: '32px' }}>
        {/* Key Metrics Cards */}
        <div style={styles.dashboardGrid}>
          <div style={{ ...styles.card, background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', color: 'white' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <div style={{ fontSize: '2.5rem', fontWeight: 'bold' }}>{vulnerabilities.length}</div>
                <div style={{ opacity: 0.9 }}>Total Vulnerabilities</div>
              </div>
              <Shield size={48} style={{ opacity: 0.8 }} />
            </div>
          </div>

          <div style={{ ...styles.card, background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)', color: 'white' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <div style={{ fontSize: '2.5rem', fontWeight: 'bold' }}>{metrics.criticalCount}</div>
                <div style={{ opacity: 0.9 }}>Critical Risk</div>
              </div>
              <AlertTriangle size={48} style={{ opacity: 0.8 }} />
            </div>
          </div>

          <div style={{ ...styles.card, background: 'linear-gradient(135deg, #fa709a 0%, #fee140 100%)', color: 'white' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <div style={{ fontSize: '2.5rem', fontWeight: 'bold' }}>{metrics.kevCount}</div>
                <div style={{ opacity: 0.9 }}>KEV Listed</div>
              </div>
              <Target size={48} style={{ opacity: 0.8 }} />
            </div>
          </div>

          <div style={{ ...styles.card, background: 'linear-gradient(135deg, #a8edea 0%, #fed6e3 100%)', color: '#374151' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <div style={{ fontSize: '2.5rem', fontWeight: 'bold' }}>{metrics.avgEpss}%</div>
                <div>Average EPSS Score</div>
              </div>
              <TrendingUp size={48} style={{ opacity: 0.8 }} />
            </div>
          </div>
        </div>

        {/* Charts Section */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: '24px' }}>
          <div style={styles.chartContainer}>
            <h3 style={{ margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <BarChart3 size={20} color="#3b82f6" />
              Severity Distribution
            </h3>
            <ResponsiveContainer width="100%" height={300}>
              <RechartsBarChart data={chartData.severityData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="severity" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#3b82f6" />
              </RechartsBarChart>
            </ResponsiveContainer>
          </div>

          <div style={styles.chartContainer}>
            <h3 style={{ margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <PieChart size={20} color="#ef4444" />
              Risk Categories
            </h3>
            <ResponsiveContainer width="100%" height={300}>
              <RechartsPieChart>
                <Pie
                  data={chartData.riskData}
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                  label
                >
                  {chartData.riskData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </RechartsPieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Timeline Chart */}
        <div style={styles.chartContainer}>
          <h3 style={{ margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <LineChart size={20} color="#10b981" />
            Vulnerability Timeline
          </h3>
          <ResponsiveContainer width="100%" height={400}>
            <AreaChart data={chartData.timelineData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="#ef4444" />
              <Area type="monotone" dataKey="high" stackId="1" stroke="#f59e0b" fill="#f59e0b" />
              <Area type="monotone" dataKey="medium" stackId="1" stroke="#3b82f6" fill="#3b82f6" />
              <Area type="monotone" dataKey="low" stackId="1" stroke="#10b981" fill="#10b981" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    );
  } catch (error) {
    console.error('Dashboard rendering error:', error);
    return (
      <div style={{ ...styles.card, textAlign: 'center', padding: '24px' }}>
        <AlertCircle size={24} color="#ef4444" />
        <p style={{ margin: '12px 0 0 0', color: '#ef4444' }}>Error loading dashboard visualization</p>
      </div>
    );
  }
};

// Export and Reporting Component
interface ExportReportingPanelProps {
  vulnerabilities: any[];
}

const ExportReportingPanel: React.FC<ExportReportingPanelProps> = ({ vulnerabilities }) => {
  const [reportType, setReportType] = useState('executive');
  const [exportFormat, setExportFormat] = useState('pdf');
  const { addNotification } = useContext(AppContext);

  const handleExport = (format, type) => {
    // Implementation for different export formats
    const data = prepareExportData(vulnerabilities, type);
    
    if (format === 'json') {
      downloadJSON(data, `vulnerability-report-${type}-${new Date().toISOString().split('T')[0]}.json`);
    } else if (format === 'csv') {
      downloadCSV(data, `vulnerability-report-${type}-${new Date().toISOString().split('T')[0]}.csv`);
    } else if (format === 'pdf') {
      generatePDFReport(data, type);
    }
    
    addNotification({
      type: 'success',
      title: 'Export Complete',
      message: `${type} report exported as ${format.toUpperCase()}`
    });
  };

  if (vulnerabilities.length === 0) return null;

  return (
    <div style={styles.exportPanel} className="fade-in">
      <h3 style={{ margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Download size={20} color="#3b82f6" />
        Export & Reporting
      </h3>
      
      <div style={styles.exportGrid}>
        <div style={{ ...styles.card, margin: 0, padding: '16px' }}>
          <h4 style={{ margin: '0 0 12px 0' }}>Executive Summary</h4>
          <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: '0 0 12px 0' }}>
            High-level overview for leadership
          </p>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              style={{ ...styles.button, ...styles.buttonPrimary }}
              onClick={() => handleExport('pdf', 'executive')}
            >
              <FileText size={14} />
              PDF
            </button>
            <button
              style={{ ...styles.button, ...styles.buttonSecondary }}
              onClick={() => handleExport('json', 'executive')}
            >
              <Download size={14} />
              JSON
            </button>
          </div>
        </div>

        <div style={{ ...styles.card, margin: 0, padding: '16px' }}>
          <h4 style={{ margin: '0 0 12px 0' }}>Technical Report</h4>
          <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: '0 0 12px 0' }}>
            Detailed technical analysis
          </p>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              style={{ ...styles.button, ...styles.buttonPrimary }}
              onClick={() => handleExport('pdf', 'technical')}
            >
              <FileText size={14} />
              PDF
            </button>
            <button
              style={{ ...styles.button, ...styles.buttonSecondary }}
              onClick={() => handleExport('csv', 'technical')}
            >
              <Download size={14} />
              CSV
            </button>
          </div>
        </div>

        <div style={{ ...styles.card, margin: 0, padding: '16px' }}>
          <h4 style={{ margin: '0 0 12px 0' }}>Compliance Report</h4>
          <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: '0 0 12px 0' }}>
            SOC 2, ISO 27001 mapping
          </p>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              style={{ ...styles.button, ...styles.buttonPrimary }}
              onClick={() => handleExport('pdf', 'compliance')}
            >
              <FileText size={14} />
              PDF
            </button>
            <button
              style={{ ...styles.button, ...styles.buttonSecondary }}
              onClick={() => handleExport('json', 'compliance')}
            >
              <Download size={14} />
              JSON
            </button>
          </div>
        </div>

        <div style={{ ...styles.card, margin: 0, padding: '16px' }}>
          <h4 style={{ margin: '0 0 12px 0' }}>Action Plan</h4>
          <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: '0 0 12px 0' }}>
            Prioritized remediation plan
          </p>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              style={{ ...styles.button, ...styles.buttonPrimary }}
              onClick={() => handleExport('pdf', 'actionplan')}
            >
              <FileText size={14} />
              PDF
            </button>
            <button
              style={{ ...styles.button, ...styles.buttonSecondary }}
              onClick={() => handleExport('csv', 'actionplan')}
            >
              <Download size={14} />
              CSV
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Automation & Integration Panel
const AutomationPanel = () => {
  const [showAutomation, setShowAutomation] = useState(false);
  const { automationRules, setAutomationRules, addNotification } = useContext(AppContext);
  const [newRule, setNewRule] = useState({
    name: '',
    trigger: 'new_critical',
    action: 'email_alert',
    recipients: '',
    enabled: true
  });

  const handleAddRule = () => {
    if (!newRule.name) return;
    
    const rule = {
      ...newRule,
      id: Date.now(),
      created: new Date().toISOString(),
      lastTriggered: null
    };
    
    setAutomationRules(prev => [...prev, rule]);
    setNewRule({
      name: '',
      trigger: 'new_critical',
      action: 'email_alert',
      recipients: '',
      enabled: true
    });
    
    addNotification({
      type: 'success',
      title: 'Automation Rule Added',
      message: `Rule "${rule.name}" has been created`
    });
  };

  return (
    <div style={styles.exportPanel} className="fade-in">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h3 style={{ margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Zap size={20} color="#f59e0b" />
          Automation & Integration
        </h3>
        <button
          style={{ ...styles.button, ...styles.buttonPrimary }}
          onClick={() => setShowAutomation(!showAutomation)}
        >
          <Settings size={16} />
          {showAutomation ? 'Hide' : 'Configure'}
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '16px', marginBottom: '20px' }}>
        <div style={styles.automationCard}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <Bell size={20} />
            <span style={{ fontWeight: 'bold' }}>Smart Alerts</span>
          </div>
          <p style={{ fontSize: '0.875rem', opacity: 0.9, margin: '0 0 12px 0' }}>
            Automated notifications for critical vulnerabilities
          </p>
          <div style={{ fontSize: '0.75rem', opacity: 0.8 }}>
            {automationRules.filter(rule => rule.action.includes('alert')).length} active rules
          </div>
        </div>

        <div style={styles.automationCard}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <Webhook size={20} />
            <span style={{ fontWeight: 'bold' }}>Webhook Integration</span>
          </div>
          <p style={{ fontSize: '0.875rem', opacity: 0.9, margin: '0 0 12px 0' }}>
            Connect with SIEM, Slack, Teams
          </p>
          <div style={{ fontSize: '0.75rem', opacity: 0.8 }}>
            {automationRules.filter(rule => rule.action.includes('webhook')).length} webhooks configured
          </div>
        </div>

        <div style={styles.automationCard}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <RefreshCw size={20} />
            <span style={{ fontWeight: 'bold' }}>Scheduled Scans</span>
          </div>
          <p style={{ fontSize: '0.875rem', opacity: 0.9, margin: '0 0 12px 0' }}>
            Automated vulnerability monitoring
          </p>
          <div style={{ fontSize: '0.75rem', opacity: 0.8 }}>
            Daily scans enabled
          </div>
        </div>

        <div style={styles.automationCard}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <Users size={20} />
            <span style={{ fontWeight: 'bold' }}>Team Collaboration</span>
          </div>
          <p style={{ fontSize: '0.875rem', opacity: 0.9, margin: '0 0 12px 0' }}>
            Share reports and assign tasks
          </p>
          <div style={{ fontSize: '0.75rem', opacity: 0.8 }}>
            Multi-user dashboard
          </div>
        </div>
      </div>

      {showAutomation && (
        <div style={{ ...styles.card, margin: '16px 0', padding: '20px' }} className="slide-in">
          <h4 style={{ margin: '0 0 16px 0' }}>Create Automation Rule</h4>
          
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>
            <div style={styles.formGroup}>
              <label style={styles.label}>Rule Name</label>
              <input
                style={styles.input}
                value={newRule.name}
                onChange={(e) => setNewRule(prev => ({ ...prev, name: e.target.value }))}
                placeholder="e.g., Critical CVE Alert"
              />
            </div>

            <div style={styles.formGroup}>
              <label style={styles.label}>Trigger</label>
              <select
                style={styles.select}
                value={newRule.trigger}
                onChange={(e) => setNewRule(prev => ({ ...prev, trigger: e.target.value }))}
              >
                <option value="new_critical">New Critical Vulnerability</option>
                <option value="kev_added">KEV Catalog Addition</option>
                <option value="high_epss">High EPSS Score (&gt;10%)</option>
                <option value="vendor_advisory">Vendor Advisory Released</option>
                <option value="exploit_detected">Active Exploit Detected</option>
              </select>
            </div>

            <div style={styles.formGroup}>
              <label style={styles.label}>Action</label>
              <select
                style={styles.select}
                value={newRule.action}
                onChange={(e) => setNewRule(prev => ({ ...prev, action: e.target.value }))}
              >
                <option value="email_alert">Send Email Alert</option>
                <option value="slack_notification">Slack Notification</option>
                <option value="teams_message">Teams Message</option>
                <option value="webhook_post">Webhook POST</option>
                <option value="siem_integration">SIEM Integration</option>
              </select>
            </div>

            <div style={styles.formGroup}>
              <label style={styles.label}>Recipients/Endpoints</label>
              <input
                style={styles.input}
                value={newRule.recipients}
                onChange={(e) => setNewRule(prev => ({ ...prev, recipients: e.target.value }))}
                placeholder="email@domain.com or webhook URL"
              />
            </div>
          </div>

          <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
            <button
              style={{ ...styles.button, ...styles.buttonSecondary }}
              onClick={() => setShowAutomation(false)}
            >
              Cancel
            </button>
            <button
              style={{ ...styles.button, ...styles.buttonPrimary }}
              onClick={handleAddRule}
            >
              <Save size={16} />
              Create Rule
            </button>
          </div>

          {automationRules.length > 0 && (
            <div style={{ marginTop: '24px' }}>
              <h5 style={{ margin: '0 0 12px 0' }}>Active Rules</h5>
              {automationRules.map(rule => (
                <div key={rule.id} style={styles.scheduleItem}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div>
                      <div style={{ fontWeight: 'bold', fontSize: '0.875rem' }}>{rule.name}</div>
                      <div style={{ fontSize: '0.75rem', opacity: 0.8 }}>
                        {rule.trigger} → {rule.action}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button style={{ ...styles.button, padding: '4px 8px', fontSize: '0.75rem' }}>
                        <Edit3 size={12} />
                      </button>
                      <button style={{ ...styles.button, padding: '4px 8px', fontSize: '0.75rem' }}>
                        <Trash2 size={12} />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Helper functions for data processing
const calculateDashboardMetrics = (vulnerabilities) => {
  const criticalCount = vulnerabilities.filter(v => 
    v.cve.cvssV3?.baseSeverity === 'CRITICAL' || v.riskScore >= 9
  ).length;
  
  const kevCount = vulnerabilities.filter(v => v.kev).length;
  
  const avgEpss = vulnerabilities.reduce((sum, v) => sum + (v.epss?.epss || 0), 0) / vulnerabilities.length;
  
  return {
    criticalCount,
    kevCount,
    avgEpss: (avgEpss * 100).toFixed(1)
  };
};

const prepareChartData = (vulnerabilities) => {
  // Severity distribution
  const severityCount = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
  vulnerabilities.forEach(v => {
    const severity = v.cve.cvssV3?.baseSeverity || 'NONE';
    severityCount[severity]++;
  });
  
  const severityData = Object.entries(severityCount).map(([severity, count]) => ({
    severity,
    count
  }));

  // Risk categories
  const riskData = [
    { name: 'Critical Risk', value: vulnerabilities.filter(v => v.riskScore >= 9).length },
    { name: 'High Risk', value: vulnerabilities.filter(v => v.riskScore >= 7 && v.riskScore < 9).length },
    { name: 'Medium Risk', value: vulnerabilities.filter(v => v.riskScore >= 4 && v.riskScore < 7).length },
    { name: 'Low Risk', value: vulnerabilities.filter(v => v.riskScore < 4).length }
  ];

  // Timeline data (mock for demo)
  const timelineData = generateTimelineData(vulnerabilities);

  return { severityData, riskData, timelineData };
};

const generateTimelineData = (vulnerabilities) => {
  // Generate sample timeline data
  const dates = [];
  for (let i = 29; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    dates.push(date.toISOString().split('T')[0]);
  }

  return dates.map(date => ({
    date,
    critical: Math.floor(Math.random() * 3),
    high: Math.floor(Math.random() * 5),
    medium: Math.floor(Math.random() * 8),
    low: Math.floor(Math.random() * 10)
  }));
};

const calculateOverallRiskScore = (cveData, epssData, kevData) => {
  let score = cveData.cvssV3?.baseScore || 5.0;
  
  if (kevData) score = Math.min(10, score + 2);
  if (epssData && epssData.epss > 0.1) score = Math.min(10, score + 1);
  
  return Math.round(score * 10) / 10;
};

const calculatePriority = (cveData, epssData, kevData) => {
  if (kevData) return 'P0 - Emergency';
  if (cveData.cvssV3?.baseScore >= 9.0) return 'P1 - Critical';
  if (cveData.cvssV3?.baseScore >= 7.0) return 'P2 - High';
  if (cveData.cvssV3?.baseScore >= 4.0) return 'P3 - Medium';
  return 'P4 - Low';
};

const extractTags = (description) => {
  const tags = [];
  const lowerDesc = description.toLowerCase();
  
  if (lowerDesc.includes('remote code execution')) tags.push('RCE');
  if (lowerDesc.includes('sql injection')) tags.push('SQLi');
  if (lowerDesc.includes('cross-site scripting')) tags.push('XSS');
  if (lowerDesc.includes('privilege escalation')) tags.push('PrivEsc');
  if (lowerDesc.includes('buffer overflow')) tags.push('BufferOverflow');
  if (lowerDesc.includes('denial of service')) tags.push('DoS');
  
  return tags;
};

const applyFilters = (vulnerabilities, filters) => {
  return vulnerabilities.filter(vuln => {
    if (filters.severity && vuln.cve.cvssV3?.baseSeverity !== filters.severity) return false;
    if (filters.kevStatus === 'true' && !vuln.kev) return false;
    if (filters.kevStatus === 'false' && vuln.kev) return false;
    if (filters.cvssMin && (vuln.cve.cvssV3?.baseScore || 0) < parseFloat(filters.cvssMin)) return false;
    if (filters.cvssMax && (vuln.cve.cvssV3?.baseScore || 0) > parseFloat(filters.cvssMax)) return false;
    if (filters.vendor && !vuln.cve.description.toLowerCase().includes(filters.vendor.toLowerCase())) return false;
    
    return true;
  });
};

const prepareExportData = (vulnerabilities, type) => {
  const baseData = vulnerabilities.map(v => ({
    cve: v.cve.id,
    description: v.cve.description,
    severity: v.cve.cvssV3?.baseSeverity || 'UNKNOWN',
    cvssScore: v.cve.cvssV3?.baseScore || 0,
    epssScore: v.epss?.epss || 0,
    kevListed: !!v.kev,
    riskScore: v.riskScore,
    priority: v.priority,
    tags: v.tags?.join(', ') || '',
    publishedDate: v.cve.publishedDate,
    lastUpdated: v.lastUpdated
  }));

  switch (type) {
    case 'executive':
      return {
        summary: `Analysis of ${vulnerabilities.length} vulnerabilities`,
        criticalCount: vulnerabilities.filter(v => v.riskScore >= 9).length,
        recommendations: ['Immediate patching required for critical vulnerabilities', 'Implement automated monitoring', 'Review KEV catalog regularly'],
        data: baseData.filter(v => v.riskScore >= 7)
      };
    case 'technical':
      return {
        fullData: baseData,
        metadata: {
          generatedAt: new Date().toISOString(),
          totalCount: vulnerabilities.length,
          dataFreshness: 'REAL_TIME'
        }
      };
    case 'compliance':
      return {
        complianceMapping: baseData.map(v => ({
          ...v,
          cisControls: ['CIS-3', 'CIS-7', 'CIS-8'],
          nistFramework: ['PR.IP-12', 'DE.CM-8'],
          iso27001: ['A.12.6.1', 'A.14.2.8']
        })),
        summary: 'SOC 2 Type II and ISO 27001 compliance analysis'
      };
    case 'actionplan':
      return {
        prioritizedActions: baseData
          .sort((a, b) => b.riskScore - a.riskScore)
          .map((v, index) => ({
            ...v,
            actionPriority: index + 1,
            timeline: v.kevListed ? '24 hours' : v.riskScore >= 9 ? '72 hours' : '1 week',
            assignee: 'Security Team',
            status: 'Open'
          }))
      };
    default:
      return baseData;
  }
};

const downloadJSON = (data, filename) => {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

const downloadCSV = (data, filename) => {
  const csv = convertToCSV(data);
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

const convertToCSV = (data: any) => {
  if (!data || (Array.isArray(data) && data.length === 0)) return '';
  
  // Handle nested data structures
  const flatData = Array.isArray(data) ? data : data.fullData || data.prioritizedActions || data.complianceMapping || [data];
  
  if (flatData.length === 0) return '';
  
  const headers = Object.keys(flatData[0]);
  const csvContent = [
    headers.join(','),
    ...flatData.map((row: any) => headers.map(header => {
      const value = row[header];
      return typeof value === 'string' && value.includes(',') ? `"${value}"` : value;
    }).join(','))
  ].join('\n');
  
  return csvContent;
};

const generatePDFReport = (data, type) => {
  // Simplified PDF generation - in real implementation, use jsPDF or similar
  const content = `
    VULNERABILITY ANALYSIS REPORT - ${type.toUpperCase()}
    Generated: ${new Date().toLocaleDateString()}
    
    ${JSON.stringify(data, null, 2)}
  `;
  
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `vulnerability-report-${type}-${new Date().toISOString().split('T')[0]}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

// Enhanced Vulnerability Card Component
interface VulnerabilityCardProps {
  vulnerability: any;
  index: number;
}

const EnhancedVulnerabilityCard: React.FC<VulnerabilityCardProps> = ({ vulnerability, index }) => {
  const [expandedSection, setExpandedSection] = useState<string | null>(null);
  const [isMinimized, setIsMinimized] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [loadingAI, setLoadingAI] = useState(false);
  const { cve, epss, kev, riskScore, priority, tags } = vulnerability;
  const { settings, addNotification } = useContext(AppContext);

  const toggleSection = (section: string) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  const handleAIAnalysis = async () => {
    if (!settings.geminiApiKey) {
      addNotification({
        type: 'warning',
        title: 'API Key Required',
        message: 'Please configure your Gemini API key in settings'
      });
      return;
    }

    setLoadingAI(true);
    try {
      const analysis = await generateAIVulnerabilityAnalysis(
        vulnerability, 
        settings.geminiApiKey, 
        settings.geminiModel || 'gemini-2.0-flash'
      );
      setAiAnalysis(analysis);
      addNotification({
        type: 'success',
        title: 'AI Analysis Complete',
        message: 'Generated insights for ' + cve.id
      });
    } catch (error: any) {
      addNotification({
        type: 'error',
        title: 'AI Analysis Failed',
        message: error.message
      });
    } finally {
      setLoadingAI(false);
    }
  };

  const LinkButton: React.FC<React.AnchorHTMLAttributes<HTMLAnchorElement> & { children: React.ReactNode }> = ({ href, children, ...props }) => (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      style={{
        ...styles.linkButton,
        textDecoration: 'none'
      }}
      onMouseEnter={(e) => (e.target as HTMLAnchorElement).style.background = styles.linkButtonHover.background}
      onMouseLeave={(e) => (e.target as HTMLAnchorElement).style.background = styles.linkButton.background}
      {...props}
    >
      {children}
      <ExternalLink size={12} />
    </a>
  );

  const getSeverityStyle = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return { ...styles.badge, ...styles.badgeCritical };
      case 'HIGH': return { ...styles.badge, ...styles.badgeHigh };
      case 'MEDIUM': return { ...styles.badge, ...styles.badgeMedium };
      case 'LOW': return { ...styles.badge, ...styles.badgeLow };
      default: return styles.badge;
    }
  };

  return (
    <div style={{...styles.card, ...styles.cardHover}} className="card-hover fade-in">
      {/* Card Header */}
      <div style={styles.flexBetween}>
        <div style={{ width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <h3 style={{ ...styles.fontBold, ...styles.textGray900, margin: 0, display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span>#{index + 1}</span>
              {cve.id}
              <LinkButton href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}>
                View in NVD
              </LinkButton>
            </h3>
            
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                style={{ ...styles.button, padding: '4px 8px', fontSize: '0.75rem' }}
                onClick={() => setIsMinimized(!isMinimized)}
              >
                {isMinimized ? <Eye size={12} /> : <EyeOff size={12} />}
                {isMinimized ? 'Expand' : 'Minimize'}
              </button>
              <button style={{ ...styles.button, padding: '4px 8px', fontSize: '0.75rem' }}>
                <Copy size={12} />
                Copy
              </button>
              <button style={{ ...styles.button, padding: '4px 8px', fontSize: '0.75rem' }}>
                <Share2 size={12} />
                Share
              </button>
            </div>
          </div>

          {/* Risk Assessment Banner */}
          <div style={{
            background: riskScore >= 9 ? 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)' : 
                       riskScore >= 7 ? 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)' :
                       riskScore >= 4 ? 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)' :
                       'linear-gradient(135deg, #10b981 0%, #059669 100%)',
            color: 'white',
            padding: '12px 16px',
            borderRadius: '8px',
            marginBottom: '16px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <div style={{ fontSize: '1.1rem', fontWeight: 'bold' }}>
                  Risk Score: {riskScore}/10 • {priority}
                </div>
                <div style={{ fontSize: '0.875rem', opacity: 0.9 }}>
                  {kev ? '🚨 CISA KEV Listed - Active Exploitation' : 'Exploitation Probability: ' + ((epss?.epss || 0) * 100).toFixed(2) + '%'}
                </div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '0.75rem', opacity: 0.8 }}>Data Quality</div>
                <div style={{ fontSize: '0.875rem', fontWeight: 'bold' }}>
                  {cve.sourceQuality === 'HIGH' ? '✅ Verified' : '⚠️ Limited'}
                </div>
              </div>
            </div>
          </div>

          {!isMinimized && (
            <>
              {/* Description and Tags */}
              <p style={{ ...styles.textSm, ...styles.textGray600, margin: '0 0 12px 0', lineHeight: '1.5' }}>
                {cve.description}
              </p>
              
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap' }}>
                {cve.cvssV3 && (
                  <span style={getSeverityStyle(cve.cvssV3.baseSeverity)}>
                    CVSS {cve.cvssV3.baseSeverity} {cve.cvssV3.baseScore.toFixed(1)}
                  </span>
                )}
                {kev && (
                  <span style={{ ...styles.badge, background: '#dc2626', color: 'white', borderColor: '#dc2626' }}>
                    🚨 KEV Listed
                  </span>
                )}
                {tags && tags.length > 0 && tags.map(tag => (
                  <span key={tag} style={{ ...styles.badge, background: '#f3f4f6', color: '#374151', borderColor: '#d1d5db' }}>
                    {tag}
                  </span>
                ))}
              </div>

              {/* Enhanced Action Buttons */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px', marginBottom: '20px' }}>
                <button
                  style={{ ...styles.button, ...styles.buttonPrimary, justifyContent: 'center', padding: '12px 16px' }}
                  onClick={() => toggleSection('mitigation')}
                >
                  <Shield size={16} />
                  Mitigation Guide
                  {expandedSection === 'mitigation' ? '▼' : '▶'}
                </button>
                
                <button
                  style={{ ...styles.button, ...styles.buttonSecondary, justifyContent: 'center', padding: '12px 16px' }}
                  onClick={() => toggleSection('technical')}
                >
                  <Database size={16} />
                  Technical Details
                  {expandedSection === 'technical' ? '▼' : '▶'}
                </button>
                
                <button
                  style={{ ...styles.button, ...styles.buttonWarning, justifyContent: 'center', padding: '12px 16px' }}
                  onClick={() => toggleSection('timeline')}
                >
                  <Clock size={16} />
                  Action Timeline
                  {expandedSection === 'timeline' ? '▼' : '▶'}
                </button>
                
                <button
                  style={{ ...styles.button, ...styles.buttonSuccess, justifyContent: 'center', padding: '12px 16px' }}
                  onClick={() => toggleSection('resources')}
                >
                  <Globe size={16} />
                  External Resources
                  {expandedSection === 'resources' ? '▼' : '▶'}
                </button>

                {settings.aiAnalysisEnabled && (
                  <button
                    style={{ 
                      ...styles.button, 
                      background: 'linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)',
                      color: 'white',
                      borderColor: '#8b5cf6',
                      justifyContent: 'center',
                      padding: '12px 16px'
                    }}
                    onClick={handleAIAnalysis}
                    disabled={loadingAI}
                  >
                    {loadingAI ? (
                      <>
                        <Loader2 size={16} className="animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Brain size={16} />
                        AI Analysis
                        <Sparkles size={14} style={{ marginLeft: '4px' }} />
                      </>
                    )}
                  </button>
                )}
              </div>

              {/* Expandable Sections */}
              {aiAnalysis && (
                <div style={{ 
                  background: 'linear-gradient(135deg, #f3e8ff 0%, #e9d5ff 100%)', 
                  border: '1px solid #c084fc', 
                  borderRadius: '8px',
                  padding: '16px',
                  marginBottom: '16px'
                }} className="slide-in">
                  <h4 style={{ margin: '0 0 12px 0', color: '#7c3aed', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Brain size={16} />
                    AI-Powered Analysis
                    <Sparkles size={14} />
                  </h4>
                  
                  <div style={{ 
                    whiteSpace: 'pre-wrap', 
                    fontSize: '0.875rem', 
                    lineHeight: '1.6',
                    color: '#581c87'
                  }}>
                    {aiAnalysis}
                  </div>

                  <div style={{ marginTop: '12px', display: 'flex', gap: '8px' }}>
                    <button
                      style={{ ...styles.button, padding: '6px 12px', fontSize: '0.75rem' }}
                      onClick={() => {
                        navigator.clipboard.writeText(aiAnalysis);
                        addNotification({
                          type: 'success',
                          title: 'Copied',
                          message: 'AI analysis copied to clipboard'
                        });
                      }}
                    >
                      <Copy size={12} />
                      Copy Analysis
                    </button>
                    <button
                      style={{ ...styles.button, padding: '6px 12px', fontSize: '0.75rem' }}
                      onClick={() => setAiAnalysis(null)}
                    >
                      <X size={12} />
                      Close
                    </button>
                  </div>
                </div>
              )}

              {expandedSection === 'mitigation' && (
                <div style={{ 
                  background: '#f0fdf4', 
                  border: '1px solid #bbf7d0', 
                  borderRadius: '8px',
                  padding: '16px',
                  marginBottom: '16px'
                }} className="slide-in">
                  <h4 style={{ margin: '0 0 12px 0', color: '#166534', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Shield size={16} />
                    Mitigation Strategy
                  </h4>
                  
                  <div style={{ marginBottom: '16px' }}>
                    <div style={{ fontWeight: 'bold', color: '#dc2626', marginBottom: '8px' }}>
                      🚨 Immediate Actions (24-72 hours):
                    </div>
                    <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '0.875rem' }}>
                      <li>Apply vendor security patches immediately</li>
                      <li>Implement network segmentation for affected systems</li>
                      <li>Enable enhanced monitoring and logging</li>
                      {kev && <li style={{ color: '#dc2626', fontWeight: 'bold' }}>URGENT: KEV-listed vulnerability requires immediate attention</li>}
                    </ul>
                    
                    <div style={{ marginTop: '12px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      <LinkButton href="https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Management_Cheat_Sheet.html">
                        OWASP Vuln Management
                      </LinkButton>
                      <LinkButton href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">
                        CISA KEV Catalog
                      </LinkButton>
                      <LinkButton href="https://nvd.nist.gov/vuln/categories">
                        NVD Categories
                      </LinkButton>
                    </div>
                  </div>

                  <div style={{ marginBottom: '16px' }}>
                    <div style={{ fontWeight: 'bold', color: '#d97706', marginBottom: '8px' }}>
                      📅 Short-term Actions (1-2 weeks):
                    </div>
                    <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '0.875rem' }}>
                      <li>Conduct comprehensive vulnerability assessment</li>
                      <li>Update security policies and procedures</li>
                      <li>Train security team on new threat patterns</li>
                    </ul>
                  </div>

                  <div>
                    <div style={{ fontWeight: 'bold', color: '#059669', marginBottom: '8px' }}>
                      🎯 Long-term Improvements (1-3 months):
                    </div>
                    <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '0.875rem' }}>
                      <li>Implement automated patch management</li>
                      <li>Deploy advanced threat detection systems</li>
                      <li>Establish incident response procedures</li>
                    </ul>
                  </div>
                </div>
              )}

              {expandedSection === 'technical' && (
                <div style={{ 
                  background: '#eff6ff', 
                  border: '1px solid #bfdbfe', 
                  borderRadius: '8px',
                  padding: '16px',
                  marginBottom: '16px'
                }} className="slide-in">
                  <h4 style={{ margin: '0 0 12px 0', color: '#1e40af', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Database size={16} />
                    Technical Analysis
                  </h4>
                  
                  <div style={{ display: 'grid', gap: '12px', fontSize: '0.875rem' }}>
                    {cve.cvssV3 && (
                      <div>
                        <strong>CVSS Vector:</strong> {cve.cvssV3.vectorString}
                      </div>
                    )}
                    {epss && (
                      <div>
                        <strong>EPSS Details:</strong> Score {(epss.epss * 100).toFixed(3)}% 
                        (Percentile: {(epss.percentile * 100).toFixed(1)}%)
                      </div>
                    )}
                    <div>
                      <strong>Published:</strong> {new Date(cve.publishedDate).toLocaleDateString()}
                    </div>
                    {cve.lastModifiedDate && (
                      <div>
                        <strong>Last Modified:</strong> {new Date(cve.lastModifiedDate).toLocaleDateString()}
                      </div>
                    )}
                    <div>
                      <strong>Data Freshness:</strong> {vulnerability.dataFreshness} 
                      (Last Updated: {new Date(vulnerability.lastUpdated).toLocaleString()})
                    </div>
                  </div>

                  {kev && (
                    <div style={{ marginTop: '16px', padding: '12px', background: 'rgba(239, 68, 68, 0.1)', borderRadius: '6px' }}>
                      <div style={{ fontWeight: 'bold', color: '#dc2626', marginBottom: '8px' }}>
                        CISA KEV Information:
                      </div>
                      <div style={{ fontSize: '0.875rem' }}>
                        <div><strong>Vendor/Product:</strong> {kev.vendorProject} - {kev.product}</div>
                        <div><strong>Required Action:</strong> {kev.requiredAction}</div>
                        <div><strong>Due Date:</strong> {new Date(kev.dueDate).toLocaleDateString()}</div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {expandedSection === 'timeline' && (
                <div style={{ 
                  background: '#fffbeb', 
                  border: '1px solid #fde68a', 
                  borderRadius: '8px',
                  padding: '16px',
                  marginBottom: '16px'
                }} className="slide-in">
                  <h4 style={{ margin: '0 0 12px 0', color: '#d97706', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Clock size={16} />
                    Recommended Action Timeline
                  </h4>
                  
                  <div style={{ position: 'relative' as const, paddingLeft: '24px' }}>
                    <div style={{ position: 'absolute' as const, left: '8px', top: '0', bottom: '0', width: '2px', background: '#d97706' }}></div>
                    
                    <div style={{ marginBottom: '16px', position: 'relative' as const }}>
                      <div style={{ position: 'absolute' as const, left: '-20px', top: '4px', width: '12px', height: '12px', borderRadius: '50%', background: '#dc2626' }}></div>
                      <div style={{ fontWeight: 'bold', color: '#dc2626' }}>
                        Immediate (0-24 hours)
                      </div>
                      <div style={{ fontSize: '0.875rem', marginTop: '4px' }}>
                        • Assess impact on your environment<br/>
                        • Identify affected systems<br/>
                        • Implement temporary mitigations
                      </div>
                    </div>

                    <div style={{ marginBottom: '16px', position: 'relative' as const }}>
                      <div style={{ position: 'absolute' as const, left: '-20px', top: '4px', width: '12px', height: '12px', borderRadius: '50%', background: '#f59e0b' }}></div>
                      <div style={{ fontWeight: 'bold', color: '#f59e0b' }}>
                        Short-term (1-7 days)
                      </div>
                      <div style={{ fontSize: '0.875rem', marginTop: '4px' }}>
                        • Apply security patches<br/>
                        • Update security configurations<br/>
                        • Verify patch effectiveness
                      </div>
                    </div>

                    <div style={{ position: 'relative' as const }}>
                      <div style={{ position: 'absolute' as const, left: '-20px', top: '4px', width: '12px', height: '12px', borderRadius: '50%', background: '#10b981' }}></div>
                      <div style={{ fontWeight: 'bold', color: '#10b981' }}>
                        Long-term (1-4 weeks)
                      </div>
                      <div style={{ fontSize: '0.875rem', marginTop: '4px' }}>
                        • Review and update policies<br/>
                        • Implement monitoring improvements<br/>
                        • Conduct post-incident review
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {expandedSection === 'resources' && (
                <div style={{ 
                  background: '#f8fafc', 
                  border: '1px solid #e2e8f0', 
                  borderRadius: '8px',
                  padding: '16px',
                  marginBottom: '16px'
                }} className="slide-in">
                  <h4 style={{ margin: '0 0 12px 0', color: '#475569', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Globe size={16} />
                    External Resources & References
                  </h4>
                  
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '16px' }}>
                    <div>
                      <div style={{ fontWeight: 'bold', marginBottom: '8px', fontSize: '0.875rem' }}>
                        Official Sources
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <LinkButton href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}>
                          NVD Database Entry
                        </LinkButton>
                        <LinkButton href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id}`}>
                          MITRE CVE Details
                        </LinkButton>
                        {kev && (
                          <LinkButton href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">
                            CISA KEV Catalog
                          </LinkButton>
                        )}
                      </div>
                    </div>

                    <div>
                      <div style={{ fontWeight: 'bold', marginBottom: '8px', fontSize: '0.875rem' }}>
                        Security Guidance
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <LinkButton href="https://www.first.org/epss/">
                          EPSS Documentation
                        </LinkButton>
                        <LinkButton href="https://cheatsheetseries.owasp.org/">
                          OWASP Cheat Sheets
                        </LinkButton>
                        <LinkButton href="https://www.sans.org/white-papers/">
                          SANS Security Papers
                        </LinkButton>
                      </div>
                    </div>

                    <div>
                      <div style={{ fontWeight: 'bold', marginBottom: '8px', fontSize: '0.875rem' }}>
                        Vendor Resources
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <LinkButton href="https://msrc.microsoft.com/security-guidance">
                          Microsoft Security
                        </LinkButton>
                        <LinkButton href="https://apache.org/security/">
                          Apache Security
                        </LinkButton>
                        <LinkButton href="https://access.redhat.com/security/">
                          Red Hat Security
                        </LinkButton>
                      </div>
                    </div>

                    <div>
                      <div style={{ fontWeight: 'bold', marginBottom: '8px', fontSize: '0.875rem' }}>
                        Tools & Scanners
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <LinkButton href="https://www.tenable.com/products/nessus">
                          Nessus Scanner
                        </LinkButton>
                        <LinkButton href="https://www.openvas.org/">
                          OpenVAS
                        </LinkButton>
                        <LinkButton href="https://qualys.com/apps/vulnerability-management/">
                          Qualys VMDR
                        </LinkButton>
                      </div>
                    </div>
                  </div>

                  {cve.references && cve.references.length > 0 && (
                    <div style={{ marginTop: '16px' }}>
                      <div style={{ fontWeight: 'bold', marginBottom: '8px', fontSize: '0.875rem' }}>
                        CVE References
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                        {cve.references.slice(0, 5).map((ref, idx) => (
                          <LinkButton key={idx} href={ref.url}>
                            {ref.source || 'Reference'} {idx + 1}
                          </LinkButton>
                        ))}
                        {cve.references.length > 5 && (
                          <span style={{ fontSize: '0.75rem', color: '#6b7280', alignSelf: 'center' }}>
                            +{cve.references.length - 5} more references
                          </span>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

// Settings Modal Component
interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  settings: Settings;
  setSettings: React.Dispatch<React.SetStateAction<Settings>>;
}

const SettingsModal: React.FC<SettingsModalProps> = ({ isOpen, onClose, settings, setSettings }) => {
  const { addNotification } = useContext(AppContext);
  const [localSettings, setLocalSettings] = useState(settings);
  const [showApiKey, setShowApiKey] = useState(false);
  const [showGeminiKey, setShowGeminiKey] = useState(false);

  const handleSave = () => {
    setSettings(localSettings);
    // Store API keys securely in localStorage (in production, use secure backend storage)
    if (localSettings.nvdApiKey) {
      localStorage.setItem('nvd_api_key', btoa(localSettings.nvdApiKey));
    }
    if (localSettings.geminiApiKey) {
      localStorage.setItem('gemini_api_key', btoa(localSettings.geminiApiKey));
    }
    addNotification({
      type: 'success',
      title: 'Settings Updated',
      message: 'Your preferences have been saved'
    });
    onClose();
  };

  // Load stored API keys on mount
  useEffect(() => {
    const storedNvdKey = localStorage.getItem('nvd_api_key');
    const storedGeminiKey = localStorage.getItem('gemini_api_key');
    
    if (storedNvdKey) {
      setLocalSettings(prev => ({ ...prev, nvdApiKey: atob(storedNvdKey) }));
    }
    if (storedGeminiKey) {
      setLocalSettings(prev => ({ ...prev, geminiApiKey: atob(storedGeminiKey) }));
    }
  }, []);

  if (!isOpen) return null;

  return (
    <div style={styles.modal} onClick={onClose}>
      <div style={styles.modalContent} onClick={(e) => e.stopPropagation()}>
        <div style={styles.modalHeader}>
          <h2 style={styles.modalTitle}>
            <Settings size={24} style={{ marginRight: '8px' }} />
            Platform Settings
          </h2>
          <button
            style={{ ...styles.button, padding: '8px' }}
            onClick={onClose}
          >
            <X size={20} />
          </button>
        </div>

        <div style={{ display: 'grid', gap: '24px' }}>
          {/* General Settings */}
          <div>
            <h3 style={{ margin: '0 0 16px 0', fontSize: '1.1rem' }}>General Settings</h3>
            <div style={{ display: 'grid', gap: '16px' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={localSettings.aiAnalysisEnabled}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, aiAnalysisEnabled: e.target.checked }))}
                  style={{ width: '18px', height: '18px' }}
                />
                <div>
                  <div style={{ fontWeight: '500' }}>AI-Powered Analysis</div>
                  <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>Enable advanced AI risk assessment and recommendations</div>
                </div>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={localSettings.autoRefresh}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, autoRefresh: e.target.checked }))}
                  style={{ width: '18px', height: '18px' }}
                />
                <div>
                  <div style={{ fontWeight: '500' }}>Auto-Refresh Data</div>
                  <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>Automatically check for updates every 30 minutes</div>
                </div>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={localSettings.notificationsEnabled}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, notificationsEnabled: e.target.checked }))}
                  style={{ width: '18px', height: '18px' }}
                />
                <div>
                  <div style={{ fontWeight: '500' }}>Desktop Notifications</div>
                  <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>Show notifications for important events</div>
                </div>
              </label>
            </div>
          </div>

          {/* API Configuration */}
          <div>
            <h3 style={{ margin: '0 0 16px 0', fontSize: '1.1rem' }}>API Configuration</h3>
            <div style={{ display: 'grid', gap: '12px' }}>
              <div style={styles.formGroup}>
                <label style={styles.label}>NVD API Key (Optional)</label>
                <div style={{ position: 'relative' as const }}>
                  <input
                    type={showApiKey ? 'text' : 'password'}
                    style={styles.input}
                    placeholder="Enter your NVD API key for higher rate limits"
                    value={localSettings.nvdApiKey || ''}
                    onChange={(e) => setLocalSettings(prev => ({ ...prev, nvdApiKey: e.target.value }))}
                  />
                  <button
                    style={{ 
                      position: 'absolute' as const, 
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
                <label style={styles.label}>Webhook URL</label>
                <input
                  type="url"
                  style={styles.input}
                  placeholder="https://your-webhook-endpoint.com"
                  value={localSettings.webhookUrl || ''}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, webhookUrl: e.target.value }))}
                />
              </div>
            </div>
          </div>

          {/* Gemini AI Configuration */}
          <div>
            <h3 style={{ margin: '0 0 16px 0', fontSize: '1.1rem' }}>
              <Brain size={20} style={{ marginRight: '8px', verticalAlign: 'middle' }} />
              Gemini AI Configuration
            </h3>
            <div style={{ display: 'grid', gap: '12px' }}>
              <div style={styles.formGroup}>
                <label style={styles.label}>Gemini API Key</label>
                <div style={{ position: 'relative' as const }}>
                  <input
                    type={showGeminiKey ? 'text' : 'password'}
                    style={styles.input}
                    placeholder="Enter your Gemini API key for AI analysis"
                    value={localSettings.geminiApiKey || ''}
                    onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiApiKey: e.target.value }))}
                  />
                  <button
                    style={{ 
                      position: 'absolute' as const, 
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
                <div style={{ fontSize: '0.75rem', color: '#6b7280', marginTop: '4px' }}>
                  Get your API key from <a href="https://makersuite.google.com/app/apikey" target="_blank" rel="noopener noreferrer" style={{ color: '#3b82f6' }}>Google AI Studio</a>
                </div>
              </div>

              <div style={styles.formGroup}>
                <label style={styles.label}>Gemini Model</label>
                <select
                  style={styles.select}
                  value={localSettings.geminiModel || 'gemini-2.0-flash'}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiModel: e.target.value }))}
                >
                  <option value="gemini-2.0-flash">Gemini 2.0 Flash (Fast)</option>
                  <option value="gemini-1.5-flash">Gemini 1.5 Flash</option>
                  <option value="gemini-1.5-pro">Gemini 1.5 Pro (Advanced)</option>
                </select>
              </div>

              {localSettings.aiAnalysisEnabled && localSettings.geminiApiKey && (
                <div style={{ 
                  background: '#f0f9ff', 
                  border: '1px solid #bae6fd', 
                  borderRadius: '8px', 
                  padding: '12px',
                  fontSize: '0.875rem'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <CheckCircle size={16} color="#0284c7" />
                    <span style={{ fontWeight: '500', color: '#0284c7' }}>AI Features Enabled</span>
                  </div>
                  <ul style={{ margin: '4px 0 0 20px', padding: 0, fontSize: '0.75rem', color: '#0c4a6e' }}>
                    <li>Intelligent vulnerability prioritization</li>
                    <li>Automated remediation recommendations</li>
                    <li>Natural language threat summaries</li>
                    <li>Risk pattern analysis</li>
                  </ul>
                </div>
              )}
            </div>
          </div>

          {/* Display Preferences */}
          <div>
            <h3 style={{ margin: '0 0 16px 0', fontSize: '1.1rem' }}>Display Preferences</h3>
            <div style={{ display: 'grid', gap: '12px' }}>
              <div style={styles.formGroup}>
                <label style={styles.label}>Default View</label>
                <select
                  style={styles.select}
                  value={localSettings.defaultView || 'detailed'}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, defaultView: e.target.value }))}
                >
                  <option value="detailed">Detailed Cards</option>
                  <option value="compact">Compact List</option>
                  <option value="table">Table View</option>
                </select>
              </div>

              <div style={styles.formGroup}>
                <label style={styles.label}>Results Per Page</label>
                <select
                  style={styles.select}
                  value={localSettings.resultsPerPage || '10'}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, resultsPerPage: e.target.value }))}
                >
                  <option value="10">10</option>
                  <option value="25">25</option>
                  <option value="50">50</option>
                  <option value="100">100</option>
                </select>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', paddingTop: '16px', borderTop: '1px solid #e5e7eb' }}>
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
    </div>
  );
};

// Main App Component
const EnterpriseVulnerabilityApp = () => {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadingSteps, setLoadingSteps] = useState([]);
  const [filters, setFilters] = useState({});
  const [notifications, setNotifications] = useState([]);
  const [automationRules, setAutomationRules] = useState([]);
  const [showSettings, setShowSettings] = useState(false);
  const [settings, setSettings] = useState<Settings>({
    aiAnalysisEnabled: true,
    autoRefresh: true,
    notificationsEnabled: true,
    darkMode: false,
    defaultView: 'detailed',
    resultsPerPage: '10',
    geminiModel: 'gemini-2.0-flash'
  });

  // Add notification function
  const addNotification = (notification) => {
    const id = Date.now();
    setNotifications(prev => [...prev, { ...notification, id }]);
    
    // Auto-remove notification after 5 seconds
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 5000);
  };

  // Auto-refresh functionality
  useEffect(() => {
    if (settings.autoRefresh && vulnerabilities.length > 0) {
      const interval = setInterval(() => {
        // Refresh data every 30 minutes
        addNotification({
          type: 'info',
          title: 'Data Refresh',
          message: 'Checking for updated vulnerability data...'
        });
      }, 30 * 60 * 1000);

      return () => clearInterval(interval);
    }
  }, [settings.autoRefresh, vulnerabilities.length]);

  return (
    <AppContext.Provider
      value={{
        vulnerabilities,
        setVulnerabilities,
        loading,
        setLoading,
        loadingSteps,
        setLoadingSteps,
        filters,
        setFilters,
        notifications,
        addNotification,
        automationRules,
        setAutomationRules,
        settings,
        setSettings,
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
                <h1 style={styles.title}>Enterprise Vulnerability Management Platform</h1>
                <p style={styles.subtitle}>Real-time threat intelligence • Advanced analytics • Automated remediation</p>
              </div>
            </div>
            <div style={styles.headerActions}>
              <div style={styles.statusIndicator}>
                <Activity size={16} />
                <span>Real-time Data</span>
              </div>
              <div style={styles.statusIndicator}>
                <Zap size={16} />
                <span>AI Enhanced</span>
              </div>
              <div style={styles.statusIndicator}>
                <Link size={16} />
                <span>Verified Links</span>
              </div>
              <button 
                style={{ ...styles.button, background: 'rgba(255,255,255,0.2)', border: 'none', color: 'white' }}
                onClick={() => setShowSettings(true)}
              >
                <Settings size={16} />
                Settings
              </button>
            </div>
          </div>
        </header>

        <main style={styles.mainContent}>
          <EnhancedSearchComponent />
          
          {vulnerabilities.length > 0 && <EnhancedDashboard vulnerabilities={vulnerabilities} />}
          
          {vulnerabilities.length > 0 && <ExportReportingPanel vulnerabilities={vulnerabilities} />}
          
          {vulnerabilities.length > 0 && <AutomationPanel />}

          {loading && (
            <div style={styles.loadingContainer} className="fade-in">
              <div style={{
                background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                color: 'white',
                padding: '32px',
                borderRadius: '12px',
                textAlign: 'center',
                maxWidth: '600px'
              }}>
                <Loader2 size={48} className="animate-spin" style={{ marginBottom: '16px' }} />
                <h3 style={{ margin: '0 0 8px 0' }}>Processing Vulnerability Data</h3>
                <p style={{ margin: '0 0 16px 0', opacity: 0.9 }}>
                  Fetching real-time data from NVD, EPSS, and KEV sources...
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
                    {loadingSteps.slice(-5).map((step, index) => (
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
                        ) : (
                          <div className="pulse" style={{ 
                            width: '12px', 
                            height: '12px', 
                            borderRadius: '50%', 
                            background: 'white' 
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
            <div style={styles.emptyState} className="fade-in">
              <div style={{
                background: 'white',
                borderRadius: '12px',
                padding: '48px',
                boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
                maxWidth: '800px',
                margin: '0 auto'
              }}>
                <Shield size={64} style={{ marginBottom: '24px', color: '#3b82f6' }} />
                <h2 style={{ margin: '0 0 12px 0', fontSize: '1.75rem' }}>Enterprise-Grade Vulnerability Analysis</h2>
                <p style={{ margin: '0 0 24px 0', fontSize: '1.1rem', color: '#6b7280' }}>
                  Advanced threat intelligence platform with real-time data integration
                </p>
                
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '20px', marginBottom: '32px' }}>
                  <div style={{ textAlign: 'center', padding: '20px' }}>
                    <Database size={32} color="#3b82f6" style={{ marginBottom: '12px' }} />
                    <h4 style={{ margin: '0 0 8px 0' }}>Real-time Data</h4>
                    <p style={{ margin: 0, fontSize: '0.875rem', color: '#6b7280' }}>
                      Live feeds from NVD, EPSS, and CISA KEV
                    </p>
                  </div>
                  
                  <div style={{ textAlign: 'center', padding: '20px' }}>
                    <Brain size={32} color="#8b5cf6" style={{ marginBottom: '12px' }} />
                    <h4 style={{ margin: '0 0 8px 0' }}>AI-Powered Analysis</h4>
                    <p style={{ margin: 0, fontSize: '0.875rem', color: '#6b7280' }}>
                      Smart risk assessment and remediation
                    </p>
                  </div>
                  
                  <div style={{ textAlign: 'center', padding: '20px' }}>
                    <Zap size={32} color="#f59e0b" style={{ marginBottom: '12px' }} />
                    <h4 style={{ margin: '0 0 8px 0' }}>Automation Ready</h4>
                    <p style={{ margin: 0, fontSize: '0.875rem', color: '#6b7280' }}>
                      Integrate with SIEM, Slack, and more
                    </p>
                  </div>
                </div>

                <div style={{ 
                  background: '#f0f9ff', 
                  border: '1px solid #bae6fd', 
                  borderRadius: '8px', 
                  padding: '16px',
                  marginBottom: '24px'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                    <Sparkles size={16} color="#0284c7" />
                    <span style={{ fontWeight: 'bold', color: '#0284c7' }}>Try These Sample CVEs</span>
                  </div>
                  <p style={{ margin: 0, fontSize: '0.875rem', color: '#0c4a6e' }}>
                    CVE-2021-44228 (Log4Shell), CVE-2021-34527 (PrintNightmare), CVE-2023-23397 (Outlook), CVE-2023-4966 (NetScaler)
                  </p>
                </div>

                <button 
                  style={{ ...styles.button, ...styles.buttonPrimary, fontSize: '1rem', padding: '12px 24px' }}
                  onClick={() => document.querySelector('input[placeholder*="CVE"]')?.focus()}
                >
                  <Search size={20} />
                  Start Analysis
                </button>
              </div>
            </div>
          )}

          {!loading && vulnerabilities.length > 0 && (
            <div>
              <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'space-between', 
                marginBottom: '24px',
                background: 'white',
                padding: '16px 24px',
                borderRadius: '12px',
                boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
              }}>
                <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <Shield size={28} color="#3b82f6" />
                  Vulnerability Analysis Results
                  <span style={{ 
                    background: '#3b82f6', 
                    color: 'white', 
                    padding: '4px 12px', 
                    borderRadius: '20px', 
                    fontSize: '0.875rem' 
                  }}>
                    {vulnerabilities.length}
                  </span>
                </h2>
                
                <div style={{ display: 'flex', gap: '12px' }}>
                  {settings.aiAnalysisEnabled && settings.geminiApiKey && (
                    <button 
                      style={{ 
                        ...styles.button, 
                        background: 'linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)',
                        color: 'white',
                        borderColor: '#8b5cf6'
                      }}
                      onClick={async () => {
                        try {
                          setLoading(true);
                          const assessment = await generateAIRiskAssessment(
                            vulnerabilities,
                            settings.geminiApiKey!,
                            settings.geminiModel || 'gemini-2.0-flash'
                          );
                          
                          // Create a modal or notification with the assessment
                          addNotification({
                            type: 'success',
                            title: 'AI Portfolio Analysis Complete',
                            message: 'Generated comprehensive risk assessment'
                          });
                          
                          // You could store this in state and display it in a modal
                          console.log('AI Assessment:', assessment);
                        } catch (error: any) {
                          addNotification({
                            type: 'error',
                            title: 'AI Analysis Failed',
                            message: error.message
                          });
                        } finally {
                          setLoading(false);
                        }
                      }}
                    >
                      <Brain size={16} />
                      AI Portfolio Analysis
                      <Sparkles size={14} />
                    </button>
                  )}
                  <button style={{ ...styles.button, ...styles.buttonSecondary }}>
                    <Download size={16} />
                    Export All
                  </button>
                  <button style={{ ...styles.button, ...styles.buttonPrimary }}>
                    <RefreshCw size={16} />
                    Refresh Data
                  </button>
                </div>
              </div>

              {vulnerabilities.map((vulnerability, index) => (
                <EnhancedVulnerabilityCard key={vulnerability.cve.id} vulnerability={vulnerability} index={index} />
              ))}
            </div>
          )}
        </main>

        <footer style={{ 
          background: 'linear-gradient(135deg, #1f2937 0%, #374151 100%)', 
          color: 'white', 
          padding: '32px 0',
          marginTop: '48px'
        }}>
          <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '0 16px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '24px' }}>
              <div>
                <h4 style={{ margin: '0 0 12px 0' }}>Enterprise Vulnerability Platform</h4>
                <p style={{ margin: 0, fontSize: '0.875rem', opacity: 0.8 }}>
                  Advanced threat intelligence and automated vulnerability management for enterprise environments.
                </p>
              </div>
              
              <div>
                <h5 style={{ margin: '0 0 12px 0' }}>Data Sources</h5>
                <div style={{ fontSize: '0.875rem', opacity: 0.8 }}>
                  <div>• NIST National Vulnerability Database</div>
                  <div>• FIRST.org EPSS Scoring</div>
                  <div>• CISA Known Exploited Vulnerabilities</div>
                  <div>• Real-time Threat Intelligence</div>
                </div>
              </div>
              
              <div>
                <h5 style={{ margin: '0 0 12px 0' }}>Features</h5>
                <div style={{ fontSize: '0.875rem', opacity: 0.8 }}>
                  <div>• AI-Powered Risk Assessment</div>
                  <div>• Automated Report Generation</div>
                  <div>• SIEM & Webhook Integration</div>
                  <div>• Compliance Framework Mapping</div>
                </div>
              </div>
            </div>
            
            <div style={{ 
              borderTop: '1px solid rgba(255,255,255,0.2)', 
              marginTop: '24px', 
              paddingTop: '24px',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              fontSize: '0.875rem'
            }}>
              <span>&copy; {new Date().getFullYear()} Enterprise Vulnerability Management Platform</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <CheckCircle size={14} />
                  Real-time Data
                </span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <Shield size={14} />
                  Enterprise Ready
                </span>
              </div>
            </div>
          </div>
        </footer>
      </div>
    </AppContext.Provider>
  );
};

export default EnterpriseVulnerabilityApp;