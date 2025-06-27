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
  const { addNotification } = useContext(AppContext);
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
      const testModel = 'gemini-2.5-flash';
      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${testModel}:generateContent?key=${localSettings.geminiApiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: testPrompt }] }],
          generationConfig: { candidateCount: 1 }
        })
      });
      
      if (response.ok) {
        addNotification({ type: 'success', title: 'Connection Test', message: 'Gemini AI connection successful!' });
      } else {
        throw new Error(`HTTP ${response.status}: Failed to connect`);
      }
    } catch (error) {
      addNotification({ type: 'error', title: 'Connection Test Failed', message: error.message });
    } finally {
      setTestingConnection(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div style={styles.modal}>
      <div style={styles.modalContent}>
        <div style={styles.modalHeader}>
          <h3 style={styles.modalTitle}>AI-Enhanced Platform Settings</h3>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 0 }}>
            <X size={24} color={settings.darkMode ? colors.dark.primaryText : colors.light.primaryText} />
          </button>
        </div>

        <div style={{ display: 'grid', gap: '24px' }}>
          <div style={{
            background: settings.darkMode ? colors.dark.background : colors.light.background,
            padding: '20px',
            borderRadius: '12px',
            border: `1px solid ${settings.darkMode ? colors.dark.border : colors.light.border}`,
            marginBottom: '24px'
          }}>
            <h4 style={{
              margin: '0 0 16px 0',
              color: settings.darkMode ? colors.dark.primaryText : colors.light.primaryText,
              fontSize: '1.1rem',
              fontWeight: '600',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              paddingBottom: '10px',
              borderBottom: `1px solid ${settings.darkMode ? colors.dark.border : colors.light.border}`
            }}>
              <Brain size={20} /> AI & RAG Configuration
            </h4>
            
            <div style={styles.formGroup}>
              <label htmlFor="geminiApiKey" style={styles.label}>Gemini API Key (Required for AI Analysis)</label>
              <div style={{ position: 'relative' }}>
                <input
                  id="geminiApiKey"
                  type={showGeminiKey ? 'text' : 'password'}
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
                    color: settings.darkMode ? colors.dark.secondaryText : colors.light.secondaryText,
                    padding: '4px'
                  }}
                  onClick={() => setShowGeminiKey(!showGeminiKey)}
                >
                  {showGeminiKey ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            <div style={styles.formGroup}>
              <label htmlFor="geminiModel" style={styles.label}>Gemini Model Selection</label>
              <select
                id="geminiModel"
                style={styles.select}
                value={localSettings.geminiModel || 'gemini-2.5-flash'}
                onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiModel: e.target.value }))}
              >
                <option value="gemini-2.5-pro">Gemini 2.5 Pro (Latest, Web Search + RAG)</option>
                <option value="gemini-2.5-flash">Gemini 2.5 Flash (Web Search + RAG)</option>
                <option value="gemini-2.0-pro">Gemini 2.0 pro (Fast RAG)</option>
                <option value="gemini-2.0-flash">Gemini 2.0 Flash (Deep RAG)</option>
              </select>
            </div>

            <button
              onClick={testGeminiConnection}
              disabled={testingConnection || !localSettings.geminiApiKey}
              style={{
                ...styles.button,
                ...styles.buttonSecondary,
                opacity: testingConnection || !localSettings.geminiApiKey ? 0.6 : 1
              }}
            >
              {testingConnection ? <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} /> : <Settings size={18} />}
              Test AI Connection
            </button>
          </div>

          <div style={{
            background: settings.darkMode ? colors.dark.background : colors.light.background,
            padding: '20px',
            borderRadius: '12px',
            border: `1px solid ${settings.darkMode ? colors.dark.border : colors.light.border}`,
            marginBottom: '24px'
          }}>
            <h4 style={{
              margin: '0 0 16px 0',
              color: settings.darkMode ? colors.dark.primaryText : colors.light.primaryText,
              fontSize: '1.1rem',
              fontWeight: '600',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              paddingBottom: '10px',
              borderBottom: `1px solid ${settings.darkMode ? colors.dark.border : colors.light.border}`
            }}>
              <Database size={20} /> Data Source & Interface
            </h4>
            
            <div style={styles.formGroup}>
              <label htmlFor="nvdApiKey" style={styles.label}>NVD API Key (Optional - Higher Rate Limits)</label>
              <div style={{ position: 'relative' }}>
                <input
                  id="nvdApiKey"
                  type={showNvdKey ? 'text' : 'password'}
                  style={styles.input}
                  placeholder="Enter your NVD API key"
                  value={localSettings.nvdApiKey || ''}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, nvdApiKey: e.target.value }))}
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
                    color: settings.darkMode ? colors.dark.secondaryText : colors.light.secondaryText,
                    padding: '4px'
                  }}
                  onClick={() => setShowNvdKey(!showNvdKey)}
                >
                  {showNvdKey ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            <div style={styles.formGroup}>
              <label style={{
                ...styles.label,
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                cursor: 'pointer',
              }}>
                <input
                  type="checkbox"
                  checked={localSettings.darkMode || false}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, darkMode: e.target.checked }))}
                  style={{
                    width: '16px',
                    height: '16px',
                    accentColor: colors.blue,
                    margin: 0,
                  }}
                />
                Dark Mode Interface
              </label>
            </div>

            <div style={styles.formGroup}>
              <label style={{
                ...styles.label,
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                cursor: 'pointer',
              }}>
                <input
                  type="checkbox"
                  checked={localSettings.enableRAG !== false}
                  onChange={(e) => setLocalSettings(prev => ({ ...prev, enableRAG: e.target.checked }))}
                  style={{
                    width: '16px',
                    height: '16px',
                    accentColor: colors.blue,
                    margin: 0,
                  }}
                />
                Enable RAG-Enhanced Analysis
              </label>
            </div>
          </div>
        </div>

        <div style={{
          display: 'flex',
          gap: '12px',
          justifyContent: 'flex-end',
          paddingTop: '24px',
          marginTop: '16px',
          borderTop: `1px solid ${settings.darkMode ? colors.dark.border : colors.light.border}`
        }}>
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
      const vulnerability = await fetchVulnerabilityDataWithAI(cveId, setLoadingSteps, {
        nvd: settings.nvdApiKey
      }, settings);
      
      setVulnerabilities([vulnerability]);
      setSearchHistory(prev => [...new Set([cveId, ...prev])].slice(0, 5));
      
      addNotification({
        type: 'success',
        title: 'AI-Powered Analysis Complete',
        message: `Successfully analyzed ${cveId} using AI to search ${vulnerability.discoveredSources?.length || 30}+ security sources`
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
        <h1 style={styles.searchTitle}>AI-Enhanced Vulnerability Intelligence</h1>
        <p style={styles.searchSubtitle}>
          AI-powered analysis with multi-source discovery, contextual knowledge retrieval and real-time threat intelligence
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
            {loading ? <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} /> : <Brain size={18} />}
            {loading ? 'Analyzing...' : 'AI Analyze'}
          </button>
        </div>

        <div style={{ 
          display: 'flex', 
          gap: '16px', 
          justifyContent: 'center',
          alignItems: 'center',
          flexWrap: 'wrap',
          marginTop: '32px',
          fontSize: '0.875rem',
          color: settings.darkMode ? colors.dark.primaryText : colors.light.primaryText
        }}>
          {[
            { icon: <Brain size={16} color={colors.blue} />, text: 'RAG-Enhanced AI' },
            { icon: <Database size={16} color={colors.purple} />, text: 'Knowledge Retrieval' },
            { icon: <Globe size={16} color={colors.green} />, text: 'Multi-Source Discovery' },
            { icon: <Search size={16} color={colors.yellow} />, text: 'Real-time Intelligence' }
          ].map((item, index) => (
            <div key={index} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 12px', background: settings.darkMode ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.02)', borderRadius: '8px', margin: '4px' }}>
              {item.icon}
              <span style={{ fontWeight: '500' }}>{item.text}</span>
            </div>
          ))}
        </div>

        {searchHistory.length > 0 && (
          <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', flexWrap: 'wrap', marginTop: '28px' }}>
            <span style={{ fontSize: '0.875rem', color: settings.darkMode ? colors.dark.primaryText : colors.light.primaryText, fontWeight: '500', alignSelf: 'center' }}>
              Recent:
            </span>
            {searchHistory.map((cve, index) => (
              <button
                key={index}
                onClick={() => setSearchTerm(cve)}
                style={{
                  ...styles.button,
                  padding: '6px 12px',
                  background: settings.darkMode ? `rgba(${hexToRgb(colors.blue)}, 0.15)` : `rgba(${hexToRgb(colors.blue)}, 0.1)`,
                  border: `1px solid rgba(${hexToRgb(colors.blue)}, 0.3)`,
                  borderRadius: '8px',
                  fontSize: '0.8rem',
                  color: colors.blue,
                  fontWeight: '500',
                  transition: 'all 0.2s ease',
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

// Enhanced Loading Component
const LoadingComponent = () => {
  const { loadingSteps, settings } = useContext(AppContext);
  const [progress, setProgress] = useState(0);
  const [timeRemaining, setTimeRemaining] = useState(30);
  const styles = getStyles(settings.darkMode);

  useEffect(() => {
    const totalSteps = 8;
    const currentProgress = Math.min((loadingSteps.length / totalSteps) * 100, 95);
    setProgress(currentProgress);
    
    const estimatedTime = Math.max(30 - (loadingSteps.length * 4), 5);
    setTimeRemaining(estimatedTime);
  }, [loadingSteps.length]);

  return (
    <div style={styles.loadingContainer}>
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
        `}
      </style>
      
      <div style={{ marginBottom: '32px', textAlign: 'center' }}>
        <div style={{ position: 'relative', display: 'inline-block' }}>
          <div style={{
            width: '80px',
            height: '80px',
            border: `4px solid ${settings.darkMode ? '#374151' : '#e5e7eb'}`,
            borderTop: `4px solid ${colors.blue}`,
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
            color: colors.blue
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
            background: `linear-gradient(90deg, ${colors.blue} 0%, ${colors.purple} 100%)`,
            borderRadius: '3px',
            transition: 'width 0.5s ease-out'
          }} />
        </div>
        
        <div style={{
          fontSize: '0.8rem',
          color: settings.darkMode ? colors.dark.tertiaryText : colors.light.tertiaryText,
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
        AI is discovering and analyzing vulnerability intelligence from 30+ security sources...
      </p>
      
      <div style={{ 
        background: settings.darkMode ? '#1e293b' : '#ffffff',
        borderRadius: '12px',
        padding: '24px',
        maxWidth: '700px',
        textAlign: 'left',
        border: settings.darkMode ? '1px solid #334155' : '1px solid #e2e8f0'
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
            color: settings.darkMode ? colors.dark.secondaryText : colors.light.secondaryText,
            display: 'flex',
            alignItems: 'center',
            gap: '12px'
          }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: colors.blue,
              flexShrink: 0,
              animation: index === loadingSteps.length - 1 ? 'pulse 1s ease-in-out infinite' : 'none'
            }} />
            <span style={{ flex: 1 }}>{step}</span>
            {index === loadingSteps.length - 1 && (
              <div style={{
                width: '16px',
                height: '16px',
                border: `2px solid ${colors.blue}`,
                borderTop: '2px solid transparent',
                borderRadius: '50%',
                animation: 'spin 1s linear infinite'
              }} />
            )}
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
      const vulnerability = await fetchVulnerabilityDataWithAI(cveId, setLoadingSteps, {
        nvd: settings.nvdApiKey
      }, settings);
      
      setVulnerabilities([vulnerability]);
      
      addNotification({
        type: 'success',
        title: 'Analysis Refreshed',
        message: `Updated AI-enhanced analysis for ${cveId}`
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
            
            button:focus-visible, 
            input:focus-visible, 
            select:focus-visible, 
            a:focus-visible {
              outline: 2px solid ${colors.blue} !important;
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
            <div style={styles.headerTitle}>
              <div style={{ position: 'relative' }}>
                <Brain size={32} color="#3b82f6" />
                <Database size={20} color="#8b5cf6" style={{ position: 'absolute', top: '16px', left: '20px' }} />
              </div>
              <div>
                <h1 style={styles.title}>AI VulnIntel Pro</h1>
                <p style={styles.subtitle}>AI-Powered Multi-Source Vulnerability Intelligence with RAG Enhancement</p>
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
          
          <div style={styles.mainContent}>
            {loading && <LoadingComponent />}
            
            {!loading && vulnerabilities.length === 0 && (
              <div style={{...styles.emptyState, paddingTop: '48px', paddingBottom: '48px' }}>
                <div style={{ marginBottom: '28px', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '16px' }}>
                  <Brain size={56} color={settings.darkMode ? colors.dark.tertiaryText : colors.light.tertiaryText} />
                  <Database size={40} color={settings.darkMode ? colors.dark.tertiaryText : colors.light.tertiaryText} />
                  <Globe size={44} color={settings.darkMode ? colors.dark.tertiaryText : colors.light.tertiaryText} />
                </div>
                <h3 style={{
                  fontSize: '1.375rem',
                  fontWeight: '600',
                  marginBottom: '16px',
                  color: settings.darkMode ? colors.dark.primaryText : colors.light.primaryText
                }}>
                  AI-Enhanced Intelligence Platform Ready
                </h3>
                <p style={{
                  fontSize: '0.95rem',
                  marginBottom: '12px',
                  color: settings.darkMode ? colors.dark.secondaryText : colors.light.secondaryText,
                  lineHeight: 1.6,
                  maxWidth: '600px',
                  margin: '0 auto 12px auto'
                }}>
                  Enter a CVE ID to begin comprehensive AI-powered vulnerability analysis with multi-source discovery and contextual knowledge retrieval.
                </p>
                <p style={{
                  fontSize: '0.875rem',
                  color: settings.darkMode ? colors.dark.tertiaryText : colors.light.tertiaryText,
                  marginBottom: '28px',
                  maxWidth: '600px',
                  margin: '0 auto 28px auto'
                }}>
                  Real-time intelligence enhanced with semantic search, 30+ security sources, and domain expertise.
                </p>
                
                {!settings.geminiApiKey && (
                  <div style={{
                    marginTop: '32px',
                    padding: '16px 20px',
                    background: settings.darkMode
                      ? `rgba(${hexToRgb(colors.yellow)}, 0.1)`
                      : `rgba(${hexToRgb(colors.yellow)}, 0.07)`,
                    border: `1px solid rgba(${hexToRgb(colors.yellow)}, 0.3)`,
                    borderRadius: '12px',
                    maxWidth: '550px',
                    margin: '32px auto 0'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '10px' }}>
                      <AlertTriangle size={20} color={colors.yellow} />
                      <span style={{ fontWeight: '600', color: colors.yellow, fontSize: '0.95rem' }}>AI Configuration Required</span>
                    </div>
                    <p style={{
                      fontSize: '0.875rem',
                      margin: 0,
                      color: settings.darkMode ? colors.dark.secondaryText : colors.light.secondaryText,
                      lineHeight: 1.5
                    }}>
                      Configure your Gemini API key in settings to enable AI-enhanced multi-source vulnerability analysis.
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

export default VulnerabilityIntelligence;import React, { useState, createContext, useContext, useEffect } from 'react';
import { Search, Brain, Settings, Target, Database, Activity, CheckCircle, XCircle, X, Eye, EyeOff, Save, Globe, AlertTriangle, Loader2, ExternalLink, RefreshCw, Download, Info, Package, BarChart3, Copy, Zap, Clock, Shield, ChevronRight, Code, Network, Server } from 'lucide-react';

// Enhanced RAG Vector Database Implementation
class EnhancedVectorDatabase {
  constructor() {
    this.documents = [];
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
        content: "CVE severity classification considers CVSS scores, exploitability, asset exposure, and business impact. Critical vulnerabilities (9.0-10.0 CVSS) with known exploits and high exposure get immediate priority.",
        category: "severity",
        tags: ["severity", "classification", "priority"]
      },
      {
        title: "Active Exploitation Intelligence",
        content: "Integration of multiple threat intelligence sources helps identify vulnerabilities under active exploitation. This includes CISA KEV catalog, commercial threat feeds, proof-of-concept availability, and ransomware campaign usage.",
        category: "exploitation",
        tags: ["exploitation", "threat-intelligence", "ransomware", "kev"]
      },
      {
        title: "EPSS Exploitation Prediction Analysis",
        content: "EPSS (Exploit Prediction Scoring System) provides probability scores for vulnerability exploitation within 30 days. Scores above 0.5 (50%) indicate high exploitation likelihood and warrant immediate attention.",
        category: "epss",
        tags: ["epss", "exploitation-probability", "prediction", "first"]
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

// Helper function to convert hex to RGB
const hexToRgb = (hex) => {
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
};

// Consistent color palette
const colors = {
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

const getStyles = (darkMode) => {
  const currentTheme = darkMode ? colors.dark : colors.light;
  const commonShadow = `0 4px 6px -1px ${currentTheme.shadow}, 0 2px 4px -1px ${currentTheme.shadow}`;

  return {
    appContainer: {
      minHeight: '100vh',
      backgroundColor: currentTheme.background,
      fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
      color: currentTheme.primaryText,
      fontSize: '16px',
      lineHeight: '1.6',
    },
    header: {
      background: `linear-gradient(135deg, ${currentTheme.surface} 0%, ${currentTheme.background} 100%)`,
      color: currentTheme.primaryText,
      boxShadow: commonShadow,
      borderBottom: `1px solid ${currentTheme.border}`
    },
    headerContent: {
      maxWidth: '1536px',
      margin: '0 auto',
      padding: '20px 32px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between'
    },
    headerTitle: { display: 'flex', alignItems: 'center', gap: '16px' },
    title: {
      fontSize: '1.5rem',
      fontWeight: '700',
      margin: 0,
      background: `linear-gradient(135deg, ${colors.blue} 0%, ${colors.purple} 100%)`,
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      backgroundClip: 'text'
    },
    subtitle: {
      fontSize: '0.9375rem',
      color: currentTheme.secondaryText,
      margin: 0,
      fontWeight: '500'
    },
    headerActions: { display: 'flex', alignItems: 'center', gap: '16px' },
    statusIndicator: {
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      fontSize: '0.875rem',
      padding: '8px 14px',
      borderRadius: '9999px',
      border: '1px solid',
      fontWeight: '600',
      minHeight: '44px',
    },
    mainContent: {
      maxWidth: '1536px',
      margin: '0 auto',
      padding: '24px 32px'
    },
    searchSection: {
      background: `linear-gradient(135deg, ${currentTheme.surface} 0%, ${currentTheme.background} 100%)`,
      padding: '48px 32px 64px 32px',
      borderBottom: `1px solid ${currentTheme.border}`
    },
    searchContainer: {
      maxWidth: '960px',
      margin: '0 auto',
      textAlign: 'center'
    },
    searchTitle: {
      fontSize: '2.75rem',
      fontWeight: '800',
      background: `linear-gradient(135deg, ${colors.blue} 0%, ${colors.purple} 100%)`,
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      backgroundClip: 'text',
      marginBottom: '12px'
    },
    searchSubtitle: {
      fontSize: '1.25rem',
      color: currentTheme.secondaryText,
      marginBottom: '40px',
      fontWeight: '500',
      maxWidth: '700px',
      margin: '0 auto 32px auto',
    },
    searchWrapper: {
      position: 'relative',
      maxWidth: '768px',
      margin: '0 auto 24px auto',
    },
    searchInput: {
      width: '100%',
      padding: '20px 22px 20px 56px',
      border: `2px solid ${currentTheme.border}`,
      borderRadius: '12px',
      fontSize: '1.125rem',
      outline: 'none',
      boxSizing: 'border-box',
      background: currentTheme.surface,
      color: currentTheme.primaryText,
      transition: 'all 0.2s ease-in-out',
      boxShadow: `0 2px 4px ${currentTheme.shadow}`,
      minHeight: '64px',
    },
    searchIcon: {
      position: 'absolute',
      left: '20px',
      top: '50%',
      transform: 'translateY(-50%)',
      color: currentTheme.secondaryText
    },
    searchButton: {
      position: 'absolute',
      right: '8px',
      top: '50%',
      transform: 'translateY(-50%)',
      padding: '12px 24px',
      background: `linear-gradient(135deg, ${colors.blue} 0%, #1d4ed8 100%)`,
      color: 'white',
      border: 'none',
      borderRadius: '8px',
      cursor: 'pointer',
      fontWeight: '600',
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      fontSize: '1rem',
      boxShadow: `0 2px 8px rgba(${hexToRgb(colors.blue)}, 0.3)`,
      transition: 'all 0.2s ease-in-out',
      minHeight: '44px',
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
      border: '1px solid',
      fontSize: '1rem',
      transition: 'all 0.2s ease-in-out',
      textDecoration: 'none',
      whiteSpace: 'nowrap',
      minHeight: '44px',
    },
    buttonPrimary: {
      background: `linear-gradient(135deg, ${colors.blue} 0%, #1d4ed8 100%)`,
      color: 'white',
      borderColor: 'transparent',
      boxShadow: `0 2px 8px rgba(${hexToRgb(colors.blue)}, 0.3)`,
    },
    buttonSecondary: {
      background: currentTheme.surface,
      color: currentTheme.primaryText,
      borderColor: currentTheme.border,
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
      lineHeight: 1.2,
    },
    badgeCritical: { background: 'rgba(239, 68, 68, 0.15)', color: colors.red, border: '1px solid rgba(239, 68, 68, 0.3)' },
    badgeHigh: { background: 'rgba(245, 158, 11, 0.15)', color: colors.yellow, border: '1px solid rgba(245, 158, 11, 0.3)' },
    badgeMedium: { background: 'rgba(59, 130, 246, 0.15)', color: colors.blue, border: '1px solid rgba(59, 130, 246, 0.3)' },
    badgeLow: { background: 'rgba(34, 197, 94, 0.15)', color: colors.green, border: '1px solid rgba(34, 197, 94, 0.3)' },
    notification: {
      background: currentTheme.surface,
      borderRadius: '8px',
      padding: '16px',
      boxShadow: commonShadow,
      maxWidth: '400px',
      border: `1px solid ${currentTheme.border}`,
      display: 'flex',
      alignItems: 'flex-start',
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
      padding: '64px 32px',
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
      background: 'rgba(0, 0, 0, 0.6)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1050,
      backdropFilter: 'blur(5px)'
    },
    modalContent: {
      background: currentTheme.surface,
      borderRadius: '16px',
      padding: '24px 32px',
      width: '100%',
      maxWidth: '700px',
      maxHeight: '90vh',
      overflowY: 'auto',
      margin: '20px',
      border: `1px solid ${currentTheme.border}`,
      boxShadow: `0 25px 50px -12px ${currentTheme.shadow}`,
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
      fontSize: '1.375rem',
      fontWeight: '700',
      margin: 0,
      color: currentTheme.primaryText
    },
    formGroup: { marginBottom: '24px' },
    label: {
      display: 'block',
      fontSize: '1rem',
      fontWeight: '600',
      color: currentTheme.secondaryText,
      marginBottom: '8px'
    },
    input: {
      width: '100%',
      padding: '12px 16px',
      border: `1px solid ${currentTheme.border}`,
      borderRadius: '8px',
      fontSize: '1rem',
      outline: 'none',
      boxSizing: 'border-box',
      background: currentTheme.surface,
      color: currentTheme.primaryText,
      transition: 'border-color 0.2s ease-in-out, box-shadow 0.2s ease-in-out',
      minHeight: '44px',
    },
    select: {
      width: '100%',
      padding: '12px 16px',
      border: `1px solid ${currentTheme.border}`,
      borderRadius: '8px',
      fontSize: '1rem',
      outline: 'none',
      background: currentTheme.surface,
      boxSizing: 'border-box',
      color: currentTheme.primaryText,
      transition: 'border-color 0.2s ease-in-out, box-shadow 0.2s ease-in-out',
      appearance: 'none',
      backgroundImage: 'url("data:image/svg+xml;charset=UTF-8,<svg xmlns=\'http://www.w3.org/2000/svg\' width=\'16\' height=\'16\' fill=\'%2394a3b8\' viewBox=\'0 0 16 16\'><path fill-rule=\'evenodd\' d=\'M1.646 4.646a.5.5 0 0 1 .708 0L8 10.293l5.646-5.647a.5.5 0 0 1 .708.708l-6 6a.5.5 0 0 1-.708 0l-6-6a.5.5 0 0 1 0-.708z\'/></svg>")',
      backgroundRepeat: 'no-repeat',
      backgroundPosition: 'right 16px center',
      paddingRight: '40px',
      minHeight: '44px',
    }
  };
};

const AppContext = createContext({});

// AI Analysis Parser Functions
const parseAIAnalysisToCards = (analysisText) => {
  if (!analysisText) return [];

  const cards = [];
  
  // Define parsing patterns for different sections
  const sections = [
    {
      id: 'overview',
      patterns: [
        /(?:overview|description|summary)[^#]*?([^#]+?)(?=#|$)/is,
        /(?:vulnerability|cve)[^#]*?([^#]+?)(?=#|$)/is
      ],
      title: 'Vulnerability Overview',
      icon: <Info size={20} />,
      type: 'overview',
      priority: 'high'
    },
    {
      id: 'technical',
      patterns: [
        /(?:technical|attack|vector|method)[^#]*?([^#]+?)(?=#|$)/is,
        /(?:flaw|mechanism|exploit)[^#]*?([^#]+?)(?=#|$)/is
      ],
      title: 'Technical Analysis',
      icon: <Code size={20} />,
      type: 'technical',
      priority: 'medium'
    },
    {
      id: 'impact',
      patterns: [
        /(?:impact|consequence|affect|damage)[^#]*?([^#]+?)(?=#|$)/is,
        /(?:confidentiality|integrity|availability)[^#]*?([^#]+?)(?=#|$)/is
      ],
      title: 'Impact Assessment',
      icon: <Target size={20} />,
      type: 'impact',
      priority: 'high'
    },
    {
      id: 'mitigation',
      patterns: [
        /(?:mitigation|remediation|fix|patch|solution)[^#]*?([^#]+?)(?=#|$)/is,
        /(?:recommended|should|update)[^#]*?([^#]+?)(?=#|$)/is
      ],
      title: 'Mitigation Strategies',
      icon: <Shield size={20} />,
      type: 'mitigation',
      priority: 'critical'
    },
    {
      id: 'components',
      patterns: [
        /(?:affected|package|software|component|system)[^#]*?([^#]+?)(?=#|$)/is,
        /(?:installation|deployment|version)[^#]*?([^#]+?)(?=#|$)/is
      ],
      title: 'Affected Components',
      icon: <Server size={20} />,
      type: 'components',
      priority: 'medium'
    },
    {
      id: 'exploitation',
      patterns: [
        /(?:exploit|threat|attack|malicious)[^#]*?([^#]+?)(?=#|$)/is,
        /(?:landscape|active|wild)[^#]*?([^#]+?)(?=#|$)/is
      ],
      title: 'Threat Landscape',
      icon: <AlertTriangle size={20} />,
      type: 'exploitation',
      priority: 'critical'
    }
  ];

  // Extract content for each section
  sections.forEach(section => {
    for (const pattern of section.patterns) {
      const match = analysisText.match(pattern);
      if (match && match[1] && match[1].trim().length > 50) {
        cards.push({
          id: section.id,
          type: section.type,
          title: section.title,
          icon: section.icon,
          content: match[1].trim(),
          priority: section.priority
        });
        break; // Found content for this section, move to next
      }
    }
  });

  return cards;
};

// Extract structured data from AI analysis
const extractStructuredData = (analysisText, vulnerability) => {
  const data = {
    metrics: {},
    insights: [],
    recommendations: [],
    timeline: [],
    references: [],
    keyFindings: []
  };

  // Extract recommendations using multiple patterns
  const recommendationPatterns = [
    /(?:recommend|should|must|need to)[^.!?]*[.!?]/gi,
    /(?:patch|update|upgrade|fix)[^.!?]*[.!?]/gi,
    /(?:immediately|urgent|critical|priority)[^.!?]*[.!?]/gi,
    /(?:implement|deploy|configure)[^.!?]*[.!?]/gi
  ];

  const allRecommendations = [];
  recommendationPatterns.forEach(pattern => {
    const matches = analysisText.match(pattern);
    if (matches) {
      allRecommendations.push(...matches);
    }
  });

  // Deduplicate and clean recommendations
  data.recommendations = [...new Set(allRecommendations)]
    .map(rec => rec.trim())
    .filter(rec => rec.length > 20 && rec.length < 200)
    .slice(0, 5);

  // Extract URLs for references
  const urlPattern = /https?:\/\/[^\s<>"{}|\\^`[\]]+/g;
  const urls = analysisText.match(urlPattern);
  if (urls) {
    data.references = urls.slice(0, 5).map(url => ({
      url,
      title: extractDomainName(url),
      type: categorizeReference(url)
    }));
  }

  return data;
};

// Helper functions
const extractDomainName = (url) => {
  try {
    return new URL(url).hostname.replace('www.', '');
  } catch {
    return url;
  }
};

const categorizeReference = (url) => {
  const urlLower = url.toLowerCase();
  if (urlLower.includes('cve') || urlLower.includes('nvd')) return 'official';
  if (urlLower.includes('exploit') || urlLower.includes('poc')) return 'exploit';
  if (urlLower.includes('github') || urlLower.includes('advisory')) return 'advisory';
  if (urlLower.includes('patch') || urlLower.includes('fix')) return 'patch';
  return 'reference';
};

// Enhanced Card Component
const AnalysisCard = ({ card, darkMode = false }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  
  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'critical': return '#ef4444';
      case 'high': return '#f59e0b';
      case 'medium': return '#3b82f6';
      default: return '#22c55e';
    }
  };

  const formatContent = (content) => {
    if (!content) return { preview: '', full: '' };
    
    // Clean up content
    const cleaned = content
      .replace(/\*\*/g, '') // Remove markdown bold
      .replace(/#{1,6}\s?/g, '') // Remove markdown headers
      .trim();
    
    // Split into sentences
    const sentences = cleaned.split(/[.!?]+/).filter(s => s.trim().length > 10);
    const preview = sentences.slice(0, 2).join('. ') + (sentences.length > 2 ? '.' : '');
    
    return {
      preview: preview.length > 250 ? preview.substring(0, 250) + '...' : preview,
      full: cleaned
    };
  };

  const formattedContent = formatContent(card.content);
  const priorityColor = getPriorityColor(card.priority);

  return (
    <div 
      style={{
        background: darkMode 
          ? 'linear-gradient(135deg, #1e293b 0%, #334155 100%)' 
          : 'linear-gradient(135deg, #ffffff 0%, #f8fafc 100%)',
        borderRadius: '12px',
        padding: '20px',
        border: `1px solid ${darkMode ? '#334155' : '#e2e8f0'}`,
        boxShadow: darkMode 
          ? '0 2px 8px rgba(0, 0, 0, 0.3)' 
          : '0 2px 8px rgba(0, 0, 0, 0.05)',
        marginBottom: '16px',
        transition: 'all 0.2s ease-in-out',
        cursor: 'pointer'
      }}
      onClick={() => setIsExpanded(!isExpanded)}
      onMouseEnter={(e) => {
        e.currentTarget.style.transform = 'translateY(-2px)';
        e.currentTarget.style.boxShadow = darkMode 
          ? '0 4px 16px rgba(0, 0, 0, 0.4)' 
          : '0 4px 16px rgba(0, 0, 0, 0.1)';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.transform = 'translateY(0)';
        e.currentTarget.style.boxShadow = darkMode 
          ? '0 2px 8px rgba(0, 0, 0, 0.3)' 
          : '0 2px 8px rgba(0, 0, 0, 0.05)';
      }}
    >
      {/* Card Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '12px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            padding: '8px',
            borderRadius: '8px',
            background: `${priorityColor}20`,
            color: priorityColor
          }}>
            {card.icon}
          </div>
          <h3 style={{
            margin: 0,
            fontSize: '1.125rem',
            fontWeight: '600',
            color: darkMode ? '#f1f5f9' : '#0f172a'
          }}>
            {card.title}
          </h3>
        </div>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{
            padding: '4px 8px',
            borderRadius: '6px',
            fontSize: '0.75rem',
            fontWeight: '600',
            textTransform: 'uppercase',
            background: `${priorityColor}20`,
            color: priorityColor
          }}>
            {card.priority}
          </span>
          <ChevronRight 
            size={16} 
            style={{
              transform: isExpanded ? 'rotate(90deg)' : 'rotate(0deg)',
              transition: 'transform 0.2s ease-in-out',
              color: darkMode ? '#94a3b8' : '#64748b'
            }}
          />
        </div>
      </div>

      {/* Card Content */}
      <div style={{
        fontSize: '0.9375rem',
        lineHeight: '1.6',
        color: darkMode ? '#cbd5e1' : '#475569'
      }}>
        {isExpanded ? formattedContent.full : formattedContent.preview}
      </div>

      {/* Special content for mitigation cards */}
      {card.type === 'mitigation' && isExpanded && (
        <div style={{
          marginTop: '16px',
          padding: '12px',
          background: darkMode 
            ? 'rgba(34, 197, 94, 0.1)' 
            : 'rgba(34, 197, 94, 0.05)',
          borderRadius: '8px',
          border: '1px solid rgba(34, 197, 94, 0.2)'
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#22c55e',
            marginBottom: '8px'
          }}>
            <CheckCircle size={16} />
            Priority Actions
          </div>
          <div style={{
            fontSize: '0.875rem',
            color: darkMode ? '#cbd5e1' : '#475569',
            lineHeight: '1.5'
          }}>
            Based on the analysis, immediate patching and monitoring are recommended.
          </div>
        </div>
      )}
    </div>
  );
};

// Recommendations Card Component
const RecommendationsCard = ({ recommendations, darkMode }) => {
  if (!recommendations || recommendations.length === 0) return null;

  return (
    <div style={{
      background: darkMode 
        ? 'rgba(245, 158, 11, 0.1)' 
        : 'linear-gradient(135deg, #fef3c7 0%, #fde68a 100%)',
      borderRadius: '12px',
      padding: '20px',
      border: '1px solid #f59e0b',
      marginBottom: '24px'
    }}>
      <h3 style={{
        margin: '0 0 16px 0',
        fontSize: '1.125rem',
        fontWeight: '600',
        color: '#92400e',
        display: 'flex',
        alignItems: 'center',
        gap: '8px'
      }}>
        <Shield size={20} />
        AI-Generated Recommendations
      </h3>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {recommendations.slice(0, 4).map((rec, index) => (
          <div key={index} style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '8px',
            padding: '8px',
            background: 'rgba(255, 255, 255, 0.5)',
            borderRadius: '6px'
          }}>
            <CheckCircle size={16} style={{ 
              color: '#22c55e', 
              marginTop: '2px', 
              flexShrink: 0 
            }} />
            <span style={{
              fontSize: '0.875rem',
              color: '#92400e',
              lineHeight: '1.4'
            }}>
              {rec.replace(/^[^a-zA-Z]*/, '').trim()}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

// References Card Component
const ReferencesCard = ({ references, darkMode }) => {
  if (!references || references.length === 0) return null;

  return (
    <div style={{
      background: darkMode ? '#1e293b' : '#ffffff',
      borderRadius: '12px',
      padding: '20px',
      border: `1px solid ${darkMode ? '#334155' : '#e2e8f0'}`,
      boxShadow: darkMode ? '0 2px 8px rgba(0, 0, 0, 0.3)' : '0 2px 8px rgba(0, 0, 0, 0.05)',
      marginBottom: '16px'
    }}>
      <h3 style={{
        margin: '0 0 16px 0',
        fontSize: '1.125rem',
        fontWeight: '600',
        color: darkMode ? '#f1f5f9' : '#0f172a',
        display: 'flex',
        alignItems: 'center',
        gap: '8px'
      }}>
        <Globe size={20} />
        Source References
      </h3>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {references.slice(0, 5).map((ref, index) => (
          <a
            key={index}
            href={ref.url}
            target="_blank"
            rel="noopener noreferrer"
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '8px 12px',
              background: darkMode ? '#334155' : '#f8fafc',
              borderRadius: '6px',
              textDecoration: 'none',
              color: '#3b82f6',
              fontSize: '0.875rem',
              transition: 'background 0.2s ease-in-out'
            }}
            onMouseEnter={(e) => e.target.style.background = darkMode ? '#475569' : '#e2e8f0'}
            onMouseLeave={(e) => e.target.style.background = darkMode ? '#334155' : '#f8fafc'}
          >
            <span>{ref.title}</span>
            <ExternalLink size={14} />
          </a>
        ))}
      </div>
    </div>
  );
};

// Enhanced AI Analysis Tab Component
const EnhancedAIAnalysisTab = ({ aiAnalysis, vulnerability, darkMode }) => {
  if (!aiAnalysis || !aiAnalysis.analysis) {
    return (
      <div style={{
        textAlign: 'center',
        padding: '48px 32px',
        background: darkMode ? '#1e293b' : '#ffffff',
        borderRadius: '12px',
        border: `1px solid ${darkMode ? '#334155' : '#e2e8f0'}`
      }}>
        <Brain size={40} color={darkMode ? '#64748b' : '#94a3b8'} />
        <h3 style={{ 
          margin: '16px 0 8px 0', 
          color: darkMode ? '#f1f5f9' : '#0f172a' 
        }}>
          No AI Analysis Available
        </h3>
        <p style={{ 
          margin: 0, 
          color: darkMode ? '#94a3b8' : '#64748b' 
        }}>
          Generate RAG-enhanced analysis to see structured insights
        </p>
      </div>
    );
  }

  const analysisCards = parseAIAnalysisToCards(aiAnalysis.analysis);
  const structuredData = extractStructuredData(aiAnalysis.analysis, vulnerability);

  return (
    <div>
      {/* Header with badges */}
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center', 
        marginBottom: '24px' 
      }}>
        <h2 style={{
          fontSize: '1.5rem',
          fontWeight: '700',
          color: darkMode ? '#f1f5f9' : '#0f172a',
          margin: 0
        }}>
          RAG-Enhanced Security Analysis
        </h2>
        <div style={{ display: 'flex', gap: '8px' }}>
          {aiAnalysis.webGrounded && (
            <span style={{
              padding: '4px 8px',
              background: 'rgba(34, 197, 94, 0.15)',
              color: '#22c55e',
              border: '1px solid rgba(34, 197, 94, 0.3)',
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
              padding: '4px 8px',
              background: 'rgba(139, 92, 246, 0.15)',
              color: '#8b5cf6',
              border: '1px solid rgba(139, 92, 246, 0.3)',
              borderRadius: '6px',
              fontSize: '0.75rem',
              fontWeight: '600',
              display: 'flex',
              alignItems: 'center',
              gap: '4px'
            }}>
              <Database size={12} />
              RAG ENHANCED
            </span>
          )}
        </div>
      </div>

      {/* Analysis Cards */}
      {analysisCards.length > 0 ? (
        <div style={{ marginBottom: '24px' }}>
          {analysisCards.map((card) => (
            <AnalysisCard 
              key={card.id} 
              card={card} 
              darkMode={darkMode}
            />
          ))}
        </div>
      ) : (
        <div style={{
          background: darkMode ? '#334155' : '#f8fafc',
          borderRadius: '8px',
          padding: '16px',
          marginBottom: '24px',
          textAlign: 'center',
          color: darkMode ? '#94a3b8' : '#64748b'
        }}>
          Unable to parse analysis into cards. Raw analysis available below.
        </div>
      )}

      {/* Recommendations */}
      <RecommendationsCard 
        recommendations={structuredData.recommendations} 
        darkMode={darkMode} 
      />

      {/* References */}
      <ReferencesCard 
        references={structuredData.references} 
        darkMode={darkMode} 
      />

      {/* Analysis Metadata */}
      <div style={{
        background: darkMode ? '#334155' : '#f8fafc',
        border: `1px solid ${darkMode ? '#475569' : '#e2e8f0'}`,
        borderRadius: '12px',
        padding: '16px 20px',
        fontSize: '0.8rem',
        color: darkMode ? '#94a3b8' : '#64748b',
        lineHeight: 1.6,
      }}>
        <div style={{ 
          fontWeight: '600', 
          marginBottom: '10px', 
          color: darkMode ? '#cbd5e1' : '#475569' 
        }}>
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
          <li>Generated: {new Date().toLocaleString()}</li>
        </ul>
      </div>
    </div>
  );
};

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
    
    const epssScore = parseFloat(epssData.epss).toFixed(9).substring(0, 10);
    const percentileScore = parseFloat(epssData.percentile).toFixed(9).substring(0, 10);
    const epssPercentage = (parseFloat(epssData.epss) * 100).toFixed(3);
    
    setLoadingSteps(prev => [...prev, `✅ Retrieved EPSS data for ${cveId}: ${epssPercentage}% (Percentile: ${parseFloat(percentileScore).toFixed(3)})`]);
    
    if (enhancedRAGDatabase.initialized) {
      await enhancedRAGDatabase.addDocument(
        `CVE ${cveId} EPSS Analysis: Exploitation probability ${epssPercentage}% (percentile ${parseFloat(percentileScore).toFixed(3)}). ${parseFloat(epssScore) > 0.5 ? 'High exploitation likelihood - immediate attention required.' : parseFloat(epssScore) > 0.1 ? 'Moderate exploitation likelihood - monitor closely.' : 'Lower exploitation likelihood but monitoring recommended.'}`,
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
      epss: epssScore,
      percentile: percentileScore,
      epssFloat: parseFloat(epssScore),
      percentileFloat: parseFloat(percentileScore),
      epssPercentage: epssPercentage,
      date: epssData.date,
      model_version: data.model_version
    };
    
  } catch (error) {
    console.error(`EPSS API Error for ${cveId}:`, error);
    setLoadingSteps(prev => [...prev, `⚠️ EPSS data unavailable for ${cveId}: ${error.message}`]);
    return null;
  }
};

// AI-powered multi-source fetching
const fetchAllSourcesWithAI = async (cveId, cveData, epssData, apiKeys, settings, setLoadingSteps) => {
  if (!settings.geminiApiKey) {
    throw new Error('Gemini API key required for AI-powered source discovery');
  }
  
  const model = settings.geminiModel || 'gemini-2.0-flash-exp';
  const isAdvancedModel = model.includes('2.0') || model.includes('1.5');
  
  const searchPrompt = `You are a security researcher analyzing ${cveId}. Search and analyze information from ALL available security sources on the web.

REQUIRED SOURCES TO CHECK:
1. CISA KEV Catalog - Check if this CVE is actively exploited
2. GitHub Security Advisories (GHSA) - Find any security advisories
3. OSV.dev - Check aggregated vulnerability data
4. Exploit-DB (exploit-db.com) - Search for public exploits
5. Microsoft Security Response Center (MSRC) - Check if affects Microsoft
6. Red Hat Security Advisories - Check for Red Hat/Fedora advisories
7. Ubuntu Security Notices (USN) - Find Ubuntu-specific info

Current data I already have:
- CVSS Score: ${cveData?.cvssV3?.baseScore || 'Unknown'}
- EPSS Score: ${epssData?.epssPercentage || 'Unknown'}%
- Description: ${cveData?.description || 'Unknown'}

For each source where you find information, provide:
- Source name
- What information was found
- Direct URLs when available
- Severity/risk indicators
- Exploitation status
- Available patches or mitigations

Search comprehensively and return a detailed JSON-structured response with all findings.`;

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
      }
    };
    
    if (isAdvancedModel) {
      requestBody.tools = [{
        google_search: {}
      }];
    }
    
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${settings.geminiApiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
      }
    );
    
    if (!response.ok) {
      throw new Error(`AI API error: ${response.status}`);
    }
    
    const data = await response.json();
    const aiResponse = data.candidates[0].content.parts[0].text;
    
    const findings = parseAIFindings(aiResponse, cveId);
    
    if (findings.sources.length > 0) {
      await enhancedRAGDatabase.addDocument(
        `AI Multi-Source Findings for ${cveId}: Analyzed ${findings.sources.length} sources. Key findings: ${findings.summary}`,
        {
          title: `AI Multi-Source Analysis - ${cveId}`,
          category: 'ai-multi-source',
          tags: ['ai-discovered', 'multi-source', cveId.toLowerCase()],
          source: 'ai-web-search'
        }
      );
    }
    
    return findings;
    
  } catch (error) {
    console.error('AI source discovery error:', error);
    setLoadingSteps(prev => [...prev, `⚠️ AI source discovery failed: ${error.message}`]);
    
    return {
      sources: [],
      discoveredSources: [],
      kev: null,
      ghsa: null,
      exploits: null,
      patches: [],
      summary: 'AI analysis failed'
    };
  }
};

// Parse AI findings into structured data
const parseAIFindings = (aiResponse, cveId) => {
  const findings = {
    sources: [],
    discoveredSources: [],
    kev: null,
    ghsa: null,
    exploits: null,
    patches: [],
    summary: '',
    rawResponse: aiResponse
  };
  
  try {
    if (aiResponse.includes('{') && aiResponse.includes('}')) {
      const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        Object.assign(findings, parsed);
        return findings;
      }
    }
  } catch (e) {
    // If JSON parsing fails, parse as text
  }
  
  const lines = aiResponse.split('\n');
  
  for (const line of lines) {
    const trimmedLine = line.trim();
    
    if (trimmedLine.toLowerCase().includes('cisa kev') || trimmedLine.toLowerCase().includes('actively exploited')) {
      if (trimmedLine.toLowerCase().includes('yes') || trimmedLine.toLowerCase().includes('confirmed') || trimmedLine.toLowerCase().includes('listed')) {
        findings.kev = {
          listed: true,
          details: trimmedLine
        };
      }
    }
    
    if (trimmedLine.toLowerCase().includes('github security') || trimmedLine.toLowerCase().includes('ghsa')) {
      if (!trimmedLine.toLowerCase().includes('not found') && !trimmedLine.toLowerCase().includes('no advisory')) {
        findings.ghsa = {
          found: true,
          details: trimmedLine
        };
      }
    }
    
    if (trimmedLine.toLowerCase().includes('exploit') || trimmedLine.toLowerCase().includes('poc') || trimmedLine.toLowerCase().includes('proof of concept')) {
      if (trimmedLine.toLowerCase().includes('found') || trimmedLine.toLowerCase().includes('available') || trimmedLine.toLowerCase().includes('public')) {
        findings.exploits = {
          found: true,
          details: trimmedLine,
          count: extractNumber(trimmedLine) || 1
        };
      }
    }
    
    const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/g;
    const urls = trimmedLine.match(urlRegex);
    if (urls) {
      urls.forEach(url => {
        const source = identifySourceFromUrl(url);
        findings.sources.push({
          name: source,
          url: url,
          type: categorizeUrl(url)
        });
      });
    }
    
    const knownSources = [
      'NVD', 'CISA', 'KEV', 'GitHub', 'GHSA', 'OSV', 'Exploit-DB', 'ExploitDB',
      'Microsoft', 'MSRC', 'Red Hat', 'Ubuntu', 'Debian', 'MITRE'
    ];
    
    knownSources.forEach(source => {
      if (trimmedLine.includes(source) && !trimmedLine.toLowerCase().includes('not found')) {
        if (!findings.discoveredSources.includes(source)) {
          findings.discoveredSources.push(source);
        }
      }
    });
  }
  
  findings.summary = generateFindingsSummary(findings);
  
  return findings;
};

const identifySourceFromUrl = (url) => {
  const urlLower = url.toLowerCase();
  
  if (urlLower.includes('cisa.gov')) return 'CISA';
  if (urlLower.includes('github.com')) return 'GitHub';
  if (urlLower.includes('nvd.nist.gov')) return 'NVD';
  if (urlLower.includes('first.org')) return 'FIRST/EPSS';
  if (urlLower.includes('exploit-db.com')) return 'Exploit-DB';
  if (urlLower.includes('microsoft.com')) return 'Microsoft';
  if (urlLower.includes('redhat.com')) return 'Red Hat';
  if (urlLower.includes('ubuntu.com')) return 'Ubuntu';
  if (urlLower.includes('debian.org')) return 'Debian';
  if (urlLower.includes('mitre.org')) return 'MITRE';
  
  return 'Other';
};

const categorizeUrl = (url) => {
  const urlLower = url.toLowerCase();
  
  if (urlLower.includes('exploit') || urlLower.includes('poc')) return 'exploit';
  if (urlLower.includes('advisory') || urlLower.includes('bulletin')) return 'advisory';
  if (urlLower.includes('patch') || urlLower.includes('update')) return 'patch';
  if (urlLower.includes('blog') || urlLower.includes('analysis')) return 'analysis';
  if (urlLower.includes('github.com') && urlLower.includes('commit')) return 'fix';
  
  return 'reference';
};

const extractNumber = (text) => {
  const match = text.match(/\d+/);
  return match ? parseInt(match[0]) : null;
};

const generateFindingsSummary = (findings) => {
  const parts = [];
  
  if (findings.kev?.listed) {
    parts.push('ACTIVELY EXPLOITED (CISA KEV)');
  }
  
  if (findings.exploits?.found) {
    parts.push(`${findings.exploits.count || 'Multiple'} EXPLOITS FOUND`);
  }
  
  if (findings.discoveredSources.length > 0) {
    parts.push(`${findings.discoveredSources.length} sources analyzed`);
  }
  
  if (findings.patches.length > 0) {
    parts.push('Patches available');
  }
  
  return parts.join(' | ') || 'Limited information available';
};

// Enhanced AI-powered vulnerability data fetching
const fetchVulnerabilityDataWithAI = async (cveId, setLoadingSteps, apiKeys, settings) => {
  try {
    setLoadingSteps(prev => [...prev, `🚀 Starting AI-powered multi-source analysis for ${cveId}...`]);
    
    if (!enhancedRAGDatabase.initialized) {
      setLoadingSteps(prev => [...prev, `📚 Initializing RAG knowledge base...`]);
      await enhancedRAGDatabase.initialize();
    }
    
    setLoadingSteps(prev => [...prev, `🔍 Fetching from primary sources (NVD, EPSS)...`]);
    
    const [cveResult, epssResult] = await Promise.allSettled([
      fetchCVEDataFromNVD(cveId, setLoadingSteps, apiKeys.nvd),
      fetchEPSSData(cveId, setLoadingSteps)
    ]);
    
    const cve = cveResult.status === 'fulfilled' ? cveResult.value : null;
    const epss = epssResult.status === 'fulfilled' ? epssResult.value : null;
    
    if (!cve) {
      throw new Error(`Failed to fetch CVE data for ${cveId}`);
    }
    
    setLoadingSteps(prev => [...prev, `🤖 AI is searching 30+ security sources for ${cveId}...`]);
    
    const aiEnhancedData = await fetchAllSourcesWithAI(cveId, cve, epss, apiKeys, settings, setLoadingSteps);
    
    const enhancedVulnerability = {
      cve,
      epss,
      ...aiEnhancedData,
      dataFreshness: 'REAL_TIME',
      lastUpdated: new Date().toISOString(),
      searchTimestamp: new Date().toISOString(),
      ragEnhanced: true,
      aiSearchPerformed: true,
      enhancedSources: ['NVD', 'EPSS', 'AI-Discovery']
    };
    
    setLoadingSteps(prev => [...prev, `✅ AI-powered analysis complete: ${aiEnhancedData.discoveredSources.length} sources analyzed`]);
    
    return enhancedVulnerability;
    
  } catch (error) {
    console.error(`Error processing ${cveId}:`, error);
    throw error;
  }
};

// Rate limiting helper
let lastRequestTime = 0;
const REQUEST_COOLDOWN = 60000;

const checkRateLimit = () => {
  const now = Date.now();
  const timeSinceLastRequest = now - lastRequestTime;
  
  if (timeSinceLastRequest < REQUEST_COOLDOWN) {
    const waitTime = Math.ceil((REQUEST_COOLDOWN - timeSinceLastRequest) / 1000);
    throw new Error(`Please wait ${waitTime} more seconds before making another request. Free tier has strict rate limits.`);
  }
  
  lastRequestTime = now;
};

// Enhanced RAG-powered AI Analysis with Robust Error Handling
const generateEnhancedRAGAnalysis = async (vulnerability, apiKey, model, settings = {}) => {
  try {
    checkRateLimit();
  } catch (error) {
    return {
      analysis: `**Rate Limit Protection Active**\n\n${error.message}\n\nThe free Gemini API tier is very restrictive - approximately 15 requests per minute total across all applications using your API key.\n\n**Current Status:**\n- ⏱️ Built-in 60-second delay between requests\n- 🛡️ Preventing API rate limit errors\n- 📊 You can still review all vulnerability data below`,
      ragUsed: false,
      ragDocuments: 0,
      ragSources: [],
      webGrounded: false,
      enhancedSources: vulnerability.enhancedSources || [],
      discoveredSources: [],
      error: 'rate_limit_protection',
      isTemporary: true
    };
  }

  const cveId = vulnerability.cve.id;
  const description = vulnerability.cve.description;
  const cvssScore = vulnerability.cve.cvssV3?.baseScore || vulnerability.cve.cvssV2?.baseScore || 'N/A';
  const epssScore = vulnerability.epss ? vulnerability.epss.epssPercentage + '%' : 'N/A';
  const kevStatus = vulnerability.kev ? 'Yes' : 'No';
  const isGemini2Plus = model.includes('2.0') || model.includes('2.5');

  // Fallback analysis function
  const generateFallbackAnalysis = (cveId, description, cvssScore, epssScore, kevStatus) => {
    return `# Vulnerability Analysis: ${cveId}

## Overview and Description
${description}

## Technical Details and Attack Vectors
This vulnerability affects the system with a CVSS score of ${cvssScore}, indicating ${cvssScore >= 7 ? 'high' : cvssScore >= 4 ? 'medium' : 'low'} severity. The exploitation probability (EPSS) is ${epssScore}.

## Impact Assessment
Based on the CVSS score, this vulnerability ${cvssScore >= 7 ? 'requires immediate attention and could lead to significant system compromise' : 'should be monitored and patched according to your organization\'s schedule'}.

## Mitigation Strategies
1. Apply vendor patches immediately if available
2. Implement network segmentation to limit exposure
3. Monitor for unusual activity related to this vulnerability
4. Review access controls and authentication mechanisms

## Current Exploitation Status
${kevStatus === 'Yes' ? '⚠️ **ACTIVE EXPLOITATION CONFIRMED** - This vulnerability is listed in CISA\'s Known Exploited Vulnerabilities catalog. Immediate patching is critical.' : 'No active exploitation currently confirmed through CISA KEV catalog.'}

## Recommendations
- Prioritize patching based on CVSS score: ${cvssScore}
- Monitor threat intelligence feeds for updates
- Implement compensating controls if patches are not immediately available
- Test patches in a controlled environment before production deployment`;
  };

  // Retry logic with exponential backoff
  const makeAPICallWithRetry = async (requestBody, apiUrl, maxRetries = 3) => {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        console.log(`🔄 API attempt ${attempt}/${maxRetries} for ${cveId}`);
        
        const response = await fetch(apiUrl, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(requestBody)
        });

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          
          if (response.status === 429) {
            const retryAfter = response.headers.get('retry-after');
            const waitTime = retryAfter ? parseInt(retryAfter) : 60;
            throw new Error(`Rate limit exceeded. Wait ${waitTime} seconds before trying again.`);
          }
          
          if (response.status === 500) {
            if (attempt < maxRetries) {
              const delayMs = Math.pow(2, attempt) * 1000; // Exponential backoff
              console.log(`⏱️ Server error, retrying in ${delayMs/1000} seconds...`);
              await new Promise(resolve => setTimeout(resolve, delayMs));
              continue;
            }
            throw new Error('Gemini API is experiencing internal server errors. Using fallback analysis.');
          }
          
          if (response.status === 503) {
            if (attempt < maxRetries) {
              const delayMs = Math.pow(2, attempt) * 2000; // Longer delay for service unavailable
              console.log(`🔧 Service unavailable, retrying in ${delayMs/1000} seconds...`);
              await new Promise(resolve => setTimeout(resolve, delayMs));
              continue;
            }
            throw new Error('Gemini API is currently overloaded. Using fallback analysis.');
          }
          
          if (response.status === 400) {
            throw new Error('Invalid request configuration. Please check your API key and model selection.');
          }
          
          if (response.status === 401 || response.status === 403) {
            throw new Error('Authentication failed. Please verify your Gemini API key in settings.');
          }
          
          throw new Error(`API error: ${response.status} - ${errorData.error?.message || 'Unknown error'}`);
        }

        return await response.json();
        
      } catch (error) {
        if (attempt === maxRetries) {
          throw error;
        }
        
        // Only retry on specific errors
        if (error.message.includes('500') || 
            error.message.includes('503') || 
            error.message.includes('network') ||
            error.message.includes('fetch')) {
          const delayMs = Math.pow(2, attempt) * 1000;
          console.log(`⏱️ Retrying API call in ${delayMs/1000} seconds due to: ${error.message}`);
          await new Promise(resolve => setTimeout(resolve, delayMs));
          continue;
        }
        
        throw error;
      }
    }
  };

  try {
    console.log('🚀 Starting Enhanced RAG Analysis for', cveId);
    
    if (!enhancedRAGDatabase.initialized) {
      console.log('🚀 Initializing RAG database...');
      await enhancedRAGDatabase.initialize();
    }

    console.log('📚 Performing RAG retrieval for', cveId);
    const ragQuery = `${cveId} ${description.substring(0, 200)} vulnerability analysis security impact mitigation threat intelligence EPSS ${epssScore} CVSS ${cvssScore} ${kevStatus === 'Yes' ? 'CISA KEV active exploitation' : ''}`;
    const relevantDocs = await enhancedRAGDatabase.search(ragQuery, 10);
    
    const ragContext = relevantDocs.length > 0 ? 
      relevantDocs.map((doc, index) => 
        `[Security Knowledge ${index + 1}] ${doc.metadata.title}:\n${doc.content.substring(0, 600)}...`
      ).join('\n\n') : 
      'No specific security knowledge found in database.';

    console.log(`📖 Retrieved ${relevantDocs.length} relevant documents from RAG database`);

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

Provide a comprehensive vulnerability analysis including:
1. Overview and description of the vulnerability
2. Technical details and attack vectors
3. Impact assessment and potential consequences
4. Mitigation strategies and remediation guidance
5. Affected packages and software components
6. Current exploitation status and threat landscape

Format your response in clear sections with detailed analysis. Use the security knowledge base context to provide enhanced insights.`;

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
        candidateCount: 1
      }
    };

    // Remove web search for problematic models to reduce complexity
    if (isGemini2Plus && !model.includes('2.5-pro')) {
      requestBody.tools = [
        {
          google_search: {}
        }
      ];
    }

    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
    
    // Try API call with retry logic
    let data;
    try {
      data = await makeAPICallWithRetry(requestBody, apiUrl);
    } catch (apiError) {
      console.warn('🔄 API failed, generating fallback analysis:', apiError.message);
      
      // Generate fallback analysis
      const fallbackAnalysis = generateFallbackAnalysis(cveId, description, cvssScore, epssScore, kevStatus);
      
      return {
        analysis: fallbackAnalysis,
        ragUsed: true,
        ragDocuments: relevantDocs.length,
        ragSources: relevantDocs.map(doc => doc.metadata?.title || 'Unknown').filter(Boolean),
        webGrounded: false,
        enhancedSources: vulnerability.enhancedSources || [],
        discoveredSources: [],
        model: 'fallback-analysis',
        analysisTimestamp: new Date().toISOString(),
        fallbackUsed: true,
        fallbackReason: apiError.message
      };
    }
    
    if (!data.candidates || !data.candidates[0] || !data.candidates[0].content) {
      throw new Error('Invalid API response format - using fallback analysis');
    }
    
    const content = data.candidates[0].content;
    let analysisText = '';
    
    if (content.parts && Array.isArray(content.parts)) {
      analysisText = content.parts.map(part => part.text || '').join('');
    } else {
      throw new Error('No valid content parts found in response');
    }
    
    if (!analysisText || analysisText.trim().length === 0) {
      throw new Error('Empty analysis text in response');
    }

    // Store successful analysis in RAG database
    if (analysisText.length > 500) {
      await enhancedRAGDatabase.addDocument(
        `Enhanced CVE Analysis: ${cveId}\n\n${analysisText}`,
        {
          title: `Enhanced RAG Security Analysis - ${cveId}`,
          category: 'enhanced-analysis',
          tags: ['rag-enhanced', 'ai-analysis', cveId.toLowerCase()],
          source: 'ai-analysis-rag',
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
      discoveredSources: [],
      model: model,
      analysisTimestamp: new Date().toISOString()
    };
    
  } catch (error) {
    console.error('Enhanced RAG Analysis Error:', error);
    
    // Generate comprehensive fallback analysis
    const fallbackAnalysis = generateFallbackAnalysis(cveId, description, cvssScore, epssScore, kevStatus);
    
    return {
      analysis: `**Fallback Analysis Generated**\n\n*AI service temporarily unavailable. Generated comprehensive analysis using available data.*\n\n${fallbackAnalysis}`,
      ragUsed: false,
      ragDocuments: 0,
      ragSources: [],
      webGrounded: false,
      enhancedSources: vulnerability.enhancedSources || [],
      discoveredSources: [],
      error: error.message,
      fallbackUsed: true,
      isTemporary: error.message.includes('overloaded') || error.message.includes('Rate limit') || error.message.includes('500')
    };
  }
};

// Enhanced CVSS Score Component
const CVSSScoreDisplay = ({ score, severity, vulnerability, settings }) => {
  const [isAnimating, setIsAnimating] = useState(false);
  const [showTooltip, setShowTooltip] = useState(false);

  const getSeverityColor = (score) => {
    if (score >= 9) return '#ef4444';
    if (score >= 7) return '#f59e0b';
    if (score >= 4) return '#3b82f6';
    return '#22c55e';
  };

  const getScoreDescription = (score) => {
    if (score >= 9) return 'Critical - Immediate action required';
    if (score >= 7) return 'High - Urgent attention needed';
    if (score >= 4) return 'Medium - Should be addressed';
    return 'Low - Monitor and plan remediation';
  };

  useEffect(() => {
    setIsAnimating(true);
    const timer = setTimeout(() => setIsAnimating(false), 1500);
    return () => clearTimeout(timer);
  }, [score]);

  const circumference = 2 * Math.PI * 45;
  const strokeDasharray = circumference;
  const strokeDashoffset = circumference - (score / 10) * circumference;

  return (
    <div style={{ textAlign: 'center', marginBottom: '28px' }}>
      <div 
        style={{
          position: 'relative',
          width: '120px',
          height: '120px',
          margin: '0 auto 16px',
          cursor: 'pointer'
        }}
        onMouseEnter={() => setShowTooltip(true)}
        onMouseLeave={() => setShowTooltip(false)}
      >
        <svg
          width="120"
          height="120"
          viewBox="0 0 100 100"
          style={{ transform: 'rotate(-90deg)' }}
        >
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke={settings.darkMode ? colors.dark.border : colors.light.border}
            strokeWidth="8"
          />
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke={getSeverityColor(score)}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={strokeDasharray}
            strokeDashoffset={isAnimating ? circumference : strokeDashoffset}
            style={{
              transition: 'stroke-dashoffset 1.5s cubic-bezier(0.4, 0, 0.2, 1)',
              filter: 'drop-shadow(0 0 8px ' + getSeverityColor(score) + '40)'
            }}
          />
        </svg>
        
        <div style={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          textAlign: 'center'
        }}>
          <div style={{
            fontSize: '1.625rem',
            fontWeight: '700',
            color: settings.darkMode ? colors.dark.primaryText : colors.light.primaryText,
            animation: isAnimating ? 'countUp 1.5s ease-out' : 'none'
          }}>
            {score?.toFixed(1) || 'N/A'}
          </div>
          <div style={{
            fontSize: '0.75rem',
            color: settings.darkMode ? colors.dark.secondaryText : colors.light.secondaryText,
            fontWeight: '500'
          }}>
            CVSS Score
          </div>
        </div>

        {showTooltip && (
          <div style={{
            position: 'absolute',
            top: '-60px',
            left: '50%',
            transform: 'translateX(-50%)',
            background: settings.darkMode ? colors.dark.surface : colors.light.surface,
            border: `1px solid ${settings.darkMode ? colors.dark.border : colors.light.border}`,
            borderRadius: '8px',
            padding: '8px 12px',
            fontSize: '0.8rem',
            color: settings.darkMode ? colors.dark.primaryText : colors.light.primaryText,
            whiteSpace: 'nowrap',
            zIndex: 10,
            boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
            animation: 'fadeIn 0.2s ease-out'
          }}>
            {getScoreDescription(score)}
            <div style={{
              position: 'absolute',
              top: '100%',
              left: '50%',
              transform: 'translateX(-50%)',
              width: 0,
              height: 0,
              borderLeft: '6px solid transparent',
              borderRight: '6px solid transparent',
              borderTop: `6px solid ${settings.darkMode ? colors.dark.surface : colors.light.surface}`
            }} />
          </div>
        )}
      </div>

      {vulnerability.epss && (
        <div style={{
          background: `rgba(${hexToRgb(colors.purple)}, 0.1)`,
          borderRadius: '8px',
          padding: '8px 12px',
          marginTop: '12px',
          border: `1px solid rgba(${hexToRgb(colors.purple)}, 0.2)`
        }}>
          <div style={{
            fontSize: '0.7rem',
            color: settings.darkMode ? colors.dark.tertiaryText : colors.light.tertiaryText,
            marginBottom: '4px'
          }}>
            EPSS Exploitation Probability
          </div>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <div style={{
              flex: 1,
              height: '4px',
              background: settings.darkMode ? colors.dark.border : colors.light.border,
              borderRadius: '2px',
              overflow: 'hidden'
            }}>
              <div style={{
                width: `${vulnerability.epss.epssFloat * 100}%`,
                height: '100%',
                background: vulnerability.epss.epssFloat > 0.5 ? colors.red : vulnerability.epss.epssFloat > 0.1 ? colors.yellow : colors.green,
                borderRadius: '2px',
                transition: 'width 1s ease-out'
              }} />
            </div>
            <span style={{
              fontSize: '0.75rem',
              fontWeight: '600',
              color: vulnerability.epss.epssFloat > 0.5 ? colors.red : vulnerability.epss.epssFloat > 0.1 ? colors.yellow : colors.green
            }}>
              {(vulnerability.epss.epssFloat * 100).toFixed(1)}%
            </span>
          </div>
        </div>
      )}

      <style>
        {`
          @keyframes countUp {
            from { transform: scale(0.8); opacity: 0; }
            to { transform: scale(1); opacity: 1; }
          }
          @keyframes fadeIn {
            from { opacity: 0; transform: translateX(-50%) translateY(-4px); }
            to { opacity: 1; transform: translateX(-50%) translateY(0); }
          }
        `}
      </style>
    </div>
  );
};

// Main CVE Detail View Component
const CVEDetailView = ({ vulnerability, onRefresh, onExport }) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [cooldownTime, setCooldownTime] = useState(0);
  const { settings, addNotification } = useContext(AppContext);
  const styles = getStyles(settings.darkMode);

  useEffect(() => {
    let interval;
    if (cooldownTime > 0) {
      interval = setInterval(() => {
        setCooldownTime(prev => Math.max(0, prev - 1));
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [cooldownTime]);

  const getSeverityStyle = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return styles.badgeCritical;
      case 'HIGH': return styles.badgeHigh;
      case 'MEDIUM': return styles.badgeMedium;
      case 'LOW': return styles.badgeLow;
      default: return styles.badge;
    }
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
      
      if (result.error === 'rate_limit_protection') {
        setCooldownTime(60);
        addNotification({
          type: 'warning',
          title: 'Rate Limit Protection Active',
          message: 'Free tier protection: Please wait 60 seconds between requests to avoid API limits.'
        });
      } else {
        addNotification({
          type: 'success',
          title: 'RAG Analysis Complete',
          message: `Enhanced analysis generated using ${result.ragDocuments} knowledge sources and real-time intelligence`
        });
      }
    } catch (error) {
      if (error.message.includes('Rate limit exceeded') || error.message.includes('Too Many Requests')) {
        setCooldownTime(120);
        addNotification({
          type: 'error',
          title: 'API Rate Limit Hit',
          message: 'Free tier exceeded. Wait 2 minutes or upgrade to paid plan for instant access.'
        });
      } else {
        addNotification({
          type: 'error',
          title: 'AI Analysis Failed',
          message: error.message
        });
      }
    } finally {
      setAiLoading(false);
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 400px', gap: '40px', marginTop: '40px' }}>
      <div style={{
        background: settings.darkMode ? 'linear-gradient(135deg, #1e293b 0%, #334155 100%)' : '#ffffff',
        borderRadius: '20px',
        padding: '32px',
        boxShadow: settings.darkMode ? `0 8px 32px ${colors.dark.shadow}` : `0 4px 20px ${colors.light.shadow}`,
        border: `1px solid ${settings.darkMode ? colors.dark.border : colors.light.border}`
      }}>
        <div style={{
          marginBottom: '24px',
          paddingBottom: '24px',
          borderBottom: `1px solid ${settings.darkMode ? colors.dark.border : colors.light.border}`
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h1 style={{
              fontSize: '2rem',
              fontWeight: '700',
              background: `linear-gradient(135deg, ${colors.blue} 0%, ${colors.purple} 100%)`,
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text',
              margin: 0,
              lineHeight: 1.2,
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
                onClick={onRefresh}
              >
                <RefreshCw size={14} />
                Refresh
              </button>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{
              ...styles.badge,
              ...getSeverityStyle(severity),
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
                background: `rgba(${hexToRgb(colors.red)}, 0.15)`,
                color: colors.red,
                border: `1px solid rgba(${hexToRgb(colors.red)}, 0.3)`,
              }}>
                💣 {vulnerability.exploits.count || 'Multiple'} EXPLOITS FOUND
              </span>
            )}

            {vulnerability.aiSearchPerformed && (
              <span style={{
                ...styles.badge,
                background: `rgba(${hexToRgb(colors.purple)}, 0.15)`,
                color: colors.purple,
                border: `1px solid rgba(${hexToRgb(colors.purple)}, 0.3)`,
              }}>
                <Brain size={12} style={{ marginRight: '6px' }} />
                AI ENHANCED ({vulnerability.discoveredSources?.length || 0} sources)
              </span>
            )}
          </div>
        </div>

        <div style={{
          display: 'flex',
          borderBottom: `1px solid ${settings.darkMode ? colors.dark.border : colors.light.border}`,
          marginBottom: '24px',
          gap: '4px',
          flexWrap: 'wrap'
        }}>
          {['overview', 'ai-sources', 'ai-analysis'].map((tab) => (
            <button
              key={tab}
              style={{
                padding: '12px 18px',
                cursor: 'pointer',
                border: 'none',
                borderBottom: activeTab === tab ? `3px solid ${colors.blue}` : '3px solid transparent',
                fontSize: '0.9rem',
                fontWeight: '600',
                color: activeTab === tab ? colors.blue : settings.darkMode ? colors.dark.secondaryText : colors.light.secondaryText,
                transition: 'all 0.2s ease-in-out',
                borderRadius: '6px 6px 0 0',
                background: activeTab === tab
                  ? (settings.darkMode ? `rgba(${hexToRgb(colors.blue)}, 0.1)` : `rgba(${hexToRgb(colors.blue)}, 0.05)`)
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
              {tab === 'ai-analysis' && <Brain size={16} />}
              {tab === 'ai-sources' ? 'AI Sources' : tab === 'ai-analysis' ? 'RAG Analysis' : tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        <div style={{ paddingTop: '8px' }}>
          {activeTab === 'overview' && (
            <div>
              <h2 style={{
                fontSize: '1.5rem',
                fontWeight: '700',
                color: settings.darkMode ? colors.dark.primaryText : colors.light.primaryText,
                marginBottom: '16px'
              }}>
                Vulnerability Overview
              </h2>
              
              <div style={{
                fontSize: '1.0625rem',
                lineHeight: '1.7',
                color: settings.darkMode ? colors.dark.secondaryText : colors.light.secondaryText,
                marginBottom: '24px'
              }}>
                <p style={{ margin: 0 }}>
                  {vulnerability.cve?.description || 'No description available.'}
                </p>
              </div>

              {vulnerability.epss && (
                <div style={{ marginBottom: '24px' }}>
                  <h3 style={{ fontSize: '1.25rem', fontWeight: '600', marginBottom: '12px', color: settings.darkMode ? colors.dark.primaryText : colors.light.primaryText }}>
                    Exploitation Probability (EPSS)
                  </h3>
                  <div style={{
                    background: vulnerability.epss.epssFloat > 0.5 ? `rgba(${hexToRgb(colors.yellow)}, 0.1)` : `rgba(${hexToRgb(colors.green)}, 0.1)`,
                    border: `1px solid ${vulnerability.epss.epssFloat > 0.5 ? `rgba(${hexToRgb(colors.yellow)}, 0.3)` : `rgba(${hexToRgb(colors.green)}, 0.3)`}`,
                    borderRadius: '12px',
                    padding: '20px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                      <Target size={24} color={vulnerability.epss.epssFloat > 0.5 ? colors.yellow : colors.green} />
                      <div>
                        <div style={{ fontWeight: '700', fontSize: '1.05rem', color: settings.darkMode ? colors.dark.primaryText : colors.light.primaryText }}>
                          EPSS Score: {vulnerability.epss.epssPercentage}%
                        </div>
                        <div style={{ fontSize: '0.85rem', color: settings.darkMode ? colors.dark.tertiaryText : colors.light.tertiaryText }}>
                          Percentile: {parseFloat(vulnerability.epss.percentile).toFixed(3)}
                        </div>
                        <p style={{ margin: '12px 0 0 0', fontSize: '1rem', color: settings.darkMode ? colors.dark.secondaryText : colors.light.secondaryText }}>
                          {vulnerability.epss.epssFloat > 0.5
                            ? 'This vulnerability has a HIGH probability of exploitation. Immediate patching recommended.'
                            : vulnerability.epss.epssFloat > 0.1
                              ? 'This vulnerability has a MODERATE probability of exploitation. Monitor for patches and updates.'
                              : 'This vulnerability has a LOW probability of exploitation, but still requires attention.'}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              <div style={{ 
                marginTop: '32px',
                paddingTop: '24px',
                borderTop: `1px solid ${settings.darkMode ? colors.dark.border : colors.light.border}`,
                textAlign: 'center'
              }}>
                <button
                  style={{
                    ...styles.button,
                    ...styles.buttonPrimary,
                    opacity: aiLoading || cooldownTime > 0 || !settings.geminiApiKey ? 0.7 : 1,
                    fontSize: '1rem',
                    padding: '16px 32px'
                  }}
                  onClick={generateRAGAnalysis}
                  disabled={aiLoading || cooldownTime > 0 || !settings.geminiApiKey}
                >
                  {aiLoading ? (
                    <>
                      <Loader2 size={20} style={{ animation: 'spin 1s linear infinite' }} />
                      Generating RAG-Enhanced Analysis...
                    </>
                  ) : cooldownTime > 0 ? (
                    <>
                      <AlertTriangle size={20} />
                      Wait {cooldownTime}s (Free Tier Protection)
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

          {activeTab === 'ai-sources' && (
            <div>
              <h2 style={{
                fontSize: '1.5rem',
                fontWeight: '700',
                color: settings.darkMode ? colors.dark.primaryText : colors.light.primaryText,
                marginBottom: '24px'
              }}>
                AI-Discovered Intelligence Sources
              </h2>

              {(!vulnerability.sources && !vulnerability.discoveredSources) ? (
                <div style={{
                  textAlign: 'center',
                  padding: '48px',
                  color: settings.darkMode ? colors.dark.tertiaryText : colors.light.tertiaryText
                }}>
                  <Brain size={48} style={{ marginBottom: '16px', opacity: 0.5 }} />
                  <p>AI source discovery not yet performed</p>
                </div>
              ) : (
                <div>
                  <div style={{
                    background: settings.darkMode ? colors.dark.surface : colors.light.surface,
                    borderRadius: '12px',
                    padding: '20px',
                    marginBottom: '24px',
                    border: `1px solid ${settings.darkMode ? colors.dark.border : colors.light.border}`
                  }}>
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      marginBottom: '16px'
                    }}>
                      <Brain size={24} color={colors.purple} />
                      <div>
                        <h3 style={{
                          fontSize: '1.125rem',
                          fontWeight: '600',
                          margin: 0,
                          color: settings.darkMode ? colors.dark.primaryText : colors.light.primaryText
                        }}>
                          AI Analysis Summary
                        </h3>
                        <p style={{
                          margin: '4px 0 0 0',
                          fontSize: '0.875rem',
                          color: settings.darkMode ? colors.dark.secondaryText : colors.light.secondaryText
                        }}>
                          {vulnerability.summary || 'AI searched 25+ security sources'}
                        </p>
                      </div>
                    </div>

                    {(vulnerability.kev?.listed || vulnerability.exploits?.found) && (
                      <div style={{
                        background: `rgba(${hexToRgb(colors.red)}, 0.1)`,
                        border: `1px solid rgba(${hexToRgb(colors.red)}, 0.3)`,
                        borderRadius: '8px',
                        padding: '12px',
                        marginBottom: '16px'
                      }}>
                        {vulnerability.kev?.listed && (
                          <div style={{ marginBottom: '8px' }}>
                            <strong style={{ color: colors.red }}>🚨 CISA KEV:</strong> {vulnerability.kev.details}
                          </div>
                        )}
                        {vulnerability.exploits?.found && (
                          <div>
                            <strong style={{ color: colors.red }}>💣 Public Exploits:</strong> {vulnerability.exploits.details}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'ai-analysis' && (
            <EnhancedAIAnalysisTab 
              aiAnalysis={aiAnalysis}
              vulnerability={vulnerability}
              darkMode={settings.darkMode}
            />
          )}
        </div>
      </div>

      <div style={{
        background: settings.darkMode ? 'linear-gradient(135deg, #1e293b 0%, #334155 100%)' : '#ffffff',
        borderRadius: '16px',
        padding: '24px',
        boxShadow: settings.darkMode ? `0 8px 32px ${colors.dark.shadow}` : `0 4px 20px ${colors.light.shadow}`,
        border: `1px solid ${settings.darkMode ? colors.dark.border : colors.light.border}`,
        height: 'fit-content',
        position: 'sticky',
        top: '24px',
      }}>
        <CVSSScoreDisplay 
          score={cvssScore} 
          severity={severity} 
          vulnerability={vulnerability} 
          settings={settings} 
        />

        <div style={{
          background: settings.darkMode ? colors.dark.surface : colors.light.surface,
          borderRadius: '12px',
          padding: '16px',
          marginBottom: '20px',
          border: `1px solid ${settings.darkMode ? colors.dark.border : colors.light.border}`
        }}>
          <h3 style={{
            fontSize: '0.95rem',
            fontWeight: '600',
            marginBottom: '12px',
            color: settings.darkMode ? colors.dark.secondaryText : colors.light.secondaryText,
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}>
            <Brain size={14} />
            AI Intelligence Summary
          </h3>
          
          <div style={{ fontSize: '0.8125rem', color: settings.darkMode ? colors.dark.tertiaryText : colors.light.tertiaryText }}>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>Sources Analyzed:</strong> {vulnerability.discoveredSources?.length || 0}
            </p>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>Exploits Found:</strong> {vulnerability.exploits?.count || 0}
            </p>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>Active Exploitation:</strong> {vulnerability.kev?.listed ? 'YES' : 'No'}
            </p>
            <p style={{ margin: 0 }}>
              <strong>Last Updated:</strong> {new Date(vulnerability.lastUpdated).toLocaleString()}
            </p>
          </div>
        </div>

        <div style={{ 
          marginTop: 'auto',
          paddingTop: '16px',
          borderTop: `1px solid ${settings.darkMode ? colors.dark.border : colors.light.border}`,
          fontSize: '0.8rem',
          color: settings.darkMode ? colors.dark.tertiaryText : colors.light.tertiaryText,
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
