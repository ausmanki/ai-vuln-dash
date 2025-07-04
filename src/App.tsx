import React, { useState, createContext, useContext, useEffect, useCallback, useMemo } from 'react';
import { 
  Search, Brain, Settings, Target, Database, Activity, CheckCircle, XCircle, X, 
  Eye, EyeOff, Save, Globe, AlertTriangle, Loader2, RefreshCw, Copy, Clock, 
  ChevronRight, Info, Package, BarChart3, Zap, Shield, Code, Network, Server, MessageSquare, UploadCloud // Added MessageSquare and UploadCloud
} from 'lucide-react';
import { CONSTANTS, COLORS } from './utils/constants';
import { utils } from './utils/helpers';
import { createStyles } from './utils/styles';
import NotificationManager from './components/NotificationManager';
import SettingsModal from './components/SettingsModal';
import SearchComponent from './components/SearchComponent';
import LoadingComponent from './components/LoadingComponent';
import CVEDetailView from './components/CVEDetailView';
import EmptyState from './components/EmptyState';
import ChatInterface from './components/ChatInterface';
import BulkUploadComponent from './components/BulkUploadComponent'; // Added
import ErrorBoundary from './components/ErrorBoundary'; // Added ErrorBoundary
// import { AppContext } from './contexts/AppContext'; // Will be imported from AppContext.ts
import { useNotifications } from './hooks/useNotifications';
import { useSettings } from './hooks/useSettings';
import { ragDatabase } from './db/EnhancedVectorDatabase';
import { AppContext } from './contexts/AppContext'; // Corrected import
import { APIService } from './services/APIService'; // Added for bulk analysis

// Main Application Component - Renamed from VulnerabilityIntelligence to App for main.jsx
const App = () => {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadingSteps, setLoadingSteps] = useState([]);
  const [showSettings, setShowSettings] = useState(false);
  const [showChat, setShowChat] = useState(false); // Added state for chat visibility
  const [showBulkUploadView, setShowBulkUploadView] = useState(false); // State for bulk upload UI
  
  // State for bulk analysis
  const [bulkAnalysisResults, setBulkAnalysisResults] = useState<Array<{cveId: string, data?: any, error?: string}>>([]);
  const [isBulkLoading, setIsBulkLoading] = useState<boolean>(false);
  const [bulkProgress, setBulkProgress] = useState<{ current: number, total: number } | null>(null);

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

  const startBulkAnalysis = async (cveIds: string[]) => {
    if (isBulkLoading) return;

    const delayMs = 1500; // throttle to avoid hitting API rate limits

    setIsBulkLoading(true);
    setBulkAnalysisResults([]);
    setBulkProgress({ current: 0, total: cveIds.length });
    addNotification({ type: 'info', title: 'Bulk Analysis Started', message: `Analyzing ${cveIds.length} CVEs...` });

    const results: Array<{cveId: string, data?: any, error?: string}> = [];
    for (let i = 0; i < cveIds.length; i++) {
      const cveId = cveIds[i];
      setBulkProgress({ current: i + 1, total: cveIds.length });
      try {
        // Pass necessary API keys from settings; APIService.fetchVulnerabilityDataWithAI expects them.
        // The setLoadingSteps can be a dummy function for bulk mode or could update a more detailed log.
        const result = await APIService.fetchVulnerabilityDataWithAI(cveId, () => {}, { nvd: settings.nvdApiKey }, settings);
        results.push({ cveId, data: result });
      } catch (error: any) {
        console.error(`Error analyzing ${cveId} in bulk:`, error);
        results.push({ cveId, error: error.message || 'Unknown error during analysis' });
      }
      // Update results incrementally or all at once at the end.
      // For now, updating incrementally to show progress.
      setBulkAnalysisResults([...results]);

      await utils.sleep(delayMs);
    }

    setIsBulkLoading(false);
    setBulkProgress(null);
    addNotification({ type: 'success', title: 'Bulk Analysis Complete', message: `Finished analyzing ${cveIds.length} CVEs.` });
  };

  return (
    <AppContext.Provider value={contextValue}>
      <ErrorBoundary>
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
              <button
                onClick={() => {
                  setShowBulkUploadView(prev => !prev);
                  if (showChat) setShowChat(false); // Close chat if open
                }}
                style={{ ...styles.button, ...styles.buttonSecondary }}
                title="Bulk CVE Analysis"
              >
                <UploadCloud size={18} />
                Bulk Analyze
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
          {/* ChatInterface will be rendered conditionally elsewhere */}
        </main>

        <SettingsModal
          isOpen={showSettings}
          onClose={() => setShowSettings(false)}
        />

        {/* Chat Toggle Button */}
        <button
          onClick={() => setShowChat(prev => !prev)}
          style={{ // Ensure this button itself is styled by styles.button if possible or has consistent styling
            position: 'fixed',
            bottom: '32px',
            right: '32px',
            background: `linear-gradient(135deg, ${COLORS.blue} 0%, #1d4ed8 100%)`,
            color: 'white',
            border: 'none',
            borderRadius: '50%',
            width: '64px',
            height: '64px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: `0 4px 12px rgba(${utils.hexToRgb(COLORS.blue)}, 0.4)`,
            cursor: 'pointer',
            zIndex: 1000, // Ensure it's above other content
          }}
          aria-label={showChat ? "Close Chat" : "Open Chat"}
        >
          {showChat ? <X size={32} /> : <MessageSquare size={32} />}
        </button>

        {/* Conditionally Render ChatInterface as a side panel */}
        {showChat && (
          <div
            style={{
              position: 'fixed',
              top: 0,
              right: 0,
              height: '100vh',
              width: '420px',
              maxWidth: '100%',
              zIndex: 999, // Below the toggle button so it's still clickable
              boxShadow: `0 0 24px rgba(${utils.hexToRgb(COLORS.dark.shadow)}, 0.3)`,
              borderLeft: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`,
              overflow: 'hidden',
              background: styles.card.background,
            }}
          >
            <ChatInterface
              initialCveId={vulnerabilities[0]?.cve?.id || null}
              bulkAnalysisResults={bulkAnalysisResults}
            />
          </div>
        )}

        {/* Conditionally Render BulkUploadComponent */}
        {showBulkUploadView && (
          <BulkUploadComponent
            onClose={() => setShowBulkUploadView(false)}
            startBulkAnalysis={startBulkAnalysis}
            bulkAnalysisResults={bulkAnalysisResults}
            isBulkLoading={isBulkLoading}
            bulkProgress={bulkProgress}
          />
        )}
      </div>
    </ErrorBoundary>
    </AppContext.Provider>
  );
};

export default App;
