import React, { useState, createContext, useContext, useEffect, useCallback, useMemo } from 'react';
import { 
  Search, Brain, Settings, Target, Database, Activity, CheckCircle, XCircle, X, 
  Eye, EyeOff, Save, Globe, AlertTriangle, Loader2, RefreshCw, Copy, Clock, 
  ChevronRight, Info, Package, BarChart3, Zap, Shield, Code, Network, Server 
} from 'lucide-react';
import { CONSTANTS, COLORS } from './utils/constants';
import { utils } from './utils/helpers';
import { createStyles } from './utils/styles';
import NotificationManager from './components/NotificationManager';
import SettingsModal from './components/SettingsModal';
import SearchComponent from './components/SearchComponent'; // Will be removed
import LoadingComponent from './components/LoadingComponent'; // May not be needed directly if chat has its own
import CVEDetailView from './components/CVEDetailView'; // Will be removed
import EmptyState from './components/EmptyState'; // May not be needed if chat is primary
import ChatInterface from './components/ChatInterface'; // Added
// import { AppContext } from './contexts/AppContext'; // Will be imported from AppContext.ts
import { useNotifications } from './hooks/useNotifications';
import { useSettings } from './hooks/useSettings';
import { ragDatabase } from './db/EnhancedVectorDatabase';
import { AppContext } from './contexts/AppContext'; // Corrected import

// Main Application Component - Renamed from VulnerabilityIntelligence to App for main.jsx
const App = () => {
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

        <main style={{ paddingTop: '20px' }}> {/* Added some padding */}
          {/* The SearchComponent and CVEDetailView are replaced by ChatInterface */}
          {/* The loading, empty states are now managed within or by ChatInterface itself */}
          <ChatInterface />
        </main>

        <SettingsModal
          isOpen={showSettings}
          onClose={() => setShowSettings(false)}
        />
      </div>
    </AppContext.Provider>
  );
};

export default App;
