import React, { useState, createContext, useContext, useEffect, useCallback, useMemo } from 'react';
import { 
  Search, Brain, Settings, Target, Database, Activity, CheckCircle, XCircle, X, 
  Eye, EyeOff, Save, Globe, AlertTriangle, Loader2, RefreshCw, Copy, Clock, 
  ChevronRight, Info, Package, BarChart3, Zap, Shield, Code, Network, Server, MessageSquare // Added MessageSquare
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
  const [showChat, setShowChat] = useState(false); // Added state for chat visibility
  
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

        {/* Conditionally Render ChatInterface */}
        {showChat && (
          <div style={{
            position: 'fixed',
            bottom: '112px', // Above the toggle button
            right: '32px',
            width: '400px', // Adjust as needed
            height: '60vh', // Adjust as needed
            maxHeight: '700px',
            zIndex: 999, // Below the toggle button if it needs to overlap, or manage carefully
            boxShadow: `0 8px 24px rgba(${utils.hexToRgb(COLORS.dark.shadow)}, 0.3)`, // Consistent shadow
            borderRadius: '12px', // Consistent with cards
            overflow: 'hidden', // To ensure ChatInterface respects border radius
            // Background will be handled by ChatInterface itself via styles.card.background
          }}>
            <ChatInterface />
          </div>
        )}
      </div>
    </AppContext.Provider>
  );
};

export default App;
