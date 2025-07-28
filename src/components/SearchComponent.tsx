import React, { useState, useCallback, useContext, useMemo } from 'react';
import { Search, Brain, Loader2 } from 'lucide-react';
import { AppContext } from '../contexts/AppContext';
import { APIService } from '../services/APIService';
import { setGlobalAISettings } from '../services/DataFetchingService';
import { utils } from '../utils/helpers';
import { createStyles } from '../utils/styles';
import { COLORS } from '../utils/constants';

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

    // Initialize AI settings for web search fallbacks
    if (settings.aiProvider) {
      setGlobalAISettings({
        aiProvider: settings.aiProvider,
        geminiModel: settings.geminiModel || 'gemini-2.5-flash',
        openAiModel: settings.openAiModel || 'gpt-4.1'
      });
      console.log('🤖 AI settings initialized for web search fallbacks');
    } else {
      console.warn('⚠️ No AI provider configured - AI web search fallbacks will not be available');
    }

    // Initialize loading state and steps
    setLoading(true);
    setLoadingSteps(['🔍 Starting AI-enhanced vulnerability analysis...']);
    setVulnerabilities([]); // Clear previous results

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

      // Enhanced completion message with AI attribution
      const aiEnhancedSources = vulnerability.discoveredSources?.length || 0;
      const isAIEnhanced = vulnerability.aiSearchPerformed || vulnerability.ragEnhanced;
      
      setLoadingSteps(prev => [...prev, '✅ Analysis complete!']);

      addNotification({
        type: 'success',
        title: 'AI Analysis Complete',
        message: `Successfully analyzed ${cveId} with ${aiEnhancedSources} sources${isAIEnhanced ? ' (AI-enhanced)' : ''}`
      });

    } catch (error: any) {
      console.error('Search failed:', error);
      
      setLoadingSteps(prev => [...prev, `❌ Error: ${error.message}`]);
      
      addNotification({
        type: 'error',
        title: 'Search Failed',
        message: error.message || 'An error occurred while searching'
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

  // Handle clicking on search history items
  const handleHistoryClick = useCallback((cve) => {
    setSearchTerm(cve);
    // Optionally auto-search when clicking history
    // handleSearch();
  }, []);

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
              opacity: loading || !searchTerm.trim() ? 0.6 : 1,
              minWidth: '120px'
            }}
          >
            {loading ? (
              <>
                <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} />
                Analyzing...
              </>
            ) : (
              <>
                <Brain size={18} />
                AI Analyze
              </>
            )}
          </button>
        </div>

        {/* Search History */}
        {searchHistory.length > 0 && (
          <div style={{ 
            display: 'flex', 
            gap: '10px', 
            justifyContent: 'center', 
            flexWrap: 'wrap',
            alignItems: 'center'
          }}>
            <span style={{
              fontSize: '0.875rem',
              color: settings.darkMode ? COLORS.dark.primaryText : COLORS.light.primaryText,
              fontWeight: '500'
            }}>
              Recent:
            </span>
            {searchHistory.map((cve, index) => (
              <button
                key={index}
                onClick={() => handleHistoryClick(cve)}
                disabled={loading}
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
                  opacity: loading ? 0.5 : 1,
                  cursor: loading ? 'not-allowed' : 'pointer',
                  transition: 'all 0.2s ease-in-out'
                }}
              >
                {cve}
              </button>
            ))}
          </div>
        )}

        {/* AI Status Indicator */}
        {settings.aiProvider === 'gemini' && (
          <div style={{
            marginTop: '24px',
            padding: '12px 16px',
            background: `rgba(${utils.hexToRgb(COLORS.green)}, 0.1)`,
            borderRadius: '8px',
            border: `1px solid rgba(${utils.hexToRgb(COLORS.green)}, 0.2)`,
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '0.875rem',
            color: COLORS.green,
            fontWeight: '500'
          }}>
            <Brain size={16} />
            AI Web Search Enabled - CORS Bypass Active
          </div>
        )}

        {settings.aiProvider === 'openai' && (
          <div style={{
            marginTop: '24px',
            padding: '12px 16px',
            background: `rgba(${utils.hexToRgb(COLORS.green)}, 0.1)`,
            borderRadius: '8px',
            border: `1px solid rgba(${utils.hexToRgb(COLORS.green)}, 0.2)`,
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '0.875rem',
            color: COLORS.green,
            fontWeight: '500'
          }}>
            <Brain size={16} />
            OpenAI Analysis Mode - Web Search
          </div>
        )}

        {!settings.aiProvider && (
          <div style={{
            marginTop: '24px',
            padding: '12px 16px',
            background: `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)`,
            borderRadius: '8px',
            border: `1px solid rgba(${utils.hexToRgb(COLORS.yellow)}, 0.2)`,
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '0.875rem',
            color: COLORS.yellow,
            fontWeight: '500'
          }}>
            ⚠️ Configure Gemini or OpenAI API Key for AI Features
          </div>
        )}
      </div>
    </div>
  );
};

export default SearchComponent;
