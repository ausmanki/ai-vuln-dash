import React, { useState, useCallback, useContext, useMemo } from 'react';
import { Search, Brain, Loader2 } from 'lucide-react';
import { AppContext } from '../contexts/AppContext';
import { APIService } from '../services/APIService';
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

export default SearchComponent;
