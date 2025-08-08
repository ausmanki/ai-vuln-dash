import React, { useContext } from 'react';
import { AppContext } from '../contexts/AppContext';
import { COLORS } from '../utils/constants';
import { APIService } from '../services/APIService';

const SearchResults = () => {
  const { searchResults, setSearchResults, setVulnerabilities, setLoading, setLoadingSteps, addNotification, settings } = useContext(AppContext);

  if (!searchResults || searchResults.length === 0) {
    return null;
  }

  const handleResultClick = async (cveId: string) => {
    setLoading(true);
    setLoadingSteps([`Fetching details for ${cveId}...`]);
    setSearchResults([]);

    try {
      const vulnerability = await APIService.fetchVulnerabilityDataWithAI(
        cveId,
        setLoadingSteps,
        { nvd: settings.nvdApiKey },
        settings
      );
      setVulnerabilities([vulnerability]);
      setLoadingSteps(prev => [...prev, '✅ Analysis complete!']);
      addNotification({
        type: 'success',
        title: 'AI Analysis Complete',
        message: `Successfully analyzed ${cveId}`
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
  };

  return (
    <div style={{ maxWidth: '960px', margin: '32px auto', padding: '0 16px' }}>
      <h2 style={{
        fontSize: '2rem',
        fontWeight: '700',
        marginBottom: '24px',
        color: settings.darkMode ? COLORS.dark.primaryText : COLORS.light.primaryText
      }}>
        Natural Language Search Results
      </h2>
      <div style={{ display: 'grid', gap: '24px' }}>
        {searchResults.map((result, index) => (
          <div key={index} style={{
            padding: '24px',
            borderRadius: '12px',
            background: settings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
            border: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`,
            boxShadow: '0 4px 12px rgba(0,0,0,0.05)'
          }}>
            <h3 style={{ fontSize: '1.25rem', fontWeight: '600', marginBottom: '12px', color: settings.darkMode ? COLORS.dark.primaryText : COLORS.light.primaryText }}>
              {result.title}
            </h3>
            <p style={{ marginBottom: '16px', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText, lineHeight: '1.6' }}>
              {result.snippet}
            </p>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '20px' }}>
              <span style={{ fontSize: '0.875rem', color: COLORS.gray[500] }}>
                Source: {result.source} | Similarity: <strong>{(result.similarity * 100).toFixed(1)}%</strong>
              </span>
              {result.cveId && (
                <button
                  onClick={() => handleResultClick(result.cveId)}
                  style={{
                    padding: '10px 20px',
                    fontSize: '0.9rem',
                    fontWeight: '600',
                    color: '#fff',
                    background: `linear-gradient(135deg, ${COLORS.blue} 0%, #1d4ed8 100%)`,
                    border: 'none',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    transition: 'all 0.2s ease-in-out'
                  }}
                >
                  View CVE Details
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SearchResults;
