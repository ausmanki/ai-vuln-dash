import React, { useState, useCallback, useContext, useMemo } from 'react';
import { AppContext } from '../contexts/AppContext';
import { APIService } from '../services/APIService';
import { utils } from '../utils/helpers';
import { createStyles } from '../utils/styles';
import { COLORS, CONSTANTS } from '../utils/constants';
import CVSSDisplay from './CVSSDisplay';
import { Brain, Database, Globe, Info, Loader2, Copy, RefreshCw, Package, CheckCircle, XCircle, AlertTriangle, Target, ChevronRight, FileText } from 'lucide-react';
import TechnicalBrief from './TechnicalBrief';
import ScoreChart from './ScoreChart';

const CVEDetailView = ({ vulnerability }) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const { settings, addNotification, setVulnerabilities } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  // Create a robust wrapper function that handles all possible parameter types
  const createRobustLoadingStepsWrapper = (prefix = 'AI Agent') => {
    return (param) => {
      try {
        // Case 1: ResearchAgent state updater function: (prev) => [...prev, message]
        if (typeof param === 'function') {
          try {
            const result = param([]);
            if (Array.isArray(result)) {
              // Log only the new message (last item)
              if (result.length > 0) {
                console.log(`${prefix}:`, result[result.length - 1]);
              }
            } else {
              console.log(`${prefix}:`, result);
            }
          } catch (funcError) {
            console.log(`${prefix}:`, 'Function execution step');
          }
          return;
        }
        
        // Case 2: Direct array of steps
        if (Array.isArray(param)) {
          param.forEach(step => {
            if (step && typeof step === 'string') {
              console.log(`${prefix}:`, step);
            } else {
              console.log(`${prefix}:`, String(step));
            }
          });
          return;
        }
        
        // Case 3: Direct string message
        if (typeof param === 'string') {
          console.log(`${prefix}:`, param);
          return;
        }
        
        // Case 4: Object with steps property
        if (param && typeof param === 'object') {
          if (param.steps && Array.isArray(param.steps)) {
            param.steps.forEach(step => console.log(`${prefix}:`, step));
            return;
          }
          if (param.message) {
            console.log(`${prefix}:`, param.message);
            return;
          }
        }
        
        // Case 5: Number, boolean, or other primitive
        if (param !== null && param !== undefined) {
          console.log(`${prefix}:`, String(param));
          return;
        }
        
        // Fallback for null/undefined
        console.log(`${prefix}:`, 'Processing...');
        
      } catch (error) {
        console.error(`Error in ${prefix} wrapper:`, error);
        console.log(`${prefix}:`, 'Step processing (error recovery)');
      }
    };
  };

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
      let enhancedVulnerability = vulnerability;

      if (
        !vulnerability.aiSearchPerformed ||
        !vulnerability.sources ||
        vulnerability.sources.length === 0 ||
        !vulnerability.patches ||
        vulnerability.patches.length === 0
      ) {
        addNotification({
          type: 'info',
          title: 'Performing AI Discovery',
          message: 'Running AI source discovery and validation analysis...'
        });

        // Use the robust wrapper
        const setLoadingStepsWrapper = createRobustLoadingStepsWrapper('AI Discovery');

        enhancedVulnerability = await APIService.fetchVulnerabilityDataWithAI(
          vulnerability.cve.id,
          setLoadingStepsWrapper, // Use the robust wrapper function
          { nvd: settings.nvdApiKey },
          settings
        );

        setVulnerabilities([enhancedVulnerability]);

        addNotification({
          type: 'success',
          title: 'AI Discovery Complete',
          message: `Discovered ${enhancedVulnerability.discoveredSources?.length || 0} sources and validation data`
        });
      }

      const result = await APIService.generateAIAnalysis(
        enhancedVulnerability,
        settings.geminiApiKey,
        settings.geminiModel,
        settings
      );

      setAiAnalysis(result);
      setActiveTab('brief');

      // Enhanced notification based on AI analysis result
      if (result.fallbackReason === 'GROUNDING_INFO_ONLY') {
        addNotification({
          type: 'warning',
          title: 'AI Analysis with Limitations',
          message: `AI performed web searches but provided fallback analysis. Generated using ${result.ragDocuments || 0} knowledge sources.`
        });
      } else if (result.fallbackReason === 'SAFETY' || result.fallbackReason === 'RECITATION') {
        addNotification({
          type: 'warning',
          title: 'Content Policy Limitation',
          message: `AI analysis was limited due to content policies. Using fallback analysis based on available data.`
        });
      } else if (result.fallbackReason) {
        addNotification({
          type: 'warning',
          title: 'AI Analysis Issue',
          message: `AI analysis encountered limitations (${result.fallbackReason}). Using enhanced fallback analysis.`
        });
      } else {
        addNotification({
          type: 'success',
          title: 'AI Analysis Complete',
          message: `Enhanced analysis generated using ${result.ragDocuments || 0} knowledge sources and real-time intelligence`
        });
      }
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
      // Use the same robust wrapper for consistency
      const setLoadingStepsWrapper = createRobustLoadingStepsWrapper('AI Refresh');

      const refreshedVulnerability = await APIService.fetchVulnerabilityDataWithAI(
        cveId,
        setLoadingStepsWrapper, // Use the robust wrapper function
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
          {['overview', 'ai-sources', 'patches', 'brief'].map((tab) => (
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
              {tab === 'patches' && <Package size={16} />}
              {tab === 'brief' && <FileText size={16} />}
              {tab === 'ai-sources'
                ? 'AI Sources'
                : tab === 'patches'
                ? 'Patches'
                : tab === 'brief'
                ? 'Tech Brief'
                : tab.charAt(0).toUpperCase() + tab.slice(1)}
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
                          EPSS Score: {vulnerability.epss.epssPercentage}
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

              {vulnerability.epss && (
                <div style={{ marginBottom: '24px' }}>
                  <h3 style={{ fontSize: '1.25rem', fontWeight: '600', marginBottom: '12px' }}>
                    CVSS vs EPSS
                  </h3>
                  <ScoreChart
                    cvss={cvssScore}
                    epss={vulnerability.epss.epssFloat * 100}
                  />
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
                      {!vulnerability.aiSearchPerformed ? 'Running Full AI Analysis...' : 'Generating AI Analysis...'}
                    </>
                  ) : (
                    <>
                      <Brain size={20} />
                      <Database size={16} style={{ marginLeft: '4px' }} />
                      {!vulnerability.aiSearchPerformed ? 'Generate Full AI Analysis' : 'Generate AI Analysis'}
                    </>
                  )}
                </button>
                {!settings.geminiApiKey && (
                  <p style={{ fontSize: '0.9rem', color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText, marginTop: '12px' }}>
                    Configure Gemini API key in settings to enable AI-powered threat intelligence
                  </p>
                )}
              </div>
            </div>
          )}

          {activeTab === 'ai-sources' && (() => {
            const cvssRisk = cvssScore >= 9.0 ? 'CRITICAL' : cvssScore >= 7.0 ? 'HIGH' : cvssScore >= 4.0 ? 'MEDIUM' : 'LOW';
            const epssRisk = vulnerability.epss?.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH ? 'HIGH' : 
                            vulnerability.epss?.epssFloat > CONSTANTS.EPSS_THRESHOLDS.MEDIUM ? 'MEDIUM' : 'LOW';
            
            return (
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
                    {/* Enhanced AI Risk Assessment Summary */}
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
                            AI Risk Assessment Summary
                          </h3>
                          <p style={{
                            margin: '4px 0 0 0',
                            fontSize: '0.875rem',
                            color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText
                          }}>
                            Comprehensive analysis of {vulnerability.cve?.id} based on multiple intelligence sources
                          </p>
                        </div>
                      </div>

                      {/* Enhanced AI Analysis Limitations Notice */}
                      {vulnerability.intelligenceSummary?.analysisMethod === 'GROUNDING_INFO_ONLY' && (
                        <div style={{
                          background: `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)`,
                          borderWidth: '1px',
                          borderStyle: 'solid', 
                          borderColor: `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.3)`,
                          borderRadius: '8px',
                          padding: '12px',
                          marginBottom: '16px'
                        }}>
                          <p style={{ margin: 0, fontSize: '0.8rem' }}>
                            <strong>⚠️ AI Search Limitation:</strong> The AI performed web searches but could not provide textual analysis. 
                            Using fallback analysis based on available vulnerability data.
                          </p>
                          {vulnerability.intelligenceSummary.searchQueries?.length > 0 && (
                            <p style={{ margin: '8px 0 0 0', fontSize: '0.75rem', color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                              {vulnerability.intelligenceSummary.searchQueries.length} search queries were executed.
                            </p>
                          )}
                        </div>
                      )}

                      {/* Critical Alerts */}
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

                      {/* AI Risk Analysis Grid */}
                      <div style={{ 
                        display: 'grid', 
                        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
                        gap: '16px',
                        marginBottom: '20px'
                      }}>
                        {/* CVSS Risk Box */}
                        <div style={{
                          padding: '12px',
                          borderRadius: '8px',
                          background: cvssRisk === 'CRITICAL' ? `rgba(${utils.hexToRgb(COLORS.red)}, 0.1)` :
                                     cvssRisk === 'HIGH' ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)` :
                                     cvssRisk === 'MEDIUM' ? `rgba(${utils.hexToRgb(COLORS.blue)}, 0.1)` : 
                                     `rgba(${utils.hexToRgb(COLORS.green)}, 0.1)`,
                          borderWidth: '1px',
                          borderStyle: 'solid',
                          borderColor: cvssRisk === 'CRITICAL' ? `rgba(${utils.hexToRgb(COLORS.red)}, 0.3)` :
                                      cvssRisk === 'HIGH' ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.3)` :
                                      cvssRisk === 'MEDIUM' ? `rgba(${utils.hexToRgb(COLORS.blue)}, 0.3)` : 
                                      `rgba(${utils.hexToRgb(COLORS.green)}, 0.3)`
                        }}>
                          <div style={{ fontWeight: '600', fontSize: '0.9rem', marginBottom: '4px' }}>
                            CVSS Risk: {cvssRisk}
                          </div>
                          <div style={{ fontSize: '0.8rem', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                            Score: {cvssScore?.toFixed(1) || 'N/A'}
                          </div>
                        </div>

                        {/* EPSS Risk Box */}
                        <div style={{
                          padding: '12px',
                          borderRadius: '8px',
                          background: epssRisk === 'HIGH' ? `rgba(${utils.hexToRgb(COLORS.red)}, 0.1)` :
                                     epssRisk === 'MEDIUM' ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)` :
                                     `rgba(${utils.hexToRgb(COLORS.green)}, 0.1)`,
                          borderWidth: '1px',
                          borderStyle: 'solid',
                          borderColor: epssRisk === 'HIGH' ? `rgba(${utils.hexToRgb(COLORS.red)}, 0.3)` :
                                      epssRisk === 'MEDIUM' ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.3)` :
                                      `rgba(${utils.hexToRgb(COLORS.green)}, 0.3)`
                        }}>
                          <div style={{ fontWeight: '600', fontSize: '0.9rem', marginBottom: '4px' }}>
                            EPSS Risk: {epssRisk}
                          </div>
                          <div style={{ fontSize: '0.8rem', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                            {vulnerability.epss?.epssPercentage || 'N/A'}
                          </div>
                        </div>

                        {/* CISA KEV Status Box */}
                        <div style={{
                          padding: '12px',
                          borderRadius: '8px',
                          background: vulnerability.kev?.listed ? `rgba(${utils.hexToRgb(COLORS.red)}, 0.1)` : `rgba(${utils.hexToRgb(COLORS.green)}, 0.1)`,
                          borderWidth: '1px',
                          borderStyle: 'solid',
                          borderColor: vulnerability.kev?.listed ? `rgba(${utils.hexToRgb(COLORS.red)}, 0.3)` : `rgba(${utils.hexToRgb(COLORS.green)}, 0.3)`
                        }}>
                          <div style={{ fontWeight: '600', fontSize: '0.9rem', marginBottom: '4px' }}>
                            CISA KEV: {vulnerability.kev?.listed ? 'LISTED' : 'Not Listed'}
                          </div>
                          <div style={{ fontSize: '0.8rem', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                            {vulnerability.kev?.listed ? 'Active Exploitation' : 'No Active Exploitation'}
                          </div>
                        </div>

                        {/* Threat Level Box */}
                        <div style={{
                          padding: '12px',
                          borderRadius: '8px',
                          background: vulnerability.threatLevel === 'CRITICAL' ? `rgba(${utils.hexToRgb(COLORS.red)}, 0.1)` :
                                     vulnerability.threatLevel === 'HIGH' ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)` :
                                     vulnerability.threatLevel === 'MEDIUM' ? `rgba(${utils.hexToRgb(COLORS.blue)}, 0.1)` :
                                     `rgba(${utils.hexToRgb(COLORS.green)}, 0.1)`,
                          borderWidth: '1px',
                          borderStyle: 'solid',
                          borderColor: vulnerability.threatLevel === 'CRITICAL' ? `rgba(${utils.hexToRgb(COLORS.red)}, 0.3)` :
                                      vulnerability.threatLevel === 'HIGH' ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.3)` :
                                      vulnerability.threatLevel === 'MEDIUM' ? `rgba(${utils.hexToRgb(COLORS.blue)}, 0.3)` :
                                      `rgba(${utils.hexToRgb(COLORS.green)}, 0.3)`
                        }}>
                          <div style={{ fontWeight: '600', fontSize: '0.9rem', marginBottom: '4px' }}>
                            Threat Level: {vulnerability.threatLevel || 'Standard'}
                          </div>
                          <div style={{ fontSize: '0.8rem', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                            {vulnerability.analysisMethod === 'AI_WEB_SEARCH' ? 'AI Enhanced' : 'Heuristic Analysis'}
                          </div>
                        </div>
                      </div>

                      {/* AI Analysis Description */}
                      <div style={{ marginBottom: '16px' }}>
                        <h4 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '8px' }}>
                          Vulnerability Analysis
                        </h4>
                        <p style={{ fontSize: '0.875rem', marginBottom: '12px', lineHeight: '1.5' }}>
                          {vulnerability.cve?.description || 'No description available.'}
                        </p>
                        
                        {/* AI-Generated Risk Summary */}
                        <div style={{
                          background: `rgba(${utils.hexToRgb(COLORS.blue)}, 0.05)`,
                          borderWidth: '1px',
                          borderStyle: 'solid',
                          borderColor: `rgba(${utils.hexToRgb(COLORS.blue)}, 0.2)`,
                          borderRadius: '6px',
                          padding: '12px',
                          marginTop: '12px'
                        }}>
                          <p style={{ margin: 0, fontSize: '0.85rem', fontStyle: 'italic' }}>
                            <strong>AI Risk Assessment:</strong> Based on CVSS {cvssRisk} severity ({cvssScore?.toFixed(1)}) and EPSS {epssRisk} exploitation probability ({vulnerability.epss?.epssPercentage || 'N/A'}), 
                            this vulnerability presents a {cvssRisk === 'CRITICAL' || epssRisk === 'HIGH' || vulnerability.kev?.listed ? 'HIGH' : 
                            cvssRisk === 'HIGH' || epssRisk === 'MEDIUM' ? 'MEDIUM' : 'LOW'} risk to your environment.
                            {vulnerability.kev?.listed && ' IMMEDIATE ACTION REQUIRED due to CISA KEV listing.'}
                            {vulnerability.exploits?.found && ` ${vulnerability.exploits.count} public exploit(s) available.`}
                          </p>
                        </div>
                      </div>

                      <div>
                        <h4 style={{
                          fontSize: '1rem',
                          fontWeight: '600',
                          marginBottom: '12px'
                        }}>
                          Sources Analyzed
                        </h4>
                        {vulnerability.discoveredSources && vulnerability.discoveredSources.length > 0 ? (
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
                        ) : (
                          <p style={{
                            fontSize: '0.875rem',
                            color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText
                          }}>
                            No sources identified.
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })()}

          {activeTab === 'patches' && (() => {
            // Helper function to extract patch info from technical brief
            const extractPatchInfoFromTechBrief = (analysis) => {
              if (!analysis) return [];
              
              const remediationSection = analysis.split('## Remediation')[1];
              if (!remediationSection) return [];
              
              const patches = [];
              const lines = remediationSection.split('\n');
              
              lines.forEach(line => {
                if (line.includes('**') && (line.includes('Patch') || line.includes('Update') || line.includes('Version'))) {
                  const match = line.match(/\*\*(.*?)\*\*/);
                  if (match) {
                    const patchInfo = match[1];
                    const parts = patchInfo.split(' - ');
                    patches.push({
                      vendor: parts[0] || 'Unknown',
                      product: parts[1] || '',
                      description: line.replace(/\*\*/g, '').trim()
                    });
                  }
                }
              });
              
              return patches;
            };

            // Get patch information from technical brief if available
            const techBriefPatches = aiAnalysis?.analysis && aiAnalysis.analysis.includes('## Remediation') ? 
              extractPatchInfoFromTechBrief(aiAnalysis.analysis) : [];
            
            const totalPatches = (vulnerability.patches?.length || 0) + (techBriefPatches?.length || 0);
            const uniqueVendors = [...new Set([
              ...(vulnerability.patches || []).map(p => p.vendor),
              ...(techBriefPatches || []).map(p => p.vendor)
            ])].filter(Boolean);

            return (
              <div>
                <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '24px' }}>
                  Patches & Remediation
                </h2>

                {/* Patch Summary Card */}
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
                    <Package size={24} color={COLORS.blue} />
                    <div>
                      <h3 style={{
                        fontSize: '1.125rem',
                        fontWeight: '600',
                        margin: 0
                      }}>
                        Patch Availability Summary
                      </h3>
                      <p style={{
                        margin: '4px 0 0 0',
                        fontSize: '0.875rem',
                        color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText
                      }}>
                        Comprehensive patch analysis for {vulnerability.cve?.id}
                      </p>
                    </div>
                  </div>

                  {/* Patch Statistics */}
                  <div style={{ 
                    display: 'grid', 
                    gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', 
                    gap: '12px',
                    marginBottom: '16px'
                  }}>
                    <div style={{
                      padding: '12px',
                      borderRadius: '8px',
                      background: totalPatches > 0 ? `rgba(${utils.hexToRgb(COLORS.green)}, 0.1)` : `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)`,
                      borderWidth: '1px',
                      borderStyle: 'solid',
                      borderColor: totalPatches > 0 ? `rgba(${utils.hexToRgb(COLORS.green)}, 0.3)` : `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.3)`
                    }}>
                      <div style={{ fontWeight: '600', fontSize: '0.9rem', marginBottom: '4px' }}>
                        Total Patches: {totalPatches}
                      </div>
                      <div style={{ fontSize: '0.8rem', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                        {totalPatches > 0 ? 'Patches Available' : 'No Patches Found'}
                      </div>
                    </div>

                    <div style={{
                      padding: '12px',
                      borderRadius: '8px',
                      background: `rgba(${utils.hexToRgb(COLORS.blue)}, 0.1)`,
                      borderWidth: '1px',
                      borderStyle: 'solid',
                      borderColor: `rgba(${utils.hexToRgb(COLORS.blue)}, 0.3)`
                    }}>
                      <div style={{ fontWeight: '600', fontSize: '0.9rem', marginBottom: '4px' }}>
                        Vendors: {uniqueVendors.length}
                      </div>
                      <div style={{ fontSize: '0.8rem', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                        {uniqueVendors.length > 0 ? uniqueVendors.slice(0, 2).join(', ') + (uniqueVendors.length > 2 ? '...' : '') : 'None identified'}
                      </div>
                    </div>

                    <div style={{
                      padding: '12px',
                      borderRadius: '8px',
                      background: `rgba(${utils.hexToRgb(COLORS.purple)}, 0.1)`,
                      borderWidth: '1px',
                      borderStyle: 'solid',
                      borderColor: `rgba(${utils.hexToRgb(COLORS.purple)}, 0.3)`
                    }}>
                      <div style={{ fontWeight: '600', fontSize: '0.9rem', marginBottom: '4px' }}>
                        Analysis Source
                      </div>
                      <div style={{ fontSize: '0.8rem', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                        {vulnerability.aiSearchPerformed ? 'AI Enhanced' : 'Standard'}
                      </div>
                    </div>
                  </div>

                  {/* Patch Recommendation */}
                  <div style={{
                    background: `rgba(${utils.hexToRgb(COLORS.blue)}, 0.05)`,
                    borderWidth: '1px',
                    borderStyle: 'solid',
                    borderColor: `rgba(${utils.hexToRgb(COLORS.blue)}, 0.2)`,
                    borderRadius: '6px',
                    padding: '12px'
                  }}>
                    <p style={{ margin: 0, fontSize: '0.85rem' }}>
                      <strong>Recommendation:</strong> {
                        totalPatches > 0 ? 
                          `${totalPatches} patch(es) available across ${uniqueVendors.length} vendor(s). Review and apply patches based on your environment and risk tolerance.` :
                          vulnerability.patchSearchSummary?.patchesFound > 0 ?
                            `${vulnerability.patchSearchSummary.patchesFound} patch(es) found across ${vulnerability.patchSearchSummary.vendorsSearched?.length || 0} vendor(s) during initial discovery.` :
                            'No patches identified in automated discovery. Check vendor security advisories manually for updates.'
                      }
                      {vulnerability.kev?.listed && ' PRIORITY: Immediate patching required due to CISA KEV listing.'}
                    </p>
                  </div>
                </div>

                {/* Available Patches */}
                {vulnerability.patches && vulnerability.patches.length > 0 ? (
                  <div style={{ marginBottom: '24px' }}>
                    <h3 style={{ fontSize: '1.25rem', fontWeight: '600', marginBottom: '16px' }}>
                      Available Patches ({vulnerability.patches.length})
                    </h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      {vulnerability.patches.map((patch, index) => (
                        <div
                          key={index}
                          style={{
                            ...styles.card,
                            padding: '12px 16px',
                            background: settings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            gap: '12px'
                          }}
                        >
                          <div style={{ flex: 1 }}>
                            <div style={{ fontWeight: '600', fontSize: '0.9rem', marginBottom: '4px' }}>
                              {patch.vendor}{patch.product ? ` - ${patch.product}` : ''}
                            </div>
                            {patch.patchVersion && (
                              <div style={{ fontSize: '0.8rem', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                                Version: {patch.patchVersion}
                              </div>
                            )}
                            {patch.description && (
                              <div style={{ fontSize: '0.8rem', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                                {patch.description}
                              </div>
                            )}
                          </div>
                          {patch.downloadUrl && patch.downloadUrl.startsWith('http') && (
                            <a
                              href={patch.downloadUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{ ...styles.button, ...styles.buttonPrimary, padding: '6px 12px', fontSize: '0.8rem', textDecoration: 'none' }}
                            >
                              Get Patch
                            </a>
                          )}
                          {!patch.downloadUrl && patch.advisoryUrl && patch.advisoryUrl.startsWith('http') && (
                            <a
                              href={patch.advisoryUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{ ...styles.button, ...styles.buttonSecondary, padding: '6px 12px', fontSize: '0.8rem', textDecoration: 'none' }}
                            >
                              View Advisory →
                            </a>
                          )}
                          {!patch.downloadUrl && !patch.advisoryUrl && patch.citationUrl && patch.citationUrl.startsWith('http') && (
                            <a
                              href={patch.citationUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{ ...styles.button, ...styles.buttonSecondary, padding: '6px 12px', fontSize: '0.8rem', textDecoration: 'none' }}
                            >
                              View Source →
                            </a>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div style={{
                    textAlign: 'center',
                    padding: '32px',
                    color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText,
                    background: settings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
                    borderRadius: '8px',
                    marginBottom: '24px'
                  }}>
                    <Package size={40} style={{ marginBottom: '12px', opacity: 0.5 }} />
                    <h4 style={{ margin: '0 0 8px 0', fontSize: '1rem' }}>No Patches Identified</h4>
                    <p style={{ margin: 0, fontSize: '0.875rem' }}>
                      No patches found through automated discovery. Check vendor advisories manually for potential updates.
                    </p>
                  </div>
                )}

                {/* Additional Patch Information from Tech Brief */}
                {techBriefPatches && techBriefPatches.length > 0 && (
                  <div>
                    <h3 style={{ fontSize: '1.25rem', fontWeight: '600', marginBottom: '16px' }}>
                      Additional Patch Information from Analysis
                    </h3>
                    <div style={{
                      background: settings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
                      borderRadius: '8px',
                      padding: '16px'
                    }}>
                      {techBriefPatches.map((patch, index) => (
                        <div key={index} style={{ marginBottom: index < techBriefPatches.length - 1 ? '12px' : 0 }}>
                          <div style={{ fontWeight: '600', fontSize: '0.9rem', marginBottom: '4px' }}>
                            {patch.vendor} {patch.product && `- ${patch.product}`}
                          </div>
                          <div style={{ fontSize: '0.85rem', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                            {patch.description}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })()}

          {activeTab === 'brief' && (
            <div>
              {aiAnalysis ? (
                <div>
                  {/* Enhanced AI Analysis Status Display */}
                  {aiAnalysis.fallbackReason && (
                    <div style={{
                      background: aiAnalysis.fallbackReason === 'GROUNDING_INFO_ONLY' 
                        ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)` 
                        : `rgba(${utils.hexToRgb(COLORS.red)}, 0.1)`,
                      borderWidth: '1px',
                      borderStyle: 'solid',
                      borderColor: aiAnalysis.fallbackReason === 'GROUNDING_INFO_ONLY' 
                        ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.3)` 
                        : `rgba(${utils.hexToRgb(COLORS.red)}, 0.3)`,
                      borderRadius: '8px',
                      padding: '12px',
                      marginBottom: '20px'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                        <AlertTriangle size={16} color={aiAnalysis.fallbackReason === 'GROUNDING_INFO_ONLY' ? COLORS.yellow : COLORS.red} />
                        <strong style={{ fontSize: '0.9rem' }}>
                          {aiAnalysis.fallbackReason === 'GROUNDING_INFO_ONLY' 
                            ? 'AI Search Performed - Fallback Analysis Used'
                            : `AI Analysis Limited - ${aiAnalysis.fallbackReason}`}
                        </strong>
                      </div>
                      <p style={{ margin: 0, fontSize: '0.8rem' }}>
                        {aiAnalysis.fallbackReason === 'GROUNDING_INFO_ONLY' 
                          ? 'The AI performed web searches but could not provide direct textual analysis. This technical brief was generated using available vulnerability data and fallback analysis methods.'
                          : aiAnalysis.fallbackReason === 'SAFETY' 
                            ? 'AI analysis was blocked due to content safety policies. Using fallback analysis based on available data.'
                            : aiAnalysis.fallbackReason === 'RECITATION'
                              ? 'AI analysis was blocked due to content recitation policies. Using fallback analysis based on available data.'
                              : `AI analysis encountered limitations (${aiAnalysis.fallbackReason}). Using enhanced fallback analysis.`}
                      </p>
                      {aiAnalysis.searchQueries?.length > 0 && (
                        <p style={{ margin: '8px 0 0 0', fontSize: '0.75rem', color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                          Search queries executed: {aiAnalysis.searchQueries.length}
                        </p>
                      )}
                    </div>
                  )}
                  
                  <TechnicalBrief brief={aiAnalysis.analysis} />
                </div>
              ) : (
                <div style={{ textAlign: 'center', padding: '48px 32px' }}>
                  <FileText size={40} color={settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText} />
                  <h3 style={{ margin: '16px 0 8px 0' }}>No Technical Brief Available</h3>
                  <p style={{ margin: 0, color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                    Generate AI analysis to view the technical brief
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

          {/* Enhanced AI Analysis Limitations Notice in Summary */}
          {vulnerability.intelligenceSummary?.analysisMethod === 'GROUNDING_INFO_ONLY' && (
            <div style={{
              background: `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)`,
              borderWidth: '1px',
              borderStyle: 'solid', 
              borderColor: `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.3)`,
              borderRadius: '8px',
              padding: '12px',
              marginBottom: '12px'
            }}>
              <p style={{ margin: 0, fontSize: '0.8rem' }}>
                <strong>⚠️ AI Search Limitation:</strong> The AI performed web searches but could not provide textual analysis. 
                Using fallback analysis based on available vulnerability data.
              </p>
              {vulnerability.intelligenceSummary.searchQueries?.length > 0 && (
                <p style={{ margin: '8px 0 0 0', fontSize: '0.75rem', color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                  {vulnerability.intelligenceSummary.searchQueries.length} search queries were executed.
                </p>
              )}
            </div>
          )}

          <div style={{ fontSize: '0.8125rem', color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>CVSS Score:</strong> {cvssScore?.toFixed(1) || 'N/A'} ({severity})
            </p>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>EPSS Score:</strong> {vulnerability.epss?.epssPercentage || 'N/A'}
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
          Powered by AI
        </div>
      </div>
    </div>
  );
};

export default CVEDetailView;
