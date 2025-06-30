import React, { useState, useCallback, useContext, useMemo } from 'react';
import { AppContext } from '../contexts/AppContext';
import { APIService } from '../services/APIService';
import { utils } from '../utils/helpers';
import { createStyles } from '../utils/styles';
import { COLORS, CONSTANTS } from '../utils/constants';
import CVSSDisplay from './CVSSDisplay';
import { Brain, Database, Globe, Info, Shield, Loader2, Copy, RefreshCw, Package, CheckCircle, XCircle, AlertTriangle, Target, ChevronRight } from 'lucide-react';

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
      let enhancedVulnerability = vulnerability;

      if (!vulnerability.aiSearchPerformed || !vulnerability.sources || vulnerability.sources.length === 0) {
        addNotification({
          type: 'info',
          title: 'Performing AI Discovery',
          message: 'Running AI source discovery and validation analysis...'
        });

        enhancedVulnerability = await APIService.fetchVulnerabilityDataWithAI(
          vulnerability.cve.id,
          (steps) => {
            steps.forEach(step => console.log(step));
          },
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
        (steps) => {},
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
                                      const sourceUrls = {
                                        'NVD': `https://nvd.nist.gov/vuln/detail/${vulnerability.cve?.id}`,
                                        'EPSS': `https://api.first.org/data/v1/epss?cve=${vulnerability.cve?.id}`,
                                        'CISA KEV': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
                                        'Microsoft Advisory': `https://msrc.microsoft.com/update-guide/en-US/vulnerability/${vulnerability.cve?.id}`,
                                        'Red Hat Advisory': `https://access.redhat.com/security/cve/${vulnerability.cve?.id}`,
                                      };
                                      let url = sourceUrls[source.name];
                                      if (!url && source.name.includes(' Advisory')) {
                                        const vendorName = source.name.replace(' Advisory', '');
                                        url = sourceUrls[vendorName];
                                      }
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
                          const sourceUrls = {
                            'NVD': `https://nvd.nist.gov/vuln/detail/${vulnerability.cve?.id}`,
                            'EPSS': `https://api.first.org/data/v1/epss?cve=${vulnerability.cve?.id}`,
                             // ... Add more mappings as needed
                          };
                          let url = sourceUrls[source] || `https://www.cvedetails.com/cve/${vulnerability.cve?.id}/`;

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

export default CVEDetailView;
