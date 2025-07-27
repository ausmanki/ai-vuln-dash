import React, { useState, useCallback, useContext, useMemo } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { AppContext } from '../contexts/AppContext';
import { APIService } from '../services/APIService';
import { utils } from '../utils/helpers';
import { createStyles } from '../utils/styles';
import { COLORS, CONSTANTS } from '../utils/constants';
import CVSSDisplay from './CVSSDisplay';
import { Brain, Database, Globe, Info, Loader2, Copy, RefreshCw, Package, CheckCircle, XCircle, AlertTriangle, Target, ChevronRight, FileText, ExternalLink, Search, Clock, Wrench } from 'lucide-react';
import TechnicalBrief from './TechnicalBrief';
import ScoreChart from './ScoreChart';
import AISourcesTab from './AISourcesTab';
import { vendorPortalMap } from '../utils/vendorPortals';

const CVEDetailView = ({ vulnerability }) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [remediationSuggestions, setRemediationSuggestions] = useState(null);
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [threatIntel, setThreatIntel] = useState(null);
  const [threatIntelLoading, setThreatIntelLoading] = useState(false);
  const [relatedVulnerabilities, setRelatedVulnerabilities] = useState(null);
  const [relatedVulnerabilitiesLoading, setRelatedVulnerabilitiesLoading] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [patchGuidance, setPatchGuidance] = useState(null);
  const [fetchingPatches, setFetchingPatches] = useState(false);
  const [activeGuidanceSection, setActiveGuidanceSection] = useState('overview');
  const [showFullDescription, setShowFullDescription] = useState(false);
  const { settings, addNotification, setVulnerabilities } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings?.darkMode || false), [settings?.darkMode]);

  // ... (existing functions)

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 350px', gap: '32px', marginTop: '32px' }}>
      <main style={styles.card}>
        {/* Header */}
        <header style={{ paddingBottom: '24px', borderBottom: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
            <div>
              <h1 style={{ ...styles.title, fontSize: '2.25rem', margin: 0, display: 'flex', alignItems: 'center', gap: '12px' }}>
                {vulnerability?.cve?.id || 'Unknown CVE'}
                <Copy size={20} style={{ cursor: 'pointer', color: COLORS.blue }} onClick={() => {}} />
              </h1>
              <p style={{ ...styles.subtitle, marginTop: '8px' }}>
                {vulnerability?.cve?.description?.split('.')[0]}
              </p>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button style={{ ...styles.button, ...styles.buttonSecondary }} onClick={() => {}}>
                <RefreshCw size={14} /> Refresh
              </button>
              <button style={{ ...styles.button, ...styles.buttonSecondary }} onClick={() => {}}>
                <Package size={14} /> Export
              </button>
            </div>
          </div>
          {/* Badges */}
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ ...styles.badge, backgroundColor: 'rgba(239, 68, 68, 0.1)', color: 'rgb(239, 68, 68)' }}>
              HIGH - 7.5
            </span>
          </div>
        </header>

        {/* Tabs */}
        <nav style={{ display: 'flex', borderBottom: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`, marginBottom: '24px' }}>
          {['overview', 'remediation', 'threat-intel', 'related-cves', 'ai-sources', 'brief'].map((tab) => (
            <button
              key={tab}
              style={{
                padding: '14px 20px',
                cursor: 'pointer',
                border: 'none',
                borderBottom: activeTab === tab ? `3px solid ${COLORS.blue}` : '3px solid transparent',
                fontSize: '1rem',
                fontWeight: '600',
                color: activeTab === tab ? COLORS.blue : settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
                background: 'transparent',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
              }}
              onClick={() => setActiveTab(tab)}
            >
              {tab === 'overview' && <Info size={18} />}
              {tab === 'remediation' && <Wrench size={18} />}
              {tab === 'threat-intel' && <Target size={18} />}
              {tab === 'related-cves' && <Package size={18} />}
              {tab === 'ai-sources' && <Globe size={18} />}
              {tab === 'brief' && <FileText size={18} />}
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </nav>

        {/* Tab Content */}
        <div>
          {activeTab === 'overview' && (
            <div>
              {/* ... existing overview content ... */}
            </div>
          )}
          {activeTab === 'remediation' && (
            <div>
              {remediationSuggestions ? (
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{remediationSuggestions}</ReactMarkdown>
              ) : (
                <div style={{ textAlign: 'center', padding: '48px 32px' }}>
                  <Wrench size={40} color={settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText} />
                  <h3 style={{ margin: '16px 0 8px 0' }}>No Remediation Suggestions Available</h3>
                  <p style={{ margin: '0 0 16px 0', color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                    Generate AI-powered remediation suggestions for this vulnerability.
                  </p>
                  <button
                    style={{ ...styles.button, ...styles.buttonPrimary }}
                    onClick={async () => {
                      setRemediationLoading(true);
                      try {
                        const result = await APIService.generateRemediationSuggestions(vulnerability, settings);
                        setRemediationSuggestions(result.suggestions);
                      } catch (error) {
                        addNotification({ type: 'error', title: 'Failed to generate suggestions', message: `Could not generate remediation suggestions. The AI model may be offline or the request may have timed out. \n\n ${error.message}` });
                      } finally {
                        setRemediationLoading(false);
                      }
                    }}
                    disabled={remediationLoading}
                  >
                    {remediationLoading ? <Loader2 size={20} style={{ animation: 'spin 1s linear infinite' }} /> : <><Brain size={18} /> Generate Suggestions</>}
                  </button>
                </div>
              )}
            </div>
          )}
          {activeTab === 'threat-intel' && (
            <div>
              {threatIntel ? (
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{threatIntel}</ReactMarkdown>
              ) : (
                <div style={{ textAlign: 'center', padding: '48px 32px' }}>
                  <Target size={40} color={settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText} />
                  <h3 style={{ margin: '16px 0 8px 0' }}>No Threat Intelligence Summary Available</h3>
                  <p style={{ margin: '0 0 16px 0', color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                    Generate an AI-powered threat intelligence summary for this vulnerability.
                  </p>
                  <button
                    style={{ ...styles.button, ...styles.buttonPrimary }}
                    onClick={async () => {
                      setThreatIntelLoading(true);
                      try {
                        const result = await APIService.fetchAIThreatIntelligence(vulnerability.cve.id, vulnerability.cve, vulnerability.epss, settings, () => {});
                        setThreatIntel(result.summary);
                      } catch (error) {
                        addNotification({ type: 'error', title: 'Failed to fetch threat intelligence', message: `Could not fetch threat intelligence. The AI model may be offline or the request may have timed out. \n\n ${error.message}` });
                      } finally {
                        setThreatIntelLoading(false);
                      }
                    }}
                    disabled={threatIntelLoading}
                  >
                    {threatIntelLoading ? <Loader2 size={20} style={{ animation: 'spin 1s linear infinite' }} /> : <><Brain size={18} /> Generate Summary</>}
                  </button>
                </div>
              )}
            </div>
          )}
          {activeTab === 'related-cves' && (
            <div>
              {relatedVulnerabilities ? (
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{relatedVulnerabilities}</ReactMarkdown>
              ) : (
                <div style={{ textAlign: 'center', padding: '48px 32px' }}>
                  <Package size={40} color={settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText} />
                  <h3 style={{ margin: '16px 0 8px 0' }}>No Related Vulnerabilities Found</h3>
                  <p style={{ margin: '0 0 16px 0', color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                    Find related vulnerabilities using AI.
                  </p>
                  <button
                    style={{ ...styles.button, ...styles.buttonPrimary }}
                    onClick={async () => {
                      setRelatedVulnerabilitiesLoading(true);
                      try {
                        const result = await APIService.findRelatedVulnerabilities(vulnerability, settings);
                        setRelatedVulnerabilities(result.related);
                      } catch (error) {
                        addNotification({ type: 'error', title: 'Failed to find related vulnerabilities', message: `Could not fetch related vulnerabilities. The AI model may be offline or the request may have timed out. \n\n ${error.message}` });
                      } finally {
                        setRelatedVulnerabilitiesLoading(false);
                      }
                    }}
                    disabled={relatedVulnerabilitiesLoading}
                  >
                    {relatedVulnerabilitiesLoading ? <Loader2 size={20} style={{ animation: 'spin 1s linear infinite' }} /> : <><Brain size={18} /> Find Related CVEs</>}
                  </button>
                </div>
              )}
            </div>
          )}
          {activeTab === 'ai-sources' && <AISourcesTab vulnerability={vulnerability} />}
          {activeTab === 'brief' && (
            <div>
              {aiAnalysis ? (
                <TechnicalBrief brief={aiAnalysis.analysis || aiAnalysis} />
              ) : (
                <div style={{ textAlign: 'center', padding: '48px 32px' }}>
                  <FileText size={40} color={settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText} />
                  <h3 style={{ margin: '16px 0 8px 0' }}>No Technical Brief Available</h3>
                  <p style={{ margin: '0 0 16px 0', color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                    Generate AI analysis to view the technical brief.
                  </p>
                  <button
                    style={{ ...styles.button, ...styles.buttonPrimary }}
                    onClick={async () => {
                      setAiLoading(true);
                      try {
                        const result = await APIService.generateAIAnalysis(vulnerability, settings.geminiApiKey, settings.geminiModel, settings);
                        setAiAnalysis(result);
                      } catch (error) {
                        addNotification({ type: 'error', title: 'Failed to generate analysis', message: `Could not generate analysis. The AI model may be offline or the request may have timed out. \n\n ${error.message}` });
                      } finally {
                        setAiLoading(false);
                      }
                    }}
                    disabled={aiLoading}
                  >
                    {aiLoading ? <Loader2 size={20} style={{ animation: 'spin 1s linear infinite' }} /> : <><Brain size={18} /> Generate Analysis</>}
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </main>
      <aside style={{ position: 'sticky', top: '24px' }}>
        {/* ... existing aside content ... */}
      </aside>
    </div>
  );
};

export default CVEDetailView;
