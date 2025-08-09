import React, { useMemo, useContext, useState, useCallback, useEffect } from 'react';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { X, Code, UploadCloud, File as FileIcon, Loader2, Brain, Search, Database } from 'lucide-react';
import { COLORS } from '../utils/constants';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { APIService } from '../services/APIService';
import { EnhancedVulnerabilityData } from '../types/cveData';

interface TaintAnalysisPageProps {
  onClose: () => void;
  vulnerability: EnhancedVulnerabilityData | null;
}

const TaintAnalysisPage: React.FC<TaintAnalysisPageProps> = ({ onClose, vulnerability }) => {
  const { settings, addNotification } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);
  const [activeTab, setActiveTab] = useState<'rag' | 'taint'>('rag');
  const [ragDocuments, setRagDocuments] = useState<any[]>([]);
  const [loadingRag, setLoadingRag] = useState(false);
  const [analysis, setAnalysis] = useState<string | null>(null);
  const [loadingTaint, setLoadingTaint] = useState(false);

  const fetchRagDocuments = useCallback(async () => {
    setLoadingRag(true);
    try {
      await ragDatabase.initialize();
      const docs = ragDatabase.getDocuments();
      setRagDocuments(docs);
    } catch (error) {
      addNotification?.({ type: 'error', title: 'Failed to load RAG documents', message: 'Could not read RAG document data.' });
    } finally {
      setLoadingRag(false);
    }
  }, [addNotification]);

  const generateTaintAnalysis = useCallback(async () => {
    if (!settings.aiProvider) {
      addNotification?.({ type: 'error', title: 'AI Provider Required', message: 'Configure AI provider in settings' });
      return;
    }
    setLoadingTaint(true);

    try {
        const docs = ragDatabase.getDocuments();
        if (docs.length === 0) {
            addNotification?.({ type: 'info', title: 'Empty RAG', message: 'RAG documents are empty, searching web.' });
            const searchResults = await APIService.performNaturalLanguageSearch('vulnerability taint analysis', settings);
            // We need to add the search results to the RAG database
            for (const result of searchResults) {
                await ragDatabase.addDocument(result.content, {
                    title: result.title,
                    source: result.url,
                });
            }
        }

      if (!vulnerability?.cve?.id) {
        addNotification?.({ type: 'info', title: 'No Vulnerability Context', message: 'Performing general taint analysis.' });
      }

      const useGemini = settings.aiProvider === 'gemini';
      const result = await APIService.generateAITaintAnalysis(
        vulnerability,
        useGemini ? settings.geminiModel : settings.openAiModel,
        settings
      );
      setAnalysis(result.analysis);
      addNotification?.({ type: 'success', title: 'Taint Analysis Complete', message: 'AI generated taint analysis' });
    } catch (error: any) {
      addNotification?.({ type: 'error', title: 'Analysis Failed', message: error.message || 'Failed to generate analysis' });
    } finally {
      setLoadingTaint(false);
    }
  }, [vulnerability, settings, addNotification]);

  useEffect(() => {
    if (activeTab === 'rag') {
      fetchRagDocuments();
    }
  }, [activeTab, fetchRagDocuments]);

  const TabButton = ({ tab, label, icon: Icon }: { tab: 'rag' | 'taint', label: string, icon: React.ElementType }) => (
    <button
      onClick={() => setActiveTab(tab)}
      style={{
        ...styles.button,
        padding: '12px 24px',
        borderBottom: activeTab === tab ? `3px solid ${COLORS.blue}` : '3px solid transparent',
        color: activeTab === tab ? (settings.darkMode ? COLORS.dark.primaryText : COLORS.light.primaryText) : (settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText),
        background: 'none',
        borderRadius: 0,
      }}
    >
      <Icon size={18} style={{ marginRight: '8px' }} />
      {label}
    </button>
  );

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.7)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1001,
    }}>
      <div style={{
        ...styles.card,
        width: '90%', maxWidth: '1280px', height: '90vh',
        display: 'flex', flexDirection: 'column', position: 'relative',
      }}>
        <button
          onClick={onClose}
          style={{
            position: 'absolute', top: '16px', right: '16px',
            background: 'none', border: 'none', cursor: 'pointer',
            color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
          }}
          aria-label="Close Taint Analysis"
        >
          <X size={24} />
        </button>
        <h2 style={{ ...styles.title, margin: '24px 0', textAlign: 'center', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px' }}>
          <Search size={28} />
          Taint Analysis
        </h2>

        <div style={{ display: 'flex', borderBottom: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`, padding: '0 24px' }}>
          <TabButton tab="rag" label="RAG Documents" icon={Database} />
          <TabButton tab="taint" label="Taint Analysis" icon={Brain} />
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: '24px' }}>
          {activeTab === 'rag' && (
            <div>
              <h3 style={styles.subtitle}>RAG Documents Analysis</h3>
              {loadingRag ? (
                <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '200px' }}>
                  <Loader2 size={32} style={{ animation: 'spin 1s linear infinite' }} />
                </div>
              ) : (
                <pre style={{
                  background: settings.darkMode ? COLORS.dark.background : COLORS.light.background,
                  border: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`,
                  borderRadius: '8px', padding: '16px', maxHeight: '60vh',
                  overflowY: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                  fontSize: '0.85rem',
                }}>
                  {ragDocuments.length > 0 ? JSON.stringify(ragDocuments, null, 2) : 'No RAG documents found.'}
                </pre>
              )}
            </div>
          )}
          {activeTab === 'taint' && (
            <div>
              <div style={{ textAlign: 'center', marginBottom: '16px' }}>
                <button
                  style={{ ...styles.button, ...styles.buttonPrimary, padding: '12px 24px', opacity: loadingTaint ? 0.7 : 1 }}
                  onClick={generateTaintAnalysis}
                  disabled={loadingTaint}
                >
                  {loadingTaint ? (
                    <>
                      <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> Generating Taint Analysis...
                    </>
                  ) : (
                    <>
                      <Brain size={16} /> Generate Taint Analysis
                    </>
                  )}
                </button>
              </div>
              {analysis ? (
                <div style={{ ...styles.card, fontSize: '0.95rem', lineHeight: '1.7', whiteSpace: 'pre-wrap', background: settings.darkMode ? COLORS.dark.background : COLORS.light.background }}>
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{analysis}</ReactMarkdown>
                </div>
              ) : !loadingTaint && (
                <div style={{ textAlign: 'center', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                  <p>Click "Generate Taint Analysis" to begin.</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default TaintAnalysisPage;
