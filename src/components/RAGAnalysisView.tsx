import React, { useContext, useMemo, useState, useCallback, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { APIService } from '../services/APIService';
import { Brain, Loader2, X } from 'lucide-react';
import { EnhancedVulnerabilityData } from '../types/cveData';
import { COLORS } from '../utils/constants';

interface RAGAnalysisViewProps {
  vulnerability: EnhancedVulnerabilityData | null;
  onClose: () => void;
}

const RAGAnalysisView: React.FC<RAGAnalysisViewProps> = ({ vulnerability, onClose }) => {
  const { settings, addNotification } = useContext(AppContext);
  const [analysis, setAnalysis] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  const generateTaintAnalysis = useCallback(async () => {
    if (!settings.aiProvider) {
      addNotification?.({ type: 'error', title: 'AI Provider Required', message: 'Configure AI provider in settings' });
      return;
    }
    if (!vulnerability?.cve?.id) {
      addNotification?.({ type: 'error', title: 'Invalid Vulnerability', message: 'Select a vulnerability first' });
      return;
    }
    setLoading(true);
    try {
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
      setLoading(false);
    }
  }, [vulnerability, settings, addNotification]);

  useEffect(() => {
    // Automatically trigger analysis if a vulnerability is present when the view opens
    if (vulnerability) {
      generateTaintAnalysis();
    }
  }, [vulnerability, generateTaintAnalysis]);


  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.5)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1001,
    }}>
      <div style={{
        ...styles.card,
        width: '80%',
        maxWidth: '1024px',
        height: '80vh',
        display: 'flex',
        flexDirection: 'column',
        position: 'relative',
      }}>
        <button
          onClick={onClose}
          style={{
            position: 'absolute',
            top: '16px',
            right: '16px',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
          }}
        >
          <X size={24} />
        </button>
        <h2 style={{ ...styles.title, marginBottom: '24px', textAlign: 'center' }}>
          RAG Taint Analysis
        </h2>

        {!vulnerability ? (
           <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
             <p>No vulnerability selected. Please select a vulnerability from the main page to perform RAG analysis.</p>
           </div>
        ) : (
          <>
            <div style={{ textAlign: 'center', marginBottom: '16px' }}>
              <button
                style={{ ...styles.button, ...styles.buttonPrimary, padding: '12px 24px', opacity: loading ? 0.7 : 1 }}
                onClick={generateTaintAnalysis}
                disabled={loading}
              >
                {loading ? (
                  <>
                    <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> Generating Taint Analysis...
                  </>
                ) : (
                  <>
                    <Brain size={16} /> Re-generate Taint Analysis
                  </>
                )}
              </button>
              {!settings.aiProvider && (
                <p style={{ fontSize: '0.8rem', color: settings.darkMode ? '#aaa' : '#555', marginTop: '8px' }}>
                  Configure Gemini or OpenAI API key to enable analysis
                </p>
              )}
            </div>

            <div style={{ flex: 1, overflowY: 'auto', padding: '0 24px 24px' }}>
                {analysis ? (
                    <div style={{ ...styles.card, fontSize: '0.95rem', lineHeight: '1.7', whiteSpace: 'pre-wrap', background: settings.darkMode ? COLORS.dark.background : COLORS.light.background }}>
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{analysis}</ReactMarkdown>
                    </div>
                ) : !loading && (
                    <div style={{ textAlign: 'center', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                        <p>Click "Generate Taint Analysis" to begin.</p>
                    </div>
                )}
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default RAGAnalysisView;
