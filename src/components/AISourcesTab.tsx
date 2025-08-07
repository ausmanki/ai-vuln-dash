import React, { useContext, useMemo, useState, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { APIService } from '../services/APIService';
import { Brain, Loader2 } from 'lucide-react';
import { EnhancedVulnerabilityData } from '../types/cveData';

interface AISourcesTabProps {
  vulnerability: EnhancedVulnerabilityData;
}

const AISourcesTab: React.FC<AISourcesTabProps> = ({ vulnerability }) => {
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

  return (
    <div>

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
              <Brain size={16} /> Generate Taint Analysis
            </>
          )}
        </button>
        {!settings.aiProvider && (
          <p style={{ fontSize: '0.8rem', color: settings.darkMode ? '#aaa' : '#555', marginTop: '8px' }}>
            Configure Gemini or OpenAI API key to enable analysis
          </p>
        )}
      </div>

      {analysis && (
        <div style={{ ...styles.card, fontSize: '0.95rem', lineHeight: '1.7', whiteSpace: 'pre-wrap' }}>
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{analysis}</ReactMarkdown>
        </div>
      )}
    </div>
  );
};

export default AISourcesTab;
