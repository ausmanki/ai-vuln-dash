import React, { useState, useCallback, useContext, useMemo } from 'react';
import { AppContext } from '../contexts/AppContext';
import { APIService } from '../services/APIService';
import { createStyles } from '../utils/styles';
import { COLORS } from '../utils/constants';
import { Brain, Loader2 } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { EnhancedVulnerabilityData } from '../types/cveData';
import { ragDatabase } from '../db/EnhancedVectorDatabase';

interface TaintAnalysisTabProps {
  vulnerability: EnhancedVulnerabilityData;
}

const TaintAnalysisTab: React.FC<TaintAnalysisTabProps> = ({ vulnerability }) => {
  const { settings, addNotification } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);
  const [analysis, setAnalysis] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const generateTaintAnalysis = useCallback(async () => {
    if (!settings.aiProvider) {
      addNotification?.({ type: 'error', title: 'AI Provider Required', message: 'Configure AI provider in settings' });
      return;
    }
    setLoading(true);

    try {
      await ragDatabase.initialize();
      const docs = ragDatabase.getDocuments();
      if (docs.length === 0) {
        addNotification?.({ type: 'info', title: 'Empty RAG', message: 'RAG documents are empty, searching web.' });
        const searchResults = await APIService.performNaturalLanguageSearch('vulnerability taint analysis', settings);
        for (const result of searchResults) {
          await ragDatabase.addDocument(result.content, {
            title: result.title,
            source: result.url,
          });
        }
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
      </div>
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
  );
};

export default TaintAnalysisTab;
