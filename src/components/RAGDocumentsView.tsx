import React, { useMemo, useContext, useState, useCallback, useEffect } from 'react';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { X, Loader2, Database } from 'lucide-react';
import { COLORS } from '../utils/constants';
import { ragDatabase } from '../db/EnhancedVectorDatabase';

interface RAGDocumentsViewProps {
  onClose: () => void;
}

const RAGDocumentsView: React.FC<RAGDocumentsViewProps> = ({ onClose }) => {
  const { settings, addNotification } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);
  const [ragDocuments, setRagDocuments] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchRagDocuments = useCallback(async () => {
    setLoading(true);
    try {
      await ragDatabase.initialize();
      const docs = ragDatabase.getDocuments();
      setRagDocuments(docs);
    } catch (error) {
      addNotification?.({ type: 'error', title: 'Failed to load RAG documents', message: 'Could not read RAG document data.' });
    } finally {
      setLoading(false);
    }
  }, [addNotification]);

  useEffect(() => {
    fetchRagDocuments();
  }, [fetchRagDocuments]);

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.7)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1001,
    }}>
      <div style={{
        ...styles.card,
        width: '80%', maxWidth: '1024px', height: '80vh',
        display: 'flex', flexDirection: 'column', position: 'relative',
      }}>
        <button
          onClick={onClose}
          style={{
            position: 'absolute', top: '16px', right: '16px',
            background: 'none', border: 'none', cursor: 'pointer',
            color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
          }}
          aria-label="Close RAG Documents View"
        >
          <X size={24} />
        </button>
        <h2 style={{ ...styles.title, margin: '24px 0', textAlign: 'center', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px' }}>
          <Database size={28} />
          RAG Documents
        </h2>
        <div style={{ flex: 1, overflowY: 'auto', padding: '24px' }}>
          {loading ? (
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
      </div>
    </div>
  );
};

export default RAGDocumentsView;
