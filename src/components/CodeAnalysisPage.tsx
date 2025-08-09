import React, { useMemo, useContext } from 'react';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { X, Code } from 'lucide-react';
import { COLORS } from '../utils/constants';

interface CodeAnalysisPageProps {
  onClose: () => void;
}

const CodeAnalysisPage: React.FC<CodeAnalysisPageProps> = ({ onClose }) => {
  const { settings } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.7)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1001,
    }}>
      <div style={{
        ...styles.card,
        width: '90%',
        maxWidth: '1280px',
        height: '90vh',
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
          aria-label="Close Code Analysis"
        >
          <X size={24} />
        </button>
        <h2 style={{ ...styles.title, marginBottom: '24px', textAlign: 'center', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px' }}>
          <Code size={28} />
          CVE-Driven Taint Analysis
        </h2>

        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText, textAlign: 'center' }}>
          <p>
            This feature is under development.
            <br />
            Soon, you will be able to upload a codebase to analyze for code-reachable vulnerabilities.
          </p>
        </div>
      </div>
    </div>
  );
};

export default CodeAnalysisPage;
