import React, { useContext, useMemo } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { COLORS } from '../utils/constants';

interface TechnicalBriefProps {
  brief: string | null | undefined;
}

const TechnicalBrief: React.FC<TechnicalBriefProps> = ({ brief }) => {
  const { settings } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  if (!brief || brief.trim().length === 0) {
    return (
      <p style={{ fontSize: '0.875rem', color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
        No technical brief available.
      </p>
    );
  }

  return (
    <div style={{ ...styles.card, fontSize: '0.95rem', lineHeight: '1.7', whiteSpace: 'pre-wrap' }}>
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{brief}</ReactMarkdown>
    </div>
  );
};

export default TechnicalBrief;
