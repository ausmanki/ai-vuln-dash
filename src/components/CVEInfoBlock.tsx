import React from 'react';
import { createStyles } from '../utils/styles';
import { COLORS } from '../utils/constants';

interface CVEInfoBlockProps {
  label: string;
  children: React.ReactNode;
  settings: { darkMode: boolean };
}

const CVEInfoBlock: React.FC<CVEInfoBlockProps> = ({ label, children, settings }) => {
  const styles = createStyles(settings.darkMode);

  return (
    <div style={{
      background: settings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
      padding: '16px',
      borderRadius: '8px',
      border: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`
    }}>
      <h4 style={{ margin: '0 0 8px 0', fontSize: '0.9rem', fontWeight: '600', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
        {label}
      </h4>
      <div style={{ margin: 0, fontSize: '1rem', color: styles.app.color, fontWeight: '500' }}>
        {children}
      </div>
    </div>
  );
};

export default CVEInfoBlock;
