import React, { useContext } from 'react';
import { AppContext } from '../contexts/AppContext';
import { COLORS } from '../utils/constants';

const Footer = () => {
  const { settings } = useContext(AppContext);
  const darkMode = settings?.darkMode;
  const textColor = darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText;
  const bgColor = darkMode ? COLORS.dark.surface : COLORS.light.surface;
  return (
    <footer
      style={{
        textAlign: 'center',
        padding: '16px',
        marginTop: '32px',
        fontSize: '0.75rem',
        background: bgColor,
        color: textColor,
        borderTop: `1px solid ${darkMode ? COLORS.dark.border : COLORS.light.border}`,
      }}
    >
      AI-generated guidance is for informational purposes only. Verify all recommendations against official sources before acting.
    </footer>
  );
};

export default Footer;
