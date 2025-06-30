import { COLORS } from './constants';
import { utils } from './helpers';

export const createStyles = (darkMode) => {
  const theme = darkMode ? COLORS.dark : COLORS.light;
  const shadow = `0 4px 6px -1px ${theme.shadow}, 0 2px 4px -1px ${theme.shadow}`;

  return {
    app: {
      minHeight: '100vh',
      backgroundColor: theme.background,
      fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      color: theme.primaryText,
      fontSize: '16px',
      lineHeight: '1.6',
    },
    header: {
      background: `linear-gradient(135deg, ${theme.surface} 0%, ${theme.background} 100%)`,
      color: theme.primaryText,
      boxShadow: shadow,
      borderBottom: `1px solid ${theme.border}`
    },
    headerContent: {
      maxWidth: '1536px',
      margin: '0 auto',
      padding: '20px 32px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between'
    },
    title: {
      fontSize: '1.5rem',
      fontWeight: '700',
      margin: 0,
      background: `linear-gradient(135deg, ${COLORS.blue} 0%, ${COLORS.purple} 100%)`,
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      backgroundClip: 'text'
    },
    subtitle: {
      fontSize: '0.9375rem',
      color: theme.secondaryText,
      margin: 0,
      fontWeight: '500'
    },
    button: {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      gap: '8px',
      padding: '12px 20px',
      borderRadius: '8px',
      fontWeight: '600',
      cursor: 'pointer',
      borderWidth: '1px',
      borderStyle: 'solid',
      fontSize: '1rem',
      transition: 'all 0.2s ease-in-out',
      textDecoration: 'none',
      whiteSpace: 'nowrap',
      minHeight: '44px',
    },
    buttonPrimary: {
      background: `linear-gradient(135deg, ${COLORS.blue} 0%, #1d4ed8 100%)`,
      color: 'white',
      borderColor: 'transparent',
      boxShadow: `0 2px 8px rgba(${utils.hexToRgb(COLORS.blue)}, 0.3)`,
    },
    buttonSecondary: {
      background: theme.surface,
      color: theme.primaryText,
      borderColor: theme.border,
    },
    card: {
      background: theme.surface,
      borderRadius: '12px',
      padding: '24px',
      borderWidth: '1px',
      borderStyle: 'solid',
      borderColor: theme.border,
      boxShadow: shadow,
    },
    input: {
      width: '100%',
      padding: '12px 16px',
      borderWidth: '1px',
      borderStyle: 'solid',
      borderColor: theme.border,
      borderRadius: '8px',
      fontSize: '1rem',
      outline: 'none',
      boxSizing: 'border-box',
      background: theme.surface,
      color: theme.primaryText,
      transition: 'border-color 0.2s ease-in-out',
      minHeight: '44px',
    },
    badge: {
      padding: '6px 12px',
      borderRadius: '6px',
      fontSize: '0.8125rem',
      fontWeight: '700',
      display: 'inline-flex',
      alignItems: 'center',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
    },
    badgeCritical: {
      background: 'rgba(239, 68, 68, 0.15)',
      color: COLORS.red,
      borderWidth: '1px',
      borderStyle: 'solid',
      borderColor: 'rgba(239, 68, 68, 0.3)'
    },
    badgeHigh: {
      background: 'rgba(245, 158, 11, 0.15)',
      color: COLORS.yellow,
      borderWidth: '1px',
      borderStyle: 'solid',
      borderColor: 'rgba(245, 158, 11, 0.3)'
    },
    badgeMedium: {
      background: 'rgba(59, 130, 246, 0.15)',
      color: COLORS.blue,
      borderWidth: '1px',
      borderStyle: 'solid',
      borderColor: 'rgba(59, 130, 246, 0.3)'
    },
    badgeLow: {
      background: 'rgba(34, 197, 94, 0.15)',
      color: COLORS.green,
      borderWidth: '1px',
      borderStyle: 'solid',
      borderColor: 'rgba(34, 197, 94, 0.3)'
    },
  };
};
