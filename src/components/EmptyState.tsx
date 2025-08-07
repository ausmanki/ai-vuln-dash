import React, { useContext, useMemo } from 'react';
import { Brain, Database, Globe, AlertTriangle } from 'lucide-react';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { COLORS } from '../utils/constants';
import { utils } from '../utils/helpers';
const EmptyState = () => {
  const { settings } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  return (
    <div style={{
      textAlign: 'center',
      padding: '64px 32px',
      color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText
    }}>
      <div style={{
        marginBottom: '28px',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        gap: '16px'
      }}>
        <Brain size={56} color={settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText} />
        <Database size={40} color={settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText} />
        <Globe size={44} color={settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText} />
      </div>

      <h3 style={{
        fontSize: '1.375rem',
        fontWeight: '600',
        marginBottom: '16px',
        color: settings.darkMode ? COLORS.dark.primaryText : COLORS.light.primaryText
      }}>
        AI-Enhanced Intelligence Platform Ready
      </h3>

      <p style={{
        fontSize: '0.95rem',
        marginBottom: '12px',
        color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
        lineHeight: 1.6,
        maxWidth: '600px',
        margin: '0 auto 12px auto'
      }}>
        Enter a CVE ID to begin comprehensive AI-powered vulnerability analysis with multi-source discovery and contextual knowledge retrieval.
      </p>

      <p style={{
        fontSize: '0.875rem',
        color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText,
        marginBottom: '28px',
        maxWidth: '600px',
        margin: '0 auto 28px auto'
      }}>
        Real-time intelligence enhanced with semantic search, security sources, and domain expertise.
      </p>

      {!settings.aiProvider && (
        <div style={{
          marginTop: '32px',
          padding: '16px 20px',
          background: settings.darkMode
            ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)`
            : `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.07)`,
          borderWidth: '1px',
          borderStyle: 'solid',
          borderColor: `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.3)`,
          borderRadius: '12px',
          maxWidth: '550px',
          margin: '32px auto 0'
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            marginBottom: '10px'
          }}>
            <AlertTriangle size={20} color={COLORS.yellow} />
            <span style={{
              fontWeight: '600',
              color: COLORS.yellow,
              fontSize: '0.95rem'
            }}>
              AI Configuration Required
            </span>
          </div>
          <p style={{
            fontSize: '0.875rem',
            margin: 0,
            color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
            lineHeight: 1.5
          }}>
            Configure AI provider settings to enable AI-enhanced multi-source vulnerability analysis.
          </p>
        </div>
      )}
    </div>
  );
};

export default EmptyState;
