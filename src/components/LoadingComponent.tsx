import React, { useState, useEffect, useContext, useMemo } from 'react';
import { Clock, Brain, Database, Globe } from 'lucide-react';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { COLORS } from '../utils/constants';

const LoadingComponent = () => {
  const { loadingSteps, settings } = useContext(AppContext);
  const [progress, setProgress] = useState(0);
  const [timeRemaining, setTimeRemaining] = useState(30);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  useEffect(() => {
    const totalSteps = 10; // Increased for multi-source analysis
    const currentProgress = Math.min((loadingSteps.length / totalSteps) * 100, 95);
    setProgress(currentProgress);

    const estimatedTime = Math.max(45 - (loadingSteps.length * 5), 5); // More realistic timing
    setTimeRemaining(estimatedTime);
  }, [loadingSteps.length]);

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '64px 32px',
      textAlign: 'center',
      color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
    }}>
      <div style={{ marginBottom: '32px' }}>
        <div style={{ position: 'relative', display: 'inline-block' }}>
          <div style={{
            width: '80px',
            height: '80px',
            border: `4px solid ${settings.darkMode ? '#374151' : '#e5e7eb'}`,
            borderTop: `4px solid ${COLORS.blue}`,
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto'
          }} />
          <div style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            fontSize: '0.75rem',
            fontWeight: '600',
            color: COLORS.blue
          }}>
            {Math.round(progress)}%
          </div>
        </div>

        <div style={{
          width: '200px',
          height: '6px',
          background: settings.darkMode ? '#374151' : '#e5e7eb',
          borderRadius: '3px',
          margin: '16px auto 8px auto',
          overflow: 'hidden'
        }}>
          <div style={{
            width: `${progress}%`,
            height: '100%',
            background: `linear-gradient(90deg, ${COLORS.blue} 0%, ${COLORS.purple} 100%)`,
            borderRadius: '3px',
            transition: 'width 0.5s ease-out'
          }} />
        </div>

        <div style={{
          fontSize: '0.8rem',
          color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '6px'
        }}>
          <Clock size={14} />
          Estimated: ~{timeRemaining} seconds remaining
        </div>
      </div>

      <h2 style={{
        fontSize: '1.5rem',
        fontWeight: '700',
        marginBottom: '16px',
        color: settings.darkMode ? '#f1f5f9' : '#0f172a',
        animation: 'pulse 2s ease-in-out infinite'
      }}>
        AI-Enhanced Multi-Source Analysis
      </h2>

      <p style={{
        fontSize: '1rem',
        color: settings.darkMode ? '#94a3b8' : '#64748b',
        marginBottom: '32px'
      }}>
        AI is discovering and analyzing vulnerability intelligence from security sources...
      </p>

      <div style={{
        ...styles.card,
        maxWidth: '700px',
        textAlign: 'left',
        background: settings.darkMode ? '#1e293b' : '#ffffff'
      }}>
        <div style={{
          marginBottom: '16px',
          fontSize: '0.9rem',
          fontWeight: '600',
          color: settings.darkMode ? '#f1f5f9' : '#0f172a',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <Brain size={18} color="#3b82f6" style={{ animation: 'pulse 2s infinite' }} />
          <Database size={16} color="#8b5cf6" />
          <Globe size={16} color="#22c55e" />
          Multi-Source AI Analysis Progress:
        </div>

        {loadingSteps.map((step, index) => (
          <div key={index} style={{
            marginBottom: '12px',
            fontSize: '0.875rem',
            color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
            display: 'flex',
            alignItems: 'center',
            gap: '12px'
          }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: index === loadingSteps.length - 1 ? COLORS.blue : COLORS.green,
              flexShrink: 0,
              animation: index === loadingSteps.length - 1 ? 'pulse 1s ease-in-out infinite' : 'none'
            }} />
            <span style={{ flex: 1 }}>{step}</span>
            {index === loadingSteps.length - 1 && (
              <div style={{
                width: '16px',
                height: '16px',
                border: `2px solid ${COLORS.blue}`,
                borderTop: '2px solid transparent',
                borderRadius: '50%',
                animation: 'spin 1s linear infinite'
              }} />
            )}
          </div>
        ))}

        {loadingSteps.length === 0 && (
          <div style={{
            textAlign: 'center',
            padding: '20px',
            color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText,
            fontStyle: 'italic'
          }}>
            Initializing AI analysis pipeline...
          </div>
        )}
      </div>
    </div>
  );
};

export default LoadingComponent;
