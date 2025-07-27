import React, { useState, useEffect, useContext, useMemo } from 'react';
import { Clock, Brain, Database, Globe, CheckCircle, AlertTriangle } from 'lucide-react';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { COLORS } from '../utils/constants';

const LoadingComponent = () => {
  const { loadingSteps, settings } = useContext(AppContext);
  const [progress, setProgress] = useState(0);
  const [timeRemaining, setTimeRemaining] = useState(45);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  const allSteps = [
    "Initializing AI analysis pipeline...",
    "Fetching base CVE data from NVD...",
    "Querying FIRST.org for EPSS score...",
    "Checking CISA KEV database...",
    "Initiating AI-powered web search for threat intelligence...",
    "Analyzing vendor advisories and patch information...",
    "Synthesizing data and generating initial assessment...",
    "Performing risk analysis and scoring...",
    "Generating remediation recommendations...",
    "Finalizing report..."
  ];

  useEffect(() => {
    const currentStepIndex = loadingSteps.length > 0 ? allSteps.indexOf(loadingSteps[loadingSteps.length - 1]) + 1 : 0;
    const totalSteps = allSteps.length;
    const currentProgress = Math.min((currentStepIndex / totalSteps) * 100, 98);
    setProgress(currentProgress);

    const estimatedTime = Math.max(45 - (currentStepIndex * 4.5), 5);
    setTimeRemaining(Math.round(estimatedTime));
  }, [loadingSteps, allSteps]);

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
      <div style={{ marginBottom: '32px', width: '100%', maxWidth: '700px' }}>
        <div style={{ position: 'relative', display: 'inline-block' }}>
          <div style={{
            width: '90px',
            height: '90px',
            border: `5px solid ${settings.darkMode ? '#374151' : '#e5e7eb'}`,
            borderTop: `5px solid ${COLORS.blue}`,
            borderRadius: '50%',
            animation: 'spin 1.2s linear infinite',
            margin: '0 auto'
          }} />
          <div style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            fontSize: '1rem',
            fontWeight: '600',
            color: COLORS.blue
          }}>
            {Math.round(progress)}%
          </div>
        </div>

        <div style={{
          width: '100%',
          height: '8px',
          background: settings.darkMode ? '#374151' : '#e5e7eb',
          borderRadius: '4px',
          margin: '24px auto 12px auto',
          overflow: 'hidden'
        }}>
          <div style={{
            width: `${progress}%`,
            height: '100%',
            background: `linear-gradient(90deg, ${COLORS.blue} 0%, ${COLORS.purple} 100%)`,
            borderRadius: '4px',
            transition: 'width 0.5s ease-out'
          }} />
        </div>

        <div style={{
          fontSize: '0.9rem',
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
        fontSize: '1.75rem',
        fontWeight: '700',
        marginBottom: '16px',
        color: settings.darkMode ? '#f1f5f9' : '#0f172a',
        animation: 'pulse 2.5s ease-in-out infinite'
      }}>
        AI-Enhanced Multi-Source Analysis in Progress
      </h2>

      <p style={{
        fontSize: '1.1rem',
        color: settings.darkMode ? '#94a3b8' : '#64748b',
        marginBottom: '32px'
      }}>
        Our AI is discovering and analyzing vulnerability intelligence from multiple security sources...
      </p>

      <div style={{
        ...styles.card,
        width: '100%',
        maxWidth: '700px',
        textAlign: 'left',
        background: settings.darkMode ? '#1e293b' : '#ffffff'
      }}>
        <div style={{
          padding: '16px',
          borderBottom: `1px solid ${settings.darkMode ? '#374151' : '#e5e7eb'}`,
          fontSize: '1rem',
          fontWeight: '600',
          color: settings.darkMode ? '#f1f5f9' : '#0f172a',
          display: 'flex',
          alignItems: 'center',
          gap: '12px'
        }}>
          <Brain size={20} color={COLORS.blue} style={{ animation: 'pulse 2s infinite' }} />
          <span>AI Analysis Progress</span>
        </div>

        <div style={{ padding: '20px' }}>
          {allSteps.map((step, index) => {
            const currentStepIndex = loadingSteps.length > 0 ? allSteps.indexOf(loadingSteps[loadingSteps.length - 1]) : -1;
            const isCompleted = index < currentStepIndex;
            const isActive = index === currentStepIndex;

            return (
              <div key={index} style={{
                marginBottom: '16px',
                fontSize: '0.95rem',
                color: isCompleted
                  ? (settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText)
                  : (isActive ? (settings.darkMode ? COLORS.dark.primaryText : COLORS.light.primaryText) : (settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText)),
                display: 'flex',
                alignItems: 'center',
                gap: '16px',
                opacity: isCompleted ? 0.6 : 1,
                transition: 'all 0.3s ease'
              }}>
                <div>
                  {isCompleted ? (
                    <CheckCircle size={20} color={COLORS.green} />
                  ) : isActive ? (
                    <div style={{
                      width: '20px',
                      height: '20px',
                      border: `3px solid ${COLORS.blue}`,
                      borderTop: '3px solid transparent',
                      borderRadius: '50%',
                      animation: 'spin 1s linear infinite'
                    }} />
                  ) : (
                    <Clock size={20} color={settings.darkMode ? '#475569' : '#94a3b8'} />
                  )}
                </div>
                <span style={{ flex: 1, fontWeight: isActive ? '600' : 'normal' }}>{step}</span>
              </div>
            );
          })}
        </div>

        {loadingSteps.length === 0 && (
          <div style={{
            textAlign: 'center',
            padding: '20px',
            color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText,
            fontStyle: 'italic'
          }}>
            Preparing to analyze...
          </div>
        )}
      </div>
    </div>
  );
};

export default LoadingComponent;
