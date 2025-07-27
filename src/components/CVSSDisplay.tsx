import React, { useMemo, useContext } from 'react';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { utils } from '../utils/helpers';
import { COLORS } from '../utils/constants';

const CVSSDisplay = ({ vulnerability }) => {
  const { settings } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);
  const cvssScore = vulnerability.cve?.cvssV3?.baseScore || vulnerability.cve?.cvssV2?.baseScore || 0;
  const severity = utils.getSeverityLevel(cvssScore);
  const color = utils.getSeverityColor(severity);

  return (
    <div style={{ textAlign: 'center' }}>
      <div style={{
        position: 'relative',
        width: '150px',
        height: '150px',
        margin: '0 auto 16px'
      }}>
        <svg width="150" height="150" viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)' }}>
          <circle
            cx="50" cy="50" r="45"
            fill="none"
            stroke={settings.darkMode ? COLORS.dark.border : COLORS.light.border}
            strokeWidth="10"
          />
          <circle
            cx="50" cy="50" r="45"
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${(cvssScore / 10) * 283} 283`}
            style={{ transition: 'stroke-dasharray 1.5s ease' }}
          />
        </svg>

        <div style={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '2rem', fontWeight: '700' }}>
            {cvssScore?.toFixed(1) || 'N/A'}
          </div>
          <div style={{ fontSize: '0.875rem', fontWeight: '500' }}>
            CVSS Score
          </div>
        </div>
      </div>

      <div style={{
        display: 'inline-block',
        padding: '8px 16px',
        borderRadius: '8px',
        fontSize: '1rem',
        fontWeight: '700',
        background: `${color}20`,
        color: color,
        border: `1px solid ${color}30`
      }}>
        {severity}
      </div>
    </div>
  );
};

export default CVSSDisplay;
