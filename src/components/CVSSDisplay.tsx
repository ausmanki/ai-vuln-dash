import React, { useMemo, useContext } from 'react';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { utils } from '../utils/helpers';
import { COLORS, CONSTANTS } from '../utils/constants';

const CVSSDisplay = ({ vulnerability }) => {
  const { settings } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);
  const cvssScore = vulnerability.cve?.cvssV3?.baseScore || vulnerability.cve?.cvssV2?.baseScore || 0;
  const severity = utils.getSeverityLevel(cvssScore);
  const color = utils.getSeverityColor(severity);

  return (
    <div style={{ textAlign: 'center', marginBottom: '28px' }}>
      <div style={{
        position: 'relative',
        width: '120px',
        height: '120px',
        margin: '0 auto 16px'
      }}>
        <svg width="120" height="120" viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)' }}>
          <circle
            cx="50" cy="50" r="45"
            fill="none"
            stroke={settings.darkMode ? COLORS.dark.border : COLORS.light.border}
            strokeWidth="8"
          />
          <circle
            cx="50" cy="50" r="45"
            fill="none"
            stroke={color}
            strokeWidth="8"
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
          <div style={{ fontSize: '1.625rem', fontWeight: '700' }}>
            {cvssScore?.toFixed(1) || 'N/A'}
          </div>
          <div style={{ fontSize: '0.75rem', fontWeight: '500' }}>
            CVSS Score
          </div>
        </div>
      </div>

      {vulnerability.epss && (
        <div style={{
          background: `rgba(${utils.hexToRgb(COLORS.purple)}, 0.1)`,
          borderRadius: '8px',
          padding: '8px 12px',
          borderWidth: '1px',
          borderStyle: 'solid',
          borderColor: `rgba(${utils.hexToRgb(COLORS.purple)}, 0.2)`
        }}>
          <div style={{ fontSize: '0.7rem', marginBottom: '4px' }}>
            EPSS Exploitation Probability
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{
              flex: 1,
              height: '4px',
              background: settings.darkMode ? COLORS.dark.border : COLORS.light.border,
              borderRadius: '2px',
              overflow: 'hidden'
            }}>
              <div style={{
                width: `${vulnerability.epss.epssFloat * 100}%`,
                height: '100%',
                background: vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH ? COLORS.red :
                           vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.MEDIUM ? COLORS.yellow : COLORS.green,
                borderRadius: '2px',
                transition: 'width 1s ease-out'
              }} />
            </div>
            <span style={{
              fontSize: '0.75rem',
              fontWeight: '600',
              color: vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH ? COLORS.red :
                     vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.MEDIUM ? COLORS.yellow : COLORS.green
            }}>
              {(vulnerability.epss.epssFloat * 100).toFixed(1)}%
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

export default CVSSDisplay;
