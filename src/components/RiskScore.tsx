import React, { useMemo, useContext } from 'react';
import { ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, Tooltip, Legend } from 'recharts';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { COLORS } from '../utils/constants';

interface RiskScoreProps {
  vulnerability: any;
}

const RiskScore: React.FC<RiskScoreProps> = ({ vulnerability }) => {
  const { settings } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  const cvssScore = vulnerability.cve?.cvssV3?.baseScore || vulnerability.cve?.cvssV2?.baseScore || 0;
  const epssScore = (vulnerability.epss?.epssFloat || 0) * 100; // as percentage

  const data = [
    { subject: 'Impact (CVSS)', value: cvssScore * 10, fullMark: 100 },
    { subject: 'Exploitability (EPSS)', value: epssScore, fullMark: 100 },
  ];

  return (
    <div style={{ width: '100%', height: 300 }}>
      <ResponsiveContainer>
        <RadarChart cx="50%" cy="50%" outerRadius="80%" data={data}>
          <PolarGrid />
          <PolarAngleAxis dataKey="subject" />
          <PolarRadiusAxis angle={30} domain={[0, 100]} />
          <Radar name="Risk Profile" dataKey="value" stroke={COLORS.blue} fill={COLORS.blue} fillOpacity={0.6} />
          <Tooltip />
          <Legend />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default RiskScore;
