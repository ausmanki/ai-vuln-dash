import React from 'react';
import { ResponsiveContainer, ScatterChart, Scatter, XAxis, YAxis, Tooltip } from 'recharts';

interface ScoreChartProps {
  cvss: number;
  epss: number;
}

const ScoreChart: React.FC<ScoreChartProps> = ({ cvss, epss }) => {
  const data = [{ cvss, epss }];
  return (
    <div style={{ width: '100%', height: 200 }}>
      <ResponsiveContainer>
        <ScatterChart>
          <XAxis type="number" dataKey="cvss" name="CVSS" domain={[0,10]} label={{ value: 'CVSS', position: 'insideBottom', offset: -5 }} />
          <YAxis type="number" dataKey="epss" name="EPSS %" domain={[0,100]} label={{ value: 'EPSS %', angle: -90, position: 'insideLeft' }} />
          <Tooltip cursor={{ strokeDasharray: '3 3' }} />
          <Scatter data={data} fill="#8884d8" />
        </ScatterChart>
      </ResponsiveContainer>
    </div>
  );
};

export default ScoreChart;
