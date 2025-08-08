import React from 'react';

interface CVESectionProps {
  title: string;
  children: React.ReactNode;
}

const CVESection: React.FC<CVESectionProps> = ({ title, children }) => {
  return (
    <div style={{ marginBottom: '24px' }}>
      <h3 style={{ fontSize: '1.25rem', fontWeight: '600', marginBottom: '16px' }}>
        {title}
      </h3>
      {children}
    </div>
  );
};

export default CVESection;
