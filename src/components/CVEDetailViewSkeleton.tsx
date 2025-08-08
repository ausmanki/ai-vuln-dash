import React from 'react';
import Skeleton from './Skeleton';
import { createStyles } from '../utils/styles';

const CVEDetailViewSkeleton = () => {
  // A dummy settings object for styling. In a real app, this might come from a context.
  const settings = { darkMode: false };
  const styles = createStyles(settings.darkMode);

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 400px', gap: '40px', marginTop: '40px' }}>
      <div style={styles.card}>
        {/* Header Skeleton */}
        <div style={{ marginBottom: '24px', paddingBottom: '24px', borderBottom: '1px solid #e2e8f0' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <Skeleton width="40%" height="2.5rem" />
            <div style={{ display: 'flex', gap: '8px' }}>
              <Skeleton width="80px" height="36px" />
              <Skeleton width="80px" height="36px" />
              <Skeleton width="80px" height="36px" />
            </div>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <Skeleton width="100px" height="24px" />
            <Skeleton width="150px" height="24px" />
          </div>
        </div>

        {/* Tabs Skeleton */}
        <div style={{ display: 'flex', borderBottom: '1px solid #e2e8f0', marginBottom: '24px', gap: '4px' }}>
          <Skeleton width="100px" height="40px" />
          <Skeleton width="120px" height="40px" />
          <Skeleton width="100px" height="40px" />
        </div>

        {/* Content Skeleton */}
        <div>
          {/* Description Skeleton */}
          <Skeleton height="1.5rem" width="30%" style={{ marginBottom: '8px' }} />
          <Skeleton height="6rem" style={{ marginBottom: '24px' }} />

          {/* Key Info Skeleton */}
          <Skeleton height="1.5rem" width="25%" style={{ marginBottom: '8px' }} />
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', marginBottom: '24px' }}>
            <Skeleton height="60px" />
            <Skeleton height="60px" />
            <Skeleton height="60px" />
            <Skeleton height="60px" />
          </div>

          {/* EPSS/KEV Skeletons */}
          <Skeleton height="1.5rem" width="40%" style={{ marginBottom: '8px' }} />
          <Skeleton height="10rem" style={{ marginBottom: '24px' }}/>

          <Skeleton height="1.5rem" width="35%" style={{ marginBottom: '8px' }} />
          <Skeleton height="8rem" />
        </div>
      </div>

      {/* Sidebar Skeleton */}
      <div style={{...styles.card, height: 'fit-content', position: 'sticky', top: '24px'}}>
        <Skeleton height="200px" style={{ marginBottom: '20px' }} />
        <Skeleton height="150px" />
      </div>
    </div>
  );
};

export default CVEDetailViewSkeleton;
