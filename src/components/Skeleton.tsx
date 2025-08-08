import React from 'react';
import styles from './Skeleton.module.css';

interface SkeletonProps {
  width?: string | number;
  height?: string | number;
  className?: string;
  style?: React.CSSProperties;
}

const Skeleton: React.FC<SkeletonProps> = ({ width = '100%', height = '1rem', className = '', style = {} }) => {
  return (
    <div
      className={`${styles.skeleton} ${className}`}
      style={{ width, height, ...style }}
    >
      <div className={styles.shimmer}></div>
    </div>
  );
};

export default Skeleton;
