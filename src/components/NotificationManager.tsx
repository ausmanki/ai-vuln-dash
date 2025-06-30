import React, { useContext, useMemo } from 'react';
import { CheckCircle, XCircle, AlertTriangle } from 'lucide-react';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { COLORS } from '../utils/constants';

const NotificationManager = () => {
  const { notifications, removeNotification, settings } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  return (
    <div style={{ position: 'fixed', top: '24px', right: '24px', zIndex: 1000 }}>
      {notifications.map((notification) => (
        <div
          key={notification.id}
          style={{
            ...styles.card,
            marginBottom: '12px',
            maxWidth: '400px',
            borderLeft: `4px solid ${
              notification.type === 'success' ? COLORS.green :
              notification.type === 'error' ? COLORS.red : COLORS.yellow
            }`,
            display: 'flex',
            alignItems: 'flex-start',
            gap: '12px',
            cursor: 'pointer'
          }}
          onClick={() => removeNotification(notification.id)}
        >
          {notification.type === 'success' && <CheckCircle size={20} color={COLORS.green} />}
          {notification.type === 'error' && <XCircle size={20} color={COLORS.red} />}
          {notification.type === 'warning' && <AlertTriangle size={20} color={COLORS.yellow} />}
          <div>
            <div style={{ fontWeight: '600', fontSize: '0.95rem' }}>{notification.title}</div>
            <div style={{ fontSize: '0.8rem', color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
              {notification.message}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

export default NotificationManager;
