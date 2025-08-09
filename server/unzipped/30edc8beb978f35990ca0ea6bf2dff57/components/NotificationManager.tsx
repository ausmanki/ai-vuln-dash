import { useEffect } from 'react';

const NotificationManager = ({ toastQueue, removeToast }) => {
  useEffect(() => {
    if (toastQueue.length > 0) {
      const timer = setTimeout(() => {
        removeToast(toastQueue[0].id);
      }, 3000);
      return () => clearTimeout(timer);
    }
  }, [toastQueue]);

  return (
    <div className="toast-container">
      {toastQueue.map((toast) => (
        <div key={toast.id} className={`toast ${toast.type}`}>
          {toast.message}
        </div>
      ))}
    </div>
  );
};

export default NotificationManager;
