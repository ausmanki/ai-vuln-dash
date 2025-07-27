import React, { useState, useEffect, useCallback, useContext, useMemo } from 'react';
import { X, Save } from 'lucide-react';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { COLORS } from '../utils/constants';

const SettingsModal = ({ isOpen, onClose }) => {
  const { settings, setSettings, addNotification } = useContext(AppContext);
  const [localSettings, setLocalSettings] = useState(settings);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);

  useEffect(() => {
    setLocalSettings(settings);
  }, [settings]);

  const handleSave = useCallback(() => {
    setSettings(localSettings);
    addNotification({
      type: 'success',
      title: 'Settings Saved',
      message: 'Configuration updated successfully'
    });
    onClose();
  }, [localSettings, setSettings, addNotification, onClose]);

  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'rgba(0, 0, 0, 0.6)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1050,
      backdropFilter: 'blur(5px)'
    }}>
      <div style={{
        ...styles.card,
        width: '100%',
        maxWidth: '600px',
        maxHeight: '90vh',
        overflowY: 'auto',
        margin: '20px'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '24px',
          paddingBottom: '16px',
          borderBottom: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`
        }}>
          <h3 style={{ fontSize: '1.375rem', fontWeight: '700', margin: 0 }}>
            AI Platform Settings
          </h3>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              cursor: 'pointer',
              padding: 0
            }}
          >
            <X size={24} />
          </button>
        </div>

        <div style={{ display: 'grid', gap: '24px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '1rem', fontWeight: '600', marginBottom: '8px' }}>
              Gemini API Key
            </label>
            <input
              type="text"
              style={{ ...styles.input, cursor: 'not-allowed', opacity: 0.7 }}
              value="Managed on server"
              disabled
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '1rem', fontWeight: '600', marginBottom: '8px' }}>
              Gemini Model
            </label>
            <select
              style={styles.input}
              value={localSettings.geminiModel || 'gemini-2.5-flash'}
              onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiModel: e.target.value }))}
            >
              <option value="gemini-1.5-pro-latest">Gemini 1.5 Pro</option>
              <option value="gemini-1.5-flash-latest">Gemini 1.5 Flash</option>
              <option value="gemini-2.5-pro">Gemini 2.5 Pro</option>
              <option value="gemini-2.5-flash">Gemini 2.5 Flash</option>
              <option value="gemini-2.0-pro">Gemini 2.0 Pro</option>
              <option value="gemini-2.0-flash">Gemini 2.0 Flash</option>
            </select>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '1rem', fontWeight: '600', marginBottom: '8px' }}>
              OpenAI API Key
            </label>
            <input
              type="text"
              style={{ ...styles.input, cursor: 'not-allowed', opacity: 0.7 }}
              value="Managed on server"
              disabled
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '1rem', fontWeight: '600', marginBottom: '8px' }}>
              OpenAI Model
            </label>
            <select
              style={styles.input}
              value={localSettings.openAiModel || 'gpt-4.1'}
              onChange={(e) => setLocalSettings(prev => ({ ...prev, openAiModel: e.target.value }))}
            >
              <option value="gpt-4.1">GPT-4.1</option>
            </select>
          </div>

          <div>
            <label style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              cursor: 'pointer',
              fontSize: '1rem',
              fontWeight: '600'
            }}>
              <input
                type="checkbox"
                checked={localSettings.darkMode || false}
                onChange={(e) => setLocalSettings(prev => ({ ...prev, darkMode: e.target.checked }))}
                style={{ width: '16px', height: '16px', accentColor: COLORS.blue }}
              />
              Dark Mode
            </label>
          </div>

          <div>
            <label style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              cursor: 'pointer',
              fontSize: '1rem',
              fontWeight: '600'
            }}>
              <input
                type="checkbox"
                checked={localSettings.enableRAG !== false}
                onChange={(e) => setLocalSettings(prev => ({ ...prev, enableRAG: e.target.checked }))}
                style={{ width: '16px', height: '16px', accentColor: COLORS.blue }}
              />
              Enable AI-Enhanced Analysis
            </label>
          </div>
        </div>

        <div style={{
          display: 'flex',
          gap: '12px',
          justifyContent: 'flex-end',
          paddingTop: '24px',
          marginTop: '16px',
          borderTop: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`
        }}>
          <button style={{ ...styles.button, ...styles.buttonSecondary }} onClick={onClose}>
            Cancel
          </button>
          <button style={{ ...styles.button, ...styles.buttonPrimary }} onClick={handleSave}>
            <Save size={18} />
            Save Settings
          </button>
        </div>
      </div>
    </div>
  );
};

export default SettingsModal;
