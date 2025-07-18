import React, { useState, useEffect, useCallback, useContext, useMemo } from 'react';
import { X, Eye, EyeOff, Save } from 'lucide-react';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { COLORS } from '../utils/constants';

const SettingsModal = ({ isOpen, onClose }) => {
  const { settings, setSettings, addNotification } = useContext(AppContext);
  const [localSettings, setLocalSettings] = useState(settings);
  const [showKeys, setShowKeys] = useState({ gemini: false, nvd: false, openai: false });
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
            <div style={{ position: 'relative' }}>
              <input
                type={showKeys.gemini ? 'text' : 'password'}
                style={styles.input}
                placeholder="Enter your Gemini API key"
                value={localSettings.geminiApiKey || ''}
                onChange={(e) => setLocalSettings(prev => ({ ...prev, geminiApiKey: e.target.value }))}
              />
              <button
                style={{
                  position: 'absolute',
                  right: '12px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'transparent',
                  border: 'none',
                  cursor: 'pointer',
                  padding: '4px'
                }}
                onClick={() => setShowKeys(prev => ({ ...prev, gemini: !prev.gemini }))}
              >
                {showKeys.gemini ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
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
            <div style={{ position: 'relative' }}>
              <input
                type={showKeys.openai ? 'text' : 'password'}
                style={styles.input}
                placeholder="Enter your OpenAI API key"
                value={localSettings.openAiApiKey || ''}
                onChange={(e) => setLocalSettings(prev => ({ ...prev, openAiApiKey: e.target.value }))}
              />
              <button
                style={{
                  position: 'absolute',
                  right: '12px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'transparent',
                  border: 'none',
                  cursor: 'pointer',
                  padding: '4px'
                }}
                onClick={() => setShowKeys(prev => ({ ...prev, openai: !prev.openai }))}
              >
                {showKeys.openai ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '1rem', fontWeight: '600', marginBottom: '8px' }}>
              OpenAI Model
            </label>
            <select
              style={styles.input}
              value={localSettings.openAiModel || 'gpt-4o'}
              onChange={(e) => setLocalSettings(prev => ({ ...prev, openAiModel: e.target.value }))}
            >
              <option value="gpt-4o">GPT-4o</option>
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
