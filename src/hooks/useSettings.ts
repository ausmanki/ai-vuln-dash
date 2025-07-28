import { useState, useEffect } from 'react';

export const useSettings = () => {
  const [settings, setSettings] = useState({
    darkMode: false,
    geminiModel: 'gemini-2.5-flash',
    nvdApiKey: '',
    openAiModel: 'gpt-4.1',
    aiProvider: null as 'openai' | 'gemini' | null,
    enableRAG: true,
    verboseLogs: import.meta.env.MODE === 'development'
  });

  useEffect(() => {
    fetch('/api/ai-config')
      .then(res => res.json())
      .then(cfg => {
        setSettings(prev => ({
          ...prev,
          aiProvider: cfg.provider,
          geminiModel: cfg.geminiModel || prev.geminiModel,
          openAiModel: cfg.openAiModel || prev.openAiModel
        }));
      })
      .catch(err => console.error('Failed to load AI config', err));
  }, []);

  return { settings, setSettings };
};
