import { useState } from 'react';

export const useSettings = () => {
  const [settings, setSettings] = useState({
    darkMode: false,
    geminiApiKey: '',
    geminiModel: 'gemini-2.5-flash',
    nvdApiKey: '',
    openAiApiKey: '',
    openAiModel: 'gpt-4o',
    enableRAG: true
  });

  return { settings, setSettings };
};
