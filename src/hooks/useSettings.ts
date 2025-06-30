import { useState } from 'react';

export const useSettings = () => {
  const [settings, setSettings] = useState({
    darkMode: false,
    geminiApiKey: '',
    geminiModel: 'gemini-2.5-flash',
    nvdApiKey: '',
    enableRAG: true
  });

  return { settings, setSettings };
};
