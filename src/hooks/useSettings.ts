import { useState } from 'react';

export const useSettings = () => {
  const [settings, setSettings] = useState({
    darkMode: false,
    geminiApiKey: 'server',
    geminiModel: 'gemini-2.5-flash',
    nvdApiKey: '',
    openAiApiKey: 'server',
    openAiModel: 'gpt-4.1',
    enableRAG: true,
    verboseLogs: import.meta.env.MODE === "development"
  });

  return { settings, setSettings };
};
