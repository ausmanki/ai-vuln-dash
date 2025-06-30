import React, { useState, useCallback, useContext, useEffect, useRef } from 'react';
import { Send, Bot, User, AlertCircle, Search } from 'lucide-react';
import { AppContext } from '../contexts/AppContext';
import { UserAssistantAgent } from '../agents/UserAssistantAgent';
import { utils } from '../utils/helpers'; // For CVE validation
import { createStyles } from '../utils/styles';
import { COLORS }_from '../utils/constants';

interface Message {
  id: string;
  text: string;
  sender: 'user' | 'bot' | 'system';
  data?: any; // Optional structured data from bot
  error?: boolean;
}

const ChatInterface: React.FC = () => {
  const { settings, addNotification } = useContext(AppContext);
  const styles = createStyles(settings.darkMode); // Assuming createStyles is memoized or lightweight

  const [agent, setAgent] = useState<UserAssistantAgent | null>(null);
  const [cveId, setCveId] = useState<string>('');
  const [currentCveId, setCurrentCveId] = useState<string>(''); // The CVE ID currently being discussed
  const [inputMessage, setInputMessage] = useState<string>('');
  const [chatHistory, setChatHistory] = useState<Message[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  const chatContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Initialize agent when settings are available
    if (settings) {
      setAgent(new UserAssistantAgent(settings));
    }
  }, [settings]);

  useEffect(() => {
    // Scroll to bottom of chat
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
    }
  }, [chatHistory]);

  const handleSetCveContext = () => {
    if (!utils.validateCVE(cveId)) {
      addNotification({
        type: 'error',
        title: 'Invalid CVE ID',
        message: 'Please enter a valid CVE ID format (e.g., CVE-2023-12345).',
      });
      return;
    }
    setCurrentCveId(cveId.toUpperCase());
    setChatHistory([
      { id: Date.now().toString(), text: `Okay, let's talk about ${cveId.toUpperCase()}. What would you like to know?`, sender: 'system' }
    ]);
    setInputMessage(''); // Clear input for the actual question
  };

  const handleSendMessage = useCallback(async () => {
    if (!inputMessage.trim() || !agent || !currentCveId) return;

    const userMessage: Message = {
      id: `user-${Date.now()}`,
      text: inputMessage,
      sender: 'user',
    };
    setChatHistory(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsLoading(true);

    try {
      const botResponse = await agent.handleQuery(inputMessage, currentCveId);
      const responseMessage: Message = {
        id: `bot-${Date.now()}`,
        text: botResponse.text,
        sender: 'bot',
        data: botResponse.data,
        error: !!botResponse.error,
      };
      setChatHistory(prev => [...prev, responseMessage]);
    } catch (error: any) {
      const errorMessage: Message = {
        id: `error-${Date.now()}`,
        text: `An unexpected error occurred: ${error.message}`,
        sender: 'system',
        error: true,
      };
      setChatHistory(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  }, [inputMessage, agent, currentCveId, addNotification]);


  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 200px)', // Adjust as needed
        maxWidth: '800px', margin: '20px auto', border: styles.border, borderRadius: '8px', background: styles.card.background }}>
      <div style={{ padding: '16px', borderBottom: styles.border, background: settings.darkMode ? COLORS.dark.surface : COLORS.light.surface, borderRadius: '8px 8px 0 0' }}>
        <h2 style={{ ...styles.title, margin: 0, fontSize: '1.25rem', textAlign: 'center' }}>
          CVE Smart Assistant
        </h2>
        {!currentCveId ? (
          <div style={{ marginTop: '16px', display: 'flex', gap: '8px' }}>
            <input
              type="text"
              value={cveId}
              onChange={(e) => setCveId(e.target.value)}
              placeholder="Enter CVE ID to discuss (e.g., CVE-2023-1234)"
              style={{ ...styles.input, flexGrow: 1, minHeight: '48px' }}
              onKeyPress={(e) => e.key === 'Enter' && handleSetCveContext()}
            />
            <button onClick={handleSetCveContext} style={{ ...styles.button, ...styles.buttonPrimary, minHeight: '48px' }} disabled={!cveId.trim()}>
              <Search size={18} /> Set CVE
            </button>
          </div>
        ) : (
          <div style={{ textAlign: 'center', marginTop: '8px', fontSize: '0.9rem', color: styles.secondaryText.color }}>
            Talking about: <strong>{currentCveId}</strong>
            <button
              onClick={() => { setCurrentCveId(''); setCveId(''); setChatHistory([]); }}
              style={{ ...styles.button, ...styles.buttonLink, marginLeft: '12px', fontSize: '0.85rem' }}
            >
              Change CVE
            </button>
          </div>
        )}
      </div>

      <div ref={chatContainerRef} style={{ flexGrow: 1, padding: '16px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {chatHistory.map((msg) => (
          <div
            key={msg.id}
            style={{
              alignSelf: msg.sender === 'user' ? 'flex-end' : 'flex-start',
              maxWidth: '75%',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', flexDirection: msg.sender === 'user' ? 'row-reverse' : 'row' }}>
              {msg.sender === 'bot' && <Bot size={24} color={COLORS.blue} style={{ flexShrink: 0, marginTop: '4px' }} />}
              {msg.sender === 'user' && <User size={24} color={COLORS.green} style={{ flexShrink: 0, marginTop: '4px' }} />}
              {msg.sender === 'system' && <AlertCircle size={24} color={msg.error ? COLORS.red : COLORS.yellow} style={{ flexShrink: 0, marginTop: '4px' }} />}

              <div
                style={{
                  background: msg.sender === 'user'
                    ? (settings.darkMode ? `rgba(${utils.hexToRgb(COLORS.green)}, 0.2)` : `rgba(${utils.hexToRgb(COLORS.green)}, 0.1)`)
                    : msg.sender === 'bot'
                    ? (settings.darkMode ? `rgba(${utils.hexToRgb(COLORS.blue)}, 0.2)` : `rgba(${utils.hexToRgb(COLORS.blue)}, 0.1)`)
                    : (settings.darkMode ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.15)` : `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)`),
                  padding: '10px 14px',
                  borderRadius: '12px',
                  border: msg.error ? `1px solid ${COLORS.red}`: 'none',
                  color: styles.primaryText.color,
                  whiteSpace: 'pre-wrap', // To respect newlines from bot
                  overflowWrap: 'break-word',
                }}
              >
                {msg.text}
              </div>
            </div>
             {msg.sender === 'bot' && msg.data && (
              <div style={{ fontSize: '0.8rem', color: styles.tertiaryText?.color || '#888', marginLeft: '32px', marginTop: '4px' }}>
                {/* Potentially render some structured data here, or offer actions */}
                {/* Example: <button onClick={() => alert(JSON.stringify(msg.data))}>View Raw Data</button> */}
              </div>
            )}
          </div>
        ))}
        {isLoading && (
          <div style={{ alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Bot size={24} color={COLORS.blue} />
            <div style={{ background: settings.darkMode ? `rgba(${utils.hexToRgb(COLORS.blue)}, 0.2)` : `rgba(${utils.hexToRgb(COLORS.blue)}, 0.1)`, padding: '10px 14px', borderRadius: '12px', color: styles.primaryText.color }}>
              Thinking...
            </div>
          </div>
        )}
      </div>

      <div style={{ padding: '16px', borderTop: styles.border, display: 'flex', gap: '8px' }}>
        <input
          type="text"
          value={inputMessage}
          onChange={(e) => setInputMessage(e.target.value)}
          placeholder={currentCveId ? `Ask about ${currentCveId}...` : "First, set a CVE ID above."}
          style={{ ...styles.input, flexGrow: 1, minHeight: '48px' }}
          onKeyPress={(e) => e.key === 'Enter' && !isLoading && handleSendMessage()}
          disabled={isLoading || !currentCveId || !agent}
        />
        <button
          onClick={handleSendMessage}
          style={{ ...styles.button, ...styles.buttonPrimary, minHeight: '48px' }}
          disabled={isLoading || !inputMessage.trim() || !currentCveId || !agent}
        >
          <Send size={18} />
        </button>
      </div>
    </div>
  );
};

export default ChatInterface;
