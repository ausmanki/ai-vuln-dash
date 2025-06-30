import React, { useState, useCallback, useContext, useEffect, useRef } from 'react';
import ReactMarkdown from 'react-markdown'; // Added for Markdown rendering
import remarkGfm from 'remark-gfm'; // Added for GitHub Flavored Markdown (tables, etc.)
import { Send, Bot, User, AlertCircle, Search } from 'lucide-react';
import { AppContext } from '../contexts/AppContext';
import { UserAssistantAgent } from '../agents/UserAssistantAgent';
import { utils } from '../utils/helpers'; // For CVE validation
import { createStyles } from '../utils/styles';
import { COLORS } from '../utils/constants';

interface Message {
  id: string;
  text: string;
  sender: 'user' | 'bot' | 'system';
  data?: any; // Optional structured data from bot
  error?: boolean;
}

interface ChatInterfaceProps {
  initialCveId?: string | null;
}

const ChatInterface: React.FC<ChatInterfaceProps> = ({ initialCveId }) => {
  const { settings, addNotification } = useContext(AppContext);
  const styles = createStyles(settings.darkMode); // Assuming createStyles is memoized or lightweight

  const [agent, setAgent] = useState<UserAssistantAgent | null>(null);
  // const [cveId, setCveId] = useState<string>(''); // No longer needed for separate input
  // const [currentCveId, setCurrentCveId] = useState<string>(''); // Agent manages context
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

  useEffect(() => {
    if (agent && initialCveId) {
      const systemMessage = agent.setContextualCVE(initialCveId);
      if (systemMessage) {
        // Check if the last message is already this system message to avoid duplicates if prop doesn't change but effect re-runs
        setChatHistory(prev => {
          if (prev.length > 0 && prev[prev.length -1].text === systemMessage.text && prev[prev.length-1].sender === 'system') {
            return prev;
          }
          return [...prev, systemMessage];
        });
      }
    }
    // Intentionally not adding chatHistory to dependencies to avoid loop with setChatHistory
    // This effect should primarily react to initialCveId or agent availability.
  }, [initialCveId, agent]);


  // const handleSetCveContext = () => { // Removed: Agent handles CVE context
  //   if (!utils.validateCVE(cveId)) {
  //     addNotification({
  //       type: 'error',
  //       title: 'Invalid CVE ID',
  //       message: 'Please enter a valid CVE ID format (e.g., CVE-2023-12345).',
  //     });
  //     return;
  //   }
  //   setCurrentCveId(cveId.toUpperCase());
  //   setChatHistory([
  //     { id: Date.now().toString(), text: `Okay, let's talk about ${cveId.toUpperCase()}. What would you like to know?`, sender: 'system' }
  //   ]);
  //   setInputMessage(''); // Clear input for the actual question
  // };

  const handleSendMessage = useCallback(async () => {
    if (!inputMessage.trim() || !agent) return; // currentCveId check removed

    const userMessage: Message = {
      id: `user-${Date.now()}`,
      text: inputMessage,
      sender: 'user',
    };
    setChatHistory(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsLoading(true);

    try {
      const botResponse = await agent.handleQuery(inputMessage); // currentCveId removed
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
  }, [inputMessage, agent, addNotification]); // currentCveId removed from dependencies


  return (
    <div style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%', // Changed from calc(100vh - 200px)
        width: '100%', // Ensure it fills its new container
        border: styles.border, // This might be redundant if App.tsx wrapper has border
        borderRadius: 'inherit', // Inherit border radius from App.tsx wrapper
        background: styles.card.background
      }}>
      <div style={{ padding: '16px', borderBottom: styles.border, background: settings.darkMode ? COLORS.dark.surface : COLORS.light.surface, borderRadius: 'inherit inherit 0 0' /* Adjust to inherit */ }}>
        <h2 style={{ ...styles.title, margin: 0, fontSize: '1.25rem', textAlign: 'center' }}>
          CVE Smart Assistant
        </h2>
        {/* Removed CVE ID input section; context is handled by agent via natural language queries */}
        <div style={{ textAlign: 'center', marginTop: '8px', fontSize: '0.9rem', color: styles.subtitle.color }}>
          Ask me about a CVE (e.g., "Tell me about CVE-2023-1234")
        </div>
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
                    : msg.error // System message with error
                    ? (settings.darkMode ? `rgba(${utils.hexToRgb(COLORS.red)}, 0.25)` : `rgba(${utils.hexToRgb(COLORS.red)}, 0.15)`)
                    : (settings.darkMode ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.15)` : `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)`), // System message, non-error
                  padding: '10px 14px',
                  borderRadius: '12px',
                  border: msg.error ? `1px solid ${settings.darkMode ? COLORS.red : utils.shadeColor(COLORS.red, -20)}`: 'none',
                  color: msg.error ? (settings.darkMode ? COLORS.light.primaryText : COLORS.dark.primaryText) : styles.app.color,
                  whiteSpace: 'pre-wrap', // To respect newlines from bot
                  overflowWrap: 'break-word',
                }}
              >
                {msg.sender === 'bot' ? (
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{msg.text}</ReactMarkdown>
                ) : (
                  msg.text
                )}
              </div>
            </div>
             {msg.sender === 'bot' && msg.data && (
              <div style={{ fontSize: '0.8rem', color: (settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText) || '#888', marginLeft: '32px', marginTop: '4px' }}>
                {/* Potentially render some structured data here, or offer actions */}
                {/* Example: <button onClick={() => alert(JSON.stringify(msg.data))}>View Raw Data</button> */}
              </div>
            )}
          </div>
        ))}
        {isLoading && (
          <div style={{ alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Bot size={24} color={COLORS.blue} />
            <div style={{ background: settings.darkMode ? `rgba(${utils.hexToRgb(COLORS.blue)}, 0.2)` : `rgba(${utils.hexToRgb(COLORS.blue)}, 0.1)`, padding: '10px 14px', borderRadius: '12px', color: styles.app.color }}> {/* Changed from styles.primaryText.color */}
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
          placeholder="Ask about a CVE or a previous topic..."
          style={{ ...styles.input, flexGrow: 1, minHeight: '48px' }}
          onKeyPress={(e) => e.key === 'Enter' && !isLoading && handleSendMessage()}
          disabled={isLoading || !agent}
        />
        <button
          onClick={handleSendMessage}
          style={{ ...styles.button, ...styles.buttonPrimary, minHeight: '48px' }}
          disabled={isLoading || !inputMessage.trim() || !agent}
        >
          <Send size={18} />
        </button>
      </div>
    </div>
  );
};

export default ChatInterface;
