import React, { useState, useCallback, useContext, useEffect, useRef } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Send, Bot, User, AlertCircle, Search } from 'lucide-react';
import { AppContext } from '../contexts/AppContext';
import { UserAssistantAgent, CybersecurityAgent } from '../agents';
import { utils } from '../utils/helpers';
import { createStyles } from '../utils/styles';
import { COLORS } from '../utils/constants';

interface Message {
  id: string;
  text: string;
  sender: 'user' | 'bot' | 'system';
  data?: any;
  error?: boolean;
}

interface ChatInterfaceProps {
  initialCveId?: string | null;
  bulkAnalysisResults?: Array<{ cveId: string; data?: any; error?: string }>;
}

const ChatInterface: React.FC<ChatInterfaceProps> = ({ initialCveId, bulkAnalysisResults = [] }) => {
  const { settings, addNotification } = useContext(AppContext);
  const styles = createStyles(settings.darkMode);

  const [agent, setAgent] = useState<UserAssistantAgent | CybersecurityAgent | null>(null);
  const [agentType, setAgentType] = useState<'userAssistant' | 'cybersecurity'>('userAssistant');
  const [inputMessage, setInputMessage] = useState<string>('');
  const [chatHistory, setChatHistory] = useState<Message[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  const chatContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (settings) {
      if (agentType === 'userAssistant') {
        setAgent(new UserAssistantAgent(settings));
      } else {
        setAgent(new CybersecurityAgent(settings));
      }
    }
  }, [settings, agentType]);

  useEffect(() => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
    }
  }, [chatHistory]);

  useEffect(() => {
    if (agent && initialCveId) {
      const systemMessage = agent.setContextualCVE(initialCveId);
      if (systemMessage) {
        setChatHistory(prev => [...prev, systemMessage]);
      }
    }
  }, [initialCveId, agent]);

  useEffect(() => {
    if (agent && agent.setBulkAnalysisResults) {
      agent.setBulkAnalysisResults(bulkAnalysisResults);
    }
  }, [agent, bulkAnalysisResults]);

  const handleSendMessage = useCallback(async () => {
    if (!inputMessage.trim() || !agent) return;

    const userMessage: Message = {
      id: `user-${Date.now()}`,
      text: inputMessage,
      sender: 'user',
    };
    setChatHistory(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsLoading(true);

    try {
      const botResponse = await agent.handleQuery(inputMessage);
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
  }, [inputMessage, agent, addNotification]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: styles.card.background }}>
      <header style={{ padding: '16px', borderBottom: styles.border, background: settings.darkMode ? COLORS.dark.surface : COLORS.light.surface }}>
        <h2 style={{ ...styles.title, margin: 0, fontSize: '1.25rem', textAlign: 'center' }}>
          AI Chat Assistant
        </h2>
      </header>

      <div ref={chatContainerRef} style={{ flexGrow: 1, padding: '16px', overflowY: 'auto' }}>
        {chatHistory.map((msg) => (
          <div key={msg.id} style={{ marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', flexDirection: msg.sender === 'user' ? 'row-reverse' : 'row' }}>
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '50%',
                backgroundColor: msg.sender === 'user' ? COLORS.green : COLORS.blue,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'white',
                flexShrink: 0
              }}>
                {msg.sender === 'user' ? <User size={18} /> : <Bot size={18} />}
              </div>
              <div style={{
                padding: '12px 16px',
                borderRadius: '12px',
                backgroundColor: msg.sender === 'user' ? (settings.darkMode ? '#22c55e20' : '#dcfce7') : (settings.darkMode ? '#3b82f620' : '#dbeafe'),
                color: styles.app.color,
                maxWidth: '80%'
              }}>
                {msg.sender === 'bot' ? (
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{msg.text}</ReactMarkdown>
                ) : (
                  msg.text
                )}
              </div>
            </div>
          </div>
        ))}
        {isLoading && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ width: '32px', height: '32px', borderRadius: '50%', backgroundColor: COLORS.blue, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white' }}>
              <Bot size={18} />
            </div>
            <div style={{ padding: '12px 16px', borderRadius: '12px', backgroundColor: settings.darkMode ? '#3b82f620' : '#dbeafe', color: styles.app.color }}>
              Thinking...
            </div>
          </div>
        )}
      </div>

      <footer style={{ padding: '16px', borderTop: styles.border }}>
        <div style={{ display: 'flex', gap: '8px' }}>
          <input
            type="text"
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            placeholder="Ask a question..."
            style={{ ...styles.input, flexGrow: 1 }}
            onKeyPress={(e) => e.key === 'Enter' && !isLoading && handleSendMessage()}
            disabled={isLoading || !agent}
          />
          <button
            onClick={handleSendMessage}
            style={{ ...styles.button, ...styles.buttonPrimary }}
            disabled={isLoading || !inputMessage.trim() || !agent}
          >
            <Send size={18} />
          </button>
        </div>
      </footer>
    </div>
  );
};

export default ChatInterface;
