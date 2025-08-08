import express from 'express';
import fetch from 'node-fetch';
import { getApiKeys, getClientConfig } from './config/apiKeys.js';
import cisaKevProxy from './cisaKevProxy.js';

const { openAiApiKey, googleApiKey } = getApiKeys();
console.log('API Keys Status:');
console.log('- OPENAI_API_KEY:', openAiApiKey ? 'Set' : 'NOT SET');
console.log('- GOOGLE_API_KEY:', googleApiKey ? 'Set' : 'NOT SET');

const app = express();
app.use(express.json({ limit: '10mb' }));

// Enable CORS for development
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

const OPENAI_BASE = 'https://api.openai.com/v1';
const GEMINI_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';

app.use(cisaKevProxy);

app.post('/api/openai', async (req, res) => {
  console.log('OpenAI request received');

  const { openAiApiKey } = getApiKeys();
  if (!openAiApiKey) {
    console.error('OPENAI_API_KEY is not set!');
    return res.status(500).json({ error: 'OpenAI API key not configured' });
  }

  const endpoint = req.query.endpoint || 'chat/completions';
  const url = `${OPENAI_BASE}/${endpoint}`;

  try {
    console.log('Making request to:', url);
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${openAiApiKey}`
      },
      body: JSON.stringify(req.body)
    });

    const text = await resp.text();
    console.log('OpenAI response status:', resp.status);

    if (resp.status === 401) {
      console.error('Authentication failed - check your API key');
    }

    res.status(resp.status).type('application/json').send(text);
  } catch (err) {
    console.error('OpenAI API error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/gemini', async (req, res) => {
  console.log('Gemini request received');

  const { googleApiKey } = getApiKeys();
  if (!googleApiKey) {
    console.error('GEMINI_API_KEY is not set!');
    return res.status(500).json({ error: 'Gemini API key not configured' });
  }

  const model = req.query.model || 'gemini-2.0-flash-exp';
  const action = req.query.action || 'generateContent';
  const url = `${GEMINI_BASE}/${model}:${action}?key=${googleApiKey}`;

  try {
    console.log('Making request to Gemini model:', model);
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body)
    });

    const text = await resp.text();
    console.log('Gemini response status:', resp.status);

    res.status(resp.status).type('application/json').send(text);
  } catch (err) {
    console.error('Gemini API error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/ai-config', (req, res) => {
  res.json(getClientConfig());
});

const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Backend server listening on port ${port}`);
  console.log('Environment check:');
  console.log('- NODE_ENV:', process.env.NODE_ENV || 'development');
  console.log('- Working directory:', process.cwd());
});