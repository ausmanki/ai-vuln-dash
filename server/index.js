import express from 'express';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

// Get the directory name in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env from project root (go up one directory from server folder)
const envPath = path.resolve(__dirname, '..', '.env');
const result = dotenv.config({ path: envPath });

// Debug: Check if .env was loaded
if (result.error) {
  console.error('Error loading .env file:', result.error);
  console.error('Looking for .env at:', envPath);
} else {
  console.log('Successfully loaded .env from:', envPath);
  console.log('API Keys Status:');
  console.log('- OPENAI_API_KEY:', process.env.OPENAI_API_KEY ? 'Set (length: ' + process.env.OPENAI_API_KEY.length + ')' : 'NOT SET');
  console.log('- GEMINI_API_KEY:', process.env.GEMINI_API_KEY ? 'Set (length: ' + process.env.GEMINI_API_KEY.length + ')' : 'NOT SET');
}

const app = express();
app.use(express.json({limit: '10mb'}));

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

app.post('/api/openai', async (req, res) => {
  console.log('OpenAI request received');
  
  if (!process.env.OPENAI_API_KEY) {
    console.error('OPENAI_API_KEY is not set!');
    return res.status(500).json({error: 'OpenAI API key not configured'});
  }
  
  const endpoint = req.query.endpoint || 'chat/completions';
  const url = `${OPENAI_BASE}/${endpoint}`;
  
  try {
    console.log('Making request to:', url);
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
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
    res.status(500).json({error: err.message});
  }
});

app.post('/api/gemini', async (req, res) => {
  console.log('Gemini request received');
  
  if (!process.env.GEMINI_API_KEY) {
    console.error('GEMINI_API_KEY is not set!');
    return res.status(500).json({error: 'Gemini API key not configured'});
  }
  
  const model = req.query.model || 'gemini-2.0-flash-exp';
  const action = req.query.action || 'generateContent';
  const url = `${GEMINI_BASE}/${model}:${action}?key=${process.env.GEMINI_API_KEY}`;
  
  try {
    console.log('Making request to Gemini model:', model);
    const resp = await fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(req.body)
    });
    
    const text = await resp.text();
    console.log('Gemini response status:', resp.status);
    
    res.status(resp.status).type('application/json').send(text);
  } catch (err) {
    console.error('Gemini API error:', err);
    res.status(500).json({error: err.message});
  }
});

const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Backend server listening on port ${port}`);
  console.log('Environment check:');
  console.log('- NODE_ENV:', process.env.NODE_ENV || 'development');
  console.log('- Working directory:', process.cwd());
});