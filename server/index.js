import express from 'express';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import NodeCache from 'node-cache';

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

const apiCache = new NodeCache({ stdTTL: 3600 }); // Cache for 1 hour

const OPENAI_BASE = 'https://api.openai.com/v1';
const GEMINI_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';

app.post('/api/openai', async (req, res, next) => {
  console.log('OpenAI request received');

  const cacheKey = JSON.stringify(req.body);
  if (apiCache.has(cacheKey)) {
    console.log('Returning cached response for OpenAI');
    return res.status(200).type('application/json').send(apiCache.get(cacheKey));
  }
  
  if (!process.env.OPENAI_API_KEY) {
    return next(new Error('OPENAI_API_KEY is not set!'));
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
    
    if (!resp.ok) {
      return next(new Error(`OpenAI API error: ${resp.status} - ${text}`));
    }
    
    apiCache.set(cacheKey, text);
    res.status(resp.status).type('application/json').send(text);
  } catch (err) {
    next(err);
  }
});

app.post('/api/gemini', async (req, res, next) => {
  console.log('Gemini request received');

  const cacheKey = JSON.stringify(req.body);
  if (apiCache.has(cacheKey)) {
    console.log('Returning cached response for Gemini');
    return res.status(200).type('application/json').send(apiCache.get(cacheKey));
  }
  
  if (!process.env.GEMINI_API_KEY) {
    return next(new Error('GEMINI_API_KEY is not set!'));
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

    if (!resp.ok) {
      return next(new Error(`Gemini API error: ${resp.status} - ${text}`));
    }
    
    apiCache.set(cacheKey, text);
    res.status(resp.status).type('application/json').send(text);
  } catch (err) {
    next(err);
  }
});

// Centralized error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: err.message || 'Something went wrong!' });
});

const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Backend server listening on port ${port}`);
  console.log('Environment check:');
  console.log('- NODE_ENV:', process.env.NODE_ENV || 'development');
  console.log('- Working directory:', process.cwd());
});