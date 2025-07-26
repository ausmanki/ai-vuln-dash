const express = require('express');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const app = express();
app.use(express.json({limit: '10mb'}));

const OPENAI_BASE = 'https://api.openai.com/v1';
const GEMINI_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';

app.post('/api/openai', async (req, res) => {
  const endpoint = req.query.endpoint || 'chat/completions';
  const url = `${OPENAI_BASE}/${endpoint}`;
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
      },
      body: JSON.stringify(req.body)
    });
    const text = await resp.text();
    res.status(resp.status).type('application/json').send(text);
  } catch (err) {
    res.status(500).json({error: err.message});
  }
});

app.post('/api/gemini', async (req, res) => {
  const model = req.query.model || 'gemini-2.5-flash';
  const action = req.query.action || 'generateContent';
  const url = `${GEMINI_BASE}/${model}:${action}?key=${process.env.GEMINI_API_KEY}`;
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(req.body)
    });
    const text = await resp.text();
    res.status(resp.status).type('application/json').send(text);
  } catch (err) {
    res.status(500).json({error: err.message});
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Backend listening on ${port}`));
