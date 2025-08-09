import express from 'express';
import fetch from 'node-fetch';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import unzipper from 'unzipper';
import { bom as createSBOM } from '@cyclonedx/bom';
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

// Multer setup for file uploads
const upload = multer({ dest: 'server/uploads/' });

async function generateSBOM(projectPath) {
    const lockFiles = [
        'package-lock.json',
        'yarn.lock',
        'pnpm-lock.yaml',
        'pom.xml',
        'build.gradle',
        'build.gradle.kts',
        'requirements.txt',
        'Pipfile.lock',
        'poetry.lock',
        'composer.lock',
        'Gemfile.lock',
    ];

    for (const lockFile of lockFiles) {
        const lockFilePath = path.join(projectPath, lockFile);
        if (fs.existsSync(lockFilePath)) {
            console.log(`Found ${lockFile}, generating SBOM...`);
            try {
                const sbom = await createSBOM(lockFilePath);
                return sbom.toJSON();
            } catch (err) {
                console.error(`Error generating SBOM for ${lockFile}:`, err);
                return null;
            }
        }
    }

    console.warn('No supported lock file found in the project.');
    return null;
}

async function scanForSinks(projectPath) {
    const sinks = [
        { cwe: 'CWE-78', pattern: /child_process\.exec\s*\(/, description: 'OS Command Injection' }
    ];

    const findings = [];
    const files = await fs.promises.readdir(projectPath, { recursive: true, withFileTypes: true });

    for (const file of files) {
        if (file.isFile()) {
            const filePath = path.join(file.path, file.name);
            try {
                const content = await fs.promises.readFile(filePath, 'utf-8');
                for (const sink of sinks) {
                    if (sink.pattern.test(content)) {
                        findings.push({
                            cwe: sink.cwe,
                            description: sink.description,
                            file: path.relative(projectPath, filePath),
                            pattern: sink.pattern.source
                        });
                    }
                }
            } catch (err) {
                // Ignore errors from binary files etc.
            }
        }
    }
    return findings;
}

app.post('/api/upload', upload.single('project'), (req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }

    const unzippedPath = `server/unzipped/${req.file.filename}`;
    fs.mkdirSync(unzippedPath, { recursive: true });

    fs.createReadStream(req.file.path)
        .pipe(unzipper.Extract({ path: unzippedPath }))
        .on('close', async () => {
            // Cleanup the uploaded zip file
            fs.unlink(req.file.path, (err) => {
                if (err) console.error("Error deleting zip file:", err);
            });
            console.log(`Project unzipped to ${unzippedPath}`);

            const sbom = await generateSBOM(unzippedPath);
            const sinks = await scanForSinks(unzippedPath);

            res.status(200).json({
                message: 'Project uploaded and unzipped successfully.',
                projectPath: unzippedPath,
                sbom: sbom,
                sinks: sinks
            });
        })
        .on('error', (err) => {
            console.error("Error unzipping file:", err);
            res.status(500).send('Error unzipping file.');
        });
});


const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Backend server listening on port ${port}`);
  console.log('Environment check:');
  console.log('- NODE_ENV:', process.env.NODE_ENV || 'development');
  console.log('- Working directory:', process.cwd());
});