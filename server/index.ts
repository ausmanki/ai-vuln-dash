import express from 'express';
import fetch from 'node-fetch';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import unzipper from 'unzipper';
import { exec } from 'child_process';
import { promisify } from 'util';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

// Fix for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Import local modules without .js extension
import { getApiKeys, getClientConfig } from './config/apiKeys';
import cisaKevProxy from './cisaKevProxy';
import { TaintRuleGenerationService } from '../src/services/TaintRuleGenerationService';
import { CorrelationService } from '../src/services/CorrelationService';
import { ExplanationService } from '../src/services/ExplanationService';

// Handle @cyclonedx/bom import - try different approaches
let createSBOM: any;
try {
    // Try named import
    const pkg = await import('@cyclonedx/bom');
    createSBOM = pkg.makeBom || pkg.createBom || pkg.bom || pkg.default;
} catch (err) {
    console.warn('Could not import @cyclonedx/bom, SBOM generation will be disabled');
    createSBOM = null;
}

const execAsync = promisify(exec);

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
  } catch (err: any) {
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
  } catch (err: any) {
    console.error('Gemini API error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/ai-config', (req, res) => {
  res.json(getClientConfig());
});

app.post('/api/generate-rule', async (req, res) => {
    const { cveDescription, cwe } = req.body;
    if (!cveDescription || !cwe) {
        return res.status(400).json({ error: 'cveDescription and cwe are required' });
    }

    try {
        const settings = getClientConfig();
        const rule = await TaintRuleGenerationService.generateSemgrepRule(cveDescription, cwe, settings);
        res.status(200).json({ rule });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate Semgrep rule' });
    }
});

// Multer setup for file uploads
const upload = multer({ dest: 'server/uploads/' });

app.post('/api/explain-finding', async (req, res) => {
    const { finding } = req.body;
    if (!finding) {
        return res.status(400).json({ error: 'finding is required' });
    }

    try {
        const settings = getClientConfig();
        const explanation = await ExplanationService.generateExplanation(finding, settings);
        res.status(200).json({ explanation });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate explanation' });
    }
});

async function generateSBOM(projectPath: string) {
    if (!createSBOM) {
        console.warn('SBOM generation is disabled (missing @cyclonedx/bom)');
        return null;
    }

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
                return sbom.toJSON ? sbom.toJSON() : sbom;
            } catch (err: any) {
                console.error(`Error generating SBOM for ${lockFile}:`, err);
                return null;
            }
        }
    }

    console.warn('No supported lock file found in the project.');
    return null;
}

async function scanForSinks(projectPath: string) {
    const sinks = [
        { cwe: 'CWE-78', pattern: /child_process\.exec\s*\(/, description: 'OS Command Injection' }
    ];

    const findings: any[] = [];
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

async function runSemgrep(projectPath: string) {
    return new Promise((resolve, reject) => {
        const command = `semgrep scan --json --config "r/javascript.lang.security.audit.taint-analysis.taint-flow" "${projectPath}"`;
        exec(command, (error, stdout, stderr) => {
            if (error && error.code !== 1) { // Semgrep exits with 1 if findings are found
                console.error(`Semgrep execution error: ${stderr}`);
                reject(`Semgrep execution failed: ${stderr}`);
                return;
            }
            try {
                const results = JSON.parse(stdout);
                resolve(results.results || []);
            } catch (parseError: any) {
                console.error(`Error parsing Semgrep output: ${parseError.message}`);
                reject('Error parsing Semgrep output.');
            }
        });
    });
}

app.post('/api/upload', upload.single('project'), (req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }

    const unzippedPath = `server/unzipped/${req.file.filename}`;
    fs.mkdirSync(unzippedPath, { recursive: true });

    let errorOccurred = false;

    const stream = fs.createReadStream(req.file.path)
        .pipe(unzipper.Extract({ path: unzippedPath }));

    stream.on('close', async () => {
        if (errorOccurred) {
            // Cleanup the uploaded zip file and the created directory
            fs.unlink(req.file.path, (err) => {
                if (err) console.error("Error deleting failed zip file:", err);
            });
            fs.rm(unzippedPath, { recursive: true, force: true }, (err) => {
                if (err) console.error("Error deleting directory for failed upload:", err);
            });
            return;
        }

        // Cleanup the uploaded zip file
        fs.unlink(req.file.path, (err) => {
            if (err) console.error("Error deleting zip file:", err);
        });
        console.log(`Project unzipped to ${unzippedPath}`);

        const sbom = await generateSBOM(unzippedPath);
        const sinks = await scanForSinks(unzippedPath);
        const semgrepResults = await runSemgrep(unzippedPath);
        const correlationResults = await CorrelationService.correlate(sbom, semgrepResults);

        res.status(200).json({
            message: 'Project uploaded and unzipped successfully.',
            projectPath: unzippedPath,
            sbom: sbom,
            sinks: sinks,
            semgrep: semgrepResults,
            correlation: correlationResults
        });
    });

    stream.on('error', (err) => {
        errorOccurred = true;
        console.error("Error unzipping file:", err);
        if (!res.headersSent) {
            res.status(500).json({
                error: 'Error unzipping file.',
                details: err.message
            });
        }
    });
});


const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Backend server listening on port ${port}`);
  console.log('Environment check:');
  console.log('- NODE_ENV:', process.env.NODE_ENV || 'development');
  console.log('- Working directory:', process.cwd());
});