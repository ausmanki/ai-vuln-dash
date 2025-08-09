import express from 'express';
import fetch from 'node-fetch';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import AdmZip from 'adm-zip';
import { exec } from 'child_process';
import { promisify } from 'util';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { createRequire } from 'module';
import net from 'net';

// Fix for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Import local modules without .js extension
import { getApiKeys, getClientConfig } from './config/apiKeys';
import cisaKevProxy from './cisaKevProxy';
import { TaintRuleGenerationService } from '../src/services/TaintRuleGenerationService';
import { CorrelationService } from '../src/services/CorrelationService';
import { ExplanationService } from '../src/services/ExplanationService';

// Import CycloneDX BOM - handle both ESM and CommonJS
let createSBOM: any = null;

// Since we're in an async context at top level, we can use dynamic import
try {
    const cycloneDxModule = await import('@cyclonedx/bom');
    // Try different possible exports
    createSBOM = cycloneDxModule.makeBom ||
                 cycloneDxModule.createBom ||
                 cycloneDxModule.default?.makeBom ||
                 cycloneDxModule.default;
    
    if (!createSBOM) {
        // If no direct function found, maybe it's the module itself
        createSBOM = cycloneDxModule;
    }
    
    console.log('✓ CycloneDX BOM library loaded');
} catch (err: any) {
    // Try CommonJS require as fallback
    try {
        const require = createRequire(import.meta.url);
        const cycloneDx = require('@cyclonedx/bom');
        createSBOM = cycloneDx.makeBom || cycloneDx;
        console.log('✓ CycloneDX BOM library loaded via require');
    } catch (requireErr: any) {
        console.warn('Could not load @cyclonedx/bom:', requireErr.message);
        console.warn('SBOM generation will use fallback method');
    }
}

// IMPORTANT: Don't check for createSBOM anymore, always use our implementation
// This ensures SBOM generation always works

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
    // Always use our implementation for reliability
    const packageJsonPath = path.join(projectPath, 'package.json');
    
    if (!fs.existsSync(packageJsonPath)) {
        // Try to find package.json in subdirectories
        const files = fs.readdirSync(projectPath);
        for (const file of files) {
            const subPath = path.join(projectPath, file);
            if (fs.statSync(subPath).isDirectory()) {
                const subPackageJson = path.join(subPath, 'package.json');
                if (fs.existsSync(subPackageJson)) {
                    return generateSBOM(subPath);
                }
            }
        }
        console.warn('No package.json found in project');
        return null;
    }

    try {
        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
        const dependencies = { 
            ...packageJson.dependencies, 
            ...packageJson.devDependencies 
        };
        
        // Try to get version information from lock file
        const packageLockPath = path.join(projectPath, 'package-lock.json');
        let resolvedVersions: any = {};
        
        if (fs.existsSync(packageLockPath)) {
            try {
                const lockData = JSON.parse(fs.readFileSync(packageLockPath, 'utf-8'));
                if (lockData.packages) {
                    // npm v7+ format
                    Object.entries(lockData.packages).forEach(([key, value]: [string, any]) => {
                        if (key && key.startsWith('node_modules/')) {
                            const pkgName = key.replace('node_modules/', '');
                            resolvedVersions[pkgName] = value.version;
                        }
                    });
                } else if (lockData.dependencies) {
                    // npm v6 format
                    Object.entries(lockData.dependencies).forEach(([key, value]: [string, any]) => {
                        resolvedVersions[key] = value.version;
                    });
                }
            } catch (lockErr) {
                console.warn('Could not parse package-lock.json:', lockErr);
            }
        }
        
        // Create CycloneDX format SBOM
        const sbom = {
            bomFormat: 'CycloneDX',
            specVersion: '1.4',
            serialNumber: `urn:uuid:${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            version: 1,
            metadata: {
                timestamp: new Date().toISOString(),
                tools: [{
                    vendor: 'ai-vuln-dash',
                    name: 'SBOM Generator',
                    version: '1.0.0'
                }],
                component: {
                    type: 'application',
                    name: packageJson.name || 'unknown',
                    version: packageJson.version || '0.0.0'
                }
            },
            components: Object.entries(dependencies).map(([name, versionSpec]) => {
                const resolvedVersion = resolvedVersions[name] || versionSpec;
                return {
                    type: 'library',
                    'bom-ref': `pkg:npm/${name}@${resolvedVersion}`,
                    name,
                    version: String(resolvedVersion).replace(/^[\^~]/, ''),
                    purl: `pkg:npm/${name}@${resolvedVersion}`.replace(/^[\^~]/, ''),
                    scope: 'required',
                    hashes: []
                };
            })
        };
        
        console.log(`✓ Generated SBOM with ${sbom.components.length} components for ${packageJson.name || 'project'}`);
        return sbom;
        
    } catch (err: any) {
        console.error('Error generating SBOM:', err);
        return null;
    }
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

async function runSemgrep(projectPath: string): Promise<any[]> {
    return new Promise((resolve, reject) => {
        const command = `semgrep scan --json --config "r/javascript.lang.security.audit.taint-analysis.taint-flow" "${projectPath}"`;
        exec(command, { maxBuffer: 1024 * 1024 * 10 }, (error, stdout, stderr) => {
            // Semgrep returns exit code 1 when it finds issues, which is not an error
            if (error && error.code !== 1 && error.code !== 0) {
                console.error(`Semgrep execution error: ${stderr}`);
                // Check if semgrep is installed
                if (stderr.includes('command not found') || stderr.includes('is not recognized')) {
                    console.error('Semgrep is not installed. Please install it with: pip install semgrep');
                    resolve([]); // Return empty results instead of rejecting
                    return;
                }
                resolve([]); // Return empty results for other errors
                return;
            }
            
            // Handle empty output
            if (!stdout || stdout.trim() === '') {
                console.log('Semgrep returned empty output');
                resolve([]);
                return;
            }
            
            try {
                const results = JSON.parse(stdout);
                resolve(results.results || []);
            } catch (parseError: any) {
                console.error(`Error parsing Semgrep output: ${parseError.message}`);
                console.error('Semgrep stdout:', stdout);
                console.error('Semgrep stderr:', stderr);
                resolve([]); // Return empty results instead of rejecting
            }
        });
    });
}

app.post('/api/upload', upload.single('project'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded.' });
    }

    console.log('File upload received:', {
        filename: req.file.filename,
        originalname: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size
    });

    // Validate file size
    if (req.file.size === 0) {
        try {
            fs.unlinkSync(req.file.path);
        } catch (err) {}
        return res.status(400).json({ error: 'Uploaded file is empty.' });
    }

    const unzippedPath = `server/unzipped/${req.file.filename}`;
    
    try {
        // Ensure directory exists
        fs.mkdirSync(unzippedPath, { recursive: true });

        // First, let's check if the file is actually a ZIP
        const fileBuffer = fs.readFileSync(req.file.path);
        const zipSignature = fileBuffer.slice(0, 4).toString('hex');
        
        // ZIP files should start with PK (504b)
        if (!zipSignature.startsWith('504b')) {
            throw new Error(`File is not a valid ZIP archive (signature: ${zipSignature}). Please upload a .zip file.`);
        }

        // Try multiple extraction methods
        let extractionSuccessful = false;
        let extractionError: any = null;

        // Method 1: Try AdmZip
        try {
            const zip = new AdmZip(req.file.path);
            const zipEntries = zip.getEntries();
            
            if (zipEntries.length === 0) {
                throw new Error('ZIP file is empty');
            }
            
            console.log(`ZIP contains ${zipEntries.length} entries`);
            zip.extractAllTo(unzippedPath, true);
            extractionSuccessful = true;
            console.log(`Project unzipped to ${unzippedPath} using AdmZip`);
        } catch (admZipError: any) {
            console.error('AdmZip extraction failed:', admZipError.message);
            extractionError = admZipError;
        }

        // Method 2: If AdmZip fails, try using system unzip command (if available)
        if (!extractionSuccessful && process.platform !== 'win32') {
            try {
                await execAsync(`unzip -o "${req.file.path}" -d "${unzippedPath}"`);
                extractionSuccessful = true;
                console.log(`Project unzipped to ${unzippedPath} using system unzip`);
            } catch (systemError) {
                console.error('System unzip failed:', systemError);
            }
        }

        // Method 3: If on Windows, try using PowerShell
        if (!extractionSuccessful && process.platform === 'win32') {
            try {
                const psCommand = `Expand-Archive -Path "${req.file.path}" -DestinationPath "${unzippedPath}" -Force`;
                await execAsync(`powershell -Command "${psCommand}"`);
                extractionSuccessful = true;
                console.log(`Project unzipped to ${unzippedPath} using PowerShell`);
            } catch (psError) {
                console.error('PowerShell extraction failed:', psError);
            }
        }

        if (!extractionSuccessful) {
            throw new Error(`Failed to extract ZIP file: ${extractionError?.message || 'All extraction methods failed'}`);
        }

        // Cleanup the uploaded zip file
        try {
            fs.unlinkSync(req.file.path);
        } catch (err) {
            console.error("Error deleting zip file:", err);
        }

        // Check if extraction produced any files
        const extractedFiles = fs.readdirSync(unzippedPath);
        if (extractedFiles.length === 0) {
            throw new Error('ZIP extraction produced no files');
        }

        console.log(`Extracted ${extractedFiles.length} items:`, extractedFiles.slice(0, 5).join(', '));

        // Process the unzipped files
        let sbom = null;
        let sinks = [];
        let semgrepResults = [];
        let correlationResults = null;
        const warnings: string[] = [];

        try {
            sbom = await generateSBOM(unzippedPath);
            if (!sbom) {
                warnings.push('SBOM generation failed - no package.json found');
            }
        } catch (err: any) {
            console.error('SBOM generation error:', err.message);
            warnings.push(`SBOM generation error: ${err.message}`);
        }

        try {
            sinks = await scanForSinks(unzippedPath);
            console.log(`Found ${sinks.length} potential security sinks`);
        } catch (err: any) {
            console.error('Sink scanning error:', err.message);
            warnings.push(`Sink scanning error: ${err.message}`);
        }

        try {
            semgrepResults = await runSemgrep(unzippedPath);
            if (semgrepResults.length === 0) {
                warnings.push('Semgrep found no issues or is not installed');
            } else {
                console.log(`Semgrep found ${semgrepResults.length} issues`);
            }
        } catch (err: any) {
            console.error('Semgrep error:', err.message);
            warnings.push(`Semgrep error: ${err.message}`);
        }

        if (sbom && semgrepResults && semgrepResults.length > 0) {
            try {
                correlationResults = await CorrelationService.correlate(sbom, semgrepResults);
            } catch (err: any) {
                console.error('Correlation error:', err.message);
                warnings.push(`Correlation error: ${err.message}`);
            }
        }

        res.status(200).json({
            message: 'Project uploaded and processed successfully.',
            projectPath: unzippedPath,
            filesExtracted: extractedFiles.length,
            sbom: sbom,
            sinks: sinks,
            semgrep: semgrepResults,
            correlation: correlationResults,
            warnings: warnings
        });

    } catch (err: any) {
        console.error("Error processing upload:", err);
        
        // Clean up on error
        try {
            if (fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }
            if (fs.existsSync(unzippedPath)) {
                fs.rmSync(unzippedPath, { recursive: true, force: true });
            }
        } catch (cleanupErr) {
            console.error("Cleanup error:", cleanupErr);
        }

        res.status(500).json({ 
            error: 'Error processing uploaded file',
            details: err.message,
            fileInfo: {
                originalName: req.file.originalname,
                size: req.file.size,
                mimetype: req.file.mimetype
            }
        });
    }
});

// Function to find an available port
async function findAvailablePort(startPort: number): Promise<number> {
    return new Promise((resolve) => {
        const server = net.createServer();
        
        server.listen(startPort, () => {
            const port = (server.address() as net.AddressInfo).port;
            server.close(() => resolve(port));
        });
        
        server.on('error', () => {
            // Port is in use, try the next one
            resolve(findAvailablePort(startPort + 1));
        });
    });
}

// Add error handling to prevent crashes
process.on('unhandledRejection', (reason: any) => {
    console.error('Unhandled Promise Rejection:', reason);
    // Don't exit the process, just log the error
});

process.on('uncaughtException', (error: Error) => {
    console.error('Uncaught Exception:', error);
    if (error.message && error.message.includes('EADDRINUSE')) {
        console.error('Port is already in use. The server will find another port...');
        // Don't exit for port errors
    } else {
        // For other uncaught exceptions, exit after logging
        process.exit(1);
    }
});

// Start the server with automatic port detection
const preferredPort = parseInt(process.env.PORT || '3001');
const actualPort = await findAvailablePort(preferredPort);

if (actualPort !== preferredPort) {
    console.log(`⚠️  Port ${preferredPort} was in use, using port ${actualPort} instead`);
}

const server = app.listen(actualPort, () => {
    console.log(`\n🚀 Backend server listening on port ${actualPort}`);
    console.log(`🔗 API available at http://localhost:${actualPort}`);
    console.log('\nEnvironment check:');
    console.log('- NODE_ENV:', process.env.NODE_ENV || 'development');
    console.log('- Working directory:', process.cwd());
    console.log('\n📝 Note: Update your frontend proxy configuration to use port', actualPort);
});
