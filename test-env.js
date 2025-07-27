import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('Current directory:', __dirname);

// Try to load .env
const envPath = path.join(__dirname, '.env');
console.log('Looking for .env at:', envPath);
console.log('.env exists?', fs.existsSync(envPath));

if (fs.existsSync(envPath)) {
  console.log('.env file contents preview:');
  const content = fs.readFileSync(envPath, 'utf8');
  const lines = content.split('\n').slice(0, 3);
  lines.forEach(line => {
    const [key] = line.split('=');
    if (key && key.trim()) {
      console.log(`- ${key.trim()} is present`);
    }
  });
}

// Load environment variables
const result = dotenv.config();

if (result.error) {
  console.error('Error loading .env:', result.error);
} else {
  console.log('\nEnvironment variables loaded:');
  console.log('OPENAI_API_KEY:', process.env.OPENAI_API_KEY ? `Set (${process.env.OPENAI_API_KEY.substring(0, 10)}...)` : 'NOT SET');
  console.log('GEMINI_API_KEY:', process.env.GEMINI_API_KEY ? `Set (${process.env.GEMINI_API_KEY.substring(0, 10)}...)` : 'NOT SET');
  console.log('PORT:', process.env.PORT || 'NOT SET');
}