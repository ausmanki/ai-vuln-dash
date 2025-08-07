import fs from 'fs';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { getApiKeys } from './server/config/apiKeys';

interface CVEReport {
  description: string;
  technical_details: string;
  cvss_score: number;
  epss_score: number;
  vendor_statements: string[];
  third_party_analysis: string[];
  exploitation_status: string;
  validation_flags: string[];
}

async function analyze(path: string) {
  const { googleApiKey } = getApiKeys();
  if (!googleApiKey) {
    throw new Error('GOOGLE_API_KEY environment variable not set');
  }
  const report: CVEReport = JSON.parse(fs.readFileSync(path, 'utf-8'));
  const genAI = new GoogleGenerativeAI(googleApiKey);
  const model = genAI.getGenerativeModel({
    model: 'gemini-1.5-flash',
    tools: [{
      "googleSearch": {}
    }],
  });

  const prompt = `You are an expert cybersecurity analyst. Assess the following CVE report according to the CVE Validation & Legitimacy Analysis Framework.
  Core Responsibilities:
  - Verify CVE authenticity – confirm that the vulnerability is real and exploitable.
  - Determine legitimacy – evaluate vendor and third-party claims, and resolve contradictions.
  - Prioritize risk – assign a practical priority level based on validated threat intelligence.
  - Assign confidence – rate your assessments and recommendations with justified confidence levels.

  Analysis Dimensions:
  Technical Validity
  - Is the attack vector technically sound?
  - Can others reproduce the exploit?
  - Does the claimed impact match the mechanism?
  - Are the prerequisites realistic?

  Source Credibility
  - How reputable is the reporter?
  - What is the vendor’s response and does it hold up technically?
  - Are there independent confirmations?
  - How thorough and consistent are the advisories?

  Evidence Consistency
  - Do CVSS and EPSS scores align?
  - Are patches available? Do they contradict vendor statements?
  - Is there proof-of-concept code or live exploitation?
  - Are there timeline inconsistencies?

  Validation Flags
  - Investigate any “VALIDATION_MISMATCH” or other indicators that hint at data quality issues.
  - Interpret confidence scores carefully.

  Decision Matrix for Legitimacy
  - Legitimate & High Priority: Exploit is sound, widely confirmed, and acknowledged by the vendor. High CVSS with significant EPSS. Exploitation is straightforward.
  - Legitimate & Medium Priority: Mechanism is valid but exploitation may require specific conditions. Patches might exist despite vendor disputes. Medium CVSS and low EPSS.
  - Disputed & Needs Investigation: Vendor challenges the vulnerability. Conflicting evidence or “VALIDATION_MISMATCH.” Assess based on the environment and technical merits of each claim.
  - False Positive & Low Priority: Technical claims don’t hold up or strong vendor evidence debunks them. No independent confirmation. Consider the issue more theoretical than practical.
  - Insufficient Data: Lacks technical detail or confirmation. No vendor statement. Requires further investigation.

  Provide your response as JSON with fields legitimacy_status, priority_level, confidence, action_required, technical_validation, evidence_quality, recommendations.`;

  const input = JSON.stringify(report);
  const response = await model.generateContent([prompt, input]);
  console.log(response.response.text());
}

const path = process.argv[2];
if (!path) {
  console.error('Usage: npx tsx cve_agent.tsx <report.json>');
  process.exit(1);
}

analyze(path).catch(err => {
  console.error(err.message);
  process.exit(1);
});
