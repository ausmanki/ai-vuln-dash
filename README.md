# AI Vulnerability Analysis Dashboard

This repository contains a minimal proof-of-concept implementation of an AI agent that evaluates CVE reports using Google's Gemini model. The agent follows the CVE Validation & Legitimacy Analysis Framework and provides a short assessment based on supplied vulnerability information.

## CVE Validation Framework

**Core Responsibilities**
- Verify CVE authenticity – confirm that the vulnerability is real and exploitable.
- Determine legitimacy – evaluate vendor and third-party claims, and resolve contradictions.
- Prioritize risk – assign a practical priority level based on validated threat intelligence.
- Assign confidence – rate your assessments and recommendations with justified confidence levels.

**Analysis Dimensions**
- *Technical Validity*: Is the attack vector technically sound? Can others reproduce the exploit? Does the claimed impact match? Are prerequisites realistic?
- *Source Credibility*: How reputable is the reporter? What is the vendor response? Are there independent confirmations? How consistent are advisories?
- *Evidence Consistency*: Do CVSS and EPSS scores align? Are patches available and do they contradict vendor statements? Is there proof-of-concept exploitation? Any timeline inconsistencies?
- *Validation Flags*: Investigate any `VALIDATION_MISMATCH` or other indicators of data quality issues. Interpret confidence scores carefully.

**Decision Matrix for Legitimacy**
- Legitimate & High Priority – exploit sound, widely confirmed, vendor acknowledged, high CVSS and EPSS, straightforward exploitation.
- Legitimate & Medium Priority – valid mechanism but requires specific conditions, vendor may dispute, medium CVSS with low EPSS.
- Disputed & Needs Investigation – vendor challenges the vulnerability, conflicting evidence or `VALIDATION_MISMATCH` present.
- False Positive & Low Priority – technical claims don't hold up or vendor debunks them, no independent confirmation.
- Insufficient Data – lacks technical detail or vendor statement; further investigation needed.

## Usage

1. Install dependencies:
   ```bash
   npm install
   ```
2. Export your Gemini API key:
   ```bash
   export GOOGLE_API_KEY=YOUR_KEY
   ```
3. Prepare a CVE report in JSON format. An example is provided in `examples/sample_report.json`.
4. Run the analysis script:
   ```bash
   npx tsx cve_agent.tsx examples/sample_report.json
   ```

The script prints a JSON object with the assessment results, including legitimacy status, priority level, confidence, and recommended action.

## Files

- `cve_agent.tsx` – simple CLI for analyzing CVE reports with Gemini.
- `examples/sample_report.json` – example input file.
