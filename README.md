# AI Vulnerability Analysis Dashboard

This repository contains a minimal proof-of-concept implementation of an AI agent
that evaluates CVE reports. The agent follows the CVE Validation & Legitimacy
Analysis Framework and provides a short assessment based on supplied vulnerability
information.

## Usage

1. Prepare a CVE report in JSON format. An example is provided in
   `examples/sample_report.json`.
2. Run the analysis script:

```bash
python3 cve_agent.py examples/sample_report.json
```

The script outputs a JSON object with the assessment results, including
legitimacy status, priority level, confidence, and recommended action.

## Files

- `cve_agent.py` – simple CLI for analyzing CVE reports.
- `examples/sample_report.json` – example input file.
