// This file contains the patch discovery prompts as a constant
// Convert your Patch_Discovery_RAG_System_Prompts.md content here

export const patchPrompts = `
# Patch Discovery RAG System Prompts

## Overview
This document contains the prompts and knowledge base for the patch discovery system.

## Security Patch Identification

### Critical Security Patches
- Patches that fix remote code execution vulnerabilities
- Patches addressing authentication bypass issues
- Updates fixing privilege escalation vulnerabilities
- Fixes for data exposure or information disclosure

### Patch Priority Factors
1. CVSS Score - Higher scores indicate more severe vulnerabilities
2. EPSS Score - Indicates likelihood of exploitation
3. CISA KEV listing - Known exploited vulnerabilities
4. Public exploit availability
5. Attack surface exposure

### Patch Analysis Methodology
When analyzing patches, consider:
- The vulnerability class being addressed
- The potential impact if left unpatched
- Dependencies and compatibility requirements
- Testing requirements before deployment
- Rollback procedures if issues arise

## Vulnerability Correlation

### Matching CVEs to Patches
- Look for CVE identifiers in patch notes
- Match vulnerability descriptions to fix descriptions
- Correlate affected components and versions
- Consider timing of patch releases vs CVE publications

### Risk Assessment
Evaluate each vulnerability based on:
- Technical severity (CVSS base score)
- Environmental factors (your specific deployment)
- Threat intelligence (active exploitation)
- Business impact if exploited

[Add the rest of your markdown content here]
`;

// Export as default for Vite compatibility
export default patchPrompts;