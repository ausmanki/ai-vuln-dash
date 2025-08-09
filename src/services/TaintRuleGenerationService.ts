import { APIService } from './APIService';
import { AgentSettings } from '../types/cveData';

export class TaintRuleGenerationService {
    static async generateSemgrepRule(cveDescription: string, cwe: string, settings: AgentSettings): Promise<string> {
        const prompt = `
You are an expert cybersecurity researcher specializing in static analysis. Your task is to generate a Semgrep rule in YAML format for a given CVE description and CWE.

The rule should identify potential taint flows related to the vulnerability. You need to identify the sources, sinks, and sanitizers from the CVE description.

Here is an example:

**CVE Description:**
"A command injection vulnerability in the 'exec' function of the 'node-cmd' package allows attackers to execute arbitrary commands via a crafted string."

**CWE:**
"CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"

**Generated Semgrep Rule:**
\`\`\`yaml
rules:
  - id: node-cmd-exec-injection
    patterns:
      - pattern-either:
          - pattern: |
              var cmd = require('node-cmd');
              ...
              cmd.run($CMD);
          - pattern: |
              var cmd = require('node-cmd');
              ...
              cmd.runSync($CMD);
    message: "Potential command injection in node-cmd. The 'run' or 'runSync' function is called with user-controllable input."
    languages:
      - javascript
      - typescript
    severity: ERROR
    metadata:
      cwe: CWE-78
      category: security
      confidence: MEDIUM
      technology:
        - node-cmd
\`\`\`

Now, given the following CVE description and CWE, generate a Semgrep rule.

**CVE Description:**
"${cveDescription}"

**CWE:**
"${cwe}"

**Generated Semgrep Rule:**
`;

        try {
            const response = await APIService.fetchGeneralAnswer(prompt, settings);
            // Extract the YAML from the response. The AI might return it in a markdown block.
            const match = response.text.match(/```yaml\n([\s\S]*?)\n```/);
            if (match && match[1]) {
                return match[1];
            }
            return response.text; // Fallback to returning the full text
        } catch (error) {
            console.error('Error generating Semgrep rule:', error);
            throw new Error('Failed to generate Semgrep rule from AI.');
        }
    }
}
