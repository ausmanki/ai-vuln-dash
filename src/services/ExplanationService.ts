import { APIService } from './APIService';
import { AgentSettings } from '../types/cveData';

export class ExplanationService {
    static async generateExplanation(finding: any, settings: AgentSettings): Promise<string> {
        const prompt = `
You are a principal security engineer. Your task is to provide a clear, concise explanation of a security finding and suggest a remediation.

The user has found a potential vulnerability in their codebase. Here are the details:
- **CVE:** ${finding.cve}
- **Vulnerable Component:** ${finding.component.name}@${finding.component.version}
- **Sink:** A vulnerable function was found in the file \`${finding.sinks[0].path}\`.
- **Taint Flow:** The analysis suggests that user-controllable input may be reaching this vulnerable function.

Please provide the following:
1.  **A brief, easy-to-understand explanation of the vulnerability.** Explain what the CVE is about and why it's a risk.
2.  **A clear explanation of the finding.** Explain what it means that a sink was found in the specified file and how it relates to the CVE.
3.  **A suggested remediation.** Provide a clear, actionable recommendation on how to fix the issue. This should include upgrading the vulnerable component and, if applicable, adding input validation.

Keep the explanation clear, concise, and actionable for a developer.
`;

        try {
            const response = await APIService.fetchGeneralAnswer(prompt, settings);
            return response.text;
        } catch (error) {
            console.error('Error generating explanation:', error);
            throw new Error('Failed to generate explanation from AI.');
        }
    }
}
