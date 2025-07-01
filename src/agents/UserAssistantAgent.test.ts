import { describe, it, expect } from 'vitest';
import { UserAssistantAgent } from './UserAssistantAgent';

// This test performs a full validation flow without mocking any API calls.
// It invokes the private getValidationInfo method to ensure the agent can
// retrieve real validation data using the underlying services.

describe('UserAssistantAgent.getValidationInfo (integration)', () => {
  it(
    'retrieves validation info for a real CVE',
    async () => {
      const agent = new UserAssistantAgent({});
      const resp = await (agent as any).getValidationInfo('CVE-2021-34527');

      expect(resp.data?.cveId).toBe('CVE-2021-34527');
      expect(resp.data?.status).toBeDefined();
    },
    30000,
  );
});
