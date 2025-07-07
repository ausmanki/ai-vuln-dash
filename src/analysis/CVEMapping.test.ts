import { describe, it, expect } from 'vitest';
import { parseCVEText } from './CVEMapping';

describe('parseCVEText', () => {
  it('groups CVE modules correctly', () => {
    const text = `
CVE-2022-22965 - org.springframework:spring-core:5.2.12.RELEASE
CVE-2022-22965 - org.springframework:spring-beans:5.2.12.RELEASE
`;
    const res = parseCVEText(text);
    expect(res['CVE-2022-22965'].modules.length).toBe(2);
    expect(res['CVE-2022-22965'].modules[0].name).toBe('org.springframework:spring-core');
  });
});
