import { describe, it, expect } from 'vitest';
import { TaintAnalyzer } from './TaintAnalyzer';
import { buildCVEMap, CVEEntry } from './CVEMapping';

describe('TaintAnalyzer', () => {
  it('detects tainted flow to sink with CVE', () => {
    const entries: CVEEntry[] = [
      { id: 'CVE-2022-0001', functions: ['eval'], description: 'Eval vulnerability', severity: 'HIGH' }
    ];
    const map = buildCVEMap(entries);
    const analyzer = new TaintAnalyzer(map);
    const code = `
      function input() { return 'bad'; }
      const user = input();
      eval(user);
    `;
    const res = analyzer.analyze(code);
    expect(res.flows.length).toBe(1);
    expect(res.flows[0].sink.cve?.id).toBe('CVE-2022-0001');
  });

  it('ignores safe code', () => {
    const map = buildCVEMap([]);
    const analyzer = new TaintAnalyzer(map);
    const code = `
      const a = 1;
      eval(a);
    `;
    const res = analyzer.analyze(code);
    expect(res.flows.length).toBe(0);
  });
});
