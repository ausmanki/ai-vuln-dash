import { AnalysisResult } from './TaintAnalyzer';

export function generateJSONReport(result: AnalysisResult) {
  return JSON.stringify(result, null, 2);
}
