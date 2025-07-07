export interface SourceInfo {
  name: string;
  loc?: any;
}

export interface SinkInfo {
  name: string;
  loc?: any;
  cve?: CVEInfo;
}

export interface CVEInfo {
  id: string;
  description: string;
  severity: string;
  module?: string;
  version?: string;
}

export interface TaintFlow {
  source: SourceInfo;
  sink: SinkInfo;
  chain: string[];
}

export interface AnalysisResult {
  flows: TaintFlow[];
}

const TAINT_SOURCES = [
  'input',
  'readFile',
  'readFileSync',
  'fetch',
  'axios',
  'getParameter',
  'socketRead'
];
const TAINT_SINKS = [
  'eval',
  'exec',
  'execSync',
  'spawn',
  'query',
  'osSystem',
  'springBind',
  'deserialize'
];

import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

export class TaintAnalyzer {
  private cveMap: Map<string, CVEInfo[]>;

  constructor(cveMap: Map<string, CVEInfo[]>) {
    this.cveMap = cveMap;
  }

  analyze(code: string, deps: Record<string, string> = {}): AnalysisResult {
    const ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'module' });
    const taintedVars: Map<string, SourceInfo> = new Map();
    const flows: TaintFlow[] = [];

    walk.simple(ast as any, {
      VariableDeclarator: (node: any) => {
        if (node.init) {
          if (this.isSourceCall(node.init)) {
            taintedVars.set(node.id.name, { name: node.init.callee.name, loc: node.loc });
          } else if (node.init.type === 'Identifier' && taintedVars.has(node.init.name)) {
            taintedVars.set(node.id.name, taintedVars.get(node.init.name)!);
          } else if (node.init.type === 'CallExpression') {
            const taintedArg = node.init.arguments.find((a: any) => a.type === 'Identifier' && taintedVars.has(a.name));
            if (taintedArg) {
              taintedVars.set(node.id.name, taintedVars.get((taintedArg as any).name)!);
            }
          }
        }
      },
      AssignmentExpression: (node: any) => {
        if (node.right.type === 'Identifier' && taintedVars.has(node.right.name)) {
          if (node.left.type === 'Identifier') {
            taintedVars.set(node.left.name, taintedVars.get(node.right.name)!);
          } else if (node.left.type === 'MemberExpression' && node.left.object.type === 'Identifier' && node.left.property.type === 'Identifier') {
            const key = `${node.left.object.name}.${node.left.property.name}`;
            taintedVars.set(key, taintedVars.get(node.right.name)!);
          }
        } else if (node.right.type === 'MemberExpression' && node.right.object.type === 'Identifier' && node.right.property.type === 'Identifier') {
          const key = `${node.right.object.name}.${node.right.property.name}`;
          if (taintedVars.has(key)) {
            if (node.left.type === 'Identifier') {
              taintedVars.set(node.left.name, taintedVars.get(key)!);
            }
          }
        } else if (node.right.type === 'CallExpression') {
          const taintedArg = node.right.arguments.find((a: any) => a.type === 'Identifier' && taintedVars.has(a.name));
          if (taintedArg && node.left.type === 'Identifier') {
            taintedVars.set(node.left.name, taintedVars.get((taintedArg as any).name)!);
          }
        }
      },
      CallExpression: (node: any) => {
        const calleeName = this.getCalleeName(node.callee);
        if (!calleeName) return;
        if (TAINT_SINKS.includes(calleeName)) {
          const arg = node.arguments[0];
          if (arg && arg.type === 'Identifier' && taintedVars.has(arg.name)) {
            const source = taintedVars.get(arg.name)!;
            const chain = [source.name, arg.name, calleeName];
            const cveEntries = this.cveMap.get(calleeName) || [];
            const matched = cveEntries.find(e => !e.module || !e.version || deps[e.module] === e.version);
            flows.push({ source, sink: { name: calleeName, loc: node.loc, cve: matched }, chain });
          }
        }
        // propagate through function returns (simplified: first arg to variable)
      }
    });

    return { flows };
  }

  private isSourceCall(node: any): boolean {
    if (node.type !== 'CallExpression') return false;
    const name = this.getCalleeName(node.callee);
    return name ? TAINT_SOURCES.includes(name) : false;
  }

  private getCalleeName(callee: any): string | null {
    if (callee.type === 'Identifier') {
      return callee.name;
    }
    if (callee.type === 'MemberExpression' && !callee.computed && callee.property.type === 'Identifier') {
      return callee.property.name;
    }
    return null;
  }
}
