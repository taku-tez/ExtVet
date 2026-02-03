/**
 * Reporter - Output formatting for ExtVet
 */

import type { Finding, ScanOptions, ScanSummary } from './types.js';

interface SarifRule {
  id: string;
  shortDescription: { text: string };
  helpUri?: string;
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
    };
  }>;
}

interface SarifReport {
  $schema: string;
  version: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
  }>;
}

interface ExtensionReport {
  id: string;
  name: string;
  riskScore: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'safe';
  findings: {
    critical: Finding[];
    warning: Finding[];
    info: Finding[];
  };
  summary: {
    critical: number;
    warning: number;
    info: number;
    total: number;
  };
}

interface JsonReport {
  meta: {
    tool: string;
    version: string;
    timestamp: string;
    browser?: string;
    profile?: string;
  };
  summary: {
    totalExtensions: number;
    extensionsWithIssues: number;
    critical: number;
    warning: number;
    info: number;
    total: number;
    riskDistribution: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      safe: number;
    };
  };
  extensions: ExtensionReport[];
  rules: Array<{
    id: string;
    severity: string;
    description: string;
    recommendation?: string;
    count: number;
  }>;
}

export class Reporter {
  private quiet: boolean;
  private format: string;
  private browser?: string;
  private profile?: string;

  constructor(options: ScanOptions = {}) {
    this.quiet = options.quiet || false;
    this.format = options.format || 'table';
    this.browser = options.browserType;
    this.profile = options.profile;
  }

  start(message: string): void {
    if (!this.quiet && this.format === 'table') {
      console.log(`\n🦅 ExtVet - Browser Extension Security Scanner\n`);
      console.log(message);
    }
  }

  warn(message: string): void {
    if (!this.quiet && this.format === 'table') {
      console.log(`⚠️  ${message}`);
    }
  }

  report(findings: Finding[], options: ScanOptions = {}): ScanSummary {
    const summary: ScanSummary = {
      critical: findings.filter(f => f.severity === 'critical').length,
      warning: findings.filter(f => f.severity === 'warning').length,
      info: findings.filter(f => f.severity === 'info').length,
      total: findings.length,
    };

    if (this.format === 'json') {
      const jsonReport = this.toJson(findings, options);
      console.log(JSON.stringify(jsonReport, null, 2));
      return summary;
    }

    if (this.format === 'sarif') {
      console.log(JSON.stringify(this.toSarif(findings), null, 2));
      return summary;
    }

    // Table format (default)
    this.printTable(findings, summary, options);

    return summary;
  }

  private toJson(findings: Finding[], options: ScanOptions): JsonReport {
    // Group findings by extension
    const extensionMap = new Map<string, Finding[]>();
    
    for (const finding of findings) {
      const extKey = finding.extension || 'Unknown';
      if (!extensionMap.has(extKey)) {
        extensionMap.set(extKey, []);
      }
      extensionMap.get(extKey)!.push(finding);
    }

    // Build extension reports
    const extensions: ExtensionReport[] = [];
    const riskDistribution = { critical: 0, high: 0, medium: 0, low: 0, safe: 0 };

    for (const [extKey, extFindings] of extensionMap) {
      const { id, name } = this.parseExtensionKey(extKey);
      
      const critical = extFindings.filter(f => f.severity === 'critical');
      const warning = extFindings.filter(f => f.severity === 'warning');
      const info = extFindings.filter(f => f.severity === 'info');
      
      const riskScore = this.calculateRiskScore(critical.length, warning.length, info.length);
      const riskLevel = this.getRiskLevel(riskScore);
      
      riskDistribution[riskLevel]++;

      extensions.push({
        id,
        name,
        riskScore,
        riskLevel,
        findings: { critical, warning, info },
        summary: {
          critical: critical.length,
          warning: warning.length,
          info: info.length,
          total: extFindings.length,
        },
      });
    }

    // Sort by risk score (highest first)
    extensions.sort((a, b) => b.riskScore - a.riskScore);

    // Build rules summary
    const ruleMap = new Map<string, { finding: Finding; count: number }>();
    for (const f of findings) {
      if (!ruleMap.has(f.id)) {
        ruleMap.set(f.id, { finding: f, count: 0 });
      }
      ruleMap.get(f.id)!.count++;
    }

    const rules = Array.from(ruleMap.values())
      .map(({ finding, count }) => ({
        id: finding.id,
        severity: finding.severity,
        description: finding.message,
        recommendation: finding.recommendation,
        count,
      }))
      .sort((a, b) => {
        const severityOrder = { critical: 0, warning: 1, info: 2 };
        const aSev = severityOrder[a.severity as keyof typeof severityOrder] ?? 3;
        const bSev = severityOrder[b.severity as keyof typeof severityOrder] ?? 3;
        if (aSev !== bSev) return aSev - bSev;
        return b.count - a.count;
      });

    return {
      meta: {
        tool: 'ExtVet',
        version: '0.6.1',
        timestamp: new Date().toISOString(),
        browser: options.browserType || this.browser,
        profile: options.profile || this.profile,
      },
      summary: {
        totalExtensions: extensions.length,
        extensionsWithIssues: extensions.filter(e => e.summary.total > 0).length,
        critical: findings.filter(f => f.severity === 'critical').length,
        warning: findings.filter(f => f.severity === 'warning').length,
        info: findings.filter(f => f.severity === 'info').length,
        total: findings.length,
        riskDistribution,
      },
      extensions,
      rules,
    };
  }

  private parseExtensionKey(extKey: string): { id: string; name: string } {
    // Parse "Extension Name (extensionid)" format
    const match = extKey.match(/^(.+?)\s*\(([^)]+)\)$/);
    if (match) {
      return { name: match[1].trim(), id: match[2] };
    }
    return { name: extKey, id: extKey };
  }

  private calculateRiskScore(critical: number, warning: number, info: number): number {
    // Risk score: 0-100
    // Critical = 40 points each (max 100)
    // Warning = 15 points each (max 60)
    // Info = 2 points each (max 20)
    const score = Math.min(critical * 40, 100) + 
                  Math.min(warning * 15, 60) + 
                  Math.min(info * 2, 20);
    return Math.min(score, 100);
  }

  private getRiskLevel(score: number): 'critical' | 'high' | 'medium' | 'low' | 'safe' {
    if (score >= 80) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    if (score > 0) return 'low';
    return 'safe';
  }

  private printTable(findings: Finding[], summary: ScanSummary, options: ScanOptions): void {
    if (this.quiet) return;

    console.log('\n' + '─'.repeat(80));
    console.log('FINDINGS');
    console.log('─'.repeat(80));

    const critical = findings.filter(f => f.severity === 'critical');
    const warning = findings.filter(f => f.severity === 'warning');
    const info = findings.filter(f => f.severity === 'info');

    for (const finding of critical) {
      console.log(`\n🔴 CRITICAL: ${finding.message}`);
      console.log(`   Extension: ${finding.extension}`);
      console.log(`   Rule: ${finding.id}`);
      if (finding.recommendation) {
        console.log(`   Fix: ${finding.recommendation}`);
      }
    }

    for (const finding of warning) {
      console.log(`\n🟡 WARNING: ${finding.message}`);
      console.log(`   Extension: ${finding.extension}`);
      console.log(`   Rule: ${finding.id}`);
      if (finding.recommendation) {
        console.log(`   Fix: ${finding.recommendation}`);
      }
    }

    if (!options.severity || options.severity === 'info') {
      for (const finding of info) {
        console.log(`\n🔵 INFO: ${finding.message}`);
        console.log(`   Extension: ${finding.extension}`);
      }
    }

    console.log('\n' + '─'.repeat(80));
    console.log('SUMMARY');
    console.log('─'.repeat(80));
    console.log(`🔴 Critical: ${summary.critical}`);
    console.log(`🟡 Warning:  ${summary.warning}`);
    console.log(`🔵 Info:     ${summary.info}`);
    console.log(`📊 Total:    ${summary.total}`);
    console.log('─'.repeat(80) + '\n');
  }

  private toSarif(findings: Finding[]): SarifReport {
    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'ExtVet',
            informationUri: 'https://github.com/taku-tez/ExtVet',
            rules: this.extractRules(findings),
          },
        },
        results: findings.map(f => ({
          ruleId: f.id,
          level: f.severity === 'critical' ? 'error' : f.severity === 'warning' ? 'warning' : 'note',
          message: { text: f.message },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: f.extension },
            },
          }],
        })),
      }],
    };
  }

  private extractRules(findings: Finding[]): SarifRule[] {
    const ruleMap = new Map<string, SarifRule>();
    for (const f of findings) {
      if (!ruleMap.has(f.id)) {
        ruleMap.set(f.id, {
          id: f.id,
          shortDescription: { text: f.message },
        });
      }
    }
    return Array.from(ruleMap.values());
  }
}
