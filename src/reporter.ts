/**
 * Reporter - Output formatting for ExtVet
 */

import type { Finding, ScanOptions, ScanSummary } from './types.js';
import { VERSION } from './constants.js';

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

  async report(findings: Finding[], options: ScanOptions = {}): Promise<ScanSummary> {
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

    if (this.format === 'html') {
      const html = this.toHtml(findings, options);
      if (options.output) {
        const fs = await import('fs');
        fs.writeFileSync(options.output, html);
        if (!this.quiet) console.log(`📄 HTML report saved to ${options.output}`);
      } else {
        console.log(html);
      }
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
        version: VERSION,
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

  private toHtml(findings: Finding[], options: ScanOptions): string {
    const critical = findings.filter(f => f.severity === 'critical');
    const warning = findings.filter(f => f.severity === 'warning');
    const info = findings.filter(f => f.severity === 'info');
    const timestamp = new Date().toISOString().replace('T', ' ').split('.')[0];

    const severityIcon = (s: string) => s === 'critical' ? '🔴' : s === 'warning' ? '🟡' : '🔵';
    const severityClass = (s: string) => s === 'critical' ? 'critical' : s === 'warning' ? 'warning' : 'info';

    const renderFindings = (items: Finding[]) => items.map(f => `
      <tr class="${severityClass(f.severity)}">
        <td>${severityIcon(f.severity)} ${f.severity.toUpperCase()}</td>
        <td>${this.escapeHtml(f.extension)}</td>
        <td>${this.escapeHtml(f.message)}</td>
        <td>${this.escapeHtml(f.recommendation || '-')}</td>
        <td><code>${this.escapeHtml(f.id)}</code></td>
      </tr>`).join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ExtVet Security Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }
  h1 { color: #58a6ff; margin-bottom: 0.5rem; }
  .meta { color: #8b949e; margin-bottom: 2rem; font-size: 0.9rem; }
  .summary { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; min-width: 150px; text-align: center; }
  .card .count { font-size: 2rem; font-weight: bold; }
  .card.critical .count { color: #f85149; }
  .card.warning .count { color: #d29922; }
  .card.info .count { color: #58a6ff; }
  .card.total .count { color: #c9d1d9; }
  .card .label { color: #8b949e; font-size: 0.85rem; margin-top: 0.25rem; }
  table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; margin-top: 1rem; }
  th { background: #21262d; color: #c9d1d9; text-align: left; padding: 0.75rem 1rem; font-size: 0.85rem; border-bottom: 1px solid #30363d; }
  td { padding: 0.6rem 1rem; border-bottom: 1px solid #21262d; font-size: 0.85rem; vertical-align: top; }
  tr.critical td { border-left: 3px solid #f85149; }
  tr.warning td { border-left: 3px solid #d29922; }
  tr.info td { border-left: 3px solid #58a6ff; }
  code { background: #21262d; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.8rem; }
  .footer { margin-top: 2rem; color: #484f58; font-size: 0.8rem; text-align: center; }
  a { color: #58a6ff; }
</style>
</head>
<body>
<h1>🦅 ExtVet Security Report</h1>
<div class="meta">
  Generated: ${timestamp} | Browser: ${options.browserType || this.browser || 'unknown'} | ExtVet v${VERSION}
</div>
<div class="summary">
  <div class="card critical"><div class="count">${critical.length}</div><div class="label">Critical</div></div>
  <div class="card warning"><div class="count">${warning.length}</div><div class="label">Warning</div></div>
  <div class="card info"><div class="count">${info.length}</div><div class="label">Info</div></div>
  <div class="card total"><div class="count">${findings.length}</div><div class="label">Total</div></div>
</div>
${findings.length > 0 ? `
<table>
<thead><tr><th>Severity</th><th>Extension</th><th>Finding</th><th>Recommendation</th><th>Rule</th></tr></thead>
<tbody>
${renderFindings(critical)}
${renderFindings(warning)}
${renderFindings(info)}
</tbody>
</table>` : '<p style="text-align:center;color:#3fb950;font-size:1.5rem;margin:3rem 0;">✅ No security issues found!</p>'}
<div class="footer">
  <a href="https://github.com/taku-tez/ExtVet">ExtVet</a> — Browser Extension Security Scanner
</div>
</body>
</html>`;
  }

  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
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
