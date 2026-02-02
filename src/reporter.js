/**
 * Reporter - Output formatting for ExtVet
 */

class Reporter {
  constructor(options = {}) {
    this.quiet = options.quiet || false;
    this.format = options.format || 'table';
  }

  start(message) {
    if (!this.quiet) {
      console.log(`\n🦅 ExtVet - Browser Extension Security Scanner\n`);
      console.log(message);
    }
  }

  warn(message) {
    if (!this.quiet) {
      console.log(`⚠️  ${message}`);
    }
  }

  report(findings, options = {}) {
    const summary = {
      critical: findings.filter(f => f.severity === 'critical').length,
      warning: findings.filter(f => f.severity === 'warning').length,
      info: findings.filter(f => f.severity === 'info').length,
      total: findings.length,
    };

    if (this.format === 'json') {
      console.log(JSON.stringify({ findings, summary }, null, 2));
      return summary;
    }

    if (this.format === 'sarif') {
      console.log(JSON.stringify(this.toSarif(findings), null, 2));
      return summary;
    }

    // Table format (default)
    if (!this.quiet) {
      console.log('\n' + '─'.repeat(80));
      console.log('FINDINGS');
      console.log('─'.repeat(80));
    }

    // Group by severity
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

    // Summary
    console.log('\n' + '─'.repeat(80));
    console.log('SUMMARY');
    console.log('─'.repeat(80));
    console.log(`🔴 Critical: ${summary.critical}`);
    console.log(`🟡 Warning:  ${summary.warning}`);
    console.log(`🔵 Info:     ${summary.info}`);
    console.log(`📊 Total:    ${summary.total}`);
    console.log('─'.repeat(80) + '\n');

    return summary;
  }

  toSarif(findings) {
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

  extractRules(findings) {
    const ruleMap = new Map();
    for (const f of findings) {
      if (!ruleMap.has(f.id)) {
        ruleMap.set(f.id, {
          id: f.id,
          shortDescription: { text: f.message },
          helpUri: f.reference || undefined,
        });
      }
    }
    return Array.from(ruleMap.values());
  }
}

module.exports = { Reporter };
