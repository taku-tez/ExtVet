import { test, describe, mock } from 'node:test';
import assert from 'node:assert';
import { Reporter } from '../dist/reporter.js';

describe('Reporter', () => {
  const mockFindings = [
    { id: 'test-1', severity: 'critical', extension: 'Ext A (id-a)', message: 'Critical issue' },
    { id: 'test-2', severity: 'warning', extension: 'Ext A (id-a)', message: 'Warning issue' },
    { id: 'test-3', severity: 'info', extension: 'Ext B (id-b)', message: 'Info issue' },
  ];

  test('constructor initializes with default options', () => {
    const reporter = new Reporter();
    assert.ok(reporter);
  });

  test('constructor accepts options', () => {
    const reporter = new Reporter({ quiet: true, format: 'json' });
    assert.ok(reporter);
  });

  test('start prints message in table mode', () => {
    const reporter = new Reporter({ format: 'table' });
    assert.doesNotThrow(() => reporter.start('Test message'));
  });

  test('start does nothing in quiet mode', () => {
    const reporter = new Reporter({ quiet: true });
    assert.doesNotThrow(() => reporter.start('Test message'));
  });

  test('warn prints message in table mode', () => {
    const reporter = new Reporter({ format: 'table' });
    assert.doesNotThrow(() => reporter.warn('Warning message'));
  });

  test('warn does nothing in quiet mode', () => {
    const reporter = new Reporter({ quiet: true });
    assert.doesNotThrow(() => reporter.warn('Warning message'));
  });

  test('report returns correct summary counts', async () => {
    const reporter = new Reporter({ quiet: true, format: 'table' });
    const summary = await await reporter.report(mockFindings);
    
    assert.strictEqual(summary.critical, 1);
    assert.strictEqual(summary.warning, 1);
    assert.strictEqual(summary.info, 1);
    assert.strictEqual(summary.total, 3);
  });

  test('report handles empty findings', async () => {
    const reporter = new Reporter({ quiet: true, format: 'table' });
    const summary = await reporter.report([]);
    
    assert.strictEqual(summary.critical, 0);
    assert.strictEqual(summary.warning, 0);
    assert.strictEqual(summary.info, 0);
    assert.strictEqual(summary.total, 0);
  });

  test('report with json format outputs JSON', async () => {
    // Capture console.log output
    let output = '';
    const originalLog = console.log;
    console.log = (msg) => { output = msg; };
    
    try {
      const reporter = new Reporter({ format: 'json', browserType: 'chrome' });
      await reporter.report(mockFindings);
      
      // Verify it's valid JSON
      const parsed = JSON.parse(output);
      assert.ok(parsed.meta);
      assert.ok(parsed.summary);
      assert.ok(parsed.extensions);
      assert.strictEqual(parsed.meta.tool, 'ExtVet');
      assert.strictEqual(parsed.meta.browser, 'chrome');
    } finally {
      console.log = originalLog;
    }
  });

  test('report with sarif format outputs SARIF', async () => {
    let output = '';
    const originalLog = console.log;
    console.log = (msg) => { output = msg; };
    
    try {
      const reporter = new Reporter({ format: 'sarif' });
      await reporter.report(mockFindings);
      
      const parsed = JSON.parse(output);
      assert.strictEqual(parsed.$schema, 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json');
      assert.strictEqual(parsed.version, '2.1.0');
      assert.ok(Array.isArray(parsed.runs));
    } finally {
      console.log = originalLog;
    }
  });

  test('json output includes risk scores', async () => {
    let output = '';
    const originalLog = console.log;
    console.log = (msg) => { output = msg; };
    
    try {
      const reporter = new Reporter({ format: 'json' });
      await reporter.report(mockFindings);
      
      const parsed = JSON.parse(output);
      // Extensions is an array, find by id
      const extA = parsed.extensions.find(e => e.id === 'id-a');
      assert.ok(extA, 'Extension id-a should exist');
      assert.ok(typeof extA.riskScore === 'number');
      assert.ok(extA.riskScore >= 0 && extA.riskScore <= 100);
      assert.ok(['critical', 'high', 'medium', 'low', 'safe'].includes(extA.riskLevel));
    } finally {
      console.log = originalLog;
    }
  });

  test('json output includes summary risk distribution', async () => {
    let output = '';
    const originalLog = console.log;
    console.log = (msg) => { output = msg; };
    
    try {
      const reporter = new Reporter({ format: 'json' });
      await reporter.report(mockFindings);
      
      const parsed = JSON.parse(output);
      assert.ok(parsed.summary.riskDistribution);
      assert.ok('critical' in parsed.summary.riskDistribution);
      assert.ok('high' in parsed.summary.riskDistribution);
      assert.ok('medium' in parsed.summary.riskDistribution);
      assert.ok('low' in parsed.summary.riskDistribution);
      assert.ok('safe' in parsed.summary.riskDistribution);
    } finally {
      console.log = originalLog;
    }
  });

  test('report does not throw with table format', async () => {
    const reporter = new Reporter({ format: 'table', quiet: true });
    await reporter.report(mockFindings);
  });

  test('profile is included in json output', async () => {
    let output = '';
    const originalLog = console.log;
    console.log = (msg) => { output = msg; };
    
    try {
      const reporter = new Reporter({ format: 'json', profile: 'Default' });
      await reporter.report(mockFindings);
      
      const parsed = JSON.parse(output);
      assert.strictEqual(parsed.meta.profile, 'Default');
    } finally {
      console.log = originalLog;
    }
  });

  test('sarif output maps severity correctly', async () => {
    let output = '';
    const originalLog = console.log;
    console.log = (msg) => { output = msg; };
    
    try {
      const reporter = new Reporter({ format: 'sarif' });
      await reporter.report(mockFindings);
      
      const parsed = JSON.parse(output);
      const results = parsed.runs[0].results;
      
      // Critical should map to 'error'
      const critical = results.find(r => r.ruleId === 'test-1');
      assert.strictEqual(critical.level, 'error');
      
      // Warning should map to 'warning'
      const warning = results.find(r => r.ruleId === 'test-2');
      assert.strictEqual(warning.level, 'warning');
      
      // Info should map to 'note'
      const info = results.find(r => r.ruleId === 'test-3');
      assert.strictEqual(info.level, 'note');
    } finally {
      console.log = originalLog;
    }
  });
});

  test('report with html format outputs HTML', async () => {
    let output = '';
    const originalLog = console.log;
    console.log = (msg) => { output += msg; };
    
    try {
      const reporter = new Reporter({ format: 'html', quiet: false });
      await reporter.report([
        { id: 'test-1', severity: 'critical', extension: 'Bad Ext', message: 'Critical issue', recommendation: 'Fix it' },
      ]);
      
      assert.ok(output.includes('<!DOCTYPE html>'));
      assert.ok(output.includes('ExtVet Security Report'));
      assert.ok(output.includes('Critical issue'));
      assert.ok(output.includes('Bad Ext'));
    } finally {
      console.log = originalLog;
    }
  });

  test('html output escapes HTML entities', async () => {
    let output = '';
    const originalLog = console.log;
    console.log = (msg) => { output += msg; };
    
    try {
      const reporter = new Reporter({ format: 'html' });
      await reporter.report([
        { id: 'test-xss', severity: 'warning', extension: '<script>alert(1)</script>', message: 'Test <b>bold</b>' },
      ]);
      
      assert.ok(output.includes('&lt;script&gt;'));
      assert.ok(!output.includes('<script>alert'));
    } finally {
      console.log = originalLog;
    }
  });

  test('html output shows no-issues message for empty findings', async () => {
    let output = '';
    const originalLog = console.log;
    console.log = (msg) => { output += msg; };
    
    try {
      const reporter = new Reporter({ format: 'html' });
      await reporter.report([]);
      
      assert.ok(output.includes('No security issues found'));
    } finally {
      console.log = originalLog;
    }
  });

  test('report with markdown format outputs markdown', async () => {
    let output = '';
    const originalLog = console.log;
    console.log = (msg) => { output += msg; };
    
    try {
      const reporter = new Reporter({ format: 'markdown' });
      await reporter.report([
        { id: 'test-1', severity: 'critical', extension: 'Bad Ext', message: 'Critical issue', recommendation: 'Fix it' },
      ]);
      
      assert.ok(output.includes('# 🦅 ExtVet Security Report'));
      assert.ok(output.includes('Critical issue'));
      assert.ok(output.includes('Bad Ext'));
      assert.ok(output.includes('💡 Fix it'));
    } finally {
      console.log = originalLog;
    }
  });
