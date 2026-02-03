const { test, describe } = require('node:test');
const assert = require('node:assert');
const { 
  loadConfig, 
  mergeConfig, 
  applySeverityOverrides, 
  filterIgnoredExtensions,
  DEFAULT_CONFIG 
} = require('../dist/config.js');

describe('Config', () => {
  test('DEFAULT_CONFIG has expected properties', () => {
    assert.ok('ignoreExtensions' in DEFAULT_CONFIG);
    assert.ok('severityOverrides' in DEFAULT_CONFIG);
    assert.ok('customRules' in DEFAULT_CONFIG);
    assert.ok('browser' in DEFAULT_CONFIG);
    assert.ok('format' in DEFAULT_CONFIG);
    assert.ok('severity' in DEFAULT_CONFIG);
  });
  
  test('loadConfig returns default config when no file exists', () => {
    const config = loadConfig('/nonexistent/path');
    assert.deepStrictEqual(config.ignoreExtensions, []);
    assert.strictEqual(config.browser, 'chrome');
  });
  
  test('mergeConfig merges objects correctly', () => {
    const base = { ...DEFAULT_CONFIG, browser: 'chrome' };
    const override = { browser: 'firefox', ignoreExtensions: ['test-id'] };
    const merged = mergeConfig(base, override);
    
    assert.strictEqual(merged.browser, 'firefox');
    assert.deepStrictEqual(merged.ignoreExtensions, ['test-id']);
  });
  
  test('mergeConfig handles undefined values', () => {
    const base = { ...DEFAULT_CONFIG };
    const override = { browser: undefined };
    const merged = mergeConfig(base, override);
    
    assert.strictEqual(merged.browser, 'chrome');
  });
  
  test('applySeverityOverrides changes finding severity', () => {
    const findings = [
      { id: 'test-finding', severity: 'info', message: 'test' },
    ];
    const overrides = { 'test-finding': 'critical' };
    
    const result = applySeverityOverrides(findings, overrides);
    
    assert.strictEqual(result[0].severity, 'critical');
  });
  
  test('applySeverityOverrides with empty overrides returns original', () => {
    const findings = [
      { id: 'test-finding', severity: 'info', message: 'test' },
    ];
    
    const result = applySeverityOverrides(findings, {});
    
    assert.strictEqual(result[0].severity, 'info');
  });
  
  test('filterIgnoredExtensions filters by extension ID', () => {
    const findings = [
      { id: 'finding-1', extension: 'Test Ext (nkbihfbeogaeaoehlefnkodbefgpgknn)', severity: 'info' },
      { id: 'finding-2', extension: 'Other Ext (cjpalhdlnbpafiamejdnhcphjbkeiagm)', severity: 'info' },
    ];
    const ignoreList = ['nkbihfbeogaeaoehlefnkodbefgpgknn'];
    
    const result = filterIgnoredExtensions(findings, ignoreList);
    
    assert.strictEqual(result.length, 1);
    assert.strictEqual(result[0].id, 'finding-2');
  });
  
  test('filterIgnoredExtensions with empty list returns all', () => {
    const findings = [
      { id: 'finding-1', extension: 'Test Ext', severity: 'info' },
    ];
    
    const result = filterIgnoredExtensions(findings, []);
    
    assert.strictEqual(result.length, 1);
  });
});
