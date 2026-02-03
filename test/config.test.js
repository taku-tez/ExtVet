const { test, describe } = require('node:test');
const assert = require('node:assert');
const { 
  loadConfig, 
  mergeConfig, 
  applySeverityOverrides, 
  filterIgnoredExtensions,
  DEFAULT_CONFIG 
} = require('../src/config.js');

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
    const base = { a: 1, b: 2, arr: [1] };
    const override = { b: 3, c: 4, arr: [2] };
    const merged = mergeConfig(base, override);
    
    assert.strictEqual(merged.a, 1);
    assert.strictEqual(merged.b, 3);
    assert.strictEqual(merged.c, 4);
    assert.deepStrictEqual(merged.arr, [1, 2]);
  });
  
  test('mergeConfig handles undefined values', () => {
    const base = { a: 1 };
    const override = { a: undefined };
    const merged = mergeConfig(base, override);
    
    assert.strictEqual(merged.a, 1);
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
