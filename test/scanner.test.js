const { test, describe } = require('node:test');
const assert = require('node:assert');
const { scan, scanUrl, version } = require('../dist/index.js');

describe('ExtVet Core', () => {
  test('version is defined and valid semver', () => {
    assert.ok(version);
    assert.match(version, /^\d+\.\d+\.\d+$/);
  });
  
  test('scan chrome returns object with summary', async () => {
    // This will likely return empty results in CI (no browser installed)
    const results = await scan('chrome', { quiet: true });
    assert.ok(typeof results === 'object');
    assert.ok('critical' in results);
    assert.ok('warning' in results);
    assert.ok('info' in results);
  });

  test('scan firefox returns object with summary', async () => {
    const results = await scan('firefox', { quiet: true });
    assert.ok(typeof results === 'object');
    assert.ok('critical' in results);
    assert.ok('warning' in results);
    assert.ok('info' in results);
  });
  
  test('scan brave returns object with summary', async () => {
    const results = await scan('brave', { quiet: true });
    assert.ok(typeof results === 'object');
    assert.ok('critical' in results);
  });
  
  test('scan edge returns object with summary', async () => {
    const results = await scan('edge', { quiet: true });
    assert.ok(typeof results === 'object');
    assert.ok('critical' in results);
  });
  
  test('scan safari returns object with summary', async () => {
    // Will return empty on non-macOS, but should not error
    const results = await scan('safari', { quiet: true });
    assert.ok(typeof results === 'object');
    assert.ok('critical' in results);
  });

  test('unknown browser throws error', async () => {
    await assert.rejects(
      () => scan('netscape', { quiet: true }),
      /Unknown browser/
    );
  });

  test('scanUrl returns object with summary', async () => {
    // Test with Firefox Add-on
    const results = await scanUrl('ublock-origin', { quiet: true });
    assert.ok(typeof results === 'object');
    assert.ok('critical' in results);
    assert.ok('warning' in results);
    assert.ok('info' in results);
  });
});
