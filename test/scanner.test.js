const { test } = require('node:test');
const assert = require('node:assert');
const { scan, version } = require('../src/index.js');

test('version is defined', () => {
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
  // This will likely return empty results in CI (no browser installed)
  const results = await scan('firefox', { quiet: true });
  assert.ok(typeof results === 'object');
  assert.ok('critical' in results);
  assert.ok('warning' in results);
  assert.ok('info' in results);
});

test('unknown browser throws error', async () => {
  await assert.rejects(
    () => scan('netscape', { quiet: true }),
    /Unknown browser/
  );
});
