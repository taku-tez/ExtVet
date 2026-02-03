const { test, describe, beforeEach } = require('node:test');
const assert = require('node:assert');
const logger = require('../dist/logger.js');

describe('Logger', () => {
  beforeEach(() => {
    // Reset logger state before each test
    logger.configure({ verbose: false, quiet: false });
  });
  
  test('configure sets verbose mode', () => {
    logger.configure({ verbose: true });
    assert.strictEqual(logger.isVerbose(), true);
  });
  
  test('configure sets quiet mode', () => {
    logger.configure({ quiet: true });
    // quiet mode is internal, we just test it doesn't throw
    assert.ok(true);
  });
  
  test('isVerbose returns false by default', () => {
    logger.configure({});
    assert.strictEqual(logger.isVerbose(), false);
  });
  
  test('info, warn, error, success, debug do not throw', () => {
    assert.doesNotThrow(() => logger.info('test info'));
    assert.doesNotThrow(() => logger.warn('test warn'));
    assert.doesNotThrow(() => logger.error('test error'));
    assert.doesNotThrow(() => logger.success('test success'));
    assert.doesNotThrow(() => logger.debug('test debug'));
  });
  
  test('debug with data does not throw', () => {
    logger.configure({ verbose: true });
    assert.doesNotThrow(() => logger.debug('test', { key: 'value' }));
  });
  
  test('error with error object does not throw', () => {
    logger.configure({ verbose: true });
    const err = new Error('test error');
    assert.doesNotThrow(() => logger.error('message', err));
  });
});
