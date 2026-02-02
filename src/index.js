/**
 * ExtVet - Browser Extension Security Scanner
 */

const { scanChrome } = require('./scanners/chrome.js');
const { scanFirefox } = require('./scanners/firefox.js');
const { Reporter } = require('./reporter.js');

const version = '0.2.0';

/**
 * Scan installed browser extensions
 * @param {string} browser - Browser type (chrome, firefox, edge, brave)
 * @param {object} options - Scan options
 * @returns {object} Scan results
 */
async function scan(browser, options = {}) {
  const reporter = new Reporter(options);
  
  reporter.start(`Scanning ${browser} extensions...`);

  let findings = [];

  switch (browser.toLowerCase()) {
    case 'chrome':
    case 'chromium':
      findings = await scanChrome(options);
      break;
    case 'brave':
      options.browserType = 'brave';
      findings = await scanChrome(options);
      break;
    case 'edge':
      options.browserType = 'edge';
      findings = await scanChrome(options);
      break;
    case 'firefox':
      findings = await scanFirefox(options);
      break;
    default:
      throw new Error(`Unknown browser: ${browser}`);
  }

  const summary = reporter.report(findings, options);
  
  return summary;
}

/**
 * Scan a specific extension from URL or store ID
 * @param {string} target - Extension URL or ID
 * @param {object} options - Scan options
 * @returns {object} Scan results
 */
async function scanUrl(target, options = {}) {
  const reporter = new Reporter(options);
  
  // Extract extension ID from URL if needed
  let extensionId = target;
  if (target.includes('chrome.google.com') || target.includes('chromewebstore')) {
    const match = target.match(/\/([a-z]{32})/);
    if (match) extensionId = match[1];
  }
  
  reporter.start(`Checking extension: ${extensionId}...`);
  
  // TODO: Implement web store lookup
  reporter.warn('Web store checking not yet implemented');
  
  return { critical: 0, warning: 0, info: 0 };
}

module.exports = {
  scan,
  scanUrl,
  version,
};
