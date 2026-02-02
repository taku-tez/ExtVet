/**
 * ExtVet - Browser Extension Security Scanner
 */

const { scanChrome } = require('./scanners/chrome.js');
const { scanFirefox } = require('./scanners/firefox.js');
const { checkWebStore } = require('./webstore.js');
const { Reporter } = require('./reporter.js');

const version = '0.4.0';

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
  
  reporter.start(`Checking extension: ${target}...`);
  
  const { info, findings } = await checkWebStore(target, options);
  
  if (info) {
    console.log(`  Found: ${info.name}`);
    if (info.users) console.log(`  Users: ${info.users.toLocaleString()}`);
    if (info.rating) console.log(`  Rating: ${info.rating.toFixed(1)}/5`);
    if (info.version) console.log(`  Version: ${info.version}`);
  }
  
  const summary = reporter.report(findings, options);
  
  return summary;
}

module.exports = {
  scan,
  scanUrl,
  version,
};
