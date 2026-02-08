/**
 * ExtVet - Browser Extension Security Scanner
 */

import { scanChrome } from './scanners/chrome.js';
import { scanFirefox } from './scanners/firefox.js';
import { scanSafari } from './scanners/safari.js';
import { checkWebStore } from './webstore.js';
import { Reporter } from './reporter.js';
import { applySeverityOverrides, filterIgnoredExtensions } from './config.js';
import * as logger from './logger.js';
import type { ScanOptions, ScanSummary, Finding, WebStoreResult } from './types.js';
import { VERSION } from './constants.js';

export const version = VERSION;

/**
 * Scan installed browser extensions
 */
export async function scan(browser: string, options: ScanOptions = {}): Promise<ScanSummary> {
  logger.configure(options);
  
  const reporter = new Reporter(options);
  
  reporter.start(`Scanning ${browser} extensions...`);

  let findings: Finding[] = [];

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
    case 'safari':
      findings = await scanSafari(options);
      break;
    default:
      throw new Error(`Unknown browser: ${browser}`);
  }

  if (options.ignoreExtensions) {
    const before = findings.length;
    findings = filterIgnoredExtensions(findings, options.ignoreExtensions);
    logger.debug(`Filtered ignored extensions: ${before} -> ${findings.length} findings`);
  }
  
  if (options.severityOverrides) {
    findings = applySeverityOverrides(findings, options.severityOverrides);
    logger.debug('Applied severity overrides');
  }

  const summary = await reporter.report(findings, options);
  
  return summary;
}

/**
 * Scan a specific extension from URL or store ID
 */
export async function scanUrl(target: string, options: ScanOptions = {}): Promise<ScanSummary> {
  logger.configure(options);
  
  const reporter = new Reporter(options);
  
  reporter.start(`Checking extension: ${target}...`);
  
  const result: WebStoreResult = await checkWebStore(target, {});
  
  // Only print details in table format
  if (result.info && options.format !== 'json' && options.format !== 'sarif') {
    console.log(`  Found: ${result.info.name}`);
    if (result.info.users) console.log(`  Users: ${result.info.users.toLocaleString()}`);
    if (result.info.rating) console.log(`  Rating: ${result.info.rating.toFixed(1)}/5`);
    if (result.info.version) console.log(`  Version: ${result.info.version}`);
  }
  
  const summary = await reporter.report(result.findings, options);
  
  return summary;
}

// Re-export types
export type { ScanOptions, ScanSummary, Finding, ExtensionRiskScore } from './types.js';
export { calculateRiskScores, calculateOverallScore } from './risk-scorer.js';
export { loadPolicy, evaluatePolicy, generateSamplePolicy } from './policy.js';
export { exportBaseline, saveBaseline, loadBaseline, diffBaseline } from './baseline.js';
export type { Baseline, BaselineDiff } from './baseline.js';
export type { ExtensionPolicy, PolicyViolation } from './policy.js';
