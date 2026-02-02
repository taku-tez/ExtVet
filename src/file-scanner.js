/**
 * File Scanner
 * Scan local extension files (.crx, .xpi, .zip)
 */

const fs = require('fs');
const path = require('path');
const { extractCrx, cleanupExtracted: cleanupCrx } = require('./crx-extractor.js');
const { extractXpi, cleanupExtracted: cleanupXpi } = require('./xpi-extractor.js');
const { Reporter } = require('./reporter.js');

// Import analyzers from Chrome scanner
const { scanChrome } = require('./scanners/chrome.js');

// Dangerous permissions (shared)
const DANGEROUS_PERMISSIONS = {
  '<all_urls>': { severity: 'critical', msg: 'Access to ALL websites' },
  '*://*/*': { severity: 'critical', msg: 'Access to ALL websites' },
  'webRequestBlocking': { severity: 'critical', msg: 'Can modify/block network requests' },
  'nativeMessaging': { severity: 'critical', msg: 'Can communicate with native apps' },
  'debugger': { severity: 'critical', msg: 'Full debugging access to tabs' },
  'proxy': { severity: 'critical', msg: 'Can control proxy settings' },
  'cookies': { severity: 'warning', msg: 'Can read/write cookies' },
  'history': { severity: 'warning', msg: 'Can read browsing history' },
  'webRequest': { severity: 'warning', msg: 'Can intercept network requests' },
  'management': { severity: 'warning', msg: 'Can manage other extensions' },
  'tabs': { severity: 'info', msg: 'Can see all open tabs' },
  'storage': { severity: 'info', msg: 'Can store data locally' },
};

// Suspicious code patterns
const SUSPICIOUS_PATTERNS = [
  { pattern: /eval\s*\(/g, severity: 'critical', msg: 'Uses eval() - code injection risk' },
  { pattern: /new\s+Function\s*\(/g, severity: 'critical', msg: 'Uses Function constructor' },
  { pattern: /document\.write/g, severity: 'warning', msg: 'Uses document.write - XSS risk' },
  { pattern: /innerHTML\s*=/g, severity: 'info', msg: 'Uses innerHTML - potential XSS' },
  { pattern: /fetch\s*\(['"](http:\/\/)/g, severity: 'warning', msg: 'Insecure HTTP fetch' },
];

/**
 * Scan a local extension file
 * @param {string} filePath - Path to .crx, .xpi, or .zip file
 * @param {object} options - Scan options
 * @returns {object} Scan results
 */
async function scanFile(filePath, options = {}) {
  const reporter = new Reporter(options);
  const findings = [];
  
  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }
  
  const ext = path.extname(filePath).toLowerCase();
  const fileName = path.basename(filePath);
  
  reporter.start(`Scanning file: ${fileName}...`);
  
  let extractedPath = null;
  let cleanupFn = null;
  
  // Extract based on file type
  if (ext === '.crx') {
    extractedPath = extractCrx(filePath);
    cleanupFn = cleanupCrx;
  } else if (ext === '.xpi') {
    extractedPath = extractXpi(filePath);
    cleanupFn = cleanupXpi;
  } else if (ext === '.zip') {
    // Try CRX extractor (handles plain ZIP)
    extractedPath = extractCrx(filePath);
    cleanupFn = cleanupCrx;
  } else {
    throw new Error(`Unsupported file type: ${ext}. Supported: .crx, .xpi, .zip`);
  }
  
  if (!extractedPath) {
    throw new Error(`Failed to extract ${fileName}. Make sure 'unzip' is installed.`);
  }
  
  try {
    // Parse manifest
    const manifestPath = path.join(extractedPath, 'manifest.json');
    if (!fs.existsSync(manifestPath)) {
      throw new Error('No manifest.json found in extension');
    }
    
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
    console.log(`  Name: ${manifest.name || 'Unknown'}`);
    console.log(`  Version: ${manifest.version || 'Unknown'}`);
    
    // Analyze permissions
    const allPermissions = [
      ...(manifest.permissions || []),
      ...(manifest.optional_permissions || []),
      ...(manifest.host_permissions || []),
    ];
    
    for (const perm of allPermissions) {
      if (DANGEROUS_PERMISSIONS[perm]) {
        const danger = DANGEROUS_PERMISSIONS[perm];
        findings.push({
          id: `file-perm-${perm.replace(/[^a-z]/gi, '-')}`,
          severity: danger.severity,
          extension: manifest.name || fileName,
          message: `Permission: ${perm} - ${danger.msg}`,
          recommendation: `Review if "${perm}" permission is necessary`,
        });
      }
    }
    
    // Check manifest version
    if (manifest.manifest_version === 2) {
      findings.push({
        id: 'file-mv2-deprecated',
        severity: 'warning',
        extension: manifest.name || fileName,
        message: 'Uses Manifest V2 (deprecated)',
        recommendation: 'Update to Manifest V3',
      });
    }
    
    // Scan JavaScript files for suspicious patterns
    const jsFiles = findJsFiles(extractedPath);
    
    for (const jsFile of jsFiles) {
      try {
        const content = fs.readFileSync(jsFile, 'utf-8');
        const relPath = path.relative(extractedPath, jsFile);
        
        for (const pattern of SUSPICIOUS_PATTERNS) {
          const matches = content.match(pattern.pattern);
          if (matches) {
            findings.push({
              id: `file-code-${pattern.msg.replace(/[^a-z]/gi, '-').toLowerCase()}`,
              severity: pattern.severity,
              extension: manifest.name || fileName,
              message: `${pattern.msg} in ${relPath}`,
              recommendation: 'Review the code for security issues',
            });
          }
        }
      } catch (err) {
        // Skip unreadable files
      }
    }
    
  } finally {
    // Cleanup
    if (cleanupFn && extractedPath) {
      cleanupFn(extractedPath);
    }
  }
  
  const summary = reporter.report(findings, options);
  return summary;
}

/**
 * Find all JavaScript files in directory
 */
function findJsFiles(dir, files = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== '.git') {
        findJsFiles(fullPath, files);
      }
    } else if (entry.isFile() && entry.name.endsWith('.js')) {
      files.push(fullPath);
    }
  }
  
  return files;
}

module.exports = { scanFile };
