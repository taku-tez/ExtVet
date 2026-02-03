/**
 * Chrome Extension Scanner
 * Scans installed Chrome/Chromium-based browser extensions
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as logger from '../logger.js';
import type { Finding, ScanOptions, ExtensionInfo, Manifest, PermissionDanger, SuspiciousPattern } from '../types.js';

// Dangerous permissions that need review
const DANGEROUS_PERMISSIONS: Record<string, PermissionDanger> = {
  '<all_urls>': { severity: 'critical', msg: 'Access to ALL websites' },
  '*://*/*': { severity: 'critical', msg: 'Access to ALL websites' },
  'http://*/*': { severity: 'warning', msg: 'Access to all HTTP sites' },
  'https://*/*': { severity: 'warning', msg: 'Access to all HTTPS sites' },
  'cookies': { severity: 'warning', msg: 'Can read/write cookies (session hijacking risk)' },
  'webRequest': { severity: 'warning', msg: 'Can intercept network requests' },
  'webRequestBlocking': { severity: 'critical', msg: 'Can modify/block network requests' },
  'proxy': { severity: 'critical', msg: 'Can control proxy settings (MitM risk)' },
  'debugger': { severity: 'critical', msg: 'Full debugging access to tabs' },
  'nativeMessaging': { severity: 'critical', msg: 'Can communicate with native apps' },
  'tabs': { severity: 'info', msg: 'Can see all open tabs and URLs' },
  'history': { severity: 'warning', msg: 'Can read browsing history' },
  'bookmarks': { severity: 'info', msg: 'Can read/modify bookmarks' },
  'downloads': { severity: 'info', msg: 'Can access downloads' },
  'management': { severity: 'warning', msg: 'Can manage other extensions' },
  'privacy': { severity: 'warning', msg: 'Can modify privacy settings' },
  'browsingData': { severity: 'warning', msg: 'Can clear browsing data' },
  'storage': { severity: 'info', msg: 'Can store data locally' },
  'clipboardRead': { severity: 'warning', msg: 'Can read clipboard' },
  'clipboardWrite': { severity: 'info', msg: 'Can write to clipboard' },
  'geolocation': { severity: 'warning', msg: 'Can access location' },
  'notifications': { severity: 'info', msg: 'Can show notifications' },
};

// Known suspicious patterns in extension code
const SUSPICIOUS_PATTERNS: SuspiciousPattern[] = [
  { pattern: /eval\s*\(/g, severity: 'critical', msg: 'Uses eval() - code injection risk' },
  { pattern: /new\s+Function\s*\(/g, severity: 'critical', msg: 'Uses Function constructor - code injection risk' },
  { pattern: /document\.write/g, severity: 'warning', msg: 'Uses document.write - XSS risk' },
  { pattern: /innerHTML\s*=/g, severity: 'info', msg: 'Uses innerHTML - potential XSS' },
  { pattern: /chrome\.runtime\.sendMessage.*\*:\/\//g, severity: 'warning', msg: 'External message passing' },
  { pattern: /fetch\s*\(['"](http:\/\/)/g, severity: 'warning', msg: 'Insecure HTTP fetch' },
  { pattern: /XMLHttpRequest.*http:/g, severity: 'warning', msg: 'Insecure HTTP XHR' },
  { pattern: /atob|btoa/g, severity: 'info', msg: 'Base64 encoding (check for obfuscation)' },
  { pattern: /crypto\.subtle/g, severity: 'info', msg: 'Uses Web Crypto API' },
  { pattern: /WebSocket\s*\(/g, severity: 'info', msg: 'Uses WebSocket connections' },
  { pattern: /declarativeNetRequest\.updateSessionRules/g, severity: 'warning', msg: 'Modifies browser network rules dynamically' },
  { pattern: /content-security-policy.*operation.*set.*value.*['"]{2}/gi, severity: 'critical', msg: 'CSP stripping attack - removes Content Security Policy' },
  { pattern: /modifyHeaders.*responseHeaders.*content-security-policy/gi, severity: 'critical', msg: 'CSP header manipulation detected' },
  { pattern: /header.*content-security-policy.*operation.*remove/gi, severity: 'critical', msg: 'CSP header removal detected' },
  { pattern: /webRequest\.onBeforeRequest.*<all_urls>/g, severity: 'warning', msg: 'Intercepts all web requests' },
  { pattern: /webRequest\.onHeadersReceived.*blocking/g, severity: 'warning', msg: 'Modifies HTTP response headers' },
  { pattern: /chrome\.storage\.local\.set.*configUpdateInterval/g, severity: 'warning', msg: 'Dynamic config update pattern (potential C2)' },
  { pattern: /setInterval.*fetch.*chrome\.storage/g, severity: 'warning', msg: 'Periodic remote config fetch' },
  { pattern: /chrome\.cookies\.getAll\s*\(\s*\{\s*\}/g, severity: 'critical', msg: 'Attempts to read all cookies' },
  { pattern: /document\.cookie.*fetch|fetch.*document\.cookie/g, severity: 'critical', msg: 'Cookie exfiltration pattern' },
  { pattern: /localStorage.*fetch|fetch.*localStorage/g, severity: 'warning', msg: 'LocalStorage exfiltration pattern' },
];

let KNOWN_MALICIOUS: Set<string> | null = null;

async function loadMaliciousDb(options: ScanOptions = {}): Promise<Set<string>> {
  if (KNOWN_MALICIOUS) return KNOWN_MALICIOUS;
  
  try {
    const { getMaliciousIds } = await import('../malicious-db.js');
    KNOWN_MALICIOUS = await getMaliciousIds({ quiet: true, ...options });
    logger.debug(`Loaded ${KNOWN_MALICIOUS.size} malicious extension IDs`);
  } catch (err) {
    logger.warn(`Failed to load malicious DB: ${(err as Error).message}`);
    KNOWN_MALICIOUS = new Set();
  }
  
  return KNOWN_MALICIOUS;
}

function getExtensionPaths(options: ScanOptions = {}): string[] {
  const browserType = options.browserType || 'chrome';
  const platform = os.platform();
  const home = os.homedir();
  
  const paths: Record<string, Record<string, string[]>> = {
    chrome: {
      darwin: [
        path.join(home, 'Library/Application Support/Google/Chrome'),
        path.join(home, 'Library/Application Support/Google/Chrome Canary'),
      ],
      linux: [
        path.join(home, '.config/google-chrome'),
        path.join(home, '.config/chromium'),
      ],
      win32: [
        path.join(home, 'AppData/Local/Google/Chrome/User Data'),
      ],
    },
    brave: {
      darwin: [path.join(home, 'Library/Application Support/BraveSoftware/Brave-Browser')],
      linux: [path.join(home, '.config/BraveSoftware/Brave-Browser')],
      win32: [path.join(home, 'AppData/Local/BraveSoftware/Brave-Browser/User Data')],
    },
    edge: {
      darwin: [path.join(home, 'Library/Application Support/Microsoft Edge')],
      linux: [path.join(home, '.config/microsoft-edge')],
      win32: [path.join(home, 'AppData/Local/Microsoft/Edge/User Data')],
    },
  };

  return paths[browserType]?.[platform] || [];
}

function findExtensions(basePaths: string[], options: ScanOptions = {}): ExtensionInfo[] {
  const extensions: ExtensionInfo[] = [];
  
  for (const basePath of basePaths) {
    if (!fs.existsSync(basePath)) continue;
    
    const profiles = ['Default', 'Profile 1', 'Profile 2', 'Profile 3'];
    if (options.profile) {
      profiles.unshift(options.profile);
    }
    
    for (const profile of profiles) {
      const extensionsDir = path.join(basePath, profile, 'Extensions');
      if (!fs.existsSync(extensionsDir)) continue;
      
      try {
        const extIds = fs.readdirSync(extensionsDir);
        for (const extId of extIds) {
          const extPath = path.join(extensionsDir, extId);
          if (!fs.statSync(extPath).isDirectory()) continue;
          
          const versions = fs.readdirSync(extPath).filter(v => {
            const vPath = path.join(extPath, v);
            return fs.statSync(vPath).isDirectory();
          }).sort().reverse();
          
          if (versions.length > 0) {
            extensions.push({
              id: extId,
              path: path.join(extPath, versions[0]),
              version: versions[0],
              profile,
            });
          }
        }
      } catch (err) {
        logger.debug(`Skipping inaccessible directory: ${extensionsDir}`, { error: (err as Error).message });
      }
    }
  }
  
  return extensions;
}

function parseManifest(extPath: string): Manifest | null {
  const manifestPath = path.join(extPath, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    logger.debug(`No manifest.json found at ${extPath}`);
    return null;
  }
  
  try {
    const content = fs.readFileSync(manifestPath, 'utf-8');
    return JSON.parse(content) as Manifest;
  } catch (err) {
    logger.warn(`Failed to parse manifest at ${manifestPath}: ${(err as Error).message}`);
    return null;
  }
}

function analyzePermissions(manifest: Manifest, extInfo: ExtensionInfo): Finding[] {
  const findings: Finding[] = [];
  const allPermissions = [
    ...(manifest.permissions || []),
    ...(manifest.optional_permissions || []),
    ...(manifest.host_permissions || []),
  ];
  
  for (const perm of allPermissions) {
    if (DANGEROUS_PERMISSIONS[perm]) {
      const danger = DANGEROUS_PERMISSIONS[perm];
      findings.push({
        id: `ext-perm-${perm.replace(/[^a-z]/gi, '-')}`,
        severity: danger.severity,
        extension: `${manifest.name} (${extInfo.id})`,
        message: `Permission: ${perm} - ${danger.msg}`,
        recommendation: `Review if "${perm}" permission is necessary`,
      });
    }
    
    if (perm.includes('://') && !DANGEROUS_PERMISSIONS[perm]) {
      if (perm.includes('*')) {
        findings.push({
          id: 'ext-perm-wildcard-host',
          severity: 'info',
          extension: `${manifest.name} (${extInfo.id})`,
          message: `Host permission: ${perm}`,
          recommendation: 'Verify this host access is expected',
        });
      }
    }
  }
  
  if (manifest.manifest_version === 2) {
    findings.push({
      id: 'ext-mv2-deprecated',
      severity: 'warning',
      extension: `${manifest.name} (${extInfo.id})`,
      message: 'Uses Manifest V2 (deprecated, will be removed)',
      recommendation: 'Update to Manifest V3 or find alternative extension',
    });
  }
  
  return findings;
}

function analyzeContentScripts(manifest: Manifest, extInfo: ExtensionInfo): Finding[] {
  const findings: Finding[] = [];
  const contentScripts = manifest.content_scripts || [];
  
  for (const cs of contentScripts) {
    const matches = cs.matches || [];
    
    if (matches.includes('<all_urls>') || matches.includes('*://*/*')) {
      findings.push({
        id: 'ext-cs-all-urls',
        severity: 'warning',
        extension: `${manifest.name} (${extInfo.id})`,
        message: 'Content script injects into ALL pages',
        recommendation: 'Limit content script to specific domains if possible',
      });
    }
    
    if (cs.run_at === 'document_start') {
      findings.push({
        id: 'ext-cs-document-start',
        severity: 'info',
        extension: `${manifest.name} (${extInfo.id})`,
        message: 'Content script runs at document_start (can modify page before load)',
      });
    }
    
    if (cs.world === 'MAIN') {
      findings.push({
        id: 'ext-cs-main-world',
        severity: 'warning',
        extension: `${manifest.name} (${extInfo.id})`,
        message: 'Content script runs in MAIN world (full page access)',
        recommendation: 'MAIN world scripts can interact with page JavaScript',
      });
    }
  }
  
  return findings;
}

function analyzeBackground(manifest: Manifest, extInfo: ExtensionInfo, extPath: string): Finding[] {
  const findings: Finding[] = [];
  const bgScripts: string[] = [];
  
  if (manifest.background) {
    if (manifest.background.service_worker) {
      bgScripts.push(manifest.background.service_worker);
    }
    if (manifest.background.scripts) {
      bgScripts.push(...manifest.background.scripts);
    }
  }
  
  for (const script of bgScripts) {
    const scriptPath = path.join(extPath, script);
    if (!fs.existsSync(scriptPath)) continue;
    
    try {
      const content = fs.readFileSync(scriptPath, 'utf-8');
      
      for (const pattern of SUSPICIOUS_PATTERNS) {
        const matches = content.match(pattern.pattern);
        if (matches) {
          findings.push({
            id: `ext-code-${pattern.msg.replace(/[^a-z]/gi, '-').toLowerCase()}`,
            severity: pattern.severity,
            extension: `${manifest.name} (${extInfo.id})`,
            message: `${pattern.msg} in ${script}`,
            recommendation: 'Review the code for potential security issues',
          });
        }
      }
      
      const urlMatches = content.match(/https?:\/\/[^\s"']+/g) || [];
      const externalUrls = urlMatches.filter(url => {
        const legitimate = [
          'chrome.google.com',
          'googleapis.com',
          'gstatic.com',
          'mozilla.org',
          'github.com',
          'githubusercontent.com',
          'cloudflare.com',
          'cdn.jsdelivr.net',
          'unpkg.com',
        ];
        return !legitimate.some(d => url.includes(d));
      });
      
      if (externalUrls.length > 0) {
        findings.push({
          id: 'ext-external-urls',
          severity: 'info',
          extension: `${manifest.name} (${extInfo.id})`,
          message: `Connects to external URLs: ${externalUrls.slice(0, 3).join(', ')}${externalUrls.length > 3 ? '...' : ''}`,
          recommendation: 'Verify these external connections are expected',
        });
      }
      
    } catch (err) {
      logger.debug(`Failed to analyze script ${script}: ${(err as Error).message}`);
    }
  }
  
  return findings;
}

function checkKnownMalicious(extInfo: ExtensionInfo, manifest: Manifest): Finding[] {
  const findings: Finding[] = [];
  
  if (KNOWN_MALICIOUS && KNOWN_MALICIOUS.has(extInfo.id)) {
    findings.push({
      id: 'ext-known-malicious',
      severity: 'critical',
      extension: `${manifest.name} (${extInfo.id})`,
      message: 'Extension is flagged as KNOWN MALICIOUS',
      recommendation: 'Remove this extension immediately',
    });
  }
  
  return findings;
}

export async function scanChrome(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];
  
  logger.debug('Starting Chrome scanner', { options: { ...options, quiet: undefined } });
  
  await loadMaliciousDb(options);
  
  const basePaths = getExtensionPaths(options);
  logger.debug('Extension base paths', basePaths);
  
  if (basePaths.length === 0) {
    logger.info('  No browser installation found');
    return findings;
  }
  
  const extensions = findExtensions(basePaths, options);
  logger.info(`  Found ${extensions.length} extensions`);
  logger.debug('Found extensions', extensions.map(e => ({ id: e.id, profile: e.profile })));
  
  for (const ext of extensions) {
    const manifest = parseManifest(ext.path);
    if (!manifest) {
      logger.debug(`Skipping extension without manifest: ${ext.id}`);
      continue;
    }
    
    logger.info(`  Scanning: ${manifest.name || ext.id}`);
    logger.debug('Extension details', { id: ext.id, version: ext.version, path: ext.path });
    
    findings.push(...checkKnownMalicious(ext, manifest));
    findings.push(...analyzePermissions(manifest, ext));
    findings.push(...analyzeContentScripts(manifest, ext));
    findings.push(...analyzeBackground(manifest, ext, ext.path));
  }
  
  logger.debug(`Scan complete, ${findings.length} findings`);
  return findings;
}
