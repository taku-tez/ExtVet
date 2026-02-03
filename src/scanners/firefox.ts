/**
 * Firefox Add-on Scanner
 * Scans installed Firefox add-ons for security issues
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as logger from '../logger.js';
import type { Finding, ScanOptions, ExtensionInfo, Manifest, PermissionDanger, SuspiciousPattern } from '../types.js';

const DANGEROUS_PERMISSIONS: Record<string, PermissionDanger> = {
  '<all_urls>': { severity: 'critical', msg: 'Access to ALL websites' },
  '*://*/*': { severity: 'critical', msg: 'Access to ALL websites' },
  'http://*/*': { severity: 'warning', msg: 'Access to all HTTP sites' },
  'https://*/*': { severity: 'warning', msg: 'Access to all HTTPS sites' },
  'cookies': { severity: 'warning', msg: 'Can read/write cookies (session hijacking risk)' },
  'webRequest': { severity: 'warning', msg: 'Can intercept network requests' },
  'webRequestBlocking': { severity: 'critical', msg: 'Can modify/block network requests' },
  'webRequestFilterResponse': { severity: 'critical', msg: 'Can filter response bodies' },
  'proxy': { severity: 'critical', msg: 'Can control proxy settings (MitM risk)' },
  'nativeMessaging': { severity: 'critical', msg: 'Can communicate with native apps' },
  'browserSettings': { severity: 'warning', msg: 'Can modify browser settings' },
  'dns': { severity: 'critical', msg: 'Can perform DNS resolution' },
  'pkcs11': { severity: 'critical', msg: 'Can access PKCS #11 security modules' },
  'tabs': { severity: 'info', msg: 'Can see all open tabs and URLs' },
  'history': { severity: 'warning', msg: 'Can read browsing history' },
  'bookmarks': { severity: 'info', msg: 'Can read/modify bookmarks' },
  'downloads': { severity: 'info', msg: 'Can access downloads' },
  'management': { severity: 'warning', msg: 'Can manage other extensions' },
  'privacy': { severity: 'warning', msg: 'Can modify privacy settings' },
  'browsingData': { severity: 'warning', msg: 'Can clear browsing data' },
  'sessions': { severity: 'warning', msg: 'Can access session data' },
  'geckoProfiler': { severity: 'critical', msg: 'Can access the Gecko profiler' },
  'contextualIdentities': { severity: 'warning', msg: 'Can access container tabs' },
  'storage': { severity: 'info', msg: 'Can store data locally' },
  'clipboardRead': { severity: 'warning', msg: 'Can read clipboard' },
  'clipboardWrite': { severity: 'info', msg: 'Can write to clipboard' },
  'geolocation': { severity: 'warning', msg: 'Can access location' },
  'notifications': { severity: 'info', msg: 'Can show notifications' },
};

const SUSPICIOUS_PATTERNS: SuspiciousPattern[] = [
  { pattern: /eval\s*\(/g, severity: 'critical', msg: 'Uses eval() - code injection risk' },
  { pattern: /new\s+Function\s*\(/g, severity: 'critical', msg: 'Uses Function constructor - code injection risk' },
  { pattern: /document\.write/g, severity: 'warning', msg: 'Uses document.write - XSS risk' },
  { pattern: /innerHTML\s*=/g, severity: 'info', msg: 'Uses innerHTML - potential XSS' },
  { pattern: /browser\.runtime\.sendMessage.*\*:\/\//g, severity: 'warning', msg: 'External message passing' },
  { pattern: /fetch\s*\(['"](http:\/\/)/g, severity: 'warning', msg: 'Insecure HTTP fetch' },
  { pattern: /XMLHttpRequest.*http:/g, severity: 'warning', msg: 'Insecure HTTP XHR' },
  { pattern: /atob|btoa/g, severity: 'info', msg: 'Base64 encoding (check for obfuscation)' },
  { pattern: /crypto\.subtle/g, severity: 'info', msg: 'Uses Web Crypto API' },
  { pattern: /WebSocket\s*\(/g, severity: 'info', msg: 'Uses WebSocket connections' },
  { pattern: /browser\.webRequest\.filterResponseData/g, severity: 'warning', msg: 'Filters response data' },
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

function getFirefoxPaths(): string[] {
  const platform = os.platform();
  const home = os.homedir();
  
  const paths: Record<string, string[]> = {
    darwin: [path.join(home, 'Library/Application Support/Firefox/Profiles')],
    linux: [
      path.join(home, '.mozilla/firefox'),
      path.join(home, 'snap/firefox/common/.mozilla/firefox'),
      path.join(home, '.var/app/org.mozilla.firefox/.mozilla/firefox'),
    ],
    win32: [path.join(home, 'AppData/Roaming/Mozilla/Firefox/Profiles')],
  };

  return paths[platform] || [];
}

interface Profile {
  name: string;
  path: string;
}

function findProfiles(basePaths: string[]): Profile[] {
  const profiles: Profile[] = [];
  
  for (const basePath of basePaths) {
    if (!fs.existsSync(basePath)) continue;
    
    try {
      const entries = fs.readdirSync(basePath);
      
      for (const entry of entries) {
        const profilePath = path.join(basePath, entry);
        if (!fs.statSync(profilePath).isDirectory()) continue;
        
        if (entry.includes('.')) {
          profiles.push({ name: entry, path: profilePath });
        }
      }
    } catch (err) {
      logger.debug(`Skipping inaccessible directory: ${basePath}`, { error: (err as Error).message });
    }
  }
  
  return profiles;
}

interface ExtensionsJson {
  addons?: Array<{
    id: string;
    type: string;
    path?: string;
    version?: string;
    defaultLocale?: { name?: string };
  }>;
}

function findExtensions(profilePath: string): ExtensionInfo[] {
  const extensions: ExtensionInfo[] = [];
  const extensionsPath = path.join(profilePath, 'extensions');
  
  if (fs.existsSync(extensionsPath)) {
    try {
      const entries = fs.readdirSync(extensionsPath);
      
      for (const entry of entries) {
        const extPath = path.join(extensionsPath, entry);
        const stat = fs.statSync(extPath);
        
        if (stat.isDirectory()) {
          extensions.push({ id: entry, path: extPath, type: 'directory' });
        } else if (entry.endsWith('.xpi')) {
          extensions.push({ id: entry.replace('.xpi', ''), path: extPath, type: 'xpi' });
        }
      }
    } catch (err) {
      logger.debug(`Skipping inaccessible extensions directory: ${extensionsPath}`, { error: (err as Error).message });
    }
  }
  
  const extensionsJsonPath = path.join(profilePath, 'extensions.json');
  if (fs.existsSync(extensionsJsonPath)) {
    try {
      const extJson = JSON.parse(fs.readFileSync(extensionsJsonPath, 'utf-8')) as ExtensionsJson;
      const addons = extJson.addons || [];
      
      for (const addon of addons) {
        if (addon.type === 'extension' && addon.path) {
          const exists = extensions.some(e => e.id === addon.id);
          if (!exists && fs.existsSync(addon.path)) {
            extensions.push({
              id: addon.id,
              path: addon.path,
              type: fs.statSync(addon.path).isDirectory() ? 'directory' : 'xpi',
              name: addon.defaultLocale?.name || addon.id,
              version: addon.version,
            });
          }
        }
      }
    } catch (err) {
      logger.debug(`Failed to parse extensions.json: ${extensionsJsonPath}`, { error: (err as Error).message });
    }
  }
  
  return extensions;
}

interface ParseOptions {
  _extractedPath?: string;
  _actualPath?: string;
}

function parseManifest(extPath: string, extType: string | undefined, options: ParseOptions = {}): Manifest | null {
  let manifestPath: string;
  let extractedPath: string | null = null;
  
  if (extType === 'xpi') {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { extractXpi } = require('../xpi-extractor.js') as { extractXpi: (p: string) => string | null };
      extractedPath = extractXpi(extPath);
      if (extractedPath) {
        manifestPath = path.join(extractedPath, 'manifest.json');
        options._extractedPath = extractedPath;
      } else {
        logger.debug(`Failed to extract XPI: ${extPath}`);
        return null;
      }
    } catch (err) {
      logger.debug(`XPI extraction error: ${extPath}`, { error: (err as Error).message });
      return null;
    }
  } else {
    manifestPath = path.join(extPath, 'manifest.json');
  }
  
  if (!fs.existsSync(manifestPath)) {
    if (extractedPath) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const { cleanupExtracted } = require('../xpi-extractor.js') as { cleanupExtracted: (p: string) => void };
        cleanupExtracted(extractedPath);
      } catch { /* Cleanup failure is non-critical */ }
    }
    return null;
  }
  
  try {
    const content = fs.readFileSync(manifestPath, 'utf-8');
    const manifest = JSON.parse(content) as Manifest;
    if (extractedPath) {
      options._actualPath = extractedPath;
    }
    return manifest;
  } catch (err) {
    logger.warn(`Failed to parse manifest at ${manifestPath}: ${(err as Error).message}`);
    if (extractedPath) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const { cleanupExtracted } = require('../xpi-extractor.js') as { cleanupExtracted: (p: string) => void };
        cleanupExtracted(extractedPath);
      } catch { /* Cleanup failure is non-critical */ }
    }
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
        id: `ff-perm-${perm.replace(/[^a-z]/gi, '-')}`,
        severity: danger.severity,
        extension: `${manifest.name || extInfo.id} (${extInfo.id})`,
        message: `Permission: ${perm} - ${danger.msg}`,
        recommendation: `Review if "${perm}" permission is necessary`,
      });
    }
    
    if (perm.includes('://') && !DANGEROUS_PERMISSIONS[perm] && perm.includes('*')) {
      findings.push({
        id: 'ff-perm-wildcard-host',
        severity: 'info',
        extension: `${manifest.name || extInfo.id} (${extInfo.id})`,
        message: `Host permission: ${perm}`,
        recommendation: 'Verify this host access is expected',
      });
    }
  }
  
  if (manifest.browser_specific_settings?.gecko) {
    const gecko = manifest.browser_specific_settings.gecko;
    if (gecko.strict_min_version) {
      const minVersion = parseInt(gecko.strict_min_version, 10);
      if (minVersion < 90) {
        findings.push({
          id: 'ff-old-min-version',
          severity: 'info',
          extension: `${manifest.name || extInfo.id} (${extInfo.id})`,
          message: `Targets Firefox ${gecko.strict_min_version}+ (may be outdated)`,
          recommendation: 'Check if extension is actively maintained',
        });
      }
    }
  }
  
  if (manifest.applications?.gecko) {
    findings.push({
      id: 'ff-legacy-applications',
      severity: 'info',
      extension: `${manifest.name || extInfo.id} (${extInfo.id})`,
      message: 'Uses legacy "applications" key instead of "browser_specific_settings"',
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
        id: 'ff-cs-all-urls',
        severity: 'warning',
        extension: `${manifest.name || extInfo.id} (${extInfo.id})`,
        message: 'Content script injects into ALL pages',
        recommendation: 'Limit content script to specific domains if possible',
      });
    }
    
    if (cs.run_at === 'document_start') {
      findings.push({
        id: 'ff-cs-document-start',
        severity: 'info',
        extension: `${manifest.name || extInfo.id} (${extInfo.id})`,
        message: 'Content script runs at document_start',
      });
    }
    
    if (cs.match_about_blank) {
      findings.push({
        id: 'ff-cs-about-blank',
        severity: 'info',
        extension: `${manifest.name || extInfo.id} (${extInfo.id})`,
        message: 'Content script can run in about:blank frames',
      });
    }
  }
  
  return findings;
}

function analyzeBackground(manifest: Manifest, extInfo: ExtensionInfo, extPath: string): Finding[] {
  const findings: Finding[] = [];
  
  if (extInfo.type === 'xpi') {
    return findings;
  }
  
  const bgScripts: string[] = [];
  
  if (manifest.background) {
    if (manifest.background.scripts) {
      bgScripts.push(...manifest.background.scripts);
    }
    if (manifest.background.service_worker) {
      bgScripts.push(manifest.background.service_worker);
    }
    if (manifest.background.page) {
      findings.push({
        id: 'ff-bg-page',
        severity: 'info',
        extension: `${manifest.name || extInfo.id} (${extInfo.id})`,
        message: 'Uses background page (persistent background)',
      });
    }
    if (manifest.background.persistent === true) {
      findings.push({
        id: 'ff-bg-persistent',
        severity: 'info',
        extension: `${manifest.name || extInfo.id} (${extInfo.id})`,
        message: 'Uses persistent background script (higher resource usage)',
      });
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
            id: `ff-code-${pattern.msg.replace(/[^a-z]/gi, '-').toLowerCase()}`,
            severity: pattern.severity,
            extension: `${manifest.name || extInfo.id} (${extInfo.id})`,
            message: `${pattern.msg} in ${script}`,
            recommendation: 'Review the code for potential security issues',
          });
        }
      }
      
      const urlMatches = content.match(/https?:\/\/[^\s"']+/g) || [];
      const externalUrls = urlMatches.filter(url => {
        const legitimate = [
          'addons.mozilla.org', 'mozilla.org', 'mozilla.net', 'firefox.com',
          'github.com', 'githubusercontent.com', 'cloudflare.com', 'cdn.jsdelivr.net',
        ];
        return !legitimate.some(d => url.includes(d));
      });
      
      if (externalUrls.length > 0) {
        findings.push({
          id: 'ff-external-urls',
          severity: 'info',
          extension: `${manifest.name || extInfo.id} (${extInfo.id})`,
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

function checkKnownMalicious(extInfo: ExtensionInfo, manifest: Manifest | null): Finding[] {
  const findings: Finding[] = [];
  
  if (KNOWN_MALICIOUS && KNOWN_MALICIOUS.has(extInfo.id)) {
    findings.push({
      id: 'ff-known-malicious',
      severity: 'critical',
      extension: `${manifest?.name || extInfo.id} (${extInfo.id})`,
      message: 'Add-on is flagged as KNOWN MALICIOUS',
      recommendation: 'Remove this add-on immediately',
    });
  }
  
  return findings;
}

export async function scanFirefox(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];
  
  logger.debug('Starting Firefox scanner', { options: { ...options, quiet: undefined } });
  
  await loadMaliciousDb(options);
  
  const basePaths = getFirefoxPaths();
  logger.debug('Firefox base paths', basePaths);
  
  if (basePaths.length === 0) {
    logger.info('  No Firefox installation found');
    return findings;
  }
  
  const profiles = findProfiles(basePaths);
  if (profiles.length === 0) {
    logger.info('  No Firefox profiles found');
    return findings;
  }
  
  logger.info(`  Found ${profiles.length} Firefox profiles`);
  logger.debug('Found profiles', profiles.map(p => p.name));
  
  let totalExtensions = 0;
  
  for (const profile of profiles) {
    const extensions = findExtensions(profile.path);
    totalExtensions += extensions.length;
    
    for (const ext of extensions) {
      const parseOptions: ParseOptions = {};
      const manifest = parseManifest(ext.path, ext.type, parseOptions);
      const scanPath = parseOptions._actualPath || ext.path;
      
      if (!manifest && ext.type === 'xpi') {
        findings.push({
          id: 'ff-xpi-packed',
          severity: 'info',
          extension: `${ext.name || ext.id}`,
          message: 'Packed XPI extension - could not extract (unzip required)',
          recommendation: 'Install unzip for full XPI analysis',
        });
        continue;
      }
      
      if (!manifest) {
        logger.debug(`Skipping extension without manifest: ${ext.id}`);
        continue;
      }
      
      logger.info(`  Scanning: ${manifest.name || ext.id}`);
      logger.debug('Extension details', { id: ext.id, type: ext.type, path: ext.path });
      
      findings.push(...checkKnownMalicious(ext, manifest));
      findings.push(...analyzePermissions(manifest, ext));
      findings.push(...analyzeContentScripts(manifest, ext));
      findings.push(...analyzeBackground(manifest, ext, scanPath));
      
      if (parseOptions._extractedPath) {
        try {
          // eslint-disable-next-line @typescript-eslint/no-require-imports
          const { cleanupExtracted } = require('../xpi-extractor.js') as { cleanupExtracted: (p: string) => void };
          cleanupExtracted(parseOptions._extractedPath);
        } catch { /* Cleanup failure is non-critical */ }
      }
    }
  }
  
  logger.info(`  Found ${totalExtensions} extensions`);
  logger.debug(`Scan complete, ${findings.length} findings`);
  
  return findings;
}
