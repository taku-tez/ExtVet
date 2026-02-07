/**
 * Firefox Add-on Scanner
 * Scans installed Firefox add-ons for security issues
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as logger from '../logger.js';
import { FIREFOX_PERMISSIONS, FIREFOX_PATTERNS } from '../constants.js';
import {
  analyzePermissions,
  analyzeContentScripts,
  analyzeBackgroundScripts,
  analyzePermissionCombos,
  analyzeCSP,
  analyzeUpdateUrl,
  analyzeExternallyConnectable,
  analyzeWebAccessibleResources,
  loadMaliciousDb,
  checkKnownMalicious,
} from '../analyzers.js';
import type { Finding, ScanOptions, ExtensionInfo, Manifest } from '../types.js';

interface Profile {
  name: string;
  path: string;
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

interface ParseOptions {
  _extractedPath?: string;
  _actualPath?: string;
}

/**
 * Get Firefox profile paths based on OS
 */
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

/**
 * Find Firefox profiles
 */
function findProfiles(basePaths: string[]): Profile[] {
  const profiles: Profile[] = [];
  
  for (const basePath of basePaths) {
    if (!fs.existsSync(basePath)) continue;
    
    try {
      const entries = fs.readdirSync(basePath);
      for (const entry of entries) {
        const profilePath = path.join(basePath, entry);
        if (fs.statSync(profilePath).isDirectory() && entry.includes('.')) {
          profiles.push({ name: entry, path: profilePath });
        }
      }
    } catch (err) {
      logger.debug(`Skipping inaccessible directory: ${basePath}`, { error: (err as Error).message });
    }
  }
  
  return profiles;
}

/**
 * Find extensions in a Firefox profile
 */
function findExtensions(profilePath: string): ExtensionInfo[] {
  const extensions: ExtensionInfo[] = [];
  const extensionsPath = path.join(profilePath, 'extensions');
  
  // Scan extensions directory
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
  
  // Check extensions.json for additional extensions
  const extensionsJsonPath = path.join(profilePath, 'extensions.json');
  if (fs.existsSync(extensionsJsonPath)) {
    try {
      const extJson = JSON.parse(fs.readFileSync(extensionsJsonPath, 'utf-8')) as ExtensionsJson;
      for (const addon of extJson.addons || []) {
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
      logger.debug(`Failed to parse extensions.json`, { error: (err as Error).message });
    }
  }
  
  return extensions;
}

/**
 * Parse manifest from XPI or directory
 */
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
    cleanupExtracted(extractedPath);
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
    cleanupExtracted(extractedPath);
    return null;
  }
}

function cleanupExtracted(extractedPath: string | null): void {
  if (!extractedPath) return;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { cleanupExtracted } = require('../xpi-extractor.js') as { cleanupExtracted: (p: string) => void };
    cleanupExtracted(extractedPath);
  } catch { /* ignore */ }
}

/**
 * Firefox-specific permission analysis
 */
function analyzeFirefoxSpecific(manifest: Manifest, extInfo: ExtensionInfo): Finding[] {
  const findings: Finding[] = [];
  const extName = manifest.name || extInfo.id;
  
  // Check browser_specific_settings
  if (manifest.browser_specific_settings?.gecko) {
    const gecko = manifest.browser_specific_settings.gecko;
    if (gecko.strict_min_version) {
      const minVersion = parseInt(gecko.strict_min_version, 10);
      if (minVersion < 90) {
        findings.push({
          id: 'ff-old-min-version',
          severity: 'info',
          extension: `${extName} (${extInfo.id})`,
          message: `Targets Firefox ${gecko.strict_min_version}+ (may be outdated)`,
          recommendation: 'Check if extension is actively maintained',
        });
      }
    }
  }
  
  // Check legacy applications key
  if (manifest.applications?.gecko) {
    findings.push({
      id: 'ff-legacy-applications',
      severity: 'info',
      extension: `${extName} (${extInfo.id})`,
      message: 'Uses legacy "applications" key instead of "browser_specific_settings"',
    });
  }
  
  // Check background settings
  if (manifest.background) {
    if (manifest.background.page) {
      findings.push({
        id: 'ff-bg-page',
        severity: 'info',
        extension: `${extName} (${extInfo.id})`,
        message: 'Uses background page (persistent background)',
      });
    }
    if (manifest.background.persistent === true) {
      findings.push({
        id: 'ff-bg-persistent',
        severity: 'info',
        extension: `${extName} (${extInfo.id})`,
        message: 'Uses persistent background script (higher resource usage)',
      });
    }
  }
  
  return findings;
}

/**
 * Main Firefox scanner function
 */
export async function scanFirefox(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];
  
  logger.debug('Starting Firefox scanner');
  
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
      
      // Run analyzers
      findings.push(...checkKnownMalicious(ext, manifest, 'ff'));
      findings.push(...analyzePermissions(manifest, ext, 'ff', FIREFOX_PERMISSIONS));
      findings.push(...analyzeContentScripts(manifest, ext, 'ff'));
      findings.push(...analyzeFirefoxSpecific(manifest, ext));
    findings.push(...analyzePermissionCombos(manifest, ext, 'ff'));
      findings.push(...analyzeCSP(manifest, ext, 'ff'));
      findings.push(...analyzeUpdateUrl(manifest, ext, 'ff'));
      findings.push(...analyzeExternallyConnectable(manifest, ext, 'ff'));
      findings.push(...analyzeWebAccessibleResources(manifest, ext, 'ff'));
      
      // Only analyze scripts for unpacked extensions
      if (ext.type !== 'xpi') {
        findings.push(...analyzeBackgroundScripts(manifest, ext, scanPath, 'ff', FIREFOX_PATTERNS));
      }
      
      // Cleanup extracted XPI
      cleanupExtracted(parseOptions._extractedPath || null);
    }
  }
  
  logger.info(`  Found ${totalExtensions} extensions`);
  logger.debug(`Scan complete, ${findings.length} findings`);
  
  return findings;
}
