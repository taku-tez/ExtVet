/**
 * Chrome Extension Scanner
 * Scans installed Chrome/Chromium-based browser extensions
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as logger from '../logger.js';
import {
  analyzePermissions,
  analyzeContentScripts,
  analyzeBackgroundScripts,
  checkManifestVersion,
  parseManifest,
  loadMaliciousDb,
  checkKnownMalicious,
} from '../analyzers.js';
import type { Finding, ScanOptions, ExtensionInfo } from '../types.js';

/**
 * Get extension paths based on OS and browser type
 */
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

/**
 * Find all installed extensions
 */
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
          
          const versions = fs.readdirSync(extPath)
            .filter(v => fs.statSync(path.join(extPath, v)).isDirectory())
            .sort()
            .reverse();
          
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

/**
 * Main Chrome scanner function
 */
export async function scanChrome(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];
  
  logger.debug('Starting Chrome scanner', { browserType: options.browserType || 'chrome' });
  
  await loadMaliciousDb(options);
  
  const basePaths = getExtensionPaths(options);
  logger.debug('Extension base paths', basePaths);
  
  if (basePaths.length === 0) {
    logger.info('  No browser installation found');
    return findings;
  }
  
  const extensions = findExtensions(basePaths, options);
  logger.info(`  Found ${extensions.length} extensions`);
  
  for (const ext of extensions) {
    const manifest = parseManifest(ext.path);
    if (!manifest) {
      logger.debug(`Skipping extension without manifest: ${ext.id}`);
      continue;
    }
    
    logger.info(`  Scanning: ${manifest.name || ext.id}`);
    logger.debug('Extension details', { id: ext.id, version: ext.version });
    
    // Run analyzers
    findings.push(...checkKnownMalicious(ext, manifest));
    findings.push(...analyzePermissions(manifest, ext, 'ext'));
    findings.push(...analyzeContentScripts(manifest, ext, 'ext'));
    findings.push(...analyzeBackgroundScripts(manifest, ext, ext.path, 'ext'));
    findings.push(...checkManifestVersion(manifest, ext, 'ext'));
  }
  
  logger.debug(`Scan complete, ${findings.length} findings`);
  return findings;
}
