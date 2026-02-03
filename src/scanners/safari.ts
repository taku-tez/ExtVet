/**
 * Safari Extension Scanner
 * Scans installed Safari extensions on macOS
 * 
 * Safari Extension Types:
 * 1. Legacy Safari Extensions (.safariextz) - ~/Library/Safari/Extensions/
 * 2. Safari Web Extensions (.appex) - Inside .app bundles in /Applications/
 * 3. App Store Extensions - Inside containers
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';
import * as logger from '../logger.js';
import {
  analyzePermissions,
  analyzeContentScripts,
  analyzeBackgroundScripts,
  checkManifestVersion,
  loadMaliciousDb,
  checkKnownMalicious,
  parseManifest,
} from '../analyzers.js';
import type { Finding, ScanOptions, ExtensionInfo, Manifest } from '../types.js';

/**
 * Get Safari extension locations
 */
function getSafariPaths(): { legacy: string[]; apps: string[] } {
  const home = os.homedir();
  
  return {
    // Legacy .safariextz extensions
    legacy: [
      path.join(home, 'Library/Safari/Extensions'),
    ],
    // App bundles that may contain Safari Web Extensions
    apps: [
      '/Applications',
      path.join(home, 'Applications'),
      // Commonly used paths for Safari extension apps
      path.join(home, 'Library/Containers'),
    ],
  };
}

/**
 * Find legacy Safari extensions (.safariextz)
 */
function findLegacyExtensions(legacyPaths: string[]): ExtensionInfo[] {
  const extensions: ExtensionInfo[] = [];
  
  for (const basePath of legacyPaths) {
    if (!fs.existsSync(basePath)) continue;
    
    try {
      const entries = fs.readdirSync(basePath);
      
      for (const entry of entries) {
        if (entry.endsWith('.safariextz')) {
          extensions.push({
            id: entry.replace('.safariextz', ''),
            path: path.join(basePath, entry),
            type: 'xpi', // We'll use xar extraction similar to xpi
            name: entry.replace('.safariextz', ''),
          });
        }
      }
    } catch (err) {
      logger.debug(`Skipping inaccessible directory: ${basePath}`, { error: (err as Error).message });
    }
  }
  
  return extensions;
}

/**
 * Find Safari Web Extensions inside .app bundles
 */
function findAppExtensions(appPaths: string[]): ExtensionInfo[] {
  const extensions: ExtensionInfo[] = [];
  
  for (const basePath of appPaths) {
    if (!fs.existsSync(basePath)) continue;
    
    try {
      // Look for .app directories
      const scanDir = (dir: string, depth: number = 0) => {
        if (depth > 3) return; // Limit recursion depth
        
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          
          if (entry.isDirectory()) {
            if (entry.name.endsWith('.app')) {
              // Check for Safari extension inside the app
              const appexPaths = findAppexInApp(fullPath);
              extensions.push(...appexPaths);
            } else if (!entry.name.startsWith('.')) {
              // Continue scanning subdirectories (but not hidden ones)
              try {
                scanDir(fullPath, depth + 1);
              } catch {
                // Skip inaccessible directories
              }
            }
          }
        }
      };
      
      scanDir(basePath);
    } catch (err) {
      logger.debug(`Error scanning ${basePath}`, { error: (err as Error).message });
    }
  }
  
  return extensions;
}

/**
 * Find Safari extension .appex files inside an .app bundle
 */
function findAppexInApp(appPath: string): ExtensionInfo[] {
  const extensions: ExtensionInfo[] = [];
  const plugInsPath = path.join(appPath, 'Contents', 'PlugIns');
  
  if (!fs.existsSync(plugInsPath)) return extensions;
  
  try {
    const entries = fs.readdirSync(plugInsPath);
    
    for (const entry of entries) {
      if (entry.endsWith('.appex')) {
        const appexPath = path.join(plugInsPath, entry);
        const resourcesPath = path.join(appexPath, 'Contents', 'Resources');
        const manifestPath = path.join(resourcesPath, 'manifest.json');
        
        // Check if this is a Safari Web Extension (has manifest.json)
        if (fs.existsSync(manifestPath)) {
          const appName = path.basename(appPath, '.app');
          extensions.push({
            id: entry.replace('.appex', ''),
            path: resourcesPath,
            type: 'directory',
            name: appName,
          });
        }
      }
    }
  } catch (err) {
    logger.debug(`Error scanning ${plugInsPath}`, { error: (err as Error).message });
  }
  
  return extensions;
}

/**
 * Extract and parse legacy .safariextz file
 */
function parseLegacyExtension(extPath: string): { manifest: Manifest | null; extractedPath: string | null } {
  try {
    // Create temp directory
    const tempDir = path.join(os.tmpdir(), 'extvet-safari-' + Date.now());
    fs.mkdirSync(tempDir, { recursive: true });
    
    // Extract using xar (macOS built-in)
    try {
      execSync(`xar -xf "${extPath}" -C "${tempDir}"`, { stdio: 'pipe' });
    } catch {
      // xar might not be available on all systems
      logger.debug(`Failed to extract ${extPath} with xar`);
      fs.rmSync(tempDir, { recursive: true, force: true });
      return { manifest: null, extractedPath: null };
    }
    
    // Find Info.plist (legacy format) or manifest.json
    const infoPlistPath = path.join(tempDir, 'Info.plist');
    const manifestPath = path.join(tempDir, 'manifest.json');
    
    if (fs.existsSync(manifestPath)) {
      const content = fs.readFileSync(manifestPath, 'utf-8');
      return { manifest: JSON.parse(content) as Manifest, extractedPath: tempDir };
    }
    
    // Parse Info.plist for legacy extensions
    if (fs.existsSync(infoPlistPath)) {
      const manifest = parsePlistToManifest(infoPlistPath);
      return { manifest, extractedPath: tempDir };
    }
    
    fs.rmSync(tempDir, { recursive: true, force: true });
    return { manifest: null, extractedPath: null };
  } catch (err) {
    logger.debug(`Error parsing legacy extension: ${(err as Error).message}`);
    return { manifest: null, extractedPath: null };
  }
}

/**
 * Convert Safari Info.plist to manifest-like structure
 */
function parsePlistToManifest(plistPath: string): Manifest | null {
  try {
    // Use plutil to convert plist to JSON (macOS built-in)
    const jsonOutput = execSync(`plutil -convert json -o - "${plistPath}"`, { encoding: 'utf-8' });
    const plist = JSON.parse(jsonOutput) as Record<string, unknown>;
    
    // Map Safari plist to manifest structure
    return {
      name: (plist.CFBundleDisplayName || plist.CFBundleName) as string,
      version: plist.CFBundleShortVersionString as string,
      manifest_version: 2, // Legacy extensions are MV2 equivalent
      permissions: extractSafariPermissions(plist),
    };
  } catch (err) {
    logger.debug(`Failed to parse plist: ${(err as Error).message}`);
    return null;
  }
}

/**
 * Extract permissions from Safari extension plist
 */
function extractSafariPermissions(plist: Record<string, unknown>): string[] {
  const permissions: string[] = [];
  
  // Website Access
  const websiteAccess = plist.Website_Access as Record<string, unknown> | undefined;
  if (websiteAccess) {
    const level = websiteAccess.Level as string;
    if (level === 'All') {
      permissions.push('<all_urls>');
    } else if (level === 'Some') {
      const allowed = websiteAccess.Allowed_Domains as string[] | undefined;
      if (allowed) {
        permissions.push(...allowed.map(d => `*://${d}/*`));
      }
    }
  }
  
  // Secure Pages Access
  if (plist.Allow_Secure_Pages === true) {
    permissions.push('https://*/*');
  }
  
  return permissions;
}

/**
 * Cleanup extracted extension
 */
function cleanupExtracted(extractedPath: string | null): void {
  if (extractedPath && extractedPath.includes('extvet-safari-')) {
    try {
      fs.rmSync(extractedPath, { recursive: true, force: true });
    } catch { /* ignore */ }
  }
}

/**
 * Safari-specific analysis
 */
function analyzeSafariSpecific(manifest: Manifest, extInfo: ExtensionInfo): Finding[] {
  const findings: Finding[] = [];
  const extName = manifest.name || extInfo.id;
  
  // Check for legacy extension format
  if (extInfo.type === 'xpi') {
    findings.push({
      id: 'safari-legacy-format',
      severity: 'info',
      extension: `${extName} (${extInfo.id})`,
      message: 'Uses legacy Safari extension format (.safariextz)',
      recommendation: 'Legacy extensions may not work in newer Safari versions',
    });
  }
  
  // Safari Web Extensions use the same manifest as Chrome
  // But check for Safari-specific issues
  
  return findings;
}

/**
 * Main Safari scanner function
 */
export async function scanSafari(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];
  
  // Safari extensions are macOS-only
  if (os.platform() !== 'darwin') {
    logger.info('  Safari extensions are only available on macOS');
    return findings;
  }
  
  logger.debug('Starting Safari scanner');
  
  await loadMaliciousDb(options);
  
  const paths = getSafariPaths();
  logger.debug('Safari paths', paths);
  
  // Find legacy extensions
  const legacyExtensions = findLegacyExtensions(paths.legacy);
  logger.debug(`Found ${legacyExtensions.length} legacy extensions`);
  
  // Find app-based extensions
  const appExtensions = findAppExtensions(paths.apps);
  logger.debug(`Found ${appExtensions.length} app extensions`);
  
  const allExtensions = [...legacyExtensions, ...appExtensions];
  
  if (allExtensions.length === 0) {
    logger.info('  No Safari extensions found');
    return findings;
  }
  
  logger.info(`  Found ${allExtensions.length} Safari extensions`);
  
  for (const ext of allExtensions) {
    let manifest: Manifest | null = null;
    let extractedPath: string | null = null;
    
    if (ext.type === 'xpi') {
      // Legacy .safariextz
      const result = parseLegacyExtension(ext.path);
      manifest = result.manifest;
      extractedPath = result.extractedPath;
    } else {
      // Modern .appex
      manifest = parseManifest(ext.path);
    }
    
    if (!manifest) {
      logger.debug(`Skipping extension without manifest: ${ext.id}`);
      if (ext.type === 'xpi') {
        findings.push({
          id: 'safari-legacy-no-parse',
          severity: 'info',
          extension: ext.name || ext.id,
          message: 'Legacy Safari extension - could not parse (xar required)',
          recommendation: 'Install Xcode command line tools for full analysis',
        });
      }
      continue;
    }
    
    logger.info(`  Scanning: ${manifest.name || ext.id}`);
    
    // Run analyzers
    findings.push(...checkKnownMalicious(ext, manifest, 'safari'));
    findings.push(...analyzePermissions(manifest, ext, 'safari'));
    findings.push(...analyzeContentScripts(manifest, ext, 'safari'));
    findings.push(...analyzeSafariSpecific(manifest, ext));
    findings.push(...checkManifestVersion(manifest, ext, 'safari'));
    
    // Analyze background scripts for modern extensions
    if (ext.type === 'directory') {
      findings.push(...analyzeBackgroundScripts(manifest, ext, ext.path, 'safari'));
    }
    
    // Cleanup extracted legacy extension
    cleanupExtracted(extractedPath);
  }
  
  logger.debug(`Scan complete, ${findings.length} findings`);
  return findings;
}
