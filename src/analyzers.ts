/**
 * Shared Analyzers
 * Common analysis functions used by both Chrome and Firefox scanners
 */

import * as fs from 'fs';
import * as path from 'path';
import * as logger from './logger.js';
import { DANGEROUS_PERMISSIONS, SUSPICIOUS_PATTERNS, LEGITIMATE_URLS } from './constants.js';
import type { Finding, Manifest, ExtensionInfo, PermissionDanger, SuspiciousPattern } from './types.js';

/**
 * Analyze extension permissions
 */
export function analyzePermissions(
  manifest: Manifest,
  extInfo: ExtensionInfo,
  prefix: string = 'ext',
  additionalPermissions: Record<string, PermissionDanger> = {}
): Finding[] {
  const findings: Finding[] = [];
  const permissionMap = { ...DANGEROUS_PERMISSIONS, ...additionalPermissions };
  
  const allPermissions = [
    ...(manifest.permissions || []),
    ...(manifest.optional_permissions || []),
    ...(manifest.host_permissions || []),
  ];
  
  const extName = manifest.name || extInfo.id;
  
  for (const perm of allPermissions) {
    if (permissionMap[perm]) {
      const danger = permissionMap[perm];
      findings.push({
        id: `${prefix}-perm-${perm.replace(/[^a-z]/gi, '-')}`,
        severity: danger.severity,
        extension: `${extName} (${extInfo.id})`,
        message: `Permission: ${perm} - ${danger.msg}`,
        recommendation: `Review if "${perm}" permission is necessary`,
      });
    }
    
    // Check wildcard URL patterns
    if (perm.includes('://') && !permissionMap[perm] && perm.includes('*')) {
      findings.push({
        id: `${prefix}-perm-wildcard-host`,
        severity: 'info',
        extension: `${extName} (${extInfo.id})`,
        message: `Host permission: ${perm}`,
        recommendation: 'Verify this host access is expected',
      });
    }
  }
  
  return findings;
}

/**
 * Analyze content scripts
 */
export function analyzeContentScripts(
  manifest: Manifest,
  extInfo: ExtensionInfo,
  prefix: string = 'ext'
): Finding[] {
  const findings: Finding[] = [];
  const contentScripts = manifest.content_scripts || [];
  const extName = manifest.name || extInfo.id;
  
  for (const cs of contentScripts) {
    const matches = cs.matches || [];
    
    // Overly broad injection
    if (matches.includes('<all_urls>') || matches.includes('*://*/*')) {
      findings.push({
        id: `${prefix}-cs-all-urls`,
        severity: 'warning',
        extension: `${extName} (${extInfo.id})`,
        message: 'Content script injects into ALL pages',
        recommendation: 'Limit content script to specific domains if possible',
      });
    }
    
    // Early execution
    if (cs.run_at === 'document_start') {
      findings.push({
        id: `${prefix}-cs-document-start`,
        severity: 'info',
        extension: `${extName} (${extInfo.id})`,
        message: 'Content script runs at document_start (can modify page before load)',
      });
    }
    
    // MAIN world access (Chrome MV3)
    if (cs.world === 'MAIN') {
      findings.push({
        id: `${prefix}-cs-main-world`,
        severity: 'warning',
        extension: `${extName} (${extInfo.id})`,
        message: 'Content script runs in MAIN world (full page access)',
        recommendation: 'MAIN world scripts can interact with page JavaScript',
      });
    }
    
    // about:blank access (Firefox)
    if (cs.match_about_blank) {
      findings.push({
        id: `${prefix}-cs-about-blank`,
        severity: 'info',
        extension: `${extName} (${extInfo.id})`,
        message: 'Content script can run in about:blank frames',
      });
    }
  }
  
  return findings;
}

/**
 * Analyze script content for suspicious patterns
 */
export function analyzeScriptContent(
  content: string,
  scriptName: string,
  extInfo: ExtensionInfo,
  manifest: Manifest,
  prefix: string = 'ext',
  additionalPatterns: SuspiciousPattern[] = []
): Finding[] {
  const findings: Finding[] = [];
  const patterns = [...SUSPICIOUS_PATTERNS, ...additionalPatterns];
  const extName = manifest.name || extInfo.id;
  
  // Check suspicious patterns
  for (const pattern of patterns) {
    const matches = content.match(pattern.pattern);
    if (matches) {
      findings.push({
        id: `${prefix}-code-${pattern.msg.replace(/[^a-z]/gi, '-').toLowerCase()}`,
        severity: pattern.severity,
        extension: `${extName} (${extInfo.id})`,
        message: `${pattern.msg} in ${scriptName}`,
        recommendation: 'Review the code for potential security issues',
      });
    }
  }
  
  // Check external URLs
  const urlMatches = content.match(/https?:\/\/[^\s"']+/g) || [];
  const externalUrls = urlMatches.filter(url => 
    !LEGITIMATE_URLS.some(d => url.includes(d))
  );
  
  if (externalUrls.length > 0) {
    findings.push({
      id: `${prefix}-external-urls`,
      severity: 'info',
      extension: `${extName} (${extInfo.id})`,
      message: `Connects to external URLs: ${externalUrls.slice(0, 3).join(', ')}${externalUrls.length > 3 ? '...' : ''}`,
      recommendation: 'Verify these external connections are expected',
    });
  }
  
  return findings;
}

/**
 * Analyze background scripts
 */
export function analyzeBackgroundScripts(
  manifest: Manifest,
  extInfo: ExtensionInfo,
  extPath: string,
  prefix: string = 'ext',
  additionalPatterns: SuspiciousPattern[] = []
): Finding[] {
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
      findings.push(...analyzeScriptContent(
        content,
        script,
        extInfo,
        manifest,
        prefix,
        additionalPatterns
      ));
    } catch (err) {
      logger.debug(`Failed to analyze script ${script}: ${(err as Error).message}`);
    }
  }
  
  return findings;
}

/**
 * Check manifest version deprecation
 */
export function checkManifestVersion(
  manifest: Manifest,
  extInfo: ExtensionInfo,
  prefix: string = 'ext'
): Finding[] {
  const findings: Finding[] = [];
  const extName = manifest.name || extInfo.id;
  
  if (manifest.manifest_version === 2) {
    findings.push({
      id: `${prefix}-mv2-deprecated`,
      severity: 'warning',
      extension: `${extName} (${extInfo.id})`,
      message: 'Uses Manifest V2 (deprecated, will be removed)',
      recommendation: 'Update to Manifest V3 or find alternative extension',
    });
  }
  
  return findings;
}

/**
 * Parse manifest.json from extension path
 */
export function parseManifest(extPath: string): Manifest | null {
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

/**
 * Shared malicious extension database cache
 */
let KNOWN_MALICIOUS: Set<string> | null = null;

/**
 * Load malicious extension database (shared across all scanners)
 */
export async function loadMaliciousDb(options: { quiet?: boolean } = {}): Promise<Set<string>> {
  if (KNOWN_MALICIOUS) return KNOWN_MALICIOUS;
  
  try {
    const { getMaliciousIds } = await import('./malicious-db.js');
    KNOWN_MALICIOUS = await getMaliciousIds({ quiet: true, ...options });
    logger.debug(`Loaded ${KNOWN_MALICIOUS.size} malicious extension IDs`);
  } catch (err) {
    logger.warn(`Failed to load malicious DB: ${(err as Error).message}`);
    KNOWN_MALICIOUS = new Set();
  }
  
  return KNOWN_MALICIOUS;
}

/**
 * Check if extension is in known malicious database
 */
export function checkKnownMalicious(
  extInfo: ExtensionInfo,
  manifest: Manifest,
  prefix: string = 'ext'
): Finding[] {
  if (!KNOWN_MALICIOUS?.has(extInfo.id)) return [];
  
  const extName = manifest.name || extInfo.id;
  return [{
    id: `${prefix}-known-malicious`,
    severity: 'critical',
    extension: `${extName} (${extInfo.id})`,
    message: 'Extension is flagged as KNOWN MALICIOUS',
    recommendation: 'Remove this extension immediately',
  }];
}
