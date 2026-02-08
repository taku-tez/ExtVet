/**
 * Shared Analyzers
 * Common analysis functions used by both Chrome and Firefox scanners
 */

import * as fs from 'fs';
import * as path from 'path';
import * as logger from './logger.js';
import { DANGEROUS_PERMISSIONS, DANGEROUS_COMBOS, SUSPICIOUS_PATTERNS, LEGITIMATE_URLS, SUSPICIOUS_DOMAINS, SERVICE_WORKER_PATTERNS } from './constants.js';
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

  // Check suspicious domain patterns
  for (const domain of SUSPICIOUS_DOMAINS) {
    const matches = content.match(domain.pattern);
    if (matches) {
      findings.push({
        id: `${prefix}-suspicious-domain`,
        severity: domain.severity,
        extension: `${extName} (${extInfo.id})`,
        message: `${domain.msg} in ${scriptName}: ${matches[0]}`,
        recommendation: 'Investigate this connection — it matches known malicious infrastructure patterns',
      });
    }
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
      findings.push(...analyzeObfuscation(content, script, extInfo, manifest, prefix));
    } catch (err) {
      logger.debug(`Failed to analyze script ${script}: ${(err as Error).message}`);
    }
  }
  
  return findings;
}

/**
 * Analyze MV3 service worker for security-specific patterns
 * Service workers have unique attack surfaces vs traditional background pages
 */
export function analyzeServiceWorker(
  manifest: Manifest,
  extInfo: ExtensionInfo,
  extPath: string,
  prefix: string = 'ext'
): Finding[] {
  const findings: Finding[] = [];
  const extName = manifest.name || extInfo.id;

  // Only applies to MV3 with service_worker
  if (!manifest.background?.service_worker) return findings;

  const swFile = manifest.background.service_worker;
  const swPath = path.join(extPath, swFile);

  if (!fs.existsSync(swPath)) return findings;

  let content: string;
  try {
    content = fs.readFileSync(swPath, 'utf-8');
  } catch {
    return findings;
  }

  // Check service worker-specific patterns
  for (const pattern of SERVICE_WORKER_PATTERNS) {
    // Reset regex lastIndex for global patterns
    pattern.pattern.lastIndex = 0;
    const matches = content.match(pattern.pattern);
    if (matches) {
      findings.push({
        id: `${prefix}-sw-${pattern.msg.replace(/[^a-z0-9]/gi, '-').toLowerCase().slice(0, 50)}`,
        severity: pattern.severity,
        extension: `${extName} (${extInfo.id})`,
        message: `[Service Worker] ${pattern.msg} in ${swFile}`,
        recommendation: 'Service worker patterns require careful review — they run persistently in the background',
      });
    }
  }

  // Check for MV3 service worker with persistent background workaround
  if (manifest.background.persistent === true && manifest.manifest_version === 3) {
    findings.push({
      id: `${prefix}-sw-persistent-mv3`,
      severity: 'warning',
      extension: `${extName} (${extInfo.id})`,
      message: 'MV3 manifest declares persistent background (should use service worker lifecycle)',
      recommendation: 'MV3 extensions should not use persistent backgrounds; this may indicate lifecycle manipulation',
    });
  }

  // Check service worker size (very large SW = likely bundled/obfuscated)
  if (content.length > 500000) {
    findings.push({
      id: `${prefix}-sw-large`,
      severity: 'info',
      extension: `${extName} (${extInfo.id})`,
      message: `Large service worker file (${Math.round(content.length / 1024)}KB) — ${swFile}`,
      recommendation: 'Large service workers may contain bundled obfuscated code; review what is included',
    });
  }

  return findings;
}

/**
 * Analyze dangerous permission combinations
 */
export function analyzePermissionCombos(
  manifest: Manifest,
  extInfo: ExtensionInfo,
  prefix: string = 'ext'
): Finding[] {
  const findings: Finding[] = [];
  const extName = manifest.name || extInfo.id;

  const allPermissions = new Set([
    ...(manifest.permissions || []),
    ...(manifest.optional_permissions || []),
    ...(manifest.host_permissions || []),
  ]);

  for (const combo of DANGEROUS_COMBOS) {
    if (combo.permissions.every(p => allPermissions.has(p))) {
      findings.push({
        id: `${prefix}-combo-${combo.permissions.join('-').replace(/[^a-z]/gi, '-').toLowerCase()}`,
        severity: combo.severity,
        extension: `${extName} (${extInfo.id})`,
        message: `Permission combo: ${combo.msg}`,
        recommendation: combo.recommendation,
      });
    }
  }

  return findings;
}

/**
 * Analyze Content Security Policy (CSP)
 */
export function analyzeCSP(
  manifest: Manifest,
  extInfo: ExtensionInfo,
  prefix: string = 'ext'
): Finding[] {
  const findings: Finding[] = [];
  const extName = manifest.name || extInfo.id;
  const csp = manifest.content_security_policy;

  // Get CSP string(s) to analyze
  const cspStrings: { label: string; value: string }[] = [];
  if (typeof csp === 'string') {
    cspStrings.push({ label: 'CSP', value: csp });
  } else if (csp && typeof csp === 'object') {
    if (csp.extension_pages) cspStrings.push({ label: 'extension_pages CSP', value: csp.extension_pages });
    if (csp.sandbox) cspStrings.push({ label: 'sandbox CSP', value: csp.sandbox });
  }

  // No CSP defined (MV2 only - MV3 has defaults)
  if (cspStrings.length === 0 && manifest.manifest_version === 2) {
    findings.push({
      id: `${prefix}-csp-missing`,
      severity: 'warning',
      extension: `${extName} (${extInfo.id})`,
      message: 'No Content Security Policy defined (MV2 default allows unsafe-eval)',
      recommendation: 'Add a restrictive content_security_policy to manifest.json',
    });
    return findings;
  }

  for (const { label, value } of cspStrings) {
    // unsafe-eval
    if (value.includes("'unsafe-eval'") || value.includes('unsafe-eval')) {
      findings.push({
        id: `${prefix}-csp-unsafe-eval`,
        severity: 'critical',
        extension: `${extName} (${extInfo.id})`,
        message: `${label} allows unsafe-eval (code injection risk)`,
        recommendation: 'Remove unsafe-eval from CSP; use alternatives to eval()',
      });
    }

    // unsafe-inline
    if (value.includes("'unsafe-inline'") || value.includes('unsafe-inline')) {
      findings.push({
        id: `${prefix}-csp-unsafe-inline`,
        severity: 'warning',
        extension: `${extName} (${extInfo.id})`,
        message: `${label} allows unsafe-inline (XSS risk)`,
        recommendation: 'Remove unsafe-inline; use nonces or hashes instead',
      });
    }

    // Wildcard sources
    if (/\bscript-src\b[^;]*\*/.test(value) || /\bdefault-src\b[^;]*\*/.test(value)) {
      findings.push({
        id: `${prefix}-csp-wildcard`,
        severity: 'critical',
        extension: `${extName} (${extInfo.id})`,
        message: `${label} uses wildcard (*) in script/default-src (allows any script source)`,
        recommendation: 'Restrict script sources to specific trusted origins',
      });
    }

    // Remote script loading (http/https in script-src)
    const remoteMatch = value.match(/script-src[^;]*?(https?:\/\/[^\s;'"]+)/);
    if (remoteMatch) {
      findings.push({
        id: `${prefix}-csp-remote-scripts`,
        severity: 'warning',
        extension: `${extName} (${extInfo.id})`,
        message: `${label} allows remote script loading from ${remoteMatch[1]}`,
        recommendation: 'Bundle scripts locally instead of loading from remote servers',
      });
    }
  }

  return findings;
}

/**
 * Analyze update_url (self-update mechanism)
 */
export function analyzeUpdateUrl(
  manifest: Manifest,
  extInfo: ExtensionInfo,
  prefix: string = 'ext'
): Finding[] {
  const findings: Finding[] = [];
  const extName = manifest.name || extInfo.id;

  if (!manifest.update_url) return findings;

  const url = manifest.update_url;

  // Non-store update URL (sideloaded auto-update)
  if (!url.includes('clients2.google.com') && !url.includes('addons.mozilla.org')) {
    findings.push({
      id: `${prefix}-update-url-external`,
      severity: 'warning',
      extension: `${extName} (${extInfo.id})`,
      message: `Auto-updates from external server: ${url}`,
      recommendation: 'External update URLs bypass store review; verify the source is trusted',
    });
  }

  // HTTP update URL (MITM risk)
  if (url.startsWith('http://')) {
    findings.push({
      id: `${prefix}-update-url-http`,
      severity: 'critical',
      extension: `${extName} (${extInfo.id})`,
      message: `Update URL uses insecure HTTP: ${url}`,
      recommendation: 'Use HTTPS for update URLs to prevent man-in-the-middle attacks',
    });
  }

  return findings;
}

/**
 * Analyze externally_connectable (cross-origin messaging)
 */
export function analyzeExternallyConnectable(
  manifest: Manifest,
  extInfo: ExtensionInfo,
  prefix: string = 'ext'
): Finding[] {
  const findings: Finding[] = [];
  const extName = manifest.name || extInfo.id;
  const ec = manifest.externally_connectable;

  if (!ec) return findings;

  if (ec.matches) {
    // Wildcard in externally connectable
    if (ec.matches.some(m => m === '<all_urls>' || m === '*://*/*')) {
      findings.push({
        id: `${prefix}-ec-all-urls`,
        severity: 'critical',
        extension: `${extName} (${extInfo.id})`,
        message: 'Any website can send messages to this extension',
        recommendation: 'Restrict externally_connectable.matches to specific trusted domains',
      });
    } else if (ec.matches.some(m => /\*:\/\/|\*\./.test(m))) {
      findings.push({
        id: `${prefix}-ec-wildcard`,
        severity: 'warning',
        extension: `${extName} (${extInfo.id})`,
        message: `Broad externally_connectable patterns: ${ec.matches.filter(m => m.includes('*')).join(', ')}`,
        recommendation: 'Use specific domains instead of wildcards in externally_connectable',
      });
    }
  }

  if (ec.ids && ec.ids.includes('*')) {
    findings.push({
      id: `${prefix}-ec-all-extensions`,
      severity: 'warning',
      extension: `${extName} (${extInfo.id})`,
      message: 'Any extension can send messages to this extension',
      recommendation: 'Restrict externally_connectable.ids to specific trusted extension IDs',
    });
  }

  return findings;
}

/**
 * Analyze web_accessible_resources (fingerprinting & data leak risk)
 */
export function analyzeWebAccessibleResources(
  manifest: Manifest,
  extInfo: ExtensionInfo,
  prefix: string = 'ext'
): Finding[] {
  const findings: Finding[] = [];
  const extName = manifest.name || extInfo.id;
  const war = manifest.web_accessible_resources;

  if (!war || war.length === 0) return findings;

  // MV2 style (string array) - all resources accessible to all pages
  if (typeof war[0] === 'string') {
    findings.push({
      id: `${prefix}-war-mv2-all`,
      severity: 'info',
      extension: `${extName} (${extInfo.id})`,
      message: `${war.length} web-accessible resources exposed to all pages (MV2 style)`,
      recommendation: 'Migrate to MV3 to restrict resource access by origin',
    });
    return findings;
  }

  // MV3 style - check for broad matches
  for (const entry of war) {
    if (typeof entry === 'object' && entry.matches) {
      if (entry.matches.includes('<all_urls>') || entry.matches.includes('*://*/*')) {
        findings.push({
          id: `${prefix}-war-all-urls`,
          severity: 'info',
          extension: `${extName} (${extInfo.id})`,
          message: `Web-accessible resources (${entry.resources.length} files) exposed to all websites`,
          recommendation: 'Restrict web_accessible_resources matches to specific domains; broad exposure enables fingerprinting',
        });
      }
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
 * Detect obfuscated/packed JavaScript code
 * Obfuscation is a strong signal of malicious intent in browser extensions
 */
export function analyzeObfuscation(
  content: string,
  scriptName: string,
  extInfo: ExtensionInfo,
  manifest: Manifest,
  prefix: string = 'ext'
): Finding[] {
  const findings: Finding[] = [];
  const extName = manifest.name || extInfo.id;

  // 1. High ratio of hex/unicode escapes (e.g. \x61\x62, \u0041)
  const hexEscapes = (content.match(/\\x[0-9a-fA-F]{2}/g) || []).length;
  const unicodeEscapes = (content.match(/\\u[0-9a-fA-F]{4}/g) || []).length;
  const escapeCount = hexEscapes + unicodeEscapes;
  if (escapeCount > 50) {
    findings.push({
      id: `${prefix}-obfuscation-escapes`,
      severity: escapeCount > 200 ? 'critical' : 'warning',
      extension: `${extName} (${extInfo.id})`,
      message: `Heavy use of hex/unicode escapes (${escapeCount}) in ${scriptName}`,
      recommendation: 'Code may be obfuscated to hide malicious behavior; manual review recommended',
    });
  }

  // 2. Long single-line strings (packed code)
  const lines = content.split('\n');
  const longLines = lines.filter(l => l.length > 5000);
  if (longLines.length > 0) {
    findings.push({
      id: `${prefix}-obfuscation-packed`,
      severity: 'warning',
      extension: `${extName} (${extInfo.id})`,
      message: `Packed/minified code detected in ${scriptName} (${longLines.length} lines >5000 chars)`,
      recommendation: 'Heavily packed code in extensions may indicate obfuscation; review carefully',
    });
  }

  // 3. String array rotation pattern (common obfuscator signature)
  // e.g., var _0x1a2b = ['string1', 'string2', ...]; function _0x3c4d(i) { ... }
  if (/var\s+_0x[a-f0-9]+\s*=\s*\[/.test(content) || /function\s+_0x[a-f0-9]+/.test(content)) {
    findings.push({
      id: `${prefix}-obfuscation-string-rotation`,
      severity: 'critical',
      extension: `${extName} (${extInfo.id})`,
      message: `JavaScript obfuscator string rotation pattern in ${scriptName}`,
      recommendation: 'This pattern is commonly used by malicious extensions to evade detection',
    });
  }

  // 4. Excessive use of String.fromCharCode
  const fromCharCodeCount = (content.match(/String\.fromCharCode/g) || []).length;
  if (fromCharCodeCount > 5) {
    findings.push({
      id: `${prefix}-obfuscation-fromcharcode`,
      severity: fromCharCodeCount > 20 ? 'critical' : 'warning',
      extension: `${extName} (${extInfo.id})`,
      message: `Excessive String.fromCharCode usage (${fromCharCodeCount}×) in ${scriptName}`,
      recommendation: 'Dynamic string construction may be hiding malicious URLs or code',
    });
  }

  // 5. High entropy variable names (lots of _0x... or single-char vars)
  const obfuscatedVars = (content.match(/\b_0x[a-f0-9]{4,}\b/g) || []);
  if (obfuscatedVars.length > 10) {
    findings.push({
      id: `${prefix}-obfuscation-varnames`,
      severity: 'warning',
      extension: `${extName} (${extInfo.id})`,
      message: `Obfuscated variable names detected (${obfuscatedVars.length}×) in ${scriptName}`,
      recommendation: 'Obfuscated identifiers reduce auditability and may hide malicious logic',
    });
  }

  // 6. Dean Edwards packer signature
  if (/eval\(function\(p,a,c,k,e,[dr]\)/.test(content)) {
    findings.push({
      id: `${prefix}-obfuscation-packer`,
      severity: 'critical',
      extension: `${extName} (${extInfo.id})`,
      message: `Dean Edwards packer detected in ${scriptName}`,
      recommendation: 'Packed code is a common technique in malicious extensions; unpack and review',
    });
  }

  return findings;
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
