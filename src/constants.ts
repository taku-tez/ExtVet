/**
 * Shared Constants
 * Common permission definitions and suspicious patterns
 */

import type { PermissionDanger, SuspiciousPattern } from './types.js';

/**
 * ExtVet version - single source of truth
 */
export const VERSION = '1.1.0';

/**
 * Dangerous permissions that need security review
 * Used by both Chrome and Firefox scanners
 */
export const DANGEROUS_PERMISSIONS: Record<string, PermissionDanger> = {
  // Critical - Full access
  '<all_urls>': { severity: 'critical', msg: 'Access to ALL websites' },
  '*://*/*': { severity: 'critical', msg: 'Access to ALL websites' },
  'http://*/*': { severity: 'warning', msg: 'Access to all HTTP sites' },
  'https://*/*': { severity: 'warning', msg: 'Access to all HTTPS sites' },
  
  // Critical - Sensitive data
  'cookies': { severity: 'warning', msg: 'Can read/write cookies (session hijacking risk)' },
  'webRequest': { severity: 'warning', msg: 'Can intercept network requests' },
  'webRequestBlocking': { severity: 'critical', msg: 'Can modify/block network requests' },
  'proxy': { severity: 'critical', msg: 'Can control proxy settings (MitM risk)' },
  'debugger': { severity: 'critical', msg: 'Full debugging access to tabs' },
  'nativeMessaging': { severity: 'critical', msg: 'Can communicate with native apps' },
  
  // Warning - Privacy concerns
  'tabs': { severity: 'info', msg: 'Can see all open tabs and URLs' },
  'history': { severity: 'warning', msg: 'Can read browsing history' },
  'bookmarks': { severity: 'info', msg: 'Can read/modify bookmarks' },
  'downloads': { severity: 'info', msg: 'Can access downloads' },
  'management': { severity: 'warning', msg: 'Can manage other extensions' },
  'privacy': { severity: 'warning', msg: 'Can modify privacy settings' },
  'browsingData': { severity: 'warning', msg: 'Can clear browsing data' },
  
  // Info - Common but notable
  'storage': { severity: 'info', msg: 'Can store data locally' },
  'clipboardRead': { severity: 'warning', msg: 'Can read clipboard' },
  'clipboardWrite': { severity: 'info', msg: 'Can write to clipboard' },
  'geolocation': { severity: 'warning', msg: 'Can access location' },
  'notifications': { severity: 'info', msg: 'Can show notifications' },
};

/**
 * Firefox-specific dangerous permissions
 */
export const FIREFOX_PERMISSIONS: Record<string, PermissionDanger> = {
  'webRequestFilterResponse': { severity: 'critical', msg: 'Can filter response bodies' },
  'browserSettings': { severity: 'warning', msg: 'Can modify browser settings' },
  'dns': { severity: 'critical', msg: 'Can perform DNS resolution' },
  'pkcs11': { severity: 'critical', msg: 'Can access PKCS #11 security modules' },
  'geckoProfiler': { severity: 'critical', msg: 'Can access the Gecko profiler' },
  'contextualIdentities': { severity: 'warning', msg: 'Can access container tabs' },
  'sessions': { severity: 'warning', msg: 'Can access session data' },
  'captivePortal': { severity: 'warning', msg: 'Can detect captive portals' },
  'identity': { severity: 'warning', msg: 'Can access browser identity' },
};

/**
 * Suspicious code patterns
 * Used for static analysis of extension scripts
 */
export const SUSPICIOUS_PATTERNS: SuspiciousPattern[] = [
  // Code injection
  { pattern: /eval\s*\(/g, severity: 'critical', msg: 'Uses eval() - code injection risk' },
  { pattern: /new\s+Function\s*\(/g, severity: 'critical', msg: 'Uses Function constructor - code injection risk' },
  
  // XSS risks
  { pattern: /document\.write/g, severity: 'warning', msg: 'Uses document.write - XSS risk' },
  { pattern: /innerHTML\s*=/g, severity: 'info', msg: 'Uses innerHTML - potential XSS' },
  
  // Network concerns
  { pattern: /fetch\s*\(['"](http:\/\/)/g, severity: 'warning', msg: 'Insecure HTTP fetch' },
  { pattern: /XMLHttpRequest.*http:/g, severity: 'warning', msg: 'Insecure HTTP XHR' },
  { pattern: /WebSocket\s*\(/g, severity: 'info', msg: 'Uses WebSocket connections' },
  
  // Encoding (potential obfuscation)
  { pattern: /atob|btoa/g, severity: 'info', msg: 'Base64 encoding (check for obfuscation)' },
  { pattern: /crypto\.subtle/g, severity: 'info', msg: 'Uses Web Crypto API' },
  
  // CSP Stripping Attack Patterns (GitLab Feb 2025)
  { pattern: /declarativeNetRequest\.updateSessionRules/g, severity: 'warning', msg: 'Modifies browser network rules dynamically' },
  { pattern: /content-security-policy.*operation.*set.*value.*['"]{2}/gi, severity: 'critical', msg: 'CSP stripping attack - removes Content Security Policy' },
  { pattern: /modifyHeaders.*responseHeaders.*content-security-policy/gi, severity: 'critical', msg: 'CSP header manipulation detected' },
  { pattern: /header.*content-security-policy.*operation.*remove/gi, severity: 'critical', msg: 'CSP header removal detected' },
  
  // Request interception
  { pattern: /webRequest\.onBeforeRequest.*<all_urls>/g, severity: 'warning', msg: 'Intercepts all web requests' },
  { pattern: /webRequest\.onHeadersReceived.*blocking/g, severity: 'warning', msg: 'Modifies HTTP response headers' },
  
  // C2 patterns
  { pattern: /chrome\.storage\.local\.set.*configUpdateInterval/g, severity: 'warning', msg: 'Dynamic config update pattern (potential C2)' },
  { pattern: /setInterval.*fetch.*chrome\.storage/g, severity: 'warning', msg: 'Periodic remote config fetch' },
  
  // Data exfiltration
  { pattern: /chrome\.cookies\.getAll\s*\(\s*\{\s*\}/g, severity: 'critical', msg: 'Attempts to read all cookies' },
  { pattern: /document\.cookie.*fetch|fetch.*document\.cookie/g, severity: 'critical', msg: 'Cookie exfiltration pattern' },
  { pattern: /localStorage.*fetch|fetch.*localStorage/g, severity: 'warning', msg: 'LocalStorage exfiltration pattern' },
];

/**
 * Firefox-specific suspicious patterns
 */
export const FIREFOX_PATTERNS: SuspiciousPattern[] = [
  { pattern: /browser\.downloads\.download/g, severity: 'info', msg: 'Can initiate downloads' },
  { pattern: /browser\.webRequest\.filterResponseData/g, severity: 'warning', msg: 'Filters response data' },
];

/**
 * Dangerous permission combinations
 * Permissions that are significantly more dangerous when combined
 */
export interface PermissionCombo {
  permissions: string[];
  severity: 'critical' | 'warning';
  msg: string;
  recommendation: string;
}

export const DANGEROUS_COMBOS: PermissionCombo[] = [
  {
    permissions: ['webRequest', 'webRequestBlocking', '<all_urls>'],
    severity: 'critical',
    msg: 'Can intercept and modify ALL network traffic (full MitM capability)',
    recommendation: 'This combination allows complete network traffic manipulation; verify the extension truly needs this',
  },
  {
    permissions: ['cookies', '<all_urls>'],
    severity: 'critical',
    msg: 'Can read cookies from ALL websites (mass session hijacking risk)',
    recommendation: 'Limit host permissions to specific domains the extension actually needs',
  },
  {
    permissions: ['cookies', '*://*/*'],
    severity: 'critical',
    msg: 'Can read cookies from ALL websites (mass session hijacking risk)',
    recommendation: 'Limit host permissions to specific domains the extension actually needs',
  },
  {
    permissions: ['tabs', 'history'],
    severity: 'warning',
    msg: 'Can build a complete browsing profile (all tabs + full history)',
    recommendation: 'Review if both tab access and history reading are necessary',
  },
  {
    permissions: ['nativeMessaging', '<all_urls>'],
    severity: 'critical',
    msg: 'Can communicate with native apps while accessing all websites (data exfiltration via native bridge)',
    recommendation: 'Native messaging + all URLs enables silent data exfiltration to local programs',
  },
  {
    permissions: ['debugger', '<all_urls>'],
    severity: 'critical',
    msg: 'Full debugging access to all tabs (can inject code, read memory, bypass CSP)',
    recommendation: 'Debugger + all URLs is equivalent to full browser compromise',
  },
  {
    permissions: ['proxy', 'webRequest'],
    severity: 'critical',
    msg: 'Can route traffic through attacker proxy and intercept requests',
    recommendation: 'This combination enables transparent traffic interception',
  },
  {
    permissions: ['management', 'downloads'],
    severity: 'warning',
    msg: 'Can disable other extensions and trigger downloads (dropper pattern)',
    recommendation: 'Extension management + download capability is a common malware dropper pattern',
  },
  {
    permissions: ['clipboardRead', '<all_urls>'],
    severity: 'warning',
    msg: 'Can read clipboard data and send it to any website (password/credential theft)',
    recommendation: 'Clipboard reading with broad host access enables credential harvesting',
  },
  {
    permissions: ['geolocation', '<all_urls>'],
    severity: 'warning',
    msg: 'Can track physical location and send it to any website',
    recommendation: 'Verify location access is necessary for the extension functionality',
  },
];

/**
 * Legitimate external URLs (not flagged as suspicious)
 */
export const LEGITIMATE_URLS = [
  'chrome.google.com',
  'googleapis.com',
  'gstatic.com',
  'mozilla.org',
  'mozilla.net',
  'firefox.com',
  'addons.mozilla.org',
  'github.com',
  'githubusercontent.com',
  'cloudflare.com',
  'cdn.jsdelivr.net',
  'unpkg.com',
];
