/**
 * Shared Constants
 * Common permission definitions and suspicious patterns
 */

import type { PermissionDanger, SuspiciousPattern } from './types.js';

/**
 * ExtVet version - single source of truth
 */
export const VERSION = '2.7.0';

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
  
  // Warning - Identity & Auth
  'identity': { severity: 'warning', msg: 'Can access OAuth tokens and user identity' },
  'identity.email': { severity: 'warning', msg: 'Can read user email address' },
  
  // Warning - System access
  'system.cpu': { severity: 'info', msg: 'Can read CPU info (fingerprinting)' },
  'system.memory': { severity: 'info', msg: 'Can read memory info (fingerprinting)' },
  'system.display': { severity: 'info', msg: 'Can read display info (fingerprinting)' },
  'topSites': { severity: 'warning', msg: 'Can read most visited sites' },
  'webNavigation': { severity: 'info', msg: 'Can observe navigation events' },
  'declarativeNetRequest': { severity: 'warning', msg: 'Can modify network requests via rules (MV3)' },
  'declarativeNetRequestWithHostAccess': { severity: 'critical', msg: 'Can modify network requests on matched hosts (MV3)' },
  'scripting': { severity: 'warning', msg: 'Can inject scripts into web pages (MV3)' },
  'offscreen': { severity: 'info', msg: 'Can create offscreen documents' },
  'sidePanel': { severity: 'info', msg: 'Can use side panel API' },
  'desktopCapture': { severity: 'critical', msg: 'Can capture screen/window/tab content' },
  'tabCapture': { severity: 'critical', msg: 'Can capture tab audio/video' },
  'pageCapture': { severity: 'warning', msg: 'Can save pages as MHTML' },
  'ttsEngine': { severity: 'info', msg: 'Implements text-to-speech engine' },
  'unlimitedStorage': { severity: 'info', msg: 'Unlimited local storage (data hoarding risk)' },
  'contentSettings': { severity: 'warning', msg: 'Can modify content settings (JS, cookies, images, etc.)' },
  'fontSettings': { severity: 'info', msg: 'Can modify font settings' },
  
  // Info - Common but notable
  'storage': { severity: 'info', msg: 'Can store data locally' },
  'clipboardRead': { severity: 'warning', msg: 'Can read clipboard' },
  'clipboardWrite': { severity: 'info', msg: 'Can write to clipboard' },
  'geolocation': { severity: 'warning', msg: 'Can access location' },
  'notifications': { severity: 'info', msg: 'Can show notifications' },
  'alarms': { severity: 'info', msg: 'Can schedule periodic tasks' },
  'contextMenus': { severity: 'info', msg: 'Can add context menu items' },
  'activeTab': { severity: 'info', msg: 'Temporary access to active tab on click' },
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
 * Service worker / background-specific suspicious patterns
 * These patterns are especially dangerous in MV3 service workers
 */
export const SERVICE_WORKER_PATTERNS: SuspiciousPattern[] = [
  // External script loading in service worker
  { pattern: /importScripts\s*\(\s*['"`]https?:\/\//g, severity: 'critical', msg: 'Service worker imports external scripts (remote code execution)' },
  { pattern: /importScripts\s*\(/g, severity: 'info', msg: 'Service worker uses importScripts' },
  // Alarm-based C2 polling
  { pattern: /chrome\.alarms\.create\s*\([^)]*periodInMinutes\s*:\s*[0-9.]+/g, severity: 'info', msg: 'Creates periodic alarm (check for C2 polling)' },
  { pattern: /chrome\.alarms\.onAlarm\.addListener[\s\S]{0,200}fetch\s*\(/g, severity: 'warning', msg: 'Alarm triggers network fetch (potential C2 beacon pattern)' },
  // Immediate data collection on install
  { pattern: /chrome\.runtime\.onInstalled\.addListener[\s\S]{0,500}chrome\.cookies\.getAll/g, severity: 'critical', msg: 'Collects all cookies immediately on install (data theft)' },
  { pattern: /chrome\.runtime\.onInstalled\.addListener[\s\S]{0,500}chrome\.history\.(search|getVisits)/g, severity: 'critical', msg: 'Harvests browsing history on install (data theft)' },
  { pattern: /chrome\.runtime\.onInstalled\.addListener[\s\S]{0,300}fetch\s*\(/g, severity: 'warning', msg: 'Phones home immediately on install' },
  // Keepalive tricks to maintain persistence
  { pattern: /chrome\.runtime\.connect[\s\S]{0,100}keepAlive|keepAlive[\s\S]{0,100}chrome\.runtime\.connect/g, severity: 'warning', msg: 'Service worker keepalive trick (persistence evasion)' },
  { pattern: /setInterval\s*\(\s*\(\)\s*=>\s*\{[\s\S]{0,50}chrome\.runtime\.getPlatformInfo/g, severity: 'warning', msg: 'Service worker keepalive via periodic API calls' },
  // Dynamic rule manipulation
  { pattern: /chrome\.declarativeNetRequest\.updateDynamicRules[\s\S]{0,300}redirect/g, severity: 'warning', msg: 'Dynamically redirects requests via declarativeNetRequest' },
  // Extension self-disabling (anti-forensics)
  { pattern: /chrome\.management\.setEnabled\s*\([^,]+,\s*false/g, severity: 'warning', msg: 'Can disable itself or other extensions (anti-forensics)' },
  { pattern: /chrome\.management\.uninstallSelf/g, severity: 'warning', msg: 'Can self-uninstall (evidence destruction)' },
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
  {
    permissions: ['scripting', '<all_urls>'],
    severity: 'critical',
    msg: 'Can inject arbitrary scripts into ALL websites (MV3 equivalent of full code injection)',
    recommendation: 'Scripting API + all URLs allows injecting code into any page including banking sites',
  },
  {
    permissions: ['declarativeNetRequest', 'cookies'],
    severity: 'warning',
    msg: 'Can modify network requests and access cookies (request hijacking + session theft)',
    recommendation: 'This combination enables request redirection with cookie theft',
  },
  {
    permissions: ['identity', '<all_urls>'],
    severity: 'critical',
    msg: 'Can steal OAuth tokens and send them to any website',
    recommendation: 'Identity access with broad host permissions enables token exfiltration',
  },
  {
    permissions: ['desktopCapture', '<all_urls>'],
    severity: 'critical',
    msg: 'Can capture screen content and exfiltrate to any website (spyware)',
    recommendation: 'Screen capture with network access is a spyware pattern',
  },
  {
    permissions: ['tabCapture', '<all_urls>'],
    severity: 'critical',
    msg: 'Can capture tab audio/video and exfiltrate (surveillance)',
    recommendation: 'Tab capture with broad host access enables surveillance',
  },
  {
    permissions: ['topSites', 'history', 'bookmarks'],
    severity: 'warning',
    msg: 'Can build comprehensive user profiling (top sites + history + bookmarks)',
    recommendation: 'This combination enables extensive user behavior profiling',
  },
  {
    permissions: ['contentSettings', '<all_urls>'],
    severity: 'warning',
    msg: 'Can disable security settings (JavaScript, cookies) on all sites',
    recommendation: 'Content settings modification with broad access can weaken site security',
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

/**
 * Suspicious URL patterns in extension code
 * Domains/patterns commonly used for C2, data exfiltration, or phishing
 */
export interface SuspiciousDomain {
  pattern: RegExp;
  severity: 'critical' | 'warning';
  msg: string;
}

export const SUSPICIOUS_DOMAINS: SuspiciousDomain[] = [
  // IP-based URLs (C2 servers)
  { pattern: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, severity: 'warning', msg: 'Connects to raw IP address (potential C2 server)' },
  // Data exfiltration endpoints
  { pattern: /https?:\/\/[^/]*\.workers\.dev/, severity: 'warning', msg: 'Uses Cloudflare Workers endpoint (common for data relay)' },
  { pattern: /https?:\/\/[^/]*\.ngrok\.io/, severity: 'critical', msg: 'Connects to ngrok tunnel (likely C2 or dev backdoor)' },
  { pattern: /https?:\/\/[^/]*\.trycloudflare\.com/, severity: 'warning', msg: 'Uses Cloudflare Tunnel (temporary endpoint, suspicious in production)' },
  // Suspicious TLDs commonly used in malicious extensions
  { pattern: /https?:\/\/[^/]*\.(tk|ml|ga|cf|gq|top|xyz|buzz|click|rest)\b/, severity: 'warning', msg: 'Uses suspicious TLD commonly associated with malware' },
  // Pastebin/code hosting for payload delivery
  { pattern: /https?:\/\/(pastebin\.com|paste\.ee|hastebin\.com|rentry\.co)/, severity: 'critical', msg: 'Fetches from paste service (payload delivery pattern)' },
  // URL shorteners (hiding actual destination)
  { pattern: /https?:\/\/(bit\.ly|tinyurl\.com|t\.co|is\.gd|v\.gd|shorturl\.at)/, severity: 'warning', msg: 'Uses URL shortener (hides actual destination)' },
  // Telegram bot API (common C2 channel)
  { pattern: /https?:\/\/api\.telegram\.org\/bot/, severity: 'critical', msg: 'Communicates with Telegram Bot API (C2 channel)' },
  // Discord webhooks (data exfiltration)
  { pattern: /https?:\/\/discord\.com\/api\/webhooks/, severity: 'critical', msg: 'Uses Discord webhook (data exfiltration channel)' },
  // Dynamic DNS services
  { pattern: /https?:\/\/[^/]*\.(duckdns\.org|no-ip\.com|dynu\.com|freedns\.afraid\.org)/, severity: 'warning', msg: 'Uses dynamic DNS (infrastructure hiding pattern)' },
];
