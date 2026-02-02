/**
 * Firefox Add-on Scanner
 * Scans installed Firefox add-ons for security issues
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Firefox-specific dangerous permissions
const DANGEROUS_PERMISSIONS = {
  // Critical - Full access
  '<all_urls>': { severity: 'critical', msg: 'Access to ALL websites' },
  '*://*/*': { severity: 'critical', msg: 'Access to ALL websites' },
  'http://*/*': { severity: 'warning', msg: 'Access to all HTTP sites' },
  'https://*/*': { severity: 'warning', msg: 'Access to all HTTPS sites' },
  
  // Critical - Sensitive data
  'cookies': { severity: 'warning', msg: 'Can read/write cookies (session hijacking risk)' },
  'webRequest': { severity: 'warning', msg: 'Can intercept network requests' },
  'webRequestBlocking': { severity: 'critical', msg: 'Can modify/block network requests' },
  'webRequestFilterResponse': { severity: 'critical', msg: 'Can filter response bodies' },
  'proxy': { severity: 'critical', msg: 'Can control proxy settings (MitM risk)' },
  'nativeMessaging': { severity: 'critical', msg: 'Can communicate with native apps' },
  'browserSettings': { severity: 'warning', msg: 'Can modify browser settings' },
  'captivePortal': { severity: 'warning', msg: 'Can detect captive portals' },
  'dns': { severity: 'critical', msg: 'Can perform DNS resolution' },
  'identity': { severity: 'warning', msg: 'Can access browser identity' },
  'pkcs11': { severity: 'critical', msg: 'Can access PKCS #11 security modules' },
  
  // Warning - Privacy concerns
  'tabs': { severity: 'info', msg: 'Can see all open tabs and URLs' },
  'history': { severity: 'warning', msg: 'Can read browsing history' },
  'bookmarks': { severity: 'info', msg: 'Can read/modify bookmarks' },
  'downloads': { severity: 'info', msg: 'Can access downloads' },
  'management': { severity: 'warning', msg: 'Can manage other extensions' },
  'privacy': { severity: 'warning', msg: 'Can modify privacy settings' },
  'browsingData': { severity: 'warning', msg: 'Can clear browsing data' },
  'sessions': { severity: 'warning', msg: 'Can access session data' },
  'topSites': { severity: 'info', msg: 'Can access most visited sites' },
  
  // Firefox-specific
  'geckoProfiler': { severity: 'critical', msg: 'Can access the Gecko profiler' },
  'theme': { severity: 'info', msg: 'Can modify browser theme' },
  'contextualIdentities': { severity: 'warning', msg: 'Can access container tabs' },
  
  // Info - Common but notable
  'storage': { severity: 'info', msg: 'Can store data locally' },
  'unlimitedStorage': { severity: 'info', msg: 'Can store unlimited data' },
  'clipboardRead': { severity: 'warning', msg: 'Can read clipboard' },
  'clipboardWrite': { severity: 'info', msg: 'Can write to clipboard' },
  'geolocation': { severity: 'warning', msg: 'Can access location' },
  'notifications': { severity: 'info', msg: 'Can show notifications' },
  'activeTab': { severity: 'info', msg: 'Can access current active tab' },
};

// Suspicious patterns in extension code
const SUSPICIOUS_PATTERNS = [
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
  // Firefox-specific
  { pattern: /browser\.downloads\.download/g, severity: 'info', msg: 'Can initiate downloads' },
  { pattern: /browser\.webRequest\.filterResponseData/g, severity: 'warning', msg: 'Filters response data' },
];

// Known malicious add-on IDs - loaded dynamically
let KNOWN_MALICIOUS = null;

async function loadMaliciousDb(options = {}) {
  if (KNOWN_MALICIOUS) return KNOWN_MALICIOUS;
  
  try {
    const { getMaliciousIds } = require('../malicious-db.js');
    KNOWN_MALICIOUS = await getMaliciousIds({ quiet: true, ...options });
  } catch (err) {
    KNOWN_MALICIOUS = new Set();
  }
  
  return KNOWN_MALICIOUS;
}

/**
 * Get Firefox profile paths based on OS
 */
function getFirefoxPaths() {
  const platform = os.platform();
  const home = os.homedir();
  
  const paths = {
    darwin: [
      path.join(home, 'Library/Application Support/Firefox/Profiles'),
    ],
    linux: [
      path.join(home, '.mozilla/firefox'),
      path.join(home, 'snap/firefox/common/.mozilla/firefox'), // Snap Firefox
      path.join(home, '.var/app/org.mozilla.firefox/.mozilla/firefox'), // Flatpak Firefox
    ],
    win32: [
      path.join(home, 'AppData/Roaming/Mozilla/Firefox/Profiles'),
    ],
  };

  return paths[platform] || [];
}

/**
 * Find Firefox profiles
 */
function findProfiles(basePaths) {
  const profiles = [];
  
  for (const basePath of basePaths) {
    if (!fs.existsSync(basePath)) continue;
    
    try {
      const entries = fs.readdirSync(basePath);
      
      for (const entry of entries) {
        const profilePath = path.join(basePath, entry);
        if (!fs.statSync(profilePath).isDirectory()) continue;
        
        // Firefox profile directories end with .default, .default-release, etc.
        if (entry.includes('.')) {
          profiles.push({
            name: entry,
            path: profilePath,
          });
        }
      }
    } catch (err) {
      // Skip inaccessible directories
    }
  }
  
  return profiles;
}

/**
 * Find extensions in a Firefox profile
 */
function findExtensions(profilePath) {
  const extensions = [];
  const extensionsPath = path.join(profilePath, 'extensions');
  
  if (!fs.existsSync(extensionsPath)) return extensions;
  
  try {
    const entries = fs.readdirSync(extensionsPath);
    
    for (const entry of entries) {
      const extPath = path.join(extensionsPath, entry);
      const stat = fs.statSync(extPath);
      
      if (stat.isDirectory()) {
        // Unpacked extension directory
        extensions.push({
          id: entry,
          path: extPath,
          type: 'directory',
        });
      } else if (entry.endsWith('.xpi')) {
        // Packed extension (XPI file)
        extensions.push({
          id: entry.replace('.xpi', ''),
          path: extPath,
          type: 'xpi',
        });
      }
    }
  } catch (err) {
    // Skip inaccessible directories
  }
  
  // Also check extensions.json for system/user extensions
  const extensionsJsonPath = path.join(profilePath, 'extensions.json');
  if (fs.existsSync(extensionsJsonPath)) {
    try {
      const extJson = JSON.parse(fs.readFileSync(extensionsJsonPath, 'utf-8'));
      const addons = extJson.addons || [];
      
      for (const addon of addons) {
        if (addon.type === 'extension' && addon.path) {
          // Check if we already have this extension
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
      // Skip if can't parse
    }
  }
  
  return extensions;
}

/**
 * Parse manifest.json from extension
 */
function parseManifest(extPath, extType) {
  let manifestPath;
  
  if (extType === 'xpi') {
    // For XPI files, we'd need to extract - skip for now
    // In production, would use JSZip or similar
    return null;
  }
  
  manifestPath = path.join(extPath, 'manifest.json');
  if (!fs.existsSync(manifestPath)) return null;
  
  try {
    const content = fs.readFileSync(manifestPath, 'utf-8');
    return JSON.parse(content);
  } catch (err) {
    return null;
  }
}

/**
 * Analyze extension permissions
 */
function analyzePermissions(manifest, extInfo) {
  const findings = [];
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
    
    // Check URL patterns
    if (perm.includes('://') && !DANGEROUS_PERMISSIONS[perm]) {
      if (perm.includes('*')) {
        findings.push({
          id: 'ff-perm-wildcard-host',
          severity: 'info',
          extension: `${manifest.name || extInfo.id} (${extInfo.id})`,
          message: `Host permission: ${perm}`,
          recommendation: 'Verify this host access is expected',
        });
      }
    }
  }
  
  // Firefox-specific: Check for browser_specific_settings
  if (manifest.browser_specific_settings?.gecko) {
    const gecko = manifest.browser_specific_settings.gecko;
    
    // Check for strict minimum version (old extension risk)
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
  
  // Check for applications key (legacy)
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

/**
 * Analyze content scripts
 */
function analyzeContentScripts(manifest, extInfo) {
  const findings = [];
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
    
    // Firefox-specific: match_about_blank
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

/**
 * Analyze background scripts
 */
function analyzeBackground(manifest, extInfo, extPath) {
  const findings = [];
  
  if (extInfo.type === 'xpi') {
    // Skip code analysis for packed extensions
    return findings;
  }
  
  let bgScripts = [];
  
  if (manifest.background) {
    if (manifest.background.scripts) {
      bgScripts.push(...manifest.background.scripts);
    }
    // Firefox supports service_worker in MV3
    if (manifest.background.service_worker) {
      bgScripts.push(manifest.background.service_worker);
    }
    // Firefox-specific: page background
    if (manifest.background.page) {
      findings.push({
        id: 'ff-bg-page',
        severity: 'info',
        extension: `${manifest.name || extInfo.id} (${extInfo.id})`,
        message: 'Uses background page (persistent background)',
      });
    }
    
    // Firefox MV2: persistent background
    if (manifest.background.persistent === true) {
      findings.push({
        id: 'ff-bg-persistent',
        severity: 'info',
        extension: `${manifest.name || extInfo.id} (${extInfo.id})`,
        message: 'Uses persistent background script (higher resource usage)',
      });
    }
  }
  
  // Analyze background script content
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
      
      // Check for external URLs
      const urlMatches = content.match(/https?:\/\/[^\s"']+/g) || [];
      const externalUrls = urlMatches.filter(url => {
        const legitimate = [
          'addons.mozilla.org',
          'mozilla.org',
          'mozilla.net',
          'firefox.com',
          'github.com',
          'githubusercontent.com',
          'cloudflare.com',
          'cdn.jsdelivr.net',
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
      // Skip unreadable files
    }
  }
  
  return findings;
}

/**
 * Check against known malicious add-ons
 */
function checkKnownMalicious(extInfo, manifest) {
  const findings = [];
  
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

/**
 * Main Firefox scanner function
 */
async function scanFirefox(options = {}) {
  const findings = [];
  
  // Load malicious DB
  await loadMaliciousDb(options);
  
  // Get Firefox paths
  const basePaths = getFirefoxPaths();
  if (basePaths.length === 0) {
    console.log('  No Firefox installation found');
    return findings;
  }
  
  // Find all profiles
  const profiles = findProfiles(basePaths);
  if (profiles.length === 0) {
    console.log('  No Firefox profiles found');
    return findings;
  }
  
  console.log(`  Found ${profiles.length} Firefox profiles`);
  
  let totalExtensions = 0;
  
  for (const profile of profiles) {
    const extensions = findExtensions(profile.path);
    totalExtensions += extensions.length;
    
    for (const ext of extensions) {
      const manifest = parseManifest(ext.path, ext.type);
      
      if (!manifest && ext.type === 'xpi') {
        // For XPI files without manifest access, just note it
        findings.push({
          id: 'ff-xpi-packed',
          severity: 'info',
          extension: `${ext.name || ext.id}`,
          message: 'Packed XPI extension - limited analysis available',
          recommendation: 'Unpack XPI for full code analysis',
        });
        continue;
      }
      
      if (!manifest) continue;
      
      console.log(`  Scanning: ${manifest.name || ext.id}`);
      
      // Run all analyzers
      findings.push(...checkKnownMalicious(ext, manifest));
      findings.push(...analyzePermissions(manifest, ext));
      findings.push(...analyzeContentScripts(manifest, ext));
      findings.push(...analyzeBackground(manifest, ext, ext.path));
    }
  }
  
  console.log(`  Found ${totalExtensions} extensions`);
  
  return findings;
}

module.exports = { scanFirefox };
