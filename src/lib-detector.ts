/**
 * Vulnerable Library Detector
 * Detect known vulnerable JavaScript libraries bundled in extensions
 */

import * as fs from 'fs';
import * as path from 'path';
import type { Finding, ExtensionInfo, Manifest } from './types.js';

interface LibSignature {
  name: string;
  /** Regex to extract version from source code */
  versionPattern: RegExp;
  /** Versions considered vulnerable (semver-like check) */
  vulnerableBelow: string;
  /** CVE or advisory reference */
  advisory: string;
  severity: 'critical' | 'warning';
}

const LIBRARY_SIGNATURES: LibSignature[] = [
  // jQuery - XSS vulnerabilities in older versions
  {
    name: 'jQuery',
    versionPattern: /jQuery\s+(?:JavaScript Library\s+)?v?(\d+\.\d+\.\d+)/,
    vulnerableBelow: '3.5.0',
    advisory: 'CVE-2020-11022/CVE-2020-11023 (XSS via HTML sanitization)',
    severity: 'warning',
  },
  {
    name: 'jQuery',
    versionPattern: /jquery[./](\d+\.\d+\.\d+)\/jquery(?:\.min)?\.js/,
    vulnerableBelow: '3.5.0',
    advisory: 'CVE-2020-11022/CVE-2020-11023',
    severity: 'warning',
  },
  // jQuery UI
  {
    name: 'jQuery UI',
    versionPattern: /jQuery UI (?:- )?v?(\d+\.\d+\.\d+)/,
    vulnerableBelow: '1.13.0',
    advisory: 'CVE-2021-41182/41183/41184 (XSS)',
    severity: 'warning',
  },
  // Angular.js (1.x - end of life)
  {
    name: 'AngularJS',
    versionPattern: /AngularJS v(\d+\.\d+\.\d+)/,
    vulnerableBelow: '1.9.0',
    advisory: 'Multiple XSS/sandbox escape CVEs; AngularJS is EOL',
    severity: 'warning',
  },
  // Lodash - prototype pollution
  {
    name: 'Lodash',
    versionPattern: /lodash\.js[^}]*?VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/s,
    vulnerableBelow: '4.17.21',
    advisory: 'CVE-2021-23337 (command injection) / CVE-2020-28500 (ReDoS)',
    severity: 'warning',
  },
  // Moment.js - ReDoS + EOL
  {
    name: 'Moment.js',
    versionPattern: /\/\/! moment\.js\s*\n\/\/! version\s*:\s*(\d+\.\d+\.\d+)/,
    vulnerableBelow: '2.29.4',
    advisory: 'CVE-2022-31129 (ReDoS); Moment.js is in maintenance mode',
    severity: 'warning',
  },
  // Handlebars - prototype pollution + RCE
  {
    name: 'Handlebars',
    versionPattern: /Handlebars v(\d+\.\d+\.\d+)/,
    vulnerableBelow: '4.7.7',
    advisory: 'CVE-2021-23369/23383 (prototype pollution → RCE)',
    severity: 'critical',
  },
  // DOMPurify (should be updated)
  {
    name: 'DOMPurify',
    versionPattern: /DOMPurify[^}]*?VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/s,
    vulnerableBelow: '3.0.6',
    advisory: 'Multiple mXSS bypass CVEs in older versions',
    severity: 'critical',
  },
  // Bootstrap
  {
    name: 'Bootstrap',
    versionPattern: /Bootstrap v(\d+\.\d+\.\d+)/,
    vulnerableBelow: '3.4.1',
    advisory: 'CVE-2019-8331 (XSS via tooltip/popover)',
    severity: 'warning',
  },
  // underscore.js - arbitrary code execution
  {
    name: 'Underscore.js',
    versionPattern: /Underscore\.js (\d+\.\d+\.\d+)/,
    vulnerableBelow: '1.13.6',
    advisory: 'CVE-2021-23358 (arbitrary code execution via template)',
    severity: 'warning',
  },
];

/**
 * Compare semver-like versions: returns true if version < target
 */
function isVersionBelow(version: string, target: string): boolean {
  const v = version.split('.').map(Number);
  const t = target.split('.').map(Number);
  for (let i = 0; i < Math.max(v.length, t.length); i++) {
    const a = v[i] || 0;
    const b = t[i] || 0;
    if (a < b) return true;
    if (a > b) return false;
  }
  return false;
}

/**
 * Scan extension files for vulnerable libraries
 */
export function detectVulnerableLibraries(
  extPath: string,
  extInfo: ExtensionInfo,
  manifest: Manifest,
  prefix: string = 'ext'
): Finding[] {
  const findings: Finding[] = [];
  const extName = manifest.name || extInfo.id;
  const jsFiles = findAllJs(extPath);
  const detected = new Set<string>(); // Avoid duplicates

  for (const jsFile of jsFiles) {
    let content: string;
    try {
      const stat = fs.statSync(jsFile);
      // Skip very large files (>2MB) for performance
      if (stat.size > 2 * 1024 * 1024) continue;
      content = fs.readFileSync(jsFile, 'utf-8');
    } catch {
      continue;
    }

    for (const sig of LIBRARY_SIGNATURES) {
      const match = content.match(sig.versionPattern);
      if (!match) continue;

      const version = match[1];
      const key = `${sig.name}@${version}`;
      if (detected.has(key)) continue;
      detected.add(key);

      if (isVersionBelow(version, sig.vulnerableBelow)) {
        findings.push({
          id: `${prefix}-vuln-lib-${sig.name.toLowerCase().replace(/[^a-z]/g, '')}`,
          severity: sig.severity,
          extension: `${extName} (${extInfo.id})`,
          message: `Vulnerable ${sig.name} ${version} (needs >=${sig.vulnerableBelow}): ${sig.advisory}`,
          recommendation: `Update ${sig.name} to latest version or remove if unused`,
        });
      } else {
        // Still note the library presence
        findings.push({
          id: `${prefix}-lib-${sig.name.toLowerCase().replace(/[^a-z]/g, '')}`,
          severity: 'info',
          extension: `${extName} (${extInfo.id})`,
          message: `Bundled library: ${sig.name} ${version}`,
          recommendation: 'Keep bundled libraries up to date',
        });
      }
    }
  }

  return findings;
}

function findAllJs(dir: string, files: string[] = [], depth: number = 0): string[] {
  if (depth > 5) return files;
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        findAllJs(full, files, depth + 1);
      } else if (entry.isFile() && /\.js$/.test(entry.name)) {
        files.push(full);
      }
    }
  } catch { /* skip */ }
  return files;
}

export { LIBRARY_SIGNATURES, isVersionBelow };
