/**
 * File Scanner
 * Scan local extension files (.crx, .xpi, .zip)
 */

import * as fs from 'fs';
import * as path from 'path';
import { extractCrx, cleanupExtracted as cleanupCrx } from './crx-extractor.js';
import { extractXpi, cleanupExtracted as cleanupXpi } from './xpi-extractor.js';
import { Reporter } from './reporter.js';
import type { Finding, ScanOptions, ScanSummary, Manifest, PermissionDanger, SuspiciousPattern } from './types.js';

const DANGEROUS_PERMISSIONS: Record<string, PermissionDanger> = {
  '<all_urls>': { severity: 'critical', msg: 'Access to ALL websites' },
  '*://*/*': { severity: 'critical', msg: 'Access to ALL websites' },
  'webRequestBlocking': { severity: 'critical', msg: 'Can modify/block network requests' },
  'nativeMessaging': { severity: 'critical', msg: 'Can communicate with native apps' },
  'debugger': { severity: 'critical', msg: 'Full debugging access to tabs' },
  'proxy': { severity: 'critical', msg: 'Can control proxy settings' },
  'cookies': { severity: 'warning', msg: 'Can read/write cookies' },
  'history': { severity: 'warning', msg: 'Can read browsing history' },
  'webRequest': { severity: 'warning', msg: 'Can intercept network requests' },
  'management': { severity: 'warning', msg: 'Can manage other extensions' },
  'tabs': { severity: 'info', msg: 'Can see all open tabs' },
  'storage': { severity: 'info', msg: 'Can store data locally' },
};

const SUSPICIOUS_PATTERNS: SuspiciousPattern[] = [
  { pattern: /eval\s*\(/g, severity: 'critical', msg: 'Uses eval() - code injection risk' },
  { pattern: /new\s+Function\s*\(/g, severity: 'critical', msg: 'Uses Function constructor' },
  { pattern: /document\.write/g, severity: 'warning', msg: 'Uses document.write - XSS risk' },
  { pattern: /innerHTML\s*=/g, severity: 'info', msg: 'Uses innerHTML - potential XSS' },
  { pattern: /fetch\s*\(['"](http:\/\/)/g, severity: 'warning', msg: 'Insecure HTTP fetch' },
];

/**
 * Scan a local extension file
 */
export async function scanFile(filePath: string, options: ScanOptions = {}): Promise<ScanSummary> {
  const reporter = new Reporter(options);
  const findings: Finding[] = [];
  
  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }
  
  const ext = path.extname(filePath).toLowerCase();
  const fileName = path.basename(filePath);
  
  reporter.start(`Scanning file: ${fileName}...`);
  
  let extractedPath: string | null = null;
  let cleanupFn: ((p: string) => void) | null = null;
  
  if (ext === '.crx') {
    extractedPath = extractCrx(filePath);
    cleanupFn = cleanupCrx;
  } else if (ext === '.xpi') {
    extractedPath = extractXpi(filePath);
    cleanupFn = cleanupXpi;
  } else if (ext === '.zip') {
    extractedPath = extractCrx(filePath);
    cleanupFn = cleanupCrx;
  } else {
    throw new Error(`Unsupported file type: ${ext}. Supported: .crx, .xpi, .zip`);
  }
  
  if (!extractedPath) {
    throw new Error(`Failed to extract ${fileName}. Make sure 'unzip' is installed.`);
  }
  
  try {
    const manifestPath = path.join(extractedPath, 'manifest.json');
    if (!fs.existsSync(manifestPath)) {
      throw new Error('No manifest.json found in extension');
    }
    
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8')) as Manifest;
    console.log(`  Name: ${manifest.name || 'Unknown'}`);
    console.log(`  Version: ${manifest.version || 'Unknown'}`);
    
    const allPermissions = [
      ...(manifest.permissions || []),
      ...(manifest.optional_permissions || []),
      ...(manifest.host_permissions || []),
    ];
    
    for (const perm of allPermissions) {
      if (DANGEROUS_PERMISSIONS[perm]) {
        const danger = DANGEROUS_PERMISSIONS[perm];
        findings.push({
          id: `file-perm-${perm.replace(/[^a-z]/gi, '-')}`,
          severity: danger.severity,
          extension: manifest.name || fileName,
          message: `Permission: ${perm} - ${danger.msg}`,
          recommendation: `Review if "${perm}" permission is necessary`,
        });
      }
    }
    
    if (manifest.manifest_version === 2) {
      findings.push({
        id: 'file-mv2-deprecated',
        severity: 'warning',
        extension: manifest.name || fileName,
        message: 'Uses Manifest V2 (deprecated)',
        recommendation: 'Update to Manifest V3',
      });
    }
    
    const jsFiles = findJsFiles(extractedPath);
    
    for (const jsFile of jsFiles) {
      try {
        const content = fs.readFileSync(jsFile, 'utf-8');
        const relPath = path.relative(extractedPath, jsFile);
        
        for (const pattern of SUSPICIOUS_PATTERNS) {
          const matches = content.match(pattern.pattern);
          if (matches) {
            findings.push({
              id: `file-code-${pattern.msg.replace(/[^a-z]/gi, '-').toLowerCase()}`,
              severity: pattern.severity,
              extension: manifest.name || fileName,
              message: `${pattern.msg} in ${relPath}`,
              recommendation: 'Review the code for security issues',
            });
          }
        }
      } catch {
        // Skip unreadable files
      }
    }
    
  } finally {
    if (cleanupFn && extractedPath) {
      cleanupFn(extractedPath);
    }
  }
  
  const summary = reporter.report(findings, options);
  return summary;
}

function findJsFiles(dir: string, files: string[] = []): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== '.git') {
        findJsFiles(fullPath, files);
      }
    } else if (entry.isFile() && entry.name.endsWith('.js')) {
      files.push(fullPath);
    }
  }
  
  return files;
}
