/**
 * File Scanner
 * Scan local extension files (.crx, .xpi, .zip)
 */

import * as fs from 'fs';
import * as path from 'path';
import { extractCrx, cleanupExtracted as cleanupCrx } from './crx-extractor.js';
import { extractXpi, cleanupExtracted as cleanupXpi } from './xpi-extractor.js';
import { Reporter } from './reporter.js';
import {
  analyzePermissions,
  analyzeScriptContent,
  analyzeObfuscation,
  checkManifestVersion,
  analyzePermissionCombos,
  analyzeCSP,
  analyzeUpdateUrl,
  analyzeExternallyConnectable,
  analyzeWebAccessibleResources,
} from './analyzers.js';
import type { ScanOptions, ScanSummary, Manifest, Finding } from './types.js';

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
  
  // Extract based on file type
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
    
    const extInfo = { id: fileName, path: extractedPath };
    
    // Run analyzers
    findings.push(...analyzePermissions(manifest, extInfo, 'file'));
    findings.push(...checkManifestVersion(manifest, extInfo, 'file'));
    findings.push(...analyzePermissionCombos(manifest, extInfo, 'file'));
    findings.push(...analyzeCSP(manifest, extInfo, 'file'));
    findings.push(...analyzeUpdateUrl(manifest, extInfo, 'file'));
    findings.push(...analyzeExternallyConnectable(manifest, extInfo, 'file'));
    findings.push(...analyzeWebAccessibleResources(manifest, extInfo, 'file'));
    
    // Scan JavaScript files
    const jsFiles = findJsFiles(extractedPath);
    for (const jsFile of jsFiles) {
      try {
        const content = fs.readFileSync(jsFile, 'utf-8');
        const relPath = path.relative(extractedPath, jsFile);
        findings.push(...analyzeScriptContent(content, relPath, extInfo, manifest, 'file'));
        findings.push(...analyzeObfuscation(content, relPath, extInfo, manifest, 'file'));
      } catch {
        // Skip unreadable files
      }
    }
    
  } finally {
    if (cleanupFn && extractedPath) {
      cleanupFn(extractedPath);
    }
  }
  
  return await reporter.report(findings, options);
}

/**
 * Recursively find JavaScript files
 */
function findJsFiles(dir: string, files: string[] = []): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    
    if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '.git') {
      findJsFiles(fullPath, files);
    } else if (entry.isFile() && entry.name.endsWith('.js')) {
      files.push(fullPath);
    }
  }
  
  return files;
}
