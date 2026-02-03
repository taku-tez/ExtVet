/**
 * XPI Extractor
 * Extract and analyze Firefox XPI (ZIP) files
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';

/**
 * Extract XPI file to temporary directory
 */
export function extractXpi(xpiPath: string): string | null {
  if (!fs.existsSync(xpiPath)) {
    return null;
  }
  
  const tempDir = path.join(os.tmpdir(), 'extvet-xpi-' + Date.now());
  fs.mkdirSync(tempDir, { recursive: true });
  
  try {
    try {
      execSync(`unzip -q "${xpiPath}" -d "${tempDir}"`, { stdio: 'pipe' });
    } catch {
      fs.rmSync(tempDir, { recursive: true, force: true });
      return null;
    }
    
    return tempDir;
  } catch {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch { /* ignore */ }
    return null;
  }
}

/**
 * Cleanup extracted directory
 */
export function cleanupExtracted(extractedPath: string): void {
  if (extractedPath && extractedPath.includes('extvet-xpi-')) {
    try {
      fs.rmSync(extractedPath, { recursive: true, force: true });
    } catch { /* ignore */ }
  }
}

/**
 * List all JavaScript files in directory
 */
export function findJsFiles(dir: string, files: string[] = []): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== '.git') {
        findJsFiles(fullPath, files);
      }
    } else if (entry.isFile()) {
      if (entry.name.endsWith('.js') || entry.name.endsWith('.html') || entry.name.endsWith('.json')) {
        files.push(fullPath);
      }
    }
  }
  
  return files;
}
