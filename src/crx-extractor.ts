/**
 * CRX Extractor
 * Extract and analyze Chrome CRX (packed extension) files
 * 
 * CRX3 format:
 * - Magic bytes: "Cr24"
 * - Version: 4 bytes (little-endian, value 3 for CRX3)
 * - Header length: 4 bytes (little-endian)
 * - Header: protobuf (skip)
 * - ZIP archive: rest of file
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';

/**
 * Extract CRX file to temporary directory
 */
export function extractCrx(crxPath: string): string | null {
  if (!fs.existsSync(crxPath)) {
    return null;
  }
  
  const tempDir = path.join(os.tmpdir(), 'extvet-crx-' + Date.now());
  fs.mkdirSync(tempDir, { recursive: true });
  
  try {
    const data = fs.readFileSync(crxPath);
    
    if (data.length < 16 || data.toString('utf8', 0, 4) !== 'Cr24') {
      return extractAsZip(crxPath, tempDir);
    }
    
    const version = data.readUInt32LE(4);
    
    let zipStart: number;
    
    if (version === 3) {
      const headerLength = data.readUInt32LE(8);
      zipStart = 12 + headerLength;
    } else if (version === 2) {
      const pubKeyLength = data.readUInt32LE(8);
      const sigLength = data.readUInt32LE(12);
      zipStart = 16 + pubKeyLength + sigLength;
    } else {
      return extractAsZip(crxPath, tempDir);
    }
    
    if (zipStart >= data.length) {
      fs.rmSync(tempDir, { recursive: true, force: true });
      return null;
    }
    
    const zipData = data.subarray(zipStart);
    const tempZip = path.join(tempDir, '_temp.zip');
    fs.writeFileSync(tempZip, zipData);
    
    try {
      execSync(`unzip -q "${tempZip}" -d "${tempDir}"`, { stdio: 'pipe' });
      fs.unlinkSync(tempZip);
      return tempDir;
    } catch {
      fs.rmSync(tempDir, { recursive: true, force: true });
      return null;
    }
    
  } catch {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch { /* ignore */ }
    return null;
  }
}

/**
 * Try to extract as plain ZIP
 */
function extractAsZip(filePath: string, tempDir: string): string | null {
  try {
    execSync(`unzip -q "${filePath}" -d "${tempDir}"`, { stdio: 'pipe' });
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
  if (extractedPath && extractedPath.includes('extvet-crx-')) {
    try {
      fs.rmSync(extractedPath, { recursive: true, force: true });
    } catch { /* ignore */ }
  }
}
