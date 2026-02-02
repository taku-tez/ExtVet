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

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

/**
 * Extract CRX file to temporary directory
 * @param {string} crxPath - Path to CRX file
 * @returns {string|null} Path to extracted directory or null on failure
 */
function extractCrx(crxPath) {
  if (!fs.existsSync(crxPath)) {
    return null;
  }
  
  const tempDir = path.join(os.tmpdir(), 'extvet-crx-' + Date.now());
  fs.mkdirSync(tempDir, { recursive: true });
  
  try {
    const data = fs.readFileSync(crxPath);
    
    // Check magic bytes "Cr24"
    if (data.length < 16 || data.toString('utf8', 0, 4) !== 'Cr24') {
      // Not a valid CRX file, try as plain ZIP
      return extractAsZip(crxPath, tempDir);
    }
    
    // Read version
    const version = data.readUInt32LE(4);
    
    let zipStart;
    
    if (version === 3) {
      // CRX3 format
      const headerLength = data.readUInt32LE(8);
      zipStart = 12 + headerLength;
    } else if (version === 2) {
      // CRX2 format (legacy)
      const pubKeyLength = data.readUInt32LE(8);
      const sigLength = data.readUInt32LE(12);
      zipStart = 16 + pubKeyLength + sigLength;
    } else {
      // Unknown version, try as ZIP
      return extractAsZip(crxPath, tempDir);
    }
    
    if (zipStart >= data.length) {
      fs.rmdirSync(tempDir, { recursive: true });
      return null;
    }
    
    // Extract ZIP portion
    const zipData = data.slice(zipStart);
    const tempZip = path.join(tempDir, '_temp.zip');
    fs.writeFileSync(tempZip, zipData);
    
    try {
      execSync(`unzip -q "${tempZip}" -d "${tempDir}"`, { stdio: 'pipe' });
      fs.unlinkSync(tempZip);
      return tempDir;
    } catch (e) {
      fs.rmdirSync(tempDir, { recursive: true });
      return null;
    }
    
  } catch (err) {
    try {
      fs.rmdirSync(tempDir, { recursive: true });
    } catch (e) {}
    return null;
  }
}

/**
 * Try to extract as plain ZIP
 */
function extractAsZip(filePath, tempDir) {
  try {
    execSync(`unzip -q "${filePath}" -d "${tempDir}"`, { stdio: 'pipe' });
    return tempDir;
  } catch (e) {
    try {
      fs.rmdirSync(tempDir, { recursive: true });
    } catch (e) {}
    return null;
  }
}

/**
 * Cleanup extracted directory
 * @param {string} extractedPath - Path to cleanup
 */
function cleanupExtracted(extractedPath) {
  if (extractedPath && extractedPath.includes('extvet-crx-')) {
    try {
      fs.rmSync(extractedPath, { recursive: true, force: true });
    } catch (err) {
      // Ignore cleanup errors
    }
  }
}

module.exports = {
  extractCrx,
  cleanupExtracted,
};
