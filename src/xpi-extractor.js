/**
 * XPI Extractor
 * Extract and analyze Firefox XPI (ZIP) files
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

/**
 * Extract XPI file to temporary directory
 * @param {string} xpiPath - Path to XPI file
 * @returns {string|null} Path to extracted directory or null on failure
 */
function extractXpi(xpiPath) {
  if (!fs.existsSync(xpiPath)) {
    return null;
  }
  
  // Create temp directory
  const tempDir = path.join(os.tmpdir(), 'extvet-xpi-' + Date.now());
  fs.mkdirSync(tempDir, { recursive: true });
  
  try {
    // XPI files are just ZIP files
    // Try unzip first (Linux/Mac), then tar (fallback)
    try {
      execSync(`unzip -q "${xpiPath}" -d "${tempDir}"`, { stdio: 'pipe' });
    } catch (e) {
      // Try with Node's built-in capabilities if unzip fails
      // For now, just return null and note the limitation
      fs.rmdirSync(tempDir, { recursive: true });
      return null;
    }
    
    return tempDir;
  } catch (err) {
    // Cleanup on error
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
  if (extractedPath && extractedPath.includes('extvet-xpi-')) {
    try {
      fs.rmSync(extractedPath, { recursive: true, force: true });
    } catch (err) {
      // Ignore cleanup errors
    }
  }
}

/**
 * List all JavaScript files in directory
 * @param {string} dir - Directory to scan
 * @returns {string[]} Array of file paths
 */
function findJsFiles(dir, files = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    
    if (entry.isDirectory()) {
      // Skip node_modules and .git
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

module.exports = {
  extractXpi,
  cleanupExtracted,
  findJsFiles,
};
