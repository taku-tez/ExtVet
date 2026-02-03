/**
 * Config Loader - .extvetrc support
 * 
 * Supports:
 * - .extvetrc (JSON)
 * - .extvetrc.json
 * - extvet.config.js
 * - package.json "extvet" field
 */

const fs = require('fs');
const path = require('path');
const logger = require('./logger.js');

const CONFIG_FILES = [
  '.extvetrc',
  '.extvetrc.json',
  'extvet.config.js',
];

/**
 * Default configuration
 */
const DEFAULT_CONFIG = {
  // Extensions to ignore (by ID)
  ignoreExtensions: [],
  
  // Severity overrides
  // e.g., { "ext-perm-tabs": "warning" }
  severityOverrides: {},
  
  // Custom rules
  customRules: [],
  
  // Default browser
  browser: 'chrome',
  
  // Output format
  format: 'table',
  
  // Minimum severity to report
  severity: 'info',
  
  // Quiet mode
  quiet: false,
  
  // Verbose mode
  verbose: false,
};

/**
 * Find and load config file
 * @param {string} startDir - Directory to start searching from
 * @returns {object} Configuration object
 */
function loadConfig(startDir = process.cwd()) {
  let config = { ...DEFAULT_CONFIG };
  
  // Try each config file
  for (const filename of CONFIG_FILES) {
    const filepath = path.join(startDir, filename);
    
    if (fs.existsSync(filepath)) {
      logger.debug(`Loading config from ${filepath}`);
      
      try {
        if (filename.endsWith('.js')) {
          // JavaScript config
          const jsConfig = require(filepath);
          config = mergeConfig(config, jsConfig);
        } else {
          // JSON config
          const content = fs.readFileSync(filepath, 'utf-8');
          const jsonConfig = JSON.parse(content);
          config = mergeConfig(config, jsonConfig);
        }
        
        logger.debug('Config loaded', config);
        return config;
      } catch (err) {
        logger.error(`Failed to load config from ${filepath}`, err);
      }
    }
  }
  
  // Try package.json
  const pkgPath = path.join(startDir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      if (pkg.extvet) {
        logger.debug('Loading config from package.json');
        config = mergeConfig(config, pkg.extvet);
        return config;
      }
    } catch (err) {
      // Ignore package.json errors
    }
  }
  
  logger.debug('No config file found, using defaults');
  return config;
}

/**
 * Merge config objects (CLI options override file config)
 */
function mergeConfig(base, override) {
  const merged = { ...base };
  
  for (const [key, value] of Object.entries(override)) {
    if (value !== undefined && value !== null) {
      if (Array.isArray(value)) {
        merged[key] = [...(base[key] || []), ...value];
      } else if (typeof value === 'object' && !Array.isArray(value)) {
        merged[key] = { ...(base[key] || {}), ...value };
      } else {
        merged[key] = value;
      }
    }
  }
  
  return merged;
}

/**
 * Apply severity overrides to findings
 */
function applySeverityOverrides(findings, overrides) {
  if (!overrides || Object.keys(overrides).length === 0) {
    return findings;
  }
  
  return findings.map(finding => {
    if (overrides[finding.id]) {
      return { ...finding, severity: overrides[finding.id] };
    }
    return finding;
  });
}

/**
 * Filter ignored extensions
 */
function filterIgnoredExtensions(findings, ignoreList) {
  if (!ignoreList || ignoreList.length === 0) {
    return findings;
  }
  
  return findings.filter(finding => {
    // Extract extension ID from the finding
    // Chrome IDs are 32 lowercase letters, Firefox can be email-like or UUID
    const match = finding.extension?.match(/\(([a-z0-9@._-]+)\)/i);
    const extId = match ? match[1] : null;
    return !ignoreList.includes(extId);
  });
}

module.exports = {
  loadConfig,
  mergeConfig,
  applySeverityOverrides,
  filterIgnoredExtensions,
  DEFAULT_CONFIG,
};
