/**
 * Config Loader - .extvetrc support
 */

import * as fs from 'fs';
import * as path from 'path';
import * as logger from './logger.js';
import type { Finding, ExtvetConfig, ScanOptions } from './types.js';

const CONFIG_FILES = [
  '.extvetrc',
  '.extvetrc.json',
  'extvet.config.js',
];

/**
 * Default configuration
 */
export const DEFAULT_CONFIG: ExtvetConfig = {
  ignoreExtensions: [],
  severityOverrides: {},
  customRules: [],
  browser: 'chrome',
  format: 'table',
  severity: 'info',
  quiet: false,
  verbose: false,
};

/**
 * Find and load config file
 */
export function loadConfig(startDir: string = process.cwd()): ExtvetConfig {
  let config: ExtvetConfig = { ...DEFAULT_CONFIG };
  
  for (const filename of CONFIG_FILES) {
    const filepath = path.join(startDir, filename);
    
    if (fs.existsSync(filepath)) {
      logger.debug(`Loading config from ${filepath}`);
      
      try {
        let fileConfig: Partial<ExtvetConfig>;
        if (filename.endsWith('.js')) {
          // eslint-disable-next-line @typescript-eslint/no-require-imports
          fileConfig = require(filepath) as Partial<ExtvetConfig>;
        } else {
          const content = fs.readFileSync(filepath, 'utf-8');
          fileConfig = JSON.parse(content) as Partial<ExtvetConfig>;
        }
        config = mergeConfig(config, fileConfig);
        
        logger.debug('Config loaded', config);
        return config;
      } catch (err) {
        logger.error(`Failed to load config from ${filepath}`, err as Error);
      }
    }
  }
  
  // Try package.json
  const pkgPath = path.join(startDir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')) as { extvet?: Partial<ExtvetConfig> };
      if (pkg.extvet) {
        logger.debug('Loading config from package.json');
        const pkgConfig = pkg.extvet;
        config = mergeConfig(config, pkgConfig);
        return config;
      }
    } catch {
      // Ignore package.json errors
    }
  }
  
  logger.debug('No config file found, using defaults');
  return config;
}

/**
 * Merge config objects (CLI options override file config)
 */
export function mergeConfig(base: ExtvetConfig, override: Partial<ExtvetConfig>): ExtvetConfig {
  return {
    ignoreExtensions: [
      ...base.ignoreExtensions,
      ...(override.ignoreExtensions || []),
    ],
    severityOverrides: {
      ...base.severityOverrides,
      ...(override.severityOverrides || {}),
    },
    customRules: [
      ...base.customRules,
      ...(override.customRules || []),
    ],
    browser: override.browser ?? base.browser,
    format: override.format ?? base.format,
    severity: override.severity ?? base.severity,
    quiet: override.quiet ?? base.quiet,
    verbose: override.verbose ?? base.verbose,
  };
}

/**
 * Apply severity overrides to findings
 */
export function applySeverityOverrides(
  findings: Finding[], 
  overrides: ScanOptions['severityOverrides']
): Finding[] {
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
export function filterIgnoredExtensions(
  findings: Finding[], 
  ignoreList: string[] | undefined
): Finding[] {
  if (!ignoreList || ignoreList.length === 0) {
    return findings;
  }
  
  return findings.filter(finding => {
    const match = finding.extension?.match(/\(([a-z0-9@._-]+)\)/i);
    const extId = match ? match[1] : null;
    return !ignoreList.includes(extId || '');
  });
}

export default {
  loadConfig,
  mergeConfig,
  applySeverityOverrides,
  filterIgnoredExtensions,
  DEFAULT_CONFIG,
};
