#!/usr/bin/env node

/**
 * ExtVet CLI
 * Browser Extension Security Scanner
 */

import { scan, scanUrl, version } from '../dist/index.js';
import * as logger from '../dist/logger.js';
import { loadConfig, mergeConfig } from '../dist/config.js';

const args = process.argv.slice(2);
const command = args[0];

function showHelp() {
  console.log(`
🦅 ExtVet - Browser Extension Security Scanner

Usage: extvet <command> [options]

Commands:
  scan [browser]      Scan installed browser extensions
  check <url|id>      Check a specific extension from web store
  file <path>         Scan a local extension file (.crx, .xpi, .zip)
  update              Update malicious extension database
  db-stats            Show database statistics
  version             Show version

Browsers:
  chrome              Google Chrome (default)
  firefox             Mozilla Firefox
  edge                Microsoft Edge
  brave               Brave Browser
  safari              Safari (macOS only)

Options:
  --profile <path>    Browser profile path
  --format <type>     Output format (table, json, sarif)
  --output <file>     Output file path
  --quiet             Suppress non-essential output
  --verbose           Enable debug output
  --severity <level>  Minimum severity to report (info, warning, critical)
  --config <file>     Config file path (default: .extvetrc)

Config file (.extvetrc):
  {
    "ignoreExtensions": ["extension-id-1", "extension-id-2"],
    "severityOverrides": { "ext-perm-tabs": "warning" },
    "browser": "chrome",
    "format": "table"
  }

Examples:
  extvet scan                                   # Scan Chrome extensions
  extvet scan firefox                           # Scan Firefox addons
  extvet scan chrome --profile "Profile 1"     # Scan specific profile
  extvet scan --verbose                        # Scan with debug output
  extvet check nkbihfbeogaeaoehlefnkodbefgpgknn # Check MetaMask by ID
  extvet check https://chrome.google.com/webstore/detail/xxx
`);
}

async function main() {
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    showHelp();
    process.exit(0);
  }

  if (command === 'version' || command === '--version' || command === '-v') {
    console.log(`ExtVet v${version}`);
    process.exit(0);
  }

  // Load config file first
  const fileConfig = loadConfig();
  
  if (command === 'update') {
    console.log('🦅 ExtVet - Updating malicious extension database...\n');
    try {
      const { updateMaliciousIds } = await import('../dist/malicious-db.js');
      const ids = await updateMaliciousIds();
      console.log(`\n✅ Database updated: ${ids.size} malicious extensions`);
      process.exit(0);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  }

  if (command === 'db-stats') {
    console.log('🦅 ExtVet - Malicious Extension Database Stats\n');
    try {
      const { getDbStats } = await import('../dist/malicious-db.js');
      const stats = await getDbStats({ quiet: true });
      console.log(`  Total malicious IDs: ${stats.totalIds}`);
      console.log(`  Built-in IDs:        ${stats.builtinIds}`);
      console.log(`  Sources:             ${stats.sources.join(', ')}`);
      if (stats.cacheAge !== null) {
        const hours = Math.round(stats.cacheAge / 3600000 * 10) / 10;
        console.log(`  Cache age:           ${hours}h`);
      } else {
        console.log(`  Cache:               Not cached (will fetch on next scan)`);
      }
      console.log(`  Cache path:          ${stats.cachePath}`);
      process.exit(0);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  }

  if (command === 'scan') {
    const browser = args[1] && !args[1].startsWith('-') ? args[1] : (fileConfig.browser || 'chrome');
    const cliOptions = parseOptions(args.slice(args[1]?.startsWith('-') ? 1 : 2));
    const options = mergeConfig(fileConfig, cliOptions);
    
    // Configure logger
    logger.configure(options);
    
    try {
      const results = await scan(browser, options);
      process.exit(results.critical > 0 ? 1 : 0);
    } catch (error) {
      logger.error(`Scan failed: ${error.message}`, error);
      process.exit(1);
    }
  }

  if (command === 'check') {
    const target = args[1];
    if (!target) {
      console.error('Error: Extension URL or ID required');
      process.exit(1);
    }
    
    const cliOptions = parseOptions(args.slice(2));
    const options = mergeConfig(fileConfig, cliOptions);
    
    // Configure logger
    logger.configure(options);
    
    try {
      const results = await scanUrl(target, options);
      process.exit(results.critical > 0 ? 1 : 0);
    } catch (error) {
      logger.error(`Check failed: ${error.message}`, error);
      process.exit(1);
    }
  }

  if (command === 'file') {
    const filePath = args[1];
    if (!filePath) {
      console.error('Error: File path required');
      process.exit(1);
    }
    
    const cliOptions = parseOptions(args.slice(2));
    const options = mergeConfig(fileConfig, cliOptions);
    
    // Configure logger
    logger.configure(options);
    
    try {
      const { scanFile } = await import('../dist/file-scanner.js');
      const results = await scanFile(filePath, options);
      process.exit(results.critical > 0 ? 1 : 0);
    } catch (error) {
      logger.error(`File scan failed: ${error.message}`, error);
      process.exit(1);
    }
  }

  console.error(`Unknown command: ${command}`);
  showHelp();
  process.exit(1);
}

function parseOptions(args) {
  const options = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--profile' && args[i + 1]) {
      options.profile = args[++i];
    } else if (args[i] === '--format' && args[i + 1]) {
      options.format = args[++i];
    } else if (args[i] === '--output' && args[i + 1]) {
      options.output = args[++i];
    } else if (args[i] === '--severity' && args[i + 1]) {
      options.severity = args[++i];
    } else if (args[i] === '--config' && args[i + 1]) {
      options.configPath = args[++i];
    } else if (args[i] === '--quiet' || args[i] === '-q') {
      options.quiet = true;
    } else if (args[i] === '--verbose' || args[i] === '-v') {
      options.verbose = true;
    }
  }
  return options;
}

main().catch(err => {
  logger.error('Unexpected error', err);
  process.exit(1);
});
