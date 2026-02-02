#!/usr/bin/env node

/**
 * ExtVet CLI
 * Browser Extension Security Scanner
 */

const { scan, scanUrl, version } = require('../src/index.js');

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
  version             Show version

Browsers:
  chrome              Google Chrome (default)
  firefox             Mozilla Firefox
  edge                Microsoft Edge
  brave               Brave Browser

Options:
  --profile <path>    Browser profile path
  --format <type>     Output format (table, json, sarif)
  --output <file>     Output file path
  --quiet             Suppress non-essential output
  --severity <level>  Minimum severity to report (info, warning, critical)

Examples:
  extvet scan                                   # Scan Chrome extensions
  extvet scan firefox                           # Scan Firefox addons
  extvet scan chrome --profile "Profile 1"     # Scan specific profile
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

  if (command === 'update') {
    console.log('🦅 ExtVet - Updating malicious extension database...\n');
    try {
      const { updateMaliciousIds } = require('../src/malicious-db.js');
      const ids = await updateMaliciousIds();
      console.log(`\n✅ Database updated: ${ids.size} malicious extensions`);
      process.exit(0);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  }

  if (command === 'scan') {
    const browser = args[1] && !args[1].startsWith('-') ? args[1] : 'chrome';
    const options = parseOptions(args.slice(args[1]?.startsWith('-') ? 1 : 2));
    
    try {
      const results = await scan(browser, options);
      process.exit(results.critical > 0 ? 1 : 0);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  }

  if (command === 'check') {
    const target = args[1];
    if (!target) {
      console.error('Error: Extension URL or ID required');
      process.exit(1);
    }
    
    const options = parseOptions(args.slice(2));
    
    try {
      const results = await scanUrl(target, options);
      process.exit(results.critical > 0 ? 1 : 0);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  }

  if (command === 'file') {
    const filePath = args[1];
    if (!filePath) {
      console.error('Error: File path required');
      process.exit(1);
    }
    
    const options = parseOptions(args.slice(2));
    
    try {
      const { scanFile } = require('../src/file-scanner.js');
      const results = await scanFile(filePath, options);
      process.exit(results.critical > 0 ? 1 : 0);
    } catch (error) {
      console.error(`Error: ${error.message}`);
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
    } else if (args[i] === '--quiet') {
      options.quiet = true;
    }
  }
  return options;
}

main().catch(console.error);
