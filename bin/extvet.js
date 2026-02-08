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
  watch [browser]     Continuous monitoring (re-scans periodically)
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
  --format <type>     Output format (table, json, sarif, html, markdown)
  --output <file>     Output file path
  --quiet             Suppress non-essential output
  --verbose           Enable debug output
  --severity <level>  Minimum severity to report (info, warning, critical)
  --fail-on <level>   Exit with code 1 on severity (critical, warning, info, none)
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

      // Policy evaluation
      if (options.policyPath) {
        const { loadPolicy, evaluatePolicy } = await import('../dist/policy.js');
        const policy = loadPolicy(options.policyPath);
        const installedIds = (results.riskScores || []).map(s => {
          const m = s.extension.match(/\(([a-z]{32})\)/);
          return m ? m[1] : s.extension;
        });
        const violations = evaluatePolicy(policy, results.riskScores || [], results.findings || [], installedIds);
        if (violations.length > 0) {
          console.log('\n⚠️  POLICY VIOLATIONS:');
          for (const v of violations) {
            console.log(`  ❌ [${v.rule}] ${v.extension}: ${v.message}`);
          }
          console.log(`\n${violations.length} violation(s) found.`);
          process.exit(2);
        } else {
          console.log('\n✅ All extensions comply with policy.');
        }
      }

      process.exit(getExitCode(results, options));
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
      process.exit(getExitCode(results, options));
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
      process.exit(getExitCode(results, options));
    } catch (error) {
      logger.error(`File scan failed: ${error.message}`, error);
      process.exit(1);
    }
  }

  if (command === 'policy-init') {
    const { generateSamplePolicy } = await import('../dist/policy.js');
    const outPath = args[1] || '.extvet-policy.json';
    const fs = await import('fs');
    fs.writeFileSync(outPath, JSON.stringify(generateSamplePolicy(), null, 2));
    console.log(`✅ Sample policy written to ${outPath}`);
    console.log('Edit this file, then use: extvet scan chrome --policy .extvet-policy.json');
    process.exit(0);
  }

  if (command === 'watch') {
    const browser = args[1] && !args[1].startsWith('-') ? args[1] : (fileConfig.browser || 'chrome');
    const cliOptions = parseOptions(args.slice(args[1]?.startsWith('-') ? 1 : 2));
    const options = mergeConfig(fileConfig, { ...cliOptions, quiet: false });
    const intervalMin = parseInt(cliOptions.watchInterval) || 30;

    logger.configure(options);
    console.log(`🦅 ExtVet Watch Mode — scanning ${browser} every ${intervalMin}min\n`);
    console.log('Press Ctrl+C to stop.\n');

    let previousScores = new Map();

    const runWatchScan = async () => {
      const timestamp = new Date().toLocaleString();
      console.log(`\n⏰ [${timestamp}] Scanning...`);
      try {
        const results = await scan(browser, { ...options, quiet: true });
        const scores = results.riskScores || [];
        const currentScores = new Map(scores.map(s => [s.extension, s]));

        // Detect changes
        const newExts = scores.filter(s => !previousScores.has(s.extension));
        const removedExts = [...previousScores.keys()].filter(e => !currentScores.has(e));
        const changedExts = scores.filter(s => {
          const prev = previousScores.get(s.extension);
          return prev && prev.score !== s.score;
        });

        if (newExts.length === 0 && removedExts.length === 0 && changedExts.length === 0) {
          console.log(`   ✅ No changes. ${scores.length} extensions, Grade ${results.overallGrade} (${results.overallRiskScore}/100)`);
        } else {
          if (newExts.length > 0) {
            console.log(`   🆕 New extensions detected:`);
            for (const e of newExts) {
              const emoji = e.grade === 'F' ? '🔴' : e.grade === 'D' ? '🟠' : e.grade === 'C' ? '🟡' : '🟢';
              console.log(`      ${emoji} ${e.grade} (${e.score}) — ${e.extension}`);
            }
          }
          if (removedExts.length > 0) {
            console.log(`   🗑️  Removed: ${removedExts.join(', ')}`);
          }
          if (changedExts.length > 0) {
            console.log(`   🔄 Risk score changes:`);
            for (const e of changedExts) {
              const prev = previousScores.get(e.extension);
              const dir = e.score > prev.score ? '📈' : '📉';
              console.log(`      ${dir} ${e.extension}: ${prev.grade}(${prev.score}) → ${e.grade}(${e.score})`);
            }
          }
          console.log(`   📊 Overall: Grade ${results.overallGrade} (${results.overallRiskScore}/100)`);
        }

        previousScores = currentScores;
      } catch (error) {
        console.error(`   ❌ Scan error: ${error.message}`);
      }
    };

    await runWatchScan();
    setInterval(runWatchScan, intervalMin * 60 * 1000);
    // Keep process alive
    await new Promise(() => {});
  }

  console.error(`Unknown command: ${command}`);
  showHelp();
  process.exit(1);
}

function getExitCode(results, options) {
  // Grade-based exit code (--fail-on-grade A|B|C|D|F)
  if (options.failOnGrade && results.riskScores) {
    const gradeOrder = { A: 0, B: 1, C: 2, D: 3, F: 4 };
    const threshold = gradeOrder[options.failOnGrade.toUpperCase()] ?? 3;
    const worstExt = results.riskScores.find(s => gradeOrder[s.grade] >= threshold);
    if (worstExt) return 1;
    return 0;
  }

  const failOn = options.failOn || 'critical';
  if (failOn === 'critical') return results.critical > 0 ? 1 : 0;
  if (failOn === 'warning') return (results.critical + results.warning) > 0 ? 1 : 0;
  if (failOn === 'info') return results.total > 0 ? 1 : 0;
  if (failOn === 'none') return 0;
  return results.critical > 0 ? 1 : 0;
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
    } else if (args[i] === '--fail-on' && args[i + 1]) {
      options.failOn = args[++i];
    } else if (args[i] === '--watch-interval' && args[i + 1]) {
      options.watchInterval = args[++i];
    } else if (args[i] === '--fail-on-grade' && args[i + 1]) {
      options.failOnGrade = args[++i];
    } else if (args[i] === '--policy' && args[i + 1]) {
      options.policyPath = args[++i];
    }
  }
  return options;
}

main().catch(err => {
  logger.error('Unexpected error', err);
  process.exit(1);
});
