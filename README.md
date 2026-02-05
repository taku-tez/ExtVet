# 🦅 ExtVet

[![CI](https://github.com/taku-tez/ExtVet/actions/workflows/ci.yml/badge.svg)](https://github.com/taku-tez/ExtVet/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/browser-extvet.svg)](https://www.npmjs.com/package/browser-extvet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)

**Browser Extension Security Scanner** - Vet your extensions before they vet your data.

ExtVet analyzes installed browser extensions for security risks, suspicious permissions, and potential malicious behavior.

## Features

- 🔍 **Permission Analysis** - Detect dangerous permissions like `<all_urls>`, `webRequestBlocking`, `nativeMessaging`
- 📜 **Manifest Inspection** - Check for deprecated Manifest V2, overly broad content scripts
- 🕵️ **Code Analysis** - Find suspicious patterns like `eval()`, external connections
- 🚨 **Known Malicious Detection** - Check against 164+ known malicious extension IDs (auto-updated)
- 🌐 **Multi-Browser Support** - Chrome, Firefox, Brave, Edge, Safari
- 🔎 **Web Store Verification** - Check extensions against Chrome Web Store & Firefox Add-ons

## Installation

```bash
# From source (recommended)
git clone https://github.com/taku-tez/ExtVet.git
cd ExtVet && npm install && npm run build && npm link

# From npm (coming soon - package: browser-extvet)
# npm install -g browser-extvet
```

## Usage

### Scan All Installed Extensions

```bash
# Scan Chrome extensions
extvet scan

# Scan specific browser
extvet scan firefox
extvet scan brave
extvet scan edge
extvet scan safari  # macOS only

# Scan specific profile
extvet scan chrome --profile "Profile 1"
```

### Update Malicious Database

```bash
# Update known malicious extension database from remote sources
extvet update
```

### Scan Local Extension Files

```bash
# Scan a downloaded .crx file
extvet file extension.crx

# Scan a Firefox .xpi file
extvet file addon.xpi

# Scan a zipped extension
extvet file extension.zip
```

### Check a Specific Extension

```bash
# By extension ID
extvet check nkbihfbeogaeaoehlefnkodbefgpgknn

# By Chrome Web Store URL
extvet check https://chrome.google.com/webstore/detail/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn
```

### Output Formats

```bash
# JSON output
extvet scan --format json

# SARIF (for CI/CD integration)
extvet scan --format sarif --output results.sarif

# Filter by severity
extvet scan --severity warning

# Verbose output (debug mode)
extvet scan --verbose
```

## Configuration

ExtVet supports configuration files to customize scanning behavior.

### Config File Locations

ExtVet searches for config in this order:
1. `.extvetrc` (JSON)
2. `.extvetrc.json`
3. `extvet.config.js`
4. `package.json` `"extvet"` field

### Config Options

```json
{
  "ignoreExtensions": [
    "nkbihfbeogaeaoehlefnkodbefgpgknn"
  ],
  "severityOverrides": {
    "ext-perm-tabs": "warning",
    "ext-mv2-deprecated": "info"
  },
  "browser": "chrome",
  "format": "table",
  "severity": "info",
  "quiet": false,
  "verbose": false
}
```

### JavaScript Config

```javascript
// extvet.config.js
module.exports = {
  ignoreExtensions: [
    'nkbihfbeogaeaoehlefnkodbefgpgknn', // MetaMask - trusted
  ],
  severityOverrides: {
    'ext-perm-tabs': 'warning',
  },
};
```

### package.json

```json
{
  "name": "my-project",
  "extvet": {
    "ignoreExtensions": ["abc123..."],
    "browser": "chrome"
  }
}
```

## Permission Risk Levels

| Severity | Permissions |
|----------|------------|
| 🔴 Critical | `<all_urls>`, `debugger`, `nativeMessaging`, `proxy`, `webRequestBlocking` |
| 🟡 Warning | `cookies`, `history`, `webRequest`, `management`, `clipboardRead` |
| 🔵 Info | `tabs`, `storage`, `notifications`, `bookmarks` |

## Detected Patterns

### Code Patterns
- `eval()` usage
- `new Function()` constructor
- External URL connections (potential C2)
- Insecure HTTP requests
- Base64 obfuscation indicators

### Manifest Issues
- Manifest V2 deprecation
- Overly broad content script injection
- MAIN world content scripts
- Wide host permissions

## Example Output

```
🦅 ExtVet - Browser Extension Security Scanner

Scanning chrome extensions...
  Found 12 extensions
  Scanning: uBlock Origin
  Scanning: MetaMask
  Scanning: Suspicious Extension

────────────────────────────────────────────────────────────────────────────────
FINDINGS
────────────────────────────────────────────────────────────────────────────────

🔴 CRITICAL: Permission: <all_urls> - Access to ALL websites
   Extension: Suspicious Extension (abc123...)
   Rule: ext-perm-all-urls
   Fix: Review if "<all_urls>" permission is necessary

🟡 WARNING: Uses Manifest V2 (deprecated, will be removed)
   Extension: Old Extension (def456...)
   Rule: ext-mv2-deprecated
   Fix: Update to Manifest V3 or find alternative extension

────────────────────────────────────────────────────────────────────────────────
SUMMARY
────────────────────────────────────────────────────────────────────────────────
🔴 Critical: 1
🟡 Warning:  3
🔵 Info:     5
📊 Total:    9
────────────────────────────────────────────────────────────────────────────────
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan Browser Extensions
  run: |
    npm install -g @extvet/cli
    extvet scan --format sarif --output extvet.sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: extvet.sarif
```

## Related Projects

- [AgentVet](https://github.com/taku-tez/agentvet) - AI Agent Security Scanner
- [PermitVet](https://github.com/taku-tez/PermitVet) - Cloud IAM Permission Auditor

## License

MIT

## Author

tez ([@tez2705](https://twitter.com/tez2705))
