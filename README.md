# 🦅 ExtVet

[![CI](https://github.com/taku-tez/ExtVet/actions/workflows/ci.yml/badge.svg)](https://github.com/taku-tez/ExtVet/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/browser-extvet.svg)](https://www.npmjs.com/package/browser-extvet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)

**Browser Extension Security Scanner** — Vet your extensions before they vet your data.

ExtVet analyzes installed browser extensions for security risks, dangerous permissions, malicious behavior, and supply chain threats.

## ✨ Features

- 🔍 **Permission Analysis** — Detect dangerous permissions (`<all_urls>`, `webRequestBlocking`, `nativeMessaging`, etc.)
- ⚡ **Permission Combo Detection** — Flag deadly combinations (e.g., `cookies + <all_urls>` = mass session hijacking)
- 🔒 **CSP Analysis** — Detect `unsafe-eval`, `unsafe-inline`, wildcard sources, and missing Content Security Policy
- 🌐 **Externally Connectable** — Warn when any website can message your extension
- 📦 **Web Accessible Resources** — Detect fingerprinting and data leak risks
- 🔄 **Update URL Analysis** — Flag extensions self-updating from external (non-store) servers
- 🚨 **Known Malicious Detection** — Check against **600+ known malicious extension IDs** from 4 threat databases (auto-updated)
- 🕵️ **Code Analysis** — Find `eval()`, CSP stripping, C2 patterns, cookie exfiltration, and 25+ suspicious patterns
- 🔮 **Obfuscation Detection** — Detect packed code, string rotation, Dean Edwards packer, hex escapes
- 🌐 **C2 Infrastructure Detection** — Flag ngrok tunnels, Telegram bots, Discord webhooks, pastebin, suspicious TLDs
- 📜 **Manifest Inspection** — Manifest V2 deprecation, broad content scripts, MAIN world access
- 🌐 **Multi-Browser** — Chrome, Firefox, Brave, Edge, Safari
- 🔎 **Web Store Verification** — Chrome Web Store & Firefox Add-ons metadata + stale extension detection
- 📊 **Risk Scoring** — Per-extension 0-100 score with A-F grades
- 📊 **5 Output Formats** — Table, JSON, SARIF, HTML dashboard, Markdown
- 🏛️ **Policy Engine** — Allowlist/blocklist, grade thresholds, required extensions, blocked permissions
- 📈 **Baseline & Diff** — Export baselines, detect extension drift over time
- 👁️ **Watch Mode** — Continuous monitoring with change detection
- 🚀 **CI/CD Ready** — GitHub Action, `--fail-on`, `--fail-on-grade`, `--policy`, exit codes

## 📦 Installation

```bash
# From npm
npm install -g browser-extvet

# From source
git clone https://github.com/taku-tez/ExtVet.git
cd ExtVet && npm install && npm run build && npm link
```

## 🚀 Usage

### Scan Installed Extensions

```bash
extvet scan                          # Scan Chrome (default)
extvet scan firefox                  # Scan Firefox
extvet scan brave                    # Scan Brave
extvet scan edge                     # Scan Edge
extvet scan safari                   # Scan Safari (macOS)
extvet scan --profile "Profile 1"    # Specific profile
```

### Check a Specific Extension

```bash
# By extension ID
extvet check nkbihfbeogaeaoehlefnkodbefgpgknn

# By Chrome Web Store URL
extvet check https://chrome.google.com/webstore/detail/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn

# By Firefox Add-ons slug
extvet check ublock-origin
```

### Scan Local Extension Files

```bash
extvet file extension.crx
extvet file addon.xpi
extvet file extension.zip
```

### Malicious Extension Database

```bash
extvet update       # Update DB from remote sources
extvet db-stats     # Show database statistics
```

### Output Formats

```bash
extvet scan --format table           # Default: colored terminal output
extvet scan --format json            # JSON with risk scores per extension
extvet scan --format sarif           # SARIF for code scanning tools
extvet scan --format html -o report.html  # Dark theme HTML dashboard
```

### CI/CD Options

```bash
extvet scan --fail-on critical       # Exit 1 on critical findings (default)
extvet scan --fail-on warning        # Exit 1 on warning or critical
extvet scan --fail-on info           # Exit 1 on any finding
extvet scan --fail-on none           # Always exit 0 (report only)
extvet scan --severity warning       # Only show warning+ in output
```

## 🔍 What ExtVet Detects

### Permission Risks

| Severity | Examples |
|----------|---------|
| 🔴 Critical | `<all_urls>`, `debugger`, `nativeMessaging`, `proxy`, `webRequestBlocking` |
| 🟡 Warning | `cookies`, `history`, `webRequest`, `management`, `clipboardRead`, `privacy` |
| 🔵 Info | `tabs`, `storage`, `notifications`, `bookmarks`, `downloads` |

### Dangerous Permission Combos

| Combo | Risk |
|-------|------|
| `webRequest + webRequestBlocking + <all_urls>` | 🔴 Full MitM capability |
| `cookies + <all_urls>` | 🔴 Mass session hijacking |
| `debugger + <all_urls>` | 🔴 Full browser compromise |
| `proxy + webRequest` | 🔴 Transparent traffic interception |
| `nativeMessaging + <all_urls>` | 🔴 Data exfiltration via native bridge |
| `management + downloads` | 🟡 Malware dropper pattern |
| `tabs + history` | 🟡 Complete browsing profile |

### Code Patterns (25+)

- `eval()` / `new Function()` — Code injection
- CSP stripping attacks (GitLab Feb 2025 campaign)
- Cookie exfiltration patterns
- C2 heartbeat/config patterns
- Remote script loading
- `document.write` / `innerHTML` XSS vectors

### Manifest & CSP

- Manifest V2 deprecation warnings
- Missing or weak Content Security Policy
- `unsafe-eval` / `unsafe-inline` in CSP
- Wildcard script sources
- Broad content script injection
- External update URLs (non-store)
- Overly permissive `externally_connectable`
- Fingerprinting via `web_accessible_resources`

### Malicious Extension Database

562+ known malicious extension IDs from 3 sources:

| Source | Description |
|--------|-----------|
| [palant](https://github.com/palant/malicious-extensions-list) | Curated list by security researcher |
| [mallorybowes](https://github.com/mallorybowes/chrome-mal-ids) | Aggregated Chrome malicious IDs |
| [toborrm9](https://github.com/toborrm9/malicious_extension_sentry) | Auto-updated malicious extension sentry |

Auto-updates with 24h cache. Includes Cyberhaven supply chain (Dec 2024), GitLab campaign (Feb 2025), and more.

## ⚙️ Configuration

```json
// .extvetrc or .extvetrc.json
{
  "ignoreExtensions": ["nkbihfbeogaeaoehlefnkodbefgpgknn"],
  "severityOverrides": {
    "ext-perm-tabs": "warning",
    "ext-mv2-deprecated": "info"
  },
  "browser": "chrome",
  "format": "table"
}
```

Also supports `extvet.config.js` and `package.json` `"extvet"` field.

## 🚀 GitHub Actions

### Reusable Action

```yaml
- uses: taku-tez/ExtVet@main
  with:
    command: check
    target: nkbihfbeogaeaoehlefnkodbefgpgknn
    format: sarif
    fail-on: warning
```

### Manual Setup

```yaml
- name: Scan Extensions
  run: |
    npm install -g browser-extvet
    extvet scan --format sarif --output extvet.sarif --fail-on warning

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: extvet.sarif
```

## 🔗 Related Projects

Part of the **xxVet** security CLI suite:

- [AgentVet](https://github.com/taku-tez/agentvet) — AI Agent Security Scanner
- [PermitVet](https://github.com/taku-tez/PermitVet) — Cloud IAM Permission Auditor
- [ModelVet](https://github.com/taku-tez/ModelVet) — AI Security Posture Management
- [SubVet](https://github.com/taku-tez/SubVet) — Subdomain Takeover Scanner
- [RepVet](https://github.com/taku-tez/RepVet) — Package Reputation Scanner
- [ReachVet](https://github.com/taku-tez/ReachVet) — Reachability Analysis

## 📄 License

MIT

## 👤 Author

tez ([@tez2705](https://twitter.com/tez2705))
