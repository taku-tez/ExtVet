# Changelog

## [2.2.0] - 2026-02-08
### Added
- C2/malicious infrastructure detection (10 domain patterns)
- Detect ngrok, Telegram Bot API, Discord webhook, pastebin, suspicious TLDs, URL shorteners, dynamic DNS, raw IP connections

## [2.1.0] - 2026-02-08
### Added
- `extvet list` command for quick extension inventory with risk grades
- Updated help text with all commands

## [2.0.0] - 2026-02-08
### Added
- **Policy engine** — allowlist/blocklist, maxGrade, maxScore, required extensions, blocked permissions
- `extvet policy-init` for sample policy generation
- `--policy <file>` and `--fail-on-grade` for CI enforcement
- **Baseline & diff** — `extvet baseline` exports state, `extvet diff` detects drift
- Drift score quantification

## [1.9.0] - 2026-02-08
### Added
- `extvet watch` continuous monitoring mode (configurable interval)
- Detects new/removed extensions and risk score changes in real-time

## [1.8.0] - 2026-02-08
### Added
- Per-extension risk scoring (0-100) with grade system (A-F)
- Overall risk score and grade in scan summary
- Risk scores in table output

## [1.7.0] - 2026-02-08
### Added
- 20+ new permission definitions (scripting, desktopCapture, tabCapture, identity, declarativeNetRequest, etc.)
- 6 new dangerous permission combos targeting MV3 supply chain patterns

## [1.6.1] - 2026-02-08
### Added
- 4th malicious DB source: gnyman/chromium-mal-ids
- 12 compromised extension IDs from Dec 2024/Jan 2025 supply chain attacks

## [1.6.0] - 2026-02-08
### Added
- JavaScript obfuscation detection (6 patterns: hex escapes, string rotation, packer, fromCharCode, variable names, packed lines)

## [1.5.0] - 2026-02-07
### Added
- Markdown report output (`--format markdown`)

## [1.4.0] - 2026-02-07
### Added
- Comprehensive README update

## [1.3.0] - 2026-02-07
### Added
- GitHub Actions reusable action (`action.yml`)
- `--fail-on` flag for CI/CD exit code control (critical/warning/info/none)

## [1.2.0] - 2026-02-07
### Added
- HTML report output (`--format html`) with dark theme dashboard
- `--output` file saving for HTML reports

## [1.1.0] - 2026-02-07
### Added
- Malicious DB cross-check during web store verification
- Stale/abandoned extension detection (>1yr warning, >2yr critical)
- Chrome Web Store version and lastUpdated parsing

## [1.0.0] - 2026-02-07
### Added
- Third malicious DB source: toborrm9/malicious_extension_sentry (437 IDs)
- CSV parser for comma-separated ID lists
- `db-stats` CLI command
- Total: 562+ malicious extension IDs from 3 sources

## [0.9.0] - 2026-02-07
### Added
- Dangerous permission combination analysis (10 patterns)
- MitM, session hijacking, dropper, data exfiltration combos
- Cross-check across permissions, optional_permissions, host_permissions

## [0.8.0] - 2026-02-07
### Added
- Content Security Policy (CSP) analysis
- Update URL analysis (external server, insecure HTTP)
- Externally connectable analysis
- Web accessible resources analysis

## [0.7.0] - 2026-02-03
### Added
- Safari extension scanner
- Improved JSON output with risk scores
- ESLint with TypeScript support
- CONTRIBUTING.md and ARCHITECTURE.md
