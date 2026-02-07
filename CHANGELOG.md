# Changelog

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
