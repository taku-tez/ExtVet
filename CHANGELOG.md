# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-02-05

### Added
- ESLint with TypeScript support and flat config
- Comprehensive test suite (58 tests)
  - Analyzer tests (permissions, content scripts, code patterns)
  - Reporter tests (JSON, SARIF, risk scoring)
- LICENSE file (MIT)
- CHANGELOG.md

### Changed
- Converted entire project to ES modules (`"type": "module"`)
- Centralized VERSION constant in `constants.ts`
- Test files converted from CommonJS to ES modules

### Fixed
- Regenerated `package-lock.json` to fix version inconsistencies
- Fixed useless escape character in regex
- Removed duplicate `dist/` entry in `.gitignore`

## [0.6.1] - 2026-02-03

### Added
- CONTRIBUTING.md with development guidelines
- ARCHITECTURE.md with codebase overview

### Changed
- Extracted shared constants to `constants.ts`
- Extracted shared analyzers to `analyzers.ts`

## [0.6.0] - 2026-02-03

### Added
- Full TypeScript conversion (strict mode)
- Verbose mode (`--verbose` flag)
- Config file support (`.extvetrc`, `.extvetrc.json`, etc.)
- Improved error handling with debug logging
- CSP stripping attack detection patterns

### Changed
- Better JSON output format with risk scoring
- Improved malicious extension database (164+ IDs)

## [0.5.0] - 2026-02-02

### Added
- Safari extension scanner (macOS only)
- Shared malicious DB loading across scanners

## [0.4.0] - 2026-02-01

### Added
- `file` command for local extension scanning
- XPI extraction support for Firefox add-ons
- CRX extraction support (CRX2/CRX3 formats)

## [0.3.0] - 2026-01-31

### Added
- GitHub Actions CI/CD workflows
- Firefox Add-ons scanner
- Web Store verification (Chrome Web Store, Firefox Add-ons)
- Malicious extension database with remote updates
- `update` command for database refresh

## [0.2.0] - 2026-01-30

### Added
- Chrome extension scanner
- Brave browser support
- Edge browser support
- Permission analysis
- Content script analysis
- Suspicious code pattern detection

## [0.1.0] - 2026-01-29

### Added
- Initial release
- Basic CLI structure
- Table, JSON, and SARIF output formats
