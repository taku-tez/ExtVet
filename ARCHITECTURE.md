# ExtVet Architecture

This document describes the architecture and design decisions of ExtVet.

## Overview

ExtVet is a browser extension security scanner that analyzes installed extensions for potential security risks. It supports Chrome, Firefox, Brave, and Edge browsers.

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI (bin/extvet.js)                 │
├─────────────────────────────────────────────────────────────┤
│                     Core (src/index.ts)                     │
├──────────────┬──────────────┬──────────────┬───────────────┤
│   Scanners   │   Analyzers  │   Reporters  │    Config     │
│  (browser-   │   (shared    │   (output    │   (settings   │
│   specific)  │   analysis)  │   formats)   │   loading)    │
├──────────────┴──────────────┴──────────────┴───────────────┤
│                    Utilities & Types                        │
│         (logger, constants, types, extractors)              │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
src/
├── index.ts           # Main entry point, exports scan() and scanUrl()
├── types.ts           # TypeScript type definitions
├── constants.ts       # Shared security patterns and permissions
├── analyzers.ts       # Reusable analysis functions
├── config.ts          # Configuration file loading (.extvetrc)
├── logger.ts          # Logging with verbose mode support
├── reporter.ts        # Output formatting (table, JSON, SARIF)
├── webstore.ts        # Chrome Web Store / Firefox Add-ons API
├── malicious-db.ts    # Known malicious extension database
├── file-scanner.ts    # Local file scanning (.crx, .xpi, .zip)
├── crx-extractor.ts   # Chrome CRX file extraction
├── xpi-extractor.ts   # Firefox XPI file extraction
└── scanners/
    ├── chrome.ts      # Chrome/Brave/Edge scanner
    └── firefox.ts     # Firefox scanner
```

## Core Components

### 1. Entry Point (`index.ts`)

The main module exports two functions:

```typescript
// Scan installed browser extensions
export async function scan(browser: string, options: ScanOptions): Promise<ScanSummary>

// Check a specific extension from web store
export async function scanUrl(target: string, options: ScanOptions): Promise<ScanSummary>
```

### 2. Type Definitions (`types.ts`)

Central type definitions used throughout the codebase:

```typescript
interface Finding {
  id: string;                    // Unique rule identifier
  severity: 'critical' | 'warning' | 'info';
  extension: string;             // Extension name and ID
  message: string;               // Human-readable description
  recommendation?: string;       // How to fix/mitigate
}

interface ScanOptions {
  quiet?: boolean;               // Suppress output
  verbose?: boolean;             // Enable debug logging
  format?: 'table' | 'json' | 'sarif';
  browserType?: 'chrome' | 'brave' | 'edge';
  ignoreExtensions?: string[];   // Extension IDs to skip
  severityOverrides?: Record<string, Severity>;
  // ... more options
}

interface Manifest {
  name?: string;
  version?: string;
  manifest_version?: number;
  permissions?: string[];
  content_scripts?: ContentScript[];
  background?: Background;
  // ... manifest.json fields
}
```

### 3. Constants (`constants.ts`)

Security-related constants shared across scanners:

```typescript
// Dangerous permissions with severity ratings
export const DANGEROUS_PERMISSIONS: Record<string, PermissionDanger> = {
  '<all_urls>': { severity: 'critical', msg: 'Access to ALL websites' },
  'webRequestBlocking': { severity: 'critical', msg: 'Can modify/block requests' },
  // ...
};

// Suspicious code patterns for static analysis
export const SUSPICIOUS_PATTERNS: SuspiciousPattern[] = [
  { pattern: /eval\s*\(/g, severity: 'critical', msg: 'Uses eval()' },
  { pattern: /document\.write/g, severity: 'warning', msg: 'Uses document.write' },
  // ...
];

// URLs considered legitimate (not flagged as suspicious)
export const LEGITIMATE_URLS = [
  'chrome.google.com',
  'googleapis.com',
  // ...
];
```

### 4. Analyzers (`analyzers.ts`)

Reusable analysis functions used by all scanners:

```typescript
// Analyze extension permissions
export function analyzePermissions(
  manifest: Manifest,
  extInfo: ExtensionInfo,
  prefix: string,
  additionalPermissions?: Record<string, PermissionDanger>
): Finding[]

// Analyze content scripts
export function analyzeContentScripts(
  manifest: Manifest,
  extInfo: ExtensionInfo,
  prefix: string
): Finding[]

// Analyze code for suspicious patterns
export function analyzeScriptContent(
  content: string,
  scriptName: string,
  extInfo: ExtensionInfo,
  manifest: Manifest,
  prefix: string,
  additionalPatterns?: SuspiciousPattern[]
): Finding[]

// Analyze background scripts
export function analyzeBackgroundScripts(
  manifest: Manifest,
  extInfo: ExtensionInfo,
  extPath: string,
  prefix: string,
  additionalPatterns?: SuspiciousPattern[]
): Finding[]
```

### 5. Scanners (`scanners/`)

Browser-specific scanners that:
1. Find extension directories
2. Parse manifest.json
3. Call shared analyzers
4. Check against malicious extension database

```typescript
// Chrome scanner (also handles Brave, Edge)
export async function scanChrome(options: ScanOptions): Promise<Finding[]>

// Firefox scanner
export async function scanFirefox(options: ScanOptions): Promise<Finding[]>
```

### 6. Reporter (`reporter.ts`)

Output formatting supporting multiple formats:

```typescript
class Reporter {
  report(findings: Finding[], options: ScanOptions): ScanSummary
  
  // Formats:
  // - table: Human-readable console output
  // - json: Machine-readable JSON
  // - sarif: SARIF format for CI/CD integration
}
```

### 7. Configuration (`config.ts`)

Loads configuration from multiple sources:

```typescript
// Search order:
// 1. .extvetrc (JSON)
// 2. .extvetrc.json
// 3. extvet.config.js
// 4. package.json "extvet" field

export function loadConfig(startDir?: string): ExtvetConfig
export function mergeConfig(base: ExtvetConfig, override: Partial<ExtvetConfig>): ExtvetConfig
```

## Data Flow

```
1. CLI parses arguments
   │
2. Load config file (.extvetrc)
   │
3. Configure logger (verbose mode)
   │
4. Call scan(browser, options)
   │
   ├─► scanChrome() or scanFirefox()
   │   │
   │   ├─► Find extension directories
   │   ├─► Parse manifest.json
   │   ├─► Load malicious DB
   │   │
   │   └─► For each extension:
   │       ├─► checkKnownMalicious()
   │       ├─► analyzePermissions()
   │       ├─► analyzeContentScripts()
   │       ├─► analyzeBackgroundScripts()
   │       └─► (Firefox) analyzeFirefoxSpecific()
   │
5. Apply config filters
   ├─► filterIgnoredExtensions()
   └─► applySeverityOverrides()
   │
6. Reporter formats output
   │
7. Return ScanSummary
```

## Security Analysis

### Permission Analysis

Extensions request permissions in `manifest.json`. ExtVet categorizes them:

| Severity | Examples |
|----------|----------|
| Critical | `<all_urls>`, `debugger`, `nativeMessaging`, `webRequestBlocking` |
| Warning | `cookies`, `history`, `webRequest`, `clipboardRead` |
| Info | `tabs`, `storage`, `notifications` |

### Code Pattern Analysis

Static analysis detects suspicious patterns:

| Category | Patterns |
|----------|----------|
| Code Injection | `eval()`, `new Function()` |
| XSS Risks | `document.write`, `innerHTML=` |
| Network | Insecure HTTP, WebSocket connections |
| CSP Stripping | Header manipulation patterns |
| Data Exfiltration | Cookie/localStorage + fetch patterns |

### Malicious Extension Database

ExtVet maintains a database of known malicious extension IDs:
- Fetched from public sources (palant, mallorybowes lists)
- Cached locally for 24 hours
- Includes built-in fallback list

## Extension Support

### Chrome/Chromium

- Extension path: `~/.config/google-chrome/Default/Extensions/`
- Format: Unpacked directories
- Manifest: V2 and V3

### Firefox

- Extension path: `~/.mozilla/firefox/*.default/extensions/`
- Format: XPI files (ZIP) or unpacked
- Additional: `extensions.json` for metadata

### Brave

- Same as Chrome, different path
- Path: `~/.config/BraveSoftware/Brave-Browser/`

### Edge

- Same as Chrome, different path
- Path: `~/.config/microsoft-edge/`

### Safari (macOS only)

- Legacy extensions: `~/Library/Safari/Extensions/*.safariextz`
- Modern Web Extensions: Inside `.app/Contents/PlugIns/*.appex/Contents/Resources/`
- App Store extensions: Inside containers
- Format: xar archive (legacy) or appex bundle (modern)

## Output Formats

### Table (Default)

```
🔴 CRITICAL: Permission: <all_urls> - Access to ALL websites
   Extension: Suspicious Extension (abc123...)
   Rule: ext-perm-all-urls
   Fix: Review if "<all_urls>" permission is necessary
```

### JSON

```json
{
  "findings": [...],
  "summary": {
    "critical": 1,
    "warning": 3,
    "info": 5,
    "total": 9
  }
}
```

### SARIF

Standard format for static analysis tools, compatible with:
- GitHub Code Scanning
- Azure DevOps
- Other CI/CD platforms

## Design Principles

1. **DRY (Don't Repeat Yourself)**
   - Shared analyzers used by all scanners
   - Common constants in one place

2. **Single Responsibility**
   - Each module has one clear purpose
   - Scanners find extensions, analyzers analyze them

3. **Type Safety**
   - Strict TypeScript configuration
   - Comprehensive type definitions

4. **Extensibility**
   - Easy to add new scanners
   - Easy to add new detection patterns
   - Configuration-based customization

5. **Graceful Degradation**
   - Handle missing files/directories
   - Fallback to built-in data when network unavailable

## Future Considerations

- **Dynamic Analysis**: Run extensions in sandbox
- **Web UI**: Browser-based dashboard
- **AI Analysis**: LLM-based code review
- **Real-time Monitoring**: Watch for new installations
- **Enterprise Features**: Central management, policy enforcement
