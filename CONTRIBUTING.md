# Contributing to ExtVet

Thank you for your interest in contributing to ExtVet! 🦅

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/taku-tez/ExtVet.git
cd ExtVet

# Install dependencies
npm install

# Build TypeScript
npm run build

# Run tests
npm test

# Link for local development
npm link
```

## Development Workflow

### Project Structure

See [ARCHITECTURE.md](./ARCHITECTURE.md) for detailed architecture documentation.

```
ExtVet/
├── src/                    # TypeScript source
│   ├── index.ts           # Main entry point
│   ├── types.ts           # Type definitions
│   ├── constants.ts       # Shared constants
│   ├── analyzers.ts       # Analysis functions
│   ├── config.ts          # Config file loader
│   ├── logger.ts          # Logging utilities
│   ├── reporter.ts        # Output formatting
│   └── scanners/          # Browser-specific scanners
├── bin/                    # CLI entry point
├── dist/                   # Compiled JavaScript (gitignored)
├── test/                   # Test files
└── docs/                   # Documentation
```

### Building

```bash
# One-time build
npm run build

# Watch mode (auto-rebuild on changes)
npm run build:watch

# Clean build artifacts
npm run clean
```

### Testing

```bash
# Run all tests
npm test

# Run specific test file
node --test test/scanner.test.js
```

### Code Style

- TypeScript strict mode enabled
- Use meaningful variable names
- Add JSDoc comments for public functions
- Keep functions small and focused

## How to Contribute

### Reporting Bugs

1. Check if the bug is already reported in [Issues](https://github.com/taku-tez/ExtVet/issues)
2. Create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment (OS, Node.js version, browser)

### Suggesting Features

1. Check existing issues and discussions
2. Create a new issue with:
   - Use case / problem statement
   - Proposed solution
   - Alternatives considered

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Add/update tests
5. Run `npm test` to ensure tests pass
6. Commit with clear message: `git commit -m "feat: add new feature"`
7. Push and create a Pull Request

### Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new feature
fix: fix bug
docs: update documentation
refactor: code refactoring
test: add/update tests
chore: maintenance tasks
```

Examples:
- `feat: add Safari extension scanner`
- `fix: handle missing manifest.json gracefully`
- `docs: add API reference`

## Adding New Features

### Adding a New Scanner

1. Create `src/scanners/newbrowser.ts`
2. Implement the scanner using shared analyzers:

```typescript
import { analyzePermissions, analyzeContentScripts } from '../analyzers.js';
import type { Finding, ScanOptions } from '../types.js';

export async function scanNewBrowser(options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];
  // ... implementation
  return findings;
}
```

3. Register in `src/index.ts`
4. Add CLI support in `bin/extvet.js`
5. Add tests in `test/`

### Adding New Detection Patterns

1. Add patterns to `src/constants.ts`:

```typescript
export const SUSPICIOUS_PATTERNS: SuspiciousPattern[] = [
  // ... existing patterns
  { 
    pattern: /your-pattern/g, 
    severity: 'warning', 
    msg: 'Description of the issue' 
  },
];
```

2. Add tests for the new pattern

### Adding New Permissions

1. Add to `DANGEROUS_PERMISSIONS` in `src/constants.ts`:

```typescript
export const DANGEROUS_PERMISSIONS: Record<string, PermissionDanger> = {
  // ... existing
  'newPermission': { 
    severity: 'warning', 
    msg: 'What this permission allows' 
  },
};
```

## Testing Guidelines

### Test Structure

```javascript
const { test, describe } = require('node:test');
const assert = require('node:assert');

describe('Feature', () => {
  test('should do something', () => {
    // Arrange
    const input = ...;
    
    // Act
    const result = functionUnderTest(input);
    
    // Assert
    assert.strictEqual(result, expected);
  });
});
```

### What to Test

- Core scanning functions
- Permission analysis
- Pattern detection
- Config loading
- Edge cases (missing files, malformed data)

## Release Process

1. Update version in `package.json`
2. Update CHANGELOG.md
3. Create a git tag: `git tag v0.x.x`
4. Push: `git push origin main --tags`
5. GitHub Actions will create a release

## Getting Help

- 📖 [Documentation](./README.md)
- 🐛 [Issues](https://github.com/taku-tez/ExtVet/issues)
- 💬 [Discussions](https://github.com/taku-tez/ExtVet/discussions)

## Code of Conduct

Be respectful and inclusive. We welcome contributors of all backgrounds and experience levels.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
