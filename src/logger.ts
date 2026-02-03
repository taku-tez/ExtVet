/**
 * Logger - Verbose logging support for ExtVet
 */

interface LoggerOptions {
  verbose?: boolean;
  quiet?: boolean;
}

let verboseEnabled = false;
let quietMode = false;

/**
 * Configure logger
 */
export function configure(options: LoggerOptions = {}): void {
  verboseEnabled = options.verbose || false;
  quietMode = options.quiet || false;
}

/**
 * Log info message (always shown unless quiet)
 */
export function info(message: string): void {
  if (!quietMode) {
    console.log(message);
  }
}

/**
 * Log verbose/debug message (only with --verbose)
 */
export function debug(message: string, data: unknown = null): void {
  if (verboseEnabled) {
    const timestamp = new Date().toISOString().slice(11, 23);
    console.log(`[${timestamp}] DEBUG: ${message}`);
    if (data !== null) {
      console.log(JSON.stringify(data, null, 2));
    }
  }
}

/**
 * Log warning message
 */
export function warn(message: string): void {
  if (!quietMode) {
    console.warn(`⚠️  ${message}`);
  }
}

/**
 * Log error message (always shown)
 */
export function error(message: string, err: Error | null = null): void {
  console.error(`❌ ${message}`);
  if (verboseEnabled && err) {
    console.error(err.stack || err);
  }
}

/**
 * Log success message
 */
export function success(message: string): void {
  if (!quietMode) {
    console.log(`✅ ${message}`);
  }
}

/**
 * Check if verbose mode is enabled
 */
export function isVerbose(): boolean {
  return verboseEnabled;
}

export default {
  configure,
  info,
  debug,
  warn,
  error,
  success,
  isVerbose,
};
