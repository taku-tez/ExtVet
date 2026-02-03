/**
 * Logger - Verbose logging support for ExtVet
 */

let verboseEnabled = false;
let quietMode = false;

/**
 * Configure logger
 * @param {object} options - Logger options
 */
function configure(options = {}) {
  verboseEnabled = options.verbose || false;
  quietMode = options.quiet || false;
}

/**
 * Log info message (always shown unless quiet)
 */
function info(message) {
  if (!quietMode) {
    console.log(message);
  }
}

/**
 * Log verbose/debug message (only with --verbose)
 */
function debug(message, data = null) {
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
function warn(message) {
  if (!quietMode) {
    console.warn(`⚠️  ${message}`);
  }
}

/**
 * Log error message (always shown)
 */
function error(message, err = null) {
  console.error(`❌ ${message}`);
  if (verboseEnabled && err) {
    console.error(err.stack || err);
  }
}

/**
 * Log success message
 */
function success(message) {
  if (!quietMode) {
    console.log(`✅ ${message}`);
  }
}

/**
 * Check if verbose mode is enabled
 */
function isVerbose() {
  return verboseEnabled;
}

module.exports = {
  configure,
  info,
  debug,
  warn,
  error,
  success,
  isVerbose,
};
