/**
 * Malicious Extension Database
 * Fetches and caches known malicious extension IDs from public sources
 */

const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Sources for malicious extension IDs
const SOURCES = [
  {
    name: 'palant',
    url: 'https://raw.githubusercontent.com/palant/malicious-extensions-list/main/list.txt',
    parser: parseLineList,
  },
  {
    name: 'mallorybowes',
    url: 'https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/src/current/crxids.txt',
    parser: parseLineList,
  },
];

// Local cache location
const CACHE_DIR = path.join(os.homedir(), '.extvet');
const CACHE_FILE = path.join(CACHE_DIR, 'malicious-ids.json');
const CACHE_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

// Built-in sample (fallback if network unavailable)
const BUILTIN_IDS = new Set([
  // From palant's list (sample)
  'lgjdgmdbfhobkdbcjnpnlmhnplnidkkp',
  'chmfnmjfghjpdamlofhlonnnnokkpbao',
  'lklmhefoneonjalpjcnhaidnodopinib',
  'ciifcakemmcbbdpmljdohdmbodagmela',
  'meljmedplehjlnnaempfdoecookjenph',
]);

/**
 * Parse line-based list (one ID per line, # for comments)
 */
function parseLineList(text) {
  const ids = new Set();
  const lines = text.split('\n');
  
  for (const line of lines) {
    const trimmed = line.trim();
    // Skip comments and empty lines
    if (!trimmed || trimmed.startsWith('#')) continue;
    // Chrome extension IDs are 32 lowercase letters
    if (/^[a-z]{32}$/.test(trimmed)) {
      ids.add(trimmed);
    }
  }
  
  return ids;
}

/**
 * Fetch URL contents
 */
function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: { 'User-Agent': 'ExtVet/0.3.0' },
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchUrl(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        return resolve(null);
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.setTimeout(15000, () => {
      req.destroy();
      reject(new Error('Timeout'));
    });
  });
}

/**
 * Load cached IDs
 */
function loadCache() {
  try {
    if (!fs.existsSync(CACHE_FILE)) return null;
    
    const data = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf-8'));
    const age = Date.now() - (data.timestamp || 0);
    
    if (age > CACHE_MAX_AGE_MS) {
      return null; // Cache expired
    }
    
    return new Set(data.ids || []);
  } catch (err) {
    return null;
  }
}

/**
 * Save IDs to cache
 */
function saveCache(ids) {
  try {
    if (!fs.existsSync(CACHE_DIR)) {
      fs.mkdirSync(CACHE_DIR, { recursive: true });
    }
    
    fs.writeFileSync(CACHE_FILE, JSON.stringify({
      timestamp: Date.now(),
      ids: Array.from(ids),
      count: ids.size,
    }));
  } catch (err) {
    // Ignore cache write errors
  }
}

/**
 * Update malicious IDs from remote sources
 */
async function updateMaliciousIds(options = {}) {
  const allIds = new Set(BUILTIN_IDS);
  
  for (const source of SOURCES) {
    try {
      if (!options.quiet) {
        console.log(`  Fetching ${source.name}...`);
      }
      
      const text = await fetchUrl(source.url);
      if (text) {
        const ids = source.parser(text);
        for (const id of ids) {
          allIds.add(id);
        }
        if (!options.quiet) {
          console.log(`    Found ${ids.size} IDs`);
        }
      }
    } catch (err) {
      if (!options.quiet) {
        console.log(`    Error: ${err.message}`);
      }
    }
  }
  
  saveCache(allIds);
  
  return allIds;
}

/**
 * Get malicious IDs (from cache or fetch)
 */
async function getMaliciousIds(options = {}) {
  // Try cache first
  const cached = loadCache();
  if (cached) {
    return cached;
  }
  
  // Fetch fresh data
  if (!options.offline) {
    try {
      return await updateMaliciousIds(options);
    } catch (err) {
      // Fall through to builtin
    }
  }
  
  // Return builtin fallback
  return BUILTIN_IDS;
}

/**
 * Check if an extension ID is known malicious
 */
async function isMalicious(extensionId, options = {}) {
  const ids = await getMaliciousIds(options);
  return ids.has(extensionId);
}

module.exports = {
  getMaliciousIds,
  updateMaliciousIds,
  isMalicious,
  SOURCES,
};
