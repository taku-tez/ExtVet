/**
 * Malicious Extension Database
 * Fetches and caches known malicious extension IDs from public sources
 */

import * as https from 'https';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

interface Source {
  name: string;
  url: string;
  parser: (text: string) => Set<string>;
}

interface CacheData {
  timestamp: number;
  ids: string[];
  count: number;
}

interface DbOptions {
  quiet?: boolean;
  offline?: boolean;
}

// Sources for malicious extension IDs
export const SOURCES: Source[] = [
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
  
  // GitLab Feb 2025 - 3.2M users affected
  'mdaboflcmhejfihjcbmdiebgfchigjcf', // Blipshot
  'gaoflciahikhligngeccdecgfjngejlh', // Emojis - Emoji Keyboard
  'fedimamkpgiemhacbdhkkaihgofncola', // WAToolkit
  'jlhgcomgldfapimdboelilfcipigkgik', // Color Changer for YouTube
  'jdjldbengpgdcfkljfdmakdgmfpneldd', // Video Effects for YouTube
  'deljjimclpnhngmikaiiodgggdniaooh', // Themes for Chrome and YouTube
  'giaoehhefkmchjbbdnahgeppblbdejmj', // Mike Adblock für Chrome
  'hmooaemjmediafeacjplpbpenjnpcneg', // Page Refresh
  'acbiaofoeebeinacmcknopaikmecdehl', // Wistia Video Downloader
  'nlgphodeccebbcnkgmokeegopgpnjfkc', // Super dark mode
  'fbcgkphadgmbalmlklhbdagcicajenei', // Emoji keyboard emojis for chrome
  'alplpnakfeabeiebipdmaenpmbgknjce', // Adblocker for Chrome - NoAds
  'ogcaehilgakehloljjmajoempaflmdci', // Adblock for You
  'onomjaelhagjjojbkcafidnepbfkpnee', // Adblock for Chrome
  'bpconcjcammlapcogcnnelfmaeghhagj', // Nimble capture
  'gdocgbfmddcfnlnpmnghmjicjognhonm', // KProxy
  
  // Cyberhaven Dec 2024 supply chain attack
  'pajkjnmeojmbapicmbpliphjmcekeaac', // Cyberhaven (compromised)
]);

/**
 * Parse line-based list (one ID per line, # for comments)
 */
function parseLineList(text: string): Set<string> {
  const ids = new Set<string>();
  const lines = text.split('\n');
  
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    if (/^[a-z]{32}$/.test(trimmed)) {
      ids.add(trimmed);
    }
  }
  
  return ids;
}

/**
 * Fetch URL contents
 */
function fetchUrl(url: string): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: { 'User-Agent': 'ExtVet/0.5.0' },
    }, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchUrl(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        return resolve(null);
      }
      let data = '';
      res.on('data', (chunk: Buffer) => data += chunk.toString());
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
function loadCache(): Set<string> | null {
  try {
    if (!fs.existsSync(CACHE_FILE)) return null;
    
    const data = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf-8')) as CacheData;
    const age = Date.now() - (data.timestamp || 0);
    
    if (age > CACHE_MAX_AGE_MS) {
      return null;
    }
    
    return new Set(data.ids || []);
  } catch {
    return null;
  }
}

/**
 * Save IDs to cache
 */
function saveCache(ids: Set<string>): void {
  try {
    if (!fs.existsSync(CACHE_DIR)) {
      fs.mkdirSync(CACHE_DIR, { recursive: true });
    }
    
    const data: CacheData = {
      timestamp: Date.now(),
      ids: Array.from(ids),
      count: ids.size,
    };
    
    fs.writeFileSync(CACHE_FILE, JSON.stringify(data));
  } catch {
    // Ignore cache write errors
  }
}

/**
 * Update malicious IDs from remote sources
 */
export async function updateMaliciousIds(options: DbOptions = {}): Promise<Set<string>> {
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
        console.log(`    Error: ${(err as Error).message}`);
      }
    }
  }
  
  saveCache(allIds);
  
  return allIds;
}

/**
 * Get malicious IDs (from cache or fetch)
 */
export async function getMaliciousIds(options: DbOptions = {}): Promise<Set<string>> {
  const cached = loadCache();
  if (cached) {
    return cached;
  }
  
  if (!options.offline) {
    try {
      return await updateMaliciousIds(options);
    } catch {
      // Fall through to builtin
    }
  }
  
  return BUILTIN_IDS;
}

/**
 * Check if an extension ID is known malicious
 */
export async function isMalicious(extensionId: string, options: DbOptions = {}): Promise<boolean> {
  const ids = await getMaliciousIds(options);
  return ids.has(extensionId);
}
