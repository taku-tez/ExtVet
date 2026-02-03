/**
 * Web Store Checker
 * Fetch extension info from Chrome Web Store / Firefox Add-ons
 */

import * as https from 'https';
import type { Finding, WebStoreInfo, WebStoreResult } from './types.js';

interface FetchOptions {
  json?: boolean;
}

interface CheckOptions {
  store?: 'auto' | 'chrome' | 'firefox';
}

interface FirefoxApiResponse {
  guid: string;
  slug: string;
  name: Record<string, string> | string;
  summary: Record<string, string> | string;
  current_version?: {
    version: string;
    file?: {
      permissions?: string[];
    };
  };
  ratings?: {
    average: number;
  };
  average_daily_users: number;
  last_updated: string;
  categories: string[];
  is_experimental: boolean;
  is_recommended: boolean;
  requires_payment: boolean;
}

interface ExtendedWebStoreInfo extends WebStoreInfo {
  id?: string;
  slug?: string;
  source?: string;
  url?: string;
  lastUpdated?: string;
  categories?: string[];
  permissions?: string[];
  isExperimental?: boolean;
  isRecommended?: boolean;
  requiresPayment?: boolean;
}

/**
 * Fetch Chrome Web Store extension info
 */
async function fetchChromeWebStore(extensionId: string): Promise<ExtendedWebStoreInfo | null> {
  const url = `https://chrome.google.com/webstore/detail/${extensionId}`;
  
  try {
    const html = await fetchUrl(url);
    if (!html) return null;
    
    const info: ExtendedWebStoreInfo = {
      id: extensionId,
      source: 'chrome-web-store',
      url,
    };
    
    const titleMatch = html.match(/<meta property="og:title" content="([^"]+)"/);
    if (titleMatch) info.name = titleMatch[1];
    
    const descMatch = html.match(/<meta property="og:description" content="([^"]+)"/);
    if (descMatch) info.description = descMatch[1];
    
    const ratingMatch = html.match(/Average rating[:\s]*([\d.]+)/);
    if (ratingMatch) info.rating = parseFloat(ratingMatch[1]);
    
    const usersMatch = html.match(/(\d[\d,]+)\s+users/i);
    if (usersMatch) info.users = parseInt(usersMatch[1].replace(/,/g, ''), 10);
    
    if (!info.name && (html.includes('404') || html.includes('not found'))) {
      return null;
    }
    
    return info;
  } catch (err) {
    console.error(`Error fetching Chrome Web Store: ${(err as Error).message}`);
    return null;
  }
}

/**
 * Fetch Firefox Add-ons (AMO) extension info
 */
async function fetchFirefoxAddons(addonId: string): Promise<ExtendedWebStoreInfo | null> {
  const url = `https://addons.mozilla.org/api/v5/addons/addon/${addonId}/`;
  
  try {
    const json = await fetchUrl(url, { json: true }) as FirefoxApiResponse | null;
    if (!json) return null;
    
    const getName = (obj: Record<string, string> | string | undefined): string => {
      if (typeof obj === 'string') return obj;
      return obj?.['en-US'] || obj?.en || Object.values(obj || {})[0] || '';
    };
    
    return {
      id: json.guid,
      slug: json.slug,
      name: getName(json.name),
      description: getName(json.summary),
      version: json.current_version?.version,
      rating: json.ratings?.average,
      users: json.average_daily_users,
      lastUpdated: json.last_updated,
      categories: json.categories,
      source: 'firefox-addons',
      url: `https://addons.mozilla.org/en-US/firefox/addon/${json.slug}/`,
      permissions: json.current_version?.file?.permissions || [],
      isExperimental: json.is_experimental,
      isRecommended: json.is_recommended,
      requiresPayment: json.requires_payment,
    };
  } catch (err) {
    console.error(`Error fetching Firefox Add-ons: ${(err as Error).message}`);
    return null;
  }
}

/**
 * Analyze web store info for security concerns
 */
function analyzeWebStoreInfo(info: ExtendedWebStoreInfo | null): Finding[] {
  const findings: Finding[] = [];
  
  if (!info) {
    findings.push({
      id: 'webstore-not-found',
      severity: 'warning',
      extension: 'Unknown',
      message: 'Extension not found in web store',
      recommendation: 'Extension may be unlisted, removed, or self-hosted',
    });
    return findings;
  }
  
  const extName = info.name || 'Unknown';
  
  if (info.users && info.users < 1000) {
    findings.push({
      id: 'webstore-low-users',
      severity: 'info',
      extension: extName,
      message: `Low user count: ${info.users.toLocaleString()} users`,
      recommendation: 'Less popular extensions may receive less security scrutiny',
    });
  }
  
  if (info.rating && info.rating < 3.0) {
    findings.push({
      id: 'webstore-low-rating',
      severity: 'warning',
      extension: extName,
      message: `Low rating: ${info.rating.toFixed(1)}/5`,
      recommendation: 'Check reviews for security or privacy concerns',
    });
  }
  
  if (info.source === 'firefox-addons') {
    if (info.isExperimental) {
      findings.push({
        id: 'webstore-experimental',
        severity: 'info',
        extension: extName,
        message: 'Add-on is marked as experimental',
        recommendation: 'Experimental add-ons may have stability issues',
      });
    }
    
    if (info.isRecommended) {
      findings.push({
        id: 'webstore-recommended',
        severity: 'info',
        extension: extName,
        message: '✓ Add-on is Mozilla Recommended',
        recommendation: 'Recommended add-ons undergo additional review',
      });
    }
    
    if (info.permissions && info.permissions.length > 0) {
      const dangerous = info.permissions.filter(p => 
        ['<all_urls>', '*://*/*', 'nativeMessaging', 'proxy', 'webRequestBlocking'].includes(p)
      );
      
      if (dangerous.length > 0) {
        findings.push({
          id: 'webstore-dangerous-perms',
          severity: 'warning',
          extension: extName,
          message: `Dangerous permissions: ${dangerous.join(', ')}`,
          recommendation: 'Review if these permissions are necessary',
        });
      }
    }
  }
  
  return findings;
}

/**
 * Check extension against web store
 */
export async function checkWebStore(target: string, options: CheckOptions = {}): Promise<WebStoreResult> {
  let extensionId = target;
  let storeType = options.store || 'auto';
  
  if (target.includes('chrome.google.com') || target.includes('chromewebstore')) {
    const match = target.match(/\/([a-z]{32})/);
    if (match) extensionId = match[1];
    storeType = 'chrome';
  } else if (target.includes('addons.mozilla.org')) {
    const match = target.match(/\/addon\/([^\/]+)/);
    if (match) extensionId = match[1];
    storeType = 'firefox';
  }
  
  if (storeType === 'auto') {
    if (/^[a-z]{32}$/.test(extensionId)) {
      storeType = 'chrome';
    } else if (extensionId.includes('@') || extensionId.startsWith('{')) {
      storeType = 'firefox';
    } else {
      storeType = 'firefox';
    }
  }
  
  let info: ExtendedWebStoreInfo | null = null;
  
  if (storeType === 'chrome') {
    info = await fetchChromeWebStore(extensionId);
  } else if (storeType === 'firefox') {
    info = await fetchFirefoxAddons(extensionId);
  }
  
  const findings = analyzeWebStoreInfo(info);
  
  return {
    info,
    findings,
  };
}

/**
 * Simple HTTPS fetch helper
 */
function fetchUrl(url: string, options: FetchOptions = {}): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: {
        'User-Agent': 'ExtVet/0.5.0',
        'Accept': options.json ? 'application/json' : 'text/html',
      },
    }, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchUrl(res.headers.location, options).then(resolve).catch(reject);
      }
      
      if (res.statusCode !== 200) {
        return resolve(null);
      }
      
      let data = '';
      res.on('data', (chunk: Buffer) => data += chunk.toString());
      res.on('end', () => {
        if (options.json) {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve(null);
          }
        } else {
          resolve(data);
        }
      });
    });
    
    req.on('error', reject);
    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
  });
}

export { fetchChromeWebStore, fetchFirefoxAddons, analyzeWebStoreInfo };
