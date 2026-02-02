/**
 * Web Store Checker
 * Fetch extension info from Chrome Web Store / Firefox Add-ons
 */

const https = require('https');

/**
 * Fetch Chrome Web Store extension info
 * @param {string} extensionId - Chrome extension ID (32-char)
 * @returns {object|null} Extension info or null if not found
 */
async function fetchChromeWebStore(extensionId) {
  // Chrome Web Store doesn't have a public API, but we can scrape the page
  const url = `https://chrome.google.com/webstore/detail/${extensionId}`;
  
  try {
    const html = await fetchUrl(url);
    if (!html) return null;
    
    // Extract basic info from page
    const info = {
      id: extensionId,
      source: 'chrome-web-store',
      url,
    };
    
    // Extract title
    const titleMatch = html.match(/<meta property="og:title" content="([^"]+)"/);
    if (titleMatch) info.name = titleMatch[1];
    
    // Extract description
    const descMatch = html.match(/<meta property="og:description" content="([^"]+)"/);
    if (descMatch) info.description = descMatch[1];
    
    // Extract rating
    const ratingMatch = html.match(/Average rating[:\s]*([\d.]+)/);
    if (ratingMatch) info.rating = parseFloat(ratingMatch[1]);
    
    // Extract user count
    const usersMatch = html.match(/(\d[\d,]+)\s+users/i);
    if (usersMatch) info.users = parseInt(usersMatch[1].replace(/,/g, ''), 10);
    
    // Check if extension exists
    if (!info.name && html.includes('404') || html.includes('not found')) {
      return null;
    }
    
    return info;
  } catch (err) {
    console.error(`Error fetching Chrome Web Store: ${err.message}`);
    return null;
  }
}

/**
 * Fetch Firefox Add-ons (AMO) extension info
 * Uses the public API
 * @param {string} addonId - Firefox add-on slug or GUID
 * @returns {object|null} Add-on info or null if not found
 */
async function fetchFirefoxAddons(addonId) {
  const url = `https://addons.mozilla.org/api/v5/addons/addon/${addonId}/`;
  
  try {
    const json = await fetchUrl(url, { json: true });
    if (!json) return null;
    
    // Handle localized strings
    const getName = (obj) => {
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
      // Security info
      permissions: json.current_version?.file?.permissions || [],
      isExperimental: json.is_experimental,
      isRecommended: json.is_recommended,
      requiresPayment: json.requires_payment,
    };
  } catch (err) {
    console.error(`Error fetching Firefox Add-ons: ${err.message}`);
    return null;
  }
}

/**
 * Analyze web store info for security concerns
 * @param {object} info - Extension info from web store
 * @returns {array} Findings
 */
function analyzeWebStoreInfo(info) {
  const findings = [];
  
  if (!info) {
    findings.push({
      id: 'webstore-not-found',
      severity: 'warning',
      message: 'Extension not found in web store',
      recommendation: 'Extension may be unlisted, removed, or self-hosted',
    });
    return findings;
  }
  
  // Low user count
  if (info.users && info.users < 1000) {
    findings.push({
      id: 'webstore-low-users',
      severity: 'info',
      extension: info.name,
      message: `Low user count: ${info.users.toLocaleString()} users`,
      recommendation: 'Less popular extensions may receive less security scrutiny',
    });
  }
  
  // Low rating
  if (info.rating && info.rating < 3.0) {
    findings.push({
      id: 'webstore-low-rating',
      severity: 'warning',
      extension: info.name,
      message: `Low rating: ${info.rating.toFixed(1)}/5`,
      recommendation: 'Check reviews for security or privacy concerns',
    });
  }
  
  // Firefox-specific checks
  if (info.source === 'firefox-addons') {
    if (info.isExperimental) {
      findings.push({
        id: 'webstore-experimental',
        severity: 'info',
        extension: info.name,
        message: 'Add-on is marked as experimental',
        recommendation: 'Experimental add-ons may have stability issues',
      });
    }
    
    if (info.isRecommended) {
      findings.push({
        id: 'webstore-recommended',
        severity: 'info',
        extension: info.name,
        message: '✓ Add-on is Mozilla Recommended',
        recommendation: 'Recommended add-ons undergo additional review',
      });
    }
    
    // Check permissions from API
    if (info.permissions && info.permissions.length > 0) {
      const dangerous = info.permissions.filter(p => 
        ['<all_urls>', '*://*/*', 'nativeMessaging', 'proxy', 'webRequestBlocking'].includes(p)
      );
      
      if (dangerous.length > 0) {
        findings.push({
          id: 'webstore-dangerous-perms',
          severity: 'warning',
          extension: info.name,
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
 * @param {string} target - Extension ID or URL
 * @param {object} options - Options
 * @returns {object} Result with info and findings
 */
async function checkWebStore(target, options = {}) {
  let extensionId = target;
  let storeType = options.store || 'auto';
  
  // Parse URL to extract ID
  if (target.includes('chrome.google.com') || target.includes('chromewebstore')) {
    const match = target.match(/\/([a-z]{32})/);
    if (match) extensionId = match[1];
    storeType = 'chrome';
  } else if (target.includes('addons.mozilla.org')) {
    const match = target.match(/\/addon\/([^\/]+)/);
    if (match) extensionId = match[1];
    storeType = 'firefox';
  }
  
  // Determine store type by ID format
  if (storeType === 'auto') {
    if (/^[a-z]{32}$/.test(extensionId)) {
      storeType = 'chrome';
    } else if (extensionId.includes('@') || extensionId.startsWith('{')) {
      storeType = 'firefox';
    } else {
      // Could be Firefox slug, try Firefox first
      storeType = 'firefox';
    }
  }
  
  let info = null;
  
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
function fetchUrl(url, options = {}) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: {
        'User-Agent': 'ExtVet/0.2.0',
        'Accept': options.json ? 'application/json' : 'text/html',
      },
    }, (res) => {
      // Handle redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchUrl(res.headers.location, options).then(resolve).catch(reject);
      }
      
      if (res.statusCode !== 200) {
        return resolve(null);
      }
      
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (options.json) {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
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

module.exports = {
  checkWebStore,
  fetchChromeWebStore,
  fetchFirefoxAddons,
  analyzeWebStoreInfo,
};
