/**
 * Threat Intelligence Database
 * Maps malicious extension IDs to campaign details for enriched reporting
 */

export interface ThreatIntelEntry {
  campaign: string;
  discovered: string; // YYYY-MM
  severity: 'critical' | 'warning';
  description: string;
  affectedUsers?: string;
  references?: string[];
}

/**
 * Known campaigns with extension IDs and context
 */
export const THREAT_INTEL: Record<string, ThreatIntelEntry> = {
  // Cyberhaven supply chain attack (Dec 2024)
  'pajkjnmeojmbapicmbpliphjmcekeaac': {
    campaign: 'Cyberhaven Supply Chain',
    discovered: '2024-12',
    severity: 'critical',
    description: 'Compromised via OAuth phishing; injected data exfiltration code targeting Facebook Ads credentials',
    affectedUsers: '400K+',
    references: ['https://www.cyberhaven.com/blog/cyberhavens-chrome-extension-security-incident'],
  },
  'cedgndijpacnfbdggppddacngjfdkaca': {
    campaign: 'Cyberhaven Supply Chain',
    discovered: '2024-12',
    severity: 'critical',
    description: 'Reader Mode compromised in same campaign as Cyberhaven',
  },
  'epdjhgbipjpbbhoccdeipghoihibnfja': {
    campaign: 'Cyberhaven Supply Chain',
    discovered: '2024-12',
    severity: 'critical',
    description: 'Rewards Search Automator compromised',
  },
  'jdkknkkbebbapilgoeccciglkfbmbnfm': {
    campaign: 'Cyberhaven Supply Chain',
    discovered: '2025-01',
    severity: 'critical',
    description: 'ChatGPT App compromised via same OAuth phishing vector',
  },
  'befflofjcniongenjmbkgkoljhgliihe': {
    campaign: 'Cyberhaven Supply Chain',
    discovered: '2024-12',
    severity: 'critical',
    description: 'YesCaptcha assistant compromised',
  },

  // GitLab Feb 2025 - CSP stripping campaign
  'mdaboflcmhejfihjcbmdiebgfchigjcf': {
    campaign: 'CSP Stripping Campaign',
    discovered: '2025-02',
    severity: 'critical',
    description: 'Blipshot: strips Content-Security-Policy headers to enable code injection on all pages',
    affectedUsers: '3.2M total across campaign',
  },
  'gaoflciahikhligngeccdecgfjngejlh': {
    campaign: 'CSP Stripping Campaign',
    discovered: '2025-02',
    severity: 'critical',
    description: 'Emojis - Emoji Keyboard: CSP stripping + ad injection',
  },
  'fedimamkpgiemhacbdhkkaihgofncola': {
    campaign: 'CSP Stripping Campaign',
    discovered: '2025-02',
    severity: 'critical',
    description: 'WAToolkit: WhatsApp toolkit weaponized for CSP stripping',
  },
  'deljjimclpnhngmikaiiodgggdniaooh': {
    campaign: 'CSP Stripping Campaign',
    discovered: '2025-02',
    severity: 'critical',
    description: 'Themes for Chrome and YouTube: CSP stripping + data exfiltration',
  },
  'alplpnakfeabeiebipdmaenpmbgknjce': {
    campaign: 'CSP Stripping Campaign',
    discovered: '2025-02',
    severity: 'critical',
    description: 'Adblocker for Chrome - NoAds: fake adblocker that strips CSP',
  },
  'gdocgbfmddcfnlnpmnghmjicjognhonm': {
    campaign: 'CSP Stripping Campaign',
    discovered: '2025-02',
    severity: 'critical',
    description: 'KProxy: proxy extension weaponized',
  },

  // Banshee Stealer variants (2024-2025)
  'lgjdgmdbfhobkdbcjnpnlmhnplnidkkp': {
    campaign: 'Data Stealer Network',
    discovered: '2024-06',
    severity: 'critical',
    description: 'Cookie and credential stealer targeting banking sites',
  },
  'chmfnmjfghjpdamlofhlonnnnokkpbao': {
    campaign: 'Data Stealer Network',
    discovered: '2024-06',
    severity: 'critical',
    description: 'Credential harvesting via injected login forms',
  },
};

/**
 * Look up threat intelligence for an extension ID
 */
export function getThreatIntel(extensionId: string): ThreatIntelEntry | null {
  return THREAT_INTEL[extensionId] || null;
}

/**
 * Get all known campaigns
 */
export function getCampaigns(): Map<string, string[]> {
  const campaigns = new Map<string, string[]>();
  for (const [id, intel] of Object.entries(THREAT_INTEL)) {
    const existing = campaigns.get(intel.campaign) || [];
    existing.push(id);
    campaigns.set(intel.campaign, existing);
  }
  return campaigns;
}
