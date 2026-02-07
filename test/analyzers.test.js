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
