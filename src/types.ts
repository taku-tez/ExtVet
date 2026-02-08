/**
 * ExtVet Type Definitions
 */

export interface Finding {
  id: string;
  severity: 'critical' | 'warning' | 'info';
  extension: string;
  message: string;
  recommendation?: string;
}

export interface ScanOptions {
  quiet?: boolean;
  verbose?: boolean;
  format?: 'table' | 'json' | 'sarif' | 'html' | 'markdown';
  output?: string;
  severity?: 'info' | 'warning' | 'critical';
  profile?: string;
  browserType?: 'chrome' | 'brave' | 'edge';
  ignoreExtensions?: string[];
  severityOverrides?: Record<string, Finding['severity']>;
  customRules?: CustomRule[];
  browser?: string;
  failOn?: 'critical' | 'warning' | 'info' | 'none';
  configPath?: string;
  verify?: boolean;
}

export interface ExtensionRiskScore {
  extension: string;
  score: number;       // 0-100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  criticalCount: number;
  warningCount: number;
  infoCount: number;
}

export interface ScanSummary {
  critical: number;
  warning: number;
  info: number;
  total: number;
  findings?: Finding[];
  riskScores?: ExtensionRiskScore[];
  overallRiskScore?: number;
  overallGrade?: string;
}

export interface ExtensionInfo {
  id: string;
  path: string;
  version?: string;
  profile?: string;
  type?: 'directory' | 'xpi';
  name?: string;
}

export interface Manifest {
  name?: string;
  version?: string;
  manifest_version?: number;
  permissions?: string[];
  optional_permissions?: string[];
  optional_host_permissions?: string[];
  host_permissions?: string[];
  declarative_net_request?: {
    rule_resources?: Array<{
      id: string;
      enabled: boolean;
      path: string;
    }>;
  };
  content_scripts?: ContentScript[];
  background?: Background;
  content_security_policy?: string | {
    extension_pages?: string;
    sandbox?: string;
  };
  update_url?: string;
  externally_connectable?: {
    matches?: string[];
    ids?: string[];
    accepts_tls_channel_id?: boolean;
  };
  web_accessible_resources?: Array<string | {
    resources: string[];
    matches?: string[];
    extension_ids?: string[];
    use_dynamic_url?: boolean;
  }>;
  browser_specific_settings?: {
    gecko?: {
      id?: string;
      strict_min_version?: string;
    };
  };
  applications?: {
    gecko?: {
      id?: string;
    };
  };
}

export interface ContentScript {
  matches?: string[];
  js?: string[];
  css?: string[];
  run_at?: 'document_start' | 'document_end' | 'document_idle';
  world?: 'ISOLATED' | 'MAIN';
  match_about_blank?: boolean;
}

export interface Background {
  service_worker?: string;
  scripts?: string[];
  page?: string;
  persistent?: boolean;
}

export interface PermissionDanger {
  severity: Finding['severity'];
  msg: string;
}

export interface SuspiciousPattern {
  pattern: RegExp;
  severity: Finding['severity'];
  msg: string;
}

export interface CustomRule {
  name: string;
  pattern?: RegExp;
  severity?: Finding['severity'];
  message?: string;
}

export interface WebStoreInfo {
  name?: string;
  users?: number;
  rating?: number;
  version?: string;
  description?: string;
}

export interface WebStoreResult {
  info: WebStoreInfo | null;
  findings: Finding[];
}

export interface ExtvetConfig {
  ignoreExtensions: string[];
  severityOverrides: Record<string, Finding['severity']>;
  customRules: CustomRule[];
  browser: string;
  format: string;
  severity: string;
  quiet: boolean;
  verbose: boolean;
}
