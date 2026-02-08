/**
 * Extension Policy Engine
 * Define and enforce extension allowlists/blocklists and grade thresholds
 */

import * as fs from 'fs';
import type { Finding, ExtensionRiskScore } from './types.js';

export interface ExtensionPolicy {
  /** Policy name */
  name?: string;
  /** Maximum allowed grade (A, B, C, D, F). Extensions worse than this fail. */
  maxGrade?: 'A' | 'B' | 'C' | 'D' | 'F';
  /** Maximum allowed risk score (0-100) */
  maxScore?: number;
  /** Allowed extension IDs (if set, only these are allowed) */
  allowlist?: string[];
  /** Blocked extension IDs (always fail) */
  blocklist?: string[];
  /** Required extensions (fail if missing) */
  required?: string[];
  /** Blocked permissions (any extension with these fails) */
  blockedPermissions?: string[];
}

export interface PolicyViolation {
  extension: string;
  extensionId?: string;
  rule: string;
  message: string;
  severity: 'error' | 'warning';
}

/**
 * Load policy from a JSON file
 */
export function loadPolicy(policyPath: string): ExtensionPolicy {
  if (!fs.existsSync(policyPath)) {
    throw new Error(`Policy file not found: ${policyPath}`);
  }
  return JSON.parse(fs.readFileSync(policyPath, 'utf-8'));
}

/**
 * Evaluate extensions against a policy
 */
export function evaluatePolicy(
  policy: ExtensionPolicy,
  riskScores: ExtensionRiskScore[],
  findings: Finding[],
  installedIds: string[]
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  const gradeOrder: Record<string, number> = { A: 0, B: 1, C: 2, D: 3, F: 4 };

  for (const score of riskScores) {
    const extId = extractId(score.extension);

    // Check blocklist
    if (policy.blocklist?.includes(extId)) {
      violations.push({
        extension: score.extension,
        extensionId: extId,
        rule: 'blocklist',
        message: `Extension is on the blocklist`,
        severity: 'error',
      });
    }

    // Check allowlist
    if (policy.allowlist && policy.allowlist.length > 0 && !policy.allowlist.includes(extId)) {
      violations.push({
        extension: score.extension,
        extensionId: extId,
        rule: 'allowlist',
        message: `Extension is not on the allowlist`,
        severity: 'error',
      });
    }

    // Check grade threshold
    if (policy.maxGrade) {
      const maxOrd = gradeOrder[policy.maxGrade] ?? 4;
      const extOrd = gradeOrder[score.grade] ?? 0;
      if (extOrd > maxOrd) {
        violations.push({
          extension: score.extension,
          extensionId: extId,
          rule: 'maxGrade',
          message: `Grade ${score.grade} exceeds maximum allowed ${policy.maxGrade}`,
          severity: 'error',
        });
      }
    }

    // Check score threshold
    if (policy.maxScore !== undefined && score.score > policy.maxScore) {
      violations.push({
        extension: score.extension,
        extensionId: extId,
        rule: 'maxScore',
        message: `Risk score ${score.score} exceeds maximum ${policy.maxScore}`,
        severity: 'error',
      });
    }
  }

  // Check required extensions
  if (policy.required) {
    for (const reqId of policy.required) {
      if (!installedIds.includes(reqId)) {
        violations.push({
          extension: reqId,
          extensionId: reqId,
          rule: 'required',
          message: `Required extension is not installed`,
          severity: 'error',
        });
      }
    }
  }

  // Check blocked permissions
  if (policy.blockedPermissions && policy.blockedPermissions.length > 0) {
    for (const f of findings) {
      for (const blocked of policy.blockedPermissions) {
        if (f.id.includes('permission') && f.message.toLowerCase().includes(blocked.toLowerCase())) {
          violations.push({
            extension: f.extension || 'unknown',
            rule: 'blockedPermission',
            message: `Uses blocked permission: ${blocked}`,
            severity: 'error',
          });
        }
      }
    }
  }

  return violations;
}

function extractId(extensionStr: string): string {
  const match = extensionStr.match(/\(([a-z]{32})\)/);
  return match ? match[1] : extensionStr;
}

/**
 * Generate a sample policy file
 */
export function generateSamplePolicy(): ExtensionPolicy {
  return {
    name: 'Corporate Extension Policy',
    maxGrade: 'C',
    maxScore: 60,
    allowlist: [],
    blocklist: [],
    required: [],
    blockedPermissions: ['debugger', 'desktopCapture', 'nativeMessaging'],
  };
}
