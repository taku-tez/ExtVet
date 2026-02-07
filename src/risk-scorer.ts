/**
 * Risk Scorer
 * Calculates per-extension and overall risk scores from findings
 */

import type { Finding, ExtensionRiskScore } from './types.js';

const WEIGHTS = {
  critical: 25,
  warning: 8,
  info: 2,
};

const MAX_SCORE = 100;

function gradeFromScore(score: number): ExtensionRiskScore['grade'] {
  if (score <= 10) return 'A';
  if (score <= 30) return 'B';
  if (score <= 55) return 'C';
  if (score <= 75) return 'D';
  return 'F';
}

/**
 * Calculate risk scores per extension from findings
 */
export function calculateRiskScores(findings: Finding[]): ExtensionRiskScore[] {
  // Group findings by extension
  const byExtension = new Map<string, Finding[]>();
  
  for (const f of findings) {
    const ext = f.extension || 'unknown';
    if (!byExtension.has(ext)) byExtension.set(ext, []);
    byExtension.get(ext)!.push(f);
  }

  const scores: ExtensionRiskScore[] = [];

  for (const [extension, extFindings] of byExtension) {
    const criticalCount = extFindings.filter(f => f.severity === 'critical').length;
    const warningCount = extFindings.filter(f => f.severity === 'warning').length;
    const infoCount = extFindings.filter(f => f.severity === 'info').length;

    const rawScore = 
      criticalCount * WEIGHTS.critical +
      warningCount * WEIGHTS.warning +
      infoCount * WEIGHTS.info;

    const score = Math.min(rawScore, MAX_SCORE);

    scores.push({
      extension,
      score,
      grade: gradeFromScore(score),
      criticalCount,
      warningCount,
      infoCount,
    });
  }

  // Sort by score descending (riskiest first)
  scores.sort((a, b) => b.score - a.score);

  return scores;
}

/**
 * Calculate overall risk score (average of all extension scores)
 */
export function calculateOverallScore(scores: ExtensionRiskScore[]): { score: number; grade: string } {
  if (scores.length === 0) return { score: 0, grade: 'A' };
  
  // Use max score as overall (one bad extension = high risk)
  const maxScore = Math.max(...scores.map(s => s.score));
  return { score: maxScore, grade: gradeFromScore(maxScore) };
}
