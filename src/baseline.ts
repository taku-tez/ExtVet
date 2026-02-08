/**
 * Baseline Manager
 * Export, load, and diff extension scan baselines
 */

import * as fs from 'fs';
import type { ScanSummary, ExtensionRiskScore } from './types.js';

export interface Baseline {
  version: string;
  timestamp: string;
  browser: string;
  extensions: ExtensionRiskScore[];
  overallScore: number;
  overallGrade: string;
}

export interface BaselineDiff {
  added: ExtensionRiskScore[];
  removed: ExtensionRiskScore[];
  gradeChanged: Array<{
    extension: string;
    before: { score: number; grade: string };
    after: { score: number; grade: string };
  }>;
  unchanged: number;
  driftScore: number; // 0 = no drift, higher = more drift
}

/**
 * Export current scan results as a baseline
 */
export function exportBaseline(
  summary: ScanSummary,
  browser: string
): Baseline {
  return {
    version: '1.0',
    timestamp: new Date().toISOString(),
    browser,
    extensions: summary.riskScores || [],
    overallScore: summary.overallRiskScore || 0,
    overallGrade: summary.overallGrade || 'A',
  };
}

/**
 * Save baseline to file
 */
export function saveBaseline(baseline: Baseline, filePath: string): void {
  fs.writeFileSync(filePath, JSON.stringify(baseline, null, 2));
}

/**
 * Load baseline from file
 */
export function loadBaseline(filePath: string): Baseline {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Baseline file not found: ${filePath}`);
  }
  return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
}

/**
 * Compare current scan against a baseline
 */
export function diffBaseline(
  baseline: Baseline,
  current: ScanSummary
): BaselineDiff {
  const currentScores = current.riskScores || [];
  const baselineMap = new Map(baseline.extensions.map(e => [e.extension, e]));
  const currentMap = new Map(currentScores.map(e => [e.extension, e]));

  const added = currentScores.filter(e => !baselineMap.has(e.extension));
  const removed = baseline.extensions.filter(e => !currentMap.has(e.extension));

  const gradeChanged: BaselineDiff['gradeChanged'] = [];
  let unchanged = 0;

  for (const [ext, curr] of currentMap) {
    const prev = baselineMap.get(ext);
    if (!prev) continue;
    if (prev.grade !== curr.grade || prev.score !== curr.score) {
      gradeChanged.push({
        extension: ext,
        before: { score: prev.score, grade: prev.grade },
        after: { score: curr.score, grade: curr.grade },
      });
    } else {
      unchanged++;
    }
  }

  // Drift score: weighted sum of changes
  const driftScore = added.length * 10 + removed.length * 5 + gradeChanged.length * 3;

  return { added, removed, gradeChanged, unchanged, driftScore };
}
