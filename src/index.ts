/**
 * GitHub Action entry point — invoked when the action runs in a workflow.
 *
 * Reads inputs, scans, emits one annotation per finding, sets outputs,
 * and exits non-zero if findings meet the configured severity floor.
 */

import * as core from '@actions/core';
import { scan, type Finding } from './scan.js';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

type Severity = 'critical' | 'high' | 'medium' | 'none';

const SEV_ORDER: Record<Severity, number> = {
  none: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

async function run(): Promise<void> {
  try {
    const scanMode = (core.getInput('scan-mode') || 'diff') as 'diff' | 'full';
    const failOn = (core.getInput('fail-on') || 'high') as Severity;
    const ignorePathsRaw = core.getInput('ignore-paths') || '';
    const ignorePaths = ignorePathsRaw.split('\n').map((s) => s.trim()).filter(Boolean);
    const reporter = (core.getInput('reporter') || 'github') as 'github' | 'sarif' | 'json';

    const root = process.env.GITHUB_WORKSPACE ?? process.cwd();
    const files = scanMode === 'diff' ? resolveDiffFiles(root) : undefined;

    core.info(`[n-pass-scan] mode=${scanMode} fail-on=${failOn} reporter=${reporter}`);
    if (files) core.info(`[n-pass-scan] scanning ${files.length} changed files`);

    const findings = scan({ root, files, ignoreGlobs: ignorePaths });

    // Per-finding annotations (only useful for the github reporter)
    if (reporter === 'github') {
      for (const f of findings) {
        const annotate =
          f.severity === 'critical' || f.severity === 'high' ? core.error : core.warning;
        annotate(
          `${f.patternName}: ${f.preview}\n${f.mitigation}`,
          { file: f.path, startLine: f.line, startColumn: f.column, title: 'N-Pass: leaked secret' },
        );
      }
    } else if (reporter === 'sarif') {
      const sarifPath = resolve(root, 'n-pass-scan.sarif');
      writeFileSync(sarifPath, JSON.stringify(toSarif(findings), null, 2));
      core.setOutput('sarif-path', sarifPath);
      core.info(`[n-pass-scan] SARIF written to ${sarifPath}`);
    } else {
      // json — emit to stdout for piping
      console.log(JSON.stringify({ findings }, null, 2));
    }

    const criticalCount = findings.filter((f) => f.severity === 'critical').length;
    const highCount = findings.filter((f) => f.severity === 'high').length;
    core.setOutput('findings', findings.length);
    core.setOutput('critical-count', criticalCount);
    core.setOutput('high-count', highCount);

    // Decide failure
    const highestSeen = findings.reduce<Severity>((max, f) => {
      return SEV_ORDER[f.severity] > SEV_ORDER[max] ? f.severity : max;
    }, 'none');
    if (failOn !== 'none' && SEV_ORDER[highestSeen] >= SEV_ORDER[failOn]) {
      core.setFailed(
        `Found ${findings.length} secret leak${findings.length === 1 ? '' : 's'} (severity ${highestSeen} ≥ fail-on ${failOn}).`,
      );
    } else if (findings.length > 0) {
      core.info(`[n-pass-scan] ${findings.length} findings — none at the fail-on threshold.`);
    } else {
      core.info('[n-pass-scan] No secrets detected.');
    }
  } catch (err) {
    core.setFailed(err instanceof Error ? err.message : String(err));
  }
}

function resolveDiffFiles(_root: string): string[] {
  // In a real Action context, GITHUB_EVENT_PATH points to the event
  // payload — pull/push event has `pull_request.base.sha` etc.
  // For MVP we fall back to "all files" if we can't determine a diff.
  // Real diff-mode requires `git diff --name-only` via execSync, which
  // we'll wire in v0.2 once the basic flow is proven.
  return [];
}

function toSarif(findings: Finding[]) {
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'n-pass-scan',
            informationUri: 'https://npass.me/scan',
            version: '0.1.0',
            rules: [],
          },
        },
        results: findings.map((f) => ({
          ruleId: f.patternId,
          level:
            f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning',
          message: { text: `${f.patternName}: ${f.preview}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.path },
                region: { startLine: f.line, startColumn: f.column },
              },
            },
          ],
          properties: { mitigation: f.mitigation, severity: f.severity },
        })),
      },
    ],
  };
}

void run();
