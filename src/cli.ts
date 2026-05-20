/**
 * CLI entry — `npx n-pass-scan` or pre-commit hook.
 *
 * Usage:
 *   n-pass-scan [path]              # scan a directory (default: cwd)
 *   n-pass-scan --staged            # scan git-staged files (pre-commit)
 *   n-pass-scan --json              # JSON output to stdout
 *   n-pass-scan --fail-on critical  # exit code 0 unless critical found
 *
 * Designed as a `.husky/pre-commit` drop-in so contributors can't push
 * leaked credentials in the first place.
 */

import { scan, type Finding } from './scan.js';
import { execSync } from 'node:child_process';
import { resolve } from 'node:path';
import { existsSync } from 'node:fs';

type Severity = 'critical' | 'high' | 'medium' | 'none';

const SEV_ORDER: Record<Severity, number> = { none: 0, medium: 1, high: 2, critical: 3 };
const SEV_COLOR: Record<'critical' | 'high' | 'medium', string> = {
  critical: '\x1b[31m', // red
  high: '\x1b[33m', // yellow
  medium: '\x1b[36m', // cyan
};
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

function parseArgs(): { root: string; staged: boolean; json: boolean; failOn: Severity } {
  const args = process.argv.slice(2);
  let root = process.cwd();
  let staged = false;
  let json = false;
  let failOn: Severity = 'high';
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === '--staged') staged = true;
    else if (a === '--json') json = true;
    else if (a === '--fail-on' && args[i + 1]) {
      failOn = args[++i] as Severity;
    } else if (a === '--help' || a === '-h') {
      printHelp();
      process.exit(0);
    } else if (!a.startsWith('-')) {
      root = resolve(a);
    }
  }
  return { root, staged, json, failOn };
}

function printHelp(): void {
  console.log(`
n-pass-scan — find leaked secrets in your code

USAGE
  n-pass-scan [path]              scan a directory (default: cwd)
  n-pass-scan --staged            scan git-staged files (pre-commit use)
  n-pass-scan --json              JSON to stdout
  n-pass-scan --fail-on <sev>     exit-code threshold (critical|high|medium|none, default: high)

PRE-COMMIT HOOK
  echo 'npx --no-install n-pass-scan --staged' > .husky/pre-commit

GITHUB ACTION
  uses: Bellazilla/n-pass-scan@v1
  with:
    fail-on: high
`);
}

function getStagedFiles(): string[] {
  try {
    const out = execSync('git diff --name-only --cached --diff-filter=ACMR', { encoding: 'utf8' });
    return out
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0)
      .map((l) => resolve(l))
      .filter((p) => existsSync(p));
  } catch {
    return [];
  }
}

function formatGroup(findings: Finding[]): string {
  if (findings.length === 0) return '';
  const sev = findings[0]!.severity;
  const color = SEV_COLOR[sev];
  const header = `${color}${BOLD}[${sev.toUpperCase()}]${RESET} ${findings.length} finding${findings.length === 1 ? '' : 's'}\n`;
  const rows = findings
    .map(
      (f) =>
        `  ${color}●${RESET} ${BOLD}${f.path}:${f.line}${RESET}  ${f.patternName}\n` +
        `      preview: ${f.preview}\n` +
        `      fix: ${f.mitigation}`,
    )
    .join('\n');
  return header + rows + '\n';
}

function main(): void {
  const args = parseArgs();
  const files = args.staged ? getStagedFiles() : undefined;

  if (args.staged && files && files.length === 0) {
    // Nothing staged — silent success for pre-commit happy path.
    process.exit(0);
  }

  const findings = scan({ root: args.root, files });

  if (args.json) {
    console.log(JSON.stringify({ findings }, null, 2));
  } else {
    const grouped = {
      critical: findings.filter((f) => f.severity === 'critical'),
      high: findings.filter((f) => f.severity === 'high'),
      medium: findings.filter((f) => f.severity === 'medium'),
    };
    console.error(formatGroup(grouped.critical));
    console.error(formatGroup(grouped.high));
    console.error(formatGroup(grouped.medium));
    if (findings.length === 0) {
      console.error(`\x1b[32m✓\x1b[0m No secrets detected.`);
    } else {
      console.error(
        `${BOLD}Total: ${findings.length} finding${findings.length === 1 ? '' : 's'}${RESET}`,
      );
    }
  }

  const highest = findings.reduce<Severity>(
    (max, f) => (SEV_ORDER[f.severity] > SEV_ORDER[max] ? f.severity : max),
    'none',
  );
  if (args.failOn !== 'none' && SEV_ORDER[highest] >= SEV_ORDER[args.failOn]) {
    process.exit(1);
  }
  process.exit(0);
}

main();
