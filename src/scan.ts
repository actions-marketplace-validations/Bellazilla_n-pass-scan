/**
 * Filesystem scanner — walk files, apply patterns, emit findings.
 *
 * Pure logic, no I/O abstraction — both the GitHub Action and the CLI
 * call into this. The Action wraps with @actions/core annotations.
 */

import { readFileSync, statSync, readdirSync } from 'node:fs';
import { join, extname, relative } from 'node:path';
import { PATTERNS } from './patterns.js';

export interface Finding {
  patternId: string;
  patternName: string;
  severity: 'critical' | 'high' | 'medium';
  path: string;
  line: number;
  column: number;
  preview: string;
  mitigation: string;
}

interface ScanOptions {
  /** Files to scan. When omitted, walks `root` recursively. */
  files?: string[];
  root: string;
  ignoreGlobs?: string[];
  maxFileBytes?: number;
}

const DEFAULT_MAX_BYTES = 500_000;

const SKIP_EXTS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.ico', '.svg', '.pdf',
  '.zip', '.gz', '.tgz', '.tar', '.bz2', '.7z', '.rar',
  '.mp3', '.mp4', '.mov', '.wav', '.ogg', '.webm',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.so', '.dylib', '.dll', '.exe', '.bin', '.wasm', '.lockb',
]);

const SKIP_DIRS = new Set([
  'node_modules', 'dist', 'build', 'out', '.next', '.turbo', '.git',
  'vendor', '__pycache__', '.venv', 'venv', 'target', '.cache',
]);

export function scan(options: ScanOptions): Finding[] {
  const max = options.maxFileBytes ?? DEFAULT_MAX_BYTES;
  const ignore = compileGlobs(options.ignoreGlobs ?? []);
  const files = options.files ?? walk(options.root);
  const findings: Finding[] = [];

  for (const absPath of files) {
    const rel = relative(options.root, absPath);
    if (ignore.some((g) => g(rel))) continue;
    if (SKIP_EXTS.has(extname(rel).toLowerCase())) continue;
    let content: string;
    try {
      const stat = statSync(absPath);
      if (stat.size > max) continue;
      if (!stat.isFile()) continue;
      content = readFileSync(absPath, 'utf8');
    } catch {
      continue;
    }
    if (looksBinary(content)) continue;

    for (const pat of PATTERNS) {
      for (const match of content.matchAll(pat.regex)) {
        const idx = match.index ?? 0;
        const before = content.slice(0, idx);
        const line = (before.match(/\n/g)?.length ?? 0) + 1;
        const column = idx - before.lastIndexOf('\n');
        const matched = match[0]!;
        const preview = matched.length > 30 ? `${matched.slice(0, 30)}…` : matched;
        findings.push({
          patternId: pat.id,
          patternName: pat.name,
          severity: pat.severity,
          path: rel,
          line,
          column,
          preview,
          mitigation: pat.mitigation,
        });
      }
    }
  }

  return findings;
}

function walk(root: string): string[] {
  const out: string[] = [];
  const stack: string[] = [root];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: ReturnType<typeof readdirSync>;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (SKIP_DIRS.has(e.name)) continue;
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        stack.push(full);
      } else if (e.isFile()) {
        out.push(full);
      }
    }
  }
  return out;
}

function looksBinary(text: string): boolean {
  return text.slice(0, 1024).indexOf('\0') >= 0;
}

function compileGlobs(globs: string[]): ((path: string) => boolean)[] {
  return globs.filter((g) => g.length > 0).map((g) => {
    const re = new RegExp(
      '^' +
        g
          .replace(/[.+^${}()|[\]\\]/g, '\\$&')
          .replace(/\*\*/g, '@@DOUBLESTAR@@')
          .replace(/\*/g, '[^/]*')
          .replace(/@@DOUBLESTAR@@/g, '.*') +
        '$',
    );
    return (p: string) => re.test(p.replace(/\\/g, '/'));
  });
}
