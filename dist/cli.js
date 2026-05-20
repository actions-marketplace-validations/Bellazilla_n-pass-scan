#!/usr/bin/env node

// src/scan.ts
import { readFileSync, statSync, readdirSync } from "node:fs";
import { join, extname, relative } from "node:path";

// src/patterns.ts
var PATTERNS = [
  {
    id: "aws-access-key",
    name: "AWS Access Key ID",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: "critical",
    mitigation: "Rotate immediately in IAM (Users \u2192 Security credentials \u2192 Make inactive \u2192 Delete). Audit CloudTrail since the commit date."
  },
  {
    id: "aws-secret-access-key",
    name: "AWS Secret Access Key (heuristic)",
    regex: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    severity: "high",
    mitigation: "Looks like an AWS Secret Access Key (40-char base64). If confirmed, rotate the matching Access Key in IAM."
  },
  {
    id: "stripe-secret",
    name: "Stripe secret key",
    regex: /\bsk_(live|test)_[a-zA-Z0-9]{24,}\b/g,
    severity: "critical",
    mitigation: "Roll in Stripe Dashboard \u2192 Developers \u2192 API keys \u2192 Reveal \u2192 Roll. Old key revoked instantly."
  },
  {
    id: "stripe-restricted",
    name: "Stripe restricted key",
    regex: /\brk_(live|test)_[a-zA-Z0-9]{24,}\b/g,
    severity: "high",
    mitigation: "Restricted keys are scope-limited but still leak data. Revoke in Stripe Dashboard."
  },
  {
    id: "github-pat-fine",
    name: "GitHub fine-grained PAT",
    regex: /\bgithub_pat_[A-Za-z0-9_]{82}\b/g,
    severity: "critical",
    mitigation: 'Revoke at https://github.com/settings/tokens. Audit "git events" for misuse.'
  },
  {
    id: "github-pat-classic",
    name: "GitHub classic PAT",
    regex: /\bghp_[A-Za-z0-9]{36}\b/g,
    severity: "critical",
    mitigation: "Revoke at https://github.com/settings/tokens. Then audit recent activity."
  },
  {
    id: "github-oauth",
    name: "GitHub OAuth token",
    regex: /\bgho_[A-Za-z0-9]{36}\b/g,
    severity: "critical",
    mitigation: "Revoke at the OAuth-app owner level."
  },
  {
    id: "github-app-installation",
    name: "GitHub App installation token",
    regex: /\bghs_[A-Za-z0-9]{36}\b/g,
    severity: "high",
    mitigation: "These rotate hourly \u2014 but if you committed one, also rotate the App's private key."
  },
  {
    id: "openai-key",
    name: "OpenAI API key",
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b/g,
    severity: "critical",
    mitigation: "Revoke at https://platform.openai.com/api-keys. Audit usage in the dashboard."
  },
  {
    id: "anthropic-key",
    name: "Anthropic API key",
    regex: /\bsk-ant-api\d{2}-[A-Za-z0-9_-]{80,}\b/g,
    severity: "critical",
    mitigation: "Revoke at https://console.anthropic.com/settings/keys."
  },
  {
    id: "slack-bot",
    name: "Slack bot token",
    regex: /\bxoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}\b/g,
    severity: "high",
    mitigation: "Revoke in your Slack App's OAuth & Permissions panel."
  },
  {
    id: "slack-user",
    name: "Slack user token",
    regex: /\bxox[ap]-[A-Za-z0-9-]{30,}\b/g,
    severity: "critical",
    mitigation: "User tokens can read DMs. Revoke immediately + audit access logs."
  },
  {
    id: "twilio-sid",
    name: "Twilio Account SID",
    regex: /\bAC[a-f0-9]{32}\b/g,
    severity: "medium",
    mitigation: "SID alone is read-only metadata, but pair with the matching auth token = full account access."
  },
  {
    id: "twilio-auth",
    name: "Twilio auth token",
    regex: /\bSK[a-f0-9]{32}\b/g,
    severity: "critical",
    mitigation: "Rotate in Twilio Console \u2192 API keys & tokens. Then audit Voice/SMS usage."
  },
  {
    id: "sendgrid",
    name: "SendGrid API key",
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    severity: "high",
    mitigation: "Revoke in SendGrid \u2192 Settings \u2192 API Keys."
  },
  {
    id: "mailgun",
    name: "Mailgun API key",
    regex: /\bkey-[a-f0-9]{32}\b/g,
    severity: "high",
    mitigation: "Rotate in Mailgun Settings \u2192 API Keys."
  },
  {
    id: "google-api",
    name: "Google API key",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    severity: "high",
    mitigation: "Restrict or delete in GCP Console \u2192 APIs & Services \u2192 Credentials."
  },
  {
    id: "rsa-private-key",
    name: "PEM private-key block",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY-----/g,
    severity: "critical",
    mitigation: "Rotate the key everywhere it's authorised (servers, registries, signing infrastructure)."
  },
  {
    id: "jwt",
    name: "JSON Web Token",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    severity: "medium",
    mitigation: "JWT is not a long-term secret but committing one suggests session leakage. Audit, rotate signing key if it's a service JWT."
  },
  {
    id: "npm-token",
    name: "npm publish token",
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    severity: "critical",
    mitigation: "Revoke at https://www.npmjs.com/settings/<you>/tokens. Audit recent publishes."
  },
  {
    id: "gitlab-pat",
    name: "GitLab personal access token",
    regex: /\bglpat-[A-Za-z0-9_-]{20}\b/g,
    severity: "critical",
    mitigation: "Revoke at https://gitlab.com/-/user_settings/personal_access_tokens."
  },
  {
    id: "sentry-auth",
    name: "Sentry auth token",
    regex: /\bsntrys_[a-f0-9]{64}\b/g,
    severity: "high",
    mitigation: "Rotate at sentry.io \u2192 Settings \u2192 Auth Tokens."
  }
];

// src/scan.ts
var DEFAULT_MAX_BYTES = 5e5;
var SKIP_EXTS = /* @__PURE__ */ new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".bmp",
  ".ico",
  ".svg",
  ".pdf",
  ".zip",
  ".gz",
  ".tgz",
  ".tar",
  ".bz2",
  ".7z",
  ".rar",
  ".mp3",
  ".mp4",
  ".mov",
  ".wav",
  ".ogg",
  ".webm",
  ".woff",
  ".woff2",
  ".ttf",
  ".otf",
  ".eot",
  ".so",
  ".dylib",
  ".dll",
  ".exe",
  ".bin",
  ".wasm",
  ".lockb"
]);
var SKIP_DIRS = /* @__PURE__ */ new Set([
  "node_modules",
  "dist",
  "build",
  "out",
  ".next",
  ".turbo",
  ".git",
  "vendor",
  "__pycache__",
  ".venv",
  "venv",
  "target",
  ".cache"
]);
function scan(options) {
  const max = options.maxFileBytes ?? DEFAULT_MAX_BYTES;
  const ignore = compileGlobs(options.ignoreGlobs ?? []);
  const files = options.files ?? walk(options.root);
  const findings = [];
  for (const absPath of files) {
    const rel = relative(options.root, absPath);
    if (ignore.some((g) => g(rel))) continue;
    if (SKIP_EXTS.has(extname(rel).toLowerCase())) continue;
    let content;
    try {
      const stat = statSync(absPath);
      if (stat.size > max) continue;
      if (!stat.isFile()) continue;
      content = readFileSync(absPath, "utf8");
    } catch {
      continue;
    }
    if (looksBinary(content)) continue;
    for (const pat of PATTERNS) {
      for (const match of content.matchAll(pat.regex)) {
        const idx = match.index ?? 0;
        const before = content.slice(0, idx);
        const line = (before.match(/\n/g)?.length ?? 0) + 1;
        const column = idx - before.lastIndexOf("\n");
        const matched = match[0];
        const preview = matched.length > 30 ? `${matched.slice(0, 30)}\u2026` : matched;
        findings.push({
          patternId: pat.id,
          patternName: pat.name,
          severity: pat.severity,
          path: rel,
          line,
          column,
          preview,
          mitigation: pat.mitigation
        });
      }
    }
  }
  return findings;
}
function walk(root) {
  const out = [];
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    let entries;
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
function looksBinary(text) {
  return text.slice(0, 1024).indexOf("\0") >= 0;
}
function compileGlobs(globs) {
  return globs.filter((g) => g.length > 0).map((g) => {
    const re = new RegExp(
      "^" + g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*/g, "@@DOUBLESTAR@@").replace(/\*/g, "[^/]*").replace(/@@DOUBLESTAR@@/g, ".*") + "$"
    );
    return (p) => re.test(p.replace(/\\/g, "/"));
  });
}

// src/cli.ts
import { execSync } from "node:child_process";
import { resolve } from "node:path";
import { existsSync } from "node:fs";
var SEV_ORDER = { none: 0, medium: 1, high: 2, critical: 3 };
var SEV_COLOR = {
  critical: "\x1B[31m",
  // red
  high: "\x1B[33m",
  // yellow
  medium: "\x1B[36m"
  // cyan
};
var RESET = "\x1B[0m";
var BOLD = "\x1B[1m";
function parseArgs() {
  const args = process.argv.slice(2);
  let root = process.cwd();
  let staged = false;
  let json = false;
  let failOn = "high";
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--staged") staged = true;
    else if (a === "--json") json = true;
    else if (a === "--fail-on" && args[i + 1]) {
      failOn = args[++i];
    } else if (a === "--help" || a === "-h") {
      printHelp();
      process.exit(0);
    } else if (!a.startsWith("-")) {
      root = resolve(a);
    }
  }
  return { root, staged, json, failOn };
}
function printHelp() {
  console.log(`
n-pass-scan \u2014 find leaked secrets in your code

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
function getStagedFiles() {
  try {
    const out = execSync("git diff --name-only --cached --diff-filter=ACMR", { encoding: "utf8" });
    return out.split("\n").map((l) => l.trim()).filter((l) => l.length > 0).map((l) => resolve(l)).filter((p) => existsSync(p));
  } catch {
    return [];
  }
}
function formatGroup(findings) {
  if (findings.length === 0) return "";
  const sev = findings[0].severity;
  const color = SEV_COLOR[sev];
  const header = `${color}${BOLD}[${sev.toUpperCase()}]${RESET} ${findings.length} finding${findings.length === 1 ? "" : "s"}
`;
  const rows = findings.map(
    (f) => `  ${color}\u25CF${RESET} ${BOLD}${f.path}:${f.line}${RESET}  ${f.patternName}
      preview: ${f.preview}
      fix: ${f.mitigation}`
  ).join("\n");
  return header + rows + "\n";
}
function main() {
  const args = parseArgs();
  const files = args.staged ? getStagedFiles() : void 0;
  if (args.staged && files && files.length === 0) {
    process.exit(0);
  }
  const findings = scan({ root: args.root, files });
  if (args.json) {
    console.log(JSON.stringify({ findings }, null, 2));
  } else {
    const grouped = {
      critical: findings.filter((f) => f.severity === "critical"),
      high: findings.filter((f) => f.severity === "high"),
      medium: findings.filter((f) => f.severity === "medium")
    };
    console.error(formatGroup(grouped.critical));
    console.error(formatGroup(grouped.high));
    console.error(formatGroup(grouped.medium));
    if (findings.length === 0) {
      console.error(`\x1B[32m\u2713\x1B[0m No secrets detected.`);
    } else {
      console.error(
        `${BOLD}Total: ${findings.length} finding${findings.length === 1 ? "" : "s"}${RESET}`
      );
    }
  }
  const highest = findings.reduce(
    (max, f) => SEV_ORDER[f.severity] > SEV_ORDER[max] ? f.severity : max,
    "none"
  );
  if (args.failOn !== "none" && SEV_ORDER[highest] >= SEV_ORDER[args.failOn]) {
    process.exit(1);
  }
  process.exit(0);
}
main();
