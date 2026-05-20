# n-pass-scan

Open-source secret scanner — GitHub Action + CLI + pre-commit hook.

22 vendor-specific patterns covering AWS, Stripe, GitHub, OpenAI, Anthropic, Slack, Twilio, SendGrid, Mailgun, Google API, RSA/PEM private keys, JWTs, npm publish tokens, GitLab PATs, Sentry auth tokens, and more.

Powered by the same engine as [N-Pass Developer Watchtower](https://npass.me/scan).

## GitHub Action

```yaml
name: Secret scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Bellazilla/n-pass-scan@v1
        with:
          fail-on: high       # critical | high | medium | none
          reporter: github    # github | sarif | json
```

Outputs `findings` / `critical-count` / `high-count` for downstream steps.

## CLI

```bash
# One-off scan of cwd
npx n-pass-scan

# JSON for piping
npx n-pass-scan --json | jq '.findings | length'

# Fail only on critical
npx n-pass-scan --fail-on critical
```

## Pre-commit hook

```bash
# Husky
echo 'npx --no-install n-pass-scan --staged' > .husky/pre-commit

# Native git hook
echo '#!/bin/sh\nnpx --no-install n-pass-scan --staged' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

`--staged` only scans the files in `git diff --cached`, so the hook is fast even on huge repos.

## How it differs from the SaaS Developer Watchtower

The free OSS scanner runs on your CI / your machine. The [SaaS Developer Watchtower](https://npass.me) adds:

- Continuous scanning across all your public repos (no need to add the Action to each one)
- Email alerts on new commits with leaks
- Private repo support (via GitHub App with read-only contents scope)
- Centralised dashboard for org-wide audit
- 100 commits/month free, paid plans unlock more

## License

MIT.

## Publishing

This directory is the seed for the public repository at `github.com/Bellazilla/n-pass-scan`. To bootstrap:

```bash
cd tools/n-pass-scan
pnpm install
pnpm run build
# Then push contents (excluding node_modules + the dist subfolder) to the public repo
```

The `dist/` JavaScript bundle is what GitHub Actions runs (Node 20 runtime, `using: node20`), so it MUST be committed to the public repo or the Action won't execute.
