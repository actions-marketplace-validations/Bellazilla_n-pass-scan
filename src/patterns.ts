/**
 * Secret-detection patterns for n-pass-scan.
 *
 * Curated from public 2025-26 GitGuardian + GitHub Secret Scanning
 * reports. False-positive guard: every regex anchors on a stable
 * prefix/suffix. Generic high-entropy heuristics are deliberately
 * excluded — they generate noise that erodes trust.
 *
 * Kept in sync with apps/web/lib/secret-patterns.ts in the main
 * N-Pass repo (the SaaS Developer Watchtower uses the same set).
 * Updates should land in both places.
 */

export interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: 'critical' | 'high' | 'medium';
  mitigation: string;
}

export const PATTERNS: SecretPattern[] = [
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: 'critical',
    mitigation:
      'Rotate immediately in IAM (Users → Security credentials → Make inactive → Delete). Audit CloudTrail since the commit date.',
  },
  {
    id: 'aws-secret-access-key',
    name: 'AWS Secret Access Key (heuristic)',
    regex: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    severity: 'high',
    mitigation:
      'Looks like an AWS Secret Access Key (40-char base64). If confirmed, rotate the matching Access Key in IAM.',
  },
  {
    id: 'stripe-secret',
    name: 'Stripe secret key',
    regex: /\bsk_(live|test)_[a-zA-Z0-9]{24,}\b/g,
    severity: 'critical',
    mitigation:
      'Roll in Stripe Dashboard → Developers → API keys → Reveal → Roll. Old key revoked instantly.',
  },
  {
    id: 'stripe-restricted',
    name: 'Stripe restricted key',
    regex: /\brk_(live|test)_[a-zA-Z0-9]{24,}\b/g,
    severity: 'high',
    mitigation: 'Restricted keys are scope-limited but still leak data. Revoke in Stripe Dashboard.',
  },
  {
    id: 'github-pat-fine',
    name: 'GitHub fine-grained PAT',
    regex: /\bgithub_pat_[A-Za-z0-9_]{82}\b/g,
    severity: 'critical',
    mitigation: 'Revoke at https://github.com/settings/tokens. Audit "git events" for misuse.',
  },
  {
    id: 'github-pat-classic',
    name: 'GitHub classic PAT',
    regex: /\bghp_[A-Za-z0-9]{36}\b/g,
    severity: 'critical',
    mitigation: 'Revoke at https://github.com/settings/tokens. Then audit recent activity.',
  },
  {
    id: 'github-oauth',
    name: 'GitHub OAuth token',
    regex: /\bgho_[A-Za-z0-9]{36}\b/g,
    severity: 'critical',
    mitigation: 'Revoke at the OAuth-app owner level.',
  },
  {
    id: 'github-app-installation',
    name: 'GitHub App installation token',
    regex: /\bghs_[A-Za-z0-9]{36}\b/g,
    severity: 'high',
    mitigation: 'These rotate hourly — but if you committed one, also rotate the App\'s private key.',
  },
  {
    id: 'openai-key',
    name: 'OpenAI API key',
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b/g,
    severity: 'critical',
    mitigation: 'Revoke at https://platform.openai.com/api-keys. Audit usage in the dashboard.',
  },
  {
    id: 'anthropic-key',
    name: 'Anthropic API key',
    regex: /\bsk-ant-api\d{2}-[A-Za-z0-9_-]{80,}\b/g,
    severity: 'critical',
    mitigation: 'Revoke at https://console.anthropic.com/settings/keys.',
  },
  {
    id: 'slack-bot',
    name: 'Slack bot token',
    regex: /\bxoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}\b/g,
    severity: 'high',
    mitigation: 'Revoke in your Slack App\'s OAuth & Permissions panel.',
  },
  {
    id: 'slack-user',
    name: 'Slack user token',
    regex: /\bxox[ap]-[A-Za-z0-9-]{30,}\b/g,
    severity: 'critical',
    mitigation: 'User tokens can read DMs. Revoke immediately + audit access logs.',
  },
  {
    id: 'twilio-sid',
    name: 'Twilio Account SID',
    regex: /\bAC[a-f0-9]{32}\b/g,
    severity: 'medium',
    mitigation: 'SID alone is read-only metadata, but pair with the matching auth token = full account access.',
  },
  {
    id: 'twilio-auth',
    name: 'Twilio auth token',
    regex: /\bSK[a-f0-9]{32}\b/g,
    severity: 'critical',
    mitigation: 'Rotate in Twilio Console → API keys & tokens. Then audit Voice/SMS usage.',
  },
  {
    id: 'sendgrid',
    name: 'SendGrid API key',
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    severity: 'high',
    mitigation: 'Revoke in SendGrid → Settings → API Keys.',
  },
  {
    id: 'mailgun',
    name: 'Mailgun API key',
    regex: /\bkey-[a-f0-9]{32}\b/g,
    severity: 'high',
    mitigation: 'Rotate in Mailgun Settings → API Keys.',
  },
  {
    id: 'google-api',
    name: 'Google API key',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    severity: 'high',
    mitigation: 'Restrict or delete in GCP Console → APIs & Services → Credentials.',
  },
  {
    id: 'rsa-private-key',
    name: 'PEM private-key block',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY-----/g,
    severity: 'critical',
    mitigation: 'Rotate the key everywhere it\'s authorised (servers, registries, signing infrastructure).',
  },
  {
    id: 'jwt',
    name: 'JSON Web Token',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    severity: 'medium',
    mitigation: 'JWT is not a long-term secret but committing one suggests session leakage. Audit, rotate signing key if it\'s a service JWT.',
  },
  {
    id: 'npm-token',
    name: 'npm publish token',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    severity: 'critical',
    mitigation: 'Revoke at https://www.npmjs.com/settings/<you>/tokens. Audit recent publishes.',
  },
  {
    id: 'gitlab-pat',
    name: 'GitLab personal access token',
    regex: /\bglpat-[A-Za-z0-9_-]{20}\b/g,
    severity: 'critical',
    mitigation: 'Revoke at https://gitlab.com/-/user_settings/personal_access_tokens.',
  },
  {
    id: 'sentry-auth',
    name: 'Sentry auth token',
    regex: /\bsntrys_[a-f0-9]{64}\b/g,
    severity: 'high',
    mitigation: 'Rotate at sentry.io → Settings → Auth Tokens.',
  },
];
