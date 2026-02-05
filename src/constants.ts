/**
 * MailVet constants
 * Centralized configuration values and limits
 */

// SPF limits (RFC 7208)
export const SPF_MAX_DNS_LOOKUPS = 10;
export const SPF_MAX_RECURSION_DEPTH = 10;

// Timeouts
export const DEFAULT_CHECK_TIMEOUT_MS = 10000;
export const DEFAULT_HTTP_TIMEOUT_MS = 5000;
export const DEFAULT_CONCURRENCY = 5;

// Scoring weights (max 100 base + 15 bonus)
export const SCORE_SPF_MAX = 35;
export const SCORE_DKIM_MAX = 25;
export const SCORE_DMARC_MAX = 40;
export const SCORE_BONUS_MAX = 20; // BIMI(5) + MTA-STS(4) + TLS-RPT(3) + ARC(3) + DNSSEC(5)

// Grade thresholds
export const GRADE_A_MIN = 90;
export const GRADE_B_MIN = 75;
export const GRADE_C_MIN = 50;
export const GRADE_D_MIN = 25;

// Key length thresholds
export const DKIM_WEAK_KEY_BITS = 1024;
export const DKIM_STRONG_KEY_BITS = 2048;

// DNS record prefixes
export const DNS_PREFIX = {
  SPF: 'v=spf1',
  DKIM: 'v=dkim1',
  DMARC: 'v=dmarc1',
  BIMI: 'v=bimi1',
  MTA_STS: 'v=sts',
  TLS_RPT: 'v=tlsrpt',
} as const;

// DNS subdomains
export const DNS_SUBDOMAIN = {
  DKIM: '_domainkey',
  DMARC: '_dmarc',
  MTA_STS: '_mta-sts',
  TLS_RPT: '_smtp._tls',
} as const;

// Common BIMI selectors
export const COMMON_BIMI_SELECTORS = [
  'default',
  'logo',
  'brand',
] as const;

// Common DKIM selectors used by popular email providers
export const COMMON_DKIM_SELECTORS = [
  'default',
  'google',
  'selector1', // Microsoft 365
  'selector2', // Microsoft 365
  'k1',
  'k2',
  's1',
  's2',
  'dkim',
  'mail',
  'email',
  'smtp',
  'mandrill',
  'mailchimp',
  'amazonses',
  'ses',
  'sendgrid',
  'sg',
  'postmark',
  'pm',
  'mailgun',
  'mg',
  'sparkpost',
  'zendesk',
  'zendesk1',
  'zendesk2',
] as const;

// Email provider patterns for MX detection
export const EMAIL_PROVIDERS = [
  { pattern: /google\.com$|googlemail\.com$/i, name: 'Google Workspace' },
  { pattern: /outlook\.com$|protection\.outlook\.com$/i, name: 'Microsoft 365' },
  { pattern: /pphosted\.com$/i, name: 'Proofpoint' },
  { pattern: /mimecast\.com$/i, name: 'Mimecast' },
  { pattern: /barracuda(networks)?\.com$/i, name: 'Barracuda' },
  { pattern: /messagelabs\.com$/i, name: 'Symantec/Broadcom' },
  { pattern: /zoho\.com$/i, name: 'Zoho Mail' },
  { pattern: /yahoodns\.net$/i, name: 'Yahoo Mail' },
  { pattern: /secureserver\.net$/i, name: 'GoDaddy' },
  { pattern: /emailsrvr\.com$/i, name: 'Rackspace' },
  { pattern: /amazonaws\.com$/i, name: 'Amazon SES' },
  { pattern: /mailgun\.org$/i, name: 'Mailgun' },
  { pattern: /sendgrid\.net$/i, name: 'SendGrid' },
  { pattern: /postmarkapp\.com$/i, name: 'Postmark' },
  { pattern: /mx\.icloud\.com$/i, name: 'Apple iCloud' },
  { pattern: /fastmail\.com$/i, name: 'Fastmail' },
] as const;

// Valid DMARC tags per RFC 7489
export const VALID_DMARC_TAGS = new Set([
  'v', 'p', 'sp', 'rua', 'ruf', 'adkim', 'aspf', 'fo', 'rf', 'ri', 'pct'
]);

// DMARC policy values
export const DMARC_POLICIES = ['none', 'quarantine', 'reject'] as const;
export type DMARCPolicy = typeof DMARC_POLICIES[number];

// MTA-STS modes
export const MTA_STS_MODES = ['enforce', 'testing', 'none'] as const;
export type MTASTSMode = typeof MTA_STS_MODES[number];
