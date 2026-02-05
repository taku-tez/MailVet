/**
 * MailVet - Email Security Configuration Scanner
 * Type definitions
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';
export type CheckStatus = 'pass' | 'warn' | 'fail' | 'info' | 'error';

export interface Issue {
  severity: Severity;
  message: string;
  recommendation?: string;
}

export interface SPFResult {
  found: boolean;
  record?: string;
  mechanism?: string; // -all, ~all, ?all, +all
  lookupCount?: number;
  includes?: string[];
  issues: Issue[];
}

export interface DKIMSelector {
  selector: string;
  found: boolean;
  keyType?: string;
  keyLength?: number;
  record?: string;
}

export interface DKIMResult {
  found: boolean;
  selectors: DKIMSelector[];
  issues: Issue[];
}

export interface DMARCResult {
  found: boolean;
  record?: string;
  policy?: 'none' | 'quarantine' | 'reject';
  subdomainPolicy?: 'none' | 'quarantine' | 'reject';
  reportingEnabled?: boolean;
  rua?: string[];
  ruf?: string[];
  pct?: number;
  issues: Issue[];
}

export interface MXRecord {
  exchange: string;
  priority: number;
}

export interface MXResult {
  found: boolean;
  records: MXRecord[];
  issues: Issue[];
}

export interface BIMIResult {
  found: boolean;
  record?: string;
  version?: string;
  logoUrl?: string;
  certificateUrl?: string;
  issues: Issue[];
}

export interface MTASTSResult {
  found: boolean;
  dnsRecord?: string;
  version?: string;
  id?: string;
  policy?: {
    version?: string;
    mode?: 'enforce' | 'testing' | 'none';
    mx?: string[];
    maxAge?: number;
  };
  issues: Issue[];
}

export interface TLSRPTResult {
  found: boolean;
  record?: string;
  version?: string;
  rua?: string[];
  issues: Issue[];
}

export interface ARCReadinessResult {
  ready: boolean;
  canSign: boolean;
  canValidate: boolean;
  issues: Issue[];
}

export interface DomainResult {
  domain: string;
  grade: Grade;
  score: number;
  timestamp: string;
  spf: SPFResult;
  dkim: DKIMResult;
  dmarc: DMARCResult;
  mx: MXResult;
  bimi?: BIMIResult;
  mtaSts?: MTASTSResult;
  tlsRpt?: TLSRPTResult;
  arc?: ARCReadinessResult;
  recommendations: string[];
  error?: string;
}

export interface ScanOptions {
  domain?: string;
  file?: string;
  stdin?: boolean;
  aws?: boolean;
  awsProfile?: string;
  gcp?: boolean;
  gcpProject?: string;
  azure?: boolean;
  azureSubscription?: string;
  cloudflare?: boolean;
  json?: boolean;
  verbose?: boolean;
  dkimSelectors?: string[];
  timeout?: number;
  concurrency?: number;
}

export interface CloudSource {
  name: string;
  getDomains(): Promise<string[]>;
}

/**
 * Normalize domain for consistent DNS lookups
 * - Lowercase
 * - Remove protocol prefixes
 * - Remove trailing dots
 * - Remove leading/trailing whitespace
 * - Remove path components
 */
export function normalizeDomain(domain: string): string {
  let normalized = domain.toLowerCase().trim();
  
  // Remove protocol prefix if present
  if (normalized.startsWith('http://') || normalized.startsWith('https://')) {
    try {
      normalized = new URL(normalized).hostname;
    } catch {
      // If URL parsing fails, try manual extraction
      normalized = normalized.replace(/^https?:\/\//, '').split('/')[0];
    }
  }
  
  // Remove path components (e.g., "example.com/path" -> "example.com")
  normalized = normalized.split('/')[0];
  
  // Remove port if present (e.g., "example.com:8080" -> "example.com")
  normalized = normalized.split(':')[0];
  
  // Remove trailing dot (DNS absolute notation)
  normalized = normalized.replace(/\.$/, '');
  
  // Remove any remaining whitespace
  normalized = normalized.replace(/\s/g, '');
  
  return normalized;
}

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
