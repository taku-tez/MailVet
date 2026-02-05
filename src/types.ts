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

export interface EndpointStatus {
  endpoint: string;
  type: 'mailto' | 'https';
  reachable?: boolean;
  error?: string;
}

export interface TLSRPTResult {
  found: boolean;
  record?: string;
  version?: string;
  rua?: string[];
  endpointStatus?: EndpointStatus[];
  issues: Issue[];
}

export interface ARCReadinessResult {
  ready: boolean;
  canSign: boolean;
  canValidate: boolean;
  issues: Issue[];
}

export interface DNSSECResult {
  enabled: boolean;
  ds?: {
    found: boolean;
    records: Array<{
      keyTag: number;
      algorithm: number;
      algorithmName: string;
      strength?: 'strong' | 'acceptable' | 'weak' | 'deprecated';
      digestType: number;
      digestTypeName: string;
      digestStrength?: 'strong' | 'acceptable' | 'weak';
    }>;
  };
  dnskey?: {
    found: boolean;
    kskCount: number;
    zskCount: number;
  };
  chainValid?: boolean;
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
  dnssec?: DNSSECResult;
  recommendations: string[];
  error?: string;
}

export interface CheckOptions {
  spf?: boolean;
  dkim?: boolean;
  dmarc?: boolean;
  mx?: boolean;
  bimi?: boolean;
  mtaSts?: boolean;
  tlsRpt?: boolean;
  arc?: boolean;
  dnssec?: boolean;
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
  verifyTlsRptEndpoints?: boolean;
  checks?: CheckOptions;
  resolver?: string;
}

export interface CloudSource {
  name: string;
  getDomains(): Promise<string[]>;
}

// Re-export constants for backward compatibility
export { COMMON_DKIM_SELECTORS } from './constants.js';
export { normalizeDomain } from './utils/domain.js';
