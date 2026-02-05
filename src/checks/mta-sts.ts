/**
 * MTA-STS (Mail Transfer Agent Strict Transport Security) checker
 * 
 * MTA-STS enables mail servers to declare their ability to receive
 * TLS-secured connections and specify whether sending servers should
 * refuse to deliver to MX hosts that do not offer TLS.
 */

import type { MTASTSResult, Issue } from '../types.js';
import { cachedResolveTxt, filterRecordsByPrefix } from '../utils/dns.js';
import { extractTag } from '../utils/parser.js';
import { DNS_PREFIX, DNS_SUBDOMAIN, DEFAULT_HTTP_TIMEOUT_MS } from '../constants.js';

// Local policy type (matches types.ts MTASTSResult.policy)
interface MTASTSPolicy {
  version?: string;
  mode?: 'enforce' | 'testing' | 'none';
  mx?: string[];
  maxAge?: number;
}

const NO_MTA_STS_RESULT: MTASTSResult = {
  found: false,
  issues: [{
    severity: 'medium',
    message: 'No MTA-STS DNS record found',
    recommendation: 'Add MTA-STS to enforce TLS for incoming email'
  }]
};

export interface MTASTSOptions {
  timeout?: number;
}

export async function checkMTASTS(domain: string, options: MTASTSOptions = {}): Promise<MTASTSResult> {
  const issues: Issue[] = [];
  const stsDomain = `${DNS_SUBDOMAIN.MTA_STS}.${domain}`;
  const httpTimeout = options.timeout || DEFAULT_HTTP_TIMEOUT_MS;

  const txtRecords = await cachedResolveTxt(stsDomain);
  const stsRecords = filterRecordsByPrefix(txtRecords, DNS_PREFIX.MTA_STS);

  if (stsRecords.length === 0) {
    return NO_MTA_STS_RESULT;
  }

  const dnsRecord = stsRecords[0];
  const version = extractTag(dnsRecord, 'v');
  const id = extractTag(dnsRecord, 'id');

  // Validate version tag (must be STSv1)
  if (!version) {
    issues.push({
      severity: 'high',
      message: 'MTA-STS record missing version tag (v=)',
      recommendation: 'Add v=STSv1 at the start of the MTA-STS record'
    });
  } else if (version.toLowerCase() !== 'stsv1') {
    issues.push({
      severity: 'medium',
      message: `Unexpected MTA-STS version: "${version}" (expected STSv1)`,
      recommendation: 'Use v=STSv1 for the version tag'
    });
  }

  if (!id) {
    issues.push({
      severity: 'high',
      message: 'MTA-STS record missing id tag',
      recommendation: 'Add id= tag to enable policy updates'
    });
  }

  // Try to fetch the policy file
  const policyResult = await fetchMTASTSPolicy(domain, httpTimeout);
  let policy: MTASTSPolicy | undefined;
  
  if (!policyResult.ok) {
    addPolicyFetchError(policyResult, domain, httpTimeout, issues);
  } else {
    policy = policyResult.policy;
    if (policy) {
      validatePolicy(policy, issues);
    }
  }

  return {
    found: true,
    dnsRecord,
    version,
    id,
    policy,
    issues
  };
}

interface PolicyFetchResult {
  ok: boolean;
  policy?: ParsedPolicy;
  status?: number;
  reason?: 'timeout' | 'network' | 'http_error' | 'parse_error';
  error?: string;
}

function addPolicyFetchError(result: PolicyFetchResult, domain: string, timeout: number, issues: Issue[]): void {
  if (result.status === 404) {
    issues.push({
      severity: 'high',
      message: 'MTA-STS policy file not found (404)',
      recommendation: `Create policy file at https://mta-sts.${domain}/.well-known/mta-sts.txt`
    });
  } else if (result.reason === 'timeout') {
    issues.push({
      severity: 'high',
      message: 'MTA-STS policy fetch timed out',
      recommendation: `Ensure the policy endpoint responds within ${timeout / 1000} seconds`
    });
  } else if (result.reason === 'network') {
    issues.push({
      severity: 'high',
      message: `Could not connect to MTA-STS policy endpoint: ${result.error || 'network error'}`,
      recommendation: `Ensure https://mta-sts.${domain} is accessible and has valid TLS`
    });
  } else {
    issues.push({
      severity: 'high',
      message: `MTA-STS policy fetch failed: ${result.error || 'unknown error'}`,
      recommendation: `Ensure https://mta-sts.${domain}/.well-known/mta-sts.txt is accessible`
    });
  }
}

function validatePolicy(policy: ParsedPolicy, issues: Issue[]): void {
  // Check required version tag (RFC 8461)
  if (!policy.version) {
    issues.push({
      severity: 'high',
      message: 'MTA-STS policy missing required version field',
      recommendation: 'Add "version: STSv1" to the policy file'
    });
  } else if (policy.version.toUpperCase() !== 'STSV1') {
    issues.push({
      severity: 'medium',
      message: `Unexpected MTA-STS version: "${policy.version}" (expected STSv1)`,
      recommendation: 'Use "version: STSv1" for the version field'
    });
  }

  // Check required mode tag
  if (!policy.mode) {
    // Distinguish between missing mode and invalid mode value
    if (policy.rawMode) {
      issues.push({
        severity: 'high',
        message: `Invalid MTA-STS mode value: "${policy.rawMode}" (expected enforce, testing, or none)`,
        recommendation: 'Use a valid mode: "enforce", "testing", or "none"'
      });
    } else {
      issues.push({
        severity: 'high',
        message: 'MTA-STS policy missing required mode field',
        recommendation: 'Add "mode: enforce" or "mode: testing" to the policy file'
      });
    }
  } else if (policy.mode === 'none') {
    issues.push({
      severity: 'high',
      message: 'MTA-STS policy mode is "none" - no protection',
      recommendation: 'Change mode to "testing" or "enforce"'
    });
  } else if (policy.mode === 'testing') {
    issues.push({
      severity: 'low',
      message: 'MTA-STS policy in testing mode',
      recommendation: 'Consider switching to "enforce" mode after validation'
    });
  }

  // Check required max_age tag
  if (policy.maxAge === undefined) {
    issues.push({
      severity: 'high',
      message: 'MTA-STS policy missing required max_age field',
      recommendation: 'Add "max_age: 604800" (1 week) or similar to the policy file'
    });
  } else if (policy.maxAge < 86400) {
    issues.push({
      severity: 'medium',
      message: `MTA-STS max_age is very short (${policy.maxAge}s)`,
      recommendation: 'Consider increasing max_age to at least 1 week (604800)'
    });
  }

  // Check MX hosts
  if (!policy.mx || policy.mx.length === 0) {
    issues.push({
      severity: 'high',
      message: 'MTA-STS policy has no MX hosts defined',
      recommendation: 'Add mx: lines matching your MX records'
    });
  }
}

async function fetchMTASTSPolicy(domain: string, timeout: number): Promise<PolicyFetchResult> {
  const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
  
  try {
    const response = await fetch(policyUrl, {
      signal: AbortSignal.timeout(timeout)
    });
    
    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        reason: 'http_error',
        error: `HTTP ${response.status}`
      };
    }

    const text = await response.text();
    const policy = parseMTASTSPolicy(text);
    return { ok: true, policy };
  } catch (err) {
    const error = err as Error;
    
    if (error.name === 'TimeoutError' || error.message.includes('timeout')) {
      return { ok: false, reason: 'timeout', error: 'Request timed out' };
    }
    
    if (error.message.includes('ENOTFOUND') || 
        error.message.includes('ECONNREFUSED') ||
        error.message.includes('fetch')) {
      return { ok: false, reason: 'network', error: error.message };
    }
    
    return { ok: false, reason: 'network', error: error.message };
  }
}

interface ParsedPolicy extends MTASTSPolicy {
  rawMode?: string; // Original mode value before validation
}

function parseMTASTSPolicy(text: string): ParsedPolicy {
  const policy: ParsedPolicy = { mx: [] };
  const lines = text.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const colonIdx = trimmed.indexOf(':');
    if (colonIdx === -1) continue;
    
    const key = trimmed.slice(0, colonIdx).trim().toLowerCase();
    const value = trimmed.slice(colonIdx + 1).trim();
    
    switch (key) {
      case 'version':
        policy.version = value;
        break;
      case 'mode':
        policy.rawMode = value; // Keep raw value for error reporting
        if (['enforce', 'testing', 'none'].includes(value.toLowerCase())) {
          policy.mode = value.toLowerCase() as 'enforce' | 'testing' | 'none';
        }
        break;
      case 'mx':
        // Normalize: lowercase and remove trailing dot for consistent comparison
        policy.mx!.push(value.toLowerCase().replace(/\.$/, ''));
        break;
      case 'max_age': {
        const maxAge = parseInt(value, 10);
        policy.maxAge = Number.isFinite(maxAge) && maxAge >= 0 ? maxAge : undefined;
        break;
      }
    }
  }

  return policy;
}
