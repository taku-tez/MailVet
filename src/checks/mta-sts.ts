/**
 * MTA-STS (Mail Transfer Agent Strict Transport Security) checker
 * 
 * MTA-STS enables mail servers to declare their ability to receive
 * TLS-secured connections and specify whether sending servers should
 * refuse to deliver to MX hosts that do not offer TLS.
 */

import type { MTASTSResult, Issue } from '../types.js';
import { isDNSNotFoundError, resolveTxtRecords, filterRecordsByPrefix } from '../utils/dns.js';
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

export async function checkMTASTS(domain: string): Promise<MTASTSResult> {
  const issues: Issue[] = [];
  const stsDomain = `${DNS_SUBDOMAIN.MTA_STS}.${domain}`;

  try {
    const txtRecords = await resolveTxtRecords(stsDomain);
    const stsRecords = filterRecordsByPrefix(txtRecords, DNS_PREFIX.MTA_STS);

    if (stsRecords.length === 0) {
      return NO_MTA_STS_RESULT;
    }

    const dnsRecord = stsRecords[0];
    const version = extractTag(dnsRecord, 'v');
    const id = extractTag(dnsRecord, 'id');

    if (!id) {
      issues.push({
        severity: 'high',
        message: 'MTA-STS record missing id tag',
        recommendation: 'Add id= tag to enable policy updates'
      });
    }

    // Try to fetch the policy file
    const policyResult = await fetchMTASTSPolicy(domain);
    let policy: MTASTSPolicy | undefined;
    
    if (!policyResult.ok) {
      addPolicyFetchError(policyResult, domain, issues);
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
  } catch (err) {
    if (isDNSNotFoundError(err)) {
      return NO_MTA_STS_RESULT;
    }
    throw err;
  }
}

interface PolicyFetchResult {
  ok: boolean;
  policy?: MTASTSPolicy;
  status?: number;
  reason?: 'timeout' | 'network' | 'http_error' | 'parse_error';
  error?: string;
}

function addPolicyFetchError(result: PolicyFetchResult, domain: string, issues: Issue[]): void {
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
      recommendation: `Ensure the policy endpoint responds within ${DEFAULT_HTTP_TIMEOUT_MS / 1000} seconds`
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

function validatePolicy(policy: MTASTSPolicy, issues: Issue[]): void {
  // Check policy mode
  if (policy.mode === 'none') {
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

  // Check max_age
  if (policy.maxAge !== undefined && policy.maxAge < 86400) {
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

async function fetchMTASTSPolicy(domain: string): Promise<PolicyFetchResult> {
  const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
  
  try {
    const response = await fetch(policyUrl, {
      signal: AbortSignal.timeout(DEFAULT_HTTP_TIMEOUT_MS)
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

function parseMTASTSPolicy(text: string): MTASTSPolicy {
  const policy: MTASTSPolicy = { mx: [] };
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
        if (['enforce', 'testing', 'none'].includes(value)) {
          policy.mode = value as 'enforce' | 'testing' | 'none';
        }
        break;
      case 'mx':
        policy.mx!.push(value);
        break;
      case 'max_age':
        policy.maxAge = parseInt(value, 10);
        break;
    }
  }

  return policy;
}
