/**
 * MTA-STS (Mail Transfer Agent Strict Transport Security) checker
 * 
 * MTA-STS enables mail servers to declare their ability to receive
 * TLS-secured connections and specify whether sending servers should
 * refuse to deliver to MX hosts that do not offer TLS.
 */

import dns from 'node:dns/promises';
import type { Issue } from '../types.js';

export interface MTASTSResult {
  found: boolean;
  dnsRecord?: string;
  version?: string;
  id?: string;
  policy?: MTASTSPolicy;
  issues: Issue[];
}

export interface MTASTSPolicy {
  version?: string;
  mode?: 'enforce' | 'testing' | 'none';
  mx?: string[];
  maxAge?: number;
}

export async function checkMTASTS(domain: string): Promise<MTASTSResult> {
  const issues: Issue[] = [];
  const stsDomain = `_mta-sts.${domain}`;

  try {
    // Check DNS record
    const txtRecords = await dns.resolveTxt(stsDomain);
    const stsRecords = txtRecords
      .map(r => r.join(''))
      .filter(r => r.toLowerCase().startsWith('v=sts'));

    if (stsRecords.length === 0) {
      return {
        found: false,
        issues: [{
          severity: 'medium',
          message: 'No MTA-STS DNS record found',
          recommendation: 'Add MTA-STS to enforce TLS for incoming email'
        }]
      };
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
    let policy: MTASTSPolicy | undefined;
    const policyResult = await fetchMTASTSPolicy(domain);
    
    if (!policyResult.ok) {
      // Policy fetch failed
      if (policyResult.status === 404) {
        issues.push({
          severity: 'high',
          message: 'MTA-STS policy file not found (404)',
          recommendation: 'Create policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt'
        });
      } else if (policyResult.reason === 'timeout') {
        issues.push({
          severity: 'high',
          message: 'MTA-STS policy fetch timed out',
          recommendation: 'Ensure the policy endpoint responds within 5 seconds'
        });
      } else if (policyResult.reason === 'network') {
        issues.push({
          severity: 'high',
          message: `Could not connect to MTA-STS policy endpoint: ${policyResult.error || 'network error'}`,
          recommendation: 'Ensure https://mta-sts.{domain} is accessible and has valid TLS'
        });
      } else {
        issues.push({
          severity: 'high',
          message: `MTA-STS policy fetch failed: ${policyResult.error || 'unknown error'}`,
          recommendation: 'Ensure https://mta-sts.{domain}/.well-known/mta-sts.txt is accessible'
        });
      }
    } else {
      policy = policyResult.policy;
      
      if (policy) {
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
        if (policy.maxAge !== undefined) {
          if (policy.maxAge < 86400) {
            issues.push({
              severity: 'medium',
              message: `MTA-STS max_age is very short (${policy.maxAge}s)`,
              recommendation: 'Consider increasing max_age to at least 1 week (604800)'
            });
          }
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
    if ((err as NodeJS.ErrnoException).code === 'ENOTFOUND' ||
        (err as NodeJS.ErrnoException).code === 'ENODATA') {
      return {
        found: false,
        issues: [{
          severity: 'medium',
          message: 'No MTA-STS DNS record found',
          recommendation: 'Add MTA-STS to enforce TLS for incoming email'
        }]
      };
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

async function fetchMTASTSPolicy(domain: string): Promise<PolicyFetchResult> {
  const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
  
  try {
    const response = await fetch(policyUrl, {
      signal: AbortSignal.timeout(5000)
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

    const [key, value] = trimmed.split(':').map(s => s.trim());
    
    switch (key.toLowerCase()) {
      case 'version':
        policy.version = value;
        break;
      case 'mode':
        policy.mode = value as 'enforce' | 'testing' | 'none';
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

function extractTag(record: string, tag: string): string | undefined {
  const regex = new RegExp(`${tag}=([^;\\s]+)`, 'i');
  const match = record.match(regex);
  return match ? match[1] : undefined;
}
