/**
 * DNSSEC (Domain Name System Security Extensions) checker
 * 
 * DNSSEC provides authentication and integrity for DNS responses
 * through cryptographic signatures.
 */

import type { Issue } from '../types.js';
import { dns } from '../utils/dns.js';

// DNSSEC algorithm names (RFC 8624)
export const DNSSEC_ALGORITHMS: Record<number, { name: string; strength: 'strong' | 'acceptable' | 'weak' | 'deprecated' }> = {
  1: { name: 'RSAMD5', strength: 'deprecated' },
  3: { name: 'DSA/SHA1', strength: 'deprecated' },
  5: { name: 'RSASHA1', strength: 'weak' },
  6: { name: 'DSA-NSEC3-SHA1', strength: 'deprecated' },
  7: { name: 'RSASHA1-NSEC3-SHA1', strength: 'weak' },
  8: { name: 'RSASHA256', strength: 'acceptable' },
  10: { name: 'RSASHA512', strength: 'strong' },
  13: { name: 'ECDSAP256SHA256', strength: 'strong' },
  14: { name: 'ECDSAP384SHA384', strength: 'strong' },
  15: { name: 'ED25519', strength: 'strong' },
  16: { name: 'ED448', strength: 'strong' },
};

// DS digest types
export const DS_DIGEST_TYPES: Record<number, { name: string; strength: 'strong' | 'acceptable' | 'weak' }> = {
  1: { name: 'SHA-1', strength: 'weak' },
  2: { name: 'SHA-256', strength: 'strong' },
  3: { name: 'GOST R 34.11-94', strength: 'acceptable' },
  4: { name: 'SHA-384', strength: 'strong' },
};

// Key flags
export const DNSKEY_FLAGS = {
  ZONE_KEY: 256,    // ZSK (Zone Signing Key)
  SEP_KEY: 257,     // KSK (Key Signing Key) / Secure Entry Point
};

export interface DNSSECResult {
  enabled: boolean;
  ds?: {
    found: boolean;
    records: DSRecord[];
  };
  dnskey?: {
    found: boolean;
    records: DNSKEYRecord[];
    kskCount: number;
    zskCount: number;
  };
  chainValid?: boolean;
  issues: Issue[];
}

export interface DSRecord {
  keyTag: number;
  algorithm: number;
  algorithmName: string;
  strength?: 'strong' | 'acceptable' | 'weak' | 'deprecated';
  digestType: number;
  digestTypeName: string;
  digestStrength?: 'strong' | 'acceptable' | 'weak';
  digest: string;
}

export interface DNSKEYRecord {
  flags: number;
  protocol: number;
  algorithm: number;
  algorithmName: string;
  keyType: 'KSK' | 'ZSK' | 'unknown';
  publicKey: string;
}

const NO_DNSSEC_RESULT: DNSSECResult = {
  enabled: false,
  issues: [{
    severity: 'medium',
    message: 'DNSSEC is not enabled for this domain',
    recommendation: 'Consider enabling DNSSEC to protect against DNS spoofing and cache poisoning'
  }]
};

export interface DNSSECOptions {
  resolver?: string; // Custom DNS resolver (e.g., '8.8.8.8')
}

export async function checkDNSSEC(domain: string, options: DNSSECOptions = {}): Promise<DNSSECResult> {
  const issues: Issue[] = [];

  // Default to Google DNS for DNSSEC - system DNS often doesn't return DS/DNSKEY
  const resolver = options.resolver || '8.8.8.8';

  try {
    // Check for DS records at parent zone
    const dsResult = await fetchDSRecords(domain, resolver);
    const dnskeyResult = await fetchDNSKEYRecords(domain, resolver);

    // Report fetch errors as issues
    if (dsResult.error && dnskeyResult.error) {
      issues.push({
        severity: 'low',
        message: dsResult.error,
        recommendation: 'Install dig (bind-utils/dnsutils) for DNSSEC validation'
      });
    }

    const dsRecords = dsResult.records;
    const dnskeyRecords = dnskeyResult.records;

    // If neither DS nor DNSKEY found, DNSSEC is not enabled
    if (dsRecords.length === 0 && dnskeyRecords.length === 0) {
      return {
        ...NO_DNSSEC_RESULT,
        issues: [...NO_DNSSEC_RESULT.issues, ...issues]
      };
    }

    // Parse DS records
    const parsedDS: DSRecord[] = dsRecords.map(record => {
      const parts = record.split(/\s+/);
      const keyTag = parseInt(parts[0], 10);
      const algorithm = parseInt(parts[1], 10);
      const digestType = parseInt(parts[2], 10);
      const digest = parts.slice(3).join('');
      
      return {
        keyTag,
        algorithm,
        algorithmName: DNSSEC_ALGORITHMS[algorithm]?.name || `Unknown (${algorithm})`,
        strength: DNSSEC_ALGORITHMS[algorithm]?.strength as DSRecord['strength'],
        digestType,
        digestTypeName: DS_DIGEST_TYPES[digestType]?.name || `Unknown (${digestType})`,
        digestStrength: DS_DIGEST_TYPES[digestType]?.strength as DSRecord['digestStrength'],
        digest,
      };
    });

    // Parse DNSKEY records
    const parsedDNSKEY: DNSKEYRecord[] = dnskeyRecords.map(record => {
      const parts = record.split(/\s+/);
      const flags = parseInt(parts[0], 10);
      const protocol = parseInt(parts[1], 10);
      const algorithm = parseInt(parts[2], 10);
      const publicKey = parts.slice(3).join('');
      
      let keyType: 'KSK' | 'ZSK' | 'unknown' = 'unknown';
      if (flags === DNSKEY_FLAGS.SEP_KEY) {
        keyType = 'KSK';
      } else if (flags === DNSKEY_FLAGS.ZONE_KEY) {
        keyType = 'ZSK';
      }
      
      return {
        flags,
        protocol,
        algorithm,
        algorithmName: DNSSEC_ALGORITHMS[algorithm]?.name || `Unknown (${algorithm})`,
        keyType,
        publicKey,
      };
    });

    const kskCount = parsedDNSKEY.filter(k => k.keyType === 'KSK').length;
    const zskCount = parsedDNSKEY.filter(k => k.keyType === 'ZSK').length;

    // Validate configuration
    validateDSRecords(parsedDS, issues);
    validateDNSKEYRecords(parsedDNSKEY, issues);
    validateChainConsistency(parsedDS, parsedDNSKEY, issues);

    // Check chain validity (simplified - full validation would require RRSIG checks)
    const chainValid = parsedDS.length > 0 && parsedDNSKEY.length > 0 && kskCount > 0;

    if (!chainValid && parsedDS.length > 0) {
      issues.push({
        severity: 'high',
        message: 'DNSSEC chain may be broken - DS records exist but DNSKEY configuration appears incomplete',
        recommendation: 'Ensure DNSKEY records are properly published and signed'
      });
    }

    return {
      enabled: true,
      ds: {
        found: parsedDS.length > 0,
        records: parsedDS,
      },
      dnskey: {
        found: parsedDNSKEY.length > 0,
        records: parsedDNSKEY,
        kskCount,
        zskCount,
      },
      chainValid,
      issues,
    };

  } catch (err) {
    const error = err as Error;
    
    // SERVFAIL often indicates DNSSEC validation failure
    if (error.message?.includes('SERVFAIL')) {
      return {
        enabled: true,
        chainValid: false,
        issues: [{
          severity: 'critical',
          message: 'DNSSEC validation failed (SERVFAIL) - DNS responses are being rejected',
          recommendation: 'Check DNSSEC configuration and ensure signatures are valid and not expired'
        }]
      };
    }

    // NXDOMAIN for DS lookup is normal (means no DS at parent)
    if (error.message?.includes('ENOTFOUND') || error.message?.includes('ENODATA')) {
      return NO_DNSSEC_RESULT;
    }

    throw err;
  }
}

interface DNSFetchResult {
  records: string[];
  error?: string;
}

async function fetchDSRecords(domain: string, resolver?: string): Promise<DNSFetchResult> {
  const dnsServer = resolver || undefined; // Use system default if not specified
  
  try {
    // Try dig first (most reliable for DNSSEC records)
    const result = await fetchWithDig('DS', domain, dnsServer);
    if (result.records.length > 0 || !result.error) {
      return result;
    }
  } catch {
    // dig not available, continue to fallback
  }

  // Return empty with info about limitation
  return {
    records: [],
    error: 'dig command not available - install bind-utils/dnsutils for full DNSSEC support'
  };
}

async function fetchDNSKEYRecords(domain: string, resolver?: string): Promise<DNSFetchResult> {
  const dnsServer = resolver || undefined;
  
  try {
    const result = await fetchWithDig('DNSKEY', domain, dnsServer);
    if (result.records.length > 0 || !result.error) {
      return result;
    }
  } catch {
    // dig not available
  }

  return {
    records: [],
    error: 'dig command not available - install bind-utils/dnsutils for full DNSSEC support'
  };
}

async function fetchWithDig(rrtype: string, domain: string, dnsServer?: string): Promise<DNSFetchResult> {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const execFileAsync = promisify(execFile);
  
  const args = ['+short', rrtype, domain];
  if (dnsServer) {
    args.push(`@${dnsServer}`);
  }
  
  try {
    const { stdout, stderr } = await execFileAsync('dig', args, { timeout: 10000 });
    
    if (stderr && stderr.includes('connection timed out')) {
      return { records: [], error: 'DNS query timed out' };
    }
    
    const records = stdout.trim().split('\n').filter(line => line.length > 0 && !line.startsWith(';'));
    return { records };
  } catch (err) {
    const error = err as Error & { code?: string };
    
    if (error.code === 'ENOENT') {
      throw new Error('dig not found');
    }
    if (error.message?.includes('ETIMEDOUT') || error.message?.includes('killed')) {
      return { records: [], error: 'DNS query timed out' };
    }
    
    return { records: [], error: error.message };
  }
}

function validateDSRecords(records: DSRecord[], issues: Issue[]): void {
  for (const ds of records) {
    // Check algorithm strength
    const algo = DNSSEC_ALGORITHMS[ds.algorithm];
    if (algo?.strength === 'deprecated') {
      issues.push({
        severity: 'critical',
        message: `DS record uses deprecated algorithm: ${ds.algorithmName}`,
        recommendation: 'Migrate to a stronger algorithm (ECDSAP256SHA256, ED25519, or RSASHA256 minimum)'
      });
    } else if (algo?.strength === 'weak') {
      issues.push({
        severity: 'high',
        message: `DS record uses weak algorithm: ${ds.algorithmName}`,
        recommendation: 'Consider migrating to ECDSAP256SHA256 or ED25519 for better security'
      });
    }

    // Check digest type
    const digest = DS_DIGEST_TYPES[ds.digestType];
    if (digest?.strength === 'weak') {
      issues.push({
        severity: 'medium',
        message: `DS record uses weak digest type: ${ds.digestTypeName}`,
        recommendation: 'Use SHA-256 (type 2) or SHA-384 (type 4) for DS digest'
      });
    }
  }
}

function validateDNSKEYRecords(records: DNSKEYRecord[], issues: Issue[]): void {
  const kskCount = records.filter(k => k.keyType === 'KSK').length;
  const zskCount = records.filter(k => k.keyType === 'ZSK').length;

  if (records.length > 0 && kskCount === 0) {
    issues.push({
      severity: 'high',
      message: 'No KSK (Key Signing Key) found in DNSKEY records',
      recommendation: 'Ensure a KSK (flags=257) is published for DNSSEC chain of trust'
    });
  }

  if (records.length > 0 && zskCount === 0) {
    issues.push({
      severity: 'medium',
      message: 'No ZSK (Zone Signing Key) found in DNSKEY records',
      recommendation: 'A ZSK (flags=256) is typically used for signing zone records'
    });
  }

  for (const key of records) {
    const algo = DNSSEC_ALGORITHMS[key.algorithm];
    if (algo?.strength === 'deprecated') {
      issues.push({
        severity: 'critical',
        message: `DNSKEY uses deprecated algorithm: ${key.algorithmName} (${key.keyType})`,
        recommendation: 'Migrate to a stronger algorithm immediately'
      });
    } else if (algo?.strength === 'weak') {
      issues.push({
        severity: 'high',
        message: `DNSKEY uses weak algorithm: ${key.algorithmName} (${key.keyType})`,
        recommendation: 'Plan migration to ECDSAP256SHA256 or ED25519'
      });
    }
  }
}

function validateChainConsistency(ds: DSRecord[], dnskey: DNSKEYRecord[], issues: Issue[]): void {
  if (ds.length === 0 && dnskey.length > 0) {
    issues.push({
      severity: 'high',
      message: 'DNSKEY records exist but no DS record found at parent zone',
      recommendation: 'Publish DS record at your domain registrar to complete DNSSEC chain'
    });
  }

  // Check if DS key tags match any DNSKEY
  // (Simplified check - full validation would compute key tags from DNSKEY)
  if (ds.length > 0 && dnskey.length > 0) {
    const dsAlgorithms = new Set(ds.map(d => d.algorithm));
    const dnskeyAlgorithms = new Set(dnskey.filter(k => k.keyType === 'KSK').map(k => k.algorithm));
    
    for (const dsAlgo of dsAlgorithms) {
      if (!dnskeyAlgorithms.has(dsAlgo)) {
        issues.push({
          severity: 'medium',
          message: `DS record algorithm (${DNSSEC_ALGORITHMS[dsAlgo]?.name || dsAlgo}) may not match any KSK`,
          recommendation: 'Verify DS record matches current KSK after key rotation'
        });
      }
    }
  }
}
