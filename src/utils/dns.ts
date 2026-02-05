/**
 * DNS utility functions
 * Common DNS operations and error handling
 */

import dns from 'node:dns/promises';

/**
 * Check if error is a DNS "not found" error
 */
export function isDNSNotFoundError(err: unknown): boolean {
  const error = err as NodeJS.ErrnoException;
  return error.code === 'ENOTFOUND' || error.code === 'ENODATA';
}

/**
 * Resolve TXT records with common error handling
 */
export async function resolveTxtRecords(domain: string): Promise<string[]> {
  const txtRecords = await dns.resolveTxt(domain);
  return txtRecords.map(r => r.join(''));
}

/**
 * Filter TXT records by prefix
 */
export function filterRecordsByPrefix(records: string[], prefix: string): string[] {
  return records.filter(r => r.toLowerCase().startsWith(prefix.toLowerCase()));
}

/**
 * Resolve TXT records filtered by prefix (common pattern)
 */
export async function resolvePrefixedTxtRecords(
  domain: string, 
  prefix: string
): Promise<string[]> {
  const records = await resolveTxtRecords(domain);
  return filterRecordsByPrefix(records, prefix);
}

/**
 * Safe DNS resolution with not-found handling
 * Returns empty array if domain/record not found
 */
export async function safeResolveTxt(domain: string): Promise<string[]> {
  try {
    return await resolveTxtRecords(domain);
  } catch (err) {
    if (isDNSNotFoundError(err)) {
      return [];
    }
    throw err;
  }
}

/**
 * MX record type
 */
export interface MxRecord {
  exchange: string;
  priority: number;
}

/**
 * Safe MX resolution with not-found handling
 */
export async function safeResolveMx(domain: string): Promise<MxRecord[]> {
  try {
    return await dns.resolveMx(domain);
  } catch (err) {
    if (isDNSNotFoundError(err)) {
      return [];
    }
    throw err;
  }
}

/**
 * Simple in-memory DNS cache for deduplication within a single domain scan.
 * TXT and MX records for the same domain are often queried multiple times
 * across SPF/DKIM/DMARC/MTA-STS/TLS-RPT checks.
 */
const dnsCache = new Map<string, { value: unknown; expires: number }>();
const DNS_CACHE_TTL_MS = 60000; // 1 minute

export function clearDnsCache(): void {
  dnsCache.clear();
}

async function cachedResolve<T>(key: string, resolver: () => Promise<T>): Promise<T> {
  const now = Date.now();
  const cached = dnsCache.get(key);
  if (cached && cached.expires > now) {
    return cached.value as T;
  }
  const value = await resolver();
  dnsCache.set(key, { value, expires: now + DNS_CACHE_TTL_MS });
  return value;
}

/**
 * Cached TXT record resolution
 */
export async function cachedResolveTxt(domain: string): Promise<string[]> {
  return cachedResolve(`txt:${domain}`, () => safeResolveTxt(domain));
}

/**
 * Cached MX record resolution
 */
export async function cachedResolveMx(domain: string): Promise<MxRecord[]> {
  return cachedResolve(`mx:${domain}`, () => safeResolveMx(domain));
}

export { dns };
