/**
 * SPF (Sender Policy Framework) checker
 * RFC 7208 compliant implementation
 */

import type { SPFResult, Issue } from '../types.js';
import { dns, isDNSNotFoundError, resolveTxtRecords, filterRecordsByPrefix } from '../utils/dns.js';
import { SPF_MAX_DNS_LOOKUPS, SPF_MAX_RECURSION_DEPTH, DNS_PREFIX } from '../constants.js';

export async function checkSPF(domain: string): Promise<SPFResult> {
  const issues: Issue[] = [];
  
  try {
    const txtRecords = await dns.resolveTxt(domain);
    const spfRecords = txtRecords
      .map(r => r.join(''))
      .filter(r => r.toLowerCase().startsWith('v=spf1'));

    if (spfRecords.length === 0) {
      return {
        found: false,
        issues: [{
          severity: 'critical',
          message: 'No SPF record found',
          recommendation: 'Add an SPF record to prevent email spoofing'
        }]
      };
    }

    if (spfRecords.length > 1) {
      issues.push({
        severity: 'high',
        message: `Multiple SPF records found (${spfRecords.length})`,
        recommendation: 'Only one SPF record should exist per domain'
      });
    }

    const record = spfRecords[0];
    const mechanism = extractMechanism(record);
    const includes = extractIncludes(record);
    
    // RFC 7208 compliant recursive DNS lookup counting
    const lookupResult = await countDNSLookupsRecursive(domain, record, new Set(), 0);
    const lookupCount = lookupResult.count;
    
    if (lookupResult.loopDetected) {
      issues.push({
        severity: 'high',
        message: 'SPF record contains circular reference',
        recommendation: 'Remove circular include/redirect references'
      });
    }

    // Check mechanism strength
    if (mechanism === '+all') {
      issues.push({
        severity: 'critical',
        message: 'SPF uses +all (pass all) - effectively no protection',
        recommendation: 'Change to -all (hardfail) for maximum protection'
      });
    } else if (mechanism === '?all') {
      issues.push({
        severity: 'high',
        message: 'SPF uses ?all (neutral) - weak protection',
        recommendation: 'Change to -all (hardfail) for maximum protection'
      });
    } else if (mechanism === '~all') {
      issues.push({
        severity: 'medium',
        message: 'SPF uses ~all (softfail) - consider using hardfail',
        recommendation: 'Change to -all (hardfail) when ready for stricter enforcement'
      });
    } else if (mechanism === '-all') {
      // Good!
    } else {
      issues.push({
        severity: 'high',
        message: 'SPF record has no all mechanism',
        recommendation: 'Add -all at the end of your SPF record'
      });
    }

    // Check DNS lookup count
    if (lookupCount > SPF_MAX_DNS_LOOKUPS) {
      issues.push({
        severity: 'high',
        message: `SPF record exceeds DNS lookup limit (${lookupCount}/${SPF_MAX_DNS_LOOKUPS})`,
        recommendation: 'Reduce the number of include/redirect mechanisms or flatten the SPF record'
      });
    } else if (lookupCount > 7) {
      issues.push({
        severity: 'medium',
        message: `SPF record is close to DNS lookup limit (${lookupCount}/${SPF_MAX_DNS_LOOKUPS})`,
        recommendation: 'Consider flattening SPF record to avoid future issues'
      });
    }

    // Check for deprecated ptr mechanism
    if (record.toLowerCase().includes(' ptr')) {
      issues.push({
        severity: 'medium',
        message: 'SPF record uses deprecated ptr mechanism',
        recommendation: 'Replace ptr with explicit IP ranges or include statements'
      });
    }

    return {
      found: true,
      record,
      mechanism,
      lookupCount,
      includes,
      issues
    };
  } catch (err) {
    if (isDNSNotFoundError(err)) {
      return {
        found: false,
        issues: [{
          severity: 'critical',
          message: 'No SPF record found',
          recommendation: 'Add an SPF record to prevent email spoofing'
        }]
      };
    }
    throw err;
  }
}

function extractMechanism(record: string): string | undefined {
  const match = record.match(/([+\-~?]?)all\b/i);
  if (match) {
    const qualifier = match[1] || '+'; // Default is +
    return `${qualifier}all`;
  }
  return undefined;
}

function extractIncludes(record: string): string[] {
  const includes: string[] = [];
  const regex = /include:([^\s]+)/gi;
  let match;
  while ((match = regex.exec(record)) !== null) {
    includes.push(match[1]);
  }
  return includes;
}

interface LookupResult {
  count: number;
  loopDetected: boolean;
}

/**
 * RFC 7208 compliant recursive DNS lookup counting
 * Counts include, a, mx, ptr, exists, redirect mechanisms recursively
 */
async function countDNSLookupsRecursive(
  domain: string,
  record: string,
  visited: Set<string>,
  depth: number
): Promise<LookupResult> {
  if (depth > SPF_MAX_RECURSION_DEPTH) {
    return { count: 0, loopDetected: true };
  }

  // Check for circular reference using domain + record hash
  // This allows the same domain to appear with different records (rare but valid)
  // while detecting actual loops where the same domain+record is visited twice
  const normalizedDomain = domain.toLowerCase();
  const recordKey = `${normalizedDomain}:${record.slice(0, 100)}`; // Truncate for efficiency
  
  if (visited.has(recordKey)) {
    return { count: 0, loopDetected: true };
  }
  visited.add(recordKey);

  let count = 0;
  let loopDetected = false;
  const lower = record.toLowerCase();

  // Count direct mechanisms that require DNS lookups (RFC 7208 Section 4.6.4)
  // Each of these counts as 1 DNS lookup:
  // - include: 1 lookup + recursive lookups from included record
  // - a: 1 lookup
  // - mx: 1 lookup (+ implicit A lookups, but those don't count against limit)
  // - ptr: 1 lookup (deprecated)
  // - exists: 1 lookup
  // - redirect: 0 lookups itself, but the target record's lookups count

  // Count 'a' mechanisms (a, a:domain, a:domain/prefix)
  const aMatches = lower.match(/\ba(:|\/|\s|$)/g);
  if (aMatches) count += aMatches.length;

  // Count 'mx' mechanisms
  const mxMatches = lower.match(/\bmx(:|\/|\s|$)/g);
  if (mxMatches) count += mxMatches.length;

  // Count 'ptr' mechanisms
  const ptrMatches = lower.match(/\bptr(:|\/|\s|$)/g);
  if (ptrMatches) count += ptrMatches.length;

  // Count 'exists' mechanisms
  const existsMatches = lower.match(/\bexists:/g);
  if (existsMatches) count += existsMatches.length;

  // Process include: mechanisms recursively
  const includeRegex = /include:([^\s]+)/gi;
  let includeMatch;
  while ((includeMatch = includeRegex.exec(record)) !== null) {
    count++; // The include itself is 1 lookup
    
    const includeDomain = includeMatch[1];
    try {
      const includeTxt = await dns.resolveTxt(includeDomain);
      const includeSPF = includeTxt
        .map(r => r.join(''))
        .find(r => r.toLowerCase().startsWith('v=spf1'));
      
      if (includeSPF) {
        const recursiveResult = await countDNSLookupsRecursive(
          includeDomain,
          includeSPF,
          visited,
          depth + 1
        );
        count += recursiveResult.count;
        if (recursiveResult.loopDetected) loopDetected = true;
      }
    } catch {
      // DNS lookup failed, but we still counted the lookup attempt
    }
  }

  // Process redirect= modifier (replaces the current record)
  const redirectMatch = lower.match(/redirect=([^\s]+)/);
  if (redirectMatch) {
    const redirectDomain = redirectMatch[1];
    try {
      const redirectTxt = await dns.resolveTxt(redirectDomain);
      const redirectSPF = redirectTxt
        .map(r => r.join(''))
        .find(r => r.toLowerCase().startsWith('v=spf1'));
      
      if (redirectSPF) {
        const recursiveResult = await countDNSLookupsRecursive(
          redirectDomain,
          redirectSPF,
          visited,
          depth + 1
        );
        count += recursiveResult.count;
        if (recursiveResult.loopDetected) loopDetected = true;
      }
    } catch {
      // DNS lookup failed
    }
  }

  return { count, loopDetected };
}
