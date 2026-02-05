/**
 * DMARC (Domain-based Message Authentication, Reporting & Conformance) checker
 * RFC 7489 compliant implementation
 */

import dns from 'node:dns/promises';
import type { DMARCResult, Issue } from '../types.js';

// Valid DMARC tags per RFC 7489
const VALID_DMARC_TAGS = new Set([
  'v', 'p', 'sp', 'rua', 'ruf', 'adkim', 'aspf', 'fo', 'rf', 'ri', 'pct'
]);

export async function checkDMARC(domain: string): Promise<DMARCResult> {
  const issues: Issue[] = [];
  const dmarcDomain = `_dmarc.${domain}`;

  try {
    const txtRecords = await dns.resolveTxt(dmarcDomain);
    const dmarcRecords = txtRecords
      .map(r => r.join(''))
      .filter(r => r.toLowerCase().trim().startsWith('v=dmarc1'));

    if (dmarcRecords.length === 0) {
      return {
        found: false,
        issues: [{
          severity: 'critical',
          message: 'No DMARC record found',
          recommendation: 'Add a DMARC record to specify email authentication policy'
        }]
      };
    }

    if (dmarcRecords.length > 1) {
      issues.push({
        severity: 'high',
        message: `Multiple DMARC records found (${dmarcRecords.length})`,
        recommendation: 'Only one DMARC record should exist'
      });
    }

    const record = dmarcRecords[0];
    
    // Parse all tags robustly
    const parsedTags = parseDMARCTags(record);
    
    // Check for invalid/unknown tags
    const invalidTags = parsedTags.invalidTags;
    if (invalidTags.length > 0) {
      issues.push({
        severity: 'low',
        message: `Unknown DMARC tags found: ${invalidTags.join(', ')}`,
        recommendation: 'Remove or correct invalid tags to ensure proper parsing'
      });
    }

    // Check for malformed tags
    if (parsedTags.malformedTags.length > 0) {
      issues.push({
        severity: 'medium',
        message: `Malformed DMARC tags: ${parsedTags.malformedTags.join(', ')}`,
        recommendation: 'Fix tag formatting (should be tag=value)'
      });
    }

    const policy = parsedTags.tags.get('p') as 'none' | 'quarantine' | 'reject' | undefined;
    const subdomainPolicy = parsedTags.tags.get('sp') as 'none' | 'quarantine' | 'reject' | undefined;
    const rua = parseReportingAddresses(parsedTags.tags.get('rua'));
    const ruf = parseReportingAddresses(parsedTags.tags.get('ruf'));
    const pct = parsedTags.tags.get('pct') ? parseInt(parsedTags.tags.get('pct')!, 10) : undefined;

    // Check policy strength
    if (!policy) {
      issues.push({
        severity: 'critical',
        message: 'DMARC record has no policy (p=) specified',
        recommendation: 'Add a policy: p=reject for maximum protection'
      });
    } else if (!['none', 'quarantine', 'reject'].includes(policy)) {
      issues.push({
        severity: 'critical',
        message: `Invalid DMARC policy value: "${policy}"`,
        recommendation: 'Use p=none, p=quarantine, or p=reject'
      });
    } else if (policy === 'none') {
      issues.push({
        severity: 'high',
        message: 'DMARC policy is "none" - no enforcement',
        recommendation: 'Change to p=quarantine or p=reject after monitoring'
      });
    } else if (policy === 'quarantine') {
      issues.push({
        severity: 'medium',
        message: 'DMARC policy is "quarantine" - consider upgrading',
        recommendation: 'Change to p=reject for maximum protection when ready'
      });
    }

    // Check subdomain policy
    if (subdomainPolicy && !['none', 'quarantine', 'reject'].includes(subdomainPolicy)) {
      issues.push({
        severity: 'medium',
        message: `Invalid subdomain policy value: "${subdomainPolicy}"`,
        recommendation: 'Use sp=none, sp=quarantine, or sp=reject'
      });
    } else if (policy === 'reject' && subdomainPolicy && subdomainPolicy !== 'reject') {
      issues.push({
        severity: 'medium',
        message: `Subdomain policy (sp=${subdomainPolicy}) is weaker than main policy`,
        recommendation: 'Consider setting sp=reject as well'
      });
    }

    // Check reporting
    const reportingEnabled = rua.length > 0 || ruf.length > 0;
    if (!reportingEnabled) {
      issues.push({
        severity: 'medium',
        message: 'No DMARC reporting configured',
        recommendation: 'Add rua= to receive aggregate reports'
      });
    }

    // Validate reporting addresses
    for (const addr of [...rua, ...ruf]) {
      if (!addr.startsWith('mailto:') && !addr.startsWith('https://')) {
        issues.push({
          severity: 'medium',
          message: `Invalid reporting address format: "${addr}"`,
          recommendation: 'Reporting addresses should use mailto: or https: scheme'
        });
      }
    }

    // Check percentage
    if (pct !== undefined) {
      if (isNaN(pct) || pct < 0 || pct > 100) {
        issues.push({
          severity: 'medium',
          message: `Invalid pct value: must be 0-100`,
          recommendation: 'Set pct to a value between 0 and 100'
        });
      } else if (pct < 100) {
        issues.push({
          severity: 'low',
          message: `DMARC policy applies to only ${pct}% of messages`,
          recommendation: 'Consider increasing pct to 100 after testing'
        });
      }
    }

    // Check alignment modes
    const adkim = parsedTags.tags.get('adkim');
    const aspf = parsedTags.tags.get('aspf');
    if (adkim && !['r', 's'].includes(adkim.toLowerCase())) {
      issues.push({
        severity: 'low',
        message: `Invalid adkim value: "${adkim}" (should be r or s)`,
        recommendation: 'Use adkim=r (relaxed) or adkim=s (strict)'
      });
    }
    if (aspf && !['r', 's'].includes(aspf.toLowerCase())) {
      issues.push({
        severity: 'low',
        message: `Invalid aspf value: "${aspf}" (should be r or s)`,
        recommendation: 'Use aspf=r (relaxed) or aspf=s (strict)'
      });
    }

    return {
      found: true,
      record,
      policy: ['none', 'quarantine', 'reject'].includes(policy || '') ? policy as 'none' | 'quarantine' | 'reject' : undefined,
      subdomainPolicy: ['none', 'quarantine', 'reject'].includes(subdomainPolicy || '') ? subdomainPolicy as 'none' | 'quarantine' | 'reject' : undefined,
      reportingEnabled,
      rua,
      ruf,
      pct: (pct !== undefined && !isNaN(pct) && pct >= 0 && pct <= 100) ? pct : undefined,
      issues
    };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOTFOUND' ||
        (err as NodeJS.ErrnoException).code === 'ENODATA') {
      return {
        found: false,
        issues: [{
          severity: 'critical',
          message: 'No DMARC record found',
          recommendation: 'Add a DMARC record to specify email authentication policy'
        }]
      };
    }
    throw err;
  }
}

interface ParsedDMARCTags {
  tags: Map<string, string>;
  invalidTags: string[];
  malformedTags: string[];
}

/**
 * Parse DMARC record tags robustly
 * Handles whitespace variations, missing delimiters, etc.
 */
function parseDMARCTags(record: string): ParsedDMARCTags {
  const tags = new Map<string, string>();
  const invalidTags: string[] = [];
  const malformedTags: string[] = [];

  // Split by semicolon, handling various whitespace
  const parts = record.split(/\s*;\s*/);
  
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;

    // Match tag=value pattern (allowing whitespace around =)
    const match = trimmed.match(/^([a-zA-Z0-9]+)\s*=\s*(.*)$/);
    if (match) {
      const [, tag, value] = match;
      const tagLower = tag.toLowerCase();
      
      if (VALID_DMARC_TAGS.has(tagLower)) {
        tags.set(tagLower, value.trim());
      } else {
        invalidTags.push(tag);
      }
    } else if (trimmed.includes('=')) {
      // Has = but doesn't match pattern
      malformedTags.push(trimmed);
    }
    // Skip parts without = (like standalone text)
  }

  return { tags, invalidTags, malformedTags };
}

/**
 * Parse comma-separated reporting addresses
 */
function parseReportingAddresses(value: string | undefined): string[] {
  if (!value) return [];
  
  return value
    .split(',')
    .map(addr => addr.trim())
    .filter(addr => addr.length > 0);
}
