/**
 * BIMI (Brand Indicators for Message Identification) checker
 * 
 * BIMI allows brands to display their logo in email clients.
 * Requires valid DMARC with p=quarantine or p=reject.
 */

import type { BIMIResult, Issue } from '../types.js';
import { isDNSNotFoundError, resolveTxtRecords, filterRecordsByPrefix } from '../utils/dns.js';
import { extractTag } from '../utils/parser.js';
import { DNS_PREFIX, DNS_SUBDOMAIN } from '../constants.js';

const NO_BIMI_RESULT: BIMIResult = {
  found: false,
  issues: [{
    severity: 'info',
    message: 'No BIMI record found',
    recommendation: 'Consider adding BIMI to display your brand logo in email clients'
  }]
};

export async function checkBIMI(domain: string): Promise<BIMIResult> {
  const issues: Issue[] = [];
  const bimiDomain = `${DNS_SUBDOMAIN.BIMI}.${domain}`;

  try {
    const txtRecords = await resolveTxtRecords(bimiDomain);
    const bimiRecords = filterRecordsByPrefix(txtRecords, DNS_PREFIX.BIMI);

    if (bimiRecords.length === 0) {
      return NO_BIMI_RESULT;
    }

    if (bimiRecords.length > 1) {
      issues.push({
        severity: 'medium',
        message: `Multiple BIMI records found (${bimiRecords.length})`,
        recommendation: 'Only one BIMI record should exist'
      });
    }

    const record = bimiRecords[0];
    const version = extractTag(record, 'v');
    const logoUrl = extractTag(record, 'l');
    const certificateUrl = extractTag(record, 'a');

    // Validate version tag
    if (!version) {
      issues.push({
        severity: 'high',
        message: 'BIMI record missing version tag (v=)',
        recommendation: 'Add v=BIMI1 at the start of the BIMI record'
      });
    } else if (version.toUpperCase() !== 'BIMI1') {
      issues.push({
        severity: 'medium',
        message: `Unexpected BIMI version: "${version}" (expected BIMI1)`,
        recommendation: 'Use v=BIMI1 for the version tag'
      });
    }

    // Validate logo URL
    validateLogoUrl(logoUrl, issues);

    // Check VMC certificate (optional but recommended)
    if (!certificateUrl) {
      issues.push({
        severity: 'low',
        message: 'No VMC (Verified Mark Certificate) specified',
        recommendation: 'Consider obtaining a VMC for broader email client support'
      });
    }

    return {
      found: true,
      record,
      version,
      logoUrl,
      certificateUrl,
      issues
    };
  } catch (err) {
    if (isDNSNotFoundError(err)) {
      return NO_BIMI_RESULT;
    }
    throw err;
  }
}

function validateLogoUrl(logoUrl: string | undefined, issues: Issue[]): void {
  if (!logoUrl) {
    issues.push({
      severity: 'high',
      message: 'BIMI record missing logo URL (l=)',
      recommendation: 'Add l= tag with URL to your SVG logo'
    });
  } else if (!logoUrl.startsWith('https://')) {
    issues.push({
      severity: 'high',
      message: 'BIMI logo URL must use HTTPS',
      recommendation: 'Update logo URL to use HTTPS'
    });
  } else if (!logoUrl.toLowerCase().endsWith('.svg')) {
    issues.push({
      severity: 'medium',
      message: 'BIMI logo should be SVG Tiny PS format',
      recommendation: 'Use SVG Tiny PS format for maximum compatibility'
    });
  }
}
