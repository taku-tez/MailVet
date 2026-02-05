/**
 * ARC (Authenticated Received Chain) support checker
 * 
 * ARC is used by mail forwarders to preserve authentication results.
 * Unlike SPF/DKIM/DMARC, ARC doesn't have a DNS record for configuration.
 * 
 * This check verifies:
 * 1. DKIM is properly configured (required for ARC signing)
 * 2. Domain has proper email authentication foundation
 * 
 * Note: Actual ARC validation happens at the receiving mail server level.
 */

import type { DKIMResult, DMARCResult, SPFResult, Issue } from '../types.js';

export interface ARCReadinessResult {
  ready: boolean;
  canSign: boolean;
  canValidate: boolean;
  issues: Issue[];
}

/**
 * Check if domain is ready for ARC
 * 
 * ARC readiness requires:
 * - DKIM configured (for signing ARC-Message-Signature)
 * - DMARC configured (ARC is typically used to preserve auth across forwards)
 */
export function checkARCReadiness(
  spf: SPFResult,
  dkim: DKIMResult,
  dmarc: DMARCResult
): ARCReadinessResult {
  const issues: Issue[] = [];
  let canSign = true;
  let canValidate = true;

  // Check DKIM (required for ARC signing)
  if (!dkim.found) {
    canSign = false;
    issues.push({
      severity: 'medium',
      message: 'DKIM not configured - cannot sign ARC headers',
      recommendation: 'Configure DKIM to enable ARC signing capability'
    });
  } else {
    // Check for strong DKIM keys (ed25519 is always considered strong)
    const hasStrongKey = dkim.selectors.some(s => 
      s.keyType === 'ed25519' || (s.keyLength && s.keyLength >= 2048)
    );
    if (!hasStrongKey) {
      issues.push({
        severity: 'low',
        message: 'DKIM keys should be 2048-bit RSA or ed25519 for ARC',
        recommendation: 'Upgrade DKIM keys to 2048-bit RSA or ed25519 for better ARC compatibility'
      });
    }
  }

  // Check DMARC (recommended for ARC usage)
  if (!dmarc.found) {
    issues.push({
      severity: 'low',
      message: 'DMARC not configured - ARC benefits are limited',
      recommendation: 'Configure DMARC to fully benefit from ARC authentication chain'
    });
  } else if (dmarc.policy === 'none') {
    issues.push({
      severity: 'info',
      message: 'DMARC policy is "none" - ARC can help when upgrading to stricter policy',
      recommendation: 'ARC preserves authentication when emails are forwarded'
    });
  }

  // Check SPF (supplementary)
  if (!spf.found) {
    issues.push({
      severity: 'info',
      message: 'SPF not configured - ARC can help preserve SPF results across forwards',
      recommendation: 'Configure SPF for complete email authentication'
    });
  }

  // Determine overall readiness
  const ready = dkim.found && dmarc.found;

  if (ready && issues.length === 0) {
    issues.push({
      severity: 'info',
      message: 'Domain is ARC-ready',
      recommendation: 'Your email infrastructure can participate in ARC chains'
    });
  }

  return {
    ready,
    canSign,
    canValidate: true, // Any domain can validate ARC headers
    issues
  };
}

/**
 * Information about ARC for display purposes
 */
export const ARC_INFO = {
  description: 'ARC preserves email authentication results across forwards',
  benefit: 'Helps legitimate forwarded emails pass DMARC checks',
  requirement: 'DKIM must be configured to sign ARC headers',
  note: 'ARC is header-based, not DNS-based. This check verifies prerequisites.'
};
