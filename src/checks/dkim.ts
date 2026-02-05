/**
 * DKIM (DomainKeys Identified Mail) checker
 */

import dns from 'node:dns/promises';
import crypto from 'node:crypto';
import type { DKIMResult, DKIMSelector, Issue } from '../types.js';
import { COMMON_DKIM_SELECTORS } from '../types.js';

export async function checkDKIM(
  domain: string, 
  selectors: readonly string[] = COMMON_DKIM_SELECTORS
): Promise<DKIMResult> {
  const issues: Issue[] = [];
  const foundSelectors: DKIMSelector[] = [];

  // Check each selector in parallel
  const results = await Promise.allSettled(
    selectors.map(async (selector) => {
      const result = await checkDKIMSelector(domain, selector);
      return { selector, ...result };
    })
  );

  for (const result of results) {
    if (result.status === 'fulfilled') {
      if (result.value.found) {
        foundSelectors.push(result.value);
      }
    }
  }

  if (foundSelectors.length === 0) {
    issues.push({
      severity: 'high',
      message: 'No DKIM records found for common selectors',
      recommendation: 'Configure DKIM signing for your email service'
    });

    return {
      found: false,
      selectors: [],
      issues
    };
  }

  // Check key lengths for found selectors
  for (const sel of foundSelectors) {
    // ed25519 keys are always 256-bit and considered strong
    if (sel.keyType === 'ed25519') {
      // ed25519 is modern and secure, no issue needed
      continue;
    }
    
    // RSA key length checks
    if (sel.keyLength && sel.keyLength < 1024) {
      issues.push({
        severity: 'critical',
        message: `DKIM selector "${sel.selector}" uses weak RSA key (${sel.keyLength}-bit)`,
        recommendation: 'Upgrade to at least 2048-bit RSA key or use ed25519'
      });
    } else if (sel.keyLength && sel.keyLength < 2048) {
      issues.push({
        severity: 'medium',
        message: `DKIM selector "${sel.selector}" uses 1024-bit RSA key`,
        recommendation: 'Consider upgrading to 2048-bit RSA key or ed25519'
      });
    }
  }

  return {
    found: true,
    selectors: foundSelectors,
    issues
  };
}

async function checkDKIMSelector(
  domain: string, 
  selector: string
): Promise<Omit<DKIMSelector, 'selector'>> {
  const dkimDomain = `${selector}._domainkey.${domain}`;
  
  try {
    const txtRecords = await dns.resolveTxt(dkimDomain);
    const dkimRecords = txtRecords
      .map(r => r.join(''))
      .filter(r => r.toLowerCase().includes('v=dkim1') || r.includes('k=') || r.includes('p='));

    if (dkimRecords.length === 0) {
      return { found: false };
    }

    const record = dkimRecords[0];
    const keyType = extractKeyType(record);
    const keyLength = extractKeyLength(record, keyType);

    return {
      found: true,
      keyType,
      keyLength,
      record
    };
  } catch {
    return { found: false };
  }
}

function extractKeyType(record: string): string | undefined {
  const match = record.match(/k=([^;\s]+)/i);
  return match ? match[1].toLowerCase() : 'rsa'; // Default is RSA
}

function extractKeyLength(record: string, keyType?: string): number | undefined {
  // ed25519 keys are always 256-bit
  if (keyType === 'ed25519') {
    return 256;
  }

  const match = record.match(/p=([^;\s]+)/i);
  if (!match) return undefined;

  const publicKey = match[1];
  if (!publicKey || publicKey === '') {
    return 0; // Revoked key
  }

  try {
    // Try to parse as actual RSA public key using crypto module
    const derKey = Buffer.from(publicKey, 'base64');
    
    // Construct PEM format for crypto.createPublicKey
    const pem = `-----BEGIN PUBLIC KEY-----\n${publicKey.match(/.{1,64}/g)?.join('\n')}\n-----END PUBLIC KEY-----`;
    
    try {
      const keyObject = crypto.createPublicKey(pem);
      const keyDetail = keyObject.asymmetricKeyDetails;
      
      if (keyDetail?.modulusLength) {
        return keyDetail.modulusLength;
      }
    } catch {
      // Fall back to estimation if crypto parsing fails
    }
    
    // Fallback: estimate from DER-encoded key size
    // RSA public key in SubjectPublicKeyInfo format:
    // - 24 bytes overhead for ASN.1 structure (approximate)
    // - Rest is modulus + exponent
    // Modulus is typically key_bits/8 bytes + a few bytes for exponent
    const estimatedModulusBytes = derKey.length - 38; // Typical ASN.1 overhead
    const keyBits = Math.max(0, estimatedModulusBytes * 8);
    
    // Round to common key sizes
    if (keyBits <= 600) return 512;
    if (keyBits <= 1100) return 1024;
    if (keyBits <= 2100) return 2048;
    if (keyBits <= 3100) return 3072;
    if (keyBits <= 4200) return 4096;
    return Math.round(keyBits / 256) * 256; // Round to nearest 256
  } catch {
    return undefined;
  }
}
