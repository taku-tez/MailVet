/**
 * DKIM (DomainKeys Identified Mail) checker
 */

import crypto from 'node:crypto';
import type { DKIMResult, DKIMSelector, Issue } from '../types.js';
import { cachedResolveTxt } from '../utils/dns.js';
import { extractTag, parseRecordTags } from '../utils/parser.js';
import { COMMON_DKIM_SELECTORS, DKIM_WEAK_KEY_BITS, DKIM_STRONG_KEY_BITS, DNS_SUBDOMAIN } from '../constants.js';

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

  // Check key lengths and status for found selectors
  for (const sel of foundSelectors) {
    // Check for revoked key (p= empty)
    if (sel.keyLength === 0) {
      issues.push({
        severity: 'critical',
        message: `DKIM selector "${sel.selector}" has a revoked key (p= is empty)`,
        recommendation: 'Generate and publish a new DKIM key pair for this selector, or remove the selector if no longer in use'
      });
      continue;
    }

    // Check for missing or unparseable key
    if (sel.keyLength === undefined) {
      issues.push({
        severity: 'high',
        message: `DKIM selector "${sel.selector}" has missing or invalid public key (p=)`,
        recommendation: 'Ensure the DKIM record contains a valid base64-encoded public key'
      });
      continue;
    }

    // ed25519 keys are always 256-bit and considered strong
    if (sel.keyType === 'ed25519') {
      continue;
    }
    
    // RSA key length checks
    if (sel.keyLength < DKIM_WEAK_KEY_BITS) {
      issues.push({
        severity: 'critical',
        message: `DKIM selector "${sel.selector}" uses weak RSA key (${sel.keyLength}-bit)`,
        recommendation: `Upgrade to at least ${DKIM_STRONG_KEY_BITS}-bit RSA key or use ed25519`
      });
    } else if (sel.keyLength < DKIM_STRONG_KEY_BITS) {
      issues.push({
        severity: 'medium',
        message: `DKIM selector "${sel.selector}" uses ${DKIM_WEAK_KEY_BITS}-bit RSA key`,
        recommendation: `Consider upgrading to ${DKIM_STRONG_KEY_BITS}-bit RSA key or ed25519`
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
    const joinedRecords = await cachedResolveTxt(dkimDomain);
    
    // Find valid DKIM record using strict validation
    const dkimRecord = findValidDKIMRecord(joinedRecords);

    if (!dkimRecord) {
      return { found: false };
    }

    const keyType = extractKeyType(dkimRecord);
    const keyLength = extractKeyLength(dkimRecord, keyType);

    return {
      found: true,
      keyType,
      keyLength,
      record: dkimRecord
    };
  } catch {
    return { found: false };
  }
}

/**
 * Find a valid DKIM record from TXT records using strict validation
 * Prioritizes v=DKIM1 records, then validates tag structure
 */
function findValidDKIMRecord(records: string[]): string | undefined {
  // First, look for records with explicit v=DKIM1
  const explicitDKIM = records.find(r => 
    r.toLowerCase().trim().startsWith('v=dkim1') ||
    /;\s*v\s*=\s*dkim1/i.test(r)
  );
  
  if (explicitDKIM) {
    return explicitDKIM;
  }
  
  // Fall back: check for records that have proper DKIM tag structure (p= is required)
  for (const record of records) {
    const tags = parseRecordTags(record);
    
    // Must have p= tag (public key) - this is required for DKIM
    if (!tags.has('p')) {
      continue;
    }
    
    // If k= is present, it should be a valid key type
    const keyType = tags.get('k');
    if (keyType && !['rsa', 'ed25519'].includes(keyType.toLowerCase())) {
      continue;
    }
    
    // Looks like a valid DKIM record
    return record;
  }
  
  return undefined;
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
