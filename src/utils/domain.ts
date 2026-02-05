/**
 * Domain manipulation utilities
 */

// Use Node.js built-in punycode (deprecated but still available)
import punycode from 'node:punycode';

/**
 * Convert IDN (Internationalized Domain Name) to ASCII (Punycode)
 */
export function toASCII(domain: string): string {
  try {
    // Handle each label separately
    return domain.split('.').map(label => {
      // Check if label contains non-ASCII characters
      if (/[^\x00-\x7F]/.test(label)) {
        return 'xn--' + punycode.encode(label);
      }
      return label;
    }).join('.');
  } catch {
    return domain; // Return as-is if conversion fails
  }
}

/**
 * Normalize domain for consistent DNS lookups
 * - Lowercase
 * - Remove protocol prefixes
 * - Remove trailing dots
 * - Remove leading/trailing whitespace
 * - Remove path components
 * - Remove port numbers
 */
export function normalizeDomain(domain: string): string {
  let normalized = domain.toLowerCase().trim();
  
  // Remove protocol prefix if present
  if (normalized.startsWith('http://') || normalized.startsWith('https://')) {
    try {
      normalized = new URL(normalized).hostname;
    } catch {
      // If URL parsing fails, try manual extraction
      normalized = normalized.replace(/^https?:\/\//, '').split('/')[0];
    }
  }
  
  // Remove path components (e.g., "example.com/path" -> "example.com")
  normalized = normalized.split('/')[0];
  
  // Remove port if present (e.g., "example.com:8080" -> "example.com")
  normalized = normalized.split(':')[0];
  
  // Remove trailing dot (DNS absolute notation)
  normalized = normalized.replace(/\.$/, '');
  
  // Remove any remaining whitespace
  normalized = normalized.replace(/\s/g, '');
  
  // Convert IDN to ASCII (Punycode) for DNS compatibility
  if (/[^\x00-\x7F]/.test(normalized)) {
    normalized = toASCII(normalized);
  }
  
  return normalized;
}

/**
 * Build DNS subdomain (e.g., "_dmarc.example.com")
 */
export function buildDNSSubdomain(prefix: string, domain: string): string {
  return `${prefix}.${domain}`;
}

/**
 * Validate domain format (basic check)
 */
export function isValidDomain(domain: string): boolean {
  // Basic domain validation
  if (!domain || domain.length === 0 || domain.length > 253) {
    return false;
  }
  
  // Must have at least one dot
  if (!domain.includes('.')) {
    return false;
  }
  
  // Each label must be 1-63 characters
  const labels = domain.split('.');
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) {
      return false;
    }
    // Labels must start/end with alphanumeric
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(label)) {
      return false;
    }
  }
  
  return true;
}
