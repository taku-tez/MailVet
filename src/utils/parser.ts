/**
 * Record parsing utilities
 * Common tag extraction and parsing functions
 */

/**
 * Extract a tag value from a DNS TXT record
 * Handles: tag=value or tag=value;
 */
export function extractTag(record: string, tag: string): string | undefined {
  const regex = new RegExp(`(?:^|;|\\s)${tag}=([^;\\s]+)`, 'i');
  const match = record.match(regex);
  return match ? match[1].trim() : undefined;
}

/**
 * Extract all values for a tag (comma-separated)
 */
export function extractTagValues(record: string, tag: string): string[] {
  const value = extractTag(record, tag);
  if (!value) return [];
  
  return value
    .split(',')
    .map(v => v.trim())
    .filter(v => v.length > 0);
}

/**
 * Parse key=value pairs from a record
 * Returns a Map of tag -> value
 */
export function parseRecordTags(record: string): Map<string, string> {
  const tags = new Map<string, string>();
  const parts = record.split(/\s*;\s*/);
  
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    
    const match = trimmed.match(/^([a-zA-Z0-9_]+)\s*=\s*(.*)$/);
    if (match) {
      const [, tag, value] = match;
      tags.set(tag.toLowerCase(), value.trim());
    }
  }
  
  return tags;
}

/**
 * Parse version tag (v=...)
 */
export function extractVersion(record: string): string | undefined {
  return extractTag(record, 'v');
}

/**
 * Validate URL format
 */
export function isValidUrl(url: string, requireHttps = false): boolean {
  try {
    const parsed = new URL(url);
    if (requireHttps && parsed.protocol !== 'https:') {
      return false;
    }
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Validate email format (basic)
 */
export function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/**
 * Parse mailto: URI and extract email
 * Handles RFC 8460 size limit suffix (!size) and query parameters
 * Examples: mailto:report@example.com, mailto:report@example.com!10m, mailto:report@example.com?subject=TLS
 */
export function parseMailtoUri(uri: string): string | undefined {
  if (!uri.toLowerCase().startsWith('mailto:')) {
    return undefined;
  }
  let email = uri.slice(7);
  
  // Remove query parameters (e.g., ?subject=...)
  email = email.split('?')[0];
  
  // Remove RFC 8460 size limit suffix (e.g., !10m, !1024)
  email = email.split('!')[0];
  
  return isValidEmail(email) ? email : undefined;
}
