/**
 * TLS-RPT (SMTP TLS Reporting) checker
 * 
 * TLS-RPT enables receiving reports about TLS connectivity issues
 * when other mail servers try to send email to your domain.
 */

import type { TLSRPTResult, Issue, EndpointStatus } from '../types.js';
import { dns, isDNSNotFoundError, resolveTxtRecords, filterRecordsByPrefix } from '../utils/dns.js';
import { extractTag, extractTagValues, isValidEmail, parseMailtoUri } from '../utils/parser.js';
import { DNS_PREFIX, DNS_SUBDOMAIN, DEFAULT_HTTP_TIMEOUT_MS } from '../constants.js';

export interface TLSRPTOptions {
  verifyEndpoints?: boolean;
  timeout?: number;
}

const NO_TLS_RPT_RESULT: TLSRPTResult = {
  found: false,
  issues: [{
    severity: 'low',
    message: 'No TLS-RPT record found',
    recommendation: 'Add TLS-RPT to receive reports about TLS connection failures'
  }]
};

export async function checkTLSRPT(
  domain: string, 
  options: TLSRPTOptions = {}
): Promise<TLSRPTResult & { endpointStatus?: EndpointStatus[] }> {
  const issues: Issue[] = [];
  const tlsrptDomain = `${DNS_SUBDOMAIN.TLS_RPT}.${domain}`;

  try {
    const txtRecords = await resolveTxtRecords(tlsrptDomain);
    const tlsrptRecords = filterRecordsByPrefix(txtRecords, DNS_PREFIX.TLS_RPT);

    if (tlsrptRecords.length === 0) {
      return NO_TLS_RPT_RESULT;
    }

    if (tlsrptRecords.length > 1) {
      issues.push({
        severity: 'medium',
        message: `Multiple TLS-RPT records found (${tlsrptRecords.length})`,
        recommendation: 'Only one TLS-RPT record should exist'
      });
    }

    const record = tlsrptRecords[0];
    const version = extractTag(record, 'v');
    const rua = extractTagValues(record, 'rua');
    const endpointStatus: EndpointStatus[] = [];

    // Validate version tag (RFC 8460)
    if (!version) {
      issues.push({
        severity: 'high',
        message: 'TLS-RPT record missing version tag (v=)',
        recommendation: 'Add v=TLSRPTv1 at the start of the TLS-RPT record'
      });
    } else if (version.toLowerCase() !== 'tlsrptv1') {
      issues.push({
        severity: 'medium',
        message: `Unexpected TLS-RPT version: "${version}" (expected TLSRPTv1)`,
        recommendation: 'Use v=TLSRPTv1 for the version tag'
      });
    }

    // Validate reporting addresses
    if (rua.length === 0) {
      issues.push({
        severity: 'high',
        message: 'TLS-RPT record has no reporting addresses (rua=)',
        recommendation: 'Add rua= tag with mailto: or https: reporting endpoints'
      });
    } else {
      await validateEndpoints(rua, options, issues, endpointStatus);
    }

    return {
      found: true,
      record,
      version,
      rua,
      endpointStatus: endpointStatus.length > 0 ? endpointStatus : undefined,
      issues
    };
  } catch (err) {
    if (isDNSNotFoundError(err)) {
      return NO_TLS_RPT_RESULT;
    }
    throw err;
  }
}

async function validateEndpoints(
  rua: string[],
  options: TLSRPTOptions,
  issues: Issue[],
  endpointStatus: EndpointStatus[]
): Promise<void> {
  const timeout = options.timeout || DEFAULT_HTTP_TIMEOUT_MS;

  for (const addr of rua) {
    if (addr.startsWith('mailto:')) {
      await validateMailtoEndpoint(addr, options, issues, endpointStatus);
    } else if (addr.startsWith('https://')) {
      await validateHttpsEndpoint(addr, timeout, options, issues, endpointStatus);
    } else {
      issues.push({
        severity: 'medium',
        message: `Invalid TLS-RPT reporting address: ${addr}`,
        recommendation: 'Use mailto: or https: scheme for reporting addresses'
      });
    }
  }
}

async function validateMailtoEndpoint(
  addr: string,
  options: TLSRPTOptions,
  issues: Issue[],
  endpointStatus: EndpointStatus[]
): Promise<void> {
  // Parse mailto: URI, handling optional query parameters (e.g., mailto:addr?subject=...)
  const email = parseMailtoUri(addr);
  
  if (!email || !isValidEmail(email)) {
    issues.push({
      severity: 'medium',
      message: `Invalid email in TLS-RPT reporting address: ${addr}`,
      recommendation: 'Use a valid email address format'
    });
    endpointStatus.push({ endpoint: addr, type: 'mailto', reachable: false, error: 'Invalid email format' });
    return;
  }

  // Check if the domain part has MX records
  const emailDomain = email.split('@')[1];
  if (emailDomain && options.verifyEndpoints) {
    try {
      await dns.resolveMx(emailDomain);
      endpointStatus.push({ endpoint: addr, type: 'mailto', reachable: true });
    } catch {
      issues.push({
        severity: 'low',
        message: `TLS-RPT reporting email domain "${emailDomain}" has no MX records`,
        recommendation: 'Verify the email address can receive reports'
      });
      endpointStatus.push({ endpoint: addr, type: 'mailto', reachable: false, error: 'No MX records' });
    }
  } else {
    endpointStatus.push({ endpoint: addr, type: 'mailto', reachable: undefined });
  }
}

async function validateHttpsEndpoint(
  addr: string,
  timeout: number,
  options: TLSRPTOptions,
  issues: Issue[],
  endpointStatus: EndpointStatus[]
): Promise<void> {
  if (options.verifyEndpoints) {
    const status = await verifyHttpsEndpoint(addr, timeout);
    endpointStatus.push(status);
    
    if (!status.reachable) {
      issues.push({
        severity: 'medium',
        message: `TLS-RPT HTTPS endpoint unreachable: ${addr}`,
        recommendation: `Verify the endpoint is accessible: ${status.error || 'unknown error'}`
      });
    }
  } else {
    // Basic URL validation
    try {
      new URL(addr);
      endpointStatus.push({ endpoint: addr, type: 'https', reachable: undefined });
    } catch {
      issues.push({
        severity: 'medium',
        message: `Invalid HTTPS URL in TLS-RPT: ${addr}`,
        recommendation: 'Use a valid HTTPS URL'
      });
      endpointStatus.push({ endpoint: addr, type: 'https', reachable: false, error: 'Invalid URL' });
    }
  }
}

async function verifyHttpsEndpoint(url: string, timeout: number): Promise<EndpointStatus> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    const response = await fetch(url, {
      method: 'HEAD',
      signal: controller.signal,
      redirect: 'follow',
    });
    
    clearTimeout(timeoutId);
    
    // Accept various status codes that indicate the endpoint is responsive
    const acceptableStatus = [200, 201, 202, 204, 301, 302, 303, 307, 308, 400, 405];
    const reachable = acceptableStatus.includes(response.status) || 
                      (response.status >= 200 && response.status < 400);
    
    return {
      endpoint: url,
      type: 'https',
      reachable,
      error: reachable ? undefined : `HTTP ${response.status}`
    };
  } catch (err) {
    const error = err as Error;
    let errorMsg = 'Unknown error';
    
    if (error.name === 'AbortError') {
      errorMsg = 'Timeout';
    } else if (error.message.includes('ENOTFOUND')) {
      errorMsg = 'DNS resolution failed';
    } else if (error.message.includes('ECONNREFUSED')) {
      errorMsg = 'Connection refused';
    } else if (error.message.includes('certificate')) {
      errorMsg = 'TLS certificate error';
    } else {
      errorMsg = error.message;
    }
    
    return {
      endpoint: url,
      type: 'https',
      reachable: false,
      error: errorMsg
    };
  }
}
