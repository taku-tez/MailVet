/**
 * TLS-RPT (SMTP TLS Reporting) checker
 * 
 * TLS-RPT enables receiving reports about TLS connectivity issues
 * when other mail servers try to send email to your domain.
 */

import dns from 'node:dns/promises';
import type { Issue } from '../types.js';

export interface TLSRPTResult {
  found: boolean;
  record?: string;
  version?: string;
  rua?: string[];
  endpointStatus?: EndpointStatus[];
  issues: Issue[];
}

export interface EndpointStatus {
  endpoint: string;
  type: 'mailto' | 'https';
  reachable?: boolean;
  error?: string;
}

export interface TLSRPTOptions {
  verifyEndpoints?: boolean;
  timeout?: number;
}

export async function checkTLSRPT(
  domain: string, 
  options: TLSRPTOptions = {}
): Promise<TLSRPTResult> {
  const issues: Issue[] = [];
  const tlsrptDomain = `_smtp._tls.${domain}`;

  try {
    const txtRecords = await dns.resolveTxt(tlsrptDomain);
    const tlsrptRecords = txtRecords
      .map(r => r.join(''))
      .filter(r => r.toLowerCase().startsWith('v=tlsrpt'));

    if (tlsrptRecords.length === 0) {
      return {
        found: false,
        issues: [{
          severity: 'low',
          message: 'No TLS-RPT record found',
          recommendation: 'Add TLS-RPT to receive reports about TLS connection failures'
        }]
      };
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
    const rua = extractReportingAddresses(record);
    const endpointStatus: EndpointStatus[] = [];

    // Check reporting addresses
    if (rua.length === 0) {
      issues.push({
        severity: 'high',
        message: 'TLS-RPT record has no reporting addresses (rua=)',
        recommendation: 'Add rua= tag with mailto: or https: reporting endpoints'
      });
    } else {
      // Validate addresses
      for (const addr of rua) {
        if (addr.startsWith('mailto:')) {
          const email = addr.slice(7);
          // Basic email format validation
          if (!email.includes('@') || !email.includes('.')) {
            issues.push({
              severity: 'medium',
              message: `Invalid email in TLS-RPT reporting address: ${addr}`,
              recommendation: 'Use a valid email address format'
            });
            endpointStatus.push({ endpoint: addr, type: 'mailto', reachable: false, error: 'Invalid email format' });
          } else {
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
              endpointStatus.push({ endpoint: addr, type: 'mailto' });
            }
          }
        } else if (addr.startsWith('https://')) {
          // Validate HTTPS endpoint
          if (options.verifyEndpoints) {
            const status = await verifyHttpsEndpoint(addr, options.timeout || 5000);
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
              endpointStatus.push({ endpoint: addr, type: 'https' });
            } catch {
              issues.push({
                severity: 'medium',
                message: `Invalid HTTPS URL in TLS-RPT: ${addr}`,
                recommendation: 'Use a valid HTTPS URL'
              });
              endpointStatus.push({ endpoint: addr, type: 'https', reachable: false, error: 'Invalid URL' });
            }
          }
        } else {
          issues.push({
            severity: 'medium',
            message: `Invalid TLS-RPT reporting address: ${addr}`,
            recommendation: 'Use mailto: or https: scheme for reporting addresses'
          });
        }
      }
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
    if ((err as NodeJS.ErrnoException).code === 'ENOTFOUND' ||
        (err as NodeJS.ErrnoException).code === 'ENODATA') {
      return {
        found: false,
        issues: [{
          severity: 'low',
          message: 'No TLS-RPT record found',
          recommendation: 'Add TLS-RPT to receive reports about TLS connection failures'
        }]
      };
    }
    throw err;
  }
}

/**
 * Verify HTTPS endpoint reachability with HEAD request
 */
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
    
    // Accept 2xx, 3xx, 405 (Method Not Allowed - POST-only endpoints), 
    // and 400 (Bad Request - expects specific format)
    const acceptableStatus = [200, 201, 202, 204, 301, 302, 303, 307, 308, 400, 405];
    const reachable = acceptableStatus.includes(response.status) || (response.status >= 200 && response.status < 400);
    
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

function extractTag(record: string, tag: string): string | undefined {
  const regex = new RegExp(`${tag}=([^;\\s]+)`, 'i');
  const match = record.match(regex);
  return match ? match[1] : undefined;
}

function extractReportingAddresses(record: string): string[] {
  const match = record.match(/rua=([^;]+)/i);
  if (!match) return [];

  return match[1]
    .split(',')
    .map(addr => addr.trim())
    .filter(addr => addr.length > 0);
}
