/**
 * Domain email security analyzer
 */

import { checkSPF, checkDKIM, checkDMARC, checkMX, checkBIMI, checkMTASTS, checkTLSRPT, checkARCReadiness } from '../checks/index.js';
import { calculateGrade, generateRecommendations } from './scorer.js';
import type { DomainResult, ScanOptions, SPFResult, DKIMResult, DMARCResult, MXResult, BIMIResult, MTASTSResult, TLSRPTResult } from '../types.js';
import { COMMON_DKIM_SELECTORS, normalizeDomain } from '../types.js';

/**
 * Create a failed result for a check that errored
 */
function createFailedResult<T extends { found: boolean; issues: Array<{ severity: string; message: string; recommendation?: string }> }>(
  checkName: string, 
  error: string, 
  defaults: Omit<T, 'found' | 'issues'>
): T {
  return {
    found: false,
    issues: [{
      severity: 'high' as const,
      message: `${checkName} check failed: ${error}`,
      recommendation: 'Check DNS configuration and try again'
    }],
    ...defaults
  } as T;
}

export async function analyzeDomain(
  domain: string, 
  options: ScanOptions = {}
): Promise<DomainResult> {
  // Normalize domain using shared function
  domain = normalizeDomain(domain);

  // Run all checks in parallel with optional timeout using allSettled
  const dkimSelectors = options.dkimSelectors || COMMON_DKIM_SELECTORS;
  const timeout = options.timeout || 10000;
  
  const wrapWithTimeout = async <T>(promise: Promise<T>, name: string): Promise<T> => {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`${name} check timed out`)), timeout);
    });
    return Promise.race([promise, timeoutPromise]);
  };

  // Use Promise.allSettled to handle individual failures gracefully
  const [spfResult, dkimResult, dmarcResult, mxResult, bimiResult, mtaStsResult, tlsRptResult] = await Promise.allSettled([
    wrapWithTimeout(checkSPF(domain), 'SPF'),
    wrapWithTimeout(checkDKIM(domain, dkimSelectors), 'DKIM'),
    wrapWithTimeout(checkDMARC(domain), 'DMARC'),
    wrapWithTimeout(checkMX(domain), 'MX'),
    wrapWithTimeout(checkBIMI(domain), 'BIMI'),
    wrapWithTimeout(checkMTASTS(domain), 'MTA-STS'),
    wrapWithTimeout(checkTLSRPT(domain), 'TLS-RPT'),
  ]);

  // Extract results, creating failed results for rejected promises
  const spf: SPFResult = spfResult.status === 'fulfilled' 
    ? spfResult.value 
    : createFailedResult<SPFResult>('SPF', spfResult.reason?.message || 'Unknown error', {});

  const dkim: DKIMResult = dkimResult.status === 'fulfilled'
    ? dkimResult.value
    : createFailedResult<DKIMResult>('DKIM', dkimResult.reason?.message || 'Unknown error', { selectors: [] });

  const dmarc: DMARCResult = dmarcResult.status === 'fulfilled'
    ? dmarcResult.value
    : createFailedResult<DMARCResult>('DMARC', dmarcResult.reason?.message || 'Unknown error', {});

  const mx: MXResult = mxResult.status === 'fulfilled'
    ? mxResult.value
    : createFailedResult<MXResult>('MX', mxResult.reason?.message || 'Unknown error', { records: [] });

  const bimi: BIMIResult = bimiResult.status === 'fulfilled'
    ? bimiResult.value
    : createFailedResult<BIMIResult>('BIMI', bimiResult.reason?.message || 'Unknown error', {});

  const mtaSts: MTASTSResult = mtaStsResult.status === 'fulfilled'
    ? mtaStsResult.value
    : createFailedResult<MTASTSResult>('MTA-STS', mtaStsResult.reason?.message || 'Unknown error', {});

  const tlsRpt: TLSRPTResult = tlsRptResult.status === 'fulfilled'
    ? tlsRptResult.value
    : createFailedResult<TLSRPTResult>('TLS-RPT', tlsRptResult.reason?.message || 'Unknown error', {});

  // ARC readiness is derived from other checks
  const arc = checkARCReadiness(spf, dkim, dmarc);

  // BIMI prerequisite check: requires DMARC quarantine or reject
  if (bimi.found) {
    if (!dmarc.found) {
      bimi.issues.push({
        severity: 'high',
        message: 'BIMI requires DMARC to be configured',
        recommendation: 'Add a DMARC record with p=quarantine or p=reject'
      });
    } else if (dmarc.policy === 'none' || !dmarc.policy) {
      bimi.issues.push({
        severity: 'high',
        message: 'BIMI requires DMARC policy of quarantine or reject',
        recommendation: 'Upgrade DMARC policy from none to quarantine or reject'
      });
    }
  }

  // MTA-STS / MX consistency check
  if (mtaSts.found && mtaSts.policy?.mx && mtaSts.policy.mx.length > 0 && mx.found) {
    const mtaStsMxPatterns = mtaSts.policy.mx;
    const mxHosts = mx.records.map(r => r.exchange.toLowerCase().replace(/\.$/, ''));
    
    for (const mxHost of mxHosts) {
      const matched = mtaStsMxPatterns.some(pattern => {
        const p = pattern.toLowerCase();
        if (p.startsWith('*.')) {
          // Wildcard: *.example.com matches mail.example.com
          const suffix = p.slice(1); // .example.com
          return mxHost.endsWith(suffix) || mxHost === p.slice(2);
        }
        return mxHost === p;
      });
      
      if (!matched) {
        mtaSts.issues.push({
          severity: 'high',
          message: `MX host "${mxHost}" not covered by MTA-STS policy`,
          recommendation: `Add "mx: ${mxHost}" or appropriate wildcard to MTA-STS policy`
        });
      }
    }
  }

  const { grade, score } = calculateGrade(spf, dkim, dmarc, mx, bimi, mtaSts, tlsRpt, arc);
  const recommendations = generateRecommendations(spf, dkim, dmarc, mx, bimi, mtaSts, tlsRpt, arc);

  // Collect any check-level errors for the error field
  const errors: string[] = [];
  if (spfResult.status === 'rejected') errors.push(`SPF: ${spfResult.reason?.message}`);
  if (dkimResult.status === 'rejected') errors.push(`DKIM: ${dkimResult.reason?.message}`);
  if (dmarcResult.status === 'rejected') errors.push(`DMARC: ${dmarcResult.reason?.message}`);
  if (mxResult.status === 'rejected') errors.push(`MX: ${mxResult.reason?.message}`);

  return {
    domain,
    grade,
    score,
    timestamp: new Date().toISOString(),
    spf,
    dkim,
    dmarc,
    mx,
    bimi,
    mtaSts,
    tlsRpt,
    arc,
    recommendations,
    ...(errors.length > 0 ? { error: errors.join('; ') } : {}),
  };
}

export async function analyzeMultiple(
  domains: string[],
  options: ScanOptions = {}
): Promise<DomainResult[]> {
  const concurrency = options.concurrency || 5;
  const results: DomainResult[] = [];

  // Process in batches
  for (let i = 0; i < domains.length; i += concurrency) {
    const batch = domains.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(domain => analyzeDomain(domain, options))
    );
    results.push(...batchResults);
  }

  return results;
}
