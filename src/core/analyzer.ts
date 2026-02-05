/**
 * Domain email security analyzer
 */

import { checkSPF, checkDKIM, checkDMARC, checkMX, checkBIMI, checkMTASTS, checkTLSRPT, checkARCReadiness } from '../checks/index.js';
import { calculateGrade, generateRecommendations } from './scorer.js';
import type { DomainResult, ScanOptions } from '../types.js';
import { COMMON_DKIM_SELECTORS } from '../types.js';

export async function analyzeDomain(
  domain: string, 
  options: ScanOptions = {}
): Promise<DomainResult> {
  const startTime = Date.now();
  
  // Normalize domain
  domain = domain.toLowerCase().trim();
  if (domain.startsWith('http://') || domain.startsWith('https://')) {
    domain = new URL(domain).hostname;
  }
  // Remove trailing dot if present
  domain = domain.replace(/\.$/, '');

  try {
    // Run all checks in parallel with optional timeout
    const dkimSelectors = options.dkimSelectors || COMMON_DKIM_SELECTORS;
    const timeout = options.timeout || 10000;
    
    const wrapWithTimeout = async <T>(promise: Promise<T>, name: string): Promise<T> => {
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error(`${name} check timed out`)), timeout);
      });
      return Promise.race([promise, timeoutPromise]);
    };

    const [spf, dkim, dmarc, mx, bimi, mtaSts, tlsRpt] = await Promise.all([
      wrapWithTimeout(checkSPF(domain), 'SPF'),
      wrapWithTimeout(checkDKIM(domain, dkimSelectors), 'DKIM'),
      wrapWithTimeout(checkDMARC(domain), 'DMARC'),
      wrapWithTimeout(checkMX(domain), 'MX'),
      wrapWithTimeout(checkBIMI(domain), 'BIMI'),
      wrapWithTimeout(checkMTASTS(domain), 'MTA-STS'),
      wrapWithTimeout(checkTLSRPT(domain), 'TLS-RPT'),
    ]);

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

    const { grade, score } = calculateGrade(spf, dkim, dmarc, mx);
    const recommendations = generateRecommendations(spf, dkim, dmarc, mx);

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
    };
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    return {
      domain,
      grade: 'F',
      score: 0,
      timestamp: new Date().toISOString(),
      spf: { found: false, issues: [] },
      dkim: { found: false, selectors: [], issues: [] },
      dmarc: { found: false, issues: [] },
      mx: { found: false, records: [], issues: [] },
      recommendations: [],
      error,
    };
  }
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
