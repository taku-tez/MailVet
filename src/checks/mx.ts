/**
 * MX (Mail Exchange) record checker
 */

import type { MXResult, MXRecord, Issue } from '../types.js';
import { cachedResolveMx } from '../utils/dns.js';
import { EMAIL_PROVIDERS } from '../constants.js';

const NO_MX_RESULT: MXResult = {
  found: false,
  records: [],
  issues: [{
    severity: 'info',
    message: 'No MX records found',
    recommendation: 'Add MX records if this domain should receive email'
  }]
};

export async function checkMX(domain: string): Promise<MXResult> {
  const mxRecords = await cachedResolveMx(domain);

  if (mxRecords.length === 0) {
    return NO_MX_RESULT;
  }

  const issues: Issue[] = [];

  // Sort by priority
  const records: MXRecord[] = mxRecords
    .sort((a, b) => a.priority - b.priority)
    .map(r => ({
      exchange: r.exchange,
      priority: r.priority
    }));

  // Check for Null MX (RFC 7505) - domain explicitly does not receive email
  const hasNullMX = records.some(r => r.exchange === '.' || r.exchange === '');
  
  if (hasNullMX) {
    // Null MX means the domain intentionally does not accept mail
    // Skip other validations (redundancy, priority, provider) as they don't apply
    issues.push({
      severity: 'info',
      message: 'Null MX record (RFC 7505) - domain does not accept email',
      recommendation: 'This is an intentional configuration to reject email'
    });
    
    return {
      found: true,
      records,
      issues
    };
  }

  // Run validation checks (only for non-Null MX domains)
  checkRedundancy(records, issues);
  checkPriorityDistribution(records, issues);
  checkEmailProvider(records, issues);

  return {
    found: true,
    records,
    issues
  };
}

function checkRedundancy(records: MXRecord[], issues: Issue[]): void {
  if (records.length === 1) {
    issues.push({
      severity: 'low',
      message: 'Only one MX record - no redundancy',
      recommendation: 'Consider adding backup MX servers'
    });
  }
}

function checkPriorityDistribution(records: MXRecord[], issues: Issue[]): void {
  if (records.length <= 1) return;
  
  const priorities = records.map(r => r.priority);
  const allSamePriority = priorities.every(p => p === priorities[0]);
  
  if (allSamePriority) {
    issues.push({
      severity: 'info',
      message: 'All MX records have same priority - round-robin delivery',
      recommendation: 'Consider different priorities for primary/backup servers'
    });
  }
}

function checkEmailProvider(records: MXRecord[], issues: Issue[]): void {
  const provider = identifyEmailProvider(records);
  if (provider) {
    issues.push({
      severity: 'info',
      message: `Email provider detected: ${provider}`
    });
  }
}

function identifyEmailProvider(records: MXRecord[]): string | undefined {
  const exchanges = records.map(r => r.exchange.toLowerCase());
  
  for (const { pattern, name } of EMAIL_PROVIDERS) {
    if (exchanges.some(ex => pattern.test(ex))) {
      return name;
    }
  }

  return undefined;
}
