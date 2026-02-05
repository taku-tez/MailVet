/**
 * Output formatting for CLI
 */

import type { DomainResult, Grade, Issue, Severity } from './types.js';

const GRADE_COLORS: Record<Grade, string> = {
  'A': '\x1b[32m', // Green
  'B': '\x1b[32m', // Green
  'C': '\x1b[33m', // Yellow
  'D': '\x1b[33m', // Yellow
  'F': '\x1b[31m', // Red
};

const SEVERITY_ICONS: Record<Severity, string> = {
  'critical': '🔴',
  'high': '🟠',
  'medium': '🟡',
  'low': '🔵',
  'info': 'ℹ️',
};

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

const CHECK = '✅';
const WARN = '⚠️';
const FAIL = '❌';
const INFO = 'ℹ️';

export function formatResult(result: DomainResult, verbose = false): string {
  const lines: string[] = [];
  const gradeColor = GRADE_COLORS[result.grade];

  // Header
  lines.push('');
  lines.push(`${BOLD}📧 ${result.domain}${RESET} - Grade: ${gradeColor}${BOLD}${result.grade}${RESET} (${result.score}/100)`);
  lines.push('');

  // SPF
  lines.push(formatSection('SPF', result.spf.found, () => {
    const sectionLines: string[] = [];
    if (result.spf.record) {
      sectionLines.push(`   Record: ${truncate(result.spf.record, 60)}`);
    }
    if (result.spf.mechanism) {
      const icon = result.spf.mechanism === '-all' ? CHECK : 
                   result.spf.mechanism === '~all' ? WARN : FAIL;
      sectionLines.push(`   ${icon} Mechanism: ${result.spf.mechanism}`);
    }
    if (result.spf.lookupCount !== undefined) {
      const icon = result.spf.lookupCount <= 7 ? CHECK :
                   result.spf.lookupCount <= 10 ? WARN : FAIL;
      sectionLines.push(`   ${icon} DNS lookups: ${result.spf.lookupCount}/10`);
    }
    if (verbose && result.spf.includes?.length) {
      sectionLines.push(`   ${INFO} Includes: ${result.spf.includes.join(', ')}`);
    }
    if (verbose) {
      sectionLines.push(...formatIssues(result.spf.issues));
    }
    return sectionLines;
  }));

  // DKIM
  lines.push(formatSection('DKIM', result.dkim.found, () => {
    const sectionLines: string[] = [];
    for (const sel of result.dkim.selectors) {
      if (sel.found) {
        const keyInfo = sel.keyLength ? ` (${sel.keyLength}-bit ${sel.keyType || 'rsa'})` : '';
        const icon = (sel.keyType === 'ed25519' || (sel.keyLength && sel.keyLength >= 2048)) ? CHECK : WARN;
        sectionLines.push(`   ${icon} ${sel.selector}._domainkey${keyInfo}`);
      }
    }
    if (verbose) {
      sectionLines.push(...formatIssues(result.dkim.issues));
    }
    return sectionLines;
  }));

  // DMARC
  lines.push(formatSection('DMARC', result.dmarc.found, () => {
    const sectionLines: string[] = [];
    if (result.dmarc.record) {
      sectionLines.push(`   Record: ${truncate(result.dmarc.record, 60)}`);
    }
    if (result.dmarc.policy) {
      const icon = result.dmarc.policy === 'reject' ? CHECK :
                   result.dmarc.policy === 'quarantine' ? WARN : FAIL;
      sectionLines.push(`   ${icon} Policy: p=${result.dmarc.policy}`);
    }
    if (result.dmarc.reportingEnabled !== undefined) {
      const icon = result.dmarc.reportingEnabled ? CHECK : WARN;
      sectionLines.push(`   ${icon} Reporting: ${result.dmarc.reportingEnabled ? 'enabled' : 'not configured'}`);
    }
    if (result.dmarc.pct !== undefined && result.dmarc.pct !== 100) {
      sectionLines.push(`   ${WARN} Coverage: ${result.dmarc.pct}%`);
    }
    if (verbose) {
      sectionLines.push(...formatIssues(result.dmarc.issues));
    }
    return sectionLines;
  }));

  // MX
  lines.push(formatSection('MX', result.mx.found, () => {
    const sectionLines: string[] = [];
    for (const mx of result.mx.records.slice(0, 3)) {
      sectionLines.push(`   ${CHECK} ${mx.exchange} (pri: ${mx.priority})`);
    }
    if (result.mx.records.length > 3) {
      sectionLines.push(`   ${DIM}... and ${result.mx.records.length - 3} more${RESET}`);
    }
    // Show provider if detected
    const providerIssue = result.mx.issues.find(i => i.message.includes('provider detected'));
    if (providerIssue) {
      sectionLines.push(`   ${INFO} ${providerIssue.message}`);
    }
    if (verbose) {
      sectionLines.push(...formatIssues(result.mx.issues.filter(i => !i.message.includes('provider detected'))));
    }
    return sectionLines;
  }));

  // BIMI (optional)
  if (result.bimi) {
    lines.push(formatSection('BIMI', result.bimi.found, () => {
      const sectionLines: string[] = [];
      if (result.bimi?.logoUrl) {
        sectionLines.push(`   ${CHECK} Logo: ${truncate(result.bimi.logoUrl, 50)}`);
      }
      if (result.bimi?.certificateUrl) {
        sectionLines.push(`   ${CHECK} VMC: configured`);
      } else if (result.bimi?.found) {
        sectionLines.push(`   ${WARN} No VMC certificate`);
      }
      // Show high severity issues (e.g., DMARC prerequisite) in non-verbose mode
      if (!verbose) {
        const criticalIssues = result.bimi?.issues.filter(i => i.severity === 'high' || i.severity === 'critical') || [];
        for (const issue of criticalIssues) {
          sectionLines.push(`   ${FAIL} ${issue.message}`);
        }
      } else {
        sectionLines.push(...formatIssues(result.bimi?.issues || []));
      }
      return sectionLines;
    }));
  }

  // MTA-STS (optional)
  if (result.mtaSts) {
    lines.push(formatSection('MTA-STS', result.mtaSts.found, () => {
      const sectionLines: string[] = [];
      if (result.mtaSts?.policy?.mode) {
        const icon = result.mtaSts.policy.mode === 'enforce' ? CHECK :
                     result.mtaSts.policy.mode === 'testing' ? WARN : FAIL;
        sectionLines.push(`   ${icon} Mode: ${result.mtaSts.policy.mode}`);
      }
      if (result.mtaSts?.policy?.maxAge) {
        const days = Math.floor(result.mtaSts.policy.maxAge / 86400);
        sectionLines.push(`   ${INFO} Max age: ${days} days`);
      }
      if (verbose && result.mtaSts?.policy?.mx && result.mtaSts.policy.mx.length > 0) {
        sectionLines.push(`   ${INFO} MX patterns: ${result.mtaSts.policy.mx.join(', ')}`);
      }
      if (verbose) {
        sectionLines.push(...formatIssues(result.mtaSts?.issues || []));
      }
      return sectionLines;
    }));
  }

  // TLS-RPT (optional)
  if (result.tlsRpt) {
    lines.push(formatSection('TLS-RPT', result.tlsRpt.found, () => {
      const sectionLines: string[] = [];
      if (result.tlsRpt?.rua && result.tlsRpt.rua.length > 0) {
        sectionLines.push(`   ${CHECK} Reporting: ${result.tlsRpt.rua.length} endpoint(s)`);
        if (verbose) {
          for (const endpoint of result.tlsRpt.rua) {
            sectionLines.push(`      - ${truncate(endpoint, 50)}`);
          }
        }
      }
      if (verbose) {
        sectionLines.push(...formatIssues(result.tlsRpt?.issues || []));
      }
      return sectionLines;
    }));
  }

  // ARC Readiness (optional)
  if (result.arc) {
    lines.push(formatSection('ARC', result.arc.ready, () => {
      const sectionLines: string[] = [];
      if (result.arc?.canSign) {
        sectionLines.push(`   ${CHECK} Can sign ARC headers`);
      }
      if (!result.arc?.ready) {
        sectionLines.push(`   ${WARN} Missing prerequisites for full ARC support`);
      }
      if (verbose) {
        sectionLines.push(...formatIssues(result.arc?.issues || []));
      }
      return sectionLines;
    }));
  }

  // All Issues (verbose mode)
  if (verbose) {
    const allIssues = collectAllIssues(result);
    if (allIssues.length > 0) {
      lines.push('');
      lines.push(`${BOLD}All Issues (${allIssues.length}):${RESET}`);
      
      // Group by severity
      const bySeverity = groupBy(allIssues, i => i.issue.severity);
      for (const severity of ['critical', 'high', 'medium', 'low', 'info'] as Severity[]) {
        const issues = bySeverity.get(severity);
        if (issues && issues.length > 0) {
          for (const { check, issue } of issues) {
            const icon = SEVERITY_ICONS[issue.severity];
            lines.push(`  ${icon} [${check}] ${issue.message}`);
            if (issue.recommendation) {
              lines.push(`      → ${issue.recommendation}`);
            }
          }
        }
      }
    }
  }

  // Recommendations
  if (result.recommendations.length > 0) {
    lines.push('');
    lines.push(`${BOLD}Recommendations:${RESET}`);
    const maxRecs = verbose ? result.recommendations.length : 5;
    for (let i = 0; i < Math.min(maxRecs, result.recommendations.length); i++) {
      lines.push(`  ${i + 1}. ${result.recommendations[i]}`);
    }
    if (!verbose && result.recommendations.length > 5) {
      lines.push(`  ${DIM}... and ${result.recommendations.length - 5} more (use --verbose)${RESET}`);
    }
  }

  // Error
  if (result.error) {
    lines.push('');
    lines.push(`${FAIL} Error: ${result.error}`);
  }

  lines.push('');
  return lines.join('\n');
}

/**
 * Format issues for inline display
 */
function formatIssues(issues: Issue[]): string[] {
  const lines: string[] = [];
  const significantIssues = issues.filter(i => i.severity !== 'info');
  
  for (const issue of significantIssues.slice(0, 3)) {
    const icon = SEVERITY_ICONS[issue.severity];
    lines.push(`   ${icon} ${issue.message}`);
  }
  
  if (significantIssues.length > 3) {
    lines.push(`   ${DIM}... and ${significantIssues.length - 3} more issues${RESET}`);
  }
  
  return lines;
}

interface CheckIssue {
  check: string;
  issue: Issue;
}

/**
 * Collect all issues from all checks
 */
function collectAllIssues(result: DomainResult): CheckIssue[] {
  const issues: CheckIssue[] = [];
  
  for (const issue of result.spf.issues) {
    issues.push({ check: 'SPF', issue });
  }
  for (const issue of result.dkim.issues) {
    issues.push({ check: 'DKIM', issue });
  }
  for (const issue of result.dmarc.issues) {
    issues.push({ check: 'DMARC', issue });
  }
  for (const issue of result.mx.issues) {
    issues.push({ check: 'MX', issue });
  }
  if (result.bimi) {
    for (const issue of result.bimi.issues) {
      issues.push({ check: 'BIMI', issue });
    }
  }
  if (result.mtaSts) {
    for (const issue of result.mtaSts.issues) {
      issues.push({ check: 'MTA-STS', issue });
    }
  }
  if (result.tlsRpt) {
    for (const issue of result.tlsRpt.issues) {
      issues.push({ check: 'TLS-RPT', issue });
    }
  }
  if (result.arc) {
    for (const issue of result.arc.issues) {
      issues.push({ check: 'ARC', issue });
    }
  }
  
  return issues;
}

/**
 * Group array items by key
 */
function groupBy<T, K>(items: T[], keyFn: (item: T) => K): Map<K, T[]> {
  const map = new Map<K, T[]>();
  for (const item of items) {
    const key = keyFn(item);
    const group = map.get(key) || [];
    group.push(item);
    map.set(key, group);
  }
  return map;
}

function formatSection(
  name: string, 
  found: boolean, 
  detailsFn: () => string[]
): string {
  const lines: string[] = [];
  const icon = found ? CHECK : FAIL;
  const status = found ? 'Found' : 'Not found';
  
  lines.push(`${BOLD}${name}${RESET}   ${icon} ${status}`);
  
  if (found) {
    lines.push(...detailsFn());
  }
  
  return lines.join('\n');
}

export function formatSummary(results: DomainResult[]): string {
  const lines: string[] = [];
  
  const grades: Record<Grade, number> = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const r of results) {
    grades[r.grade]++;
  }

  lines.push('');
  lines.push(`${BOLD}📊 Scan Summary${RESET}`);
  lines.push(`   Total: ${results.length} domains`);
  lines.push('');
  lines.push('   Grade Distribution:');
  lines.push(`   ${GRADE_COLORS['A']}A: ${grades.A}${RESET}  ${GRADE_COLORS['B']}B: ${grades.B}${RESET}  ${GRADE_COLORS['C']}C: ${grades.C}${RESET}  ${GRADE_COLORS['D']}D: ${grades.D}${RESET}  ${GRADE_COLORS['F']}F: ${grades.F}${RESET}`);
  lines.push('');

  // Show worst performers
  const failures = results
    .filter(r => r.grade === 'F' || r.grade === 'D')
    .sort((a, b) => a.score - b.score)
    .slice(0, 10);

  if (failures.length > 0) {
    lines.push(`${BOLD}⚠️  Needs Attention:${RESET}`);
    for (const r of failures) {
      const gradeColor = GRADE_COLORS[r.grade];
      lines.push(`   ${gradeColor}${r.grade}${RESET} ${r.domain} - ${r.recommendations[0] || 'Multiple issues'}`);
    }
    lines.push('');
  }

  // Show best performers
  const best = results
    .filter(r => r.grade === 'A')
    .slice(0, 5);

  if (best.length > 0) {
    lines.push(`${BOLD}✅ Top Performers:${RESET}`);
    for (const r of best) {
      lines.push(`   ${GRADE_COLORS['A']}A${RESET} ${r.domain} (${r.score}/100)`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + '...';
}
