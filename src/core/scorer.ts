/**
 * Email security scoring and grading
 */

import type { 
  SPFResult, 
  DKIMResult, 
  DMARCResult, 
  MXResult, 
  BIMIResult,
  MTASTSResult,
  TLSRPTResult,
  ARCReadinessResult,
  Grade,
  Issue,
  Severity
} from '../types.js';

// Penalty points for issues by severity
const SEVERITY_PENALTIES: Record<Severity, number> = {
  critical: 15,
  high: 8,
  medium: 3,
  low: 1,
  info: 0,
};

interface GradeResult {
  grade: Grade;
  score: number;
}

/**
 * Calculate grade based on email security configuration
 * 
 * Base scoring (max 100 points from core checks):
 * - SPF: max 35 points
 * - DKIM: max 25 points
 * - DMARC: max 40 points
 * 
 * Bonus points (up to +15, capped at 100 total):
 * - BIMI: +3 (with VMC: +5)
 * - MTA-STS enforce: +4 (testing: +2)
 * - TLS-RPT: +3
 * - ARC ready: +3
 * 
 * Grading criteria:
 * - A (90-100): SPF (-all) + DKIM + DMARC (reject)
 * - B (75-89): SPF + DKIM + DMARC (quarantine)
 * - C (50-74): SPF + DMARC (any policy)
 * - D (25-49): SPF only
 * - F (0-24): Nothing or major issues
 */
export function calculateGrade(
  spf: SPFResult,
  dkim: DKIMResult,
  dmarc: DMARCResult,
  mx: MXResult,
  bimi?: BIMIResult,
  mtaSts?: MTASTSResult,
  tlsRpt?: TLSRPTResult,
  arc?: ARCReadinessResult
): GradeResult {
  let score = 0;

  // SPF scoring (max 35 points)
  if (spf.found) {
    score += 15; // Base points for having SPF
    
    if (spf.mechanism === '-all') {
      score += 20; // Hardfail
    } else if (spf.mechanism === '~all') {
      score += 10; // Softfail
    } else if (spf.mechanism === '?all') {
      score += 5; // Neutral
    }
    // +all gets no additional points
    
    // Penalty for too many DNS lookups
    if (spf.lookupCount && spf.lookupCount > 10) {
      score -= 10;
    }
  }

  // DKIM scoring (max 25 points)
  if (dkim.found) {
    score += 15; // Base points for having DKIM
    
    // Check key strength (ed25519 is always considered strong)
    const hasStrongKey = dkim.selectors.some(s => 
      s.keyType === 'ed25519' || (s.keyLength && s.keyLength >= 2048)
    );
    if (hasStrongKey) {
      score += 10;
    } else {
      const hasAnyKey = dkim.selectors.some(s => s.keyLength && s.keyLength >= 1024);
      if (hasAnyKey) {
        score += 5;
      }
    }
  }

  // DMARC scoring (max 40 points)
  if (dmarc.found) {
    score += 10; // Base points for having DMARC
    
    if (dmarc.policy === 'reject') {
      score += 20;
    } else if (dmarc.policy === 'quarantine') {
      score += 12;
    } else if (dmarc.policy === 'none') {
      score += 3;
    }
    
    // Reporting bonus
    if (dmarc.reportingEnabled) {
      score += 5;
    }
    
    // Full coverage bonus
    if (dmarc.pct === undefined || dmarc.pct === 100) {
      score += 5;
    }
  }

  // Bonus points for advanced features (max +15)
  let bonus = 0;

  // BIMI bonus (+3 base, +5 with VMC)
  if (bimi?.found) {
    // Only award points if DMARC prerequisite is met
    const dmarcOk = dmarc.found && dmarc.policy && dmarc.policy !== 'none';
    if (dmarcOk) {
      bonus += 3;
      if (bimi.certificateUrl) {
        bonus += 2; // Additional for VMC
      }
    }
  }

  // MTA-STS bonus (+4 enforce, +2 testing)
  if (mtaSts?.found && mtaSts.policy?.mode) {
    if (mtaSts.policy.mode === 'enforce') {
      bonus += 4;
    } else if (mtaSts.policy.mode === 'testing') {
      bonus += 2;
    }
  }

  // TLS-RPT bonus (+3)
  if (tlsRpt?.found && tlsRpt.rua && tlsRpt.rua.length > 0) {
    bonus += 3;
  }

  // ARC readiness bonus (+3)
  if (arc?.ready && arc.canSign) {
    bonus += 3;
  }

  // Apply bonus (capped so total doesn't exceed 100)
  score = Math.min(100, score + Math.min(bonus, 15));

  // Apply penalties for critical/high severity issues (misconfigurations)
  const penalty = calculateIssuePenalty(spf, dkim, dmarc, mx, bimi, mtaSts, tlsRpt, arc);
  score = Math.max(0, score - penalty);

  // Clamp score to 0-100
  score = Math.max(0, Math.min(100, score));

  // Determine grade
  let grade: Grade;
  if (score >= 90) {
    grade = 'A';
  } else if (score >= 75) {
    grade = 'B';
  } else if (score >= 50) {
    grade = 'C';
  } else if (score >= 25) {
    grade = 'D';
  } else {
    grade = 'F';
  }

  return { grade, score };
}

/**
 * Calculate penalty based on issue severity across all checks
 * Focuses on critical/high issues that indicate misconfigurations
 */
function calculateIssuePenalty(
  spf: SPFResult,
  dkim: DKIMResult,
  dmarc: DMARCResult,
  mx: MXResult,
  bimi?: BIMIResult,
  mtaSts?: MTASTSResult,
  tlsRpt?: TLSRPTResult,
  arc?: ARCReadinessResult
): number {
  // Collect all issues
  const allIssues: Issue[] = [
    ...spf.issues,
    ...dkim.issues,
    ...dmarc.issues,
    ...mx.issues,
    ...(bimi?.issues || []),
    ...(mtaSts?.issues || []),
    ...(tlsRpt?.issues || []),
    ...(arc?.issues || []),
  ];

  // Calculate total penalty (cap per severity to prevent excessive deductions)
  let penalty = 0;
  const severityCounts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const issue of allIssues) {
    severityCounts[issue.severity]++;
  }

  // Apply penalties with caps:
  // - Critical: up to 3 issues counted (max 45 point penalty)
  // - High: up to 3 issues counted (max 24 point penalty)
  // - Medium: up to 5 issues counted (max 15 point penalty)
  // - Low/Info: no penalty
  penalty += Math.min(severityCounts.critical, 3) * SEVERITY_PENALTIES.critical;
  penalty += Math.min(severityCounts.high, 3) * SEVERITY_PENALTIES.high;
  penalty += Math.min(severityCounts.medium, 5) * SEVERITY_PENALTIES.medium;

  return penalty;
}

/**
 * Generate prioritized recommendations
 */
export function generateRecommendations(
  spf: SPFResult,
  dkim: DKIMResult,
  dmarc: DMARCResult,
  mx: MXResult,
  bimi?: BIMIResult,
  mtaSts?: MTASTSResult,
  tlsRpt?: TLSRPTResult,
  arc?: ARCReadinessResult
): string[] {
  const recommendations: Array<{ priority: number; text: string }> = [];

  // Critical: Missing records
  if (!spf.found) {
    recommendations.push({
      priority: 1,
      text: 'Add an SPF record to specify authorized email senders'
    });
  }

  if (!dmarc.found) {
    recommendations.push({
      priority: 2,
      text: 'Add a DMARC record to define your email authentication policy'
    });
  }

  if (!dkim.found) {
    recommendations.push({
      priority: 3,
      text: 'Configure DKIM signing for your email service'
    });
  }

  // High: Weak configurations
  if (spf.found && spf.mechanism === '+all') {
    recommendations.push({
      priority: 4,
      text: 'Change SPF from +all to -all to block unauthorized senders'
    });
  } else if (spf.found && spf.mechanism === '~all') {
    recommendations.push({
      priority: 7,
      text: 'Consider changing SPF from ~all (softfail) to -all (hardfail)'
    });
  }

  if (dmarc.found && dmarc.policy === 'none') {
    recommendations.push({
      priority: 5,
      text: 'Upgrade DMARC policy from none to quarantine or reject'
    });
  } else if (dmarc.found && dmarc.policy === 'quarantine') {
    recommendations.push({
      priority: 8,
      text: 'Consider upgrading DMARC policy from quarantine to reject'
    });
  }

  // Medium: Improvements
  if (dkim.found) {
    const hasWeakKey = dkim.selectors.some(s => s.keyLength && s.keyLength < 2048);
    if (hasWeakKey) {
      recommendations.push({
        priority: 6,
        text: 'Upgrade DKIM keys to 2048-bit for better security'
      });
    }
  }

  if (dmarc.found && !dmarc.reportingEnabled) {
    recommendations.push({
      priority: 9,
      text: 'Add DMARC reporting (rua=) to monitor authentication failures'
    });
  }

  if (spf.found && spf.lookupCount && spf.lookupCount > 7) {
    recommendations.push({
      priority: 10,
      text: `Reduce SPF DNS lookups (${spf.lookupCount}/10) to avoid evaluation failures`
    });
  }

  // Advanced feature recommendations
  if (!mtaSts?.found) {
    recommendations.push({
      priority: 11,
      text: 'Add MTA-STS to enforce TLS for incoming mail'
    });
  } else if (mtaSts.policy?.mode === 'testing') {
    recommendations.push({
      priority: 14,
      text: 'Upgrade MTA-STS from testing to enforce mode'
    });
  }

  if (!tlsRpt?.found) {
    recommendations.push({
      priority: 12,
      text: 'Add TLS-RPT to receive TLS connection failure reports'
    });
  }

  // BIMI recommendation (only if DMARC is properly configured)
  if (dmarc.found && dmarc.policy && dmarc.policy !== 'none') {
    if (!bimi?.found) {
      recommendations.push({
        priority: 15,
        text: 'Add BIMI to display your brand logo in email clients'
      });
    } else if (bimi.found && !bimi.certificateUrl) {
      recommendations.push({
        priority: 16,
        text: 'Add a VMC certificate to BIMI for wider logo display support'
      });
    }
  }

  // Sort by priority and return texts
  return recommendations
    .sort((a, b) => a.priority - b.priority)
    .map(r => r.text);
}
