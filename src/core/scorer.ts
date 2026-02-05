/**
 * Email security scoring and grading
 */

import type { 
  SPFResult, 
  DKIMResult, 
  DMARCResult, 
  MXResult, 
  Grade 
} from '../types.js';

interface GradeResult {
  grade: Grade;
  score: number;
}

/**
 * Calculate grade based on email security configuration
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
  mx: MXResult
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
 * Generate prioritized recommendations
 */
export function generateRecommendations(
  spf: SPFResult,
  dkim: DKIMResult,
  dmarc: DMARCResult,
  mx: MXResult
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

  // Sort by priority and return texts
  return recommendations
    .sort((a, b) => a.priority - b.priority)
    .map(r => r.text);
}
