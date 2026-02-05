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
  DNSSECResult,
  Grade,
  Issue,
  Severity
} from '../types.js';
import {
  GRADE_A_MIN,
  GRADE_B_MIN,
  GRADE_C_MIN,
  GRADE_D_MIN,
  SCORE_BONUS_MAX,
  DKIM_STRONG_KEY_BITS,
  DKIM_WEAK_KEY_BITS
} from '../constants.js';

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
 * - DNSSEC enabled: +5 (with chain valid), +3 (enabled only)
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
  arc?: ARCReadinessResult,
  dnssec?: DNSSECResult
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
      s.keyType === 'ed25519' || (s.keyLength && s.keyLength >= DKIM_STRONG_KEY_BITS)
    );
    if (hasStrongKey) {
      score += 10;
    } else {
      const hasAnyKey = dkim.selectors.some(s => s.keyLength && s.keyLength >= DKIM_WEAK_KEY_BITS);
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

  // DNSSEC bonus (+5 with valid chain, +3 enabled only)
  if (dnssec?.enabled) {
    if (dnssec.chainValid) {
      bonus += 5;
    } else {
      bonus += 3;
    }
  }

  // Apply bonus (capped so total doesn't exceed 100)
  score = Math.min(100, score + Math.min(bonus, SCORE_BONUS_MAX));

  // Apply penalties for critical/high severity issues (misconfigurations)
  const penalty = calculateIssuePenalty(spf, dkim, dmarc, mx, bimi, mtaSts, tlsRpt, arc, dnssec);
  score = Math.max(0, score - penalty);

  // Clamp score to 0-100
  score = Math.max(0, Math.min(100, score));

  // Determine grade based on score thresholds (from constants.ts)
  let grade: Grade;
  if (score >= GRADE_A_MIN) {
    grade = 'A';
  } else if (score >= GRADE_B_MIN) {
    grade = 'B';
  } else if (score >= GRADE_C_MIN) {
    grade = 'C';
  } else if (score >= GRADE_D_MIN) {
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
  arc?: ARCReadinessResult,
  dnssec?: DNSSECResult
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
    ...(dnssec?.issues || []),
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
 * Generate prioritized recommendations with user-friendly explanations
 */
export function generateRecommendations(
  spf: SPFResult,
  dkim: DKIMResult,
  dmarc: DMARCResult,
  mx: MXResult,
  bimi?: BIMIResult,
  mtaSts?: MTASTSResult,
  tlsRpt?: TLSRPTResult,
  arc?: ARCReadinessResult,
  dnssec?: DNSSECResult
): string[] {
  const recommendations: Array<{ priority: number; text: string }> = [];

  // Critical: Missing records
  if (!spf.found) {
    recommendations.push({
      priority: 1,
      text: '🚨 [緊急] SPFレコードを追加してください - 現在、誰でもあなたのドメインを騙ってメールを送信できる状態です'
    });
  }

  if (!dmarc.found) {
    recommendations.push({
      priority: 2,
      text: '🚨 [緊急] DMARCレコードを追加してください - なりすましメール対策の要となる設定が未実施です'
    });
  }

  if (!dkim.found) {
    recommendations.push({
      priority: 3,
      text: '⚠️ [重要] DKIMを設定してください - メールの改ざん検知ができず、配信率が低下する可能性があります'
    });
  }

  // High: Weak configurations
  if (spf.found && spf.mechanism === '+all') {
    recommendations.push({
      priority: 4,
      text: '🚨 [緊急] SPFの「+all」を「-all」に変更してください - 現在の設定はすべての送信元を許可しており、実質無防備です'
    });
  } else if (spf.found && spf.mechanism === '~all') {
    recommendations.push({
      priority: 7,
      text: '💡 [推奨] SPFの「~all」を「-all」に強化することを検討してください - softfailからhardfailにすることで、不正送信をより確実にブロックできます'
    });
  }

  if (dmarc.found && dmarc.policy === 'none') {
    recommendations.push({
      priority: 5,
      text: '⚠️ [重要] DMARCポリシーを「none」から「quarantine」または「reject」に変更してください - 現在は監視モードのみで、なりすましメールをブロックできていません'
    });
  } else if (dmarc.found && dmarc.policy === 'quarantine') {
    recommendations.push({
      priority: 8,
      text: '💡 [推奨] DMARCポリシーを「quarantine」から「reject」への移行を検討してください - 認証失敗メールを迷惑メールフォルダではなく完全に拒否できます'
    });
  }

  // Medium: Improvements
  if (dkim.found) {
    const weakKeys = dkim.selectors.filter(s => s.keyLength && s.keyLength < 2048 && s.keyType !== 'ed25519');
    if (weakKeys.length > 0) {
      const selectors = weakKeys.map(s => s.selector).join(', ');
      recommendations.push({
        priority: 6,
        text: `⚠️ [重要] DKIMキーを2048ビット以上に更新してください（対象: ${selectors}）- 1024ビットは現在の基準では脆弱とされています`
      });
    }
  }

  if (dmarc.found && !dmarc.reportingEnabled) {
    recommendations.push({
      priority: 9,
      text: '💡 [推奨] DMARCレポート（rua=）を設定してください - 認証失敗の状況を把握でき、問題の早期発見に役立ちます'
    });
  }

  if (spf.found && spf.lookupCount && spf.lookupCount > 7) {
    recommendations.push({
      priority: 10,
      text: `⚠️ [注意] SPFのDNS参照回数が多すぎます（${spf.lookupCount}/10回）- 上限を超えると認証が失敗し、メールが届かなくなる恐れがあります`
    });
  }

  // Advanced feature recommendations
  if (!mtaSts?.found) {
    recommendations.push({
      priority: 11,
      text: '💡 [推奨] MTA-STSを設定してください - 受信メールのTLS暗号化を強制し、中間者攻撃を防止できます'
    });
  } else if (mtaSts.policy?.mode === 'testing') {
    recommendations.push({
      priority: 14,
      text: '💡 [推奨] MTA-STSをtestingモードからenforceモードに移行してください - テストで問題なければ本番適用しましょう'
    });
  }

  if (!tlsRpt?.found) {
    recommendations.push({
      priority: 12,
      text: '💡 [推奨] TLS-RPTを設定してください - TLS接続の失敗レポートを受け取れるようになり、配信問題の把握に役立ちます'
    });
  }

  // BIMI recommendation (only if DMARC is properly configured)
  if (dmarc.found && dmarc.policy && dmarc.policy !== 'none') {
    if (!bimi?.found) {
      recommendations.push({
        priority: 15,
        text: '✨ [オプション] BIMIを設定すると、対応メールクライアントで御社のロゴが表示されます - ブランド認知度向上に効果的です'
      });
    } else if (bimi.found && !bimi.certificateUrl) {
      recommendations.push({
        priority: 16,
        text: '✨ [オプション] VMC証明書を追加すると、より多くのメールクライアントでロゴが表示されます（Gmail等で必須）'
      });
    }
  }

  // DNSSEC recommendations
  if (!dnssec?.enabled) {
    recommendations.push({
      priority: 13,
      text: '💡 [推奨] DNSSECを有効にしてください - DNSスプーフィングやキャッシュポイズニングからドメインを保護できます'
    });
  } else if (dnssec.enabled && !dnssec.chainValid) {
    recommendations.push({
      priority: 6,
      text: '⚠️ [重要] DNSSECのチェーンオブトラストが不完全です - DS/DNSKEYレコードの設定を確認してください'
    });
  } else {
    // Check for weak algorithms
    const weakAlgos = dnssec.ds?.records.filter(r => r.strength === 'weak' || r.strength === 'deprecated');
    if (weakAlgos && weakAlgos.length > 0) {
      recommendations.push({
        priority: 8,
        text: `⚠️ [重要] DNSSECで弱いアルゴリズムが使用されています（${weakAlgos.map(a => a.algorithmName).join(', ')}）- より強力なアルゴリズムへの移行を検討してください`
      });
    }
    const weakDigests = dnssec.ds?.records.filter(r => r.digestStrength === 'weak');
    if (weakDigests && weakDigests.length > 0) {
      recommendations.push({
        priority: 9,
        text: '💡 [推奨] DSレコードのダイジェストタイプをSHA-256以上に更新してください - SHA-1は非推奨です'
      });
    }
  }

  // ARC recommendations
  if (arc && !arc.ready) {
    if (!dkim.found) {
      recommendations.push({
        priority: 14,
        text: '💡 [推奨] DKIMを設定するとARC署名が可能になります - メーリングリストや転送メールの認証維持に有効です'
      });
    } else if (!arc.canSign) {
      recommendations.push({
        priority: 15,
        text: '✨ [オプション] ARC署名を有効にしてください - メーリングリストや転送経由のメール認証を維持できます'
      });
    }
  }

  // Sort by priority and return texts
  return recommendations
    .sort((a, b) => a.priority - b.priority)
    .map(r => r.text);
}
