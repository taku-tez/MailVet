import { describe, it, expect } from 'vitest';
import { formatResult, formatSummary } from './output.js';
import type { DomainResult } from './types.js';

const createMockResult = (overrides: Partial<DomainResult> = {}): DomainResult => ({
  domain: 'example.com',
  grade: 'A',
  score: 95,
  timestamp: '2026-02-05T10:00:00Z',
  spf: {
    found: true,
    record: 'v=spf1 include:_spf.google.com -all',
    mechanism: '-all',
    lookupCount: 3,
    includes: ['_spf.google.com'],
    issues: []
  },
  dkim: {
    found: true,
    selectors: [
      { selector: 'google', found: true, keyType: 'rsa', keyLength: 2048 }
    ],
    issues: []
  },
  dmarc: {
    found: true,
    record: 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com',
    policy: 'reject',
    reportingEnabled: true,
    rua: ['mailto:dmarc@example.com'],
    issues: []
  },
  mx: {
    found: true,
    records: [
      { exchange: 'mail.example.com', priority: 10 }
    ],
    issues: []
  },
  recommendations: [],
  ...overrides
});

describe('formatResult', () => {
  it('includes domain name and grade', () => {
    const result = createMockResult();
    const output = formatResult(result);
    
    expect(output).toContain('example.com');
    expect(output).toContain('A');
    expect(output).toContain('95/100');
  });

  it('shows SPF details', () => {
    const result = createMockResult();
    const output = formatResult(result);
    
    expect(output).toContain('SPF');
    expect(output).toContain('-all');
    expect(output).toContain('3/10'); // lookupCount
  });

  it('shows DKIM selectors', () => {
    const result = createMockResult();
    const output = formatResult(result);
    
    expect(output).toContain('DKIM');
    expect(output).toContain('google._domainkey');
    expect(output).toContain('2048-bit');
  });

  it('shows DMARC policy', () => {
    const result = createMockResult();
    const output = formatResult(result);
    
    expect(output).toContain('DMARC');
    expect(output).toContain('p=reject');
  });

  it('shows MX records', () => {
    const result = createMockResult();
    const output = formatResult(result);
    
    expect(output).toContain('MX');
    expect(output).toContain('mail.example.com');
    expect(output).toContain('pri: 10');
  });

  it('shows recommendations', () => {
    const result = createMockResult({
      recommendations: ['Add DMARC reporting', 'Upgrade DKIM key']
    });
    const output = formatResult(result);
    
    expect(output).toContain('Recommendations');
    expect(output).toContain('Add DMARC reporting');
    expect(output).toContain('Upgrade DKIM key');
  });

  it('shows error if present', () => {
    const result = createMockResult({
      error: 'DNS timeout'
    });
    const output = formatResult(result);
    
    expect(output).toContain('Error');
    expect(output).toContain('DNS timeout');
  });

  it('shows BIMI when present', () => {
    const result = createMockResult({
      bimi: {
        found: true,
        logoUrl: 'https://example.com/logo.svg',
        certificateUrl: 'https://example.com/vmc.pem',
        issues: []
      }
    });
    const output = formatResult(result);
    
    expect(output).toContain('BIMI');
    expect(output).toContain('Logo');
    expect(output).toContain('VMC');
  });

  it('shows MTA-STS when present', () => {
    const result = createMockResult({
      mtaSts: {
        found: true,
        policy: { mode: 'enforce', maxAge: 604800 },
        issues: []
      }
    });
    const output = formatResult(result);
    
    expect(output).toContain('MTA-STS');
    expect(output).toContain('enforce');
    expect(output).toContain('7 days');
  });

  it('shows TLS-RPT when present', () => {
    const result = createMockResult({
      tlsRpt: {
        found: true,
        rua: ['mailto:tls@example.com'],
        issues: []
      }
    });
    const output = formatResult(result);
    
    expect(output).toContain('TLS-RPT');
    expect(output).toContain('1 endpoint');
  });

  it('shows ARC readiness when present', () => {
    const result = createMockResult({
      arc: {
        ready: true,
        canSign: true,
        canValidate: true,
        issues: []
      }
    });
    const output = formatResult(result);
    
    expect(output).toContain('ARC');
    expect(output).toContain('Can sign');
  });

  it('verbose mode shows all issues', () => {
    const result = createMockResult({
      spf: {
        found: true,
        mechanism: '~all',
        issues: [
          { severity: 'medium', message: 'Using softfail', recommendation: 'Use -all' }
        ]
      },
      dkim: { found: true, selectors: [], issues: [] },
      dmarc: { found: true, issues: [] },
      mx: { found: true, records: [], issues: [] }
    });
    
    const output = formatResult(result, true);
    
    expect(output).toContain('Using softfail');
    expect(output).toContain('All Issues');
  });

  it('verbose mode shows includes', () => {
    const result = createMockResult();
    const output = formatResult(result, true);
    
    expect(output).toContain('Includes');
    expect(output).toContain('_spf.google.com');
  });

  it('handles failing grade correctly', () => {
    const result = createMockResult({
      grade: 'F',
      score: 10,
      spf: { found: false, issues: [{ severity: 'critical', message: 'No SPF' }] },
      dkim: { found: false, selectors: [], issues: [] },
      dmarc: { found: false, issues: [] },
      mx: { found: false, records: [], issues: [] }
    });
    const output = formatResult(result);
    
    expect(output).toContain('F');
    expect(output).toContain('10/100');
    expect(output).toContain('Not found');
  });
});

describe('formatSummary', () => {
  it('shows total domain count', () => {
    const results = [
      createMockResult({ domain: 'a.com', grade: 'A', score: 95 }),
      createMockResult({ domain: 'b.com', grade: 'B', score: 80 }),
      createMockResult({ domain: 'c.com', grade: 'F', score: 10 }),
    ];
    
    const output = formatSummary(results);
    
    expect(output).toContain('3 domains');
  });

  it('shows grade distribution', () => {
    const results = [
      createMockResult({ grade: 'A', score: 95 }),
      createMockResult({ grade: 'A', score: 92 }),
      createMockResult({ grade: 'B', score: 80 }),
      createMockResult({ grade: 'F', score: 10 }),
    ];
    
    const output = formatSummary(results);
    
    expect(output).toContain('A: 2');
    expect(output).toContain('B: 1');
    expect(output).toContain('F: 1');
  });

  it('shows worst performers', () => {
    const results = [
      createMockResult({ domain: 'good.com', grade: 'A', score: 95, recommendations: [] }),
      createMockResult({ 
        domain: 'bad.com', 
        grade: 'F', 
        score: 10,
        recommendations: ['Add SPF record'] 
      }),
    ];
    
    const output = formatSummary(results);
    
    expect(output).toContain('Needs Attention');
    expect(output).toContain('bad.com');
  });

  it('shows top performers', () => {
    const results = [
      createMockResult({ domain: 'excellent.com', grade: 'A', score: 100 }),
      createMockResult({ domain: 'great.com', grade: 'A', score: 95 }),
    ];
    
    const output = formatSummary(results);
    
    expect(output).toContain('Top Performers');
    expect(output).toContain('excellent.com');
    expect(output).toContain('great.com');
  });

  it('handles empty results', () => {
    const output = formatSummary([]);
    
    expect(output).toContain('0 domains');
  });
});
