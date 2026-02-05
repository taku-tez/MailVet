import { describe, it, expect, vi, beforeEach } from 'vitest';
import { cachedResolveTxt } from '../utils/dns.js';
import { checkDMARC } from './dmarc.js';

vi.mock('../utils/dns.js', async () => {
  const actual = await vi.importActual<typeof import('../utils/dns.js')>('../utils/dns.js');
  return {
    ...actual,
    cachedResolveTxt: vi.fn()
  };
});

describe('checkDMARC', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('detects DMARC with reject policy', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=DMARC1; p=reject; rua=mailto:dmarc@example.com'
    ]);

    const result = await checkDMARC('example.com');
    
    expect(result.found).toBe(true);
    expect(result.policy).toBe('reject');
    expect(result.reportingEnabled).toBe(true);
  });

  it('warns on quarantine policy', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=DMARC1; p=quarantine'
    ]);

    const result = await checkDMARC('example.com');
    
    expect(result.policy).toBe('quarantine');
    expect(result.issues.some(i => i.severity === 'medium')).toBe(true);
  });

  it('high severity on none policy', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=DMARC1; p=none'
    ]);

    const result = await checkDMARC('example.com');
    
    expect(result.policy).toBe('none');
    expect(result.issues.some(i => i.severity === 'high')).toBe(true);
  });

  it('extracts subdomain policy', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=DMARC1; p=reject; sp=quarantine'
    ]);

    const result = await checkDMARC('example.com');
    
    expect(result.subdomainPolicy).toBe('quarantine');
    expect(result.issues.some(i => i.message.includes('Subdomain policy'))).toBe(true);
  });

  it('extracts percentage', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=DMARC1; p=reject; pct=50'
    ]);

    const result = await checkDMARC('example.com');
    
    expect(result.pct).toBe(50);
    expect(result.issues.some(i => i.message.includes('50%'))).toBe(true);
  });

  it('warns when reporting not configured', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=DMARC1; p=reject'
    ]);

    const result = await checkDMARC('example.com');
    
    expect(result.reportingEnabled).toBe(false);
    expect(result.issues.some(i => i.message.includes('reporting'))).toBe(true);
  });

  it('reports no DMARC found', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([]);

    const result = await checkDMARC('example.com');
    
    expect(result.found).toBe(false);
    expect(result.issues.some(i => i.severity === 'critical')).toBe(true);
  });
});
