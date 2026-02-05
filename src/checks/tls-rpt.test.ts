import { describe, it, expect, vi, beforeEach } from 'vitest';
import { cachedResolveTxt } from '../utils/dns.js';
import { checkTLSRPT } from './tls-rpt.js';

vi.mock('../utils/dns.js', async () => {
  const actual = await vi.importActual<typeof import('../utils/dns.js')>('../utils/dns.js');
  return {
    ...actual,
    cachedResolveTxt: vi.fn()
  };
});

describe('checkTLSRPT', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('detects valid TLS-RPT with mailto', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=TLSRPTv1; rua=mailto:tlsrpt@example.com'
    ]);

    const result = await checkTLSRPT('example.com');
    
    expect(result.found).toBe(true);
    expect(result.rua).toContain('mailto:tlsrpt@example.com');
    expect(result.issues.filter(i => i.severity === 'high')).toHaveLength(0);
  });

  it('detects TLS-RPT with https endpoint', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=TLSRPTv1; rua=https://report.example.com/tlsrpt'
    ]);

    const result = await checkTLSRPT('example.com');
    
    expect(result.found).toBe(true);
    expect(result.rua).toContain('https://report.example.com/tlsrpt');
  });

  it('detects multiple reporting addresses', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://report.example.com/tlsrpt'
    ]);

    const result = await checkTLSRPT('example.com');
    
    expect(result.found).toBe(true);
    expect(result.rua).toHaveLength(2);
  });

  it('marks endpoints as unverified when verification is disabled', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://report.example.com/tlsrpt'
    ]);

    const result = await checkTLSRPT('example.com');

    expect(result.found).toBe(true);
    expect(result.endpointStatus).toHaveLength(2);
    expect(result.endpointStatus?.every(status => status.reachable === undefined)).toBe(true);
  });

  it('warns on missing rua', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=TLSRPTv1'
    ]);

    const result = await checkTLSRPT('example.com');
    
    expect(result.found).toBe(true);
    expect(result.issues.some(i => i.message.includes('no reporting'))).toBe(true);
  });

  it('warns on invalid scheme', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=TLSRPTv1; rua=ftp://example.com/report'
    ]);

    const result = await checkTLSRPT('example.com');
    
    expect(result.found).toBe(true);
    expect(result.issues.some(i => i.message.includes('Invalid'))).toBe(true);
  });

  it('reports no TLS-RPT found', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([]);

    const result = await checkTLSRPT('example.com');
    
    expect(result.found).toBe(false);
    expect(result.issues.some(i => i.severity === 'low')).toBe(true);
  });

  it('handles multiple TLS-RPT records', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=TLSRPTv1; rua=mailto:one@example.com',
      'v=TLSRPTv1; rua=mailto:two@example.com'
    ]);

    const result = await checkTLSRPT('example.com');
    
    expect(result.found).toBe(true);
    expect(result.issues.some(i => i.message.includes('Multiple'))).toBe(true);
  });
});
