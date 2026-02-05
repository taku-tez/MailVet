import { describe, it, expect, vi, beforeEach } from 'vitest';
import { cachedResolveTxt } from '../utils/dns.js';
import { checkSPF } from './spf.js';

vi.mock('../utils/dns.js', async () => {
  const actual = await vi.importActual<typeof import('../utils/dns.js')>('../utils/dns.js');
  return {
    ...actual,
    cachedResolveTxt: vi.fn()
  };
});

describe('checkSPF', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('detects valid SPF with -all', async () => {
    // Mock both the main domain and the included domain for recursive lookup
    vi.mocked(cachedResolveTxt)
      .mockResolvedValueOnce(['v=spf1 include:_spf.google.com -all']) // example.com
      .mockResolvedValueOnce(['v=spf1 ip4:172.217.0.0/16 -all']); // _spf.google.com

    const result = await checkSPF('example.com');
    
    expect(result.found).toBe(true);
    expect(result.mechanism).toBe('-all');
    expect(result.issues).toHaveLength(0);
  });

  it('warns on ~all softfail', async () => {
    vi.mocked(cachedResolveTxt)
      .mockResolvedValueOnce(['v=spf1 include:_spf.google.com ~all'])
      .mockResolvedValueOnce(['v=spf1 ip4:172.217.0.0/16 -all']);

    const result = await checkSPF('example.com');
    
    expect(result.found).toBe(true);
    expect(result.mechanism).toBe('~all');
    expect(result.issues.some(i => i.severity === 'medium')).toBe(true);
  });

  it('critical issue on +all', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=spf1 +all'
    ]);

    const result = await checkSPF('example.com');
    
    expect(result.found).toBe(true);
    expect(result.mechanism).toBe('+all');
    expect(result.issues.some(i => i.severity === 'critical')).toBe(true);
  });

  it('reports no SPF found', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'google-site-verification=xxx'
    ]);

    const result = await checkSPF('example.com');
    
    expect(result.found).toBe(false);
    expect(result.issues.some(i => i.severity === 'critical')).toBe(true);
  });

  it('counts DNS lookups correctly', async () => {
    // Mock main domain and all includes (they resolve to simple records with no further includes)
    vi.mocked(cachedResolveTxt)
      .mockResolvedValueOnce(['v=spf1 include:a.com include:b.com include:c.com a mx -all'])
      .mockResolvedValueOnce(['v=spf1 ip4:1.1.1.0/24 -all']) // a.com
      .mockResolvedValueOnce(['v=spf1 ip4:2.2.2.0/24 -all']) // b.com
      .mockResolvedValueOnce(['v=spf1 ip4:3.3.3.0/24 -all']); // c.com

    const result = await checkSPF('example.com');
    
    expect(result.found).toBe(true);
    // 3 includes + a + mx = 5 lookups
    expect(result.lookupCount).toBeGreaterThanOrEqual(5);
  });

  it('warns on exceeding DNS lookup limit', async () => {
    // Mock main domain and all 11 includes
    vi.mocked(cachedResolveTxt)
      .mockResolvedValueOnce(['v=spf1 include:1.com include:2.com include:3.com include:4.com include:5.com include:6.com include:7.com include:8.com include:9.com include:10.com include:11.com -all'])
      .mockResolvedValueOnce(['v=spf1 ip4:1.0.0.0/8 -all']) // 1.com
      .mockResolvedValueOnce(['v=spf1 ip4:2.0.0.0/8 -all']) // 2.com
      .mockResolvedValueOnce(['v=spf1 ip4:3.0.0.0/8 -all']) // 3.com
      .mockResolvedValueOnce(['v=spf1 ip4:4.0.0.0/8 -all']) // 4.com
      .mockResolvedValueOnce(['v=spf1 ip4:5.0.0.0/8 -all']) // 5.com
      .mockResolvedValueOnce(['v=spf1 ip4:6.0.0.0/8 -all']) // 6.com
      .mockResolvedValueOnce(['v=spf1 ip4:7.0.0.0/8 -all']) // 7.com
      .mockResolvedValueOnce(['v=spf1 ip4:8.0.0.0/8 -all']) // 8.com
      .mockResolvedValueOnce(['v=spf1 ip4:9.0.0.0/8 -all']) // 9.com
      .mockResolvedValueOnce(['v=spf1 ip4:10.0.0.0/8 -all']) // 10.com
      .mockResolvedValueOnce(['v=spf1 ip4:11.0.0.0/8 -all']); // 11.com

    const result = await checkSPF('example.com');
    
    expect(result.lookupCount).toBeGreaterThan(10);
    expect(result.issues.some(i => i.message.includes('exceeds DNS lookup limit'))).toBe(true);
  });

  it('handles DNS errors gracefully', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([]);

    const result = await checkSPF('nonexistent.example');
    
    expect(result.found).toBe(false);
  });
});
