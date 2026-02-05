import { describe, it, expect, vi, beforeEach } from 'vitest';
import { cachedResolveTxt } from '../utils/dns.js';
import { checkMTASTS } from './mta-sts.js';

vi.mock('../utils/dns.js', async () => {
  const actual = await vi.importActual<typeof import('../utils/dns.js')>('../utils/dns.js');
  return {
    ...actual,
    cachedResolveTxt: vi.fn()
  };
});

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('checkMTASTS', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('detects valid MTA-STS with enforce policy', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=STSv1; id=20240101'
    ]);
    
    mockFetch.mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(`version: STSv1
mode: enforce
mx: mail.example.com
max_age: 604800`)
    });

    const result = await checkMTASTS('example.com');
    
    expect(result.found).toBe(true);
    expect(result.id).toBe('20240101');
    expect(result.policy?.mode).toBe('enforce');
    expect(result.policy?.maxAge).toBe(604800);
  });

  it('warns on testing mode', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=STSv1; id=20240101'
    ]);
    
    mockFetch.mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(`version: STSv1
mode: testing
mx: mail.example.com
max_age: 604800`)
    });

    const result = await checkMTASTS('example.com');
    
    expect(result.found).toBe(true);
    expect(result.policy?.mode).toBe('testing');
    expect(result.issues.some(i => i.message.includes('testing'))).toBe(true);
  });

  it('critical issue on none mode', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=STSv1; id=20240101'
    ]);
    
    mockFetch.mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(`version: STSv1
mode: none
max_age: 86400`)
    });

    const result = await checkMTASTS('example.com');
    
    expect(result.policy?.mode).toBe('none');
    expect(result.issues.some(i => i.severity === 'high')).toBe(true);
  });

  it('warns on short max_age', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=STSv1; id=20240101'
    ]);
    
    mockFetch.mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(`version: STSv1
mode: enforce
mx: mail.example.com
max_age: 3600`)
    });

    const result = await checkMTASTS('example.com');
    
    expect(result.policy?.maxAge).toBe(3600);
    expect(result.issues.some(i => i.message.includes('short'))).toBe(true);
  });

  it('reports no MTA-STS found', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([]);

    const result = await checkMTASTS('example.com');
    
    expect(result.found).toBe(false);
    expect(result.issues.some(i => i.severity === 'medium')).toBe(true);
  });

  it('handles policy fetch failure', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=STSv1; id=20240101'
    ]);
    
    mockFetch.mockResolvedValue({
      ok: false,
      status: 404
    });

    const result = await checkMTASTS('example.com');
    
    expect(result.found).toBe(true);
    // When policy fetch fails, policy should be undefined
    expect(result.policy).toBeUndefined();
  });

  it('warns on missing id tag', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=STSv1'
    ]);
    
    mockFetch.mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(`version: STSv1
mode: enforce
mx: mail.example.com
max_age: 604800`)
    });

    const result = await checkMTASTS('example.com');
    
    expect(result.found).toBe(true);
    expect(result.id).toBeUndefined();
    expect(result.issues.some(i => i.message.includes('missing id'))).toBe(true);
  });
});
