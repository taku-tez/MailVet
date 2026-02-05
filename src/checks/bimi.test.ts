import { describe, it, expect, vi, beforeEach } from 'vitest';
import { cachedResolveTxt } from '../utils/dns.js';
import { checkBIMI } from './bimi.js';

vi.mock('../utils/dns.js', async () => {
  const actual = await vi.importActual<typeof import('../utils/dns.js')>('../utils/dns.js');
  return {
    ...actual,
    cachedResolveTxt: vi.fn()
  };
});

describe('checkBIMI', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('detects valid BIMI record with logo and VMC', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem'
    ]);

    const result = await checkBIMI('example.com');
    
    expect(result.found).toBe(true);
    expect(result.logoUrl).toBe('https://example.com/logo.svg');
    expect(result.certificateUrl).toBe('https://example.com/vmc.pem');
  });

  it('detects BIMI without VMC certificate', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=BIMI1; l=https://example.com/logo.svg'
    ]);

    const result = await checkBIMI('example.com');
    
    expect(result.found).toBe(true);
    expect(result.logoUrl).toBe('https://example.com/logo.svg');
    expect(result.certificateUrl).toBeUndefined();
    expect(result.issues.some(i => i.message.includes('VMC'))).toBe(true);
  });

  it('warns on non-HTTPS logo URL', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=BIMI1; l=http://example.com/logo.svg'
    ]);

    const result = await checkBIMI('example.com');
    
    expect(result.found).toBe(true);
    expect(result.issues.some(i => i.message.includes('HTTPS'))).toBe(true);
  });

  it('warns on non-SVG logo', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=BIMI1; l=https://example.com/logo.png'
    ]);

    const result = await checkBIMI('example.com');
    
    expect(result.found).toBe(true);
    expect(result.issues.some(i => i.message.includes('SVG'))).toBe(true);
  });

  it('reports no BIMI found', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([]);

    const result = await checkBIMI('example.com');
    
    expect(result.found).toBe(false);
    expect(result.issues.some(i => i.severity === 'info')).toBe(true);
  });

  it('handles missing logo URL', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([
      'v=BIMI1; a=https://example.com/vmc.pem'
    ]);

    const result = await checkBIMI('example.com');
    
    expect(result.found).toBe(true);
    expect(result.issues.some(i => i.message.includes('missing logo'))).toBe(true);
  });
});
