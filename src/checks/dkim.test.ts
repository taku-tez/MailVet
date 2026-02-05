import { describe, it, expect, vi, beforeEach } from 'vitest';
import { cachedResolveTxt } from '../utils/dns.js';
import { checkDKIM } from './dkim.js';

vi.mock('../utils/dns.js', async () => {
  const actual = await vi.importActual<typeof import('../utils/dns.js')>('../utils/dns.js');
  return {
    ...actual,
    cachedResolveTxt: vi.fn()
  };
});

describe('checkDKIM', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('detects valid DKIM with RSA 2048-bit key', async () => {
    vi.mocked(cachedResolveTxt).mockImplementation(async (domain: string) => {
      if (domain === 'google._domainkey.example.com') {
        // Simulated 2048-bit RSA key (256 bytes base64)
        const key = 'A'.repeat(340);
        return [`v=DKIM1; k=rsa; p=${key}`];
      }
      return [];
    });

    const result = await checkDKIM('example.com', ['google']);
    
    expect(result.found).toBe(true);
    expect(result.selectors.length).toBe(1);
    expect(result.selectors[0].keyType).toBe('rsa');
    expect(result.selectors[0].keyLength).toBeGreaterThanOrEqual(2048);
  });

  it('detects ed25519 key and treats as strong', async () => {
    vi.mocked(cachedResolveTxt).mockImplementation(async (domain: string) => {
      if (domain === 'default._domainkey.example.com') {
        return [`v=DKIM1; k=ed25519; p=MCowBQYDK2VwAyEAtest`];
      }
      return [];
    });

    const result = await checkDKIM('example.com', ['default']);
    
    expect(result.found).toBe(true);
    expect(result.selectors[0].keyType).toBe('ed25519');
    expect(result.selectors[0].keyLength).toBe(256);
    // Should not have weak key warning for ed25519
    expect(result.issues.some(i => i.message.includes('weak'))).toBe(false);
  });

  it('warns on weak 1024-bit RSA key', async () => {
    vi.mocked(cachedResolveTxt).mockImplementation(async (domain: string) => {
      if (domain === 'selector1._domainkey.example.com') {
        // Simulated 1024-bit RSA key (128 bytes base64)
        const key = 'A'.repeat(170);
        return [`v=DKIM1; k=rsa; p=${key}`];
      }
      return [];
    });

    const result = await checkDKIM('example.com', ['selector1']);
    
    expect(result.found).toBe(true);
    expect(result.issues.some(i => i.message.includes('1024-bit'))).toBe(true);
  });

  it('reports no DKIM found', async () => {
    vi.mocked(cachedResolveTxt).mockResolvedValue([]);

    const result = await checkDKIM('example.com', ['google', 'selector1']);
    
    expect(result.found).toBe(false);
    expect(result.selectors).toHaveLength(0);
    expect(result.issues.some(i => i.message.includes('No DKIM'))).toBe(true);
  });

  it('detects multiple selectors', async () => {
    vi.mocked(cachedResolveTxt).mockImplementation(async (domain: string) => {
      if (domain === 'google._domainkey.example.com' || 
          domain === 'selector1._domainkey.example.com') {
        const key = 'A'.repeat(340);
        return [`v=DKIM1; k=rsa; p=${key}`];
      }
      return [];
    });

    const result = await checkDKIM('example.com', ['google', 'selector1', 'nonexistent']);
    
    expect(result.found).toBe(true);
    expect(result.selectors.length).toBe(2);
  });

  it('detects revoked key (empty p=)', async () => {
    vi.mocked(cachedResolveTxt).mockImplementation(async (domain: string) => {
      if (domain === 'revoked._domainkey.example.com') {
        return [`v=DKIM1; k=rsa; p=`];
      }
      return [];
    });

    const result = await checkDKIM('example.com', ['revoked']);
    
    expect(result.found).toBe(true);
    // Empty p= may result in 0 or undefined depending on parsing
    expect(result.selectors[0].keyLength === 0 || result.selectors[0].keyLength === undefined).toBe(true);
  });
});
