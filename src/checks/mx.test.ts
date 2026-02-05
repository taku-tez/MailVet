import { describe, it, expect, vi, beforeEach } from 'vitest';
import { cachedResolveMx } from '../utils/dns.js';
import { checkMX } from './mx.js';

vi.mock('../utils/dns.js', async () => {
  const actual = await vi.importActual<typeof import('../utils/dns.js')>('../utils/dns.js');
  return {
    ...actual,
    cachedResolveMx: vi.fn()
  };
});

describe('checkMX', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('detects valid MX records', async () => {
    vi.mocked(cachedResolveMx).mockResolvedValue([
      { exchange: 'mx1.example.com', priority: 10 },
      { exchange: 'mx2.example.com', priority: 20 },
    ]);

    const result = await checkMX('example.com');
    
    expect(result.found).toBe(true);
    expect(result.records).toHaveLength(2);
    expect(result.records[0].exchange).toBe('mx1.example.com');
    expect(result.records[0].priority).toBe(10);
  });

  it('identifies Google Workspace', async () => {
    vi.mocked(cachedResolveMx).mockResolvedValue([
      { exchange: 'aspmx.l.google.com', priority: 1 },
      { exchange: 'alt1.aspmx.l.google.com', priority: 5 },
    ]);

    const result = await checkMX('example.com');
    
    expect(result.found).toBe(true);
    expect(result.issues.some(i => i.message.includes('Google Workspace'))).toBe(true);
  });

  it('identifies Microsoft 365', async () => {
    vi.mocked(cachedResolveMx).mockResolvedValue([
      { exchange: 'example-com.mail.protection.outlook.com', priority: 10 },
    ]);

    const result = await checkMX('example.com');
    
    expect(result.found).toBe(true);
    expect(result.issues.some(i => i.message.includes('Microsoft 365'))).toBe(true);
  });

  it('warns on single MX record', async () => {
    vi.mocked(cachedResolveMx).mockResolvedValue([
      { exchange: 'mail.example.com', priority: 10 },
    ]);

    const result = await checkMX('example.com');
    
    expect(result.found).toBe(true);
    expect(result.issues.some(i => i.message.includes('no redundancy'))).toBe(true);
  });

  it('notes same priority for all MX records', async () => {
    vi.mocked(cachedResolveMx).mockResolvedValue([
      { exchange: 'mx1.example.com', priority: 10 },
      { exchange: 'mx2.example.com', priority: 10 },
    ]);

    const result = await checkMX('example.com');
    
    expect(result.found).toBe(true);
    expect(result.issues.some(i => i.message.includes('same priority'))).toBe(true);
  });

  it('detects null MX record', async () => {
    vi.mocked(cachedResolveMx).mockResolvedValue([
      { exchange: '.', priority: 0 },
    ]);

    const result = await checkMX('example.com');
    
    expect(result.found).toBe(true);
    expect(result.issues.some(i => i.message.includes('Null MX'))).toBe(true);
  });

  it('reports no MX found', async () => {
    vi.mocked(cachedResolveMx).mockResolvedValue([]);

    const result = await checkMX('example.com');
    
    expect(result.found).toBe(false);
    expect(result.records).toHaveLength(0);
  });

  it('sorts MX records by priority', async () => {
    vi.mocked(cachedResolveMx).mockResolvedValue([
      { exchange: 'mx3.example.com', priority: 30 },
      { exchange: 'mx1.example.com', priority: 10 },
      { exchange: 'mx2.example.com', priority: 20 },
    ]);

    const result = await checkMX('example.com');
    
    expect(result.records[0].exchange).toBe('mx1.example.com');
    expect(result.records[1].exchange).toBe('mx2.example.com');
    expect(result.records[2].exchange).toBe('mx3.example.com');
  });
});
