import { describe, it, expect } from 'vitest';
import { checkARCReadiness } from './arc.js';
import type { SPFResult, DKIMResult, DMARCResult } from '../types.js';

const baseSPF: SPFResult = { found: false, issues: [] };
const baseDKIM: DKIMResult = { found: false, selectors: [], issues: [] };
const baseDMARC: DMARCResult = { found: false, issues: [] };

describe('checkARCReadiness', () => {
  it('reports not ready when DKIM missing', () => {
    const result = checkARCReadiness(baseSPF, baseDKIM, baseDMARC);
    
    expect(result.ready).toBe(false);
    expect(result.canSign).toBe(false);
    expect(result.issues.some(i => i.message.includes('DKIM not configured'))).toBe(true);
  });

  it('reports ready with DKIM and DMARC', () => {
    const dkim: DKIMResult = {
      found: true,
      selectors: [{ selector: 'default', found: true, keyLength: 2048 }],
      issues: []
    };
    const dmarc: DMARCResult = {
      found: true,
      policy: 'reject',
      issues: []
    };

    const result = checkARCReadiness(baseSPF, dkim, dmarc);
    
    expect(result.ready).toBe(true);
    expect(result.canSign).toBe(true);
    expect(result.canValidate).toBe(true);
  });

  it('can sign with DKIM only', () => {
    const dkim: DKIMResult = {
      found: true,
      selectors: [{ selector: 'default', found: true, keyLength: 2048 }],
      issues: []
    };

    const result = checkARCReadiness(baseSPF, dkim, baseDMARC);
    
    expect(result.canSign).toBe(true);
    expect(result.ready).toBe(false); // Not fully ready without DMARC
  });

  it('warns on weak DKIM keys', () => {
    const dkim: DKIMResult = {
      found: true,
      selectors: [{ selector: 'default', found: true, keyLength: 1024 }],
      issues: []
    };
    const dmarc: DMARCResult = {
      found: true,
      policy: 'reject',
      issues: []
    };

    const result = checkARCReadiness(baseSPF, dkim, dmarc);
    
    expect(result.ready).toBe(true);
    expect(result.issues.some(i => i.message.includes('2048-bit'))).toBe(true);
  });

  it('notes DMARC none policy', () => {
    const dkim: DKIMResult = {
      found: true,
      selectors: [{ selector: 'default', found: true, keyLength: 2048 }],
      issues: []
    };
    const dmarc: DMARCResult = {
      found: true,
      policy: 'none',
      issues: []
    };

    const result = checkARCReadiness(baseSPF, dkim, dmarc);
    
    expect(result.ready).toBe(true);
    expect(result.issues.some(i => i.message.includes('none'))).toBe(true);
  });

  it('always reports canValidate as true', () => {
    const result = checkARCReadiness(baseSPF, baseDKIM, baseDMARC);
    
    expect(result.canValidate).toBe(true); // Any domain can validate
  });

  it('notes missing SPF', () => {
    const dkim: DKIMResult = {
      found: true,
      selectors: [{ selector: 'default', found: true, keyLength: 2048 }],
      issues: []
    };
    const dmarc: DMARCResult = {
      found: true,
      policy: 'reject',
      issues: []
    };

    const result = checkARCReadiness(baseSPF, dkim, dmarc);
    
    expect(result.issues.some(i => i.message.includes('SPF'))).toBe(true);
  });
});
