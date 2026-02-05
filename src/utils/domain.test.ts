import { describe, it, expect } from 'vitest';
import { toASCII, isValidDomain } from './domain.js';

describe('Domain utilities', () => {
  describe('toASCII', () => {
    it('should pass through ASCII domains unchanged', () => {
      expect(toASCII('example.com')).toBe('example.com');
    });

    it('should convert Japanese IDN to punycode', () => {
      const result = toASCII('日本語.jp');
      expect(result).toContain('xn--');
      expect(result).toContain('.jp');
    });

    it('should convert German IDN to punycode', () => {
      const result = toASCII('münchen.de');
      expect(result).toBe('xn--mnchen-3ya.de');
    });

    it('should handle emoji domains', () => {
      const result = toASCII('💩.la');
      // Should not throw, should return punycode or original
      expect(result).toBeTruthy();
    });

    it('should return original on invalid input', () => {
      expect(toASCII('')).toBe('');
    });

    it('should handle mixed ASCII and non-ASCII labels', () => {
      const result = toASCII('test.日本語.jp');
      expect(result).toContain('xn--');
      expect(result).toContain('test');
    });
  });

  describe('isValidDomain', () => {
    it('should accept valid domains', () => {
      expect(isValidDomain('example.com')).toBe(true);
      expect(isValidDomain('sub.example.com')).toBe(true);
      expect(isValidDomain('my-domain.co.uk')).toBe(true);
    });

    it('should reject invalid domains', () => {
      expect(isValidDomain('')).toBe(false);
      expect(isValidDomain('not a domain')).toBe(false);
      expect(isValidDomain('-invalid.com')).toBe(false);
    });

    it('should reject URLs', () => {
      expect(isValidDomain('https://example.com')).toBe(false);
      expect(isValidDomain('http://example.com')).toBe(false);
    });

    it('should accept numeric-like domains (DNS allows them)', () => {
      // Note: IP-like strings pass basic domain validation
      // Real DNS resolution will handle the difference
      expect(isValidDomain('192.168.1.1')).toBe(true);
    });
  });
});
