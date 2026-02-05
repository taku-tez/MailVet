import { describe, it, expect } from 'vitest';
import { DNSSEC_ALGORITHMS, DS_DIGEST_TYPES, DNSKEY_FLAGS } from './dnssec.js';

// We test parsing logic directly since the full check requires dig

describe('DNSSEC', () => {
  describe('Algorithm classification', () => {
    it('should classify RSAMD5 as deprecated', () => {
      expect(DNSSEC_ALGORITHMS[1].strength).toBe('deprecated');
    });

    it('should classify DSA as deprecated', () => {
      expect(DNSSEC_ALGORITHMS[3].strength).toBe('deprecated');
    });

    it('should classify RSASHA1 as weak', () => {
      expect(DNSSEC_ALGORITHMS[5].strength).toBe('weak');
    });

    it('should classify RSASHA256 as acceptable', () => {
      expect(DNSSEC_ALGORITHMS[8].strength).toBe('acceptable');
    });

    it('should classify ECDSAP256SHA256 as strong', () => {
      expect(DNSSEC_ALGORITHMS[13].strength).toBe('strong');
    });

    it('should classify ED25519 as strong', () => {
      expect(DNSSEC_ALGORITHMS[15].strength).toBe('strong');
    });
  });

  describe('DS Digest Types', () => {
    it('should classify SHA-1 as weak', () => {
      expect(DS_DIGEST_TYPES[1].strength).toBe('weak');
    });

    it('should classify SHA-256 as strong', () => {
      expect(DS_DIGEST_TYPES[2].strength).toBe('strong');
    });

    it('should classify SHA-384 as strong', () => {
      expect(DS_DIGEST_TYPES[4].strength).toBe('strong');
    });
  });

  describe('DNSKEY flags', () => {
    it('should recognize KSK flag (257)', () => {
      expect(DNSKEY_FLAGS.SEP_KEY).toBe(257);
    });

    it('should recognize ZSK flag (256)', () => {
      expect(DNSKEY_FLAGS.ZONE_KEY).toBe(256);
    });
  });
});
