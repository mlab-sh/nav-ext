import { describe, expect, it } from 'vitest';
// We test the inference helpers by exercising the full scan* path would require fetch mocks;
// instead we re-export via an internal helper using dynamic import semantics.
// Easier: inline the same heuristics shape and rely on them being pure.

// Because inferCryptoVerdict isn't exported, we test via the publicly exposed scan flow shape:
// we directly construct payloads that should be valid samples and assert the verdict computed.
// To avoid coupling to private functions, this is a behavioral test via a tiny adapter:
import { __inferCryptoVerdictForTest as inferCryptoVerdict } from './mlab-client';

describe('inferCryptoVerdict', () => {
  it('returns clean for a real low-risk EOA with sanctions:{is_sanctioned:false}', () => {
    const data = {
      address: '0xCDe377407d9b819EFc0e185Aa2D442194c2233E6',
      categories: ['eoa'],
      chain: 'ETH',
      labels: [],
      risk_level: 'low',
      risk_score: 0,
      sanctions: { is_sanctioned: false },
      type: 'eoa',
    };
    expect(inferCryptoVerdict(data)).toBe('clean');
  });

  it('returns malicious when actually sanctioned', () => {
    expect(inferCryptoVerdict({
      address: '0x1', risk_level: 'low', risk_score: 0,
      sanctions: { is_sanctioned: true, authority: 'OFAC' },
    })).toBe('malicious');
  });

  it('returns malicious for high risk_level', () => {
    expect(inferCryptoVerdict({
      address: '0x1', risk_level: 'high', risk_score: 88,
      sanctions: { is_sanctioned: false },
    })).toBe('malicious');
  });

  it('returns suspicious for medium', () => {
    expect(inferCryptoVerdict({
      address: '0x1', risk_level: 'medium', risk_score: 55,
      sanctions: { is_sanctioned: false },
    })).toBe('suspicious');
  });

  it('returns malicious when categories contain a flagged term', () => {
    expect(inferCryptoVerdict({
      address: '0x1', risk_level: 'low', risk_score: 0,
      categories: ['mixer', 'eoa'],
      sanctions: { is_sanctioned: false },
    })).toBe('malicious');
  });

  it('returns unknown on empty/error payload', () => {
    expect(inferCryptoVerdict(null)).toBe('unknown');
    expect(inferCryptoVerdict({})).toBe('unknown');
  });
});
