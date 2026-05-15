import { describe, expect, it } from 'vitest';
import { refang } from './refang';

describe('refang', () => {
  it('replaces bracketed dot variants', () => {
    expect(refang('evil[.]com')).toBe('evil.com');
    expect(refang('evil(.)com')).toBe('evil.com');
    expect(refang('evil{.}com')).toBe('evil.com');
    // internal whitespace inside the brackets is tolerated
    expect(refang('evil[ . ]com')).toBe('evil.com');
  });

  it('replaces bracketed colon variants in URLs', () => {
    expect(refang('http[:]//example.com')).toBe('http://example.com');
    expect(refang('https(:)//example.com')).toBe('https://example.com');
  });

  it('refangs hxxp / hxxps / fxp', () => {
    expect(refang('hxxp://bad.tld/path')).toBe('http://bad.tld/path');
    expect(refang('hXXps://bad.tld')).toBe('https://bad.tld');
    expect(refang('HXXP://up.tld')).toBe('http://up.tld');
    expect(refang('fxp://files.tld')).toBe('ftp://files.tld');
  });

  it('refangs IPv4 with bracketed dots', () => {
    expect(refang('1.1.1[.]1')).toBe('1.1.1.1');
    expect(refang('192[.]168[.]1[.]1')).toBe('192.168.1.1');
  });

  it('refangs email-style at variants', () => {
    expect(refang('user[at]example.com')).toBe('user@example.com');
    expect(refang('user(at)example.com')).toBe('user@example.com');
    expect(refang('user[@]example.com')).toBe('user@example.com');
  });

  it('leaves clean strings untouched', () => {
    expect(refang('https://example.com/path?a=1')).toBe('https://example.com/path?a=1');
    expect(refang('plain text 1.2.3.4 with example.com')).toBe('plain text 1.2.3.4 with example.com');
  });

  it('handles mixed defanging in a single string', () => {
    expect(refang('hxxps://malicious[.]example[.]com sent to user[at]victim.com'))
      .toBe('https://malicious.example.com sent to user@victim.com');
  });
});
