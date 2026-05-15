import { describe, expect, it } from 'vitest';
import { classifyCrypto, classifyIoc, detectIocs } from './regex';

describe('classifyIoc', () => {
  it('classifies IPv4', () => {
    expect(classifyIoc('1.1.1.1')).toBe('ipv4');
    expect(classifyIoc('255.255.255.255')).toBe('ipv4');
    expect(classifyIoc('0.0.0.0')).toBe('ipv4');
  });

  it('rejects invalid IPv4', () => {
    expect(classifyIoc('999.1.1.1')).not.toBe('ipv4');
    expect(classifyIoc('1.1.1')).not.toBe('ipv4');
    expect(classifyIoc('1.1.1.1.1')).not.toBe('ipv4');
  });

  it('classifies IPv6', () => {
    expect(classifyIoc('2001:db8::1')).toBe('ipv6');
    expect(classifyIoc('fe80::1')).toBe('ipv6');
    expect(classifyIoc('::1')).toBe('ipv6');
  });

  it('classifies domains with known TLDs', () => {
    expect(classifyIoc('example.com')).toBe('domain');
    expect(classifyIoc('sub.example.co.uk')).toBe('domain');
    expect(classifyIoc('mlab.sh')).toBe('domain');
  });

  it('rejects bogus extensions that arent TLDs', () => {
    expect(classifyIoc('malware.unknownxyz123')).toBeNull();
    expect(classifyIoc('file.bak')).toBeNull();
  });

  it('handles trailing dot', () => {
    expect(classifyIoc('example.com.')).toBe('domain');
  });
});

describe('detectIocs', () => {
  it('finds bare domains', () => {
    const out = detectIocs('Visit malicious-site.com for more info.', { currentHost: '' });
    expect(out.map((i) => i.value)).toContain('malicious-site.com');
  });

  it('finds IPv4', () => {
    const out = detectIocs('Beacon to 185.220.101.7 detected.', { currentHost: '' });
    expect(out.find((i) => i.value === '185.220.101.7')?.type).toBe('ipv4');
  });

  it('flags reserved IPv4 ranges', () => {
    const out = detectIocs('Local 192.168.1.1 and 10.0.0.1 and 127.0.0.1', { currentHost: '' });
    const ips = out.filter((i) => i.type === 'ipv4');
    expect(ips.length).toBeGreaterThan(0);
    for (const ip of ips) expect(ip.reserved).toBe(true);
  });

  it('skips the current host and its subdomains', () => {
    const out = detectIocs('news.example.com and example.com and unrelated.test', { currentHost: 'news.example.com' });
    expect(out.find((i) => i.value === 'example.com')).toBeUndefined();
    expect(out.find((i) => i.value === 'news.example.com')).toBeUndefined();
  });

  it('filters allowlisted infra domains', () => {
    const out = detectIocs('Loaded from www.google.com and cdn.jsdelivr.net', { currentHost: '' });
    expect(out.find((i) => i.value === 'www.google.com')).toBeUndefined();
    expect(out.find((i) => i.value === 'cdn.jsdelivr.net')).toBeUndefined();
  });

  it('deduplicates repeated IOCs', () => {
    const out = detectIocs('evil.com evil.com evil.com 1.2.3.4 1.2.3.4', { currentHost: '' });
    expect(out.filter((i) => i.value === 'evil.com')).toHaveLength(1);
    expect(out.filter((i) => i.value === '1.2.3.4')).toHaveLength(1);
  });

  it('rejects domains whose extension isnt a known TLD', () => {
    const out = detectIocs('Found malware.bak and image.png references.', { currentHost: '' });
    expect(out.find((i) => i.value === 'malware.bak')).toBeUndefined();
    expect(out.find((i) => i.value === 'image.png')).toBeUndefined();
  });

  it('respects maxIocs cap', () => {
    const text = Array.from({ length: 50 }, (_, i) => `host${i}.example.org`).join(' ');
    const out = detectIocs(text, { currentHost: '', maxIocs: 5 });
    expect(out.length).toBeLessThanOrEqual(5);
  });

  it('does not detect crypto when detectCrypto is off (default)', () => {
    const text = 'send to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e please';
    const out = detectIocs(text, { currentHost: '' });
    expect(out.find((i) => i.type === 'crypto')).toBeUndefined();
  });

  it('detects ETH/EVM addresses when crypto detection is on', () => {
    const text = 'Send to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e for the payment.';
    const out = detectIocs(text, { currentHost: '', detectCrypto: true });
    const eth = out.find((i) => i.type === 'crypto');
    expect(eth).toBeDefined();
    expect(eth?.chain).toBe('ETH');
  });

  it('detects BTC legacy / p2sh / bech32', () => {
    const text = 'Pay 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy or bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq.';
    const out = detectIocs(text, { currentHost: '', detectCrypto: true });
    const btcs = out.filter((i) => i.type === 'crypto' && i.chain === 'BTC');
    expect(btcs.length).toBeGreaterThanOrEqual(3);
  });

  it('detects TRX addresses', () => {
    const text = 'TRX deposit: TLyqzVGLV1srkB7dToTAEqgDSfPtXRJZYH thanks.';
    const out = detectIocs(text, { currentHost: '', detectCrypto: true });
    expect(out.find((i) => i.chain === 'TRX')).toBeDefined();
  });

  it('classifies isolated addresses via classifyCrypto', () => {
    expect(classifyCrypto('0x742d35Cc6634C0532925a3b844Bc454e4438f44e')).toBe('ETH');
    expect(classifyCrypto('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')).toBe('BTC');
    expect(classifyCrypto('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq')).toBe('BTC');
    expect(classifyCrypto('TLyqzVGLV1srkB7dToTAEqgDSfPtXRJZYH')).toBe('TRX');
    // Solana — well-known address (Wrapped SOL mint, 44 chars base58 mixed-case+digits)
    expect(classifyCrypto('So11111111111111111111111111111111111111112')).toBe('SOL');
  });

  it('classifyIoc dispatches to crypto', () => {
    expect(classifyIoc('0x742d35Cc6634C0532925a3b844Bc454e4438f44e')).toBe('crypto');
  });

  it('does not flag long random base58 strings as SOL without entropy', () => {
    // All-lowercase, no digit — should NOT match Solana
    expect(classifyCrypto('abcdefghijklmnopqrstuvwxyzabcdefghij')).toBeNull();
  });
});
