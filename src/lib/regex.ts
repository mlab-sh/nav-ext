import type { CryptoChain, DetectedIoc, IocType } from './types';
import TLDS from './data/tlds.json';

// IPv4 octet: 0-255
const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)';
export const IPV4_RE = new RegExp(`\\b${OCTET}(?:\\.${OCTET}){3}\\b`, 'g');

// IPv6: simplified but practical pattern (covers ::, IPv4-mapped, full form).
// Matches things like 2001:db8::1, fe80::1, ::1, ::ffff:192.0.2.1
export const IPV6_RE =
  /\b(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})|:(?:(?::[0-9a-f]{1,4}){1,7}|:)|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b/gi;

// --- Crypto wallet patterns ---
// EVM (Ethereum + chains compatible: BSC, Polygon, Arbitrum, Optimism, Base, Avalanche, Blast, Mantle).
// Exactly 40 hex chars after 0x.
export const ETH_RE = /\b0x[a-fA-F0-9]{40}\b/g;
// Bitcoin: legacy (1...), p2sh (3...), bech32 (bc1...). Length 26-62 for bech32, 26-35 for legacy/p2sh.
// Base58: no 0, O, I, l. Bech32: lowercase a-z 0-9 (excluding 1, b, i, o).
export const BTC_RE = /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{6,87})\b/g;
// Tron: 'T' + 33 base58 chars.
export const TRX_RE = /\bT[a-km-zA-HJ-NP-Z1-9]{33}\b/g;
// Solana: base58 32-44 chars. To avoid false positives on regular base58 strings, require a high-entropy pattern
// containing at least one uppercase + one digit. Also exclude strings that look like BTC/TRX.
export const SOL_RE = /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g;

// Domain: 1+ labels then a TLD. Lowercased input expected.
// Allows underscores in labels (some legitimate uses, but rare — kept conservative without).
export const DOMAIN_RE =
  /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;

// Full IANA TLD list (ASCII only — IDN punycode TLDs excluded to keep the regex predictable).
// Source: https://data.iana.org/TLD/tlds-alpha-by-domain.txt, embedded as JSON.
export const KNOWN_TLDS: ReadonlySet<string> = new Set(TLDS as string[]);

const RESERVED_IPV4_PREFIXES = [
  '0.', '10.', '127.', '169.254.', '224.', '255.255.255.',
];

function isReservedIpv4(ip: string): boolean {
  if (RESERVED_IPV4_PREFIXES.some((p) => ip.startsWith(p))) return true;
  const [a, b] = ip.split('.').map(Number);
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  return false;
}

function isReservedIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  return (
    lower === '::1' ||
    lower === '::' ||
    lower.startsWith('fe80:') ||
    lower.startsWith('fc') ||
    lower.startsWith('fd') ||
    lower.startsWith('ff')
  );
}

/**
 * Hostname allowlist — registrable domains where we never propose a scan.
 * Matching is suffix-based: any subdomain of an allowlisted apex is filtered out.
 * Keep the list opinionated and bounded; the goal is to cut top-N false positives,
 * not to be exhaustive (users can still scan manually via popup if needed).
 */
const ALLOWLIST_APEX: ReadonlySet<string> = new Set([
  // Google
  'google.com','google.co.uk','google.fr','google.de','google.es','google.it','google.jp','google.ca','google.com.au',
  'gstatic.com','googleapis.com','googleusercontent.com','googletagmanager.com','google-analytics.com','googlesyndication.com','googleadservices.com','doubleclick.net','ggpht.com',
  'gmail.com','youtube.com','youtu.be','ytimg.com','blogspot.com','goo.gl',
  // Cloudflare / CDNs
  'cloudflare.com','cloudflareinsights.com','cloudflare-cdn.com','cdnjs.cloudflare.com','workers.dev','pages.dev',
  'jsdelivr.net','unpkg.com','npmjs.com','npmjs.org','rawgit.com','rawgithubusercontent.com',
  'fastly.net','fastlylb.net','akamai.net','akamaihd.net','akamaized.net','edgekey.net','edgesuite.net',
  // Mozilla
  'mozilla.org','firefox.com','mozilla.net','mozaws.net','services.mozilla.com',
  // Microsoft
  'microsoft.com','msft.net','live.com','office.com','office365.com','sharepoint.com','outlook.com','hotmail.com',
  'bing.com','msn.com','msecnd.net','windowsupdate.com','windows.net','azure.com','azureedge.net','azurewebsites.net','azure-api.net','visualstudio.com','vscode.dev','msftauth.net',
  // Apple
  'apple.com','icloud.com','itunes.com','apple-cloudkit.com','mzstatic.com','cdn-apple.com',
  // GitHub / GitLab
  'github.com','githubusercontent.com','githubassets.com','github.io','githubapp.com','gitlab.com','gitlab.io','bitbucket.org','sourceforge.net',
  // Knowledge / docs
  'wikipedia.org','wikimedia.org','wiktionary.org','wikidata.org','archive.org',
  // AWS / GCP / Cloud
  'amazon.com','amazonaws.com','aws.amazon.com','cloudfront.net','s3.amazonaws.com','elasticbeanstalk.com',
  'googlecloud.com','gcr.io','firebaseapp.com','firebase.com','appspot.com',
  'digitalocean.com','linode.com','ovh.com','ovh.net','heroku.com','herokuapp.com','vercel.app','vercel.com','netlify.com','netlify.app','render.com',
  // Meta
  'facebook.com','fbcdn.net','fb.com','instagram.com','cdninstagram.com','threads.net','whatsapp.com','whatsapp.net','messenger.com',
  // X / Twitter
  'x.com','twitter.com','twimg.com','t.co',
  // LinkedIn / Reddit / Pinterest
  'linkedin.com','licdn.com',
  'reddit.com','redd.it','redditstatic.com','redditmedia.com',
  'pinterest.com','pinimg.com',
  // Dev/community
  'stackoverflow.com','stackexchange.com','superuser.com','serverfault.com',
  'medium.com','dev.to','hashnode.dev','substack.com',
  // Ads / analytics (treat as allowlisted to reduce noise — user can scan manually if needed)
  'doubleclick.net','adservice.google.com','adsystem.com','adsafeprotected.com','scorecardresearch.com','quantserve.com','hotjar.com','mixpanel.com','segment.com','segment.io','amplitude.com','sentry.io','datadoghq.com','newrelic.com',
  // Fonts / web infra
  'fonts.googleapis.com','fonts.gstatic.com','typekit.net','typekit.com','use.typekit.net',
  // Communication
  'slack.com','slack-edge.com','discord.com','discordapp.com','discordapp.net','zoom.us','zoom.com','teams.microsoft.com',
  // Atlassian
  'atlassian.com','atlassian.net','jira.com','confluence.com',
  // Payment / SaaS leaders
  'stripe.com','paypal.com','paypalobjects.com','squareup.com','shopify.com','myshopify.com',
  // News / video
  'cnn.com','nytimes.com','bbc.com','bbc.co.uk','theguardian.com','reuters.com','bloomberg.com','wsj.com',
  'twitch.tv','twitchcdn.net','vimeo.com','vimeocdn.com','dailymotion.com',
  'spotify.com','scdn.co','soundcloud.com',
  // Misc tooling
  'figma.com','notion.so','notion.site','airtable.com','dropbox.com','dropboxusercontent.com','box.com','intercom.com','intercom.io','zendesk.com','hubspot.com','salesforce.com','force.com',
  // mlab.sh itself
  'mlab.sh',
]);

/** True iff `domain` equals or is a subdomain of any allowlisted apex. */
function isInAllowlist(domain: string): boolean {
  const d = domain.toLowerCase();
  if (ALLOWLIST_APEX.has(d)) return true;
  for (const apex of ALLOWLIST_APEX) {
    if (d.endsWith('.' + apex)) return true;
  }
  return false;
}

function isAllowlisted(domain: string, currentHost: string): boolean {
  const d = domain.toLowerCase();
  if (isInAllowlist(d)) return true;
  const host = currentHost.toLowerCase();
  if (!host) return false;
  if (d === host) return true;
  if (host.endsWith('.' + d)) return true;
  if (d.endsWith('.' + host)) return true;
  return false;
}

export interface DetectOptions {
  currentHost?: string;
  /** Cap total IOCs to avoid huge pages destroying perf */
  maxIocs?: number;
  /** Detect crypto wallet addresses. Off by default — opt-in via settings. */
  detectCrypto?: boolean;
}

/** Heuristic: a base58 string is "wallet-like" if it has both digits and mixed case. Cuts down Solana false positives. */
function isHighEntropyBase58(s: string): boolean {
  return /[0-9]/.test(s) && /[A-Z]/.test(s) && /[a-z]/.test(s);
}

/**
 * Identify the most likely crypto chain for a given address string.
 * Returns null when the format doesn't match any supported chain.
 */
export function classifyCrypto(value: string): CryptoChain | null {
  const v = value.trim();
  if (/^0x[a-fA-F0-9]{40}$/.test(v)) return 'ETH';
  if (/^T[a-km-zA-HJ-NP-Z1-9]{33}$/.test(v)) return 'TRX';
  if (/^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{6,87})$/.test(v)) return 'BTC';
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(v) && isHighEntropyBase58(v)) return 'SOL';
  return null;
}

/**
 * Detect IOCs in a string. Caller is responsible for refanging beforehand.
 * Returns deduplicated list with type classification.
 */
export function detectIocs(text: string, opts: DetectOptions = {}): DetectedIoc[] {
  const max = opts.maxIocs ?? 500;
  const host = opts.currentHost ?? '';
  const seen = new Map<string, DetectedIoc>(); // key: `${type}:${value}`

  const push = (type: IocType, value: string, raw: string, extra: Partial<DetectedIoc> = {}) => {
    const key = `${type}:${value}`;
    if (seen.has(key)) return;
    if (seen.size >= max) return;
    seen.set(key, { type, value, raw, ...extra });
  };

  // IPv4
  for (const m of text.matchAll(IPV4_RE)) {
    const ip = m[0];
    push('ipv4', ip, ip, { reserved: isReservedIpv4(ip) });
  }

  // IPv6 (skip if it looks like a plain "::" or a time)
  for (const m of text.matchAll(IPV6_RE)) {
    const ip = m[0].toLowerCase();
    if (!ip.includes(':')) continue;
    if (ip.length < 3) continue;
    push('ipv6', ip, m[0], { reserved: isReservedIpv6(ip) });
  }

  // Crypto wallets (opt-in)
  if (opts.detectCrypto) {
    for (const m of text.matchAll(ETH_RE)) {
      const v = m[0].toLowerCase();
      push('crypto', v, m[0], { chain: 'ETH' });
    }
    for (const m of text.matchAll(BTC_RE)) {
      const v = m[0];
      push('crypto', v, v, { chain: 'BTC' });
    }
    for (const m of text.matchAll(TRX_RE)) {
      push('crypto', m[0], m[0], { chain: 'TRX' });
    }
    for (const m of text.matchAll(SOL_RE)) {
      const v = m[0];
      // Skip strings already captured as BTC/TRX
      if (seen.has(`crypto:${v}`)) continue;
      // Solana addresses overlap with random base58. Apply entropy filter and length floor.
      if (v.length < 32 || v.length > 44) continue;
      if (!isHighEntropyBase58(v)) continue;
      // Skip if it could be classified as another chain
      const chain = classifyCrypto(v);
      if (chain && chain !== 'SOL') continue;
      push('crypto', v, v, { chain: 'SOL' });
    }
  }

  // Domains
  for (const m of text.matchAll(DOMAIN_RE)) {
    const raw = m[0];
    const d = raw.toLowerCase();
    // strip trailing dot
    const value = d.endsWith('.') ? d.slice(0, -1) : d;
    const tld = value.split('.').pop()!;
    if (!KNOWN_TLDS.has(tld)) continue;
    if (isAllowlisted(value, host)) continue;
    // also drop pure-numeric "domains" (already caught by IPv4 but defensive)
    if (/^\d+(\.\d+)+$/.test(value)) continue;
    push('domain', value, raw);
  }

  return [...seen.values()];
}

/** Classify a single string entered manually or selected — returns its IOC type. */
export function classifyIoc(text: string): IocType | null {
  const t = text.trim();
  if (!t) return null;
  if (new RegExp(`^${OCTET}(?:\\.${OCTET}){3}$`).test(t)) return 'ipv4';
  if (/^[0-9a-f:]+$/i.test(t) && t.includes(':')) return 'ipv6';
  if (classifyCrypto(t)) return 'crypto';
  const lower = t.toLowerCase().replace(/\.$/, '');
  const tld = lower.split('.').pop();
  if (tld && KNOWN_TLDS.has(tld) && DOMAIN_RE.test(lower)) {
    DOMAIN_RE.lastIndex = 0;
    return 'domain';
  }
  return null;
}
