import type { DetectedIoc, IocType } from './types';

// IPv4 octet: 0-255
const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)';
export const IPV4_RE = new RegExp(`\\b${OCTET}(?:\\.${OCTET}){3}\\b`, 'g');

// IPv6: simplified but practical pattern (covers ::, IPv4-mapped, full form).
// Matches things like 2001:db8::1, fe80::1, ::1, ::ffff:192.0.2.1
export const IPV6_RE =
  /\b(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})|:(?:(?::[0-9a-f]{1,4}){1,7}|:)|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b/gi;

// Domain: 1+ labels then a TLD. Lowercased input expected.
// Allows underscores in labels (some legitimate uses, but rare — kept conservative without).
export const DOMAIN_RE =
  /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;

// Common TLDs allow-list (subset of IANA list, kept short for size).
// Anything matching DOMAIN_RE whose TLD isn't here is dropped to cut false positives like "foo.exe".
// Source: most-frequent + ccTLDs. Easy to expand.
export const KNOWN_TLDS: ReadonlySet<string> = new Set([
  'com','net','org','io','ai','co','gov','edu','mil','info','biz','app','dev','xyz','site','online','tech','cloud','sh','me','tv','cc','to','ly','it','de','fr','uk','us','ca','au','nz','jp','cn','kr','ru','br','mx','in','nl','se','no','fi','dk','pl','cz','at','ch','be','es','pt','gr','tr','ie','hu','ro','bg','hr','sk','si','lt','lv','ee','il','sa','ae','za','ng','ke','eg','ma','ar','cl','co','pe','ve','tw','hk','sg','my','th','id','ph','vn','pk','bd','lk','ir','iq','ua','by','rs','ba','mk','al','md','mt','lu','is','li','mc','sm','va','re','io','cat','eu','asia','tel','mobi','name','pro','aero','coop','museum','jobs','xxx','adult','wiki','blog','news','today','life','world','space','live','store','shop','game','games','art','design','studio','agency','solutions','services','tools','digital','network','systems','software','technology','academy','school','university','health','medical','clinic','legal','finance','bank','exchange','trade','market','capital','fund','money','pay','crypto','nft','dao','eth','box','one','top','vip','run','red','blue','green','black','gold','party','team','club','fans','fan','social','community','forum','chat','group','events','expert','guru','ninja','rocks','works','zone','center','center','energy','engineering','science','support','help','review','reviews','rocks','gallery','photography','photos','video','audio','music','film','movie','tube','press','media','tv','radio','show','live','stream','play','win','lose','best','plus','cool','fun','hot','new','sexy','wtf','lol','pizza','coffee','tea','bar','cafe','restaurant','food','beer','wine','vegas','beach','ski','golf','football','tennis','run','bike','fish','vet','pets','dog','cat'
]);

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

/** Hostname allowlist — domains where we never propose a scan. */
const ALLOWLIST: ReadonlySet<string> = new Set([
  'google.com','www.google.com','gstatic.com','googleapis.com','googleusercontent.com','gmail.com','youtube.com','youtu.be',
  'cloudflare.com','cloudflareinsights.com','cdnjs.cloudflare.com',
  'mozilla.org','firefox.com','mozilla.net',
  'microsoft.com','live.com','office.com','bing.com','msn.com','windows.net','azureedge.net',
  'apple.com','icloud.com','itunes.com',
  'github.com','githubusercontent.com','githubassets.com',
  'wikipedia.org','wikimedia.org',
  'amazon.com','amazonaws.com','aws.amazon.com',
  'facebook.com','fbcdn.net','instagram.com','threads.net','whatsapp.com',
  'x.com','twitter.com','twimg.com','t.co',
  'linkedin.com','licdn.com',
  'reddit.com','redd.it','redditstatic.com',
  'jsdelivr.net','unpkg.com','npmjs.com',
  'stackoverflow.com','stackexchange.com',
  'mlab.sh',
]);

function isAllowlisted(domain: string, currentHost: string): boolean {
  const d = domain.toLowerCase();
  if (ALLOWLIST.has(d)) return true;
  // also skip the current site and its parent (e.g. on news.example.com, drop example.com too)
  const host = currentHost.toLowerCase();
  if (d === host) return true;
  if (host.endsWith('.' + d)) return true;
  if (d.endsWith('.' + host)) return true;
  return false;
}

export interface DetectOptions {
  currentHost?: string;
  /** Cap total IOCs to avoid huge pages destroying perf */
  maxIocs?: number;
}

/**
 * Detect IOCs in a string. Caller is responsible for refanging beforehand.
 * Returns deduplicated list with type classification.
 */
export function detectIocs(text: string, opts: DetectOptions = {}): DetectedIoc[] {
  const max = opts.maxIocs ?? 500;
  const host = opts.currentHost ?? '';
  const seen = new Map<string, DetectedIoc>(); // key: `${type}:${value}`

  const push = (type: IocType, value: string, raw: string, reserved?: boolean) => {
    const key = `${type}:${value}`;
    if (seen.has(key)) return;
    if (seen.size >= max) return;
    seen.set(key, { type, value, raw, reserved });
  };

  // IPv4
  for (const m of text.matchAll(IPV4_RE)) {
    const ip = m[0];
    push('ipv4', ip, ip, isReservedIpv4(ip));
  }

  // IPv6 (skip if it looks like a plain "::" or a time)
  for (const m of text.matchAll(IPV6_RE)) {
    const ip = m[0].toLowerCase();
    if (!ip.includes(':')) continue;
    if (ip.length < 3) continue;
    push('ipv6', ip, m[0], isReservedIpv6(ip));
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
  const lower = t.toLowerCase().replace(/\.$/, '');
  const tld = lower.split('.').pop();
  if (tld && KNOWN_TLDS.has(tld) && DOMAIN_RE.test(lower)) {
    DOMAIN_RE.lastIndex = 0;
    return 'domain';
  }
  return null;
}
