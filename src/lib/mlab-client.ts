import type { CryptoChain, Limits, ScanResult, Verdict } from './types';

const API_BASE = 'https://mlab.sh/api/v1';
const REPORT_BASE = 'https://mlab.sh';
const API_KEY_STORAGE = 'apiKey';

export class MlabError extends Error {
  status: number;
  code: 'unauthorized' | 'rate-limited' | 'timeout' | 'http';
  constructor(code: MlabError['code'], message: string, status = 0) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

async function getApiKey(): Promise<string | null> {
  const r = await chrome.storage.local.get(API_KEY_STORAGE);
  return (r[API_KEY_STORAGE] as string | undefined) ?? null;
}

export async function setApiKey(key: string): Promise<void> {
  await chrome.storage.local.set({ [API_KEY_STORAGE]: key });
}

export async function clearApiKey(): Promise<void> {
  await chrome.storage.local.remove(API_KEY_STORAGE);
}

export async function hasApiKey(): Promise<boolean> {
  return !!(await getApiKey());
}

/**
 * Build request headers. Auth is optional — when no key is set, requests are
 * sent anonymously and rely on the mlab.sh "Anonymous" tier quota.
 */
async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const key = await getApiKey();
  const headers: Record<string, string> = {
    ...(init.headers as Record<string, string> | undefined),
    Accept: 'application/json',
  };
  if (key) headers.Authorization = `token ${key}`;
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (res.status === 401) throw new MlabError('unauthorized', 'Invalid API key', 401);
  if (res.status === 429) throw new MlabError('rate-limited', 'Quota exhausted', 429);
  if (!res.ok) throw new MlabError('http', `HTTP ${res.status}`, res.status);
  return res;
}

/** Verify a candidate API key by calling /limit/domain. Does not persist. */
export async function validateKey(key: string): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/limit/domain`, {
      headers: { Authorization: `token ${key}`, Accept: 'application/json' },
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function scanIp(ip: string, signal?: AbortSignal): Promise<ScanResult> {
  const res = await request(`/scan/ip?ip=${encodeURIComponent(ip)}`, { signal });
  const data = await res.json();
  return {
    ioc: { type: ip.includes(':') ? 'ipv6' : 'ipv4', value: ip },
    verdict: inferIpVerdict(data),
    data,
    fetchedAt: Date.now(),
    reportUrl: `${REPORT_BASE}/ip/${encodeURIComponent(ip)}`,
  };
}

export async function scanDomain(domain: string, signal?: AbortSignal): Promise<ScanResult> {
  // 0. Try fetching existing results first — if mlab.sh already has a report
  // for this domain, reuse it instead of burning a fresh scan against the quota.
  const existing = await tryFetchExistingDomain(domain, signal);
  if (existing) return existing;

  // 1. launch
  await request('/scan/domain', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain }),
    signal,
  });

  // 2. poll status
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    await sleep(2000, signal);
    const sres = await request(`/scan/domain/status?domain=${encodeURIComponent(domain)}`, { signal });
    const s = await sres.json();
    const st = (s?.status ?? '').toString().toLowerCase();
    if (['success', 'done', 'completed'].includes(st)) break;
    if (['error', 'failed'].includes(st)) throw new MlabError('http', 'Scan failed');
  }

  // 3. results
  const rres = await request(`/scan/domain/results?domain=${encodeURIComponent(domain)}`, { signal });
  const data = await rres.json();
  return buildDomainResult(domain, data);
}

/**
 * Cheap probe: GET /scan/domain/status returns {"status":"success", ...} when
 * mlab.sh already has a finished report for the domain. We reuse the existing
 * results in that case, skipping POST /scan/domain (the quota-consuming op).
 * Any other status ("pending"/"scanning"/error/404) means we should launch.
 */
async function tryFetchExistingDomain(domain: string, signal?: AbortSignal): Promise<ScanResult | null> {
  let status: string;
  try {
    const sres = await request(`/scan/domain/status?domain=${encodeURIComponent(domain)}`, { signal });
    const s = await sres.json();
    status = (s?.status ?? '').toString().toLowerCase();
  } catch (e) {
    if (e instanceof MlabError && (e.code === 'unauthorized' || e.code === 'rate-limited')) throw e;
    return null;
  }
  if (!['success', 'done', 'completed'].includes(status)) return null;

  try {
    const rres = await request(`/scan/domain/results?domain=${encodeURIComponent(domain)}`, { signal });
    const data = await rres.json();
    if (!data || typeof data !== 'object' || Object.keys(data as object).length === 0) return null;
    return buildDomainResult(domain, data);
  } catch (e) {
    if (e instanceof MlabError && (e.code === 'unauthorized' || e.code === 'rate-limited')) throw e;
    return null;
  }
}

function buildDomainResult(domain: string, data: unknown): ScanResult {
  return {
    ioc: { type: 'domain', value: domain },
    verdict: inferDomainVerdict(data),
    data,
    fetchedAt: Date.now(),
    reportUrl: `${REPORT_BASE}/domain/${encodeURIComponent(domain)}`,
  };
}

export async function scanCrypto(address: string, chain?: CryptoChain, signal?: AbortSignal): Promise<ScanResult> {
  const qs = new URLSearchParams({ address });
  if (chain) qs.set('chain', chain);
  const res = await request(`/scan/crypto?${qs.toString()}`, { signal });
  const data = await res.json();
  return {
    ioc: { type: 'crypto', value: address, chain },
    verdict: inferCryptoVerdict(data),
    data,
    fetchedAt: Date.now(),
    reportUrl: `${REPORT_BASE}/crypto/${encodeURIComponent(address)}`,
  };
}

export async function getLimits(): Promise<Limits> {
  const out: Limits = {};
  await Promise.all([
    request('/limit/domain').then((r) => r.json()).then((d) => { out.domain = parseLimit(d); }).catch(() => {}),
    request('/limit/ip').then((r) => r.json()).then((d) => { out.ip = parseLimit(d); }).catch(() => {}),
    request('/limit/crypto').then((r) => r.json()).then((d) => { out.crypto = parseLimit(d); }).catch(() => {}),
  ]);
  return out;
}

function parseLimit(data: any): { remaining: number; limit: number } {
  // Best-effort parsing — API shape may vary; we look for common keys.
  const remaining = Number(data?.remaining ?? data?.left ?? data?.available ?? 0);
  const limit = Number(data?.limit ?? data?.total ?? data?.max ?? 0);
  return { remaining, limit };
}

/**
 * Domain payload shape (sample):
 *   { domain, status: "completed", scan_date, results: { dns, ssl[], subdomains[], subdomains_suspicious[], files{} } }
 */
function inferDomainVerdict(data: any): Verdict {
  if (!data || typeof data !== 'object') return 'unknown';
  const results = data.results;
  if (!results || typeof results !== 'object') {
    // Top-level status fallback
    const st = (data.status ?? '').toString().toLowerCase();
    return st === 'completed' || st === 'success' || st === 'done' ? 'clean' : 'unknown';
  }
  const suspicious = results.subdomains_suspicious;
  if (Array.isArray(suspicious) && suspicious.length > 0) return 'suspicious';
  // No negative signals + we got a real report → clean
  return 'clean';
}

// Exported for unit tests; not part of the public API.
export { inferCryptoVerdict as __inferCryptoVerdictForTest };

/**
 * Crypto payload (real shape):
 *   { address, chain, type, categories[], labels[], risk_level, risk_score,
 *     sanctions: { is_sanctioned: bool, authority?, date? }, checked_at }
 */
function inferCryptoVerdict(data: any): Verdict {
  if (!data || typeof data !== 'object') return 'unknown';

  // Actually sanctioned → malicious. (Presence of the sanctions object alone is NOT a signal.)
  const sanctioned = data?.sanctions?.is_sanctioned === true || data?.sanctions?.sanctioned === true;
  if (sanctioned) return 'malicious';

  const cats: string[] = Array.isArray(data.categories)
    ? data.categories.map((c: any) => String(c).toLowerCase())
    : [];
  if (cats.some((c) => /scam|mixer|illicit|hack|stolen|ransom|sanctioned/.test(c))) return 'malicious';

  const level = (data.risk_level ?? '').toString().toLowerCase();
  const score = Number(data.risk_score);
  if (level === 'high' || (Number.isFinite(score) && score >= 75)) return 'malicious';
  if (level === 'medium' || (Number.isFinite(score) && score >= 40)) return 'suspicious';
  if (level === 'low' || (Number.isFinite(score) && score >= 0)) return 'clean';

  // Got a real payload (has address/type/categories) without negative signals → clean.
  if (data.address && (data.type || data.address_type || Array.isArray(data.categories))) return 'clean';

  return 'unknown';
}

/**
 * IP payload shape (sample):
 *   { ip, isp, as, country, region, city, lat, lon, reserved: bool, status: "success", ... }
 */
function inferIpVerdict(data: any): Verdict {
  if (!data || typeof data !== 'object') return 'unknown';
  // Reserved IPs (RFC1918, loopback…) aren't a threat signal, but they shouldn't show as "clean" either.
  if (data.reserved === true) return 'unknown';
  const st = (data.status ?? '').toString().toLowerCase();
  if (st === 'error' || st === 'failed') return 'unknown';
  // Real IP data with ASN/ISP info and not reserved → no negative signal exposed by this endpoint → clean.
  if (data.ip && (data.as || data.isp || data.country)) return 'clean';
  return 'unknown';
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => { clearTimeout(t); reject(new MlabError('timeout', 'aborted')); });
  });
}
