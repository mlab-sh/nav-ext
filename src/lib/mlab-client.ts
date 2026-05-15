import type { Limits, ScanResult, Verdict } from './types';

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

export async function scanIp(ip: string): Promise<ScanResult> {
  const res = await request(`/scan/ip?ip=${encodeURIComponent(ip)}`);
  const data = await res.json();
  return {
    ioc: { type: ip.includes(':') ? 'ipv6' : 'ipv4', value: ip },
    verdict: inferVerdict(data),
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
    if (s?.status === 'success' || s?.status === 'done' || s?.status === 'completed') break;
    if (s?.status === 'error' || s?.status === 'failed') throw new MlabError('http', 'Scan failed');
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
  if (status !== 'success' && status !== 'done' && status !== 'completed') return null;

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
    verdict: inferVerdict(data),
    data,
    fetchedAt: Date.now(),
    reportUrl: `${REPORT_BASE}/domain/${encodeURIComponent(domain)}`,
  };
}

export async function getLimits(): Promise<Limits> {
  const out: Limits = {};
  await Promise.all([
    request('/limit/domain').then((r) => r.json()).then((d) => { out.domain = parseLimit(d); }).catch(() => {}),
    request('/limit/ip').then((r) => r.json()).then((d) => { out.ip = parseLimit(d); }).catch(() => {}),
  ]);
  return out;
}

function parseLimit(data: any): { remaining: number; limit: number } {
  // Best-effort parsing — API shape may vary; we look for common keys.
  const remaining = Number(data?.remaining ?? data?.left ?? data?.available ?? 0);
  const limit = Number(data?.limit ?? data?.total ?? data?.max ?? 0);
  return { remaining, limit };
}

function inferVerdict(data: any): Verdict {
  if (!data || typeof data !== 'object') return 'unknown';

  // Explicit verdict/threat fields take precedence
  const v = (data.verdict || data.threat || '').toString().toLowerCase();
  if (v.includes('malicious') || v.includes('bad')) return 'malicious';
  if (v.includes('suspicious') || v.includes('warn')) return 'suspicious';
  if (v.includes('clean') || v.includes('good') || v.includes('safe')) return 'clean';

  // Heuristics on common report shapes
  const suspiciousSubs = data.subdomains_suspicious;
  if (Array.isArray(suspiciousSubs) && suspiciousSubs.length > 0) return 'suspicious';
  if (typeof suspiciousSubs === 'number' && suspiciousSubs > 0) return 'suspicious';

  const reputation = (data.reputation || data.risk_level || data.category || '').toString().toLowerCase();
  if (reputation.includes('malicious') || reputation.includes('high')) return 'malicious';
  if (reputation.includes('suspicious') || reputation.includes('medium')) return 'suspicious';
  if (reputation.includes('clean') || reputation.includes('low') || reputation.includes('safe')) return 'clean';

  // Got a real report payload without negative signals → treat as clean.
  // We distinguish this from an empty/error payload by checking for at least one known report key.
  const KNOWN = ['subdomains', 'dns', 'ssl', 'whois', 'certificates', 'ips', 'asn', 'geolocation', 'hosting', 'files', 'isp', 'organization', 'country'];
  if (KNOWN.some((k) => k in data)) return 'clean';

  // status:"success" alone (without any data field) — still treat as clean
  if ((data.status || '').toString().toLowerCase() === 'success') return 'clean';

  return 'unknown';
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => { clearTimeout(t); reject(new MlabError('timeout', 'aborted')); });
  });
}
