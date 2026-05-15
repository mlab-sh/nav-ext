import type { Ioc, ScanResult } from './types';

const NS = 'cache:';
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_ENTRIES = 500;

const key = (ioc: Ioc) => `${NS}${ioc.type}:${ioc.value}`;

export async function getCached(ioc: Ioc, ttlMs = DEFAULT_TTL_MS): Promise<ScanResult | null> {
  const k = key(ioc);
  const raw = await chrome.storage.local.get(k);
  const entry = raw[k] as ScanResult | undefined;
  if (!entry) return null;
  if (Date.now() - entry.fetchedAt > ttlMs) {
    await chrome.storage.local.remove(k);
    return null;
  }
  return entry;
}

export async function setCached(result: ScanResult): Promise<void> {
  const k = key(result.ioc);
  await chrome.storage.local.set({ [k]: result });
  // Best-effort eviction
  const all = await chrome.storage.local.get(null);
  const entries = Object.entries(all).filter(([kk]) => kk.startsWith(NS)) as [string, ScanResult][];
  if (entries.length > MAX_ENTRIES) {
    entries.sort((a, b) => a[1].fetchedAt - b[1].fetchedAt);
    const toRemove = entries.slice(0, entries.length - MAX_ENTRIES).map(([kk]) => kk);
    if (toRemove.length) await chrome.storage.local.remove(toRemove);
  }
}

export async function clearCache(): Promise<void> {
  const all = await chrome.storage.local.get(null);
  const toRemove = Object.keys(all).filter((k) => k.startsWith(NS));
  if (toRemove.length) await chrome.storage.local.remove(toRemove);
}
