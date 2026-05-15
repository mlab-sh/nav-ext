import type { ScanResult } from './types';

const KEY = 'history';
const MAX_ENTRIES = 10;

export async function getHistory(): Promise<ScanResult[]> {
  const r = await chrome.storage.local.get(KEY);
  return (r[KEY] as ScanResult[] | undefined) ?? [];
}

export async function addToHistory(result: ScanResult): Promise<void> {
  const list = await getHistory();
  const key = `${result.ioc.type}:${result.ioc.value}`;
  // de-dupe: move to top if already present
  const filtered = list.filter((r) => `${r.ioc.type}:${r.ioc.value}` !== key);
  filtered.unshift(result);
  const trimmed = filtered.slice(0, MAX_ENTRIES);
  await chrome.storage.local.set({ [KEY]: trimmed });
}

export async function clearHistory(): Promise<void> {
  await chrome.storage.local.remove(KEY);
}
