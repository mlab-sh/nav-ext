export interface Settings {
  /** Visually highlight detected IOCs inline on every page. Off by default. */
  highlightEnabled: boolean;
  /** Hostnames where the extension stays passive (no scan, no highlight, no badge). */
  disabledHosts: string[];
  /** Show a desktop notification when a scan returns "malicious". */
  notifyOnMalicious: boolean;
  /** Detect crypto wallet addresses (BTC/ETH/TRX/SOL/…). Off by default — opt-in. */
  cryptoDetectionEnabled: boolean;
}

const KEY = 'settings';

const DEFAULTS: Settings = {
  highlightEnabled: false,
  disabledHosts: [],
  notifyOnMalicious: true,
  cryptoDetectionEnabled: false,
};

export async function getSettings(): Promise<Settings> {
  const r = await chrome.storage.local.get(KEY);
  return { ...DEFAULTS, ...(r[KEY] as Partial<Settings> | undefined) };
}

export async function updateSettings(patch: Partial<Settings>): Promise<Settings> {
  const current = await getSettings();
  const next = { ...current, ...patch };
  await chrome.storage.local.set({ [KEY]: next });
  return next;
}

export const SETTINGS_KEY = KEY;

export function isHostDisabled(host: string, disabled: string[]): boolean {
  const h = host.toLowerCase();
  return disabled.some((d) => {
    const dd = d.toLowerCase();
    return h === dd || h.endsWith('.' + dd);
  });
}

export async function toggleHostDisabled(host: string): Promise<boolean> {
  const s = await getSettings();
  const h = host.toLowerCase();
  const isDisabled = isHostDisabled(h, s.disabledHosts);
  const next = isDisabled
    ? s.disabledHosts.filter((d) => d.toLowerCase() !== h)
    : [...s.disabledHosts, h];
  await updateSettings({ disabledHosts: next });
  return !isDisabled;
}
