export interface Settings {
  /** Visually highlight detected IOCs inline on every page. Off by default. */
  highlightEnabled: boolean;
}

const KEY = 'settings';

const DEFAULTS: Settings = {
  highlightEnabled: false,
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
