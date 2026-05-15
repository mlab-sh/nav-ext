import { clearCache } from '../lib/cache';
import { clearApiKey, hasApiKey, setApiKey, validateKey } from '../lib/mlab-client';
import { getSettings, updateSettings } from '../lib/settings';
import type { Msg } from '../lib/types';

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const apiKeyInput = $<HTMLInputElement>('apiKey');
const toggleVisibility = $<HTMLButtonElement>('toggleVisibility');
const saveBtn = $<HTMLButtonElement>('save');
const clearBtn = $<HTMLButtonElement>('clear');
const messageEl = $('message');
const statusEl = $('status');
const quotaEl = $('quota');
const refreshQuotaBtn = $<HTMLButtonElement>('refreshQuota');
const clearCacheBtn = $<HTMLButtonElement>('clearCache');
const cacheMessageEl = $('cacheMessage');
const versionEl = $('version');
const highlightToggle = $<HTMLInputElement>('highlightEnabled');

versionEl.textContent = chrome.runtime.getManifest().version;

async function refreshStatus() {
  const present = await hasApiKey();
  statusEl.textContent = present ? 'Authenticated' : 'Anonymous';
  statusEl.dataset.status = present ? 'authenticated' : 'anonymous';
  clearBtn.disabled = !present;
  apiKeyInput.placeholder = present ? '•••••••• (key stored)' : 'mlab_xxxxxxxxxxxxxxxx';
}

async function refreshQuota() {
  quotaEl.innerHTML = '<p class="muted">Loading…</p>';
  const r = await sendMsg<{ kind: 'limits'; limits: { domain?: { remaining: number; limit: number }; ip?: { remaining: number; limit: number } } }>({ kind: 'get-limits' });
  const l = r?.limits ?? {};
  const items: string[] = [];
  if (l.domain) items.push(pill('Domain', `${l.domain.remaining} / ${l.domain.limit}`));
  if (l.ip) items.push(pill('IP', `${l.ip.remaining} / ${l.ip.limit}`));
  if (!items.length) {
    quotaEl.innerHTML = '<p class="muted">Quota info unavailable — try again after a scan.</p>';
    return;
  }
  quotaEl.innerHTML = items.join('');
}

function pill(label: string, value: string): string {
  return `<div class="quota-pill"><span class="label">${label}</span><span class="value">${value}</span></div>`;
}

toggleVisibility.addEventListener('click', () => {
  apiKeyInput.type = apiKeyInput.type === 'password' ? 'text' : 'password';
});

saveBtn.addEventListener('click', async () => {
  const key = apiKeyInput.value.trim();
  if (!key) {
    showMessage(messageEl, 'Enter a key first.', 'error');
    return;
  }
  saveBtn.disabled = true;
  saveBtn.textContent = 'Validating…';
  const ok = await validateKey(key);
  if (ok) {
    await setApiKey(key);
    apiKeyInput.value = '';
    showMessage(messageEl, 'Key saved.', 'success');
    await refreshStatus();
    await refreshQuota();
  } else {
    showMessage(messageEl, 'Invalid key — mlab.sh rejected it.', 'error');
  }
  saveBtn.disabled = false;
  saveBtn.textContent = 'Save key';
});

clearBtn.addEventListener('click', async () => {
  await clearApiKey();
  apiKeyInput.value = '';
  showMessage(messageEl, 'Key removed. Reverting to Anonymous tier.', 'success');
  await refreshStatus();
  await refreshQuota();
});

refreshQuotaBtn.addEventListener('click', () => { refreshQuota(); });

clearCacheBtn.addEventListener('click', async () => {
  await clearCache();
  showMessage(cacheMessageEl, 'Cache cleared.', 'success');
});

function showMessage(el: HTMLElement, text: string, kind: 'success' | 'error') {
  el.textContent = text;
  el.className = `message ${kind}`;
  el.classList.remove('hidden');
  setTimeout(() => el.classList.add('hidden'), 3500);
}

function sendMsg<T>(msg: Msg): Promise<T | undefined> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (resp) => {
      if (chrome.runtime.lastError) resolve(undefined);
      else resolve(resp as T);
    });
  });
}

highlightToggle.addEventListener('change', async () => {
  await updateSettings({ highlightEnabled: highlightToggle.checked });
});

async function loadSettings() {
  const s = await getSettings();
  highlightToggle.checked = s.highlightEnabled;
}

refreshStatus();
refreshQuota();
loadSettings();
