import { classifyCrypto, classifyIoc } from '../lib/regex';
import { refang } from '../lib/refang';
import { getSettings, isHostDisabled, toggleHostDisabled } from '../lib/settings';
import type { DetectedIoc, Ioc, Msg, ScanResult } from '../lib/types';

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const authBadge = $('authBadge');
const openSettings = $<HTMLButtonElement>('openSettings');
const openSettingsFooter = $<HTMLButtonElement>('openSettingsFooter');
const scanCurrentBtn = $<HTMLButtonElement>('scanCurrent');
const manualInput = $<HTMLInputElement>('manualInput');
const scanManualBtn = $<HTMLButtonElement>('scanManual');
const manualHint = $('manualHint');
const iocList = $('iocList');
const iocCount = $('iocCount');
const resultsEl = $('results');
const limitsEl = $('limits');
const historyList = $('historyList');
const historyFilter = $<HTMLInputElement>('historyFilter');
const clearHistoryBtn = $<HTMLButtonElement>('clearHistory');
const siteHostEl = $('siteHost');
const toggleSiteBtn = $<HTMLButtonElement>('toggleSite');

let currentHost = '';

const recentResults = new Map<string, ScanResult>();

async function init() {
  setupTabs();
  await refreshSiteToggle();
  await refreshAuthStatus();
  await refreshAll();
}

async function refreshSiteToggle() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try {
    currentHost = tab?.url ? new URL(tab.url).hostname : '';
  } catch { currentHost = ''; }
  if (!currentHost) {
    siteHostEl.textContent = '';
    toggleSiteBtn.classList.add('hidden');
    return;
  }
  siteHostEl.textContent = currentHost;
  const s = await getSettings();
  const disabled = isHostDisabled(currentHost, s.disabledHosts);
  toggleSiteBtn.textContent = disabled ? 'Enable on this site' : 'Disable on this site';
  toggleSiteBtn.classList.remove('hidden');
}

toggleSiteBtn.addEventListener('click', async () => {
  if (!currentHost) return;
  await toggleHostDisabled(currentHost);
  await refreshSiteToggle();
});

function setupTabs() {
  const tabs = document.querySelectorAll<HTMLButtonElement>('.tab');
  tabs.forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      if (!target) return;
      tabs.forEach((b) => b.classList.toggle('active', b === btn));
      document.querySelectorAll<HTMLElement>('.tab-panel').forEach((p) => {
        p.classList.toggle('active', p.id === `tab-${target}`);
      });
      if (target === 'history') refreshHistory();
    });
  });
}

clearHistoryBtn.addEventListener('click', async () => {
  await sendMsg({ kind: 'clear-history' });
  await refreshHistory();
});

let historyCache: ScanResult[] = [];

historyFilter.addEventListener('input', () => renderHistoryList());

async function refreshHistory() {
  const r = await sendMsg<{ kind: 'history'; entries: ScanResult[] }>({ kind: 'get-history' });
  historyCache = r?.entries ?? [];
  renderHistoryList();
}

function renderHistoryList() {
  const q = historyFilter.value.trim().toLowerCase();
  const entries = q
    ? historyCache.filter((r) => r.ioc.value.toLowerCase().includes(q) || r.ioc.type.includes(q) || r.verdict.includes(q))
    : historyCache;
  historyList.innerHTML = '';
  if (!entries.length) {
    historyList.innerHTML = `<p class="muted empty">${q ? 'No matches.' : 'No scans yet.'}</p>`;
    return;
  }
  for (const r of entries) {
    const isError = !!(r.data && typeof r.data === 'object' && (r.data as any).error);
    const label = isError ? (r.data as any).error : r.verdict;
    const ago = relTime(r.fetchedAt);
    const row = document.createElement('div');
    row.className = 'ioc-row';
    row.innerHTML = `
      <span class="verdict" data-v="${escapeHtml(r.verdict)}"></span>
      <span class="ioc-type">${r.ioc.type}</span>
      <span class="ioc-value" title="${escapeHtml(r.ioc.value)}">${escapeHtml(r.ioc.value)}</span>
      <span class="${isError ? 'error small' : 'muted small'}" title="${escapeHtml(label)}">${escapeHtml(ago)}</span>
    `;
    if (r.reportUrl) {
      const a = document.createElement('a');
      a.href = r.reportUrl;
      a.target = '_blank';
      a.rel = 'noopener';
      a.textContent = '↗';
      a.className = 'small';
      a.style.color = 'var(--accent-hover)';
      a.style.marginLeft = '4px';
      row.appendChild(a);
    }
    row.addEventListener('click', (e) => {
      if ((e.target as HTMLElement).tagName === 'A') return;
      triggerScan({ type: r.ioc.type, value: r.ioc.value });
      // switch to detected tab to show pending result
      document.querySelector<HTMLButtonElement>('.tab[data-tab="detected"]')?.click();
    });
    row.style.cursor = 'pointer';
    historyList.appendChild(row);
  }
}

function relTime(ts: number): string {
  const diff = Date.now() - ts;
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

async function refreshAuthStatus() {
  const r = await sendMsg<{ kind: 'has-api-key-result'; present: boolean }>({ kind: 'has-api-key' });
  const present = !!r?.present;
  authBadge.textContent = present ? 'Authenticated' : 'Anonymous';
  authBadge.dataset.auth = present ? 'authenticated' : 'anonymous';
  authBadge.title = present ? 'Using your mlab.sh API key' : 'Using mlab.sh Anonymous tier (limited quota) — click ⚙ to add a key';
}

const openOptions = () => chrome.runtime.openOptionsPage();
openSettings.addEventListener('click', openOptions);
openSettingsFooter.addEventListener('click', openOptions);

scanCurrentBtn.addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;
  try {
    const u = new URL(tab.url);
    if (!u.hostname) return;
    triggerScan({ type: 'domain', value: u.hostname });
  } catch { /* ignore */ }
});

manualInput.addEventListener('input', () => {
  const v = refang(manualInput.value.trim());
  const t = v ? classifyIoc(v) : null;
  if (!v) {
    manualHint.classList.add('hidden');
  } else if (t) {
    const chain = t === 'crypto' ? classifyCrypto(v) : null;
    const label = chain ? `${t.toUpperCase()} (${chain})` : t.toUpperCase();
    manualHint.textContent = `Detected as ${label}${v !== manualInput.value.trim() ? ` (refanged: ${v})` : ''}`;
    manualHint.classList.remove('hidden');
  } else {
    manualHint.textContent = 'Unrecognized format.';
    manualHint.classList.remove('hidden');
  }
});

function makeIoc(t: ReturnType<typeof classifyIoc>, v: string): Ioc | null {
  if (!t) return null;
  // Crypto addresses are checksum/base58 — preserve case. Others normalize to lowercase.
  if (t === 'crypto') return { type: t, value: v, chain: classifyCrypto(v) ?? undefined };
  return { type: t, value: v.toLowerCase() };
}

scanManualBtn.addEventListener('click', () => {
  const raw = manualInput.value;
  if (!raw.trim()) return;
  const tokens = raw.split(/[\s,;]+/).map((t) => refang(t.trim())).filter(Boolean);
  if (tokens.length <= 1) {
    const v = refang(raw.trim());
    const ioc = makeIoc(v ? classifyIoc(v) : null, v);
    if (!ioc) return;
    triggerScan(ioc);
    return;
  }
  const seen = new Set<string>();
  let scanned = 0;
  for (const v of tokens) {
    const ioc = makeIoc(classifyIoc(v), v);
    if (!ioc) continue;
    const key = `${ioc.type}:${ioc.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    triggerScan(ioc);
    scanned++;
  }
  manualHint.textContent = `Queued ${scanned} scan${scanned === 1 ? '' : 's'}.`;
  manualHint.classList.remove('hidden');
  manualInput.value = '';
});

manualInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') scanManualBtn.click();
});

function triggerScan(ioc: Ioc) {
  addPendingResult(ioc);
  chrome.runtime.sendMessage<Msg>({ kind: 'scan', ioc });
}

chrome.runtime.onMessage.addListener((msg: Msg) => {
  if (msg.kind === 'scan-result') {
    recentResults.set(`${msg.result.ioc.type}:${msg.result.ioc.value}`, msg.result);
    renderResults();
    refreshLimits();
    // history may be visible — refresh in background
    refreshHistory();
  }
});

async function refreshAll() {
  await Promise.all([refreshIocs(), refreshLimits()]);
}

async function refreshIocs() {
  const r = await sendMsg<{ kind: 'tab-iocs'; iocs: DetectedIoc[] }>({ kind: 'get-tab-iocs' });
  const iocs = r?.iocs ?? [];
  iocCount.textContent = iocs.length ? `(${iocs.length})` : '';
  iocList.innerHTML = '';
  if (!iocs.length) {
    iocList.innerHTML = '<p class="muted empty">No IOCs detected.</p>';
    return;
  }
  for (const ioc of iocs.slice(0, 50)) {
    const row = document.createElement('div');
    row.className = 'ioc-row';
    if (ioc.reserved) row.dataset.reserved = '1';
    const typeLabel = ioc.type === 'crypto' && ioc.chain ? `${ioc.type} ${ioc.chain}` : ioc.type;
    row.innerHTML = `
      <span class="ioc-type">${escapeHtml(typeLabel)}</span>
      <span class="ioc-value" title="${escapeHtml(ioc.value)}">${escapeHtml(ioc.value)}</span>
      <button class="scan-btn">Scan</button>
    `;
    row.querySelector<HTMLButtonElement>('.scan-btn')?.addEventListener('click', () => {
      triggerScan({ type: ioc.type, value: ioc.value, chain: ioc.chain });
    });
    iocList.appendChild(row);
  }
}

async function refreshLimits() {
  const r = await sendMsg<{ kind: 'limits'; limits: { domain?: { remaining: number; limit: number }, ip?: { remaining: number; limit: number }, crypto?: { remaining: number; limit: number } } }>({ kind: 'get-limits' });
  const l = r?.limits;
  const parts: string[] = [];
  if (l?.domain) parts.push(`<span class="pill">D ${l.domain.remaining}/${l.domain.limit}</span>`);
  if (l?.ip) parts.push(`<span class="pill">IP ${l.ip.remaining}/${l.ip.limit}</span>`);
  if (l?.crypto) parts.push(`<span class="pill">C ${l.crypto.remaining}/${l.crypto.limit}</span>`);
  limitsEl.innerHTML = parts.join('');
}

function addPendingResult(ioc: Ioc) {
  const key = `${ioc.type}:${ioc.value}`;
  if (recentResults.has(key)) return;
  recentResults.set(key, {
    ioc,
    verdict: 'unknown',
    data: { pending: true },
    fetchedAt: Date.now(),
  });
  renderResults();
}

function renderResults() {
  resultsEl.innerHTML = '';
  if (!recentResults.size) {
    resultsEl.innerHTML = '<p class="muted empty">Scan something to see results.</p>';
    return;
  }
  const sorted = [...recentResults.values()].sort((a, b) => b.fetchedAt - a.fetchedAt);
  for (const r of sorted.slice(0, 15)) {
    const isError = !!(r.data && typeof r.data === 'object' && (r.data as any).error);
    const isPending = !!(r.data && typeof r.data === 'object' && (r.data as any).pending);
    const label = isPending ? 'scanning…' : isError ? (r.data as any).error : r.verdict;
    const row = document.createElement('div');
    row.className = 'result-row';
    row.innerHTML = `
      <span class="verdict" data-v="${escapeHtml(r.verdict)}"></span>
      <span class="ioc-type">${r.ioc.type}</span>
      <span class="ioc-value" title="${escapeHtml(r.ioc.value)}">${escapeHtml(r.ioc.value)}</span>
      <span class="${isError ? 'error small' : 'muted small'}">${escapeHtml(label)}</span>
    `;
    if (r.reportUrl) {
      const a = document.createElement('a');
      a.href = r.reportUrl;
      a.target = '_blank';
      a.rel = 'noopener';
      a.textContent = '↗';
      row.appendChild(a);
    }
    resultsEl.appendChild(row);
  }
}

function sendMsg<T>(msg: Msg): Promise<T | undefined> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (resp) => {
      if (chrome.runtime.lastError) resolve(undefined);
      else resolve(resp as T);
    });
  });
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

async function copyToClipboard(value: string, anchor?: HTMLElement) {
  try {
    await navigator.clipboard.writeText(value);
    if (anchor) flashCopied(anchor);
  } catch { /* clipboard write may fail in some contexts */ }
}

function flashCopied(el: HTMLElement) {
  const original = el.textContent ?? '';
  el.dataset.flashOriginal = original;
  el.textContent = 'copied!';
  el.classList.add('flash');
  setTimeout(() => {
    if (el.dataset.flashOriginal !== undefined) {
      el.textContent = el.dataset.flashOriginal;
      delete el.dataset.flashOriginal;
    }
    el.classList.remove('flash');
  }, 900);
}

// Click on any .ioc-value copies it to clipboard. Delegated so it works
// for IOC list, history, and recent-results rows alike.
document.addEventListener('click', (e) => {
  const target = (e.target as HTMLElement | null)?.closest<HTMLElement>('.ioc-value');
  if (!target) return;
  const value = target.textContent?.trim();
  if (!value) return;
  e.stopPropagation();
  copyToClipboard(value, target);
});

init();
