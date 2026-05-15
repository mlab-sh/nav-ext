import { refang } from '../lib/refang';
import { detectIocs } from '../lib/regex';
import { SETTINGS_KEY, getSettings, isHostDisabled } from '../lib/settings';
import type { DetectedIoc, Msg, ScanResult } from '../lib/types';

const HL_CLASS = 'mlab-ioc-hl';
const SKIP_TAGS = new Set(['SCRIPT','STYLE','NOSCRIPT','IFRAME','OBJECT','EMBED','SVG','CANVAS','CODE','PRE','TEXTAREA','INPUT','SELECT','OPTION']);

let lastIocs: DetectedIoc[] = [];
let scanScheduled = false;
let highlightEnabled = false;
let siteDisabled = false;
let cryptoDetection = false;
let suppressMutations = false;

getSettings().then((s) => {
  highlightEnabled = s.highlightEnabled;
  cryptoDetection = s.cryptoDetectionEnabled;
  siteDisabled = isHostDisabled(location.hostname, s.disabledHosts);
  if (!siteDisabled) scheduleScan();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local' || !changes[SETTINGS_KEY]) return;
  const next = changes[SETTINGS_KEY].newValue as {
    highlightEnabled?: boolean;
    disabledHosts?: string[];
    cryptoDetectionEnabled?: boolean;
  } | undefined;
  const prevHl = highlightEnabled;
  const prevDisabled = siteDisabled;
  const prevCrypto = cryptoDetection;
  highlightEnabled = !!next?.highlightEnabled;
  cryptoDetection = !!next?.cryptoDetectionEnabled;
  siteDisabled = isHostDisabled(location.hostname, next?.disabledHosts ?? []);

  if (!prevDisabled && siteDisabled) {
    removeHighlights();
    lastIocs = [];
    chrome.runtime.sendMessage<Msg>({ kind: 'detected', iocs: [], href: location.href }).catch(() => {});
    return;
  }
  if (prevDisabled && !siteDisabled) { scheduleScan(); return; }
  if (siteDisabled) return;
  if (prevCrypto !== cryptoDetection) { scheduleScan(); return; }
  if (prevHl && !highlightEnabled) removeHighlights();
  else if (!prevHl && highlightEnabled) scheduleScan();
});

function removeHighlights() {
  suppressMutations = true;
  try {
    for (const mark of document.querySelectorAll<HTMLElement>('.' + HL_CLASS)) {
      const text = document.createTextNode(mark.textContent ?? '');
      mark.replaceWith(text);
    }
  } finally {
    setTimeout(() => { suppressMutations = false; }, 0);
  }
}

function scheduleScan() {
  if (scanScheduled || siteDisabled) return;
  scanScheduled = true;
  setTimeout(() => {
    scanScheduled = false;
    if (siteDisabled) return;
    runScan();
  }, 600);
}

function gatherTextNodes(): Text[] {
  const nodes: Text[] = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      if (!node.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
      const parent = node.parentElement;
      if (!parent) return NodeFilter.FILTER_REJECT;
      if (SKIP_TAGS.has(parent.tagName)) return NodeFilter.FILTER_REJECT;
      if (parent.closest('.' + HL_CLASS)) return NodeFilter.FILTER_REJECT;
      if (parent.isContentEditable) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    },
  });
  let n: Node | null;
  // eslint-disable-next-line no-cond-assign
  while ((n = walker.nextNode())) nodes.push(n as Text);
  return nodes;
}

function runScan() {
  if (!document.body) return;
  const textNodes = gatherTextNodes();
  const fullText = textNodes.map((n) => n.nodeValue ?? '').join('\n');
  const refanged = refang(fullText);
  const iocs = detectIocs(refanged, { currentHost: location.hostname, detectCrypto: cryptoDetection });
  lastIocs = iocs;

  // notify background → badge
  chrome.runtime.sendMessage<Msg>({ kind: 'detected', iocs, href: location.href }).catch(() => {});

  if (highlightEnabled) {
    suppressMutations = true;
    try { applyHighlights(textNodes, iocs); } finally {
      // release on next tick so the MO callback (already queued) doesn't re-trigger
      setTimeout(() => { suppressMutations = false; }, 0);
    }
  }
}

function applyHighlights(textNodes: Text[], iocs: DetectedIoc[]) {
  if (!iocs.length) return;
  // Build a single regex of all raw values (escaped). Use refanged AND raw to catch both.
  const variants = new Set<string>();
  for (const ioc of iocs) {
    variants.add(escapeRe(ioc.value));
    variants.add(escapeRe(ioc.raw));
    // common defanged variants
    variants.add(escapeRe(ioc.value.replace(/\./g, '[.]')));
    variants.add(escapeRe(ioc.value.replace(/\./g, '(.)')));
  }
  if (!variants.size) return;
  const big = new RegExp('(' + [...variants].join('|') + ')', 'gi');
  const valueByLower = new Map<string, DetectedIoc>();
  for (const ioc of iocs) valueByLower.set(ioc.value.toLowerCase(), ioc);

  for (const node of textNodes) {
    const text = node.nodeValue ?? '';
    if (!text) continue;
    big.lastIndex = 0;
    if (!big.test(text)) continue;
    big.lastIndex = 0;

    const frag = document.createDocumentFragment();
    let last = 0;
    let m: RegExpExecArray | null;
    // eslint-disable-next-line no-cond-assign
    while ((m = big.exec(text))) {
      const matchText = m[0];
      const start = m.index;
      if (start > last) frag.appendChild(document.createTextNode(text.slice(last, start)));
      const refangedMatch = refang(matchText).toLowerCase().replace(/\.$/, '');
      const ioc = valueByLower.get(refangedMatch);
      if (!ioc) {
        frag.appendChild(document.createTextNode(matchText));
      } else {
        const mark = document.createElement('mark');
        mark.className = HL_CLASS;
        mark.dataset.iocType = ioc.type;
        mark.dataset.iocValue = ioc.value;
        if (ioc.reserved) mark.dataset.reserved = '1';
        mark.title = `${ioc.type.toUpperCase()} · ${ioc.value}${ioc.reserved ? ' (reserved)' : ''} — click to scan with mlab.sh`;
        mark.textContent = matchText;
        frag.appendChild(mark);
      }
      last = start + matchText.length;
    }
    if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
    node.parentNode?.replaceChild(frag, node);
  }
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Click on a highlighted IOC: open a small info popover instead of scanning directly.
document.addEventListener('click', (e) => {
  const target = e.target as HTMLElement | null;
  if (!target) return;
  // Clicking outside the popover closes it
  if (popover && !popover.contains(target)) {
    const mark = target.closest<HTMLElement>('.' + HL_CLASS);
    if (!mark) { closePopover(); return; }
  }
  const mark = target.closest<HTMLElement>('.' + HL_CLASS);
  if (!mark) return;
  const type = mark.dataset.iocType as DetectedIoc['type'] | undefined;
  const value = mark.dataset.iocValue;
  if (!type || !value) return;
  e.preventDefault();
  e.stopPropagation();
  openPopover(mark, type, value, mark.dataset.reserved === '1', mark.dataset.verdict);
}, true);

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closePopover();
});
window.addEventListener('scroll', () => closePopover(), { passive: true });
window.addEventListener('resize', () => closePopover());

let popover: HTMLElement | null = null;

function closePopover() {
  if (popover) { popover.remove(); popover = null; }
}

function openPopover(anchor: HTMLElement, type: DetectedIoc['type'], value: string, reserved: boolean, verdict?: string) {
  closePopover();
  const reportUrl =
    type === 'domain' ? `https://mlab.sh/domain/${encodeURIComponent(value)}` :
    `https://mlab.sh/ip/${encodeURIComponent(value)}`;

  const host = document.createElement('div');
  host.className = 'mlab-popover-host';
  // Shadow DOM keeps the popover styles isolated from the host page.
  const shadow = host.attachShadow({ mode: 'closed' });
  shadow.innerHTML = `
    <style>${POPOVER_CSS}</style>
    <div class="card" role="dialog">
      <div class="head">
        <span class="type">${escapeHtml(type)}</span>
        ${reserved ? '<span class="badge">reserved</span>' : ''}
        ${verdict ? `<span class="verdict" data-v="${escapeHtml(verdict)}">${escapeHtml(verdict)}</span>` : ''}
        <button class="close" aria-label="Close">×</button>
      </div>
      <div class="value" title="${escapeHtml(value)}">${escapeHtml(value)}</div>
      <div class="actions">
        ${reserved
          ? '<span class="muted small">Reserved address — no lookup available.</span>'
          : '<button class="primary scan-btn">Scan with mlab.sh</button>'}
        <button class="copy-btn">Copy</button>
        <a class="report" href="${reportUrl}" target="_blank" rel="noopener">Open report ↗</a>
      </div>
    </div>
  `;
  document.body.appendChild(host);
  positionPopover(host, anchor);

  const close = () => closePopover();
  shadow.querySelector<HTMLButtonElement>('.close')?.addEventListener('click', close);
  shadow.querySelector<HTMLButtonElement>('.scan-btn')?.addEventListener('click', () => {
    chrome.runtime.sendMessage<Msg>({ kind: 'scan', ioc: { type, value } });
    anchor.classList.add('mlab-ioc-scanning');
    const status = document.createElement('div');
    status.className = 'status';
    status.textContent = 'Scan queued — open the extension popup for results.';
    shadow.querySelector('.actions')?.replaceWith(status);
  });
  shadow.querySelector<HTMLButtonElement>('.copy-btn')?.addEventListener('click', async (e) => {
    try {
      await navigator.clipboard.writeText(value);
      const btn = e.currentTarget as HTMLButtonElement;
      const orig = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = orig; }, 900);
    } catch { /* no clipboard access */ }
  });

  popover = host;
}

function positionPopover(host: HTMLElement, anchor: HTMLElement) {
  const rect = anchor.getBoundingClientRect();
  // Anchor below the mark, clamped to viewport. Use position:fixed so scroll/resize handlers close it.
  host.style.position = 'fixed';
  host.style.zIndex = '2147483647';
  host.style.top = `${Math.min(window.innerHeight - 200, rect.bottom + 6)}px`;
  host.style.left = `${Math.max(8, Math.min(window.innerWidth - 280, rect.left))}px`;
}

const POPOVER_CSS = `
  :host { all: initial; }
  .card {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 13px;
    color: #e2e8f0;
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45);
    width: 260px;
    padding: 10px 12px;
  }
  .head { display: flex; align-items: center; gap: 6px; margin-bottom: 6px; }
  .type {
    font-size: 10px;
    text-transform: uppercase;
    background: #334155;
    color: #94a3b8;
    padding: 2px 6px;
    border-radius: 3px;
    letter-spacing: 0.05em;
  }
  .badge {
    font-size: 10px;
    background: rgba(148, 163, 184, 0.18);
    color: #94a3b8;
    padding: 2px 6px;
    border-radius: 3px;
  }
  .verdict {
    font-size: 10px;
    text-transform: uppercase;
    padding: 2px 6px;
    border-radius: 3px;
    background: #334155;
    color: #94a3b8;
  }
  .verdict[data-v="clean"] { background: rgba(34,197,94,0.18); color: #22c55e; }
  .verdict[data-v="suspicious"] { background: rgba(234,88,12,0.22); color: #fb923c; }
  .verdict[data-v="malicious"] { background: rgba(220,38,38,0.22); color: #ef4444; }
  .close {
    margin-left: auto;
    background: transparent;
    border: none;
    color: #94a3b8;
    font-size: 18px;
    line-height: 1;
    padding: 0 4px;
    cursor: pointer;
    border-radius: 3px;
  }
  .close:hover { background: #334155; color: #e2e8f0; }
  .value {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 13px;
    word-break: break-all;
    padding: 6px 8px;
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 4px;
    margin-bottom: 10px;
    color: #e2e8f0;
  }
  .actions { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
  button, .report {
    font: inherit;
    border-radius: 5px;
    border: 1px solid #334155;
    background: #334155;
    color: #e2e8f0;
    padding: 6px 10px;
    cursor: pointer;
    text-decoration: none;
    line-height: 1;
  }
  button:hover, .report:hover { background: #475569; }
  .primary { background: #6366f1; border-color: #6366f1; color: white; }
  .primary:hover { background: #818cf8; border-color: #818cf8; }
  .report { font-size: 12px; color: #94a3b8; background: transparent; border: none; padding: 6px 4px; }
  .report:hover { color: #e2e8f0; background: transparent; }
  .muted { color: #94a3b8; }
  .small { font-size: 12px; }
  .status {
    font-size: 12px;
    color: #94a3b8;
    padding: 6px 8px;
    background: rgba(99,102,241,0.12);
    border-radius: 4px;
  }
`;

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

// React to scan results: tag the highlight with verdict
chrome.runtime.onMessage.addListener((msg: Msg) => {
  if (msg.kind === 'scan-result') {
    applyVerdict(msg.result);
  } else if (msg.kind === 'get-tab-iocs') {
    chrome.runtime.sendMessage<Msg>({ kind: 'tab-iocs', iocs: lastIocs }).catch(() => {});
  }
});

function applyVerdict(result: ScanResult) {
  const sel = `.${HL_CLASS}[data-ioc-type="${result.ioc.type}"][data-ioc-value="${cssEscape(result.ioc.value)}"]`;
  for (const el of document.querySelectorAll<HTMLElement>(sel)) {
    el.classList.remove('mlab-ioc-scanning');
    el.dataset.verdict = result.verdict;
    el.title = `${result.ioc.type.toUpperCase()} · ${result.ioc.value} — ${result.verdict}`;
  }
}

function cssEscape(s: string): string {
  return s.replace(/["\\]/g, '\\$&');
}

// init
if (document.readyState === 'loading') {
  window.addEventListener('DOMContentLoaded', () => scheduleScan());
} else {
  scheduleScan();
}

// SPA: react to DOM mutations
const mo = new MutationObserver(() => { if (!suppressMutations) scheduleScan(); });
mo.observe(document.body || document.documentElement, { childList: true, subtree: true, characterData: true });
