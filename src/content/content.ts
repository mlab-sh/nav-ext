import { refang } from '../lib/refang';
import { detectIocs } from '../lib/regex';
import { SETTINGS_KEY, getSettings } from '../lib/settings';
import type { DetectedIoc, Msg, ScanResult } from '../lib/types';

const HL_CLASS = 'mlab-ioc-hl';
const SKIP_TAGS = new Set(['SCRIPT','STYLE','NOSCRIPT','IFRAME','OBJECT','EMBED','SVG','CANVAS','CODE','PRE','TEXTAREA','INPUT','SELECT','OPTION']);

let lastIocs: DetectedIoc[] = [];
let scanScheduled = false;
let highlightEnabled = false;
let suppressMutations = false;

getSettings().then((s) => { highlightEnabled = s.highlightEnabled; scheduleScan(); });

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local' || !changes[SETTINGS_KEY]) return;
  const next = changes[SETTINGS_KEY].newValue as { highlightEnabled?: boolean } | undefined;
  const prev = highlightEnabled;
  highlightEnabled = !!next?.highlightEnabled;
  if (prev && !highlightEnabled) removeHighlights();
  else if (!prev && highlightEnabled) scheduleScan();
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
  if (scanScheduled) return;
  scanScheduled = true;
  setTimeout(() => {
    scanScheduled = false;
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
  const iocs = detectIocs(refanged, { currentHost: location.hostname });
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

// Click-to-scan on a highlighted IOC
document.addEventListener('click', (e) => {
  const target = e.target as HTMLElement | null;
  if (!target) return;
  const mark = target.closest<HTMLElement>('.' + HL_CLASS);
  if (!mark) return;
  if (mark.dataset.reserved === '1') return;
  const type = mark.dataset.iocType as DetectedIoc['type'] | undefined;
  const value = mark.dataset.iocValue;
  if (!type || !value) return;
  e.preventDefault();
  e.stopPropagation();
  chrome.runtime.sendMessage<Msg>({ kind: 'scan', ioc: { type, value } });
  mark.classList.add('mlab-ioc-scanning');
}, true);

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
