import { getCached, setCached } from '../lib/cache';
import { addToHistory, clearHistory, getHistory } from '../lib/history';
import { classifyIoc } from '../lib/regex';
import { refang } from '../lib/refang';
import { MlabError, getLimits, hasApiKey, scanDomain, scanIp, setApiKey, validateKey } from '../lib/mlab-client';
import type { DetectedIoc, Ioc, Msg } from '../lib/types';

const CTX_MENU_ID = 'mlab-scan-selection';

// per-tab state
const iocsByTab = new Map<number, DetectedIoc[]>();

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: CTX_MENU_ID,
    title: 'Scan with mlab.sh',
    contexts: ['selection'],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== CTX_MENU_ID) return;
  const selection = (info.selectionText || '').trim();
  if (!selection) return;
  const refanged = refang(selection).trim().replace(/[.,;:)\]}>]+$/, '');
  const type = classifyIoc(refanged);
  if (!type) {
    notifyTab(tab?.id, { kind: 'scan-result', result: errorResult({ type: 'domain', value: refanged }, 'Unrecognized IOC format') });
    return;
  }
  await performScan({ type, value: refanged.toLowerCase() }, tab?.id);
});

chrome.runtime.onMessage.addListener((msg: Msg, sender, sendResponse) => {
  (async () => {
    switch (msg.kind) {
      case 'detected': {
        const tabId = sender.tab?.id;
        if (tabId !== undefined) {
          iocsByTab.set(tabId, msg.iocs);
          updateBadge(tabId, msg.iocs.length);
        }
        sendResponse({ ok: true });
        break;
      }
      case 'scan': {
        const tabId = sender.tab?.id ?? (await activeTabId());
        await performScan(msg.ioc, tabId);
        sendResponse({ ok: true });
        break;
      }
      case 'get-cached': {
        const r = await getCached(msg.ioc);
        sendResponse({ kind: 'cached-result', result: r });
        break;
      }
      case 'get-limits': {
        try {
          const limits = await getLimits();
          sendResponse({ kind: 'limits', limits });
        } catch {
          sendResponse({ kind: 'limits', limits: {} });
        }
        break;
      }
      case 'get-tab-iocs': {
        const tabId = await activeTabId();
        sendResponse({ kind: 'tab-iocs', iocs: tabId !== undefined ? (iocsByTab.get(tabId) ?? []) : [] });
        break;
      }
      case 'set-api-key': {
        const ok = await validateKey(msg.key);
        if (ok) await setApiKey(msg.key);
        sendResponse({ kind: 'api-key-ok', ok, error: ok ? undefined : 'Invalid key' });
        break;
      }
      case 'has-api-key': {
        sendResponse({ kind: 'has-api-key-result', present: await hasApiKey() });
        break;
      }
      case 'get-history': {
        sendResponse({ kind: 'history', entries: await getHistory() });
        break;
      }
      case 'clear-history': {
        await clearHistory();
        sendResponse({ ok: true });
        break;
      }
      default:
        sendResponse(undefined);
    }
  })();
  return true; // keep channel open for async sendResponse
});

async function performScan(ioc: Ioc, tabId?: number): Promise<void> {
  // cache first
  const cached = await getCached(ioc);
  if (cached) {
    await addToHistory(cached);
    notifyTab(tabId, { kind: 'scan-result', result: cached });
    return;
  }

  try {
    const result =
      ioc.type === 'domain' ? await scanDomain(ioc.value) : await scanIp(ioc.value);
    await setCached(result);
    await addToHistory(result);
    notifyTab(tabId, { kind: 'scan-result', result });
  } catch (e) {
    const err = e instanceof MlabError ? e : new MlabError('http', String(e));
    const msg =
      err.code === 'unauthorized' ? 'Invalid API key.' :
      err.code === 'rate-limited' ? 'Daily quota exhausted (Anonymous tier is limited — add an API key in Settings).' :
      err.message;
    const errResult = errorResult(ioc, msg);
    await addToHistory(errResult);
    notifyTab(tabId, { kind: 'scan-result', result: errResult });
  }
}

function errorResult(ioc: Ioc, message: string) {
  return {
    ioc,
    verdict: 'unknown' as const,
    data: { error: message },
    fetchedAt: Date.now(),
  };
}

function notifyTab(tabId: number | undefined, msg: Msg) {
  if (tabId === undefined) {
    // forward to popup if open (no tab) — popup listens via runtime.onMessage too
    chrome.runtime.sendMessage(msg).catch(() => {});
    return;
  }
  chrome.tabs.sendMessage(tabId, msg).catch(() => {});
  chrome.runtime.sendMessage(msg).catch(() => {});
}

function updateBadge(tabId: number, count: number) {
  const text = count > 0 ? (count > 99 ? '99+' : String(count)) : '';
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#6366f1' });
}

async function activeTabId(): Promise<number | undefined> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id;
}

// clear per-tab state on close
chrome.tabs.onRemoved.addListener((tabId) => iocsByTab.delete(tabId));
