# Privacy Policy — mlab.sh INTEL browser extension

**Last updated:** 2026-05-15
**Effective version:** 1.0.0

This extension is designed to be privacy-respecting by default. This document
describes exactly what data is processed, where it is stored, and to whom it is
sent.

## TL;DR

- The extension does **not** send any browsing data to any server unless you
  explicitly click "Scan".
- Your API key, scan cache, scan history and settings are stored **locally on
  your device** (`chrome.storage.local`). They never leave your browser.
- The only third party contacted is **mlab.sh**, and only when you trigger a
  scan, open the popup (to refresh quotas), or save / validate an API key.

## Data we process

### 1. Locally stored (never sent to anyone)

| Item | Where | Purpose |
|---|---|---|
| API key (if you set one) | `chrome.storage.local` | Authenticate calls to mlab.sh |
| Scan cache (24h, max 500 entries) | `chrome.storage.local` | Avoid burning quota on the same IOC |
| Scan history (last 10) | `chrome.storage.local` | Show the History tab in the popup |
| Settings | `chrome.storage.local` | Persist your preferences |
| Disabled sites list | `chrome.storage.local` | Keep the extension passive on chosen hosts |

You can clear all of this at any time from the Settings page ("Clear cache",
"Clear history", "Remove API key") or by uninstalling the extension.

### 2. Sent to mlab.sh (only on your explicit action)

When you click **Scan**, use **"Scan with mlab.sh"** from the context menu,
press **Scan this domain** in the popup, or scan the current domain via the
inline popover, the extension sends a request to the mlab.sh API
(`https://mlab.sh/api/v1/`) containing:

- The IOC you want to scan (domain, IP, or crypto address)
- Your API key as `Authorization` header, **only if you have set one** in
  Settings. Otherwise the request is sent anonymously.

The popup also refreshes your remaining quota by calling
`/limit/domain`, `/limit/ip`, `/limit/crypto` when opened.

**Nothing else is sent.** In particular, the extension does NOT send:

- URLs of pages you visit
- Page titles, content, or HTML
- IOCs detected passively but not scanned
- Browsing history
- A device identifier or user ID
- Cookies, referrers, or telemetry of any kind

## Permissions and why we need them

| Permission | Why |
|---|---|
| `storage` | Persist API key, settings, cache and history locally |
| `contextMenus` | Provide the "Scan with mlab.sh" right-click menu |
| `activeTab` | Read the hostname of the current tab for the "Scan this domain" button |
| `tabs` | Maintain a per-tab IOC count for the toolbar badge |
| `notifications` | Show a desktop alert when a scan returns "malicious" (you can disable this) |
| `host_permissions: https://mlab.sh/*` | Call the mlab.sh API |
| `<all_urls>` (content script) | Scan page text locally for IOCs. **No content is sent off-device.** |

## Data sent to mlab.sh — what mlab.sh does with it

When you scan an IOC, the corresponding API call reaches mlab.sh. mlab.sh's own
privacy policy governs that processing — see <https://mlab.sh/> for details.
This extension does not perform any additional collection beyond what the API
strictly requires.

## Third parties

The extension contacts **only** `https://mlab.sh/`. No analytics, no crash
reporting, no advertising, no CDN-loaded scripts. The bundled source is fully
inspectable (we ship JavaScript built from the public source).

## Your rights

You can at any time:

- View what is stored: open your browser DevTools → Application → Storage
- Clear stored data: Settings page → "Clear cache" / "Clear history" / "Remove API key"
- Uninstall the extension: removes all locally stored data

## Contact

For questions about this extension's privacy practices, contact the
maintainer through the issue tracker linked in the store listing.
