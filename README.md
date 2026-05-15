# mlab.sh INTEL — browser extension

Detect domain and IP IOCs on any page and pivot to a [mlab.sh](https://mlab.sh) investigation in one click.

## Features (MVP)

- **Passive DOM scan** of every page — detects domains, IPv4, IPv6 (incl. defanged `evil[.]com`, `1.1.1[.]1`, `hxxp://`).
- **Inline highlight** of detected IOCs with verdict colors after scan.
- **Context menu** "Scan with mlab.sh" on any selected text.
- **Popup**: scan current domain, manual input (auto-detects type + refangs), list of detected IOCs, recent results, quota remaining.
- **Local-first**: detection is regex-based and free. API calls only fire on explicit user action.
- **24h cache** of results in `chrome.storage.local`.

## Build

```bash
npm install
npm run build              # builds both Chrome + Firefox into dist/
npm run build:chrome
npm run build:firefox
npm run watch              # rebuild on change
npm run typecheck
```

## Load the extension

### Chrome / Chromium / Edge / Brave

1. Go to `chrome://extensions`
2. Toggle **Developer mode** on
3. Click **Load unpacked** → select `dist/chrome/`

### Firefox

1. Go to `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on…** → select `dist/firefox/manifest.json`

## First use

On first scan, the popup will prompt for your **mlab.sh API key**. Get it from your mlab.sh account. The key is validated against `/limit/domain` before being saved to `chrome.storage.local`.

## Verification checklist

1. Popup opens without errors → onboarding modal shows if no key
2. Save a valid key → popup switches to main view, quota chips appear
3. Open a page with IOCs (e.g. a threat-intel blog post) → badge shows count, IOCs are highlighted
4. Click a highlighted IOC → scan triggers, color updates (clean / suspicious / malicious)
5. Right-click a selected `1.1.1[.]1` → "Scan with mlab.sh" → refangs to `1.1.1.1` and scans
6. Manual popup input with `evil[.]com` → hint shows refanged value + detected type
7. "Scan this domain" button scans the current tab's hostname
8. Re-scan an already-scanned IOC → no network call (cache)
9. Same flow works on Firefox after `npm run build:firefox`

## Roadmap (out of MVP scope)

- Hashes (MD5/SHA1/SHA256) via `/scan/file/results`
- Crypto addresses via `/scan/crypto`
- SSL info via `/domain/ssl`
- Chrome side panel for detailed view
- Export to CSV / STIX / MISP
- "Defensive mode": warn when the current page hostname matches a known-malicious IOC
- Real PNG icons (currently relies on browser default; SVG source in `src/assets/icons/`)

## Architecture

```
manifest.json                  MV3, rewritten per-browser at build time
src/
  background/service-worker   Message router, context menu, badge, scan orchestration
  content/content.ts          DOM scan, highlight, click-to-scan
  content/highlight.css       Verdict colors
  popup/                      UI (HTML/CSS/TS)
  lib/regex.ts                IOC patterns, allowlist, reserved-IP filter
  lib/refang.ts               Defanged → canonical
  lib/mlab-client.ts          API wrapper (auth, polling, errors)
  lib/cache.ts                TTL'd storage.local cache (LRU eviction)
  lib/types.ts                Shared types + message protocol
build.mjs                     esbuild bundler, dual-target output
```
