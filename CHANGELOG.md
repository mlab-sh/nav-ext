# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-05-15

First public release.

### Added
- Passive detection of domains, IPv4, IPv6 and crypto wallet addresses (BTC, ETH/EVM, TRX, SOL) on every page
- Defanging support (`evil[.]com`, `hxxp://`, `1.1.1[.]1`, `user[at]example.com`)
- Click-to-open IOC popover (Shadow DOM isolated) with Scan / Copy / Open report actions
- Popup with two tabs: Detected (current page) and History (last 10 scans, persisted, filterable)
- Manual input in popup with auto type detection and bulk paste support (newline / comma / space)
- Right-click context menu "Scan with mlab.sh" on any selected text
- Settings page:
  - API key management with validation against `/limit/domain`
  - Inline highlight toggle (off by default)
  - Crypto wallet detection toggle (off by default)
  - Malicious / suspicious desktop notification toggle (on by default)
  - Per-site disable list management
  - Quota display (Domain / IP / Crypto)
  - Cache clearing
- Anonymous tier supported — no account required to start
- Local 24h cache + server-side cache probe before launching a domain scan
- AbortController per scan, in-flight deduplication, 60s rate-limit backoff on 429
- Full IANA TLD list embedded (1286 entries)
- ~150-entry trusted host allowlist (CDNs, infra, popular services)
- Reserved IP range filtering (RFC1918, loopback, CGNAT, link-local, multicast)
- Cross-browser support: Chrome / Chromium MV3 + Firefox MV3

### Tests
- 34 unit tests covering refanging, IOC detection, classification, crypto chains and verdict inference

## [Unreleased]

Planned items tracked in README under "Roadmap".
