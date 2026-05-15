# Store listing copy — mlab.sh INTEL

Ready-to-paste text for Chrome Web Store and Mozilla AMO submission.

---

## Name
mlab.sh INTEL

## Summary / Short description (max ~132 chars)
Detect domain, IP and crypto wallet IOCs on any page and pivot to a mlab.sh threat intelligence investigation in one click.

## Categories
- Chrome Web Store: **Developer Tools** (primary) + **Productivity** (secondary)
- AMO: **Other** → tag *security, threat intelligence, IOC*

---

## Full description

**Threat intelligence at the speed of your browser.**

mlab.sh INTEL turns every page into a launch pad for security investigation. Read a threat report, a vulnerability advisory, a darkweb dump or a phishing email? See indicators of compromise instantly, scan them in one click, and pivot to a full mlab.sh report — without leaving the page.

**What it does**

• **Detects automatically** on every page you read: domains, IPv4, IPv6 addresses and (opt-in) crypto wallet addresses across Bitcoin, Ethereum / EVM chains, Tron and Solana.

• **Understands defanged IOCs** like `evil[.]com`, `hxxp://`, `1.1.1[.]1`, `user[at]example.com` — the format used in every serious threat report.

• **One-click investigation** via the toolbar popup, the right-click menu, or by clicking a highlighted IOC directly in the page. Each result links to the full mlab.sh report.

• **Inline highlighting** (off by default) colours IOCs with the verdict returned by mlab.sh: clean / suspicious / malicious.

• **History tab** keeps your 10 most recent scans, with filter, copy-to-clipboard and re-scan in one click.

• **Bulk scan** by pasting a list of IOCs into the popup — newline, comma or space separated, refanged automatically.

• **Per-site disable** keeps the extension passive on your bank, intranet or any host you choose.

• **Smart quota management**: 24-hour local cache, server-side cache probe before launching new scans, in-flight deduplication, 60-second back-off when the API is rate-limited.

**Privacy by design**

The extension is built around an aggressive privacy policy:

• No browsing telemetry. The extension only contacts mlab.sh when you explicitly trigger a scan or refresh your quota.
• No third parties — no analytics, no ads, no CDN-loaded scripts.
• Your API key, cache, history and settings stay on your device.
• Works fully **anonymously** by default using mlab.sh's free Anonymous tier. Add your own API key for higher quota when you need it.

See PRIVACY.md in the repository for the full disclosure.

**Who is this for?**

SOC analysts, incident responders, threat hunters, security researchers, journalists covering cyber, students, and anyone curious about the indicators they spot online.

---

## Permissions justification (Chrome Web Store form)

- **storage**: persist API key, scan cache, scan history and user settings locally.
- **contextMenus**: provide the right-click "Scan with mlab.sh" entry on any selected text.
- **activeTab**: read the active tab's hostname for the "Scan this domain" button.
- **tabs**: maintain a per-tab badge count of detected IOCs.
- **notifications**: optionally alert the user when a scan returns a malicious verdict.
- **host_permissions `https://mlab.sh/*`**: call the mlab.sh API.
- **content_scripts on `<all_urls>`**: run the IOC detection regex on page text locally. **No content is transmitted off-device** unless the user explicitly clicks Scan.

**Are you collecting any user data?** → No.

---

## Tagline ideas (under 50 chars, for promo tile)
- "IOCs on any page, one click to mlab.sh"
- "Threat intel where you browse"
- "Pivot from any page to mlab.sh"

---

## Keywords / tags
threat intelligence, ioc, security, malware, phishing, domain reputation, ip lookup, soc, incident response, threat hunting, mlab, mlab.sh, refang, defang

---

## Support links
- Homepage / source: https://github.com/Sn0wAlice/nav-ext  *(adjust to actual repo URL)*
- Issue tracker: same
- Privacy policy: link to PRIVACY.md raw or to a hosted copy on mlab.sh
- mlab.sh: https://mlab.sh
