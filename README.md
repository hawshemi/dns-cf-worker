# Personal DoH

A tiny Cloudflare Worker that gives you your own **DNS over HTTPS (DoH)** endpoint. Your DNS lookups get encrypted and forwarded to a malware-filtering resolver, so your ISP or network can't see or tamper with them.

- **Primary resolver:** Quad9 (`dns.quad9.net`)
- **Fallback resolver:** Cloudflare 1.1.1.2 (`security.cloudflare-dns.com`)
- Both block known malware and phishing domains.

Open the Worker's URL in a browser and you get a small page with your endpoint and copy-paste setup steps for each device.

## What it does

- Proxies DoH queries (both wire-format and JSON) to the resolvers above.
- Fails over to the fallback if the primary returns an error.
- Caches answers at Cloudflare's edge for faster repeat lookups.
- Optional per-client rate limiting to stop abuse.
- The info page is marked `noindex` so search engines don't list your endpoint.

## Deploy

**Option A: Dashboard**
1. Cloudflare dashboard, Workers & Pages, Create Worker.
2. Paste the contents of `doh-worker.js` and deploy.
3. Your endpoint is `https://<your-worker>.workers.dev/dns-query`.

**Option B: Wrangler**
```sh
npm install -g wrangler
wrangler deploy
```

Minimal `wrangler.toml`:
```toml
name = "personal-doh"
main = "doh-worker.js"
compatibility_date = "2026-07-03"
```

## Optional: rate limiting

Without this, anyone who finds your URL can run unlimited DNS through your account. To cap it, add a rate-limit binding. The code uses it automatically if present, and just skips it if not.

Add to `wrangler.toml`:
```toml
[[ratelimits]]
binding = "RATE_LIMITER"
namespace_id = "1001"           # any number, unique per limiter
simple = { limit = 100, period = 10 }   # 100 requests per 10s per client
```

Notes:
- `period` must be `10` or `60` (seconds).
- The limit is keyed on the client IP. People behind the same NAT share a limit, so keep the number generous (a single page load can trigger many DNS queries).

## Usage

Set the endpoint as a **custom Secure DNS (DoH)** server in your browser:

- **Chrome / Edge / Brave:** Settings, Privacy and security, Security, Use secure DNS, Custom, paste the link.
- **Firefox:** Settings, Privacy & Security, DNS over HTTPS, Max Protection, Custom, paste the link.
- **Android:** Chrome's Secure DNS, or a DoH app (Intra, RethinkDNS). Android's Private DNS won't work, it needs a bare hostname.
- **iOS / macOS:** A DoH configuration profile or a DoH app, or just set it in a browser.
- **Linux / Windows:** Browser settings, or point dnscrypt-proxy / cloudflared at the endpoint for system-wide.

## Limitations

- **DoH only.** Android Private DNS and system DoT settings take a bare hostname, not a URL, so they can't use this.
- **Not a censorship bypass.** DoH only fixes DNS-level blocking. It does nothing against SNI filtering, IP blocking, or protocol blocking, and heavily censored networks often block DoH endpoints outright.
- **Public by default.** There's no login. Rate limiting reduces abuse but doesn't authenticate anyone.
