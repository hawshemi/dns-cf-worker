// DoH proxy -> Quad9 (primary), Cloudflare 1.1.1.2 (fallback). Both block malware/phishing.
// Features: upstream failover, per-client rate limiting (optional binding), edge caching for GET.

// Ordered by preference. Both hostnames are dual-stack (IPv4 + IPv6); the runtime picks the transport.
const UPSTREAMS = [
  "https://dns.quad9.net/dns-query",               // Quad9 primary (9.9.9.9 / 2620:fe::fe)
  "https://security.cloudflare-dns.com/dns-query", // Cloudflare 1.1.1.2 fallback
];

// DoH messages are tiny. Reject anything larger than this to fail fast on abuse.
const MAX_BODY = 8192;

// Path the resolver answers on. Anything else gets the info page.
const DOH_PATH = "/dns-query";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === DOH_PATH) {
      return resolveDns(request, env, ctx, url);
    }

    return infoPage(url.origin + DOH_PATH);
  },
};

async function resolveDns(request, env, ctx, url) {
  const method = request.method;

  // DoH only speaks GET and POST.
  if (method !== "GET" && method !== "POST") {
    return dnsError(405, "Method Not Allowed");
  }

  // GET must carry the query: ?dns= (wire format) or ?name= (JSON). Bounce empty probes.
  if (method === "GET" && !url.searchParams.has("dns") && !url.searchParams.has("name")) {
    return dnsError(400, "Missing dns or name query parameter");
  }

  // Per-client rate limit. Skipped automatically if the RATE_LIMITER binding isn't configured.
  if (env && env.RATE_LIMITER) {
    const key = request.headers.get("CF-Connecting-IP") || "anonymous";
    const { success } = await env.RATE_LIMITER.limit({ key });
    if (!success) return dnsError(429, "Too Many Requests");
  }

  // Serve GET answers from Cloudflare's edge cache when we have a fresh copy.
  const cache = caches.default;
  if (method === "GET") {
    const hit = await cache.match(request);
    if (hit) return hit;
  }

  // Read the POST body once (reused across failover) and enforce the size cap.
  let body;
  if (method === "POST") {
    const declared = Number(request.headers.get("Content-Length"));
    if (declared && declared > MAX_BODY) return dnsError(413, "Query too large");
    body = await request.arrayBuffer();
    if (body.byteLength === 0) return dnsError(400, "Empty query body");
    if (body.byteLength > MAX_BODY) return dnsError(413, "Query too large");
  }

  const accept = request.headers.get("Accept") || "application/dns-message";
  const contentType = request.headers.get("Content-Type") || "application/dns-message";

  // Try each upstream in order. Fail over only on network errors or 5xx.
  let lastError = null;
  for (const base of UPSTREAMS) {
    try {
      const upstream = await fetch(base + url.search, {
        method,
        headers: { Accept: accept, "Content-Type": contentType },
        body: method === "POST" ? body : undefined,
      });

      if (upstream.status >= 500) {
        lastError = new Error(`upstream ${upstream.status}`);
        continue; // resolver is unhealthy, try the next one
      }

      const headers = new Headers();
      headers.set("Content-Type", upstream.headers.get("Content-Type") || "application/dns-message");
      // Honor the resolver's TTL so answers can be cached, instead of forcing no-store.
      headers.set("Cache-Control", upstream.headers.get("Cache-Control") || "max-age=60");

      const response = new Response(upstream.body, { status: upstream.status, headers });

      // Store successful GET answers at the edge (honors the Cache-Control TTL above).
      if (method === "GET" && response.ok) {
        ctx.waitUntil(cache.put(request, response.clone()));
      }

      return response;
    } catch (err) {
      lastError = err; // network failure, try the next upstream
    }
  }

  // Everything is down. Return a real error, not a thrown 5xx.
  return dnsError(502, `All upstream resolvers failed: ${lastError ? lastError.message : "unknown"}`);
}

function dnsError(status, message) {
  return new Response(message + "\n", {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function infoPage(dohLink) {
  const safeLink = esc(dohLink);

  // Resolver list rendered from UPSTREAMS so the page never drifts from the code.
  const resolvers = UPSTREAMS.map((u, i) => {
    const host = esc(new URL(u).hostname);
    const tag = i === 0 ? "primary" : "fallback";
    return `<div class="res"><span class="i">${i + 1}</span><span class="h">${host}</span><span class="t">${tag}</span></div>`;
  }).join("");

  return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="robots" content="noindex, nofollow">
<title>my doh</title>
<style>
:root {
  --bg: #060606;
  --panel: #0d0d0d;
  --panel-2: #141414;
  --line: rgba(255,255,255,0.09);
  --ink: #e9e9e6;
  --dim: #8c8c88;
  --accent: #e7a64a;
  --accent-soft: rgba(231,166,74,0.12);
  --ok: #7fae63;
  --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background: var(--bg);
  color: var(--ink);
  font-family: var(--sans);
  display: flex;
  justify-content: center;
  padding: 28px 16px;
}
.wrap {
  width: 100%;
  max-width: 720px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.card {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 13px;
  padding: 20px;
}
.eyebrow {
  font-family: var(--mono);
  font-size: 10.5px;
  letter-spacing: 0.13em;
  text-transform: uppercase;
  color: var(--accent);
  margin: 0 0 11px;
}
.prompt {
  display: flex;
  align-items: center;
  gap: 8px;
  background: var(--panel-2);
  border: 1px solid var(--line);
  border-radius: 9px;
  padding: 10px 11px;
  font-family: var(--mono);
  font-size: 12.5px;
}
.prompt .sig { color: var(--accent); user-select: none; }
.prompt input {
  flex: 1;
  min-width: 0;
  background: none;
  border: none;
  color: var(--ink);
  font: inherit;
  padding: 0;
}
.prompt input:focus { outline: none; }
.copy {
  flex-shrink: 0;
  min-height: 30px;
  background: var(--accent-soft);
  color: var(--accent);
  border: 1px solid var(--line);
  border-radius: 7px;
  padding: 5px 12px;
  font-family: var(--mono);
  font-size: 11.5px;
  cursor: pointer;
  transition: background 0.15s, color 0.15s;
}
.copy:hover { background: var(--accent); color: #060606; }
.copy.ok { background: var(--ok); color: #060606; border-color: transparent; }
.copy:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.lede { margin: 13px 0 0; font-size: 12.5px; line-height: 1.55; color: var(--dim); }
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(205px, 1fr));
  gap: 14px;
}
.set h2 {
  margin: 0 0 10px;
  font-family: var(--mono);
  font-size: 12.5px;
  color: var(--accent);
  font-weight: 600;
}
.step {
  margin: 0 0 7px;
  font-size: 12px;
  line-height: 1.55;
  color: var(--dim);
}
.step:last-child { margin-bottom: 0; }
.step b { color: var(--ink); font-weight: 600; }
.step code {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--ink);
  background: var(--panel-2);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 1px 5px;
}
.res-list { display: grid; gap: 1px; }
.res {
  display: grid;
  grid-template-columns: 16px 1fr auto;
  align-items: center;
  gap: 9px;
  padding: 8px 0;
  border-top: 1px solid var(--line);
  font-family: var(--mono);
  font-size: 12px;
}
.res:first-child { border-top: none; }
.res .i { color: var(--accent); }
.res .h { color: var(--ink); overflow: hidden; text-overflow: ellipsis; }
.res .t { color: var(--dim); font-size: 10.5px; }
.foot { margin: 12px 0 0; font-size: 11.5px; line-height: 1.5; color: var(--dim); }
@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
</style>
</head>
<body>
<div class="wrap">

  <section class="card">
    <p class="eyebrow">personal doh</p>
    <div class="prompt">
      <span class="sig">$</span>
      <input id="doh" value="${safeLink}" readonly aria-label="DNS over HTTPS endpoint">
      <button type="button" class="copy" data-label="copy" onclick="copyLink(this)">copy</button>
    </div>
    <p class="lede">Encrypts your DNS lookups and sends them over HTTPS. Add it as a custom Secure DNS (DoH) server using the steps below.</p>
  </section>

  <section class="grid">
    <div class="card set">
      <h2>Chrome / Edge / Brave</h2>
      <p class="step">Settings &gt; Privacy and security &gt; Security &gt; Use secure DNS.</p>
      <p class="step">Turn it on, pick <b>Custom</b>, paste the link. Shortcut: <code>chrome://settings/security</code></p>
    </div>

    <div class="card set">
      <h2>Firefox</h2>
      <p class="step">Settings &gt; Privacy &amp; Security &gt; DNS over HTTPS.</p>
      <p class="step"><b>Max Protection</b> &gt; Choose provider &gt; <b>Custom</b>, paste the link.</p>
    </div>

    <div class="card set">
      <h2>Android</h2>
      <p class="step">Use Chrome's Secure DNS (same as above), or a DoH app like Intra or RethinkDNS.</p>
      <p class="step">Private DNS won't accept it, it wants a bare hostname, not a URL.</p>
    </div>

    <div class="card set">
      <h2>iOS / macOS</h2>
      <p class="step">No system paste field. Install a DoH configuration profile or use a DoH app.</p>
      <p class="step">Simplest is to set it inside Firefox or Chrome.</p>
    </div>

    <div class="card set">
      <h2>Windows</h2>
      <p class="step">Easiest path is the browser settings above.</p>
      <p class="step">System-wide DoH needs the resolver's IP registered first, more hassle.</p>
    </div>

    <div class="card set">
      <h2>Linux</h2>
      <p class="step">Browser settings above for per-app.</p>
      <p class="step">System-wide: run dnscrypt-proxy or cloudflared pointed at the link.</p>
    </div>
  </section>

  <section class="card">
    <p class="eyebrow">resolvers</p>
    <div class="res-list">${resolvers}</div>
    <p class="foot">Primary first, fallback only if it's down. Both filter malware and phishing.</p>
  </section>

</div>

<script>
function copyLink(btn) {
  var input = document.getElementById("doh");
  function done() {
    var label = btn.dataset.label;
    btn.textContent = "copied";
    btn.classList.add("ok");
    setTimeout(function () { btn.textContent = label; btn.classList.remove("ok"); }, 1600);
  }
  function fallback() {
    input.focus();
    input.select();
    input.setSelectionRange(0, 99999);
    try { document.execCommand("copy"); done(); } catch (e) {}
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(input.value).then(done).catch(fallback);
  } else {
    fallback();
  }
}
</script>
</body>
</html>`, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}
