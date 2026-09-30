/**
 * Signed Lane - instrumented Signature Agent origin.
 *
 * WHY THIS EXISTS
 * ---------------
 * E1b showed that origins block requests carrying Web Bot Auth header NAMES
 * with syntactically invalid contents at 93.6%, against 96.8% for a validly
 * signed request. Statistically indistinguishable. That suggests the
 * enforcement path never evaluates the cryptography - but it is inference
 * from a rate, and a determined reviewer can propose alternatives.
 *
 * There is a decisive test. Verifying an RFC 9421 signature requires the
 * signer's public key, and the only way to obtain ours is to fetch the
 * directory named in the Signature-Agent header. If we serve that directory
 * ourselves and log every retrieval, then send signed requests to thousands
 * of origins, the fetch log answers the question directly:
 *
 *   - any fetch  -> that origin obtained key material and could have verified
 *   - zero fetches -> no origin held the key. Verification did not merely
 *     fail to happen; it was impossible. Whatever the block is keyed on, it
 *     is not the signature.
 *
 * GitHub Pages cannot answer this because it exposes no access logs. This
 * Worker can, and as a side effect fixes our own conformance gap: Pages
 * serves the directory as application/octet-stream, which is the one
 * dimension where all nine measured operators conform and we did not.
 *
 * ROUTES
 *   /.well-known/http-message-signatures-directory   the JWKS  (logged)
 *   /hits?token=...                                  the fetch log
 *   /echo                                            reflects what the edge
 *                                                    delivered, for testing
 *                                                    header pass-through
 *   /                                                a study description
 *
 * Logging goes to console.log (visible to `wrangler tail`) and, when a KV
 * namespace is bound as WBA_LOG, to durable storage that survives the run.
 */

const JWKS = {
  keys: [
    {
      kty: "OKP",
      crv: "Ed25519",
      x: "fw5_IB1MB7TGzHEPz6S91-Dhf2Xg2Vfi88PVyrSuys0",
      // RFC 7638 thumbprint: DS9-MCWEmbVUgP_btQf_a3ojatyLEi-dfBO8cXqGw7w
      // (verified 13 Sep 2026 against keys/research.pem, docs/ and Pages)
    },
  ],
};

// The media type the specification defines. GitHub Pages cannot set this,
// which is why our own directory was non-conformant.
const DIR_TYPE = "application/http-message-signatures-directory+json";

const DIR_PATH = "/.well-known/http-message-signatures-directory";

// KV free tier allows 1,000 writes/day. We expect approximately zero fetches;
// this cap exists so that an unexpected flood degrades to counting rather
// than failing, and never silently drops the fact that it happened.
const MAX_LOGGED = 800;

function nowISO() {
  return new Date().toISOString();
}

function snapshot(request) {
  const url = new URL(request.url);
  const h = {};
  for (const [k, v] of request.headers) h[k] = v;
  const cf = request.cf || {};
  return {
    t: nowISO(),
    path: url.pathname,
    query: url.search,
    method: request.method,
    ip: request.headers.get("cf-connecting-ip"),
    country: cf.country || request.headers.get("cf-ipcountry"),
    asn: cf.asn,
    as_org: cf.asOrganization,
    colo: cf.colo,
    tls: cf.tlsVersion,
    http: cf.httpProtocol,
    ua: request.headers.get("user-agent"),
    referer: request.headers.get("referer"),
    ray: request.headers.get("cf-ray"),
    // If a verifier is fetching our key, these tell us who and on whose
    // behalf. Cloudflare's own fetcher would identify itself here.
    signature_agent: request.headers.get("signature-agent"),
    accept: request.headers.get("accept"),
  };
}

async function record(env, entry) {
  // Always emit: `wrangler tail` captures this even with no KV bound.
  console.log("DIRFETCH " + JSON.stringify(entry));
  if (!env || !env.WBA_LOG) return;
  try {
    const n = parseInt((await env.WBA_LOG.get("__count")) || "0", 10);
    await env.WBA_LOG.put("__count", String(n + 1));
    if (n < MAX_LOGGED) {
      const key = "hit:" + entry.t + ":" + (entry.ray || Math.random().toString(36).slice(2));
      await env.WBA_LOG.put(key, JSON.stringify(entry), {
        expirationTtl: 60 * 60 * 24 * 90,
      });
    }
  } catch (e) {
    console.log("KVERR " + String(e));
  }
}

async function readLog(env, token, want) {
  if (!env || !env.WBA_LOG) {
    return { error: "no KV namespace bound; use `wrangler tail` instead" };
  }
  const expected = env.HITS_TOKEN;
  // The log holds third-party IP addresses. It is not public.
  if (!expected || token !== expected) {
    return { error: "unauthorized" };
  }
  const count = parseInt((await env.WBA_LOG.get("__count")) || "0", 10);
  const out = [];
  let cursor;
  do {
    const page = await env.WBA_LOG.list({ prefix: "hit:", cursor, limit: 1000 });
    for (const k of page.keys) out.push(k.name);
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor && out.length < want);
  const entries = [];
  for (const name of out.slice(0, want)) {
    const v = await env.WBA_LOG.get(name);
    if (v) entries.push(JSON.parse(v));
  }
  return { total_fetches: count, stored: entries.length, entries };
}

const PAGE = `<!doctype html><meta charset="utf-8">
<title>Signed Lane - Web Bot Auth measurement study</title>
<style>body{font:15px/1.6 system-ui,sans-serif;max-width:40em;margin:3em auto;padding:0 1em}
code{background:#f3f3f3;padding:.1em .3em;border-radius:3px}</style>
<h1>Signed Lane</h1>
<p>This origin is part of an academic measurement study of Web Bot Auth
(<code>draft-ietf-webbotauth-httpsig-protocol</code>) and its deployment.</p>
<p>It publishes an Ed25519 signing key at
<code>/.well-known/http-message-signatures-directory</code> and records
retrievals of that directory, in order to establish whether origins that
respond differently to signed requests ever obtain the key material needed
to verify a signature.</p>
<p>Requests originating from this study are rate-limited, obey
<code>robots.txt</code>, and identify themselves in the User-Agent with a
contact address. Study description and code:
<a href="https://sumit-sagar.github.io/signed-lane/">sumit-sagar.github.io/signed-lane</a></p>
<p>Contact: <code>sumit.sagar.ug23@nsut.ac.in</code></p>`;


/**
 * /vantage - run the E1 matched pair from a different network.
 *
 * The single remaining structural limitation of the study is that every
 * measurement leaves one residential IP in one country. The matched-pair
 * design holds the source constant within each comparison, which is what
 * licenses the causal reading, but the absolute rates belong to that vantage.
 *
 * This Worker runs on a different network entirely. Requests it makes leave
 * Cloudflare's edge, not the researcher's ISP: different ASN, different
 * address, different reputation, no shared history with the origins.
 *
 * The private key never comes here. The laptop signs each request and posts
 * the finished headers; this route only replays them and reports what came
 * back. A leaked Worker secret would then expose nothing but a public key.
 *
 * POST /vantage
 *   { "ua": "...", "jobs": [ {"host": "x.com", "signed": {header: value}} ] }
 *
 * Free-tier Workers allow 50 subrequests per invocation, so the caller must
 * batch at 25 hosts or fewer (two arms each). Requests within a batch run
 * sequentially with a delay, matching the laptop's pacing rather than
 * hammering 25 origins at once from a shared edge address.
 *
 * KNOWN CONFOUND, stated here so it cannot be forgotten downstream: traffic
 * from Cloudflare's network to Cloudflare-fronted origins may be routed or
 * treated differently from traffic arriving over the public internet. Roughly
 * two thirds of the sample is not Cloudflare-fronted, and the comparison
 * should be reported split on that.
 */
const CHALLENGE_MARKERS = ["just a moment", "checking your browser",
  "attention required", "cf_chl_opt", "verifying you are human"];

function classifyResp(status, ctype, body) {
  if (status === 401 || status === 403) return "blocked";
  if (status === 429) return "rate_limited";
  if (status === 402) return "payment_required";
  if (status >= 200 && status < 300) {
    if ((ctype || "").toLowerCase().includes("html") && body) {
      const b = body.slice(0, 8000).toLowerCase();
      for (const m of CHALLENGE_MARKERS) if (b.includes(m)) return "challenged";
    }
    return "served";
  }
  return "http_" + status;
}

async function oneArm(url, headers, ua) {
  const t0 = Date.now();
  try {
    const r = await fetch(url, {
      headers: Object.assign({ "User-Agent": ua }, headers || {}),
      redirect: "follow",
      // never reuse a cached answer: a cached 200 would silently become an
      // observation we never actually made
      cf: { cacheTtl: 0, cacheEverything: false },
    });
    const ctype = r.headers.get("content-type") || "";
    let body = "";
    try { body = await r.text(); } catch (e) { body = ""; }
    return {
      outcome: classifyResp(r.status, ctype, body),
      status: r.status,
      bytes: body.length,
      latency_ms: Date.now() - t0,
      server: r.headers.get("server"),
      cf_ray: r.headers.get("cf-ray"),
      cf_mitigated: r.headers.get("cf-mitigated"),
    };
  } catch (e) {
    return { outcome: "error", error: String(e).slice(0, 120),
             latency_ms: Date.now() - t0 };
  }
}

async function vantage(request, env) {
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "POST only" }), {
      status: 405, headers: { "content-type": "application/json" } });
  }
  const token = new URL(request.url).searchParams.get("token");
  if (!env.HITS_TOKEN || token !== env.HITS_TOKEN) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401, headers: { "content-type": "application/json" } });
  }
  let job;
  try { job = await request.json(); }
  catch (e) { return new Response(JSON.stringify({ error: "bad json" }),
    { status: 400, headers: { "content-type": "application/json" } }); }

  const jobs = (job.jobs || []).slice(0, 25);
  const ua = job.ua || "wba-vantage/0.1";
  const delay = Math.min(Math.max(job.delay_ms || 400, 0), 2000);
  const out = [];
  for (const j of jobs) {
    const url = "https://" + j.host + "/";
    // unsigned first, then signed, both from this edge in the same instant
    const a = await oneArm(url, {}, ua);
    await new Promise((r) => setTimeout(r, delay));
    const b = await oneArm(url, j.signed || {}, ua);
    await new Promise((r) => setTimeout(r, delay));
    out.push({ host: j.host, A: a, B: b });
  }
  return new Response(JSON.stringify({
    vantage: "cloudflare-worker",
    colo: (request.cf && request.cf.colo) || null,
    results: out,
  }, null, 2), { headers: { "content-type": "application/json" } });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname;

    if (p === DIR_PATH) {
      // Log before responding, but do not make the response wait on KV.
      const entry = snapshot(request);
      if (ctx && ctx.waitUntil) ctx.waitUntil(record(env, entry));
      else await record(env, entry);
      return new Response(JSON.stringify(JWKS), {
        headers: {
          "content-type": DIR_TYPE,
          "cache-control": "max-age=86400",
          "access-control-allow-origin": "*",
        },
      });
    }

    if (p === "/hits") {
      const want = Math.min(parseInt(url.searchParams.get("n") || "500", 10), 1000);
      const body = await readLog(env, url.searchParams.get("token"), want);
      return new Response(JSON.stringify(body, null, 2), {
        status: body.error === "unauthorized" ? 401 : 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (p === "/vantage") {
      return vantage(request, env);
    }

    if (p === "/echo") {
      const h = {};
      for (const [k, v] of request.headers) h[k] = v;
      return new Response(
        JSON.stringify(
          {
            note: "what the Cloudflare edge actually delivered to the origin",
            received_headers: h,
            cf: request.cf || null,
          },
          null,
          2
        ),
        { headers: { "content-type": "application/json" } }
      );
    }

    if (p === "/robots.txt") {
      return new Response("User-agent: *\nAllow: /\n", {
        headers: { "content-type": "text/plain" },
      });
    }

    return new Response(PAGE, {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  },
};
