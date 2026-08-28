/**
 * Flannel Trappe site API.
 *
 * Runs as a Cloudflare Worker with static assets. The Worker serves
 * /api/* itself and hands every other request to the static site in
 * ./public via the ASSETS binding, so the API and the page share one
 * origin and there is no CORS to configure.
 *
 * Bindings required (declared in wrangler.jsonc):
 *   ASSETS     static assets  - the ./public folder
 *   SITE_KV    KV namespace   - holds the site content JSON
 *   SITE_R2    R2 bucket      - holds uploaded photos
 *
 * Auth. Two roles, each set as a plaintext secret or, preferably, as a
 * SHA-256 hash that is safe to commit:
 *   ADMIN_KEY / ADMIN_KEY_SHA256   master  - may change anything
 *   BAND_KEY  / BAND_KEY_SHA256    band    - photos and shows only
 *
 * The band limit is enforced HERE, not in the browser. A band-role
 * publish is merged over the stored content so only photos and shows
 * can move, whatever the client sends. Client-side limits alone would
 * be decorative. Plaintext wins over the hash if both are set.
 *
 * Routes:
 *   GET    /api/site           read the published content
 *   PUT    /api/site           publish content            (auth)
 *   GET    /api/venues         read the private venue list (auth)
 *   PUT    /api/venues         save the private venue list (auth)
 *   POST   /api/auth           check an admin key
 *   POST   /api/upload?name=   store an image in R2       (auth)
 *   GET    /api/img/<key>      serve an image from R2
 *   DELETE /api/img/<key>      remove an image            (auth)
 *   GET    /api/images         list stored images         (auth)
 */

const KV_KEY = "site";
/* Private to the band. Stored under its own key and served only from
   /api/venues behind auth, so it can never leak through /api/site. */
const KV_VENUES = "venues";
const MAX_JSON = 2 * 1024 * 1024;   // 2 MB of content JSON
const MAX_IMAGE = 12 * 1024 * 1024; // 12 MB per image

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });

/* Compare without leaking length or position through timing. */
function sameSecret(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const enc = new TextEncoder();
  const x = enc.encode(a), y = enc.encode(b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

async function sha256hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function authConfigured(env) {
  return Boolean(env.ADMIN_KEY || env.ADMIN_KEY_SHA256 || env.BAND_KEY || env.BAND_KEY_SHA256);
}

async function matches(sent, plain, hash) {
  if (plain) return sameSecret(sent, plain);
  if (hash) return sameSecret(await sha256hex(sent), String(hash).trim().toLowerCase());
  return false;
}

/* "master", "band", or null. Master is tested first so that if both keys
   were ever set to the same string, the wider role wins. */
async function role(request, env) {
  const sent = request.headers.get("X-Admin-Key") || "";
  if (!sent || !authConfigured(env)) return null;
  if (await matches(sent, env.ADMIN_KEY, env.ADMIN_KEY_SHA256)) return "master";
  if (await matches(sent, env.BAND_KEY, env.BAND_KEY_SHA256)) return "band";
  return null;
}

async function authed(request, env) {
  return (await role(request, env)) !== null;
}

/* Only allow characters that are safe in an R2 key and a URL path. */
function cleanName(raw) {
  const base = String(raw || "image")
    .replace(/[^A-Za-z0-9._-]/g, "-")
    .replace(/-+/g, "-")
    .slice(-80);
  return `${Date.now().toString(36)}-${base || "image"}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // Static files are served before the Worker is even invoked. This
    // only runs for paths with no matching asset, so /api/* lands here.
    if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
      const rest = url.pathname.replace(/^\/api\/?/, "");
      return handleApi(request, env, rest ? rest.split("/") : []);
    }
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response("Not found", { status: 404 });
  },
};

async function handleApi(request, env, parts) {
  const route = parts[0] || "site";
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: { "Allow": "GET, PUT, POST, DELETE, OPTIONS" },
    });
  }

  /* ---- images are public, so handle them before the binding check ---- */
  if (route === "img") {
    const key = parts.slice(1).join("/");
    if (!key) return json({ error: "missing image key" }, 400);
    if (!env.SITE_R2) return json({ error: "R2 bucket is not bound" }, 503);

    if (method === "DELETE") {
      if ((await role(request, env)) !== "master") return json({ error: "master key required" }, 403);
      await env.SITE_R2.delete(key);
      return json({ deleted: key });
    }
    if (method !== "GET" && method !== "HEAD") return json({ error: "method not allowed" }, 405);

    const obj = await env.SITE_R2.get(key);
    if (!obj) return json({ error: "not found" }, 404);
    const headers = new Headers();
    obj.writeHttpMetadata(headers);
    headers.set("etag", obj.httpEtag);
    // Names carry a timestamp, so a given key never changes content.
    headers.set("Cache-Control", "public, max-age=31536000, immutable");
    return new Response(method === "HEAD" ? null : obj.body, { headers });
  }

  /* ---- auth check, used by the admin panel unlock screen ---- */
  if (route === "auth") {
    if (method !== "POST") return json({ error: "method not allowed" }, 405);
    if (!authConfigured(env)) return json({ error: "No publish key is configured on this project" }, 503);
    const who = await role(request, env);
    if (who) return json({ ok: true, role: who });
    // Echo a short prefix of the hash this deployment is actually running.
    // The full hash is already public in wrangler.jsonc, so this leaks
    // nothing, and it tells you whether the deploy is stale or your key
    // simply hashes to something else.
    const configured = env.ADMIN_KEY
      ? "plaintext ADMIN_KEY secret"
      : String(env.ADMIN_KEY_SHA256 || "").trim().toLowerCase().slice(0, 8);
    const sent = (await sha256hex(request.headers.get("X-Admin-Key") || "")).slice(0, 8);
    return json({ error: "bad key", configuredHashStartsWith: configured, yourKeyHashesTo: sent }, 401);
  }

  /* ---- site content ---- */
  if (route === "site") {
    if (!env.SITE_KV) return json({ error: "KV namespace is not bound" }, 503);

    if (method === "GET") {
      const stored = await env.SITE_KV.get(KV_KEY);
      // Deliberately 200, not 404. A 404 here is indistinguishable from
      // "the Function did not deploy", which makes debugging miserable.
      if (!stored) return json({ published: false, message: "Bindings are working. Nothing published yet." });
      return new Response(stored, {
        headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
      });
    }

    if (method === "PUT" || method === "POST") {
      const who = await role(request, env);
      if (!who) return json({ error: "unauthorized" }, 401);
      const body = await request.text();
      if (body.length > MAX_JSON) return json({ error: "content too large" }, 413);
      let parsed;
      try { parsed = JSON.parse(body); }
      catch { return json({ error: "body is not valid JSON" }, 400); }
      if (!parsed || typeof parsed !== "object") return json({ error: "expected a JSON object" }, 400);

      if (who === "band") {
        const current = await env.SITE_KV.get(KV_KEY);
        if (!current) {
          return json({ error: "The master account has to publish the site once before band members can add to it." }, 409);
        }
        const base = JSON.parse(current);
        // Only these two lists may move. Everything else comes from what
        // is already published, so a tampered client changes nothing.
        if (Array.isArray(parsed.photos)) base.photos = parsed.photos;
        if (Array.isArray(parsed.shows))  base.shows  = parsed.shows;
        parsed = base;
      }

      parsed._savedAt = new Date().toISOString();
      parsed._savedBy = who;
      await env.SITE_KV.put(KV_KEY, JSON.stringify(parsed));
      // Keep the previous three publishes so a bad edit is recoverable.
      await env.SITE_KV.put(`backup:${Date.now()}`, JSON.stringify(parsed), { expirationTtl: 60 * 60 * 24 * 30 });
      return json({ ok: true, savedAt: parsed._savedAt });
    }

    return json({ error: "method not allowed" }, 405);
  }

  /* ---- private venue tracker, never public ---- */
  if (route === "venues") {
    if (!env.SITE_KV) return json({ error: "KV namespace is not bound" }, 503);
    const who = await role(request, env);
    if (!who) return json({ error: "unauthorized" }, 401);

    if (method === "GET") {
      const stored = await env.SITE_KV.get(KV_VENUES);
      return json({ venues: stored ? JSON.parse(stored) : [] }, 200, { "Cache-Control": "no-store" });
    }

    if (method === "PUT" || method === "POST") {
      const body = await request.text();
      if (body.length > MAX_JSON) return json({ error: "venue list too large" }, 413);
      let parsed;
      try { parsed = JSON.parse(body); }
      catch { return json({ error: "body is not valid JSON" }, 400); }
      const list = Array.isArray(parsed) ? parsed : parsed && parsed.venues;
      if (!Array.isArray(list)) return json({ error: "expected an array of venues" }, 400);
      await env.SITE_KV.put(KV_VENUES, JSON.stringify(list));
      await env.SITE_KV.put(`venues-backup:${Date.now()}`, JSON.stringify(list), { expirationTtl: 60 * 60 * 24 * 30 });
      return json({ ok: true, count: list.length, savedBy: who });
    }

    return json({ error: "method not allowed" }, 405);
  }

  /* ---- image upload ---- */
  if (route === "upload") {
    if (method !== "POST") return json({ error: "method not allowed" }, 405);
    if (!(await authed(request, env))) return json({ error: "unauthorized" }, 401);
    if (!env.SITE_R2) return json({ error: "R2 bucket is not bound" }, 503);

    const url = new URL(request.url);
    const type = request.headers.get("Content-Type") || "image/jpeg";
    if (!/^image\//.test(type)) return json({ error: "only image uploads are accepted" }, 415);

    const bytes = await request.arrayBuffer();
    if (!bytes.byteLength) return json({ error: "empty upload" }, 400);
    if (bytes.byteLength > MAX_IMAGE) return json({ error: "image too large" }, 413);

    const key = cleanName(url.searchParams.get("name"));
    await env.SITE_R2.put(key, bytes, { httpMetadata: { contentType: type } });
    return json({ ok: true, key, url: `/api/img/${key}`, bytes: bytes.byteLength });
  }

  /* ---- list stored images, for tidying up ---- */
  if (route === "images") {
    if (method !== "GET") return json({ error: "method not allowed" }, 405);
    if ((await role(request, env)) !== "master") return json({ error: "master key required" }, 403);
    if (!env.SITE_R2) return json({ error: "R2 bucket is not bound" }, 503);
    const listed = await env.SITE_R2.list({ limit: 1000 });
    return json({
      images: listed.objects.map((o) => ({ key: o.key, url: `/api/img/${o.key}`, size: o.size, uploaded: o.uploaded })),
    });
  }

  return json({ error: "unknown route" }, 404);
}
