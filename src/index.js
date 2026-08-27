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
 * And ONE of these for auth:
 *   ADMIN_KEY         secret text  - the publish key in plain text
 *   ADMIN_KEY_SHA256  plain var    - SHA-256 hex of the publish key
 *
 * The hash form exists so the key can be configured from a committed
 * wrangler.jsonc without the key itself ever entering the repository.
 * ADMIN_KEY wins if both are present.
 *
 * Routes:
 *   GET    /api/site           read the published content
 *   PUT    /api/site           publish content            (auth)
 *   POST   /api/auth           check an admin key
 *   POST   /api/upload?name=   store an image in R2       (auth)
 *   GET    /api/img/<key>      serve an image from R2
 *   DELETE /api/img/<key>      remove an image            (auth)
 *   GET    /api/images         list stored images         (auth)
 */

const KV_KEY = "site";
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
  return Boolean(env.ADMIN_KEY || env.ADMIN_KEY_SHA256);
}

async function authed(request, env) {
  const header = request.headers.get("X-Admin-Key") || "";
  if (!header || !authConfigured(env)) return false;
  if (env.ADMIN_KEY) return sameSecret(header, env.ADMIN_KEY);
  return sameSecret(await sha256hex(header), String(env.ADMIN_KEY_SHA256).trim().toLowerCase());
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
      if (!(await authed(request, env))) return json({ error: "unauthorized" }, 401);
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
    return (await authed(request, env)) ? json({ ok: true }) : json({ error: "bad key" }, 401);
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
      if (!(await authed(request, env))) return json({ error: "unauthorized" }, 401);
      const body = await request.text();
      if (body.length > MAX_JSON) return json({ error: "content too large" }, 413);
      let parsed;
      try { parsed = JSON.parse(body); }
      catch { return json({ error: "body is not valid JSON" }, 400); }
      if (!parsed || typeof parsed !== "object") return json({ error: "expected a JSON object" }, 400);

      parsed._savedAt = new Date().toISOString();
      await env.SITE_KV.put(KV_KEY, JSON.stringify(parsed));
      // Keep the previous three publishes so a bad edit is recoverable.
      await env.SITE_KV.put(`backup:${Date.now()}`, JSON.stringify(parsed), { expirationTtl: 60 * 60 * 24 * 30 });
      return json({ ok: true, savedAt: parsed._savedAt });
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
    if (!(await authed(request, env))) return json({ error: "unauthorized" }, 401);
    if (!env.SITE_R2) return json({ error: "R2 bucket is not bound" }, 503);
    const listed = await env.SITE_R2.list({ limit: 1000 });
    return json({
      images: listed.objects.map((o) => ({ key: o.key, url: `/api/img/${o.key}`, size: o.size, uploaded: o.uploaded })),
    });
  }

  return json({ error: "unknown route" }, 404);
}
