const CACHE_NAME = "everstoring-signer-LOCKED-v2";
const SCOPE_URL = new URL(self.registration.scope);
const SCOPE_PATH = SCOPE_URL.pathname.endsWith("/") ? SCOPE_URL.pathname : `${SCOPE_URL.pathname}/`;
const SCOPE_NO_SLASH = SCOPE_PATH.replace(/\/$/, "");

const APP_SHELL_FILES = [
  "./",
  "./index.html",
  "./manifest.json",
  "./sw.js",
  "./hotpocket-js-client.min.js",
  "./bson.bundle.min.js",
  "./sodium.js",
  "./jsQR.js",
  "./icon.png",
  "./icon.svg",
  "./signer_terms.md"
];

const APP_SHELL_URLS = APP_SHELL_FILES.map((item) => new URL(item, self.registration.scope).toString());

function isSignerPath(pathname) {
  return pathname === SCOPE_NO_SLASH || pathname.startsWith(SCOPE_PATH);
}

function offlineError(message, status = 503) {
  return new Response(
    `<!doctype html><meta charset="utf-8">
<title>EV Signer offline</title>
<body style="background:#0f1115;color:white;font-family:system-ui;padding:24px">
<h1>EV Signer local snapshot unavailable</h1>
<pre style="white-space:pre-wrap;color:#fca5a5">${String(message || "The local signer snapshot is incomplete.")}</pre>
<p>No website fallback was attempted.</p>
</body>`,
    { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } }
  );
}

self.addEventListener("message", (event) => {
  if (event.data && event.data.type === "SKIP_WAITING") self.skipWaiting();
});

self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    // This is the one intentional website read: create a complete local snapshot atomically
    // during first install/update. If any file is unavailable, this SW does not activate.
    await cache.addAll(APP_SHELL_URLS);
    await self.skipWaiting();
  })());
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    // Deliberately preserve every older signer snapshot. A bad/future deployment must not
    // erase a known-good installed signer cache.
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // Signing APIs remain network-capable. The signer *application shell* is what is locked local.
  if (url.pathname.startsWith("/api/")) return;
  if (!isSignerPath(url.pathname)) return;

  if (request.mode === "navigate") {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE_NAME);
      const cachedIndex =
        await cache.match(new URL("./index.html", self.registration.scope).toString(), { ignoreSearch: true }) ||
        await cache.match(new URL("./", self.registration.scope).toString(), { ignoreSearch: true });
      return cachedIndex || offlineError("The installed EV Signer index is missing from local storage.");
    })());
    return;
  }

  event.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);
    const cached = await cache.match(request, { ignoreSearch: true });
    if (cached) return cached;
    return offlineError(`Missing locked signer resource:\n${url.pathname}\n\nThe signer will not fetch this asset from the website.`, 504);
  })());
});
