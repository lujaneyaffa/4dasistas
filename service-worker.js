const CACHE_NAME = '4dasistas-v70';
const APP_SHELL = ['/', '/index.html', '/manifest.webmanifest', '/app-icon.svg', '/assets/apple-touch-icon.png', '/assets/icon-192.png', '/assets/icon-512.png'];

// Everything the app needs to open and show its content with no connection. Data files are added one by one so a missing
// file can never fail the whole install.
const DATA_FILES = ['/data/sports.json', '/data/gatherings.json', '/data/dayactivities.json', '/data/mosquegatherings.json', '/data/trips.json', '/data/clubs.json', '/data/resources.json', '/data/supportprograms.json', '/data/sitetext.json'];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(async cache => {
    await cache.addAll(APP_SHELL);
    await Promise.all(DATA_FILES.map(f => cache.add(f).catch(() => {})));
  }));
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
    ))
  );
  self.clients.claim();
});

// Read-only API calls that are safe to show from the cache when offline. They are cached PER SIGN-IN (the key includes a hash
// of the Authorization header), so one person's data can never be served to someone else who logs in on the same phone.
const CACHEABLE_API = /^\/api\/(clubs|idea-availability|members|labels|avail-period)(\/|$)/;
async function apiCacheKey(request, url) {
  const auth = request.headers.get('Authorization') || '';
  let h = 'anon';
  if (auth) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(auth));
    h = [...new Uint8Array(buf)].slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  return new Request(location.origin + '/__api__/' + h + url.pathname + url.search);
}
async function networkFirstApi(event, url) {
  const key = await apiCacheKey(event.request, url);
  const cache = await caches.open(CACHE_NAME);
  const fromCache = () => cache.match(key);
  const network = fetch(event.request).then(response => {
    if (response.ok) cache.put(key, response.clone());
    return response;
  });
  // A slow or dead connection falls back to the saved copy after a few seconds instead of leaving the screen waiting.
  const timeout = new Promise(resolve => setTimeout(() => resolve(null), 6000));
  try {
    const first = await Promise.race([network.catch(() => null), timeout]);
    // A good answer wins. If the server errors (5xx / 429 — e.g. a Cloudflare limit) or is slow, show the last saved copy instead.
    if (first && (first.ok || (first.status < 500 && first.status !== 429))) return first;
    const cached = await fromCache();
    if (cached) return cached;
    if (first) return first;
    return await network;
  } catch (e) {
    return (await fromCache()) || Response.error();
  }
}

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  const path = url.pathname;

  // Never cache the CMS admin app, its config, or admin/private API calls — these must always be fresh.
  if (path.startsWith('/admin') || path === '/editor') return;
  if (path.startsWith('/api')) {
    if (url.origin === location.origin && CACHEABLE_API.test(path)) event.respondWith(networkFirstApi(event, url));
    return;
  }

  const sameOrigin = url.origin === location.origin;
  const crossStatic = !sameOrigin && ['script', 'style', 'font'].includes(event.request.destination); // CDN libraries + fonts, so maps/globe/fonts also work offline
  event.respondWith(
    fetch(event.request)
      .then(response => {
        if ((sameOrigin && response.ok) || (crossStatic && (response.ok || response.type === 'opaque'))) {
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, response.clone()));
        }
        return response;
      })
      .catch(() => caches.match(event.request).then(cached => {
        if (cached) return cached;
        // Only fall back to the app shell for page navigations — a failed
        // fetch for data/*.json must stay a failure, not silently become HTML.
        if (event.request.mode === 'navigate') return caches.match('/');
        return Response.error();
      }))
  );
});

// ---- Push notifications. The server sends an EMPTY push; we fetch the actual text (keyed by a hash of this device's
// endpoint) and show it. (iOS requires every push to show a notification right away, so we always do — falling back
// to a generic message if the fetch fails.)
self.addEventListener('push', event => {
  event.waitUntil((async () => {
    let msg = { title: '4DASISTAS', body: 'You have a new update — tap to open.', url: '/' };
    try {
      const sub = await self.registration.pushManager.getSubscription();
      if (sub) {
        const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(sub.endpoint));
        const hash = [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
        const r = await fetch('/api/push/message?e=' + hash, { cache: 'no-store' });
        if (r.ok) msg = await r.json();
      }
    } catch (e) { /* keep the generic message */ }
    await self.registration.showNotification(msg.title || '4DASISTAS', {
      body: msg.body || '', icon: '/assets/icon-192.png', badge: '/assets/icon-192.png', data: { url: msg.url || '/' },
    });
  })());
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const c of list) {
      if ('focus' in c) { if (c.navigate) c.navigate(url).catch(() => {}); return c.focus(); }
    }
    return self.clients.openWindow(url);
  }));
});
