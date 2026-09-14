const CACHE_NAME = '4dasistas-v6';
const APP_SHELL = ['/', '/index.html', '/manifest.webmanifest', '/app-icon.svg', '/assets/apple-touch-icon.png', '/assets/icon-192.png', '/assets/icon-512.png'];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL)));
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

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;

  // Never cache the CMS admin app, its config, or any API call — these must
  // always be fresh. The Cache-Control: no-store rules in _headers only stop
  // the browser's own HTTP cache; this service worker's cache.put() below
  // ignores Cache-Control entirely, so it needs its own explicit exclusion.
  const path = new URL(event.request.url).pathname;
  if (path.startsWith('/admin') || path.startsWith('/api') || path === '/editor') return;

  event.respondWith(
    fetch(event.request)
      .then(response => {
        if (response.ok && new URL(event.request.url).origin === location.origin) {
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
