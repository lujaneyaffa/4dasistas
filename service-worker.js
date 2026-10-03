const CACHE_NAME = '4dasistas-v31';
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
