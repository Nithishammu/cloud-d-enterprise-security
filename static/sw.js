// Cloud-D Service Worker v3 (Automated Web-to-App Sync & Push Notifications)
// Task 1: Web-to-App Automatic Synchronization & Hot-Reloading Pipeline
// Task 3: Native Mobile Push Notifications

const CACHE_NAME = 'cloud-d-v2.4.0-hotfix';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/cloud-d.js',
  '/manifest.json',
  '/favicon.ico'
];

// Broadcast channel for instantaneous cross-tab and mobile hot-reloads
const syncChannel = 'BroadcastChannel' in self ? new BroadcastChannel('cloud_d_sync') : null;

// 1. Install: Pre-cache core application shell
self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS)).catch((err) => {
      console.warn('[Cloud-D SW] Pre-cache warning:', err);
    })
  );
});

// 2. Activate: Wipe stale caches and take immediate control of all open clients
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => {
          console.log('[Cloud-D SW] Purging stale cache:', k);
          return caches.delete(k);
        })
      )
    ).then(() => self.clients.claim()).then(() => {
      // Notify all clients of active hot-reload
      if (syncChannel) {
        syncChannel.postMessage({ type: 'VERSION_ACTIVATED', cacheName: CACHE_NAME });
      }
    })
  );
});

// 3. Client Message Listener (Task 1: Hot-Update signal)
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// 4. Fetch: Dynamic routing (Network-First for APIs, Cache-First for Shell Assets)
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Always go to network for APIs, shares, and WebSockets/SSE
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/share/')) {
    event.respondWith(
      fetch(event.request).catch(() =>
        new Response(
          JSON.stringify({ error: 'Cloud-D Shard Offline. Check network connectivity.' }),
          { status: 503, headers: { 'Content-Type': 'application/json' } }
        )
      )
    );
    return;
  }

  // Cache-first with background revalidation for static assets
  if (event.request.method === 'GET') {
    event.respondWith(
      caches.match(event.request).then((cached) => {
        const fetchPromise = fetch(event.request).then((networkResponse) => {
          if (networkResponse && networkResponse.ok) {
            const clone = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return networkResponse;
        }).catch(() => cached);

        return cached || fetchPromise;
      })
    );
  }
});

// 5. Task 3: Native Mobile Push Notification Event Handler
self.addEventListener('push', (event) => {
  let payload = {
    title: '🚨 Sentinel Threat Alert',
    body: 'Adversarial payload intercepted across cloud storage shards.',
    tag: 'threat-alert',
    url: '/#threats'
  };

  if (event.data) {
    try {
      const data = event.data.json();
      payload = { ...payload, ...data };
    } catch (e) {
      payload.body = event.data.text();
    }
  }

  const options = {
    body: payload.body,
    icon: '/favicon.ico',
    badge: '/favicon.ico',
    tag: payload.tag || 'cloud-d-alert',
    vibrate: [200, 100, 200, 100, 200],
    data: { url: payload.url || '/#threats' },
    actions: [
      { action: 'open_threats', title: '🛡️ View Sentinel Shield' },
      { action: 'dismiss', title: 'Dismiss' }
    ]
  };

  event.waitUntil(self.registration.showNotification(payload.title, options));
});

// 6. Notification Click Handler
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url) || '/';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if (client.url.includes(targetUrl) && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
    })
  );
});
