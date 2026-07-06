/**
 * RECAUDA — service worker mínimo
 * Guarda en caché la app (HTML/JS/CSS) para que abra aunque no haya
 * conexión. Los datos (API) NUNCA se cachean aquí: eso lo maneja
 * la propia app guardando una copia en localStorage.
 */
const CACHE = 'recauda-shell-v1';

self.addEventListener('install', (e)=>{
  e.waitUntil(caches.open(CACHE).then(c=>c.add('/')));
  self.skipWaiting();
});

self.addEventListener('activate', (e)=>{
  e.waitUntil(
    caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k))))
  );
  self.clients.claim();
});

self.addEventListener('fetch', (e)=>{
  if(e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  if(url.pathname.startsWith('/api/')) return; // la API nunca se sirve desde caché
  if(url.origin !== self.location.origin) return; // recursos externos (mapa, fuentes): sin caché propia

  e.respondWith(
    fetch(e.request).then(res=>{
      const copy = res.clone();
      caches.open(CACHE).then(c=>c.put(e.request, copy));
      return res;
    }).catch(()=> caches.match(e.request).then(r => r || caches.match('/')))
  );
});

self.addEventListener('push', (e)=>{
  let data = { title: 'ZaJu Tech', body: 'Tienes clientes pendientes por pagar.' };
  try{ if(e.data) data = e.data.json(); }catch(err){ /* usa el mensaje por defecto */ }
  e.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/icon-192.png',
      badge: '/icon-192.png'
    })
  );
});

self.addEventListener('notificationclick', (e)=>{
  e.notification.close();
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list=>{
      for(const c of list){ if('focus' in c) return c.focus(); }
      if(clients.openWindow) return clients.openWindow('/');
    })
  );
});
