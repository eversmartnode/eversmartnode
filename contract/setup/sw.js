const CACHE_NAME='everadmin-signer-setup-v4';
const APP_SHELL=['/setup/','/setup/index.html','/setup/manifest.json','/setup/sw.js','/setup/qrcode.js','/setup/sodium.js','/setup/hotpocket-js-client.min.js','/setup/icon.svg','/setup/terms.md'];
self.addEventListener('install',event=>{event.waitUntil(caches.open(CACHE_NAME).then(cache=>cache.addAll(APP_SHELL)));self.skipWaiting()});
self.addEventListener('activate',event=>{event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE_NAME&&k.startsWith('everadmin-signer-setup-')).map(k=>caches.delete(k)))));self.clients.claim()});
self.addEventListener('fetch',event=>{if(event.request.mode==='navigate'){event.respondWith(fetch(event.request).catch(()=>caches.match('/setup/index.html')));return}event.respondWith(caches.match(event.request).then(cached=>cached||fetch(event.request).then(response=>{const copy=response.clone();caches.open(CACHE_NAME).then(cache=>cache.put(event.request,copy));return response})))})
