const CACHE='eversmartnode-v1.7.0-alpha.53.95-purity-fence-handover';
const ASSETS=['./','./index.html','./evernode.html','./evernode-logo.svg','./hotpocket-js-client.min.js','./sodium.js','./qrcode.js'];
self.addEventListener('install',e=>{self.skipWaiting();e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).catch(()=>{}))});
self.addEventListener('activate',e=>e.waitUntil(Promise.all([self.clients.claim(),caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE&&(/^everadmin-v/i.test(k)||/^eversmartnode-v/i.test(k))).map(k=>caches.delete(k))))])));
self.addEventListener('fetch',e=>{
  const u=new URL(e.request.url);
  if(u.origin===self.location.origin&&(u.pathname.startsWith('/signer/')||u.pathname==='/signer'||u.pathname.startsWith('/setup/')||u.pathname==='/setup'))return;
  e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)));
});
