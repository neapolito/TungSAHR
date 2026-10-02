// TungNet — dependency-free rewriting web proxy. Run: node server.js
const http = require('http'), https = require('https'), fs = require('fs');
const path = require('path'), zlib = require('zlib'), dns = require('dns'), net = require('net');

const PORT = process.env.PORT || 8080;
const jars = new Map(); // sid -> Map(domain -> Map(name -> value))

const prox = u => '/p/' + encodeURIComponent(u);
const isPrivate = ip => /^(127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc|fd|fe80)/i.test(ip);

// ---------- cookies (kept server-side so third-party/cross-site logins still work) ----------
function sidOf(req, res) {
  const m = /(?:^|;\s*)tn_sid=([\w-]+)/.exec(req.headers.cookie || '');
  if (m) return m[1];
  const sid = require('crypto').randomUUID();
  res.setHeader('Set-Cookie', `tn_sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000`);
  return sid;
}
function cookieHeader(sid, host) {
  const jar = jars.get(sid); if (!jar) return '';
  const out = [];
  for (const [dom, c] of jar) if (host === dom || host.endsWith('.' + dom)) for (const [k, v] of c) out.push(k + '=' + v);
  return out.join('; ');
}
function storeCookies(sid, host, list) {
  if (!list) return;
  if (!jars.has(sid)) jars.set(sid, new Map());
  const jar = jars.get(sid);
  for (const raw of list) {
    const parts = raw.split(';').map(s => s.trim());
    const i = parts[0].indexOf('='); if (i < 1) continue;
    const name = parts[0].slice(0, i), val = parts[0].slice(i + 1);
    let dom = host, del = false;
    for (const p of parts.slice(1)) {
      const [k, v = ''] = p.split('='); const key = k.toLowerCase();
      if (key === 'domain' && v) dom = v.replace(/^\./, '').toLowerCase();
      if (key === 'max-age' && Number(v) <= 0) del = true;
      if (key === 'expires' && Date.parse(v) < Date.now()) del = true;
    }
    if (!(host === dom || host.endsWith('.' + dom))) dom = host;
    if (!jar.has(dom)) jar.set(dom, new Map());
    del ? jar.get(dom).delete(name) : jar.get(dom).set(name, val);
  }
}

// ---------- rewriting ----------
function resolve(u, base) {
  u = u.trim().replace(/&amp;/g, '&');
  if (!u || /^(data:|blob:|javascript:|mailto:|tel:|about:|#)/i.test(u)) return null;
  try { const a = new URL(u, base); return /^https?:$/.test(a.protocol) ? a.href : null; } catch { return null; }
}
function rewriteCSS(css, base) {
  return css
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (m, q, u) => { const a = resolve(u, base); return a ? `url(${q}${prox(a)}${q})` : m; })
    .replace(/@import\s+(['"])(.*?)\1/gi, (m, q, u) => { const a = resolve(u, base); return a ? `@import ${q}${prox(a)}${q}` : m; });
}
const CLIENT = base => `<script>(function(){var B=${JSON.stringify(base)};
function rw(u){if(typeof u!=='string'||/^(data:|blob:|javascript:|mailto:|tel:|about:|#)/i.test(u)||u.indexOf('/p/')===0)return u;
try{var a=new URL(u,B).href;return /^https?:/i.test(a)?'/p/'+encodeURIComponent(a):u}catch(e){return u}}
var f=window.fetch;if(f)window.fetch=function(i,o){try{if(typeof i==='string')i=rw(i);else if(i&&i.url)i=new Request(rw(i.url),i)}catch(e){}return f.call(this,i,o)};
var xo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){arguments[1]=rw(String(u));return xo.apply(this,arguments)};
var wo=window.open;window.open=function(u){if(u)arguments[0]=rw(String(u));return wo.apply(this,arguments)};
var sa=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){if(/^(src|href|action|poster)$/i.test(n))v=rw(String(v));return sa.call(this,n,v)};
[[HTMLScriptElement,'src'],[HTMLImageElement,'src'],[HTMLIFrameElement,'src'],[HTMLSourceElement,'src'],[HTMLMediaElement,'src'],[HTMLLinkElement,'href'],[HTMLAnchorElement,'href'],[HTMLFormElement,'action']].forEach(function(p){
var d=Object.getOwnPropertyDescriptor(p[0].prototype,p[1]);if(d&&d.set)Object.defineProperty(p[0].prototype,p[1],{get:d.get,set:function(v){d.set.call(this,rw(String(v)))},configurable:true})});
['pushState','replaceState'].forEach(function(k){var o=history[k];history[k]=function(s,t,u){try{return o.call(this,s,t,u)}catch(e){return o.call(this,s,t)}}});
})();</script>`;
function rewriteHTML(html, base) {
  html = html
    .replace(/<meta[^>]+http-equiv=["']?content-security-policy[^>]*>/gi, '')
    .replace(/\s(integrity|nonce|crossorigin)=("[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/(\s(?:href|src|action|poster|data-src)=)(["'])(.*?)\2/gi, (m, pre, q, u) => { const a = resolve(u, base); return a ? `${pre}${q}${prox(a)}${q}` : m; })
    .replace(/(\ssrcset=)(["'])(.*?)\2/gi, (m, pre, q, v) => pre + q + v.split(',').map(s => {
      const [u, ...rest] = s.trim().split(/\s+/); const a = resolve(u, base); return (a ? prox(a) : u) + (rest.length ? ' ' + rest.join(' ') : '');
    }).join(', ') + q)
    .replace(/(<style[^>]*>)([\s\S]*?)(<\/style>)/gi, (m, a, css, b) => a + rewriteCSS(css, base) + b)
    .replace(/(\sstyle=)(["'])(.*?)\2/gi, (m, pre, q, css) => pre + q + rewriteCSS(css, base) + q);
  const tag = CLIENT(base);
  return /<head[^>]*>/i.test(html) ? html.replace(/<head[^>]*>/i, m => m + tag) : tag + html;
}

// ---------- proxy ----------
function decode(buf, enc) {
  if (enc === 'gzip') return zlib.gunzipSync(buf);
  if (enc === 'br') return zlib.brotliDecompressSync(buf);
  if (enc === 'deflate') return zlib.inflateSync(buf);
  return buf;
}
function safeLookup(host, opts, cb) {
  dns.lookup(host, opts, (err, addr, fam) => {
    if (err) return cb(err);
    const list = Array.isArray(addr) ? addr.map(a => a.address) : [addr];
    if (list.some(isPrivate)) return cb(new Error('Blocked address'));
    cb(null, addr, fam);
  });
}
function proxy(req, res, target, sid) {
  let url;
  try { url = new URL(target); } catch { res.writeHead(400); return res.end('Bad URL'); }
  if (!/^https?:$/.test(url.protocol) || (net.isIP(url.hostname) && isPrivate(url.hostname))) { res.writeHead(403); return res.end('Blocked'); }

  const h = { ...req.headers };
  for (const k of ['host', 'cookie', 'connection', 'accept-encoding', 'x-forwarded-for', 'x-forwarded-proto', 'x-real-ip']) delete h[k];
  h.host = url.host; h['accept-encoding'] = 'gzip, deflate, br';
  if (h.origin) h.origin = url.origin;
  h.referer = url.origin + '/';
  const ck = cookieHeader(sid, url.hostname); if (ck) h.cookie = ck;

  const lib = url.protocol === 'https:' ? https : http;
  const up = lib.request({ protocol: url.protocol, hostname: url.hostname, port: url.port || undefined,
    path: url.pathname + url.search, method: req.method, headers: h, lookup: safeLookup }, ur => {
    storeCookies(sid, url.hostname, ur.headers['set-cookie']);
    const oh = { ...ur.headers };
    for (const k of ['set-cookie', 'content-security-policy', 'content-security-policy-report-only', 'x-frame-options',
      'strict-transport-security', 'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy',
      'report-to', 'nel', 'alt-svc']) delete oh[k];
    if (oh.location) { const a = resolve(oh.location, url.href); if (a) oh.location = prox(a); }
    const sc = res.getHeader('Set-Cookie'); if (sc) oh['set-cookie'] = sc;

    const type = (oh['content-type'] || '').toLowerCase();
    const isHTML = type.includes('text/html'), isCSS = type.includes('text/css');
    if (!(isHTML || isCSS) || ur.statusCode === 206) { res.writeHead(ur.statusCode, oh); return ur.pipe(res); }

    const chunks = []; ur.on('data', c => chunks.push(c));
    ur.on('end', () => {
      try {
        let body = decode(Buffer.concat(chunks), oh['content-encoding']).toString('utf8');
        body = isHTML ? rewriteHTML(body, url.href) : rewriteCSS(body, url.href);
        delete oh['content-encoding']; delete oh['content-length'];
        res.writeHead(ur.statusCode, oh); res.end(body);
      } catch (e) { res.writeHead(502); res.end('Decode error'); }
    });
  });
  up.on('error', e => { if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' }); res.end('TungNet could not reach that site: ' + e.message); });
  req.pipe(up);
}

// ---------- server ----------
const toTarget = q => {
  q = (q || '').trim(); if (!q) return null;
  if (/^https?:\/\//i.test(q)) return q;
  if (/^[\w-]+(\.[\w-]+)+(\/.*)?$/.test(q)) return 'https://' + q;
  return 'https://html.duckduckgo.com/html/?q=' + encodeURIComponent(q);
};
http.createServer((req, res) => {
  const [pathname, query] = req.url.split('?');
  if (pathname === '/' || pathname === '/index.html') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return fs.createReadStream(path.join(__dirname, 'public', 'index.html')).pipe(res);
  }
  if (pathname === '/go') {
    const t = toTarget(new URLSearchParams(query).get('q'));
    res.writeHead(302, { location: t ? prox(t) : '/' }); return res.end();
  }
  const sid = sidOf(req, res);
  if (pathname.startsWith('/p/')) {
    let target = decodeURIComponent(pathname.slice(3));
    if (query) target += (target.includes('?') ? '&' : '?') + query; // GET forms append to action
    return proxy(req, res, target, sid);
  }
  // Root-relative request that escaped rewriting: recover the site from the Referer.
  const m = /\/p\/([^?]+)/.exec(req.headers.referer || '');
  if (m) {
    try { res.writeHead(307, { location: prox(new URL(req.url, decodeURIComponent(m[1])).href) }); return res.end(); } catch {}
  }
  res.writeHead(404, { 'content-type': 'text/plain' }); res.end('Not found');
}).listen(PORT, () => console.log('TungNet running on http://localhost:' + PORT));
