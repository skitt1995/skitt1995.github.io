// ═══════════════════════════════════════════
// RANSOMBOARD — Local Proxy Server v2
// Proxies ransomware.live API to avoid CORS
// Includes caching, proper headers, fallbacks
// ═══════════════════════════════════════════

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const PORT = 3000;

// Multiple API bases — tried in order
const API_BASES = [
  'https://api.ransomware.live',
  'https://www.ransomware.live/api',
];

// Static data fallback (JSON dumps updated periodically)
const DATA_FALLBACKS = {
  '/recentvictims': 'https://data.ransomware.live/recentvictims.json',
  '/v1/recentvictims': 'https://data.ransomware.live/recentvictims.json',
  '/allcyberattacks': 'https://data.ransomware.live/allcyberattacks.json',
  '/v1/allcyberattacks': 'https://data.ransomware.live/allcyberattacks.json',
  '/groups': 'https://data.ransomware.live/groups.json',
  '/v1/groups': 'https://data.ransomware.live/groups.json',
  '/recentcyberattacks': 'https://data.ransomware.live/recentcyberattacks.json',
  '/v1/recentcyberattacks': 'https://data.ransomware.live/recentcyberattacks.json',
};

const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

// ── In-memory cache (5 min TTL) ──
const cache = {};
const CACHE_TTL = 5 * 60 * 1000;

function getCached(key) {
  const entry = cache[key];
  if (entry && Date.now() - entry.ts < CACHE_TTL) {
    console.log(`  [CACHE HIT] ${key}`);
    return entry.data;
  }
  return null;
}

function setCache(key, data) {
  cache[key] = { data, ts: Date.now() };
}

// ── Request helper with proper headers ──
function httpsGet(url, timeout = 15000) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      method: 'GET',
      timeout,
      headers: {
        'User-Agent': 'RansomBoard/2.0 (Threat Intelligence Dashboard)',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Encoding': 'identity',
        'Connection': 'close',
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, data }));
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
}

// ── Follow redirects properly ──
async function fetchWithRedirects(url, maxRedirects = 3) {
  let currentUrl = url;
  for (let i = 0; i < maxRedirects; i++) {
    const result = await httpsGet(currentUrl);

    if (result.status >= 300 && result.status < 400 && result.headers.location) {
      const loc = result.headers.location;
      const parsed = new URL(currentUrl);
      currentUrl = loc.startsWith('http') ? loc : `${parsed.protocol}//${parsed.host}${loc}`;
      console.log(`  → Redirect ${result.status} → ${currentUrl}`);
      continue;
    }

    return result;
  }
  throw new Error('Too many redirects');
}

// ── Main proxy logic ──
async function proxyRequest(apiPath) {
  // Check cache first
  const cached = getCached(apiPath);
  if (cached) return { status: 200, data: cached };

  // Try each API base
  for (let i = 0; i < API_BASES.length; i++) {
    const base = API_BASES[i];
    const url = `${base}${apiPath}`;
    console.log(`  → Trying: ${url}`);

    try {
      const result = await fetchWithRedirects(url);

      if (result.status === 200) {
        console.log(`  → Success (${result.data.length} bytes)`);
        setCache(apiPath, result.data);
        return { status: 200, data: result.data };
      }

      if (result.status === 429) {
        console.log(`  → Rate limited (429), waiting 2s...`);
        await new Promise(r => setTimeout(r, 2000));
        // Retry same base once
        try {
          const retry = await fetchWithRedirects(url);
          if (retry.status === 200) {
            setCache(apiPath, retry.data);
            return { status: 200, data: retry.data };
          }
        } catch (e) { /* fall through */ }
      }

      console.log(`  → Got ${result.status}, trying next...`);
    } catch (err) {
      console.log(`  → Error: ${err.message}, trying next...`);
    }
  }

  // Try static data fallback
  const fallbackUrl = DATA_FALLBACKS[apiPath];
  if (fallbackUrl) {
    console.log(`  → Trying static fallback: ${fallbackUrl}`);
    try {
      const result = await fetchWithRedirects(fallbackUrl);
      if (result.status === 200) {
        console.log(`  → Fallback success (${result.data.length} bytes)`);
        setCache(apiPath, result.data);
        return { status: 200, data: result.data };
      }
    } catch (err) {
      console.log(`  → Fallback failed: ${err.message}`);
    }
  }

  // Also try with /v1/ prefix if not already present
  if (!apiPath.startsWith('/v1/')) {
    const v1Path = `/v1${apiPath}`;
    for (const base of API_BASES) {
      const url = `${base}${v1Path}`;
      console.log(`  → Trying v1 variant: ${url}`);
      try {
        const result = await fetchWithRedirects(url);
        if (result.status === 200) {
          console.log(`  → v1 variant success (${result.data.length} bytes)`);
          setCache(apiPath, result.data);
          return { status: 200, data: result.data };
        }
      } catch (err) {
        console.log(`  → v1 variant error: ${err.message}`);
      }
    }
  }

  throw new Error('All API bases and fallbacks failed');
}

// ── HTTP Server ──
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // ── API Proxy ──
  if (url.pathname.startsWith('/api/')) {
    const apiPath = url.pathname.replace(/^\/api/, '');
    console.log(`\n[PROXY] ${req.method} ${apiPath}`);

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    try {
      const result = await proxyRequest(apiPath);
      res.writeHead(result.status, {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=300'
      });
      res.end(result.data);
    } catch (err) {
      console.error(`[PROXY] FAILED: ${err.message}`);
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: 'All upstream endpoints failed',
        message: err.message,
        hint: 'The ransomware.live API may be rate-limiting or down. Try again in a few minutes.'
      }));
    }
    return;
  }

  // ── Cache Status Endpoint ──
  if (url.pathname === '/cache-status') {
    const entries = Object.entries(cache).map(([key, val]) => ({
      endpoint: key,
      age: Math.round((Date.now() - val.ts) / 1000) + 's',
      size: val.data.length + ' bytes'
    }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ cached: entries.length, entries }, null, 2));
    return;
  }

  // ── Static Files ──
  let filePath = url.pathname === '/' ? '/index.html' : url.pathname;
  filePath = path.join(__dirname, filePath);

  if (!filePath.startsWith(__dirname)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(err.code === 'ENOENT' ? 404 : 500);
      res.end(err.code === 'ENOENT' ? 'Not Found' : 'Server Error');
      return;
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════════╗');
  console.log('  ║         RANSOMBOARD — PROXY SERVER v2        ║');
  console.log('  ╠══════════════════════════════════════════════╣');
  console.log(`  ║  → http://localhost:${PORT}                      ║`);
  console.log('  ║  → Proxying ransomware.live API              ║');
  console.log('  ║  → 5-minute response cache enabled           ║');
  console.log('  ║  → Static data fallbacks enabled             ║');
  console.log('  ╚══════════════════════════════════════════════╝');
  console.log('');
});
