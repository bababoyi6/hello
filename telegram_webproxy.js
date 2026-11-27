// SPDX-License-Identifier: GPL-3.0-only
// Derived from ToiCF/CF-Workers-TGProxy, e565c57ff58656fd544755f67e1c266148c0b88f, with modifications through 2026-11-20.
const KiB = 1024;
const MiB = 1024 * KiB;
const WINDOW = 4 * MiB;
const DOWN_FRAME = 64 * KiB;
const CRYPT_CHUNK = 512 * KiB;
const SOCKET_BUFFER = 2 * MiB;
const MAX_MESSAGE = 2 * MiB;
const MAX_FRAME = MiB;
const MAX_PACKET = 8 * MiB + 4;
const PACK = 32 * KiB, BULK_PACK = 256 * KiB;
function packLimit(first) {
  // Merge ready media chunks of moderate size. Large chunks bypass the copy.
  return first >= 64 * KiB && first < 128 * KiB ? BULK_PACK : PACK;
}
const OPEN = 1, DATA = 2, CLOSE = 3, CREDIT = 4, WELCOME = 17;
const BOOTSTRAP = 1, SESSION = 2, RENEWAL = 3, PORTAL_SESSION = 4;
const BOOT_LIFETIME = 120, TICKET_LIFETIME = 300, GRANT_LIFETIME = 12 * 3600;
const FAST_TICKET_LIFETIME = 90, PORTAL_LIFETIME = 30 * 60;
const MAX_SID = 0xffffff;
const SESSION_EXPIRED_CLOSE = 4001;
const ADMIN_BODY_LIMIT = 1024;
const EMPTY = new Uint8Array(0);
const textEncoder = new TextEncoder();
const subtle = crypto.subtle;
const noStore = {
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-DNS-Prefetch-Control': 'off',
};
const permissions = 'autoplay=(), camera=(), microphone=(), geolocation=(), display-capture=(), payment=(), usb=(), hid=(), serial=()';

const unavailable = () => new Response(null, { status: 404, headers: noStore });
const overloaded = () => new Response(null, { status: 503, headers: { ...noStore, 'Retry-After': '1' } });
const now = () => Math.floor(Date.now() / 1000);
const random = n => crypto.getRandomValues(new Uint8Array(n));
const hexString = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const view = bytes => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
const hex = value => Uint8Array.from(value.match(/../g), pair => Number.parseInt(pair, 16));
const b64 = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
const binary = value => value instanceof ArrayBuffer ? new Uint8Array(value) : value;
const tokenPattern = /^[A-Za-z0-9_-]{43}$/;
// A canonical 32-byte base64url token has two zero padding bits.
const canonicalTokenPattern = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const accessCodePattern = /^[0-9a-f]{64}$/i;

function decodeToken(value) {
  if (typeof value !== 'string' || !canonicalTokenPattern.test(value)) return null;
  return Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='), c => c.charCodeAt(0));
}

function equalBytes(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  if (typeof subtle.timingSafeEqual === 'function') return subtle.timingSafeEqual(a, b);
  let mismatch = 0;
  for (let i = 0; i < a.byteLength; i++) mismatch |= a[i] ^ b[i];
  return mismatch === 0;
}

function append(a, b) {
  const bytes = new Uint8Array(a.byteLength + b.byteLength);
  bytes.set(a);
  bytes.set(b, a.byteLength);
  return bytes;
}

function canonicalHost(url) {
  const host = url.hostname;
  if (url.protocol !== 'https:' || url.port || host.length > 253) return null;
  if (!host.includes('.') || !/[a-z]/.test(host.split('.').at(-1))) return null;
  return host.split('.').every(s => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s)) ? host : null;
}

const importMAC = key => subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
const derivationSalt = textEncoder.encode('cf-tgproxy-portal-v1');
// The offline setup tool fills this value in the private Dashboard copy.
const dashboardSeed = '';
const configurations = new Map();
const MAX_CONFIGURATIONS = 8;
let storedSeed;

async function derivePasswordSeed(password, host) {
  const key = await subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
  return subtle.deriveBits({
    name: 'PBKDF2',
    hash: 'SHA-256',
    salt: textEncoder.encode('cf-tgproxy-dashboard-v1\0' + host),
    iterations: 16000,
  }, key, 256);
}

export class ProxySeedStore {
  constructor(state) {
    this.storage = state.storage;
  }

  fetch(request) {
    if (request.method !== 'GET' && request.method !== 'PUT') return unavailable();
    const storage = this.storage;
    const seed = request.method === 'PUT' ? storage.transactionSync(() => {
      const existing = storage.kv.get('seed');
      if (existing !== undefined) return existing;
      const generated = hexString(random(32));
      storage.kv.put('seed', generated);
      return generated;
    }) : storage.kv.get('seed');
    return seed === undefined ? unavailable() : new Response(seed, { headers: noStore });
  }
}

async function configuration(env, host, initialize = false, password = portalPassword(env)) {
  let seed = env.PROXY_SEED ?? env.PORTAL_KEY;
  const store = env.PROXY_STATE;
  if (seed === undefined && store) {
    const id = store.idFromName('deployment');
    const storageId = id.toString();
    seed = storedSeed?.id === storageId ? storedSeed.seed : undefined;
    if (seed === undefined) {
      const response = await store.get(id).fetch('https://seed.internal/', {
        method: initialize ? 'PUT' : 'GET',
      });
      if (!response.ok) return null;
      seed = await response.text();
      if (!accessCodePattern.test(seed)) return null;
      storedSeed = { id: storageId, seed };
    }
  }
  // Persisted and manually prepared seeds take precedence over password-only setup.
  seed ??= dashboardSeed || undefined;
  const fromPassword = seed === undefined;
  if (!fromPassword && (typeof seed !== 'string' || !accessCodePattern.test(seed))) return null;
  const source = fromPassword ? env.p : seed.toLowerCase();
  const cached = configurations.get(host);
  if (cached?.source === source && cached?.fromPassword === fromPassword) {
    configurations.delete(host);
    configurations.set(host, cached);
    return cached.result;
  }
  // Only pure WebCrypto work is shared. The legacy binding fetch above
  // stays in the invocation that owns the I/O.
  if (fromPassword && !password) return null;
  const result = deriveConfiguration(host, fromPassword ? password : null, source);
  const entry = { source, fromPassword, result };
  configurations.delete(host);
  configurations.set(host, entry);
  if (configurations.size > MAX_CONFIGURATIONS) configurations.delete(configurations.keys().next().value);
  try {
    return await result;
  } catch (error) {
    if (configurations.get(host) === entry) configurations.delete(host);
    throw error;
  }
}

async function deriveConfiguration(host, password, source) {
  const seed = password ? await derivePasswordSeed(password, host) : hex(source);
  const masterKey = await subtle.importKey('raw', seed, 'HKDF', false, ['deriveBits']);
  const derive = (purpose, length) => subtle.deriveBits({
    name: 'HKDF',
    hash: 'SHA-256',
    salt: derivationSalt,
    info: textEncoder.encode(purpose + '\0' + host),
  }, masterKey, length);
  const [proxyBits, carrierBits] = await Promise.all([
    derive('telegram-proxy', 128),
    derive('carrier-signing', 256),
  ]);
  const proxyKey = new Uint8Array(proxyBits);
  const [bridgeKey, carrierKey] = await Promise.all([importMAC(proxyKey), importMAC(carrierBits)]);
  return { secret: hexString(proxyKey), proxyKey, bridgeKey, carrierKey };
}

async function verifyBridge(bridgeKey, host, capability) {
  const signature = decodeToken(capability);
  if (!signature) return false;
  const context = textEncoder.encode('tdesktop-web-proxy-bridge-v1\n' + host);
  return subtle.verify('HMAC', bridgeKey, signature, context);
}

async function carrierMAC(cfg, host, purpose, body) {
  const context = textEncoder.encode('cf-tgproxy-token-v1\0' + purpose + '\0' + host + '\0');
  return new Uint8Array(await subtle.sign('HMAC', cfg.carrierKey, append(context, body))).subarray(0, 16);
}

async function issueToken(cfg, host, purpose, expires, id) {
  const bytes = new Uint8Array(32);
  view(bytes).setUint32(0, expires);
  bytes.set(id, 4);
  bytes.set(await carrierMAC(cfg, host, purpose, bytes.subarray(0, 16)), 16);
  return b64(bytes);
}

function decodeLiveToken(purpose, value, clock = now()) {
  const bytes = decodeToken(value);
  if (!bytes) return null;
  const expires = view(bytes).getUint32(0);
  const maxAge = purpose === BOOTSTRAP ? BOOT_LIFETIME :
    purpose === SESSION ? TICKET_LIFETIME + BOOT_LIFETIME : GRANT_LIFETIME + BOOT_LIFETIME;
  if (expires <= clock || expires > clock + maxAge) return null;
  return { bytes, expires };
}

async function authenticateToken(cfg, host, purpose, { bytes, expires }, clock = now()) {
  if (expires <= clock || !equalBytes(bytes.subarray(16), await carrierMAC(cfg, host, purpose, bytes.subarray(0, 16)))) {
    return null;
  }
  return { expires, id: bytes.subarray(4, 16) };
}

async function verifyToken(cfg, host, purpose, value, clock = now()) {
  const token = decodeLiveToken(purpose, value, clock);
  return token && authenticateToken(cfg, host, purpose, token, clock);
}

async function sessionTickets(cfg, host, expires, id) {
  return Promise.all([
    issueToken(cfg, host, SESSION, expires, id),
    issueToken(cfg, host, RENEWAL, view(id).getUint32(0), id),
  ]);
}

function writeFrame(bytes, header, offset, type, sid, payload) {
  header.setUint32(offset, type * 0x1000000 + sid);
  header.setUint32(offset + 4, payload.byteLength);
  bytes.set(payload, offset + 8);
}

function encodeFrame(type, sid, payload = EMPTY) {
  const bytes = new Uint8Array(8 + payload.byteLength);
  writeFrame(bytes, view(bytes), 0, type, sid, payload);
  return bytes;
}

function encodeDataBatch(sid, payload, size) {
  const bytes = new Uint8Array(size);
  const header = view(bytes);
  for (let start = 0, offset = 0; start < payload.length; start += DOWN_FRAME) {
    const part = payload.subarray(start, start + DOWN_FRAME);
    writeFrame(bytes, header, offset, DATA, sid, part);
    offset += part.length + 8;
  }
  return bytes;
}

function visitFrames(value, visit) {
  const bytes = binary(value);
  if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > MAX_MESSAGE) throw new LaneFault('frame');
  const header = view(bytes);
  let frames = 0;
  for (let offset = 0; offset < bytes.length;) {
    if (bytes.length - offset < 8 || ++frames > 4096) throw new LaneFault('frame');
    const id = header.getUint32(offset);
    const size = header.getUint32(offset + 4);
    const end = offset + 8 + size;
    if (size > MAX_FRAME || end > bytes.length) throw new LaneFault('frame');
    visit(id >>> 24, id & MAX_SID, bytes, offset + 8, end);
    offset = end;
  }
}

const helloFrame = Uint8Array.of(16, 0, 0, 0, 0, 0, 0, 1, 1);

async function readExactBody(request, expected) {
  const length = request.headers.get('Content-Length');
  if (length !== null && length !== String(expected.length)) return false;
  const body = await readBoundedBody(request, expected.length);
  return body !== null && equalBytes(body, expected);
}

async function readBoundedBody(request, limit) {
  if (!lengthAllowed(request.headers, limit)) return null;
  if (!request.body) return EMPTY;
  const reader = request.body.getReader();
  const body = new Uint8Array(limit);
  let offset = 0, timer;
  const deadline = new Promise(resolve => { timer = setTimeout(() => resolve(null), 2500); });
  try {
    for (;;) {
      const next = await Promise.race([reader.read(), deadline]);
      if (!next) return null;
      if (next.done) return body.subarray(0, offset);
      if (!next.value.byteLength || next.value.byteLength > body.length - offset) return null;
      body.set(next.value, offset);
      offset += next.value.byteLength;
    }
  } finally {
    clearTimeout(timer);
    // Reader cancellation can wait for the sender. It must not delay the response.
    void reader.cancel().catch(() => {});
  }
}

function lengthAllowed(headers, limit) {
  const length = headers.get('Content-Length');
  return length === null || (/^\d+$/.test(length) && Number(length) <= limit);
}

class LaneFault extends Error {
  constructor(kind) {
    super(kind);
    this.kind = kind;
  }
}

// Local admission and memory accounting. Entries never own sockets or other
// request-scoped I/O. Every isolate can independently verify a valid ticket.
const groups = new Map();
const counters = Object.create(null);
const timingBounds = [10, 25, 50, 100, 200, 400, 800, 1600, 3000, 6000];
const newHistogram = () => new Uint32Array(timingBounds.length + 1);
const timings = {
  bridgeConfig: newHistogram(), bridgePage: newHistogram(), client: newHistogram(), upgrade: newHistogram(),
  kws: newHistogram(), firstUpstream: newHistogram(), firstForwarded: newHistogram(),
  downCredit: newHistogram(), downSocket: newHistogram(),
};
const upstreamStats = Array.from({ length: 10 }, () => ({
  connected: 0, failed: 0, cancelled: 0, retries: 0, timeout: 0, network: 0, http: 0, protocol: 0,
  timing: newHistogram(),
}));
const dcIndex = ({ dc, media }) => (dc - 1) * 2 + Number(media);
let upstreamBytes = 0, forwardedBytes = 0;
let activeLanes = 0, queuedBytes = 0, peakQueuedBytes = 0, recordedIds = 0, nextSweep = 0;

function getGroup(key, expires) {
  const time = now();
  if (time >= nextSweep) {
    nextSweep = time + 30;
    for (const [id, group] of groups) {
      if (group.expires <= time && !group.active) {
        recordedIds -= group.used.size;
        groups.delete(id);
      }
    }
  }
  let group = groups.get(key);
  if (!group && groups.size < 256) {
    group = { expires, active: 0, used: new Set(), bytes: 0, deleted: false };
    groups.set(key, group);
  }
  if (group) group.expires = Math.max(group.expires, expires);
  return group;
}

function laneBudget(group) {
  let total = 0;
  return {
    hold(size) {
      if (size > 32 * MiB - total || size > 36 * MiB - group.bytes ||
          size > 40 * MiB - queuedBytes) throw new LaneFault('queue');
      total += size;
      group.bytes += size;
      queuedBytes += size;
      if (queuedBytes > peakQueuedBytes) peakQueuedBytes = queuedBytes;
    },
    release(size) {
      total -= size;
      group.bytes -= size;
      queuedBytes -= size;
    },
  };
}

function increment(object, name) {
  object[name] = Math.min((object[name] ?? 0) + 1, 0x7fffffff);
}

function count(kind) {
  if (kind !== 'normal') increment(counters, kind);
}

function clientRtt(request) {
  return request.cf?.clientQuicRtt ?? request.cf?.clientTcpRtt;
}

function observeTiming(histogram, milliseconds) {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return;
  let bucket = 0;
  while (bucket < timingBounds.length && milliseconds > timingBounds[bucket]) bucket++;
  if (histogram[bucket] < 0x7fffffff) histogram[bucket]++;
}

function timingSummary(histogram) {
  const samples = histogram.reduce((sum, count) => sum + count, 0);
  if (!samples) return '暂无样本';
  const target = Math.ceil(samples * 0.95);
  let seen = 0, bucket = 0;
  while ((seen += histogram[bucket]) < target) bucket++;
  const bound = bucket < timingBounds.length ? '≤ ' + timingBounds[bucket] : '> ' + timingBounds.at(-1);
  return samples + ' 次，P95 ' + bound + ' ms';
}

function createWorker(dial = dialKWS, directTCP = false) {
  return {
    async fetch(request, env) {
      try {
        return await route(request, env, dial, directTCP);
      } catch {
        count('request');
        return unavailable();
      }
    },
  };
}

export default createWorker();


function sessionID(bootstrap) {
  const id = random(12);
  view(id).setUint32(0, bootstrap + GRANT_LIFETIME);
  return id;
}

const bearer = request => /^Bearer ([A-Za-z0-9_-]{43})$/.exec(request.headers.get('Authorization') ?? '')?.[1];
const groupKey = (host, id) => host + '/' + b64(id);
const portalCookie = '__Secure-site_session';
const adminPath = '/admin';
const logoutPath = adminPath + '/logout';
const loginAttempts = new Map();
let loginWindow = -1, loginTotal = 0;

function portalPassword(env) {
  const value = env.p;
  if (typeof value !== 'string' || value.length < 16 || value.length > 256) return null;
  const bytes = textEncoder.encode(value);
  return bytes.length <= 256 ? bytes : null;
}

function allowLogin(request, host) {
  const window = Math.floor(now() / 60);
  if (loginWindow !== window) {
    loginWindow = window;
    loginTotal = 0;
    loginAttempts.clear();
  }
  const key = host + '/' + (request.headers.get('CF-Connecting-IP') ?? '').slice(0, 64);
  const attempts = loginAttempts.get(key) ?? 0;
  if (attempts >= 8 || loginTotal >= 120) return false;
  loginAttempts.set(key, attempts + 1);
  loginTotal++;
  return true;
}

function portalRedirect(location, token = '', age = 0) {
  return new Response(null, { status: 303, headers: {
    ...noStore, Location: location,
    'Set-Cookie': portalCookie + '=' + token + '; Max-Age=' + age + '; Path=' + adminPath + '; Secure; HttpOnly; SameSite=Strict',
  } });
}

const passwordDigest = async bytes => new Uint8Array(await subtle.digest('SHA-256', bytes));

async function portalSessionMAC(cfg, host, password, body) {
  return carrierMAC(cfg, host, PORTAL_SESSION, append(await passwordDigest(password), body));
}

async function routePortal(request, env, url, host, password) {
  const { pathname, search } = url;
  const { method, headers } = request;
  const read = method === 'GET' || method === 'HEAD';
  if (pathname === logoutPath && !search && method === 'POST' && headers.get('Origin') === url.origin) {
    return portalRedirect('/');
  }
  if (pathname !== adminPath) return unavailable();
  if (method === 'POST' && !search) {
    if (headers.get('Origin') !== url.origin ||
        headers.get('Content-Type')?.split(';', 1)[0] !== 'application/x-www-form-urlencoded' ||
        !lengthAllowed(headers, ADMIN_BODY_LIMIT)) return unavailable();
    if (!allowLogin(request, host)) return loginResponse(method, '尝试次数过多，请稍后再试。', 429);
    const body = await readBoundedBody(request, ADMIN_BODY_LIMIT);
    const submitted = body && new URLSearchParams(new TextDecoder().decode(body)).getAll('password');
    const value = submitted?.length === 1 && textEncoder.encode(submitted[0]);
    if (!value || value.length > 256 ||
        !equalBytes(await passwordDigest(value), await passwordDigest(password))) {
      return loginResponse(method, '密码有误，请重试。', 401);
    }
    const cfg = await configuration(env, host, true, password).catch(() => {
      count('configuration-error');
      return null;
    });
    if (!cfg) return loginResponse(method, '页面暂时不可用。', 503);
    const token = random(32);
    view(token).setUint32(0, now() + PORTAL_LIFETIME);
    token.set(await portalSessionMAC(cfg, host, password, token.subarray(0, 16)), 16);
    return portalRedirect(adminPath, b64(token), PORTAL_LIFETIME);
  }
  const probe = search === '?probe=1' && method === 'HEAD';
  if (!read || (search && search !== '?diagnostics=1' && !probe)) return unavailable();
  const cookies = (headers.get('Cookie') ?? '').split(';').map(value => value.trim())
    .filter(value => value.startsWith(portalCookie + '='));
  const token = cookies.length === 1 && decodeToken(cookies[0].slice(portalCookie.length + 1));
  const expiry = token ? view(token).getUint32(0) : 0;
  const clock = now();
  if (expiry <= clock || expiry > clock + PORTAL_LIFETIME + 5) return probe ? unavailable() : loginResponse(method);
  const cfg = await configuration(env, host, false, password);
  if (!cfg || !equalBytes(token.subarray(16), await portalSessionMAC(cfg, host, password, token.subarray(0, 16))) || expiry <= now()) {
    return probe ? unavailable() : loginResponse(method);
  }
  if (probe) return new Response(null, { status: 204, headers: noStore });
  return portalResponse(host, cfg.secret, request, Boolean(search));
}

async function route(request, env, dial, directTCP) {
  const url = new URL(request.url);
  const host = canonicalHost(url);
  if (!host) return unavailable();
  const { method, headers } = request;
  const path = url.pathname;
  if (path === '/' && !url.search && (method === 'GET' || method === 'HEAD')) {
    return publicHomeResponse(method);
  }
  if (path === adminPath || path === logoutPath) {
    const password = portalPassword(env);
    return password ? routePortal(request, env, url, host, password) : unavailable();
  }
  const sameOrigin = !headers.has('Origin') || headers.get('Origin') === url.origin;
  const capability = method === 'GET' && path === '/' && /^\?bridge=([A-Za-z0-9_-]{43})$/.exec(url.search)?.[1];
  const api = !url.search && sameOrigin;
  const session = api && path === '/api/v1/session' && (method === 'POST' || method === 'DELETE');
  const renewal = api && path === '/api/v1/session/renew' && method === 'POST';
  const upgrade = api && path === '/api/v1/ws' && method === 'GET' &&
    headers.get('Upgrade')?.toLowerCase() === 'websocket' && parseLaneProtocol(headers);
  if (renewal || (session && method === 'POST')) {
    const length = headers.get('Content-Length');
    if (length !== null && length !== String(renewal ? 0 : helloFrame.length)) return unavailable();
    if (session && headers.get('Content-Type')?.trim().toLowerCase() !== 'application/octet-stream') return unavailable();
  }
  const token = (session || renewal) && !headers.has('Cookie') ? bearer(request) : null;
  const purpose = upgrade || method === 'DELETE' ? SESSION : renewal ? RENEWAL : BOOTSTRAP;
  const claims = decodeLiveToken(purpose, upgrade ? upgrade.token : token);
  if (!((capability && canonicalTokenPattern.test(capability)) || claims)) return unavailable();
  const password = portalPassword(env);
  if (!password) return unavailable();

  const started = upgrade || capability ? Date.now() : 0;
  const cfg = await configuration(env, host, false, password);
  if (!cfg) return unavailable();

  if (capability) {
    const configured = Date.now();
    if (!(await verifyBridge(cfg.bridgeKey, host, capability))) return unavailable();
    // The verified Bridge request already authenticates the client. It can
    // carry the first ticket while the bridge validates HELLO locally.
    const issued = now();
    const expires = issued + BOOT_LIFETIME;
    const id = sessionID(expires);
    const fastExpiry = issued + FAST_TICKET_LIFETIME;
    const [boot, [ticket, grant]] = await Promise.all([
      issueToken(cfg, host, BOOTSTRAP, expires, id),
      sessionTickets(cfg, host, fastExpiry, id),
    ]);
    const response = bridgeResponse(host, boot, { ticket, grant, ttl: fastExpiry - now() });
    observeTiming(timings.bridgeConfig, configured - started);
    observeTiming(timings.bridgePage, Date.now() - started);
    return response;
  }
  const auth = await authenticateToken(cfg, host, purpose, claims);
  if (!auth || now() >= auth.expires) return unavailable();
  if (upgrade) return upgradeLane(request, cfg, host, upgrade, auth, started, dial, directTCP);
  const deadline = view(auth.id).getUint32(0);
  const key = groupKey(host, auth.id);
  if (method === 'DELETE') {
    const group = getGroup(key, deadline);
    if (!group) return overloaded();
    group.deleted = true;
    return new Response(null, { status: 204, headers: noStore });
  }
  if (groups.get(key)?.deleted) return unavailable();
  if (renewal) {
    if (!(await readExactBody(request, EMPTY)) || now() >= auth.expires || groups.get(key)?.deleted) return unavailable();
    const expires = Math.min(now() + TICKET_LIFETIME, auth.expires);
    const ticket = await issueToken(cfg, host, SESSION, expires, auth.id);
    const ttl = expires - now();
    if (ttl <= 0 || groups.get(key)?.deleted) return unavailable();
    return new Response(null, { status: 204, headers: {
      ...noStore, 'X-Session-Token': ticket, 'X-Session-TTL': String(ttl),
    } });
  }
  if (!(await readExactBody(request, helloFrame)) || now() >= auth.expires || groups.get(key)?.deleted) return unavailable();
  // Byte-identical creation retries get the same tickets in every isolate.
  const expires = auth.expires - BOOT_LIFETIME + TICKET_LIFETIME;
  const [ticket, refresh] = await sessionTickets(cfg, host, expires, auth.id);
  const issued = now();
  if (issued >= auth.expires || groups.get(key)?.deleted) return unavailable();
  return new Response(encodeFrame(WELCOME, 0), {
    headers: {
      ...noStore, 'Content-Type': 'application/octet-stream',
      'X-Carrier-Mode': 'websocket-lanes', 'X-Down-Cursor': '0',
      'X-Session-Token': ticket, 'X-Session-TTL': String(expires - issued), 'X-Session-Renewal': refresh,
    },
  });
}

function parseLaneProtocol(headers) {
  const version = headers.get('Sec-WebSocket-Version');
  if (version !== null && version !== '13') return null;
  const protocol = headers.get('Sec-WebSocket-Protocol');
  const match = /^tproxy-lane-v1\.([A-Za-z0-9_-]{43})\.([1-9][0-9]{0,7})$/.exec(protocol ?? '');
  if (!match || Number(match[2]) > MAX_SID) return null;
  return { protocol, token: match[1], sid: Number(match[2]) };
}

function upgradeLane(request, cfg, host, { protocol, sid }, auth, started, dial, directTCP) {
  const group = getGroup(groupKey(host, auth.id), view(auth.id).getUint32(0));
  if (group?.deleted || group?.used.has(sid)) return unavailable();
  if (!group || group.used.size >= 4096 || group.active >= 64 ||
      activeLanes >= 128 || recordedIds >= 16384) return overloaded();

  const [client, server] = Object.values(new WebSocketPair());
  group.active++;
  group.used.add(sid);
  activeLanes++;
  recordedIds++;
  const release = () => { group.active--; activeLanes--; };
  let lane;
  try {
    lane = new Lane(server, sid, cfg.proxyKey, group, dial, { release, directTCP });
    lane.attach();
    const response = new Response(null, { status: 101, webSocket: client, headers: {
      ...noStore, 'Sec-WebSocket-Protocol': protocol, 'Sec-WebSocket-Extensions': '',
    } });
    observeTiming(timings.client, clientRtt(request));
    observeTiming(timings.upgrade, Date.now() - started);
    return response;
  } catch {
    if (lane) lane.stop('attach', false);
    else {
      release();
      releaseSocket(server);
    }
    group.used.delete(sid);
    recordedIds--;
    return unavailable();
  }
}

// Counters are big-endian, including carries through the highest bytes.
function advanceCounter(counter, blocks) {
  for (let i = counter.length - 1; i >= 0 && blocks; i--) {
    const sum = counter[i] + (blocks & 255);
    counter[i] = sum;
    blocks = Math.floor(blocks / 256) + (sum >>> 8);
  }
  return blocks !== 0;
}

function createCTR(rawKey, counter) {
  const key = subtle.importKey('raw', rawKey, 'AES-CTR', false, ['encrypt']);
  // A lane can close before using every key. The first use still sees a failed import.
  void key.catch(() => {});
  const iv = new Uint8Array(counter);
  const start = new Uint8Array(16);
  const tail = new Uint8Array(16);
  let remaining = 0, busy = false, exhausted = false;

  return async function crypt(value, reusePadding = false) {
    if (busy) throw new Error('concurrent CTR use');
    const bytes = binary(value);
    if (!bytes.byteLength) return EMPTY;
    if (bytes.length <= remaining) {
      const out = new Uint8Array(bytes.length);
      for (let i = 0; i < out.length; i++) out[i] = bytes[i] ^ tail[16 - remaining + i];
      remaining -= out.length;
      return out;
    }
    if (exhausted) throw new Error('CTR exhausted');
    busy = true;
    try {
      const skip = remaining ? 16 - remaining : 0;
      const end = skip + bytes.length;
      const padded = Math.ceil(end / 16) * 16;
      const blocks = (padded >>> 4) - (skip ? 1 : 0);
      start.set(iv);
      // Reject a range that would wrap before its last block.
      if (advanceCounter(start, blocks - 1)) throw new Error('CTR exhausted');
      start.set(iv);
      if (skip) {
        for (let i = 15; i >= 0; i--) if (start[i]--) break;
      }
      let input = bytes;
      if (padded !== bytes.length) {
        if (reusePadding && bytes.byteOffset === skip && bytes.buffer.byteLength === padded) {
          // Only the downlink's freshly decrypted output takes this path.
          // Its payload is already aligned for the second cipher. Bytes
          // beyond the view are scratch, and the tail must start at zero.
          input = new Uint8Array(bytes.buffer);
          input.fill(0, 0, skip);
          input.fill(0, end);
        } else {
          input = new Uint8Array(padded);
          input.set(bytes, skip);
        }
      }
      const result = new Uint8Array(await subtle.encrypt(
        { name: 'AES-CTR', counter: start, length: 128 }, await key, input,
      ));
      exhausted = advanceCounter(iv, blocks);
      remaining = padded - end;
      if (remaining) tail.set(result.subarray(end), 16 - remaining);
      return skip || remaining ? result.subarray(skip, end) : result;
    } finally {
      busy = false;
    }
  };
}

async function obfuscationCipher(head, secret, reverse = false) {
  const bytes = reverse ? head.slice(8, 56).reverse() : head.subarray(8, 56);
  const raw = bytes.subarray(0, 32);
  const key = secret.length ? await subtle.digest('SHA-256', append(raw, secret)) : raw;
  return createCTR(key, bytes.subarray(32));
}

function readHead(head) {
  const tag = view(head).getUint32(56, true);
  const mode = tag === 0xefefefef ? 0xef : tag === 0xeeeeeeee ? 0xee : tag === 0xdddddddd ? 0xdd : 0;
  const dc = view(head).getInt16(60, true);
  if (!mode || Math.abs(dc) < 1 || Math.abs(dc) > 5) throw new LaneFault('obfuscation');
  return { mode, dc: Math.abs(dc), media: dc < 0 };
}

function makeHead({ mode, dc, media }, directTCP = false) {
  const head = new Uint8Array(64);
  const header = view(head);
  const forbidden = [0x48454144, 0x504f5354, 0x47455420, 0x4f505449, 0xeeeeeeee, 0xdddddddd, 0x16030102];
  do {
    crypto.getRandomValues(head);
  } while (head[0] === 0xef || forbidden.includes(header.getUint32(0)) || !header.getUint32(4));
  head.fill(mode, 56, 60);
  if (!directTCP) header.setInt16(60, media ? -dc : dc, true);
  return head;
}

function packetSize(bytes, offset, mode) {
  const available = bytes.length - offset;
  let header, payload;
  if (mode === 0xef) {
    const words = bytes[offset] & 127;
    if (words === 127 && available < 4) return 0;
    header = words === 127 ? 4 : 1;
    payload = header === 1 ? words * 4 :
      (bytes[offset + 1] | (bytes[offset + 2] << 8) | (bytes[offset + 3] << 16)) * 4;
  } else {
    if (available < 4) return 0;
    header = 4;
    payload = (bytes[offset] | (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) & 0x7fffffff;
  }
  if (!payload || header + payload > MAX_PACKET) throw new LaneFault('packet');
  return header + payload;
}

class PacketAssembly {
  prefix = new Uint8Array(4);
  size = 0;
  length = 0;
  packet = null;
  filled = 0;

  constructor(mode, budget) {
    this.mode = mode;
    this.budget = budget;
  }

  get pending() { return this.length > 0 || this.size > 0; }

  add(bytes, offset) {
    if (!this.length) {
      const width = this.mode === 0xef && ((this.size ? this.prefix[0] : bytes[offset]) & 127) !== 127 ? 1 : 4;
      const take = Math.min(width - this.size, bytes.length - offset);
      this.prefix.set(bytes.subarray(offset, offset + take), this.size);
      this.size += take;
      offset += take;
      if (this.size < width) return { offset, packet: null };
      this.length = packetSize(this.prefix, 0, this.mode);
      this.filled = width;
      this.size = 0;
    }
    const take = Math.min(this.length - this.filled, bytes.length - offset);
    const required = this.filled + take;
    const previous = this.packet?.length ?? 0;
    if (required > previous) {
      // Grow with received bytes, so a four-byte length cannot reserve an
      // entire maximum-size packet. Charge both buffers during a resize.
      const capacity = Math.min(this.length, Math.max(required, 64 * KiB, 2 * previous));
      this.budget.hold(capacity);
      try {
        const next = new Uint8Array(capacity);
        next.set(this.packet ? this.packet.subarray(0, this.filled) : this.prefix.subarray(0, this.filled));
        this.packet = next;
      } catch (error) {
        this.budget.release(capacity);
        throw error;
      }
      if (previous) this.budget.release(previous);
    }
    this.packet.set(bytes.subarray(offset, offset + take), this.filled);
    this.filled += take;
    offset += take;
    if (this.filled < this.length) return { offset, packet: null };
    const packet = this.packet;
    this.packet = null;
    this.length = 0;
    return { offset, packet };
  }

  clear() {
    if (this.packet) this.budget.release(this.packet.length);
    this.packet = null;
    this.size = this.length = 0;
  }
}


class Queue {
  items = [];
  head = 0;
  bytes = 0;

  get length() { return this.items.length - this.head; }
  prefixBytes(limit) {
    let bytes = 0;
    for (let index = this.head; index < this.items.length; index++) {
      const size = this.items[index].data.length;
      if (bytes + size > limit) break;
      bytes += size;
    }
    return bytes;
  }

  add(item) {
    this.items.push(item);
    this.bytes += item.data.length;
  }

  take() {
    const item = this.items[this.head];
    this.items[this.head++] = null;
    this.bytes -= item.data.length;
    if (this.head === this.items.length) {
      this.items.length = this.head = 0;
    } else if (this.head >= 256 && 2 * this.head >= this.items.length) {
      this.items.splice(0, this.head);
      this.head = 0;
    }
    return item;
  }

  clear(release) {
    while (this.length) release(this.take());
  }
}

const kwsHosts = ({ dc, media }) => [
  'kws' + dc + (media ? '-1' : '') + '.web.telegram.org',
  'kws' + dc + (media ? '' : '-1') + '.web.telegram.org',
];

function safeClose(socket, code = 1000) {
  try { socket?.close(code); } catch {}
}

function releaseSocket(socket) {
  try { socket.accept(); } catch {}
  safeClose(socket);
}

function releaseUpgrade(response) {
  if (response.webSocket) releaseSocket(response.webSocket);
  else void response.body?.cancel().catch(() => {});
}

const MAX_PARALLEL_BACKUPS = 8;
let parallelBackups = 0;

// Each route keeps state for its two official endpoints only. A new isolate
// starts with the protocol's original control/media preference.
class UpstreamRouter {
  paths = Array.from({ length: 10 }, () => Array.from({ length: 2 }, () => ({
    failures: 0, lastFailure: 0, retryAt: 0, serial: 0, latestSuccess: 0,
  })));

  constructor(clock = Date.now) {
    this.clock = clock;
  }

  path(info, candidate) {
    return this.paths[dcIndex(info)][candidate];
  }

  plan(info) {
    const primary = this.path(info, 0).retryAt;
    const alternate = this.path(info, 1).retryAt;
    return primary > this.clock() && primary > alternate ? [1, 0] : [0, 1];
  }

  canHedge(info, candidate) {
    return this.path(info, candidate).retryAt <= this.clock();
  }

  start(info, candidate) {
    const path = this.path(info, candidate);
    const generation = ++path.serial;
    const time = this.clock();
    if (path.retryAt && path.retryAt <= time) path.retryAt = time + 5000;
    return success => {
      const completed = this.clock();
      if (success) {
        path.latestSuccess = Math.max(path.latestSuccess, generation);
        path.failures = path.retryAt = 0;
      } else if (generation > path.latestSuccess) {
        path.failures = completed - path.lastFailure <= 30000 ? path.failures + 1 : 1;
        path.lastFailure = completed;
        if (path.failures >= 2) path.retryAt = completed + 15000;
      }
    };
  }
}

const kwsRouter = new UpstreamRouter();

function dialKWS(info, signal) {
  return connectKWS(info, signal, fetch, 3000, 900, kwsRouter);
}

async function attemptKWS(host, attempt, fetcher, timeout, record) {
  const signal = attempt.signal;
  if (signal.aborted) return null;
  let wake;
  const stopped = new Promise(resolve => { wake = () => resolve(null); });
  signal.addEventListener('abort', wake, { once: true });
  const timer = setTimeout(() => {
    record('timeout');
    attempt.abort();
  }, timeout);
  try {
    const response = await Promise.race([stopped, fetcher('https://' + host + '/apiws', {
      headers: { Upgrade: 'websocket', 'Sec-WebSocket-Protocol': 'binary' },
      redirect: 'manual',
      signal,
    }).then(result => {
      if (!signal.aborted) return result;
      releaseUpgrade(result);
      return null;
    })]);
    if (!response) return null;
    if (signal.aborted || response.status !== 101 || !response.webSocket ||
        response.headers.get('Sec-WebSocket-Protocol') !== 'binary') {
      if (!signal.aborted) {
        record(response.status === 101 ? 'protocol' : 'http');
      }
      releaseUpgrade(response);
      return null;
    }
    record(null);
    return response.webSocket;
  } catch {
    if (!signal.aborted) record('network');
    return null;
  } finally {
    clearTimeout(timer);
    signal.removeEventListener('abort', wake);
  }
}

async function connectKWS(info, signal, fetcher = fetch, timeout = 3000, backupDelay = 900, router) {
  if (!Number.isInteger(info.dc) || info.dc < 1 || info.dc > 5 || typeof info.media !== 'boolean') {
    throw new LaneFault('obfuscation');
  }
  if (signal.aborted) throw new LaneFault('kws-connect');

  const hosts = kwsHosts(info);
  const stats = upstreamStats[dcIndex(info)];
  const order = router?.plan(info) ?? [0, 1];
  if (order[0] === 1) count('kws-cooldown-bypass');
  const attempts = [];
  const started = Date.now();

  return new Promise((resolve, reject) => {
    let done = false, pending = 0, backupStarted = false, parallel = false;
    const timer = setTimeout(() => {
      if (done || backupStarted || parallelBackups >= MAX_PARALLEL_BACKUPS) return;
      if (router && !router.canHedge(info, order[1])) return;
      parallel = true;
      parallelBackups++;
      count('kws-parallel-backup');
      startBackup();
    }, backupDelay);

    const abort = () => finish(-1, null);
    signal.addEventListener('abort', abort, { once: true });
    start(0);

    function finish(winner, socket) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal.removeEventListener('abort', abort);
      if (parallel) parallelBackups--;
      for (const [i, attempt] of attempts.entries()) {
        if (i !== winner) attempt.abort();
      }
      if (!socket) {
        increment(stats, signal.aborted ? 'cancelled' : 'failed');
        reject(new LaneFault('kws-connect'));
        return;
      }
      if (winner === 1) count('kws-backup-won');
      increment(stats, 'connected');
      const elapsed = Date.now() - started;
      observeTiming(timings.kws, elapsed);
      observeTiming(stats.timing, elapsed);
      resolve(socket);
    }

    function startBackup() {
      backupStarted = true;
      clearTimeout(timer);
      count('kws-retry');
      increment(stats, 'retries');
      start(1);
    }

    function start(index) {
      pending++;
      const attempt = new AbortController();
      attempts[index] = attempt;
      const candidate = order[index];
      const record = router?.start(info, candidate);
      void attemptKWS(hosts[candidate], attempt, fetcher, timeout, reason => {
        if (reason) {
          count('kws-handshake-' + reason);
          increment(stats, reason);
        }
        record?.(!reason);
      }).then(socket => {
        pending--;
        if (done) {
          if (socket) releaseSocket(socket);
          return;
        }
        if (socket) {
          finish(index, socket);
        } else if (!backupStarted) {
          startBackup();
        } else if (!pending) {
          finish(-1, null);
        }
      });
    }
  });
}

function pause(ms, signal) {
  if (signal.aborted) return Promise.resolve();
  return new Promise(resolve => {
    const timer = setTimeout(done, ms);
    signal.addEventListener('abort', done, { once: true });
    function done() {
      clearTimeout(timer);
      signal.removeEventListener('abort', done);
      resolve();
    }
  });
}

function nativeBufferedAmount(socket) {
  try {
    const amount = socket?.bufferedAmount;
    return Number.isSafeInteger(amount) && amount >= 0 ? amount : undefined;
  } catch {
    return undefined;
  }
}

function congested(socket, length) {
  return (nativeBufferedAmount(socket) ?? 0) > SOCKET_BUFFER - Math.min(length, SOCKET_BUFFER);
}

class Lane {
  phase = 'waiting';
  up = new Queue();
  down = new Queue();
  controller = new AbortController();
  upItems = 0;
  receiving = WINDOW;
  sending = WINDOW;
  head = new Uint8Array(64);
  headSize = 0;
  peer = null;
  peerEnded = false;
  packets = null;
  upBusy = false;
  downBusy = false;
  creditWake = null;
  openTimer = null;
  expiryTimer = null;
  packetTimer = null;
  nativeTimer = null;
  peerDrainTimer = null;
  nativeBytes = [0, 0];

  constructor(socket, sid, secret, group, dial = connectKWS, options = {}) {
    this.socket = socket;
    this.sid = sid;
    this.secret = secret;
    this.group = group;
    this.dial = dial;
    this.directTCP = options.directTCP === true;
    this.budget = laneBudget(group);
    this.release = options.release ?? (() => { group.active--; });
    this.openMs = options.openMs ?? 12000;
    this.stallMs = options.stallMs ?? 30000;
    this.expiresAt = group.expires === undefined ? Infinity : group.expires * 1000;
    this.openedAt = Date.now();
    this.firstUpstream = false;
    this.firstForwarded = false;
    this.onMessage = event => this.receive(event.data);
    this.onClose = () => this.stop('normal', false);
    this.onError = () => this.stop('client-socket', false);
    this.onDown = event => { void this.enqueueDown(event.data); };
    this.onPeerClose = event => this.closeFromPeer(event.code);
    this.onPeerError = () => this.stop('kws-socket');
  }

  attach() {
    const socket = this.socket;
    socket.binaryType = 'arraybuffer';
    socket.addEventListener('message', this.onMessage);
    socket.addEventListener('close', this.onClose);
    socket.addEventListener('error', this.onError);
    socket.accept();
    this.openTimer = setTimeout(() => this.stop('stream-timeout'), this.openMs);
    if (this.expiresAt !== Infinity) {
      this.expiryTimer = setTimeout(() => this.stop('session-expired'), Math.max(0, this.expiresAt - Date.now()));
    }
  }

  get ended() { return this.phase === 'closed'; }

  assertLive() {
    if (this.ended) throw new LaneFault('normal');
    if (this.group.deleted) throw new LaneFault('revoked');
    if (this.expiresAt !== Infinity && Date.now() >= this.expiresAt) throw new LaneFault('session-expired');
  }

  assertSocket(socket) {
    this.assertLive();
    if (socket?.readyState !== 1) throw new LaneFault(socket === this.socket ? 'client-socket' : 'kws-socket');
  }

  fault(error) {
    const kind = error instanceof LaneFault ? error.kind : 'internal';
    // A concurrent upload can encounter the closed peer while its final
    // downlink bytes are still being forwarded.
    if (kind !== 'kws-socket' || !this.peerEnded) this.stop(kind);
  }

  closeFromPeer(code) {
    if (this.ended || this.peerEnded) return;
    if (code !== 1000 || !this.downBusy) {
      this.stop('kws-close');
      return;
    }
    this.peerEnded = true;
    this.peerDrainTimer = setTimeout(() => this.stop('kws-close'), this.stallMs);
  }

  receive(value) {
    if (this.ended) return;
    let retention;
    try {
      this.assertLive();
      visitFrames(value, (type, id, bytes, start, end) => {
        if (this.ended) return;
        if (id !== this.sid) throw new LaneFault('frame');
        const length = end - start;
        if (type === OPEN && !length && this.phase === 'waiting') {
          this.phase = 'header';
        } else if (this.phase === 'waiting') {
          throw new LaneFault('frame');
        } else if (type === DATA && length) {
          if (this.peerEnded) return;
          if (length > this.receiving || this.upItems >= 1024) throw new LaneFault('queue');
          const first = !retention;
          this.budget.hold(256 + (first ? bytes.length : 0));
          retention ??= { size: bytes.length, refs: 0 };
          retention.refs++;
          this.receiving -= length;
          this.upItems++;
          this.up.add({ data: bytes.subarray(start, end), retention });
        } else if (type === CREDIT && length === 4) {
          const delta = view(bytes).getUint32(start);
          if (!delta) throw new LaneFault('frame');
          this.sending = Math.min(WINDOW, this.sending + delta);
          this.creditWake?.();
        } else if (type === CLOSE && !length) {
          this.stop('normal', false);
        } else {
          throw new LaneFault('frame');
        }
      });
      if (!this.upBusy && !this.ended && !this.peerEnded && this.up.length) void this.pumpUp();
    } catch (error) {
      this.fault(error);
    }
  }

  releaseUp(item) {
    const { retention } = item;
    this.upItems--;
    this.budget.release(256 + (--retention.refs ? 0 : retention.size));
  }

  releaseDown(item) {
    this.budget.release(item.data.length + 256);
  }

  async drain(socket, length) {
    const deadline = Date.now() + this.stallMs;
    const threshold = SOCKET_BUFFER - Math.min(length, SOCKET_BUFFER);
    let delay = 8, previous = Infinity;
    for (let amount; (amount = nativeBufferedAmount(socket) ?? 0) > threshold;) {
      this.assertSocket(socket);
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new LaneFault('socket-backpressure');
      delay = amount < previous ? 8 : Math.min(delay * 2, 32);
      previous = amount;
      await pause(Math.min(delay, remaining), this.controller.signal);
    }
    this.assertSocket(socket);
  }

  async startStream() {
    const header = this.head;
    const clientRead = await obfuscationCipher(header, this.secret);
    const info = readHead(await clientRead(header));
    this.assertLive();
    const head = makeHead(info, this.directTCP);
    const dialing = Promise.resolve(this.dial(info, this.controller.signal));
    let peer, prepared;
    const prepare = Promise.all([
      obfuscationCipher(header, this.secret, true),
      obfuscationCipher(head, EMPTY),
      obfuscationCipher(head, EMPTY, true),
    ]).then(async ([clientWrite, peerWrite, peerRead]) => {
      const wire = await peerWrite(head);
      wire.set(head.subarray(0, 56));
      return { clientWrite, peerWrite, peerRead, wire };
    });
    try {
      [prepared, peer] = await Promise.all([prepare, dialing]);
      this.assertLive();
    } catch (error) {
      this.controller.abort();
      void dialing.then(releaseSocket, () => {});
      throw error;
    }
    const { clientWrite, peerWrite, peerRead, wire } = prepared;
    this.peer = peer;
    this.clientRead = clientRead;
    this.clientWrite = clientWrite;
    this.peerRead = peerRead;
    this.peerWrite = peerWrite;
    this.packets = new PacketAssembly(info.mode, this.budget);
    this.head = null;
    if (this.directTCP) {
      await this.writeTCP(peer, wire);
    } else {
      peer.binaryType = 'arraybuffer';
      peer.addEventListener('message', this.onDown);
      peer.addEventListener('close', this.onPeerClose);
      peer.addEventListener('error', this.onPeerError);
      peer.accept();
      this.assertSocket(peer);
      this.writeNative(peer, wire);
    }
    this.phase = 'streaming';
    clearTimeout(this.openTimer);
    if (this.directTCP) void this.readTCP(peer);
  }

  async writeTCP(peer, bytes) {
    this.assertLive();
    const timer = setTimeout(() => this.stop('tcp-write-timeout'), this.stallMs);
    try {
      await peer.write(bytes);
      this.assertLive();
    } catch {
      throw new LaneFault('tcp-write');
    } finally {
      clearTimeout(timer);
    }
  }

  async readTCP(peer) {
    let readSize = DOWN_FRAME;
    try {
      while (!this.ended) {
        if (!this.sending) await this.waitForCredit();
        if (congested(this.socket, Math.min(DOWN_FRAME, this.sending) + 8)) {
          await this.drain(this.socket, Math.min(DOWN_FRAME, this.sending) + 8);
        }
        // A BYOB read can neither exceed credit nor allocate an unbounded chunk.
        const size = Math.min(this.sending, readSize);
        this.budget.hold(size);
        try {
          const { done, value } = await peer.read(size);
          this.assertLive();
          if (done) {
            this.stop('tcp-close');
            return;
          }
          // Increase capacity only when the reader uses the entire buffer.
          if (size === readSize) {
            readSize = value.byteLength === size ? Math.min(CRYPT_CHUNK, size * 2) : Math.max(DOWN_FRAME, size / 2);
          }
          await this.enqueueDown(value);
        } finally {
          this.budget.release(size);
        }
      }
    } catch (error) {
      this.fault(error instanceof LaneFault ? error : new LaneFault('tcp-read'));
    }
  }

  async feed(raw) {
    this.assertLive();
    if (this.head) {
      const size = Math.min(64 - this.headSize, raw.length);
      this.head.set(raw.subarray(0, size), this.headSize);
      this.headSize += size;
      if (this.headSize < 64) return;
      await this.startStream();
      if (size === raw.length) return;
      raw = raw.subarray(size);
    }
    this.assertLive();
    // Account for input padding and the crypto result while parsing packet spans.
    const transient = 2 * (raw.length + 32);
    this.budget.hold(transient);
    try {
      const plain = await this.clientRead(raw);
      this.assertLive();
      await this.writePackets(plain);
    } finally {
      this.budget.release(transient);
    }
  }

  async writePackets(bytes) {
    const assembly = this.packets;
    const ends = [];
    for (let offset = 0; offset < bytes.length;) {
      const size = assembly.pending ? 0 : packetSize(bytes, offset, assembly.mode);
      if (!size || size > bytes.length - offset) {
        this.packetTimer ??= setTimeout(() => this.stop('packet-timeout'), this.stallMs);
        const part = assembly.add(bytes, offset);
        offset = part.offset;
        if (part.packet) {
          clearTimeout(this.packetTimer);
          this.packetTimer = null;
          try { await this.sendPackets(part.packet, [part.packet.length]); }
          finally { this.budget.release(part.packet.length); }
        }
        continue;
      }
      const start = offset;
      offset += size;
      ends[0] = size;
      const limit = packLimit(size);
      while (offset < bytes.length && ends.length < 128 && offset - start < limit) {
        const next = packetSize(bytes, offset, assembly.mode);
        if (!next || next > bytes.length - offset || offset - start + next > limit) break;
        offset += next;
        ends.push(offset - start);
      }
      await this.sendPackets(bytes.subarray(start, offset), ends);
      ends.length = 0;
    }
  }

  async sendPackets(bytes, ends) {
    this.assertLive();
    const peer = this.peer;
    let wire;
    // A single native call needs at most the previous output + chunk reserve
    // up to 512 KiB. Bigger packets keep bounded padding scratch space.
    const large = bytes.length > CRYPT_CHUNK;
    const reserve = large ? bytes.length + 512 * KiB + 64 : 2 * (bytes.length + 32);
    this.budget.hold(reserve);
    try {
      if (large) {
        wire = new Uint8Array(bytes.length);
        for (let offset = 0; offset < bytes.length; offset += BULK_PACK) {
          wire.set(await this.peerWrite(bytes.subarray(offset, offset + BULK_PACK)), offset);
          this.assertLive();
        }
      } else {
        wire = await this.peerWrite(bytes);
      }
      if (this.directTCP) {
        await this.writeTCP(peer, wire);
        return;
      }
      let start = 0;
      for (const end of ends) {
        this.assertSocket(peer);
        if (congested(peer, end - start)) await this.drain(peer, end - start);
        // Each KWS message is a complete MTProto transport packet.
        this.writeNative(peer, start === 0 && end === wire.length ? wire : wire.subarray(start, end));
        start = end;
      }
    } finally {
      this.budget.release(reserve);
    }
  }

  async pumpUp() {
    this.upBusy = true;
    try {
      while (!this.ended && !this.peerEnded && this.up.length) {
        let item = this.up.take();
        let raw = item.data, copy = 0;
        const length = raw.length + this.up.prefixBytes(packLimit(raw.length) - raw.length);
        try {
          if (length !== raw.length) {
            this.budget.hold(length);
            copy = length;
            const packed = new Uint8Array(length);
            packed.set(raw);
            let offset = raw.length;
            this.releaseUp(item);
            item = null;
            while (offset < length) {
              const next = this.up.take();
              packed.set(next.data, offset);
              offset += next.data.length;
              this.releaseUp(next);
            }
            raw = packed;
          }
          await this.feed(raw);
          // The CREDIT notification can block even after the upstream send.
          raw = null;
          if (item) {
            this.releaseUp(item);
            item = null;
          }
          if (copy) {
            this.budget.release(copy);
            copy = 0;
          }
          this.assertLive();
          if (congested(this.socket, 12)) await this.drain(this.socket, 12);
          this.sendCredit(length);
          this.receiving += length;
        } finally {
          if (item) this.releaseUp(item);
          if (copy) this.budget.release(copy);
        }
      }
    } catch (error) {
      this.fault(error);
    } finally {
      this.upBusy = false;
    }
  }

  enqueueDown(value) {
    if (this.ended || this.peerEnded) return;
    try {
      this.assertLive();
      const data = binary(value);
      if (!(data instanceof Uint8Array) || !data.length || data.length > MAX_PACKET) throw new LaneFault('kws-frame');
      if (data.length + this.down.bytes > MAX_PACKET + WINDOW || this.down.length >= 512) throw new LaneFault('queue');
      this.budget.hold(data.length + 256);
      upstreamBytes += data.length;
      if (!this.firstUpstream) {
        observeTiming(timings.firstUpstream, Date.now() - this.openedAt);
        this.firstUpstream = true;
      }
      this.down.add({ data });
      if (!this.downBusy) return this.pumpDown();
    } catch (error) {
      this.fault(error);
    }
  }

  async waitForCredit() {
    let timer;
    const started = Date.now();
    try {
      await new Promise((resolve, reject) => {
        this.creditWake = resolve;
        timer = setTimeout(() => reject(new LaneFault('window-timeout')), this.stallMs);
      });
    } finally {
      observeTiming(timings.downCredit, Date.now() - started);
      clearTimeout(timer);
      this.creditWake = null;
    }
    this.assertLive();
  }

  recordForwarded(size) {
    forwardedBytes += size;
    if (this.firstForwarded) return;
    this.firstForwarded = true;
    observeTiming(timings.firstForwarded, Date.now() - this.openedAt);
  }

  async pumpDown() {
    this.downBusy = true;
    try {
      while (!this.ended && this.down.length) {
        let item = this.down.take();
        let bytes = item.data, copy = 0;
        const length = bytes.length + this.down.prefixBytes(packLimit(bytes.length) - bytes.length);
        try {
          if (length !== bytes.length) {
            this.budget.hold(length);
            copy = length;
            const packed = new Uint8Array(length);
            packed.set(bytes);
            let offset = bytes.length;
            this.releaseDown(item);
            item = null;
            while (offset < length) {
              const next = this.down.take();
              packed.set(next.data, offset);
              offset += next.data.length;
              this.releaseDown(next);
            }
            bytes = packed;
          }
          for (let offset = 0; offset < length;) {
            if (!this.sending) await this.waitForCredit();
            const size = Math.min(this.sending, CRYPT_CHUNK, length - offset);
            const reserve = 4 * (size + 32);
            this.budget.hold(reserve);
            try {
              const plain = await this.peerRead(bytes.subarray(offset, offset + size));
              if (offset + size === length) {
                // Sending may wait on the client. The upstream ciphertext is
                // no longer referenced by WebCrypto or by the send queue.
                bytes = null;
                if (copy) {
                  this.budget.release(copy);
                  copy = 0;
                } else {
                  this.releaseDown(item);
                  item = null;
                }
              }
              this.assertLive();
              const wire = await this.clientWrite(plain, true);
              for (let pos = 0; pos < wire.length;) {
                this.assertSocket(this.socket);
                const remaining = wire.length - pos;
                const minimum = Math.min(remaining, DOWN_FRAME) + 8;
                const available = SOCKET_BUFFER - (nativeBufferedAmount(this.socket) ?? 0);
                if (available < minimum) {
                  const started = Date.now();
                  try { await this.drain(this.socket, minimum); }
                  finally { observeTiming(timings.downSocket, Date.now() - started); }
                  continue;
                }
                let payloadBytes = remaining;
                let framedBytes = remaining + Math.ceil(remaining / DOWN_FRAME) * 8;
                if (available < framedBytes) {
                  const frames = Math.floor(available / (DOWN_FRAME + 8));
                  payloadBytes = frames * DOWN_FRAME;
                  framedBytes = payloadBytes + frames * 8;
                }
                const payload = wire.subarray(pos, pos + payloadBytes);
                const message = payloadBytes <= DOWN_FRAME ? encodeFrame(DATA, this.sid, payload) :
                  encodeDataBatch(this.sid, payload, framedBytes);
                this.sending -= payloadBytes;
                this.writeNative(this.socket, message);
                this.recordForwarded(payloadBytes);
                pos += payloadBytes;
              }
            } finally {
              this.budget.release(reserve);
            }
            offset += size;
          }
        } finally {
          if (item) this.releaseDown(item);
          if (copy) this.budget.release(copy);
        }
      }
    } catch (error) {
      this.fault(error);
    } finally {
      this.downBusy = false;
      if (this.peerEnded) this.stop('kws-close');
    }
  }

  sendCredit(length) {
    this.assertSocket(this.socket);
    const bytes = new Uint8Array(12);
    const header = view(bytes);
    header.setUint32(0, CREDIT * 0x1000000 + this.sid);
    header.setUint32(4, 4);
    header.setUint32(8, length);
    this.writeNative(this.socket, bytes);
  }

  reconcileNative(socket, side, queued = nativeBufferedAmount(socket)) {
    const before = this.nativeBytes[side];
    if (!before) return;
    if (queued === undefined) {
      // This socket previously exposed a nonempty native queue. Its bytes
      // cannot safely be treated as drained when the reading disappears.
      this.stop('socket-buffer-unavailable');
    } else if (queued < before) {
      this.nativeBytes[side] = queued;
      this.budget.release(before - queued);
    }
  }

  scheduleNativeCheck(delay = 30) {
    if (this.nativeTimer !== null || !(this.nativeBytes[0] || this.nativeBytes[1])) return;
    this.nativeTimer = setTimeout(() => {
      this.nativeTimer = null;
      if (this.ended) return;
      const before = this.nativeBytes[0] + this.nativeBytes[1];
      if (this.nativeBytes[0]) this.reconcileNative(this.socket, 0);
      if (this.nativeBytes[1]) this.reconcileNative(this.peer, 1);
      // Bound the polling cost while the native queue makes no progress.
      const drained = this.nativeBytes[0] + this.nativeBytes[1] < before;
      this.scheduleNativeCheck(drained ? 30 : Math.min(delay * 2, 250));
    }, delay);
  }

  writeNative(socket, payload) {
    const side = socket === this.socket ? 0 : 1;
    const queued = nativeBufferedAmount(socket);
    if (queued === undefined) {
      if (this.nativeBytes[side]) throw new LaneFault('socket-buffer-unavailable');
      socket.send(payload);
      return;
    }
    this.reconcileNative(socket, side, queued);
    this.budget.hold(payload.byteLength);
    this.nativeBytes[side] += payload.byteLength;
    socket.send(payload);
    this.reconcileNative(socket, side);
    this.scheduleNativeCheck();
  }

  stop(kind, notify = true) {
    if (this.ended) return;
    this.phase = 'closed';
    count(kind);
    clearTimeout(this.openTimer);
    clearTimeout(this.expiryTimer);
    clearTimeout(this.packetTimer);
    clearTimeout(this.nativeTimer);
    clearTimeout(this.peerDrainTimer);
    this.openTimer = this.expiryTimer = this.packetTimer = this.nativeTimer = null;
    this.peerDrainTimer = null;
    this.budget.release(this.nativeBytes[0] + this.nativeBytes[1]);
    this.nativeBytes.fill(0);
    this.controller.abort();
    this.creditWake?.();
    this.up.clear(item => this.releaseUp(item));
    this.down.clear(item => this.releaseDown(item));
    this.packets?.clear();
    this.packets = this.head = null;
    this.clientRead = this.clientWrite = this.peerRead = this.peerWrite = null;
    const { socket, peer } = this;
    this.peer = null;
    socket.removeEventListener('message', this.onMessage);
    socket.removeEventListener('close', this.onClose);
    socket.removeEventListener('error', this.onError);
    if (peer && !this.directTCP) {
      peer.removeEventListener('message', this.onDown);
      peer.removeEventListener('close', this.onPeerClose);
      peer.removeEventListener('error', this.onPeerError);
    }
    this.release();
    const parentInvalid = kind === 'session-expired' || kind === 'revoked';
    // These close codes carry parent or policy status. A preceding lane CLOSE
    // would make the Bridge detach before it receives the WebSocket close.
    if (notify && !parentInvalid && kind !== 'frame' && socket.readyState === 1 && !congested(socket, 8)) {
      try { socket.send(encodeFrame(CLOSE, this.sid)); } catch {}
    }
    safeClose(socket, parentInvalid ? SESSION_EXPIRED_CLOSE : kind === 'frame' ? 1008 : kind === 'queue' ? 1013 : 1000);
    safeClose(peer);
  }
}


function runBridge(origin, fast, bootstrap) {
  'use strict';
  const WS = origin.replace(/^https:/, 'wss:') + '/api/v1/ws';
  const tokenPattern = /^[A-Za-z0-9_-]{43}$/;
  const lanes = new Map(), used = new Set();
  const lifetime = new AbortController();
  const rejected = Symbol();
  const fragment = /^#android=([A-Za-z0-9_-]{43})$/.exec(location.hash)?.[1];
  try { history.replaceState(null, '', location.pathname); } catch {}
  let port, started = false, ready = false, closed = false, failing = false, status;
  let startupDeadline = 0, startupTimer;
  let ticket = '', grant = '', until = 0, renewal;
  let pendingBytes = 0, pendingItems = 0;
  let trafficTimer = null, sentBytes = 0, receivedBytes = 0;

  function report(state) {
    if (state === status || closed) return;
    status = state;
    port.postMessage({ t: 'status', state });
  }

  function noteTraffic(up, down) {
    sentBytes += up;
    receivedBytes += down;
    if (trafficTimer !== null) return;
    trafficTimer = setTimeout(() => {
      trafficTimer = null;
      const report = { t: 'traffic', up: sentBytes, down: receivedBytes };
      sentBytes = receivedBytes = 0;
      if (closed) return;
      try { port.postMessage(report); } catch { fail(); }
    }, 100);
  }

  function eachFrame(buffer, fn) {
    if (!(buffer instanceof ArrayBuffer) || !buffer.byteLength || buffer.byteLength > 2097152) throw Error();
    const data = new DataView(buffer);
    let n = 0;
    for (let offset = 0; offset < buffer.byteLength;) {
      if (buffer.byteLength - offset < 8 || ++n > 4096) throw Error();
      const id = data.getUint32(offset);
      const length = data.getUint32(offset + 4);
      const end = offset + 8 + length;
      if (length > 1048576 || end > buffer.byteLength) throw Error();
      fn(id >>> 24, id & 0xffffff, length, offset, end, data);
      offset = end;
    }
  }

  function finish(lane, notify) {
    if (lane.done) return;
    lane.done = true;
    lanes.delete(lane.id);
    clearTimeout(lane.timer);
    clearTimeout(lane.handshake);
    pendingBytes -= lane.bytes;
    pendingItems -= lane.queue.length - lane.head;
    lane.queue.length = lane.bytes = lane.head = 0;
    const ws = lane.socket;
    lane.socket = null;
    if (ws) {
      ws.onopen = ws.onmessage = ws.onclose = null;
      if (ws.readyState < 2) {
        try { ws.close(); } catch {}
      }
    }
    if (notify && !closed) {
      const frame = new ArrayBuffer(8);
      new DataView(frame).setUint32(0, 3 * 0x1000000 + lane.id);
      try { port.postMessage(frame, [frame]); } catch { fail(); }
    }
  }

  function laneFailed(lane) {
    if (closed || lane.done) return;
    const lastStartupLane = startupDeadline && lanes.size === 1;
    finish(lane, !lastStartupLane);
    if (lastStartupLane) fail();
  }

  function shutdown() {
    if (closed) return;
    closed = true;
    lifetime.abort();
    clearTimeout(startupTimer);
    clearTimeout(trafficTimer);
    for (const lane of lanes.values()) finish(lane, false);
    used.clear();
    try { port?.close(); } catch {}
    if (ticket && performance.now() < until) {
      try {
        fetch(origin + '/api/v1/session', {
          method: 'DELETE', keepalive: true, mode: 'same-origin', credentials: 'omit',
          redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer',
          headers: { Authorization: 'Bearer ' + ticket },
        }).catch(() => {});
      } catch {}
    }
    ticket = grant = '';
  }

  function fail() {
    if (closed || failing) return;
    failing = true;
    try { report('failed'); } catch {}
    try { port?.postMessage({ t: 'close' }); } catch {}
    shutdown();
  }

  function parentFailed() {
    until = 0;
    fail();
  }

  async function request(path, auth, body, code) {
    const deadline = Math.min(startupDeadline || Infinity, performance.now() + 21500);
    for (let attempt = 0; attempt < 4 && !closed; attempt++) {
      const remaining = deadline - performance.now();
      if (remaining <= 0) return null;
      const control = new AbortController();
      const cancel = () => control.abort();
      lifetime.signal.addEventListener('abort', cancel, { once: true });
      const timer = setTimeout(cancel, Math.min(4500, remaining));
      let retryAfter = 0;
      try {
        const response = await fetch(origin + path, {
          method: 'POST', body, mode: 'same-origin', credentials: 'omit',
          cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
          headers: { Authorization: 'Bearer ' + auth, ...(body && { 'Content-Type': 'application/octet-stream' }) },
          signal: control.signal,
        });
        if (response.status === code && !control.signal.aborted) {
          const welcome = body ? await response.arrayBuffer() : null;
          if (!control.signal.aborted && performance.now() <= deadline) return { response, welcome };
        }
        response.body?.cancel().catch(() => {});
        if (!control.signal.aborted) {
          const status = response.status;
          if (status < 500 && status !== 408 && status !== 429) return rejected;
          const after = response.headers.get('Retry-After');
          if (after !== null) {
            const delay = /^\d+$/.test(after) ? Number(after) * 1000 : Date.parse(after) - Date.now();
            if (delay > 0) retryAfter = delay;
          }
        }
      } catch {
        if (closed) return null;
      } finally {
        clearTimeout(timer);
        lifetime.signal.removeEventListener('abort', cancel);
      }
      if (attempt < 3) {
        const delay = Math.max(retryAfter, 250 * 2 ** attempt) + Math.random() * 120;
        if (closed || delay >= deadline - performance.now()) return null;
        await new Promise(resolve => {
          const timer = setTimeout(done, delay);
          lifetime.signal.addEventListener('abort', done, { once: true });
          if (closed) done();
          function done() {
            clearTimeout(timer);
            lifetime.signal.removeEventListener('abort', done);
            resolve();
          }
        });
      }
    }
    return null;
  }

  function updateTicket(next, ttl) {
    if (!tokenPattern.test(next ?? '') || !Number.isInteger(ttl) || ttl < 1 || ttl > 300) throw Error();
    ticket = next;
    until = performance.now() + 1000 * ttl;
  }

  async function currentTicket() {
    // All lanes opened together share a renewal, while established lanes continue.
    renewal ??= (async () => {
      const result = await request('/api/v1/session/renew', grant, undefined, 204);
      if (closed || !result) return null;
      if (result === rejected) { parentFailed(); return null; }
      try {
        updateTicket(result.response.headers.get('X-Session-Token'), Number(result.response.headers.get('X-Session-TTL')));
      } catch { parentFailed(); return null; }
      return ticket;
    })().finally(() => { renewal = null; });
    return renewal;
  }

  function socketBuffer(socket) {
    try {
      const amount = socket?.bufferedAmount;
      return Number.isSafeInteger(amount) && amount >= 0 ? amount : 0;
    } catch {
      return 0;
    }
  }

  function flush(lane) {
    const ws = lane.socket;
    if (closed || lane.done || ws?.readyState !== WebSocket.OPEN || lane.timer) return;
    let progressed = false;
    for (let sends = 0; lane.head < lane.queue.length && sends < 64; sends++) {
      const first = lane.queue[lane.head];
      const buffered = socketBuffer(ws);
      if (buffered > 2097152 - first.byteLength) break;
      let length = first.byteLength, last = lane.head + 1;
      while (last < lane.queue.length && length + lane.queue[last].byteLength <= 32768 &&
             buffered + length + lane.queue[last].byteLength <= 2097152) {
        length += lane.queue[last++].byteLength;
      }
      let data = first;
      if (last > lane.head + 1) {
        const joined = new Uint8Array(length);
        let offset = 0;
        for (let i = lane.head; i < last; i++) {
          joined.set(new Uint8Array(lane.queue[i]), offset);
          offset += lane.queue[i].byteLength;
        }
        data = joined.buffer;
      }
      ws.send(data);
      progressed = true;
      pendingItems -= last - lane.head;
      pendingBytes -= length;
      lane.bytes -= length;
      while (lane.head < last) lane.queue[lane.head++] = null;
      noteTraffic(length, 0);
    }
    if (lane.head === lane.queue.length) {
      lane.queue.length = lane.head = 0;
      lane.stalled = lane.stallDelay = undefined;
      return;
    }
    if (lane.head >= 128 && lane.head * 2 >= lane.queue.length) {
      lane.queue.splice(0, lane.head);
      lane.head = 0;
    }
    const blocked = socketBuffer(ws) > 2097152 - lane.queue[lane.head].byteLength;
    const stalled = blocked && !progressed ? lane.stalled : undefined;
    lane.stalled = blocked ? stalled ?? performance.now() : undefined;
    if (blocked && performance.now() - lane.stalled >= 30000) {
      finish(lane, true);
      return;
    }
    lane.stallDelay = blocked ? Math.min(80, (stalled === undefined ? 5 : lane.stallDelay) * 2) : 0;
    lane.timer = setTimeout(() => {
      lane.timer = 0;
      try { flush(lane); } catch { finish(lane, true); }
    }, lane.stallDelay);
  }

  async function openLane(lane) {
    if (lane.opening || lane.done || closed) return;
    lane.opening = true;
    try {
      const auth = until - performance.now() > 10000 ? ticket : await currentTicket();
      if (closed || lane.done) return;
      if (!auth) { laneFailed(lane); return; }
      const remaining = startupDeadline ? startupDeadline - performance.now() : 8000;
      if (remaining <= 0) { fail(); return; }
      const handshakeMs = Math.min(8000, remaining);
      const handshakeDeadline = performance.now() + handshakeMs;
      const protocol = 'tproxy-lane-v1.' + auth + '.' + lane.id;
      const ws = lane.socket = new WebSocket(WS, protocol);
      ws.binaryType = 'arraybuffer';
      lane.handshake = setTimeout(() => {
        if (!lane.done && lane.socket === ws && !lane.opened) laneFailed(lane);
      }, handshakeMs);
      ws.onopen = () => {
        if (closed || lane.done || lane.socket !== ws) return;
        if (ws.protocol !== protocol) { fail(); return; }
        if (performance.now() >= handshakeDeadline) { laneFailed(lane); return; }
        clearTimeout(lane.handshake);
        lane.opened = true;
        if (startupDeadline) {
          clearTimeout(startupTimer);
          startupDeadline = 0;
        }
        try { flush(lane); } catch { finish(lane, true); }
      };
      ws.onmessage = event => {
        if (closed || lane.done || lane.socket !== ws) return;
        try {
          let ended = false;
          let boundaries;
          eachFrame(event.data, (type, id, length, start, end, view) => {
            if (id !== lane.id || ended) throw Error();
            if (port.postFrames && (start || end < event.data.byteLength)) (boundaries ??= []).push(end);
            if (type === 3 && !length) ended = true;
            else if (type === 2 && length) return;
            else if (type === 4 && length === 4 && view.getUint32(start + 8)) return;
            else throw Error();
          });
          noteTraffic(0, event.data.byteLength);
          if (boundaries) port.postFrames(event.data, boundaries);
          else port.postMessage(event.data, [event.data]);
          if (ended) finish(lane, false);
        } catch { fail(); }
      };
      ws.onclose = event => {
        if (closed || lane.done || lane.socket !== ws) return;
        if (event?.code === 4001) parentFailed();
        else if (event?.code === 1008) fail();
        else laneFailed(lane);
      };
    } catch {
      laneFailed(lane);
    }
  }

  function enqueue(buffer) {
    let buffered = 0;
    const touched = new Set();
    for (const lane of lanes.values()) buffered += socketBuffer(lane.socket);
    eachFrame(buffer, (type, id, length, start, end, view) => {
      if (closed) return;
      if (!id) throw Error();
      let lane = lanes.get(id);
      if (type === 1 && !length) {
        if (lane || used.has(id) || lanes.size >= 128 || used.size >= 4096) throw Error();
        used.add(id);
        lane = { id, head: 0, bytes: 0, queue: [], socket: null };
        lanes.set(id, lane);
      } else if (type === 3 && !length) {
        if (lane) finish(lane, false);
        return;
      } else if (!(type === 2 && length) &&
                 !(type === 4 && length === 4 && view.getUint32(start + 8))) throw Error();
      if (!lane) return; // Late DATA or WINDOW for a lane that has closed.
      const size = end - start;
      if (pendingBytes + buffered + size > 33554432 || pendingItems >= 16384 ||
          lane.bytes + socketBuffer(lane.socket) + size > 8388608 ||
          lane.queue.length - lane.head >= 1024) {
        finish(lane, true);
        return;
      }
      pendingBytes += size;
      pendingItems++;
      lane.bytes += size;
      lane.queue.push(start === 0 && end === buffer.byteLength ? buffer : buffer.slice(start, end));
      touched.add(lane);
    });
    for (const lane of touched) {
      if (lane.done || !ready) continue;
      if (!lane.opening) void openLane(lane);
      else {
        try { flush(lane); } catch { finish(lane, true); }
      }
    }
  }

  async function create(first) {
    try {
      let welcome;
      const remaining = Math.floor(fast?.ttl - performance.now() / 1000);
      if (remaining > 10 && remaining <= 90 && tokenPattern.test(fast.ticket ?? '') &&
          tokenPattern.test(fast.grant ?? '')) {
        updateTicket(fast.ticket, remaining);
        grant = fast.grant;
        welcome = new Uint8Array([17, 0, 0, 0, 0, 0, 0, 0]).buffer;
      } else {
        const result = await request('/api/v1/session', bootstrap, first, 200);
        if (!result || result === rejected || closed) { fail(); return; }
        welcome = result.welcome;
        const { headers } = result.response;
        if (headers.get('X-Carrier-Mode') !== 'websocket-lanes' ||
            welcome.byteLength !== 8 || new DataView(welcome).getUint32(0) !== 0x11000000 ||
            new DataView(welcome).getUint32(4)) throw Error();
        grant = headers.get('X-Session-Renewal');
        if (!tokenPattern.test(grant ?? '')) throw Error();
        updateTicket(headers.get('X-Session-Token'), Number(headers.get('X-Session-TTL')));
      }
      fast = null;
      bootstrap = '';
      ready = true;
      port.postMessage(welcome, [welcome]);
      report('connected');
      for (const lane of lanes.values()) void openLane(lane);
    } catch { fail(); }
  }

  function start(next) {
    if (port || closed) return;
    port = next;
    port.onmessage = event => {
      if (closed || failing) return;
      const data = event.data;
      try {
        if (data instanceof ArrayBuffer) {
          if (!started) {
            const hello = new DataView(data);
            if (hello.byteLength !== 9 || hello.getUint32(0) !== 0x10000000 ||
                hello.getUint32(4) !== 1 || hello.getUint8(8) !== 1) throw Error();
            started = true;
            startupDeadline = performance.now() + 30000;
            startupTimer = setTimeout(fail, 30000);
            void create(data);
          } else if (ready) enqueue(data);
          else throw Error();
        } else if (data?.t === 'close') shutdown();
      } catch { fail(); }
    };
    try {
      port.start();
      report('connecting');
    } catch { fail(); }
  }

  addEventListener('message', event => {
    const { source, data, ports } = event;
    if (port || closed || source !== parent || !data || typeof data !== 'object' ||
        Object.keys(data).length !== 2 || data.t !== 'tproxy-init' || data.v !== 1 ||
        ports.length !== 1) return;
    let supplied;
    try { supplied = new URL(event.origin); } catch { return; }
    if (supplied.protocol !== 'http:' || supplied.hostname !== '127.0.0.1' ||
        !supplied.port || supplied.origin !== event.origin) return;
    start(ports[0]);
  });
  addEventListener('pagehide', shutdown, { once: true });
  const injected = globalThis.TelegramWebProxy;
  if (fragment && typeof injected?.postMessage === 'function') {
    const adapter = {
      onmessage: null,
      start() {},
      close() { injected.onmessage = null; },
      postMessage(value) {
        injected.postMessage(value instanceof ArrayBuffer ? value : JSON.stringify(value));
      },
      postFrames(buffer, boundaries) {
        let start = 0;
        for (const end of boundaries) {
          injected.postMessage(buffer.slice(start, end));
          start = end;
        }
      },
    };
    injected.onmessage = event => {
      let data = event.data;
      if (typeof data === 'string') {
        try { data = JSON.parse(data); } catch { return; }
      }
      adapter.onmessage?.({ data });
    };
    // Native clients expect the authenticated init before any status or data.
    try {
      injected.postMessage(JSON.stringify({ t: 'tproxy-android-init', v: 1, nonce: fragment }));
      start(adapter);
    } catch {
      adapter.close();
      shutdown();
    }
  }
}


function htmlResponse(body, csp, permissionsPolicy, { status = 200, form = false } = {}) {
  return new Response(body, { status, headers: {
    ...noStore,
    // Navigation form POSTs can send Origin: null under no-referrer.
    'Referrer-Policy': form ? 'same-origin' : noStore['Referrer-Policy'],
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Security-Policy': csp,
    'Permissions-Policy': permissionsPolicy,
  } });
}

function bridgeResponse(host, boot, fast) {
  const nonce = b64(random(18));
  const body = '<!doctype html><meta charset="utf-8"><script nonce="' + nonce + '">' +
    '(' + runBridge.toString() + ')(' + JSON.stringify('https://' + host) + ',' +
    JSON.stringify(fast) + ',' + JSON.stringify(boot) + ');</script>';
  return htmlResponse(body, [
    "default-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-src 'none'",
    "frame-ancestors http://127.0.0.1:*", "connect-src 'self' wss://" + host,
    "script-src 'nonce-" + nonce + "'", 'sandbox allow-same-origin allow-scripts',
  ].join('; '), permissions + ', clipboard-read=(), clipboard-write=()');
}

function portalResponse(host, secret, request, diagnostics) {
  const nonce = b64(random(18));
  const csp = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; " +
    (diagnostics ? "connect-src 'self'; " : '') +
    "script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'";
  const link = 'tg://webproxy?server=' + encodeURIComponent(host) + '&amp;secret=' + encodeURIComponent(secret);
  const details = diagnostics ? portalDiagnostics(request) : '';
  const body = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Telegram WEB Proxy</title>
<style nonce="${nonce}">
:root{color-scheme:light;font-family:system-ui,"Microsoft YaHei",sans-serif;background:#f3f7fc;color:#16243d}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(ellipse at top,#deebfb,transparent 60%)}
main{width:min(100%,650px);background:#ffffff;border:1px solid #dce6f3;border-radius:25px;padding:clamp(22px,6vw,44px);box-shadow:0 20px 65px #294b7b14;min-width:0}
h1{margin:0;font-size:clamp(27px,5vw,42px);line-height:1.15;letter-spacing:-.045em}
.host{margin:10px 0 25px;color:#425979;overflow-wrap:anywhere}
.status{padding:12px 14px;border-radius:12px;background:#eef6ff;color:#174667;font-size:.91rem}
label{display:block;font-size:.88rem;font-weight:650;margin:24px 0 8px}
textarea{display:block;width:100%;min-height:80px;resize:vertical;padding:12px;border:1px solid #cfdff0;border-radius:12px;color:#203355;background:#f9fbfe;font:14px/1.5 ui-monospace,Consolas,monospace;overflow-wrap:anywhere}
.actions{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0 0}
button,a{display:inline-flex;align-items:center;justify-content:center;text-decoration:none;padding:11px 16px;min-height:44px;border:1px solid #cbdcf1;border-radius:10px;font:650 .91rem system-ui,sans-serif;cursor:pointer}
button{color:#174667;background:#f7fbff}
a{color:white;background:#075cae;border-color:#075cae}
:focus-visible{outline:3px solid #4c9cf0;outline-offset:3px}
p{line-height:1.55}
#feedback{min-height:1.5em;margin:8px 0;font-size:.85rem;color:#174667}
.help,details{border-top:1px solid #e0e9f5;padding-top:14px;margin:12px 0 0;color:#425979;font-size:.88rem}
dl{display:grid;grid-template-columns:1fr auto;gap:5px}dd{margin:0}
</style>
</head>
<body>
<main>
<h1>Telegram WEB Proxy</h1>
<p class="host">${host}</p>
<p class="status">配置已就绪。连接状态请在 Telegram 的代理设置中查看。</p>
<label for="link">代理链接</label>
<textarea id="link" readonly spellcheck="false" aria-describedby="help">${link}</textarea>
<div class="actions">
  <a href="${link}" rel="noreferrer">打开 Telegram</a>
  <button type="button" id="copy">复制链接</button>
  <form action="${logoutPath}" method="post"><button type="submit">退出登录</button></form>
</div>
<p id="feedback" role="status"></p>
<p class="help" id="help">请使用支持 WEB 代理的 Telegram 版本。在应用内确认添加后启用代理。若设备没有打开 Telegram，可复制链接，在应用内打开。请将此页面和代理链接保存在私密位置。</p>
${diagnostics ? '' : '<p class="help"><a href="' + adminPath + '?diagnostics=1">连接诊断</a></p>'}
${details}
${diagnostics ? '<p class="help"><button type="button" id="probe">测量本机 HTTPS 往返</button></p><p id="probe-result" role="status"></p>' : ''}
</main>
<script nonce="${nonce}">
document.getElementById('copy').addEventListener('click', async () => {
  const link = document.getElementById('link');
  const status = document.getElementById('feedback');
  try {
    await navigator.clipboard.writeText(link.value);
    status.textContent = '链接已复制';
  } catch {
    link.focus();
    link.select();
    status.textContent = '链接已选中，请手动复制';
  }
});
${diagnostics ? `document.getElementById('probe').addEventListener('click', async event => {
  const button = event.currentTarget;
  const result = document.getElementById('probe-result');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  const times = [];
  button.disabled = true;
  result.textContent = '正在测量…';
  try {
    for (let i = 0; i < 5; i++) {
      const start = performance.now();
      const response = await fetch('/admin?probe=1', {
        method: 'HEAD', cache: 'no-store', credentials: 'same-origin',
        mode: 'same-origin', redirect: 'error', signal: controller.signal,
      });
      if (response.status !== 204) throw Error();
      times.push(performance.now() - start);
    }
    times.sort((a, b) => a - b);
    result.textContent = '5 次 HTTPS 往返中位数 ' + Math.round(times[2]) +
      ' ms，含浏览器请求与 Worker 鉴权。';
  } catch {
    result.textContent = '测量未完成，请检查网络和登录状态。';
  } finally {
    clearTimeout(timer);
    button.disabled = false;
  }
});` : ''}
</script>
</body>
</html>`;
  return htmlResponse(request.method === 'HEAD' ? null : body, csp,
    permissions + ', clipboard-read=(), clipboard-write=(self)', { form: true });
}

function upstreamSummary() {
  let rows = '';
  for (const [index, stats] of upstreamStats.entries()) {
    const finished = stats.connected + stats.failed;
    if (!finished && !stats.cancelled && !stats.retries) continue;
    const rate = finished ? Math.round(stats.connected * 100 / finished) + '%' : '暂无';
    rows += '<dt>DC ' + (Math.floor(index / 2) + 1) + (index % 2 ? ' · 媒体' : ' · 通用') + '</dt><dd>' +
      '成功 ' + stats.connected + ' / ' + finished + '（' + rate + '），取消 ' + stats.cancelled +
      '，备用尝试 ' + stats.retries + '<br>' + timingSummary(stats.timing) +
      '<br>拨号错误：超时 ' + stats.timeout + '，网络 ' + stats.network +
      '，HTTP ' + stats.http + '，协议 ' + stats.protocol + '</dd>';
  }
  return rows ? '<dl>' + rows + '</dl>' : '<p>暂无 KWS 拨号样本。</p>';
}

function portalDiagnostics(request) {
  const colo = request.cf?.colo ?? '';
  const incoming = /^[A-Z]{3}$/.test(colo) ? colo : '未提供';
  const rtt = clientRtt(request);
  const pageRtt = Number.isFinite(rtt) && rtt >= 0 ? rtt + ' ms' : '未提供';

  return '<details open><summary>当前实例诊断</summary>' +
    '<p>机房和 RTT 来自本次管理页请求的 Cloudflare 元数据，反映该请求的接入位置与往返耗时。</p><dl>' +
    '<dt>接入机房（colo）</dt><dd>' + incoming + '</dd>' +
    '<dt>客户端到 Cloudflare RTT</dt><dd>' + pageRtt + '</dd></dl>' +
    '<p>Bridge 签发、客户端 WebSocket 升级和 Telegram KWS 握手是三个阶段。收到并转发上游数据另行计数。P95 按区间显示。</p><dl>' +
    '<dt>Bridge 配置与密钥准备</dt><dd>' + timingSummary(timings.bridgeConfig) + '</dd>' +
    '<dt>成功签发 Bridge 页面</dt><dd>' + timingSummary(timings.bridgePage) + '</dd>' +
    '<dt>代理升级请求的入口 RTT</dt><dd>' + timingSummary(timings.client) + '</dd>' +
    '<dt>客户端 WebSocket 升级成功</dt><dd>' + timingSummary(timings.upgrade) + '</dd>' +
    '<dt>Telegram KWS 握手成功</dt><dd>' + timingSummary(timings.kws) + '</dd>' +
    '<dt>升级后收到首批上游数据</dt><dd>' + timingSummary(timings.firstUpstream) + '</dd>' +
    '<dt>升级后转发首批数据</dt><dd>' + timingSummary(timings.firstForwarded) + '</dd>' +
    '<dt>等待客户端接收额度</dt><dd>' + timingSummary(timings.downCredit) + '</dd>' +
    '<dt>等待 WebSocket 发送缓冲</dt><dd>' + timingSummary(timings.downSocket) + '</dd>' +
    '<dt>上游接收 / 已转发</dt><dd>' + upstreamBytes + ' / ' + forwardedBytes + ' 字节</dd></dl>' +
    '<h2>Telegram 数据中心</h2><p>成功率按已完成的 KWS 拨号计算。取消单列，失败原因按实际尝试计数。</p>' + upstreamSummary() +
    '<p>计数仅覆盖处理本次页面请求的实例，实例重启时清零。</p><dl>' +
    Object.entries(counters).sort(([a], [b]) => a.localeCompare(b))
      .map(([kind, value]) => '<dt>' + kind + '</dt><dd>' + value + '</dd>').join('') +
    '<dt>活动连接</dt><dd>' + activeLanes + '</dd><dt>应用缓冲当前 / 峰值</dt><dd>' + queuedBytes + ' / ' + peakQueuedBytes + ' 字节</dd></dl>' +
    '<p>应用缓冲基于代码记账，运行时原生缓冲仅在接口提供读数时可见。</p></details>';
}

function publicHomeResponse(method) {
  return publicPage(method, 'Welcome to nginx!', `<h1>Welcome to nginx!</h1>
<p>This is the default welcome page. Further site configuration may be required.</p>
<p>For documentation and community support, visit <a href="https://nginx.org/">nginx.org</a>.<br>
Commercial support is available at <a href="https://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p>`);
}

function loginResponse(method, error = '', status = 200) {
  return publicPage(method, '站点管理', `<h1>站点管理</h1>
<form action="${adminPath}" method="post">
  <label for="password">访问密码</label>
  <input id="password" name="password" type="password" maxlength="256" required autocomplete="current-password">
  <button type="submit">登录</button>
</form>
${error ? '<p role="alert">' + error + '</p>' : ''}
<p><a href="/">返回首页</a></p>`, true, status);
}

function publicPage(method, title, content, form = false, status = 200) {
  const nonce = b64(random(18));
  const csp = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action " + (form ? "'self'; " : "'none'; ") +
    "style-src 'nonce-" + nonce + "'";
  const body = `<!doctype html>
<html lang="${form ? 'zh-CN' : 'en'}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style nonce="${nonce}">
  ${form ? `:root { color-scheme: light dark; font: 16px/1.6 system-ui, sans-serif; }
  body { min-height: 100vh; margin: 0; display: grid; place-items: center; }
  main { margin: 24px; padding: 32px; border: 1px solid GrayText; border-radius: 16px; }
  h1 { margin: 0; font-size: 1.6rem; }
  form { margin-top: 16px; display: grid; gap: 8px; }
  input, button { font: inherit; padding: 6px 10px; }
  a { color: LinkText; }` :
    'body { max-width: 35rem; margin: 0 auto; padding: 0 1rem; font-family: Tahoma, Verdana, Arial, sans-serif; }'}
</style>
</head>
<body>
<main>${content}</main>
</body>
</html>`;
  return htmlResponse(method === 'HEAD' ? null : body, csp,
    permissions + ', clipboard-read=(), clipboard-write=()', { status, form });
}

export {
  advanceCounter, configuration, connectKWS, createCTR, createWorker, encodeFrame, issueToken,
  Lane, makeHead, packetSize, readHead, UpstreamRouter, verifyBridge, verifyToken, visitFrames,
};
