import { afterEach, describe, expect, it, vi } from 'vitest';
import { createCipheriv } from 'node:crypto';
import { readFileSync } from 'node:fs';
import worker, {
  advanceCounter, configuration, connectKWS, createCTR, encodeFrame, issueToken, makeHead,
  packetSize, readHead, verifyBridge, verifyToken, visitFrames,
} from '../telegram_webproxy.js';
import { ENV, HELLO, HOST, ORIGIN, PROXY_SECRET, VECTOR, FakeSocket, authRequest, bridgeBoot, packet, synthetic } from './fixtures.js';

it('allows password setup and keeps portal sessions separate from stable proxy credentials', async () => {
  const password = '本地 notebook lantern 2026';
  const env = { ...ENV, p: password };
  const login = (bindings, value = password, origin = ORIGIN, ip = '192.0.2.5') => worker.fetch(new Request(ORIGIN + '/admin', {
    method: 'POST', body: new URLSearchParams({ password: value }),
    headers: { Origin: origin, 'CF-Connecting-IP': ip },
  }), bindings);
  const welcome = await (await worker.fetch(new Request(ORIGIN), env)).text();
  expect(welcome).toContain('<h1>Welcome to nginx!</h1>');
  expect(welcome).toContain('default welcome page');
  expect(welcome).toContain('href="https://nginx.org/"');
  expect(welcome).toContain('href="https://nginx.com/"');
  expect(welcome).toContain('Thank you for using nginx.');
  expect(welcome).not.toMatch(/tg:\/\/|PROXY_SEED|Telegram|\/admin|<form/);
  const admin = await worker.fetch(new Request(ORIGIN + '/admin'), env);
  expect(admin.headers.get('Referrer-Policy')).toBe('same-origin');
  expect(await admin.text()).toContain('<form action="/admin" method="post">');
  for (const path of ['/login', '/manage']) {
    expect((await worker.fetch(new Request(ORIGIN + path), env)).status).toBe(404);
  }
  expect((await worker.fetch(new Request(ORIGIN + '/' + ENV.PORTAL_KEY), env)).status).toBe(404);
  expect((await login(env, password, 'https://other.example.com')).status).toBe(404);
  expect((await login(env, 'incorrect password')).status).toBe(401);

  expect((await login({ p: password, PROXY_SEED: 'broken' })).status).toBe(503);

  const signedIn = await login(env);
  expect(signedIn.status).toBe(303);
  expect(signedIn.headers.get('Location')).toBe('/admin');
  const session = signedIn.headers.get('Set-Cookie');
  expect(session).toContain('Path=/admin; Secure; HttpOnly; SameSite=Strict');
  expect(session).not.toContain(PROXY_SECRET);
  const cookie = session.split(';', 1)[0];
  const manage = (bindings, site = ORIGIN, credential = cookie) => worker.fetch(new Request(site + '/admin', {
    headers: { Cookie: credential },
  }), bindings);
  const page = await manage(env);
  expect(page.status).toBe(200);
  expect(page.headers.get('Referrer-Policy')).toBe('same-origin');
  const panel = await page.text();
  expect(panel).toContain(PROXY_SECRET);
  expect(panel).toContain('href="/admin?diagnostics=1"');
  const rotated = { ...env, p: 'another memorable password' };
  for (const response of await Promise.all([
    manage(env, 'https://other.example.com'),
    manage(env, ORIGIN, cookie + '; ' + cookie),
    manage(env, ORIGIN, cookie.replace(/=./, '=~')),
    manage(rotated),
  ])) {
    const html = await response.text();
    expect(html).toContain('<form action="/admin" method="post">');
    expect(html).not.toContain('tg://');
  }
  expect((await configuration(rotated, HOST)).secret).toBe(PROXY_SECRET);
  expect((await configuration({ PROXY_SEED: '42'.repeat(32), p: password }, HOST)).secret).not.toBe(PROXY_SECRET);
  const logout = await worker.fetch(new Request(ORIGIN + '/admin/logout', {
    method: 'POST', headers: { Cookie: cookie, Origin: ORIGIN },
  }), env);
  expect(logout.headers.get('Set-Cookie')).toContain('Max-Age=0');
  expect(logout.headers.get('Location')).toBe('/');

  const legacy = { PORTAL_KEY: ENV.PORTAL_KEY, PORTAL_PASSWORD: password };
  expect((await login(legacy)).status).toBe(404);
  expect((await login({ ...legacy, p: rotated.p })).status).toBe(401);

  const ip = '192.0.2.6';
  for (let i = 0; i < 8; i++) expect((await login(env, 'incorrect password', ORIGIN, ip)).status).toBe(401);
  expect((await login(env, password, ORIGIN, ip)).status).toBe(429);
});

it('rejects oversized login claims before spending the login-attempt budget', async () => {
  const origin = 'https://login-budget.example.com';
  const login = length => worker.fetch(new Request(origin + '/admin', {
    method: 'POST', body: new URLSearchParams({ password: ENV.p }), headers: {
      Origin: origin, 'CF-Connecting-IP': '192.0.2.17', 'Content-Length': length,
    },
  }), ENV);
  for (let i = 0; i < 10; i++) expect((await login('1025')).status).toBe(404);
  const length = new URLSearchParams({ password: ENV.p }).toString().length;
  expect((await login(String(length))).status).toBe(303);
});

it('rejects an implausibly future-dated portal cookie without deriving credentials', async () => {
  const token = Buffer.alloc(32);
  token.writeUInt32BE(Math.floor(Date.now() / 1000) + 3600);
  const derive = vi.spyOn(crypto.subtle, 'deriveBits');
  const response = await worker.fetch(new Request('https://future-cookie.example.com/admin', {
    headers: { Cookie: '__Secure-site_session=' + token.toString('base64url') },
  }), { p: 'synthetic-future-cookie-password' });
  expect(await response.text()).toContain('<form');
  expect(derive).not.toHaveBeenCalled();
});

it('keeps per-DC results private and separates failed attempts from successful fallback and cancellation', async () => {
  const origin = 'https://diagnostics.example.com';
  const path = '/admin?diagnostics=1';
  const unauthenticated = await worker.fetch(new Request(origin + path), ENV);
  expect(await unauthenticated.text()).not.toContain('Telegram 数据中心');
  const route = { dc: 5, media: true };
  const peer = new FakeSocket();
  const fetcher = vi.fn(async () => ({
    status: 101, webSocket: peer, headers: new Headers({ 'Sec-WebSocket-Protocol': 'binary' }),
  }));
  fetcher.mockResolvedValueOnce(new Response(null, { status: 502 }));
  expect(await connectKWS(route, new AbortController().signal, fetcher)).toBe(peer);
  const abort = new AbortController();
  const cancelled = connectKWS(route, abort.signal, () => new Promise(() => {}));
  abort.abort();
  await expect(cancelled).rejects.toThrow('kws-connect');
  const login = await worker.fetch(new Request(origin + '/admin', {
    method: 'POST', body: new URLSearchParams({ password: ENV.p }), headers: { Origin: origin },
  }), ENV);
  const cookie = login.headers.get('Set-Cookie').split(';', 1)[0];
  const response = await worker.fetch(new Request(origin + path, { headers: { Cookie: cookie } }), ENV);
  const html = await response.text();
  expect(html).toMatch(/DC 5 · 媒体<\/dt><dd>成功 1 \/ 1（100%），取消 1，备用尝试 1/);
  expect(html).toContain('HTTP 1');
  expect(html).not.toContain('kws5-1.web.telegram.org');
  expect(response.headers.get('Cache-Control')).toBe('no-store');
});

it('shows a stable proxy link after signing in with only the password binding', async () => {
  const p = 'unbound-dashboard-example-password';
  const env = { p };
  const signIn = await worker.fetch(new Request(ORIGIN + '/admin', {
    method: 'POST', body: new URLSearchParams({ password: p }), headers: { Origin: ORIGIN },
  }), env);
  expect(signIn.status).toBe(303);
  expect(signIn.headers.get('Location')).toBe('/admin');
  const cookie = signIn.headers.get('Set-Cookie').split(';', 1)[0];
  const admin = await worker.fetch(new Request(ORIGIN + '/admin', { headers: { Cookie: cookie } }), env);
  const html = await admin.text();
  const proxyKey = /&amp;secret=([\da-f]{32})/.exec(html)?.[1];
  expect(proxyKey).toBeTruthy();
  expect(html).not.toContain(p);

  const salt = Buffer.from('cf-tgproxy-dashboard-v1\0' + HOST);
  const input = await crypto.subtle.importKey('raw', new TextEncoder().encode(p), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', iterations: 16000, salt }, input, 256);
  const expected = await configuration({ PROXY_SEED: Buffer.from(bits).toString('hex') }, HOST);
  expect(proxyKey).toBe(expected.secret);
  const rotated = { p: 'another-unbound-example-password' };
  expect((await configuration(rotated, HOST)).secret).not.toBe(proxyKey);
  expect((await configuration(env, HOST)).secret).toBe(proxyKey);
  expect((await configuration(env, 'other.example.com')).secret).not.toBe(proxyKey);
  const mac = await crypto.subtle.sign('HMAC', await crypto.subtle.importKey('raw',
    Buffer.from(proxyKey, 'hex'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']),
    new TextEncoder().encode('tdesktop-web-proxy-bridge-v1\n' + HOST));
  const bridge = await worker.fetch(new Request(ORIGIN + '/?bridge=' + Buffer.from(mac).toString('base64url')), env);
  expect(bridge.status).toBe(200);
});

it('signs in with only a password when the Worker source has been prepared for the dashboard', async () => {
  const source = readFileSync(new URL('../telegram_webproxy.js', import.meta.url), 'utf8');
  const prepared = source.replace("const dashboardSeed = '';", "const dashboardSeed = '" + ENV.PORTAL_KEY + "';");
  expect(prepared).not.toBe(source);
  const { default: dashboard, configuration: dashboardConfiguration } =
    await import(/* @vite-ignore */ 'data:text/javascript;base64,' + Buffer.from(prepared).toString('base64'));
  const p = 'dashboard-only-password';
  const env = { p };
  const login = await dashboard.fetch(new Request(ORIGIN + '/admin', {
    method: 'POST', body: new URLSearchParams({ password: p }), headers: { Origin: ORIGIN },
  }), env);
  expect(login.status).toBe(303);
  const cookie = login.headers.get('Set-Cookie').split(';', 1)[0];
  const admin = await dashboard.fetch(new Request(ORIGIN + '/admin', { headers: { Cookie: cookie } }), env);
  const body = await admin.text();
  expect(body).toContain(PROXY_SECRET);
  expect(body).not.toContain(ENV.PORTAL_KEY);
  expect((await dashboardConfiguration({ p: 'rotated-dashboard-password' }, HOST)).secret).toBe(PROXY_SECRET);
  expect((await dashboard.fetch(new Request(ORIGIN + '/?bridge=' + VECTOR), env)).status).toBe(200);
  expect((await dashboard.fetch(new Request(ORIGIN + '/?bridge=' + VECTOR), {})).status).toBe(404);
});

it('lets the first login retry after a temporary storage error', async () => {
  const password = 'temporary-storage-test-password';
  const fetchSeed = vi.fn()
    .mockRejectedValueOnce(new Error('storage unavailable'))
    .mockResolvedValueOnce(new Response(ENV.PORTAL_KEY));
  const env = {
    p: password,
    PROXY_STATE: {
      idFromName: () => 'retry-test-storage',
      get: () => ({ fetch: fetchSeed }),
    },
  };
  const login = () => worker.fetch(new Request(ORIGIN + '/admin', {
    method: 'POST',
    headers: { Origin: ORIGIN, 'CF-Connecting-IP': '192.0.2.70' },
    body: new URLSearchParams({ password }),
  }), env);
  const unavailable = await login();
  expect(unavailable.status).toBe(503);
  expect(unavailable.headers.get('Set-Cookie')).toBeNull();
  expect(await unavailable.text()).toContain('<form action="/admin" method="post">');
  const signedIn = await login();
  expect(signedIn.status).toBe(303);
  expect(signedIn.headers.get('Set-Cookie')).toContain('Path=/admin');
  expect(fetchSeed).toHaveBeenCalledTimes(2);
});

afterEach(() => vi.restoreAllMocks());

it.each([15, 16, 17])('applies the p length boundary and expires admin cookies (%i)', async length => {
  const origin = 'https://password-boundary.example.com';
  const env = { p: 'a'.repeat(length) };
  const clock = vi.spyOn(Date, 'now').mockReturnValue(1_790_000_000_000);
  const login = await worker.fetch(new Request(origin + '/admin', {
    method: 'POST', headers: { Origin: origin, 'CF-Connecting-IP': '192.0.2.90' },
    body: new URLSearchParams({ password: env.p }),
  }), env);
  if (length < 16) {
    expect(login.status).toBe(404);
    return;
  }
  expect(login.status).toBe(303);
  const Cookie = login.headers.get('Set-Cookie').split(';', 1)[0];
  const manage = async () => (await worker.fetch(new Request(origin + '/admin', { headers: { Cookie } }), env)).text();
  clock.mockReturnValue(1_790_001_799_000);
  expect(await manage()).toContain('tg://webproxy');
  clock.mockReturnValue(1_790_001_800_000);
  expect(await manage()).not.toContain('tg://webproxy');
});

it('shares password derivation per host and evicts a rejected crypto result', async () => {
  const derive = vi.spyOn(crypto.subtle, 'deriveBits');
  const config = { p: 'synthetic-concurrent-configuration' };
  const host = 'concurrent.example.com';
  const concurrent = await Promise.all(Array.from({ length: 8 }, () => configuration(config, host)));
  expect(new Set(concurrent).size).toBe(1);
  expect(derive.mock.calls.map(([algorithm]) => algorithm.name)).toEqual(['PBKDF2', 'HKDF', 'HKDF']);
  const alternate = await configuration(config, 'alternate.example.com');
  expect(alternate.secret).not.toBe(concurrent[0].secret);
  expect(await configuration(config, host)).toBe(concurrent[0]);

  const rotated = { p: 'synthetic-rotated-configuration' };
  derive.mockRejectedValueOnce(new Error('synthetic crypto failure'));
  const failed = await Promise.allSettled([configuration(rotated, host), configuration(rotated, host)]);
  expect(failed.map(result => result.status)).toEqual(['rejected', 'rejected']);
  const replacement = await configuration(rotated, host);
  expect(replacement.secret).not.toBe(concurrent[0].secret);
  expect((await configuration(config, host)).secret).toBe(concurrent[0].secret);
});

it('rederives the same host-specific keys after cache eviction', async () => {
  const env = { p: 'synthetic-cache-eviction' };
  const host = 'evicted.example.com';
  const before = await configuration(env, host);
  for (let index = 0; index < 8; index++) await configuration(env, `new-${index}.example.com`);
  const derive = vi.spyOn(crypto.subtle, 'deriveBits');
  const restored = await configuration(env, host);
  expect(restored).not.toBe(before);
  expect(restored.secret).toBe(before.secret);
  expect(derive.mock.calls.map(([algorithm]) => algorithm.name)).toEqual(['PBKDF2', 'HKDF', 'HKDF']);
  expect(await configuration(env, host)).toBe(restored);
  expect(derive).toHaveBeenCalledTimes(3);
});

describe('MTProto and WEB Proxy wire formats', () => {
  it.each([
    ['000102030405060708090a0b0c0d0e0f', 'MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk'],
    ['dd000102030405060708090a0b0c0d0e0f', 'IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA'],
  ])('matches the official Bridge vector for %s', async (key, result) => {
    const bridgeKey = await crypto.subtle.importKey(
      'raw', Buffer.from(key, 'hex'), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'],
    );
    expect(await verifyBridge(bridgeKey, HOST, result)).toBe(true);
    expect(await verifyBridge(bridgeKey, 'other.example.com', result)).toBe(false);
  });

  it('matches independent AES-CTR with deterministic random partitions and NIST material', async () => {
    const key = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex');
    const counter = Buffer.from('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', 'hex');
    const input = Buffer.from('6bc1bee22e409f96e93d7e117393172a', 'hex');
    expect(Buffer.from(await createCTR(key, new Uint8Array(counter))(input)).toString('hex'))
      .toBe('874d6191b620e3261bef6864990db6ce');
    const draw = synthetic(0x469af2ee);
    for (let trial = 0; trial < 20; trial++) {
      const key256 = Uint8Array.from({ length: 32 }, () => draw(256));
      const iv = Uint8Array.from({ length: 16 }, (_, i) => i >= 12 ? 255 : draw(256));
      const data = Uint8Array.from({ length: 1500 + draw(6000) }, () => draw(256));
      const expected = createCipheriv('aes-256-ctr', key256, iv).update(data);
      const crypt = createCTR(key256, iv);
      const chunks = [];
      for (let o = 0; o < data.length;) {
        const n = 1 + draw(trial < 10 ? 16 : 1000);
        chunks.push(await crypt(data.subarray(o, o + n)));
        o += n;
      }
      expect(Buffer.concat(chunks)).toEqual(expected);
    }
  });

  it('rejects concurrent CTR use and counter wrap without losing a final partial block', async () => {
    const iv = new Uint8Array(16).fill(255);
    const key = new Uint8Array(32);
    const crypt = createCTR(key, iv);
    const first = crypt(Uint8Array.of(1));
    await expect(crypt(Uint8Array.of(2))).rejects.toThrow('concurrent');
    const expected = createCipheriv('aes-256-ctr', key, iv).update(Buffer.alloc(16, 1));
    const tail = await cryptAfter(first, crypt, expected);
    expect(tail).toEqual(expected);
    await expect(crypt(Uint8Array.of(1))).rejects.toThrow('exhausted');
    const finalBlock = createCTR(key, iv);
    await expect(finalBlock(new Uint8Array(17))).rejects.toThrow('exhausted');
    expect(Buffer.from(await finalBlock(Buffer.alloc(16, 1)))).toEqual(expected);
    const carry = Uint8Array.of(0x7e, 0xff, 0xff, 0xff, 0xff);
    expect(advanceCounter(carry, 0x10002)).toBe(false);
    expect([...carry]).toEqual([0x7f, 0, 1, 0, 1]);
  });

  it('reuses only private CTR padding between independent downlink ciphers', async () => {
    const upstreamKey = new Uint8Array(32).fill(31);
    const clientKey = new Uint8Array(32).fill(53);
    const upstreamCounter = new Uint8Array(16).fill(255, 11);
    const clientCounter = new Uint8Array(16).fill(127, 0, 11).fill(255, 11);
    const upstream = createCipheriv('aes-256-ctr', upstreamKey, upstreamCounter);
    const expectedClient = createCipheriv('aes-256-ctr', clientKey, clientCounter);
    const decode = createCTR(upstreamKey, upstreamCounter);
    const encode = createCTR(clientKey, clientCounter);
    const encrypt = vi.spyOn(crypto.subtle, 'encrypt');
    let reused = 0;
    for (const size of [1, 14, 3, 341, 65535, 524287, 65536, 2, 1024]) {
      const original = Buffer.alloc(size, size % 251);
      const plain = await decode(upstream.update(original));
      const previous = encrypt.mock.calls.length;
      const output = await encode(plain, true);
      if (encrypt.mock.calls.length > previous && plain.buffer.byteLength > plain.length) {
        expect(encrypt.mock.lastCall[2].buffer).toBe(plain.buffer);
        reused++;
      }
      expect(Buffer.from(plain)).toEqual(original);
      expect(Buffer.from(output)).toEqual(expectedClient.update(original));
    }
    expect(reused).toBeGreaterThan(3);
  });

  it('observes a failed prewarmed key import even before its first use', async () => {
    const failed = new Error('synthetic key import failure');
    vi.spyOn(crypto.subtle, 'importKey').mockRejectedValueOnce(failed);
    const crypt = createCTR(new Uint8Array(32), new Uint8Array(16));
    await new Promise(resolve => setTimeout(resolve, 0));
    await expect(crypt(Uint8Array.of(1))).rejects.toBe(failed);
  });

  it.each([0xef, 0xee, 0xdd])('preserves mode 0x%s and signed DC, with valid framing', mode => {
    const head = makeHead({ mode, dc: 5, media: true });
    expect(readHead(head)).toEqual({ mode, dc: 5, media: true });
    new DataView(head.buffer).setInt16(60, -6, true);
    expect(() => readHead(head)).toThrow('obfuscation');
    const p = packet(Buffer.alloc(512), mode, true);
    expect(packetSize(p, 0, mode)).toBe(p.length);
    expect(packetSize(p.subarray(0, 2), 0, mode)).toBe(0);
    expect(() => packetSize(new Uint8Array(4), 0, mode)).toThrow('packet');
  });

  it('decodes unsigned IDs, multiple frames and offsets, rejecting truncated or oversized input', () => {
    const frames = [];
    const capture = (type, id, data, start, end) => frames.push([type, id, [...data.subarray(start, end)]]);
    const stream = Buffer.concat([encodeFrame(1, 0xffffff), encodeFrame(2, 0xffffff, Uint8Array.of(255, 0))]);
    visitFrames(stream, capture);
    expect(frames).toEqual([[1, 0xffffff, []], [2, 0xffffff, [255, 0]]]);
    for (const malformed of [stream.subarray(0, -1), 'string', new Uint8Array(2097153), new Uint8Array(8 * 4097)]) {
      expect(() => visitFrames(malformed, () => {})).toThrow('frame');
    }
    const large = encodeFrame(2, 1, new Uint8Array(1048577));
    expect(() => visitFrames(large, () => {})).toThrow('frame');
  });
});

async function cryptAfter(first, crypt) {
  const a = await first;
  const b = await crypt(Buffer.alloc(15, 1));
  return Buffer.concat([a, b]);
}

describe('carrier authentication', () => {
  it('rejects malformed carrier headers before deriving the cold host key', async () => {
    const cfg = await configuration(ENV, HOST);
    const expires = Math.floor(Date.now() / 1000) + 60;
    const boot = await issueToken(cfg, HOST, 1, expires, new Uint8Array(12));
    const ticket = await issueToken(cfg, HOST, 2, expires, new Uint8Array(12));
    const cold = 'https://cold-headers.example.com';
    const env = { p: 'synthetic-cold-headers-password' };
    const derive = vi.spyOn(crypto.subtle, 'deriveBits');
    for (const request of [
      new Request(cold + '/api/v1/session', {
        method: 'POST', headers: { Authorization: 'Bearer ' + boot, 'Content-Type': 'text/plain' }, body: HELLO,
      }),
      new Request(cold + '/api/v1/session', {
        method: 'POST', headers: { Authorization: 'Bearer ' + boot, 'Content-Type': 'application/octet-stream', 'Content-Length': '1000' }, body: HELLO,
      }),
      new Request(cold + '/api/v1/ws', {
        headers: { Upgrade: 'websocket', 'Sec-WebSocket-Version': '12', 'Sec-WebSocket-Protocol': 'tproxy-lane-v1.' + ticket + '.1' },
      }),
    ]) {
      const response = await worker.fetch(request, env);
      expect(response.status).toBe(404);
      expect(await response.text()).toBe('');
    }
    expect(derive).not.toHaveBeenCalled();
  });

  it('protects the portal and separates it from Bridge authentication', async () => {
    const login = await worker.fetch(new Request(ORIGIN + '/admin', {
      method: 'POST', headers: { Origin: ORIGIN, 'CF-Connecting-IP': '192.0.2.71' },
      body: new URLSearchParams({ password: ENV.p }),
    }), ENV);
    expect(login.status).toBe(303);
    const cookie = login.headers.get('Set-Cookie').split(';', 1)[0];
    const response = await worker.fetch(new Request(ORIGIN + '/admin', { headers: { Cookie: cookie } }), ENV);
    const html = await response.text();
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('referrer-policy')).toBe('same-origin');
    expect(response.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    expect(html).toContain('tg://webproxy?server=proxy.example.com&amp;secret=' + PROXY_SECRET);
    expect(html).not.toContain('382abaf798ad5db247fdccdb3fd6521d8c99ced045d85ff689a997a6a4baec88');
    expect(html).not.toContain(ENV.PORTAL_KEY);
    expect(html).not.toContain('当前实例诊断');
    const diagnostic = new Request(ORIGIN + '/admin?diagnostics=1', {
      headers: { Cookie: cookie, 'cf-placement': 'remote-NRT' },
    });
    Object.defineProperty(diagnostic, 'cf', { value: { colo: 'HKG', clientTcpRtt: 42 } });
    const debug = await worker.fetch(diagnostic, ENV);
    const details = await debug.text();
    expect(details).toContain('当前实例诊断');
    expect(details).toContain('接入机房（colo）</dt><dd>HKG');
    expect(details).not.toContain('remote-NRT');
    expect(details).toContain('应用缓冲当前 / 峰值');
    expect(details).toContain('客户端到 Cloudflare RTT</dt><dd>42 ms');
    expect(details).toContain('代理升级请求的入口 RTT');
    expect(details).toContain('Telegram KWS 握手成功');
    const head = await worker.fetch(new Request(ORIGIN + '/admin', { method: 'HEAD', headers: { Cookie: cookie } }), ENV);
    expect(await head.text()).toBe('');
    const bridge = await worker.fetch(new Request(ORIGIN + '/?bridge=' + VECTOR), ENV);
    expect(await bridge.text()).not.toContain(PROXY_SECRET);
    expect(bridge.headers.get('content-security-policy')).toContain('wss://' + HOST);
  });

  it('serves a neutral public homepage with or without the access code', async () => {
    for (const env of [{}, ENV]) {
      const home = await worker.fetch(new Request(ORIGIN), env);
      expect(home.status).toBe(200);
      expect(home.headers.get('cache-control')).toBe('no-store');
      expect(home.headers.get('content-type')).toContain('text/html');
      expect(home.headers.get('permissions-policy')).toContain('clipboard-write=()');
      const html = await home.text();
      const nonce = /<style nonce="([^"]+)">/.exec(html)?.[1];
      const policy = home.headers.get('content-security-policy');
      expect(nonce).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(policy).toContain("default-src 'none'");
      expect(policy).toContain("frame-ancestors 'none'");
      expect(policy).toContain("style-src 'nonce-" + nonce + "'");
      expect(policy).not.toContain('unsafe-inline');
      expect(html).toContain('Welcome to nginx!');
      expect(html).not.toMatch(/Telegram|密钥|<script|webproxy|PORTAL_KEY/i);
      expect(html).not.toContain(ENV.PORTAL_KEY);
      expect(html).not.toContain(PROXY_SECRET);
    }

    const head = await worker.fetch(new Request(ORIGIN, { method: 'HEAD' }), {});
    expect(head.status).toBe(200);
    expect(await head.text()).toBe('');
    const post = await worker.fetch(new Request(ORIGIN, { method: 'POST' }), {});
    expect(post.status).toBe(404);
    const withoutSecrets = await worker.fetch(new Request(ORIGIN + '/?bridge=' + VECTOR), {});
    expect(withoutSecrets.status).toBe(404);
  });

  it('returns a uniform empty response to unknown and unauthenticated requests', async () => {
    for (const url of ['/?unrecognized=1', '/?bridge=invalid', '/health', '/api/v1/session', '/' + ENV.PORTAL_KEY + '?foo=1', '/?bridge=' + VECTOR + '&x=1',
      '/prefix/?bridge=' + VECTOR, '/?bridge=' + VECTOR.slice(0, -1) + 'A', '/' + '0'.repeat(64)]) {
      const response = await worker.fetch(new Request(ORIGIN + url), ENV);
      expect(response.status).toBe(404);
      expect(await response.text()).toBe('');
      expect(response.headers.get('cache-control')).toBe('no-store');
    }
    const imports = vi.spyOn(crypto.subtle, 'importKey');
    const invalid = new Request('https://cold.example.com/' + '0'.repeat(64));
    expect((await worker.fetch(invalid, ENV)).status).toBe(404);
    expect(imports).not.toHaveBeenCalled();
    imports.mockRestore();
    for (const url of ['https://192.0.2.1/', 'http://' + HOST + '/', ORIGIN + ':8443/']) {
      expect((await worker.fetch(new Request(url + ENV.PORTAL_KEY), ENV)).status).toBe(404);
    }
  });

  it('keeps saved seeds compatible with valid p and rejects invalid seeds', async () => {
    for (const bad of [{}, { PORTAL_KEY: '' }, { PORTAL_KEY: 'short' },
      { PORTAL_KEY: ENV.PORTAL_KEY + ' ' }, { PORTAL_KEY: 'z'.repeat(64) }]) {
      expect(await configuration(bad, HOST)).toBeNull();
      expect((await worker.fetch(new Request(ORIGIN + '/?bridge=' + VECTOR), bad)).status).toBe(404);
    }
    const cfg = await configuration(ENV, HOST);
    expect(cfg.secret).toBe(PROXY_SECRET);
    expect((await configuration(ENV, 'other.example.com')).secret).not.toBe(PROXY_SECRET);
    expect((await configuration({ PORTAL_KEY: ENV.PORTAL_KEY.toUpperCase() }, HOST)).secret).toBe(PROXY_SECRET);
    const rotated = { ...ENV, PORTAL_KEY: 'a3' + ENV.PORTAL_KEY.slice(2) };
    expect((await configuration(rotated, HOST)).secret).not.toBe(PROXY_SECRET);
    expect((await worker.fetch(new Request(ORIGIN + '/?bridge=' + VECTOR), rotated)).status).toBe(404);
  });

  it('rejects real capabilities and tickets when p is missing or invalid', async () => {
    const boot = await bridgeBoot(worker);
    const session = await worker.fetch(authRequest('/api/v1/session', boot, HELLO), ENV);
    expect(session.status).toBe(200);
    const ticket = session.headers.get('X-Session-Token');
    const renewal = session.headers.get('X-Session-Renewal');
    const derive = vi.spyOn(crypto.subtle, 'deriveBits');
    for (const env of [
      { PORTAL_KEY: ENV.PORTAL_KEY },
      { PORTAL_KEY: ENV.PORTAL_KEY, PORTAL_PASSWORD: ENV.p },
      { PROXY_SEED: ENV.PORTAL_KEY, p: ENV.p.slice(0, 15) },
      { PROXY_SEED: ENV.PORTAL_KEY, p: '界'.repeat(86) },
    ]) {
      for (const request of [
        new Request(ORIGIN + '/admin'),
        new Request(ORIGIN + '/?bridge=' + VECTOR),
        authRequest('/api/v1/session', boot, HELLO),
        authRequest('/api/v1/session', ticket, null, 'DELETE'),
        authRequest('/api/v1/session/renew', renewal),
        new Request(ORIGIN + '/api/v1/ws', { headers: {
          Upgrade: 'websocket', 'Sec-WebSocket-Protocol': 'tproxy-lane-v1.' + ticket + '.1',
        } }),
      ]) {
        const response = await worker.fetch(request, env);
        expect(response.status).toBe(404);
        expect(await response.text()).toBe('');
      }
    }
    expect(derive).not.toHaveBeenCalled();
  });

  it('rejects raw keys, wrong purpose, expired, forged and cross-host credentials', async () => {
    const cfg = await configuration(ENV, HOST);
    const expires = Math.floor(Date.now() / 1000) + 60;
    const good = await issueToken(cfg, HOST, 1, expires, new Uint8Array(12));
    expect((await verifyToken(cfg, HOST, 1, good, expires - 1)).expires).toBe(expires);
    expect(await verifyToken(cfg, HOST, 1, good, expires)).toBeNull();
    expect(await verifyToken(cfg, HOST, 2, good)).toBeNull();
    expect(await verifyToken(cfg, 'other.example.com', 1, good)).toBeNull();
    expect(await verifyToken(cfg, HOST, 1, good.slice(0, -3) + 'zzz')).toBeNull();
    const rotated = await configuration({ PORTAL_KEY: 'a3' + ENV.PORTAL_KEY.slice(2) }, HOST);
    expect(await verifyToken(rotated, HOST, 1, good)).toBeNull();
    for (const token of [ENV.PORTAL_KEY, PROXY_SECRET, '382abaf798ad5db247fdccdb3fd6521d8c99ced045d85ff689a997a6a4baec88', VECTOR]) {
      expect((await worker.fetch(authRequest('/api/v1/session', token, HELLO), ENV)).status).toBe(404);
    }
  });

  it('makes byte-identical HELLO retries deterministic, and renews after a lane ticket expires', async () => {
    const clock = vi.spyOn(Date, 'now');
    const start = Date.now();
    clock.mockReturnValue(start);
    const boot = await bridgeBoot(worker);
    const create = () => worker.fetch(authRequest('/api/v1/session', boot, HELLO), ENV);
    const [a, b] = await Promise.all([create(), create()]);
    expect(a.status).toBe(200);
    const ticket = a.headers.get('x-session-token');
    const grant = a.headers.get('x-session-renewal');
    expect(b.headers.get('x-session-token')).toBe(ticket);
    expect(b.headers.get('x-session-renewal')).toBe(grant);
    expect([...new Uint8Array(await a.arrayBuffer())]).toEqual([17, 0, 0, 0, 0, 0, 0, 0]);
    expect(a.headers.get('x-down-cursor')).toBe('0');
    clock.mockReturnValue(start + 301000);
    expect((await create()).status).toBe(404);
    expect(await verifyToken(await configuration(ENV, HOST), HOST, 2, ticket)).toBeNull();
    const renew = await worker.fetch(authRequest('/api/v1/session/renew', grant), ENV);
    expect(renew.status).toBe(204);
    const renewed = renew.headers.get('x-session-token');
    expect(renewed).not.toBe(ticket);
    expect(await verifyToken(await configuration(ENV, HOST), HOST, 2, renewed)).toBeTruthy();
    const deleted = await worker.fetch(authRequest('/api/v1/session', renewed, null, 'DELETE'), ENV);
    expect(deleted.status).toBe(204);
    expect((await worker.fetch(authRequest('/api/v1/session/renew', grant), ENV)).status).toBe(404);
    clock.mockReturnValue(start + 13 * 3600_000);
    expect((await worker.fetch(authRequest('/api/v1/session/renew', grant), ENV)).status).toBe(404);
  });

  it('validates a grant in a fresh isolate and refuses it at the absolute parent deadline', async () => {
    const start = 1_791_000_000_000;
    const clock = vi.spyOn(Date, 'now').mockReturnValue(start);
    const boot = await bridgeBoot(worker);
    const create = (instance, token) => instance.fetch(authRequest('/api/v1/session', token, HELLO), ENV);
    const initial = await create(worker, boot);
    expect(initial.status).toBe(200);
    const grant = initial.headers.get('X-Session-Renewal');
    const source = readFileSync(new URL('../telegram_webproxy.js', import.meta.url));
    const url = 'data:text/javascript;base64,' + source.toString('base64');
    const { default: fresh, configuration: cfg } = await import(/* @vite-ignore */ url + '#fresh-isolate');
    const renew = () => fresh.fetch(authRequest('/api/v1/session/renew', grant), ENV);
    const deadline = start + (120 + 12 * 3600) * 1000;
    clock.mockReturnValue(deadline - 1000);
    const last = await renew();
    expect(last.status).toBe(204);
    expect(last.headers.get('X-Session-TTL')).toBe('1');
    const ticket = last.headers.get('X-Session-Token');
    const keys = await cfg(ENV, HOST);
    expect(await verifyToken(keys, HOST, 2, ticket)).toBeTruthy();
    clock.mockReturnValue(deadline);
    expect((await renew()).status).toBe(404);
    expect(await verifyToken(keys, HOST, 2, ticket)).toBeNull();
    clock.mockReturnValue(deadline + 1000);
    expect((await renew()).status).toBe(404);
    expect((await create(fresh, boot)).status).toBe(404);
    const replacement = await create(fresh, await bridgeBoot(fresh));
    expect(replacement.status).toBe(200);
    expect(replacement.headers.get('X-Session-Renewal')).not.toBe(grant);
  });

  it('rejects a renewal whose ticket finishes signing after the parent expires', async () => {
    const start = 1_792_000_000_000;
    const clock = vi.spyOn(Date, 'now').mockReturnValue(start);
    const boot = await bridgeBoot(worker);
    const session = await worker.fetch(authRequest('/api/v1/session', boot, HELLO), ENV);
    expect(session.status).toBe(200);
    const grant = session.headers.get('X-Session-Renewal');
    const deadline = start + (120 + 12 * 3600) * 1000;
    clock.mockReturnValue(deadline - 1000);
    const nativeSign = crypto.subtle.sign.bind(crypto.subtle);
    let signs = 0;
    vi.spyOn(crypto.subtle, 'sign').mockImplementation(async (...args) => {
      const signed = await nativeSign(...args);
      if (++signs === 2) clock.mockReturnValue(deadline);
      return signed;
    });
    const response = await worker.fetch(authRequest('/api/v1/session/renew', grant), ENV);
    expect(signs).toBe(2);
    expect(response.status).toBe(404);
    expect(response.headers.has('X-Session-Token')).toBe(false);
  });

  it('bounds HELLO buffers and rejects cookies, incompatible origins, invalid bodies and query strings', async () => {
    const boot = await bridgeBoot(worker);
    for (const [body, headers] of [[new Uint8Array(10), {}], [new Uint8Array(9), {}],
      [HELLO, { Origin: 'https://different.example' }], [HELLO, { Cookie: 'a=b' }],
      [HELLO, { 'Content-Type': 'text/plain' }], [HELLO, { 'Content-Length': '2000' }]]) {
      const request = new Request(ORIGIN + '/api/v1/session', { method: 'POST', body, headers: {
        'Content-Type': 'application/octet-stream', Authorization: 'Bearer ' + boot, ...headers,
      } });
      expect((await worker.fetch(request, ENV)).status).toBe(404);
    }
    expect((await worker.fetch(authRequest('/api/v1/session?x=1', boot, HELLO), ENV)).status).toBe(404);
  });
});
