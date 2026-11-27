import { expect, it, vi } from 'vitest';
import { env as bindings } from 'cloudflare:workers';
import worker, { encodeFrame, visitFrames } from '../telegram_webproxy.js';

const base = 'https://proxy.example.com';
const env = {
  p: 'synthetic-case-1',
  PORTAL_KEY: '29ea5f6692816233fd6716b5728035fe30349835161228520064a5015a2a50af',
};
const HELLO = Uint8Array.of(16, 0, 0, 0, 0, 0, 0, 1, 1);
const VECTOR = 'cF3iQgotmFPcdnqmM642-vNpdfk-WLl8e50OXWBuxBQ';
const PROXY_SECRET = 'f7113e191685fefc9ae763a6d4e77c1f';

it('bootstraps one persistent key on the first successful login with only a password', async () => {
  const password = 'test-login-password';
  const configuration = { p: password, PROXY_STATE: bindings.PROXY_STATE };
  const seedEndpoint = 'https://seed.internal/';
  const seedStore = bindings.PROXY_STATE.getByName('deployment');
  const signIn = (config, submitted = config.p) => worker.fetch(new Request(base + '/admin', {
    method: 'POST',
    headers: { Origin: base, 'CF-Connecting-IP': '192.0.2.8' },
    body: new URLSearchParams({ password: submitted }),
  }), config);
  const manage = (config, cookie) => worker.fetch(new Request(base + '/admin', {
    headers: { Cookie: cookie },
  }), config);

  expect((await seedStore.fetch(seedEndpoint)).status).toBe(404);
  expect((await signIn(configuration, 'wrong password')).status).toBe(401);
  expect((await worker.fetch(new Request(base + '/?bridge=' + VECTOR), configuration)).status).toBe(404);
  expect((await seedStore.fetch(seedEndpoint)).status).toBe(404);

  const [first, concurrent] = await Promise.all([signIn(configuration), signIn(configuration)]);
  const seed = await (await seedStore.fetch(seedEndpoint)).text();
  expect(seed).toMatch(/^[a-f0-9]{64}$/);
  let secret;
  for (const response of [first, concurrent]) {
    expect(response.status).toBe(303);
    expect(response.headers.get('Location')).toBe('/admin');
    const cookie = response.headers.get('Set-Cookie').split(';', 1)[0];
    const portal = await manage(configuration, cookie);
    expect(portal.status).toBe(200);
    const html = await portal.text();
    const proposed = /&amp;secret=([a-f0-9]{32})/.exec(html)?.[1];
    expect(proposed).toBeTruthy();
    expect(html).not.toContain(seed);
    secret ??= proposed;
    expect(proposed).toBe(secret);
  }

  const changedPassword = { ...configuration, p: 'new-test-login-password' };
  const oldCookie = first.headers.get('Set-Cookie').split(';', 1)[0];
  const expired = await (await manage(changedPassword, oldCookie)).text();
  expect(expired).toContain('<form action="/admin" method="post">');
  expect(expired).not.toContain('tg://');
  const next = await signIn(changedPassword);
  const newCookie = next.headers.get('Set-Cookie').split(';', 1)[0];
  expect(await (await manage(changedPassword, newCookie)).text()).toContain(secret);
  expect(await (await seedStore.fetch(seedEndpoint)).text()).toBe(seed);

  const proxyKey = Uint8Array.from(secret.match(/../g), byte => Number.parseInt(byte, 16));
  const key = await crypto.subtle.importKey('raw', proxyKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const challenge = new TextEncoder().encode('tdesktop-web-proxy-bridge-v1\nproxy.example.com');
  const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, challenge));
  const capability = btoa(String.fromCharCode(...digest)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  const bridge = await worker.fetch(new Request(base + '/?bridge=' + capability), changedPassword);
  expect(bridge.status).toBe(200);
  expect(await bridge.text()).toContain('"ticket":');
});

async function create(inline = false) {
  const bridge = await worker.fetch(new Request(base + '/?bridge=' + VECTOR), env);
  expect(bridge.status).toBe(200);
  const page = await bridge.text();
  if (inline) {
    const ticket = /"ticket":"([A-Za-z0-9_-]{43})"/.exec(page)?.[1];
    expect(ticket).toBeTruthy();
    return ticket;
  }
  const boot = /,"([A-Za-z0-9_-]{43})"\);<\/script>/.exec(page)?.[1];
  const result = await worker.fetch(new Request(base + '/api/v1/session', {
    method: 'POST', body: HELLO, headers: {
      Authorization: 'Bearer ' + boot, 'Content-Type': 'application/octet-stream',
    },
  }), env);
  expect(result.status).toBe(200);
  return result.headers.get('X-Session-Token');
}

it('signs in, serves concurrent Bridges and upgrades using only the password in workerd', async () => {
  const host = 'dashboard.example.com';
  const origin = 'https://' + host;
  const configuration = { p: 'synthetic-dashboard-password' };
  // Password-only vector derived independently with Node's PBKDF2/HKDF.
  const capability = '2w8TO5ICl4qQE8JmSUukADb63tfkZGdvlFne8wHXdbk';
  const request = () => new Request(origin + '/?bridge=' + capability);
  const bridges = await Promise.all(Array.from({ length: 4 }, () => worker.fetch(request(), configuration)));
  expect(bridges.map(response => response.status)).toEqual([200, 200, 200, 200]);
  const login = await worker.fetch(new Request(origin + '/admin', {
    method: 'POST', headers: { Origin: origin },
    body: new URLSearchParams({ password: configuration.p }),
  }), configuration);
  expect(login.status).toBe(303);
  const page = await worker.fetch(new Request(origin + '/admin', {
    headers: { Cookie: login.headers.get('Set-Cookie').split(';', 1)[0] },
  }), configuration);
  expect(await page.text()).toContain('&amp;secret=cff9db686d249771b43ec0b598ce8982');
  const ticket = /"ticket":"([A-Za-z0-9_-]{43})"/.exec(await bridges[0].text())[1];
  const protocol = 'tproxy-lane-v1.' + ticket + '.1';
  const upgrade = await worker.fetch(new Request(origin + '/api/v1/ws', {
    headers: { Upgrade: 'websocket', 'Sec-WebSocket-Protocol': protocol },
  }), configuration);
  expect(upgrade.status).toBe(101);
  expect(upgrade.headers.get('Sec-WebSocket-Protocol')).toBe(protocol);
  const socket = upgrade.webSocket;
  socket.accept();
  socket.close();
});

function open(token, sid, origin = base) {
  return worker.fetch(new Request(base + '/api/v1/ws', { headers: {
    Upgrade: 'websocket', Origin: origin, 'Sec-WebSocket-Protocol': 'tproxy-lane-v1.' + token + '.' + sid,
  } }), env);
}

async function adminCookie() {
  const login = await worker.fetch(new Request(base + '/admin', {
    method: 'POST', headers: { Origin: base, 'CF-Connecting-IP': '192.0.2.33' },
    body: new URLSearchParams({ password: env.p }),
  }), env);
  expect(login.status).toBe(303);
  return login.headers.get('Set-Cookie').split(';', 1)[0];
}

it('loads the single module under workerd and authenticates portal, Bridge and the lane upgrade', async () => {
  const home = await worker.fetch(new Request(base), {});
  expect(home.status).toBe(200);
  expect(await home.text()).toContain('Welcome to nginx!');
  expect((await worker.fetch(new Request(base + '/' + env.PORTAL_KEY), {})).status).toBe(404);
  expect((await worker.fetch(new Request(base + '/' + env.PORTAL_KEY), env)).status).toBe(404);
  expect((await worker.fetch(new Request(base + '/?bridge=' + VECTOR), { PORTAL_KEY: env.PORTAL_KEY })).status).toBe(404);
  const admin = await worker.fetch(new Request(base + '/admin', { headers: { Cookie: await adminCookie() } }), env);
  expect(await admin.text()).toContain(PROXY_SECRET);
  const ticket = await create(true);
  expect((await open(ticket, 9, 'https://other.example.com')).status).toBe(404);
  expect((await open(ticket, '09')).status).toBe(404);
  const upgrade = await open(ticket, 9);
  expect(upgrade.status).toBe(101);
  expect(upgrade.headers.get('sec-websocket-protocol')).toBe('tproxy-lane-v1.' + ticket + '.9');
  const socket = upgrade.webSocket;
  try {
    socket.binaryType = 'arraybuffer';
    socket.accept();
    expect(typeof socket.bufferedAmount).toBe('number');
    expect((await open(ticket, 9)).status).toBe(404);
    const shut = new Promise(resolve => socket.addEventListener('close', resolve, { once: true }));
    socket.send(encodeFrame(1, 9));
    socket.send(encodeFrame(2, 8, Uint8Array.of(255)));
    expect((await shut).code).toBe(1008);
  } finally {
    socket.close();
  }
});

it.each(['client', 'upstream'])('streams through real workerd sockets when the %s closes first', async closer => {
  const ticket = await create();
  const upstream = new WebSocketPair();
  upstream[1].binaryType = 'arraybuffer';
  upstream[1].accept();
  const firstPeerMessage = new Promise(resolve => upstream[1].addEventListener('message', resolve, { once: true }));
  const peerClosed = new Promise(resolve => upstream[1].addEventListener('close', resolve, { once: true }));
  const wsFetch = vi.fn(async () => new Response(null, {
    status: 101, webSocket: upstream[0], headers: { 'Sec-WebSocket-Protocol': 'binary' },
  }));
  vi.stubGlobal('fetch', wsFetch);
  const client = (await open(ticket, 20)).webSocket;
  try {
    client.binaryType = 'arraybuffer';
    client.accept();
    const clientClosed = new Promise(resolve => client.addEventListener('close', resolve, { once: true }));
    const head = Uint8Array.from({ length: 64 }, (_, i) => (i * 11 + 27) & 255);
    head.fill(0xdd, 56, 60);
    new DataView(head.buffer).setInt16(60, -3, true);
    const input = new Uint8Array(48);
    input.set(head.subarray(8, 40));
    input.set(Uint8Array.from(PROXY_SECRET.match(/../g), hex => Number.parseInt(hex, 16)), 32);
    const raw = await crypto.subtle.digest('SHA-256', input);
    const key = await crypto.subtle.importKey('raw', raw, 'AES-CTR', false, ['encrypt']);
    const wire = new Uint8Array(await crypto.subtle.encrypt({
      name: 'AES-CTR', counter: head.subarray(40, 56), length: 128,
    }, key, head));
    wire.set(head.subarray(0, 56));
    client.send(encodeFrame(1, 20));
    client.send(encodeFrame(2, 20, wire));
    const event = await firstPeerMessage;
    expect(event.data.byteLength).toBe(64);
    expect(wsFetch).toHaveBeenCalledTimes(1);
    expect(wsFetch.mock.calls[0][0]).toBe('https://kws3-1.web.telegram.org/apiws');

    const payload = Uint8Array.from({ length: 65571 }, (_, i) => i * 67 & 255);
    const peerMaterial = new Uint8Array(event.data).slice(8, 56).reverse();
    const peerKey = await crypto.subtle.importKey('raw', peerMaterial.subarray(0, 32), 'AES-CTR', false, ['encrypt']);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({
      name: 'AES-CTR', counter: peerMaterial.subarray(32), length: 128,
    }, peerKey, payload));
    const received = new Uint8Array(payload.length);
    let laneClosed = false;
    const delivered = new Promise(resolve => {
      let offset = 0;
      client.addEventListener('message', ({ data }) => visitFrames(data, (type, id, bytes, start, end) => {
        if (type === 3) laneClosed = true;
        if (type !== 2) return;
        received.set(bytes.subarray(start, end), offset);
        offset += end - start;
        if (offset === received.length) resolve();
      }));
    });
    upstream[1].send(ciphertext.subarray(0, 17));
    upstream[1].send(ciphertext.subarray(17));
    if (closer === 'upstream') upstream[1].close(1000);
    await delivered;
    const clientMaterial = head.slice(8, 56).reverse();
    input.set(clientMaterial.subarray(0, 32));
    const expectedKey = await crypto.subtle.importKey('raw', await crypto.subtle.digest('SHA-256', input), 'AES-CTR', false, ['encrypt']);
    const expected = await crypto.subtle.encrypt({
      name: 'AES-CTR', counter: clientMaterial.subarray(32), length: 128,
    }, expectedKey, payload);
    expect(received).toEqual(new Uint8Array(expected));
    const diagnostics = await worker.fetch(new Request(base + '/admin?diagnostics=1', {
      headers: { Cookie: await adminCookie() },
    }), env);
    const details = await diagnostics.text();
    expect(details).toMatch(/客户端 WebSocket 升级成功<\/dt><dd>\d+ 次，P95/);
    expect(details).toMatch(/Telegram KWS 握手成功<\/dt><dd>\d+ 次，P95/);
    expect(details).toContain('DC 3 · 媒体');
    if (closer === 'client') {
      client.close(1000);
      expect((await peerClosed).code).toBe(1000);
    } else {
      expect((await clientClosed).code).toBe(1000);
      expect(laneClosed).toBe(true);
    }
  } finally {
    vi.unstubAllGlobals();
    client.close();
    upstream[1].close();
  }
});


it('blocks new lanes after local DELETE and closes an existing lane at its next I/O', async () => {
  const ticket = await create();
  const connected = await open(ticket, 45);
  const socket = connected.webSocket;
  socket.accept();
  try {
    const deleted = await worker.fetch(new Request(base + '/api/v1/session', {
      method: 'DELETE', headers: { Authorization: 'Bearer ' + ticket },
    }), env);
    expect(deleted.status).toBe(204);
    expect((await open(ticket, 46)).status).toBe(404);
    const closed = new Promise(resolve => socket.addEventListener('close', resolve, { once: true }));
    socket.send(encodeFrame(1, 45));
    expect((await closed).code).toBe(4001);
  } finally {
    socket.close();
  }
});
