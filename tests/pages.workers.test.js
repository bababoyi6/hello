import { expect, it } from 'vitest';
import pages from '../dist/verified/_worker.js';
import workers, { configuration, encodeFrame, issueToken } from '../dist/workers/verified/telegram_webproxy.js';

it.each([['Pages', pages], ['Workers', workers]])('runs packaged %s with only p and issues the established link and lane protocol', async (_, worker) => {
  const origin = 'https://dashboard.example.com';
  const env = { p: 'synthetic-dashboard-password' };
  const endpoint = origin + '/admin';
  expect((await worker.fetch(new Request(endpoint), {})).status).toBe(404);
  const empty = await worker.fetch(new Request(endpoint), env);
  expect(await empty.text()).not.toContain('tg://webproxy');
  const login = await worker.fetch(new Request(endpoint, {
    method: 'POST',
    headers: { Origin: origin },
    body: new URLSearchParams({ password: env.p }),
  }), env);
  expect(login.status).toBe(303);
  const Cookie = login.headers.get('Set-Cookie').split(';')[0];
  const portal = await worker.fetch(new Request(endpoint, { headers: { Cookie } }), env);
  expect(await portal.text()).toContain('tg://webproxy?server=dashboard.example.com&amp;secret=cff9db686d249771b43ec0b598ce8982');
  expect((await worker.fetch(new Request(endpoint + '?probe=1', { method: 'HEAD' }), env)).status).toBe(404);
  expect((await worker.fetch(new Request(endpoint + '?probe=1', { method: 'HEAD', headers: { Cookie } }), env)).status).toBe(204);
  const diagnostics = await worker.fetch(new Request(endpoint + '?diagnostics=1', { headers: { Cookie } }), env);
  expect(diagnostics.headers.get('Content-Security-Policy')).toContain("connect-src 'self'");
  expect(await diagnostics.text()).toContain('id="probe"');

  const bridge = await worker.fetch(new Request(origin + '/?bridge=2w8TO5ICl4qQE8JmSUukADb63tfkZGdvlFne8wHXdbk'), env);
  const ticket = /"ticket":"([A-Za-z0-9_-]{43})"/.exec(await bridge.text())?.[1];
  expect(ticket).toBeTruthy();
  const protocol = 'tproxy-lane-v1.' + ticket + '.41';
  const upgrade = await worker.fetch(new Request(origin + '/api/v1/ws', {
    headers: { Upgrade: 'websocket', 'Sec-WebSocket-Protocol': protocol },
  }), env);
  expect(upgrade.status).toBe(101);
  expect(upgrade.headers.get('Sec-WebSocket-Protocol')).toBe(protocol);
  const socket = upgrade.webSocket;
  socket.accept();
  socket.send(encodeFrame(1, 41));
  socket.close();
});

it('sends the private parent-expiration close code through workerd', async () => {
  const host = 'expiry.example.com';
  const env = { p: 'synthetic-dashboard-password' };
  const cfg = await configuration(env, host);
  const limit = Math.floor(Date.now() / 1000) + 2;
  const id = crypto.getRandomValues(new Uint8Array(12));
  new DataView(id.buffer).setUint32(0, limit);
  const ticket = await issueToken(cfg, host, 2, limit, id);
  const response = await workers.fetch(new Request('https://' + host + '/api/v1/ws', { headers: {
    Upgrade: 'websocket', 'Sec-WebSocket-Protocol': 'tproxy-lane-v1.' + ticket + '.1',
  } }), env);
  expect(response.status).toBe(101);
  const socket = response.webSocket;
  try {
    socket.accept();
    const close = new Promise(resolve => socket.addEventListener('close', resolve, { once: true }));
    socket.send(encodeFrame(1, 1));
    expect((await close).code).toBe(4001);
  } finally {
    socket.close();
  }
});
