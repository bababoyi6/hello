import { runInNewContext } from 'node:vm';
import { afterEach, expect, it, vi } from 'vitest';
import worker, { encodeFrame } from '../telegram_webproxy.js';
import { ENV, HELLO, ORIGIN, VECTOR, FakeSocket, until } from './fixtures.js';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

it.each([
  ['fresh inline ticket', 0, 0],
  ['stale inline ticket', 82000, 1],
])('executes the Bridge with a %s and isolates an established lane close', async (_, initialDelay, creates) => {
  const start = Date.now();
  const clock = vi.spyOn(Date, 'now').mockReturnValue(start);
  const response = await worker.fetch(new Request(ORIGIN + '/?bridge=' + VECTOR), ENV);
  const html = await response.text();
  const script = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(html)?.[1];
  expect(script).toBeTruthy();
  const calls = [], sockets = [], messages = [], listeners = new Map();
  let elapsed = initialDelay;
  clock.mockReturnValue(start + elapsed);
  class BrowserSocket extends FakeSocket {
    static OPEN = 1;
    constructor(url, protocol) {
      super();
      this.url = url;
      this.protocol = protocol;
      sockets.push(this);
      queueMicrotask(() => { this.accept(); this.onopen?.(); });
    }
    close(code = 1000) {
      super.close(code);
      this.onclose?.({ code });
    }
  }
  const injected = { postMessage(data) { messages.push(data); } };
  const parent = {};
  runInNewContext(script, {
    ArrayBuffer, Uint8Array, DataView, URL, AbortController, setTimeout, clearTimeout, parent,
    TelegramWebProxy: injected,
    location: { hash: '#android=' + 'A'.repeat(43), pathname: '/' },
    history: { replaceState: vi.fn() },
    addEventListener(name, listener) { listeners.set(name, listener); },
    WebSocket: BrowserSocket,
    performance: { now: () => elapsed },
    async fetch(url, options) {
      calls.push([url, options]);
      return worker.fetch(new Request(url, options), ENV);
    },
  });
  expect(JSON.parse(messages[0])).toEqual({ t: 'tproxy-android-init', v: 1, nonce: 'A'.repeat(43) });
  injected.onmessage({ data: HELLO.buffer });
  await until(() => messages.some(value => value instanceof ArrayBuffer && new Uint8Array(value)[0] === 17));
  try {
    expect(calls.filter(([url]) => url.endsWith('/api/v1/session'))).toHaveLength(creates);
    injected.onmessage({ data: encodeFrame(1, 1).buffer });
    await until(() => sockets[0]?.sent.length > 0);
    const first = encodeFrame(2, 1, Uint8Array.of(4, 5));
    const second = encodeFrame(2, 1, Uint8Array.of(6));
    const batch = new Uint8Array(first.length + second.length);
    batch.set(first);
    batch.set(second, first.length);
    const delivered = messages.length;
    sockets[0].onmessage({ data: batch.buffer });
    expect(messages.slice(delivered).filter(value => value instanceof ArrayBuffer)
      .map(value => [...new Uint8Array(value)])).toEqual([[...first], [...second]]);
    sockets[0].onmessage({ data: first.buffer });
    const traffic = () => messages.filter(value => typeof value === 'string')
      .map(value => JSON.parse(value)).filter(value => value.t === 'traffic');
    await until(() => traffic().length);
    expect(traffic()).toEqual([{ t: 'traffic', up: 8, down: batch.byteLength + first.byteLength }]);
    const original = sockets[0].protocol;
    elapsed = 301000;
    clock.mockReturnValue(start + elapsed);
    injected.onmessage({ data: encodeFrame(1, 2).buffer });
    injected.onmessage({ data: encodeFrame(1, 3).buffer });
    await until(() => sockets[2]?.sent.length > 0);
    expect(calls.filter(([url]) => url.endsWith('/renew'))).toHaveLength(1);
    expect(sockets[0].readyState).toBe(1);
    expect(sockets[1].protocol.split('.')[1]).not.toBe(original.split('.')[1]);
    expect(sockets[1].protocol.split('.')[1]).toBe(sockets[2].protocol.split('.')[1]);
    sockets[0].close();
    expect(messages.some(value => value instanceof ArrayBuffer && new DataView(value).getUint32(0) === 0x03000001)).toBe(true);
    expect(sockets[1].readyState).toBe(1);
    const lateClose = sockets[2].onclose;
    sockets[1].close(4001);
    lateClose({ code: 4001 });
    expect(messages.filter(value => typeof value === 'string' && JSON.parse(value).t === 'close')).toHaveLength(1);
    expect(calls.filter(([, options]) => options.method === 'DELETE')).toHaveLength(0);
    expect(sockets[2].readyState).toBe(3);
  } finally {
    listeners.get('pagehide')();
  }
  expect(sockets.every(socket => socket.readyState === 3)).toBe(true);
  expect(injected.onmessage).toBeNull();
});

async function bridgeFixture({ broken = [], renew = () => new Response(null, { status: 503 }) } = {}) {
  const response = await worker.fetch(new Request(ORIGIN + '/?bridge=' + VECTOR), ENV);
  const script = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(await response.text())[1];
  vi.useFakeTimers();
  const epoch = Date.now();
  const messages = [], calls = [], sockets = new Map(), attempts = [], listeners = new Map();
  const injected = { postMessage(data) { messages.push(typeof data === 'string' ? JSON.parse(data) : data); } };
  class BrowserSocket extends FakeSocket {
    static OPEN = 1;
    constructor(_, protocol) {
      super();
      const id = Number(protocol.split('.').at(-1));
      attempts.push(id);
      if (broken.includes(id)) throw new Error('synthetic browser setup failure');
      this.protocol = protocol;
      sockets.set(id, this);
    }
    open(protocol = this.protocol) {
      this.protocol = protocol;
      this.accept();
      this.onopen?.();
    }
    disconnect(code) {
      const onclose = this.onclose;
      this.close(code);
      onclose?.({ code });
    }
  }
  runInNewContext(script, {
    ArrayBuffer, Uint8Array, DataView, URL, AbortController, setTimeout, clearTimeout, parent: {},
    TelegramWebProxy: injected,
    location: { hash: '#android=' + 'A'.repeat(43), pathname: '/' },
    history: { replaceState() {} },
    addEventListener(name, listener) { listeners.set(name, listener); },
    Math: Object.assign(Object.create(Math), { random: () => 0 }),
    Date,
    performance: { now: () => Date.now() - epoch },
    WebSocket: BrowserSocket,
    async fetch(url, options) {
      calls.push(options);
      return url.endsWith('/renew') ? renew(options) : new Response(null, { status: 204 });
    },
  });
  const send = data => injected.onmessage?.({ data });
  send(HELLO.buffer);
  return {
    sockets, attempts, calls, send, messages,
    open(...ids) { send(Uint8Array.from(Buffer.concat(ids.map(id => encodeFrame(1, id)))).buffer); },
    localCloses() {
      return messages.filter(value => value instanceof ArrayBuffer && new Uint8Array(value)[0] === 3)
        .map(value => new DataView(value).getUint32(0) & 0xffffff);
    },
    globalCloses: () => messages.filter(value => value.t === 'close').length,
    cleanup: () => listeners.get('pagehide')(),
    active: () => typeof injected.onmessage === 'function',
  };
}

it('isolates a new lane timeout, constructor failure and abnormal close from working traffic', async () => {
  const b = await bridgeFixture({ broken: [3] });
  b.open(1);
  const healthy = b.sockets.get(1);
  healthy.open();
  b.open(2, 3, 4);
  const hung = b.sockets.get(2);
  const delayedClose = hung.onclose;
  const delayedOpen = hung.onopen;
  b.sockets.get(4).disconnect(1006);
  await vi.advanceTimersByTimeAsync(7999);
  expect(b.localCloses()).toEqual([3, 4]);
  await vi.advanceTimersByTimeAsync(1);
  delayedOpen();
  delayedClose({ code: 1006 });
  expect(b.localCloses()).toEqual([3, 4, 2]);
  const data = encodeFrame(2, 1, Uint8Array.of(17));
  b.send(data.buffer);
  healthy.onmessage({ data: data.buffer });
  expect(healthy.sent.at(-1)).toEqual(Buffer.from(data));
  expect(b.messages).toContain(data.buffer);
  expect(b.globalCloses()).toBe(0);
  expect(b.attempts).toEqual([1, 2, 3, 4]);
  expect(healthy.readyState).toBe(1);
  expect(hung.readyState).toBe(3);
  expect(hung.onopen).toBeNull();
  b.cleanup();
  expect(b.calls.map(({ method }) => method)).toEqual(['DELETE']);
  expect(vi.getTimerCount()).toBe(0);
});

it('lets a sibling finish initial setup after a concurrent lane fails', async () => {
  const b = await bridgeFixture({ broken: [1] });
  b.open(1, 2);
  b.sockets.get(2).open();
  await vi.advanceTimersByTimeAsync(30000);
  expect(b.localCloses()).toEqual([1]);
  expect(b.globalCloses()).toBe(0);
  expect(b.sockets.get(2).readyState).toBe(1);
  b.cleanup();
  expect(vi.getTimerCount()).toBe(0);
});

it('forwards a backend CLOSE and ignores the following socket-close event', async () => {
  const b = await bridgeFixture();
  b.open(1, 2);
  for (const ws of b.sockets.values()) ws.open();
  const first = b.sockets.get(1);
  const socketClose = first.onclose;
  first.onmessage({ data: encodeFrame(3, 1).buffer });
  socketClose({ code: 1000 });
  expect(b.localCloses()).toEqual([1]);
  expect(b.globalCloses()).toBe(0);
  expect(b.sockets.get(2).readyState).toBe(1);
  b.cleanup();
  expect(vi.getTimerCount()).toBe(0);
});

it('keeps Bridge queue caps when a WebView reports an invalid native buffer size', async () => {
  const b = await bridgeFixture();
  try {
    b.open(1);
    await vi.advanceTimersByTimeAsync(0);
    const socket = b.sockets.get(1);
    socket.bufferedAmount = NaN;
    // The socket is still connecting, so these bytes stay in the Bridge queue.
    const frame = encodeFrame(2, 1, new Uint8Array(1024 * 1024)).buffer;
    for (let i = 0; i < 8; i++) b.send(frame);
    expect(b.localCloses()).toEqual([1]);
    expect(b.globalCloses()).toBe(0);
    expect(socket.readyState).toBe(3);
  } finally {
    b.cleanup();
  }
});

it('keeps a congested Bridge lane when it makes progress before the stall deadline', async () => {
  const b = await bridgeFixture();
  try {
    b.open(1);
    const ws = b.sockets.get(1);
    ws.open();
    ws.bufferedAmount = 2 * 1024 * 1024;
    const small = encodeFrame(2, 1, new Uint8Array(10)).buffer;
    const large = encodeFrame(2, 1, new Uint8Array(65536)).buffer;
    b.send(small);
    b.send(large);
    await vi.advanceTimersByTimeAsync(29500);
    ws.bufferedAmount -= small.byteLength;
    await vi.advanceTimersByTimeAsync(200);
    expect(ws.sent.at(-1).length).toBe(small.byteLength);
    await vi.advanceTimersByTimeAsync(500);
    expect(b.localCloses()).toEqual([]);
    expect(ws.readyState).toBe(1);
    ws.bufferedAmount = 0;
    await vi.advanceTimersByTimeAsync(100);
    expect(ws.sent.at(-1).length).toBe(large.byteLength);
  } finally {
    b.cleanup();
  }
});

it('accepts the loopback MessagePort handshake and keeps native carrier status semantics', async () => {
  const response = await worker.fetch(new Request(ORIGIN + '/?bridge=' + VECTOR), ENV);
  const script = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(await response.text())[1];
  vi.useFakeTimers();
  const messages = [], listeners = new Map();
  const parent = {};
  const port = { start: vi.fn(), close: vi.fn(), postMessage: message => messages.push(message) };
  runInNewContext(script, {
    ArrayBuffer, Uint8Array, DataView, URL, AbortController, setTimeout, clearTimeout, parent,
    location: { hash: '', pathname: '/' }, history: { replaceState: vi.fn() },
    addEventListener(name, listener) { listeners.set(name, listener); },
    performance: { now: () => 1 }, fetch: vi.fn(async () => new Response(null, { status: 204 })),
  });
  const receive = listeners.get('message');
  const message = { source: parent, data: { t: 'tproxy-init', v: 1 }, ports: [port] };
  receive({ ...message, origin: 'http://127.0.0.2:8480' });
  expect(port.start).not.toHaveBeenCalled();
  receive({ ...message, origin: 'http://127.0.0.1:8480' });
  expect(port.start).toHaveBeenCalledOnce();
  port.onmessage({ data: HELLO.buffer });
  expect(messages.map(message => message instanceof ArrayBuffer ? new Uint8Array(message)[0] : message.state))
    .toEqual(['connecting', 17, 'connected']);
  listeners.get('pagehide')();
  expect(port.close).toHaveBeenCalledOnce();
  expect(vi.getTimerCount()).toBe(0);
});

it.each([false, true])('exits initial setup safely with a failed lane (%s)', async connect => {
  const b = await bridgeFixture();
  if (connect) b.open(1);
  const limit = connect ? 8000 : 30000;
  await vi.advanceTimersByTimeAsync(limit - 1);
  expect(b.globalCloses()).toBe(0);
  await vi.advanceTimersByTimeAsync(1);
  expect(b.globalCloses()).toBe(1);
  expect(b.localCloses()).toEqual([]);
  expect(b.active()).toBe(false);
  expect(vi.getTimerCount()).toBe(0);
});

it.each(['subprotocol', 'frame', 'policy', 'reused id'])('fails the whole Bridge for %s', async failure => {
  const b = await bridgeFixture();
  b.open(1, 2);
  const first = b.sockets.get(1), second = b.sockets.get(2);
  first.open();
  if (failure === 'subprotocol') second.open('wrong');
  else {
    second.open();
    if (failure === 'frame') second.onmessage({ data: encodeFrame(2, 1, Uint8Array.of(1)).buffer });
    if (failure === 'policy') second.disconnect(1008);
    if (failure === 'reused id') {
      second.disconnect(1006);
      b.open(2);
    }
  }
  b.cleanup();
  expect(b.attempts).toEqual([1, 2]);
  expect(b.globalCloses()).toBe(1);
  expect(first.readyState).toBe(3);
  expect(second.readyState).toBe(3);
  expect(vi.getTimerCount()).toBe(0);
});

it('bounds a shared transient renewal failure while preserving a healthy lane', async () => {
  const renew = vi.fn(async () => new Response(null, { status: 503 }));
  const b = await bridgeFixture({ renew });
  b.open(1);
  b.sockets.get(1).open();
  await vi.advanceTimersByTimeAsync(90000);
  b.open(2, 3);
  await vi.advanceTimersByTimeAsync(1800);
  expect(renew).toHaveBeenCalledTimes(4);
  expect(b.localCloses()).toEqual([2, 3]);
  expect(b.attempts).toEqual([1]);
  expect(b.sockets.get(1).readyState).toBe(1);
  expect(b.globalCloses()).toBe(0);
  b.cleanup();
  await vi.advanceTimersByTimeAsync(60000);
  expect(renew).toHaveBeenCalledTimes(4);
  expect(vi.getTimerCount()).toBe(0);
});

it.each([
  [408, null, 250],
  [429, '2', 2000],
  [502, 'date', 2000],
])('retries renewal HTTP %s once for concurrent lanes after the required delay', async (status, retryAfter, delay) => {
  const headers = { 'X-Session-Token': 'A'.repeat(43), 'X-Session-TTL': '300' };
  const renew = vi.fn(() => new Response(null, { status: 204, headers }));
  renew.mockImplementationOnce(() => {
    const after = retryAfter === 'date' ? new Date(Date.now() + 2000).toUTCString() : retryAfter;
    return new Response(null, { status, headers: after === null ? {} : { 'Retry-After': after } });
  });
  const b = await bridgeFixture({ renew });
  b.open(1);
  b.sockets.get(1).open();
  await vi.advanceTimersByTimeAsync(90000);
  vi.setSystemTime(Math.floor(Date.now() / 1000) * 1000);
  b.open(2, 3);
  await vi.advanceTimersByTimeAsync(delay - 1);
  expect(renew).toHaveBeenCalledTimes(1);
  expect(b.attempts).toEqual([1]);
  await vi.advanceTimersByTimeAsync(1);
  expect(renew).toHaveBeenCalledTimes(2);
  expect(b.attempts).toEqual([1, 2, 3]);
  expect(b.sockets.get(1).readyState).toBe(1);
  expect(b.localCloses()).toEqual([]);
  b.cleanup();
  expect(vi.getTimerCount()).toBe(0);
});

it('stops retrying when Retry-After would exceed the renewal deadline', async () => {
  const renew = vi.fn(() => new Response(null, { status: 429, headers: { 'Retry-After': '60' } }));
  const b = await bridgeFixture({ renew });
  b.open(1);
  b.sockets.get(1).open();
  await vi.advanceTimersByTimeAsync(90000);
  b.open(2);
  await vi.advanceTimersByTimeAsync(60000);
  expect(renew).toHaveBeenCalledTimes(1);
  expect(b.localCloses()).toEqual([2]);
  expect(b.sockets.get(1).readyState).toBe(1);
  b.cleanup();
  expect(vi.getTimerCount()).toBe(0);
});

it.each([404, 204])('fails closed on a renewal rejection or malformed response (%s)', async status => {
  const renew = vi.fn(async () => new Response(null, { status }));
  const b = await bridgeFixture({ renew });
  b.open(1);
  b.sockets.get(1).open();
  await vi.advanceTimersByTimeAsync(81000);
  b.open(2, 3);
  await vi.advanceTimersByTimeAsync(0);
  expect(renew).toHaveBeenCalledTimes(1);
  expect(b.globalCloses()).toBe(1);
  expect(b.sockets.get(1).readyState).toBe(3);
  expect(b.calls.map(({ method }) => method)).toEqual(['POST']);
  expect(vi.getTimerCount()).toBe(0);
});

it('aborts pending renewal at parent expiry and ignores a late response and sibling events', async () => {
  let respond;
  const renew = vi.fn(() => new Promise(resolve => { respond = resolve; }));
  const b = await bridgeFixture({ renew });
  b.open(1, 2);
  for (const ws of b.sockets.values()) ws.open();
  const parentLifetime = (12 * 3600 + 120) * 1000;
  await vi.advanceTimersByTimeAsync(parentLifetime - 1000);
  b.open(3, 4);
  expect(renew).toHaveBeenCalledTimes(1);
  const staleClose = b.sockets.get(2).onclose;
  await vi.advanceTimersByTimeAsync(1000);
  b.sockets.get(1).disconnect(4001);
  staleClose({ code: 4001 });
  staleClose({ code: 1006 });
  expect(b.calls[0].signal.aborted).toBe(true);
  respond(new Response(null, { status: 204, headers: { 'X-Session-Token': 'A'.repeat(43), 'X-Session-TTL': '300' } }));
  await vi.advanceTimersByTimeAsync(1000);
  expect(b.attempts).toEqual([1, 2]);
  expect(b.globalCloses()).toBe(1);
  expect(b.localCloses()).toEqual([]);
  expect(b.calls.map(({ method }) => method)).toEqual(['POST']);
  expect(vi.getTimerCount()).toBe(0);
});

it.each([404, 503])('classifies a Session HTTP %s and cancels the pending retry on pagehide', async status => {
  const response = await worker.fetch(new Request(ORIGIN + '/?bridge=' + VECTOR), ENV);
  const script = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(await response.text())[1];
  vi.useFakeTimers();
  const start = Date.now();
  const messages = [], listeners = new Map();
  const injected = { postMessage(data) { messages.push(data); } };
  const post = vi.fn(async () => new Response(null, { status, headers: { 'Retry-After': '1' } }));
  runInNewContext(script, {
    ArrayBuffer, Uint8Array, DataView, URL, AbortController, setTimeout, clearTimeout, parent: {},
    TelegramWebProxy: injected,
    location: { hash: '#android=' + 'A'.repeat(43), pathname: '/' },
    history: { replaceState() {} },
    addEventListener(name, listener) { listeners.set(name, listener); },
    Math: Object.assign(Object.create(Math), { random: () => 0 }),
    performance: { now: () => Date.now() - start + 82000 },
    fetch: post,
  });
  injected.onmessage({ data: HELLO.buffer });
  await vi.advanceTimersByTimeAsync(999);
  expect(post).toHaveBeenCalledTimes(1);
  if (status === 404) {
    expect(messages.map(JSON.parse)).toContainEqual({ t: 'close' });
  } else {
    await vi.advanceTimersByTimeAsync(1);
    expect(post).toHaveBeenCalledTimes(2);
  }
  listeners.get('pagehide')();
  await vi.advanceTimersByTimeAsync(30000);
  expect(post).toHaveBeenCalledTimes(status === 404 ? 1 : 2);
  expect(injected.onmessage).toBeNull();
});
