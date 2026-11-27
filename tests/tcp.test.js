import { expect, it, vi } from 'vitest';
import { Lane, createTCPEngine, createUpstreamDial, encodeFrame, visitFrames } from '../telegram_webproxy.js';
import { FakeSocket, independentCTR, packet, syntheticGroup, transportFixture, until, windowFrame } from './fixtures.js';

function socketFixture({ opened = Promise.resolve(), write } = {}) {
  let ingress;
  const written = [];
  function end() {
    const pending = ingress.byobRequest;
    ingress.close();
    pending?.respond(0);
  }
  const socket = {
    opened, closed: Promise.resolve(),
    readable: new ReadableStream({ type: 'bytes', start(controller) { ingress = controller; } }),
    writable: new WritableStream({ write(chunk) { written.push(Buffer.from(chunk)); return write?.(); } }),
    close: vi.fn(async () => { try { end(); } catch {} }),
  };
  return { socket, written, receive: bytes => ingress.enqueue(Uint8Array.from(bytes)), end };
}

function downstream(client, type) {
  const chunks = [];
  for (const message of client.sent) {
    visitFrames(message, (tag, id, bytes, start, end) => {
      if (tag === type) chunks.push(Buffer.from(bytes.subarray(start, end)));
    });
  }
  return Buffer.concat(chunks);
}

it('dials only compiled Telegram bootstrap addresses and refuses media or invalid DCs', async () => {
  const provision = vi.fn(() => socketFixture().socket);
  const dial = createTCPEngine(provision);
  const signal = new AbortController().signal;
  for (let dc = 1; dc <= 5; dc++) (await dial({ dc, media: false }, signal)).close();
  expect(provision.mock.calls.map(([address]) => address)).toEqual([
    '149.154.175.50', '149.154.167.51', '149.154.175.100', '149.154.167.91', '149.154.171.5',
  ].map(hostname => ({ hostname, port: 443 })));
  expect(provision.mock.calls.every(([, opts]) => opts.secureTransport === 'off' && !opts.allowHalfOpen)).toBe(true);
  for (const [dc, media] of [[5, true], [0, false], [6, false], ['2', false], [2, 'false']]) {
    await expect(dial({ dc, media }, signal)).rejects.toThrow('obfuscation');
  }
  expect(provision).toHaveBeenCalledTimes(5);
});

it.each(['timeout', 'abort', 'reject'])('closes an unsuccessful native TCP open (%s)', async mode => {
  vi.useFakeTimers();
  try {
    const controller = new AbortController();
    let rejectOpen;
    const { socket } = socketFixture({ opened: new Promise((_, reject) => { rejectOpen = reject; }) });
    const dial = createTCPEngine(() => socket, 100);
    const outcome = dial({ dc: 2, media: false }, controller.signal).catch(error => error.message);
    if (mode === 'abort') controller.abort();
    else if (mode === 'reject') rejectOpen(new Error('native rejected'));
    else await vi.advanceTimersByTimeAsync(100);
    expect(await outcome).toMatch(/timeout|cancelled|native rejected/);
    expect(socket.close).toHaveBeenCalledTimes(1);
    expect(socket.readable.locked).toBe(false);
    expect(socket.writable.locked).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    vi.useRealTimers();
  }
});

it('uses TCP for a healthy ordinary DC and keeps media on KWS', async () => {
  const native = socketFixture();
  const tcp = vi.fn(createTCPEngine(() => native.socket));
  const media = {};
  const kws = vi.fn(() => media);
  const dial = createUpstreamDial(tcp, kws);
  const signal = new AbortController().signal;
  const opened = await dial({ dc: 2, media: false }, signal);
  opened.close();
  expect(tcp).toHaveBeenCalledOnce();
  expect(kws).not.toHaveBeenCalled();
  expect(await dial({ dc: 2, media: true }, signal)).toBe(media);
  expect(tcp).toHaveBeenCalledOnce();
  expect(kws).toHaveBeenCalledWith({ dc: 2, media: true }, signal);
});

it('falls back at the TCP deadline and skips just that DC until its cooldown expires', async () => {
  vi.useFakeTimers();
  try {
    const hung = socketFixture({ opened: new Promise(() => {}) });
    const open = vi.fn()
      .mockReturnValueOnce(hung.socket)
      .mockImplementation(() => socketFixture().socket);
    const standby = {};
    const kws = vi.fn(() => standby);
    const route = createUpstreamDial(createTCPEngine(open), kws);
    const signal = new AbortController().signal;
    const info = { dc: 2, media: false };
    const result = route(info, signal);
    await vi.advanceTimersByTimeAsync(749);
    expect(kws).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(await result).toBe(standby);
    expect(hung.socket.close).toHaveBeenCalledOnce();
    expect(await route(info, signal)).toBe(standby);
    expect(open).toHaveBeenCalledOnce();
    (await route({ dc: 3, media: false }, signal)).close();
    await vi.advanceTimersByTimeAsync(15000);
    (await route(info, signal)).close();
    expect(open).toHaveBeenCalledTimes(3);
    expect(kws).toHaveBeenCalledTimes(2);
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    vi.useRealTimers();
  }
});

it('does not start a fallback for a cancelled TCP dial', async () => {
  const controller = new AbortController();
  const native = socketFixture({ opened: new Promise(() => {}) });
  const kws = vi.fn();
  const dial = createUpstreamDial(createTCPEngine(() => native.socket), kws);
  const result = expect(dial({ dc: 1, media: false }, controller.signal)).rejects.toThrow('tcp-cancelled');
  controller.abort();
  await result;
  expect(kws).not.toHaveBeenCalled();
  expect(native.socket.close).toHaveBeenCalledOnce();
});

it('starts a fresh signed KWS stream after a refused TCP dial', async () => {
  const rejected = socketFixture();
  const kws = new FakeSocket();
  const standby = vi.fn(async () => kws);
  const dial = createUpstreamDial(createTCPEngine(() => {
    rejected.socket.opened = Promise.reject(new Error('refused'));
    return rejected.socket;
  }), standby);
  const fixture = transportFixture(0xdd, 3);
  const client = new FakeSocket();
  const lane = new Lane(client, 1, fixture.secret, syntheticGroup(), dial);
  lane.attach();
  try {
    const payload = packet(Buffer.alloc(24, 43));
    client.receive(encodeFrame(1, 1));
    client.receive(encodeFrame(2, 1, Buffer.concat([fixture.wire, fixture.toWorker.update(payload)])));
    await until(() => kws.sent.length === 2);
    expect(rejected.written).toHaveLength(0);
    const decipher = independentCTR(kws.sent[0]);
    expect(decipher.update(kws.sent[0]).readInt16LE(60)).toBe(3);
    expect(decipher.update(kws.sent[1])).toEqual(payload);
    expect(standby).toHaveBeenCalledOnce();
  } finally {
    client.close();
  }
});

it.each([0xef, 0xee, 0xdd])('preserves encrypted stream bytes through fragmented TCP and closes on EOF (%s)', async mode => {
  const { socket, written, receive, end } = socketFixture();
  const fixture = transportFixture(mode, 2);
  const client = new FakeSocket();
  const group = syntheticGroup();
  const lane = new Lane(client, 1, fixture.secret, group, createTCPEngine(() => socket));
  lane.attach();
  try {
    const frames = Buffer.concat([packet(Buffer.alloc(32, 5), mode, mode !== 0xdd), packet(Buffer.alloc(220, 10), mode)]);
    const wire = Buffer.concat([fixture.wire, fixture.toWorker.update(frames)]);
    client.receive(encodeFrame(1, 1));
    client.receive(encodeFrame(2, 1, wire.subarray(0, 53)));
    client.receive(encodeFrame(2, 1, wire.subarray(53)));
    await until(() => written.length > 1);
    const forward = independentCTR(written[0]);
    const decodedHead = forward.update(written[0]);
    expect([...decodedHead.subarray(56, 60)]).toEqual([mode, mode, mode, mode]);
    expect(decodedHead.readInt16LE(60)).toBe(0);
    expect(forward.update(Buffer.concat(written.slice(1)))).toEqual(frames);
    const response = Buffer.from([0x80, 0x18, 0x37, 0x20, 4, 5, 6, 7, 8, 9, 10]);
    const reversed = independentCTR(written[0], null, true).update(response);
    receive(reversed.subarray(0, 2));
    receive(reversed.subarray(2));
    await until(() => downstream(client, 2).length === response.length);
    expect(fixture.fromWorker.update(downstream(client, 2))).toEqual(response);
    end();
    await until(() => lane.ended);
    expect(client.readyState).toBe(3);
  } finally {
    client.close();
  }
  await until(() => !lane.upBusy && !lane.downBusy && group.bytes === 0);
  expect(socket.close).toHaveBeenCalledTimes(1);
  expect(socket.readable.locked || socket.writable.locked).toBe(false);
});

it('does not read beyond available downstream credit and releases an interrupted lane', async () => {
  const { socket, written, receive } = socketFixture();
  const fixture = transportFixture(0xdd, 4);
  const client = new FakeSocket();
  const group = syntheticGroup();
  const lane = new Lane(client, 1, fixture.secret, group, createTCPEngine(() => socket));
  lane.sending = 9;
  lane.attach();
  try {
    client.receive(encodeFrame(1, 1));
    client.receive(encodeFrame(2, 1, fixture.wire));
    await until(() => written.length === 1);
    const source = Buffer.alloc(123, 50);
    receive(independentCTR(written[0], null, true).update(source));
    await until(() => Boolean(lane.creditWake));
    expect(downstream(client, 2).length).toBe(9);
    client.receive(encodeFrame(4, 1, windowFrame(114)));
    await until(() => downstream(client, 2).length === 123);
    expect(fixture.fromWorker.update(downstream(client, 2))).toEqual(source);
  } finally {
    client.close();
  }
  await until(() => group.bytes === 0);
  expect(socket.close).toHaveBeenCalledTimes(1);
  expect(socket.readable.locked || socket.writable.locked).toBe(false);
});

it('closes a failed TCP stream without replay and remembers it for the next lane', async () => {
  const write = vi.fn().mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error('write failed'));
  const { socket, written } = socketFixture({ write });
  const kws = vi.fn(() => new FakeSocket());
  const dial = createUpstreamDial(createTCPEngine(() => socket), kws);
  const fixture = transportFixture(0xdd, 3);
  const client = new FakeSocket();
  const group = syntheticGroup();
  const lane = new Lane(client, 1, fixture.secret, group, dial);
  lane.attach();
  client.receive(encodeFrame(1, 1));
  const payload = packet(Buffer.alloc(16, 40));
  client.receive(encodeFrame(2, 1, Buffer.concat([fixture.wire, fixture.toWorker.update(payload)])));
  await until(() => lane.ended && group.bytes === 0);
  expect(client.readyState).toBe(3);
  expect(socket.close).toHaveBeenCalledTimes(1);
  expect(socket.readable.locked || socket.writable.locked).toBe(false);
  expect(written).toHaveLength(2);
  expect(kws).not.toHaveBeenCalled();
  expect(await dial({ dc: 3, media: false }, new AbortController().signal)).toBeInstanceOf(FakeSocket);
  expect(kws).toHaveBeenCalledOnce();
});
