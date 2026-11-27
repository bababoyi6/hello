import { expect, it, vi } from 'vitest';
import { connectKWS, encodeFrame, Lane, visitFrames } from '../telegram_webproxy.js';
import { FakeSocket, independentCTR, packet, synthetic, syntheticGroup, transportFixture, until, wait, windowFrame } from './fixtures.js';

function laneOf(id, fixture, dial, options = {}) {
  const client = new FakeSocket();
  const group = syntheticGroup();
  const lane = new Lane(client, id, fixture.secret, group, dial, options);
  lane.attach();
  client.receive(encodeFrame(1, id));
  return { lane, group, client };
}

function headers(socket, expectedMode, expectedDc) {
  const wire = socket.sent[0];
  const forward = independentCTR(wire);
  const plain = forward.update(wire);
  expect(plain.readInt16LE(60)).toBe(expectedDc);
  expect([...plain.subarray(56, 60)]).toEqual(Array(4).fill(expectedMode));
  return { forward, reverse: independentCTR(wire, null, true) };
}

function frames(socket, type) {
  const output = [];
  for (const message of socket.sent) {
    visitFrames(message, (tag, id, bytes, start, end) => {
      if (tag === type) output.push(Buffer.from(bytes.subarray(start, end)));
    });
  }
  return output;
}

it.each([0xef, 0xee, 0xdd])('transcodes bidirectionally and preserves one KWS message per packet (%s)', async mode => {
  const fixture = transportFixture(mode);
  const peer = new FakeSocket();
  const dial = vi.fn(async () => peer);
  const { lane, client, group } = laneOf(42, fixture, dial);
  try {
    const packets = [
      packet(Buffer.alloc(8, 7), mode, true),
      packet(Buffer.alloc(572, 68), mode),
      packet(Buffer.alloc(3092, 30), mode),
      packet(Buffer.alloc(128, 88), mode),
    ];
    const stream = Buffer.concat([fixture.wire, fixture.toWorker.update(Buffer.concat(packets))]);
    const draw = synthetic(0xa327ac);
    for (let offset = 0; offset < stream.length;) {
      const end = Math.min(stream.length, offset + draw(114) + 1);
      client.receive(encodeFrame(2, 42, stream.subarray(offset, end)));
      offset = end;
    }
    await until(() => peer.sent.length >= packets.length + 1);
    expect(dial.mock.calls[0][0]).toEqual({ mode, dc: 2, media: true });
    const { forward, reverse } = headers(peer, mode, -2);
    expect(peer.sent.slice(1).map(data => forward.update(data))).toEqual(packets);
    const payloads = [Buffer.alloc(67, 11), Buffer.alloc(55553, 222), Buffer.alloc(8129, 9)];
    for (const data of payloads) peer.receive(reverse.update(data));
    await until(() => frames(client, 2).reduce((size, data) => size + data.length, 0) === 63749);
    expect(fixture.fromWorker.update(Buffer.concat(frames(client, 2)))).toEqual(Buffer.concat(payloads));
    await until(() => frames(client, 4).reduce((n, frame) => n + frame.readUInt32BE(), 0) === stream.length);
  } finally {
    client.close();
  }
  await until(() => !lane.upBusy && !lane.downBusy);
  expect(peer.readyState).toBe(3);
  expect(group.bytes).toBe(0);
  expect(group.active).toBe(0);
});

it('uses fixed KWS hosts and the binary subprotocol, enforces timeout, and releases late successes', async () => {
  let settle;
  const late = new FakeSocket(), good = new FakeSocket();
  const calls = [];
  const result = (socket, protocol = 'binary') => ({
    status: 101, webSocket: socket, headers: new Headers({ 'Sec-WebSocket-Protocol': protocol }),
  });
  const lookup = (url, opts) => {
    calls.push([url, opts]);
    if (calls.length === 1) return new Promise(resolve => { settle = () => resolve(result(late)); });
    return Promise.resolve(result(good));
  };
  const signal = new AbortController().signal;
  expect(await connectKWS({ dc: 2, media: true }, signal, lookup, 12, 1)).toBe(good);
  settle();
  await until(() => late.readyState === 3);
  expect(calls.map(call => call[0])).toEqual([
    'https://kws2-1.web.telegram.org/apiws', 'https://kws2.web.telegram.org/apiws',
  ]);
  expect(calls[0][1].redirect).toBe('manual');
  expect(calls[0][1].headers['Sec-WebSocket-Protocol']).toBe('binary');
  expect(calls[0][1].signal.aborted).toBe(true);
  const wrong = new FakeSocket();
  const reject = vi.fn(async () => result(wrong, 'text'));
  await expect(connectKWS({ dc: 1, media: false }, signal, reject, 12, 1)).rejects.toThrow('kws-connect');
  expect(reject).toHaveBeenCalledTimes(2);
  expect(wrong.readyState).toBe(3);
});

it('opens the fallback only for a slow primary and cancels a losing handshake', async () => {
  vi.useFakeTimers();
  try {
    const replies = [];
    const first = new FakeSocket(), backup = new FakeSocket();
    const reply = socket => ({
      status: 101, webSocket: socket, headers: new Headers({ 'Sec-WebSocket-Protocol': 'binary' }),
    });
    const fetcher = vi.fn((url, opts) => new Promise(resolve => replies.push({ resolve, signal: opts.signal })));
    const socket = connectKWS({ dc: 3, media: false }, new AbortController().signal, fetcher);
    await vi.advanceTimersByTimeAsync(899);
    expect(fetcher).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(fetcher).toHaveBeenCalledTimes(2);
    replies[1].resolve(reply(backup));
    expect(await socket).toBe(backup);
    expect(replies[0].signal.aborted).toBe(true);
    expect(replies[1].signal.aborted).toBe(false);
    replies[0].resolve(reply(first));
    await vi.advanceTimersByTimeAsync(0);
    expect(first.readyState).toBe(3);
    expect(first.sent).toHaveLength(0);

    const quick = vi.fn(async () => reply(new FakeSocket()));
    await connectKWS({ dc: 3, media: false }, new AbortController().signal, quick);
    await vi.advanceTimersByTimeAsync(3000);
    expect(quick).toHaveBeenCalledTimes(1);
    expect(quick.mock.calls[0][1].signal.aborted).toBe(false);
  } finally {
    vi.useRealTimers();
  }
});

it('bounds simultaneous fallback races and cleans up when all callers abort', async () => {
  vi.useFakeTimers();
  const controllers = Array.from({ length: 10 }, () => new AbortController());
  const signals = [];
  const fetcher = vi.fn((url, options) => {
    signals.push(options.signal);
    return new Promise(() => {});
  });
  try {
    const results = Promise.allSettled(controllers.map(c => connectKWS({ dc: 1, media: false }, c.signal, fetcher)));
    await vi.advanceTimersByTimeAsync(900);
    expect(fetcher).toHaveBeenCalledTimes(18);
    for (const controller of controllers) controller.abort();
    expect((await results).every(result => result.status === 'rejected')).toBe(true);
    expect(signals.every(signal => signal.aborted)).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    for (const controller of controllers) controller.abort();
    vi.useRealTimers();
  }
});

it('kills a dial result from a closed lane and lets a new lane connect', async () => {
  const fixture = transportFixture();
  let resolveDial, abortSignal;
  const oldPeer = new FakeSocket();
  const currentPeer = new FakeSocket();
  const { lane, client, group } = laneOf(1, fixture, (_, signal) => {
    abortSignal = signal;
    return new Promise(resolve => { resolveDial = resolve; });
  });
  client.receive(encodeFrame(2, 1, fixture.wire));
  await until(() => Boolean(resolveDial));
  client.close();
  expect(abortSignal.aborted).toBe(true);
  const newer = laneOf(2, fixture, async () => currentPeer);
  newer.client.receive(encodeFrame(2, 2, fixture.wire));
  resolveDial(oldPeer);
  try {
    await until(() => oldPeer.readyState === 3 && newer.lane.phase === 'streaming');
    expect(oldPeer.sent).toHaveLength(0);
    expect(currentPeer.sent).toHaveLength(1);
    expect(lane.ended).toBe(true);
    expect(group.bytes).toBe(0);
  } finally {
    newer.client.close();
  }
});

it('stops a stalled KWS writer while an independent established lane continues', async () => {
  const first = transportFixture();
  const second = transportFixture(0xee, 5);
  const slowPeer = new FakeSocket(), fastPeer = new FakeSocket();
  const slow = laneOf(14, first, async () => slowPeer, { stallMs: 45 });
  const fast = laneOf(15, second, async () => fastPeer);
  try {
    slow.client.receive(encodeFrame(2, 14, first.wire));
    fast.client.receive(encodeFrame(2, 15, second.wire));
    await until(() => slow.lane.phase === 'streaming' && fast.lane.phase === 'streaming');
    slowPeer.bufferedAmount = 2097152;
    const payload = packet(Buffer.alloc(4096));
    slow.client.receive(encodeFrame(2, 14, first.toWorker.update(payload)));
    const live = packet(Buffer.alloc(512, 31), 0xee);
    fast.client.receive(encodeFrame(2, 15, second.toWorker.update(live)));
    await until(() => slow.lane.ended && fastPeer.sent.length === 2);
    expect(slowPeer.sent).toHaveLength(1);
    expect(frames(slow.client, 3)).toHaveLength(1);
    expect(fast.lane.ended).toBe(false);
    expect(headers(fastPeer, 0xee, 5).forward.update(fastPeer.sent[1])).toEqual(live);
    expect(slow.group.bytes).toBe(0);
  } finally {
    slow.client.close();
    fast.client.close();
  }
});

it('caps the downlink window, resumes on credit and reclaims overflow queues on close', async () => {
  const fixture = transportFixture();
  const peer = new FakeSocket();
  const { lane, client, group } = laneOf(6, fixture, async () => peer, { stallMs: 2000 });
  try {
    client.receive(encodeFrame(2, 6, fixture.wire));
    await until(() => lane.phase === 'streaming');
    const { reverse } = headers(peer, 0xdd, -2);
    const sample = Buffer.alloc(4 * 1024 * 1024 + 13, 91);
    peer.receive(reverse.update(sample));
    await until(() => Boolean(lane.creditWake));
    expect(frames(client, 2).reduce((sum, bytes) => sum + bytes.length, 0)).toBe(4 * 1024 * 1024);
    client.receive(encodeFrame(4, 6, windowFrame(13)));
    await until(() => !lane.downBusy);
    const chunks = frames(client, 2);
    expect(fixture.fromWorker.update(Buffer.concat(chunks)).equals(sample)).toBe(true);
    expect(chunks.map(b => b.length).every(n => n <= 65536)).toBe(true);
    expect(client.sent.filter(message => message[0] === 2)).toHaveLength(9);
    const small = Buffer.alloc(16, 55);
    for (let i = 0; i < 514 && !lane.ended; i++) peer.receive(reverse.update(small));
    await until(() => lane.ended && !lane.downBusy);
    expect(group.bytes).toBe(0);
    expect(peer.readyState).toBe(3);
  } finally {
    client.close();
  }
}, 15000);

it('sends all complete DATA frames that fit a congested WebSocket', async () => {
  const fixture = transportFixture();
  const peer = new FakeSocket();
  const { lane, client } = laneOf(19, fixture, async () => peer);
  const frameBytes = 64 * 1024 + 8;
  try {
    client.receive(encodeFrame(2, 19, fixture.wire));
    await until(() => lane.phase === 'streaming' && frames(client, 4).length === 1);
    const send = client.send.bind(client);
    client.send = bytes => {
      send(bytes);
      client.bufferedAmount += bytes.length;
    };
    client.bufferedAmount = 2 * 1024 * 1024 - 3 * frameBytes;
    const plain = Buffer.alloc(512 * 1024, 91);
    peer.receive(headers(peer, 0xdd, -2).reverse.update(plain));
    const dataMessages = () => client.sent.filter(message => message[0] === 2);
    await until(() => dataMessages().length > 0);
    expect(dataMessages().map(message => message.length)).toEqual([3 * frameBytes]);

    client.bufferedAmount -= 5 * frameBytes;
    await until(() => !lane.downBusy);
    expect(dataMessages().map(message => message.length)).toEqual([3 * frameBytes, 5 * frameBytes]);
    expect(fixture.fromWorker.update(Buffer.concat(frames(client, 2)))).toEqual(plain);
    expect(client.bufferedAmount).toBe(2 * 1024 * 1024);
  } finally {
    client.close();
  }
});

it('rejects cross-lane frames and times out waiting for the initial head', async () => {
  const fixture = transportFixture();
  const dial = vi.fn();
  const wrong = laneOf(7, fixture, dial);
  wrong.client.receive(encodeFrame(2, 8, fixture.wire));
  expect(wrong.client.code).toBe(1008);
  const idle = laneOf(8, fixture, dial, { openMs: 12 });
  await wait(30);
  expect(idle.lane.ended).toBe(true);
  expect(dial).not.toHaveBeenCalled();
  expect(wrong.group.bytes + idle.group.bytes).toBe(0);
});


it('assembles one maximum padded packet across DATA frames before a single KWS send', async () => {
  const fixture = transportFixture();
  const peer = new FakeSocket();
  const { lane, client, group } = laneOf(25, fixture, async () => peer);
  try {
    client.receive(encodeFrame(2, 25, fixture.wire));
    await until(() => lane.phase === 'streaming' && frames(client, 4).length === 1);
    const large = packet(Buffer.alloc(8 * 1024 * 1024, 77));
    const wire = fixture.toWorker.update(large);
    for (let offset = 0; offset < wire.length;) {
      const end = Math.min(wire.length, offset + 1024 * 1024);
      const before = frames(client, 4).length;
      client.receive(encodeFrame(2, 25, wire.subarray(offset, end)));
      await until(() => frames(client, 4).length > before || lane.ended);
      offset = end;
    }
    expect(lane.ended).toBe(false);
    expect(peer.sent).toHaveLength(2);
    expect(headers(peer, 0xdd, -2).forward.update(peer.sent[1]).equals(large)).toBe(true);
  } finally {
    client.close();
  }
  expect(group.bytes).toBe(0);
}, 15000);

it('refuses an out-of-range or nonnumeric KWS destination without dialing', async () => {
  const fetcher = vi.fn();
  const signal = new AbortController().signal;
  for (const dc of [0, 6, '1.evil.example/']) {
    await expect(connectKWS({ dc, media: false }, signal, fetcher)).rejects.toThrow('obfuscation');
  }
  expect(fetcher).not.toHaveBeenCalled();
});

it('sends an unaligned and an aligned media packet as separate KWS messages', async () => {
  const fixture = transportFixture();
  const peer = new FakeSocket();
  const { lane, group, client } = laneOf(1, fixture, async () => peer);
  try {
    client.receive(encodeFrame(2, 1, fixture.wire));
    const packets = [packet(Buffer.alloc(512 * 1024 - 5, 31)), packet(Buffer.alloc(512 * 1024 - 4, 12))];
    for (const bytes of packets) client.receive(encodeFrame(2, 1, fixture.toWorker.update(bytes)));
    await until(() => peer.sent.length === 3 && !lane.upBusy);
    const { forward } = headers(peer, 0xdd, -2);
    expect(peer.sent.slice(1).map(wire => forward.update(wire))).toEqual(packets);
  } finally {
    client.close();
  }
  expect(group.bytes).toBe(0);
});

it('releases an idle lane when the parent session expires', async () => {
  vi.useFakeTimers();
  const group = { ...syntheticGroup(), expires: Math.floor(Date.now() / 1000) + 1 };
  const client = new FakeSocket();
  try {
    const lane = new Lane(client, 1, transportFixture().secret, group);
    lane.attach();
    client.receive(encodeFrame(1, 1));
    await vi.advanceTimersByTimeAsync(1000);
    expect(lane.ended).toBe(true);
    expect(client.readyState).toBe(3);
    expect(client.code).toBe(4001);
    expect(group.active).toBe(0);
    expect(group.bytes).toBe(0);
  } finally {
    client.close();
    vi.useRealTimers();
  }
});

it('rejects stream input at the expiry instant even when the timer has not run', () => {
  vi.useFakeTimers();
  try {
    const now = 1_791_000_000_000;
    vi.setSystemTime(now);
    const group = { ...syntheticGroup(), expires: now / 1000 + 1 };
    const client = new FakeSocket();
    const dial = vi.fn();
    const lane = new Lane(client, 1, transportFixture().secret, group, dial);
    lane.attach();
    vi.setSystemTime(now + 1000);
    client.receive(encodeFrame(1, 1));
    expect(client.code).toBe(4001);
    expect(client.sent).toHaveLength(0);
    expect(group.active).toBe(0);
    expect(group.bytes).toBe(0);
    expect(dial).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    vi.useRealTimers();
  }
});

it('emits one lane CLOSE for a disconnected KWS peer and keeps the sibling usable', async () => {
  const fixture = transportFixture();
  const peer = new FakeSocket(), sibling = new FakeSocket();
  const a = laneOf(1, fixture, async () => peer);
  const b = laneOf(2, fixture, async () => sibling);
  try {
    a.client.receive(encodeFrame(2, 1, fixture.wire));
    b.client.receive(encodeFrame(2, 2, fixture.wire));
    await until(() => !a.lane.upBusy && !b.lane.upBusy);
    expect(peer.readyState).toBe(1);
    expect(sibling.readyState).toBe(1);
    peer.close();
    peer.dispatchEvent(new Event('error'));
    expect(frames(a.client, 3)).toHaveLength(1);
    const data = Buffer.from([1, 2, 3]);
    sibling.receive(headers(sibling, 0xdd, -2).reverse.update(data));
    await until(() => !b.lane.downBusy);
    expect(fixture.fromWorker.update(Buffer.concat(frames(b.client, 2)))).toEqual(data);
    expect(b.client.readyState).toBe(1);
    expect(a.group.bytes).toBe(0);
    expect(a.group.active).toBe(0);
  } finally {
    a.client.close();
    b.client.close();
  }
});

it('releases the upstream data charge before a congested downstream send', async () => {
  const fixture = transportFixture();
  const peer = new FakeSocket();
  const { lane, group, client } = laneOf(1, fixture, async () => peer);
  const payload = Buffer.alloc(256 * 1024, 3);
  try {
    client.receive(encodeFrame(2, 1, fixture.wire));
    await until(() => peer.sent.length === 1 && !lane.upBusy);
    client.bufferedAmount = 2 * 1024 * 1024;
    const drain = vi.spyOn(lane, 'drain');
    peer.receive(headers(peer, 0xdd, -2).reverse.update(payload));
    await until(() => drain.mock.calls.length === 1);
    expect(group.bytes).toBe(4 * (payload.length + 32));
  } finally {
    client.close();
  }
  await until(() => group.bytes === 0);
});

it('releases consumed upload buffers before waiting to return credit', async () => {
  const fixture = transportFixture();
  const peer = new FakeSocket();
  const { lane, group, client } = laneOf(1, fixture, async () => peer);
  const payload = packet(Buffer.alloc(256 * 1024 - 4, 31));
  try {
    client.receive(encodeFrame(2, 1, fixture.wire));
    await until(() => !lane.upBusy);
    const creditBefore = lane.receiving;
    client.bufferedAmount = 2 * 1024 * 1024;
    const drain = vi.spyOn(lane, 'drain');
    client.receive(encodeFrame(2, 1, fixture.toWorker.update(payload)));
    await until(() => drain.mock.calls.length === 1);
    expect(group.bytes).toBe(0);
    expect(lane.receiving).toBe(creditBefore - payload.length);
    expect(headers(peer, 0xdd, -2).forward.update(peer.sent[1])).toEqual(payload);
    client.bufferedAmount = 0;
    await until(() => !lane.upBusy);
    expect(frames(client, 4).map(frame => frame.readUInt32BE())).toEqual([64, payload.length]);
    expect(lane.receiving).toBe(creditBefore);
  } finally {
    client.close();
  }
  expect(group.bytes).toBe(0);
});

it('backs off native queue checks, releases drained bytes and cancels the next check on close', async () => {
  vi.useFakeTimers();
  const { lane, group, client } = laneOf(1, transportFixture(), async () => new FakeSocket());
  const send = client.send.bind(client);
  client.send = bytes => { send(bytes); client.bufferedAmount += bytes.length; };
  try {
    lane.writeNative(client, encodeFrame(4, 1, windowFrame(64)));
    const reconcile = vi.spyOn(lane, 'reconcileNative');
    await vi.advanceTimersByTimeAsync(1000);
    expect(reconcile.mock.calls.filter(([socket]) => socket === client)).toHaveLength(6);
    expect(group.bytes).toBe(12);
    client.bufferedAmount = 0;
    await vi.advanceTimersByTimeAsync(250);
    expect(group.bytes).toBe(0);
    expect(lane.nativeTimer).toBeNull();
    lane.writeNative(client, encodeFrame(4, 1, windowFrame(64)));
    client.close();
    expect(vi.getTimerCount()).toBe(0);
    expect(group.bytes).toBe(0);
  } finally {
    client.close();
    vi.useRealTimers();
  }
});

it.each([undefined, NaN, Infinity, -1])('keeps application flow control with an unavailable native buffer (%s)', async amount => {
  const fixture = transportFixture();
  const peer = new FakeSocket();
  const { lane, group, client } = laneOf(1, fixture, async () => peer);
  client.bufferedAmount = peer.bufferedAmount = amount;
  try {
    client.receive(encodeFrame(2, 1, fixture.wire));
    await until(() => frames(client, 4).length === 1);
    const payload = Buffer.alloc(2 * 65536 + 13, 9);
    const { reverse } = headers(peer, 0xdd, -2);
    peer.receive(reverse.update(payload));
    await until(() => !lane.downBusy);
    expect(fixture.fromWorker.update(Buffer.concat(frames(client, 2)))).toEqual(payload);
    expect(lane.sending).toBe(4 * 1024 * 1024 - payload.length);
    expect(lane.nativeTimer).toBeNull();
    expect(group.bytes).toBe(0);
  } finally {
    client.close();
  }
});

it('reclaims a small native queue when only the other direction makes progress', async () => {
  vi.useFakeTimers();
  const peer = new FakeSocket();
  peer.accept();
  const { lane, group, client } = laneOf(1, transportFixture(), async () => peer, { stallMs: 1000 });
  lane.peer = peer;
  const queueSends = socket => {
    const send = socket.send.bind(socket);
    socket.send = bytes => { send(bytes); socket.bufferedAmount += bytes.length; };
  };
  queueSends(client);
  queueSends(peer);
  try {
    lane.writeNative(client, new Uint8Array(12));
    lane.writeNative(peer, new Uint8Array(64));
    await vi.advanceTimersByTimeAsync(400);
    peer.bufferedAmount = 40;
    await vi.advanceTimersByTimeAsync(599);
    expect(lane.ended).toBe(false);
    expect(group.bytes).toBe(52);
    await vi.advanceTimersByTimeAsync(1);
    expect(lane.ended).toBe(true);
    expect(group.bytes).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    client.close();
    vi.useRealTimers();
  }
});

it('extends a queued socket deadline on partial writes and leaves a drained lane open', async () => {
  vi.useFakeTimers();
  const { lane, group, client } = laneOf(1, transportFixture(), async () => new FakeSocket(), { stallMs: 1000 });
  const send = client.send.bind(client);
  client.send = bytes => { send(bytes); client.bufferedAmount += bytes.length; };
  try {
    lane.writeNative(client, new Uint8Array(12));
    await vi.advanceTimersByTimeAsync(500);
    client.bufferedAmount = 6;
    await vi.advanceTimersByTimeAsync(700);
    expect(lane.ended).toBe(false);
    expect(group.bytes).toBe(6);
    client.bufferedAmount = 0;
    await vi.advanceTimersByTimeAsync(1200);
    expect(group.bytes).toBe(0);
    expect(lane.nativeTimer).toBeNull();
    expect(lane.ended).toBe(false);
  } finally {
    client.close();
    vi.useRealTimers();
  }
});

it('closes an accounted socket whose native buffer reading becomes invalid', async () => {
  vi.useFakeTimers();
  const { lane, group, client } = laneOf(1, transportFixture(), async () => new FakeSocket());
  const send = client.send.bind(client);
  client.send = bytes => { send(bytes); client.bufferedAmount += bytes.length; };
  try {
    lane.sendCredit(64);
    expect(group.bytes).toBe(12);
    client.bufferedAmount = NaN;
    await vi.advanceTimersByTimeAsync(30);
    expect(lane.ended).toBe(true);
    expect(group.bytes).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    client.close();
    vi.useRealTimers();
  }
});

it('backs off reads of an unchanged send buffer and enforces the exact stall deadline', async () => {
  vi.useFakeTimers();
  const { lane, client } = laneOf(1, transportFixture(), async () => new FakeSocket(), { stallMs: 1000 });
  const read = vi.fn(() => 2 * 1024 * 1024);
  Object.defineProperty(client, 'bufferedAmount', { get: read });
  try {
    const drained = expect(lane.drain(client, 8)).rejects.toThrow('socket-backpressure');
    await vi.advanceTimersByTimeAsync(1000);
    await drained;
    expect(read.mock.calls.length).toBeLessThan(40);
  } finally {
    client.close();
    vi.useRealTimers();
  }
});

it('delivers final unaligned upstream bytes before the lane CLOSE on a normal peer close', async () => {
  const fixture = transportFixture();
  const peer = new FakeSocket();
  const { lane, group, client } = laneOf(1, fixture, async () => peer);
  try {
    client.receive(encodeFrame(2, 1, fixture.wire));
    await until(() => frames(client, 4).length === 1);
    const payloads = [Buffer.alloc(17, 91), Buffer.alloc(143, 81)];
    const { reverse } = headers(peer, 0xdd, -2);
    for (const payload of payloads) peer.receive(reverse.update(payload));
    peer.close(1000);
    await until(() => lane.ended && !lane.downBusy);
    expect(fixture.fromWorker.update(Buffer.concat(frames(client, 2)))).toEqual(Buffer.concat(payloads));
    expect(client.sent.at(-1)[0]).toBe(3);
    expect(frames(client, 3)).toHaveLength(1);
    expect(group.bytes).toBe(0);
  } finally {
    client.close();
  }
});

it('bounds the lifetime of final data waiting for a blocked client', async () => {
  const fixture = transportFixture();
  const peer = new FakeSocket();
  const { lane, group, client } = laneOf(1, fixture, async () => peer, { stallMs: 120 });
  try {
    client.receive(encodeFrame(2, 1, fixture.wire));
    await until(() => frames(client, 4).length === 1);
    client.bufferedAmount = 2 * 1024 * 1024;
    peer.receive(headers(peer, 0xdd, -2).reverse.update(Buffer.alloc(231, 53)));
    peer.close(1000);
    await until(() => lane.ended && !lane.downBusy);
    expect(frames(client, 2)).toHaveLength(0);
    expect(group.bytes).toBe(0);
    expect(lane.peerDrainTimer).toBeNull();
  } finally {
    client.close();
  }
});

it('bounds the allocation for an incomplete maximum-size packet and reclaims it on close', async () => {
  const fixture = transportFixture();
  const peer = new FakeSocket();
  const { lane, group, client } = laneOf(1, fixture, async () => peer);
  try {
    client.receive(encodeFrame(2, 1, fixture.wire));
    await until(() => frames(client, 4).length === 1);
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32LE(8 * 1024 * 1024);
    client.receive(encodeFrame(2, 1, fixture.toWorker.update(prefix)));
    await until(() => frames(client, 4).length === 2);
    expect(peer.sent).toHaveLength(1);
    expect(group.bytes).toBe(64 * 1024);
  } finally {
    client.close();
  }
  expect(group.bytes).toBe(0);
});
