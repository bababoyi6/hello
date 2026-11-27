import { connect } from 'cloudflare:sockets';
import { expect, inject, it, vi } from 'vitest';
import { createWorker, encodeFrame, visitFrames } from '../telegram_webproxy.js';
import { createTCPEngine } from '../experiments/tcp.mjs';
import { ENV, ORIGIN, VECTOR, packet, transportFixture } from './fixtures.js';

it('forwards a fragmented upload and drains the final native TCP bytes on EOF in workerd', async () => {
  const dial = vi.fn((_, options) => connect({ hostname: '127.0.0.1', port: inject('tcpOriginPort') }, options));
  const worker = createWorker(createTCPEngine(dial), true);
  const document = await worker.fetch(new Request(ORIGIN + '/?bridge=' + VECTOR), ENV);
  const ticket = /"ticket":"([A-Za-z0-9_-]{43})"/.exec(await document.text())?.[1];
  expect(ticket).toBeTruthy();

  const upgraded = await worker.fetch(new Request(ORIGIN + '/api/v1/ws', { headers: {
    Upgrade: 'websocket', 'Sec-WebSocket-Protocol': 'tproxy-lane-v1.' + ticket + '.1',
  } }), ENV);
  expect(upgraded.status).toBe(101);
  const client = upgraded.webSocket;
  try {
    client.binaryType = 'arraybuffer';
    client.accept();
    const received = [];
    let closeFrame = false;
    client.addEventListener('message', ({ data }) => visitFrames(data, (type, id, bytes, start, end) => {
      expect(id).toBe(1);
      if (type === 2) received.push(bytes.slice(start, end));
      if (type === 3) closeFrame = true;
    }));
    const closed = new Promise(resolve => client.addEventListener('close', resolve, { once: true }));
    const fixture = transportFixture(0xdd, 2);
    const upload = fixture.toWorker.update(packet(Buffer.alloc(125000, 67)));
    client.send(encodeFrame(1, 1));
    client.send(encodeFrame(2, 1, fixture.wire));
    for (let offset = 0; offset < upload.length; offset += 49148) {
      client.send(encodeFrame(2, 1, upload.subarray(offset, offset + 49148)));
    }
    expect((await closed).code).toBe(1000);
    expect(closeFrame).toBe(true);
    expect(dial).toHaveBeenCalledOnce();
    const actual = fixture.fromWorker.update(Buffer.concat(received));
    const expected = Buffer.from(Array.from({ length: 131071 }, (_, i) => (i * 13 + 97) & 255));
    expect(actual.length).toBe(expected.length);
    expect(actual.equals(expected)).toBe(true);
  } finally {
    client.close();
  }
});
