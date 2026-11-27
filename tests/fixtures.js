import { createCipheriv, createHash } from 'node:crypto';

export const HOST = 'proxy.example.com';
export const ORIGIN = 'https://' + HOST;
export const VECTOR = 'cF3iQgotmFPcdnqmM642-vNpdfk-WLl8e50OXWBuxBQ';
export const PROXY_SECRET = 'f7113e191685fefc9ae763a6d4e77c1f';
export const ENV = {
  p: 'synthetic-case-1',
  PORTAL_KEY: '29ea5f6692816233fd6716b5728035fe' + '30349835161228520064a5015a2a50af',
};
export const HELLO = Uint8Array.of(16, 0, 0, 0, 0, 0, 0, 1, 1);

export const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

export async function until(predicate, timeout = 5000) {
  const start = performance.now();
  while (!predicate()) {
    if (performance.now() - start > timeout) throw new Error('fixture timed out');
    await wait(1);
  }
}

export class FakeSocket extends EventTarget {
  bufferedAmount = 0;
  readyState = 0;
  sent = [];

  accept() {
    this.readyState = 1;
  }

  send(value) {
    if (this.readyState !== 1) throw Error('socket closed');
    const data = Buffer.from(value instanceof ArrayBuffer ? new Uint8Array(value) : value);
    this.sent.push(data);
    this.onSend?.(data);
  }

  receive(data) {
    if (this.readyState !== 1) throw Error('socket closed');
    this.dispatchEvent(new MessageEvent('message', { data }));
  }

  close(code = 1000) {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.code = code;
    const event = new Event('close');
    event.code = code;
    this.dispatchEvent(event);
  }
}

export function synthetic(seed) {
  let state = seed;
  return max => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) % max;
  };
}

export function independentCTR(head, secret, reverse) {
  const material = Buffer.from(head.subarray(8, 56));
  if (reverse) material.reverse();
  const key = material.subarray(0, 32);
  const derived = secret?.length ? createHash('sha256').update(key).update(secret).digest() : key;
  return createCipheriv('aes-256-ctr', derived, material.subarray(32));
}

export function transportFixture(mode = 0xdd, dc = -2, secret = Buffer.from(PROXY_SECRET, 'hex')) {
  const head = Buffer.from(Array.from({ length: 64 }, (_, i) => (i * 13 + 23) & 255));
  head.fill(mode, 56, 60);
  head.writeInt16LE(dc, 60);
  const toWorker = independentCTR(head, secret, false);
  const fromWorker = independentCTR(head, secret, true);
  const wire = toWorker.update(head);
  head.copy(wire, 0, 0, 56);
  return { secret, wire, toWorker, fromWorker, head };
}

export function packet(payload, mode = 0xdd, quickAck = false) {
  if (mode !== 0xef) {
    const header = Buffer.alloc(4);
    header.writeUInt32LE(payload.length + (quickAck ? 0x80000000 : 0));
    return Buffer.concat([header, payload]);
  }
  const words = payload.length / 4;
  const flag = quickAck ? 0x80 : 0;
  const header = words < 127 ? Buffer.of(words | flag) :
    Buffer.of(127 | flag, words & 255, (words >>> 8) & 255, words >>> 16);
  return Buffer.concat([header, payload]);
}

export function windowFrame(size) {
  const result = Buffer.alloc(4);
  result.writeUInt32BE(size);
  return result;
}

export function syntheticGroup() {
  return { active: 1, bytes: 0, deleted: false };
}

export function authRequest(path, token, body, method = 'POST', host = ORIGIN) {
  return new Request(host + path, {
    method, body,
    headers: {
      Authorization: 'Bearer ' + token,
      ...(body && { 'Content-Type': 'application/octet-stream' }),
    },
  });
}

export async function bridgeBoot(worker, env = ENV) {
  const response = await worker.fetch(new Request(ORIGIN + '/?bridge=' + VECTOR), env);
  const html = await response.text();
  const boot = /,"([A-Za-z0-9_-]{43})"\);<\/script>/.exec(html)?.[1];
  if (!boot) throw new Error('bridge did not issue a bootstrap');
  return boot;
}
