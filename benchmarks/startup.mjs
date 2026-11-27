import { execFileSync } from 'node:child_process';
import { createHmac, hkdfSync, pbkdf2Sync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import '../scripts/node-sockets.mjs';
import { FakeSocket, HELLO, independentCTR, transportFixture } from '../tests/fixtures.js';

const ref = process.argv.find(arg => arg.startsWith('--against='))?.slice('--against='.length) ??
  'cc6854dac1e368c9ad1b3467bcc7cee276c893c7';
const baseline = execFileSync('git', ['rev-parse', '--verify', '--end-of-options', ref + '^{commit}'], {
  encoding: 'utf8',
}).trim();
const moduleUrl = source => 'data:text/javascript;base64,' + source.toString('base64');
const sources = {
  baseline: moduleUrl(execFileSync('git', ['show', baseline + ':telegram_webproxy.js'])),
  candidate: moduleUrl(readFileSync(new URL('../telegram_webproxy.js', import.meta.url))),
};
const env = { p: 'synthetic-startup-benchmark-password' };
const host = 'startup.example.com';
const origin = 'https://' + host;
const seed = pbkdf2Sync(env.p, 'cf-tgproxy-dashboard-v1\0' + host, 16000, 32, 'sha256');
const proxyKey = Buffer.from(hkdfSync('sha256', seed, 'cf-tgproxy-portal-v1', 'telegram-proxy\0' + host, 16));
const capability = createHmac('sha256', proxyKey).update('tdesktop-web-proxy-bridge-v1\n' + host).digest('base64url');
const bridgeRequest = () => new Request(origin + '/?bridge=' + capability);
const rounds = process.argv.includes('--quick') ? 12 : 40;
const warmRuns = 5;
let run = 0;
const freshModule = variant => import(sources[variant] + '#run' + ++run);
const nativeResponse = globalThis.Response;
const nativeFetch = globalThis.fetch;
const nativePair = globalThis.WebSocketPair;

class RelaySocket extends FakeSocket {
  counterpart;
  send(value) {
    if (this.readyState !== 1) throw new Error('closed relay socket');
    const bytes = value instanceof ArrayBuffer ? value.slice(0) : Uint8Array.from(value).buffer;
    const other = this.counterpart;
    queueMicrotask(() => { if (other.readyState === 1) other.receive(bytes); });
  }
}

const probe = () => {
  const marks = {};
  const start = performance.now();
  return { marks, mark: name => { marks[name] = performance.now() - start; } };
};

async function bridgePage(worker) {
  const response = await worker.fetch(bridgeRequest(), env);
  if (response.status !== 200) throw new Error('bridge request failed');
  return (await response.text()).match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/)[1];
}

async function connection(version, reconnect) {
  const { default: worker, encodeFrame } = version;
  const { marks, mark } = probe();
  const traffic = Uint8Array.of(0xa1, 0xb2, 0xc3, 0xd4);
  const transport = transportFixture(0xdd, -2, proxyKey);
  let hide, client, peer, attempts = 0, sessionPosts = 0;
  class UpgradeResponse extends nativeResponse {
    constructor(body, options) {
      if (options?.status === 101) return { ...options, headers: new Headers(options.headers) };
      super(body, options);
    }
  }
  globalThis.Response = UpgradeResponse;
  globalThis.WebSocketPair = class {
    constructor() {
      this[0] = new RelaySocket();
      this[1] = new RelaySocket();
      this[0].counterpart = this[1];
      this[1].counterpart = this[0];
    }
  };
  globalThis.fetch = async () => {
    if (!attempts) mark('validHeadFirstKWSDial');
    if (++attempts === 1 && reconnect) return new UpgradeResponse(null, { status: 503 });
    peer = new FakeSocket();
    peer.onSend = wire => {
      if (wire.length !== 64) throw new Error('invalid upstream initialization');
      mark('upstreamHeaderSent');
      const encrypted = independentCTR(wire, null, true).update(traffic);
      queueMicrotask(() => {
        mark('firstUpstreamBytes');
        peer.receive(encrypted);
      });
    };
    mark('kwsConnected');
    return new UpgradeResponse(null, { status: 101, webSocket: peer, headers: { 'Sec-WebSocket-Protocol': 'binary' } });
  };
  let timer;
  try {
    const script = await bridgePage(worker);
    mark('bridgeDocument');
    await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error('first forwarded bytes timed out')), 4000);
      const injected = { postMessage(value) {
        if (!(value instanceof ArrayBuffer)) return;
        const frame = new Uint8Array(value);
        if (frame[0] === 17) {
          mark('initialSessionReady');
          queueMicrotask(() => {
            injected.onmessage({ data: encodeFrame(1, 1).buffer });
            injected.onmessage({ data: encodeFrame(2, 1, transport.wire).buffer });
          });
        }
        if (frame[0] === 2) {
          try {
            if (!transport.fromWorker.update(frame.subarray(8)).equals(Buffer.from(traffic))) {
              throw new Error('forwarded bytes differ');
            }
            mark('firstForwardedBytes');
            resolve();
          } catch (error) { reject(error); }
        }
      } };
      class BrowserSocket {
        static OPEN = 1;
        readyState = 0;
        bufferedAmount = 0;
        constructor(url, protocol) {
          void worker.fetch(new Request(url.replace(/^wss:/, 'https:'), {
            headers: { Upgrade: 'websocket', 'Sec-WebSocket-Protocol': protocol },
          }), env).then(upgrade => {
            if (upgrade.status !== 101) throw new Error('upgrade failed');
            client = upgrade.webSocket;
            client.accept();
            client.addEventListener('message', event => this.onmessage?.(event));
            this.protocol = upgrade.headers.get('Sec-WebSocket-Protocol');
            this.readyState = 1;
            mark('websocketUpgrade');
            this.onopen?.();
          }).catch(reject);
        }
        send(value) { client.send(value); }
        close() { client?.counterpart.close(); client?.close(); this.readyState = 3; }
      }
      runInNewContext(script, {
        AbortController, ArrayBuffer, Uint8Array, DataView, URL, setTimeout, clearTimeout, performance,
        parent: {}, TelegramWebProxy: injected, WebSocket: BrowserSocket,
        location: { hash: '#android=' + 'A'.repeat(43), pathname: '/' },
        history: { replaceState() {} },
        addEventListener(name, handler) { if (name === 'pagehide') hide = handler; },
        async fetch(url, options) {
          if (options.method === 'POST') sessionPosts++;
          return worker.fetch(new Request(url, options), env);
        },
      });
      mark('bridgeScript');
      injected.onmessage({ data: HELLO.buffer });
    });
    return { ...marks, sessionPosts, kwsAttempts: attempts };
  } finally {
    clearTimeout(timer);
    hide?.();
    peer?.close();
    globalThis.Response = nativeResponse;
    globalThis.fetch = nativeFetch;
    globalThis.WebSocketPair = nativePair;
  }
}

async function wave({ default: worker }) {
  const { marks, mark } = probe();
  const subtle = crypto.subtle;
  const { deriveBits, importKey, verify, sign } = subtle;
  const stats = { PBKDF2: 0, HKDF: 0, keyImports: 0, macs: 0 };
  subtle.deriveBits = function (...args) {
    stats[args[0].name]++;
    return deriveBits.apply(this, args);
  };
  subtle.importKey = function (...args) { stats.keyImports++; return importKey.apply(this, args); };
  subtle.verify = function (...args) { stats.macs++; return verify.apply(this, args); };
  subtle.sign = function (...args) { stats.macs++; return sign.apply(this, args); };
  try {
    await Promise.all(Array.from({ length: 8 }, () => bridgePage(worker)));
    mark('eightBridgeDocuments');
    return { ...marks, ...stats };
  } finally {
    Object.assign(subtle, { deriveBits, importKey, verify, sign });
  }
}

async function sample(variant, mode, warm) {
  const start = performance.now();
  const cpuStart = process.cpuUsage();
  const version = mode === 'warm' ? warm : await freshModule(variant);
  const moduleMs = performance.now() - start;
  const result = mode === 'coldWave' ? await wave(version) : await connection(version, mode === 'primaryFailure');
  const cpu = process.cpuUsage(cpuStart);
  return { ...(mode !== 'warm' && { moduleMs }), ...result, processCpuMs: (cpu.user + cpu.system) / 1000 };
}

console.log(JSON.stringify({ baseline, rounds, node: process.version, platform: process.platform }));
for (const mode of ['cold', 'warm', 'primaryFailure', 'coldWave']) {
  const results = { baseline: [], candidate: [] };
  const warm = {};
  for (const variant of Object.keys(results)) {
    warm[variant] = await freshModule(variant);
    for (let i = 0; i < warmRuns; i++) await sample(variant, mode, warm[variant]);
  }
  for (let i = 0; i < rounds; i++) {
    const order = i % 2 ? ['candidate', 'baseline'] : ['baseline', 'candidate'];
    for (const variant of order) results[variant].push(await sample(variant, mode, warm[variant]));
  }
  for (const [variant, rows] of Object.entries(results)) {
    const summaries = Object.fromEntries(Object.keys(rows[0]).map(name => {
      const sorted = rows.map(row => row[name]).sort((a, b) => a - b);
      const p = percentile => sorted[Math.ceil(percentile * sorted.length) - 1];
      return [name, [p(.5), p(.95), sorted[0], sorted.at(-1)].map(value => Number(value.toFixed(3)))];
    }));
    console.log(JSON.stringify({ mode, variant, successes: rows.length, p50P95MinMax: summaries }));
  }
}
