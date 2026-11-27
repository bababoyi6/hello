import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { pathToFileURL } from 'node:url';
import { encodeFrame, visitFrames } from '../telegram_webproxy.js';
import { createTCPEngine } from '../experiments/tcp.mjs';
import { FakeSocket, independentCTR, packet, syntheticGroup, transportFixture, until, windowFrame } from '../tests/fixtures.js';

const ORIGINAL = 'e565c57ff58656fd544755f67e1c266148c0b88f';
const candidatePath = process.argv.find(arg => arg.startsWith('--candidate='))?.slice('--candidate='.length);
const candidateURL = candidatePath ? pathToFileURL(candidatePath) : new URL('../telegram_webproxy.js', import.meta.url);
const countCopies = process.argv.includes('--copy-stats');
const copies = { calls: 0, bytes: 0 };
if (countCopies) {
  // Shadow only this module's Uint8Array. Count explicit .set calls in the
  // Worker, leaving fixture generation and native copies outside the metric.
  globalThis.MeasuredWorkerBytes = class extends Uint8Array {
    static [Symbol.hasInstance](value) { return value instanceof Uint8Array; }
    set(source, offset) {
      super.set(source, offset);
      copies.calls++;
      copies.bytes += source.length;
    }
  };
}
function moduleSource(source) {
  const prefix = countCopies ? 'const Uint8Array = globalThis.MeasuredWorkerBytes;\n' : '';
  return 'data:text/javascript;base64,' + Buffer.from(prefix + source).toString('base64');
}
const { Lane } = await import(countCopies ? moduleSource(readFileSync(candidateURL, 'utf8')) : candidateURL.href);
const verifyPayload = process.argv.includes('--verify');
const compare = process.argv.find(arg => arg.startsWith('--against='));
let baseline = null;
let BaselineLane, mkSession;
if (compare !== undefined) {
  const revision = compare.slice('--against='.length);
  if (!revision) throw new Error('--against requires a Git revision');
  baseline = execFileSync('git', ['rev-parse', '--verify', '--end-of-options', revision + '^{commit}'], {
    encoding: 'utf8',
  }).trim();
  const upstream = execFileSync('git', ['show', baseline + ':telegram_webproxy.js'], { encoding: 'utf8' });
  const baselineSource = baseline === ORIGINAL ? upstream + '\nexport { mkSession };' : upstream;
  ({ Lane: BaselineLane, mkSession } = await import(moduleSource(baselineSource)));
  if (!BaselineLane && !mkSession) throw new Error('The reference must export Lane or mkSession');
}
const workloads = [
  ['交互小包', [[220, 60, 1]]],
  ['交互与媒体', [[160, 124, 1], [64, 65532, 8], [96, 8188, 12]]],
  ['连续大块', [[96, 131068, 8]]],
  ['512 KiB 媒体包', [[32, 524284, 2]]],
  ['持续下载', [[128, 131068, 8, 'down']]],
  ['持续上传', [[64, 524284, 4, 'up']]],
];
if (process.argv.includes('--sizes')) {
  for (const size of [1024, 16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024]) {
    workloads.push([size / 1024 + ' KiB 下载', [[64, size - 4, size >= 1024 * 1024 ? 2 : 8, 'down']]]);
  }
  workloads.push(['1024 KiB 上传', [[32, 1024 * 1024 - 4, 2, 'up']]]);
  workloads.push(['非对齐媒体下载', [[96, 128 * 1024 - 7, 8, 'down']]]);
  workloads.push(['分片媒体上传', [[24, 1024 * 1024 - 7, 2, 'up', false, 48 * 1024]]]);
  workloads.push(['慢客户端持续下载', [[64, 128 * 1024 - 4, 8, 'down', true]]]);
}

class Socket extends FakeSocket {
  sentBytes = 0;
  sends = 0;
  head;
  send(value) {
    if (this.readyState !== 1) throw Error('closed');
    if (this.sends++ === 0) this.head = Buffer.from(value);
    this.sentBytes += value.byteLength;
    this.onSend?.(value);
  }
}

class TCPSocket extends Socket {
  opened = Promise.resolve();
  closed = Promise.resolve();
  readable = new ReadableStream({ type: 'bytes', start: controller => { this.controller = controller; } });
  writable = new WritableStream({ write: bytes => this.send(bytes) });

  constructor() {
    super();
    this.accept();
  }

  receive(bytes) {
    this.controller.enqueue(Uint8Array.from(bytes));
  }

  async close() {
    super.close();
    const pending = this.controller.byobRequest;
    this.controller.close();
    pending?.respond(0);
  }
}

function openFixture() {
  return new Promise(resolve => {
    const native = globalThis.WebSocket;
    globalThis.WebSocket = class extends Socket {
      protocol = 'binary';
      constructor() {
        super();
        queueMicrotask(() => {
          this.accept();
          this.dispatchEvent(new Event('open'));
          globalThis.WebSocket = native;
          resolve(this);
        });
      }
    };
  });
}

async function start(version, id, [count, size, burst, direction, slow = false, fragment = 0]) {
  const directTCP = version === 'tcp' || version === 'upstream-tcp';
  const fixture = transportFixture(0xdd, id);
  const client = new Socket();
  const expected = verifyPayload ? createHash('sha256') : null;
  const receivedUp = verifyPayload && direction !== 'down' ? createHash('sha256') : null;
  const receivedDown = verifyPayload && direction !== 'up' ? createHash('sha256') : null;
  let peer, current;
  let credit = 0, downstream = 0, queuedPayload = 0, wake;
  client.onSend = data => {
    if (slow && data[0] === 2) client.bufferedAmount += data.byteLength;
    visitFrames(data, (type, sid, bytes, start, end) => {
      if (type === 4) credit += new DataView(bytes.buffer, bytes.byteOffset).getUint32(start);
      if (type === 2) {
        downstream += end - start;
        if (receivedDown) receivedDown.update(fixture.fromWorker.update(bytes.subarray(start, end)));
        if (slow) queuedPayload += end - start;
        else client.receive(encodeFrame(4, id, windowFrame(end - start)));
      }
    });
    wake?.();
  };
  let ready;
  if (version === 'upstream' && !BaselineLane) {
    ready = openFixture();
    mkSession({ secret: fixture.secret, sid: id }).attach(client);
  } else {
    peer = directTCP ? new TCPSocket() : new Socket();
    const Relay = version.startsWith('upstream') ? BaselineLane : Lane;
    const dial = directTCP ? createTCPEngine(() => peer) : async () => peer;
    current = new Relay(client, id, fixture.secret, syntheticGroup(), dial, { directTCP });
    current.attach();
    ready = Promise.resolve(peer);
  }
  client.receive(encodeFrame(1, id));
  client.receive(encodeFrame(2, id, fixture.wire));
  peer = await ready;
  await until(() => peer.sends === 1 && credit === 64);
  const reverse = independentCTR(peer.head, null, true);
  if (receivedUp) {
    const forward = independentCTR(peer.head);
    forward.update(peer.head); // The 64-byte obfuscation header consumes the first four blocks.
    peer.onSend = bytes => receivedUp.update(forward.update(bytes));
  }
  const payload = packet(Buffer.alloc(size, 47));
  const batches = [];
  for (let i = 0; i < count; i += burst) {
    const batch = [];
    for (let pos = i; pos < Math.min(count, i + burst); pos++) {
      let sample = payload;
      if (expected) {
        sample = Buffer.from(payload);
        sample.writeUInt16LE(pos, sample.length - 2);
        expected.update(sample);
      }
      const uplink = [];
      if (direction !== 'down') {
        const encoded = fixture.toWorker.update(sample);
        const step = fragment || encoded.length;
        for (let start = 0; start < encoded.length; start += step) {
          uplink.push(encodeFrame(2, id, encoded.subarray(start, start + step)));
        }
      }
      batch.push([uplink, direction !== 'up' ? reverse.update(sample) : null]);
    }
    batches.push(batch);
  }
  const consume = slow ? setInterval(() => {
    const wireBytes = Math.min(client.bufferedAmount, 128 * 1024);
    client.bufferedAmount -= wireBytes;
    const payloadBytes = Math.min(queuedPayload, wireBytes);
    if (!payloadBytes) return;
    queuedPayload -= payloadBytes;
    client.receive(encodeFrame(4, id, windowFrame(payloadBytes)));
  }, 4) : null;
  return {
    client, peer, budgetBytes: () => current?.group.bytes ?? 0,
    async close() {
      clearInterval(consume);
      client.close();
      if (current) await until(() => !current.upBusy && !current.downBusy);
    },
    async replay(latencies, probe) {
      let upBytes = 0, downBytes = 0;
      for (const batch of batches) {
        const time = performance.now();
        if (direction !== 'down') upBytes += batch.length * payload.length;
        if (direction !== 'up') downBytes += batch.length * payload.length;
        await new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error('bench lane timed out')), 5000);
          wake = () => {
            if (downstream < downBytes || credit < upBytes + 64) return;
            wake = null;
            clearTimeout(timer);
            resolve();
          };
          for (const [up, down] of batch) {
            for (const carrier of up) client.receive(carrier);
            if (down) peer.receive(down);
          }
          if (slow) probe();
        });
        latencies.push(performance.now() - time);
        probe();
      }
      if (slow) await until(() => client.bufferedAmount === 0);
      if (credit !== upBytes + 64 || downstream !== downBytes) throw new Error('byte count mismatch');
      if (peer.sentBytes !== upBytes + 64) throw new Error('upstream byte count mismatch');
      if (!directTCP && peer.sends !== (direction === 'down' ? 1 : count + 1)) {
        throw new Error('KWS frame boundary mismatch');
      }
      if (expected) {
        const checksum = expected.digest('hex');
        if ((receivedUp && receivedUp.digest('hex') !== checksum) ||
            (receivedDown && receivedDown.digest('hex') !== checksum)) throw new Error('plaintext integrity mismatch');
      }
      return upBytes + downBytes;
    },
  };
}

async function measure(version, spec) {
  const lanes = [];
  const samples = [];
  const cryptoStats = { calls: 0, output: 0 };
  const originalEncrypt = crypto.subtle.encrypt;
  const takeMemory = () => process.memoryUsage().arrayBuffers;
  let timer;
  try {
    for (const [n, lane] of spec.entries()) lanes.push(await start(version, n + 1, lane));
    globalThis.gc?.();
    const before = takeMemory();
    let peak = before, peakBudget = 0;
    const probe = () => {
      peak = Math.max(peak, takeMemory());
      peakBudget = Math.max(peakBudget, lanes.reduce((sum, lane) => sum + lane.budgetBytes(), 0));
    };
    timer = setInterval(probe, 2);
    crypto.subtle.encrypt = async function (algorithm, key, input) {
      const result = await originalEncrypt.call(this, algorithm, key, input);
      cryptoStats.calls++;
      cryptoStats.output += result.byteLength;
      return result;
    };
    copies.calls = copies.bytes = 0;
    const startTime = performance.now();
    const startCPU = process.cpuUsage();
    const bytes = (await Promise.all(lanes.map(lane => lane.replay(samples, probe)))).reduce((a, b) => a + b);
    const elapsed = performance.now() - startTime;
    const cpu = process.cpuUsage(startCPU);
    probe();
    samples.sort((a, b) => a - b);
    const percentile = p => samples[Math.ceil(samples.length * p) - 1];
    return {
      MiBps: bytes / (1024 * 1024) / (elapsed / 1000),
      cpuMs: (cpu.user + cpu.system) / 1000, p50Ms: percentile(.50), p95Ms: percentile(.95),
      peakBuffersMiB: (peak - before) / (1024 * 1024), peakBudgetMiB: peakBudget / (1024 * 1024),
      cryptoCalls: cryptoStats.calls,
      cryptoOutputMiB: cryptoStats.output / (1024 * 1024),
      ...(countCopies ? { jsPayloadCopies: copies.calls, jsCopiedBytes: copies.bytes } : {}),
      [version.endsWith('tcp') ? 'tcpWrites' : 'kwsSends']: lanes.reduce((n, lane) => n + lane.peer.sends - 1, 0),
      workerSends: lanes.reduce((n, lane) => n + lane.client.sends - 1, 0),
    };
  } finally {
    clearInterval(timer);
    crypto.subtle.encrypt = originalEncrypt;
    await Promise.all(lanes.map(lane => lane.close()));
  }
}

const rounds = process.argv.includes('--quick') ? 3 : 7;
const variants = baseline ? ['upstream', 'candidate'] : ['candidate'];
if (process.argv.includes('--tcp')) {
  if (BaselineLane && process.argv.includes('--tcp-baseline')) variants.push('upstream-tcp');
  variants.push('tcp');
}
console.log(JSON.stringify({ node: process.version, platform: process.platform, cpus: availableParallelism(), rounds, baseline, candidatePath, verifyPayload, countCopies }));
for (const [name, spec] of workloads) {
  const results = Object.fromEntries(variants.map(variant => [variant, []]));
  for (const variant of variants) await measure(variant, spec);
  for (let i = 0; i < rounds; i++) {
    const order = i % 2 ? variants.toReversed() : variants;
    for (const variant of order) results[variant].push(await measure(variant, spec));
  }
  for (const [variant, rows] of Object.entries(results)) {
    const summary = Object.fromEntries(Object.keys(rows[0]).map(metric => {
      const values = rows.map(row => row[metric]).sort((a, b) => a - b);
      const round = n => Number(n.toFixed(3));
      return [metric, [round(values[(values.length - 1) / 2]), round(values[0]), round(values.at(-1))]];
    }));
    console.log(JSON.stringify({ name, variant, medianMinMax: summary }));
  }
}
