import { afterEach, expect, it, vi } from 'vitest';
import { connectKWS, UpstreamRouter } from '../telegram_webproxy.js';
import { FakeSocket } from './fixtures.js';

afterEach(() => vi.useRealTimers());

const control = { dc: 2, media: false };
const good = () => ({
  status: 101, webSocket: new FakeSocket(), headers: new Headers({ 'Sec-WebSocket-Protocol': 'binary' }),
});

it('skips a repeatedly failing primary per DC and traffic class, then probes it again', async () => {
  vi.useFakeTimers();
  const router = new UpstreamRouter();
  let failed = true;
  const fetcher = vi.fn(url => new Promise(resolve => {
    const reject = failed && new URL(url).hostname === 'kws2.web.telegram.org';
    setTimeout(() => resolve(reject ? new Response(null, { status: 502 }) : good()), reject ? 500 : 50);
  }));
  async function dial() {
    const time = Date.now();
    const attempts = fetcher.mock.calls.length;
    const pending = connectKWS(control, new AbortController().signal, fetcher, 3000, 900, router);
    let sample;
    void pending.then(socket => {
      socket.close();
      sample = [Date.now() - time, fetcher.mock.calls.length - attempts];
    });
    await vi.advanceTimersByTimeAsync(600);
    return sample;
  }
  expect(await dial()).toEqual([550, 2]);
  expect(await dial()).toEqual([550, 2]);
  expect(await dial()).toEqual([50, 1]);
  expect(router.plan({ dc: 2, media: true })).toEqual([0, 1]);
  expect(router.plan({ dc: 1, media: false })).toEqual([0, 1]);
  await vi.advanceTimersByTimeAsync(15000);
  failed = false;
  expect(await dial()).toEqual([50, 1]);
  expect(new URL(fetcher.mock.lastCall[0]).hostname).toBe('kws2.web.telegram.org');
});

it('learns only from outcomes and rejects a stale failure after a newer success', () => {
  let clock = 50;
  const router = new UpstreamRouter(() => clock);
  const old = router.start(control, 0);
  const cancelled = router.start(control, 0);
  expect(cancelled).toBeTypeOf('function');
  router.start(control, 0)(true);
  old(false);
  router.start(control, 0)(false);
  expect(router.plan(control)).toEqual([0, 1]);
  router.start(control, 0)(false);
  expect(router.plan(control)).toEqual([1, 0]);
  expect(router.canHedge(control, 0)).toBe(false);
  clock += 15001;
  expect(router.plan(control)).toEqual([0, 1]);
  const probe = router.start(control, 0);
  expect(router.plan(control)).toEqual([1, 0]);
  probe(true);
  expect(router.plan(control)).toEqual([0, 1]);
});
