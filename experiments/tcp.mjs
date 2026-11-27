// SPDX-License-Identifier: GPL-3.0-only
// TDLib production TCP bootstrap IPv4 addresses, one per regular DC.
// https://github.com/tdlib/td/blob/master/td/telegram/net/ConnectionCreator.cpp
const endpoints = Object.freeze([
  '149.154.175.50', '149.154.167.51', '149.154.175.100', '149.154.167.91', '149.154.171.5',
]);

function closeSocket(socket) {
  try { void socket.close().catch(() => {}); } catch {}
}

class TCPPeer {
  constructor(socket) {
    this.socket = socket;
    this.reader = socket.readable.getReader({ mode: 'byob' });
    try {
      this.writer = socket.writable.getWriter();
    } catch (error) {
      this.reader.releaseLock();
      throw error;
    }
  }

  read(size) {
    return this.reader.read(new Uint8Array(size));
  }

  write(bytes) {
    return this.writer.write(bytes);
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    closeSocket(this.socket);
    this.reader.releaseLock();
    this.writer.releaseLock();
  }
}

export function createTCPEngine(connect, timeout = 3000) {
  return async ({ dc, media }, signal) => {
    if (!Number.isInteger(dc) || dc < 1 || dc > endpoints.length || media !== false) {
      throw new Error('Unsupported direct Telegram DC');
    }
    if (signal.aborted) throw new Error('TCP cancelled');
    const socket = connect({ hostname: endpoints[dc - 1], port: 443 }, { secureTransport: 'off', allowHalfOpen: false });
    void socket.closed.catch(() => {});
    let timer, abort;
    try {
      const cancelled = new Promise((_, reject) => {
        abort = () => reject(new Error('TCP cancelled'));
        signal.addEventListener('abort', abort, { once: true });
        timer = setTimeout(() => reject(new Error('TCP connect timeout')), timeout);
        if (signal.aborted) abort();
      });
      await Promise.race([socket.opened, cancelled]);
      if (signal.aborted) throw new Error('TCP cancelled');
      return new TCPPeer(socket);
    } catch (error) {
      closeSocket(socket);
      throw error;
    } finally {
      clearTimeout(timer);
      signal.removeEventListener('abort', abort);
    }
  };
}
