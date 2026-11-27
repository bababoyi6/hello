import { once } from 'node:events';
import { createServer } from 'node:net';
import { independentCTR } from './fixtures.js';

export default async function startOrigin({ provide }) {
  const connections = new Set();
  const server = createServer(socket => {
    connections.add(socket);
    socket.on('error', () => socket.destroy());
    socket.on('close', () => connections.delete(socket));
    let input = Buffer.alloc(0);
    function receive(chunk) {
      input = Buffer.concat([input, chunk]);
      if (input.length < 64 + 4 + 125000) return;
      socket.removeListener('data', receive);
      const head = input.subarray(0, 64);
      const read = independentCTR(head);
      const write = independentCTR(head, null, true);
      const tag = read.update(head).readUInt32LE(56);
      const uploaded = read.update(input.subarray(64));
      if (tag !== 0xdddddddd || uploaded.readUInt32LE(0) !== 125000 ||
          !uploaded.subarray(4).every(byte => byte === 67)) {
        socket.destroy();
        return;
      }
      const response = write.update(Uint8Array.from({ length: 131071 }, (_, i) => (i * 13 + 97) & 255));
      socket.write(response.subarray(0, 17));
      socket.end(response.subarray(17));
    }
    socket.on('data', receive);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  provide('tcpOriginPort', server.address().port);
  return async () => {
    for (const socket of connections) socket.destroy();
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  };
}
