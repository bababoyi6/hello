import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { crc32 } from 'node:zlib';

const source = readFileSync(new URL('../telegram_webproxy.js', import.meta.url), 'utf8').replaceAll('\r\n', '\n');
const workers = process.argv.includes('--workers');
const filename = workers ? 'telegram_webproxy.js' : '_worker.js';
const archive = workers ? 'Workers.zip' : 'Pages.zip';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
if (!/^const dashboardSeed = '';$/m.test(source) || !/^  const value = env\.p;$/m.test(source)) {
  throw new Error('Build requires the public source with the p Secret');
}
if (/^\s*import\b/m.test(source) || !source.includes('export default')) {
  throw new Error('Expected a standalone Module Worker');
}

// ZIP with one stored file, UTF-8 flag, and fixed timestamp for reproducible releases.
const name = Buffer.from(filename);
const file = Buffer.from(source);
const checksum = crc32(file);
const local = Buffer.alloc(30);
local.writeUInt32LE(0x04034b50, 0);
local.writeUInt16LE(20, 4);
local.writeUInt16LE(0x800, 6);
local.writeUInt16LE(0x21, 12);
local.writeUInt32LE(checksum, 14);
local.writeUInt32LE(file.length, 18);
local.writeUInt32LE(file.length, 22);
local.writeUInt16LE(name.length, 26);

const central = Buffer.alloc(46);
central.writeUInt32LE(0x02014b50, 0);
central.writeUInt16LE(20, 4);
local.copy(central, 6, 4, 28);
const end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0);
end.writeUInt16LE(1, 8);
end.writeUInt16LE(1, 10);
end.writeUInt32LE(central.length + name.length, 12);
end.writeUInt32LE(local.length + name.length + file.length, 16);
const zip = Buffer.concat([local, name, file, central, name, end]);

const output = new URL(workers ? '../dist/workers/' : '../dist/', import.meta.url);
mkdirSync(output, { recursive: true });
const hash = digest(zip);
writeFileSync(new URL(archive, output), zip);
let checksums = hash + '  ' + archive + '\n';
if (workers) {
  writeFileSync(new URL(filename, output), file);
  checksums += digest(file) + '  ' + filename + '\n';
}
writeFileSync(new URL('SHA256SUMS.txt', output), checksums);
console.log(checksums.trimEnd());
