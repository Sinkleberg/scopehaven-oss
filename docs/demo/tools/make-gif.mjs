#!/usr/bin/env node
// Assembles the PNG frames and frames.json written by record-frames.mjs into one looping GIF.
//
// Node only, nothing to install: PNG decoding with node:zlib, one global palette of at most 255 colours by median cut,
// frame differencing (each frame after the first stores only the rectangle that changed, with unchanged pixels inside it
// transparent) and a GIF LZW encoder. Not a dependency of ScopeHaven or its tests. The run fails unless the result stays
// within --max-seconds (default 25) and --max-bytes (default 3000000).
//
//   node docs/demo/tools/make-gif.mjs --frames /absolute/frames --out /absolute/docs/demo/false-success-refund.gif
import { inflateSync } from 'node:zlib';
import { readFile, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';

const options = parseArgs(process.argv.slice(2));
const framesDir = required('--frames'), out = required('--out');
const maxSeconds = Number(options['--max-seconds'] ?? 25), maxBytes = Number(options['--max-bytes'] ?? 3000000);
if (!isAbsolute(framesDir) || !isAbsolute(out)) fail('--frames and --out must be absolute paths.');
const TRANSPARENT = 255, MAX_COLORS = 255;   // index 255 is reserved for "unchanged since the previous frame"

const manifest = JSON.parse(await readFile(join(framesDir, 'frames.json'), 'utf8'));
if (!Array.isArray(manifest.frames) || !manifest.frames.length) fail('frames.json lists no frames.');
const images = [];
for (const frame of manifest.frames) {
  const png = decodePng(await readFile(join(framesDir, frame.file)));
  if (images.length && (png.width !== images[0].width || png.height !== images[0].height)) fail(`${frame.file} has a different size from the first frame.`);
  if (!Number.isInteger(frame.delayMs) || frame.delayMs < 20) fail(`${frame.file} needs a whole delayMs of at least 20.`);
  images.push({ ...png, file: frame.file, delayMs: frame.delayMs });
}
const { width, height } = images[0];
const totalMs = images.reduce((sum, image) => sum + image.delayMs, 0);
if (totalMs > maxSeconds * 1000) fail(`The frames run ${totalMs} ms, over the ${maxSeconds} s limit.`);

const palette = buildPalette(images, MAX_COLORS);
const cache = new Map();
const indexed = images.map(image => ({ ...image, indices: indexImage(image.rgb, palette, cache) }));
const gif = encodeGif({ width, height, palette, frames: indexed });
if (gif.length > maxBytes) fail(`The GIF is ${gif.length} bytes, over the ${maxBytes} byte limit. Shorten the scene, shrink the viewport or simplify the frames.`);
await writeFile(out, gif, { flag: 'wx', mode: 0o644 });
console.log(`${out}: ${width}x${height}, ${indexed.length} frames, ${totalMs} ms, ${palette.length} colours, ${gif.length} bytes`);

function parseArgs(argv) {
  const parsed = {};
  for (let i = 0; i < argv.length; i += 2) { if (!argv[i].startsWith('--') || argv[i + 1] === undefined) fail(`Unexpected argument ${argv[i]}.`); parsed[argv[i]] = argv[i + 1]; }
  return parsed;
}
function required(name) { if (!options[name]) fail(`${name} is required.`); return options[name]; }
function fail(message) { console.error(`make-gif: ${message}`); process.exit(2); }

// A non-interlaced 8-bit RGB or RGBA PNG (what Chrome's screenshots are), returned as packed RGB.
function decodePng(buffer) {
  if (!buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) fail('Not a PNG file.');
  let offset = 8, width = 0, height = 0, bitDepth = 0, colorType = 0, interlace = 0;
  const idat = [];
  while (offset + 8 <= buffer.length) {
    const length = buffer.readUInt32BE(offset), type = buffer.toString('latin1', offset + 4, offset + 8), data = buffer.subarray(offset + 8, offset + 8 + length);
    if (type === 'IHDR') { width = data.readUInt32BE(0); height = data.readUInt32BE(4); bitDepth = data[8]; colorType = data[9]; interlace = data[12]; }
    else if (type === 'IDAT') idat.push(data);
    else if (type === 'IEND') break;
    offset += 12 + length;
  }
  if (bitDepth !== 8 || ![2, 6].includes(colorType) || interlace !== 0) fail(`Unsupported PNG (bit depth ${bitDepth}, colour type ${colorType}, interlace ${interlace}); 8-bit RGB or RGBA without interlace is expected.`);
  const channels = colorType === 6 ? 4 : 3, stride = width * channels, raw = inflateSync(Buffer.concat(idat));
  if (raw.length !== (stride + 1) * height) fail('PNG data has the wrong length.');
  const rgb = new Uint8Array(width * height * 3);
  let previous = new Uint8Array(stride), current = new Uint8Array(stride);
  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)], line = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    for (let i = 0; i < stride; i++) {
      const a = i >= channels ? current[i - channels] : 0, b = previous[i], c = i >= channels ? previous[i - channels] : 0;
      let value = line[i];
      if (filter === 1) value += a;
      else if (filter === 2) value += b;
      else if (filter === 3) value += (a + b) >> 1;
      else if (filter === 4) { const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c); value += pa <= pb && pa <= pc ? a : pb <= pc ? b : c; }
      else if (filter !== 0) fail(`Unknown PNG filter ${filter}.`);
      current[i] = value & 255;
    }
    for (let x = 0, o = y * width * 3; x < width; x++, o += 3) { rgb[o] = current[x * channels]; rgb[o + 1] = current[x * channels + 1]; rgb[o + 2] = current[x * channels + 2]; }
    [previous, current] = [current, previous];
  }
  return { width, height, rgb };
}

// Median cut over the colours of every frame, weighted by how many pixels use each colour.
function buildPalette(images, maxColors) {
  const counts = new Map();
  for (const { rgb } of images) for (let i = 0; i < rgb.length; i += 3) { const key = rgb[i] << 16 | rgb[i + 1] << 8 | rgb[i + 2]; counts.set(key, (counts.get(key) ?? 0) + 1); }
  const colors = [...counts].map(([key, n]) => ({ r: key >> 16 & 255, g: key >> 8 & 255, b: key & 255, n }));
  const channels = ['r', 'g', 'b'];
  const span = box => channels.map(channel => { let lo = 255, hi = 0; for (const c of box) { if (c[channel] < lo) lo = c[channel]; if (c[channel] > hi) hi = c[channel]; } return hi - lo; });
  const weight = box => box.reduce((sum, c) => sum + c.n, 0);
  const boxes = [colors];
  while (boxes.length < maxColors) {
    let best = -1, bestScore = 0;
    for (let i = 0; i < boxes.length; i++) { if (boxes[i].length < 2) continue; const score = Math.max(...span(boxes[i])) * weight(boxes[i]); if (score > bestScore) { bestScore = score; best = i; } }
    if (best < 0) break;
    const box = boxes[best], extent = span(box), channel = channels[extent.indexOf(Math.max(...extent))];
    box.sort((a, b) => a[channel] - b[channel]);
    const half = weight(box) / 2;
    let cut = 0, seen = 0;
    while (cut < box.length - 1 && seen + box[cut].n < half) seen += box[cut++].n;
    if (cut === 0) cut = 1;
    boxes.splice(best, 1, box.slice(0, cut), box.slice(cut));
  }
  return boxes.map(box => { let r = 0, g = 0, b = 0, n = 0; for (const c of box) { r += c.r * c.n; g += c.g * c.n; b += c.b * c.n; n += c.n; } return [Math.round(r / n), Math.round(g / n), Math.round(b / n)]; });
}
function indexImage(rgb, palette, cache) {
  const indices = new Uint8Array(rgb.length / 3);
  for (let i = 0, p = 0; i < rgb.length; i += 3, p++) {
    const key = rgb[i] << 16 | rgb[i + 1] << 8 | rgb[i + 2];
    let index = cache.get(key);
    if (index === undefined) {
      let best = 0, bestDistance = Infinity;
      for (let j = 0; j < palette.length; j++) { const dr = palette[j][0] - rgb[i], dg = palette[j][1] - rgb[i + 1], db = palette[j][2] - rgb[i + 2], d = dr * dr + dg * dg + db * db; if (d < bestDistance) { bestDistance = d; best = j; } }
      index = best; cache.set(key, index);
    }
    indices[p] = index;
  }
  return indices;
}

function encodeGif({ width, height, palette, frames }) {
  const parts = [Buffer.from('GIF89a', 'latin1')];
  const screen = Buffer.alloc(7); screen.writeUInt16LE(width, 0); screen.writeUInt16LE(height, 2); screen[4] = 0xF7; // global table, 8 bits per channel, 256 entries
  const table = Buffer.alloc(256 * 3);
  palette.forEach(([r, g, b], i) => { table[i * 3] = r; table[i * 3 + 1] = g; table[i * 3 + 2] = b; });
  parts.push(screen, table, Buffer.from([0x21, 0xFF, 0x0B, ...Buffer.from('NETSCAPE2.0', 'latin1'), 0x03, 0x01, 0x00, 0x00, 0x00])); // loop for ever
  let canvas = null, previousControl = null, previousDelay = 0;
  for (const frame of frames) {
    const delay = Math.round(frame.delayMs / 10);
    let x0 = 0, y0 = 0, x1 = width - 1, y1 = height - 1, pixels = frame.indices, transparent = false;
    if (canvas) {
      x0 = width; y0 = height; x1 = -1; y1 = -1;
      for (let y = 0, i = 0; y < height; y++) for (let x = 0; x < width; x++, i++) if (frame.indices[i] !== canvas[i]) { if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y; }
      if (x1 < 0) { previousDelay += delay; previousControl.writeUInt16LE(previousDelay, 4); console.log(`${frame.file}: identical to the previous frame, its time added to it`); continue; }
      const w = x1 - x0 + 1, h = y1 - y0 + 1;
      pixels = new Uint8Array(w * h); transparent = true;
      for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) { const i = (y0 + y) * width + x0 + x; pixels[y * w + x] = frame.indices[i] === canvas[i] ? TRANSPARENT : frame.indices[i]; }
    }
    const control = Buffer.from([0x21, 0xF9, 0x04, 0x04 | (transparent ? 1 : 0), 0, 0, transparent ? TRANSPARENT : 0, 0]); // disposal: leave in place
    control.writeUInt16LE(delay, 4);
    const descriptor = Buffer.alloc(10); descriptor[0] = 0x2C; descriptor.writeUInt16LE(x0, 1); descriptor.writeUInt16LE(y0, 3); descriptor.writeUInt16LE(x1 - x0 + 1, 5); descriptor.writeUInt16LE(y1 - y0 + 1, 7);
    const data = lzw(pixels, 8);
    parts.push(control, descriptor, Buffer.from([8]), data, Buffer.from([0]));
    console.log(`${frame.file}: ${x1 - x0 + 1}x${y1 - y0 + 1} at ${x0},${y0}, ${delay * 10} ms, ${data.length} bytes`);
    canvas = frame.indices; previousControl = control; previousDelay = delay;
  }
  parts.push(Buffer.from([0x3B]));
  return Buffer.concat(parts);
}
// GIF-flavoured LZW (variable code size from minCodeSize + 1 to 12 bits, clear at 4096 entries), packed into 255-byte sub-blocks.
function lzw(indices, minCodeSize) {
  const clear = 1 << minCodeSize, end = clear + 1, bytes = [];
  let codeSize = minCodeSize + 1, next = end + 1, dictionary = new Map(), accumulator = 0, bits = 0;
  const emit = code => { accumulator |= code << bits; bits += codeSize; while (bits >= 8) { bytes.push(accumulator & 255); accumulator >>>= 8; bits -= 8; } };
  emit(clear);
  let prefix = indices[0];
  for (let i = 1; i < indices.length; i++) {
    const symbol = indices[i], key = prefix * 256 + symbol, known = dictionary.get(key);
    if (known !== undefined) { prefix = known; continue; }
    emit(prefix);
    if (next === 4096) { emit(clear); dictionary = new Map(); next = end + 1; codeSize = minCodeSize + 1; }
    else { if (next === 1 << codeSize) codeSize++; dictionary.set(key, next++); }
    prefix = symbol;
  }
  emit(prefix); emit(end);
  if (bits > 0) bytes.push(accumulator & 255);
  const blocks = [];
  for (let i = 0; i < bytes.length; i += 255) { const chunk = bytes.slice(i, i + 255); blocks.push(Buffer.from([chunk.length]), Buffer.from(chunk)); }
  return Buffer.concat(blocks);
}
