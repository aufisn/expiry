// Generates the PWA icons (PNG) with no dependencies: midnight background, brass calendar with a clock.
// Run: node tools/make-icons.js
const fs = require('fs'), zlib = require('zlib'), path = require('path');
const BG = [0x12, 0x16, 0x1f], BRASS = [0xc9, 0xa2, 0x27];
function crc32(buf){ let c, crc = 0xffffffff; for (let n = 0; n < buf.length; n++){ c = (crc ^ buf[n]) & 0xff; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crc = (crc >>> 8) ^ c; } return (crc ^ 0xffffffff) >>> 0; }
function chunk(type, data){ const len = Buffer.alloc(4); len.writeUInt32BE(data.length); const td = Buffer.concat([Buffer.from(type), data]); const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td)); return Buffer.concat([len, td, crc]); }
function png(size, px){ const raw = Buffer.alloc((size * 4 + 1) * size); for (let y = 0; y < size; y++){ raw[y * (size * 4 + 1)] = 0; px.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4); }
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4); ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]); }
// signed distance helpers (unit square coordinates 0..1)
const sdRoundRect = (x, y, cx, cy, hw, hh, r) => { const qx = Math.abs(x - cx) - hw + r, qy = Math.abs(y - cy) - hh + r; return Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) - r; };
const sdSeg = (x, y, ax, ay, bx, by) => { const pax = x - ax, pay = y - ay, bax = bx - ax, bay = by - ay; const h = Math.max(0, Math.min(1, (pax * bax + pay * bay) / (bax * bax + bay * bay))); return Math.hypot(pax - bax * h, pay - bay * h); };
function draw(size, scale, rounded){
  const px = Buffer.alloc(size * size * 4);
  const aa = 1.2 / size;
  for (let j = 0; j < size; j++) for (let i = 0; i < size; i++){
    const x = (i + 0.5) / size, y = (j + 0.5) / size;
    // map into the artwork box (scale < 1 leaves the maskable safe zone)
    const u = 0.5 + (x - 0.5) / scale, v = 0.5 + (y - 0.5) / scale;
    const s = 1 / scale; // distances in artwork units -> pixel units
    let d = Infinity;
    const st = 0.026; // stroke half-width
    d = Math.min(d, Math.abs(sdRoundRect(u, v, 0.5, 0.54, 0.30, 0.28, 0.07)) - st);   // calendar body
    d = Math.min(d, sdRoundRect(u, v, 0.5, 0.33, 0.30, 0.07, 0.05));                  // header band
    d = Math.min(d, sdSeg(u, v, 0.36, 0.18, 0.36, 0.30) - st);                         // rings
    d = Math.min(d, sdSeg(u, v, 0.64, 0.18, 0.64, 0.30) - st);
    d = Math.min(d, Math.abs(Math.hypot(u - 0.5, v - 0.60) - 0.13) - st * 0.8);        // clock face
    d = Math.min(d, sdSeg(u, v, 0.5, 0.60, 0.5, 0.52) - st * 0.7);                     // hands
    d = Math.min(d, sdSeg(u, v, 0.5, 0.60, 0.57, 0.63) - st * 0.7);
    const a = Math.max(0, Math.min(1, 0.5 - (d / s) / aa));
    let bgA = 1;
    if (rounded){ const r = sdRoundRect(x, y, 0.5, 0.5, 0.5, 0.5, 0.22); bgA = Math.max(0, Math.min(1, 0.5 - r / aa)); }
    const o = (j * size + i) * 4;
    for (let c = 0; c < 3; c++) px[o + c] = Math.round(BG[c] * (1 - a) + BRASS[c] * a);
    px[o + 3] = Math.round(255 * bgA);
  }
  return png(size, px);
}
const out = path.join(__dirname, '..');
fs.writeFileSync(path.join(out, 'icon-192.png'), draw(192, 1, true));
fs.writeFileSync(path.join(out, 'icon-512.png'), draw(512, 1, true));
fs.writeFileSync(path.join(out, 'icon-maskable-512.png'), draw(512, 0.72, false));
fs.writeFileSync(path.join(out, 'apple-touch-icon.png'), draw(180, 0.9, false));
fs.writeFileSync(path.join(out, 'favicon-32.png'), draw(32, 1, true));
console.log('icons written');
