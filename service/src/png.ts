// 8-bit RGBA PNGs, as scripts/assets.py writes the game's art, read into pixels, and the preview card's raster layers
// (src/raster.ts) written out for resvg.

export interface Pixels {
  width: number;
  height: number;
  // RGBA, row by row.
  data: Uint8Array;
}

const SIGNATURE = [137, 80, 78, 71, 13, 10, 26, 10];
const RGBA = 6;

async function inflate(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate"))).arrayBuffer());
}

function paeth(a: number, b: number, c: number): number {
  const p = a + b - c;
  const [pa, pb, pc] = [Math.abs(p - a), Math.abs(p - b), Math.abs(p - c)];
  return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}

export async function decodePng(bytes: Uint8Array): Promise<Pixels> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const width = view.getUint32(16);
  const height = view.getUint32(20);
  if (bytes[24] !== 8 || bytes[25] !== RGBA || bytes[28] !== 0) throw new Error("not an 8-bit RGBA PNG");
  const chunks: Uint8Array[] = [];
  for (let at = SIGNATURE.length; at < bytes.length; ) {
    const length = view.getUint32(at);
    if (String.fromCharCode(...bytes.subarray(at + 4, at + 8)) === "IDAT") chunks.push(bytes.subarray(at + 8, at + 8 + length));
    at += length + 12;
  }
  const filtered = await inflate(new Uint8Array(await new Blob(chunks).arrayBuffer()));
  const stride = width * 4;
  const data = new Uint8Array(stride * height);
  for (let y = 0; y < height; y++) {
    const filter = filtered[y * (stride + 1)]!;
    const row = filtered.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    for (let x = 0; x < stride; x++) {
      const i = y * stride + x;
      const left = x >= 4 ? data[i - 4]! : 0;
      const up = y > 0 ? data[i - stride]! : 0;
      const corner = x >= 4 && y > 0 ? data[i - stride - 4]! : 0;
      const predicted = [0, left, up, (left + up) >> 1, paeth(left, up, corner)][filter]!;
      data[i] = (row[x]! + predicted) & 0xff;
    }
  }
  return { width, height, data };
}

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function chunk(type: string, body: Uint8Array): Uint8Array {
  const out = new Uint8Array(body.length + 12);
  const view = new DataView(out.buffer);
  view.setUint32(0, body.length);
  out.set([...type].map((ch) => ch.charCodeAt(0)), 4);
  out.set(body, 8);
  let crc = 0xffffffff;
  for (const byte of out.subarray(4, 8 + body.length)) crc = CRC_TABLE[(crc ^ byte) & 0xff]! ^ (crc >>> 8);
  view.setUint32(8 + body.length, (crc ^ 0xffffffff) >>> 0);
  return out;
}

// Unfiltered rows in stored deflate blocks: resvg decodes the image straight away, so compressing it buys nothing.
export function encodePng({ width, height, data }: Pixels): Uint8Array {
  const stride = width * 4;
  const raw = new Uint8Array((stride + 1) * height);
  for (let y = 0; y < height; y++) raw.set(data.subarray(y * stride, (y + 1) * stride), y * (stride + 1) + 1);
  const BLOCK = 0xffff;
  const blocks = Math.ceil(raw.length / BLOCK);
  const zlib = new Uint8Array(2 + raw.length + blocks * 5 + 4);
  const view = new DataView(zlib.buffer);
  zlib.set([0x78, 0x01]);
  let at = 2;
  for (let i = 0; i < blocks; i++) {
    const block = raw.subarray(i * BLOCK, (i + 1) * BLOCK);
    zlib[at] = i === blocks - 1 ? 1 : 0;
    view.setUint16(at + 1, block.length, true);
    view.setUint16(at + 3, ~block.length & 0xffff, true);
    zlib.set(block, at + 5);
    at += 5 + block.length;
  }
  let [a, b] = [1, 0];
  for (let i = 0; i < raw.length; i++) {
    a = (a + raw[i]!) % 65521;
    b = (b + a) % 65521;
  }
  view.setUint32(at, ((b << 16) | a) >>> 0);
  const header = new Uint8Array(13);
  const fields = new DataView(header.buffer);
  fields.setUint32(0, width);
  fields.setUint32(4, height);
  header.set([8, RGBA, 0, 0, 0], 8);
  const parts = [new Uint8Array(SIGNATURE), chunk("IHDR", header), chunk("IDAT", zlib), chunk("IEND", new Uint8Array())];
  const png = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  parts.reduce((offset, part) => (png.set(part, offset), offset + part.length), 0);
  return png;
}
